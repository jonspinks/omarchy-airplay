//! One sender clock for every timestamp that reaches the wire.
//!
//! Audio (TimeAnnounce/sync packets) and, once the session layer is switched
//! over, video PTS and timing replies all read CLOCK_BOOTTIME through
//! [`SenderClock`]. BOOTTIME rather than MONOTONIC because it keeps counting
//! across suspend, so a suspend shows up to the audio timeline as a long gap
//! and forces a re-anchor instead of silently sending stale timestamps.
//!
//! A [`ClockReading`] carries both the duration used for gap/deadline
//! arithmetic and the NTP stamp that goes on the wire, computed from the SAME
//! read, so the two can never disagree. The NTP conversion is exactly
//! [`NtpTimestamp::from_boottime_parts`], the same one `timing.rs` and the
//! video path already use.

use crate::timing::NtpTimestamp;
use std::sync::Mutex;
use std::time::Duration;

/// One read of the sender clock. There is no public constructor other than
/// [`SenderClock::read`] (and the hidden test constructor), so a timeline that
/// takes a `ClockReading` is guaranteed to be handed a real clock read, not a
/// value computed ahead of time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockReading {
    boot: Duration,
    ntp: NtpTimestamp,
}

impl ClockReading {
    /// The NTP timestamp for this instant (BOOTTIME + NTP epoch offset).
    pub fn ntp(&self) -> NtpTimestamp {
        self.ntp
    }

    /// Time since BOOTTIME zero.
    pub fn boot(&self) -> Duration {
        self.boot
    }

    /// `self - earlier`, saturating at zero.
    pub fn since(&self, earlier: &ClockReading) -> Duration {
        self.boot.saturating_sub(earlier.boot)
    }

    fn from_timespec(sec: u64, nsec: u32) -> Self {
        ClockReading {
            boot: Duration::new(sec, nsec),
            // Identical to NtpTimestamp::now_from_boottime().
            ntp: NtpTimestamp::from_boottime_parts(sec, nsec as f64 / 1_000_000_000.0),
        }
    }

    /// TEST ONLY. A reading at `t` seconds of BOOTTIME, converted to NTP with
    /// exactly the probe's float arithmetic (`seconds = int(t)`,
    /// `fraction = int((t - seconds) * 2**32)`), so replayed probe traces
    /// produce byte-identical sync packets.
    #[doc(hidden)]
    pub fn from_boottime_secs_f64(t: f64) -> Self {
        assert!(t.is_finite() && t >= 0.0, "boottime must be finite and >= 0");
        let seconds = t as u64;
        ClockReading {
            boot: Duration::from_secs_f64(t),
            ntp: NtpTimestamp::from_boottime_parts(seconds, t - seconds as f64),
        }
    }
}

/// The sender's clock. Production is [`BoottimeClock`].
pub trait SenderClock: Send + Sync {
    fn read(&self) -> ClockReading;
}

/// `clock_gettime(CLOCK_BOOTTIME)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct BoottimeClock;

impl SenderClock for BoottimeClock {
    fn read(&self) -> ClockReading {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid timespec pointer, well-defined clock id.
        unsafe {
            libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts);
        }
        ClockReading::from_timespec(ts.tv_sec as u64, ts.tv_nsec as u32)
    }
}

/// TEST ONLY. A settable clock (seconds of BOOTTIME as f64, like the probe's
/// patched `time.clock_gettime`).
#[doc(hidden)]
#[derive(Debug)]
pub struct FakeClock {
    t: Mutex<f64>,
}

#[doc(hidden)]
impl FakeClock {
    pub fn new(t: f64) -> Self {
        FakeClock { t: Mutex::new(t) }
    }
    pub fn set(&self, t: f64) {
        *self.t.lock().unwrap() = t;
    }
    pub fn advance(&self, d: f64) {
        *self.t.lock().unwrap() += d;
    }
    pub fn now_secs(&self) -> f64 {
        *self.t.lock().unwrap()
    }
}

impl SenderClock for FakeClock {
    fn read(&self) -> ClockReading {
        ClockReading::from_boottime_secs_f64(*self.t.lock().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boottime_reading_matches_timing_conversion() {
        // Same clock, same conversion: two reads bracket the timing.rs one.
        let a = BoottimeClock.read();
        let t = NtpTimestamp::now_from_boottime();
        let b = BoottimeClock.read();
        assert!(a.ntp().0 <= t.0 && t.0 <= b.ntp().0);
        assert!(b.since(&a) < Duration::from_secs(1));
        assert_eq!(a.since(&b), Duration::ZERO);
    }

    #[test]
    fn fake_clock_uses_probe_float_conversion() {
        let c = FakeClock::new(1000.5);
        assert_eq!(c.read().ntp().0, ((1000 + 2_208_988_800u64) << 32) | 0x8000_0000);
        c.advance(0.25);
        assert_eq!(c.read().boot(), Duration::from_millis(1_000_750));
    }
}
