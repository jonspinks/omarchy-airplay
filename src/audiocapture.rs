//! audiocapture: system-audio capture for the type-96 audio stream.
//!
//! Everything here produces exact 1408-byte frames (352 samples of s16le
//! stereo at 44.1 kHz) through one trait, [`PcmSource`]:
//!
//! * [`PipewireSource`] — production, in two modes, both one passive capture
//!   node that touches no volume and no routing:
//!   * **sink** ([`PwCaptureOpts::target`] set, `dont_fallback`): the monitor
//!     of the sink the sender published itself ([`crate::audiosink`]). That
//!     sink's monitor carries no channel volumes, so the samples are taken
//!     BEFORE its level is applied and the level is applied exactly once, at
//!     the TV. The sound moves to the TV instead of playing on the laptop,
//!     because that sink IS the laptop's output while the session runs.
//!     Nothing in *this* module makes that sink the default — taking and
//!     giving back the output is [`crate::audiosink`]'s job, with a claim on
//!     disk and a lock.
//!   * **pipewire** (`target: None`): the DEFAULT SINK'S MONITOR, which
//!     WirePlumber moves when the user changes output device. The sound plays on
//!     the laptop *and* goes to the TV — the only mode in which the room can
//!     hear both, which is how lip sync gets A/B'd.
//! * [`ParecSource`] — fallback (`--audio-capture parec`), the exact `parec`
//!   invocation the probe used and the tester heard work.
//! * [`ToneSource`] — the probe's 880 Hz beep, paced by the sender clock.
//! * [`ScriptedSource`] — a test fake with a scripted release schedule.
//!
//! # What this layer guarantees to the audio timeline
//!
//! * `next_frame` blocks for at most its `timeout` and never forever; the
//!   stopper returned by [`PcmSource::stopper`] unblocks it from another
//!   thread within one poll slice (≤ [`POLL_SLICE`]).
//! * A frame is returned only when all 1408 bytes are in hand. Capture
//!   start-up time is therefore never inside a frame: the sender reads its
//!   clock after `next_frame` returns, which is what makes the probe's
//!   silent-audio bug impossible (see `audio.rs`).
//! * Per-buffer timestamps ([`PcmBlock::boot_ns`]) are on the sender clock's
//!   domain (BOOTTIME nanoseconds) but are deliberately a plain `u64`, NOT a
//!   [`ClockReading`](crate::clock::ClockReading): they describe when the
//!   buffer was delivered and can never be handed to `AudioTimeline::emit` as
//!   the send time. They are for logging, stall diagnosis and future A/V work.
//! * Discontinuities (a relink when the default sink changes, a callback gap,
//!   a graph-clock jump, a ring overrun, a reconnect after an error) are
//!   flagged on the first frame that contains post-discontinuity audio and
//!   counted in [`CaptureStats`]. They are NOT papered over here (no
//!   zero-filling — that is a TV-gated experiment). The timeline's own rules
//!   (gap > 250 ms or late against the deadline ⇒ re-anchor with a 0x90) are
//!   what keep the receiver's clock mapping honest across them.
//!
//! # Default sink changes mid-session (`--audio-capture pipewire` only)
//!
//! Everything in this section is about the **default-monitor** mode. In sink
//! mode the stream is pinned to one node name with `dont_fallback`, so it
//! never follows anything: if the sink the sender published disappears, the
//! capture reports it rather than quietly taping the desk speakers.
//!
//! The default-monitor stream has no `target.object`, so it is a "follow the
//! default" stream: when the default sink changes, WirePlumber relinks it to
//! the new sink's monitor. PipeWire reports that as a state change
//! (Streaming → Paused → Streaming) and/or a graph-clock change; the stream
//! keeps delivering, the next frame is flagged [`Discontinuity::Relinked`] or
//! [`Discontinuity::ClockJump`], and if the relink paused callbacks for more
//! than 250 ms the timeline re-anchors. If the stream ever reaches the
//! `Error` state it is reconnected after [`RECONNECT_DELAY`].
//!
//! Proven offline and on owned null sinks: the relink path when our stream's
//! own target is moved between two null sinks (`tests/audio_capture_live.rs`).
//! NOT proven: WirePlumber moving the stream on a real default-sink change —
//! testing that means changing the user's default sink, which is forbidden. The
//! `parec` fallback resolves `@DEFAULT_MONITOR@` once at start and is not
//! expected to follow a default-sink change (unproven either way).

use crate::audio::{ALAC_SPF, AUDIO_RATE, PCM_FRAME_BYTES};
use crate::clock::SenderClock;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Longest single blocking wait inside any `next_frame`: the stop flag is
/// re-checked at least this often.
pub const POLL_SLICE: Duration = Duration::from_millis(50);
/// Delay before a stream in the `Error` state is reconnected.
pub const RECONNECT_DELAY: Duration = Duration::from_millis(500);
/// The PipeWire ring holds this much audio (2 s). The sender drains it every
/// frame, so it only fills if the sender thread itself stalls.
pub const RING_SECONDS: usize = 2;
/// `node.latency` requested from PipeWire: one ALAC frame.
pub const PW_NODE_LATENCY: &str = "352/44100";
/// A gap between PipeWire callbacks longer than this many buffer durations
/// is a [`Discontinuity::CallbackGap`].
pub const CALLBACK_GAP_FACTOR: u64 = 3;
/// A parec read gap longer than this is a [`Discontinuity::CallbackGap`]
/// (parec is asked for 10 ms reads).
pub const PAREC_READ_GAP: Duration = Duration::from_millis(100);
/// Graph clock vs `pw_time.now` disagreement beyond this is a
/// [`Discontinuity::ClockJump`].
pub const CLOCK_JUMP_TOLERANCE: Duration = Duration::from_millis(50);
/// How long after a (re)connect WirePlumber's `restore-stream` may still land
/// a remembered `channelVolumes` on our capture node. The level pin is
/// written once immediately and once more after this, so a late restore does
/// not stand. Measured at well under a second on this machine; 1.2 s is slack.
pub const CAPTURE_LEVEL_RESEED: Duration = Duration::from_millis(1200);
/// `channelVolumes` further than this from 1.0 counts as attenuation and is
/// written back. Float round-trips through the pod are exact for 1.0, so this
/// only absorbs arithmetic slop.
const LEVEL_EPSILON: f32 = 0.001;

const FRAME_NS: u64 = ALAC_SPF as u64 * 1_000_000_000 / AUDIO_RATE as u64;

// --------------------------------------------------------------------------
// Public types
// --------------------------------------------------------------------------

/// Why a frame follows a break in the captured audio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discontinuity {
    /// The stream went back to Streaming after leaving it: it was relinked,
    /// e.g. the default sink changed or its target was moved.
    Relinked,
    /// The stream was reconnected after reaching the `Error` state.
    Reconnected,
    /// No capture data for longer than expected (callbacks or reads stopped).
    CallbackGap { gap: Duration },
    /// The graph clock stepped inconsistently with the monotonic clock, or
    /// its rate changed: a different driver is now feeding us.
    ClockJump,
    /// The consumer fell behind and whole buffers were dropped.
    Overrun { dropped_bytes: u64 },
}

/// One 352-sample frame of s16le stereo PCM.
#[derive(Clone, Debug)]
pub struct PcmBlock {
    pub pcm: [u8; PCM_FRAME_BYTES],
    /// BOOTTIME nanoseconds (the sender clock's domain) at which the capture
    /// buffer holding this frame's first sample was delivered, advanced by the
    /// sample's offset within that buffer. Informational only: deliberately
    /// not a `ClockReading`, so it can never become a send time.
    pub boot_ns: Option<u64>,
    /// PipeWire's `pw_time.now` (CLOCK_MONOTONIC) for that buffer, advanced
    /// the same way. Discontinuity diagnosis only; never converted to NTP.
    pub mono_ns: Option<u64>,
    /// Set on the first frame containing audio after a break.
    pub discontinuity: Option<Discontinuity>,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("capture stopped")]
    Stopped,
    #[error("capture ended (source closed)")]
    Ended,
    #[error("failed to start capture: {0}")]
    Spawn(#[source] io::Error),
    #[error("capture I/O error: {0}")]
    Io(#[source] io::Error),
    #[error("PipeWire: {0}")]
    Pipewire(String),
}

/// Coarse state for status reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CaptureState {
    #[default]
    Starting,
    Streaming,
    /// Connected but not currently delivering (paused / relinking).
    Paused,
    /// In the `Error` state, waiting to reconnect.
    Error,
    Stopped,
}

impl CaptureState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaptureState::Starting => "starting",
            CaptureState::Streaming => "streaming",
            CaptureState::Paused => "paused",
            CaptureState::Error => "error",
            CaptureState::Stopped => "stopped",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Capture buffers (PipeWire callbacks / parec reads) received.
    pub buffers: u64,
    /// Bytes received (including any later dropped by an overrun).
    pub bytes: u64,
    /// Whole frames handed to the consumer.
    pub frames: u64,
    pub discontinuities: u64,
    pub relinks: u64,
    pub reconnects: u64,
    pub overruns: u64,
    pub dropped_bytes: u64,
    pub state: CaptureState,
}

/// A source of 1408-byte PCM frames.
pub trait PcmSource: Send {
    /// The next full frame. `Ok(None)` means `timeout` elapsed first; this
    /// never blocks longer than `timeout` (plus scheduling slop). After the
    /// stopper has run it returns `Err(CaptureError::Stopped)`.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<PcmBlock>, CaptureError>;
    /// A handle that stops the source and unblocks `next_frame` from any
    /// thread. Idempotent.
    fn stopper(&self) -> Box<dyn Fn() + Send + Sync>;
    fn stats(&self) -> CaptureStats;
    /// "pipewire", "parec", "tone" or "scripted".
    fn kind(&self) -> &'static str;
}

// --------------------------------------------------------------------------
// Wake-up primitive: an eventfd the producer pokes and the consumer polls
// --------------------------------------------------------------------------

#[derive(Debug)]
struct Wake {
    fd: OwnedFd,
}

impl Wake {
    fn new() -> io::Result<Self> {
        // SAFETY: plain syscall; the returned fd is owned below.
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh, valid descriptor we own.
        Ok(Wake { fd: unsafe { OwnedFd::from_raw_fd(fd) } })
    }

    /// Non-blocking, allocation-free: safe from the RT process callback.
    fn notify(&self) {
        let one: u64 = 1;
        // SAFETY: writes 8 bytes from a valid u64 to our eventfd.
        unsafe {
            libc::write(self.fd.as_raw_fd(), &one as *const u64 as *const libc::c_void, 8);
        }
    }

    /// Wait until notified or `timeout`; clears the counter.
    fn wait(&self, timeout: Duration) {
        poll_readable(self.fd.as_raw_fd(), timeout);
        let mut v: u64 = 0;
        // SAFETY: reads at most 8 bytes into a valid u64; fd is non-blocking.
        unsafe {
            libc::read(self.fd.as_raw_fd(), &mut v as *mut u64 as *mut libc::c_void, 8);
        }
    }
}

/// poll(2) one fd for readability (or hangup). Returns true if ready.
fn poll_readable(fd: RawFd, timeout: Duration) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // Round sub-millisecond waits up so a tiny timeout still yields.
    let ms = if ms == 0 && !timeout.is_zero() { 1 } else { ms };
    // SAFETY: one valid pollfd.
    let r = unsafe { libc::poll(&mut p, 1, ms) };
    r > 0
}

// --------------------------------------------------------------------------
// The lock-free ring between the RT callback and the consumer
// --------------------------------------------------------------------------

/// One `pw_time` sample, as read in the process callback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PwTimeSample {
    /// CLOCK_MONOTONIC ns.
    pub now: i64,
    pub ticks: u64,
    pub rate_num: u32,
    pub rate_denom: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct BufMeta {
    /// Absolute byte position (in the pushed stream) of this buffer's start.
    start: u64,
    boot_ns: u64,
    mono_ns: Option<i64>,
    disc: Option<Discontinuity>,
}


/// State shared between the RT producer, the PipeWire loop thread and the
/// consumer. Only atomics are touched from the RT callback.
#[derive(Debug)]
struct Shared {
    stop: AtomicBool,
    wake: Wake,
    /// Incremented on every transition INTO Streaming.
    streaming_epoch: AtomicU64,
    /// Incremented on every reconnect after an Error.
    reconnect_epoch: AtomicU64,
    state: AtomicU64,
    buffers: AtomicU64,
    bytes: AtomicU64,
    frames: AtomicU64,
    discontinuities: AtomicU64,
    relinks: AtomicU64,
    overruns: AtomicU64,
    dropped_bytes: AtomicU64,
    /// The capture node's current id (it changes when a reconnect creates a
    /// new node); u32::MAX while unknown.
    node_id: std::sync::atomic::AtomicU32,
    /// The loudest `channelVolumes` entry the last `Props` param carried,
    /// as `f32::to_bits`. Meaningless until `props_epoch` is non-zero.
    ///
    /// A capture stream is a source-output with a node volume of its OWN,
    /// which WirePlumber remembers per `application.name` and restores
    /// asynchronously after connect. If it ever came back at anything but
    /// 1.0 every sample shipped to the TV would be attenuated a second time,
    /// on top of the dB the TV was told — the exact double-application the
    /// sink path exists to make impossible. So it is watched, not hoped for.
    channel_volume: std::sync::atomic::AtomicU32,
    /// Incremented on every `Props` param seen; 0 means none yet.
    props_epoch: AtomicU64,
    /// How many times the level had to be written back to 1.0.
    level_writes: AtomicU64,
    /// Set (never from the RT thread) when the source cannot continue.
    fatal: Mutex<Option<String>>,
}

impl Shared {
    fn new() -> io::Result<Self> {
        Ok(Shared {
            stop: AtomicBool::new(false),
            wake: Wake::new()?,
            streaming_epoch: AtomicU64::new(0),
            reconnect_epoch: AtomicU64::new(0),
            state: AtomicU64::new(state_code(CaptureState::Starting)),
            buffers: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            frames: AtomicU64::new(0),
            discontinuities: AtomicU64::new(0),
            relinks: AtomicU64::new(0),
            overruns: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
            node_id: std::sync::atomic::AtomicU32::new(u32::MAX),
            channel_volume: std::sync::atomic::AtomicU32::new(1.0f32.to_bits()),
            props_epoch: AtomicU64::new(0),
            level_writes: AtomicU64::new(0),
            fatal: Mutex::new(None),
        })
    }

    /// The capture node's own `channelVolumes`, if a `Props` param has been
    /// seen. `None` means "not observed", never "1.0".
    fn channel_volume(&self) -> Option<f32> {
        if self.props_epoch.load(Ordering::Relaxed) == 0 {
            return None;
        }
        Some(f32::from_bits(self.channel_volume.load(Ordering::Relaxed)))
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.notify();
    }

    fn set_state(&self, s: CaptureState) {
        self.state.store(state_code(s), Ordering::Relaxed);
    }

    fn set_fatal(&self, msg: String) {
        let mut f = self.fatal.lock().unwrap_or_else(|p| p.into_inner());
        if f.is_none() {
            *f = Some(msg);
        }
        drop(f);
        self.wake.notify();
    }

    fn fatal(&self) -> Option<String> {
        self.fatal.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn stats(&self) -> CaptureStats {
        CaptureStats {
            buffers: self.buffers.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            frames: self.frames.load(Ordering::Relaxed),
            discontinuities: self.discontinuities.load(Ordering::Relaxed),
            relinks: self.relinks.load(Ordering::Relaxed),
            reconnects: self.reconnect_epoch.load(Ordering::Relaxed),
            overruns: self.overruns.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            state: if self.stop.load(Ordering::Relaxed) {
                CaptureState::Stopped
            } else {
                state_from_code(self.state.load(Ordering::Relaxed))
            },
        }
    }
}

fn state_code(s: CaptureState) -> u64 {
    match s {
        CaptureState::Starting => 0,
        CaptureState::Streaming => 1,
        CaptureState::Paused => 2,
        CaptureState::Error => 3,
        CaptureState::Stopped => 4,
    }
}

fn state_from_code(c: u64) -> CaptureState {
    match c {
        1 => CaptureState::Streaming,
        2 => CaptureState::Paused,
        3 => CaptureState::Error,
        4 => CaptureState::Stopped,
        _ => CaptureState::Starting,
    }
}

/// The RT-side half of the ring. `push` does no allocation, no locking and
/// no blocking: two SPSC ring commits, a handful of atomics and one
/// non-blocking eventfd write.
struct RingWriter {
    bytes: rtrb::Producer<u8>,
    meta: rtrb::Producer<BufMeta>,
    written: u64,
    pending: Option<Discontinuity>,
    pending_dropped: u64,
    last_boot_ns: Option<u64>,
    last_frames: u64,
    last_time: Option<PwTimeSample>,
    seen_streaming_epoch: u64,
    seen_reconnect_epoch: u64,
    shared: Arc<Shared>,
}

/// The consumer half: cuts exact 1408-byte frames and attaches timestamps
/// and discontinuities.
struct RingReader {
    bytes: rtrb::Consumer<u8>,
    meta: rtrb::Consumer<BufMeta>,
    read: u64,
    cur: Option<BufMeta>,
    frame: [u8; PCM_FRAME_BYTES],
    fill: usize,
    frame_boot: Option<u64>,
    frame_mono: Option<u64>,
    frame_disc: Option<Discontinuity>,
    shared: Arc<Shared>,
}

fn ring_pair(capacity_bytes: usize, shared: Arc<Shared>) -> (RingWriter, RingReader) {
    let (bp, bc) = rtrb::RingBuffer::<u8>::new(capacity_bytes);
    // Worst case one meta per 4-byte buffer is absurd; one per 32 samples is
    // far below any real quantum and keeps this small.
    let (mp, mc) = rtrb::RingBuffer::<BufMeta>::new((capacity_bytes / 128).max(64));
    (
        RingWriter {
            bytes: bp,
            meta: mp,
            written: 0,
            pending: None,
            pending_dropped: 0,
            last_boot_ns: None,
            last_frames: 0,
            last_time: None,
            seen_streaming_epoch: 0,
            seen_reconnect_epoch: 0,
            shared: shared.clone(),
        },
        RingReader {
            bytes: bc,
            meta: mc,
            read: 0,
            cur: None,
            frame: [0; PCM_FRAME_BYTES],
            fill: 0,
            frame_boot: None,
            frame_mono: None,
            frame_disc: None,
            shared,
        },
    )
}

fn frames_to_ns(frames: u64) -> u64 {
    frames * 1_000_000_000 / AUDIO_RATE as u64
}

impl RingWriter {
    /// Record a discontinuity for the next pushed buffer. The most specific
    /// cause wins: an earlier-recorded cause is kept unless it is a relink
    /// being upgraded to a reconnect.
    fn note(&mut self, d: Discontinuity) {
        match (self.pending, d) {
            (None, _) | (Some(Discontinuity::Relinked), Discontinuity::Reconnected) => {
                self.pending = Some(d)
            }
            _ => {}
        }
    }

    /// Push one capture buffer delivered at `boot_ns` (sender clock domain).
    fn push(&mut self, data: &[u8], boot_ns: u64, time: Option<PwTimeSample>) {
        // Only whole stereo s16 samples; a stray partial sample would swap
        // channels for the rest of the stream.
        let data = &data[..data.len() - data.len() % 4];
        self.shared.buffers.fetch_add(1, Ordering::Relaxed);
        self.shared.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        let rec = self.shared.reconnect_epoch.load(Ordering::Relaxed);
        if rec != self.seen_reconnect_epoch {
            self.seen_reconnect_epoch = rec;
            self.note(Discontinuity::Reconnected);
        }
        let ep = self.shared.streaming_epoch.load(Ordering::Relaxed);
        if ep != self.seen_streaming_epoch {
            // The first entry into Streaming is the start, not a break.
            if self.seen_streaming_epoch != 0 || self.written > 0 {
                self.shared.relinks.fetch_add(1, Ordering::Relaxed);
                self.note(Discontinuity::Relinked);
            }
            self.seen_streaming_epoch = ep;
        }
        if let Some(prev) = self.last_boot_ns {
            let expected = frames_to_ns(self.last_frames).max(FRAME_NS);
            let gap = boot_ns.saturating_sub(prev);
            if gap > CALLBACK_GAP_FACTOR * expected {
                self.note(Discontinuity::CallbackGap {
                    gap: Duration::from_nanos(gap),
                });
            }
        }
        if let (Some(p), Some(t)) = (self.last_time, time) {
            if p.now != 0 && t.now != 0 && p.rate_denom != 0 && t.rate_denom != 0 {
                let jumped = if (p.rate_num, p.rate_denom) != (t.rate_num, t.rate_denom)
                    || t.ticks < p.ticks
                    || t.now < p.now
                {
                    true
                } else {
                    let ticks_ns = ((t.ticks - p.ticks) as u128 * 1_000_000_000u128
                        * t.rate_num as u128
                        / t.rate_denom as u128) as i128;
                    let now_ns = (t.now - p.now) as i128;
                    (ticks_ns - now_ns).unsigned_abs() > CLOCK_JUMP_TOLERANCE.as_nanos()
                };
                if jumped {
                    self.note(Discontinuity::ClockJump);
                }
            }
        }
        self.last_boot_ns = Some(boot_ns);
        self.last_frames = (data.len() / 4) as u64;
        if time.is_some() {
            self.last_time = time;
        }

        if data.is_empty() {
            return;
        }
        if self.bytes.slots() < data.len() || self.meta.slots() == 0 {
            // Overrun: drop the whole buffer rather than a partial one, so the
            // stream the consumer sees stays sample-aligned.
            self.shared.overruns.fetch_add(1, Ordering::Relaxed);
            self.shared.dropped_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
            self.pending_dropped += data.len() as u64;
            self.pending = Some(Discontinuity::Overrun {
                dropped_bytes: self.pending_dropped,
            });
            self.shared.wake.notify();
            return;
        }
        let disc = self.pending.take();
        if disc.is_some() {
            self.shared.discontinuities.fetch_add(1, Ordering::Relaxed);
            self.pending_dropped = 0;
        }
        // Meta first, then bytes: once the consumer can see a byte it can
        // also see the meta describing it.
        let _ = self.meta.push(BufMeta {
            start: self.written,
            boot_ns,
            mono_ns: time.map(|t| t.now).filter(|&n| n != 0),
            disc,
        });
        let _ = self.bytes.push_entire_slice(data);
        self.written += data.len() as u64;
        self.shared.wake.notify();
    }
}

impl RingReader {
    /// A frame if one is complete; never blocks.
    fn try_frame(&mut self) -> Option<PcmBlock> {
        loop {
            if self.fill == PCM_FRAME_BYTES {
                let block = PcmBlock {
                    pcm: self.frame,
                    boot_ns: self.frame_boot.take(),
                    mono_ns: self.frame_mono.take(),
                    discontinuity: self.frame_disc.take(),
                };
                self.fill = 0;
                self.shared.frames.fetch_add(1, Ordering::Relaxed);
                return Some(block);
            }
            // Read the byte count BEFORE looking at metas (see push order).
            let avail = self.bytes.slots();
            while let Ok(m) = self.meta.peek() {
                if m.start > self.read {
                    break;
                }
                let m = self.meta.pop().expect("peeked");
                if m.disc.is_some() && self.frame_disc.is_none() {
                    self.frame_disc = m.disc;
                }
                self.cur = Some(m);
            }
            if avail == 0 {
                return None;
            }
            if self.fill == 0 {
                if let Some(c) = self.cur {
                    let off = frames_to_ns((self.read - c.start) / 4);
                    self.frame_boot = Some(c.boot_ns + off);
                    self.frame_mono = c.mono_ns.map(|m| (m.max(0) as u64) + off);
                }
            }
            let mut n = avail.min(PCM_FRAME_BYTES - self.fill);
            if let Ok(next) = self.meta.peek() {
                // Stop at the next buffer boundary so its meta is applied.
                n = n.min((next.start - self.read) as usize);
            }
            if n == 0 {
                continue;
            }
            let chunk = self.bytes.read_chunk(n).expect("n <= slots");
            let (a, b) = chunk.as_slices();
            self.frame[self.fill..self.fill + a.len()].copy_from_slice(a);
            self.frame[self.fill + a.len()..self.fill + a.len() + b.len()].copy_from_slice(b);
            chunk.commit_all();
            self.fill += n;
            self.read += n as u64;
        }
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<PcmBlock>, CaptureError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.shared.stop.load(Ordering::SeqCst) {
                return Err(CaptureError::Stopped);
            }
            if let Some(f) = self.try_frame() {
                return Ok(Some(f));
            }
            if let Some(msg) = self.shared.fatal() {
                return Err(CaptureError::Pipewire(msg));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            self.shared.wake.wait((deadline - now).min(POLL_SLICE));
        }
    }
}

// --------------------------------------------------------------------------
// PipeWire backend
// --------------------------------------------------------------------------

/// Options for [`PipewireSource`].
#[derive(Clone, Debug)]
pub struct PwCaptureOpts {
    /// Pin the capture to one sink's monitor, by node name.
    ///
    /// Production uses this in sink mode to capture the sink **this process
    /// published itself** ([`crate::audiosink`]), whose monitor is
    /// pre-volume: the level is then applied exactly once, at the TV.
    /// `None` follows the default sink's monitor, which is
    /// `--audio-capture pipewire` — sound plays on the laptop as well.
    pub target: Option<String>,
    pub app_name: String,
    /// Never capture anything but `target`: neither a fallback to the default
    /// sink if `target` disappears, nor a move somebody else asks for.
    ///
    /// Set in sink mode: if our own sink is gone the session is over, and
    /// silently capturing the desk speakers instead would send the room to the
    /// TV. It takes TWO WirePlumber keys to mean that — see
    /// [`capture_props`], which is where they live and where they are tested.
    pub dont_fallback: bool,
    /// Node name; tests use a unique one to find the node in `pw-dump`.
    pub node_name: String,
}

impl Default for PwCaptureOpts {
    fn default() -> Self {
        PwCaptureOpts {
            target: None,
            app_name: "airplay-rs".into(),
            dont_fallback: false,
            node_name: "airplay-rs-capture".into(),
        }
    }
}

/// Every property the capture stream is created with.
///
/// Pure, and unit-tested offline, because two groups of keys here are safety
/// claims rather than tuning:
///
/// * **The pin.** [`PwCaptureOpts::dont_fallback`] promises the capture can
///   never end up on anything but `target`. `node.dont-fallback` alone does
///   NOT deliver that: WirePlumber consults it only when the pinned target
///   fails to resolve (`linking/find-defined-target.lua:116`). A *targeted*
///   move — pavucontrol's Recording tab, `pactl move-source-output`, a policy
///   re-link — resolves fine, and is refused only by `node.dont-move`
///   (`find-defined-target.lua:55-69`, `if metadata and not dont_move`). Both
///   keys, or the promise is not kept and the room goes to the TV.
///   `node.dont-reconnect` is deliberately NOT set: the vanished-target path
///   relies on WirePlumber erroring and destroying the node, which the core
///   error listener already tolerates and the reconnect path already handles.
/// * **The remembered level.** `state.restore-props` /
///   `node.stream.restore-props` ask WirePlumber not to restore a remembered
///   `channelVolumes` onto the capture node. Best-effort only, exactly as on
///   the published sink — correctness comes from the write-and-watch in
///   [`pw_thread`], not from these.
pub(crate) fn capture_props(opts: &PwCaptureOpts) -> Vec<(&'static str, String)> {
    use pipewire as pw;
    let mut props = vec![
        (*pw::keys::MEDIA_TYPE, "Audio".to_string()),
        (*pw::keys::MEDIA_CATEGORY, "Capture".to_string()),
        (*pw::keys::NODE_NAME, opts.node_name.clone()),
        (*pw::keys::NODE_DESCRIPTION, "AirPlay audio capture".to_string()),
        (*pw::keys::APP_NAME, opts.app_name.clone()),
        ("stream.capture.sink", "true".to_string()),
        ("node.latency", PW_NODE_LATENCY.to_string()),
        ("state.restore-props", "false".to_string()),
        ("node.stream.restore-props", "false".to_string()),
    ];
    if let Some(t) = &opts.target {
        props.push(("target.object", t.clone()));
    }
    if opts.dont_fallback {
        props.push(("node.dont-fallback", "true".to_string()));
        props.push(("node.dont-move", "true".to_string()));
    }
    props
}

/// Native PipeWire capture of the default sink's monitor.
pub struct PipewireSource {
    reader: RingReader,
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
    done: mpsc::Receiver<()>,
}

impl PipewireSource {
    /// Connect the capture stream. Returns once PipeWire accepted the
    /// connection (not once audio flows). `clock` stamps each buffer in the
    /// RT callback, so it must be real-time safe: [`crate::clock::BoottimeClock`]
    /// is (a vDSO `clock_gettime`); `FakeClock` takes a mutex and is for
    /// non-PipeWire tests only.
    pub fn new(opts: PwCaptureOpts, clock: Arc<dyn SenderClock>) -> Result<Self, CaptureError> {
        let shared = Arc::new(Shared::new().map_err(CaptureError::Spawn)?);
        let cap = AUDIO_RATE as usize * 4 * RING_SECONDS;
        let (writer, reader) = ring_pair(cap, shared.clone());
        let (ready_tx, ready_rx) = mpsc::channel::<Result<u32, String>>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let sh = shared.clone();
        let thread = std::thread::Builder::new()
            .name("airplay-pw-capture".into())
            .spawn(move || {
                pw_thread(opts, sh.clone(), writer, clock, ready_tx);
                sh.set_state(CaptureState::Stopped);
                let _ = done_tx.send(());
            })
            .map_err(CaptureError::Spawn)?;
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let _ = thread.join();
                return Err(CaptureError::Pipewire(e));
            }
            Err(_) => {
                shared.stop();
                return Err(CaptureError::Pipewire(
                    "timed out connecting to PipeWire".into(),
                ));
            }
        }
        Ok(PipewireSource {
            reader,
            shared,
            thread: Some(thread),
            done: done_rx,
        })
    }

    /// The capture node's current id (tests use it to inspect links);
    /// `u32::MAX` if not yet known. A reconnect creates a new node, so this
    /// can change during a session.
    pub fn node_id(&self) -> u32 {
        self.shared.node_id.load(Ordering::Relaxed)
    }

    /// The capture node's OWN `channelVolumes`, as the last `Props` reported
    /// it. `None` until one has been seen — "not observed", never "1.0".
    ///
    /// Anything but 1.0 here is a second attenuation on top of the dB the TV
    /// was told. The loop thread writes it back; this is how a test proves it
    /// did, rather than trusting `state.restore-props` to have been honoured.
    pub fn channel_volume(&self) -> Option<f32> {
        self.shared.channel_volume()
    }

    /// How many times the capture node's level has been written to 1.0
    /// (at least once per connect, by construction).
    pub fn level_writes(&self) -> u64 {
        self.shared.level_writes.load(Ordering::Relaxed)
    }
}

impl PcmSource for PipewireSource {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<PcmBlock>, CaptureError> {
        self.reader.next_frame(timeout)
    }
    fn stopper(&self) -> Box<dyn Fn() + Send + Sync> {
        let sh = self.shared.clone();
        Box::new(move || sh.stop())
    }
    fn stats(&self) -> CaptureStats {
        self.shared.stats()
    }
    fn kind(&self) -> &'static str {
        "pipewire"
    }
}

impl Drop for PipewireSource {
    fn drop(&mut self) {
        self.shared.stop();
        // The loop thread polls the stop flag every POLL_SLICE; give it 2 s,
        // then detach rather than hang the caller.
        if let Some(t) = self.thread.take() {
            if self.done.recv_timeout(Duration::from_secs(2)).is_ok() {
                let _ = t.join();
            } else {
                eprintln!("audiocapture: PipeWire thread did not stop within 2 s; detaching");
            }
        }
    }
}

fn boottime_ns(clock: &dyn SenderClock) -> u64 {
    clock.read().boot().as_nanos() as u64
}

/// The one format this crate offers PipeWire: S16LE, 44100 Hz, stereo.
/// Shared with [`crate::audiosink`], which offers the same format on the sink
/// it publishes — the capture and the sink it taps must not disagree.
pub(crate) fn format_pod() -> Result<Vec<u8>, String> {
    use pipewire::spa;
    let mut info = spa::param::audio::AudioInfoRaw::new();
    info.set_format(spa::param::audio::AudioFormat::S16LE);
    info.set_rate(AUDIO_RATE);
    info.set_channels(2);
    let mut pos = [0u32; libspa_sys::SPA_AUDIO_MAX_CHANNELS as usize];
    pos[0] = libspa_sys::SPA_AUDIO_CHANNEL_FL;
    pos[1] = libspa_sys::SPA_AUDIO_CHANNEL_FR;
    info.set_position(pos);
    let obj = spa::pod::Object {
        type_: spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: spa::param::ParamType::EnumFormat.as_raw(),
        properties: info.into(),
    };
    spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    )
    .map(|(c, _)| c.into_inner())
    .map_err(|e| format!("format pod: {e:?}"))
}

/// Body of the PipeWire loop thread. Reports readiness (node id or error)
/// on `ready`, then iterates the loop in POLL_SLICE steps until stopped,
/// reconnecting RECONNECT_DELAY after any `Error` state.
fn pw_thread(
    opts: PwCaptureOpts,
    shared: Arc<Shared>,
    writer: RingWriter,
    clock: Arc<dyn SenderClock>,
    ready: mpsc::Sender<Result<u32, String>>,
) {
    use pipewire as pw;
    use pw::spa;
    use std::cell::Cell;
    use std::rc::Rc;

    let fail = |ready: &mpsc::Sender<Result<u32, String>>, e: String| {
        let _ = ready.send(Err(e));
    };

    pw::init();
    let mainloop = match pw::main_loop::MainLoopRc::new(None) {
        Ok(m) => m,
        Err(e) => return fail(&ready, format!("main loop: {e}")),
    };
    let context = match pw::context::ContextRc::new(&mainloop, None) {
        Ok(c) => c,
        Err(e) => return fail(&ready, format!("context: {e}")),
    };
    let core = match context.connect_rc(None) {
        Ok(c) => c,
        Err(e) => return fail(&ready, format!("connect to PipeWire: {e}")),
    };
    let sh_core = shared.clone();
    let _core_listener = core
        .add_listener_local()
        .error(move |id, _seq, res, msg| {
            // Only a lost connection (-EPIPE on the core) is fatal. Other core
            // errors are expected around relinks, e.g. WirePlumber destroying
            // our node when a pinned target vanishes ("unknown resource"),
            // and are handled by the stream's own state machine.
            if id == pw::core::PW_ID_CORE && res == -libc::EPIPE {
                sh_core.set_fatal(format!("connection to PipeWire lost: {msg}"));
            } else {
                eprintln!("audiocapture: PipeWire error on {id} ({res}): {msg}");
            }
        })
        .register();

    // One list, built by a pure function so the safety keys are unit-tested
    // without PipeWire. See `capture_props`.
    let mut props = pw::properties::PropertiesBox::new();
    for (k, v) in capture_props(&opts) {
        props.insert(k, v.as_str());
    }

    let stream = match pw::stream::StreamBox::new(&core, "airplay-rs capture", props) {
        Ok(s) => s,
        Err(e) => return fail(&ready, format!("stream: {e}")),
    };

    // Written only on this (loop) thread: the Instant the stream last
    // entered Error, for the delayed reconnect.
    let error_since: Rc<Cell<Option<Instant>>> = Rc::new(Cell::new(None));
    let err_cell = error_since.clone();
    let sh_state = shared.clone();
    let sh_param = shared.clone();
    let mut writer = writer;
    let rt_clock = clock.clone();

    let listener = stream
        .add_local_listener_with_user_data(())
        .state_changed(move |_, _, old, new| {
            use pw::stream::StreamState as S;
            match new {
                S::Streaming => {
                    sh_state.streaming_epoch.fetch_add(1, Ordering::Relaxed);
                    sh_state.set_state(CaptureState::Streaming);
                }
                S::Paused | S::Connecting | S::Unconnected => {
                    if !matches!(old, S::Error(_)) || err_cell.get().is_none() {
                        sh_state.set_state(if matches!(new, S::Paused) {
                            CaptureState::Paused
                        } else {
                            CaptureState::Starting
                        });
                    }
                }
                S::Error(msg) => {
                    eprintln!("audiocapture: stream error: {msg}; reconnecting in {RECONNECT_DELAY:?}");
                    sh_state.set_state(CaptureState::Error);
                    if err_cell.get().is_none() {
                        err_cell.set(Some(Instant::now()));
                    }
                }
            }
        })
        .param_changed(move |_, _, id, param| {
            let Some(p) = param else { return };
            if id == spa::param::ParamType::Props.as_raw() {
                // The capture node's OWN volume. Recorded here; the loop
                // thread is what writes it back to 1.0 (see the level pin
                // below) — `set_control` must not be called from a callback.
                if let Some(v) = crate::audiosink::channel_volume_of(p.as_bytes()) {
                    sh_param.channel_volume.store(v.to_bits(), Ordering::Relaxed);
                    sh_param.props_epoch.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let mut info = spa::param::audio::AudioInfoRaw::new();
            if info.parse(p).is_ok()
                && (info.rate() != AUDIO_RATE
                    || info.channels() != 2
                    || info.format() != spa::param::audio::AudioFormat::S16LE)
            {
                // We only offer S16LE/44100/2; the adapter converts. Anything
                // else would corrupt every frame, so refuse to continue.
                sh_param.set_fatal(format!(
                    "negotiated {:?} {} Hz {} ch, need S16LE 44100 Hz 2 ch",
                    info.format(),
                    info.rate(),
                    info.channels()
                ));
            }
        })
        .process(move |stream, _| {
            // RT thread: no allocation, no locks, no blocking.
            let boot_ns = boottime_ns(&*rt_clock);
            let time = stream.time().ok().map(|t| {
                let r = t.as_raw();
                PwTimeSample {
                    now: r.now,
                    ticks: r.ticks,
                    rate_num: r.rate.num,
                    rate_denom: r.rate.denom,
                }
            });
            let Some(mut buf) = stream.dequeue_buffer() else { return };
            let datas = buf.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let off = d.chunk().offset() as usize;
            let size = d.chunk().size() as usize;
            if let Some(bytes) = d.data() {
                let start = off.min(bytes.len());
                let end = (off + size).min(bytes.len());
                writer.push(&bytes[start..end], boot_ns, time);
            }
        })
        .register();
    let listener = match listener {
        Ok(l) => l,
        Err(e) => return fail(&ready, format!("stream listener: {e}")),
    };

    let pod = match format_pod() {
        Ok(p) => p,
        Err(e) => return fail(&ready, e),
    };
    let connect = |stream: &pw::stream::Stream| -> Result<(), String> {
        let mut params = [spa::pod::Pod::from_bytes(&pod).ok_or("format pod")?];
        stream
            .connect(
                spa::utils::Direction::Input,
                None,
                pw::stream::StreamFlags::AUTOCONNECT
                    | pw::stream::StreamFlags::MAP_BUFFERS
                    | pw::stream::StreamFlags::RT_PROCESS,
                &mut params,
            )
            .map_err(|e| format!("stream connect: {e}"))
    };
    if let Err(e) = connect(&stream) {
        return fail(&ready, e);
    }
    // Let the node get an id so tests can find it (bounded).
    let lp = mainloop.loop_();
    let t0 = Instant::now();
    while stream.node_id() == u32::MAX && t0.elapsed() < Duration::from_secs(2) {
        lp.iterate(pw::loop_::Timeout::Finite(Duration::from_millis(10)));
    }
    shared.node_id.store(stream.node_id(), Ordering::Relaxed);
    let _ = ready.send(Ok(stream.node_id()));

    // THE LEVEL PIN. Our capture node has a channel volume of its own, which
    // WirePlumber remembers per `application.name` and restores after
    // connect, asynchronously — the state file on this machine holds one for
    // `airplay-rs` already. At anything but 1.0 every sample would be
    // attenuated a SECOND time on the way to the TV, under a slider that says
    // otherwise, and nothing else in the sender can see it: the sink's
    // `monitor.channel-volumes` check looks at a different node, and
    // `seed_level` writes the sink, not this.
    //
    // So it is written, not assumed: once now, once past the restore window,
    // and again whenever a `Props` says it drifted. Failures are reported and
    // retried rather than fatal — too soft is a wrong number, not a hazard,
    // and killing the session would be the worse answer.
    let pin_level = |stream: &pw::stream::Stream, when: &str| {
        match stream.set_control(libspa_sys::SPA_PROP_channelVolumes, &[1.0, 1.0]) {
            Ok(()) => {
                shared.level_writes.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => eprintln!("audiocapture: cannot pin the capture level to 1.0 ({when}): {e}"),
        }
    };
    let mut seen_props = 0u64;
    let mut reseed_at = Some(Instant::now() + CAPTURE_LEVEL_RESEED);
    pin_level(&stream, "at connect");

    while !shared.stop.load(Ordering::SeqCst) {
        lp.iterate(pw::loop_::Timeout::Finite(POLL_SLICE));
        shared.node_id.store(stream.node_id(), Ordering::Relaxed);
        // A Props we have not seen yet: check what it says about our own
        // volume, and put it back if it is not unity.
        let epoch = shared.props_epoch.load(Ordering::Relaxed);
        if epoch != seen_props {
            seen_props = epoch;
            if let Some(v) = shared.channel_volume() {
                if (v - 1.0).abs() > LEVEL_EPSILON {
                    eprintln!(
                        "audiocapture: the capture node's own volume reads {v:.3}, which would attenuate \
                         the audio a second time; putting it back to 1.0"
                    );
                    pin_level(&stream, "after a Props");
                }
            }
        }
        if reseed_at.is_some_and(|t| Instant::now() >= t) {
            reseed_at = None;
            pin_level(&stream, "after the restore window");
        }
        if let Some(since) = error_since.get() {
            if since.elapsed() >= RECONNECT_DELAY {
                error_since.set(None);
                let _ = stream.disconnect();
                match connect(&stream) {
                    Ok(()) => {
                        shared.reconnect_epoch.fetch_add(1, Ordering::Relaxed);
                        shared.set_state(CaptureState::Starting);
                        // A reconnect makes a NEW node, so the restore can
                        // land all over again: pin it all over again.
                        pin_level(&stream, "after a reconnect");
                        reseed_at = Some(Instant::now() + CAPTURE_LEVEL_RESEED);
                    }
                    Err(e) => {
                        // Try again after another delay.
                        eprintln!("audiocapture: reconnect failed: {e}");
                        error_since.set(Some(Instant::now()));
                    }
                }
            }
        }
    }
    let _ = stream.disconnect();
    drop(listener);
    drop(stream);
}

// --------------------------------------------------------------------------
// parec fallback
// --------------------------------------------------------------------------

/// The probe's exact parec arguments (probe.py AudioSender._frames).
pub fn parec_args(device: &str) -> Vec<String> {
    vec![
        "-d".into(),
        device.into(),
        "--raw".into(),
        "--format=s16le".into(),
        format!("--rate={AUDIO_RATE}"),
        "--channels=2".into(),
        "--latency-msec=10".into(),
    ]
}

/// The probe's device: whatever the default sink's monitor is at start.
pub const PAREC_DEFAULT_DEVICE: &str = "@DEFAULT_MONITOR@";

/// Capture through a `parec` child process (the probe's proven path).
pub struct ParecSource {
    child: Arc<Mutex<Option<Child>>>,
    stdout: ChildStdout,
    stop: Arc<AtomicBool>,
    clock: Arc<dyn SenderClock>,
    frame: [u8; PCM_FRAME_BYTES],
    fill: usize,
    frame_boot: Option<u64>,
    frame_disc: Option<Discontinuity>,
    last_read_boot: Option<u64>,
    stats: CaptureStats,
    shared_stats: Arc<Mutex<CaptureStats>>,
}

impl ParecSource {
    /// `parec -d <device> --raw --format=s16le --rate=44100 --channels=2
    /// --latency-msec=10`, exactly as the probe ran it.
    pub fn new(device: &str, clock: Arc<dyn SenderClock>) -> Result<Self, CaptureError> {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new("parec");
        cmd.args(parec_args(device));
        // SAFETY: prctl is async-signal-safe. If this process dies without
        // running its destructors (a second Ctrl-C, SIGKILL, a crash), the
        // kernel SIGTERMs parec rather than leaving it capturing.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        Self::spawn_command(cmd, clock)
    }

    /// Run any command whose stdout is raw s16le/44100/2 PCM (tests use this
    /// with stand-ins for parec). stdin and stderr are closed.
    #[doc(hidden)]
    pub fn spawn_command(mut cmd: Command, clock: Arc<dyn SenderClock>) -> Result<Self, CaptureError> {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(CaptureError::Spawn)?;
        let stdout = child.stdout.take().expect("piped stdout");
        // Non-blocking so a read after poll() can never wedge the thread.
        // SAFETY: fcntl on a valid fd we own.
        unsafe {
            let fd = stdout.as_raw_fd();
            let fl = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        Ok(ParecSource {
            child: Arc::new(Mutex::new(Some(child))),
            stdout,
            stop: Arc::new(AtomicBool::new(false)),
            clock,
            frame: [0; PCM_FRAME_BYTES],
            fill: 0,
            frame_boot: None,
            frame_disc: None,
            last_read_boot: None,
            stats: CaptureStats::default(),
            shared_stats: Arc::new(Mutex::new(CaptureStats::default())),
        })
    }

    /// TESTS: the child's pid (to find its PipeWire node), while running.
    #[doc(hidden)]
    pub fn child_pid(&self) -> Option<u32> {
        self.child
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|c| c.id())
    }

    fn publish_stats(&self) {
        *self.shared_stats.lock().unwrap_or_else(|p| p.into_inner()) = self.stats;
    }

    fn kill_child(child: &Mutex<Option<Child>>) {
        if let Some(c) = child.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
            let _ = c.kill();
        }
    }
}

impl PcmSource for ParecSource {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<PcmBlock>, CaptureError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.stop.load(Ordering::SeqCst) {
                self.stats.state = CaptureState::Stopped;
                self.publish_stats();
                return Err(CaptureError::Stopped);
            }
            if self.fill == PCM_FRAME_BYTES {
                self.fill = 0;
                self.stats.frames += 1;
                self.publish_stats();
                return Ok(Some(PcmBlock {
                    pcm: self.frame,
                    boot_ns: self.frame_boot.take(),
                    mono_ns: None,
                    discontinuity: self.frame_disc.take(),
                }));
            }
            match self.stdout.read(&mut self.frame[self.fill..]) {
                Ok(0) => {
                    self.stats.state = CaptureState::Stopped;
                    self.publish_stats();
                    return Err(if self.stop.load(Ordering::SeqCst) {
                        CaptureError::Stopped
                    } else {
                        CaptureError::Ended
                    });
                }
                Ok(n) => {
                    let now = boottime_ns(&*self.clock);
                    if let Some(prev) = self.last_read_boot {
                        let gap = now.saturating_sub(prev);
                        if gap > PAREC_READ_GAP.as_nanos() as u64 && self.frame_disc.is_none() {
                            self.frame_disc = Some(Discontinuity::CallbackGap {
                                gap: Duration::from_nanos(gap),
                            });
                            self.stats.discontinuities += 1;
                        }
                    }
                    self.last_read_boot = Some(now);
                    if self.fill == 0 {
                        self.frame_boot = Some(now);
                    }
                    self.fill += n;
                    self.stats.buffers += 1;
                    self.stats.bytes += n as u64;
                    self.stats.state = CaptureState::Streaming;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    if now >= deadline {
                        self.publish_stats();
                        return Ok(None);
                    }
                    poll_readable(self.stdout.as_raw_fd(), (deadline - now).min(POLL_SLICE));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(CaptureError::Io(e)),
            }
        }
    }

    fn stopper(&self) -> Box<dyn Fn() + Send + Sync> {
        let child = self.child.clone();
        let stop = self.stop.clone();
        Box::new(move || {
            stop.store(true, Ordering::SeqCst);
            ParecSource::kill_child(&child);
        })
    }

    fn stats(&self) -> CaptureStats {
        let mut s = *self.shared_stats.lock().unwrap_or_else(|p| p.into_inner());
        if self.stop.load(Ordering::SeqCst) {
            s.state = CaptureState::Stopped;
        }
        s
    }

    fn kind(&self) -> &'static str {
        "parec"
    }
}

impl Drop for ParecSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(mut c) = self.child.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// --------------------------------------------------------------------------
// Tone
// --------------------------------------------------------------------------

/// The probe's tone level.
pub const TONE_LEVEL: f64 = 0.3;

#[derive(Debug, Default)]
struct StopSignal {
    stopped: Mutex<bool>,
    cv: Condvar,
}

impl StopSignal {
    fn stop(&self) {
        *self.stopped.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.cv.notify_all();
    }
    fn is_stopped(&self) -> bool {
        *self.stopped.lock().unwrap_or_else(|p| p.into_inner())
    }
    /// Sleep up to `d` (real time), returning early if stopped.
    fn sleep(&self, d: Duration) {
        let g = self.stopped.lock().unwrap_or_else(|p| p.into_inner());
        if !*g {
            let _ = self.cv.wait_timeout(g, d);
        }
    }
}

/// The probe's 880 Hz beep ([`crate::audio::tone_frame`]), self-paced: frame
/// `k` is released once the sender clock reaches `start + k·352/44100`, where
/// `start` is the clock at the first `next_frame` call.
///
/// A small lag (up to [`crate::audio::REANCHOR_GAP`]) is caught up in a
/// burst, as the probe did. A larger one (a suspend — BOOTTIME counts it — or
/// a long sender stall) is NOT: the missed frames are skipped and the time
/// base is rebased to "now", so exactly one frame is released at once and the
/// rest are paced again. Without this a 1 h suspend would release ~451k
/// frames back to back. (A burst cannot be relied on to re-anchor the
/// receiver: the timeline stamps frames on arrival, so burst frames look
/// early, not late, and no late rule fires; the gap before the first
/// post-stall frame is what re-anchors.) The frame index is not advanced by
/// a skip, so the tone carries on in phase from the last frame sent.
pub struct ToneSource {
    clock: Arc<dyn SenderClock>,
    level: f64,
    k: u64,
    /// BOOTTIME (ns) at which frame `start_k` is due; set on the first call
    /// and on every rebase.
    start: Option<u64>,
    start_k: u64,
    rebases: u64,
    stop: Arc<StopSignal>,
    frames: u64,
}

impl ToneSource {
    pub fn new(clock: Arc<dyn SenderClock>, level: f64) -> Self {
        ToneSource {
            clock,
            level,
            k: 0,
            start: None,
            start_k: 0,
            rebases: 0,
            stop: Arc::new(StopSignal::default()),
            frames: 0,
        }
    }

    fn due_ns(&self, start_ns: u64) -> u64 {
        start_ns + (self.k - self.start_k) * ALAC_SPF as u64 * 1_000_000_000 / AUDIO_RATE as u64
    }

    /// How many times a lag larger than [`crate::audio::REANCHOR_GAP`] made
    /// the source skip missed frames instead of bursting them.
    pub fn rebases(&self) -> u64 {
        self.rebases
    }
}

impl PcmSource for ToneSource {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<PcmBlock>, CaptureError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.stop.is_stopped() {
                return Err(CaptureError::Stopped);
            }
            let now_ns = self.clock.read().boot().as_nanos() as u64;
            let start = *self.start.get_or_insert(now_ns);
            let mut due = self.due_ns(start);
            if now_ns.saturating_sub(due) > crate::audio::REANCHOR_GAP.as_nanos() as u64 {
                // Too far behind to catch up: skip the missed frames and
                // restart the time base at this frame.
                self.start = Some(now_ns);
                self.start_k = self.k;
                self.rebases += 1;
                due = now_ns;
            }
            if now_ns >= due {
                let pcm = crate::audio::tone_frame(self.k * ALAC_SPF as u64, self.level);
                self.k += 1;
                self.frames += 1;
                return Ok(Some(PcmBlock {
                    pcm,
                    boot_ns: Some(due),
                    mono_ns: None,
                    discontinuity: None,
                }));
            }
            let real_now = Instant::now();
            if real_now >= deadline {
                return Ok(None);
            }
            let wait = Duration::from_nanos(due - now_ns)
                .min(deadline - real_now)
                .min(POLL_SLICE);
            self.stop.sleep(wait);
            if Instant::now() >= deadline && (self.clock.read().boot().as_nanos() as u64) < due {
                return Ok(None);
            }
        }
    }

    fn stopper(&self) -> Box<dyn Fn() + Send + Sync> {
        let s = self.stop.clone();
        Box::new(move || s.stop())
    }

    fn stats(&self) -> CaptureStats {
        CaptureStats {
            frames: self.frames,
            buffers: self.frames,
            bytes: self.frames * PCM_FRAME_BYTES as u64,
            state: if self.stop.is_stopped() {
                CaptureState::Stopped
            } else {
                CaptureState::Streaming
            },
            ..Default::default()
        }
    }

    fn kind(&self) -> &'static str {
        "tone"
    }
}

// --------------------------------------------------------------------------
// Scripted fake (tests of the layers above)
// --------------------------------------------------------------------------

/// TEST FAKE. Releases scripted frames after real-time delays, then either
/// ends or (with `stall_forever`) never yields again — the stuck-source case.
#[doc(hidden)]
pub struct ScriptedSource {
    frames: std::collections::VecDeque<(Duration, [u8; PCM_FRAME_BYTES])>,
    next_at: Option<Instant>,
    stall_forever: bool,
    stop: Arc<StopSignal>,
    delivered: u64,
}

#[doc(hidden)]
impl ScriptedSource {
    /// `frames[i].0` is the real-time delay before frame `i` is released,
    /// measured from the previous release (or the first `next_frame` call).
    pub fn new(frames: Vec<(Duration, [u8; PCM_FRAME_BYTES])>, stall_forever: bool) -> Self {
        ScriptedSource {
            frames: frames.into(),
            next_at: None,
            stall_forever,
            stop: Arc::new(StopSignal::default()),
            delivered: 0,
        }
    }
}

impl PcmSource for ScriptedSource {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<PcmBlock>, CaptureError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.stop.is_stopped() {
                return Err(CaptureError::Stopped);
            }
            let now = Instant::now();
            let Some((delay, _)) = self.frames.front() else {
                if !self.stall_forever {
                    return Err(CaptureError::Ended);
                }
                if now >= deadline {
                    return Ok(None);
                }
                self.stop.sleep((deadline - now).min(POLL_SLICE));
                continue;
            };
            let at = *self.next_at.get_or_insert(now + *delay);
            if now >= at {
                let (_, pcm) = self.frames.pop_front().expect("front");
                self.next_at = self.frames.front().map(|(d, _)| now + *d);
                self.delivered += 1;
                return Ok(Some(PcmBlock {
                    pcm,
                    boot_ns: None,
                    mono_ns: None,
                    discontinuity: None,
                }));
            }
            if now >= deadline {
                return Ok(None);
            }
            self.stop.sleep((at - now).min(deadline - now).min(POLL_SLICE));
        }
    }

    fn stopper(&self) -> Box<dyn Fn() + Send + Sync> {
        let s = self.stop.clone();
        Box::new(move || s.stop())
    }

    fn stats(&self) -> CaptureStats {
        CaptureStats {
            frames: self.delivered,
            ..Default::default()
        }
    }

    fn kind(&self) -> &'static str {
        "scripted"
    }
}

// --------------------------------------------------------------------------
// Read-only helpers for status
// --------------------------------------------------------------------------

/// The current default sink's node name (`pactl get-default-sink`, read-only).
pub fn default_sink_name() -> Option<String> {
    let out = Command::new("pactl")
        .arg("get-default-sink")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

/// Whether `sink`'s monitor carries the sink's channel volumes (post-volume),
/// from a read-only `pw-dump`. `None` if the sink is not found.
///
/// PipeWire's node property `monitor.channel-volumes` (default false) decides
/// it; an absent property is reported as `Some(false)` from that documented
/// default. Whether that also holds for the ALSA speaker sink's hardware
/// volume is NOT proven (it would need sound in the room). Status only;
/// nothing acts on this automatically.
pub fn sink_monitor_is_post_volume(sink: &str) -> Option<bool> {
    let out = Command::new("pw-dump")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    monitor_post_volume_from_dump(&String::from_utf8_lossy(&out.stdout), sink)
}

/// Pure half of [`sink_monitor_is_post_volume`].
pub fn monitor_post_volume_from_dump(dump_json: &str, sink: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(dump_json).ok()?;
    for o in v.as_array()? {
        if !o["type"].as_str().is_some_and(|t| t.ends_with(":Node")) {
            continue;
        }
        let props = &o["info"]["props"];
        if props["node.name"].as_str() != Some(sink) {
            continue;
        }
        if !props["media.class"]
            .as_str()
            .is_some_and(|c| c.starts_with("Audio/Sink"))
        {
            continue;
        }
        return Some(match &props["monitor.channel-volumes"] {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::String(s) => s == "true" || s == "1",
            _ => false,
        });
    }
    None
}

/// Whether the CURRENT default sink's monitor is post-volume: the default
/// sink is re-read each call (`--audio system` captures the default sink's
/// monitor, which follows a default-sink switch). Read-only.
pub fn default_sink_monitor_is_post_volume() -> Option<bool> {
    default_sink_name().and_then(|s| sink_monitor_is_post_volume(&s))
}

/// Keeps the `monitor.channel-volumes` status flag current across a
/// default-sink switch, without running `pw-dump` twice a second: the
/// default sink name is re-read at most every `every`, and the flag is looked
/// up again when the name changed (or on the first call). A look-up that
/// finds nothing reports `None` rather than keeping the old sink's value.
/// Status only; nothing acts on it.
pub struct PostVolumeTracker {
    every: Duration,
    checked: Option<Instant>,
    sink: Option<String>,
    value: Option<bool>,
}

impl PostVolumeTracker {
    pub fn new(every: Duration) -> Self {
        PostVolumeTracker { every, checked: None, sink: None, value: None }
    }

    /// The flag for the current default sink, refreshed if due.
    pub fn get(&mut self) -> Option<bool> {
        self.get_with(Instant::now(), default_sink_name, sink_monitor_is_post_volume)
    }

    /// Pure core of [`Self::get`] (tests inject the look-ups and the time).
    pub fn get_with(
        &mut self,
        now: Instant,
        sink_name: impl FnOnce() -> Option<String>,
        lookup: impl FnOnce(&str) -> Option<bool>,
    ) -> Option<bool> {
        if self.checked.is_some_and(|t| now.saturating_duration_since(t) < self.every) {
            return self.value;
        }
        self.checked = Some(now);
        let sink = sink_name();
        if sink != self.sink || self.value.is_none() {
            self.value = sink.as_deref().and_then(lookup);
            self.sink = sink;
        }
        self.value
    }
}

// --------------------------------------------------------------------------
// Tests (offline: no PipeWire, no receiver, no sound)
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;

    fn prn(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn pair(cap: usize) -> (RingWriter, RingReader, Arc<Shared>) {
        let sh = Arc::new(Shared::new().unwrap());
        let (w, r) = ring_pair(cap, sh.clone());
        (w, r, sh)
    }

    fn t(now: i64, ticks: u64) -> Option<PwTimeSample> {
        Some(PwTimeSample {
            now,
            ticks,
            rate_num: 1,
            rate_denom: 48000,
        })
    }

    /// Drive the writer the way the RT callback does: buffers of `sizes`
    /// bytes, delivered every `period_ns` with a consistent graph clock.
    fn feed(w: &mut RingWriter, data: &[u8], sizes: &[usize], t0: u64, period_ns: u64) {
        let mut pos = 0;
        let mut i = 0u64;
        while pos < data.len() {
            let n = sizes[i as usize % sizes.len()].min(data.len() - pos);
            let now = t0 + i * period_ns;
            w.push(&data[pos..pos + n], now, t(now as i64, now * 48 / 1_000_000));
            pos += n;
            i += 1;
        }
    }

    #[test]
    fn frames_are_cut_exactly_across_odd_buffer_sizes() {
        let (mut w, mut r, _sh) = pair(1 << 20);
        let data = prn(PCM_FRAME_BYTES * 50, 1);
        // Buffer sizes that never line up with a 1408-byte frame.
        feed(&mut w, &data, &[940, 1764, 4, 3000, 1024], 1_000_000_000, 5_000_000);
        let mut out = Vec::new();
        while let Some(f) = r.try_frame() {
            assert!(f.discontinuity.is_none(), "steady feed has no discontinuity");
            out.extend_from_slice(&f.pcm);
        }
        assert_eq!(out, data);
        assert_eq!(r.shared.stats().frames, 50);
    }

    #[test]
    fn partial_samples_are_dropped_not_misaligned() {
        let (mut w, mut r, _sh) = pair(1 << 16);
        let data = prn(PCM_FRAME_BYTES + 3, 2);
        w.push(&data, 1, None);
        let f = r.try_frame().expect("one frame");
        assert_eq!(&f.pcm[..], &data[..PCM_FRAME_BYTES]);
        assert!(r.try_frame().is_none());
    }

    #[test]
    fn stamps_follow_buffer_time_plus_offset() {
        let (mut w, mut r, _sh) = pair(1 << 16);
        // One 2816-byte (704-sample) buffer delivered at 10 s: frame 0 starts
        // at the buffer, frame 1 is 352 samples (7.98 ms) later.
        w.push(&prn(2816, 3), 10_000_000_000, t(9_000_000_000, 0));
        let f0 = r.try_frame().unwrap();
        let f1 = r.try_frame().unwrap();
        assert_eq!(f0.boot_ns, Some(10_000_000_000));
        assert_eq!(f1.boot_ns, Some(10_000_000_000 + FRAME_NS));
        assert_eq!(f0.mono_ns, Some(9_000_000_000));
        assert_eq!(f1.mono_ns, Some(9_000_000_000 + FRAME_NS));
    }

    #[test]
    fn relink_marks_first_frame_after_it() {
        let (mut w, mut r, sh) = pair(1 << 20);
        sh.streaming_epoch.store(1, Ordering::Relaxed); // initial Streaming
        feed(&mut w, &prn(PCM_FRAME_BYTES * 2, 4), &[1408], 1_000_000_000, FRAME_NS);
        // Default sink changed: WirePlumber relinked us (Paused -> Streaming).
        sh.streaming_epoch.store(2, Ordering::Relaxed);
        let t1 = 1_000_000_000 + 2 * FRAME_NS;
        w.push(&prn(PCM_FRAME_BYTES, 5), t1, t(t1 as i64, t1 * 48 / 1_000_000));
        let a = r.try_frame().unwrap();
        let b = r.try_frame().unwrap();
        let c = r.try_frame().unwrap();
        assert_eq!(a.discontinuity, None);
        assert_eq!(b.discontinuity, None);
        assert_eq!(c.discontinuity, Some(Discontinuity::Relinked));
        let s = sh.stats();
        assert_eq!((s.relinks, s.discontinuities), (1, 1));
    }

    #[test]
    fn first_streaming_is_not_a_discontinuity() {
        let (mut w, mut r, sh) = pair(1 << 16);
        sh.streaming_epoch.store(1, Ordering::Relaxed);
        w.push(&prn(PCM_FRAME_BYTES, 6), 5, None);
        assert_eq!(r.try_frame().unwrap().discontinuity, None);
        assert_eq!(sh.stats().discontinuities, 0);
    }

    #[test]
    fn callback_gap_is_flagged_with_its_length() {
        let (mut w, mut r, _sh) = pair(1 << 20);
        w.push(&prn(PCM_FRAME_BYTES, 7), 1_000_000_000, None);
        // 400 ms of nothing (a suspended/relinking sink), then data again.
        w.push(&prn(PCM_FRAME_BYTES, 8), 1_400_000_000, None);
        assert_eq!(r.try_frame().unwrap().discontinuity, None);
        assert_eq!(
            r.try_frame().unwrap().discontinuity,
            Some(Discontinuity::CallbackGap {
                gap: Duration::from_millis(400)
            })
        );
    }

    #[test]
    fn normal_jitter_is_not_a_gap() {
        let (mut w, mut r, sh) = pair(1 << 20);
        let mut now = 1_000_000_000u64;
        for i in 0..100u64 {
            // Up to 2x the nominal period: jitter, not a break.
            now += FRAME_NS + (i % 2) * FRAME_NS;
            w.push(&prn(PCM_FRAME_BYTES, i), now, None);
        }
        while let Some(f) = r.try_frame() {
            assert_eq!(f.discontinuity, None);
        }
        assert_eq!(sh.stats().discontinuities, 0);
    }

    #[test]
    fn graph_clock_change_is_a_clock_jump() {
        let (mut w, mut r, _sh) = pair(1 << 20);
        w.push(&prn(PCM_FRAME_BYTES, 9), 1_000_000_000, t(1_000_000_000, 48_000));
        // New driver: ticks restart from a different base.
        w.push(
            &prn(PCM_FRAME_BYTES, 10),
            1_000_000_000 + FRAME_NS,
            t(1_000_000_000 + FRAME_NS as i64, 17),
        );
        r.try_frame().unwrap();
        assert_eq!(r.try_frame().unwrap().discontinuity, Some(Discontinuity::ClockJump));
        // Rate change is also a jump.
        let (mut w, mut r, _sh) = pair(1 << 20);
        w.push(&prn(PCM_FRAME_BYTES, 9), 1_000_000_000, t(1_000_000_000, 48_000));
        let mut t2 = t(1_000_000_000 + FRAME_NS as i64, 48_000 + 383).unwrap();
        t2.rate_denom = 44100;
        w.push(&prn(PCM_FRAME_BYTES, 10), 1_000_000_000 + FRAME_NS, Some(t2));
        r.try_frame().unwrap();
        assert_eq!(r.try_frame().unwrap().discontinuity, Some(Discontinuity::ClockJump));
    }

    #[test]
    fn overrun_drops_whole_buffers_and_flags_the_next_frame() {
        // Ring of exactly 2 frames.
        let (mut w, mut r, sh) = pair(PCM_FRAME_BYTES * 2);
        let a = prn(PCM_FRAME_BYTES, 11);
        let b = prn(PCM_FRAME_BYTES, 12);
        let c = prn(PCM_FRAME_BYTES, 13);
        let d = prn(PCM_FRAME_BYTES, 14);
        w.push(&a, 1, None);
        w.push(&b, 2, None);
        w.push(&c, 3, None); // no room: dropped whole
        assert_eq!(r.try_frame().unwrap().pcm[..], a[..]);
        assert_eq!(r.try_frame().unwrap().pcm[..], b[..]);
        w.push(&d, 4, None);
        let f = r.try_frame().unwrap();
        assert_eq!(f.pcm[..], d[..], "stream stays aligned after the drop");
        assert_eq!(
            f.discontinuity,
            Some(Discontinuity::Overrun {
                dropped_bytes: PCM_FRAME_BYTES as u64
            })
        );
        let s = sh.stats();
        assert_eq!((s.overruns, s.dropped_bytes), (1, PCM_FRAME_BYTES as u64));
    }

    #[test]
    fn discontinuity_inside_a_frame_marks_that_frame() {
        let (mut w, mut r, sh) = pair(1 << 16);
        sh.streaming_epoch.store(1, Ordering::Relaxed);
        w.push(&prn(700, 15), 1, None);
        sh.streaming_epoch.store(2, Ordering::Relaxed);
        w.push(&prn(708, 16), 2, None);
        assert_eq!(r.try_frame().unwrap().discontinuity, Some(Discontinuity::Relinked));
    }

    #[test]
    fn reconnect_outranks_relink() {
        let (mut w, mut r, sh) = pair(1 << 16);
        sh.streaming_epoch.store(1, Ordering::Relaxed);
        w.push(&prn(PCM_FRAME_BYTES, 17), 1, None);
        sh.reconnect_epoch.store(1, Ordering::Relaxed);
        sh.streaming_epoch.store(2, Ordering::Relaxed);
        w.push(&prn(PCM_FRAME_BYTES, 18), 2, None);
        r.try_frame().unwrap();
        assert_eq!(r.try_frame().unwrap().discontinuity, Some(Discontinuity::Reconnected));
    }

    #[test]
    fn next_frame_times_out_and_never_blocks_forever() {
        let (_w, mut r, _sh) = pair(1 << 16);
        let t0 = Instant::now();
        assert!(matches!(r.next_frame(Duration::from_millis(120)), Ok(None)));
        let el = t0.elapsed();
        assert!(el >= Duration::from_millis(115) && el < Duration::from_millis(600), "{el:?}");
    }

    #[test]
    fn producer_on_another_thread_wakes_the_consumer() {
        let (mut w, mut r, _sh) = pair(1 << 20);
        let data = prn(PCM_FRAME_BYTES * 20, 19);
        let d2 = data.clone();
        let h = std::thread::spawn(move || {
            for c in d2.chunks(940) {
                std::thread::sleep(Duration::from_millis(2));
                w.push(c, 1, None);
            }
        });
        let mut out = Vec::new();
        while out.len() < data.len() {
            match r.next_frame(Duration::from_secs(2)) {
                Ok(Some(f)) => out.extend_from_slice(&f.pcm),
                other => panic!("unexpected {other:?}"),
            }
        }
        h.join().unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn stop_unblocks_a_waiting_consumer() {
        let (_w, mut r, sh) = pair(1 << 16);
        let sh2 = sh.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sh2.stop();
        });
        let t0 = Instant::now();
        let res = r.next_frame(Duration::from_secs(10));
        assert!(matches!(res, Err(CaptureError::Stopped)), "{res:?}");
        assert!(t0.elapsed() < Duration::from_secs(1));
        h.join().unwrap();
        assert_eq!(sh.stats().state, CaptureState::Stopped);
    }

    #[test]
    fn fatal_error_is_reported_to_the_consumer() {
        let (_w, mut r, sh) = pair(1 << 16);
        sh.set_fatal("negotiated F32LE".into());
        assert!(matches!(r.next_frame(Duration::from_secs(1)), Err(CaptureError::Pipewire(m)) if m.contains("F32LE")));
    }

    #[test]
    fn tone_source_is_paced_by_the_sender_clock() {
        let clock = Arc::new(FakeClock::new(100.0));
        let mut s = ToneSource::new(clock.clone(), TONE_LEVEL);
        let f0 = s.next_frame(Duration::from_millis(10)).unwrap().unwrap();
        assert_eq!(f0.pcm, crate::audio::tone_frame(0, TONE_LEVEL));
        // Frame 1 is due 352/44100 s later; the fake clock has not moved.
        assert!(s.next_frame(Duration::from_millis(20)).unwrap().is_none());
        clock.advance(0.008);
        let f1 = s.next_frame(Duration::from_millis(10)).unwrap().unwrap();
        assert_eq!(f1.pcm, crate::audio::tone_frame(352, TONE_LEVEL));
        assert_eq!(f1.boot_ns.unwrap() - f0.boot_ns.unwrap(), FRAME_NS);
        // Behind by 3 frames: they come out back to back (probe behaviour).
        clock.advance(3.0 * 352.0 / 44100.0);
        for k in 2..5u64 {
            let f = s.next_frame(Duration::from_millis(1)).unwrap().unwrap();
            assert_eq!(f.pcm, crate::audio::tone_frame(k * 352, TONE_LEVEL));
        }
        s.stopper()();
        assert!(matches!(s.next_frame(Duration::from_secs(5)), Err(CaptureError::Stopped)));
    }

    #[test]
    fn tone_source_skips_rather_than_bursts_after_a_suspend() {
        let clock = Arc::new(FakeClock::new(100.0));
        let mut s = ToneSource::new(clock.clone(), TONE_LEVEL);
        let f0 = s.next_frame(Duration::from_millis(1)).unwrap().unwrap();
        assert_eq!(f0.pcm, crate::audio::tone_frame(0, TONE_LEVEL));
        // A 1 h suspend (BOOTTIME counts it): exactly one frame, then wait.
        clock.advance(3600.0);
        let f1 = s.next_frame(Duration::from_millis(1)).unwrap().unwrap();
        // The tone carries on in phase from the last frame sent.
        assert_eq!(f1.pcm, crate::audio::tone_frame(352, TONE_LEVEL));
        assert_eq!(f1.boot_ns.unwrap(), 3_700_000_000_000);
        assert_eq!(s.rebases(), 1);
        assert!(s.next_frame(Duration::from_millis(5)).unwrap().is_none());
        // Paced from the new base: the next frame is one frame period on.
        clock.advance(0.008);
        let f2 = s.next_frame(Duration::from_millis(1)).unwrap().unwrap();
        assert_eq!(f2.pcm, crate::audio::tone_frame(704, TONE_LEVEL));
        assert_eq!(f2.boot_ns.unwrap() - f1.boot_ns.unwrap(), FRAME_NS);
        assert!(s.next_frame(Duration::from_millis(5)).unwrap().is_none());
        // A 2 s stall: also one frame, not ~251.
        clock.advance(2.0);
        s.next_frame(Duration::from_millis(1)).unwrap().unwrap();
        assert!(s.next_frame(Duration::from_millis(5)).unwrap().is_none());
        assert_eq!(s.rebases(), 2);
        // A lag within REANCHOR_GAP (200 ms = 25 frames) is still caught up.
        clock.advance(0.2);
        let mut n = 0;
        while s.next_frame(Duration::from_millis(1)).unwrap().is_some() {
            n += 1;
        }
        assert_eq!(n, 25);
        assert_eq!(s.rebases(), 2);
    }

    #[test]
    fn post_volume_tracker_follows_a_default_sink_switch() {
        let t0 = Instant::now();
        let mut tr = PostVolumeTracker::new(Duration::from_secs(2));
        let look = |s: &str| match s {
            "a" => Some(true),
            "b" => Some(false),
            _ => None,
        };
        assert_eq!(tr.get_with(t0, || Some("a".into()), look), Some(true));
        // Within the interval: cached, the look-ups are not called.
        assert_eq!(
            tr.get_with(t0 + Duration::from_secs(1), || panic!("re-read"), |_: &str| panic!("re-read")),
            Some(true)
        );
        // Same sink after the interval: no second pw-dump.
        assert_eq!(
            tr.get_with(t0 + Duration::from_secs(3), || Some("a".into()), |_: &str| panic!("re-dumped")),
            Some(true)
        );
        // The switch: the new sink's flag, not the stale one.
        assert_eq!(tr.get_with(t0 + Duration::from_secs(6), || Some("b".into()), look), Some(false));
        // Unknown sink / no default: None, never the old value.
        assert_eq!(tr.get_with(t0 + Duration::from_secs(9), || Some("zz".into()), look), None);
        assert_eq!(tr.get_with(t0 + Duration::from_secs(12), || None, look), None);
    }

    #[test]
    fn tone_source_real_clock_rate() {
        let mut s = ToneSource::new(Arc::new(crate::clock::BoottimeClock), TONE_LEVEL);
        let t0 = Instant::now();
        for _ in 0..25 {
            s.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        }
        // 24 intervals of 7.98 ms = 191.6 ms.
        let el = t0.elapsed();
        assert!(el >= Duration::from_millis(185) && el < Duration::from_millis(400), "{el:?}");
    }

    #[test]
    fn parec_args_are_the_probes() {
        assert_eq!(
            parec_args(PAREC_DEFAULT_DEVICE).join(" "),
            "-d @DEFAULT_MONITOR@ --raw --format=s16le --rate=44100 --channels=2 --latency-msec=10"
        );
    }

    #[test]
    fn parec_like_child_frames_then_end() {
        // A stand-in child writing exactly 2.5 frames of known bytes.
        let data = prn(PCM_FRAME_BYTES * 5 / 2, 20);
        let path = std::env::temp_dir().join(format!("airplay_capture_{}.raw", std::process::id()));
        std::fs::write(&path, &data).unwrap();
        let mut cmd = Command::new("cat");
        cmd.arg(&path);
        let mut s = ParecSource::spawn_command(cmd, Arc::new(crate::clock::BoottimeClock)).unwrap();
        let a = s.next_frame(Duration::from_secs(2)).unwrap().unwrap();
        let b = s.next_frame(Duration::from_secs(2)).unwrap().unwrap();
        assert_eq!(&a.pcm[..], &data[..PCM_FRAME_BYTES]);
        assert_eq!(&b.pcm[..], &data[PCM_FRAME_BYTES..2 * PCM_FRAME_BYTES]);
        assert!(a.boot_ns.is_some());
        assert!(matches!(s.next_frame(Duration::from_secs(2)), Err(CaptureError::Ended)));
        assert_eq!(s.stats().frames, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parec_like_stuck_child_times_out_then_stopper_kills_it() {
        let mut cmd = Command::new("sleep");
        cmd.arg("100");
        let mut s = ParecSource::spawn_command(cmd, Arc::new(crate::clock::BoottimeClock)).unwrap();
        let pid = s.child.lock().unwrap().as_ref().unwrap().id();
        let t0 = Instant::now();
        assert!(matches!(s.next_frame(Duration::from_millis(100)), Ok(None)));
        assert!(t0.elapsed() < Duration::from_millis(500));
        let stop = s.stopper();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            stop();
        });
        let t1 = Instant::now();
        assert!(matches!(s.next_frame(Duration::from_secs(10)), Err(CaptureError::Stopped)));
        assert!(t1.elapsed() < Duration::from_secs(1));
        h.join().unwrap();
        drop(s);
        // Killed AND reaped by Drop. A zombie's cmdline is empty, so check
        // /proc/<pid>/stat: state Z at the deadline means Drop killed without
        // wait() (only this process could reap it, so it would never go away).
        let end = Instant::now() + Duration::from_secs(2);
        // Err: gone, reaped.
        while let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if !stat.contains("(sleep)") {
                break; // pid reused by something else: ours was reaped
            }
            assert!(
                Instant::now() < end,
                "child {pid} not reaped (still {}): {stat}",
                if stat.contains(") Z ") { "a zombie — Drop killed without wait()" } else { "running" }
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn scripted_source_stall_forever_is_stoppable() {
        let mut s = ScriptedSource::new(vec![(Duration::ZERO, [7u8; PCM_FRAME_BYTES])], true);
        assert_eq!(s.next_frame(Duration::from_millis(10)).unwrap().unwrap().pcm[0], 7);
        assert!(s.next_frame(Duration::from_millis(60)).unwrap().is_none());
        let stop = s.stopper();
        stop();
        assert!(matches!(s.next_frame(Duration::from_secs(5)), Err(CaptureError::Stopped)));
    }

    #[test]
    fn monitor_post_volume_parses_pw_dump() {
        let dump = r#"[
          {"id":1,"type":"PipeWire:Interface:Node","info":{"props":{"node.name":"a","media.class":"Audio/Sink","monitor.channel-volumes":true}}},
          {"id":2,"type":"PipeWire:Interface:Node","info":{"props":{"node.name":"b","media.class":"Audio/Sink","monitor.channel-volumes":"false"}}},
          {"id":3,"type":"PipeWire:Interface:Node","info":{"props":{"node.name":"c","media.class":"Audio/Sink"}}},
          {"id":4,"type":"PipeWire:Interface:Node","info":{"props":{"node.name":"d","media.class":"Stream/Output/Audio"}}},
          {"id":5,"type":"PipeWire:Interface:Link","info":{"props":{}}}
        ]"#;
        assert_eq!(monitor_post_volume_from_dump(dump, "a"), Some(true));
        assert_eq!(monitor_post_volume_from_dump(dump, "b"), Some(false));
        assert_eq!(monitor_post_volume_from_dump(dump, "c"), Some(false));
        assert_eq!(monitor_post_volume_from_dump(dump, "d"), None);
        assert_eq!(monitor_post_volume_from_dump(dump, "zz"), None);
        assert_eq!(monitor_post_volume_from_dump("not json", "a"), None);
    }
}

// --------------------------------------------------------------------------
// Tests for the capture's properties (pure: no PipeWire, no sound)
// --------------------------------------------------------------------------

#[cfg(test)]
mod prop_tests {
    use super::*;

    fn props_of(opts: &PwCaptureOpts) -> std::collections::HashMap<&'static str, String> {
        capture_props(opts).into_iter().collect()
    }

    fn sink_mode_opts() -> PwCaptureOpts {
        PwCaptureOpts { target: Some("airplay-sink.frame".into()), dont_fallback: true, ..Default::default() }
    }

    /// The pin is a SAFETY claim — "if our own sink is gone the session is
    /// over, and silently capturing the desk speakers instead would send the
    /// room to the TV". WirePlumber needs BOTH keys to keep it:
    /// `node.dont-fallback` is consulted only when the pinned target fails to
    /// resolve, so a targeted move (pavucontrol's Recording tab,
    /// `pactl move-source-output`, a policy re-link) walks straight past it.
    /// Only `node.dont-move` refuses that. Deleting either line fails here.
    #[test]
    fn a_pinned_capture_refuses_both_a_fallback_and_a_move() {
        let p = props_of(&sink_mode_opts());
        assert_eq!(p.get("target.object").map(String::as_str), Some("airplay-sink.frame"));
        assert_eq!(
            p.get("node.dont-fallback").map(String::as_str),
            Some("true"),
            "the capture could fall back to the default sink — the desk speakers — and send the room to the TV"
        );
        assert_eq!(
            p.get("node.dont-move").map(String::as_str),
            Some("true"),
            "dont-fallback alone does not stop a TARGETED move; the capture could be pointed at the desk speakers mid-session"
        );
        // Deliberately absent: the vanished-target path relies on
        // WirePlumber erroring and destroying the node, which the core error
        // listener tolerates and the reconnect path handles.
        assert_eq!(p.get("node.dont-reconnect"), None);
    }

    /// The unpinned (`--audio-capture pipewire`) capture follows the default
    /// sink's monitor on purpose, so neither key may be set there.
    #[test]
    fn an_unpinned_capture_is_not_pinned() {
        let p = props_of(&PwCaptureOpts::default());
        assert_eq!(p.get("target.object"), None);
        assert_eq!(p.get("node.dont-fallback"), None);
        assert_eq!(p.get("node.dont-move"), None);
    }

    /// Ask WirePlumber not to restore a remembered `channelVolumes` onto the
    /// capture node. Best-effort — the level pin in the loop thread is what
    /// makes it true — but it is the cheap half and must not go missing.
    #[test]
    fn the_capture_asks_not_to_have_a_remembered_volume_restored() {
        for opts in [PwCaptureOpts::default(), sink_mode_opts()] {
            let p = props_of(&opts);
            assert_eq!(p.get("state.restore-props").map(String::as_str), Some("false"));
            assert_eq!(p.get("node.stream.restore-props").map(String::as_str), Some("false"));
        }
    }

    /// The identity properties the rest of the project keys on: the node name
    /// tests look for, and the `application.name` WirePlumber remembers a
    /// stream volume under.
    #[test]
    fn the_capture_keeps_its_identity_and_shape() {
        let p = props_of(&PwCaptureOpts::default());
        assert_eq!(p.get("node.name").map(String::as_str), Some("airplay-rs-capture"));
        assert_eq!(p.get("application.name").map(String::as_str), Some("airplay-rs"));
        assert_eq!(p.get("media.category").map(String::as_str), Some("Capture"));
        assert_eq!(p.get("stream.capture.sink").map(String::as_str), Some("true"));
        assert_eq!(p.get("node.latency").map(String::as_str), Some(PW_NODE_LATENCY));
    }

    /// A never-observed level must read `None`, not 1.0: "we have not looked"
    /// and "we looked and it was unity" are different answers, and a test
    /// that proves the pin took must not be satisfiable by the former.
    #[test]
    fn an_unobserved_capture_level_is_unknown_not_unity() {
        let sh = Shared::new().expect("shared");
        assert_eq!(sh.channel_volume(), None);
        sh.channel_volume.store(0.5f32.to_bits(), Ordering::Relaxed);
        sh.props_epoch.fetch_add(1, Ordering::Relaxed);
        assert_eq!(sh.channel_volume(), Some(0.5));
    }
}
