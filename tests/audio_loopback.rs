//! Offline loopback tests for the audio packet layer: our packets go over real
//! UDP on 127.0.0.1 to a fake receiver (tests/support/fake_audio_receiver.rs)
//! that decrypts them and checks timing from the receiver's side, using kernel
//! receive timestamps. No AirPlay device, no audio device, no sound.
//!
//! The "sender" here is a minimal test driver around [`AudioTimeline`] with
//! the exact send order the production sender thread must use: the sync from
//! `Emitted` to the control port, THEN the RTP to the data port, then
//! `periodic`. The production sender thread (`spawn_audio_sender`) is
//! covered by the same checks in tests/audio_sender_loopback.rs; these stay
//! as the timeline-level baseline.

#[path = "support/fake_audio_receiver.rs"]
mod fake;

use airplay_rs::audio::{tone_frame, AudioLatency, AudioTimeline, ALAC_SPF, AUDIO_RATE};
use airplay_rs::clock::{BoottimeClock, SenderClock};
use fake::{boottime_secs, decrypt, parse_sync, FakeAirplayAudioReceiver, OpenError, Sync};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

const SHK: [u8; 32] = [
    0x1f, 0x8e, 0x3a, 0x44, 0x90, 0x02, 0xc7, 0x5d, 0x61, 0xaa, 0x0b, 0x7e, 0x13, 0xf4, 0x28, 0x99,
    0x35, 0x6c, 0xd0, 0x81, 0x4e, 0xbb, 0x07, 0x52, 0xe9, 0x1a, 0x66, 0xc3, 0x3d, 0x70, 0xa5, 0x0f,
];

/// Seeded PRN PCM (xorshift), so every frame's bytes are distinct.
fn prn_pcm(frame: u64) -> [u8; 1408] {
    let mut x = frame.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03;
    let mut out = [0u8; 1408];
    for c in out.as_chunks_mut::<8>().0 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.copy_from_slice(&x.to_le_bytes());
    }
    out
}

struct Run {
    control: Vec<fake::Rx>,
    data: Vec<fake::Rx>,
    spawn_boot: f64,
    first_frame_boot: f64,
    lat: AudioLatency,
    stats: airplay_rs::audio::AudioStats,
}

/// Stream `frames` frames. Frame k is "captured" (handed to the sender) at
/// `start + k*352/44100 + extra(k)` where `extra` is cumulative stall time;
/// `startup` delays the first frame (capture start-up). `pace=false` sends as
/// fast as possible with a 1 ms breather.
fn stream(
    frames: u64,
    seq0: u16,
    rtp0: u32,
    startup: Duration,
    stall: impl Fn(u64) -> Duration,
    pace: bool,
    pcm: impl Fn(u64) -> [u8; 1408],
) -> Run {
    let rx = FakeAirplayAudioReceiver::start();
    let ctrl = UdpSocket::bind("127.0.0.1:0").unwrap();
    let data = UdpSocket::bind("127.0.0.1:0").unwrap();
    let lat = AudioLatency::new(300, 0).unwrap();
    let clock = BoottimeClock;
    let spawn_boot = boottime_secs();
    let mut tl = AudioTimeline::new(SHK, &lat, seq0, rtp0);
    let t0 = Instant::now() + startup;
    let mut extra = Duration::ZERO;
    let mut first_frame_boot = 0.0;
    for k in 0..frames {
        extra += stall(k);
        let target = if pace {
            t0 + Duration::from_nanos(k * ALAC_SPF as u64 * 1_000_000_000 / AUDIO_RATE as u64) + extra
        } else {
            t0 + extra
        };
        if let Some(d) = target.checked_duration_since(Instant::now()) {
            std::thread::sleep(d);
        }
        if !pace {
            std::thread::sleep(Duration::from_millis(1));
        }
        let frame = pcm(k);
        // The clock is read only once the frame is in hand.
        let now = clock.read();
        if k == 0 {
            first_frame_boot = now.boot().as_secs_f64();
        }
        let e = tl.emit(&frame, now);
        if let Some(s) = e.sync {
            ctrl.send_to(&s, ("127.0.0.1", rx.control_port)).unwrap();
        }
        data.send_to(&e.rtp, ("127.0.0.1", rx.data_port)).unwrap();
        if let Some(s) = tl.periodic(now) {
            ctrl.send_to(&s, ("127.0.0.1", rx.control_port)).unwrap();
        }
    }
    let stats = tl.stats();
    let (control, data) = rx.finish();
    Run {
        control,
        data,
        spawn_boot,
        first_frame_boot,
        lat,
        stats,
    }
}

fn syncs(r: &Run) -> Vec<Sync> {
    r.control.iter().map(|c| parse_sync(c).expect("only sync packets on control")).collect()
}

/// The newest sync that ARRIVED before `at` (what a receiver would be using).
fn mapping_at(syncs: &[Sync], at: f64) -> Option<Sync> {
    syncs.iter().rfind(|s| s.at <= at).copied()
}

/// Every data packet has a mapping that arrived before it, and arrives at
/// least 45 ms before its play-out time under that mapping. (The sender
/// guarantees LATE_MARGIN = 50 ms at SEND time; 5 ms is allowed for loopback
/// transit and scheduling so the check cannot flake at the boundary.) This is the direct
/// offline check for the silent-audio bug (late packets are dropped silently).
fn assert_all_on_time(r: &Run) {
    let s = syncs(r);
    let mut worst = f64::INFINITY;
    for (i, d) in r.data.iter().enumerate() {
        let o = decrypt(&d.bytes, &SHK).unwrap();
        let m = mapping_at(&s, d.at).unwrap_or_else(|| panic!("packet {i} arrived before any sync"));
        let slack = m.playout(o.rtp) - d.at;
        worst = worst.min(slack);
        assert!(slack >= 0.045, "packet {i} (rtp {}) only {:.1} ms before play-out", o.rtp, slack * 1e3);
    }
    eprintln!("worst slack {:.1} ms over {} packets", worst * 1e3, r.data.len());
}

#[test]
fn loopback_pcm_roundtrips_byte_exact() {
    let r = stream(500, 0xFFF0, 0xFFFF_F000, Duration::ZERO, |_| Duration::ZERO, false, prn_pcm);
    assert_eq!(r.data.len(), 500, "every packet delivered on loopback");
    // Kernel arrival order == send order on loopback; check contiguity.
    let mut prev: Option<fake::Opened> = None;
    for (k, d) in r.data.iter().enumerate() {
        assert_eq!(d.bytes.len(), 1448);
        assert_eq!(&d.bytes[..2], &[0x80, 0x60]);
        assert_eq!(&d.bytes[8..12], &[0, 0, 0, 0], "SSRC 0");
        let o = decrypt(&d.bytes, &SHK).unwrap();
        assert_eq!(o.pcm, prn_pcm(k as u64), "frame {k} PCM round trip");
        assert_eq!(o.counter, k as u64);
        if let Some(p) = &prev {
            assert_eq!(o.seq, p.seq.wrapping_add(1));
            assert_eq!(o.rtp, p.rtp.wrapping_add(352));
        } else {
            assert_eq!((o.seq, o.rtp), (0xFFF0, 0xFFFF_F000));
        }
        prev = Some(o);
    }
    // the run crossed both the 16-bit seq and 32-bit rtp wraps
    let last = prev.unwrap();
    assert!(last.seq < 0xFFF0 && last.rtp < 0xFFFF_F000);
    assert_eq!(r.stats.packets, 500);
}

#[test]
fn loopback_rejects_wrong_key_and_tampered_header() {
    let r = stream(3, 7, 7000, Duration::ZERO, |_| Duration::ZERO, false, prn_pcm);
    let p = &r.data[1].bytes;
    assert!(decrypt(p, &SHK).is_ok());
    let mut other = SHK;
    other[0] ^= 1;
    assert_eq!(decrypt(p, &other).unwrap_err(), OpenError::Auth);
    // The AAD is header[4..12]: changing the RTP timestamp must fail auth...
    let mut t = p.clone();
    t[7] ^= 1;
    assert_eq!(decrypt(&t, &SHK).unwrap_err(), OpenError::Auth);
    // ...while the sequence number (bytes 2..4) is outside the AAD.
    let mut t = p.clone();
    t[3] ^= 1;
    assert!(decrypt(&t, &SHK).is_ok());
    // The nonce in clear is what the receiver decrypts with.
    let mut t = p.clone();
    t[1440] ^= 1;
    assert_eq!(decrypt(&t, &SHK).unwrap_err(), OpenError::Auth);
}

#[test]
fn loopback_first_sync_precedes_first_rtp() {
    let r = stream(50, 1, 0x1234_5678, Duration::ZERO, |_| Duration::ZERO, true, prn_pcm);
    let s = syncs(&r);
    let first = s[0];
    assert!(first.first, "first control packet is a 0x90");
    assert!(first.at <= r.data[0].at, "0x90 arrives before data packet 0 (kernel timestamps)");
    let p0 = decrypt(&r.data[0].bytes, &SHK).unwrap();
    assert_eq!(first.rtp_now, p0.rtp);
    assert_eq!(first.latency_samples, r.lat.samples());
    assert_eq!(first.latency_samples, 13230);
    assert_all_on_time(&r);
}

#[test]
fn loopback_every_packet_arrives_before_deadline() {
    // ~2 s real-time stream with a burst-starved capture: three consecutive
    // 200 ms holes (each below the 250 ms gap rule, cumulatively far behind),
    // plus small jitter. The lateness guard must re-anchor rather than send late.
    let stall = |k: u64| match k {
        60..=62 => Duration::from_millis(200),
        k if k % 17 == 0 => Duration::from_millis(6),
        _ => Duration::ZERO,
    };
    let r = stream(250, 40000, 1 << 31, Duration::ZERO, stall, true, prn_pcm);
    assert_eq!(r.data.len(), 250);
    assert!(r.stats.late_reanchors >= 1, "{:?}", r.stats);
    assert_all_on_time(&r);
}

#[test]
fn loopback_capture_startup_700ms_not_counted() {
    let r = stream(40, 9, 99, Duration::from_millis(700), |_| Duration::ZERO, true, prn_pcm);
    let s = syncs(&r);
    assert!(s[0].first);
    assert!(
        s[0].boot >= r.spawn_boot + 0.7,
        "anchor NTP {:.3} must be >= spawn {:.3} + 700 ms",
        s[0].boot,
        r.spawn_boot
    );
    assert!((s[0].boot - r.first_frame_boot).abs() < 1e-6, "anchored at the first frame's clock read");
    assert_eq!(r.stats.anchors, 1);
    assert_all_on_time(&r);
}

#[test]
fn loopback_stall_400ms_reanchors() {
    let r = stream(60, 65530, 0, Duration::ZERO, |k| if k == 30 { Duration::from_millis(400) } else { Duration::ZERO }, true, prn_pcm);
    let s = syncs(&r);
    let firsts: Vec<&Sync> = s.iter().filter(|x| x.first).collect();
    assert_eq!(firsts.len(), 2, "{s:?}");
    let post = decrypt(&r.data[30].bytes, &SHK).unwrap();
    let pre = decrypt(&r.data[29].bytes, &SHK).unwrap();
    assert_eq!(post.rtp, pre.rtp.wrapping_add(352), "rtp continuous across the re-anchor");
    assert_eq!(firsts[1].rtp_now, post.rtp);
    assert!(firsts[1].at <= r.data[30].at && firsts[1].at >= r.data[29].at);
    assert!(firsts[1].boot - firsts[0].boot > 0.6, "only the NTP jumps");
    assert_eq!((r.stats.anchors, r.stats.gap_reanchors), (2, 1));
    assert_all_on_time(&r);
}

#[test]
fn loopback_periodic_syncs_1s() {
    // 3 s of the probe's tone, real-time paced.
    let frames = 3 * AUDIO_RATE as u64 / ALAC_SPF as u64;
    let r = stream(frames, 0, 0, Duration::ZERO, |_| Duration::ZERO, true, |k| tone_frame(k * ALAC_SPF as u64, 0.3));
    let s = syncs(&r);
    let periodic: Vec<&Sync> = s.iter().filter(|x| !x.first).collect();
    assert!(periodic.len() >= 2, "{} periodic syncs", periodic.len());
    for w in periodic.windows(2) {
        let d = w[1].boot - w[0].boot;
        assert!((1.0..1.05).contains(&d), "sync spacing {d}");
    }
    // Each 0x80 names the rtp of the data packet that follows it.
    for p in &periodic {
        let next = r.data.iter().find(|d| d.at >= p.at).unwrap();
        assert_eq!(decrypt(&next.bytes, &SHK).unwrap().rtp, p.rtp_now);
    }
    assert_all_on_time(&r);
}
