//! Offline loopback tests of the PRODUCTION audio sender thread
//! ([`spawn_audio_sender`]): real UDP on 127.0.0.1 to the fake receiver
//! (tests/support/fake_audio_receiver.rs), which decrypts every packet and
//! checks timing from the receiver's side with kernel receive timestamps.
//!
//! No AirPlay device, no audio device, no sound: the PCM comes from scripted
//! fakes ([`ScriptedSource`]), the probe's tone generator, or a `sleep`
//! child standing in for parec.

#[path = "support/fake_audio_receiver.rs"]
mod fake;

use airplay_rs::audio::{
    spawn_audio_sender, spawn_audio_sender_with_start, AudioEvent, AudioLatency, AudioSockets, AudioStreamParams,
    SenderState, ALAC_SPF, AUDIO_RATE,
};
use airplay_rs::audiocapture::{ParecSource, PcmSource, ScriptedSource, ToneSource};
use airplay_rs::clock::{BoottimeClock, SenderClock};
use fake::{boottime_secs, decrypt, parse_sync, FakeAirplayAudioReceiver, Sync};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SHK: [u8; 32] = [
    0x5a, 0x11, 0x3c, 0x90, 0x02, 0x7e, 0xc1, 0x48, 0x66, 0x0d, 0xbe, 0x21, 0xf3, 0x94, 0x57, 0x08, 0xaa, 0x6b, 0x39,
    0xd2, 0x1e, 0x85, 0x40, 0xcf, 0x73, 0x2a, 0x9d, 0x04, 0xe8, 0x51, 0xb6, 0x1f,
];

fn frame_dur() -> Duration {
    Duration::from_nanos(ALAC_SPF as u64 * 1_000_000_000 / AUDIO_RATE as u64)
}

fn prn_pcm(frame: u64) -> [u8; 1408] {
    let mut x = frame.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x1234_5678_9ABC_DEF1;
    let mut out = [0u8; 1408];
    for c in out.as_chunks_mut::<8>().0 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.copy_from_slice(&x.to_le_bytes());
    }
    out
}

fn params(rx: &FakeAirplayAudioReceiver) -> AudioStreamParams {
    AudioStreamParams {
        shk: SHK,
        latency: AudioLatency::new(300, 0).unwrap(),
        receiver: IpAddr::V4(Ipv4Addr::LOCALHOST),
        receiver_data_port: rx.data_port,
        receiver_control_port: rx.control_port,
    }
}

/// A scripted source releasing `n` PRN frames at real-time pace, with
/// `startup` before frame 0 and `stall(k)` extra before frame k.
fn scripted(n: u64, startup: Duration, stall: impl Fn(u64) -> Duration) -> ScriptedSource {
    ScriptedSource::new(
        (0..n)
            .map(|k| {
                let d = if k == 0 { startup } else { frame_dur() };
                (d + stall(k), prn_pcm(k))
            })
            .collect(),
        false,
    )
}

struct Run {
    control: Vec<fake::Rx>,
    data: Vec<fake::Rx>,
    spawn_boot: f64,
    events: Vec<AudioEvent>,
    report: airplay_rs::audio::AudioReport,
}

/// Run the production sender until the source ends, then collect.
fn run(src: Box<dyn PcmSource>, seq0: u16, rtp0: u32) -> Run {
    let rx = FakeAirplayAudioReceiver::start();
    let (tx, erx) = std::sync::mpsc::channel();
    let spawn_boot = boottime_secs();
    let h = spawn_audio_sender_with_start(
        params(&rx),
        AudioSockets::bind_ephemeral_for_test().unwrap(),
        src,
        Arc::new(BoottimeClock),
        Some(tx),
        seq0,
        rtp0,
    );
    // The scripted source ends with Err(Ended): wait for the thread to see it.
    let end = Instant::now() + Duration::from_secs(20);
    while h.report().state != SenderState::Stopped {
        assert!(Instant::now() < end, "sender never finished");
        std::thread::sleep(Duration::from_millis(10));
    }
    let report = h.join(Duration::from_secs(2)).expect("joins");
    let (control, data) = rx.finish();
    Run {
        control,
        data,
        spawn_boot,
        events: erx.try_iter().collect(),
        report,
    }
}

fn syncs(r: &Run) -> Vec<Sync> {
    r.control.iter().map(|c| parse_sync(c).expect("only sync packets on control")).collect()
}

fn assert_all_on_time(r: &Run) {
    let s = syncs(r);
    for (i, d) in r.data.iter().enumerate() {
        let o = decrypt(&d.bytes, &SHK).unwrap();
        let m = s
            .iter()
            .rfind(|x| x.at <= d.at)
            .copied()
            .unwrap_or_else(|| panic!("packet {i} arrived before any sync"));
        let slack = m.playout(o.rtp) - d.at;
        assert!(slack >= 0.045, "packet {i} only {:.1} ms before play-out", slack * 1e3);
    }
}

#[test]
fn sender_pcm_roundtrips_byte_exact() {
    let r = run(Box::new(scripted(500, Duration::ZERO, |_| Duration::ZERO)), 0xFFF0, 0xFFFF_F000);
    assert_eq!(r.data.len(), 500);
    let mut prev: Option<fake::Opened> = None;
    for (k, d) in r.data.iter().enumerate() {
        assert_eq!(d.bytes.len(), 1448);
        assert_eq!(&d.bytes[..2], &[0x80, 0x60]);
        assert_eq!(&d.bytes[8..12], &[0, 0, 0, 0]);
        let o = decrypt(&d.bytes, &SHK).unwrap();
        assert_eq!(o.pcm, prn_pcm(k as u64), "frame {k}");
        assert_eq!(o.counter, k as u64);
        match &prev {
            Some(p) => {
                assert_eq!(o.seq, p.seq.wrapping_add(1));
                assert_eq!(o.rtp, p.rtp.wrapping_add(352));
            }
            None => assert_eq!((o.seq, o.rtp), (0xFFF0, 0xFFFF_F000)),
        }
        prev = Some(o);
    }
    assert_eq!(r.report.timeline.packets, 500);
    assert_eq!(r.report.send_errors, 0);
    assert_eq!(r.report.rtp_sent, 500);
    assert_eq!(r.report.capture_kind, "scripted");
    assert_all_on_time(&r);
}

#[test]
fn sender_first_sync_precedes_first_rtp_and_reports_it() {
    let r = run(Box::new(scripted(40, Duration::ZERO, |_| Duration::ZERO)), 1, 0x1234_5678);
    let s = syncs(&r);
    assert!(s[0].first);
    assert!(s[0].at <= r.data[0].at, "0x90 arrives before data packet 0");
    let p0 = decrypt(&r.data[0].bytes, &SHK).unwrap();
    assert_eq!(s[0].rtp_now, p0.rtp);
    assert_eq!(s[0].latency_samples, 13230);
    match r.events.first() {
        Some(AudioEvent::FirstPacketSent(at)) => {
            assert!((at.boot().as_secs_f64() - s[0].boot).abs() < 1e-6, "event carries the anchoring read");
        }
        other => panic!("first event {other:?}"),
    }
    assert_all_on_time(&r);
}

#[test]
fn sender_capture_startup_700ms_not_counted() {
    let r = run(Box::new(scripted(40, Duration::from_millis(700), |_| Duration::ZERO)), 9, 99);
    let s = syncs(&r);
    assert!(s[0].first);
    assert!(s[0].boot >= r.spawn_boot + 0.7, "anchor {:.3} vs spawn {:.3}", s[0].boot, r.spawn_boot);
    assert_eq!(r.report.timeline.anchors, 1);
    assert_all_on_time(&r);
}

#[test]
fn sender_stall_400ms_reanchors() {
    let stall = |k: u64| if k == 30 { Duration::from_millis(400) } else { Duration::ZERO };
    let r = run(Box::new(scripted(60, Duration::ZERO, stall)), 65530, 0);
    let s = syncs(&r);
    let firsts: Vec<&Sync> = s.iter().filter(|x| x.first).collect();
    assert_eq!(firsts.len(), 2, "{s:?}");
    let pre = decrypt(&r.data[29].bytes, &SHK).unwrap();
    let post = decrypt(&r.data[30].bytes, &SHK).unwrap();
    assert_eq!(post.rtp, pre.rtp.wrapping_add(352));
    assert_eq!(firsts[1].rtp_now, post.rtp);
    assert!(firsts[1].at <= r.data[30].at);
    assert_eq!((r.report.timeline.anchors, r.report.timeline.gap_reanchors), (2, 1));
    assert!(r.events.iter().any(|e| matches!(e, AudioEvent::Anchored(airplay_rs::audio::AnchorReason::Gap(_)))));
    assert_all_on_time(&r);
}

#[test]
fn sender_burst_starved_capture_never_sends_late() {
    // Three consecutive 200 ms holes: each below the 250 ms gap rule, but the
    // lateness guard must re-anchor rather than send late.
    let stall = |k: u64| match k {
        60..=62 => Duration::from_millis(200),
        _ => Duration::ZERO,
    };
    let r = run(Box::new(scripted(150, Duration::ZERO, stall)), 7, 7);
    assert!(r.report.timeline.late_reanchors >= 1, "{:?}", r.report);
    assert_all_on_time(&r);
}

#[test]
fn sender_periodic_syncs_1s_with_tone() {
    let rx = FakeAirplayAudioReceiver::start();
    let clock: Arc<dyn SenderClock> = Arc::new(BoottimeClock);
    let h = spawn_audio_sender(
        params(&rx),
        AudioSockets::bind_ephemeral_for_test().unwrap(),
        Box::new(ToneSource::new(clock.clone(), 0.3)),
        clock,
        None,
    );
    std::thread::sleep(Duration::from_millis(3100));
    let rep = h.join(Duration::from_secs(2)).unwrap();
    let (control, data) = rx.finish();
    let r = Run { control, data, spawn_boot: 0.0, events: vec![], report: rep };
    let s = syncs(&r);
    let periodic: Vec<&Sync> = s.iter().filter(|x| !x.first).collect();
    assert!(periodic.len() >= 2, "{} periodic", periodic.len());
    for w in periodic.windows(2) {
        let d = w[1].boot - w[0].boot;
        assert!((1.0..1.05).contains(&d), "spacing {d}");
    }
    assert_eq!(r.report.capture_kind, "tone");
    assert_eq!(r.report.timeline.anchors, 1);
    assert!(r.data.len() as u64 >= 3 * AUDIO_RATE as u64 / ALAC_SPF as u64 - 10);
    assert_all_on_time(&r);
}

#[test]
fn sender_stop_with_stuck_source_returns_within_2s_and_frees_ports() {
    let rx = FakeAirplayAudioReceiver::start();
    let socks = AudioSockets::bind_ephemeral_for_test().unwrap();
    let (cp, dp) = (socks.control.local_addr().unwrap().port(), socks.data.local_addr().unwrap().port());
    // Two frames, then never yields again.
    let src = ScriptedSource::new(vec![(Duration::ZERO, prn_pcm(0)), (frame_dur(), prn_pcm(1))], true);
    let h = spawn_audio_sender(params(&rx), socks, Box::new(src), Arc::new(BoottimeClock), None);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(h.report().state, SenderState::Stalled, "a source that stops yielding shows as stalled");
    let t = Instant::now();
    let rep = h.join(Duration::from_secs(2)).expect("stuck source still joins");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(rep.timeline.packets, 2);
    assert_eq!(rep.state, SenderState::Stopped);
    // The sockets went with the thread.
    UdpSocket::bind(("127.0.0.1", cp)).expect("control port free again");
    UdpSocket::bind(("127.0.0.1", dp)).expect("data port free again");
}

#[test]
fn sender_drop_stops_the_thread() {
    let rx = FakeAirplayAudioReceiver::start();
    let socks = AudioSockets::bind_ephemeral_for_test().unwrap();
    let cp = socks.control.local_addr().unwrap().port();
    let src = ScriptedSource::new(vec![], true);
    let h = spawn_audio_sender(params(&rx), socks, Box::new(src), Arc::new(BoottimeClock), None);
    std::thread::sleep(Duration::from_millis(60));
    let t = Instant::now();
    drop(h);
    assert!(t.elapsed() < Duration::from_secs(2));
    UdpSocket::bind(("127.0.0.1", cp)).expect("control port free after Drop");
}

#[test]
fn sender_drains_unsolicited_control_packets() {
    let rx = FakeAirplayAudioReceiver::start();
    let socks = AudioSockets::bind_ephemeral_for_test().unwrap();
    let our_ctrl = socks.control.local_addr().unwrap();
    let h = spawn_audio_sender_with_start(
        params(&rx),
        socks,
        Box::new(scripted(120, Duration::ZERO, |_| Duration::ZERO)),
        Arc::new(BoottimeClock),
        None,
        0,
        0,
    );
    let junk = UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..5u8 {
        // A retransmit-request-shaped datagram and plain junk.
        junk.send_to(&[0x80, 0xD5, 0, i, 0, 0, 0, 1], our_ctrl).unwrap();
        std::thread::sleep(Duration::from_millis(40));
    }
    let end = Instant::now() + Duration::from_secs(10);
    while h.report().state != SenderState::Stopped {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(10));
    }
    let rep = h.join(Duration::from_secs(2)).unwrap();
    assert_eq!(rep.control_rx, 5, "{rep:?}");
    assert_eq!(rep.timeline.packets, 120, "junk changes nothing");
    let (_, data) = rx.finish();
    assert_eq!(data.len(), 120);
}

#[test]
fn sender_parec_like_stopper_kills_child() {
    // `sleep 100` stands in for a parec that never produces a sample.
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("100");
    let src = ParecSource::spawn_command(cmd, Arc::new(BoottimeClock)).unwrap();
    let pid = src.child_pid().unwrap();
    let rx = FakeAirplayAudioReceiver::start();
    let h = spawn_audio_sender(params(&rx), AudioSockets::bind_ephemeral_for_test().unwrap(), Box::new(src), Arc::new(BoottimeClock), None);
    std::thread::sleep(Duration::from_millis(200));
    let t = Instant::now();
    let rep = h.join(Duration::from_secs(2)).expect("joins");
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(rep.timeline.packets, 0, "no sample, no packet, no sync");
    assert_eq!(rep.timeline.syncs, 0);
    assert_eq!(rep.capture_kind, "parec");
    // The child is gone: killed AND reaped by the source's Drop. A zombie
    // (state Z) is a failure — it means Drop killed without wait(), and the
    // session would leak one per run. Only this test process could reap it,
    // so a zombie that persists to the deadline was never going to go away.
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
    let (control, data) = rx.finish();
    assert!(control.is_empty() && data.is_empty());
}

#[test]
fn sender_unreachable_sync_forces_reanchor_and_never_sends_unanchored_rtp() {
    // Control port 0 is not a valid destination: every sync send fails. The
    // sender must then send NO RTP at all (it would be unanchored).
    let rx = FakeAirplayAudioReceiver::start();
    let mut p = params(&rx);
    p.receiver_control_port = 0;
    let r = {
        let h = spawn_audio_sender_with_start(
            p,
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(scripted(20, Duration::ZERO, |_| Duration::ZERO)),
            Arc::new(BoottimeClock),
            None,
            0,
            0,
        );
        let end = Instant::now() + Duration::from_secs(10);
        while h.report().state != SenderState::Stopped {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(10));
        }
        h.join(Duration::from_secs(2)).unwrap()
    };
    let (_, data) = rx.finish();
    assert!(data.is_empty(), "{} RTP packets sent without a delivered anchor", data.len());
    assert_eq!(r.send_errors, 20);
    assert_eq!(r.rtp_sent, 0);
    assert_eq!(r.timeline.anchors, 20, "every frame tried to anchor afresh");
    assert_eq!(r.timeline.forced_reanchors, 19);
}
