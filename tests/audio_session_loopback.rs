//! Offline end-to-end tests of audio in a SESSION: `Session::bring_up` with
//! audio on, against a fake control endpoint (tests/support/fake_rtsp_receiver.rs)
//! and a fake audio receiver (tests/support/fake_audio_receiver.rs), both on
//! 127.0.0.1. Covers the audio SETUP, the sender started by the session, the
//! volume policy over the real encrypted control connection (with a fake
//! LAPTOP, so the machine's own sink is never touched), a `dvlc` arriving on
//! the event channel, and the shutdown order.
//!
//! The audio source is the probe's tone, or `LoudSource` for the blast
//! proofs, generated in memory: no capture device, no playback, no sound, no
//! AirPlay device.

#[path = "support/fake_audio_receiver.rs"]
mod fake_audio;
#[path = "support/fake_rtsp_receiver.rs"]
mod fake_rtsp;

use airplay_rs::session::{AudioMode, Session, SessionConfig, SessionError};
use airplay_rs::volume::{LaptopEvent, LaptopLevel, LaptopVolume, VolumeTiming};
use fake_audio::{decrypt, parse_sync, FakeAirplayAudioReceiver};
use fake_rtsp::{Behaviour, FakeRtspReceiver};
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SHARED: [u8; 32] = [0x33; 32];

/// A timing port whose +1/+2 are free right now (bring_up binds all three).
fn free_timing_port() -> u16 {
    for _ in 0..50 {
        let s = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let p = s.local_addr().unwrap().port();
        drop(s);
        if p < 65000
            && [p, p + 1, p + 2].iter().all(|q| std::net::UdpSocket::bind(("0.0.0.0", *q)).is_ok())
        {
            return p;
        }
    }
    panic!("no free timing port");
}

struct FakeLaptop {
    level: Arc<Mutex<(u8, bool)>>,
    sets: Arc<Mutex<Vec<(u8, bool)>>>,
    events: Arc<Mutex<Option<Sender<LaptopEvent>>>>,
}

impl LaptopVolume for FakeLaptop {
    fn read(&mut self) -> io::Result<LaptopLevel> {
        let (p, m) = *self.level.lock().unwrap();
        let raw = (p as u32 * 65536 + 50) / 100;
        Ok(LaptopLevel::from_pactl(
            &format!("Volume: front-left: {raw} / {p}% / 0 dB,   front-right: {raw} / {p}% / 0 dB"),
            if m { "Mute: yes" } else { "Mute: no" },
        )
        .unwrap())
    }
    fn set(&mut self, pct: u8, muted: bool) -> io::Result<()> {
        self.sets.lock().unwrap().push((pct, muted));
        let mut l = self.level.lock().unwrap();
        if muted {
            l.1 = true;
        } else {
            *l = (pct, false);
        }
        // pactl would report the change back to us.
        if let Some(tx) = self.events.lock().unwrap().as_ref() {
            let _ = tx.send(LaptopEvent::Change);
        }
        Ok(())
    }
    fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>> {
        let (tx, rx) = mpsc::channel();
        *self.events.lock().unwrap() = Some(tx);
        Ok(rx)
    }
    fn describe(&self) -> String {
        "fake laptop".into()
    }
}

/// The blast proofs are real-time proofs: each asserts about WHEN a packet
/// left, relative to WHEN the gate moved. Run in parallel on a loaded
/// machine — several of them plus whatever else `cargo test` is doing — the
/// sender thread can be descheduled long enough for a packet encoded before
/// the gate was held to be sent after it. That is a scheduling artefact, not
/// the property under test, and it makes the proofs report failures they did
/// not find.
///
/// So they run one at a time. This serialises nothing but these tests and
/// weakens no assertion: every deadline, sleep and ordering check is exactly
/// as strict inside the lock as outside it.
fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn timing() -> VolumeTiming {
    VolumeTiming {
        start_delay: Duration::from_millis(300),
        readback_delay: Duration::from_millis(100),
        arm_grace: Duration::from_millis(100),
        tick: Duration::from_millis(10),
    }
}

#[test]
fn session_audio_end_to_end_offline() {
    let audio_rx = FakeAirplayAudioReceiver::start();
    let fake = FakeRtspReceiver::start(
        &SHARED,
        Behaviour {
            audio_ports: (audio_rx.data_port, audio_rx.control_port),
            offer_event_port: true,
            volume_db: -20.4,
            ..Default::default()
        },
    );
    let tp = free_timing_port();
    let mut cfg = SessionConfig::new("127.0.0.1");
    cfg.timing_port = tp;
    cfg.audio = AudioMode::Tone;
    let session = Session::bring_up(fake.connect(), SHARED.to_vec(), &cfg).expect("bring-up against the fake");
    assert_eq!(session.model, "LS03F");

    // --- the audio SETUP on the wire
    let reqs = fake.requests();
    let audio_setup = reqs
        .iter()
        .find(|r| r.method == "SETUP" && r.stream0().and_then(|s| s.get("type").and_then(|t| t.as_unsigned_integer())) == Some(96))
        .expect("an audio SETUP");
    let s0 = audio_setup.stream0().unwrap();
    assert_eq!(s0["latencyMax"].as_unsigned_integer(), Some(13230), "300 ms, offset 0");
    assert_eq!(s0["controlPort"].as_unsigned_integer(), Some(tp as u64 + 1));
    let shk: [u8; 32] = s0["shk"].as_data().unwrap().try_into().unwrap();
    assert_eq!(
        reqs.iter().filter(|r| r.method == "SETUP").count(),
        3,
        "control, audio, video: no [4b] re-SETUP"
    );
    let info = session.audio_monitor().expect("audio on").info;
    // Calibrated since 634d386: 0 ms is the Frame's measured-by-ear offset, not
    // a placeholder. An explicit --av-offset still reports uncalibrated, which
    // the second case below pins.
    assert_eq!((info.av_offset_ms, info.av_offset_calibrated, info.effective_latency_ms), (0, true, 300));

    // Nothing is sent before streaming starts.
    std::thread::sleep(Duration::from_millis(150));
    assert!(fake.requests().iter().all(|r| r.method != "GET_PARAMETER" && r.method != "SET_PARAMETER"));

    // --- start: tone -> sender -> fake receiver; volume sync with a fake laptop at 40 %
    let level = Arc::new(Mutex::new((40u8, false)));
    let sets = Arc::new(Mutex::new(vec![]));
    let events = Arc::new(Mutex::new(None));
    session.start_audio_with(
        Box::new(FakeLaptop { level: level.clone(), sets: sets.clone(), events: events.clone() }),
        timing(),
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("volume armed", 10, || mon.volume().state == "armed");

    let vol_reqs: Vec<fake_rtsp::Req> =
        fake.requests().into_iter().filter(|r| r.method.ends_with("_PARAMETER")).collect();
    let kinds: Vec<&str> = vol_reqs.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(kinds, ["GET_PARAMETER", "SET_PARAMETER", "GET_PARAMETER"]);
    let set = &vol_reqs[1];
    assert_eq!(set.body, b"volume: -18.000000\r\n", "the TV takes the laptop's 40 %");
    assert!(set.header("Session").is_none(), "no Session header: the proven form");
    assert_eq!(set.uri, audio_setup.uri, "on the audio stream URI");
    assert_eq!(set.header("Content-Type"), Some("text/parameters"));
    assert_eq!(*fake.volume_db.lock().unwrap(), -18.0);
    assert_eq!(mon.volume().tv_volume_db, Some(-18.0), "read back");

    // The first GET waited for audio: >= start_delay after the first packet arrived.
    let (control_so_far, data_so_far) = {
        // peek without stopping: the receiver keeps recording until finish()
        std::thread::sleep(Duration::from_millis(20));
        (mon.report().timeline.syncs, mon.report().rtp_sent)
    };
    assert!(control_so_far >= 1 && data_so_far > 0, "audio is flowing");

    // --- laptop key -> TV
    *level.lock().unwrap() = (75, false);
    events.lock().unwrap().as_ref().unwrap().send(LaptopEvent::Change).unwrap();
    wait_for("SET to 75 %", 5, || *fake.volume_db.lock().unwrap() == -7.5);

    // --- TV remote -> laptop, via the event channel; and no echo back.
    std::thread::sleep(Duration::from_millis(50));
    let n_sets_before = fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count();
    // First the TV echoing our own SET (0.75): must be ignored.
    fake.send_event(FakeRtspReceiver::dvlc(0.75, false));
    std::thread::sleep(Duration::from_millis(150));
    assert!(sets.lock().unwrap().is_empty(), "echo of our SET moved the laptop");
    // Then a real remote press.
    fake.send_event(FakeRtspReceiver::dvlc(0.3, false));
    wait_for("laptop set by dvlc", 5, || !sets.lock().unwrap().is_empty());
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(*sets.lock().unwrap(), vec![(30, false)]);
    assert_eq!(
        fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count(),
        n_sets_before,
        "the laptop change caused by the TV is not sent back to the TV"
    );
    assert_eq!(fake.event_replies(), vec![200, 200], "every event answered 200");

    // --- shutdown: volume, audio, feedback, TEARDOWN last.
    let t = Instant::now();
    session.shutdown();
    assert!(t.elapsed() < Duration::from_secs(8), "shutdown took {:?}", t.elapsed());
    let final_reqs = fake.requests();
    assert_eq!(final_reqs.last().unwrap().method, "TEARDOWN");
    let teardown_at = final_reqs.last().unwrap().at;
    std::thread::sleep(Duration::from_millis(100));
    let (control, data) = audio_rx.finish();
    assert!(data.iter().all(|d| d.at < teardown_at), "no audio after TEARDOWN");
    assert!(!data.is_empty());

    // What reached the audio receiver decrypts with the SETUP shk and was
    // anchored first.
    let syncs: Vec<_> = control.iter().map(|c| parse_sync(c).unwrap()).collect();
    assert!(syncs[0].first && syncs[0].at <= data[0].at);
    assert_eq!(syncs[0].latency_samples, 13230);
    let first_rtp = decrypt(&data[0].bytes, &shk).expect("decrypts with the SETUP key");
    assert_eq!(syncs[0].rtp_now, first_rtp.rtp);
    let first_get = vol_reqs[0].at;
    assert!(first_get >= data[0].at + 0.3 - 0.01, "first volume GET {first_get} vs first audio {}", data[0].at);
    for d in &data {
        decrypt(&d.bytes, &shk).unwrap();
    }
    // Never 0 dB.
    assert!(final_reqs.iter().filter(|r| r.method == "SET_PARAMETER").all(|r| r.body != b"volume: 0.000000\r\n"));
}

#[test]
fn audio_off_session_sends_no_audio_setup_and_no_volume() {
    let fake = FakeRtspReceiver::start(&SHARED, Behaviour::default());
    let mut cfg = SessionConfig::new("127.0.0.1");
    cfg.timing_port = free_timing_port();
    let session = Session::bring_up(fake.connect(), SHARED.to_vec(), &cfg).unwrap();
    assert!(session.audio_monitor().is_none());
    session.start_audio(); // no-op
    std::thread::sleep(Duration::from_millis(100));
    session.shutdown();
    let methods: Vec<String> = fake.requests().into_iter().map(|r| r.method).collect();
    assert!(!methods.iter().any(|m| m.ends_with("_PARAMETER")), "{methods:?}");
    assert_eq!(methods.iter().filter(|m| *m == "SETUP").count(), 2, "control + video only");
}

#[test]
fn fallback_4b_skipped_when_audio_on() {
    let audio_rx = FakeAirplayAudioReceiver::start();
    let fake = FakeRtspReceiver::start(
        &SHARED,
        Behaviour { audio_ports: (audio_rx.data_port, audio_rx.control_port), video_status: 400, ..Default::default() },
    );
    let tp = free_timing_port();
    let mut cfg = SessionConfig::new("127.0.0.1");
    cfg.timing_port = tp;
    cfg.audio = AudioMode::Tone;
    let err = match Session::bring_up(fake.connect(), SHARED.to_vec(), &cfg) {
        Err(e) => e,
        Ok(_) => panic!("video rejected must fail with audio on"),
    };
    assert!(matches!(err, SessionError::Audio(_)), "{err}");
    assert!(err.to_string().contains("--audio none"), "{err}");
    let setups = fake.requests().into_iter().filter(|r| r.method == "SETUP").count();
    assert_eq!(setups, 3, "control, audio, video: the [4b] audio re-SETUP was not sent");
    // The error path released every port it bound.
    for p in [tp, tp + 1, tp + 2] {
        std::net::UdpSocket::bind(("0.0.0.0", p)).unwrap_or_else(|e| panic!("port {p} still bound: {e}"));
    }
}

#[test]
fn audio_setup_rejected_is_an_error_not_silence() {
    let fake = FakeRtspReceiver::start(&SHARED, Behaviour { audio_status: 500, ..Default::default() });
    let mut cfg = SessionConfig::new("127.0.0.1");
    cfg.timing_port = free_timing_port();
    cfg.audio = AudioMode::Tone;
    let err = Session::bring_up(fake.connect(), SHARED.to_vec(), &cfg).err().expect("fails");
    assert!(err.to_string().contains("audio SETUP returned 500"), "{err}");
}

#[test]
fn av_offset_moves_setup_latency() {
    let audio_rx = FakeAirplayAudioReceiver::start();
    let fake = FakeRtspReceiver::start(
        &SHARED,
        Behaviour { audio_ports: (audio_rx.data_port, audio_rx.control_port), ..Default::default() },
    );
    let mut cfg = SessionConfig::new("127.0.0.1");
    cfg.timing_port = free_timing_port();
    cfg.audio = AudioMode::Tone;
    cfg.av_offset_ms = Some(200);
    let session = Session::bring_up(fake.connect(), SHARED.to_vec(), &cfg).unwrap();
    let info = session.audio_monitor().unwrap().info;
    assert_eq!((info.effective_latency_ms, info.av_offset_calibrated), (500, false));
    session.shutdown();
    let setup = fake
        .requests()
        .into_iter()
        .find(|r| r.method == "SETUP" && r.stream0().and_then(|s| s.get("type").and_then(|t| t.as_unsigned_integer())) == Some(96))
        .unwrap();
    assert_eq!(setup.stream0().unwrap()["latencyMax"].as_unsigned_integer(), Some(22050));
}

// ---------------------------------------------------------------------------
// Volume safety (the "TV blast" findings), end to end through the SESSION's
// own gate wiring: Session::start_audio_with -> one AudioGate shared by the
// audio sender and the volume driver. Fake TV + fake audio receiver on
// 127.0.0.1, fake laptop; the tone is generated in memory. No sound.
// ---------------------------------------------------------------------------

fn is_silent(pcm: &[u8]) -> bool {
    pcm.iter().all(|b| *b == 0)
}

/// A source that is LOUD in every single frame, paced like a real capture.
///
/// The probe tone is not usable for the blast proof: `tone_frame` beeps for
/// only the first 150 ms of each second and is digital zero for the other
/// 850 ms. A proof that looks for "the first non-silent packet" would then be
/// satisfied by the tone's own quiet phase instead of by the gate — measured,
/// not assumed: with the tone, planting `gate.open()` BEFORE the start SET
/// still left the first non-silent packet at the 1 s beep, long after the
/// read-back, so the mutant passed. With a source that is loud in every
/// frame, "first non-silent packet" is exactly "the moment the gate opened",
/// so any frame the gate fails to suppress is audible and fails the test.
struct LoudSource {
    clock: Arc<dyn airplay_rs::clock::SenderClock>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    k: u64,
    start_ns: Option<u64>,
    frames: u64,
}

impl LoudSource {
    /// Full-scale square wave: every sample is +/- 24000, never zero, so no
    /// frame can be mistaken for the gate's digital silence.
    fn loud_frame(k: u64) -> [u8; airplay_rs::audio::PCM_FRAME_BYTES] {
        let mut out = [0u8; airplay_rs::audio::PCM_FRAME_BYTES];
        for (j, c) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let s: i16 = if (k as usize + j).is_multiple_of(2) { 24000 } else { -24000 };
            c[0..2].copy_from_slice(&s.to_le_bytes());
            c[2..4].copy_from_slice(&s.to_le_bytes());
        }
        out
    }

    fn new(clock: Arc<dyn airplay_rs::clock::SenderClock>) -> Self {
        LoudSource { clock, stop: Arc::new(std::sync::atomic::AtomicBool::new(false)), k: 0, start_ns: None, frames: 0 }
    }
}

impl airplay_rs::audiocapture::PcmSource for LoudSource {
    fn next_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<airplay_rs::audiocapture::PcmBlock>, airplay_rs::audiocapture::CaptureError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.stop.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(airplay_rs::audiocapture::CaptureError::Stopped);
            }
            let now = self.clock.read().boot().as_nanos() as u64;
            let start = *self.start_ns.get_or_insert(now);
            // Same cadence as ToneSource: one ALAC frame every 352/44100 s.
            let due = start + self.k * 352 * 1_000_000_000 / 44_100;
            if now >= due {
                let pcm = Self::loud_frame(self.k);
                self.k += 1;
                self.frames += 1;
                return Ok(Some(airplay_rs::audiocapture::PcmBlock {
                    pcm,
                    boot_ns: Some(due),
                    mono_ns: None,
                    discontinuity: None,
                }));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(1).min(deadline - Instant::now()));
        }
    }

    fn stopper(&self) -> Box<dyn Fn() + Send + Sync> {
        let s = self.stop.clone();
        Box::new(move || s.store(true, std::sync::atomic::Ordering::SeqCst))
    }

    fn stats(&self) -> airplay_rs::audiocapture::CaptureStats {
        airplay_rs::audiocapture::CaptureStats {
            frames: self.frames,
            buffers: self.frames,
            bytes: self.frames * airplay_rs::audio::PCM_FRAME_BYTES as u64,
            state: if self.stop.load(std::sync::atomic::Ordering::SeqCst) {
                airplay_rs::audiocapture::CaptureState::Stopped
            } else {
                airplay_rs::audiocapture::CaptureState::Streaming
            },
            ..Default::default()
        }
    }

    fn kind(&self) -> &'static str {
        "scripted"
    }
}

/// Bring up a tone session against a fake TV that starts at `tv_db`.
fn tone_session(
    tv_db: f64,
    apply_volume_set: bool,
) -> (FakeAirplayAudioReceiver, FakeRtspReceiver, Session, [u8; 32]) {
    let audio_rx = FakeAirplayAudioReceiver::start();
    let fake = FakeRtspReceiver::start(
        &SHARED,
        Behaviour {
            audio_ports: (audio_rx.data_port, audio_rx.control_port),
            offer_event_port: true,
            volume_db: tv_db,
            apply_volume_set,
            ..Default::default()
        },
    );
    let mut cfg = SessionConfig::new("127.0.0.1");
    cfg.timing_port = free_timing_port();
    cfg.audio = AudioMode::Tone;
    let session = Session::bring_up(fake.connect(), SHARED.to_vec(), &cfg).expect("bring-up against the fake");
    let shk: [u8; 32] = fake
        .requests()
        .iter()
        .find(|r| r.method == "SETUP" && r.stream0().and_then(|s| s.get("type").and_then(|t| t.as_unsigned_integer())) == Some(96))
        .and_then(|r| r.stream0().and_then(|s| s["shk"].as_data().map(|d| d.try_into().unwrap())))
        .expect("audio SETUP with shk");
    (audio_rx, fake, session, shk)
}

/// The TV starts at 0 dB (AirPlay MAXIMUM), the laptop at 17 %. Every audio
/// packet that reaches the TV before the start SET has been read back must
/// be digital silence; the first audible one comes after the read-back.
#[test]
fn blast_proof_no_audible_sample_before_the_start_set_is_read_back() {
    let _serial = one_at_a_time();
    let (audio_rx, fake, session, shk) = tone_session(0.0, true);
    let level = Arc::new(Mutex::new((17u8, false)));
    let (sets, events) = (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(None)));
    let clock = session.clock();
    session.start_audio_with_source(
        Box::new(LoudSource::new(clock)),
        Box::new(FakeLaptop { level, sets, events }),
        timing(),
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("volume armed", 10, || mon.volume().state == "armed");
    // Let real audio flow after the gate opened. Every frame of LoudSource is
    // audible, so the first non-silent packet IS the moment the gate opened.
    std::thread::sleep(Duration::from_millis(300));
    let rep = mon.report();
    assert!(rep.gate_open, "gate opened once the volume was read back");
    // Everything from here on is shutdown: the gate is deliberately HELD
    // again when volume sync stops, so those tail packets are silent by
    // design and are not part of the "is the source always loud" self-check.
    let stream_until = fake_audio::boottime_secs();
    session.shutdown();
    let (_control, data) = audio_rx.finish();

    let vol: Vec<fake_rtsp::Req> = fake.requests().into_iter().filter(|r| r.method.ends_with("_PARAMETER")).collect();
    let kinds: Vec<&str> = vol.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(kinds, ["GET_PARAMETER", "SET_PARAMETER", "GET_PARAMETER"]);
    assert_eq!(vol[1].body, b"volume: -24.900000\r\n", "17 % -> -24.9 dB, not the TV's 0 dB");
    let (set_at, readback_at) = (vol[1].at, vol[2].at);

    let pcm: Vec<(f64, bool)> =
        data.iter().map(|d| (d.at, is_silent(&decrypt(&d.bytes, &shk).expect("decrypts").pcm))).collect();
    let first_real = pcm.iter().position(|(_, silent)| !silent).expect("real audio after the gate opened");
    assert!(first_real > 0, "silence was streamed while the volume was being set");
    assert!(rep.silenced_frames > 0);
    assert!(pcm[..first_real].iter().all(|(_, s)| *s));
    let first_real_at = pcm[first_real].0;
    assert!(
        first_real_at > readback_at && readback_at > set_at,
        "first audible packet at {first_real_at}, start SET at {set_at}, read-back GET at {readback_at}"
    );
    assert!(pcm.iter().filter(|(at, _)| *at <= readback_at).all(|(_, s)| *s), "an audible packet preceded the read-back");
    // Self-check that the proof is not vacuous: the source is loud in EVERY
    // frame, so everything from the gate opening on must be non-silent. If
    // this ever fails the source has quiet stretches again and "first
    // non-silent packet" would no longer mean "the gate opened".
    let loud_window: Vec<bool> =
        pcm[first_real..].iter().filter(|(at, _)| *at < stream_until).map(|(_, s)| *s).collect();
    assert!(loud_window.len() > 10, "too few packets to judge: {}", loud_window.len());
    assert!(
        loud_window.iter().all(|s| !*s),
        "the source must be audible in EVERY frame between the gate opening and shutdown, \
         or 'first non-silent packet' would not mean 'the gate opened' and this proof would be vacuous"
    );
    eprintln!(
        "blast-proof: {} silent packets, then first audible at +{:.3}s after the read-back GET (SET at {set_at:.3}, GET at {readback_at:.3})",
        first_real,
        first_real_at - readback_at
    );
}

/// A deaf TV (acknowledges the SET, never applies it; still at 0 dB): the
/// volume is never established, so the whole session stays SILENT and says so.
#[test]
fn blast_proof_a_tv_that_ignores_the_set_gets_only_silence() {
    let _serial = one_at_a_time();
    let (audio_rx, fake, session, shk) = tone_session(0.0, false);
    let level = Arc::new(Mutex::new((17u8, false)));
    let (sets, events) = (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(None)));
    let clock = session.clock();
    session.start_audio_with_source(
        Box::new(LoudSource::new(clock)),
        Box::new(FakeLaptop { level, sets: sets.clone(), events }),
        timing(),
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("volume failure", 10, || mon.volume().state.starts_with("error"));
    std::thread::sleep(Duration::from_millis(400));
    let st = mon.volume().state;
    assert!(st.contains("not established") && st.contains("silent"), "{st}");
    assert!(!mon.report().gate_open);
    assert!(mon.report().rtp_sent > 0, "the stream (of silence) kept flowing");
    session.shutdown();
    let (_c, data) = audio_rx.finish();
    assert!(!data.is_empty());
    for d in &data {
        assert!(is_silent(&decrypt(&d.bytes, &shk).unwrap().pcm), "an audible packet reached a TV at an unknown level");
    }
    let bodies: Vec<Vec<u8>> =
        fake.requests().into_iter().filter(|r| r.method == "SET_PARAMETER").map(|r| r.body).collect();
    assert_eq!(bodies, vec![b"volume: -24.900000\r\n".to_vec(); 2], "one SET, one retry, never 0 dB");
    assert!(sets.lock().unwrap().is_empty(), "the laptop was never written");
}

/// A laptop whose default output can switch (as PactlVolume follows it).
struct SwitchingLaptop {
    inner: FakeLaptop,
    switched: Arc<Mutex<bool>>,
}

impl LaptopVolume for SwitchingLaptop {
    fn read(&mut self) -> io::Result<LaptopLevel> {
        self.inner.read()
    }
    fn set(&mut self, pct: u8, muted: bool) -> io::Result<()> {
        self.inner.set(pct, muted)
    }
    fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>> {
        self.inner.subscribe()
    }
    fn refresh_target(&mut self) -> bool {
        std::mem::replace(&mut *self.switched.lock().unwrap(), false)
    }
    fn describe(&self) -> String {
        "fake switching laptop".into()
    }
}

/// Mid-session the default output switches to a sink at 100 % (e.g. BT
/// headphones). That is not a key press: nothing may be sent, least of all
/// 0 dB. A later key press on the new sink is sent as its own level.
#[test]
fn blast_proof_a_sink_switch_to_100_percent_never_sets_the_tv_to_0db() {
    let _serial = one_at_a_time();
    let (audio_rx, fake, session, _shk) = tone_session(-20.4, true);
    let level = Arc::new(Mutex::new((40u8, false)));
    let (sets, events) = (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(None)));
    let switched = Arc::new(Mutex::new(false));
    session.start_audio_with(
        Box::new(SwitchingLaptop {
            inner: FakeLaptop { level: level.clone(), sets: sets.clone(), events: events.clone() },
            switched: switched.clone(),
        }),
        timing(),
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("volume armed", 10, || mon.volume().state == "armed");
    let n_sets = || fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count();
    assert_eq!(n_sets(), 1);

    // The switch: new sink reads 100 % unmuted.
    *level.lock().unwrap() = (100, false);
    *switched.lock().unwrap() = true;
    events.lock().unwrap().as_ref().unwrap().send(LaptopEvent::DefaultChanged).unwrap();
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(n_sets(), 1, "a sink switch sent a SET to the TV");
    assert_eq!(*fake.volume_db.lock().unwrap(), -18.0, "TV still at the laptop's old 40 %");

    // A real key press on the new sink: 95 % -> -1.5 dB (not 0 dB).
    *level.lock().unwrap() = (95, false);
    events.lock().unwrap().as_ref().unwrap().send(LaptopEvent::Change).unwrap();
    wait_for("SET for the key press", 5, || n_sets() == 2);
    assert_eq!(*fake.volume_db.lock().unwrap(), -1.5);
    session.shutdown();
    let _ = audio_rx.finish();
    assert!(
        fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").all(|r| r.body != b"volume: 0.000000\r\n"),
        "0 dB was sent without a 100 % key press"
    );
    assert!(sets.lock().unwrap().is_empty());
}

/// No offline session may ever publish a real PipeWire sink.
///
/// The sink is created on the `None => match rt.mode` arm of
/// `start_audio_inner`, never on the `src_override` branch these tests inject
/// through — but that is a structural guarantee, and this is the alarm that
/// goes off if it ever stops being true. A sink created here would publish a
/// node on the user's machine and take his default output in the middle of
/// `cargo test`.
///
/// Deterministic: the counter is process-wide, and needs neither PipeWire nor
/// `pactl` to be installed.
#[test]
fn offline_sessions_publish_no_sink() {
    assert_eq!(airplay_rs::audiosink::published_in_this_process(), 0, "before");
    let (audio_rx, _fake, session, _shk) = tone_session(-20.0, true);
    let level = Arc::new(Mutex::new((40u8, false)));
    let (sets, events) = (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(None)));
    let clock = session.clock();
    session.start_audio_with_source(
        Box::new(LoudSource::new(clock)),
        Box::new(FakeLaptop { level, sets, events }),
        timing(),
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("volume armed", 10, || mon.volume().state == "armed");
    session.shutdown();
    let _ = audio_rx.finish();
    assert_eq!(
        airplay_rs::audiosink::published_in_this_process(),
        0,
        "an offline loopback session published a PipeWire sink"
    );
}

/// A laptop bound to one sink the sender owns — what `PactlVolume::for_sink`
/// is in sink mode — whose "is it still the output?" answer can be flipped.
struct FixedLaptop {
    inner: FakeLaptop,
    sink: String,
    is_default: Arc<std::sync::atomic::AtomicBool>,
}

impl LaptopVolume for FixedLaptop {
    fn read(&mut self) -> io::Result<LaptopLevel> {
        self.inner.read()
    }
    fn set(&mut self, pct: u8, muted: bool) -> io::Result<()> {
        self.inner.set(pct, muted)
    }
    fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>> {
        self.inner.subscribe()
    }
    fn bound_sink(&self) -> Option<&str> {
        Some(&self.sink)
    }
    fn still_default(&mut self) -> Option<bool> {
        Some(self.is_default.load(std::sync::atomic::Ordering::SeqCst))
    }
    fn describe(&self) -> String {
        format!("fake laptop fixed to {}", self.sink)
    }
}

/// Sink mode, mid-session: the user picks another output himself.
///
/// The session keeps its picture, but the AirPlay sink is no longer where
/// the sound goes, so every sample from that moment on must be digital
/// silence again — and nothing may be sent to the TV, least of all the
/// 100 % (= 0 dB, AirPlay MAXIMUM) that the new output happens to read.
#[test]
fn blast_proof_leaving_the_airplay_output_holds_the_gate_and_sends_nothing() {
    let _serial = one_at_a_time();
    let (audio_rx, fake, session, shk) = tone_session(-20.4, true);
    let level = Arc::new(Mutex::new((40u8, false)));
    let (sets, events) = (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(None)));
    let is_default = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let clock = session.clock();
    session.start_audio_with_source(
        Box::new(LoudSource::new(clock)),
        Box::new(FixedLaptop {
            inner: FakeLaptop { level: level.clone(), sets: sets.clone(), events: events.clone() },
            sink: "airplay-sink.test".into(),
            is_default: is_default.clone(),
        }),
        timing(),
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("volume armed", 10, || mon.volume().state == "armed");
    // Bounded wait, not a bare assert: the driver opens the gate and arms
    // `arm_grace` (100 ms) later, but the SENDER republishes its report only
    // every 200 ms — so "armed" can be visible up to ~200 ms before
    // `report().gate_open` catches up. A bare assert here fails about one run
    // in eight. This still fails if the gate never opens.
    wait_for("the gate open in the sender's report", 10, || mon.report().gate_open);
    std::thread::sleep(Duration::from_millis(200));
    let n_sets = || fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count();
    assert_eq!(n_sets(), 1, "the start SET, and only that");

    // The user moves his output elsewhere; the new output happens to read
    // 100 % unmuted, which would be 0 dB if anything ever sent it.
    *level.lock().unwrap() = (100, false);
    is_default.store(false, std::sync::atomic::Ordering::SeqCst);
    events.lock().unwrap().as_ref().unwrap().send(LaptopEvent::DefaultChanged).unwrap();
    wait_for("detached", 10, || mon.volume().state.starts_with("detached"));
    let detached_at = fake_audio::boottime_secs();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!mon.report().gate_open, "the gate must be held once the sound is not going to the TV");
    assert_eq!(n_sets(), 1, "a detached session sent the TV a level");

    session.shutdown();
    let (_control, data) = audio_rx.finish();
    let pcm: Vec<(f64, bool)> =
        data.iter().map(|d| (d.at, is_silent(&decrypt(&d.bytes, &shk).expect("decrypts").pcm))).collect();
    assert!(
        pcm.iter().any(|(at, s)| *at < detached_at && !*s),
        "the proof is vacuous unless real audio was flowing before the output was changed"
    );
    let after: Vec<bool> = pcm.iter().filter(|(at, _)| *at > detached_at).map(|(_, s)| *s).collect();
    assert!(after.len() > 10, "too few packets after the change to judge: {}", after.len());
    assert!(after.iter().all(|s| *s), "an audible packet reached the TV after the output was taken away");
    assert!(
        fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").all(|r| r.body != b"volume: 0.000000\r\n"),
        "0 dB (AirPlay MAX) was sent to the TV"
    );
    assert!(sets.lock().unwrap().is_empty(), "the laptop was written");
    assert!(
        mon.volume().state.contains("output was changed"),
        "the status must say why the TV went quiet: {}",
        mon.volume().state
    );
}

/// A laptop whose level cannot be read at all — `pactl` missing, the daemon
/// restarting, the sink gone between resolve and read.
struct UnreadableLaptop {
    /// Held so the change feed is open rather than already disconnected: the
    /// property under test is what a failed READ does, and a dead feed would
    /// be a second, different reason to stop.
    _tx: Option<Sender<LaptopEvent>>,
}

impl LaptopVolume for UnreadableLaptop {
    fn read(&mut self) -> io::Result<LaptopLevel> {
        Err(io::Error::other("pactl: connection refused"))
    }
    fn set(&mut self, _pct: u8, _muted: bool) -> io::Result<()> {
        panic!("a laptop that cannot be read must never be written");
    }
    fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>> {
        let (tx, rx) = mpsc::channel();
        self._tx = Some(tx);
        Ok(rx)
    }
    fn describe(&self) -> String {
        "fake laptop that cannot be read".into()
    }
}

/// If the laptop's level cannot be read, the TV is never told a level — and
/// the gate stays shut for the whole session.
///
/// The gap this closes was found by mutation, not by reading: replacing the
/// `fail_silent` on this path with `set_state` + `gate.open()` — i.e. "carry
/// on, at whatever the TV is already set to" — left every blast proof in this
/// file GREEN. Every one of them drives a laptop that answers. This is the
/// only one that does not, and the whole start sequence's promise ("nothing
/// audible until the TV's level has been established from the laptop's")
/// rests on the failing case as much as on the working one: the TV's own
/// level has been seen at 100 % on the Frame.
#[test]
fn blast_proof_a_laptop_that_cannot_be_read_never_opens_the_gate() {
    let _serial = one_at_a_time();
    let (audio_rx, fake, session, shk) = tone_session(-20.0, true);
    let clock = session.clock();
    session.start_audio_with_source(
        Box::new(LoudSource::new(clock)),
        Box::new(UnreadableLaptop { _tx: None }),
        timing(),
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("the driver to give up on the laptop", 10, || {
        mon.volume().state.starts_with("disabled: cannot read the laptop volume")
    });
    // Long enough for the whole start sequence to have run twice over.
    std::thread::sleep(Duration::from_millis(400));
    assert!(!mon.report().gate_open, "the gate opened although the laptop level was never read");

    session.shutdown();
    let (_control, data) = audio_rx.finish();
    assert!(data.len() > 10, "too few packets to judge: {}", data.len());
    assert!(
        data.iter().all(|d| is_silent(&decrypt(&d.bytes, &shk).expect("decrypts").pcm)),
        "an audible packet reached the TV although the laptop level was never read"
    );
    assert!(
        fake.requests().iter().all(|r| r.method != "SET_PARAMETER"),
        "the TV was sent a level derived from a laptop read that failed"
    );
    assert!(
        mon.volume().state.contains("audio held silent"),
        "the status must say the audio is being held: {}",
        mon.volume().state
    );
}

// --------------------------------------------------------------------------
// Sink mode at SESSION level
//
// Everything the sink model promises is carried by three fields of the
// `SinkBinding` the session hands the volume driver: `require_sink`,
// `on_open` and `on_detach`. The other blast proofs cannot reach them —
// they all inject a source, and the injecting arm deliberately never
// publishes a sink (that would put a real node on the user's machine and take his
// output in the middle of `cargo test`), so the binding is always the empty
// default. `start_audio_with_source_and_binding` is the seam that lets the
// same rig carry a binding, so these proofs run with no PipeWire, no sink,
// no receiver and no sound.
// --------------------------------------------------------------------------

/// A laptop transport bound to one named sink, as `PactlVolume::for_sink` is
/// in sink mode, whose "is it still the output?" and "which output is it?"
/// answers can both be driven.
struct SinkLaptop {
    inner: FakeLaptop,
    /// What the transport is really bound to — the name the driver checks
    /// `require_sink` against.
    bound: String,
    output: Arc<Mutex<String>>,
}

impl LaptopVolume for SinkLaptop {
    fn read(&mut self) -> io::Result<LaptopLevel> {
        self.inner.read()
    }
    fn set(&mut self, pct: u8, muted: bool) -> io::Result<()> {
        self.inner.set(pct, muted)
    }
    fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>> {
        self.inner.subscribe()
    }
    fn bound_sink(&self) -> Option<&str> {
        Some(&self.bound)
    }
    fn still_default(&mut self) -> Option<bool> {
        Some(*self.output.lock().unwrap() == self.bound)
    }
    fn current_default(&mut self) -> Option<String> {
        Some(self.output.lock().unwrap().clone())
    }
    fn describe(&self) -> String {
        format!("fake laptop fixed to {}", self.bound)
    }
}

const OUR_SINK: &str = "airplay-sink.test_frame";

/// What the rig hands back with a [`SinkLaptop`]: the levels it was told to
/// write (must stay empty in sink mode), and the output it reports being on.
type SinkLaptopRig = (SinkLaptop, Arc<Mutex<Vec<(u8, bool)>>>, Arc<Mutex<String>>);

fn sink_laptop(pct: u8, output: &str) -> SinkLaptopRig {
    let sets = Arc::new(Mutex::new(vec![]));
    let out = Arc::new(Mutex::new(output.to_string()));
    let l = SinkLaptop {
        inner: FakeLaptop {
            level: Arc::new(Mutex::new((pct, false))),
            sets: sets.clone(),
            events: Arc::new(Mutex::new(None)),
        },
        bound: OUR_SINK.into(),
        output: out.clone(),
    };
    (l, sets, out)
}

/// A session whose volume transport is NOT bound to the sink it published
/// must never read or write a level, and must never make a sound.
///
/// This is the case the session's own construction cannot produce today, and
/// exactly the one a future wiring slip would: `rt.sink` unexpectedly `None`
/// in sink mode gives `PactlVolume::follow_output()`, pointed at the user's
/// hardware output, and a `dvlc` from the TV remote then writes his
/// speakers. The driver's binding check is the barrier; nothing offline
/// proved it was armed through a `Session`, and neutering it left every test
/// green.
#[test]
fn blast_proof_a_session_bound_to_the_wrong_sink_sends_nothing() {
    let _serial = one_at_a_time();
    let (audio_rx, fake, session, shk) = tone_session(-20.4, true);
    let (laptop, sets, _out) = sink_laptop(40, "alsa_output.speakers");
    let opened = Arc::new(Mutex::new(0u32));
    let (o, clock) = (opened.clone(), session.clock());
    session.start_audio_with_source_and_binding(
        Box::new(LoudSource::new(clock)),
        // Bound to OUR_SINK; the session demands a DIFFERENT one.
        Box::new(laptop),
        timing(),
        airplay_rs::volume::SinkBinding {
            require_sink: Some("airplay-sink.some_other_receiver".into()),
            expected_default: None,
            on_open: Some(Box::new(move || {
                *o.lock().unwrap() += 1;
                Ok(())
            })),
            on_detach: None,
        },
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("the driver to refuse", 10, || mon.volume().state.starts_with("disabled: not bound"));
    std::thread::sleep(Duration::from_millis(500));

    assert!(!mon.report().gate_open, "the gate must stay shut when the binding is wrong");
    assert_eq!(*opened.lock().unwrap(), 0, "the output was handed over on a binding the driver rejected");
    assert!(mon.report().rtp_sent > 0, "the stream (of silence) must keep flowing");
    session.shutdown();
    let (_c, data) = audio_rx.finish();

    assert!(
        fake.requests().iter().all(|r| !r.method.ends_with("_PARAMETER")),
        "a wrongly-bound session touched the TV's volume"
    );
    assert!(sets.lock().unwrap().is_empty(), "a wrongly-bound session wrote a laptop volume");
    assert!(!data.is_empty(), "nothing was sent at all, so this proves nothing");
    for d in &data {
        assert!(is_silent(&decrypt(&d.bytes, &shk).unwrap().pcm), "an audible packet left a wrongly-bound session");
    }
    let st = mon.volume().state;
    assert!(st.contains("airplay-sink.some_other_receiver") && st.contains("silent"), "{st}");
}

/// The handover happens at the instant the gate opens — not at publish, not
/// before the TV's level is established — and exactly once.
///
/// Taking the output any earlier would leave several seconds in which the
/// speakers are already silent and the TV is still gated: audio audible
/// nowhere. Taking it later, or twice, would fight whatever the user did in the
/// meantime.
#[test]
fn the_output_is_handed_over_once_at_the_moment_the_gate_opens() {
    let _serial = one_at_a_time();
    let (audio_rx, fake, session, shk) = tone_session(-20.4, true);
    let (laptop, sets, out) = sink_laptop(40, OUR_SINK);
    let events = laptop.inner.events.clone();
    let opens: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(vec![]));
    let detaches = Arc::new(Mutex::new(0u32));
    let (o, d, clock) = (opens.clone(), detaches.clone(), session.clock());
    session.start_audio_with_source_and_binding(
        Box::new(LoudSource::new(clock)),
        Box::new(laptop),
        timing(),
        airplay_rs::volume::SinkBinding {
            require_sink: Some(OUR_SINK.into()),
            expected_default: None,
            on_open: Some(Box::new(move || {
                o.lock().unwrap().push(fake_audio::boottime_secs());
                Ok(())
            })),
            on_detach: Some(Box::new(move || *d.lock().unwrap() += 1)),
        },
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("volume armed", 10, || mon.volume().state == "armed");
    wait_for("the gate open in the sender's report", 10, || mon.report().gate_open);
    std::thread::sleep(Duration::from_millis(200));
    let handover_at = {
        let o = opens.lock().unwrap();
        assert_eq!(o.len(), 1, "the output must be handed over exactly once, not {} times", o.len());
        o[0]
    };
    assert_eq!(*detaches.lock().unwrap(), 0, "nothing was taken away, so nothing may be detached");

    // Now the user picks another output himself: detached once, silent from then
    // on, and the session never takes it back.
    *out.lock().unwrap() = "alsa_output.headphones".into();
    events.lock().unwrap().as_ref().unwrap().send(LaptopEvent::DefaultChanged).unwrap();
    wait_for("detached", 10, || mon.volume().state.starts_with("detached"));
    let detached_at = fake_audio::boottime_secs();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(*detaches.lock().unwrap(), 1, "the detach hook must fire exactly once");
    assert_eq!(opens.lock().unwrap().len(), 1, "the output was taken BACK after the user moved it");
    assert!(!mon.report().gate_open);

    session.shutdown();
    let (_c, data) = audio_rx.finish();
    let pcm: Vec<(f64, bool)> =
        data.iter().map(|d| (d.at, is_silent(&decrypt(&d.bytes, &shk).expect("decrypts").pcm))).collect();
    // Nothing audible before the output was ours...
    assert!(
        pcm.iter().filter(|(at, _)| *at <= handover_at).all(|(_, s)| *s),
        "an audible packet reached the TV before the output was handed over"
    );
    // ...and the proof is not vacuous: real audio did flow afterwards.
    assert!(
        pcm.iter().any(|(at, s)| *at > handover_at && *at < detached_at && !*s),
        "no real audio ever flowed, so the ordering above proves nothing"
    );
    let after: Vec<bool> = pcm.iter().filter(|(at, _)| *at > detached_at).map(|(_, s)| *s).collect();
    assert!(after.len() > 5, "too few packets after the change to judge: {}", after.len());
    assert!(after.iter().all(|s| *s), "an audible packet reached the TV after the output was taken away");
    assert_eq!(fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count(), 1, "the start SET, and only that");
    assert!(sets.lock().unwrap().is_empty(), "the laptop was written");
}

/// A handover that FAILS costs the user nothing: the gate stays shut, the session
/// is silent, the laptop keeps its output, and the failure is on the status.
///
/// In production this is `take_default()` reporting that the output is not
/// ours — the one moment the session could leave the speakers silent AND the
/// TV playing at an unknown level.
#[test]
fn blast_proof_a_failed_handover_holds_the_gate_and_keeps_the_speakers() {
    let _serial = one_at_a_time();
    let (audio_rx, fake, session, shk) = tone_session(-20.4, true);
    let (laptop, sets, _out) = sink_laptop(40, OUR_SINK);
    let detaches = Arc::new(Mutex::new(0u32));
    let (d, clock) = (detaches.clone(), session.clock());
    session.start_audio_with_source_and_binding(
        Box::new(LoudSource::new(clock)),
        Box::new(laptop),
        timing(),
        airplay_rs::volume::SinkBinding {
            require_sink: Some(OUR_SINK.into()),
            expected_default: None,
            on_open: Some(Box::new(|| Err("the default output reads \"alsa_output.speakers\"".into()))),
            on_detach: Some(Box::new(move || *d.lock().unwrap() += 1)),
        },
    );
    let mon = session.audio_monitor().unwrap();
    wait_for("the handover to fail", 10, || mon.volume().state.starts_with("error"));
    std::thread::sleep(Duration::from_millis(400));
    let st = mon.volume().state;
    assert!(st.contains("hand the output") && st.contains("silent"), "{st}");
    assert!(!mon.report().gate_open, "the gate must be held when the output was not taken");
    assert!(mon.report().rtp_sent > 0, "the stream (of silence) must keep flowing");
    assert_eq!(*detaches.lock().unwrap(), 0, "nothing was taken, so nothing may be disowned");

    session.shutdown();
    let (_c, data) = audio_rx.finish();
    assert!(!data.is_empty());
    for x in &data {
        assert!(
            is_silent(&decrypt(&x.bytes, &shk).unwrap().pcm),
            "an audible packet reached the TV although the speakers still had the output"
        );
    }
    assert!(sets.lock().unwrap().is_empty(), "the laptop was written after a failed handover");
    // The start SET did go out (that is what opens the gate); nothing after.
    assert_eq!(fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count(), 1);
}
