//! Live audio-capture tests against the running PipeWire. `#[ignore]`d; run
//! explicitly, one at a time:
//!
//! ```text
//! mise exec -- cargo test --release --test audio_capture_live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! SILENT AND NON-INVASIVE BY CONSTRUCTION (hard rule 2):
//! * Every test snapshots the default sink, the default source and the
//!   default sink's volume/mute first and asserts them identical at the end
//!   (and right after each null sink is loaded).
//! * Audio only ever flows into null sinks this test loads itself
//!   (`airplay_test_<pid>_<tag>`, `priority.session=0`), unloaded by module
//!   index in a Drop guard. Nothing reaches a real device.
//! * The player is `pw-cat` pinned to that sink with `node.dont-move`,
//!   `node.dont-fallback` and `node.dont-reconnect`; it plays SILENCE first,
//!   and the test verifies in `pw-dump` that its only links go to our null
//!   sink before any signal is written. Signals peak at 300/32768 (-40.8 dBFS).
//! * Captures are pinned to our own sinks (`target.object`, test-only, with
//!   `node.dont-fallback`), and their links are verified the same way. No test
//!   captures the user's real default monitor.
//! * The only volume ever changed is our own null sink's.
//!
//! No AirPlay receiver is contacted.

#[path = "support/fake_audio_receiver.rs"]
mod fake;

/// The rule-2 scaffolding and signal analysis, shared with
/// `audio_sink_live.rs`. This file keeps its own `Untouched`/`AudioSnapshot`
/// (they shadow the glob): these tests legitimately load and unload a null
/// sink mid-run, so their snapshot must not include the module list.
#[path = "support/audio_rules.rs"]
mod rules;
use rules::*;

use airplay_rs::audiocapture::{
    sink_monitor_is_post_volume, CaptureStats, Discontinuity, ParecSource, PcmBlock, PcmSource,
    PipewireSource, PwCaptureOpts,
};
use airplay_rs::clock::BoottimeClock;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

// --------------------------------------------------------------------------
// Rule-2 guards
// --------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, Clone)]
struct AudioSnapshot {
    default_sink: String,
    default_source: String,
    sink_volume: String,
}

fn snapshot() -> AudioSnapshot {
    AudioSnapshot {
        default_sink: sh("pactl", &["get-default-sink"]),
        default_source: sh("pactl", &["get-default-source"]),
        sink_volume: sh("wpctl", &["get-volume", "@DEFAULT_AUDIO_SINK@"]),
    }
}

/// Holds the "before" snapshot; `check` asserts nothing of the user's changed.
struct Untouched(AudioSnapshot);

impl Untouched {
    fn take() -> Self {
        let s = snapshot();
        println!("snapshot before: {s:?}");
        assert!(!s.default_sink.is_empty(), "no default sink? refusing to run");
        Untouched(s)
    }
    fn check(&self, when: &str) {
        let now = snapshot();
        assert_eq!(now, self.0, "the user's audio state changed ({when})");
        println!("snapshot {when}: identical");
    }
}

struct NullSink {
    name: String,
    module: u32,
}

impl NullSink {
    fn load(tag: &str, extra_props: &str, guard: &Untouched) -> NullSink {
        Self::load_named(&unique(tag), extra_props, guard)
    }

    fn load_named(name: &str, extra_props: &str, guard: &Untouched) -> NullSink {
        let props = format!("node.description={name} priority.session=0 priority.driver=0 {extra_props}");
        let out = Command::new("pactl")
            .args([
                "load-module",
                "module-null-sink",
                &format!("sink_name={name}"),
                "rate=44100",
                "channels=2",
                "format=s16le",
                &format!("sink_properties={props}"),
            ])
            .output()
            .expect("pactl load-module");
        assert!(out.status.success(), "load-module failed: {out:?}");
        let module: u32 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("module index");
        let s = NullSink {
            name: name.to_string(),
            module,
        };
        println!("loaded null sink {name} (module {module})");
        // Wait for the node to exist, then prove it did not become default.
        let t0 = Instant::now();
        while node_id(name).is_none() {
            assert!(t0.elapsed() < Duration::from_secs(3), "sink {name} never appeared");
            std::thread::sleep(Duration::from_millis(20));
        }
        guard.check("after loading a null sink");
        s
    }
}

impl Drop for NullSink {
    fn drop(&mut self) {
        let ok = Command::new("pactl")
            .args(["unload-module", &self.module.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        println!("unloaded null sink {} (module {}): {ok}", self.name, self.module);
    }
}

// --------------------------------------------------------------------------
// Capture helpers and analysis
// --------------------------------------------------------------------------

fn pw_capture(sink: &str) -> PipewireSource {
    capture_with(sink, true)
}

/// A capture pinned to `sink` but NOT carrying the sink-mode safety pin —
/// the shape `--audio-capture pipewire` has, where following the graph is
/// the wanted behaviour.
///
/// `dont_fallback` is what asks for the pin, and the pin now means both of
/// WirePlumber's keys: `node.dont-fallback` AND `node.dont-move`. A capture
/// that is meant to be movable must therefore not set it; a capture that is
/// meant to stay put must, and
/// `a_pinned_capture_refuses_the_same_retarget` proves it does.
fn movable_capture(sink: &str) -> PipewireSource {
    capture_with(sink, false)
}

fn capture_with(sink: &str, dont_fallback: bool) -> PipewireSource {
    let opts = PwCaptureOpts {
        target: Some(sink.to_string()),
        dont_fallback,
        node_name: unique("capture"),
        ..Default::default()
    };
    let src = PipewireSource::new(opts, Arc::new(BoottimeClock)).expect("PipeWire capture");
    assert_ne!(src.node_id(), u32::MAX, "capture node has an id");
    src
}

/// Point `node`'s `target.object` at `sink`, the way pavucontrol's Recording
/// tab and `pactl move-source-output` do (by the target's `object.serial`,
/// which is what WirePlumber matches on). Returns a guard that clears the
/// metadata again, so nothing about our node outlives the test.
fn retarget(node: u32, sink: &str) {
    let serial = pw_dump()
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["info"]["props"]["node.name"].as_str() == Some(sink))
        .and_then(|o| o["info"]["props"]["object.serial"].as_u64())
        .unwrap_or_else(|| panic!("{sink} serial"));
    let out = Command::new("pw-metadata")
        .args([&node.to_string(), "target.object", &serial.to_string(), "Spa:Id"])
        .output()
        .unwrap();
    assert!(out.status.success(), "pw-metadata");
}

fn clear_retarget(node: u32) {
    for key in ["target.object", "target.node"] {
        let _ = Command::new("pw-metadata")
            .args(["-d", &node.to_string(), key])
            .stdout(Stdio::null())
            .status();
    }
}

/// Pull frames for `dur`, with a stats print.
fn collect(src: &mut dyn PcmSource, dur: Duration) -> Vec<PcmBlock> {
    let t0 = Instant::now();
    let mut v = Vec::new();
    while t0.elapsed() < dur {
        match src.next_frame(Duration::from_millis(50)) {
            Ok(Some(b)) => v.push(b),
            Ok(None) => {}
            Err(e) => panic!("capture error: {e}"),
        }
    }
    v
}

fn print_stats(s: &CaptureStats) {
    println!("capture stats: {s:?}");
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[test]
#[ignore = "needs PipeWire; loads its own silent null sink"]
fn pipewire_capture_own_null_sink_matches_signal() {
    let guard = Untouched::take();
    {
        let sink = NullSink::load("sig", "", &guard);
        let mut cap = pw_capture(&sink.name);
        assert_linked_only_to(cap.node_id() as u64, &sink.name, "capture");
        let mut player = Player::start(&sink.name);
        player.preroll_and_verify(&sink.name, 0.4);
        let reference = chirp(2.0);
        let bytes = to_bytes(&reference);
        let writer = std::thread::spawn(move || {
            player.write(&bytes);
            player.write(&vec![0u8; RATE * 4 / 2]);
            player
        });
        let blocks = collect(&mut cap, Duration::from_millis(3600));
        let player = writer.join().unwrap();
        drop(player);
        print_stats(&cap.stats());
        let pcm = samples(&blocks);
        let m = align_and_compare(&reference, &pcm);
        println!(
            "frames {} | signal at frame {:.2} | max |err| {} LSB | rms err {:.3} LSB | exact {}/{}",
            blocks.len(),
            m.delay_frames,
            m.max_err,
            m.rms_err,
            m.exact,
            m.compared
        );
        // Every block is a whole frame and timestamps are monotonic, ~8 ms apart.
        let stamps: Vec<u64> = blocks.iter().filter_map(|b| b.boot_ns).collect();
        assert_eq!(stamps.len(), blocks.len(), "every PipeWire frame is stamped");
        assert!(stamps.windows(2).all(|w| w[1] >= w[0]), "stamps monotonic");
        let span_s = (stamps[stamps.len() - 1] - stamps[0]) as f64 / 1e9;
        let rate = (blocks.len() - 1) as f64 * 352.0 / span_s;
        println!("stamp-derived capture rate {rate:.1} Hz over {span_s:.2} s");
        assert!((rate - 44100.0).abs() < 441.0, "rate {rate}");
        // The whole 2 s chirp is present, sample-continuous and in the right
        // channels. The graph may run at 48 kHz (two resamples), so exactness
        // is reported rather than required; the tolerance is 1.5 % of full
        // signal amplitude, far below what a dropped or duplicated sample or a
        // channel swap would produce (hundreds of LSB).
        assert!(m.max_err <= 4, "max error {} LSB", m.max_err);
        let disc: Vec<_> = blocks.iter().filter_map(|b| b.discontinuity).collect();
        println!("discontinuities during steady capture: {disc:?}");
        assert!(disc.is_empty(), "steady capture flagged {disc:?}");
        drop(cap);
    }
    guard.check("at end");
}

#[test]
#[ignore = "needs PipeWire; loads two silent null sinks"]
fn pipewire_capture_follows_a_retarget_and_flags_it() {
    // Stand-in for "the default sink changed": WirePlumber moves our capture
    // stream from sink A's monitor to sink B's. We move it by setting OUR
    // node's target.object metadata (as pavucontrol would) — the default
    // sink is never touched.
    let guard = Untouched::take();
    {
        let a = NullSink::load("a", "", &guard);
        let b = NullSink::load("b", "", &guard);
        // The MOVABLE shape (`--audio-capture pipewire`): this test is about
        // what the layer above does when a relink happens, which is a real
        // event on that path. The sink-mode capture refuses the identical
        // move by design — see `a_pinned_capture_refuses_the_same_retarget`.
        let mut cap = movable_capture(&a.name);
        let node = cap.node_id();
        assert_linked_only_to(node as u64, &a.name, "capture");
        let mut player = Player::start(&b.name);
        player.preroll_and_verify(&b.name, 0.4);
        // 4 s of chirp into B, looping, while we sit on A (silence).
        let reference = chirp(1.0);
        let bytes = to_bytes(&reference);
        let writer = std::thread::spawn(move || {
            for _ in 0..4 {
                player.write(&bytes);
            }
            player
        });
        let mut blocks = collect(&mut cap, Duration::from_millis(800));
        let before = blocks.len();
        assert!(samples(&blocks).iter().all(|&s| s == 0), "sink A is silent");
        // Move OUR node only: its target.object in the default metadata,
        // by the target's object.serial (what WirePlumber matches on).
        retarget(node, &b.name);
        let moved_at = Instant::now();
        blocks.extend(collect(&mut cap, Duration::from_millis(1500)));
        // Links BEFORE clearing the metadata (clearing it moves us back to A).
        let after_links = links_of(node as u64);
        // Clear the move so no metadata about our node outlives the test.
        clear_retarget(node);
        println!("links after move: {after_links:?}");
        assert!(
            after_links.iter().all(|(o, i)| o == &b.name || i == &b.name) && !after_links.is_empty(),
            "capture must now be on B only"
        );
        let player = writer.join().unwrap();
        drop(player);
        let st = cap.stats();
        print_stats(&st);
        let flagged: Vec<(usize, Discontinuity)> = blocks
            .iter()
            .enumerate()
            .filter_map(|(i, b)| b.discontinuity.map(|d| (i, d)))
            .collect();
        println!("frames before move {before}, total {}, flagged {flagged:?}", blocks.len());
        let first_signal = blocks
            .iter()
            .position(|b| b.pcm.chunks(4).any(|f| i16::from_le_bytes([f[0], f[1]]).unsigned_abs() > 20))
            .expect("B's signal reached the capture after the move");
        assert!(first_signal >= before, "signal only after the move");
        // The move is visible to the layer above: flagged at or before the
        // first frame carrying B's audio.
        assert!(!flagged.is_empty(), "relink not flagged");
        assert!(flagged[0].0 >= before && flagged[0].0 <= first_signal, "{flagged:?} vs {first_signal}");
        // Largest gap between consecutive frame stamps around the move.
        let stamps: Vec<u64> = blocks.iter().filter_map(|b| b.boot_ns).collect();
        let max_gap = stamps.windows(2).map(|w| w[1].saturating_sub(w[0])).max().unwrap();
        println!(
            "relink: max stamp gap {:.1} ms; relink flagged on frame {}, first frame with B's signal {} ({:?} since the move, at print time)",
            max_gap as f64 / 1e6,
            flagged[0].0,
            first_signal,
            moved_at.elapsed()
        );
        drop(cap);
    }
    guard.check("at end");
}

/// The other half of the retarget story, and the one that matters in sink
/// mode: a capture that carries the pin must REFUSE the identical move.
///
/// `PwCaptureOpts::dont_fallback` promises the capture can never end up on
/// anything but its target — "if our own sink is gone the session is over,
/// and silently capturing the desk speakers instead would send the room to the
/// TV". `node.dont-fallback` alone does not deliver that: WirePlumber
/// consults it only when the pinned target fails to RESOLVE
/// (`linking/find-defined-target.lua:116`). A targeted move resolves fine,
/// and is refused only by `node.dont-move`
/// (`find-defined-target.lua:55-69`). Here sink B stands for the desk speakers.
#[test]
#[ignore = "needs PipeWire; loads two silent null sinks"]
fn a_pinned_capture_refuses_the_same_retarget() {
    let guard = Untouched::take();
    {
        let a = NullSink::load("pin_a", "", &guard);
        let b = NullSink::load("pin_b", "", &guard);
        // Production's sink-mode options, `dont_fallback` and all.
        let mut cap = pw_capture(&a.name);
        let node = cap.node_id();
        assert_linked_only_to(node as u64, &a.name, "pinned capture");

        // The move that walks straight past `node.dont-fallback`.
        retarget(node, &b.name);
        // Give WirePlumber more than long enough to act on it: the movable
        // capture above has relinked well inside this window.
        let _ = collect(&mut cap, Duration::from_millis(1500));
        let links = links_of(node as u64);
        clear_retarget(node);

        println!("pinned capture links after the move: {links:?}");
        assert!(!links.is_empty(), "the pinned capture lost its links altogether");
        assert!(
            links.iter().all(|(o, i)| o == &a.name || i == &a.name),
            "a pinned capture was retargeted to {}; in a real session that is the desk speakers going to the TV",
            b.name
        );
        assert!(
            links.iter().all(|(o, i)| o != &b.name && i != &b.name),
            "the pinned capture is linked to {} as well",
            b.name
        );
        drop(cap);
    }
    guard.check("at end");
}

#[test]
#[ignore = "needs PipeWire; loads (and reloads) its own silent null sink"]
fn pipewire_capture_reconnects_after_target_disappears() {
    let guard = Untouched::take();
    {
        let name = unique("gone");
        let sink = NullSink::load_named(&name, "", &guard);
        let mut cap = pw_capture(&name);
        assert_linked_only_to(cap.node_id() as u64, &name, "capture");
        let first = collect(&mut cap, Duration::from_millis(500));
        assert!(!first.is_empty(), "frames before removal");
        drop(sink); // target vanishes; dont_fallback => Error, never the user's sink
        let during = collect(&mut cap, Duration::from_millis(1500));
        let mid = cap.stats();
        print_stats(&mid);
        println!("frames while target absent: {}", during.len());
        let sink = NullSink::load_named(&name, "", &guard);
        let after = collect(&mut cap, Duration::from_millis(2500));
        let st = cap.stats();
        print_stats(&st);
        let node = cap.node_id() as u64;
        println!("capture node id now {node}");
        let l = links_of(node);
        println!("links after reload: {l:?}");
        assert!(!after.is_empty(), "frames resume after the sink returns");
        assert!(st.reconnects >= 1, "stream reconnected");
        assert!(
            after.iter().chain(during.iter()).any(|b| b.discontinuity.is_some()),
            "the resume is flagged"
        );
        assert!(!l.is_empty() && l.iter().all(|(o, i)| o == &name || i == &name), "linked, and only to our sink");
        drop(cap);
        drop(sink);
    }
    guard.check("at end");
}

#[test]
#[ignore = "needs PipeWire + pipewire-pulse; loads its own silent null sink"]
fn parec_capture_own_null_sink() {
    let guard = Untouched::take();
    {
        let sink = NullSink::load("parec", "", &guard);
        let mut cap = ParecSource::new(&format!("{}.monitor", sink.name), Arc::new(BoottimeClock))
            .expect("spawn parec");
        // parec's own capture stream links only to our sink.
        let pid = cap.child_pid().expect("parec pid");
        let t0 = Instant::now();
        let parec_node = loop {
            let found = pw_dump().as_array().unwrap().iter().find_map(|o| {
                let p = &o["info"]["props"];
                let is_pid = p["application.process.id"].as_u64() == Some(pid as u64)
                    || p["application.process.id"].as_str() == Some(pid.to_string().as_str());
                (o["type"].as_str()?.ends_with(":Node") && is_pid).then(|| o["id"].as_u64()).flatten()
            });
            if let Some(n) = found {
                break n;
            }
            assert!(t0.elapsed() < Duration::from_secs(3), "parec node never appeared");
            std::thread::sleep(Duration::from_millis(30));
        };
        assert_linked_only_to(parec_node, &sink.name, "parec");
        let mut player = Player::start(&sink.name);
        player.preroll_and_verify(&sink.name, 0.4);
        let reference = chirp(2.0);
        let bytes = to_bytes(&reference);
        let writer = std::thread::spawn(move || {
            player.write(&bytes);
            player.write(&vec![0u8; RATE * 4 / 2]);
            player
        });
        let blocks = collect(&mut cap, Duration::from_millis(3600));
        drop(writer.join().unwrap());
        print_stats(&cap.stats());
        let m = align_and_compare(&reference, &samples(&blocks));
        println!(
            "parec frames {} | max |err| {} LSB | rms {:.3} | exact {}/{}",
            blocks.len(),
            m.max_err,
            m.rms_err,
            m.exact,
            m.compared
        );
        assert!(m.max_err <= 4, "max error {} LSB", m.max_err);
        cap.stopper()();
        drop(cap);
    }
    guard.check("at end");
}

#[test]
#[ignore = "needs PipeWire; loads two silent null sinks and changes only THEIR volume"]
fn monitor_post_volume_detection() {
    let guard = Untouched::take();
    {
        let post = NullSink::load("post", "monitor.channel-volumes=true", &guard);
        let pre = NullSink::load("pre", "monitor.channel-volumes=false", &guard);
        let plain = NullSink::load("plain", "", &guard);
        assert_eq!(sink_monitor_is_post_volume(&post.name), Some(true));
        assert_eq!(sink_monitor_is_post_volume(&pre.name), Some(false));
        // pipewire-pulse's module-null-sink sets monitor.channel-volumes=true
        // itself when not told otherwise (seen in pw-dump); a sink with the
        // property absent (e.g. the ALSA speaker here) reads as false, which is
        // PipeWire's default. Report what this one says.
        let p = sink_monitor_is_post_volume(&plain.name);
        println!("plain pulse null sink post-volume: {p:?}");
        assert!(p.is_some());
        assert_eq!(sink_monitor_is_post_volume("airplay_test_no_such_sink"), None);

        // Empirically: with OUR sink at 50 % volume, the post-volume monitor
        // is attenuated and the pre-volume one is not.
        let mut peaks = Vec::new();
        for s in [&post, &pre] {
            let st = Command::new("pactl")
                .args(["set-sink-volume", &s.name, "50%"])
                .status()
                .unwrap();
            assert!(st.success());
            let mut cap = pw_capture(&s.name);
            assert_linked_only_to(cap.node_id() as u64, &s.name, "capture");
            let mut player = Player::start(&s.name);
            player.preroll_and_verify(&s.name, 0.3);
            let bytes = to_bytes(&chirp(1.0));
            let w = std::thread::spawn(move || {
                player.write(&bytes);
                player
            });
            let blocks = collect(&mut cap, Duration::from_millis(1800));
            drop(w.join().unwrap());
            let peak = samples(&blocks).iter().map(|s| s.unsigned_abs()).max().unwrap_or(0);
            println!("{}: peak {peak} (unattenuated signal peak {})", s.name, AMP as u16);
            peaks.push(peak);
        }
        assert!(peaks[0] < 200, "post-volume monitor attenuated: {}", peaks[0]);
        assert!(peaks[1] >= 295, "pre-volume monitor untouched: {}", peaks[1]);
    }
    guard.check("at end");
}

/// The whole send path with a REAL capture: our own null sink -> PipeWire
/// capture -> the production sender thread -> the fake receiver on
/// 127.0.0.1, which decrypts and un-ALACs every packet; the recovered PCM
/// must match the chirp played into the sink. Silent (null sink, -40.8 dBFS),
/// no AirPlay device.
#[test]
#[ignore = "needs PipeWire; loads its own silent null sink; sends only to 127.0.0.1"]
fn end_to_end_null_sink_to_loopback_receiver() {
    use airplay_rs::audio::{spawn_audio_sender, AudioLatency, AudioSockets, AudioStreamParams};
    let shk = [0x42u8; 32];
    let guard = Untouched::take();
    {
        let sink = NullSink::load("e2e", "", &guard);
        let cap = pw_capture(&sink.name);
        assert_linked_only_to(cap.node_id() as u64, &sink.name, "capture");
        let rx = fake::FakeAirplayAudioReceiver::start();
        let h = spawn_audio_sender(
            AudioStreamParams {
                shk,
                latency: AudioLatency::new(300, 0).unwrap(),
                receiver: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                receiver_data_port: rx.data_port,
                receiver_control_port: rx.control_port,
            },
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(cap),
            Arc::new(BoottimeClock),
            None,
        );
        let mut player = Player::start(&sink.name);
        player.preroll_and_verify(&sink.name, 0.4);
        let reference = chirp(2.0);
        player.write(&to_bytes(&reference));
        player.write(&vec![0u8; RATE * 4 / 2]);
        std::thread::sleep(Duration::from_millis(3200));
        drop(player);
        let rep = h.join(Duration::from_secs(2)).expect("sender joins");
        let (control, data) = rx.finish();
        println!("sender: {rep:?}");
        println!("receiver: {} control, {} data packets", control.len(), data.len());
        assert!(rep.timeline.packets > 300);
        assert_eq!(rep.send_errors, 0);
        // Anchored first, and every packet on time.
        let syncs: Vec<fake::Sync> = control.iter().map(|c| fake::parse_sync(c).unwrap()).collect();
        assert!(syncs[0].first && syncs[0].at <= data[0].at);
        let mut worst = f64::INFINITY;
        let mut pcm: Vec<i16> = Vec::new();
        let mut prev_rtp: Option<u32> = None;
        for d in &data {
            let o = fake::decrypt(&d.bytes, &shk).expect("decrypts");
            if let Some(p) = prev_rtp {
                assert_eq!(o.rtp, p.wrapping_add(352), "rtp contiguous");
            }
            prev_rtp = Some(o.rtp);
            let m = syncs.iter().rfind(|s| s.at <= d.at).unwrap();
            worst = worst.min(m.playout(o.rtp) - d.at);
            pcm.extend(o.pcm.chunks(2).map(|c| i16::from_le_bytes([c[0], c[1]])));
        }
        println!("worst slack {:.1} ms", worst * 1e3);
        assert!(worst >= 0.045, "a packet arrived {:.1} ms before play-out", worst * 1e3);
        let m = align_and_compare(&reference, &pcm);
        println!(
            "recovered: signal at frame {:.2} | max |err| {} LSB | rms {:.3} | exact {}/{}",
            m.delay_frames, m.max_err, m.rms_err, m.exact, m.compared
        );
        assert!(m.max_err <= 4, "max error {} LSB", m.max_err);
    }
    guard.check("at end");
}

/// Wraps a real capture so the test can hold the sender's `next_frame` for
/// `stall` once per arming: the sender sees exactly what a capture that
/// delivers nothing for that long looks like, while the capture keeps running.
struct StallOnDemand {
    inner: Box<dyn PcmSource>,
    arm: Arc<std::sync::atomic::AtomicBool>,
    stall: Duration,
}

impl PcmSource for StallOnDemand {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<PcmBlock>, airplay_rs::audiocapture::CaptureError> {
        if self.arm.swap(false, Ordering::SeqCst) {
            std::thread::sleep(self.stall);
        }
        self.inner.next_frame(timeout)
    }
    fn stopper(&self) -> Box<dyn Fn() + Send + Sync> {
        self.inner.stopper()
    }
    fn stats(&self) -> CaptureStats {
        self.inner.stats()
    }
    fn kind(&self) -> &'static str {
        "stall-wrapper"
    }
}

/// Real capture from our own silent null sink -> the real sender -> the
/// loopback fake receiver, with TWO forced stalls in the silence between two
/// chirps. Stall 1 always holds the sender off the capture for 600 ms; stall
/// 2 is `stall2` (it must stop frames reaching the sender for > 250 ms). Each
/// must re-anchor with a fresh 0x90 that reaches the receiver before the
/// first post-stall RTP; every packet must be on time against the newest sync
/// that had arrived; RTP stays contiguous; and the second chirp must
/// round-trip after both re-anchors.
fn stall_reanchor_run(
    sink: &NullSink,
    src: Box<dyn PcmSource>,
    stall2_what: &str,
    stall2: &dyn Fn(&Arc<std::sync::atomic::AtomicBool>),
) {
    use airplay_rs::audio::{
        spawn_audio_sender, AnchorReason, AudioEvent, AudioLatency, AudioSockets, AudioStreamParams, PERIODIC_STEP_MAX,
    };
    let shk = [0x5au8; 32];
    let arm = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let src = StallOnDemand { inner: src, arm: arm.clone(), stall: Duration::from_millis(600) };
    let rx = fake::FakeAirplayAudioReceiver::start();
    let (etx, erx) = std::sync::mpsc::channel();
    let h = spawn_audio_sender(
        AudioStreamParams {
            shk,
            latency: AudioLatency::new(300, 0).unwrap(),
            receiver: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            receiver_data_port: rx.data_port,
            receiver_control_port: rx.control_port,
        },
        AudioSockets::bind_ephemeral_for_test().unwrap(),
        Box::new(src),
        Arc::new(BoottimeClock),
        Some(etx),
    );
    let mut player = Player::start(&sink.name);
    player.preroll_and_verify(&sink.name, 0.4);
    let a = chirp(1.5);
    let b: Vec<i16> = chirp(1.5).iter().map(|x| -x).collect(); // distinguishable
    let (a2, b2, sname) = (a.clone(), b.clone(), sink.name.clone());
    let writer = std::thread::spawn(move || {
        player.write(&to_bytes(&a2));
        player.write(&vec![0u8; RATE * 4 * 4]); // 4 s of silence: the stalls happen here
        // Before any non-zero sample again: still linked only to our sink.
        let id = node_id(&player.name).expect("player node");
        assert_linked_only_to(id, &sname, "player (before chirp B)");
        player.write(&to_bytes(&b2));
        player.write(&vec![0u8; RATE * 4]);
        player
    });
    let t0 = Instant::now();
    let at = |s: f64| std::thread::sleep(Duration::from_secs_f64(s).saturating_sub(t0.elapsed()));
    at(2.3);
    let boot_stall1 = fake::boottime_secs();
    println!("stall 1 at t={:.2}s: sender held off the capture for 600 ms", t0.elapsed().as_secs_f64());
    arm.store(true, Ordering::SeqCst);
    at(3.6);
    let boot_stall2 = fake::boottime_secs();
    println!("stall 2 at t={:.2}s: {stall2_what}", t0.elapsed().as_secs_f64());
    stall2(&arm);
    let player = writer.join().expect("writer");
    std::thread::sleep(Duration::from_millis(1200));
    drop(player);
    let rep = h.join(Duration::from_secs(2)).expect("sender joins");
    let (control, data) = rx.finish();
    let events: Vec<AudioEvent> = erx.try_iter().collect();
    println!("sender: {rep:?}");
    println!("events: {events:?}");
    println!("receiver: {} control, {} data packets", control.len(), data.len());

    let syncs: Vec<fake::Sync> = control.iter().map(|c| fake::parse_sync(c).unwrap()).collect();
    let anchors: Vec<&fake::Sync> = syncs.iter().filter(|s| s.first).collect();
    println!(
        "0x90 anchors arrived at (boot s): {:?}  [stall 1 began {boot_stall1:.3}, stall 2 began {boot_stall2:.3}]",
        anchors.iter().map(|s| format!("{:.3}", s.at)).collect::<Vec<_>>()
    );
    assert_eq!(rep.send_errors, 0);
    assert!(matches!(events.first(), Some(AudioEvent::FirstPacketSent(_))), "{events:?}");
    let gaps: Vec<Duration> = events
        .iter()
        .filter_map(|e| match e {
            AudioEvent::Anchored(AnchorReason::Gap(d)) => Some(*d),
            _ => None,
        })
        .collect();
    println!("gap re-anchors: {gaps:?}");
    assert_eq!(gaps.len(), 2, "each stall re-anchors exactly once: {events:?}");
    assert!(gaps.iter().all(|g| *g > Duration::from_millis(250)));
    assert_eq!(rep.timeline.gap_reanchors, 2);
    // Every 0x90 on the wire is the first anchor or a COUNTED re-anchor;
    // nothing anchors for a reason the sender did not record. A real capture
    // recovering from a stall may also need a step re-anchor (finding 7:
    // a correction bigger than PERIODIC_STEP_MAX must arrive as a 0x90, not
    // hide inside a silent 0x80), so that count is not fixed -- but it is the
    // only thing allowed to explain a 0x90 beyond the first + the two gaps.
    let t = &rep.timeline;
    assert_eq!(
        anchors.len() as u64,
        1 + t.gap_reanchors + t.late_reanchors + t.forced_reanchors + t.step_reanchors,
        "every 0x90 is the first anchor or a counted re-anchor: {t:?}"
    );
    assert!(anchors.len() >= 3, "first + the two gap re-anchors: {t:?}");
    assert!(anchors.iter().any(|s| s.at > boot_stall1 && s.at < boot_stall2), "stall-1 re-anchor");
    assert!(anchors.iter().any(|s| s.at > boot_stall2), "stall-2 re-anchor");
    assert!(syncs[0].first && syncs[0].at <= data[0].at, "anchored before the first RTP");
    // Finding 7, on real hardware: a periodic 0x80 must never move the
    // receiver's play-out mapping by more than PERIODIC_STEP_MAX. Compare
    // each sync with the one before it on a common RTP. Across a `first`
    // sync any step is allowed -- that IS the anchor, and it is visible.
    for w in syncs.windows(2) {
        if w[1].first {
            continue;
        }
        let step = (w[1].playout(w[0].rtp_now) - w[0].playout(w[0].rtp_now)).abs();
        println!("0x80 step: {:.1} ms", step * 1e3);
        assert!(
            step <= PERIODIC_STEP_MAX.as_secs_f64() + 0.005,
            "a silent 0x80 moved play-out by {:.1} ms (guard {PERIODIC_STEP_MAX:?}): {:?} -> {:?}",
            step * 1e3,
            w[0],
            w[1]
        );
    }

    let mut worst = f64::INFINITY;
    let mut pcm: Vec<i16> = Vec::new();
    let mut prev_rtp: Option<u32> = None;
    let mut first_after: [Option<(usize, f64)>; 2] = [None, None];
    for (i, d) in data.iter().enumerate() {
        let o = fake::decrypt(&d.bytes, &shk).expect("decrypts");
        if let Some(p) = prev_rtp {
            assert_eq!(o.rtp, p.wrapping_add(352), "rtp contiguous across stalls");
        }
        prev_rtp = Some(o.rtp);
        let m = syncs.iter().rfind(|s| s.at <= d.at).expect("a sync before every packet");
        let slack = m.playout(o.rtp) - d.at;
        worst = worst.min(slack);
        for (k, t) in [boot_stall1, boot_stall2].iter().enumerate() {
            if first_after[k].is_none() && m.first && m.at > *t {
                first_after[k] = Some((i, slack));
            }
        }
        pcm.extend(o.pcm.chunks(2).map(|c| i16::from_le_bytes([c[0], c[1]])));
    }
    for (k, f) in first_after.iter().enumerate() {
        let (i, s) = f.expect("a packet under each re-anchor");
        println!("first RTP under the stall-{} re-anchor: packet #{i}, slack {:.1} ms", k + 1, s * 1e3);
    }
    println!("worst slack over all {} packets: {:.1} ms", data.len(), worst * 1e3);
    assert!(worst >= 0.045, "a packet arrived {:.1} ms before play-out", worst * 1e3);

    let ma = align_and_compare(&a, &pcm);
    println!(
        "chirp A (before the stalls): at frame {:.2} | max |err| {} LSB | rms {:.3} | exact {}/{}",
        ma.delay_frames, ma.max_err, ma.rms_err, ma.exact, ma.compared
    );
    assert!(ma.max_err <= 4);
    let tail = first_after[1].unwrap().0 * 704;
    let mb = align_and_compare(&b, &pcm[tail..]);
    println!(
        "chirp B (after both re-anchors): at frame {:.2} | max |err| {} LSB | rms {:.3} | exact {}/{}",
        mb.delay_frames + (tail / 2) as f64,
        mb.max_err,
        mb.rms_err,
        mb.exact,
        mb.compared
    );
    assert!(mb.max_err <= 4);
}

#[test]
#[ignore = "needs PipeWire; loads its own silent null sink; sends only to 127.0.0.1"]
fn end_to_end_pipewire_stalls_reanchor() {
    let guard = Untouched::take();
    {
        let sink = NullSink::load("stallpw", "", &guard);
        let cap = pw_capture(&sink.name);
        assert_linked_only_to(cap.node_id() as u64, &sink.name, "capture");
        stall_reanchor_run(&sink, Box::new(cap), "sender held off the capture again, 600 ms", &|arm| {
            arm.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(900));
        });
    }
    guard.check("at end");
}

/// The probe's own failure mode: the parec PROCESS stops delivering. Stall 2
/// SIGSTOPs our parec child for 700 ms, then SIGCONTs it.
#[test]
#[ignore = "needs PipeWire + pipewire-pulse; loads its own silent null sink; sends only to 127.0.0.1"]
fn end_to_end_parec_sigstop_reanchors() {
    let guard = Untouched::take();
    {
        let sink = NullSink::load("stallparec", "", &guard);
        let cap = ParecSource::new(&format!("{}.monitor", sink.name), Arc::new(BoottimeClock)).expect("spawn parec");
        let pid = cap.child_pid().expect("parec pid") as i32;
        let t0 = Instant::now();
        let parec_node = loop {
            let found = pw_dump().as_array().unwrap().iter().find_map(|o| {
                let p = &o["info"]["props"];
                let is_pid = p["application.process.id"].as_u64() == Some(pid as u64)
                    || p["application.process.id"].as_str() == Some(pid.to_string().as_str());
                (o["type"].as_str()?.ends_with(":Node") && is_pid).then(|| o["id"].as_u64()).flatten()
            });
            if let Some(n) = found {
                break n;
            }
            assert!(t0.elapsed() < Duration::from_secs(3), "parec node never appeared");
            std::thread::sleep(Duration::from_millis(30));
        };
        assert_linked_only_to(parec_node, &sink.name, "parec");
        stall_reanchor_run(&sink, Box::new(cap), "SIGSTOP the parec capture process for 700 ms", &|_| {
            // SAFETY: our own live child (parec), signalled by pid.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
            std::thread::sleep(Duration::from_millis(700));
            assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
        });
    }
    guard.check("at end");
}
