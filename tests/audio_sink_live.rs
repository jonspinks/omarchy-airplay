//! Live tests for the sender's own PipeWire sink (`airplay_rs::audiosink`),
//! against the running PipeWire. `#[ignore]`d; run explicitly, one at a time:
//!
//! ```text
//! mise exec -- cargo test --release --test audio_sink_live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! SILENT AND NON-INVASIVE BY CONSTRUCTION (hard rule 2):
//! * Every test snapshots the default sink, the default source, the default
//!   sink's volume/mute, the loaded modules and the *configured* default
//!   first, and asserts they are identical at the end.
//! * The only sink any test creates is the one `audiosink` publishes — a
//!   client node owned by this process. No `module-null-sink`, no
//!   `pactl load-module` at all: the module list is asserted unchanged.
//! * The only sink whose volume is ever written is our own published one.
//!   the user's sinks are read, never set.
//! * Two tests change the default output, which the user approved. Both put it
//!   back, and prove they did: once in the body, and once more from a
//!   `Drop` guard that also runs on panic — one of them deliberately panics
//!   to demonstrate exactly that.
//! * Audio only ever flows into our own sink, from a `pw-cat` pinned to it
//!   with `node.dont-move`/`dont-fallback`/`dont-reconnect`, which plays
//!   silence until `pw-dump` has proved its only links go to our sink.
//!   Signals peak at 300/32768 (-40.8 dBFS), and our sink is not the default
//!   in that test, so nothing reaches a real device.
//! * The claim and lock files are redirected to a scratch directory, so a
//!   test can never repair, or corrupt, a real session's record.
//!
//! No AirPlay receiver is contacted.

#[path = "support/audio_rules.rs"]
mod rules;

use airplay_rs::audiocapture::{sink_monitor_is_post_volume, PcmSource, PipewireSource, PwCaptureOpts};
use airplay_rs::audiosink::{self, AirPlaySink, Repair, SinkError, SinkOpts};
use airplay_rs::clock::BoottimeClock;
use rules::*;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Redirect the claim (state dir) and the lock (runtime dir) into a scratch
/// directory. Must run before anything publishes.
fn scratch_dirs() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("airplay-sink-live-{}", std::process::id()));
    std::fs::create_dir_all(base.join("state")).unwrap();
    std::fs::create_dir_all(base.join("run")).unwrap();
    std::env::set_var("AIRPLAY_RS_STATE_DIR", base.join("state"));
    std::env::set_var("AIRPLAY_RS_RUNTIME_DIR", base.join("run"));
    base
}

fn opts(tag: &str) -> SinkOpts {
    SinkOpts::for_receiver(&format!("75\" Test Frame {tag}"))
}

/// One name for every test that takes the default output.
///
/// WirePlumber's `default-nodes` file keeps a permanent numbered history of
/// every sink name that has ever been the configured default, so a per-test
/// name would leave the user a new entry in it on every run. Sharing one name
/// bounds that at a single entry, for ever — the same trade the production
/// naming rule makes. Tests that never become default keep their own tags,
/// because they leave nothing behind to bound.
fn default_taking_opts() -> SinkOpts {
    SinkOpts::for_receiver("75\" Test Frame")
}

/// Pull frames for `dur`.
fn collect(src: &mut dyn PcmSource, dur: Duration) -> Vec<airplay_rs::audiocapture::PcmBlock> {
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

// --------------------------------------------------------------------------
// 1. Shape
// --------------------------------------------------------------------------

#[test]
#[ignore]
fn sink_appears_with_the_right_shape_and_no_module() {
    scratch_dirs();
    let guard = Untouched::take();

    let sink = AirPlaySink::publish(opts("shape")).expect("publish");
    println!("published {} (node id {})", sink.node_name(), sink.node_id());

    // It is a sink pactl can see, in the one format we offer.
    let short = sh("pactl", &["list", "short", "sinks"]);
    let line = short
        .lines()
        .find(|l| l.split('\t').nth(1) == Some(sink.node_name()))
        .unwrap_or_else(|| panic!("our sink is not in `pactl list short sinks`:\n{short}"));
    println!("pactl: {line}");
    assert!(line.contains("s16le 2ch 44100Hz"), "wrong format: {line}");

    // The receiver's own text, byte for byte, quote included.
    let props = node_props(sink.node_name()).expect("our node in pw-dump");
    assert_eq!(props["node.description"].as_str(), Some("AirPlay: 75\" Test Frame shape"));
    assert_eq!(props["media.class"].as_str(), Some("Audio/Sink"));
    assert_eq!(props["application.name"].as_str(), Some("airplay-rs-sink"));

    // The monitor is pre-volume: `monitor.channel-volumes=false` took. This is
    // the property the whole "applied exactly once, at the TV" claim rests on.
    assert_eq!(sink_monitor_is_post_volume(sink.node_name()), Some(false));
    assert!(sink.monitor_is_pre_volume());

    // `node.always-process=true` took: process() is called although nothing is
    // playing. Without it the node sits in Paused and never runs.
    std::thread::sleep(Duration::from_millis(400));
    assert!(sink.process_calls() > 0, "the sink node never processed; node.always-process did not take");

    // Publishing took nothing: not the output, not a module.
    assert_eq!(sink.is_default(), Some(false), "publish must not take the output");
    guard.check("with the sink published");

    let name = sink.node_name().to_string();
    drop(sink);
    let gone = wait_until_gone(&name, Duration::from_secs(3));
    println!("node gone {gone:?} after drop");
    guard.check("after drop");
}

// --------------------------------------------------------------------------
// 2. The output moves, and comes back — including on panic
// --------------------------------------------------------------------------

fn take_and_check(guard: &Untouched) -> (AirPlaySink, String) {
    let mut sink = AirPlaySink::publish(default_taking_opts()).expect("publish");
    let name = sink.node_name().to_string();

    // Seeded from the sink the user was using, and verified by read-back. This is
    // what stops a remembered 337 % volume reading back as 100 % -> 0 dB.
    let seeded = sink.seeded_level().expect("seeded");
    // On `raw_pct`, the UNCLAMPED percent, not `pct()`. Both sides of a
    // `pct()` comparison go through the same clamp to 100, so at the top of
    // the slider it compares 100 with 100 whatever the node is really at —
    // vacuous exactly where it matters, since the failure being excluded is a
    // remembered 337 % reading back as a tidy 100 % and mapping to 0 dB.
    assert_eq!(
        (seeded.raw_pct(), seeded.muted()),
        (sink.previous_level().raw_pct(), sink.previous_level().muted()),
        "our sink did not take the previous output's level"
    );
    assert!(
        seeded.raw_pct() <= 100 && !seeded.boosted(),
        "our sink is boosted to {} %, which must never be read as a genuine maximum",
        seeded.raw_pct()
    );
    assert_eq!(sink.previous_default(), guard.default_sink());

    sink.take_default().expect("take the output");
    assert_eq!(sh("pactl", &["get-default-sink"]), name, "active default");
    assert_eq!(audiosink::configured_default_sink().as_deref(), Some(name.as_str()), "configured default");
    println!("the output is now {name}");
    guard.check_except_default("with the output taken");
    (sink, name)
}

#[test]
#[ignore]
fn the_sink_becomes_default_and_the_previous_one_comes_back() {
    scratch_dirs();
    let guard = Untouched::take();
    let mut restorer = DefaultRestorer::arm(guard.default_sink());

    // Phase 1: the ordinary path.
    {
        let (sink, name) = take_and_check(&guard);
        drop(sink);
        wait_until_gone(&name, Duration::from_secs(3));
        guard.check("after drop");
        assert!(audiosink::state::read().is_none(), "the claim must be cleared");
    }

    // Phase 2: the same body, with a panic after the output has been taken.
    // `Drop` runs during the unwind (this crate does not set panic="abort"),
    // so the restore is proven on the failure path in the same test.
    let name2 = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let n = name2.clone();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (_sink, name) = take_and_check(&guard);
        *n.lock().unwrap() = name;
        panic!("deliberate: proving the output comes back during an unwind");
    }));
    assert!(res.is_err(), "the deliberate panic must have happened");
    let name2 = name2.lock().unwrap().clone();
    assert!(!name2.is_empty(), "phase 2 never got as far as taking the output");
    wait_until_gone(&name2, Duration::from_secs(3));
    guard.check("after a panic unwind");
    assert!(audiosink::state::read().is_none(), "the claim must be cleared on panic too");

    restorer.disarm();
}

// --------------------------------------------------------------------------
// 3. Consequence 2: samples are taken BEFORE the sink's volume
// --------------------------------------------------------------------------

/// The measurement the whole design rests on: our sink's own monitor is
/// pre-volume, so moving its slider changes only what the TV is told.
///
/// Non-vacuity is built in. "The captured peak did not change" would also be
/// true if the volume had never been applied at all, so each pass also reads
/// the peak the sink node's OWN `process()` saw — the post-volume port — and
/// requires it to be the cube of the percentage. One run proves both that the
/// level really moved and that our tap is a different, earlier port.
#[test]
#[ignore]
fn samples_arrive_pre_volume_from_our_own_monitor() {
    scratch_dirs();
    let guard = Untouched::take();

    // Deliberately NOT the default: nothing played here can reach a device.
    let sink = AirPlaySink::publish(opts("prevol")).expect("publish");
    let ours = sink.node_name().to_string();
    assert_eq!(sink.is_default(), Some(false));

    let signal = chirp(1.0);
    let reference = peak_of(&signal);
    println!("reference peak {reference}");

    for (pct, cube) in [(100u8, 1.0f64), (50, 0.125), (25, 0.015625)] {
        // Our own sink only. the user's sinks are read, never written.
        let st = Command::new("pactl")
            .args(["set-sink-volume", &ours, &format!("{pct}%")])
            .status()
            .expect("set-sink-volume");
        assert!(st.success());

        let cap_name = unique("capture");
        let mut cap = PipewireSource::new(
            PwCaptureOpts {
                target: Some(ours.clone()),
                dont_fallback: true,
                node_name: cap_name.clone(),
                ..Default::default()
            },
            Arc::new(BoottimeClock),
        )
        .expect("capture our own monitor");
        assert_linked_only_to(wait_for_node(&cap_name, "capture node"), &ours, "capture");

        let mut player = Player::start(&ours);
        player.preroll_and_verify(&ours, 0.4);
        sink.reset_process_peak();
        let bytes = to_bytes(&signal);
        let writer = std::thread::spawn(move || {
            player.write(&bytes);
            player.write(&vec![0u8; RATE * 4 / 2]);
            player
        });
        let blocks = collect(&mut cap, Duration::from_millis(2200));
        drop(writer.join().unwrap());
        let processed = sink.last_process_peak();

        // (a) PRE-volume: the monitor carries the signal itself, sample for
        // sample, at every setting. The comparison is the capture tests' own —
        // fractional-delay alignment then a per-sample error bound — because a
        // bare peak picks up a few LSB of resampler overshoot.
        let m = align_and_compare(&signal, &samples(&blocks));
        println!(
            "{pct}%: delay {:.2} frames, max err {} LSB, rms {:.2}; node process() peak {processed}",
            m.delay_frames, m.max_err, m.rms_err
        );
        assert!(
            m.max_err <= 4,
            "{pct}%: the monitor is {} LSB off the unattenuated signal — the tap is not pre-volume",
            m.max_err
        );

        // (b) POST-volume, and therefore a genuinely different port: the sink
        // node's own payload is scaled by the CUBE of the percentage, which is
        // what pactl's cubic scale means in linear channelVolumes. Without
        // this, "the waveform is unchanged" would also hold if the volume had
        // never applied at all.
        let want = (reference as f64 * cube).round();
        let slack = (want * 0.25).max(3.0);
        assert!(
            (processed as f64 - want).abs() <= slack,
            "{pct}%: the node's own peak {processed} is not ~{want} — the sink's volume never applied, \
             so (a) proves nothing"
        );
        drop(cap);
    }

    guard.check("after the pre-volume measurement");
    let name = ours.clone();
    drop(sink);
    wait_until_gone(&name, Duration::from_secs(3));
    guard.check("after drop");
}

// --------------------------------------------------------------------------
// 4. The volume keys land on our sink
// --------------------------------------------------------------------------

/// Read-only. `/usr/bin/omarchy-audio-output-sink` is what the volume keys
/// resolve through; it is never modified, only asked.
#[test]
#[ignore]
fn volume_keys_resolve_to_our_sink() {
    scratch_dirs();
    let guard = Untouched::take();
    let sink = AirPlaySink::publish(opts("keys")).expect("publish");
    let ours = sink.node_name().to_string();

    let resolved = sh("/usr/bin/omarchy-audio-output-sink", &[&ours]);
    assert_eq!(resolved, ours, "the volume keys would drive {resolved}, not our sink");

    // The script's downstream lookup is a PREFIX match on sink-inputs'
    // node.name. Our capture taps a monitor, so it is a source-output and
    // cannot appear there at all — but the naming rule is the belt.
    let inputs = sh("pactl", &["list", "sink-inputs"]);
    for line in inputs.lines() {
        if let Some(rest) = line.trim().strip_prefix("node.name = \"") {
            let name = rest.trim_end_matches('"');
            assert!(!name.starts_with(&ours), "a sink-input {name:?} is prefixed by our sink name");
        }
    }

    guard.check("after the read-only key lookup");
    let name = ours.clone();
    drop(sink);
    wait_until_gone(&name, Duration::from_secs(3));
    guard.check("after drop");
}

// --------------------------------------------------------------------------
// 5. SIGKILL
// --------------------------------------------------------------------------

/// The child half of [`a_sigkilled_sender_leaves_no_sink_and_the_next_run_restores_the_default`],
/// re-invoked as this same test binary with `AIRPLAY_SINK_HOLD_SECONDS` set.
/// Run without that variable — as a plain `-- --ignored` sweep does — it does
/// nothing at all and says so.
#[test]
#[ignore]
fn sigkill_hold_child() {
    let Ok(secs) = std::env::var("AIRPLAY_SINK_HOLD_SECONDS") else {
        println!("sigkill_hold_child: not the child (AIRPLAY_SINK_HOLD_SECONDS unset); nothing to do");
        return;
    };
    let secs: u64 = secs.parse().expect("AIRPLAY_SINK_HOLD_SECONDS");
    let mut sink = AirPlaySink::publish(default_taking_opts()).expect("publish");
    sink.take_default().expect("take the output");
    println!("child: holding {} for {secs}s", sink.node_name());
    std::thread::sleep(Duration::from_secs(secs));
    // Not reached in the test: the parent SIGKILLs us. If it ever is, the
    // destructor still puts the output back.
}

#[test]
#[ignore]
fn a_sigkilled_sender_leaves_no_sink_and_the_next_run_restores_the_default() {
    let _scratch = scratch_dirs();
    let guard = Untouched::take();
    let original = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&original);

    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", "sigkill_hold_child", "--ignored", "--nocapture", "--test-threads=1"])
        .env("AIRPLAY_SINK_HOLD_SECONDS", "30")
        .spawn()
        .expect("spawn the holder");

    // The child's own node name, from the same rule it used.
    let held = airplay_rs::audiosink::node_name_for(&default_taking_opts().label);
    let t0 = Instant::now();
    while sh("pactl", &["get-default-sink"]) != held {
        assert!(t0.elapsed() < Duration::from_secs(20), "the child never took the output");
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("child took the output as {held}");

    // The PID from `spawn`, never `pgrep -f`: a pattern match finds wrappers
    // and shells and kills the wrong thing.
    let pid = child.id() as i32;
    // SAFETY: a plain kill(2) on a child we spawned ourselves.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0, "kill -9 failed");
    let _ = child.wait();
    println!("SIGKILLed pid {pid}");

    // The node is OWNED BY THE PROCESS: it goes on its own, with no destructor
    // and no sweep. This is the whole reason the sink is a client node and not
    // a module-null-sink.
    let gone = wait_until_gone(&held, Duration::from_secs(5));
    println!("the sink vanished {gone:?} after SIGKILL, with nobody asking");
    assert!(gone < Duration::from_secs(5));

    // the user still has sound: PipeWire elected a fallback by itself.
    let fallback = sh("pactl", &["get-default-sink"]);
    assert_ne!(fallback, held, "the active default still names the dead sink");
    assert!(
        audiosink::live_sinks().iter().any(|s| s == &fallback),
        "the active default {fallback} is not a live sink"
    );

    // What does NOT die with the process: the configured default, which
    // persists across a reboot and would re-seize the output the moment a sink
    // of that name appeared again.
    let rotted = audiosink::configured_default_sink();
    println!("configured default after SIGKILL: {rotted:?}");
    assert!(audiosink::state::read().is_some(), "the claim must have survived the SIGKILL");

    // The sweep: the flock was released by the kernel, so this can run.
    let repair = audiosink::reclaim_orphan().expect("reclaim");
    println!("reclaim: {repair:?}");
    assert!(audiosink::state::read().is_none(), "the claim must be cleared");

    if rotted.as_deref() == Some(held.as_str()) {
        assert_eq!(
            repair,
            Some(Repair::RestoredDefault { from: held.clone(), to: original.clone() }),
            "the sweep must put the recorded output back"
        );
        guard.check("after the sweep");
    } else {
        // WirePlumber occasionally clears the configured default itself. Then
        // there is nothing naming our dead sink and the sweep must NOT guess.
        assert_eq!(repair, Some(Repair::ClearedStaleClaim));
        println!("WirePlumber had already cleared the configured default; the sweep restored nothing");
        Command::new("pactl").args(["set-default-sink", &original]).status().expect("restore");
        guard.check("after restoring by hand");
    }
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 6. One at a time
// --------------------------------------------------------------------------

#[test]
#[ignore]
fn two_senders_cannot_publish_at_once() {
    scratch_dirs();
    let guard = Untouched::take();
    let first = AirPlaySink::publish(opts("one")).expect("publish");

    match AirPlaySink::publish(opts("two")) {
        Err(SinkError::Busy) => println!("the second publish was refused, as it must be"),
        other => panic!("expected Busy, got {other:?}", other = other.map(|s| s.node_name().to_string())),
    }

    // The first is untouched by the refusal.
    assert!(audiosink::live_sinks().iter().any(|s| s == first.node_name()));
    guard.check("after the refused second publish");
    let name = first.node_name().to_string();
    drop(first);
    wait_until_gone(&name, Duration::from_secs(3));
    guard.check("after drop");
}

// --------------------------------------------------------------------------
// 7. A stale configured default must not let a new sink steal the output
// --------------------------------------------------------------------------

/// The direct test of the nastiest finding: a configured default naming our
/// (stable) node name seizes the output the instant a sink of that name
/// appears, with nobody asking — which would hand us the user's output before
/// `seed_level` had corrected the remembered volume. `publish` sweeps under
/// the lock *before* the node exists, so it cannot happen.
#[test]
#[ignore]
fn a_stale_claim_does_not_let_a_new_sink_steal_the_default() {
    scratch_dirs();
    let guard = Untouched::take();
    let original = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&original);

    let name = airplay_rs::audiosink::node_name_for(&default_taking_opts().label);

    // Exactly the rot a SIGKILL leaves: a claim on disk, and the configured
    // default naming a sink that does not exist.
    airplay_rs::audiosink::state::write(&airplay_rs::audiosink::Claim {
        node_name: name.clone(),
        label: default_taking_opts().label,
        previous_default: original.clone(),
        took_default: true,
        restore_default: true,
        pid: std::process::id(),
        created_unix: 0,
    })
    .expect("write the stale claim");
    let st = Command::new("pw-metadata")
        .args([
            "-n", "default", "0", "default.configured.audio.sink",
            &format!("{{\"name\":\"{name}\"}}"), "Spa:String:JSON",
        ])
        .status()
        .expect("pw-metadata");
    assert!(st.success());
    assert_eq!(audiosink::configured_default_sink().as_deref(), Some(name.as_str()));

    let mut sink = AirPlaySink::publish(default_taking_opts()).expect("publish");
    assert_eq!(sink.node_name(), name);

    // The sweep ran first, so the stale pointer was gone before the node was:
    // publishing did not take the output.
    assert_eq!(sh("pactl", &["get-default-sink"]), original, "our sink stole the output");
    assert_eq!(audiosink::configured_default_sink().as_deref(), Some(original.as_str()));
    guard.check("after publishing over a stale claim");

    // And it is still ours to take, explicitly.
    sink.take_default().expect("take the output");
    assert_eq!(sh("pactl", &["get-default-sink"]), name);

    drop(sink);
    wait_until_gone(&name, Duration::from_secs(3));
    guard.check("after drop");
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 8. The volume binding, against the real thing
// --------------------------------------------------------------------------

/// the user's rule — "change the headphones' volume instead" — is a property of
/// which sink the volume driver may write, so this proves that binding
/// against a live sink rather than a fake.
///
/// A `dvlc` from the TV remote reaches the laptop as
/// `PactlVolume::set(pct, muted)` on whatever sink the transport is bound to.
/// Bound to our own published sink, that moves OUR slider; the desk speakers are
/// read at the start and must be byte-identical afterwards, with the write in
/// between. The same test then proves the detach trigger: `still_default()`
/// is what tells the driver the output is somebody else's now, so it is
/// checked before the handover, after it, and after the output is moved away
/// again.
#[test]
#[ignore]
fn the_volume_transport_writes_only_our_sink_and_sees_the_output_move() {
    use airplay_rs::volume::{LaptopVolume, PactlVolume};
    scratch_dirs();
    let guard = Untouched::take();
    let mut restorer = DefaultRestorer::arm(guard.default_sink());

    let mut sink = AirPlaySink::publish(default_taking_opts()).expect("publish");
    let ours = sink.node_name().to_string();
    let previous = sink.previous_default().to_string();
    assert_eq!(previous, guard.default_sink());

    // What the session builds in sink mode, and nothing else.
    let mut laptop = PactlVolume::for_sink(&ours);
    assert_eq!(laptop.bound_sink(), Some(ours.as_str()), "the transport must be fixed to our sink");
    assert_eq!(laptop.still_default(), Some(false), "we have not taken the output yet");
    assert!(!laptop.refresh_target(), "a fixed binding must never re-target");

    // the user's own sink, exactly as it reads now.
    let before = sh("pactl", &["get-sink-volume", &previous]);
    let before_mute = sh("pactl", &["get-sink-mute", &previous]);

    sink.take_default().expect("take the output");
    assert_eq!(laptop.still_default(), Some(true), "our sink IS the output now");

    // The TV remote arrives: `VolAction::SetLaptop` on the bound transport.
    let seeded = sink.seeded_level().expect("seeded");
    let want = if seeded.pct() >= 20 { seeded.pct() - 7 } else { seeded.pct() + 7 };
    laptop.set(want, false).expect("write our own sink");
    let got = laptop.read().expect("read our own sink");
    assert_eq!((got.pct(), got.muted()), (want, false), "the remote's level landed on our sink");
    assert!(!laptop.refresh_target(), "still fixed after a write");

    // ...and nowhere else.
    assert_eq!(sh("pactl", &["get-sink-volume", &previous]), before, "{previous}'s volume was written");
    assert_eq!(sh("pactl", &["get-sink-mute", &previous]), before_mute, "{previous}'s mute was written");
    guard.check_except_default("after a remote-style write to our own sink");

    // the user picks his own output again, mid-session: this is the one signal the
    // driver detaches on, and it must be true of the real thing.
    let st = Command::new("pactl")
        .args(["set-default-sink", &previous])
        .stdin(std::process::Stdio::null())
        .status()
        .expect("pactl set-default-sink");
    assert!(st.success());
    assert_eq!(laptop.still_default(), Some(false), "the driver must see that the output moved away");
    // And the sink stops claiming it back, exactly as the detach hook does.
    sink.disown_default();
    assert!(!sink.restores_default());

    drop(sink);
    wait_until_gone(&ours, Duration::from_secs(3));
    guard.check("after drop");
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 8. The whole thing, as a real `Session`
//
// Everything above drives `AirPlaySink` and `PactlVolume` by hand. Nothing
// did that through a `Session`, so `open_sink_capture`, the monitor writes,
// the `SinkBinding` construction and the shutdown order had no coverage in
// either suite: a wiring slip there passed every offline test and every
// hardware-gated one. This is that test — a real session, real PipeWire, a
// real published sink, against the loopback fake receiver.
//
// Rule 2 compliance: the only sink created is our own client node; the fake
// receiver is on 127.0.0.1; no AirPlay device is contacted; the only volume
// written is our own sink's. The output IS taken (that is the property under
// test) and is put back three times over — by `shutdown`, by `Drop` of the
// sink, and by the `DefaultRestorer` that also runs on panic.
// --------------------------------------------------------------------------

#[path = "support/fake_audio_receiver.rs"]
mod fake_audio;
#[path = "support/fake_rtsp_receiver.rs"]
mod fake_rtsp;

use airplay_rs::session::{AudioMode, CaptureBackend, Session, SessionConfig};
use fake_audio::FakeAirplayAudioReceiver;
use fake_rtsp::{Behaviour, FakeRtspReceiver};

const SHARED: [u8; 32] = [0x33; 32];

/// A timing port whose +1/+2 are free right now (bring_up binds all three).
fn free_timing_port() -> u16 {
    for _ in 0..50 {
        let s = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let p = s.local_addr().unwrap().port();
        drop(s);
        if p < 65000 && [p, p + 1, p + 2].iter().all(|q| std::net::UdpSocket::bind(("0.0.0.0", *q)).is_ok()) {
            return p;
        }
    }
    panic!("no free timing port");
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Everything `pw-dump` reports under the capture node's params, for the
/// message when the shape is not what this test expects.
fn capture_params_json() -> String {
    pw_dump()
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|o| o["info"]["props"]["node.name"].as_str() == Some("airplay-rs-capture"))
                .map(|o| o["info"]["params"].to_string())
        })
        .unwrap_or_else(|| "<no capture node>".into())
}

/// The capture node's OWN `channelVolumes`, from `pw-dump`.
fn capture_channel_volumes() -> Option<Vec<f64>> {
    let d = pw_dump();
    let node = d
        .as_array()?
        .iter()
        .find(|o| o["info"]["props"]["node.name"].as_str() == Some("airplay-rs-capture"))?;
    node["info"]["params"]["Props"]
        .as_array()?
        .iter()
        .find_map(|p| p["channelVolumes"].as_array())
        .map(|v| v.iter().filter_map(|x| x.as_f64()).collect())
}

#[test]
#[ignore]
fn a_real_session_in_sink_mode_takes_the_output_at_the_gate_and_gives_it_back() {
    scratch_dirs();
    let guard = Untouched::take();
    let previous = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&previous);

    let audio_rx = FakeAirplayAudioReceiver::start();
    let fake = FakeRtspReceiver::start(
        &SHARED,
        Behaviour {
            audio_ports: (audio_rx.data_port, audio_rx.control_port),
            offer_event_port: true,
            volume_db: -20.4,
            apply_volume_set: true,
            ..Default::default()
        },
    );
    let mut cfg = SessionConfig::new("127.0.0.1");
    cfg.timing_port = free_timing_port();
    cfg.audio = AudioMode::System { capture: CaptureBackend::Sink };
    let session = Session::bring_up(fake.connect(), SHARED.to_vec(), &cfg).expect("bring-up against the fake");
    let mon = session.audio_monitor().expect("audio is on");

    // Nothing is published until the audio actually starts.
    assert_eq!(mon.sink(), None, "a sink was published before start_audio");
    session.start_audio();

    // 1. The sink arm really ran: our own node, and the capture that opened
    //    is the sink backend rather than a quiet fallback to the monitor
    //    path. (A fallback would say `Pipewire` here and publish nothing.)
    let info = mon.sink().expect("sink mode must record its sink");
    assert_eq!(mon.capture_backend(), Some(CaptureBackend::Sink), "sink mode fell back: {info:?}");
    assert!(info.node_name.starts_with("airplay-sink."), "{}", info.node_name);
    assert_eq!(info.previous_output, previous, "the sink must remember the output it will give back");
    wait_for("our sink to be listed", 5, || {
        sh("pactl", &["list", "short", "sinks"]).contains(&info.node_name)
    });

    // 2. The output is NOT taken at publish: the speakers keep playing until
    //    the TV's level is established. This is the window that would
    //    otherwise be audible nowhere.
    assert!(!info.is_default, "publish must not take the output");
    assert_eq!(sh("pactl", &["get-default-sink"]), previous, "the output moved before the gate opened");

    // 3. The handover happens when the gate opens, and only then.
    wait_for("the volume gate to open", 20, || mon.report().gate_open);
    wait_for("the sink to be recorded as the output", 5, || mon.sink().is_some_and(|s| s.is_default));
    assert_eq!(sh("pactl", &["get-default-sink"]), info.node_name, "the session did not take the output");
    assert_eq!(
        audiosink::configured_default_sink().as_deref(),
        Some(info.node_name.as_str()),
        "the CONFIGURED default must be ours too, or WirePlumber puts the old one back"
    );
    // the user's own sinks were read, never written.
    guard.check_except_default("with a real session holding the output");

    // 4. The tap is our own sink's monitor, pinned — never the speakers.
    assert_eq!(
        sink_monitor_is_post_volume(&info.node_name),
        Some(false),
        "our monitor must be pre-volume, or the level is applied twice"
    );
    let cap = wait_for_node("airplay-rs-capture", "the session's capture node");
    assert_linked_only_to(cap, &info.node_name, "the session's capture");
    let props = node_props("airplay-rs-capture").expect("capture props");
    // pw-dump types these: a property we wrote as the string "true" comes
    // back as a JSON boolean, so read either shape rather than silently
    // matching neither.
    let flag = |k: &str| props[k].as_bool().or_else(|| props[k].as_str().map(|s| s == "true"));
    assert_eq!(flag("node.dont-fallback"), Some(true), "props: {props}");
    assert_eq!(
        flag("node.dont-move"),
        Some(true),
        "without dont-move the capture can be retargeted at the desk speakers mid-session: {props}"
    );
    assert_eq!(flag("state.restore-props"), Some(false));
    assert_eq!(flag("node.stream.restore-props"), Some(false));
    assert_eq!(props["target.object"].as_str(), Some(info.node_name.as_str()), "the capture is not pinned to our sink");
    // The capture node has a channel volume of ITS OWN, which WirePlumber
    // remembers per `application.name` and restores after connect. At
    // anything but 1.0 every sample would be attenuated a second time, under
    // a slider that says otherwise — the double application sink mode exists
    // to prevent — and nothing else in the sender can see it. Proven here,
    // not assumed: `state.restore-props` above is best-effort.
    let vols = capture_channel_volumes()
        .unwrap_or_else(|| panic!("the capture node must report channelVolumes: {}", capture_params_json()));
    assert!(
        vols.iter().all(|v| (*v - 1.0).abs() < 1e-6),
        "the capture node's own volume is {vols:?}, so the TV's audio is attenuated a second time"
    );
    // ...and that is not just what it happened to come up as. Drive it the
    // way WirePlumber's restore, a pavucontrol Recording-tab drag or a stray
    // `wpctl set-volume` would, and require the session to put it back.
    // (Our own node; no hardware sink is written, and nothing is audible.)
    let st = Command::new("wpctl")
        .args(["set-volume", &cap.to_string(), "0.5"])
        .stdin(std::process::Stdio::null())
        .status()
        .expect("wpctl set-volume on our own capture node");
    assert!(st.success());
    let t0 = Instant::now();
    let mut back = capture_channel_volumes();
    while t0.elapsed() < Duration::from_secs(3) && !back.as_ref().is_some_and(|v| v.iter().all(|x| (*x - 1.0).abs() < 1e-6)) {
        std::thread::sleep(Duration::from_millis(50));
        back = capture_channel_volumes();
    }
    if !back.as_ref().is_some_and(|v| v.iter().all(|x| (*x - 1.0).abs() < 1e-6)) {
        // Put it back by hand before failing: WirePlumber remembers this
        // value per `application.name`, so a 0.5 left here would come back
        // on every future run.
        let _ = Command::new("wpctl")
            .args(["set-volume", &cap.to_string(), "1.0"])
            .stdin(std::process::Stdio::null())
            .status();
        panic!("the capture node stayed at {back:?} after being attenuated; the TV's audio would be halved");
    }
    println!("the capture level was forced to 0.5 and put back within {:?}", t0.elapsed());

    // 5. Exactly one SET went to the TV, at the level OUR sink carries —
    //    which was seeded from the output the user was using. Nothing was sent at
    //    the TV's own level, and nothing was sent twice.
    let sets: Vec<fake_rtsp::Req> =
        fake.requests().into_iter().filter(|r| r.method == "SET_PARAMETER").collect();
    assert_eq!(sets.len(), 1, "the start SET, and only that: {:?}", sets.iter().map(|r| &r.body).collect::<Vec<_>>());
    assert_ne!(sets[0].body, b"volume: 0.000000\r\n", "0 dB (AirPlay MAXIMUM) was sent");

    // 6. Shutdown gives the output back, removes the node and clears the
    //    claim.
    session.shutdown();
    let _ = audio_rx.finish();
    wait_until_gone(&info.node_name, Duration::from_secs(5));
    assert_eq!(sh("pactl", &["get-default-sink"]), previous, "the output did not come back");
    guard.check("after the session shut down");
    assert!(airplay_rs::audiosink::state::read().is_none(), "the claim must be cleared after a clean session");

    restorer.disarm();
}

// --------------------------------------------------------------------------
// 11. The node dies UNDER the session
//
// The failure the review called a repeat of milestone 3: when our node goes
// away while it is the output, the ACTIVE default moves (WirePlumber elects a
// fallback) but `default.configured.audio.sink` keeps naming the corpse. Told
// only by the active default, teardown reads that as "the user picked another
// output himself", leaves it alone, and clears the claim — so the machine is
// left configured for a sink that does not exist, with the one record that
// could repair it deleted. The CONFIGURED default is the discriminator: his
// choice rewrites it, a fallback election does not.
// --------------------------------------------------------------------------

/// Destroy a node by id, the way a WirePlumber restart or a `pw-cli destroy`
/// does. Returns the command's own report for the log.
fn destroy_node(id: u32) -> String {
    let out = Command::new("pw-cli")
        .args(["destroy", &id.to_string()])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("pw-cli");
    format!(
        "pw-cli destroy {id}: {} {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

#[test]
#[ignore]
fn a_node_that_dies_while_it_is_the_output_still_gives_the_output_back() {
    let _scratch = scratch_dirs();
    let guard = Untouched::take();
    let previous = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&previous);

    let (sink, name) = take_and_check(&guard);
    let id = sink.node_id();
    assert!(sink.is_healthy(), "a fresh sink reports a fatal: {:?}", sink.fatal());

    // The node dies under us, with the output pointed at it.
    println!("{}", destroy_node(id));
    wait_for("the sink node to report its death", 10, || !sink.is_healthy());
    println!("audiosink reported: {:?}", sink.fatal());
    wait_until_gone(&name, Duration::from_secs(5));

    // The state the finding is about: the active default has moved (or is
    // about to), and the CONFIGURED one still names a sink that is gone.
    let rot = audiosink::configured_default_sink();
    let active = sh("pactl", &["get-default-sink"]);
    println!("after the node died: active={active} configured={rot:?}");

    // Teardown now. The active default is not ours any more, which is exactly
    // what a choice of the user's looks like — and the whole question is whether
    // this is told apart from one.
    drop(sink);

    let back = sh("pactl", &["get-default-sink"]);
    assert_eq!(back, previous, "the output was not given back after the node died (active default)");
    assert_ne!(
        audiosink::configured_default_sink().as_deref(),
        Some(name.as_str()),
        "the machine is still configured for a sink that no longer exists"
    );
    guard.check("after a node that died under the session");
    assert!(
        audiosink::state::read().is_none(),
        "the restore was confirmed, so the claim may go: {:?}",
        audiosink::state::read()
    );
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 12. A restore that cannot run keeps the claim
//
// The milestone-3 rule, live: a claim may be cleared only when the thing it
// describes is known repaired or known not ours. Here the machine becomes
// unreadable and unwritable at the worst possible moment — every `pactl` and
// `pw-metadata` call fails — so teardown cannot put the output back and
// cannot confirm anything. The claim must survive that, because it is the
// only thing `airplay audio --cleanup` (and the next run) can repair from.
// --------------------------------------------------------------------------

#[test]
#[ignore]
fn a_restore_that_cannot_run_keeps_the_claim_and_cleanup_finishes_it() {
    let _scratch = scratch_dirs();
    let guard = Untouched::take();
    let previous = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&previous);

    let (sink, name) = take_and_check(&guard);

    // Every shell-out this module makes goes through PATH. Empty it and the
    // machine is, from teardown's point of view, unreadable and unwritable:
    // `pactl get-default-sink`, `pactl list short sinks`, `pw-metadata` and
    // `pactl set-default-sink` all fail. Nothing of the user's is touched by this;
    // it is this process's own environment.
    let real_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", "");
    drop(sink);
    std::env::set_var("PATH", &real_path);

    // The node is gone anyway: it is owned by this process, not by pactl.
    wait_until_gone(&name, Duration::from_secs(5));
    // And the output really was left rotten — this test is worthless if the
    // restore somehow succeeded.
    assert_eq!(
        audiosink::configured_default_sink().as_deref(),
        Some(name.as_str()),
        "the restore ran after all; this test proved nothing"
    );

    let claim = audiosink::state::read().expect("the claim MUST survive a restore that could not run");
    println!("claim after the failed restore: {claim:?}");
    assert_eq!(claim.node_name, name);
    assert_eq!(claim.previous_default, previous);
    assert!(claim.took_default, "the claim must still say the output was taken");
    assert!(
        claim.restore_default,
        "a failed restore must not write `restore_default: false`, or --cleanup skips the repair too"
    );

    // ...and that record is enough for `airplay audio --cleanup` to finish the
    // job, which is the whole reason it was kept.
    let repair = audiosink::reclaim_orphan().expect("reclaim");
    println!("cleanup: {repair:?}");
    assert_eq!(repair, Some(Repair::RestoredDefault { from: name.clone(), to: previous.clone() }));
    assert_eq!(sh("pactl", &["get-default-sink"]), previous, "cleanup did not put the output back");
    assert!(audiosink::state::read().is_none(), "the claim must be cleared once the repair is confirmed");
    guard.check("after --cleanup finished the job");
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 13. The output the user picks himself is left alone, and the node goes with it
// --------------------------------------------------------------------------

/// After a detach the sender is gated to digital silence for the rest of the
/// session and nothing re-opens it. A node still called `AirPlay: …` in the
/// output menu is therefore a trap: picking it — the obvious reaction to the
/// TV going quiet — routes every stream into a sink that makes no sound
/// anywhere. `unpublish` is what the detach hook owes the user.
#[test]
#[ignore]
fn a_detach_leaves_his_choice_alone_and_takes_the_node_down() {
    let _scratch = scratch_dirs();
    let guard = Untouched::take();
    let previous = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&previous);

    let (mut sink, name) = take_and_check(&guard);

    // the user picks his speakers back, himself. That rewrites the CONFIGURED
    // default, which is what tells this apart from our node dying.
    assert!(Command::new("pactl")
        .args(["set-default-sink", &previous])
        .stdin(std::process::Stdio::null())
        .status()
        .expect("pactl")
        .success());
    wait_for("his choice to land", 5, || sh("pactl", &["get-default-sink"]) == previous);

    // What the session's `on_detach` hook does, in order.
    sink.disown_default();
    sink.unpublish();

    assert!(!sink.restores_default(), "the sink must stop claiming an output the user took back");
    wait_until_gone(&name, Duration::from_secs(5));
    assert!(
        !audiosink::live_sinks().iter().any(|s| s == &name),
        "the AirPlay sink is still in the output menu, and picking it would be silence"
    );
    assert_eq!(sh("pactl", &["get-default-sink"]), previous, "his choice was overridden");
    assert!(audiosink::state::read().is_none(), "nothing of ours is left, so the claim may go");
    guard.check("after the detach");

    // Idempotent: the `Drop` that follows must not re-run any of it.
    drop(sink);
    assert_eq!(sh("pactl", &["get-default-sink"]), previous, "Drop after unpublish moved the output");
    guard.check("after the drop that followed the detach");
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 14. A DSP sink is an output; the sink underneath is only where the level is
// --------------------------------------------------------------------------

/// With EasyEffects (or `omarchy_speaker_tuning`) selected, the user's output is
/// the DSP sink and the volume keys drive the ALSA sink underneath. Those are
/// two different questions, and restoring the answer to the second one would
/// silently drop his DSP chain — and stick, because it lands in
/// `default.configured.audio.sink`.
#[test]
#[ignore]
fn the_output_put_back_is_the_dsp_sink_he_selected_not_the_one_underneath() {
    let _scratch = scratch_dirs();
    let guard = Untouched::take();
    let original = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&original);

    let dsp = match audiosink::live_sinks()
        .into_iter()
        .find(|s| s == "easyeffects_sink" || s == "omarchy_speaker_tuning")
    {
        Some(d) => d,
        None => {
            println!("no DSP sink on this machine; nothing to prove");
            restorer.disarm();
            return;
        }
    };
    assert!(Command::new("pactl")
        .args(["set-default-sink", &dsp])
        .stdin(std::process::Stdio::null())
        .status()
        .expect("pactl")
        .success());
    wait_for("the DSP sink to be the output", 5, || sh("pactl", &["get-default-sink"]) == dsp);

    let mut sink = AirPlaySink::publish(default_taking_opts()).expect("publish");
    let name = sink.node_name().to_string();
    println!(
        "output={} level copied from={} at {} %",
        sink.previous_default(),
        sink.level_source(),
        sink.previous_level().raw_pct()
    );
    assert_eq!(sink.previous_default(), dsp, "the output to put back must be the DSP sink he selected");
    assert!(
        audiosink::live_sinks().iter().any(|s| s == sink.level_source()),
        "the level was copied from {}, which is not a live sink",
        sink.level_source()
    );
    // The level really is the one the volume keys drive, whichever sink that
    // resolves to — and our sink carries it exactly.
    let seeded = sink.seeded_level().expect("seeded");
    assert_eq!((seeded.raw_pct(), seeded.muted()), (sink.previous_level().raw_pct(), sink.previous_level().muted()));

    sink.take_default().expect("take the output");
    assert_eq!(sh("pactl", &["get-default-sink"]), name);
    drop(sink);
    wait_until_gone(&name, Duration::from_secs(5));
    assert_eq!(
        sh("pactl", &["get-default-sink"]),
        dsp,
        "his DSP chain was dropped: the sink underneath was put back instead"
    );
    assert_eq!(audiosink::configured_default_sink().as_deref(), Some(dsp.as_str()));

    // Back to where the machine started.
    assert!(Command::new("pactl")
        .args(["set-default-sink", &original])
        .stdin(std::process::Stdio::null())
        .status()
        .expect("pactl")
        .success());
    wait_for("the original output", 5, || sh("pactl", &["get-default-sink"]) == original);
    guard.check("after the DSP round trip");
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 15. Ctrl-C and `kill` give the output back
// --------------------------------------------------------------------------

/// The child half of [`a_signalled_sender_gives_the_output_back`]: hold the
/// output until a signal arrives, then return NORMALLY so every `Drop` runs —
/// which is exactly what `crate::signals` turns SIGINT/SIGTERM into, and what
/// `airplay mirror`'s stream loop does with it.
#[test]
#[ignore]
fn signal_hold_child() {
    let Ok(secs) = std::env::var("AIRPLAY_SINK_SIGNAL_SECONDS") else {
        println!("signal_hold_child: not the child (AIRPLAY_SINK_SIGNAL_SECONDS unset); nothing to do");
        return;
    };
    let secs: u64 = secs.parse().expect("AIRPLAY_SINK_SIGNAL_SECONDS");
    airplay_rs::signals::install().expect("install signal handlers");
    let mut sink = AirPlaySink::publish(default_taking_opts()).expect("publish");
    sink.take_default().expect("take the output");
    println!("child: holding {} for up to {secs}s", sink.node_name());
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end && !airplay_rs::signals::interrupted() {
        std::thread::sleep(Duration::from_millis(20));
    }
    println!("child: {} -> returning; Drop gives the output back", airplay_rs::signals::signal_name().unwrap_or("timed out"));
    // `sink` drops here, on the ordinary return path.
}

#[test]
#[ignore]
fn a_signalled_sender_gives_the_output_back() {
    let _scratch = scratch_dirs();
    let guard = Untouched::take();
    let original = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&original);
    let held = airplay_rs::audiosink::node_name_for(&default_taking_opts().label);

    for (signo, label) in [(libc::SIGINT, "SIGINT"), (libc::SIGTERM, "SIGTERM")] {
        let mut child = Command::new(std::env::current_exe().expect("current exe"))
            .args(["--exact", "signal_hold_child", "--ignored", "--nocapture", "--test-threads=1"])
            .env("AIRPLAY_SINK_SIGNAL_SECONDS", "30")
            .spawn()
            .expect("spawn the holder");
        let t0 = Instant::now();
        while sh("pactl", &["get-default-sink"]) != held {
            assert!(t0.elapsed() < Duration::from_secs(20), "the child never took the output ({label})");
            std::thread::sleep(Duration::from_millis(100));
        }
        println!("{label}: the child took the output as {held}");

        // SAFETY: a plain kill(2) on a child we spawned ourselves.
        assert_eq!(unsafe { libc::kill(child.id() as i32, signo) }, 0, "kill -{label} failed");
        let status = child.wait().expect("wait");
        println!("{label}: child exited {status}");

        wait_until_gone(&held, Duration::from_secs(5));
        let back = sh("pactl", &["get-default-sink"]);
        assert_eq!(back, original, "the output did not come back after {label}");
        assert_eq!(
            audiosink::configured_default_sink().as_deref(),
            Some(original.as_str()),
            "the configured default is still rotten after {label}"
        );
        assert!(audiosink::state::read().is_none(), "the claim must be cleared after {label}");
        guard.check(&format!("after {label}"));
    }
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 16. A real session whose sink dies under it
//
// The session half of the same failure: nothing polled the sink's health, so
// a node that died mid-session left the capture starving — which is exactly
// what nothing playing looks like — while the gate stayed OPEN and the
// sender kept shipping. The session must hold the gate, say why, and end the
// stream; and it must NOT quietly fall back to the laptop's own monitor,
// which would send the room to the TV and attenuate it twice.
// --------------------------------------------------------------------------

/// Bring up a real sink-mode session against the loopback fake, take it to
/// the point where the gate is open and the output is ours. Returns
/// everything the caller needs to drive and then shut it down.
fn live_sink_session(
    previous: &str,
) -> (
    FakeAirplayAudioReceiver,
    FakeRtspReceiver,
    Session,
    airplay_rs::session::AudioSinkInfo,
) {
    let audio_rx = FakeAirplayAudioReceiver::start();
    let fake = FakeRtspReceiver::start(
        &SHARED,
        Behaviour {
            audio_ports: (audio_rx.data_port, audio_rx.control_port),
            offer_event_port: true,
            volume_db: -20.4,
            apply_volume_set: true,
            ..Default::default()
        },
    );
    let mut cfg = SessionConfig::new("127.0.0.1");
    cfg.timing_port = free_timing_port();
    cfg.audio = AudioMode::System { capture: CaptureBackend::Sink };
    let session = Session::bring_up(fake.connect(), SHARED.to_vec(), &cfg).expect("bring-up against the fake");
    let mon = session.audio_monitor().expect("audio is on");
    session.start_audio();
    let info = mon.sink().expect("sink mode must record its sink");
    assert_eq!(mon.capture_backend(), Some(CaptureBackend::Sink), "sink mode fell back: {info:?}");
    assert_eq!(info.previous_output, previous, "the sink must remember the output it will give back");
    wait_for("the volume gate to open", 20, || mon.report().gate_open);
    wait_for("the handover", 5, || mon.sink().is_some_and(|s| s.is_default));
    assert_eq!(sh("pactl", &["get-default-sink"]), info.node_name, "the session did not take the output");
    (audio_rx, fake, session, info)
}

#[test]
#[ignore]
fn a_session_whose_sink_dies_holds_the_gate_and_gives_the_output_back() {
    scratch_dirs();
    let guard = Untouched::take();
    let previous = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&previous);

    let (audio_rx, fake, session, info) = live_sink_session(&previous);
    let mon = session.audio_monitor().unwrap();
    let id = wait_for_node(&info.node_name, "our sink node");
    let sets_before = fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count();

    // The node dies under the running session.
    println!("{}", destroy_node(id as u32));

    // 1. The session notices, and says so.
    wait_for("the session to report the dead sink", 15, || {
        mon.report().error.as_deref().is_some_and(|e| e.contains("sink node died"))
    });
    println!("the session reported: {:?}", mon.report().error);
    // 2. The gate is shut again: no more audible samples to the TV.
    wait_for("the gate to be held", 10, || !mon.report().gate_open);
    // 3. And NOT a silent fallback to the laptop's own monitor.
    assert_eq!(
        mon.capture_backend(),
        Some(CaptureBackend::Sink),
        "the session fell back to the default monitor after the sink died"
    );
    assert_eq!(
        fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count(),
        sets_before,
        "a level was sent to the TV after the sink died"
    );

    // 4. the user's output comes back anyway.
    session.shutdown();
    let _ = audio_rx.finish();
    wait_until_gone(&info.node_name, Duration::from_secs(5));
    assert_eq!(sh("pactl", &["get-default-sink"]), previous, "the output did not come back");
    assert_ne!(
        audiosink::configured_default_sink().as_deref(),
        Some(info.node_name.as_str()),
        "the machine is still configured for the dead sink"
    );
    guard.check("after a session whose sink died");
    restorer.disarm();
}

// --------------------------------------------------------------------------
// 17. A real session, and the user takes his output back
// --------------------------------------------------------------------------

/// The detach path end to end: the user picks his speakers again mid-session. His
/// choice must stand, the TV must go quiet, and the AirPlay sink must
/// DISAPPEAR from his output menu — because after a detach nothing re-opens
/// the gate, so picking it again would be silence everywhere.
#[test]
#[ignore]
fn a_session_the_user_takes_his_output_back_from_keeps_his_choice_and_removes_the_sink() {
    scratch_dirs();
    let guard = Untouched::take();
    let previous = guard.default_sink().to_string();
    let mut restorer = DefaultRestorer::arm(&previous);

    let (audio_rx, fake, session, info) = live_sink_session(&previous);
    let mon = session.audio_monitor().unwrap();
    let sets_before = fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count();

    // He picks his speakers back, from the desktop.
    assert!(Command::new("pactl")
        .args(["set-default-sink", &previous])
        .stdin(std::process::Stdio::null())
        .status()
        .expect("pactl")
        .success());

    wait_for("the session to detach", 20, || mon.volume().state.starts_with("detached"));
    println!("the session reported: {}", mon.volume().state);
    // The node must go, or it sits in his output menu making no sound.
    wait_until_gone(&info.node_name, Duration::from_secs(10));
    assert!(
        !audiosink::live_sinks().iter().any(|s| s == &info.node_name),
        "the AirPlay sink is still selectable after the detach"
    );
    // His choice stands, and the TV is told nothing more.
    assert_eq!(sh("pactl", &["get-default-sink"]), previous, "his choice was overridden");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!mon.report().gate_open, "the gate must be held once the sound is not going to the TV");
    assert_eq!(
        fake.requests().iter().filter(|r| r.method == "SET_PARAMETER").count(),
        sets_before,
        "a level was sent to the TV after the user took his output back"
    );

    session.shutdown();
    let _ = audio_rx.finish();
    assert_eq!(sh("pactl", &["get-default-sink"]), previous, "shutdown moved his output");
    guard.check("after the user took his output back");
    assert!(audiosink::state::read().is_none(), "nothing of ours is left, so the claim may go");
    restorer.disarm();
}
