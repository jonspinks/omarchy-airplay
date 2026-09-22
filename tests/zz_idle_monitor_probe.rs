//! TEMPORARY adversarial probe (review verification, not a kept test).
//!
//! Question: with the sender's own sink published and NOTHING playing into
//! it, does a `PipewireSource` pinned to that sink's monitor deliver frames?
//! That is the single fact the sink-mode start-up path depends on.
//!
//! Non-invasive: publishes our own client node only, never becomes the
//! default, never writes a volume, loads no module.

#[path = "support/audio_rules.rs"]
mod rules;

use airplay_rs::audiocapture::{PcmSource, PipewireSource, PwCaptureOpts};
use airplay_rs::audiosink::{AirPlaySink, SinkOpts};
use airplay_rs::clock::BoottimeClock;
use rules::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn scratch_dirs() {
    let base = std::env::temp_dir().join(format!("airplay-idle-probe-{}", std::process::id()));
    std::fs::create_dir_all(base.join("state")).unwrap();
    std::fs::create_dir_all(base.join("run")).unwrap();
    std::env::set_var("AIRPLAY_RS_STATE_DIR", base.join("state"));
    std::env::set_var("AIRPLAY_RS_RUNTIME_DIR", base.join("run"));
}

#[test]
#[ignore]
fn idle_monitor_delivers_silence_frames() {
    scratch_dirs();
    let guard = Untouched::take();

    let sink = AirPlaySink::publish(SinkOpts::for_receiver("75\" Probe Frame idle")).expect("publish");
    let ours = sink.node_name().to_string();
    assert_eq!(sink.is_default(), Some(false), "probe must not take the output");

    let cap_name = unique("idleprobe");
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

    // NOTHING is played into the sink. This is the `airplay mirror --audio
    // system` start-up case exactly.
    let t0 = Instant::now();
    let mut frames = 0u64;
    let mut nonzero = 0u64;
    let mut first_frame_at: Option<Duration> = None;
    while t0.elapsed() < Duration::from_secs(2) {
        match cap.next_frame(Duration::from_millis(50)) {
            Ok(Some(b)) => {
                frames += 1;
                first_frame_at.get_or_insert(t0.elapsed());
                if b.pcm.iter().any(|&x| x != 0) {
                    nonzero += 1;
                }
            }
            Ok(None) => {}
            Err(e) => panic!("capture error: {e}"),
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    println!(
        "IDLE MONITOR: {frames} frames in {secs:.2} s = {:.1}/s (expected ~{:.1}/s); \
         first frame at {first_frame_at:?}; non-silent frames {nonzero}; \
         node process() calls {}; capture stats {:?}",
        frames as f64 / secs,
        44100.0 / 352.0,
        sink.process_calls(),
        cap.stats()
    );

    drop(cap);
    let name = ours.clone();
    drop(sink);
    wait_until_gone(&name, Duration::from_secs(3));
    guard.check("after the idle probe");

    assert!(frames > 0, "REFUTED-OR-REAL: the idle monitor delivered NO frames at all");
    let rate = frames as f64 / secs;
    assert!(rate > 100.0, "idle monitor frame rate {rate:.1}/s is far below 125/s");
    assert_eq!(nonzero, 0, "the idle monitor was not silent");
}
