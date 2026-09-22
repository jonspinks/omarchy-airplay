//! Live test of the laptop side of the volume sync ([`PactlVolume`]) against
//! the running PipeWire (pipewire-pulse). `#[ignore]`d; run explicitly:
//!
//! ```text
//! mise exec -- cargo test --release --test volume_live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! SILENT AND NON-INVASIVE (hard rule 2): it loads its OWN null sink
//! (`airplay_test_<pid>_vol`, `priority.session=0`), and every read, set,
//! mute and subscription is on that sink only, by name. Nothing is played.
//! The default sink, default source and default sink volume are snapshotted
//! first and asserted identical at the end. The module is unloaded by index
//! in a Drop guard. No AirPlay receiver is contacted.

use airplay_rs::volume::{LaptopEvent, LaptopVolume, PactlVolume, TvVolume};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn sh(cmd: &str, args: &[&str]) -> String {
    let o = Command::new(cmd).args(args).stdin(Stdio::null()).output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn snapshot() -> (String, String, String) {
    (
        sh("pactl", &["get-default-sink"]),
        sh("pactl", &["get-default-source"]),
        sh("wpctl", &["get-volume", "@DEFAULT_AUDIO_SINK@"]),
    )
}

struct NullSink {
    name: String,
    module: u32,
}

impl Drop for NullSink {
    fn drop(&mut self) {
        let ok = Command::new("pactl").args(["unload-module", &self.module.to_string()]).status().map(|s| s.success());
        println!("unloaded {} (module {}): {ok:?}", self.name, self.module);
    }
}

#[test]
#[ignore = "needs pipewire-pulse; loads its own silent null sink and changes only ITS volume"]
fn pactl_backend_roundtrip_own_null_sink() {
    let before = snapshot();
    println!("snapshot before: {before:?}");
    assert!(!before.0.is_empty());
    {
        let name = format!("airplay_test_{}_vol", std::process::id());
        let out = Command::new("pactl")
            .args([
                "load-module",
                "module-null-sink",
                &format!("sink_name={name}"),
                "rate=44100",
                "channels=2",
                &format!("sink_properties=node.description={name} priority.session=0 priority.driver=0"),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let sink = NullSink { name: name.clone(), module: String::from_utf8_lossy(&out.stdout).trim().parse().unwrap() };
        let t0 = Instant::now();
        while !sh("pactl", &["list", "short", "sinks"]).contains(&name) {
            assert!(t0.elapsed() < Duration::from_secs(3));
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(snapshot(), before, "loading our sink changed the user's defaults");

        let mut v = PactlVolume::for_sink(&sink.name);
        let rx = v.subscribe().unwrap();
        let l = v.read().unwrap();
        println!("initial: {}% muted={}", l.pct(), l.muted());

        let drain = |rx: &std::sync::mpsc::Receiver<LaptopEvent>| while rx.try_recv().is_ok() {};
        let wait_change = |rx: &std::sync::mpsc::Receiver<LaptopEvent>| {
            rx.recv_timeout(Duration::from_secs(2)).expect("a change event from pactl subscribe")
        };

        drain(&rx);
        v.set(37, false).unwrap();
        assert_eq!(wait_change(&rx), LaptopEvent::Change);
        let l = v.read().unwrap();
        assert_eq!((l.pct(), l.muted()), (37, false));
        assert_eq!(TvVolume::from_laptop(l).set_body(), b"volume: -18.900000\r\n");

        drain(&rx);
        v.set(0, true).unwrap();
        wait_change(&rx);
        let l = v.read().unwrap();
        assert_eq!((l.pct(), l.muted()), (37, true), "mute keeps the slider");
        assert!(TvVolume::from_laptop(l).is_mute());

        drain(&rx);
        v.set(62, false).unwrap();
        wait_change(&rx);
        let l = v.read().unwrap();
        assert_eq!((l.pct(), l.muted()), (62, false));
        drop(v); // kills pactl subscribe
    }
    let after = snapshot();
    println!("snapshot after: {after:?}");
    assert_eq!(after, before, "the user's audio state changed");
}
