//! Shared hard-rule-2 scaffolding for the live audio tests: the "nothing of
//! the user's changed" snapshot, a `pw-cat` player pinned to one sink, the link
//! verifier, and the chirp.
//!
//! Every helper here is read-only about the user's machine except
//! [`DefaultRestorer`], which exists precisely so that a test that *does*
//! change the default output puts it back — on success, on failure and on
//! panic, because the restore happens in a `Drop`.
//!
//! Lifted here (rather than copied) so that `audio_sink_live.rs` and any
//! later live test share one definition of what "non-invasive" means.

#![allow(dead_code)]

use airplay_rs::audiocapture::PcmBlock;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

pub const RATE: usize = 44100;
/// Signal peak: -40.8 dBFS. Nothing here is ever routed to a real device, and
/// this is quiet even if something did.
pub const AMP: f64 = 300.0;

pub fn sh(cmd: &str, args: &[&str]) -> String {
    let o = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{cmd}: {e}"));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

// --------------------------------------------------------------------------
// Rule-2 snapshot
// --------------------------------------------------------------------------

/// Everything a test must leave exactly as it found it.
///
/// Wider than the capture tests' three-field snapshot, because this sink work
/// can change the default output and must prove it changed nothing else:
/// `modules` is here so that "our sink loads no module" is an assertion rather
/// than a belief, and `configured_default` because that is the field that
/// survives a reboot.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AudioSnapshot {
    pub default_sink: String,
    pub default_source: String,
    pub sink_volume: String,
    pub modules: String,
    pub configured_default: String,
}

pub fn snapshot() -> AudioSnapshot {
    AudioSnapshot {
        default_sink: sh("pactl", &["get-default-sink"]),
        default_source: sh("pactl", &["get-default-source"]),
        sink_volume: sh("wpctl", &["get-volume", "@DEFAULT_AUDIO_SINK@"]),
        modules: sh("pactl", &["list", "short", "modules"]),
        configured_default: airplay_rs::audiosink::configured_default_sink().unwrap_or_default(),
    }
}

/// Holds the "before" snapshot; `check` asserts nothing of the user's changed.
pub struct Untouched(pub AudioSnapshot);

impl Untouched {
    pub fn take() -> Self {
        let s = snapshot();
        println!("snapshot before: default={} configured={}", s.default_sink, s.configured_default);
        assert!(!s.default_sink.is_empty(), "no default sink? refusing to run");
        Untouched(s)
    }

    pub fn check(&self, when: &str) {
        let now = snapshot();
        assert_eq!(now.default_sink, self.0.default_sink, "default sink changed ({when})");
        assert_eq!(now.default_source, self.0.default_source, "default source changed ({when})");
        assert_eq!(now.sink_volume, self.0.sink_volume, "default sink volume changed ({when})");
        assert_eq!(now.modules, self.0.modules, "a module was loaded or unloaded ({when})");
        assert_eq!(
            now.configured_default, self.0.configured_default,
            "the configured default sink changed ({when})"
        );
        println!("snapshot {when}: identical");
    }

    /// Everything except the two default-sink fields, for the window in which
    /// a test legitimately owns the output.
    pub fn check_except_default(&self, when: &str) {
        let now = snapshot();
        assert_eq!(now.default_source, self.0.default_source, "default source changed ({when})");
        assert_eq!(now.modules, self.0.modules, "a module was loaded or unloaded ({when})");
        println!("snapshot {when}: nothing but the output changed");
    }

    pub fn default_sink(&self) -> &str {
        &self.0.default_sink
    }
}

/// Puts the default output back on `Drop`, whatever happened — success,
/// assertion failure or panic. Hard rule 2 wants the restore proven in the
/// same test as the change, and a destructor is the only thing that is.
pub struct DefaultRestorer {
    want: String,
    armed: bool,
}

impl DefaultRestorer {
    pub fn arm(want: &str) -> Self {
        DefaultRestorer { want: want.to_string(), armed: true }
    }

    /// The test restored it itself and proved it; stop trying.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DefaultRestorer {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let now = sh("pactl", &["get-default-sink"]);
        let configured = airplay_rs::audiosink::configured_default_sink().unwrap_or_default();
        if now == self.want && configured == self.want {
            return;
        }
        eprintln!("restorer: putting the output back to {} (was {now}/{configured})", self.want);
        let _ = Command::new("pactl")
            .args(["set-default-sink", &self.want])
            .stdin(Stdio::null())
            .status();
    }
}

// --------------------------------------------------------------------------
// Graph inspection
// --------------------------------------------------------------------------

static SEQ: AtomicU32 = AtomicU32::new(0);

pub fn unique(tag: &str) -> String {
    format!("airplay_test_{}_{}_{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed), tag)
}

pub fn pw_dump() -> serde_json::Value {
    let out = Command::new("pw-dump").stdin(Stdio::null()).output().expect("pw-dump");
    serde_json::from_slice(&out.stdout).expect("pw-dump json")
}

pub fn node_id(name: &str) -> Option<u64> {
    pw_dump().as_array()?.iter().find_map(|o| {
        (o["type"].as_str()?.ends_with(":Node") && o["info"]["props"]["node.name"].as_str()? == name)
            .then(|| o["id"].as_u64())
            .flatten()
    })
}

/// One node's props, by `node.name`.
pub fn node_props(name: &str) -> Option<serde_json::Value> {
    pw_dump().as_array()?.iter().find_map(|o| {
        (o["type"].as_str()?.ends_with(":Node") && o["info"]["props"]["node.name"].as_str()? == name)
            .then(|| o["info"]["props"].clone())
    })
}

pub fn wait_for_node(name: &str, what: &str) -> u64 {
    let t0 = Instant::now();
    loop {
        if let Some(id) = node_id(name) {
            return id;
        }
        assert!(t0.elapsed() < Duration::from_secs(5), "{what} ({name}) never appeared");
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn wait_until_gone(name: &str, within: Duration) -> Duration {
    let t0 = Instant::now();
    loop {
        if node_id(name).is_none() {
            return t0.elapsed();
        }
        assert!(t0.elapsed() < within, "{name} was still there after {within:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// (output node name, input node name) for every link touching `node`.
pub fn links_of(node: u64) -> Vec<(String, String)> {
    let d = pw_dump();
    let arr = d.as_array().unwrap();
    let name = |id: u64| {
        arr.iter()
            .find(|o| o["id"].as_u64() == Some(id))
            .and_then(|o| o["info"]["props"]["node.name"].as_str())
            .unwrap_or("?")
            .to_string()
    };
    arr.iter()
        .filter(|o| o["type"].as_str().is_some_and(|t| t.ends_with(":Link")))
        .filter_map(|o| {
            let i = &o["info"];
            let (a, b) = (i["output-node-id"].as_u64()?, i["input-node-id"].as_u64()?);
            (a == node || b == node).then(|| (name(a), name(b)))
        })
        .collect()
}

/// Wait until `node` has at least one link and every link is to/from `peer`.
/// Called before any non-zero sample is written, so nothing can reach a real
/// device even if the routing were wrong.
pub fn assert_linked_only_to(node: u64, peer: &str, what: &str) {
    let t0 = Instant::now();
    loop {
        let l = links_of(node);
        if !l.is_empty() {
            for (a, b) in &l {
                assert!(a == peer || b == peer, "{what} linked to something other than {peer}: {l:?}");
            }
            println!("{what} links: {l:?}");
            return;
        }
        assert!(t0.elapsed() < Duration::from_secs(5), "{what} never linked");
        std::thread::sleep(Duration::from_millis(30));
    }
}

// --------------------------------------------------------------------------
// Signal and player
// --------------------------------------------------------------------------

/// A 200 Hz -> 1 kHz linear chirp at -40.8 dBFS; R = -2/3 L so a channel swap
/// is visible. Interleaved s16 samples.
pub fn chirp(seconds: f64) -> Vec<i16> {
    let n = (seconds * RATE as f64) as usize;
    let (f0, f1) = (200.0, 1000.0);
    let k = (f1 - f0) / seconds;
    let mut v = Vec::with_capacity(n * 2);
    for i in 0..n {
        let t = i as f64 / RATE as f64;
        let ph = 2.0 * std::f64::consts::PI * (f0 * t + 0.5 * k * t * t);
        v.push((AMP * ph.sin()).round() as i16);
        v.push((-(AMP * 2.0 / 3.0) * ph.sin()).round() as i16);
    }
    v
}

pub fn to_bytes(s: &[i16]) -> Vec<u8> {
    s.iter().flat_map(|x| x.to_le_bytes()).collect()
}

pub fn peak_of(samples: &[i16]) -> u16 {
    samples.iter().map(|s| s.unsigned_abs()).max().unwrap_or(0)
}

/// `pw-cat` pinned to `sink`, with `node.dont-move`, `node.dont-fallback` and
/// `node.dont-reconnect` so it cannot end up anywhere else.
pub struct Player {
    child: Child,
    pub name: String,
}

impl Player {
    pub fn start(sink: &str) -> Player {
        let name = unique("player");
        let props = format!(
            "{{ node.name = \"{name}\" node.dont-move = true node.dont-fallback = true node.dont-reconnect = true }}"
        );
        let child = Command::new("pw-cat")
            .args([
                "--playback", "--raw", "--target", sink, "--rate", "44100", "--channels", "2",
                "--format", "s16", "--volume", "1.0", "-P", &props, "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pw-cat");
        Player { child, name }
    }

    /// Write silence, then verify our only link is into `sink` before any
    /// non-zero sample is written.
    pub fn preroll_and_verify(&mut self, sink: &str, seconds: f64) {
        let silence = vec![0u8; (seconds * RATE as f64) as usize * 4];
        self.child.stdin.as_mut().unwrap().write_all(&silence[..silence.len() / 2]).unwrap();
        let id = wait_for_node(&self.name, "player node");
        assert_linked_only_to(id, sink, "player");
        self.child.stdin.as_mut().unwrap().write_all(&silence[silence.len() / 2..]).unwrap();
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    }
}

impl Drop for Player {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// --------------------------------------------------------------------------
// Capture analysis
// --------------------------------------------------------------------------

pub fn samples(blocks: &[PcmBlock]) -> Vec<i16> {
    blocks
        .iter()
        .flat_map(|b| b.pcm.chunks(2).map(|c| i16::from_le_bytes([c[0], c[1]])))
        .collect()
}

pub struct Match {
    /// Signal start in the capture, in (fractional) sample frames.
    pub delay_frames: f64,
    pub max_err: i32,
    pub rms_err: f64,
    /// Samples identical to the integer-aligned reference (reported only).
    pub exact: usize,
    pub compared: usize,
}

/// Linear interpolation of channel `ch` of interleaved `r` at frame `x`.
fn interp(r: &[i16], x: f64, ch: usize) -> f64 {
    let i = x.floor() as usize;
    let f = x - i as f64;
    let a = r[i * 2 + ch] as f64;
    let b = r.get((i + 1) * 2 + ch).copied().unwrap_or(0) as f64;
    a + (b - a) * f
}

/// Align `reference` (interleaved) inside `cap`: coarse by the first loud
/// sample, integer search, then a fractional-delay search (the graph may
/// resample 44.1 -> 48 -> 44.1 kHz, which shifts by a fraction of a sample).
/// Then compare every sample of both channels.
pub fn align_and_compare(reference: &[i16], cap: &[i16]) -> Match {
    let first = cap
        .chunks(2)
        .position(|f| f[0].unsigned_abs() > 20)
        .expect("signal never arrived in the capture");
    let ref_first = reference.chunks(2).position(|f| f[0].unsigned_abs() > 20).unwrap();
    let guess = first as i64 - ref_first as i64;
    let n = reference.len() / 2;
    let err_at = |d: f64, step: usize| -> f64 {
        let mut e = 0f64;
        for i in (0..n - 1).step_by(step) {
            // cap at integer frame kk corresponds to reference at kk - d.
            let kk = (d.ceil() as usize) + i;
            if (kk + 1) * 2 > cap.len() || (kk as f64 - d) > (n - 2) as f64 {
                break;
            }
            let x = kk as f64 - d;
            for ch in 0..2 {
                let dd = cap[kk * 2 + ch] as f64 - interp(reference, x, ch);
                e += dd * dd;
            }
        }
        e
    };
    let mut best = (f64::MAX, 0f64);
    for lag in (guess - 64).max(0)..=(guess + 64) {
        let e = err_at(lag as f64, 7);
        if e < best.0 {
            best = (e, lag as f64);
        }
    }
    let base = best.1;
    for s in -50..=50 {
        let d = base + s as f64 * 0.02;
        if d < 0.0 {
            continue;
        }
        let e = err_at(d, 3);
        if e < best.0 {
            best = (e, d);
        }
    }
    let d = best.1;
    let start = d.ceil() as usize;
    assert!((start + n) * 2 <= cap.len(), "capture too short for the whole signal");
    let (mut max_err, mut sq, mut cnt, mut exact) = (0i32, 0f64, 0usize, 0usize);
    let lag_i = d.round() as usize;
    for kk in start..start + n - 1 {
        let x = kk as f64 - d;
        if x > (n - 2) as f64 {
            break;
        }
        for ch in 0..2 {
            let dd = (cap[kk * 2 + ch] as f64 - interp(reference, x, ch)).round() as i32;
            max_err = max_err.max(dd.abs());
            sq += (dd * dd) as f64;
            cnt += 1;
        }
    }
    for (i, r) in reference.iter().enumerate().take(n * 2) {
        exact += (cap.get(lag_i * 2 + i) == Some(r)) as usize;
    }
    Match {
        delay_frames: d,
        max_err,
        rms_err: (sq / cnt as f64).sqrt(),
        exact,
        compared: cnt,
    }
}
