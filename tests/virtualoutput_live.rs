//! Live tests for the Extend virtual output. These drive a **real Hyprland**
//! and create and remove real headless outputs, so they are `#[ignore]`d and
//! run explicitly:
//!
//! ```text
//! mise exec -- cargo test --test virtualoutput_live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `--test-threads=1` is not optional in spirit — they mutate one shared
//! compositor and the state file path is a process-wide environment variable —
//! but it is not relied on either: every test takes [`serial`] first, so a run
//! without the flag is still correct, just no faster.
//!
//! **Safety contract, enforced by every test in this file:**
//!
//! * the monitor set is snapshotted at entry and asserted identical at exit,
//!   so a phantom output can never survive a run;
//! * a [`Bomb`] guard raw-removes the test's own output on drop, so a *panicking
//!   assertion* cannot leak one either — this is the case a `?`-based cleanup
//!   would miss;
//! * every output is named `AIRPLAY-T<n>`, one per test, so two tests can never
//!   fight over a name and nothing here can name `eDP-1`. The three workspace
//!   tests are the exception and must be: the whole point of the appended
//!   workspace is that the name is `AIRPLAY-<N>` for the N being claimed, so
//!   they cannot use a `T`-prefixed name and still test anything. They are
//!   serialised like everything else, and they carry a second snapshot —
//!   [`workspace_shape`] — because pinning is the one operation here that could
//!   move a workspace of the user's, which a restored monitor set would not reveal.
//!
//! The last group of tests drives the **real `airplay` binary** as a child
//! process and signals it, because that is the only honest way to test the
//! teardown layers: a `Drop` guard exercised in-process proves nothing about
//! what SIGINT does, and signalling through a shell wrapper (`cmd & kill $!`)
//! signals the *shell*, not the binary — a trap that produced two wrong
//! measurements before this file existed. [`Run::spawn`] execs the binary
//! directly, so `child.id()` is the pid that matters.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use airplay_rs::virtualoutput::{
    self as vo, state, Monitor, VirtualOutput, VirtualOutputError,
};

// ------------------------------------------------------------------ harness

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `hyprctl <args>`, or `None` if it could not be run at all. Used where a
/// panic is not an option: inside a `Drop` that may already be unwinding, where
/// panicking would abort the test binary outright and leave every *other* guard
/// unrun — including the ones that remove outputs.
fn hyprctl_opt(args: &[&str]) -> Option<String> {
    let out = Command::new("hyprctl").args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn hyprctl(args: &[&str]) -> String {
    hyprctl_opt(args).expect("run hyprctl")
}

fn monitors() -> Vec<Monitor> {
    vo::parse_monitors(&hyprctl(&["monitors", "all", "-j"])).expect("parse monitors all -j")
}

/// The part of a monitor row the user would notice if it changed: which outputs
/// exist, how big they are, and where they sit. `focused` is deliberately
/// excluded — creating an output steals focus and removing it hands focus back,
/// and that transient is not what "restore his desktop" means.
fn shape(ms: &[Monitor]) -> Vec<(String, u32, u32, i32, i32, String)> {
    let mut v: Vec<_> = ms
        .iter()
        .map(|m| (m.name.clone(), m.width, m.height, m.x, m.y, format!("{:.3}", m.scale)))
        .collect();
    v.sort();
    v
}

fn names(ms: &[Monitor]) -> Vec<String> {
    let mut v: Vec<_> = ms.iter().map(|m| m.name.clone()).collect();
    v.sort();
    v
}

fn present(name: &str) -> bool {
    monitors().iter().any(|m| m.name == name)
}

/// Every live workspace as `(id, monitor, windows)`, sorted.
///
/// The second half of the safety contract, and the half the monitor snapshot
/// cannot see: pinning a workspace to the TV is exactly the operation that
/// could *move* one of the user's workspaces, windows and all, and a restored
/// monitor set would say nothing about that. Asserted identical at exit by
/// every test that pins anything.
fn workspace_shape() -> Vec<(i64, String, i64)> {
    let json = hyprctl(&["workspaces", "-j"]);
    let v: serde_json::Value = serde_json::from_str(&json).expect("parse workspaces -j");
    let mut out: Vec<(i64, String, i64)> = v
        .as_array()
        .expect("workspaces -j is an array")
        .iter()
        .map(|w| {
            (
                w["id"].as_i64().expect("workspace id"),
                w["monitor"].as_str().unwrap_or_default().to_string(),
                w["windows"].as_i64().unwrap_or(0),
            )
        })
        .collect();
    out.sort();
    out
}

/// The workspace `name`'s output is currently showing, per `monitors all -j`.
fn active_workspace_of(name: &str) -> Option<i64> {
    monitors()
        .iter()
        .find(|m| m.name == name)
        .and_then(|m| m.active_workspace.as_ref())
        .map(|w| w.id)
}

/// Unconditionally removes `name` on drop, including while a panic unwinds.
/// `hyprctl output remove` on a name that is already gone is harmless.
struct Bomb(String);
impl Bomb {
    fn new(name: impl Into<String>) -> Self {
        Bomb(name.into())
    }
}
impl Drop for Bomb {
    fn drop(&mut self) {
        // The removal is *verified*, not assumed. A child killed mid-`output
        // create` can leave its own `hyprctl` still in flight, so a single
        // one-shot remove can land before the output it is meant to remove has
        // even appeared. Re-read the monitor set and retry briefly.
        //
        // Nothing in here may panic: this runs during unwinds, where a second
        // panic aborts the process and every remaining guard with it.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let _ = hyprctl_opt(&["output", "remove", &self.0]);
            let gone = hyprctl_opt(&["monitors", "all", "-j"])
                .and_then(|j| vo::parse_monitors(&j).ok())
                .map(|ms| !ms.iter().any(|m| m.name == self.0))
                .unwrap_or(true); // cannot tell: retrying would not help either
            if gone || Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// A private runtime dir for the claim + lock, so a test can plant a claim
/// without touching the real one the user's own runs would use.
///
/// Declare it **before** any [`Run`] in the same test. Drop order is reverse
/// declaration order, so the child is killed and reaped first and this dir —
/// holding that child's claim and lock — is only deleted once no live process
/// depends on it.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("airplay-rs-live-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::env::set_var("AIRPLAY_RS_RUNTIME_DIR", &p);
        Scratch(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::env::remove_var("AIRPLAY_RS_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn instance() -> String {
    std::env::var("HYPRLAND_INSTANCE_SIGNATURE").expect("running under Hyprland")
}

fn claim(name: &str, instance: &str) -> state::Claim {
    state::Claim {
        name: name.to_string(),
        instance: instance.to_string(),
        pid: 999_999, // a pid that is not us and is not running
        created_unix: state::now_unix(),
        // These fixtures plant claims for `AIRPLAY-T<n>` names, which spell no
        // workspace, so there is none to record.
        workspace: vo::workspace_for_name(name),
    }
}

/// Poll `cond` until it holds or `deadline` passes. Returns whether it held.
fn wait_until(deadline: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    loop {
        if cond() {
            return true;
        }
        if started.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ------------------------------------------------- the binary, as a child

/// A live `airplay` child process, its output captured to a file.
///
/// Output goes to a **file**, not a pipe: a piped stdout that nobody reads until
/// `wait` can deadlock on the 64 KiB pipe buffer, and the whole point here is to
/// let the child run unattended while we signal it.
struct Run {
    child: Child,
    log: PathBuf,
    /// Set once the child has been reaped. `Drop` consults it so it never
    /// signals a pid that has already been waited on and may since have been
    /// recycled onto some unrelated process.
    reaped: bool,
}

/// Kill and reap the child if nothing else has.
///
/// `std::process::Child` deliberately does *not* kill or reap on drop, so
/// without this any panic between [`Run::spawn`] and [`Run::wait`] — most
/// reachably the `wait_until` assert in [`spawn_streaming_extend`], or one of
/// the `.expect`s inside its polling closure — detaches a live `airplay
/// mirror-bench --extend` child that owns a real headless output on the user's
/// desktop, and leaves it there for the remaining `--seconds`.
///
/// Reaping (not merely signalling) is the point: it makes the child *already
/// gone* by the time the guards declared before the `Run` drop, so the [`Bomb`]
/// removes an output nobody is still creating, and [`Scratch`] deletes a
/// runtime dir whose claim and lock no live process still depends on. That
/// ordering is why every test declares its `Scratch` before its `Run`.
impl Drop for Run {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: our own child, not yet reaped, so the pid cannot be recycled.
        let _ = unsafe { libc::kill(self.child.id() as i32, libc::SIGKILL) };
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Run {
    /// Exec the binary directly. `env!("CARGO_BIN_EXE_airplay")` is the very
    /// binary this test run built, debug or release.
    fn spawn(runtime_dir: &Path, log: PathBuf, args: &[&str]) -> Self {
        let file = std::fs::File::create(&log).expect("create child log");
        let err = file.try_clone().expect("dup child log");
        let child = Command::new(env!("CARGO_BIN_EXE_airplay"))
            .args(args)
            .env("AIRPLAY_RS_RUNTIME_DIR", runtime_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn airplay");
        Run { child, log, reaped: false }
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    fn signal(&self, sig: libc::c_int) {
        // SAFETY: our own child, not yet reaped, so the pid cannot be recycled.
        assert_eq!(unsafe { libc::kill(self.pid(), sig) }, 0, "kill({sig}) failed");
    }

    /// Wait for exit, killing it if it overruns so a hung child can never hold
    /// the test (or a phantom output) open.
    fn wait(mut self, deadline: Duration) -> (std::process::ExitStatus, String) {
        let started = Instant::now();
        let status = loop {
            match self.child.try_wait().expect("try_wait") {
                Some(s) => break s,
                None if started.elapsed() >= deadline => {
                    self.signal(libc::SIGKILL);
                    break self.child.wait().expect("wait after kill");
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        self.reaped = true; // `Drop` must not signal this pid again
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        (status, text)
    }
}

/// Start a `mirror-bench --extend` run and wait until its output is actually
/// live and the pipeline is streaming, so what we signal is a *running* stream
/// and not a process still starting up.
///
/// `mirror-bench` is used rather than `mirror` on purpose: it runs the identical
/// create -> capture -> encode -> `run_stream` -> teardown path with no receiver,
/// so these tests need the compositor and the GPU but not the TV.
fn spawn_streaming_extend(dir: &Path, log: PathBuf, name: &'static str) -> Run {
    spawn_extend_bench(dir, log, name, "120")
}

/// As [`spawn_streaming_extend`], with `--seconds` spelled out — `"0"` for a run
/// that only a signal can end.
fn spawn_extend_bench(dir: &Path, log: PathBuf, name: &'static str, seconds: &str) -> Run {
    let run = Run::spawn(
        dir,
        log,
        &["mirror-bench", "--extend", name, "--receiver", "1920x1080", "--seconds", seconds],
    );
    assert!(
        wait_until(Duration::from_secs(30), || present(name)),
        "{name} never came up; child log:\n{}",
        std::fs::read_to_string(&run.log).unwrap_or_default()
    );
    // Let the pipeline get past `ScreenPipeline::start` and into `run_stream`,
    // so the signal lands on a live capture + encoder and not on the setup path.
    std::thread::sleep(Duration::from_secs(3));
    run
}

/// `airplay status --json` through the real binary, parsed.
///
/// The document is found by its leading `{`: this harness points the child's
/// stdout and stderr at one file, and the contract is that stdout carries
/// nothing but the one JSON object, so a diagnostic line must not be mistaken
/// for it.
fn status_json(dir: &Path, log: PathBuf) -> serde_json::Value {
    let (code, out) = Run::spawn(dir, log, &["status", "--json"]).wait(Duration::from_secs(15));
    assert!(code.success(), "status --json must exit 0; got {code:?}\n{out}");
    let line = out
        .lines()
        .find(|l| l.starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON object on stdout:\n{out}"));
    assert_eq!(
        out.lines().filter(|l| l.starts_with('{')).count(),
        1,
        "exactly one JSON object, never a stream:\n{out}"
    );
    serde_json::from_str(line).unwrap_or_else(|e| panic!("parse {line:?}: {e}"))
}

/// Pull the value out of one `label<padding>: value` line of the bench ledger.
///
/// Matched on the label and the padded ` : ` separator rather than on the
/// padding width (which is cosmetic) or on a bare `:` (the label `extend 1:1`
/// contains one of its own).
fn field<'a>(log: &'a str, label: &str) -> Option<&'a str> {
    log.lines().find_map(|l| {
        let (k, v) = l.split_once(" : ")?;
        (k.trim_end() == label).then_some(v.trim())
    })
}

/// The leading integer of a ledger value: `142` out of
/// `142  (7 IDR, 0 from keepalive repeats)`.
fn leading_count(v: &str) -> Option<u64> {
    v.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// Assert the run actually *did* something, as opposed to merely starting and
/// stopping cleanly.
///
/// This is the counterpart to every teardown assertion in this file, and it is
/// not redundant with them: a headless output that delivers zero frames still
/// gets created, `ScreenPipeline::start` still opens on the format alone,
/// `run_stream` still returns `Ok` with `access_units: 0`, `finish_extend`
/// still prints its removal line, and the process still exits 0. Without these
/// four lines all three binary-driven tests pass with Extend producing nothing.
///
/// The sizes are exact on purpose: `--receiver 1920x1080` makes
/// `extend_mode` a fixed point of the fit, so a 1:1 passthrough is the only
/// correct answer and any scale pass shows up here as a different coded size.
fn assert_extend_actually_streamed(log: &str) {
    assert!(
        field(log, "fit").is_some_and(|v| v.starts_with("1920x1080 -> 1920x1080")),
        "the headless output must be captured and coded at the receiver's exact size:\n{log}"
    );
    assert!(
        field(log, "extend 1:1").is_some_and(|v| v.starts_with("yes")),
        "extend must be a 1:1 passthrough with no scale pass:\n{log}"
    );
    let aus = field(log, "access units forwarded").and_then(leading_count);
    assert!(
        aus.unwrap_or(0) > 0,
        "not one access unit came out of the headless output (got {aus:?}):\n{log}"
    );
    let fresh = field(log, "frames captured").and_then(leading_count);
    assert!(
        fresh.unwrap_or(0) > 0,
        "not one fresh frame was captured from the headless output (got {fresh:?}):\n{log}"
    );
}

// -------------------------------------------------------------------- tests

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn create_then_drop_restores_the_monitor_set() {
    let _g = serial();
    let _s = Scratch::new("t1");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T1");

    let out = VirtualOutput::create("AIRPLAY-T1", (1920, 1080), 60).expect("create AIRPLAY-T1");
    assert_eq!(out.name(), "AIRPLAY-T1");
    assert_eq!(out.size(), (1920, 1080));

    // The compositor must report exactly what we asked for. `hl.monitor`
    // answers `ok` for an output that does not exist, so this read-back is the
    // only thing that proves the mode landed.
    let live = monitors();
    let m = live.iter().find(|m| m.name == "AIRPLAY-T1").expect("AIRPLAY-T1 is live");
    assert_eq!((m.width, m.height), (1920, 1080));
    assert_eq!(m.scale, 1.0, "scale must be 1: the capture buffer is the physical mode size");
    assert!(vo::is_headless(m), "our own output must satisfy the headless veto: {m:?}");

    // The whole point: it is capturable through the existing source type, with
    // no change anywhere below `session.rs`.
    let inv = airplay_rs::capture::list().expect("enumerate wayland outputs");
    let seen = inv
        .outputs
        .iter()
        .find(|o| o.name == "AIRPLAY-T1")
        .unwrap_or_else(|| panic!("AIRPLAY-T1 not in capture::list(): {:?}", inv.outputs));
    assert_eq!((seen.width, seen.height), (1920, 1080));
    assert_eq!(out.source(), airplay_rs::capture::CaptureSource::Output("AIRPLAY-T1".into()));

    // Extend on this Frame is a 1:1 passthrough, not a scale.
    assert_eq!(airplay_rs::encoder::fit_source_to_receiver(out.size(), (1920, 1080)), out.size());

    out.remove().expect("explicit removal reports success");
    assert!(!present("AIRPLAY-T1"));
    assert_eq!(shape(&monitors()), shape(&before), "monitor set must be exactly as found");
    assert!(state::read().is_none(), "the claim is cleared on removal");
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn a_non_default_mode_lands_and_is_read_back() {
    let _g = serial();
    let _s = Scratch::new("t2");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T2");

    let out = VirtualOutput::create("AIRPLAY-T2", (1280, 720), 30).expect("create at 1280x720@30");
    let live = monitors();
    let m = live.iter().find(|m| m.name == "AIRPLAY-T2").unwrap();
    assert_eq!((m.width, m.height), (1280, 720), "the requested mode, not the default");
    assert_eq!(m.scale, 1.0);
    assert_eq!(out.size(), (1280, 720));
    // Note what is NOT asserted: `availableModes`. It does not follow a mode
    // change on a headless output, so validating against it would fail here
    // even though the mode is demonstrably live.

    drop(out);
    assert!(!present("AIRPLAY-T2"));
    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn an_output_we_did_not_record_is_never_removed() {
    // Hard Rule 2, in test form. This is the one that must never regress: a
    // headless-looking output we did not create is refused, not swept.
    let _g = serial();
    let _s = Scratch::new("t3");
    let before = monitors();
    let bomb = Bomb::new("AIRPLAY-T3"); // the TEST owns this one, not the module

    assert_eq!(hyprctl(&["output", "create", "headless", "AIRPLAY-T3"]).trim(), "ok");
    assert!(present("AIRPLAY-T3"));
    assert!(state::read().is_none(), "no claim: we are pretending another tool made it");

    let err = VirtualOutput::create("AIRPLAY-T3", (1920, 1080), 60)
        .expect_err("an unrecorded output must not be adopted");
    assert!(matches!(err, VirtualOutputError::NameTaken(_)), "want NameTaken, got {err:?}");
    assert!(present("AIRPLAY-T3"), "the output we did not record must still be there");

    drop(bomb);
    assert!(!present("AIRPLAY-T3"));
    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn an_orphan_we_recorded_is_reclaimed() {
    // The fix for the probe's permanent-phantom bug: `created = not
    // already_present` lives only in memory, so a crashed probe run leaves an
    // output nothing will ever remove. A state file survives the crash.
    let _g = serial();
    let _s = Scratch::new("t4");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T4");

    assert_eq!(hyprctl(&["output", "create", "headless", "AIRPLAY-T4"]).trim(), "ok");
    state::write(&claim("AIRPLAY-T4", &instance())).expect("plant a claim from a dead run");

    let out = VirtualOutput::create("AIRPLAY-T4", (1920, 1080), 60)
        .expect("our own orphan must be reclaimed, not refused");
    assert_eq!(out.size(), (1920, 1080));
    assert_eq!(monitors().iter().filter(|m| m.name == "AIRPLAY-T4").count(), 1);

    drop(out);
    assert!(!present("AIRPLAY-T4"));
    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn reclaim_orphan_sweeps_a_recorded_phantom_on_its_own() {
    // What `airplay extend --cleanup` does: no create, just the sweep.
    let _g = serial();
    let _s = Scratch::new("t5");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T5");

    assert!(vo::reclaim_orphan().expect("sweep with no claim"). is_none());

    assert_eq!(hyprctl(&["output", "create", "headless", "AIRPLAY-T5"]).trim(), "ok");
    state::write(&claim("AIRPLAY-T5", &instance())).unwrap();

    let removed = vo::reclaim_orphan().expect("sweep");
    assert_eq!(removed.as_deref(), Some("AIRPLAY-T5"));
    assert!(!present("AIRPLAY-T5"));
    assert!(state::read().is_none(), "the claim is consumed");
    assert!(vo::reclaim_orphan().expect("second sweep").is_none(), "sweeping twice is a no-op");

    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn a_claim_from_another_hyprland_instance_is_ignored() {
    // A claim written under a compositor that has since died says nothing about
    // the outputs of the one running now — the names may well have been reused.
    let _g = serial();
    let _s = Scratch::new("t6");
    let before = monitors();
    let bomb = Bomb::new("AIRPLAY-T6");

    assert_eq!(hyprctl(&["output", "create", "headless", "AIRPLAY-T6"]).trim(), "ok");
    state::write(&claim("AIRPLAY-T6", "a_dead_instance_signature")).unwrap();

    let err = VirtualOutput::create("AIRPLAY-T6", (1920, 1080), 60)
        .expect_err("a stale-instance claim must not authorise a removal");
    assert!(matches!(err, VirtualOutputError::NameTaken(_)), "want NameTaken, got {err:?}");
    assert!(present("AIRPLAY-T6"), "the output must be left exactly alone");

    // ...and the useless claim is dropped rather than left to mislead the next run.
    assert!(state::read().is_none());

    drop(bomb);
    assert!(!present("AIRPLAY-T6"));
    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn a_second_instance_is_refused() {
    let _g = serial();
    let _s = Scratch::new("t7");
    let before = monitors();
    let _b1 = Bomb::new("AIRPLAY-T7");
    let _b2 = Bomb::new("AIRPLAY-T8");

    let first = VirtualOutput::create("AIRPLAY-T7", (1920, 1080), 60).expect("first create");

    let err = VirtualOutput::create("AIRPLAY-T8", (1920, 1080), 60)
        .expect_err("a second --extend must be refused while the first runs");
    assert!(matches!(err, VirtualOutputError::Busy(_)), "want Busy, got {err:?}");

    assert!(!present("AIRPLAY-T8"), "the refused run must not have created anything");
    assert!(present("AIRPLAY-T7"), "the running owner must be untouched");
    // The refused run must also not have eaten the owner's claim.
    assert_eq!(state::read().map(|c| c.name).as_deref(), Some("AIRPLAY-T7"));

    drop(first);
    assert!(!present("AIRPLAY-T7"));
    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn drop_is_idempotent_when_the_output_vanished() {
    let _g = serial();
    let _s = Scratch::new("t9");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T9");

    let out = VirtualOutput::create("AIRPLAY-T9", (1920, 1080), 60).expect("create");
    // Pull it out from under the guard, as a `hyprctl output remove` typed by
    // hand (or an `extend --cleanup` from another terminal) would.
    assert_eq!(hyprctl(&["output", "remove", "AIRPLAY-T9"]).trim(), "ok");
    assert!(!present("AIRPLAY-T9"));

    drop(out); // must not panic, must not error, must not remove anything else
    assert_eq!(shape(&monitors()), shape(&before));
    assert_eq!(names(&monitors()), names(&before));
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn status_and_preflight_are_read_only() {
    let _g = serial();
    let _s = Scratch::new("t10");
    let before = monitors();

    vo::preflight().expect("hyprctl is present and monitors all -j parses");

    let st = vo::status().expect("status");
    assert!(st.claimed.is_none(), "no run of ours is live");
    assert!(st.live.is_none());
    assert!(!st.lock_held_elsewhere);
    assert_eq!(names(&st.monitors), names(&before));

    assert_eq!(shape(&monitors()), shape(&before), "status must change nothing");
}

// ----------------------------------------------------- teardown, layer by layer

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn a_panic_holding_the_guard_still_removes_the_output() {
    // Layer (a), the case a `?`-based cleanup misses entirely: an encode panic,
    // a poisoned mailbox, any `unwrap` on the main thread. `Drop` runs during the
    // unwind, so the output goes with it.
    let _g = serial();
    let _s = Scratch::new("t11");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T11");

    let caught = std::panic::catch_unwind(|| {
        let out = VirtualOutput::create("AIRPLAY-T11", (1920, 1080), 60).expect("create");
        assert!(present(out.name()));
        panic!("deliberate panic with the guard live");
    });
    assert!(caught.is_err(), "the panic must have happened");

    assert!(!present("AIRPLAY-T11"), "Drop must have removed it while unwinding");
    assert!(state::read().is_none(), "and cleared the claim");
    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland, a VA-API device, and spawns the real binary"]
fn sigint_ends_a_live_run_and_removes_the_output() {
    // Layer (b). Before `signals::install()` this measured exit 130 with zero
    // destructors run and the output still on the desktop.
    let _g = serial();
    let s = Scratch::new("t12");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T12");

    let run = spawn_streaming_extend(&s.0, s.0.join("sigint.log"), "AIRPLAY-T12");
    run.signal(libc::SIGINT);

    let (status, log) = run.wait(Duration::from_secs(30));
    assert!(status.success(), "Ctrl-C is the EXPECTED way to end an open-ended run; got {status:?}\n{log}");
    assert!(
        log.contains("interrupted              : yes (SIGINT)"),
        "the ledger must say why the run is short:\n{log}"
    );
    assert!(
        log.contains("extend: removed virtual output AIRPLAY-T12"),
        "teardown must be reported:\n{log}"
    );
    // ...and there was a real stream to interrupt, not just a process to signal.
    assert_extend_actually_streamed(&log);
    assert!(!present("AIRPLAY-T12"), "the output must be gone");
    assert!(state::read().is_none(), "and the claim cleared");
    assert_eq!(shape(&monitors()), shape(&before), "monitor set must be exactly as found");
}

#[test]
#[ignore = "needs a live Hyprland, a VA-API device, and spawns the real binary"]
fn sigterm_ends_a_live_run_and_removes_the_output() {
    // Same layer, the signal a service manager or `pkill` sends.
    let _g = serial();
    let s = Scratch::new("t13");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T13");

    let run = spawn_streaming_extend(&s.0, s.0.join("sigterm.log"), "AIRPLAY-T13");
    run.signal(libc::SIGTERM);

    let (status, log) = run.wait(Duration::from_secs(30));
    assert!(status.success(), "got {status:?}\n{log}");
    assert!(log.contains("interrupted              : yes (SIGTERM)"), "{log}");
    assert!(!present("AIRPLAY-T13"));
    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland, a VA-API device, and spawns the real binary"]
fn a_run_that_finishes_normally_removes_the_output_and_says_so() {
    // The path every other teardown test is measured against, through the real
    // binary: no signal, no error, the clock simply runs out. `finish_extend`
    // reports the removal on stdout — `Drop` would only manage stderr — so the
    // message is asserted as well as the absence.
    let _g = serial();
    let s = Scratch::new("t14");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T14");

    let (status, log) = Run::spawn(
        &s.0,
        s.0.join("normal.log"),
        &["mirror-bench", "--extend", "AIRPLAY-T14", "--receiver", "1920x1080", "--seconds", "3"],
    )
    .wait(Duration::from_secs(90));

    assert!(status.success(), "a plain run must exit 0; got {status:?}\n{log}");
    assert!(!log.contains("interrupted"), "nothing interrupted this run:\n{log}");
    assert!(
        log.contains("extend: removed virtual output AIRPLAY-T14"),
        "the normal path must report its own teardown:\n{log}"
    );
    assert_extend_actually_streamed(&log);
    assert!(!present("AIRPLAY-T14"));
    assert!(state::read().is_none(), "the claim is cleared on a clean exit");
    assert_eq!(shape(&monitors()), shape(&before));
}

#[test]
#[ignore = "needs a live Hyprland, a VA-API device, and spawns the real binary"]
fn sigkill_leaks_an_output_that_the_next_run_reclaims() {
    // Layer (c), the only cover for SIGKILL/SIGSEGV/power loss: nothing runs in
    // the dying process, so the fix has to live in the NEXT one. This is the
    // probe's permanent-phantom bug, end to end through the real binary.
    let _g = serial();
    let s = Scratch::new("t15");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T15");

    let run = spawn_streaming_extend(&s.0, s.0.join("kill.log"), "AIRPLAY-T15");
    run.signal(libc::SIGKILL);
    let (status, log) = run.wait(Duration::from_secs(15));
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{log}");

    assert!(present("AIRPLAY-T15"), "SIGKILL runs nothing; the phantom is expected here");
    // The `flock` is released by the kernel when the fd closed, so the next run
    // is not locked out by a process that no longer exists.
    let st = vo::status().expect("status");
    assert!(!st.lock_held_elsewhere, "a dead owner must not hold the lock");
    assert!(st.live.is_some(), "status must show the claimed output as live");

    // `airplay extend --cleanup` — the escape hatch the user runs instead of hunting
    // for a phantom monitor by hand — sweeps it, through the real binary.
    let (status, out) = Run::spawn(&s.0, s.0.join("cleanup.log"), &["extend", "--cleanup"])
        .wait(Duration::from_secs(15));
    assert!(status.success(), "{out}");
    assert!(out.contains("extend: removed orphaned output AIRPLAY-T15"), "{out}");

    assert!(!present("AIRPLAY-T15"));
    assert!(state::read().is_none(), "the claim is consumed by the sweep");
    assert_eq!(shape(&monitors()), shape(&before));
}

// ------------------------------------------- run until stopped, and status

#[test]
#[ignore = "needs a live Hyprland, a VA-API device, and spawns the real binary"]
fn an_indefinite_run_streams_until_a_signal_and_prints_its_full_ledger() {
    // `--seconds 0`, the mode a panel-started session needs: no clock may end
    // it, and the signal path — which is the only way out — must behave exactly
    // as it does for a run whose clock ran out.
    //
    // Short and signalled by this test, never left running: `--seconds 0` with
    // nobody to stop it is precisely what must not be started on the user's desktop.
    let _g = serial();
    let s = Scratch::new("t20");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T20");

    let run = spawn_extend_bench(&s.0, s.0.join("indefinite.log"), "AIRPLAY-T20", "0");
    // Past `mirror-bench`'s own 10 s default, so a run still alive here is one
    // that genuinely ignored the clock rather than one that hasn't reached it.
    std::thread::sleep(Duration::from_secs(12));
    assert!(
        present("AIRPLAY-T20"),
        "an indefinite run must still be streaming after the default would have expired"
    );

    run.signal(libc::SIGTERM);
    let (code, log) = run.wait(Duration::from_secs(30));

    assert!(code.success(), "a signalled indefinite run exits 0; got {code:?}\n{log}");
    assert_eq!(
        field(&log, "duration").map(str::to_string),
        Some("until stopped".to_string()),
        "the ledger must say the run had no clock:\n{log}"
    );
    assert!(
        log.contains("interrupted              : yes (SIGTERM)"),
        "the full stats block must still print, and say why the run ended:\n{log}"
    );
    // The real stream that was interrupted, not merely a process that was
    // signalled.
    assert_extend_actually_streamed(&log);
    assert!(log.contains("-> balances"), "the frame ledger must close:\n{log}");

    // Every rate is divided by MEASURED elapsed time. With a requested duration
    // of zero, a rate computed from the request would be `inf` or `NaN` — so
    // these are parsed as numbers, not merely grepped for.
    let rate = field(&log, "measured rate").unwrap_or_else(|| panic!("no rate line:\n{log}"));
    let fps: f64 = rate
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("fps is not a number in {rate:?}"));
    let mbps: f64 = rate
        .split(", ")
        .nth(1)
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("Mb/s is not a number in {rate:?}"));
    let secs: f64 = rate
        .split(" over ")
        .nth(1)
        .and_then(|v| v.split('s').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("seconds is not a number in {rate:?}"));
    assert!(fps.is_finite() && fps > 0.0, "fps {fps} in {rate:?}");
    assert!(mbps.is_finite() && mbps > 0.0, "Mb/s {mbps} in {rate:?}");
    assert!(secs.is_finite() && secs >= 10.0, "measured seconds {secs} in {rate:?}");

    // ...and the same for the CPU line, the other place a requested duration of
    // zero would have divided by nothing.
    let cpu = field(&log, "process CPU").unwrap_or_else(|| panic!("no CPU line:\n{log}"));
    let pct: f64 = cpu
        .split("= ")
        .nth(1)
        .and_then(|v| v.split('%').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("CPU share is not a number in {cpu:?}"));
    assert!(pct.is_finite(), "CPU share {pct} in {cpu:?}");

    assert!(!present("AIRPLAY-T20"), "teardown is unchanged: the output must be gone");
    assert!(state::read().is_none(), "and the claim cleared");
    assert_eq!(shape(&monitors()), shape(&before), "monitor set must be exactly as found");
}

#[test]
#[ignore = "needs a live Hyprland, a VA-API device, and spawns the real binary"]
fn status_sees_a_live_session_then_its_orphan_and_disturbs_neither() {
    // What the user's panel polls. Four states, through the real binary: nothing
    // running, a live session, a session whose owner was SIGKILLed (an orphan
    // the panel offers to clean up), and cleaned up again.
    use serde_json::Value;
    use std::os::unix::process::ExitStatusExt as _;

    let _g = serial();
    let s = Scratch::new("t21");
    let before = monitors();
    let _bomb = Bomb::new("AIRPLAY-T21");

    // --- nothing running.
    let doc = status_json(&s.0, s.0.join("status-idle.log"));
    assert_eq!(doc["session"], Value::Null, "{doc}");
    assert_eq!(doc["orphan"], Value::Null, "{doc}");

    // --- a --output session is VISIBLE, which is the whole reason the session
    // --- record is a file of its own: before it, only --extend was. A real one
    // --- needs the TV, so the record a real run writes is planted here and the
    // --- reporting path is what gets tested.
    airplay_rs::sessionstate::write(&airplay_rs::sessionstate::SessionFile {
        session: airplay_rs::sessionstate::SessionRecord {
            kind: airplay_rs::sessionstate::SessionKind::Output,
            receiver: Some("192.0.2.187".into()),
            name: Some("eDP-1".into()),
            workspace: None,
            pid: std::process::id(), // alive: this test process
            audio: None,
        },
        created_unix: airplay_rs::sessionstate::now_unix(),
        instance: None,
    })
    .expect("plant a session record");
    let doc = status_json(&s.0, s.0.join("status-output.log"));
    assert_eq!(doc["session"]["kind"], "output", "{doc}");
    assert_eq!(doc["session"]["name"], "eDP-1", "{doc}");
    assert_eq!(doc["session"]["receiver"], "192.0.2.187", "{doc}");
    assert_eq!(doc["session"]["workspace"], Value::Null, "{doc}");
    assert_eq!(doc["session"]["pid"], std::process::id(), "{doc}");

    // A record whose owner is gone is NOT a session.
    airplay_rs::sessionstate::write(&airplay_rs::sessionstate::SessionFile {
        session: airplay_rs::sessionstate::SessionRecord {
            kind: airplay_rs::sessionstate::SessionKind::Output,
            receiver: Some("192.0.2.187".into()),
            name: Some("eDP-1".into()),
            workspace: None,
            pid: 999_999, // not us, and not running
            audio: None,
        },
        created_unix: airplay_rs::sessionstate::now_unix(),
        instance: None,
    })
    .expect("plant a dead session record");
    let doc = status_json(&s.0, s.0.join("status-dead.log"));
    assert_eq!(doc["session"], Value::Null, "a dead pid is nothing running: {doc}");
    airplay_rs::sessionstate::clear().expect("clear the planted record");

    // --- a live --extend run. `mirror-bench` has no receiver, so this also
    // --- exercises the fallback: no session record, so the Extend ownership
    // --- claim is what `status` reports, with the receiver it does not know as
    // --- null.
    let run = spawn_extend_bench(&s.0, s.0.join("t21.log"), "AIRPLAY-T21", "0");
    let pid = run.pid();
    let doc = status_json(&s.0, s.0.join("status-live.log"));
    assert_eq!(doc["session"]["kind"], "extend", "{doc}");
    assert_eq!(doc["session"]["name"], "AIRPLAY-T21", "{doc}");
    assert_eq!(doc["session"]["pid"], pid, "{doc}");
    assert_eq!(doc["session"]["receiver"], Value::Null, "{doc}");
    assert_eq!(doc["orphan"], Value::Null, "a live owner is not an orphan: {doc}");

    // Polling it hard must not disturb the run — the finding this guards
    // against is a status poll taking the exclusive lock, which failed any
    // `--extend` starting inside that window.
    for i in 0..8 {
        let doc = status_json(&s.0, s.0.join(format!("status-poll{i}.log")));
        assert_eq!(doc["session"]["pid"], pid, "poll {i}: {doc}");
    }
    assert!(present("AIRPLAY-T21"), "the run must have survived being polled");
    assert!(
        vo::status().expect("status").lock_held_elsewhere,
        "the live run still holds its lock: a poll neither took it nor broke it"
    );

    // --- SIGKILL: nothing runs in the dying process, so the output is left
    // --- behind. That is the orphan the panel offers to clean up.
    run.signal(libc::SIGKILL);
    let (code, log) = run.wait(Duration::from_secs(15));
    assert_eq!(code.signal(), Some(libc::SIGKILL), "{log}");
    assert!(present("AIRPLAY-T21"), "SIGKILL runs nothing; the phantom is expected here");

    let doc = status_json(&s.0, s.0.join("status-orphan.log"));
    assert_eq!(doc["session"], Value::Null, "the owner is dead: {doc}");
    assert_eq!(doc["orphan"]["kind"], "extend", "{doc}");
    assert_eq!(doc["orphan"]["name"], "AIRPLAY-T21", "{doc}");
    assert_eq!(doc["orphan"]["pid"], pid, "{doc}");

    // And status changed nothing: the sweep still has the same work to do.
    let (code, out) = Run::spawn(&s.0, s.0.join("cleanup21.log"), &["extend", "--cleanup"])
        .wait(Duration::from_secs(15));
    assert!(code.success(), "{out}");
    assert!(out.contains("extend: removed orphaned output AIRPLAY-T21"), "{out}");

    let doc = status_json(&s.0, s.0.join("status-clean.log"));
    assert_eq!(doc["session"], Value::Null, "{doc}");
    assert_eq!(doc["orphan"], Value::Null, "{doc}");

    assert!(!present("AIRPLAY-T21"));
    assert_eq!(shape(&monitors()), shape(&before), "monitor set must be exactly as found");
}

// ----------------------------------------------- the appended workspace

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn an_appended_output_lands_on_max_plus_one_and_moves_nothing() {
    // The behaviour the user asked for, against the real compositor: the extend
    // screen takes the workspace AFTER his highest, so it is the last button on
    // the bar rather than wedged into a gap in the middle of his set.
    //
    // This is the one test that pins a workspace on the live machine, so it
    // snapshots the WORKSPACES as well as the monitors: moving one of the user's
    // workspaces onto the TV is the failure this whole design is shaped to make
    // impossible, and a restored monitor set would not reveal it.
    let _g = serial();
    let _s = Scratch::new("t16");
    let before = monitors();
    let before_ws = workspace_shape();

    let live_ids: Vec<i64> = before_ws.iter().map(|(id, _, _)| *id).collect();
    let want = vo::next_workspace_id(&live_ids)
        .expect("this desktop has a free bar-renderable workspace");
    let highest = live_ids.iter().copied().filter(|&i| i > 0).max().unwrap_or(0);

    // One past the greater of his highest workspace and the bar's five
    // always-drawn buttons — not the lowest free id (what Hyprland would have
    // picked, which put the TV in the middle of the set) and not bare `max + 1`
    // (which lands on default slot 5 whenever his highest is below it).
    let preferred = vo::preferred_workspace_id(&live_ids);
    assert!(
        preferred > vo::BAR_DEFAULT_WORKSPACES,
        "the preferred id must clear the bar's default buttons; live ids {live_ids:?}"
    );
    if preferred <= vo::BAR_MAX_WORKSPACE {
        assert_eq!(want, preferred, "the pick must be the append target");
        assert_eq!(
            i64::from(want),
            highest.max(i64::from(vo::BAR_DEFAULT_WORKSPACES)) + 1,
            "with a highest of {highest}, the pick must append past the defaults too; \
             live ids {live_ids:?}"
        );
        assert!(
            want > vo::BAR_DEFAULT_WORKSPACES,
            "workspace {want} is one of the bar's permanent buttons, so nothing was appended"
        );
    }
    assert!(
        !live_ids.contains(&i64::from(want)),
        "the pick must be a FREE workspace; live ids {live_ids:?}"
    );
    assert!(vo::bar_shows_workspace(want), "workspace {want} would have no button on the bar");

    // The name is derived from the workspace, which is what makes a second
    // session with a different number get a fresh (uncleanable) workspace rule.
    let name = vo::name_for_workspace(want);
    assert_eq!(name, vo::append().expect("append agrees").name);
    let _bomb = Bomb::new(name.clone());

    let out = VirtualOutput::create(&name, (1920, 1080), 60)
        .unwrap_or_else(|e| panic!("create {name}: {e}"));

    // Confirmed by read-back from the compositor, not by what we asked for.
    assert_eq!(out.workspace(), Some(want), "the guard must report a CONFIRMED workspace");
    assert_eq!(
        active_workspace_of(&name),
        Some(i64::from(want)),
        "hyprctl must report {name} owning workspace {want}"
    );

    // Every one of the user's workspaces is still on the monitor it was on, with the
    // windows it had. The only change is the new one, on the new output.
    let during = workspace_shape();
    for row in &before_ws {
        assert!(
            during.contains(row),
            "workspace {} moved or lost windows: was {row:?}, now {:?}",
            row.0,
            during.iter().find(|(id, _, _)| *id == row.0)
        );
    }
    assert!(
        during.contains(&(i64::from(want), name.clone(), 0)),
        "workspace {want} must be on {name} and empty; got {during:?}"
    );
    assert_eq!(
        during.len(),
        before_ws.len() + 1,
        "exactly one workspace was added; before {before_ws:?} during {during:?}"
    );

    // The claim records the id as its own integer, for readers that should not
    // have to parse the name (the Omarchy bar widget reads this file).
    let claimed = state::read().expect("a claim while the output is up");
    assert_eq!(claimed.name, name);
    assert_eq!(claimed.workspace, Some(want));

    drop(out);
    assert!(!present(&name));
    assert_eq!(shape(&monitors()), shape(&before), "the monitor set must be restored exactly");
    assert_eq!(
        workspace_shape(),
        before_ws,
        "and every workspace must be back where it started"
    );
}

#[test]
#[ignore = "needs a live Hyprland that can create a headless output"]
fn a_name_that_asks_for_no_workspace_gets_hyprlands_choice_whatever_it_is() {
    // The `--extend NAME` escape hatch: a name with no number in it asks for no
    // particular workspace and gets Hyprland's own choice — exactly the
    // behaviour this module had before workspaces were pinned at all. Kept
    // working on purpose, because it is the way out if the pinning ever
    // misbehaves on a future Hyprland.
    //
    // This test originally asserted that the user's workspaces were untouched on
    // this path, and that assertion was WRONG — it encoded a belief the
    // unpinned path cannot deliver. **Hyprland remembers, per monitor NAME,
    // which workspace that name last displayed, and restores the association
    // when a monitor of that name reappears — even if the workspace is now
    // the user's and has his windows on it.** Measured on 0.56.2 with nothing but
    // `hyprctl`, no Rust involved, workspaces 1/2/3 all occupied:
    //
    //     hyprctl output create headless AIRPLAY-T17   -> takes workspace 3
    //                                                     (seen earlier this
    //                                                      uptime, when 3 was
    //                                                      free) — the user's
    //                                                      workspace 3 and its
    //                                                      window MOVE to it
    //     hyprctl output create headless AIRPLAY-ZZ1   -> takes workspace 4
    //                                                     (never seen: lowest
    //                                                      free)
    //
    // Deterministic, four for four, and independent of which workspace is
    // focused. `hyprctl workspacerules` shows no rule for 3, so this is the
    // memory and not the rule mechanism.
    //
    // That is the strongest argument for pinning: a workspace rule applied
    // before `output create` makes the output come up owning a **free** id, so
    // it has nothing to steal. `an_appended_output_lands_on_max_plus_one_and_
    // moves_nothing` asserts exactly that, and passes. Here the honest
    // guarantee is narrower and is what gets asserted: whatever Hyprland
    // decides, the teardown puts it all back.
    let _g = serial();
    let _s = Scratch::new("t17");
    let before = monitors();
    let before_ws = workspace_shape();
    let _bomb = Bomb::new("AIRPLAY-T17");

    let out = VirtualOutput::create("AIRPLAY-T17", (1920, 1080), 60).expect("create");
    assert_eq!(out.workspace(), None, "nothing was pinned, so nothing is claimed");
    assert_eq!(state::read().expect("a claim").workspace, None);
    assert!(present("AIRPLAY-T17"));

    // Hyprland put it *somewhere*, and we record which so the log says whether
    // this run saw a steal. Either outcome is accepted here; only the pinned
    // path promises otherwise.
    let during = workspace_shape();
    let stolen: Vec<_> =
        during.iter().filter(|(_, mon, w)| mon == "AIRPLAY-T17" && *w > 0).collect();
    assert_eq!(
        during.len(),
        before_ws.len() + usize::from(stolen.is_empty()),
        "either a new empty workspace appeared, or an existing one moved across — \
         never both and never neither\n  before: {before_ws:?}\n  during: {during:?}"
    );
    if !stolen.is_empty() {
        eprintln!(
            "note: unpinned output AIRPLAY-T17 took over the user's workspace(s) {:?} — \
             Hyprland's name-keyed workspace memory; this is what pinning prevents",
            stolen.iter().map(|(id, _, _)| *id).collect::<Vec<_>>()
        );
    }

    // The guarantee that DOES hold on every path: teardown restores both sets
    // exactly, so even a steal is transient and nothing is left moved.
    drop(out);
    assert!(!present("AIRPLAY-T17"));
    assert_eq!(shape(&monitors()), shape(&before));
    assert_eq!(
        workspace_shape(),
        before_ws,
        "every workspace must be back on its own monitor with its windows"
    );
}

#[test]
#[ignore = "needs a live Hyprland, a VA-API device, and spawns the real binary"]
fn sigkill_on_a_bare_extend_is_reclaimed_under_its_varying_name() {
    // The reclaim path keys on the recorded NAME, and the name is no longer a
    // constant — it is `AIRPLAY-<N>` for whatever N the run appended. So the
    // whole crash-recovery layer is re-proved here with a varying name: SIGKILL
    // a real `--extend` (no name given, so the binary picks), then show the
    // claim names the appended output and that `extend --cleanup` sweeps exactly
    // that name.
    let _g = serial();
    let s = Scratch::new("t18");
    let before = monitors();
    let before_ws = workspace_shape();

    let live_ids: Vec<i64> = before_ws.iter().map(|(id, _, _)| *id).collect();
    let want = vo::next_workspace_id(&live_ids).expect("a free bar-renderable workspace");
    let name = vo::name_for_workspace(want);
    let _bomb = Bomb::new(name.clone());

    // A BARE `--extend`: the binary resolves the name itself, which is the
    // path the user actually uses.
    let run = Run::spawn(
        &s.0,
        s.0.join("bare-kill.log"),
        &["mirror-bench", "--extend", "--receiver", "1920x1080", "--seconds", "120"],
    );
    assert!(
        wait_until(Duration::from_secs(30), || present(&name)),
        "{name} never came up; child log:\n{}",
        std::fs::read_to_string(&run.log).unwrap_or_default()
    );
    std::thread::sleep(Duration::from_secs(3));

    // The claim written before the output was created records both.
    let claimed = state::read().expect("a claim from the live run");
    assert_eq!(claimed.name, name, "a bare --extend must append, not use a fixed name");
    assert_eq!(claimed.workspace, Some(want));
    assert_eq!(active_workspace_of(&name), Some(i64::from(want)));

    run.signal(libc::SIGKILL);
    let (status, log) = run.wait(Duration::from_secs(15));
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{log}");
    assert!(present(&name), "SIGKILL runs nothing; the phantom is expected here");

    // The kernel released the flock when the fd closed, so the sweep is not
    // locked out by a process that no longer exists.
    let st = vo::status().expect("status");
    assert!(!st.lock_held_elsewhere, "a dead owner must not hold the lock");
    assert!(st.live.is_some(), "status must show the claimed output as live");

    // ...and the escape hatch finds it under its varying name.
    let (status, out) = Run::spawn(&s.0, s.0.join("bare-cleanup.log"), &["extend", "--cleanup"])
        .wait(Duration::from_secs(15));
    assert!(status.success(), "{out}");
    assert!(
        out.contains(&format!("extend: removed orphaned output {name}")),
        "the sweep must name the appended output:\n{out}"
    );

    assert!(!present(&name));
    assert!(state::read().is_none(), "the claim is consumed by the sweep");
    assert_eq!(shape(&monitors()), shape(&before));
    assert_eq!(workspace_shape(), before_ws, "the crash must not have moved a workspace");
}

#[test]
#[ignore = "needs a live Hyprland (read-only: creates nothing)"]
fn an_explicit_name_for_one_of_his_live_workspaces_is_refused() {
    // the user's decision, against the real compositor: naming a workspace he is
    // already using must fail rather than be reinterpreted. Pinning it would
    // move those windows to the TV, and going ahead unpinned is no safer —
    // Hyprland's per-monitor-name workspace memory can move them anyway.
    //
    // Safe to run on his live desktop precisely BECAUSE it refuses: the check
    // happens before the workspace rule and before `output create`, so this
    // test creates nothing, pins nothing and needs no Bomb. Both snapshots are
    // asserted unchanged to prove exactly that.
    let _g = serial();
    let _s = Scratch::new("t19");
    let before = monitors();
    let before_ws = workspace_shape();

    // One of his real, occupied workspaces.
    let (occupied, _, windows) = before_ws
        .iter()
        .find(|(id, _, w)| *id > 0 && *w > 0)
        .cloned()
        .expect("this desktop has at least one workspace with a window on it");
    let name = vo::name_for_workspace(u32::try_from(occupied).expect("a small positive id"));

    // Read-only pre-flight: the "fail at the keyboard, before the TV is woken"
    // slot.
    let e = vo::preflight_workspace(&name).expect_err("pre-flight must refuse");
    assert!(
        matches!(e, VirtualOutputError::WorkspaceInUse { id, .. } if i64::from(id) == occupied),
        "want WorkspaceInUse({occupied}), got {e:?}"
    );

    // ...and again under the lock, where the authoritative decision is made,
    // because the workspace set can change in between.
    let e = VirtualOutput::create(&name, (1920, 1080), 60).expect_err("create must refuse");
    assert!(
        matches!(e, VirtualOutputError::WorkspaceInUse { id, .. } if i64::from(id) == occupied),
        "want WorkspaceInUse({occupied}), got {e:?}"
    );
    let msg = e.to_string();
    assert!(msg.contains("bare `--extend`"), "the message must point at the fix: {msg}");

    // Nothing was created, nothing was claimed, and his window is still where
    // it was — the whole point of refusing.
    assert!(!present(&name), "{name} must not exist");
    assert!(state::read().is_none(), "a refused run leaves no claim");
    assert_eq!(shape(&monitors()), shape(&before));
    assert_eq!(workspace_shape(), before_ws);
    assert_eq!(
        workspace_shape().iter().find(|(id, _, _)| *id == occupied).map(|(_, _, w)| *w),
        Some(windows),
        "workspace {occupied} must still hold its windows"
    );

    // The same id, once free, would have been perfectly acceptable — the
    // refusal is about occupancy, not about explicit names.
    let free = vo::next_workspace_id(&before_ws.iter().map(|(id, _, _)| *id).collect::<Vec<_>>())
        .expect("a free bar-renderable workspace");
    vo::preflight_workspace(&vo::name_for_workspace(free)).expect("a free id passes pre-flight");
}
