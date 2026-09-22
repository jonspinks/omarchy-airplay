//! audiosink: the sender's own PipeWire sink, so the laptop's sound goes to
//! the TV **instead of** to the speakers (the macOS AirPlay behaviour).
//!
//! While a session runs this module publishes one `Audio/Sink` client node
//! named after the receiver (`node.description = "AirPlay: 75\" The Frame"`),
//! makes it the default output, and puts the previous output back when the
//! session ends. [`crate::audiocapture::PipewireSource`] then captures **this
//! sink's own monitor**, which is pre-volume, so the level the user sets is applied
//! exactly once — at the TV.
//!
//! # Why a client node and not `module-null-sink`
//!
//! A `pactl load-module module-null-sink` sink is owned by `pipewire-pulse`,
//! not by us: it survives a SIGKILL and has to be unloaded by module index
//! from a destructor that a SIGKILL never runs. A pw-stream node is owned by
//! **this process** — kill -9 and the node is gone within about a second and
//! PipeWire elects a fallback sink on its own, so audio keeps working with
//! nobody asking. That is the whole reason this module exists in this shape,
//! and why `module-null-sink` is forbidden anywhere in this feature.
//!
//! # What does *not* die with the process
//!
//! `default.configured.audio.sink` does. It is written by
//! `pactl set-default-sink`, it persists in
//! `~/.local/state/wireplumber/default-nodes` **across a reboot**, and after a
//! SIGKILL it is left naming a sink that no longer exists. Worse, the instant
//! a sink with that name appears again it is made the default with nobody
//! asking — which would hand our sink the output *before* [`AirPlaySink::seed_level`]
//! had corrected the volume WirePlumber remembers for it.
//!
//! So the default-sink switch gets the same treatment [`crate::virtualoutput`]
//! gives its headless output:
//!
//! * a **claim** in `$XDG_STATE_HOME/airplay-rs/audiosink.json`, fsynced
//!   *before* the default is taken, recording the sink to put back. It lives
//!   in the state dir, not the runtime dir, precisely because the rot it
//!   repairs survives a reboot. It is cleared only when the output is **known
//!   put back or known not ours** — never after a restore that failed or
//!   could not be confirmed, because the claim is the only thing `--cleanup`
//!   and the next run can repair from (the same rule
//!   [`crate::virtualoutput`] had to learn about its own ownership claim);
//! * an **flock** in the runtime dir, which the kernel releases on SIGKILL, so
//!   "the lock can be taken" means "no live sender owns that claim". It is
//!   also the one-sender-at-a-time gate, and it serialises the default-sink
//!   switch;
//! * a **sweep** ([`reclaim_orphan`], and the same code inside [`AirPlaySink::publish`]
//!   before the node is created) that puts the recorded sink back.
//!
//! # What this module never does
//!
//! It never writes a hardware sink's volume or mute: the only sink it sets a
//! level on is the one it published itself. It never moves a stream
//! (`pactl move-sink-input` writes a persistent per-application target that
//! outlives the session); streams follow the default natively. It never loads
//! a PipeWire/PulseAudio module. It knows nothing about AirPlay.

use crate::audiocapture::{PwCaptureOpts, PW_NODE_LATENCY};
use crate::volume::{LaptopLevel, LaptopVolume as _, PactlVolume};
use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

// --------------------------------------------------------------------------
// Names
// --------------------------------------------------------------------------

/// Every `node.name` this module will publish, claim or sweep starts with this.
///
/// Chosen so that it is **not** `alsa_output.*`, which
/// `/usr/bin/omarchy-audio-output-sink` short-circuits on, and so that it is
/// neither a prefix of nor prefixed by the capture stream's node name
/// `airplay-rs-capture` — that script matches sink-inputs with a *prefix*
/// test, and a name that collided either way would make the volume keys
/// resolve to the wrong node.
pub const NAME_PREFIX: &str = "airplay-sink.";

/// The whole `node.name`, prefix included, is kept to this.
const MAX_NAME_LEN: usize = 60;

/// What the capture stream calls itself. Nothing published here may be a
/// prefix of it, or have it as a prefix (see [`NAME_PREFIX`]).
const CAPTURE_NODE_NAME: &str = "airplay-rs-capture";

/// How long the node may take to get an id and a format before `publish`
/// gives up.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for WirePlumber's remembered-volume restore to land
/// before seeding our own level over it (see [`AirPlaySink::seed_level`]).
const RESTORE_SETTLE: Duration = Duration::from_millis(300);

/// The belt-and-braces re-write of the seeded level, against a late restore.
const RESEED_AFTER: Duration = Duration::from_millis(500);

/// How long `Drop` waits for the loop thread.
const JOIN_BOUND: Duration = Duration::from_secs(2);

const POLL_SLICE: Duration = Duration::from_millis(20);

/// How long the **active** default may lag a `pactl set-default-sink` before
/// we believe the read.
///
/// `set-default-sink` writes `default.configured.audio.sink`;
/// `get-default-sink` reports `default.audio.sink`, which WirePlumber writes
/// *afterwards*. Measured on this machine: 5-8 ms when it is idle, and a
/// single immediate read missed 2-6 times in 25 while it was busy — which is
/// exactly when we take the output. One immediate read is therefore not
/// evidence of anything; a poll is. Same reason as [`AirPlaySink::wait_until_listed`].
const DEFAULT_SETTLE: Duration = Duration::from_secs(1);

/// `AirPlay: <receiver>` — what the sink calls itself in the user's output menu.
pub fn display_label(receiver: &str) -> String {
    format!("AirPlay: {receiver}")
}

/// `airplay-sink.<slug>`: lowercase, `[a-z0-9_-]` only, runs of anything else
/// collapsed to a single `_`, trimmed of leading/trailing `_`, truncated so
/// the whole name fits [`MAX_NAME_LEN`].
///
/// A leading `AirPlay: ` is stripped first, so the pretty label and the bare
/// receiver name produce the same node name.
///
/// **Stable for a given receiver**, deliberately: WirePlumber's
/// `default-nodes` state file grows by one permanent entry per distinct sink
/// name it has ever seen as default, so a per-session-unique name would grow
/// that file without bound. The cost of a stable name is that a stale
/// configured default can point at it — which is what the sweep is for.
pub fn node_name_for(label: &str) -> String {
    let base = label.strip_prefix("AirPlay: ").unwrap_or(label);
    let mut slug = String::with_capacity(base.len());
    let mut pending_sep = false;
    for c in base.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            if pending_sep && !slug.is_empty() {
                slug.push('_');
            }
            pending_sep = false;
            slug.push(c);
        } else {
            pending_sep = true;
        }
    }
    if slug.is_empty() {
        slug.push_str("receiver");
    }
    let room = MAX_NAME_LEN - NAME_PREFIX.len();
    if slug.len() > room {
        slug.truncate(room);
        while slug.ends_with('_') {
            slug.pop();
        }
    }
    format!("{NAME_PREFIX}{slug}")
}

/// The structural gate, exactly like [`crate::virtualoutput::validate_name`]:
/// a name that does not pass this is never published, never claimed and never
/// acted on by the sweep. A corrupt or hand-edited claim naming
/// `alsa_output.…` must not be able to make this module touch it.
pub fn validate_name(name: &str) -> Result<(), SinkError> {
    if !name.starts_with(NAME_PREFIX) || name.len() <= NAME_PREFIX.len() || name.len() > MAX_NAME_LEN {
        return Err(SinkError::BadName(name.to_string()));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.')
    {
        return Err(SinkError::BadName(name.to_string()));
    }
    // The omarchy volume script matches sink-inputs by prefix, in both
    // directions; a name that collides either way would misroute the keys.
    if name.starts_with(CAPTURE_NODE_NAME) || CAPTURE_NODE_NAME.starts_with(name) {
        return Err(SinkError::BadName(name.to_string()));
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("another AirPlay sink is running; see `airplay audio --status`")]
    Busy,
    #[error("PipeWire: {0}")]
    Pipewire(String),
    #[error("format: {0}")]
    Format(String),
    #[error("could not seed the AirPlay sink's level: {0}")]
    Seed(String),
    #[error("bad AirPlay sink name {0:?} (want `{NAME_PREFIX}…`, [a-z0-9_.-], <= 60 chars)")]
    BadName(String),
    #[error("a sink called {0:?} already exists")]
    NameTaken(String),
    /// The laptop's output was changed — by the user, by a Bluetooth connect, by a
    /// USB DAC appearing — after this sink recorded what to put back and
    /// before the handover. Nothing was taken and nothing is owed: the caller
    /// must leave that choice alone.
    #[error("the laptop's output was changed to {0:?} before the handover; leaving that choice alone")]
    OutputMoved(String),
    /// The handover was ACCEPTED — `default.configured.audio.sink` names our
    /// node — but the active default has not followed. The output really may
    /// be ours, so the claim and the restore are kept; the caller must not
    /// report this as "the output stays where it is".
    #[error("the output is configured for {node} but still reads {reads}")]
    TookUnsettled { node: String, reads: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

// --------------------------------------------------------------------------
// Shell-outs (all read-only except where named)
// --------------------------------------------------------------------------

fn pactl() -> Command {
    let mut c = Command::new("pactl");
    c.env("LC_ALL", "C").stdin(Stdio::null()).stderr(Stdio::null());
    c
}

fn run_out(mut c: Command) -> std::io::Result<String> {
    let out = c.output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!("{c:?} exited {}", out.status)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `pactl list short sinks` -> the node names, or `None` when the listing
/// itself failed.
///
/// The distinction is load-bearing and it is why this function exists next to
/// [`live_sinks`]: "the list came back and your sink is not in it" means the
/// sink is **gone**, while "the list did not come back" means **unknown**, and
/// a caller that decides whether to put the user's output back, or whether to throw
/// away the only record that could repair it, must never confuse the two.
pub fn live_sinks_checked() -> Option<Vec<String>> {
    let mut c = pactl();
    c.args(["list", "short", "sinks"]);
    let out = run_out(c).ok()?;
    Some(parse_short_sinks(&out))
}

/// `pactl list short sinks` -> the node names. Empty on any failure, so it
/// may only be used where "empty" and "could not tell" deserve the same
/// answer (a retry loop, a status report). Anything that acts on the
/// difference uses [`live_sinks_checked`].
pub fn live_sinks() -> Vec<String> {
    live_sinks_checked().unwrap_or_default()
}

/// Pure half of [`live_sinks`]: `id\tname\tdriver\t…` per line.
pub(crate) fn parse_short_sinks(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split('\t').nth(1))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The **active** default sink (`pactl get-default-sink`). Read-only.
pub fn default_sink() -> Option<String> {
    let mut c = pactl();
    c.arg("get-default-sink");
    let s = run_out(c).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The **configured** default sink — the persistent one, which is what a
/// SIGKILL leaves pointing at a dead node. Read-only.
pub fn configured_default_sink() -> Option<String> {
    let out = Command::new("pw-metadata")
        .args(["-n", "default", "0", "default.configured.audio.sink"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    parse_configured_default(&String::from_utf8_lossy(&out.stdout))
}

/// Pure half of [`configured_default_sink`]. `pw-metadata` prints
///
/// ```text
/// update: id:0 key:'default.configured.audio.sink' value:'{"name":"alsa_output.…"}' type:'Spa:String:JSON'
/// ```
///
/// and prints no `update:` line at all when the key is unset.
pub(crate) fn parse_configured_default(out: &str) -> Option<String> {
    let line = out
        .lines()
        .rev()
        .find(|l| l.contains("default.configured.audio.sink") && l.contains("value:'"))?;
    let rest = line.split_once("value:'")?.1;
    // The FIRST closing quote: the line goes on to `type:'Spa:String:JSON'`,
    // so taking the last one would swallow that too.
    let json = rest.split_once('\'')?.0;
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let name = v.get("name")?.as_str()?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// **Writes** the default sink. The only mutation this module makes outside
/// the sink it published itself, and the reason for the claim and the lock.
fn set_default_sink(name: &str) -> std::io::Result<()> {
    let mut c = pactl();
    c.args(["set-default-sink", name]);
    run_out(c).map(|_| ())
}

/// Set one sink's volume and mute **independently** (`pactl set-sink-volume`
/// then `set-sink-mute`), so that a muted source level still seeds the slider
/// and the read-back in [`AirPlaySink::seed_level`] can be exact.
///
/// [`crate::volume::PactlVolume::set`] deliberately does not do this — for a
/// muted level it sets mute only and leaves the slider where it is, which is
/// right for tracking the TV but wrong for seeding.
fn set_sink_level(sink: &str, pct: u8, muted: bool) -> std::io::Result<()> {
    let mut c = pactl();
    c.args(["set-sink-volume", sink, &format!("{}%", pct.min(100))]);
    run_out(c)?;
    let mut c = pactl();
    c.args(["set-sink-mute", sink, if muted { "1" } else { "0" }]);
    run_out(c).map(|_| ())
}

/// Where the level to copy lives, and what it reads, for a given **output**.
///
/// Split deliberately from the output name itself: `resolve_output_sink()`
/// answers "the sink whose volume and mute this output really uses", which for
/// a DSP default is the physical sink *underneath* it. That is the right sink
/// to read a level from and the wrong name to ever write back as the output.
/// If the resolver cannot answer, the output's own level is the best guess and
/// a read failure is still an error — never a guessed level.
fn resolve_level_source(output: &str) -> Result<(String, LaptopLevel), SinkError> {
    let source = crate::volume::resolve_output_sink().unwrap_or_else(|_| output.to_string());
    let level = PactlVolume::for_sink(&source)
        .read()
        .map_err(|e| SinkError::Seed(format!("cannot read {source}'s level: {e}")))?;
    Ok((source, level))
}

// --------------------------------------------------------------------------
// Claim + lock
// --------------------------------------------------------------------------

/// What a running (or crashed) sender recorded about the output it took.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Claim {
    /// Ours. Validated against [`NAME_PREFIX`] before any action is taken on
    /// its say-so.
    pub node_name: String,
    pub label: String,
    /// The sink to put back. A **name**, never an id: ids are ephemeral and
    /// the sink we have to restore may not even exist while we are running.
    pub previous_default: String,
    /// False until [`AirPlaySink::take_default`] has succeeded.
    pub took_default: bool,
    /// False after [`AirPlaySink::disown_default`]: the user picked an output
    /// himself and neither `Drop` nor a later sweep may undo that.
    pub restore_default: bool,
    pub pid: u32,
    pub created_unix: u64,
}

/// Where the claim lives, and how it is written.
///
/// Deliberately **not** the runtime directory the Extend claim uses: the rot
/// this claim repairs (`default.configured.audio.sink` naming a dead sink)
/// survives a reboot, and a claim wiped at logout could not repair it.
pub mod state {
    use super::*;

    /// `$AIRPLAY_RS_STATE_DIR`, else `$XDG_STATE_HOME/airplay-rs`, else
    /// `$HOME/.local/state/airplay-rs`, else `<tmp>/airplay-rs-state`.
    pub fn dir() -> PathBuf {
        if let Ok(d) = std::env::var("AIRPLAY_RS_STATE_DIR") {
            if !d.is_empty() {
                return PathBuf::from(d);
            }
        }
        if let Ok(d) = std::env::var("XDG_STATE_HOME") {
            if !d.is_empty() {
                return PathBuf::from(d).join("airplay-rs");
            }
        }
        if let Ok(h) = std::env::var("HOME") {
            if !h.is_empty() {
                return PathBuf::from(h).join(".local/state/airplay-rs");
            }
        }
        std::env::temp_dir().join("airplay-rs-state")
    }

    pub fn path() -> PathBuf {
        dir().join("audiosink.json")
    }

    /// The lock goes in the **runtime** dir, where the Extend lock lives: the
    /// kernel must release it on SIGKILL, and it must not survive a reboot.
    pub fn lock_path() -> PathBuf {
        crate::virtualoutput::state::dir().join("audiosink.lock")
    }

    /// Write the claim and `fsync` it. It has to survive a SIGKILL that lands
    /// microseconds after the `pactl set-default-sink` it precedes, which is
    /// the entire point of writing it at all.
    pub fn write(c: &Claim) -> std::io::Result<()> {
        std::fs::create_dir_all(dir())?;
        let json = serde_json::to_vec_pretty(c).map_err(std::io::Error::other)?;
        let mut f = File::create(path())?;
        f.write_all(&json)?;
        f.sync_all()
    }

    /// `None` when absent, unreadable or corrupt — all of which mean "no claim".
    pub fn read() -> Option<Claim> {
        serde_json::from_slice(&std::fs::read(path()).ok()?).ok()
    }

    pub fn clear() -> std::io::Result<()> {
        match std::fs::remove_file(path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    pub fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// `flock(LOCK_EX|LOCK_NB)` held for the whole session.
///
/// Released by the kernel when the fd closes — including on SIGKILL, where no
/// destructor runs — so it is both the "one AirPlay sink at a time" gate and
/// the thing that makes the sweep safe. Its third job is serialising the
/// default-sink switch: two senders racing `default.configured.audio.sink`
/// each restore the other's value and the user ends up on neither.
struct OwnerLock {
    _file: File,
}

impl OwnerLock {
    fn acquire() -> Result<Self, SinkError> {
        std::fs::create_dir_all(crate::virtualoutput::state::dir())?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(state::lock_path())?;
        // SAFETY: `file` owns the fd for the duration of the call.
        let rc = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EWOULDBLOCK) => Err(SinkError::Busy),
                _ => Err(SinkError::Io(e)),
            };
        }
        Ok(OwnerLock { _file: file })
    }

    /// Read-only probe for `--status`: `LOCK_SH` is blocked by an exclusive
    /// holder but locks nobody out itself, so a status call can never make a
    /// starting session fail with [`SinkError::Busy`].
    fn held_elsewhere() -> bool {
        let Ok(file) = std::fs::OpenOptions::new().read(true).open(state::lock_path()) else {
            return false;
        };
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        // SAFETY: `file` owns the fd for the duration of both calls.
        let rc = unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) };
        if rc == 0 {
            // SAFETY: as above; unlocked explicitly rather than relying on the
            // close, so the fd's lifetime is not load-bearing.
            unsafe { libc::flock(fd, libc::LOCK_UN) };
            return false;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
    }
}

// --------------------------------------------------------------------------
// The sweep
// --------------------------------------------------------------------------

/// What a sweep did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repair {
    /// A live sink still answers to the claimed name: somebody else's, or an
    /// orphan we must not destroy. Nothing was done.
    Nothing,
    /// The machine could not be read at all (`pactl list short sinks`
    /// failed), so nothing is known about the claimed sink and nothing was
    /// decided. Distinct from [`Repair::Nothing`], which is a positive
    /// finding: this one means "ask again later". The claim is kept either
    /// way, but only one of the two is a reason to re-run `--cleanup`.
    CouldNotTell,
    ClearedStaleClaim,
    RestoredDefault { from: String, to: String },
}

/// Pure decision core of the sweep: what should be done, given the claim and
/// read-only facts. The IO is the caller's.
///
/// The rules are deliberately narrow. The sweep only ever acts when something
/// still names **our** dead sink as the configured default; it never guesses
/// a replacement, because WirePlumber's own priority election already keeps
/// audio working and a guess would override a choice the user may have made since.
///
/// `live_sinks` is `None` when the sink listing could not be read at all.
/// That is "unknown", never "gone": the answer is then [`Repair::Nothing`],
/// which leaves the claim on disk for the next sweep, because a claim that
/// survives costs nothing and a claim thrown away on a failed `pactl` can
/// never be repaired.
pub(crate) fn reclaim_decision(claim: &Claim, configured_default: Option<&str>, live_sinks: Option<&[String]>) -> Repair {
    // The selector is a name out of a file, so it goes through the same gate a
    // name from the caller does. A corrupt, hand-edited or forward-version
    // claim naming a hardware sink must never make us act on it. This one is
    // decidable without reading anything, so it is answered even when the
    // sinks are unknown.
    if validate_name(&claim.node_name).is_err() {
        return Repair::ClearedStaleClaim;
    }
    let Some(live_sinks) = live_sinks else {
        // We cannot tell whether our node is still up, nor whether the sink to
        // put back exists. Decide nothing and keep the record.
        return Repair::CouldNotTell;
    };
    // We hold the lock, so no live sender owns this claim — but if a node with
    // that name is still up, it is not ours to reason about.
    if live_sinks.iter().any(|s| s == &claim.node_name) {
        return Repair::Nothing;
    }
    if configured_default == Some(claim.node_name.as_str())
        && claim.took_default
        && claim.restore_default
        && live_sinks.iter().any(|s| s == &claim.previous_default)
    {
        return Repair::RestoredDefault {
            from: claim.node_name.clone(),
            to: claim.previous_default.clone(),
        };
    }
    Repair::ClearedStaleClaim
}

/// Do the sweep under an already-held [`OwnerLock`].
fn reclaim_locked() -> Result<Option<Repair>, SinkError> {
    let Some(claim) = state::read() else { return Ok(None) };
    let live = live_sinks_checked();
    let repair = reclaim_decision(&claim, configured_default_sink().as_deref(), live.as_deref());
    match &repair {
        Repair::RestoredDefault { from, to } => {
            // On an Err the `?` returns BEFORE the claim is cleared below, so
            // a failed repair leaves the record for the next attempt.
            set_default_sink(to)?;
            eprintln!("audiosink: reclaimed the output from the dead sink {from}: default restored to {to}");
        }
        Repair::CouldNotTell => {
            eprintln!(
                "audiosink: could not list the sinks, so nothing about {} is known; \
                 leaving the claim and the output alone",
                claim.node_name
            );
        }
        Repair::Nothing => {
            eprintln!(
                "audiosink: a sink called {} is still live; leaving it and the output alone",
                claim.node_name
            );
        }
        Repair::ClearedStaleClaim => {}
    }
    // Both "a live sink still answers to that name" and "the machine could
    // not be read" leave the claim exactly where it is. Everything else has
    // established what the claim describes, so the record may go.
    if !matches!(repair, Repair::Nothing | Repair::CouldNotTell) {
        let _ = state::clear();
    }
    Ok(Some(repair))
}

/// `airplay audio --cleanup`: repair a run that was SIGKILLed, where no
/// destructor got to run. Refuses while a live sender holds the lock, because
/// that process legitimately owns its sink and its claim.
pub fn reclaim_orphan() -> Result<Option<Repair>, SinkError> {
    let _lock = OwnerLock::acquire()?;
    reclaim_locked()
}

// --------------------------------------------------------------------------
// Status
// --------------------------------------------------------------------------

/// A read-only picture, for `airplay audio --status`. Creates nothing,
/// changes nothing, takes no exclusive lock.
#[derive(Debug)]
pub struct Status {
    pub claimed: Option<Claim>,
    /// Is the claimed node actually live right now? `None` when the sink
    /// listing could not be read — which is NOT "no". A status that answered
    /// "not live" to a failed `pactl` would invite `--cleanup` to repair a
    /// sink that is in fact up, and would print the "run --cleanup" advice on
    /// no evidence at all.
    pub claimed_is_live: Option<bool>,
    pub lock_held_elsewhere: bool,
    pub default_sink: Option<String>,
    pub configured_default: Option<String>,
    /// Every live sink whose name starts with [`NAME_PREFIX`].
    pub airplay_sinks: Vec<String>,
}

pub fn status() -> Status {
    let sinks = live_sinks_checked();
    let claimed = state::read();
    Status {
        claimed_is_live: match (&claimed, &sinks) {
            (Some(c), Some(live)) => Some(live.iter().any(|s| s == &c.node_name)),
            // No claim, or no listing: in neither case has anything been
            // established about a claimed node.
            _ => None,
        },
        claimed,
        lock_held_elsewhere: OwnerLock::held_elsewhere(),
        default_sink: default_sink(),
        configured_default: configured_default_sink(),
        airplay_sinks: sinks
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.starts_with(NAME_PREFIX))
            .collect(),
    }
}

// --------------------------------------------------------------------------
// The published node
// --------------------------------------------------------------------------

/// How many sinks **this process** has published. The offline session tests
/// assert this is still 0 after a loopback run: a sink created on the
/// test-injection path would publish a real node and hijack the user's output
/// during `cargo test`.
static PUBLISHED: AtomicUsize = AtomicUsize::new(0);

pub fn published_in_this_process() -> usize {
    PUBLISHED.load(Ordering::Relaxed)
}

#[derive(Clone, Debug)]
pub struct SinkOpts {
    /// Goes into `node.description` **verbatim** — this is the text the user sees
    /// in his output menu, e.g. `AirPlay: 75" The Frame` (the double quote
    /// survives intact). See [`display_label`].
    pub label: String,
    /// `node.name`. [`node_name_for`] the label when `None`.
    pub node_name: Option<String>,
    /// Deliberately different from the capture stream's `airplay-rs`, so that
    /// WirePlumber's remembered volume for the sink and for the capture
    /// stream are separate keys.
    pub app_name: String,
}

impl SinkOpts {
    pub fn for_receiver(receiver: &str) -> Self {
        SinkOpts {
            label: display_label(receiver),
            node_name: None,
            app_name: "airplay-rs-sink".into(),
        }
    }
}

impl Default for SinkOpts {
    fn default() -> Self {
        SinkOpts {
            label: "AirPlay".into(),
            node_name: None,
            app_name: "airplay-rs-sink".into(),
        }
    }
}

/// Shared with the PipeWire loop thread.
struct Shared {
    stop: AtomicBool,
    node_id: AtomicU32,
    /// Count of `Props` params carrying `channelVolumes`. The first one is
    /// WirePlumber's remembered-volume restore landing on the node.
    props_epoch: AtomicU32,
    /// The loudest `channelVolumes` entry, f32 bits. **Diagnostics and the
    /// seed-settle logic only.** It is linear (= pactl's cubic percent cubed)
    /// and is never fed to the TV mapping, which is defined on the percent.
    channel_volume: AtomicU32,
    /// Peak the sink node's own `process()` has seen since the last reset.
    /// POST-volume, so it is the non-vacuity check for the pre-volume claim
    /// about the monitor, never an audio path.
    process_peak: AtomicU32,
    process_calls: AtomicU64,
    /// Has the stream ever been connected (reached `Paused` or `Streaming`)?
    ///
    /// The difference between "not up yet" and "was up and is gone", which
    /// `StreamState::Unconnected` alone cannot tell apart.
    connected: AtomicBool,
    fatal: Mutex<Option<String>>,
}

impl Shared {
    fn new() -> Self {
        Shared {
            stop: AtomicBool::new(false),
            node_id: AtomicU32::new(u32::MAX),
            props_epoch: AtomicU32::new(0),
            channel_volume: AtomicU32::new(f32::NAN.to_bits()),
            process_peak: AtomicU32::new(0),
            process_calls: AtomicU64::new(0),
            connected: AtomicBool::new(false),
            fatal: Mutex::new(None),
        }
    }

    fn set_fatal(&self, msg: String) {
        if let Ok(mut g) = self.fatal.lock() {
            if g.is_none() {
                *g = Some(msg);
            }
        }
    }

    fn fatal(&self) -> Option<String> {
        self.fatal.lock().ok().and_then(|g| g.clone())
    }
}

/// What the active default settled to after a write of our own.
///
/// `Unknown` is a first-class answer on purpose: every read failing is not
/// evidence that somebody else owns the output, and treating it as such is
/// what would forfeit the user's restore.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Settled {
    Ours,
    Other(String),
    Unknown,
}

/// What [`AirPlaySink::take_default`] does once it has written the default and
/// read the machine back.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TakeVerdict {
    /// Ours, confirmed. Open the gate.
    Took,
    /// Nobody could be read. The write succeeded, so we may well be the
    /// output: keep the claim and open the gate.
    TookUnconfirmed,
    /// The configured default is ours but the active one is not: the rot is
    /// ours to repair, so keep the claim; hold the gate.
    KeepAndHold(String),
    /// The write did not take and the output the user already had still has it.
    /// Nothing was taken, so nothing is owed.
    NotTaken(String),
    /// Something else stably owns the output. Give up the restore so neither
    /// `Drop` nor a sweep undoes that choice.
    Disown(String),
}

/// Pure decision core of the handover, so the rule that matters most in this
/// file — **an unreadable machine never costs the user their restore** — is decided
/// by a function with no IO in it and is unit-tested exhaustively.
///
/// `volume::still_default` states the same rule for the same class of read in
/// its own doc comment: a read that fails answers "unknown", never "somebody
/// else's". Only a stable `Other` that is neither our node nor the output we
/// came from may forfeit the claim.
fn take_verdict(settled: &Settled, configured: Option<&str>, node: &str, previous: &str) -> TakeVerdict {
    match settled {
        Settled::Ours => TakeVerdict::Took,
        Settled::Unknown => TakeVerdict::TookUnconfirmed,
        Settled::Other(d) if configured == Some(node) => TakeVerdict::KeepAndHold(d.clone()),
        Settled::Other(d) if d == previous => TakeVerdict::NotTaken(d.clone()),
        Settled::Other(d) => TakeVerdict::Disown(d.clone()),
    }
}

/// The output the user moved to while the TV's volume was being established —
/// `None` when nothing moved.
///
/// `previous` was sampled at publish and is consumed 3-4 seconds later (the
/// start delay, the TV's GET, the SET, the read-back). Bluetooth headphones
/// connecting, a USB DAC appearing, or the user picking an output in that window
/// all mean the sink we were about to take the output FROM is not the one he
/// is using.
///
/// A `Some` here **refuses the handover** ([`AirPlaySink::take_default`]). It
/// used to adopt the new output instead — take it too, and remember it as the
/// one to put back — and that is the theft the review named: a move in this
/// window is a deliberate choice of his, seconds old, and answering it by
/// seizing the device he just picked is the same wrong as seizing the one he
/// left. Refusing costs him nothing: the gate never opens, the TV stays
/// silent, and whatever he chose keeps making sound.
///
/// An unreadable default (`None`) moves nothing: unknown is never a reason to
/// act, in either direction.
fn output_moved_under_us<'a>(now: Option<&'a str>, previous: &str, node: &str) -> Option<&'a str> {
    let now = now?;
    (now != previous && now != node).then_some(now)
}

/// Is a monitor pre-volume, given what `monitor.channel-volumes` reads back?
///
/// **Only an explicit `false` counts.** `None` means the dump could not be
/// read or the node is not in it, and the caller's whole reason for asking is
/// to refuse the sink path unless the monitor is known pre-volume: an unknown
/// that answers "pre-volume" is a guard that fails open, and the failure it
/// lets through is every sample attenuated twice.
fn pre_volume_verdict(monitor_is_post_volume: Option<bool>) -> bool {
    monitor_is_post_volume == Some(false)
}

/// A live AirPlay sink **this process owns**, and the output claim that goes
/// with it. Both are given back on `Drop` — including during a panic unwind,
/// which is why this crate must not set `panic = "abort"`.
pub struct AirPlaySink {
    node_name: String,
    label: String,
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// The **output** to put back: a `pactl get-default-sink` name, never a
    /// resolved one. See [`AirPlaySink::publish`].
    previous_default: String,
    /// The sink the level was copied FROM, which is a different question and
    /// may be a different sink: with a DSP chain selected
    /// (`easyeffects_sink`, `omarchy_speaker_tuning`) the volume keys drive
    /// the physical sink underneath, so that is where the level to copy
    /// lives — but it is emphatically not the output to restore.
    level_source: String,
    previous_level: LaptopLevel,
    seeded: Option<LaptopLevel>,
    took_default: bool,
    restore_default: bool,
    /// Has the node been taken down and the claim settled? Set by
    /// [`AirPlaySink::teardown`], which both `Drop` and
    /// [`AirPlaySink::unpublish`] go through, so the whole sequence runs
    /// exactly once however it is reached.
    torn_down: bool,
    _lock: OwnerLock,
}

impl AirPlaySink {
    /// Sweep any orphan claim, then publish the node. Does **not** take the
    /// default output — [`Self::take_default`] does that, and the session
    /// defers it until the volume gate opens so the speakers keep playing
    /// right up to the moment the TV starts making sound.
    ///
    /// Returns once PipeWire has given the node an id, the negotiated format
    /// is S16LE/44100/2, and our level has been seeded from the sink the user is
    /// using and verified by read-back.
    pub fn publish(opts: SinkOpts) -> Result<Self, SinkError> {
        let lock = OwnerLock::acquire()?;

        // Under the lock, BEFORE the node exists. Not cosmetic: a stale
        // configured default seizes the output the instant a sink with that
        // name appears, with nobody asking — which would make us the output
        // before `seed_level` had corrected WirePlumber's remembered volume.
        if let Err(e) = reclaim_locked() {
            eprintln!("audiosink: sweep before publishing failed: {e}");
        }

        let node_name = match opts.node_name.clone() {
            Some(n) => n,
            None => node_name_for(&opts.label),
        };
        validate_name(&node_name)?;

        let sinks = live_sinks();
        if sinks.iter().any(|s| s == &node_name) {
            return Err(SinkError::NameTaken(node_name));
        }

        // The output the user is using now: what we put back. `pactl
        // get-default-sink`, NOT `resolve_output_sink()` — those answer two
        // different questions and only one of them is an output name. With a
        // DSP chain selected, `/usr/bin/omarchy-audio-output-sink` resolves
        // *through* `easyeffects_sink`/`omarchy_speaker_tuning` to the ALSA
        // sink underneath (that is its documented job), and writing that back
        // at the end would drop the user's DSP chain and stick, because it lands in
        // `default.configured.audio.sink`.
        let previous_default =
            default_sink().ok_or_else(|| SinkError::Seed("cannot read the current output sink".into()))?;
        // The level, however, really does live on the resolved sink: that is
        // the one the volume keys drive.
        let (level_source, previous_level) = resolve_level_source(&previous_default)?;

        let shared = Arc::new(Shared::new());
        let (ready_tx, ready_rx) = mpsc::channel::<Result<u32, String>>();
        let sh = shared.clone();
        let thread_opts = (node_name.clone(), opts.label.clone(), opts.app_name.clone());
        let thread = std::thread::Builder::new()
            .name("airplay-pw-sink".into())
            .spawn(move || sink_thread(thread_opts, sh, ready_tx))
            .map_err(SinkError::Io)?;

        match ready_rx.recv_timeout(PUBLISH_TIMEOUT) {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                shared.stop.store(true, Ordering::SeqCst);
                let _ = thread.join();
                return Err(SinkError::Pipewire(e));
            }
            Err(_) => {
                shared.stop.store(true, Ordering::SeqCst);
                let _ = thread.join();
                return Err(SinkError::Pipewire("timed out publishing the AirPlay sink".into()));
            }
        }
        PUBLISHED.fetch_add(1, Ordering::Relaxed);

        let mut sink = AirPlaySink {
            node_name,
            label: opts.label,
            shared,
            thread: Some(thread),
            previous_default,
            level_source,
            previous_level,
            seeded: None,
            took_default: false,
            restore_default: true,
            torn_down: false,
            _lock: lock,
        };

        // The sink has to be visible to pactl before it can be seeded.
        sink.wait_until_listed()?;
        sink.seed_level()?;
        // The sweep above removed any stale configured default naming us, so
        // this should not happen — but if the node has become the output
        // anyway (a configured default written between the sweep and the node
        // appearing, or a policy rule), say so and OWN it. Recording it is the
        // only thing that makes `Drop` and the sweep give it back; pretending
        // we did not take it is how an output gets seized for good.
        if sink.is_default() == Some(true) {
            eprintln!(
                "audiosink: {} became the output the moment it appeared, with nobody asking; \
                 it will be given back to {} at the end",
                sink.node_name, sink.previous_default
            );
            sink.took_default = true;
        }
        sink.write_claim();
        Ok(sink)
    }

    fn wait_until_listed(&self) -> Result<(), SinkError> {
        let t0 = Instant::now();
        while t0.elapsed() < PUBLISH_TIMEOUT {
            if let Some(msg) = self.shared.fatal() {
                return Err(SinkError::Format(msg));
            }
            if live_sinks().iter().any(|s| s == &self.node_name) {
                return Ok(());
            }
            std::thread::sleep(POLL_SLICE);
        }
        Err(SinkError::Pipewire(format!(
            "{} never appeared in `pactl list short sinks`",
            self.node_name
        )))
    }

    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn node_id(&self) -> u32 {
        self.shared.node_id.load(Ordering::Relaxed)
    }

    /// The output that comes back at the end: the one the user was using when we
    /// published. Always a `pactl get-default-sink` name, and never rewritten
    /// behind his back — if he moves his output before the handover,
    /// [`Self::take_default`] refuses rather than re-pointing this at the
    /// device he just chose. It is also the baseline the volume driver checks
    /// against ([`crate::volume::SinkBinding::expected_default`]).
    pub fn previous_default(&self) -> &str {
        &self.previous_default
    }

    pub fn previous_level(&self) -> LaptopLevel {
        self.previous_level
    }

    /// The sink [`Self::previous_level`] was read from. The same as
    /// [`Self::previous_default`] for a plain output, and the physical sink
    /// underneath it for a DSP one (`easyeffects_sink`,
    /// `omarchy_speaker_tuning`) — which is why the two are stored apart.
    pub fn level_source(&self) -> &str {
        &self.level_source
    }

    /// The level [`Self::seed_level`] put on our sink and read back.
    pub fn seeded_level(&self) -> Option<LaptopLevel> {
        self.seeded
    }

    /// Seed our level from the one the user's output is using, verified by
    /// read-back.
    ///
    /// The level is read from [`Self::level_source`], not from
    /// [`Self::previous_default`]: with a DSP chain selected they are
    /// different sinks, and the level lives on the physical one underneath.
    /// Run once, at publish. If the output moves before the handover the
    /// session does not continue onto the new device at all
    /// ([`Self::take_default`] refuses), so there is never a live session
    /// whose TV level came from a device the user had already left.
    ///
    /// # Why this is not optional
    ///
    /// WirePlumber restores a **remembered** `channelVolumes` onto the node
    /// after connect, asynchronously, keyed on `application.name`. The stored
    /// value can be well above 1.0 — the state file on this machine already
    /// holds `[3.375, 3.375]` — and `parse_pactl_volume` clamps to 100 %, so a
    /// 337 % restore would read back as **100 % → 0 dB → AirPlay MAXIMUM**.
    /// That is the single worst failure available to this feature, and this
    /// method is what closes it: by the time the volume driver reads the
    /// laptop level, our sink reads what the user's real output reads.
    ///
    /// So: wait for the restore to land (it is the first `Props` the node is
    /// handed), write our level over it, and require an **exact** read-back.
    /// Re-write and re-verify once more against a late restore. A failure is
    /// an error, never a guess.
    pub fn seed_level(&mut self) -> Result<LaptopLevel, SinkError> {
        let (pct, muted) = (self.previous_level.pct(), self.previous_level.muted());

        let t0 = Instant::now();
        while self.shared.props_epoch.load(Ordering::Relaxed) == 0 && t0.elapsed() < RESTORE_SETTLE {
            std::thread::sleep(Duration::from_millis(10));
        }

        let mut last = self.write_and_verify(pct, muted)?;

        // Belt and braces: a restore that lands after the first write would
        // otherwise stand. After this we stop asserting — a change from here
        // on is the user moving the slider, which is the whole point of the sink.
        std::thread::sleep(RESEED_AFTER);
        if self.read_level()? != last {
            last = self.write_and_verify(pct, muted)?;
        }
        self.seeded = Some(last);
        Ok(last)
    }

    fn read_level(&self) -> Result<LaptopLevel, SinkError> {
        PactlVolume::for_sink(&self.node_name)
            .read()
            .map_err(|e| SinkError::Seed(format!("cannot read {}'s level: {e}", self.node_name)))
    }

    /// Write one level onto OUR sink and require the read-back to be exactly
    /// it.
    ///
    /// The comparison is on [`LaptopLevel::raw_pct`], the UNCLAMPED percent,
    /// never on `pct()`. `pct()` is clamped to 100, so a sink still sitting on
    /// WirePlumber's remembered `[3.375, 3.375]` reads back as a tidy "100 %"
    /// and a verify against it would pass while the node was at 337 % — the
    /// exact failure `seed_level` exists to prevent, waved through by its own
    /// check. `raw_pct` cannot be fooled that way: 337 is not 100.
    fn write_and_verify(&self, pct: u8, muted: bool) -> Result<LaptopLevel, SinkError> {
        set_sink_level(&self.node_name, pct, muted)
            .map_err(|e| SinkError::Seed(format!("cannot set {}'s level: {e}", self.node_name)))?;
        let got = self.read_level()?;
        if (got.raw_pct(), got.muted()) != (pct as u32, muted) {
            return Err(SinkError::Seed(format!(
                "{} reads {}%{} after being set to {pct}%{}; refusing to guess",
                self.node_name,
                got.raw_pct(),
                if got.muted() { " muted" } else { "" },
                if muted { " muted" } else { "" },
            )));
        }
        Ok(got)
    }

    /// Hand the output over. The claim is on disk and fsynced first, so a
    /// SIGKILL in the microseconds that follow still leaves a repairable
    /// record. Idempotent.
    ///
    /// The session calls this **at the instant the volume gate opens**, not at
    /// publish time: taking the output earlier would leave a 3-4 second window
    /// in which the speakers are already silent and the TV is still gated —
    /// audio audible nowhere. It also gives the safest failure there is: if
    /// the gate never opens, the user's output is never taken and he keeps his
    /// sound.
    pub fn take_default(&mut self) -> Result<(), SinkError> {
        if self.took_default {
            return Ok(());
        }
        // PRECONDITION, checked here and not only by the caller: the output
        // the user has RIGHT NOW must still be the one we recorded. Between the two
        // there is the start delay, the TV's GET, the SET and the read-back —
        // 3-4 seconds in which Bluetooth headphones can connect, a USB DAC can
        // appear, or he can simply pick another output.
        //
        // `crate::volume`'s driver makes the same check before it calls this,
        // against the baseline this sink hands it (`expected_default`), and
        // that is the one with the retries. This one closes what that cannot
        // see: the direct call from the `--no-volume-sync` arm, and the gap
        // between `publish` and the volume thread starting. Two independent
        // guards on the one action that can take the user's sound away.
        if let Some(moved) = output_moved_under_us(
            default_sink().as_deref(),
            &self.previous_default,
            &self.node_name,
        ) {
            let moved = moved.to_string();
            eprintln!(
                "audiosink: the output is {moved} now, not {}; that is a choice of yours, \
                 so it is not being taken and nothing will be put back over it",
                self.previous_default
            );
            return Err(SinkError::OutputMoved(moved));
        }

        self.took_default = true;
        self.write_claim();
        if let Err(e) = set_default_sink(&self.node_name) {
            self.took_default = false;
            self.write_claim();
            return Err(SinkError::Io(e));
        }
        // The set succeeded, so the output HAS moved. From here on the only
        // question is what the machine reports, and no report may cost the user the
        // restore: `took_default` and `restore_default` stay as they are
        // unless something else is stably and provably the output. The rules
        // are in `take_verdict`, which is pure and unit-tested.
        let settled = self.settled_default();
        // Only asked when it can change the answer: one pw-metadata call.
        let configured = match settled {
            Settled::Other(_) => configured_default_sink(),
            _ => None,
        };
        match take_verdict(&settled, configured.as_deref(), &self.node_name, &self.previous_default) {
            TakeVerdict::Took => Ok(()),
            TakeVerdict::TookUnconfirmed => {
                // Every read failed. Unknown is not hostile — `pactl` being
                // unreadable says nothing about who owns the output, and the
                // set we just made says we do. Keep the claim, open the gate.
                eprintln!(
                    "audiosink: took the output as {} but cannot read it back; \
                     keeping the claim so it is given back either way",
                    self.node_name
                );
                Ok(())
            }
            // The handover was accepted — the configured default names us —
            // but the active default has not followed. We own the rot, so we
            // keep the claim that repairs it; the gate holds, because the TV
            // would hear nothing anyway.
            TakeVerdict::KeepAndHold(d) => Err(SinkError::TookUnsettled {
                node: self.node_name.clone(),
                reads: d,
            }),
            TakeVerdict::NotTaken(d) => {
                // Our write did not take and nothing else claimed the output:
                // the user still has his sound on the sink we would restore anyway.
                // Nothing was taken, so nothing is owed — but the record stays
                // honest rather than disowned.
                self.took_default = false;
                self.write_claim();
                Err(SinkError::Pipewire(format!("asked for the output but it is still {d}")))
            }
            TakeVerdict::Disown(d) => {
                // Something else really owns the output. Do not fight for it:
                // give up the claim so neither Drop nor a later sweep undoes
                // whatever that was, and report it so the gate holds the audio
                // silent.
                eprintln!("audiosink: asked for the output but it reads {d:?}; not taking it, and not putting anything back");
                self.disown_default();
                Err(SinkError::Pipewire(format!(
                    "the default output reads {d:?}, not {}",
                    self.node_name
                )))
            }
        }
    }

    /// Poll the active default until it is ours, for up to [`DEFAULT_SETTLE`].
    ///
    /// Never conflates a failed read with somebody else's output: that is the
    /// rule [`crate::volume`]'s `still_default` states in its own doc comment
    /// ("a read that fails answers `None` ('unknown'), never `false`"), and
    /// the cost of breaking it here is the user's restore.
    fn settled_default(&self) -> Settled {
        let t0 = Instant::now();
        let mut last: Option<String> = None;
        loop {
            match default_sink() {
                Some(d) if d == self.node_name => return Settled::Ours,
                Some(d) => last = Some(d),
                None => {}
            }
            if t0.elapsed() >= DEFAULT_SETTLE {
                break;
            }
            std::thread::sleep(POLL_SLICE);
        }
        match last {
            Some(d) => Settled::Other(d),
            None => Settled::Unknown,
        }
    }

    /// Is our sink still the laptop's output? One `pactl get-default-sink`.
    pub fn is_default(&self) -> Option<bool> {
        default_sink().map(|d| d == self.node_name)
    }

    /// the user chose another output himself. Never put the old one back, and say
    /// so in the claim so a later sweep does not either.
    ///
    /// Only for a choice of his. The caller's evidence is that the ACTIVE
    /// default moved away from us, and that is also what a node of ours dying
    /// looks like — so the same discriminator [`Self::teardown`] uses applies
    /// here, and it matters more: this writes `restore_default: false` into
    /// the claim, which makes even `airplay audio --cleanup` skip the repair
    /// after a SIGKILL.
    pub fn disown_default(&mut self) {
        if !self.restore_default {
            return;
        }
        if configured_default_sink().as_deref() == Some(self.node_name.as_str()) {
            // A choice of his rewrites the configured default; a WirePlumber
            // fallback election does not. This one still names our node, so
            // the output did not move because he asked — keep the restore.
            eprintln!(
                "audiosink: the output moved away but is still configured for {}; \
                 that is our own node, not a choice of yours — keeping the restore",
                self.node_name
            );
            return;
        }
        self.restore_default = false;
        self.write_claim();
        eprintln!(
            "audiosink: the output was changed away from {}; leaving the new choice alone",
            self.node_name
        );
    }

    pub fn restores_default(&self) -> bool {
        self.restore_default
    }

    /// Is our monitor pre-volume? If `monitor.channel-volumes=false` did not
    /// take, capturing this monitor would attenuate twice and ship
    /// quietly-too-soft audio at every setting; the caller refuses the sink
    /// path rather than do that.
    ///
    /// # What this does and does not establish
    ///
    /// It reads `monitor.channel-volumes` back out of `pw-dump`, and that
    /// dictionary is the **client-supplied** property list: a value we passed
    /// comes back verbatim (passing `"banana"` reads back `"banana"`). So a
    /// `Some(false)` proves that nothing on the host overrode what we asked
    /// for — a WirePlumber `update-props` rule would show up here — and it
    /// does not prove that PipeWire honoured it. The behavioural proof is
    /// `samples_arrive_pre_volume_from_our_own_monitor` in
    /// `tests/audio_sink_live.rs`, which compares the monitor's peak against
    /// [`Self::last_process_peak`] at three levels.
    ///
    /// Unknown is therefore **not** pre-volume. An absent or unparseable
    /// dump used to read as "pre-volume", i.e. the one guard on the path
    /// failed open; it now answers `false` and the caller takes the monitor
    /// path, which is quieter-but-correct rather than confidently wrong.
    /// Polled briefly, because a node that has just appeared may not be in
    /// the dump yet.
    pub fn monitor_is_pre_volume(&self) -> bool {
        let t0 = Instant::now();
        loop {
            match crate::audiocapture::sink_monitor_is_post_volume(&self.node_name) {
                Some(post) => return pre_volume_verdict(Some(post)),
                None if t0.elapsed() < DEFAULT_SETTLE => std::thread::sleep(POLL_SLICE),
                None => {
                    eprintln!(
                        "audiosink: cannot tell whether {}'s monitor carries the sink's volume; \
                         treating it as post-volume",
                        self.node_name
                    );
                    return pre_volume_verdict(None);
                }
            }
        }
    }

    /// Capture options that tap **this sink's own monitor**, pre-volume.
    ///
    /// `dont_fallback` is set: if our own sink is gone the session is over,
    /// and silently capturing the desk speakers instead would send the room to
    /// the TV.
    pub fn capture_opts(&self) -> PwCaptureOpts {
        PwCaptureOpts {
            target: Some(self.node_name.clone()),
            dont_fallback: true,
            ..Default::default()
        }
    }

    /// Diagnostics only: the peak the **sink node's own** `process()` has seen
    /// since [`Self::reset_process_peak`].
    ///
    /// This payload is POST-volume and is never sent anywhere — it is
    /// dequeued and dropped. It is exposed so a test can prove, in one run,
    /// that the monitor tap is pre-volume *and* that the sink's volume really
    /// was applied: without the second half, "peak unchanged" could just mean
    /// the volume never took.
    pub fn last_process_peak(&self) -> u16 {
        self.shared.process_peak.load(Ordering::Relaxed).min(u16::MAX as u32) as u16
    }

    pub fn reset_process_peak(&self) {
        self.shared.process_peak.store(0, Ordering::Relaxed);
    }

    /// How many times the node's `process()` has been called. Non-zero while
    /// nothing is playing is what proves `node.always-process=true` took.
    pub fn process_calls(&self) -> u64 {
        self.shared.process_calls.load(Ordering::Relaxed)
    }

    /// The first fatal thing that happened to the node, if any: the stream
    /// reaching `Error`, the connection to PipeWire being lost, or a format
    /// other than S16LE/44100/2 being negotiated.
    ///
    /// Live for the whole session, not just for `publish`. A node can die
    /// under a running sender — a WirePlumber restart, a renegotiation — and
    /// the only other symptom is that the capture quietly starves, which
    /// looks exactly like nothing playing. The session is expected to poll
    /// this and hold the gate rather than send silence to the TV.
    pub fn fatal(&self) -> Option<String> {
        self.shared.fatal()
    }

    /// `false` once [`Self::fatal`] has an answer.
    pub fn is_healthy(&self) -> bool {
        self.shared.fatal().is_none()
    }

    /// The last `channelVolumes` the node was handed (linear, the cube of
    /// pactl's percent). Diagnostics; never the TV's level source.
    pub fn channel_volume(&self) -> Option<f32> {
        let v = f32::from_bits(self.shared.channel_volume.load(Ordering::Relaxed));
        v.is_finite().then_some(v)
    }

    fn claim(&self) -> Claim {
        Claim {
            node_name: self.node_name.clone(),
            label: self.label.clone(),
            previous_default: self.previous_default.clone(),
            took_default: self.took_default,
            restore_default: self.restore_default,
            pid: std::process::id(),
            created_unix: state::now_unix(),
        }
    }

    fn write_claim(&self) {
        if let Err(e) = state::write(&self.claim()) {
            eprintln!("audiosink: could not record the output claim: {e}");
        }
    }

    /// Take the published node down NOW, without waiting for `Drop`: the
    /// output goes back (or is deliberately left alone), the node disappears
    /// from the user's output menu, and the claim is settled.
    ///
    /// This is what the session's detach hook owes the user, and it is a
    /// safety property, not tidiness. Once the laptop's output has been moved
    /// away from our sink the sender is gated to digital silence for the rest
    /// of the session and nothing re-opens it — so a node still listed as
    /// "AirPlay: <TV>" is a trap: picking it, which is the obvious reaction to
    /// the TV going quiet, routes every stream into a sink that makes no sound
    /// anywhere. Idempotent, and `Drop` is a no-op afterwards.
    pub fn unpublish(&mut self) {
        if self.torn_down {
            return;
        }
        eprintln!(
            "audiosink: taking {} down now, so it is not left in your output menu making no sound",
            self.node_name
        );
        self.teardown();
    }

    /// Put the output back, stop the node, clear the claim. Called by `Drop`
    /// and by [`Self::unpublish`]; separated so the order is readable and
    /// testable. Idempotent: the second call does nothing at all, so an early
    /// `unpublish` cannot make `Drop` re-run a restore against a machine the
    /// user has since changed.
    fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        // The output goes back FIRST, while our node still exists: streams
        // follow the default natively, so they are already back on the user's
        // speakers by the time the node disappears. The other order leaves a
        // window with no default at all.
        let outcome = if self.took_default && self.restore_default {
            self.give_the_output_back()
        } else {
            // Never taken, or deliberately disowned because the user picked an
            // output himself. Either way there is nothing of ours left to
            // repair, so the record may go.
            Given::NotOurs
        };
        self.took_default = false;

        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let t0 = Instant::now();
            while !t.is_finished() && t0.elapsed() < JOIN_BOUND {
                std::thread::sleep(POLL_SLICE);
            }
            if t.is_finished() {
                let _ = t.join();
            } else {
                eprintln!("audiosink: PipeWire thread did not stop within {JOIN_BOUND:?}; detaching");
            }
        }

        // The rule this module inherits from `virtualoutput`'s teardown, where
        // it was learned the hard way: a claim may be cleared only when the
        // thing it describes is known repaired or known not ours. On anything
        // unsettled it STAYS, so `--cleanup` and the next run's sweep can
        // still finish the job. The claim on disk already says
        // `took_default: true` with the sink to put back; it is deliberately
        // NOT rewritten here, because rewriting it from this object's
        // now-cleared fields would poison the very record we are keeping.
        if may_clear_claim(outcome) {
            let _ = state::clear();
        } else {
            eprintln!(
                "audiosink: the output was not put back to {}; keeping the claim so \
                 `airplay audio --cleanup` (or the next run) can finish it",
                self.previous_default
            );
        }
    }

    /// The restore itself. Returns what is now known, which is what decides
    /// whether the claim may be cleared.
    fn give_the_output_back(&self) -> Given {
        // "Not in the list" and "the list did not come back" are different
        // answers and only the first one means the sink is gone.
        let live = live_sinks_checked();
        let previous_is_live = live.as_ref().map(|l| l.iter().any(|s| s == &self.previous_default));
        let active = default_sink();
        // One pw-metadata call, and only where it changes the answer.
        let configured = match (previous_is_live, active.as_deref()) {
            (Some(false), _) => configured_default_sink(),
            (_, Some(d)) if d != self.node_name => configured_default_sink(),
            _ => None,
        };
        match give_back_plan(
            previous_is_live,
            active.as_deref(),
            configured.as_deref(),
            &self.node_name,
        ) {
            GiveBackPlan::Restore => self.restore_to_previous(),
            GiveBackPlan::TheirChoice(d) => {
                eprintln!("audiosink: the output is {d}, not ours; leaving it");
                Given::NotOurs
            }
            GiveBackPlan::OursIsDead(d) => {
                eprintln!(
                    "audiosink: the output reads {d} but is still configured for {}; \
                     that is our node, not a choice of yours — putting {} back",
                    self.node_name, self.previous_default
                );
                self.restore_to_previous()
            }
            GiveBackPlan::PreviousGone { rot_is_ours } => {
                eprintln!(
                    "audiosink: {} is gone; leaving the output to PipeWire's own fallback",
                    self.previous_default
                );
                if rot_is_ours {
                    Given::Unsettled
                } else {
                    Given::NotOurs
                }
            }
        }
    }

    fn restore_to_previous(&self) -> Given {
        if let Err(e) = set_default_sink(&self.previous_default) {
            eprintln!(
                "audiosink: could not put the output back to {}: {e}",
                self.previous_default
            );
            return Given::Unsettled;
        }
        // Verify, for the same reason `take_default` does: the active default
        // lags the write by milliseconds, and an unread default is unknown,
        // never a failure. A confirmation from either key counts.
        let t0 = Instant::now();
        loop {
            if default_sink().as_deref() == Some(self.previous_default.as_str()) {
                return Given::Back;
            }
            if t0.elapsed() >= DEFAULT_SETTLE {
                break;
            }
            std::thread::sleep(POLL_SLICE);
        }
        match configured_default_sink() {
            Some(c) if c == self.previous_default => Given::Back,
            other => {
                eprintln!(
                    "audiosink: put the output back to {} but it reads {other:?}",
                    self.previous_default
                );
                Given::Unsettled
            }
        }
    }
}

/// What teardown should do about the output it was holding, given read-only
/// facts. Pure, so the discrimination that matters — **"the user picked another
/// output" versus "our node died and WirePlumber elected a fallback"** — is
/// unit-tested rather than reasoned about once.
///
/// The two look identical in the ACTIVE default (both are "not us"), and
/// conflating them is how a dead node ends up named in
/// `default.configured.audio.sink` for good. The CONFIGURED default tells
/// them apart: a choice of his rewrites it, a fallback election does not.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GiveBackPlan {
    /// The output is ours (or unreadable, which is not somebody else's):
    /// put the previous one back.
    Restore,
    /// Somebody else's choice owns the output and nothing of ours is
    /// configured. Leave it alone.
    TheirChoice(String),
    /// The active default is not ours, but the configured default still names
    /// our node: that is our corpse, not his choice. Put it back.
    OursIsDead(String),
    /// The sink to put back no longer exists. `rot_is_ours` when the machine
    /// is still configured for our node, which is a record that must outlive
    /// this process.
    PreviousGone { rot_is_ours: bool },
}

fn give_back_plan(
    previous_is_live: Option<bool>,
    active: Option<&str>,
    configured: Option<&str>,
    node: &str,
) -> GiveBackPlan {
    // `None` is "the sink listing failed", which is unknown, never gone: the
    // restore is attempted, and restoring to a sink that really did vanish is
    // benign because PipeWire re-elects. Only `Some(false)` means gone.
    if previous_is_live == Some(false) {
        return GiveBackPlan::PreviousGone { rot_is_ours: configured == Some(node) };
    }
    match active {
        Some(d) if d != node => {
            if configured == Some(node) {
                GiveBackPlan::OursIsDead(d.to_string())
            } else {
                GiveBackPlan::TheirChoice(d.to_string())
            }
        }
        _ => GiveBackPlan::Restore,
    }
}

/// What teardown established about the output it was holding — and so whether
/// the claim may be cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Given {
    /// Put back and confirmed. Nothing left to repair.
    Back,
    /// Nothing of ours is configured anywhere: never taken, deliberately
    /// disowned, or the user's own choice now owns the output.
    NotOurs,
    /// The restore failed, could not be confirmed, or our dead node is still
    /// the configured default. The claim stays on disk.
    Unsettled,
}

/// The rule `virtualoutput`'s teardown had to learn the hard way, stated once
/// and tested: **a claim may be cleared only when the thing it describes is
/// known repaired or known not ours.** Anything unsettled keeps it, so
/// `airplay audio --cleanup` and the next run's sweep can still finish the
/// job. A surviving claim costs nothing — the next sweep clears it as stale —
/// while a deleted one can never be repaired.
fn may_clear_claim(given: Given) -> bool {
    match given {
        Given::Back | Given::NotOurs => true,
        Given::Unsettled => false,
    }
}

impl Drop for AirPlaySink {
    fn drop(&mut self) {
        self.teardown();
    }
}

// --------------------------------------------------------------------------
// The PipeWire loop thread
// --------------------------------------------------------------------------

/// `SPA_PROP_channelVolumes`. Read for diagnostics and for the seed's
/// settle logic only.
const SPA_PROP_CHANNEL_VOLUMES: u32 = libspa_sys::SPA_PROP_channelVolumes;

/// Body of the loop thread: publish an `Audio/Sink` node and iterate until
/// stopped. Modelled on [`crate::audiocapture`]'s capture thread, with four
/// differences that are each load-bearing (see the comments at `props`).
fn sink_thread(opts: (String, String, String), shared: Arc<Shared>, ready: mpsc::Sender<Result<u32, String>>) {
    use pipewire as pw;
    use pw::properties::properties;
    use pw::spa;

    let (node_name, label, app_name) = opts;
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
            // Only a lost connection (-EPIPE on the core) is fatal; other core
            // errors are expected around relinks.
            if id == pw::core::PW_ID_CORE && res == -libc::EPIPE {
                sh_core.set_fatal(format!("connection to PipeWire lost: {msg}"));
            } else {
                eprintln!("audiosink: PipeWire error on {id} ({res}): {msg}");
            }
        })
        .register();

    let props = properties! {
        *pw::keys::MEDIA_TYPE => "Audio",
        // Playback, not Capture: samples flow INTO this node.
        *pw::keys::MEDIA_CATEGORY => "Playback",
        // This is the property that makes the node a sink the user can pick.
        *pw::keys::MEDIA_CLASS => "Audio/Sink",
        *pw::keys::NODE_NAME => node_name.as_str(),
        *pw::keys::NODE_DESCRIPTION => label.as_str(),
        *pw::keys::APP_NAME => app_name.as_str(),
        // NOT optional: without it the node never leaves Paused and
        // `process()` is never called while no application is playing.
        // `node.pause-on-idle=false` does not do this. Do NOT add
        // `node.driver`/`priority.driver`: that kills the callbacks entirely.
        "node.always-process" => "true",
        // Never win a fallback election: becoming the output is something we
        // do explicitly, with a claim on disk, or not at all.
        "priority.session" => "0",
        // The monitor of this sink must NOT carry the sink's channel volumes:
        // that is what makes our capture pre-volume, so the level is applied
        // exactly once, at the TV. `AirPlaySink::monitor_is_pre_volume` reads
        // this back before the sink path is used — which catches a host-side
        // override of the property and refuses on an unknown, but is not a
        // proof that PipeWire honoured it; that proof is behavioural and
        // lives in `tests/audio_sink_live.rs`.
        "monitor.channel-volumes" => "false",
        "node.latency" => PW_NODE_LATENCY,
        // Best-effort: ask WirePlumber not to restore a remembered volume onto
        // us. Correctness does not depend on either of these — `seed_level`
        // writes and verifies the level regardless.
        "state.restore-props" => "false",
        "node.stream.restore-props" => "false",
    };

    let stream = match pw::stream::StreamBox::new(&core, "airplay-rs sink", props) {
        Ok(s) => s,
        Err(e) => return fail(&ready, format!("stream: {e}")),
    };

    let sh_param = shared.clone();
    let sh_rt = shared.clone();
    let sh_state = shared.clone();
    let listener = stream
        .add_local_listener_with_user_data(())
        // Without this the node can die under a running session in silence:
        // the capture is pinned to it with `dont_fallback`, so it simply stops
        // delivering and the sender reports "stalled", which is what nothing
        // playing looks like too. There is no reconnect here on purpose — a
        // sink that comes back under a new id has already lost the output and
        // the streams that followed it — so the error is RECORDED and the
        // session decides.
        .state_changed(move |_, _, old, new| {
            use pw::stream::StreamState as S;
            match &new {
                S::Error(msg) => {
                    eprintln!("audiosink: the sink stream failed: {msg}");
                    sh_state.set_fatal(format!("the sink node failed: {msg}"));
                }
                // The node going AWAY, which is the common shape of this
                // failure and is not an `Error` at all. Measured: `pw-cli
                // destroy` on our own node (what a WirePlumber restart, or a
                // policy tearing the node down, looks like from here) gives
                // `Paused -> Unconnected` plus a stream of `unknown resource`
                // core errors — no `Error` state ever. Watching only for
                // `Error` therefore missed exactly the case the watch exists
                // for, and the session went on sending into a sink that was
                // gone. `connected` is what tells this apart from the
                // `Unconnected` every stream starts in, and `stop` from the
                // `Unconnected` our own teardown causes.
                S::Unconnected
                    if sh_state.connected.load(Ordering::SeqCst)
                        && !sh_state.stop.load(Ordering::SeqCst) =>
                {
                    eprintln!("audiosink: the sink node went away (the stream is Unconnected again)");
                    sh_state.set_fatal("the sink node was destroyed under the session".into());
                }
                _ => {
                    if matches!(new, S::Paused | S::Streaming) {
                        sh_state.connected.store(true, Ordering::SeqCst);
                    }
                    eprintln!("audiosink: stream {old:?} -> {new:?}");
                }
            }
        })
        .param_changed(move |_, _, id, param| {
            let Some(p) = param else { return };
            if id == spa::param::ParamType::Format.as_raw() {
                let mut info = spa::param::audio::AudioInfoRaw::new();
                if info.parse(p).is_ok()
                    && (info.rate() != crate::audio::AUDIO_RATE
                        || info.channels() != 2
                        || info.format() != spa::param::audio::AudioFormat::S16LE)
                {
                    // We offer S16LE/44100/2 and a sink negotiates exactly what
                    // it is offered; anything else would corrupt every frame.
                    sh_param.set_fatal(format!(
                        "negotiated {:?} {} Hz {} ch, need S16LE 44100 Hz 2 ch",
                        info.format(),
                        info.rate(),
                        info.channels()
                    ));
                }
                return;
            }
            if id == spa::param::ParamType::Props.as_raw() {
                if let Some(v) = channel_volume_of(p.as_bytes()) {
                    sh_param.channel_volume.store(v.to_bits(), Ordering::Relaxed);
                    sh_param.props_epoch.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
        .process(move |stream, _| {
            // RT thread: no allocation, no locks, no blocking. This payload is
            // post-volume and goes nowhere — it is dequeued so the node stays
            // healthy, measured for the pre-volume test, and dropped.
            let Some(mut buf) = stream.dequeue_buffer() else { return };
            let datas = buf.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let off = d.chunk().offset() as usize;
            let size = d.chunk().size() as usize;
            let mut peak: u32 = 0;
            if let Some(bytes) = d.data() {
                let start = off.min(bytes.len());
                let end = (off + size).min(bytes.len());
                for s in bytes[start..end].as_chunks::<2>().0 {
                    let v = i16::from_le_bytes(*s).unsigned_abs() as u32;
                    if v > peak {
                        peak = v;
                    }
                }
            }
            sh_rt.process_peak.fetch_max(peak, Ordering::Relaxed);
            sh_rt.process_calls.fetch_add(1, Ordering::Relaxed);
        })
        .register();
    let listener = match listener {
        Ok(l) => l,
        Err(e) => return fail(&ready, format!("stream listener: {e}")),
    };

    let pod = match crate::audiocapture::format_pod() {
        Ok(p) => p,
        Err(e) => return fail(&ready, e),
    };
    {
        let Some(pod_ref) = spa::pod::Pod::from_bytes(&pod) else {
            return fail(&ready, "format pod".into());
        };
        let mut params = [pod_ref];
        // Direction::Input: this node CONSUMES audio. No AUTOCONNECT — a sink
        // is not connected to anything; applications connect to it.
        if let Err(e) = stream.connect(
            spa::utils::Direction::Input,
            None,
            pw::stream::StreamFlags::MAP_BUFFERS | pw::stream::StreamFlags::RT_PROCESS,
            &mut params,
        ) {
            return fail(&ready, format!("stream connect: {e}"));
        }
    }

    let lp = mainloop.loop_();
    let t0 = Instant::now();
    while stream.node_id() == u32::MAX && t0.elapsed() < Duration::from_secs(2) {
        lp.iterate(pw::loop_::Timeout::Finite(Duration::from_millis(10)));
    }
    shared.node_id.store(stream.node_id(), Ordering::Relaxed);
    if let Some(msg) = shared.fatal() {
        let _ = stream.disconnect();
        return fail(&ready, msg);
    }
    if stream.node_id() == u32::MAX {
        let _ = stream.disconnect();
        return fail(&ready, "the sink node never got an id".into());
    }
    let _ = ready.send(Ok(stream.node_id()));

    let mut reported_fatal = false;
    while !shared.stop.load(Ordering::SeqCst) {
        lp.iterate(pw::loop_::Timeout::Finite(POLL_SLICE));
        shared.node_id.store(stream.node_id(), Ordering::Relaxed);
        // Said once, here, because after `publish` returns nobody was reading
        // it: `AirPlaySink::fatal()` is now the session's handle on this, and
        // the log line is for the run where nothing polls it.
        if !reported_fatal {
            if let Some(msg) = shared.fatal() {
                reported_fatal = true;
                eprintln!("audiosink: {msg}; the sink is no longer carrying audio to the TV");
            }
        }
    }
    let _ = stream.disconnect();
    drop(listener);
    drop(stream);
}

/// The loudest `channelVolumes` entry in a `Props` pod, if it carries one.
/// Pure, so the parse is unit-tested without PipeWire.
pub(crate) fn channel_volume_of(pod_bytes: &[u8]) -> Option<f32> {
    use pipewire::spa::pod::{deserialize::PodDeserializer, Value, ValueArray};
    let (_, value) = PodDeserializer::deserialize_any_from(pod_bytes).ok()?;
    let Value::Object(obj) = value else { return None };
    for p in obj.properties {
        if p.key != SPA_PROP_CHANNEL_VOLUMES {
            continue;
        }
        if let Value::ValueArray(ValueArray::Float(v)) = p.value {
            return v.into_iter().filter(|f| f.is_finite()).fold(None, |m: Option<f32>, f| {
                Some(m.map_or(f, |m| m.max(f)))
            });
        }
    }
    None
}

// --------------------------------------------------------------------------
// tests (pure; none of these publish a node or run pactl)
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(node: &str, prev: &str) -> Claim {
        Claim {
            node_name: node.into(),
            label: "AirPlay: test".into(),
            previous_default: prev.into(),
            took_default: true,
            restore_default: true,
            pid: 1234,
            created_unix: 1_700_000_000,
        }
    }

    const SPEAKER: &str = "alsa_output.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__Speaker__sink";

    #[test]
    fn sink_node_name_is_sanitised_and_collision_safe() {
        assert_eq!(node_name_for("75\" The Frame"), "airplay-sink.75_the_frame");
        // The pretty label and the bare receiver name agree, so the name is
        // stable however the caller spells it.
        assert_eq!(node_name_for("AirPlay: 75\" The Frame"), node_name_for("75\" The Frame"));
        assert_eq!(node_name_for("Living Room"), "airplay-sink.living_room");
        assert_eq!(node_name_for("  ???  "), "airplay-sink.receiver");
        assert_eq!(node_name_for("Owner's Apple TV (4K)"), "airplay-sink.owner_s_apple_tv_4k");

        for label in ["75\" The Frame", "Living Room", "!!!", &"x".repeat(200)] {
            let n = node_name_for(label);
            assert!(n.starts_with(NAME_PREFIX), "{n}");
            assert!(n.len() <= MAX_NAME_LEN, "{n} is {} bytes", n.len());
            assert!(!n.starts_with("alsa_output."), "{n} would short-circuit the omarchy script");
            // Both prefix directions: the omarchy volume script matches
            // sink-inputs with a prefix test.
            assert!(!n.starts_with(CAPTURE_NODE_NAME), "{n}");
            assert!(!CAPTURE_NODE_NAME.starts_with(&n), "{n}");
            validate_name(&n).unwrap_or_else(|e| panic!("{n}: {e}"));
        }
        // Stable across calls: WirePlumber's default-nodes file must grow by
        // at most one entry per receiver, not one per session.
        assert_eq!(node_name_for("75\" The Frame"), node_name_for("75\" The Frame"));
    }

    #[test]
    fn validate_name_refuses_anything_that_is_not_ours() {
        for bad in [
            SPEAKER,
            "alsa_output.x",
            "easyeffects_sink",
            "airplay-sink.",
            "",
            "AIRPLAY-1",
            "airplay-sink.WithCaps",
            "airplay-sink.spaces here",
            &format!("{NAME_PREFIX}{}", "x".repeat(MAX_NAME_LEN)),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(validate_name("airplay-sink.75_the_frame").is_ok());
    }

    #[test]
    fn node_description_keeps_the_receivers_own_text() {
        let o = SinkOpts::for_receiver("75\" The Frame");
        assert_eq!(o.label, "AirPlay: 75\" The Frame");
        assert!(o.label.contains('"'), "the receiver's own quote must survive");
        assert_eq!(o.app_name, "airplay-rs-sink");
        // Deliberately NOT the capture stream's application.name: the two
        // remembered volumes must be separate keys.
        assert_ne!(o.app_name, PwCaptureOpts::default().app_name);
    }

    #[test]
    fn parse_configured_default_reads_pw_metadata() {
        let real = "Found \"default\" metadata 39\n\
                    update: id:0 key:'default.configured.audio.sink' \
                    value:'{\"name\":\"alsa_output.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__Speaker__sink\"}' \
                    type:'Spa:String:JSON'\n";
        assert_eq!(parse_configured_default(real).as_deref(), Some(SPEAKER));

        // The spaced form pw-metadata also prints.
        let spaced = "update: id:0 key:'default.configured.audio.sink' value:'{ \"name\": \"airplay-sink.x\" }' type:'Spa:String:JSON'\n";
        assert_eq!(parse_configured_default(spaced).as_deref(), Some("airplay-sink.x"));

        // Unset, unrelated, and garbage all mean "nothing named".
        assert_eq!(parse_configured_default("Found \"default\" metadata 39\n"), None);
        assert_eq!(parse_configured_default(""), None);
        assert_eq!(
            parse_configured_default("update: id:0 key:'default.audio.source' value:'{\"name\":\"x\"}'\n"),
            None
        );
        assert_eq!(
            parse_configured_default("update: id:0 key:'default.configured.audio.sink' value:'not json'\n"),
            None
        );
        assert_eq!(
            parse_configured_default("update: id:0 key:'default.configured.audio.sink' value:'{\"name\":\"\"}'\n"),
            None
        );
    }

    #[test]
    fn parse_short_sinks_reads_pactl() {
        let out = "92\teasyeffects_sink\tPipeWire\tfloat32le 2ch 48000Hz\tSUSPENDED\n\
                   10463\talsa_output.speaker\tPipeWire\ts32le 2ch 48000Hz\tSUSPENDED\n";
        assert_eq!(parse_short_sinks(out), vec!["easyeffects_sink", "alsa_output.speaker"]);
        assert!(parse_short_sinks("").is_empty());
        assert!(parse_short_sinks("garbage\n").is_empty());
    }

    #[test]
    fn claim_roundtrips_through_json() {
        let c = claim("airplay-sink.frame", SPEAKER);
        let bytes = serde_json::to_vec(&c).unwrap();
        assert_eq!(serde_json::from_slice::<Claim>(&bytes).unwrap(), c);
    }

    #[test]
    fn a_foreign_name_is_never_swept() {
        // A hand-edited or corrupt claim naming a hardware sink must be
        // cleared, never acted on: nothing may make this module set the
        // default on the say-so of a name it did not publish.
        let hostile = claim(SPEAKER, "airplay-sink.frame");
        assert_eq!(
            reclaim_decision(&hostile, Some(SPEAKER), Some(&[SPEAKER.into(), "airplay-sink.frame".into()])),
            Repair::ClearedStaleClaim
        );
        let hostile = claim("AIRPLAY-1", SPEAKER);
        assert_eq!(
            reclaim_decision(&hostile, Some("AIRPLAY-1"), Some(&[SPEAKER.into()])),
            Repair::ClearedStaleClaim
        );
    }

    #[test]
    fn reclaim_decision_table() {
        let ours = "airplay-sink.frame";
        let c = claim(ours, SPEAKER);
        let live_speaker = vec![SPEAKER.to_string()];

        // The SIGKILL case: our node is gone, the configured default still
        // names it, the sink we took the output from is back.
        assert_eq!(
            reclaim_decision(&c, Some(ours), Some(&live_speaker)),
            Repair::RestoredDefault { from: ours.into(), to: SPEAKER.into() }
        );

        // Our node is still live: not ours to reason about, and nothing is
        // cleared either (the claim still describes something real).
        assert_eq!(
            reclaim_decision(&c, Some(ours), Some(&[SPEAKER.into(), ours.into()])),
            Repair::Nothing
        );

        // The configured default is somebody else's: the user (or WirePlumber)
        // moved on. Clear the record; restore nothing.
        assert_eq!(reclaim_decision(&c, Some(SPEAKER), Some(&live_speaker)), Repair::ClearedStaleClaim);
        assert_eq!(reclaim_decision(&c, None, Some(&live_speaker)), Repair::ClearedStaleClaim);

        // The previous default is gone (the headphones were unplugged while we
        // were dead). Do NOT guess another sink: WirePlumber's own election
        // already kept audio working.
        assert_eq!(reclaim_decision(&c, Some(ours), Some(&[])), Repair::ClearedStaleClaim);
        assert_eq!(
            reclaim_decision(&c, Some(ours), Some(&["some_other_sink".into()])),
            Repair::ClearedStaleClaim
        );

        // We never took the output, so there is nothing to put back.
        let never = Claim { took_default: false, ..c.clone() };
        assert_eq!(reclaim_decision(&never, Some(ours), Some(&live_speaker)), Repair::ClearedStaleClaim);

        // the user chose an output himself mid-session: the sweep must not undo it
        // any more than Drop may.
        let disowned = Claim { restore_default: false, ..c.clone() };
        assert_eq!(reclaim_decision(&disowned, Some(ours), Some(&live_speaker)), Repair::ClearedStaleClaim);
    }

    #[test]
    fn an_unreadable_sink_list_never_throws_the_claim_away() {
        // `Some(&[])` is "the list came back and it is empty"; `None` is "the
        // list did not come back". The second must not decide anything —
        // least of all that the sink to put back is gone, which would clear
        // the one record `airplay audio --cleanup` repairs from. A claim that
        // survives costs nothing; the next sweep clears it if it is stale.
        let ours = "airplay-sink.frame";
        let c = claim(ours, SPEAKER);
        assert_eq!(reclaim_decision(&c, Some(ours), None), Repair::CouldNotTell);
        assert_eq!(reclaim_decision(&c, Some(SPEAKER), None), Repair::CouldNotTell);
        assert_eq!(reclaim_decision(&c, None, None), Repair::CouldNotTell);
        // `CouldNotTell` is one of the two answers `reclaim_locked` leaves the
        // claim on disk for, and it is the one that does not claim to have
        // found anything: `Repair::Nothing` says "a sink of that name is live",
        // which here would be a fact nobody read.
        let never = Claim { took_default: false, ..c.clone() };
        assert_eq!(reclaim_decision(&never, Some(ours), None), Repair::CouldNotTell);
        assert_ne!(reclaim_decision(&c, Some(ours), None), Repair::Nothing);

        // One thing IS still decidable without reading anything: a claim
        // naming a sink we could never have published stays hostile, and is
        // cleared rather than kept.
        let hostile = claim(SPEAKER, ours);
        assert_eq!(reclaim_decision(&hostile, Some(SPEAKER), None), Repair::ClearedStaleClaim);
    }

    #[test]
    fn an_unreadable_machine_never_costs_the_restore() {
        let ours = "airplay-sink.frame";

        // The ordinary handover.
        assert_eq!(take_verdict(&Settled::Ours, None, ours, SPEAKER), TakeVerdict::Took);

        // Nothing could be read. `pactl` failing says nothing about who owns
        // the output, and the `set-default-sink` that preceded it succeeded —
        // so the output may well be ours. Anything that forfeited the claim
        // here would leave the user on the AirPlay sink after the session, with the
        // one record that could repair it deliberately disabled.
        assert_eq!(
            take_verdict(&Settled::Unknown, None, ours, SPEAKER),
            TakeVerdict::TookUnconfirmed
        );

        // The write was accepted (the configured default names us) but the
        // active default has not followed. The rot is ours: keep the claim.
        assert_eq!(
            take_verdict(&Settled::Other(SPEAKER.into()), Some(ours), ours, SPEAKER),
            TakeVerdict::KeepAndHold(SPEAKER.into())
        );

        // The write did not take at all and the user's own output still has the
        // sound. Nothing taken, nothing owed — and nothing disowned either.
        assert_eq!(
            take_verdict(&Settled::Other(SPEAKER.into()), Some(SPEAKER), ours, SPEAKER),
            TakeVerdict::NotTaken(SPEAKER.into())
        );

        // The one case that may forfeit the restore: a stable other output
        // that is neither us nor the one we came from.
        assert_eq!(
            take_verdict(&Settled::Other("bt_headphones".into()), Some("bt_headphones"), ours, SPEAKER),
            TakeVerdict::Disown("bt_headphones".into())
        );

        // ...and it is the ONLY one. Anything else forfeiting is the bug.
        for v in [
            take_verdict(&Settled::Ours, None, ours, SPEAKER),
            take_verdict(&Settled::Unknown, None, ours, SPEAKER),
            take_verdict(&Settled::Unknown, Some(SPEAKER), ours, SPEAKER),
            take_verdict(&Settled::Other(SPEAKER.into()), Some(ours), ours, SPEAKER),
            take_verdict(&Settled::Other(SPEAKER.into()), None, ours, SPEAKER),
        ] {
            assert!(!matches!(v, TakeVerdict::Disown(_)), "{v:?} must not forfeit the restore");
        }
    }

    #[test]
    fn a_dead_node_is_not_a_choice() {
        let ours = "airplay-sink.frame";

        // The ordinary end: we are the output, and it goes back.
        assert_eq!(give_back_plan(Some(true), Some(ours), None, ours), GiveBackPlan::Restore);

        // the user picked another output himself: his choice rewrote the configured
        // default, so nothing of ours is named anywhere. Leave it alone.
        assert_eq!(
            give_back_plan(Some(true), Some(SPEAKER), Some(SPEAKER), ours),
            GiveBackPlan::TheirChoice(SPEAKER.into())
        );

        // The one this discrimination exists for: our node died mid-session (a
        // PipeWire restart, a stream error) and WirePlumber elected a
        // fallback. The active default looks exactly like his choice — but the
        // CONFIGURED default still names our node, which his choice would have
        // rewritten. Restore, or `default.configured.audio.sink` is left
        // naming a sink that does not exist, across a reboot.
        assert_eq!(
            give_back_plan(Some(true), Some(SPEAKER), Some(ours), ours),
            GiveBackPlan::OursIsDead(SPEAKER.into())
        );

        // Unreadable is not "somebody else's", in either read.
        assert_eq!(give_back_plan(Some(true), None, None, ours), GiveBackPlan::Restore);
        assert_eq!(give_back_plan(None, Some(ours), None, ours), GiveBackPlan::Restore);
        assert_eq!(
            give_back_plan(None, Some(SPEAKER), Some(ours), ours),
            GiveBackPlan::OursIsDead(SPEAKER.into())
        );

        // Only a listing that really came back and really lacks it means the
        // sink to restore is gone. The rot is still ours if we are configured.
        assert_eq!(
            give_back_plan(Some(false), Some(SPEAKER), Some(ours), ours),
            GiveBackPlan::PreviousGone { rot_is_ours: true }
        );
        assert_eq!(
            give_back_plan(Some(false), Some(SPEAKER), Some(SPEAKER), ours),
            GiveBackPlan::PreviousGone { rot_is_ours: false }
        );
    }

    #[test]
    fn an_output_chosen_during_the_gate_window_is_never_taken() {
        let ours = "airplay-sink.frame";
        // `previous_default` is sampled at publish and used 3-4 seconds later.
        // If the user's Bluetooth headphones connected in that window, the output
        // is his choice of seconds ago — and the handover is refused rather
        // than taking that device too (`take_default` turns this `Some` into
        // `SinkError::OutputMoved`, takes nothing, and owes nothing).
        assert_eq!(
            output_moved_under_us(Some("bluez_output.AC_80_0A"), SPEAKER, ours),
            Some("bluez_output.AC_80_0A")
        );
        // Nothing moved.
        assert_eq!(output_moved_under_us(Some(SPEAKER), SPEAKER, ours), None);
        // Already ours (a stale configured default seized it at publish): not
        // a new choice of his, and treating it as one would refuse a handover
        // that has in fact already happened.
        assert_eq!(output_moved_under_us(Some(ours), SPEAKER, ours), None);
        // Unreadable: unknown is never a reason to act — neither to refuse nor
        // to re-point the restore.
        assert_eq!(output_moved_under_us(None, SPEAKER, ours), None);
    }

    #[test]
    fn an_unknown_monitor_is_not_pre_volume() {
        // Known pre-volume: the only answer that may take the sink path.
        assert!(pre_volume_verdict(Some(false)));
        // Known post-volume: capturing it would attenuate twice.
        assert!(!pre_volume_verdict(Some(true)));
        // Unknown — no pw-dump, or the node not in it yet. The guard exists to
        // refuse in exactly this case; answering "pre-volume" is failing open.
        assert!(!pre_volume_verdict(None));
    }

    #[test]
    fn the_claim_survives_anything_unsettled() {
        // `virtualoutput`'s rule, inherited: cleared only when known repaired
        // or known not ours.
        assert!(may_clear_claim(Given::Back));
        assert!(may_clear_claim(Given::NotOurs));
        assert!(!may_clear_claim(Given::Unsettled));

        // And every unsettled plan really does reach it: a failed restore, an
        // unconfirmable one, and our dead node still configured.
        assert!(!may_clear_claim(
            match give_back_plan(Some(false), Some(SPEAKER), Some("airplay-sink.frame"), "airplay-sink.frame") {
                GiveBackPlan::PreviousGone { rot_is_ours: true } => Given::Unsettled,
                other => panic!("{other:?}"),
            }
        ));
    }

    #[test]
    fn a_published_sink_is_never_created_by_a_pure_test() {
        // The counter the offline session tests assert on. Nothing in this
        // module's own unit tests may move it.
        assert_eq!(published_in_this_process(), 0);
    }

    #[test]
    fn channel_volume_of_reads_a_props_pod() {
        use pipewire::spa;
        let obj = spa::pod::Object {
            type_: spa::utils::SpaTypes::ObjectParamProps.as_raw(),
            id: spa::param::ParamType::Props.as_raw(),
            properties: vec![
                spa::pod::Property::new(libspa_sys::SPA_PROP_mute, spa::pod::Value::Bool(false)),
                spa::pod::Property::new(
                    SPA_PROP_CHANNEL_VOLUMES,
                    spa::pod::Value::ValueArray(spa::pod::ValueArray::Float(vec![0.125, 3.375])),
                ),
            ],
        };
        let bytes = spa::pod::serialize::PodSerializer::serialize(
            std::io::Cursor::new(Vec::new()),
            &spa::pod::Value::Object(obj),
        )
        .map(|(c, _)| c.into_inner())
        .expect("serialize");

        // The loudest channel, and a value well above 1.0 read as itself: a
        // remembered 3.375 is exactly the restore `seed_level` overwrites.
        assert_eq!(channel_volume_of(&bytes), Some(3.375));
        assert_eq!(channel_volume_of(&[]), None);
        assert_eq!(channel_volume_of(&[0u8; 8]), None);
    }

    #[test]
    fn display_label_is_what_the_user_sees() {
        assert_eq!(display_label("75\" The Frame"), "AirPlay: 75\" The Frame");
    }
}
