//! A Hyprland **headless output** used as an Extend desktop, removed again on
//! every exit path.
//!
//! Ported from `VirtualOutput` at `probe.py:863` in the omarchy-airplay-probe repo,
//! with the probe's two latent bugs fixed:
//!
//! * **Ownership comes from a state file, not from `created = not
//!   already_present`.** The probe decides at construction time whether it made
//!   the output, and keeps that answer only in memory; a crashed run therefore
//!   leaves a phantom monitor that nothing will ever remove. Here the claim is
//!   written to `$XDG_RUNTIME_DIR/airplay-rs/extend.json` *before* the output is
//!   created, so the next run can reclaim it.
//! * **The mode is confirmed by read-back, not by `time.sleep(0.5)`.** If
//!   capture binds while the output is still at its default mode, the whole
//!   pipeline is built at the wrong size and the receiver is told a resolution
//!   that is silently wrong. [`VirtualOutput::create`] polls
//!   `hyprctl monitors all -j` until the requested mode is actually reported,
//!   and fails (removing the output again) if it never is.
//!
//! Two rules are structural here, not advisory:
//!
//! 1. **An output this process did not create is never removed.** The selector
//!    is the name in our own state file; a headless-looking output we did not
//!    record is refused with [`VirtualOutputError::NameTaken`], never swept.
//! 2. **`hyprctl` reports failure on stdout with exit status 0.** `Name already
//!    taken`, `output not found` and `no such option` all exit 0. The only
//!    success test is [`check_ok`]: exit 0 *and* `stdout.trim() == "ok"`, and
//!    even that is confirmed by re-reading `monitors all -j`, because
//!    `hl.monitor` on a nonexistent output answers `ok` and does nothing.

use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

/// Every name this crate is willing to create or remove starts with this.
pub const NAME_PREFIX: &str = "AIRPLAY-";

/// How long the requested mode has to show up in `monitors all -j`.
const MODE_DEADLINE: Duration = Duration::from_millis(2000);
/// How long the pinned workspace has to show up as the output's active one.
/// Shorter than [`MODE_DEADLINE`] because missing it is only a warning: the
/// stream is already usable, and a run must not sit here for two seconds to
/// find out the number is untidy.
const WORKSPACE_DEADLINE: Duration = Duration::from_millis(1000);
/// Re-read interval while waiting for it.
const MODE_POLL: Duration = Duration::from_millis(50);
/// How long any one `hyprctl` invocation may take before it is SIGKILLed.
const HYPRCTL_DEADLINE: Duration = Duration::from_millis(1500);
/// Longest name we will accept, including the prefix.
const MAX_NAME_LEN: usize = 32;

// ===================================================================== errors

/// Everything that can go wrong creating, configuring or removing the output.
#[derive(Debug, thiserror::Error)]
pub enum VirtualOutputError {
    /// `hyprctl` is missing, or `HYPRLAND_INSTANCE_SIGNATURE` is unset (we are
    /// not running under Hyprland at all).
    #[error("no usable Hyprland here: {0}")]
    NoHyprland(String),
    /// Exit status was not 0, or stdout was not exactly `ok`. The verbatim
    /// stdout is carried because hyprctl's failures arrive *there*, with exit 0.
    #[error("hyprctl {cmd} failed (exit {code:?}): {stdout}")]
    Hyprctl { cmd: String, code: Option<i32>, stdout: String },
    /// hyprctl did not answer within [`HYPRCTL_DEADLINE`]; it was SIGKILLed.
    #[error("hyprctl {0} timed out (compositor wedged?)")]
    Timeout(String),
    /// Another `airplay --extend` holds the lock.
    #[error("{0}")]
    Busy(String),
    /// The name exists and is not ours, or is no longer headless. Never removed.
    #[error("{0}")]
    NameTaken(String),
    /// The output came up but never reported the requested mode.
    #[error("output {name} never reported {}x{} (last saw {got:?}); removed again", want.0, want.1)]
    ModeTimeout { name: String, want: (u32, u32), got: Option<(u32, u32, f64)> },
    /// The output came up but never took the workspace its name asks for.
    ///
    /// Constructed but deliberately **never returned** from [`VirtualOutput::create`]:
    /// it is formatted into a warning instead. A stream on the wrong workspace
    /// number is a cosmetic annoyance; refusing the run over it would cost the user
    /// the whole session, TV bring-up included, for a tidier integer.
    #[error("output {name} did not take workspace {want} (it is on {got:?}); streaming anyway")]
    WorkspaceNotTaken { name: String, want: u32, got: Option<i64> },
    /// All of workspaces 1-10 are in use, so there is no id left that the
    /// Omarchy bar can render. Refused **before** anything is created: no
    /// output, no workspace rule, no claim file, nothing to clean up.
    #[error(
        "all {BAR_MAX_WORKSPACE} workspaces the Omarchy bar can show are in use ({in_use}), so the \
         extend screen would have no button on the bar — close the windows on one workspace and \
         try again. (The bar only renders workspace ids 1-{BAR_MAX_WORKSPACE}; this is its limit, \
         not a fault here. `--extend AIRPLAY-NAME` overrides, at the cost of no bar button.)"
    )]
    NoFreeWorkspace { in_use: String },
    /// An explicit `--extend AIRPLAY-<N>` named a workspace that is currently
    /// in use. Refused **before** anything is created.
    ///
    /// Its own variant rather than a reuse of
    /// [`NoFreeWorkspace`](Self::NoFreeWorkspace): the cause is different (one
    /// named workspace is busy, not "the bar is full") and so is the remedy
    /// (use a bare `--extend`, or name a different id — not "close a
    /// workspace").
    ///
    /// The alternative was to carry on without a rule and let Hyprland choose,
    /// which is what this did before. That is not the safe option it looks
    /// like: Hyprland remembers per monitor *name* which workspace that name
    /// last displayed and restores the pairing when the name reappears, so an
    /// unpinned create can drag one of the user's occupied workspaces — windows and
    /// all — onto the television. A hand-typed flag silently relocating his
    /// windows is a bad surprise, and the bare `--extend` that people actually
    /// use always pins a free id, so nothing is lost by refusing here.
    #[error(
        "workspace {id} is already in use, so {name} cannot claim it — pinning it would carry \
         those windows onto the TV. Use a bare `--extend`, which picks a free workspace \
         automatically, or name one that is free."
    )]
    WorkspaceInUse { name: String, id: u32 },
    #[error("bad virtual output name {0:?} (want `{NAME_PREFIX}…`, [A-Za-z0-9._-], 1-32 chars)")]
    BadName(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not parse hyprctl json: {0}")]
    Json(String),
}

// ==================================================================== monitors

/// The `activeWorkspace` / `specialWorkspace` sub-object of a `monitors` row.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct WorkspaceRef {
    pub id: i64,
    pub name: String,
}

/// One row of `hyprctl monitors all -j`, with only the fields we act on.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Monitor {
    pub id: i64,
    pub name: String,
    pub width: u32,
    pub height: u32,
    #[serde(rename = "refreshRate")]
    pub refresh_hz: f64,
    pub scale: f64,
    pub x: i32,
    pub y: i32,
    #[serde(rename = "physicalWidth")]
    pub physical_width: i32,
    #[serde(rename = "physicalHeight")]
    pub physical_height: i32,
    pub description: String,
    pub make: String,
    pub serial: String,
    pub focused: bool,
    /// The workspace this monitor is currently showing.
    ///
    /// `Option` because it is the one field here that is only *read back*, not
    /// acted on: `#[serde(default)]` keeps every older fixture and any future
    /// `monitors` row that omits it parsing, rather than turning a missing
    /// cosmetic field into a hard `Json` error on the path that creates the
    /// output.
    #[serde(rename = "activeWorkspace", default)]
    pub active_workspace: Option<WorkspaceRef>,
}

// ================================================================ pure helpers

/// Parse `hyprctl monitors all -j`.
pub fn parse_monitors(json: &str) -> Result<Vec<Monitor>, VirtualOutputError> {
    serde_json::from_str(json).map_err(|e| VirtualOutputError::Json(e.to_string()))
}

/// Find a monitor by exact name.
pub fn find<'a>(ms: &'a [Monitor], name: &str) -> Option<&'a Monitor> {
    ms.iter().find(|m| m.name == name)
}

/// Is this a headless output?
///
/// A **veto**, not a selector: a headless output reports no physical size and
/// no EDID strings at all, where a real panel (`eDP-1`: 300x190 mm, make
/// `AU Optronics`) reports at least some of them. All five must hold, so a real
/// monitor with a blank serial — `eDP-1` on this machine has exactly that — is
/// still correctly rejected.
pub fn is_headless(m: &Monitor) -> bool {
    m.physical_width == 0
        && m.physical_height == 0
        && m.description.is_empty()
        && m.make.is_empty()
        && m.serial.is_empty()
}

// ============================================================== workspace pick
//
// Hyprland assigns a brand-new output the LOWEST FREE workspace id, so on the user's
// sparse set (1, 2, 4, 6) the TV used to land on 3 — wedged into the middle of
// his workspaces rather than appended after them, which is what makes the bar's
// screen selector ambiguous. The fix is to pick the id ourselves and pin it with
// a workspace rule applied *before* `output create`.
//
// Three facts bound the choice, and all of them are load-bearing:
//
// 1. **A workspace rule persists for Hyprland's whole uptime and cannot be
//    cleared.** `hl.workspace_rule({workspace = "7", monitor = ""})` answers
//    `ok` and does nothing, so a *fixed* output name is a trap: the first
//    session's rule wins for every later one, and a second run asking for 9
//    still gets 7. Naming the output after its workspace — `AIRPLAY-<N>` — makes
//    a different number a different monitor name and therefore a fresh, unused
//    rule. That is why the name is derived from the id and not the other way
//    round, and why [`workspace_for_name`] can recover it.
// 2. **Omarchy's bar renders ids 1-5 ALWAYS, and 6-10 only when live.**
//    `/usr/share/omarchy/shell/plugins/bar/widgets/Workspaces.qml` builds its
//    model as `var ids = [1, 2, 3, 4, 5]` plus, for every live workspace,
//    `if (id > 0 && id <= 10 && ids.indexOf(id) === -1) ids.push(id)`, then
//    sorts ascending.
// 3. **11 and up are silently dropped** by that same filter. An invisible
//    button is strictly worse than the mid-set wedging we are fixing, so the
//    ceiling is handled explicitly rather than walked off the end of.
//
// Fact 2 is why the rule is not simply `max + 1`. With workspaces {1, 2, 4},
// `max + 1` is 5 — and 5 is one of the five buttons the bar draws whether or
// not anyone uses it, so taking it appends *nothing*: it consumes one of the user's
// five permanent slots and leaves the TV inside the default range instead of
// after it. The append has to clear the defaults as well as his live set, which
// is what `max(highest, 5) + 1` in [`next_workspace_id`] does.
//
// The ascending sort is what makes this an *append*: a higher id renders to the
// right of everything else, which is exactly what the user asked for.

/// The highest workspace id Omarchy's bar will render. See fact 3 above.
///
/// The widget labels its buttons `String(modelData)` — the **id**, never the
/// workspace name (10 is special-cased to `"0"`). Naming the workspace
/// `AirPlay` would therefore show nothing, so nothing here tries to.
pub const BAR_MAX_WORKSPACE: u32 = 10;

/// How many workspace buttons Omarchy's bar draws unconditionally: ids 1-5,
/// live or not (`var ids = [1, 2, 3, 4, 5]`). See fact 2 above.
///
/// An append has to get *past* these, not merely past what the user is using.
pub const BAR_DEFAULT_WORKSPACES: u32 = 5;

/// Will Omarchy's bar render a button for this workspace id?
pub fn bar_shows_workspace(id: u32) -> bool {
    (1..=BAR_MAX_WORKSPACE).contains(&id)
}

/// The id the append rule *wants*, before the [`BAR_MAX_WORKSPACE`] ceiling.
///
/// `max(highest live id, BAR_DEFAULT_WORKSPACES) + 1` — one past the greater of
/// what the user is using and the five buttons the bar always draws. Never `max + 1`
/// alone: on {1, 2, 4} that is 5, which is a permanent bar slot, so the TV would
/// sit *inside* the default range and append nothing.
///
/// Always `>= BAR_DEFAULT_WORKSPACES + 1`, and always greater than every live
/// id, so it is **free** by construction.
pub fn preferred_workspace_id(ids: &[i64]) -> u32 {
    let highest = ids.iter().copied().filter(|&i| i > 0).max().unwrap_or(0);
    // `i64 -> u32` cannot wrap: a positive `i64` past `u32::MAX` saturates, and
    // `saturating_add` keeps the increment in range too.
    u32::try_from(highest).unwrap_or(u32::MAX).max(BAR_DEFAULT_WORKSPACES).saturating_add(1)
}

/// Pick the workspace the Extend output should own, given every live id.
///
/// [`preferred_workspace_id`] when the bar can render it, which is the case that
/// matters: `{1,2,4} -> 6`, `{1,2,4,6} -> 7`, `{} -> 6`, `{1..=9} -> 10`. Not
/// "first free" (3 on the user's sparse set) and not `count + 1` (4) — both of those
/// put the TV *inside* his workspaces, and not bare `max + 1` either, which
/// lands on a default bar slot whenever his highest is below 5.
///
/// Above [`BAR_MAX_WORKSPACE`] the answer is instead the **highest free id in
/// `1..=10`**, so the TV still lands as far right as the bar can actually draw.
/// With `{1, 2, 10}` that is 9. This fallback may land at 5 or below — e.g.
/// `{6,7,8,9,10} -> 5` — which means 6-10 were all taken; visible-but-not-last
/// beats refusing, and callers compare against `preferred_workspace_id` to say
/// so out loud rather than leaving the user wondering.
///
/// `None` when `1..=10` are **all** occupied: there is no id left that both the
/// bar can render and the user is not already using, and the two ways out are both
/// worse than stopping. Picking 11 puts the TV on a workspace with no button on
/// the bar — the selector problem this whole change exists to fix, in a harsher
/// form. Reusing an occupied id points a workspace rule at a workspace holding
/// the user's windows. So the caller refuses the run instead, before anything is
/// created; [`VirtualOutputError::NoFreeWorkspace`] carries that decision.
///
/// Negative ids — Hyprland's special and named workspaces — are ignored, and an
/// empty input answers 6, because an empty set still has five default buttons.
///
/// Every `Some` is **free**, on both branches, which is what keeps the workspace
/// rule from ever capturing one of the user's workspaces.
pub fn next_workspace_id(ids: &[i64]) -> Option<u32> {
    let want = preferred_workspace_id(ids);
    if want <= BAR_MAX_WORKSPACE {
        return Some(want);
    }
    // Over the ceiling: the highest id the bar can draw that nobody holds.
    (1..=BAR_MAX_WORKSPACE).rev().find(|&c| !ids.iter().any(|&i| i == i64::from(c)))
}

/// The output name for a workspace: `AIRPLAY-<id>`.
///
/// The name *is* the workspace request — see fact 1 in the note above — so this
/// and [`workspace_for_name`] are two directions of one mapping and must stay
/// exact inverses.
pub fn name_for_workspace(id: u32) -> String {
    format!("{NAME_PREFIX}{id}")
}

/// The workspace an output name asks for, or `None` if it asks for none.
///
/// Exactly the inverse of [`name_for_workspace`]: the round trip must reproduce
/// the name byte for byte, so `AIRPLAY-tv` (no digits) and `AIRPLAY-007`
/// (`name_for_workspace(7)` is `AIRPLAY-7`, not `AIRPLAY-007`) both answer
/// `None`. Those names then get today's behaviour — no rule, Hyprland picks —
/// rather than a rule built from a number the name does not actually spell.
pub fn workspace_for_name(name: &str) -> Option<u32> {
    let id: u32 = name.strip_prefix(NAME_PREFIX)?.parse().ok()?;
    (id >= 1 && name_for_workspace(id) == name).then_some(id)
}

/// The Lua one-liner that pins a workspace to an output, applied **before**
/// `output create` so the output comes up already owning it.
///
/// `hyprctl keyword` is dead in Hyprland 0.56 ("keyword can't work with
/// non-legacy parsers. Use eval."), so this goes through `hyprctl eval` like
/// [`monitor_eval`]. `default = true` is what makes the output adopt the
/// workspace on arrival instead of merely preferring it later.
pub fn workspace_rule_eval(id: u32, name: &str) -> String {
    format!(
        "hl.workspace_rule({{ workspace = \"{id}\", monitor = \"{name}\", default = true }})"
    )
}

/// One row of `hyprctl workspaces -j`: the id, and the output showing it.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Workspace {
    pub id: i64,
    #[serde(default)]
    pub monitor: String,
}

/// Parse `hyprctl workspaces -j`.
pub fn parse_workspaces(json: &str) -> Result<Vec<Workspace>, VirtualOutputError> {
    serde_json::from_str(json).map_err(|e| VirtualOutputError::Json(e.to_string()))
}

/// Every workspace id in `hyprctl workspaces -j`.
pub fn parse_workspace_ids(json: &str) -> Result<Vec<i64>, VirtualOutputError> {
    Ok(parse_workspaces(json)?.into_iter().map(|w| w.id).collect())
}

/// The ids to treat as in use, given the live set and our own claim.
///
/// A workspace held by the output our **own** claim names belongs to a crashed
/// run, and `VirtualOutput::create`'s reclaim sweep is about to remove that
/// output — so counting it would make the restart append *past its own phantom*,
/// landing on 8 where 7 is about to come free. Two things follow from excluding
/// it, and the second matters more: the restart lands on the same number it had
/// before the crash, and it therefore reuses that workspace rule instead of
/// stranding a new one. Rules cannot be cleared for Hyprland's uptime, so
/// "crash, restart, crash, restart" must not accumulate one per attempt.
///
/// Only *our* claim, and only for *this* compositor: an output another tool
/// created, or one from a dead Hyprland, is somebody else's and is left in the
/// count.
fn ids_in_use(ws: &[Workspace]) -> Vec<i64> {
    let ours = state::read().filter(|c| Some(&c.instance) == instance().ok().as_ref()).map(|c| c.name);
    ws.iter()
        .filter(|w| ours.as_deref() != Some(w.monitor.as_str()))
        .map(|w| w.id)
        .collect()
}

/// `"1920x1080@60"`, the spelling `hl.monitor`'s `mode` field wants.
pub fn mode_string(size: (u32, u32), fps: u32) -> String {
    format!("{}x{}@{}", size.0, size.1, fps)
}

/// The Lua one-liner handed to `hyprctl eval`. Byte-identical to the probe's
/// rendering at `probe.py:872-874`.
pub fn monitor_eval(name: &str, size: (u32, u32), fps: u32) -> String {
    format!(
        "hl.monitor({{ output = \"{name}\", mode = \"{}\", position = \"auto-right\", scale = 1 }})",
        mode_string(size, fps)
    )
}

/// The only success test for a state-changing `hyprctl` call.
///
/// Exit 0 on its own proves nothing: `hyprctl` answers `Name already taken`,
/// `output not found` and `no such option` on **stdout** and still exits 0.
pub fn check_ok(code: Option<i32>, stdout: &str) -> Result<(), String> {
    if code == Some(0) && stdout.trim() == "ok" {
        Ok(())
    } else {
        Err(stdout.to_string())
    }
}

/// Accept only names this crate is allowed to create *and* remove.
///
/// The name is interpolated into a Lua string literal in [`monitor_eval`] and
/// into an argv, so quotes, shell metacharacters and path separators are
/// refused outright. The `AIRPLAY-` prefix is what keeps `eDP-1` — the user's actual
/// laptop panel — permanently out of reach of every code path in this module.
pub fn validate_name(name: &str) -> Result<(), VirtualOutputError> {
    let bad = || VirtualOutputError::BadName(name.to_string());
    if !name.starts_with(NAME_PREFIX) || name.len() <= NAME_PREFIX.len() || name.len() > MAX_NAME_LEN
    {
        return Err(bad());
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
        return Err(bad());
    }
    Ok(())
}

/// The size to create the Extend output at.
///
/// Not the receiver's raw display size: the fixed point of
/// [`crate::encoder::fit_source_to_receiver`] against itself. The fit is
/// idempotent, so creating here makes the *created* size equal the *coded*
/// size for every receiver — the compositor renders exactly what is encoded,
/// with no silent downscale in between. On this Frame (1920x1080) it is a
/// genuine 1:1 passthrough and no wire bytes move.
pub fn extend_mode(display: (u32, u32)) -> (u32, u32) {
    crate::encoder::fit_source_to_receiver(display, display)
}

// =============================================================== hyprctl runner

/// Run `hyprctl <args>` with a hard deadline, returning raw stdout.
///
/// `std::process::Command` has no timeout and a wedged compositor must not park
/// the caller once the NTP and event threads are live — the same reason
/// `bounded_roundtrip` exists in `capture.rs`. The child is moved into a
/// short-lived thread so `wait_with_output` drains both pipes (the `monitors`
/// JSON is well past the 64 KiB pipe buffer once a few outputs exist), and the
/// pid is taken *before* the move so the timeout path can still kill it.
fn hyprctl(args: &[&str], deadline: Duration) -> Result<String, VirtualOutputError> {
    use std::process::{Command, Stdio};

    let label = args.join(" ");
    let child = Command::new("hyprctl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VirtualOutputError::NoHyprland("`hyprctl` is not on PATH".into())
            } else {
                VirtualOutputError::Io(e)
            }
        })?;
    let pid = child.id();
    // A pidfd *pins* the child: a signal sent through it can only ever reach
    // the process we spawned. The plain `kill(pid, …)` below cannot promise
    // that, because `wait_with_output` reaps the child a moment *before* it
    // sends, so a deadline landing in that gap would signal a pid the kernel
    // has already freed. Taken here, before the waiting thread exists, so the
    // child is certainly still unreaped at this point.
    // SAFETY: a plain syscall with an owned pid and no pointer arguments.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as i32;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });

    let r = match rx.recv_timeout(deadline) {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            if out.status.success() {
                Ok(stdout)
            } else {
                Err(VirtualOutputError::Hyprctl {
                    cmd: label,
                    code: out.status.code(),
                    stdout: if stdout.trim().is_empty() {
                        String::from_utf8_lossy(&out.stderr).into_owned()
                    } else {
                        stdout
                    },
                })
            }
        }
        Ok(Err(e)) => Err(VirtualOutputError::Io(e)),
        Err(_) => {
            if pidfd >= 0 {
                // SAFETY: `pidfd` is ours and still open here, and a null
                // `siginfo` means "as if from kill(2)". The child may already
                // have been reaped, in which case this is a harmless ESRCH —
                // it cannot reach anything else.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd,
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
            } else {
                // No pidfd (ancient kernel, or seccomp): fall back to the
                // best-effort kill. A wedged compositor leaves `hyprctl`
                // blocked on its socket and `create` makes dozens of calls, so
                // not killing at all would leak a process and a thread each.
                // SAFETY: a plain syscall with no pointer arguments.
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
            Err(VirtualOutputError::Timeout(label))
        }
    };
    if pidfd >= 0 {
        // SAFETY: our own fd, not used again.
        unsafe { libc::close(pidfd) };
    }
    r
}

/// `hyprctl` for a call whose stdout must be exactly `ok`.
fn hyprctl_ok(args: &[&str]) -> Result<(), VirtualOutputError> {
    let label = args.join(" ");
    let stdout = hyprctl(args, HYPRCTL_DEADLINE)?;
    check_ok(Some(0), &stdout).map_err(|s| VirtualOutputError::Hyprctl {
        cmd: label,
        code: Some(0),
        stdout: s,
    })
}

/// Read and parse the full monitor set.
pub fn monitors() -> Result<Vec<Monitor>, VirtualOutputError> {
    parse_monitors(&hyprctl(&["monitors", "all", "-j"], HYPRCTL_DEADLINE)?)
}

/// Every live workspace id, from `hyprctl workspaces -j`, minus any held by a
/// phantom output of our own that is about to be reclaimed. See [`ids_in_use`].
pub fn workspace_ids() -> Result<Vec<i64>, VirtualOutputError> {
    Ok(ids_in_use(&parse_workspaces(&hyprctl(&["workspaces", "-j"], HYPRCTL_DEADLINE)?)?))
}

/// Render [`NoFreeWorkspace`](VirtualOutputError::NoFreeWorkspace) for a set of
/// live ids, so the message names the workspaces that are actually in the way.
fn no_free_workspace(ids: &[i64]) -> VirtualOutputError {
    let mut live: Vec<i64> = ids.iter().copied().filter(|&i| i > 0).collect();
    live.sort_unstable();
    live.dedup();
    VirtualOutputError::NoFreeWorkspace {
        in_use: live.iter().map(i64::to_string).collect::<Vec<_>>().join(", "),
    }
}

/// Read-only: could this name's workspace be placed right now?
///
/// Exactly the one hard error `VirtualOutput::create`'s pin step can raise, and
/// nothing else — so a run that would die on [`NoFreeWorkspace`] can be refused
/// at the keyboard rather than after the TV has been woken and a session
/// negotiated. Deliberately **permissive** about everything create merely warns
/// on (an occupied id, an unreadable workspace list): nothing here may refuse a
/// run create would have accepted.
///
/// [`NoFreeWorkspace`]: VirtualOutputError::NoFreeWorkspace
/// [`WorkspaceInUse`]: VirtualOutputError::WorkspaceInUse
pub fn preflight_workspace(name: &str) -> Result<(), VirtualOutputError> {
    let Some(id) = workspace_for_name(name) else { return Ok(()) };
    // Unreadable list: say nothing and let `create` deal with it. Refusing on a
    // failed *read* would turn a transient hyprctl hiccup into a dead run.
    let Ok(ids) = workspace_ids() else { return Ok(()) };
    if ids.contains(&i64::from(id)) {
        return Err(VirtualOutputError::WorkspaceInUse { name: name.to_string(), id });
    }
    Ok(())
}

/// Where a bare `--extend` should go, and how it got there.
#[derive(Debug, Clone, PartialEq)]
pub struct Appended {
    /// The output name to create: `AIRPLAY-<workspace>`.
    pub name: String,
    /// The workspace it will ask to own.
    pub workspace: u32,
    /// True when the [`BAR_MAX_WORKSPACE`] ceiling forced the pick down to one
    /// of the bar's five always-drawn slots, which means 6-10 were **all** in
    /// use. The TV is still visible but is no longer at the end of the bar, so
    /// the caller says so rather than leaving the user to wonder why.
    pub squeezed: bool,
}

/// Where a bare `--extend` should go: `AIRPLAY-<next workspace>`.
///
/// Resolved against the live compositor exactly **once** per run — the name is
/// the workspace request, so two calls that disagreed would create an output
/// under one name and capture another.
pub fn append() -> Result<Appended, VirtualOutputError> {
    let ids = workspace_ids()?;
    match next_workspace_id(&ids) {
        Some(workspace) => Ok(Appended {
            name: name_for_workspace(workspace),
            workspace,
            // The preferred id is always past the defaults, so anything at or
            // below them can only be the ceiling fallback.
            squeezed: workspace <= BAR_DEFAULT_WORKSPACES,
        }),
        None => Err(no_free_workspace(&ids)),
    }
}

fn instance() -> Result<String, VirtualOutputError> {
    std::env::var("HYPRLAND_INSTANCE_SIGNATURE").map_err(|_| {
        VirtualOutputError::NoHyprland("HYPRLAND_INSTANCE_SIGNATURE is not set".into())
    })
}

/// `hyprctl` present, running under Hyprland, and `monitors all -j` parses.
///
/// Called before pairing so `--extend` fails at the keyboard rather than after
/// the TV has already been woken and a session negotiated.
pub fn preflight() -> Result<(), VirtualOutputError> {
    instance()?;
    monitors()?;
    Ok(())
}

// ============================================================ ownership state

/// Where the claim and the lock live, and what they say.
///
/// Deliberately **not** the credentials directory (`$XDG_CONFIG_HOME`): the
/// runtime dir is wiped on logout, so a record can never outlive the Hyprland
/// instance it refers to and be mistaken for a live claim.
pub mod state {
    use super::*;

    /// What a running (or crashed) `airplay --extend` recorded about itself.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Claim {
        pub name: String,
        /// `$HYPRLAND_INSTANCE_SIGNATURE` at the time of writing. A claim from a
        /// different instance refers to a compositor that is gone; its outputs
        /// went with it, so nothing may be removed on its say-so.
        pub instance: String,
        pub pid: u32,
        pub created_unix: u64,
        /// The workspace this run asked the output to own, for readers that
        /// should not have to parse `name`. `null` when the name spells no
        /// workspace (an explicit `--extend AIRPLAY-tv`), which is *unknown*,
        /// not invalid.
        ///
        /// `#[serde(default)]` is the compatibility contract in both
        /// directions. An older binary's claim file has no `workspace` key and
        /// must still deserialize: [`read`] treats a claim that fails to parse
        /// as *no claim at all*, so without the default, a run from the
        /// previous build would become unreclaimable and leave the user a phantom
        /// monitor. It is additive for readers too — the Omarchy bar widget
        /// reads this file, and anything that does not know the key is
        /// unaffected by it.
        #[serde(default)]
        pub workspace: Option<u32>,
    }

    /// `$AIRPLAY_RS_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/airplay-rs`, else
    /// `/run/user/<uid>/airplay-rs`, else `<tmp>/airplay-rs`.
    pub fn dir() -> PathBuf {
        if let Ok(d) = std::env::var("AIRPLAY_RS_RUNTIME_DIR") {
            if !d.is_empty() {
                return PathBuf::from(d);
            }
        }
        if let Ok(d) = std::env::var("XDG_RUNTIME_DIR") {
            if !d.is_empty() {
                return PathBuf::from(d).join("airplay-rs");
            }
        }
        // SAFETY: getuid is always successful and has no preconditions.
        let uid = unsafe { libc::getuid() };
        let run = PathBuf::from(format!("/run/user/{uid}"));
        if run.is_dir() {
            return run.join("airplay-rs");
        }
        std::env::temp_dir().join("airplay-rs")
    }

    pub fn path() -> PathBuf {
        dir().join("extend.json")
    }

    pub fn lock_path() -> PathBuf {
        dir().join("extend.lock")
    }

    /// Write the claim and `fsync` it: it has to survive a SIGKILL that lands
    /// microseconds later, which is the entire point of writing it at all.
    pub fn write(c: &Claim) -> std::io::Result<()> {
        std::fs::create_dir_all(dir())?;
        let json = serde_json::to_vec_pretty(c).map_err(std::io::Error::other)?;
        let mut f = File::create(path())?;
        f.write_all(&json)?;
        f.sync_all()
    }

    /// `None` when absent, unreadable or corrupt — all of which mean "no claim".
    pub fn read() -> Option<Claim> {
        let bytes = std::fs::read(path()).ok()?;
        serde_json::from_slice(&bytes).ok()
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

    /// Serialises every test that redirects `AIRPLAY_RS_RUNTIME_DIR`.
    ///
    /// Lives here, not in one module's test block, because the variable is
    /// process-wide and [`crate::sessionstate`]'s tests redirect the very same
    /// directory: two private locks would not exclude each other and the tests
    /// would trip over one another's scratch dirs under `cargo test`'s default
    /// parallelism.
    #[cfg(test)]
    pub(crate) fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
}

use state::Claim;

/// `flock(LOCK_EX|LOCK_NB)` held for the whole run.
///
/// The kernel releases it when the fd closes — including on SIGKILL, where no
/// destructor runs — so it is both the "only one `--extend` at a time" gate and
/// the thing that makes the reclaim sweep safe: if the lock can be taken, no
/// live process owns the recorded output.
struct OwnerLock {
    _file: File,
}

impl OwnerLock {
    fn acquire() -> Result<Self, VirtualOutputError> {
        std::fs::create_dir_all(state::dir())?;
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
                Some(libc::EWOULDBLOCK) => Err(VirtualOutputError::Busy(
                    "another `airplay --extend` is running; see `airplay extend --status`".into(),
                )),
                _ => Err(VirtualOutputError::Io(e)),
            };
        }
        Ok(OwnerLock { _file: file })
    }

    /// Is someone else holding it right now? Read-only; used by `status`.
    ///
    /// Probes with `LOCK_SH`, which an exclusive holder still blocks but which
    /// does not itself lock anyone out, and opens the file without `create`.
    /// An `acquire()` here would take the real exclusive lock for the length of
    /// the probe, and a `--extend` calling [`Self::acquire`] inside that window
    /// fails the whole run with `Busy` — after the TV has already been woken
    /// and the session negotiated. `status` changes nothing, lock included.
    fn held_elsewhere() -> bool {
        let Ok(file) = std::fs::OpenOptions::new().read(true).open(state::lock_path()) else {
            return false; // no lock file at all: nobody has ever held it
        };
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        // SAFETY: `file` owns the fd for the duration of both calls.
        let rc = unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) };
        if rc == 0 {
            // SAFETY: as above; released explicitly rather than relying on the
            // close, so the fd's lifetime is not load-bearing.
            unsafe { libc::flock(fd, libc::LOCK_UN) };
            return false;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
    }
}

// =============================================================== the guard

/// A live headless output **this process owns**. Removed on [`Self::remove`] or
/// on `Drop`, whichever comes first.
pub struct VirtualOutput {
    name: String,
    size: (u32, u32),
    fps: u32,
    /// The workspace the output was *confirmed* to own, by read-back. `None`
    /// when the name spells no workspace, when the id was already in use, or
    /// when the pin was applied but never landed — so this is what actually
    /// happened, never what was asked for.
    workspace: Option<u32>,
    /// Cleared once the output has been removed, so `remove()` followed by the
    /// implicit `Drop` does not try twice.
    armed: bool,
    _lock: OwnerLock,
}

impl std::fmt::Debug for VirtualOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualOutput")
            .field("name", &self.name)
            .field("size", &self.size)
            .field("fps", &self.fps)
            .field("workspace", &self.workspace)
            .field("armed", &self.armed)
            .finish()
    }
}

impl VirtualOutput {
    /// Reclaim any phantom we recorded, then create and configure the output.
    ///
    /// Ordering matters at three points and all of them are load-bearing:
    ///
    /// * the claim is written **before** `output create`, so a crash in the gap
    ///   leaves a harmless stale record rather than an unrecorded phantom;
    /// * the workspace rule is applied **before** `output create`, because that
    ///   is the only moment it takes effect — the output has to come up already
    ///   owning the workspace. Afterwards there is no way to move it: on an
    ///   unfocused, empty workspace `hl.dsp.workspace.change_id` answers `ok`
    ///   and does nothing, and `hl.dsp.workspace.move` acts on whatever is
    ///   *focused*, which is one stray focus change away from dragging one of
    ///   the user's workspaces onto the TV;
    /// * the mode is confirmed by polling the compositor, not by sleeping, so
    ///   the capture can never bind at the default mode. The workspace is
    ///   confirmed the same way, but only *warns* — see below.
    pub fn create(name: &str, size: (u32, u32), fps: u32) -> Result<Self, VirtualOutputError> {
        validate_name(name)?;
        let inst = instance()?;
        let lock = OwnerLock::acquire()?;

        // --- reclaim, under the lock we now hold.
        reclaim_locked(&inst)?;

        // --- Hard Rule 2 gate. An output we did not record is never removed,
        //     by any path, for any reason.
        let ms = monitors()?;
        if let Some(m) = find(&ms, name) {
            return Err(VirtualOutputError::NameTaken(format!(
                "output {name} already exists ({}x{}, headless={}) and was not created by this \
                 process; refusing to touch it",
                m.width,
                m.height,
                is_headless(m)
            )));
        }

        // --- Which workspace, if any, does this name ask for?
        //
        // Re-decided here rather than trusted from the caller: `append_name`
        // ran before pairing and before the TV was woken, and the user may well have
        // opened or closed a workspace in between. This is the authoritative
        // check, under the lock.
        let want_ws = Self::pin_target(name)?;
        if let Some(id) = want_ws {
            // Inert until a monitor by this name appears, so it creates nothing
            // and there is nothing to undo if the create below fails. (It does
            // persist for Hyprland's uptime and cannot be cleared — which is
            // exactly why the name encodes the id: a different number is a
            // different monitor name, hence a fresh rule, rather than the first
            // session's rule silently winning forever.)
            hyprctl_ok(&["eval", &workspace_rule_eval(id, name)])?;
        }

        state::write(&Claim {
            name: name.to_string(),
            instance: inst,
            pid: std::process::id(),
            created_unix: state::now_unix(),
            workspace: want_ws,
        })?;

        // A `hyprctl` that fails does not prove the compositor did nothing.
        // The timeout path SIGKILLs our *client*, which does not cancel a
        // request Hyprland may already have accepted, and a Ctrl-C at the
        // terminal reaches `hyprctl` too (`spawn` leaves it in our process
        // group), killing it mid-request with `code: None`. Both arrive here
        // as a "failed" create with the output possibly live, so ask the
        // compositor what actually happened instead of assuming.
        if let Err(e) = hyprctl_ok(&["output", "create", "headless", name]) {
            let uncertain = matches!(
                &e,
                VirtualOutputError::Timeout(_) | VirtualOutputError::Hyprctl { code: None, .. }
            );
            if !uncertain {
                // The compositor answered and refused (`Name already taken`),
                // or the client never reached it. Nothing of ours exists under
                // this name, and the claim must not outlive the attempt: it
                // would point a later sweep at an output we did not create.
                let _ = state::clear();
                return Err(e);
            }
            match monitors() {
                // It landed after all. The Hard Rule 2 gate above proved this
                // name was free moments ago and it is headless now, so it is
                // ours: adopt it into the guard and drop it, which removes it
                // again and applies the same claim policy as every other
                // teardown.
                Ok(ms) if find(&ms, name).is_some_and(is_headless) => {
                    drop(VirtualOutput {
                        name: name.to_string(),
                        size,
                        fps,
                        workspace: None,
                        armed: true,
                        _lock: lock,
                    });
                }
                // The compositor answered, and the name is either absent or no
                // longer a headless output of ours: nothing was created.
                Ok(_) => {
                    let _ = state::clear();
                }
                // We cannot tell. Keep the claim, so `airplay extend --cleanup`
                // and the next run's reclaim sweep can still find whatever is
                // up there.
                Err(_) => {}
            }
            return Err(e);
        }

        // From here on the output exists, so every failure must remove it again.
        let mut vo =
            VirtualOutput { name: name.to_string(), size, fps, workspace: None, armed: true, _lock: lock };

        // Every `?` from here on drops `vo`, which removes the output again —
        // that is the whole reason the guard is constructed before it is
        // configured rather than after.
        hyprctl_ok(&["eval", &monitor_eval(name, size, fps)])?;

        // `hl.monitor` answers `ok` even for an output that does not exist, so
        // the only proof the mode landed is the compositor reporting it. Never
        // validate against `availableModes`: it does not follow a mode change
        // on a headless output.
        let started = Instant::now();
        let mut got: Option<(u32, u32, f64)> = None;
        // "hyprctl did not answer" is not the same fact as "the output never
        // appeared", and reporting the second when the first happened points
        // the reader at the wrong thing entirely. `ModeTimeout` is kept for the
        // case the compositor actually answered.
        let mut last_err: Option<VirtualOutputError>;
        loop {
            match monitors() {
                Ok(ms) => {
                    last_err = None;
                    match find(&ms, name) {
                        Some(m) => {
                            got = Some((m.width, m.height, m.scale));
                            if m.width == size.0
                                && m.height == size.1
                                && (m.scale - 1.0).abs() < 1e-6
                            {
                                vo.size = (m.width, m.height);
                                vo.workspace = vo.confirm_workspace(want_ws);
                                return Ok(vo);
                            }
                        }
                        None => got = None,
                    }
                }
                Err(e) => last_err = Some(e),
            }
            if started.elapsed() >= MODE_DEADLINE {
                // `vo` drops here and removes the output.
                return Err(last_err.unwrap_or(VirtualOutputError::ModeTimeout {
                    name: name.to_string(),
                    want: size,
                    got,
                }));
            }
            std::thread::sleep(MODE_POLL);
        }
    }

    /// Which workspace, if any, may be pinned to `name` right now.
    ///
    /// The authoritative check, under the lock. Three outcomes:
    ///
    /// * `Ok(Some(id))` — pin `id`. The name spelled it and nobody holds it.
    ///   Above [`BAR_MAX_WORKSPACE`] it is still honoured, with a warning that
    ///   it gets no button on the bar: an explicit id that high is an escape
    ///   hatch and the user typed it, and an invisible button is a cosmetic
    ///   loss, not a destructive one.
    /// * `Err(WorkspaceInUse)` — the name spelled an **occupied** id. Refused;
    ///   see below.
    /// * `Ok(None)` — apply no rule and let Hyprland choose. Only two ways in
    ///   now: the name spells no workspace at all (`--extend AIRPLAY-tv`), or
    ///   `hyprctl workspaces -j` could not be read. Both warn, because this is
    ///   **not the safe outcome it looks like** — see the note on
    ///   [`VirtualOutputError::WorkspaceInUse`] for Hyprland's per-monitor-name
    ///   workspace memory, which can pull an occupied workspace onto the TV.
    ///   For the unreadable-list case a stream on an untidy workspace still
    ///   beats no stream, and a genuinely wedged compositor is about to make
    ///   itself obvious anyway.
    ///
    /// Refusing an occupied explicit id is the user's call, and it is the right one:
    /// the two alternatives were pinning it (which relocates his windows
    /// outright) and carrying on unpinned (which can relocate them via the name
    /// memory, silently). Reachable only by an explicit `--extend AIRPLAY-<N>`,
    /// because [`next_workspace_id`] returns a free id by construction — this
    /// re-read is what keeps that true if a workspace was opened between
    /// [`preflight_workspace`] and here.
    ///
    /// Every error here is raised before the rule and before `output create`,
    /// so nothing exists to undo.
    fn pin_target(name: &str) -> Result<Option<u32>, VirtualOutputError> {
        let Some(id) = workspace_for_name(name) else {
            eprintln!(
                "extend: WARNING — {name} names no workspace, so Hyprland chooses one. Its \
                 choice may be a workspace you are already using (it remembers which one this \
                 output name last displayed); it returns to your panel when the run ends. A \
                 bare `--extend` pins a free workspace instead."
            );
            return Ok(None);
        };
        let ids = match workspace_ids() {
            Ok(ids) => ids,
            Err(e) => {
                eprintln!(
                    "extend: WARNING — could not read workspaces ({e}); leaving the workspace \
                     to Hyprland, so {name} may not appear at the end of the bar — and may \
                     take over a workspace you are already using until the run ends"
                );
                return Ok(None);
            }
        };
        if ids.contains(&i64::from(id)) {
            // The branch that protects the user's windows, and the one place a
            // hand-typed name is refused rather than quietly reinterpreted.
            return Err(VirtualOutputError::WorkspaceInUse { name: name.to_string(), id });
        }
        if !bar_shows_workspace(id) {
            eprintln!(
                "extend: WARNING — workspace {id} is above {BAR_MAX_WORKSPACE}, which the \
                 Omarchy bar does not render; {name} will have no button on the bar"
            );
        }
        Ok(Some(id))
    }

    /// Read back the workspace the output actually came up on.
    ///
    /// Same discipline as the mode confirm — poll the compositor, never sleep
    /// and assume — but the outcome is a **warning, not a failure**. A stream on
    /// workspace 3 instead of 7 still mirrors, still takes a dragged window and
    /// still ends cleanly; failing here would throw away a working session, TV
    /// bring-up and pairing included, to protect a cosmetic number. So the
    /// return value is what *happened*: `Some(id)` only when the compositor
    /// itself reported it.
    fn confirm_workspace(&self, want: Option<u32>) -> Option<u32> {
        let want = want?;
        let started = Instant::now();
        let mut got: Option<i64> = None;
        loop {
            if let Ok(ms) = monitors() {
                got = find(&ms, &self.name).and_then(|m| m.active_workspace.as_ref()).map(|w| w.id);
                if got == Some(i64::from(want)) {
                    return Some(want);
                }
            }
            if started.elapsed() >= WORKSPACE_DEADLINE {
                eprintln!(
                    "extend: WARNING — {}",
                    VirtualOutputError::WorkspaceNotTaken {
                        name: self.name.clone(),
                        want,
                        got,
                    }
                );
                return None;
            }
            std::thread::sleep(MODE_POLL);
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The workspace the compositor confirmed this output owns, if any. Never
    /// the requested id — only a read-back one.
    pub fn workspace(&self) -> Option<u32> {
        self.workspace
    }

    /// The size the compositor actually reported, which is what the capture
    /// will hand the encoder.
    pub fn size(&self) -> (u32, u32) {
        self.size
    }

    pub fn fps(&self) -> u32 {
        self.fps
    }

    /// The capture source for this output — exactly the value `--output NAME`
    /// already yields, so nothing below `session.rs` needs to know Extend
    /// exists.
    pub fn source(&self) -> crate::capture::CaptureSource {
        crate::capture::CaptureSource::Output(self.name.clone())
    }

    /// How many windows are currently on this output.
    ///
    /// Read-only, best effort (0 if hyprctl cannot be reached), and used only
    /// for the teardown warning. We never *move* anything: `hl.dsp.window.move`
    /// acts on whatever is focused, which is one focus change away from
    /// throwing an unrelated window onto the TV.
    pub fn occupants(&self) -> usize {
        let Ok(ms) = monitors() else { return 0 };
        let Some(id) = find(&ms, &self.name).map(|m| m.id) else { return 0 };
        let Ok(json) = hyprctl(&["clients", "-j"], HYPRCTL_DEADLINE) else { return 0 };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else { return 0 };
        v.as_array()
            .map(|cs| {
                cs.iter().filter(|c| c.get("monitor").and_then(|m| m.as_i64()) == Some(id)).count()
            })
            .unwrap_or(0)
    }

    /// Explicit teardown, with a reportable error. Disarms `Drop`.
    ///
    /// Prefer this over letting the guard fall out of scope when the caller can
    /// actually *report* a failure — `Drop` can only print. An output that has
    /// already gone is success, not an error.
    pub fn remove(self) -> Result<(), VirtualOutputError> {
        self.remove_and_report().map(|_| ())
    }

    /// [`Self::remove`], keeping the distinction the caller needs to tell the
    /// truth: `Ok(true)` means *we* removed the output, `Ok(false)` that it had
    /// already gone (someone ran `hyprctl output remove` by hand, say). Both
    /// are success; only the first is a removal.
    pub fn remove_and_report(mut self) -> Result<bool, VirtualOutputError> {
        let r = self.teardown();
        // `armed` is cleared even when the teardown failed: `Drop` would re-run
        // `teardown()` microseconds later against the same wedged compositor
        // and print a second line over the caller's own report. What carries
        // the retry is the *claim*, to `airplay extend --cleanup` and to the
        // next run's reclaim sweep — by which time a wedged compositor has had
        // time to recover.
        self.armed = false;
        if teardown_settled(&r) {
            let _ = state::clear();
        }
        r
    }

    /// Re-verify, then remove. Shared by [`Self::remove`] and `Drop`.
    /// `Ok(true)` means we removed it; `Ok(false)` that it had already gone.
    ///
    /// The re-verification is Hard Rule 2 applied at the last possible moment:
    /// even a name we recorded is left alone if the live output under that name
    /// is no longer headless (i.e. something else now owns it).
    fn teardown(&mut self) -> Result<bool, VirtualOutputError> {
        let ms = monitors()?;
        match find(&ms, &self.name) {
            None => Ok(false), // already gone; nothing to do, not an error
            Some(m) if !is_headless(m) => Err(VirtualOutputError::NameTaken(format!(
                "output {} is no longer headless; left alone",
                self.name
            ))),
            Some(_) => hyprctl_ok(&["output", "remove", &self.name]).map(|()| true),
        }
    }
}

/// Does a teardown outcome prove the output is no longer ours to remove?
///
/// Only then may the claim be deleted. `Ok(_)` means the output is gone — we
/// removed it, or it had already gone — and `NameTaken` means the live output
/// under that name is not the headless one we recorded, so it was never ours
/// to sweep. Every other error (a timeout, a `hyprctl` that failed or whose
/// JSON would not parse) leaves the output quite possibly still up and still
/// ours, and the claim is the **only** record that authorises removing it
/// later: [`reclaim_locked`] returns early without it. Clearing it on that path
/// strands the output on the desktop with `airplay extend --cleanup` — the very
/// command the failure message recommends — reduced to "nothing to clean up".
fn teardown_settled(r: &Result<bool, VirtualOutputError>) -> bool {
    matches!(r, Ok(_) | Err(VirtualOutputError::NameTaken(_)))
}

impl Drop for VirtualOutput {
    /// Infallible, best effort, and **never panics**: a panic in `Drop` during
    /// an unwind aborts the process, which manufactures exactly the
    /// SIGKILL-shaped leak this guard exists to prevent.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let r = self.teardown();
        match &r {
            Ok(true) => eprintln!("extend: removed virtual output {}", self.name),
            Ok(false) => eprintln!("extend: virtual output {} was already gone", self.name),
            Err(VirtualOutputError::NameTaken(msg)) => eprintln!("extend: {msg}"),
            Err(e) => eprintln!(
                "extend: could not remove {}: {e} — run `airplay extend --cleanup`",
                self.name
            ),
        }
        // Only when the output is provably gone, or provably not ours. On any
        // other failure the claim stays on disk, which is what makes the
        // `--cleanup` the line above just recommended able to do anything.
        if teardown_settled(&r) {
            let _ = state::clear();
        }
    }
}

// ================================================================ reclaim sweep

/// Do the reclaim under an already-held [`OwnerLock`].
///
/// Returns the name removed, if any. The **selector is the state file**: only a
/// name we recorded ourselves, for *this* Hyprland instance, that is still
/// headless, is removed. A heuristic selector ("remove anything headless")
/// would happily sweep another tool's output.
fn reclaim_locked(inst: &str) -> Result<Option<String>, VirtualOutputError> {
    let Some(claim) = state::read() else { return Ok(None) };

    // The selector is a name out of a file, so it goes through the same gate a
    // name off the command line does before anything destructive is done with
    // it. `is_headless` alone keeps `eDP-1` safe, but only `validate_name` keeps
    // the `AIRPLAY-` guarantee: a corrupt, hand-edited or forward-version claim
    // naming another tool's headless output must not be swept.
    if validate_name(&claim.name).is_err() {
        let _ = state::clear();
        return Ok(None);
    }

    // A claim from a different compositor refers to outputs that died with it.
    // Clear the record and touch nothing: the names may well have been reused.
    if claim.instance != inst {
        let _ = state::clear();
        return Ok(None);
    }

    let removed = match find(&monitors()?, &claim.name) {
        // Our phantom: recorded by us, same instance, still headless.
        Some(m) if is_headless(m) => {
            hyprctl_ok(&["output", "remove", &claim.name])?;
            eprintln!(
                "extend: reclaimed orphaned output {} from pid {}",
                claim.name, claim.pid
            );
            Some(claim.name.clone())
        }
        // The name is live but is not a headless output any more, so it is not
        // the thing we recorded. Drop the stale record; remove nothing.
        Some(_) => None,
        // Stale record, output already gone.
        None => None,
    };
    let _ = state::clear();
    Ok(removed)
}

/// Remove a phantom this machine's state file claims, and return its name.
///
/// This is what `airplay extend --cleanup` runs — the escape hatch for a run
/// that was SIGKILLed, where no destructor got to run. It refuses while another
/// `--extend` holds the lock, because that process legitimately owns its
/// output.
pub fn reclaim_orphan() -> Result<Option<String>, VirtualOutputError> {
    let inst = instance()?;
    let _lock = OwnerLock::acquire()?;
    reclaim_locked(&inst)
}

// ===================================================================== status

/// A read-only picture of the Extend state, for `airplay extend --status`.
#[derive(Debug)]
pub struct Status {
    /// What the state file claims, if anything.
    pub claimed: Option<Claim>,
    /// That claimed name in `monitors all -j`, if it is live.
    pub live: Option<Monitor>,
    /// Is another `airplay --extend` running?
    pub lock_held_elsewhere: bool,
    /// The full monitor set, so the caller can print what the user would otherwise
    /// have to run `hyprctl monitors` for.
    pub monitors: Vec<Monitor>,
}

/// Read-only. Creates nothing, removes nothing.
pub fn status() -> Result<Status, VirtualOutputError> {
    instance()?;
    let monitors = monitors()?;
    let claimed = state::read();
    let live = claimed.as_ref().and_then(|c| find(&monitors, &c.name).cloned());
    Ok(Status {
        claimed,
        live,
        lock_held_elsewhere: OwnerLock::held_elsewhere(),
        monitors,
    })
}

// =============================================================== tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    /// Verbatim `hyprctl monitors all -j` with the Extend output up: `eDP-1`
    /// exactly as this machine reports it (note the **empty serial** on a real
    /// panel, which is why `is_headless` cannot key on serial alone), plus
    /// `AIRPLAY-1` as the spikes recorded it.
    const MONITORS_JSON: &str = r#"[{
        "id": 0,
        "name": "eDP-1",
        "description": "AU Optronics B140UAN02.7",
        "make": "AU Optronics",
        "model": "B140UAN02.7 ",
        "serial": "",
        "width": 1920,
        "height": 1200,
        "physicalWidth": 300,
        "physicalHeight": 190,
        "refreshRate": 60.00000,
        "x": 0,
        "y": 0,
        "scale": 1.5,
        "transform": 0,
        "focused": true,
        "dpmsStatus": true,
        "disabled": false,
        "currentFormat": "XRGB8888",
        "availableModes": ["1920x1200@60.00Hz"]
    },{
        "id": 1,
        "name": "AIRPLAY-1",
        "description": "",
        "make": "",
        "model": "",
        "serial": "",
        "width": 1920,
        "height": 1080,
        "physicalWidth": 0,
        "physicalHeight": 0,
        "refreshRate": 60.00000,
        "x": 1280,
        "y": 0,
        "scale": 1.0,
        "transform": 0,
        "focused": false,
        "dpmsStatus": true,
        "disabled": false,
        "currentFormat": "XRGB8888",
        "availableModes": [],
        "activeWorkspace": { "id": 7, "name": "7" }
    }]"#;

    /// `hyprctl workspaces -j` exactly as this machine reported it while the
    /// change was being written: **sparse** (1, 2, 4, 6) and not in id order,
    /// which is the whole reason `next_workspace_id` is `max + 1` rather than
    /// "first free" (3) or `count + 1` (5).
    const WORKSPACES_JSON: &str = r#"[
        {"id":1,"name":"1","monitor":"eDP-1","windows":1},
        {"id":4,"name":"4","monitor":"eDP-1","windows":1},
        {"id":6,"name":"6","monitor":"eDP-1","windows":1},
        {"id":2,"name":"2","monitor":"eDP-1","windows":1}
    ]"#;

    /// The state-file tests mutate a process-wide environment variable, so they
    /// take turns — with each other AND with `sessionstate`'s tests, which
    /// redirect the same directory, hence the shared lock in [`state`].
    fn env_guard() -> MutexGuard<'static, ()> {
        state::env_guard()
    }

    /// A scratch runtime dir, removed on drop. `tempfile` is not a dependency
    /// and this is not worth adding one for.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir()
                .join(format!("airplay-rs-test-{}-{tag}-{}", std::process::id(), state::now_unix()));
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

    /// A `hyprctl` on `PATH` that answers from files in a scratch dir, so the
    /// teardown paths can be driven — including the ones that *fail* — without
    /// going anywhere near the real compositor. `HYPRLAND_INSTANCE_SIGNATURE`
    /// is faked too, as a second net: nothing here can address a live Hyprland.
    struct FakeHyprctl {
        dir: PathBuf,
        saved_path: Option<String>,
        saved_sig: Option<String>,
    }

    impl FakeHyprctl {
        /// `before` answers the first `monitors all -j` (the Hard Rule 2 gate,
        /// which must not see the name yet); `after` answers every later one.
        fn new(dir: PathBuf, before: &str, after: &str) -> Self {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("before.json"), before).unwrap();
            std::fs::write(dir.join("after.json"), after).unwrap();
            // the user's real shape, and deliberately one where workspace 1 is
            // OCCUPIED: the `AIRPLAY-1` these tests use therefore takes the
            // "do not steal a live workspace" branch and gets no rule, which is
            // exactly the pre-change behaviour they were written against.
            // `set_workspaces` opts into the pinning path.
            std::fs::write(dir.join("workspaces.json"), WORKSPACES_JSON).unwrap();
            let script = r#"#!/bin/sh
d="$(dirname "$0")"
printf '%s\n' "$*" >> "$d/log"
die() { echo "Couldn't connect to the Hyprland socket" >&2; exit 1; }
if [ "$*" = "workspaces -j" ]; then
  if [ -f "$d/workspaces_fail" ]; then die; fi
  cat "$d/workspaces.json"
  exit 0
fi
if [ "$*" = "monitors all -j" ]; then
  n=$(cat "$d/n" 2>/dev/null || echo 0)
  n=$((n+1))
  echo "$n" > "$d/n"
  if [ -f "$d/monitors_fail" ]; then die; fi
  if [ -f "$d/fail_after" ] && [ "$n" -gt "$(cat "$d/fail_after")" ]; then die; fi
  if [ "$n" -le 1 ]; then cat "$d/before.json"; else cat "$d/after.json"; fi
  exit 0
fi
case "$*" in
  'output create'*)
    if [ -f "$d/create_signal" ]; then kill -INT $$; sleep 5; fi
    if [ -f "$d/create_refuse" ]; then echo 'Name already taken'; exit 0; fi
    ;;
esac
echo ok
"#;
            let bin = dir.join("hyprctl");
            std::fs::write(&bin, script).unwrap();
            let mut perm = std::fs::metadata(&bin).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
            std::fs::set_permissions(&bin, perm).unwrap();

            let saved_path = std::env::var("PATH").ok();
            let saved_sig = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok();
            std::env::set_var(
                "PATH",
                format!("{}:{}", dir.display(), saved_path.clone().unwrap_or_default()),
            );
            std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", "fake_test_instance");
            FakeHyprctl { dir, saved_path, saved_sig }
        }

        fn set_after(&self, json: &str) {
            std::fs::write(self.dir.join("after.json"), json).unwrap();
        }

        /// What `workspaces -j` answers, as a list of ids.
        fn set_workspaces(&self, ids: &[i64]) {
            let rows: Vec<String> = ids
                .iter()
                .map(|i| format!(r#"{{"id":{i},"name":"{i}","monitor":"eDP-1","windows":1}}"#))
                .collect();
            std::fs::write(self.dir.join("workspaces.json"), format!("[{}]", rows.join(",")))
                .unwrap();
        }

        /// Make `workspaces -j` unreachable, which must degrade to "no pin",
        /// never to a failed run.
        fn break_workspaces(&self, on: bool) {
            let p = self.dir.join("workspaces_fail");
            if on {
                std::fs::write(p, b"1").unwrap();
            } else {
                let _ = std::fs::remove_file(p);
            }
        }

        /// Re-arm the `before`/`after` split for another [`VirtualOutput::create`].
        fn rearm(&self, before: &str, after: &str) {
            let _ = std::fs::remove_file(self.dir.join("n"));
            std::fs::write(self.dir.join("before.json"), before).unwrap();
            self.set_after(after);
        }

        /// Make every later `monitors all -j` fail, which is how a wedged or
        /// unreachable compositor reaches `teardown()`.
        fn break_monitors(&self) {
            std::fs::write(self.dir.join("monitors_fail"), b"1").unwrap();
        }

        /// Answer the first `n` `monitors all -j` calls, then start failing —
        /// so the Hard Rule 2 gate can still be passed before the compositor
        /// becomes unreachable.
        fn break_monitors_after(&self, n: u32) {
            std::fs::write(self.dir.join("fail_after"), n.to_string()).unwrap();
        }

        fn heal_monitors(&self) {
            let _ = std::fs::remove_file(self.dir.join("monitors_fail"));
            let _ = std::fs::remove_file(self.dir.join("fail_after"));
        }

        /// Make `output create` die of SIGINT, the way a Ctrl-C at the terminal
        /// kills the `hyprctl` client mid-request (it is in our process group)
        /// while Hyprland goes on to make the output anyway.
        fn signal_create(&self, on: bool) {
            let p = self.dir.join("create_signal");
            if on {
                std::fs::write(p, b"1").unwrap();
            } else {
                let _ = std::fs::remove_file(p);
            }
        }

        /// Make `output create` fail the way the compositor itself refuses:
        /// answered, exit 0, failure text on stdout.
        fn refuse_create(&self, on: bool) {
            let p = self.dir.join("create_refuse");
            if on {
                std::fs::write(p, b"1").unwrap();
            } else {
                let _ = std::fs::remove_file(p);
            }
        }

        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        }

        fn clear_log(&self) {
            let _ = std::fs::remove_file(self.dir.join("log"));
        }
    }

    impl Drop for FakeHyprctl {
        fn drop(&mut self) {
            match self.saved_path.take() {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
            match self.saved_sig.take() {
                Some(s) => std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", s),
                None => std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"),
            }
        }
    }

    /// One `monitors all -j` row with the fields this module acts on.
    ///
    /// `activeWorkspace` is omitted deliberately, so the default-shaped rows
    /// keep proving that a `monitors` row without it still parses — the
    /// compatibility property `Monitor::active_workspace`'s `#[serde(default)]`
    /// exists for. [`monitor_json_on`] adds it where a test needs it.
    fn monitor_json(name: &str, w: u32, h: u32, headless: bool) -> String {
        let (pw, ph, desc, make) =
            if headless { (0, 0, "", "") } else { (300, 190, "AU Optronics B1", "AU Optronics") };
        format!(
            r#"{{"id":1,"name":"{name}","width":{w},"height":{h},"refreshRate":60.0,"scale":1.0,
               "x":0,"y":0,"physicalWidth":{pw},"physicalHeight":{ph},"description":"{desc}",
               "make":"{make}","serial":"","focused":false}}"#
        )
    }

    /// [`monitor_json`] plus the `activeWorkspace` sub-object, as the real
    /// `hyprctl` reports it.
    fn monitor_json_on(name: &str, w: u32, h: u32, headless: bool, ws: i64) -> String {
        let row = monitor_json(name, w, h, headless);
        format!(
            "{},\"activeWorkspace\":{{\"id\":{ws},\"name\":\"{ws}\"}}}}",
            row.trim_end_matches('}')
        )
    }

    fn panel_only() -> String {
        format!("[{}]", monitor_json("eDP-1", 1920, 1200, false))
    }

    fn panel_and(name: &str, headless: bool) -> String {
        format!(
            "[{},{}]",
            monitor_json("eDP-1", 1920, 1200, false),
            monitor_json(name, 1920, 1080, headless)
        )
    }

    /// `panel_and`, but the headless output reports the workspace it owns.
    fn panel_and_on(name: &str, ws: i64) -> String {
        format!(
            "[{},{}]",
            monitor_json("eDP-1", 1920, 1200, false),
            monitor_json_on(name, 1920, 1080, true, ws)
        )
    }

    #[test]
    fn only_a_settled_teardown_may_clear_the_claim() {
        // The whole rule in one place: the claim is the only record that
        // authorises removing the output later, so it survives every outcome
        // that does not prove the output is gone or not ours.
        assert!(teardown_settled(&Ok(true)), "we removed it: gone");
        assert!(teardown_settled(&Ok(false)), "it had already gone");
        assert!(
            teardown_settled(&Err(VirtualOutputError::NameTaken("x".into()))),
            "no longer headless: never ours to sweep"
        );
        for unknown in [
            VirtualOutputError::Timeout("monitors all -j".into()),
            VirtualOutputError::Hyprctl {
                cmd: "output remove AIRPLAY-1".into(),
                code: Some(0),
                stdout: "Shell is not responding".into(),
            },
            VirtualOutputError::Json("expected value".into()),
            VirtualOutputError::Io(std::io::Error::other("boom")),
        ] {
            assert!(
                !teardown_settled(&Err(unknown)),
                "an unknown teardown outcome must keep the claim"
            );
        }
    }

    #[test]
    fn a_failed_teardown_keeps_the_claim_so_cleanup_still_works() {
        let _g = env_guard();
        let s = Scratch::new("failteardown");
        let fake = FakeHyprctl::new(
            s.0.join("bin"),
            &panel_only(),
            &panel_and("AIRPLAY-1", true),
        );
        // This test is about the teardown/claim policy, not about workspaces.
        // Leave workspace 1 free so `AIRPLAY-1` pins cleanly instead of being
        // refused for naming an occupied one.
        fake.set_workspaces(&[2, 4, 6]);

        let vo = VirtualOutput::create("AIRPLAY-1", (1920, 1080), 60).expect("fake create");
        assert!(state::read().is_some(), "create records a claim");

        // The compositor stops answering. `teardown()` fails on its very first
        // line, so `output remove` is never even attempted and the output is
        // certainly still up.
        fake.break_monitors();
        let err = vo.remove_and_report().expect_err("teardown must fail");
        assert!(!teardown_settled(&Err(err)));
        assert!(
            !fake.log().contains("output remove"),
            "removal was never attempted:\n{}",
            fake.log()
        );
        let claim = state::read().expect("the claim must survive a failed teardown");
        assert_eq!(claim.name, "AIRPLAY-1");

        // ...which is what makes the `airplay extend --cleanup` the failure
        // message recommends able to do anything at all.
        fake.heal_monitors();
        assert_eq!(
            reclaim_locked("fake_test_instance").expect("sweep"),
            Some("AIRPLAY-1".to_string()),
            "the sweep must still find the output"
        );
        assert!(fake.log().contains("output remove AIRPLAY-1"), "{}", fake.log());
        assert!(state::read().is_none(), "a completed sweep clears the claim");

        // The same rule on the `Drop` path, which is where an erroring or
        // panicking run ends up, and which prints the `--cleanup` advice.
        fake.rearm(&panel_only(), &panel_and("AIRPLAY-1", true));
        let vo = VirtualOutput::create("AIRPLAY-1", (1920, 1080), 60).expect("fake create");
        fake.break_monitors();
        drop(vo);
        assert_eq!(
            state::read().map(|c| c.name).as_deref(),
            Some("AIRPLAY-1"),
            "a failed teardown in `Drop` keeps the claim too"
        );
    }

    #[test]
    fn a_settled_teardown_still_clears_the_claim() {
        let _g = env_guard();
        let s = Scratch::new("okteardown");
        let fake =
            FakeHyprctl::new(s.0.join("bin"), &panel_only(), &panel_and("AIRPLAY-1", true));
        fake.set_workspaces(&[2, 4, 6]); // workspace 1 free: see above

        // Removed by us.
        let vo = VirtualOutput::create("AIRPLAY-1", (1920, 1080), 60).expect("fake create");
        assert!(vo.remove_and_report().expect("teardown succeeds"), "we removed it");
        assert!(state::read().is_none(), "a successful teardown clears the claim");
        assert!(fake.log().contains("output remove AIRPLAY-1"));

        // Already gone: success, but not a removal — the distinction
        // `remove_and_report` exists to preserve.
        fake.rearm(&panel_only(), &panel_and("AIRPLAY-1", true));
        let vo = VirtualOutput::create("AIRPLAY-1", (1920, 1080), 60).expect("fake create");
        fake.set_after(&panel_only());
        assert!(!vo.remove_and_report().expect("already gone is success"), "we did not remove it");
        assert!(state::read().is_none(), "an output that is gone clears the claim");

        // No longer headless, so not the thing we recorded: left alone, and the
        // claim goes, because it was never ours to sweep.
        fake.rearm(&panel_only(), &panel_and("AIRPLAY-1", true));
        let vo = VirtualOutput::create("AIRPLAY-1", (1920, 1080), 60).expect("fake create");
        fake.set_after(&panel_and("AIRPLAY-1", false));
        let e = vo.remove_and_report().expect_err("a non-headless name is refused");
        assert!(matches!(e, VirtualOutputError::NameTaken(_)), "{e:?}");
        assert!(state::read().is_none(), "an output that is not ours clears the claim");
    }

    #[test]
    fn a_create_that_died_mid_request_does_not_leave_the_output_behind() {
        let _g = env_guard();
        let s = Scratch::new("createsignal");
        let fake =
            FakeHyprctl::new(s.0.join("bin"), &panel_only(), &panel_and("AIRPLAY-1", true));
        fake.set_workspaces(&[2, 4, 6]); // workspace 1 free: see above

        // The client dies of a signal, but the compositor made the output: the
        // failure says nothing about what Hyprland did, so we ask it.
        fake.signal_create(true);
        let e = VirtualOutput::create("AIRPLAY-1", (1920, 1080), 60).expect_err("create fails");
        assert!(matches!(e, VirtualOutputError::Hyprctl { code: None, .. }), "{e:?}");
        assert!(
            fake.log().contains("output remove AIRPLAY-1"),
            "the output it did create must be removed again:\n{}",
            fake.log()
        );
        assert!(state::read().is_none(), "nothing of ours is left, so nothing is claimed");

        // Same failure, but the compositor cannot be reached afterwards either:
        // we do not know what is up there, so the claim stays for the sweep.
        fake.rearm(&panel_only(), &panel_and("AIRPLAY-1", true));
        fake.clear_log();
        fake.break_monitors_after(1); // the gate answers; the probe after it does not
        let e = VirtualOutput::create("AIRPLAY-1", (1920, 1080), 60).expect_err("create fails");
        assert!(matches!(e, VirtualOutputError::Hyprctl { code: None, .. }), "{e:?}");
        assert_eq!(
            state::read().map(|c| c.name).as_deref(),
            Some("AIRPLAY-1"),
            "an unknown outcome keeps the claim so the sweep can find it"
        );
        fake.heal_monitors();
        fake.signal_create(false);

        // A clean refusal is different in kind: the compositor answered and
        // made nothing, so the claim must not outlive the attempt. (Start from
        // no claim, so the reclaim sweep does not consume the gate's answer.)
        state::clear().unwrap();
        fake.rearm(&panel_only(), &panel_and("AIRPLAY-1", true));
        fake.clear_log();
        fake.refuse_create(true);
        let e = VirtualOutput::create("AIRPLAY-1", (1920, 1080), 60).expect_err("create fails");
        assert!(matches!(e, VirtualOutputError::Hyprctl { code: Some(0), .. }), "{e:?}");
        assert!(
            !fake.log().contains("output remove"),
            "an output we did not create is never removed:\n{}",
            fake.log()
        );
        assert!(state::read().is_none(), "a refused create leaves no claim");
    }

    #[test]
    fn a_corrupt_claim_is_dropped_rather_than_swept() {
        let _g = env_guard();
        let s = Scratch::new("badname");
        let fake = FakeHyprctl::new(
            s.0.join("bin"),
            &panel_and("HEADLESS-1", true),
            &panel_and("HEADLESS-1", true),
        );

        // A claim naming an output this crate could never have created — the
        // shape a corrupt, hand-edited or forward-version state file has.
        state::write(&Claim {
            name: "HEADLESS-1".into(),
            instance: "fake_test_instance".into(),
            pid: 1,
            created_unix: 0,
            workspace: None,
        })
        .unwrap();

        assert_eq!(reclaim_locked("fake_test_instance").expect("sweep"), None);
        assert!(
            !fake.log().contains("output remove"),
            "another tool's output must not be touched:\n{}",
            fake.log()
        );
        assert!(state::read().is_none(), "the unusable record is dropped");
    }

    #[test]
    fn mode_string_matches_probe() {
        assert_eq!(mode_string((1920, 1080), 60), "1920x1080@60");
        assert_eq!(mode_string((1280, 720), 30), "1280x720@30");
    }

    #[test]
    fn monitor_eval_is_byte_identical_to_probe() {
        // probe.py:872-874, rendered for AIRPLAY-1 at 1920x1080@60.
        assert_eq!(
            monitor_eval("AIRPLAY-1", (1920, 1080), 60),
            r#"hl.monitor({ output = "AIRPLAY-1", mode = "1920x1080@60", position = "auto-right", scale = 1 })"#
        );
    }

    #[test]
    fn parse_monitors_reads_the_fields_we_act_on() {
        let ms = parse_monitors(MONITORS_JSON).expect("fixture parses");
        assert_eq!(ms.len(), 2);

        let panel = find(&ms, "eDP-1").expect("eDP-1 in fixture");
        assert_eq!(panel.id, 0);
        assert_eq!((panel.width, panel.height), (1920, 1200));
        assert_eq!(panel.scale, 1.5);
        assert_eq!(panel.refresh_hz, 60.0);
        assert_eq!((panel.physical_width, panel.physical_height), (300, 190));
        assert_eq!(panel.make, "AU Optronics");
        assert_eq!(panel.description, "AU Optronics B140UAN02.7");
        assert_eq!(panel.serial, "");
        assert!(panel.focused);

        let vo = find(&ms, "AIRPLAY-1").expect("AIRPLAY-1 in fixture");
        assert_eq!((vo.width, vo.height), (1920, 1080));
        assert_eq!(vo.scale, 1.0);
        assert_eq!((vo.x, vo.y), (1280, 0));
        assert!(!vo.focused);
        // The read-back the workspace confirm keys on.
        assert_eq!(vo.active_workspace.as_ref().map(|w| w.id), Some(7));
        assert_eq!(vo.active_workspace.as_ref().map(|w| w.name.as_str()), Some("7"));
        // ...and a row WITHOUT `activeWorkspace` must still parse rather than
        // failing the whole document, which is what would break `create` on a
        // compositor that reports the field differently.
        assert_eq!(panel.active_workspace, None);

        assert!(find(&ms, "HEADLESS-1").is_none());
    }

    #[test]
    fn is_headless_selects_only_the_headless_output() {
        let ms = parse_monitors(MONITORS_JSON).unwrap();
        assert!(is_headless(find(&ms, "AIRPLAY-1").unwrap()));
        assert!(!is_headless(find(&ms, "eDP-1").unwrap()));

        // All five conditions are required: a zero physical size alone is not
        // enough, or a monitor whose EDID the compositor failed to read would
        // be swept.
        let mut fake = find(&ms, "AIRPLAY-1").unwrap().clone();
        fake.make = "AU Optronics".into();
        assert!(!is_headless(&fake));

        let mut fake = find(&ms, "AIRPLAY-1").unwrap().clone();
        fake.serial = "ABC123".into();
        assert!(!is_headless(&fake));

        let mut fake = find(&ms, "AIRPLAY-1").unwrap().clone();
        fake.physical_width = 300;
        assert!(!is_headless(&fake));
    }

    #[test]
    fn check_ok_rejects_exit_zero_failures() {
        // hyprctl's own failure modes, all of which exit 0.
        for bad in [
            "Name already taken",
            "output not found",
            "no such option",
            "headless: refusing to create output AIRPLAY-1, name already in use",
            "",
        ] {
            assert!(check_ok(Some(0), bad).is_err(), "{bad:?} must not count as success");
        }
        assert!(check_ok(Some(0), "ok").is_ok());
        assert!(check_ok(Some(0), "ok\n").is_ok());
        assert!(check_ok(Some(7), "ok").is_err());
        assert!(check_ok(None, "ok").is_err()); // killed by a signal
    }

    #[test]
    fn validate_name_refuses_a_real_output() {
        for bad in [
            "eDP-1",
            "",
            "AIRPLAY-",
            "HEADLESS-1",
            "airplay-1", // prefix is case-sensitive
            r#"AIRPLAY-1"})--"#,
            "../x",
            "AIRPLAY-$(x)",
            "AIRPLAY-a b",
            "AIRPLAY-a/b",
            "AIRPLAY-';rm -rf /",
            "AIRPLAY-0123456789012345678901234567890123456789",
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?} must be refused");
        }
        for good in ["AIRPLAY-1", "AIRPLAY-tv", "AIRPLAY-T1", "AIRPLAY-frame.2", "AIRPLAY-a_b"] {
            validate_name(good).unwrap_or_else(|e| panic!("{good:?} must be accepted: {e}"));
        }
    }

    #[test]
    fn state_round_trip() {
        let _g = env_guard();
        let _s = Scratch::new("roundtrip");
        assert!(state::read().is_none(), "a fresh runtime dir has no claim");

        let c = Claim {
            name: "AIRPLAY-7".into(),
            instance: "abc_123".into(),
            pid: 4242,
            created_unix: 1_700_000_000,
            workspace: Some(7),
        };
        state::write(&c).unwrap();
        assert_eq!(state::read().as_ref(), Some(&c));

        state::clear().unwrap();
        assert!(state::read().is_none());
        state::clear().unwrap(); // clearing twice is not an error
    }

    #[test]
    fn state_absent_and_corrupt_are_both_none() {
        let _g = env_guard();
        let _s = Scratch::new("corrupt");
        assert!(state::read().is_none());

        std::fs::write(state::path(), b"{ not json at all").unwrap();
        assert!(state::read().is_none(), "a corrupt claim is no claim");

        std::fs::write(state::path(), br#"{"name":"AIRPLAY-1"}"#).unwrap();
        assert!(state::read().is_none(), "a truncated claim is no claim");
    }

    #[test]
    fn state_instance_mismatch_is_not_ours() {
        let _g = env_guard();
        let _s = Scratch::new("instance");
        let c = Claim {
            name: "AIRPLAY-1".into(),
            instance: "dead_instance".into(),
            pid: 1,
            created_unix: 0,
            workspace: Some(1),
        };
        state::write(&c).unwrap();
        let read = state::read().unwrap();
        // This is the comparison `reclaim_locked` makes before it is willing to
        // remove anything.
        assert_ne!(read.instance, "live_instance");
        assert_eq!(read.instance, "dead_instance");
    }

    #[test]
    fn the_runtime_dir_is_overridable_and_never_the_config_dir() {
        let _g = env_guard();
        let s = Scratch::new("dir");
        assert_eq!(state::dir(), s.0);
        assert_eq!(state::path(), s.0.join("extend.json"));
        assert_eq!(state::lock_path(), s.0.join("extend.lock"));
    }

    #[test]
    fn extend_mode_is_the_fixed_point() {
        // The whole sizing scheme rests on this: creating the output at
        // `extend_mode(display)` makes the created size equal the coded size,
        // so the compositor renders exactly what the encoder encodes.
        for d in [(1920, 1080), (1920, 1200), (3840, 2160), (3440, 1440), (1280, 720), (2560, 1600)]
        {
            let p = extend_mode(d);
            assert_eq!(extend_mode(p), p, "extend_mode is not idempotent at {d:?} -> {p:?}");
            assert_eq!(
                crate::encoder::fit_source_to_receiver(p, d),
                p,
                "a source created at {p:?} must reach a {d:?} receiver unscaled"
            );
        }
        // This Frame: a genuine 1:1 passthrough.
        assert_eq!(extend_mode((1920, 1080)), (1920, 1080));
    }

    // ======================================================= workspace picking

    #[test]
    fn next_workspace_id_appends_past_his_set_and_past_the_bars_defaults() {
        // the user's set at the time of writing, and the reason this is not "first
        // free" (3) or `count + 1` (4): both of those put the TV INSIDE his
        // workspaces — the mid-set wedging that made the bar's screen selector
        // ambiguous in the first place.
        assert_eq!(next_workspace_id(&[1, 2, 4, 6]), Some(7));
        assert_eq!(next_workspace_id(&[1, 4, 6, 2]), Some(7), "input order is irrelevant");

        // ...and the reason it is not bare `max + 1` either. the user caught this on
        // a live run: with {1, 2, 4}, `max + 1` is 5, and 5 is one of the five
        // buttons the bar draws whether or not anyone uses it. Taking it
        // consumes a permanent slot and leaves the TV inside the default range,
        // appending nothing. 6 is the first id that is actually past the bar's
        // defaults AND past his set.
        assert_eq!(next_workspace_id(&[1, 2, 4]), Some(6), "5 is a default bar slot");
        assert_eq!(next_workspace_id(&[1]), Some(6));
        assert_eq!(next_workspace_id(&[1, 2, 3]), Some(6));
        assert_eq!(next_workspace_id(&[3]), Some(6));
        assert_eq!(next_workspace_id(&[1, 2, 3, 4, 5]), Some(6), "the defaults all live");

        // Above the defaults it is plain `max + 1` again.
        assert_eq!(next_workspace_id(&[1, 2, 3, 4, 5, 6]), Some(7));
        assert_eq!(next_workspace_id(&[2, 9]), Some(10));
        assert_eq!(next_workspace_id(&[7]), Some(8), "a gap BELOW the highest is not filled");

        // Empty: still 6, not 1. There is no highest, but the bar is still
        // drawing five buttons, so 1 would be squarely inside them.
        assert_eq!(next_workspace_id(&[]), Some(6));

        // Hyprland's special and named workspaces have NEGATIVE ids. They are
        // not part of the numbered set the bar draws and must not drag the
        // answer down.
        assert_eq!(next_workspace_id(&[-99]), Some(6));
        assert_eq!(next_workspace_id(&[-99, -1, 1, 2]), Some(6));
        assert_eq!(next_workspace_id(&[-98, 6]), Some(7));

        // Duplicates (the same id reported twice) change nothing.
        assert_eq!(next_workspace_id(&[6, 6, 6]), Some(7));

        // The preferred id is the uncapped form of all of the above, and is
        // never inside the bar's defaults.
        assert_eq!(preferred_workspace_id(&[1, 2, 4]), 6);
        assert_eq!(preferred_workspace_id(&[]), 6);
        assert_eq!(preferred_workspace_id(&[1, 2, 4, 6]), 7);
        assert_eq!(preferred_workspace_id(&[42]), 43, "uncapped, unlike next_workspace_id");
        for ids in [vec![], vec![1], vec![-5], vec![1, 2, 3, 4, 5], vec![999]] {
            assert!(
                preferred_workspace_id(&ids) > BAR_DEFAULT_WORKSPACES,
                "preferred must clear the bar's defaults, for {ids:?}"
            );
        }
    }

    #[test]
    fn next_workspace_id_respects_the_bars_ten_workspace_ceiling() {
        // Omarchy's bar builds its model as `[1,2,3,4,5]` plus any live
        // workspace with `id > 0 && id <= 10`, so 11 and up are silently
        // dropped: putting the TV there would leave it with no button at all,
        // which is strictly worse than the mid-set wedging being fixed.
        assert_eq!(BAR_MAX_WORKSPACE, 10);
        assert_eq!(BAR_DEFAULT_WORKSPACES, 5);
        assert_eq!(next_workspace_id(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), Some(10), "10 is renderable");

        // The preferred id would be 11, so fall back to the highest id the bar
        // can draw that nobody holds. Not quite the right-hand end, but visible.
        assert_eq!(next_workspace_id(&[1, 2, 10]), Some(9));
        assert_eq!(next_workspace_id(&[1, 2, 9, 10]), Some(8));
        // A stray high workspace must not push the TV out of sight either.
        assert_eq!(next_workspace_id(&[1, 50]), Some(10));
        assert_eq!(next_workspace_id(&[1, 2, 4, 6, 999]), Some(10));
        // And an absurd id cannot overflow the increment into a wrap.
        assert_eq!(next_workspace_id(&[i64::MAX]), Some(10));

        // The fallback may land at or below 5, which is the one case where the
        // TV is visible but NOT the last button. Allowed on purpose — it beats
        // refusing — and `append()` flags it so the CLI can explain itself.
        assert_eq!(next_workspace_id(&[6, 7, 8, 9, 10]), Some(5));
        assert_eq!(next_workspace_id(&[4, 5, 6, 7, 8, 9, 10]), Some(3));
        assert_eq!(next_workspace_id(&[2, 3, 4, 5, 6, 7, 8, 9, 10]), Some(1));

        // All ten in use: no answer. the user's call — stop, rather than create a
        // workspace with no bar button or steal one he is using.
        assert_eq!(next_workspace_id(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), None);
        assert_eq!(
            next_workspace_id(&[10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 11, 12, -99]),
            None,
            "extra ids above the ceiling do not create room below it"
        );

        assert!(bar_shows_workspace(1) && bar_shows_workspace(10));
        assert!(!bar_shows_workspace(0) && !bar_shows_workspace(11));
    }

    #[test]
    fn every_picked_workspace_is_free_and_appends_when_it_can() {
        // Two properties over every subset of 1..=10, plus a few out-of-range
        // ids, exercising both branches of the pick.
        //
        // 1. SAFETY: the id handed to a workspace rule is never one the user is
        //    already using, so the rule can never carry his windows onto the TV.
        // 2. APPEND: whenever any id in 6..=10 is free, the pick is >= 6 — i.e.
        //    it gets past the five buttons the bar always draws. This is the
        //    property bare `max + 1` violated on {1, 2, 4}, where it chose 5.
        for mask in 0u32..(1 << 10) {
            let mut ids: Vec<i64> =
                (1..=10).filter(|c| mask & (1 << (c - 1)) != 0).map(i64::from).collect();
            if mask % 7 == 0 {
                ids.push(-99); // a special workspace
            }
            if mask % 11 == 0 {
                ids.push(42); // a workspace above the ceiling
            }
            let room_above_defaults = (BAR_DEFAULT_WORKSPACES + 1..=BAR_MAX_WORKSPACE)
                .any(|c| !ids.contains(&i64::from(c)));

            match next_workspace_id(&ids) {
                Some(id) => {
                    assert!(
                        !ids.contains(&i64::from(id)),
                        "pick {id} is already in use, for {ids:?}"
                    );
                    assert!(bar_shows_workspace(id), "pick {id} is unrenderable, for {ids:?}");
                    if room_above_defaults {
                        assert!(
                            id > BAR_DEFAULT_WORKSPACES,
                            "pick {id} sits in the bar's default slots although {}-{} had room, \
                             for {ids:?}",
                            BAR_DEFAULT_WORKSPACES + 1,
                            BAR_MAX_WORKSPACE
                        );
                    }
                }
                // Only the full house may decline.
                None => assert_eq!(
                    (1..=10).filter(|c| ids.contains(&i64::from(*c))).count(),
                    10,
                    "declined with room left, for {ids:?}"
                ),
            }
        }
    }

    #[test]
    fn the_name_and_its_workspace_are_exact_inverses() {
        // The name IS the request: a workspace rule cannot be cleared for
        // Hyprland's uptime, so `AIRPLAY-<N>` is what makes a different number
        // a different monitor name and therefore a fresh rule. These two
        // functions are the two directions of that, and must not drift.
        for id in [1u32, 2, 7, 9, 10, 11, 99, 1234] {
            let name = name_for_workspace(id);
            assert_eq!(workspace_for_name(&name), Some(id), "{name} did not round-trip");
            validate_name(&name).unwrap_or_else(|e| panic!("{name} must be creatable: {e}"));
        }
        assert_eq!(name_for_workspace(7), "AIRPLAY-7");
        assert_eq!(workspace_for_name("AIRPLAY-7"), Some(7));

        // Names that spell no workspace get the old behaviour — no rule,
        // Hyprland picks — rather than a rule built from a number the name
        // does not actually spell.
        for none in [
            "AIRPLAY-tv",      // no digits at all
            "AIRPLAY-007",     // parses as 7, but name_for_workspace(7) != this
            "AIRPLAY-0",       // workspace 0 does not exist in Hyprland
            "AIRPLAY-7.1",     // not an integer
            "AIRPLAY-7a",      // trailing junk
            "AIRPLAY--1",      // negative: a special workspace, never ours
            "AIRPLAY-+7",      // `parse` would accept the sign; the name must not
            "AIRPLAY-7 ",      // whitespace
            "AIRPLAY-99999999999999999999", // past u32
            "eDP-1",           // no prefix
        ] {
            assert_eq!(workspace_for_name(none), None, "{none:?} must ask for no workspace");
        }
    }

    #[test]
    fn workspace_rule_eval_is_the_recipe_verified_on_the_machine() {
        // Byte-for-byte what was run by hand against Hyprland 0.56.2 and seen
        // to bring the output up already owning the workspace. `hyprctl
        // keyword` is dead in 0.56 ("keyword can't work with non-legacy
        // parsers. Use eval."), so this has to go through `eval`.
        assert_eq!(
            workspace_rule_eval(7, "AIRPLAY-7"),
            r#"hl.workspace_rule({ workspace = "7", monitor = "AIRPLAY-7", default = true })"#
        );
        // `default = true` is the part that makes the output adopt it on
        // arrival rather than merely prefer it later.
        assert!(workspace_rule_eval(9, "AIRPLAY-9").contains("default = true"));
    }

    #[test]
    fn parse_workspace_ids_reads_this_machines_sparse_set() {
        assert_eq!(parse_workspace_ids(WORKSPACES_JSON).unwrap(), vec![1, 4, 6, 2]);
        assert_eq!(next_workspace_id(&parse_workspace_ids(WORKSPACES_JSON).unwrap()), Some(7));
        assert_eq!(parse_workspace_ids("[]").unwrap(), Vec::<i64>::new());
        assert!(parse_workspace_ids("not json").is_err());
        // Rows carry a dozen other keys; only `id` is required.
        assert_eq!(parse_workspace_ids(r#"[{"id":3,"whatever":true}]"#).unwrap(), vec![3]);
    }

    #[test]
    fn a_full_desktop_refuses_before_anything_is_created() {
        let _g = env_guard();
        let s = Scratch::new("fullhouse");
        let fake = FakeHyprctl::new(s.0.join("bin"), &panel_only(), &panel_only());
        fake.set_workspaces(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // The pure pick declines...
        assert_eq!(next_workspace_id(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), None);

        // ...and the live resolution turns that into its OWN error variant, not
        // a generic hyprctl failure, so the CLI can tell the user what to do.
        let e = append().expect_err("a full desktop must refuse");
        assert!(matches!(e, VirtualOutputError::NoFreeWorkspace { .. }), "{e:?}");
        let msg = e.to_string();
        assert!(msg.contains("1, 2, 3, 4, 5, 6, 7, 8, 9, 10"), "must name the blockers: {msg}");
        assert!(msg.contains("close the windows on one workspace"), "must say what to do: {msg}");

        // Nothing was created and nothing was claimed: there is nothing to
        // clean up after this refusal.
        assert!(!fake.log().contains("output create"), "{}", fake.log());
        assert!(!fake.log().contains("workspace_rule"), "{}", fake.log());
        assert!(state::read().is_none());

        // The read-only pre-flight refuses an explicit name here too, but for
        // the more precise reason: workspace 3 specifically is in use. The
        // remedy differs — name a free id, rather than close a workspace — so
        // it is a different variant, not this one.
        let e = preflight_workspace("AIRPLAY-3").expect_err("pre-flight must refuse too");
        assert!(matches!(e, VirtualOutputError::WorkspaceInUse { id: 3, .. }), "{e:?}");
        // ...but only for a name that actually asks for an occupied workspace.
        preflight_workspace("AIRPLAY-tv").expect("a name asking for no workspace is fine");
    }

    #[test]
    fn append_names_the_next_workspace_and_flags_a_squeeze() {
        let _g = env_guard();
        let s = Scratch::new("appendname");
        let fake = FakeHyprctl::new(s.0.join("bin"), &panel_only(), &panel_only());

        // The default fixture is the user's sparse 1, 2, 4, 6.
        let a = append().unwrap();
        assert_eq!(a, Appended { name: "AIRPLAY-7".into(), workspace: 7, squeezed: false });

        // Once the TV is up, workspace 7 exists, so a second concurrent run
        // would append again rather than collide.
        fake.set_workspaces(&[1, 2, 4, 6, 7]);
        assert_eq!(append().unwrap().name, "AIRPLAY-8");

        // The shape the user actually hit: his highest is 4, and 5 is a default bar
        // slot, so the append has to clear it.
        fake.set_workspaces(&[1, 2, 4]);
        let a = append().unwrap();
        assert_eq!(a, Appended { name: "AIRPLAY-6".into(), workspace: 6, squeezed: false });

        // Over the ceiling but still past the defaults: not squeezed.
        fake.set_workspaces(&[1, 2, 10]);
        let a = append().unwrap();
        assert_eq!(a, Appended { name: "AIRPLAY-9".into(), workspace: 9, squeezed: false });

        // 6-10 all taken: forced into the default range, and SAID so, which is
        // the whole reason `squeezed` exists.
        fake.set_workspaces(&[6, 7, 8, 9, 10]);
        let a = append().unwrap();
        assert_eq!(a, Appended { name: "AIRPLAY-5".into(), workspace: 5, squeezed: true });
        assert!(bar_shows_workspace(a.workspace), "still visible, just not last");
    }

    #[test]
    fn a_restart_reuses_the_workspace_its_own_phantom_is_holding() {
        let _g = env_guard();
        let s = Scratch::new("restart");
        let fake = FakeHyprctl::new(s.0.join("bin"), &panel_only(), &panel_only());

        // A crashed run left AIRPLAY-7 up, so workspace 7 is live — but on OUR
        // phantom, which `create`'s reclaim sweep is about to remove.
        std::fs::write(
            s.0.join("bin/workspaces.json"),
            br#"[{"id":1,"monitor":"eDP-1"},{"id":2,"monitor":"eDP-1"},
                 {"id":4,"monitor":"eDP-1"},{"id":6,"monitor":"eDP-1"},
                 {"id":7,"monitor":"AIRPLAY-7"}]"#,
        )
        .unwrap();

        // With no claim, 7 is somebody else's and counts: append to 8.
        assert_eq!(append().unwrap().name, "AIRPLAY-8");

        // With our own claim naming it, the restart lands back on 7. That is
        // not just tidier: a workspace rule cannot be cleared while Hyprland is
        // up, so a crash loop that walked 7, 8, 9, 10 would stack up a new
        // uncleanable rule per attempt and then run out of bar-visible ids.
        state::write(&Claim {
            name: "AIRPLAY-7".into(),
            instance: "fake_test_instance".into(),
            pid: 4242,
            created_unix: 1,
            workspace: Some(7),
        })
        .unwrap();
        assert_eq!(append().unwrap().name, "AIRPLAY-7");

        // A claim from a DEAD compositor says nothing about this one's outputs,
        // so its name must not excuse a live workspace.
        state::write(&Claim {
            name: "AIRPLAY-7".into(),
            instance: "a_dead_instance".into(),
            pid: 4242,
            created_unix: 1,
            workspace: Some(7),
        })
        .unwrap();
        assert_eq!(append().unwrap().name, "AIRPLAY-8");

        // And another tool's output is likewise left in the count.
        state::write(&Claim {
            name: "AIRPLAY-9".into(),
            instance: "fake_test_instance".into(),
            pid: 4242,
            created_unix: 1,
            workspace: Some(9),
        })
        .unwrap();
        assert_eq!(append().unwrap().name, "AIRPLAY-8");

        // The same thing one workspace lower, which is now the common shape:
        // the user's highest is 4, the append cleared the bar's defaults to land on
        // 6, and the crash left AIRPLAY-6 holding workspace 6. The restart must
        // come back to 6 and not walk on to 7.
        std::fs::write(
            s.0.join("bin/workspaces.json"),
            br#"[{"id":1,"monitor":"eDP-1"},{"id":2,"monitor":"eDP-1"},
                 {"id":4,"monitor":"eDP-1"},{"id":6,"monitor":"AIRPLAY-6"}]"#,
        )
        .unwrap();
        state::clear().unwrap();
        assert_eq!(append().unwrap().name, "AIRPLAY-7", "without a claim, 6 is somebody else's");
        state::write(&Claim {
            name: "AIRPLAY-6".into(),
            instance: "fake_test_instance".into(),
            pid: 4242,
            created_unix: 1,
            workspace: Some(6),
        })
        .unwrap();
        assert_eq!(append().unwrap().name, "AIRPLAY-6", "the restart reuses its own workspace");

        state::clear().unwrap();
        drop(fake);
    }

    #[test]
    fn create_pins_the_workspace_before_creating_the_output() {
        let _g = env_guard();
        let s = Scratch::new("pin");
        let fake =
            FakeHyprctl::new(s.0.join("bin"), &panel_only(), &panel_and_on("AIRPLAY-7", 7));
        fake.set_workspaces(&[1, 2, 4, 6]); // -> 7 is the append target

        let vo = VirtualOutput::create("AIRPLAY-7", (1920, 1080), 60).expect("create");
        assert_eq!(vo.name(), "AIRPLAY-7");
        // Confirmed by READ-BACK, not by what was asked for.
        assert_eq!(vo.workspace(), Some(7));

        // The rule is applied, and applied BEFORE `output create` — the only
        // moment it can take effect, since the output has to come up already
        // owning the workspace.
        let log = fake.log();
        let rule = log
            .find("workspace_rule")
            .unwrap_or_else(|| panic!("no rule applied:\n{log}"));
        let create =
            log.find("output create").unwrap_or_else(|| panic!("no create:\n{log}"));
        assert!(rule < create, "the rule must precede the create:\n{log}");
        assert!(
            log.contains(r#"workspace = "7", monitor = "AIRPLAY-7", default = true"#),
            "{log}"
        );

        // The claim records the id as its own integer field, for the bar widget
        // that reads this file and should not have to parse the name.
        let claim = state::read().expect("a claim");
        assert_eq!(claim.workspace, Some(7));
        assert_eq!(claim.name, "AIRPLAY-7");
        let raw = std::fs::read_to_string(state::path()).unwrap();
        assert!(raw.contains("\"workspace\": 7"), "an integer in the JSON, not a string:\n{raw}");

        drop(vo);
    }

    #[test]
    fn an_explicit_name_for_an_occupied_workspace_is_refused() {
        let _g = env_guard();
        let s = Scratch::new("nosteal");
        let fake = FakeHyprctl::new(s.0.join("bin"), &panel_only(), &panel_and("AIRPLAY-2", true));
        fake.set_workspaces(&[1, 2, 4, 6]); // workspace 2 is LIVE

        // An explicit `--extend AIRPLAY-2` asks for workspace 2, which holds
        // the user's windows. Pinning it would carry them onto the TV; carrying on
        // unpinned is no safer, because Hyprland's per-monitor-name workspace
        // memory can relocate them anyway, silently. So the run is refused —
        // the user's call, and the only option that cannot move his windows.
        let e = VirtualOutput::create("AIRPLAY-2", (1920, 1080), 60)
            .expect_err("an occupied explicit workspace must be refused");
        assert!(matches!(e, VirtualOutputError::WorkspaceInUse { id: 2, .. }), "{e:?}");
        let msg = e.to_string();
        assert!(msg.contains("workspace 2"), "must name the workspace: {msg}");
        assert!(msg.contains("already in use"), "must say why: {msg}");
        assert!(msg.contains("bare `--extend`"), "must point at the fix: {msg}");

        // Refused BEFORE anything happened: no rule, no output, no claim, so
        // there is nothing to clean up.
        let log = fake.log();
        assert!(!log.contains("workspace_rule"), "a live workspace must never be pinned:\n{log}");
        assert!(!log.contains("output create"), "nothing may be created:\n{log}");
        assert!(state::read().is_none(), "and nothing may be claimed");

        // A free explicit id is still honoured.
        fake.rearm(&panel_only(), &panel_and_on("AIRPLAY-9", 9));
        fake.clear_log();
        let vo = VirtualOutput::create("AIRPLAY-9", (1920, 1080), 60).expect("a free id is fine");
        assert_eq!(vo.workspace(), Some(9), "pinned and confirmed by read-back");
        assert!(fake.log().contains(r#"workspace = "9""#), "{}", fake.log());
        drop(vo);

        // So is a free id ABOVE the bar's ceiling — honoured, with a warning
        // that it gets no button, because that is cosmetic and was asked for.
        fake.rearm(&panel_only(), &panel_and_on("AIRPLAY-99", 99));
        fake.clear_log();
        let vo = VirtualOutput::create("AIRPLAY-99", (1920, 1080), 60).expect("99 is free");
        assert_eq!(vo.workspace(), Some(99));
        assert!(!bar_shows_workspace(99), "the case the warning is about");
        assert!(fake.log().contains(r#"workspace = "99""#), "{}", fake.log());
        drop(vo);

        // ...but an occupied one above the ceiling is refused like any other.
        fake.rearm(&panel_only(), &panel_and("AIRPLAY-42", true));
        fake.set_workspaces(&[1, 2, 42]);
        let e = VirtualOutput::create("AIRPLAY-42", (1920, 1080), 60)
            .expect_err("occupied beats above-the-ceiling");
        assert!(matches!(e, VirtualOutputError::WorkspaceInUse { id: 42, .. }), "{e:?}");

        // A name that spells NO workspace keeps working: it names nothing that
        // could be occupied, so the user's "refuse" does not reach it. It is the
        // documented escape hatch, and it warns instead.
        fake.rearm(&panel_only(), &panel_and("AIRPLAY-tv", true));
        fake.set_workspaces(&[1, 2, 4, 6]);
        fake.clear_log();
        let vo = VirtualOutput::create("AIRPLAY-tv", (1920, 1080), 60).expect("create");
        assert_eq!(vo.workspace(), None);
        assert!(!fake.log().contains("workspace_rule"), "{}", fake.log());
        drop(vo);
    }

    #[test]
    fn an_unreadable_workspace_list_still_streams() {
        let _g = env_guard();
        let s = Scratch::new("wsbroken");
        let fake =
            FakeHyprctl::new(s.0.join("bin"), &panel_only(), &panel_and("AIRPLAY-7", true));
        fake.break_workspaces(true);

        // A stream on an untidy workspace number beats no stream at all, so an
        // unreadable workspace list degrades to "no pin" with a warning rather
        // than failing the run.
        let vo = VirtualOutput::create("AIRPLAY-7", (1920, 1080), 60)
            .expect("an unreadable workspace list must not fail the run");
        assert_eq!(vo.workspace(), None);
        assert!(!fake.log().contains("workspace_rule"), "{}", fake.log());
        drop(vo);
    }

    #[test]
    fn a_workspace_that_never_lands_warns_but_keeps_the_stream() {
        let _g = env_guard();
        let s = Scratch::new("wsnotland");
        let fake = FakeHyprctl::new(
            s.0.join("bin"),
            &panel_only(),
            // The output comes up at the right MODE but on the wrong workspace.
            &panel_and_on("AIRPLAY-7", 3),
        );
        fake.set_workspaces(&[1, 2, 4, 6]);

        // This is the deliberate asymmetry with the mode confirm: a wrong mode
        // means the whole pipeline is built at the wrong size and is fatal, but
        // a wrong workspace number is cosmetic. Failing here would throw away a
        // working session — pairing and TV bring-up included — for a tidier
        // integer, so it warns and streams.
        let vo = VirtualOutput::create("AIRPLAY-7", (1920, 1080), 60)
            .expect("a workspace that did not land must not fail the run");
        assert_eq!(vo.size(), (1920, 1080), "the mode still had to be confirmed");
        assert_eq!(vo.workspace(), None, "and the guard reports what happened, not what we asked");
        drop(vo);
    }

    #[test]
    fn a_claim_from_the_previous_build_is_still_reclaimable() {
        let _g = env_guard();
        let s = Scratch::new("oldclaim");
        let fake = FakeHyprctl::new(
            s.0.join("bin"),
            &panel_and("AIRPLAY-1", true),
            &panel_and("AIRPLAY-1", true),
        );

        // Exactly the bytes the previous build wrote: no `workspace` key. A
        // claim that fails to parse is treated as NO claim, so without
        // `#[serde(default)]` this run's output would become an unreclaimable
        // phantom monitor on the user's desktop.
        std::fs::write(
            state::path(),
            br#"{"name":"AIRPLAY-1","instance":"fake_test_instance","pid":1234,"created_unix":1}"#,
        )
        .unwrap();
        let claim = state::read().expect("an older claim must still parse");
        assert_eq!(claim.name, "AIRPLAY-1");
        assert_eq!(claim.workspace, None, "a missing field is UNKNOWN, not corrupt");

        assert_eq!(
            reclaim_locked("fake_test_instance").expect("sweep"),
            Some("AIRPLAY-1".to_string()),
            "the phantom from the older build must still be swept"
        );
        assert!(fake.log().contains("output remove AIRPLAY-1"), "{}", fake.log());
        assert!(state::read().is_none());
    }

    #[test]
    fn the_varying_name_still_reclaims_under_its_own_name() {
        let _g = env_guard();
        let s = Scratch::new("varyname");
        let fake = FakeHyprctl::new(
            s.0.join("bin"),
            &panel_and("AIRPLAY-9", true),
            &panel_and("AIRPLAY-9", true),
        );

        // The claim keys on the recorded NAME, and the name now varies with the
        // workspace — so a run that was SIGKILLed on AIRPLAY-9 must be swept as
        // AIRPLAY-9, not as some fixed default.
        state::write(&Claim {
            name: "AIRPLAY-9".into(),
            instance: "fake_test_instance".into(),
            pid: 999,
            created_unix: 1,
            workspace: Some(9),
        })
        .unwrap();
        assert_eq!(
            reclaim_locked("fake_test_instance").expect("sweep"),
            Some("AIRPLAY-9".to_string())
        );
        assert!(fake.log().contains("output remove AIRPLAY-9"), "{}", fake.log());
        assert!(state::read().is_none());
    }

    #[test]
    fn a_missing_hyprland_signature_is_reported_not_panicked() {
        let _g = env_guard();
        let saved = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok();
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let e = instance().expect_err("no signature must be an error");
        assert!(matches!(e, VirtualOutputError::NoHyprland(_)), "{e:?}");
        if let Some(v) = saved {
            std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", v);
        }
    }
}
