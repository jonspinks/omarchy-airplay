//! "What is running right now", for `airplay status [--json]`.
//!
//! # Why this is a second file and not two more fields on the Extend claim
//!
//! [`crate::virtualoutput::state`] already writes a record to
//! `$XDG_RUNTIME_DIR/airplay-rs/extend.json`, and the obvious move is to add a
//! `kind` and a `receiver` to it so `status` can see every session. It is the
//! wrong move, for three reasons that are all about the claim's *other* job:
//!
//! 1. **That file is an ownership claim, not a status record.** It is the
//!    selector for the reclaim sweep — the thing that stops a SIGKILLed run
//!    leaving a headless output on the user's desktop forever. `reclaim_locked`
//!    passes `claim.name` through `validate_name` and clears any claim that
//!    fails, so an `--output eDP-1` session writing its own name there would be
//!    silently erased by the next `--extend` run (and, worse, a name like
//!    `eDP-1` is exactly what that gate exists to keep out of a removal path).
//! 2. **Two concurrent sessions would clobber each other.** Only one `--extend`
//!    can run at a time (an `flock` enforces it), but nothing stops an
//!    `--output` mirror running alongside one. Both writing `extend.json` means
//!    whichever exits first deletes the other's record: for the `--extend` run
//!    that record is what makes its output reclaimable, so the cost of the
//!    collision is a phantom monitor, not a wrong status line.
//! 3. **Something else already reads it.** The Omarchy bar widget parses
//!    `extend.json`; its schema is additive-compatible by design, and changing
//!    what the file *means* (every session, not just Extend) is not an additive
//!    change.
//!
//! So the claim keeps its single job, and this module adds a record with the
//! single job of answering "what is running": `session.json`, in the same
//! runtime directory (so it is wiped on logout for the same reason), written by
//! **every** mirror session — `--output`, `--window`, `--extend` and
//! `--test-pattern` — and removed by a guard on the way out, including on the
//! signal path, which returns through destructors.
//!
//! `status` never takes the exclusive lock and never writes anything.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Which source a running session is mirroring.
///
/// Serialises to the strings the CLI contract uses: `"extend"`, `"output"`,
/// `"window"`, `"test-pattern"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionKind {
    /// `mirror --extend`: a Hyprland headless output as a second desktop.
    Extend,
    /// `mirror --output NAME`: a real output, mirrored.
    Output,
    /// `mirror --window TEXT`: one window, mirrored.
    Window,
    /// `mirror --test-pattern`: the generated control pattern.
    TestPattern,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionKind::Extend => "extend",
            SessionKind::Output => "output",
            SessionKind::Window => "window",
            SessionKind::TestPattern => "test-pattern",
        }
    }
}

impl std::fmt::Display for SessionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The object `airplay status --json` prints as `session` (and as `orphan`).
///
/// Every key is always present — a missing value is `null`, never an omitted
/// key — so a consumer can read `session.workspace` without first testing for
/// it. That is the opposite of the choice made for `discover`'s `model` and
/// `srcvers`, and deliberately: there, absence is a fact about the receiver's
/// advertisement; here, every field is a fact about a session we started
/// ourselves, and `null` means "does not apply to this kind".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub kind: SessionKind,
    /// The receiver's address, as the session connected to it. `null` only for
    /// an `orphan`, whose receiver is not recorded anywhere.
    pub receiver: Option<String>,
    /// The Extend output's name (`AIRPLAY-6`), the mirrored output's name
    /// (`eDP-1`), or the `--window` match text. `null` for `--test-pattern`,
    /// which has no source of its own.
    pub name: Option<String>,
    /// The workspace the Extend output owns. `null` for every other kind, and
    /// for an Extend output whose workspace Hyprland chose rather than us.
    pub workspace: Option<u32>,
    pub pid: u32,
    /// The audio stream, `null` when the session sends no audio (the
    /// default). Added in Milestone 4; `#[serde(default)]` so a record written
    /// by an older build still reads.
    #[serde(default)]
    pub audio: Option<AudioStatus>,
}

/// `session.audio` in `airplay status --json`. Every key always present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AudioStatus {
    /// "system" or "tone".
    pub mode: String,
    /// "sink", "pipewire", "parec" or "tone" — the capture that actually
    /// OPENED, not the one asked for: `sink` falls back to `pipewire` rather
    /// than ship audio that is quietly attenuated twice.
    pub capture: String,
    pub latency_ms: u32,
    pub av_offset_ms: i32,
    /// false until the A/V offset has been measured on this receiver model.
    pub av_offset_calibrated: bool,
    pub effective_latency_ms: u32,
    pub volume_sync: bool,
    /// "waiting for audio", "starting", "armed", "disabled: ...", "error: ...",
    /// or "detached: ..." (sink mode, after the user picked another output).
    pub volume_state: String,
    pub tv_volume_db: Option<f64>,
    pub tv_muted: Option<bool>,
    pub laptop_pct: Option<u8>,
    /// Whether the captured sink's monitor is post-volume (read-only
    /// `pw-dump`); `null` when unknown. Unproven for the ALSA speaker sink.
    pub capture_post_volume: Option<bool>,
    /// The sender's own published sink (`node.name`, e.g.
    /// `airplay-sink.75_the_frame`); `null` in every capture mode but `sink`,
    /// and also when `sink` was asked for and fell back to the default sink's
    /// monitor. `capture` says which of those two it is.
    #[serde(default)]
    pub output_sink: Option<String>,
    /// That sink's `node.description` — what the user sees in his output menu,
    /// e.g. `AirPlay: 75" The Frame`.
    #[serde(default)]
    pub output_sink_label: Option<String>,
    /// Is it the laptop's output right now? `false` before the volume gate
    /// opens (the speakers are still playing then, deliberately) and `false`
    /// again once the user has picked another output himself — at which point the
    /// TV goes silent and `volume_state` starts with `detached`.
    #[serde(default)]
    pub output_is_default: Option<bool>,
    /// The output that comes back when the session ends.
    #[serde(default)]
    pub previous_output: Option<String>,
    pub packets: u64,
    pub anchors: u64,
    pub syncs: u64,
    pub late_reanchors: u64,
    pub discontinuities: u64,
    /// "starting", "streaming", "silent" (streaming digital silence: the TV
    /// volume is not established), "stalled", "error" or "stopped".
    pub state: String,
}

/// `session.json` on disk: the record plus the bookkeeping `status` needs but
/// does not print.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionFile {
    #[serde(flatten)]
    pub session: SessionRecord,
    pub created_unix: u64,
    /// `$HYPRLAND_INSTANCE_SIGNATURE` when known. Informational: a session's
    /// liveness comes from its pid, not from the compositor.
    #[serde(default)]
    pub instance: Option<String>,
}

/// `$XDG_RUNTIME_DIR/airplay-rs/session.json` — the same directory as the
/// Extend claim, so `AIRPLAY_RS_RUNTIME_DIR` redirects both in tests.
pub fn path() -> PathBuf {
    crate::virtualoutput::state::dir().join("session.json")
}

/// Write the record and `fsync` it, for the same reason the Extend claim is
/// fsynced: it has to be on disk before the thing it describes starts.
///
/// Atomic: written to a temporary file in the same directory and renamed
/// over `session.json`, so a `status` poll racing a mid-session update (the
/// audio fields change while streaming) never reads a half-written file.
pub fn write(f: &SessionFile) -> std::io::Result<()> {
    use std::io::Write as _;
    std::fs::create_dir_all(crate::virtualoutput::state::dir())?;
    let json = serde_json::to_vec_pretty(f).map_err(std::io::Error::other)?;
    let tmp = crate::virtualoutput::state::dir().join(format!(".session.json.{}.tmp", std::process::id()));
    let res = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&json)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&tmp, path())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Replace the `audio` object of the record owned by `pid`. Does nothing
/// (and returns Ok(false)) when the file is absent or belongs to another
/// process, so an update can never resurrect or steal a record.
pub fn update_audio(pid: u32, audio: Option<AudioStatus>) -> std::io::Result<bool> {
    match read() {
        Some(mut f) if f.session.pid == pid => {
            if f.session.audio == audio {
                return Ok(true);
            }
            f.session.audio = audio;
            write(&f).map(|_| true)
        }
        _ => Ok(false),
    }
}

/// `None` when absent, unreadable or corrupt — all of which mean "no record".
pub fn read() -> Option<SessionFile> {
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
    crate::virtualoutput::state::now_unix()
}

/// Is `pid` a live process?
///
/// `/proc/<pid>` rather than `kill(pid, 0)`: the existence test cannot signal
/// anything by accident, needs no permission to the target, and a status poll
/// running every couple of seconds should not be issuing signals at all. (A
/// zombie still has a `/proc` entry, but a zombie `airplay` has already run its
/// destructors and removed this file, so it cannot be mistaken for a running
/// session.)
pub fn pid_alive(pid: u32) -> bool {
    pid != 0 && Path::new(&format!("/proc/{pid}")).is_dir()
}

/// Writes the session record on construction and removes it on drop.
///
/// The removal rides the existing teardown: `main` returns through its
/// destructors on SIGINT/SIGTERM/SIGHUP, so the record goes with the session it
/// describes without touching the signal path at all. A SIGKILL leaves the file
/// behind, and a stale file is harmless — [`pid_alive`] is what makes it
/// "nothing is running" rather than a phantom session.
pub struct SessionClaim {
    pid: u32,
}

impl SessionClaim {
    /// Best effort: a session that cannot record itself still streams. The
    /// warning goes to stderr so `--json` consumers never see it on stdout.
    pub fn new(session: SessionRecord) -> Self {
        let pid = session.pid;
        let file = SessionFile {
            session,
            created_unix: now_unix(),
            instance: std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok(),
        };
        if let Err(e) = write(&file) {
            eprintln!(
                "warning: could not record this session in {} ({e}); `airplay status` will \
                 report nothing running",
                path().display()
            );
        }
        SessionClaim { pid }
    }
}

impl Drop for SessionClaim {
    /// Removes the record only while it is still ours. Two `airplay mirror`
    /// runs at once share one file, so the second one's claim must not delete
    /// the record the first one is still described by.
    fn drop(&mut self) {
        if read().is_some_and(|f| f.session.pid == self.pid) {
            let _ = clear();
        }
    }
}

/// The whole `airplay status --json` document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    /// The live session, or `null` when nothing is running.
    pub session: Option<SessionRecord>,
    /// An Extend output whose owner is dead but which is still on the desktop —
    /// the case `airplay extend --cleanup` fixes. `null` when there is none.
    pub orphan: Option<SessionRecord>,
}

impl StatusReport {
    /// One line of compact JSON, newline-terminated, and nothing else.
    pub fn to_json_line(&self) -> String {
        match serde_json::to_string(self) {
            Ok(s) => format!("{s}\n"),
            Err(_) => "{\"session\":null,\"orphan\":null}\n".to_string(),
        }
    }
}

// ===================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    fn extend_session() -> SessionRecord {
        SessionRecord {
            kind: SessionKind::Extend,
            receiver: Some("192.0.2.187".into()),
            name: Some("AIRPLAY-6".into()),
            workspace: Some(6),
            pid: 12345,
            audio: None,
        }
    }

    /// The CLI contract, byte for byte — the user's Quickshell panel parses exactly
    /// this, so key order, the `null`s and the kind spellings are all pinned.
    #[test]
    fn the_status_document_matches_the_contract_bytes() {
        let doc = StatusReport { session: Some(extend_session()), orphan: None };
        assert_eq!(
            doc.to_json_line(),
            "{\"session\":{\"kind\":\"extend\",\"receiver\":\"192.0.2.187\",\
             \"name\":\"AIRPLAY-6\",\"workspace\":6,\"pid\":12345,\"audio\":null},\"orphan\":null}\n"
        );

        // Nothing running, nothing left behind.
        assert_eq!(
            StatusReport { session: None, orphan: None }.to_json_line(),
            "{\"session\":null,\"orphan\":null}\n"
        );

        // An orphan is the same shape with no receiver: nothing records which
        // TV a dead run was streaming to.
        let doc = StatusReport {
            session: None,
            orphan: Some(SessionRecord {
                kind: SessionKind::Extend,
                receiver: None,
                name: Some("AIRPLAY-6".into()),
                workspace: Some(6),
                pid: 12345,
                audio: None,
            }),
        };
        assert_eq!(
            doc.to_json_line(),
            "{\"session\":null,\"orphan\":{\"kind\":\"extend\",\"receiver\":null,\
             \"name\":\"AIRPLAY-6\",\"workspace\":6,\"pid\":12345,\"audio\":null}}\n"
        );
    }

    /// The audio object, byte for byte: key order and the `null`s are the
    /// contract the panel parses.
    #[test]
    fn the_audio_object_matches_the_contract_bytes() {
        let mut s = extend_session();
        s.audio = Some(AudioStatus {
            mode: "system".into(),
            capture: "pipewire".into(),
            latency_ms: 300,
            av_offset_ms: 0,
            av_offset_calibrated: false,
            effective_latency_ms: 300,
            volume_sync: true,
            volume_state: "armed".into(),
            tv_volume_db: Some(-24.9),
            tv_muted: Some(false),
            laptop_pct: Some(17),
            capture_post_volume: None,
            output_sink: None,
            output_sink_label: None,
            output_is_default: None,
            previous_output: None,
            packets: 0,
            anchors: 0,
            syncs: 0,
            late_reanchors: 0,
            discontinuities: 0,
            state: "starting".into(),
        });
        let doc = StatusReport { session: Some(s.clone()), orphan: None };
        assert_eq!(
            doc.to_json_line(),
            "{\"session\":{\"kind\":\"extend\",\"receiver\":\"192.0.2.187\",\
             \"name\":\"AIRPLAY-6\",\"workspace\":6,\"pid\":12345,\"audio\":{\"mode\":\"system\",\
             \"capture\":\"pipewire\",\"latency_ms\":300,\"av_offset_ms\":0,\
             \"av_offset_calibrated\":false,\"effective_latency_ms\":300,\"volume_sync\":true,\
             \"volume_state\":\"armed\",\"tv_volume_db\":-24.9,\"tv_muted\":false,\"laptop_pct\":17,\
             \"capture_post_volume\":null,\"output_sink\":null,\"output_sink_label\":null,\
             \"output_is_default\":null,\"previous_output\":null,\"packets\":0,\"anchors\":0,\"syncs\":0,\
             \"late_reanchors\":0,\"discontinuities\":0,\"state\":\"starting\"}},\"orphan\":null}\n"
        );

        // Sink mode with the output actually handed over: the four keys carry
        // the receiver's own text verbatim, double quote and all, so the panel
        // can print the name the user sees in his output menu.
        let mut sink = s;
        let a = sink.audio.as_mut().unwrap();
        a.capture = "sink".into();
        a.output_sink = Some("airplay-sink.75_the_frame".into());
        a.output_sink_label = Some("AirPlay: 75\" The Frame".into());
        a.output_is_default = Some(true);
        a.previous_output = Some("alsa_output.pci-0000_00_1f.3.analog-stereo".into());
        let doc = StatusReport { session: Some(sink), orphan: None };
        assert_eq!(
            doc.to_json_line(),
            "{\"session\":{\"kind\":\"extend\",\"receiver\":\"192.0.2.187\",\
             \"name\":\"AIRPLAY-6\",\"workspace\":6,\"pid\":12345,\"audio\":{\"mode\":\"system\",\
             \"capture\":\"sink\",\"latency_ms\":300,\"av_offset_ms\":0,\
             \"av_offset_calibrated\":false,\"effective_latency_ms\":300,\"volume_sync\":true,\
             \"volume_state\":\"armed\",\"tv_volume_db\":-24.9,\"tv_muted\":false,\"laptop_pct\":17,\
             \"capture_post_volume\":null,\"output_sink\":\"airplay-sink.75_the_frame\",\
             \"output_sink_label\":\"AirPlay: 75\\\" The Frame\",\"output_is_default\":true,\
             \"previous_output\":\"alsa_output.pci-0000_00_1f.3.analog-stereo\",\
             \"packets\":0,\"anchors\":0,\"syncs\":0,\
             \"late_reanchors\":0,\"discontinuities\":0,\"state\":\"starting\"}},\"orphan\":null}\n"
        );

        // A record written before Milestone 4 (no "audio" key) still reads.
        let old = "{\"kind\":\"output\",\"receiver\":null,\"name\":null,\"workspace\":null,\"pid\":1,\
                   \"created_unix\":5}";
        let f: SessionFile = serde_json::from_str(old).unwrap();
        assert_eq!(f.session.audio, None);

        // And one written by the Milestone 4 build, before the four sink keys
        // existed: it still reads, with all four null.
        let m4 = "{\"kind\":\"extend\",\"receiver\":\"192.0.2.187\",\"name\":\"AIRPLAY-6\",\
                  \"workspace\":6,\"pid\":1,\"audio\":{\"mode\":\"system\",\"capture\":\"pipewire\",\
                  \"latency_ms\":300,\"av_offset_ms\":0,\"av_offset_calibrated\":false,\
                  \"effective_latency_ms\":300,\"volume_sync\":true,\"volume_state\":\"armed\",\
                  \"tv_volume_db\":null,\"tv_muted\":null,\"laptop_pct\":null,\
                  \"capture_post_volume\":null,\"packets\":0,\"anchors\":0,\"syncs\":0,\
                  \"late_reanchors\":0,\"discontinuities\":0,\"state\":\"starting\"},\
                  \"created_unix\":5}";
        let f: SessionFile = serde_json::from_str(m4).unwrap();
        let a = f.session.audio.expect("the audio object still parses");
        assert_eq!(
            (a.output_sink, a.output_sink_label, a.output_is_default, a.previous_output),
            (None, None, None, None)
        );
    }

    /// Every kind spells itself the same way in JSON as on the command line.
    #[test]
    fn every_session_kind_has_a_stable_spelling() {
        for (kind, want) in [
            (SessionKind::Extend, "extend"),
            (SessionKind::Output, "output"),
            (SessionKind::Window, "window"),
            (SessionKind::TestPattern, "test-pattern"),
        ] {
            assert_eq!(kind.as_str(), want);
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{want}\""));
            assert_eq!(
                serde_json::from_str::<SessionKind>(&format!("\"{want}\"")).unwrap(),
                kind
            );
        }
        // A --output session records the output's name and no workspace.
        let doc = StatusReport {
            session: Some(SessionRecord {
                kind: SessionKind::Output,
                receiver: Some("192.0.2.187".into()),
                name: Some("eDP-1".into()),
                workspace: None,
                pid: 4242,
                audio: None,
            }),
            orphan: None,
        };
        assert_eq!(
            doc.to_json_line(),
            "{\"session\":{\"kind\":\"output\",\"receiver\":\"192.0.2.187\",\
             \"name\":\"eDP-1\",\"workspace\":null,\"pid\":4242,\"audio\":null},\"orphan\":null}\n"
        );
    }

    /// The record survives a round trip through the file, and the guard removes
    /// it again — the two halves `status` depends on.
    #[test]
    fn the_record_round_trips_through_the_runtime_dir_and_the_guard_clears_it() {
        // Shared with `virtualoutput`'s state tests: same process-wide variable,
        // same directory.
        let _g = crate::virtualoutput::state::env_guard();
        let dir = std::env::temp_dir().join(format!("airplay-rs-sess-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AIRPLAY_RS_RUNTIME_DIR", &dir);
        assert_eq!(path(), dir.join("session.json"));
        assert!(read().is_none(), "an absent file is no session");

        let mut rec = extend_session();
        rec.pid = std::process::id();
        {
            let _claim = SessionClaim::new(rec.clone());
            let f = read().expect("the record is on disk while the session runs");
            assert_eq!(f.session, rec);
            assert!(f.created_unix > 0);
        }
        assert!(read().is_none(), "the guard removes it on the way out");

        // A record belonging to some other process is left alone.
        write(&SessionFile {
            session: extend_session(), // pid 12345, not us
            created_unix: now_unix(),
            instance: None,
        })
        .expect("write");
        drop(SessionClaim::new({
            let mut r = extend_session();
            r.pid = std::process::id();
            r
        }));
        // ...our own guard wrote and removed its own record, and the earlier
        // one was overwritten by it — what matters is that a guard only ever
        // deletes a file whose pid matches, which the next case proves.
        write(&SessionFile {
            session: extend_session(),
            created_unix: now_unix(),
            instance: None,
        })
        .expect("write");
        {
            let claim = SessionClaim { pid: 999_999_999 }; // not the file's pid
            drop(claim);
        }
        assert!(
            read().is_some(),
            "a guard must not delete a record that is not its own"
        );

        // Corrupt is "no record", never a panic.
        std::fs::write(path(), b"{ not json").expect("write garbage");
        assert!(read().is_none());

        std::env::remove_var("AIRPLAY_RS_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn liveness_is_a_proc_lookup_and_signals_nothing() {
        assert!(pid_alive(std::process::id()), "our own pid is alive");
        assert!(pid_alive(1), "pid 1 is always alive");
        // Above every possible pid_max, so this can never be a live process —
        // and, unlike `kill(pid, 0)`, asking cannot perturb one either.
        assert!(!pid_alive(u32::MAX));
        assert!(!pid_alive(0), "pid 0 is not a process we could have started");
    }
}
