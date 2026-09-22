//! volume: the laptop <-> TV volume policy while audio goes to the receiver.
//!
//! # What is proven, and what is not
//!
//! Proven on the Frame by the probe (run 163229): `SET_PARAMETER` with body
//! `volume: <dB>` (content type `text/parameters`) on the AUDIO stream URI,
//! with NO Session header, sent >= 2 s after the first audio packet, is
//! APPLIED even though the Frame replies `500 Internal Server Error`; a
//! `GET_PARAMETER volume` reads it back. The scale is -30..0 dB for 0..100 %,
//! and -144 means mute. The TV's own volume changes arrive on the event
//! channel as `dvlc` (0..1).
//!
//! NOT proven (needs the TV, with the user): -144 actually muting the Frame, the
//! timing of the `dvlc` echo after one of our SETs, whether a TV-remote mute
//! reports `isMuted`, and whether the dvlc<->dB mapping holds beyond the 1 %
//! quantisation seen.
//!
//! # the user's policy
//!
//! At session start the TV takes the LAPTOP's volume: `dB = -30 + 30 x pct`,
//! and a muted laptop sends -144. After that the laptop volume keys drive the
//! TV, and TV-remote changes (`dvlc`) move the laptop slider: two-way sync.
//! Loops are broken by comparing VALUES (never by counting events).
//!
//! Decisions taken here that are the user's to revisit:
//! * laptop 0 % sends -144 (mute), not -30 (which is audible);
//! * laptop > 100 % (boost) is clamped for the MAPPING (there is no headroom
//!   above 0 dB on the AirPlay scale) but NOT for the reading: the raw
//!   percent is kept, and a boost sends just under 0 dB rather than 0 dB —
//!   see "0 dB is AirPlay MAXIMUM" below;
//! * there is no start-of-session cap: a laptop at 100 % sends 0 dB, with a
//!   warning in the log.
//!
//! # 0 dB is AirPlay MAXIMUM, so it can never be sent by accident
//!
//! A SET body can only be produced by [`TvVolume::set_body`]. [`TvVolume`] has
//! no `Default`, no `From<f32/f64>`, no public field; its only constructors
//! are [`TvVolume::mute`] and [`TvVolume::from_laptop`], and a [`LaptopLevel`]
//! can only come from [`LaptopLevel::from_pactl`], i.e. from parsing a real
//! read of the laptop's sink. So the only way to put 0 dB on the wire is for
//! the laptop to read exactly 100 % and unmuted. The volume the TV reports
//! back (`dvlc`, GET) is bookkept as a plain number and can never be turned
//! into a `TvVolume`.
//!
//! "Exactly 100 %" means the RAW percent, not a clamped one. PipeWire sinks
//! go above 100 % (pavucontrol reaches 153 %, `wpctl set-volume` without a
//! limit goes anywhere, and WirePlumber restores a remembered boost), and a
//! read that clamped 150 % down to 100 % would be indistinguishable from a
//! slider genuinely at the top — 0 dB, AirPlay MAXIMUM, from a level the user
//! never chose. So [`LaptopLevel`] keeps [`LaptopLevel::raw_pct`] beside the
//! clamped [`LaptopLevel::pct`], and [`TvVolume::from_laptop`] sends
//! [`TvVolume::JUST_UNDER_MAX`] for anything above 100 %: inaudibly below the
//! top, but never [`TvVolume::is_max`]. The clamp stays where it belongs, in
//! the mapping; it is the *read* that must not lie.
//!
//! # Silence until the TV's volume is established ([`AudioGate`])
//!
//! Not sending 0 dB is only half of it: the TV may ALREADY be at maximum
//! (the Frame has been seen at 100 % at session start), and the only proven
//! SET is sent >= 2 s after the first audio packet. So the audio sender runs
//! behind an [`AudioGate`]: until the driver has SET the TV from the laptop's
//! level AND read that value back, every frame it sends is digital silence
//! (real packets with zeroed PCM, so the 0x90 anchor and the receiver's
//! timeline stay valid). Only the volume driver opens the gate, and only after
//! the verified read-back. Every failure (GET, laptop read, SET, read-back
//! mismatch, a later SET error, the audio stream dying) leaves it held, or
//! holds it again for good, with the reason in the status: the session stays
//! silent, it never falls through to playing at an unknown level. The one
//! exception is [`AudioGate::ungated`], for an explicit `--no-volume-sync`.

use crate::clock::{ClockReading, SenderClock};
use std::collections::VecDeque;
use std::io;
use std::process::{Child, Command, Stdio};
use crate::audio::AudioGate;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

// --------------------------------------------------------------------------
// Values
// --------------------------------------------------------------------------

/// The laptop's output level, as READ from its sink. Private fields: the only
/// constructor is [`LaptopLevel::from_pactl`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaptopLevel {
    pct: u8,
    /// The percent as READ, unclamped: 150 % stays 150. See the module docs —
    /// this is what keeps a boost from passing for a genuine 100 %.
    raw_pct: u32,
    muted: bool,
}

impl LaptopLevel {
    /// Parse the outputs of `pactl get-sink-volume` and `pactl get-sink-mute`.
    /// None unless both parse.
    pub fn from_pactl(volume_out: &str, mute_out: &str) -> Option<Self> {
        let raw_pct = parse_pactl_volume_raw(volume_out)?;
        Some(LaptopLevel {
            pct: raw_pct.min(100) as u8,
            raw_pct,
            muted: parse_pactl_mute(mute_out)?,
        })
    }

    /// 0..=100: the level as the TV mapping uses it (a boost reads 100).
    pub fn pct(&self) -> u8 {
        self.pct
    }

    /// The percent as it was actually read, which may be above 100.
    /// [`Self::pct`] is this clamped.
    pub fn raw_pct(&self) -> u32 {
        self.raw_pct
    }

    /// Is this sink above 100 % (a boost)? Then it is NOT a genuine maximum,
    /// whatever [`Self::pct`] says.
    pub fn boosted(&self) -> bool {
        self.raw_pct > 100
    }

    pub fn muted(&self) -> bool {
        self.muted
    }

    fn key(&self) -> (u8, bool) {
        (self.pct, self.muted)
    }
}

/// `pactl get-sink-volume` -> percent (the loudest channel, raw/65536,
/// rounded, clamped to 100). None on anything that is not a channel list of
/// integers.
///
/// The clamp makes this LOSSY above 100 %: use [`parse_pactl_volume_raw`]
/// (or [`LaptopLevel::raw_pct`]) wherever a boost must be distinguishable
/// from a slider genuinely at the top — verifying a value written back, or
/// deciding whether 0 dB (AirPlay MAXIMUM) may be sent.
///
/// ```text
/// Volume: front-left: 19660 /  30% / -31.37 dB,   front-right: 19660 /  30% / -31.37 dB
///         balance 0.00
/// ```
pub fn parse_pactl_volume(out: &str) -> Option<u8> {
    Some(parse_pactl_volume_raw(out)?.min(100) as u8)
}

/// [`parse_pactl_volume`] WITHOUT the clamp: 150 % answers 150, 337 % answers
/// 337. This is the honest read; the clamp belongs to the mapping, not here.
pub fn parse_pactl_volume_raw(out: &str) -> Option<u32> {
    let line = out.lines().find_map(|l| l.trim_start().strip_prefix("Volume:"))?;
    let mut max: Option<u64> = None;
    for seg in line.split(',') {
        let (_, rest) = seg.split_once(':')?;
        let raw: u64 = rest.split_whitespace().next()?.parse().ok()?;
        max = Some(max.map_or(raw, |m: u64| m.max(raw)));
    }
    let raw = max?;
    // round(raw * 100 / 65536), in integers.
    let pct = (raw * 100 + 32768) / 65536;
    Some(pct.min(u32::MAX as u64) as u32)
}

/// `pactl get-sink-mute` -> `Mute: yes|no`.
pub fn parse_pactl_mute(out: &str) -> Option<bool> {
    match out.lines().find_map(|l| l.trim().strip_prefix("Mute:"))?.trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// dB x 100 for mute.
const MUTE_X100: i32 = -14400;

/// An AirPlay volume we are allowed to SEND. See the module docs: it can only
/// be built from a real laptop read (or be mute).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TvVolume(i32 /* dB x 100 */);

impl TvVolume {
    /// -144 dB.
    pub fn mute() -> Self {
        TvVolume(MUTE_X100)
    }

    /// The loudest value a laptop that is NOT at a genuine 100 % can produce:
    /// -0.01 dB. Inaudibly below the top, and [`Self::is_max`] is false, so
    /// the module's invariant ("only an exact, unclamped 100 % sends 0 dB")
    /// survives a boosted sink.
    pub const JUST_UNDER_MAX: i32 = -1;

    /// the user's linear mapping: muted or 0 % -> -144 (mute); else
    /// `-30 + 30 x pct/100` dB (1 % -> -29.7, 50 % -> -15, 100 % -> 0 = MAX).
    ///
    /// A boosted sink (raw > 100 %) has no headroom to map to — 0 dB is the
    /// top of the AirPlay scale — so it sends [`Self::JUST_UNDER_MAX`]
    /// instead of 0 dB. That is not a safety cap on the level (it is 0.01 dB
    /// down, which nobody hears); it is what keeps 0 dB reachable ONLY from a
    /// slider genuinely at 100 %, so a WirePlumber-restored 337 % or a
    /// pavucontrol boost cannot manufacture an AirPlay maximum the user never set.
    pub fn from_laptop(l: LaptopLevel) -> Self {
        let pct = l.pct.min(100) as i32;
        if l.muted || pct == 0 {
            TvVolume::mute()
        } else if l.boosted() {
            TvVolume(TvVolume::JUST_UNDER_MAX)
        } else {
            TvVolume(-3000 + 30 * pct)
        }
    }

    pub fn db(&self) -> f64 {
        self.0 as f64 / 100.0
    }

    pub fn db_x100(&self) -> i32 {
        self.0
    }

    /// 0 dB: AirPlay maximum.
    pub fn is_max(&self) -> bool {
        self.0 == 0
    }

    pub fn is_mute(&self) -> bool {
        self.0 == MUTE_X100
    }

    /// `volume: <dB>.6f\r\n`, the SET_PARAMETER body.
    pub fn set_body(&self) -> Vec<u8> {
        volume_body_text(self.0).into_bytes()
    }
}

/// The text of a volume SET body for `db_x100` hundredths of a dB. Formatting
/// only: it returns a String, not something a transport accepts, so it does
/// not open a path around [`TvVolume`].
pub fn volume_body_text(db_x100: i32) -> String {
    format!("volume: {:.6}\r\n", db_x100 as f64 / 100.0)
}

/// Parse a `GET_PARAMETER volume` reply body (`volume: -20.400000\r\n`).
/// Finite values only.
pub fn parse_get_parameter_volume(body: &[u8]) -> Option<f64> {
    let text = std::str::from_utf8(body).ok()?;
    let v: f64 = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("volume:"))?
        .trim()
        .parse()
        .ok()?;
    v.is_finite().then_some(v)
}

/// A TV volume in dB -> (laptop %, muted). At or below -30.5 dB is mute
/// (the scale's floor is -30; -144 is mute).
pub fn laptop_pct_from_tv_db(db: f64) -> Option<(u8, bool)> {
    if !db.is_finite() {
        return None;
    }
    if db <= -30.5 {
        return Some((0, true));
    }
    let pct = ((db + 30.0) / 30.0 * 100.0).round().clamp(0.0, 100.0);
    Some((pct as u8, false))
}

/// A `dvlc` event (volume 0..1, isMuted) -> (laptop %, muted).
pub fn laptop_pct_from_dvlc(v: f64, muted: bool) -> Option<(u8, bool)> {
    if !v.is_finite() {
        return None;
    }
    Some(((v.clamp(0.0, 1.0) * 100.0).round() as u8, muted))
}

/// What a TV value (dB x 100) means as a laptop % (for echo comparison).
fn pct_of_x100(db_x100: i32) -> Option<u8> {
    if db_x100 == MUTE_X100 {
        None
    } else {
        Some(((db_x100 + 3000) as f64 / 30.0).round().clamp(0.0, 100.0) as u8)
    }
}

/// Two laptop states are the same if equal, or if both are muted (a muted
/// sink's slider position is not what the TV hears).
fn same_laptop(a: (u8, bool), b: (u8, bool)) -> bool {
    (a.1 && b.1) || a == b
}

/// Does a TV report of (pct, muted) match the value we last put on it?
fn tv_matches(db_x100: i32, pct: u8, muted: bool) -> bool {
    match pct_of_x100(db_x100) {
        None => muted || pct == 0,
        Some(p) => !muted && (p as i32 - pct as i32).abs() <= 1,
    }
}

// --------------------------------------------------------------------------
// RTSP forms (pinned to the probe's bytes by tests/vectors.rs)
// --------------------------------------------------------------------------

pub const VOLUME_CONTENT_TYPE: &str = "text/parameters";
pub const VOLUME_GET_BODY: &[u8] = b"volume\r\n";
/// Per-request timeout for volume requests: short, so a wedged receiver
/// cannot hold the control connection (and the session's teardown) long.
/// Kept well below [`VOLUME_JOIN_BOUND`], so a volume request in flight
/// always ends before the session gives up joining the volume thread (and
/// never still holds the control lock when TEARDOWN wants it).
pub const VOLUME_REQUEST_TIMEOUT: Duration = Duration::from_millis(1500);
/// How long stopping the volume thread waits for it ([`VolumeHandle`]'s
/// `Drop`; the session's `stop_audio` should use this too).
pub const VOLUME_JOIN_BOUND: Duration = Duration::from_secs(2);
/// A start read-back within this of the value we SET counts as applied.
/// Only one read-back was ever observed on the Frame (-24.9 dB SET, -24.9
/// dB read), so this is a guess; a mismatch fails SAFE (silence), never loud.
pub const READBACK_TOLERANCE_DB: f64 = 0.5;

/// Does a GET read-back of `db` show that `v` was applied? Mute must read
/// back as mute (at or below -30.5 dB; the audible floor is -30).
pub fn readback_matches(v: &TvVolume, db: f64) -> bool {
    if !db.is_finite() {
        return false;
    }
    if v.is_mute() {
        db <= -30.5
    } else {
        (db - v.db()).abs() <= READBACK_TOLERANCE_DB
    }
}

/// The GET_PARAMETER request, as [`RtspTvVolume::get`] sends it.
pub fn volume_get_request(uri: &str, cseq: u32) -> Vec<u8> {
    crate::rtsp::build_request("GET_PARAMETER", uri, cseq, &[], &[], Some(VOLUME_CONTENT_TYPE), VOLUME_GET_BODY)
}

/// The SET_PARAMETER request, as [`RtspTvVolume::set`] sends it: audio URI,
/// NO Session header (the one form proven by read-back).
pub fn volume_set_request(uri: &str, cseq: u32, v: &TvVolume) -> Vec<u8> {
    crate::rtsp::build_request("SET_PARAMETER", uri, cseq, &[], &[], Some(VOLUME_CONTENT_TYPE), &v.set_body())
}

// --------------------------------------------------------------------------
// Transports
// --------------------------------------------------------------------------

/// The laptop side.
pub trait LaptopVolume: Send {
    fn read(&mut self) -> io::Result<LaptopLevel>;
    /// Muted: set mute only (the slider keeps its place). Unmuted: set the
    /// level, then unmute.
    fn set(&mut self, pct: u8, muted: bool) -> io::Result<()>;
    /// Change notifications. Called once.
    fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>>;
    /// The default output may have changed: re-resolve which sink to follow.
    /// True if the sink being followed is now a different one.
    fn refresh_target(&mut self) -> bool {
        false
    }
    /// The single sink this transport is bound to and may write, if it is
    /// fixed to one. `None` means it follows the default output.
    ///
    /// In sink mode this is the sink the sender published itself, and that
    /// binding is what makes writing a hardware sink structurally
    /// unreachable: a `dvlc` from the TV remote moves our own slider, never
    /// the speakers'.
    fn bound_sink(&self) -> Option<&str> {
        None
    }
    /// For a fixed binding: is that sink still the laptop's output?
    /// `None` when unknown, or when the transport follows the default anyway.
    fn still_default(&mut self) -> Option<bool> {
        None
    }
    /// The sink the laptop's output is on RIGHT NOW, whatever it is (not
    /// "is it ours?" — the name). `None` means unknown: a read that failed,
    /// or a transport that has no such notion.
    ///
    /// The driver samples this once before the start sequence and again just
    /// before the handover, so an output the user (or WirePlumber) moved during
    /// the several-second gate window is never quietly taken from him. Like
    /// [`Self::still_default`], a failed read must answer `None`, never a
    /// wrong name.
    fn current_default(&mut self) -> Option<String> {
        None
    }
    /// "pactl" or "fake".
    fn describe(&self) -> String;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaptopEvent {
    /// Some sink changed (re-read and compare).
    Change,
    /// The server changed (e.g. a new default sink).
    DefaultChanged,
}

/// The TV side.
pub trait TvVolumeTransport: Send {
    /// Current volume in dB.
    fn get(&mut self) -> io::Result<f64>;
    /// SET; Ok(status) when the receiver accepted it (200 or the Frame's 500).
    fn set(&mut self, v: &TvVolume) -> io::Result<u16>;
}

/// Production TV transport: the encrypted control connection, audio URI.
pub struct RtspTvVolume {
    control: crate::session::ControlConn,
    uri: String,
}

impl RtspTvVolume {
    pub fn new(control: crate::session::ControlConn, audio_uri: String) -> Self {
        RtspTvVolume { control, uri: audio_uri }
    }

    fn exchange(&mut self, method: &str, body: &[u8]) -> io::Result<(u16, Vec<u8>)> {
        let mut c = self
            .control
            .0
            .lock()
            .map_err(|_| io::Error::other("control connection lock poisoned"))?;
        let (status, msg) = c
            .request(method, &self.uri, &[], Some(VOLUME_CONTENT_TYPE), body, Some(VOLUME_REQUEST_TIMEOUT))
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok((status, msg.body))
    }
}

impl TvVolumeTransport for RtspTvVolume {
    fn get(&mut self) -> io::Result<f64> {
        let (status, body) = self.exchange("GET_PARAMETER", VOLUME_GET_BODY)?;
        if status != 200 {
            return Err(io::Error::other(format!("GET_PARAMETER volume returned {status}")));
        }
        parse_get_parameter_volume(&body).ok_or_else(|| io::Error::other("unparseable GET_PARAMETER volume reply"))
    }

    fn set(&mut self, v: &TvVolume) -> io::Result<u16> {
        let (status, _) = self.exchange("SET_PARAMETER", &v.set_body())?;
        if crate::session::volume_success(status) {
            Ok(status)
        } else {
            Err(io::Error::other(format!("SET_PARAMETER volume returned {status}")))
        }
    }
}

/// Production laptop transport: `pactl`, on the sink the user's volume keys drive
/// (`omarchy-audio-output-sink`, falling back to the default sink).
pub struct PactlVolume {
    sink: String,
    fixed: bool,
    child: Option<Child>,
}

pub const OMARCHY_OUTPUT_SINK: &str = "/usr/bin/omarchy-audio-output-sink";

fn pactl() -> Command {
    let mut c = Command::new("pactl");
    c.env("LC_ALL", "C");
    c
}

fn run_ok(mut c: Command) -> io::Result<String> {
    let out = c.stderr(Stdio::null()).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!("{c:?} exited {}", out.status)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The sink the volume keys drive. Read-only.
pub fn resolve_output_sink() -> io::Result<String> {
    if std::path::Path::new(OMARCHY_OUTPUT_SINK).exists() {
        if let Ok(s) = run_ok(Command::new(OMARCHY_OUTPUT_SINK)) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Ok(s);
            }
        }
    }
    let mut c = pactl();
    c.arg("get-default-sink");
    let s = run_ok(c)?.trim().to_string();
    if s.is_empty() {
        return Err(io::Error::other("no default sink"));
    }
    Ok(s)
}

impl PactlVolume {
    /// Follow the output the volume keys drive, re-resolving on server change.
    pub fn follow_output() -> io::Result<Self> {
        Ok(PactlVolume {
            sink: resolve_output_sink()?,
            fixed: false,
            child: None,
        })
    }

    /// A sink this process owns: the published AirPlay sink
    /// ([`crate::audiosink`]) in production, or a test's own null sink.
    ///
    /// `fixed` makes [`Self::refresh_target`] a permanent no-op, so this
    /// transport can only ever read and write the one sink it was given.
    /// That is deliberate and load-bearing: with `follow_output` and a
    /// mid-session default change, a `dvlc` from the TV remote would write
    /// the user's *hardware* volume.
    pub fn for_sink(sink: &str) -> Self {
        PactlVolume {
            sink: sink.to_string(),
            fixed: true,
            child: None,
        }
    }

    pub fn sink(&self) -> &str {
        &self.sink
    }
}

impl LaptopVolume for PactlVolume {
    fn read(&mut self) -> io::Result<LaptopLevel> {
        let mut v = pactl();
        v.args(["get-sink-volume", &self.sink]);
        let mut m = pactl();
        m.args(["get-sink-mute", &self.sink]);
        let (vo, mo) = (run_ok(v)?, run_ok(m)?);
        LaptopLevel::from_pactl(&vo, &mo).ok_or_else(|| io::Error::other(format!("unparseable pactl output: {vo:?} {mo:?}")))
    }

    fn set(&mut self, pct: u8, muted: bool) -> io::Result<()> {
        if muted {
            let mut c = pactl();
            c.args(["set-sink-mute", &self.sink, "1"]);
            run_ok(c)?;
        } else {
            let mut c = pactl();
            c.args(["set-sink-volume", &self.sink, &format!("{}%", pct.min(100))]);
            run_ok(c)?;
            let mut c = pactl();
            c.args(["set-sink-mute", &self.sink, "0"]);
            run_ok(c)?;
        }
        Ok(())
    }

    fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>> {
        use std::io::BufRead;
        use std::os::unix::process::CommandExt;
        let mut c = pactl();
        c.arg("subscribe").stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null());
        // SAFETY: prctl is async-signal-safe; this only asks the kernel to
        // SIGTERM the child if we die (e.g. the second Ctrl-C), so a
        // `pactl subscribe` can never outlive the session.
        unsafe {
            c.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let mut child = c.spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| io::Error::other("no pactl stdout"))?;
        self.child = Some(child);
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("airplay-pactl-sub".into())
            .spawn(move || {
                for line in io::BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let ev = if line.contains("'change' on sink #") {
                        LaptopEvent::Change
                    } else if line.contains("'change' on server") {
                        LaptopEvent::DefaultChanged
                    } else {
                        continue;
                    };
                    if tx.send(ev).is_err() {
                        break;
                    }
                }
            })?;
        Ok(rx)
    }

    fn refresh_target(&mut self) -> bool {
        if !self.fixed {
            if let Ok(s) = resolve_output_sink() {
                if s != self.sink {
                    eprintln!("volume: laptop output changed: {} -> {s}", self.sink);
                    self.sink = s;
                    return true;
                }
            }
        }
        false
    }

    fn bound_sink(&self) -> Option<&str> {
        self.fixed.then_some(self.sink.as_str())
    }

    /// One `pactl` call. A read that fails answers `None` ("unknown"), never
    /// `false`: a transient failure must not look like the user moving his
    /// output, which would detach the session for good.
    fn still_default(&mut self) -> Option<bool> {
        if !self.fixed {
            return None;
        }
        resolve_output_sink().ok().map(|s| s == self.sink)
    }

    /// The same single fact [`Self::still_default`] compares against, by
    /// name. One `pactl` call; a failure answers `None` ("unknown").
    fn current_default(&mut self) -> Option<String> {
        resolve_output_sink().ok()
    }

    fn describe(&self) -> String {
        format!("pactl sink {}", self.sink)
    }
}

impl Drop for PactlVolume {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// --------------------------------------------------------------------------
// The policy (pure, clock-injected)
// --------------------------------------------------------------------------

/// A laptop value that equals the one we just set it to, within this window,
/// is our own echo.
pub const LAPTOP_ECHO_WINDOW: Duration = Duration::from_secs(2);
/// A dvlc within +-1 % of ANY value we SET the TV to within this window is
/// the TV echoing that SET, never a remote press. The probe measured SET ->
/// echo delays of 3.7 s and 6.0 s (and a possible 14.5 s); 10 s covers the
/// two sure ones. UNPROVEN: the real distribution needs the TV.
pub const DVLC_ECHO_WINDOW: Duration = Duration::from_secs(10);
/// How many recent SETs are remembered for echo matching (a bound only; the
/// window is what normally ages them out).
const SENT_HISTORY_MAX: usize = 64;
/// A dvlc this soon after an `updateInfo` is dropped (the spurious 0.0).
pub const UPDATE_INFO_GUARD: Duration = Duration::from_millis(100);
/// A dvlc of 0.0 (not muted) this soon after an `updateInfo`, or the first
/// dvlc after one whatever the delay, is taken for the spurious 0.0 the
/// Frame sends with every `updateInfo` (probe run 071704).
pub const UPDATE_INFO_ZERO_GUARD: Duration = Duration::from_secs(2);
/// Laptop changes are coalesced: SET once the value has been still this long...
pub const COALESCE_QUIET: Duration = Duration::from_millis(100);
/// ...or once a burst has gone on this long (so a held key still moves the TV).
pub const COALESCE_MAX: Duration = Duration::from_millis(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolAction {
    SetTv(TvVolume),
    SetLaptop { pct: u8, muted: bool },
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    level: LaptopLevel,
    first: ClockReading,
    last: ClockReading,
}

/// The two-way sync policy. Pure: the driver feeds it events and a clock and
/// performs the actions it returns.
#[derive(Debug, Default)]
pub struct VolumeSync {
    armed: bool,
    /// What we believe the TV is at (dB x 100) and when that was set — by our
    /// SET, or by a dvlc we accepted. Bookkeeping only; never sent.
    last_to_tv: Option<(i32, ClockReading)>,
    /// Every value we SET the TV to recently (dB x 100), for echo matching.
    sent_to_tv: VecDeque<(i32, ClockReading)>,
    /// What we last set the laptop to, and when.
    last_to_laptop: Option<((u8, bool), ClockReading)>,
    last_update_info: Option<ClockReading>,
    /// No dvlc has been seen since the last `updateInfo`.
    first_dvlc_after_update_info: bool,
    pending: Option<Pending>,
    /// After the followed sink changed: that sink's level when we switched to
    /// it. Not a key press, so it is never sent to the TV.
    baseline: Option<(u8, bool)>,
    /// The laptop level the USER last chose (at start, or a key press) — what
    /// the laptop goes back to at the end if the TV remote moved it.
    user_level: Option<(u8, bool)>,
    /// The followed sink changed during the session (no restore then).
    target_changed: bool,
}

impl VolumeSync {
    pub fn new() -> Self {
        Self::default()
    }

    fn record_sent(&mut self, x: i32, now: ClockReading) {
        self.sent_to_tv.retain(|(_, t)| now.since(t) <= DVLC_ECHO_WINDOW);
        while self.sent_to_tv.len() >= SENT_HISTORY_MAX {
            self.sent_to_tv.pop_front();
        }
        self.sent_to_tv.push_back((x, now));
    }

    /// Session start: the TV takes the laptop's level. Returns the value to
    /// SET. Not armed yet; the driver arms after its read-back and grace.
    pub fn on_start(&mut self, laptop: LaptopLevel, now: ClockReading) -> TvVolume {
        let v = TvVolume::from_laptop(laptop);
        self.last_to_tv = Some((v.db_x100(), now));
        self.record_sent(v.db_x100(), now);
        self.user_level = Some(laptop.key());
        v
    }

    /// The same value SET again (the start retry): an echo candidate again.
    pub fn on_resent(&mut self, v: &TvVolume, now: ClockReading) {
        self.last_to_tv = Some((v.db_x100(), now));
        self.record_sent(v.db_x100(), now);
    }

    pub fn arm(&mut self) {
        self.armed = true;
    }

    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// What we believe the TV is at, dB x 100.
    pub fn believed_tv_x100(&self) -> Option<i32> {
        self.last_to_tv.map(|(v, _)| v)
    }

    /// A fresh read of the laptop after a change notification. Queues a
    /// coalesced SET unless the value is our own echo or already on the TV.
    /// Laptop changes before arming are queued too, and go out once armed.
    pub fn on_laptop_change(&mut self, l: LaptopLevel, now: ClockReading) {
        if let Some((k, t)) = self.last_to_laptop {
            if same_laptop(k, l.key()) && now.since(&t) <= LAPTOP_ECHO_WINDOW {
                return; // our own SetLaptop coming back
            }
        }
        if let Some(b) = self.baseline {
            if same_laptop(b, l.key()) {
                // Still the level the new sink had when we switched to it.
                return;
            }
            self.baseline = None;
        }
        self.user_level = Some(l.key());
        if self.last_to_tv.map(|(v, _)| v) == Some(TvVolume::from_laptop(l).db_x100()) {
            // Already what the TV is at (or the laptop came back to it).
            self.pending = None;
            return;
        }
        self.pending = Some(match self.pending {
            Some(p) => Pending { level: l, first: p.first, last: now },
            None => Pending { level: l, first: now, last: now },
        });
    }

    /// The followed sink is now a different one (a new default output, not a
    /// key press): re-baseline on its level `l` and send NOTHING to the TV.
    /// Only later changes on this sink drive the TV.
    pub fn on_target_changed(&mut self, l: LaptopLevel) {
        self.pending = None;
        self.baseline = Some(l.key());
        self.target_changed = true;
    }

    /// The receiver sent `updateInfo`.
    pub fn on_update_info(&mut self, now: ClockReading) {
        self.last_update_info = Some(now);
        self.first_dvlc_after_update_info = true;
    }

    /// A `dvlc` from the TV (its remote, or the echo of our SET).
    pub fn on_dvlc(&mut self, v: f64, muted: bool, now: ClockReading) -> Option<VolAction> {
        let first_after_ui = std::mem::take(&mut self.first_dvlc_after_update_info);
        if !self.armed {
            return None;
        }
        if let Some(t) = self.last_update_info {
            if now.since(&t) <= UPDATE_INFO_GUARD {
                return None;
            }
        }
        let (pct, m) = laptop_pct_from_dvlc(v, muted)?;
        if pct == 0 && !m {
            if let Some(t) = self.last_update_info {
                if first_after_ui || now.since(&t) <= UPDATE_INFO_ZERO_GUARD {
                    return None; // the spurious 0.0 that follows updateInfo
                }
            }
        }
        if self.pending.is_some() {
            // The laptop is being changed right now; its SET will win.
            return None;
        }
        if let Some((x, _)) = self.last_to_tv {
            if tv_matches(x, pct, m) {
                return None; // no change from what the TV is at
            }
        }
        if self.sent_to_tv.iter().any(|(x, t)| now.since(t) <= DVLC_ECHO_WINDOW && tv_matches(*x, pct, m)) {
            // A (late) echo of one of our SETs: never a reason to move the
            // laptop or to rewrite what we believe the TV is at.
            return None;
        }
        self.last_to_laptop = Some(((pct, m), now));
        // The TV is now at this value; bookkeeping in dB x 100.
        let x = if m || pct == 0 { MUTE_X100 } else { -3000 + 30 * pct as i32 };
        self.last_to_tv = Some((x, now));
        Some(VolAction::SetLaptop { pct, muted: m })
    }

    /// Call every tick; emits the coalesced SET once due.
    pub fn on_tick(&mut self, now: ClockReading) -> Option<VolAction> {
        if !self.armed {
            return None;
        }
        let p = self.pending?;
        if now.since(&p.last) < COALESCE_QUIET && now.since(&p.first) < COALESCE_MAX {
            return None;
        }
        self.pending = None;
        let v = TvVolume::from_laptop(p.level);
        if self.last_to_tv.map(|(x, _)| x) == Some(v.db_x100()) {
            return None;
        }
        self.last_to_tv = Some((v.db_x100(), now));
        self.record_sent(v.db_x100(), now);
        Some(VolAction::SetTv(v))
    }

    /// Session end: the laptop level to put back, if the TV remote was the
    /// last to move it (the laptop still reads what we set it to) and it
    /// differs from what the user last chose. None if the followed sink
    /// changed during the session (the saved level belongs to another sink).
    pub fn restore_level(&self, current: LaptopLevel) -> Option<(u8, bool)> {
        if self.target_changed {
            return None;
        }
        let ((k, _), user) = (self.last_to_laptop?, self.user_level?);
        if !same_laptop(k, current.key()) || same_laptop(user, current.key()) {
            return None;
        }
        Some(user)
    }
}

// --------------------------------------------------------------------------
// The driver thread
// --------------------------------------------------------------------------

/// Volume status for `airplay status`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VolumeStatus {
    /// "waiting for audio", "starting", "armed", "disabled: ...", "error: ...".
    pub state: String,
    /// Last TV volume read back or reported (dB).
    pub tv_volume_db: Option<f64>,
    pub tv_muted: Option<bool>,
    pub laptop_pct: Option<u8>,
    pub laptop_muted: Option<bool>,
    pub sets_to_tv: u64,
    pub sets_to_laptop: u64,
}

pub type StatusSink = Arc<Mutex<VolumeStatus>>;

/// Delays of the start sequence (production: 2 s / 1 s / 1 s, tick 20 ms).
#[derive(Clone, Copy, Debug)]
pub struct VolumeTiming {
    /// After the first audio packet, before the first GET (probe: 2 s).
    pub start_delay: Duration,
    /// After the start SET, before the read-back GET (probe: 1 s).
    pub readback_delay: Duration,
    /// After the read-back, before dvlc is honoured.
    pub arm_grace: Duration,
    pub tick: Duration,
}

impl Default for VolumeTiming {
    fn default() -> Self {
        VolumeTiming {
            start_delay: Duration::from_secs(2),
            readback_delay: Duration::from_secs(1),
            arm_grace: Duration::from_secs(1),
            tick: Duration::from_millis(20),
        }
    }
}

/// What the driver knows about the sender's own published sink
/// ([`crate::audiosink`]). All three parts are `None` in monitor mode
/// (`--audio-capture pipewire`/`parec`), where there is no such sink.
#[derive(Default)]
pub struct SinkBinding {
    /// The output the sink recorded at PUBLISH time
    /// ([`crate::audiosink::AirPlaySink::previous_default`]) — the one it will
    /// put back, and so the one the handover is allowed to take.
    ///
    /// It is the baseline for the pre-handover check, in preference to a
    /// sample this driver takes itself. The driver's own sample is taken when
    /// the volume thread starts, which is already later than publish, so a
    /// change in that gap would be baked into the baseline and read as "the
    /// output never moved" — the driver would hand over an output the user had
    /// already left, and the sink would then put the pre-session one back over
    /// his newer choice at the end. Taking the baseline from the sink itself
    /// closes that window: the two are then the same fact.
    ///
    /// `None` in monitor mode, and in any rig with no sink.
    pub expected_default: Option<String>,
    /// Refuse to run at all unless the laptop transport is bound to exactly
    /// this sink. Proved, not assumed: if the binding were ever wrong, a
    /// `dvlc` from the TV would write somebody else's volume.
    pub require_sink: Option<String>,
    /// Called once, the instant the gate opens — i.e. the moment the TV's
    /// level has been set from the laptop's and read back. This is where the
    /// output is handed over ([`crate::audiosink::AirPlaySink::take_default`]),
    /// so the speakers keep playing right up to the moment the TV starts
    /// making sound, and so a TV that never answers never costs the user their
    /// output. `Err` holds the gate: silent audio, output untouched.
    pub on_open: Option<Box<dyn FnOnce() -> Result<(), String> + Send>>,
    /// Called once if the laptop's output is changed away from our sink —
    /// either mid-session (the user picked another output himself) or during the
    /// gate window, before the handover. The session keeps its video, the
    /// gate is held for good, and the sink stops claiming the output back.
    ///
    /// CONTRACT for whoever fills this in: dropping the claim is not enough.
    /// Once this fires the sender is gated to digital silence for the rest of
    /// the session and nothing re-opens it, so the published node must be
    /// taken down too. Left up, it is still listed as an output, and picking
    /// it — the obvious reaction to the TV going quiet — routes every stream
    /// into a sink that makes no sound anywhere. The hook, not this module,
    /// owns the node, so this is a requirement on the caller.
    pub on_detach: Option<Box<dyn FnOnce() + Send>>,
}

/// Handle to the sync thread; `Drop` stops it and joins for at most
/// [`VOLUME_JOIN_BOUND`].
pub struct VolumeHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    status: StatusSink,
    gate: AudioGate,
}

impl VolumeHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn status(&self) -> VolumeStatus {
        self.status.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The gate this sync opens once the TV's volume is established.
    pub fn gate(&self) -> AudioGate {
        self.gate.clone()
    }

    /// Stop and wait at most `bound` (detaching after that). Returns the
    /// final status.
    pub fn join(mut self, bound: Duration) -> VolumeStatus {
        self.join_inner(bound);
        self.status()
    }

    fn join_inner(&mut self, bound: Duration) {
        self.stop();
        if let Some(h) = self.join.take() {
            let deadline = Instant::now() + bound;
            while !h.is_finished() {
                if Instant::now() >= deadline {
                    eprintln!("volume: sync thread did not stop within {bound:?}; detaching it");
                    // Whatever it was doing, no real audio from here on.
                    self.gate.hold("volume sync did not stop in time");
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = h.join();
        }
    }
}

impl Drop for VolumeHandle {
    fn drop(&mut self) {
        if self.join.is_some() {
            self.join_inner(VOLUME_JOIN_BOUND);
        }
    }
}

/// [`spawn_volume_sync_gated`] with a fresh held gate, available from
/// [`VolumeHandle::gate`]. NOTE: an audio sender spawned BEFORE this call
/// cannot be behind that gate; the session must create the gate first and
/// use [`spawn_volume_sync_gated`].
pub fn spawn_volume_sync(
    laptop: Box<dyn LaptopVolume>,
    tv: Box<dyn TvVolumeTransport>,
    rx_events: Receiver<crate::session::ReceiverEvent>,
    audio_events: Receiver<crate::audio::AudioEvent>,
    clock: Arc<dyn SenderClock>,
    status: StatusSink,
    timing: VolumeTiming,
) -> VolumeHandle {
    spawn_volume_sync_gated(
        laptop,
        tv,
        rx_events,
        audio_events,
        clock,
        status,
        timing,
        AudioGate::held(crate::audio::GATE_WAITING_FOR_VOLUME),
        SinkBinding::default(),
    )
}

/// Start the two-way sync. Nothing is sent to either side until the audio
/// sender reports [`crate::audio::AudioEvent::FirstPacketSent`] and the
/// start delay has passed. `gate` (shared with the audio sender) is opened
/// only once the start SET has been read back from the TV; on every failure
/// it stays held or is failed, so the session stays silent rather than
/// playing at the TV's own (possibly maximum) level.
#[allow(clippy::too_many_arguments)]
pub fn spawn_volume_sync_gated(
    laptop: Box<dyn LaptopVolume>,
    tv: Box<dyn TvVolumeTransport>,
    rx_events: Receiver<crate::session::ReceiverEvent>,
    audio_events: Receiver<crate::audio::AudioEvent>,
    clock: Arc<dyn SenderClock>,
    status: StatusSink,
    timing: VolumeTiming,
    gate: AudioGate,
    binding: SinkBinding,
) -> VolumeHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let (stop_t, status_t, gate_t) = (stop.clone(), status.clone(), gate.clone());
    let join = std::thread::Builder::new()
        .name("airplay-volume".into())
        .spawn(move || {
            let mut d = Driver {
                laptop,
                tv,
                rx_events,
                audio_events,
                clock,
                status: status_t,
                stop: stop_t,
                sync: VolumeSync::new(),
                gate: gate_t,
                require_sink: binding.require_sink,
                expected_default: binding.expected_default,
                on_open: binding.on_open,
                on_detach: binding.on_detach,
            };
            d.run(timing);
            // Sync is over: no real audio without it.
            d.gate.hold("volume sync stopped");
            d.restore_laptop();
            // `laptop` (and its pactl subscribe child) drops here.
        })
        .expect("spawn volume thread");
    VolumeHandle {
        stop,
        join: Some(join),
        status,
        gate,
    }
}

/// How many times the pre-handover output read is attempted before the
/// answer is called unknown, and the gap between attempts.
const OUTPUT_RECHECK_TRIES: usize = 3;
const OUTPUT_RECHECK_GAP: Duration = Duration::from_millis(60);

/// What the pre-handover output check found.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OutputCheck {
    /// The laptop is on the same output it started on (or there was nothing
    /// to compare against): the handover may go ahead.
    Unchanged,
    /// It is on a different one now — a choice made during the gate window,
    /// naming the sink it is on.
    Moved(String),
    /// The read could not be made. Neither confirmed nor refuted.
    Unknown,
}

struct Driver {
    laptop: Box<dyn LaptopVolume>,
    tv: Box<dyn TvVolumeTransport>,
    rx_events: Receiver<crate::session::ReceiverEvent>,
    audio_events: Receiver<crate::audio::AudioEvent>,
    clock: Arc<dyn SenderClock>,
    status: StatusSink,
    stop: Arc<AtomicBool>,
    sync: VolumeSync,
    gate: AudioGate,
    /// Sink mode: the sink the laptop transport MUST be bound to.
    require_sink: Option<String>,
    /// Sink mode: the output the sink recorded at publish time, which is the
    /// baseline the handover is checked against. See
    /// [`SinkBinding::expected_default`].
    expected_default: Option<String>,
    /// Sink mode: hand the laptop's output over, at gate-open.
    on_open: Option<Box<dyn FnOnce() -> Result<(), String> + Send>>,
    /// Sink mode: stop claiming the output, because the user took it.
    on_detach: Option<Box<dyn FnOnce() + Send>>,
}

impl Driver {
    fn set_state(&self, s: impl Into<String>) {
        let s = s.into();
        eprintln!("volume: {s}");
        self.status.lock().unwrap_or_else(|p| p.into_inner()).state = s;
    }

    /// Hold the gate (silence for the rest of the session: nothing here
    /// opens it again), then report.
    fn fail_silent(&self, s: impl Into<String>) {
        let s = s.into();
        self.gate.hold(format!("volume: {s}"));
        self.set_state(s);
    }

    fn status_mut(&self) -> std::sync::MutexGuard<'_, VolumeStatus> {
        self.status.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Drain receiver events that are not acted on yet, but still RECORD an
    /// `updateInfo` (its spurious dvlc 0.0 may be handled after arming).
    fn drain_events(&mut self) {
        while let Ok(ev) = self.rx_events.try_recv() {
            if let crate::session::ReceiverEvent::UpdateInfo = ev {
                self.sync.on_update_info(self.clock.read());
            }
        }
    }

    /// Has the audio stream died? (A capture error, or the sender gone.)
    fn audio_dead(&self) -> Option<String> {
        use crate::audio::AudioEvent;
        loop {
            match self.audio_events.try_recv() {
                Ok(AudioEvent::SourceError(e)) => return Some(format!("audio capture failed ({e})")),
                Ok(_) => {}
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => return Some("the audio sender ended".into()),
            }
        }
    }

    /// Sleep up to `d`, draining receiver events. False if stopped, or if
    /// the audio died (then the state says so and this parks until stopped).
    fn idle(&mut self, d: Duration) -> bool {
        let end = Instant::now() + d;
        loop {
            if self.stopped() {
                return false;
            }
            self.drain_events();
            if let Some(why) = self.audio_dead() {
                self.fail_silent(format!("disabled: audio stopped ({why})"));
                self.park();
                return false;
            }
            if Instant::now() >= end {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10).min(end.saturating_duration_since(Instant::now())));
        }
    }

    fn park(&self) {
        while !self.stopped() {
            while self.rx_events.try_recv().is_ok() {}
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Is the laptop still on the output it was on when this session's start
    /// sequence began? Answers the three states honestly — the middle one,
    /// "unknown", is the whole point: a failed read must never be reported as
    /// "unchanged" (we would seize an output that may not be ours to take)
    /// nor as "moved" (we would abandon a session over a `pactl` hiccup).
    ///
    /// `at_start` of `None` means there was nothing to compare against
    /// (monitor mode, or a transport with no notion of a default), and the
    /// caller proceeds exactly as it did before this check existed.
    fn output_moved_before_handover(&mut self, at_start: Option<&str>) -> OutputCheck {
        let Some(want) = at_start else {
            return OutputCheck::Unchanged;
        };
        // A read failing here is anomalous (several pactl calls have already
        // succeeded in this run), so retry briefly rather than throwing the
        // session away on one hiccup.
        for attempt in 0..OUTPUT_RECHECK_TRIES {
            if self.stopped() {
                return OutputCheck::Unknown;
            }
            match self.laptop.current_default() {
                Some(now) if now == want => return OutputCheck::Unchanged,
                Some(now) => return OutputCheck::Moved(now),
                None => {
                    if attempt + 1 < OUTPUT_RECHECK_TRIES {
                        std::thread::sleep(OUTPUT_RECHECK_GAP);
                    }
                }
            }
        }
        OutputCheck::Unknown
    }

    fn run(&mut self, timing: VolumeTiming) {
        use crate::audio::AudioEvent;
        // Before anything is read or sent: in sink mode the laptop transport
        // must be bound to the sink we published, and nothing else. Without
        // this the "the TV remote moves OUR slider" rule would hold only by
        // luck; with it, a wrong binding is a silent session instead of a
        // write to somebody else's volume.
        if let Some(want) = self.require_sink.clone() {
            let bound = self.laptop.bound_sink().map(|s| s.to_string());
            if bound.as_deref() != Some(want.as_str()) {
                self.fail_silent(format!(
                    "disabled: not bound to the AirPlay sink (want {want}, bound {bound:?}); audio held silent"
                ));
                return self.park();
            }
        }
        // Sink mode: which output the user is on BEFORE the start sequence. The
        // handover at the end of it is only allowed if this has not moved —
        // see `output_moved_before_handover`. Sampled once, here, so the
        // whole gate window (first packet + start delay + GET + SET +
        // read-back, 3-5 s in production) is covered. `None` in monitor
        // mode, and for any transport that cannot answer.
        //
        // It comes from the SINK when there is one (`expected_default`): that
        // is the value teardown will restore, and it was sampled at publish,
        // earlier than anything this thread could read. Only when there is no
        // such value — a rig, a transport with no notion of a default — does
        // this fall back to reading it here.
        let output_at_start = if self.on_open.is_some() {
            self.expected_default.clone().or_else(|| self.laptop.current_default())
        } else {
            None
        };
        self.set_state("waiting for audio");
        loop {
            if self.stopped() {
                return;
            }
            match self.audio_events.recv_timeout(Duration::from_millis(50)) {
                Ok(AudioEvent::FirstPacketSent(_)) => break,
                Ok(AudioEvent::SourceError(e)) => {
                    self.fail_silent(format!("disabled: audio capture failed ({e})"));
                    return self.park();
                }
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.fail_silent("disabled: audio ended before the first packet");
                    return self.park();
                }
            }
            self.drain_events();
        }
        self.set_state("starting");
        if !self.idle(timing.start_delay) {
            return;
        }
        // 1. GET: proves the volume path answers. On failure NOTHING is sent,
        //    and the audio stays silent for the whole session.
        match self.tv.get() {
            Ok(db) => {
                let mut st = self.status_mut();
                st.tv_volume_db = Some(db);
                st.tv_muted = laptop_pct_from_tv_db(db).map(|(_, m)| m);
            }
            Err(e) => {
                self.fail_silent(format!("disabled: GET failed ({e}); audio held silent"));
                return self.park();
            }
        }
        // 2. Subscribe before the read so no laptop change is missed.
        let laptop_rx = match self.laptop.subscribe() {
            Ok(rx) => rx,
            Err(e) => {
                self.fail_silent(format!("disabled: cannot watch the laptop volume ({e}); audio held silent"));
                return self.park();
            }
        };
        let l = match self.laptop.read() {
            Ok(l) => l,
            Err(e) => {
                self.fail_silent(format!("disabled: cannot read the laptop volume ({e}); audio held silent"));
                return self.park();
            }
        };
        {
            let mut st = self.status_mut();
            st.laptop_pct = Some(l.pct());
            st.laptop_muted = Some(l.muted());
        }
        // 3. The TV takes the laptop's level.
        let v = self.sync.on_start(l, self.clock.read());
        if v.is_max() {
            eprintln!("volume: WARN sending 0 dB (AirPlay MAX) because the laptop reads 100%");
        }
        eprintln!("volume: start: laptop {}%{} -> TV {:.1} dB", l.pct(), if l.muted() { " (muted)" } else { "" }, v.db());
        if let Err(e) = self.tv.set(&v) {
            self.fail_silent(format!("error: start SET failed ({e}); audio held silent"));
            return self.park();
        }
        self.status_mut().sets_to_tv += 1;
        // 4. Read back, and COMPARE: the Frame answers 500 whether or not it
        //    applied the SET. One re-SET on a mismatch; a failed GET is not
        //    retried (the control connection may be out of step after it).
        let mut resent = false;
        loop {
            if !self.idle(timing.readback_delay) {
                return;
            }
            let db = match self.tv.get() {
                Ok(db) => db,
                Err(e) => {
                    self.fail_silent(format!("error: read-back GET failed ({e}); TV volume unknown, audio held silent"));
                    return self.park();
                }
            };
            eprintln!("volume: TV reads back {db:.1} dB");
            {
                let mut st = self.status_mut();
                st.tv_volume_db = Some(db);
                st.tv_muted = laptop_pct_from_tv_db(db).map(|(_, m)| m);
            }
            if readback_matches(&v, db) {
                break;
            }
            if resent {
                self.fail_silent(format!(
                    "error: TV volume not established (SET {:.1} dB twice, TV reads {db:.1} dB); audio held silent",
                    v.db()
                ));
                return self.park();
            }
            eprintln!("volume: read-back {db:.1} dB is not the {:.1} dB we SET; sending it once more", v.db());
            if let Err(e) = self.tv.set(&v) {
                self.fail_silent(format!("error: start SET retry failed ({e}); audio held silent"));
                return self.park();
            }
            self.status_mut().sets_to_tv += 1;
            self.sync.on_resent(&v, self.clock.read());
            resent = true;
        }
        // The TV's level is now the laptop's, read back. THIS is the moment
        // the sound moves: the laptop's output becomes the AirPlay sink, so
        // the speakers go quiet exactly as the TV starts making sound.
        // Taking it any earlier (at publish time) would leave 3-4 seconds
        // audible NOWHERE; this way, if the TV never answers, the user never
        // loses his output at all.
        //
        // The handover runs just BEFORE the gate opens, not just after (the
        // plan said after): both orders are safe, because the TV's level is
        // already established either way, but this one makes the failure
        // atomic — a handover that fails means the gate never opened and not
        // one audible sample ever left, instead of a millisecond of real
        // audio followed by silence — and it puts the speakers' silence and
        // the TV's first sound in the right order rather than overlapping.
        //
        // But ONLY if the output is still the one this session started on.
        // The window above is seconds wide and it is exactly the window in
        // which the user plugs in headphones, or picks another output himself, or
        // WirePlumber moves the default on its own. Taking it then would
        // override a deliberate choice — the very thing `steady()`'s detach
        // rule refuses to do after arming — and silently, because once we
        // hold the default `still_default()` answers "yes, ours" and the
        // detach rule can never fire. Worse, the sink's `previous_default`
        // was snapshotted at publish time, so teardown would put THAT back
        // and erase the newer choice too.
        match self.output_moved_before_handover(output_at_start.as_deref()) {
            OutputCheck::Unchanged => {
                if let Some(f) = self.on_open.take() {
                    if let Err(e) = f() {
                        self.fail_silent(format!(
                            "error: could not hand the output to the AirPlay sink ({e}); \
                             audio held silent, the laptop keeps its output"
                        ));
                        return self.park();
                    }
                }
            }
            OutputCheck::Moved(now) => {
                // KNOWN not ours: the user's new choice is on the machine
                // right now. Drop the claim (so teardown cannot put the
                // pre-session sink back over it), keep the picture, stay
                // silent. Never take it back.
                self.on_open.take();
                if let Some(f) = self.on_detach.take() {
                    f();
                }
                self.fail_silent(format!(
                    "detached: the laptop's output was changed to {now} while the TV volume was \
                     being established; leaving that choice alone, audio held silent"
                ));
                return self.park();
            }
            OutputCheck::Unknown => {
                // UNSETTLED: we cannot tell whether it moved. Do not take the
                // output on a guess, and do not disown anything either — the
                // claim describes nothing we touched, so it stays as it is
                // for `--cleanup` and the next run.
                self.on_open.take();
                self.fail_silent(
                    "error: could not read which output the laptop is on; not taking it, \
                     audio held silent, the laptop keeps its output",
                );
                return self.park();
            }
        }
        // Real audio may flow.
        self.gate.open();
        eprintln!("volume: TV volume established and read back; audio gate open");
        // 5. Grace, then arm.
        if !self.idle(timing.arm_grace) {
            return;
        }
        self.sync.arm();
        self.set_state("armed");
        self.steady(laptop_rx, timing.tick);
    }

    fn steady(&mut self, laptop_rx: Receiver<LaptopEvent>, tick: Duration) {
        use crate::session::ReceiverEvent;
        let mut laptop_alive = true;
        // A sink switch whose new level could not be read yet: the next
        // successful read is the new baseline, not a key press.
        let mut need_baseline = false;
        while !self.stopped() {
            if let Some(why) = self.audio_dead() {
                self.fail_silent(format!("disabled: audio stopped ({why}); sync stopped"));
                return self.park();
            }
            // Laptop: any number of notifications -> one re-read.
            let mut changed = false;
            let mut default_changed = false;
            while laptop_alive {
                match laptop_rx.try_recv() {
                    Ok(LaptopEvent::Change) => changed = true,
                    Ok(LaptopEvent::DefaultChanged) => {
                        changed = true;
                        default_changed = true;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        laptop_alive = false;
                        eprintln!("volume: laptop change feed ended; laptop -> TV sync stops");
                    }
                }
            }
            // Sink mode: the user chose another output himself. Keep the
            // session and the picture, hold the gate (our sink receives
            // nothing now, so the TV is already getting silence), stop
            // claiming the output back, and never re-open — re-opening would
            // need a fresh GET/SET/read-back, and fighting for the default
            // would override an explicit choice.
            if default_changed && self.laptop.still_default() == Some(false) {
                if let Some(f) = self.on_detach.take() {
                    f();
                }
                self.fail_silent("detached: the laptop's output was changed; the TV is silent");
                return self.park();
            }
            if default_changed && self.laptop.refresh_target() {
                need_baseline = true;
            }
            if changed || need_baseline {
                if let Ok(l) = self.laptop.read() {
                    {
                        let mut st = self.status_mut();
                        st.laptop_pct = Some(l.pct());
                        st.laptop_muted = Some(l.muted());
                    }
                    if need_baseline {
                        need_baseline = false;
                        eprintln!(
                            "volume: laptop output switched; re-baselined at {}%{}, nothing sent to the TV",
                            l.pct(),
                            if l.muted() { " (muted)" } else { "" }
                        );
                        self.sync.on_target_changed(l);
                    } else {
                        self.sync.on_laptop_change(l, self.clock.read());
                    }
                }
            }
            // TV events.
            loop {
                match self.rx_events.try_recv() {
                    Ok(ReceiverEvent::Volume { v, muted }) => {
                        if let Some(VolAction::SetLaptop { pct, muted }) = self.sync.on_dvlc(v, muted, self.clock.read()) {
                            eprintln!("volume: TV remote -> laptop {pct}%{}", if muted { " (muted)" } else { "" });
                            match self.laptop.set(pct, muted) {
                                Ok(()) => {
                                    let mut st = self.status_mut();
                                    st.sets_to_laptop += 1;
                                    st.laptop_pct = Some(pct);
                                    st.laptop_muted = Some(muted);
                                    st.tv_volume_db = Some(if muted || pct == 0 { -144.0 } else { -30.0 + 0.3 * pct as f64 });
                                    st.tv_muted = Some(muted || pct == 0);
                                }
                                Err(e) => eprintln!("volume: setting the laptop failed ({e})"),
                            }
                        }
                    }
                    Ok(ReceiverEvent::UpdateInfo) => self.sync.on_update_info(self.clock.read()),
                    Ok(ReceiverEvent::Other(_)) => {}
                    Err(_) => break,
                }
            }
            if let Some(VolAction::SetTv(v)) = self.sync.on_tick(self.clock.read()) {
                if v.is_max() {
                    eprintln!("volume: WARN sending 0 dB (AirPlay MAX) because the laptop reads 100%");
                }
                match self.tv.set(&v) {
                    Ok(_) => {
                        let mut st = self.status_mut();
                        st.sets_to_tv += 1;
                        st.tv_volume_db = Some(v.db());
                        st.tv_muted = Some(v.is_mute());
                    }
                    Err(e) => {
                        // The TV's level is no longer known to follow the
                        // laptop, and the connection may be out of step.
                        self.fail_silent(format!("error: SET failed ({e}); sync stopped, audio held silent"));
                        return self.park();
                    }
                }
            }
            std::thread::sleep(tick);
        }
    }

    /// Session end: put the laptop back to the level the user last chose if
    /// the TV remote was the last to move it. Best effort (two pactl calls).
    ///
    /// In sink mode this restores the level of a sink that is about to be
    /// destroyed — a harmless no-op, and harmless *only* because the binding
    /// is fixed to our own sink. The restore that matters under that model
    /// ("the previous output comes back") is
    /// [`crate::audiosink::AirPlaySink`]'s `Drop`, not this.
    fn restore_laptop(&mut self) {
        if self.sync.last_to_laptop.is_none() || self.sync.target_changed {
            return;
        }
        let Ok(cur) = self.laptop.read() else { return };
        if let Some((pct, muted)) = self.sync.restore_level(cur) {
            eprintln!("volume: session end: laptop back to {pct}%{}", if muted { " (muted)" } else { "" });
            if let Err(e) = self.laptop.set(pct, muted) {
                eprintln!("volume: restoring the laptop failed ({e})");
            }
        }
    }
}

// ===================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;

    fn vol_out(raw: u32) -> String {
        format!(
            "Volume: front-left: {raw} /  x% / 0 dB,   front-right: {raw} /  x% / 0 dB\n        balance 0.00\n"
        )
    }

    /// A LaptopLevel through the only door there is: parsing pactl output.
    fn lvl(pct: u8, muted: bool) -> LaptopLevel {
        let raw = (pct as u32 * 65536 + 50) / 100;
        LaptopLevel::from_pactl(&vol_out(raw), if muted { "Mute: yes\n" } else { "Mute: no\n" }).unwrap()
    }

    fn at(c: &FakeClock) -> ClockReading {
        c.read()
    }

    #[test]
    fn parses_real_pactl_output() {
        let real = "Volume: front-left: 19660 /  30% / -31.37 dB,   front-right: 19660 /  30% / -31.37 dB\n        balance 0.00\n";
        assert_eq!(parse_pactl_volume(real), Some(30));
        assert_eq!(parse_pactl_volume("Volume: mono: 65536 / 100% / 0.00 dB\n"), Some(100));
        assert_eq!(parse_pactl_volume("Volume: front-left: 1000 / 2%,   front-right: 30000 / 46%\n"), Some(46));
        assert_eq!(parse_pactl_mute("Mute: no\n"), Some(false));
        assert_eq!(parse_pactl_mute("Mute: yes\n"), Some(true));
        for pct in 0..=100u8 {
            assert_eq!(lvl(pct, false).pct(), pct);
        }
    }

    #[test]
    fn over_100_clamped() {
        // The MAPPING clamps (there is no headroom above 0 dB)...
        let l = LaptopLevel::from_pactl(&vol_out(98304), "Mute: no").unwrap();
        assert_eq!(l.pct(), 100);
        assert!(TvVolume::from_laptop(l).db_x100() <= 0, "never above the top of the scale");
        // ...but the READ does not: 150 % stays 150 %, so it is telling apart
        // from a slider genuinely at the top, and it never sends 0 dB
        // (AirPlay MAXIMUM). 3.375 linear = 337 % is the remembered-boost
        // restore audiosink calls the worst failure available here.
        for (raw, pct) in [(98304u32, 150u32), (220856, 337)] {
            let l = LaptopLevel::from_pactl(&vol_out(raw), "Mute: no").unwrap();
            assert_eq!(l.raw_pct(), pct, "the read must not clamp");
            assert_eq!(l.pct(), 100, "the mapping still sees 100");
            assert!(l.boosted());
            let v = TvVolume::from_laptop(l);
            assert!(!v.is_max(), "{pct} % manufactured an AirPlay MAXIMUM");
            assert_eq!(v.db_x100(), TvVolume::JUST_UNDER_MAX);
            assert_eq!(v.set_body(), b"volume: -0.010000\r\n");
        }
        // And exactly 100 % still is a maximum.
        let genuine = LaptopLevel::from_pactl(&vol_out(65536), "Mute: no").unwrap();
        assert_eq!(genuine.raw_pct(), 100);
        assert!(!genuine.boosted());
        assert!(TvVolume::from_laptop(genuine).is_max());
        // A boosted sink that is MUTED is still mute, not just-under-max.
        let m = LaptopLevel::from_pactl(&vol_out(98304), "Mute: yes").unwrap();
        assert!(TvVolume::from_laptop(m).is_mute());
        // The clamped parser stays as it was (it is the lossy one, by name).
        assert_eq!(parse_pactl_volume(&vol_out(98304)), Some(100));
        assert_eq!(parse_pactl_volume_raw(&vol_out(98304)), Some(150));
    }

    #[test]
    fn nan_sends_nothing() {
        for garbage in ["", "Volume:", "Volume: front-left: NaN / 1%", "Volume: front-left: -5 / 1%", "Mute: no", "volume: 12"] {
            assert_eq!(parse_pactl_volume(garbage), None, "{garbage:?}");
        }
        assert_eq!(parse_pactl_mute("Mute: maybe"), None);
        assert_eq!(parse_pactl_mute(""), None);
        assert!(LaptopLevel::from_pactl("garbage", "Mute: no").is_none());
        assert_eq!(parse_get_parameter_volume(b"volume: nan\r\n"), None);
        assert_eq!(parse_get_parameter_volume(b"volume: inf\r\n"), None);
        assert_eq!(parse_get_parameter_volume(b"garbage"), None);
        assert_eq!(parse_get_parameter_volume(b"volume: -20.400000\r\n"), Some(-20.4));
        assert_eq!(laptop_pct_from_dvlc(f64::NAN, false), None);
        assert_eq!(laptop_pct_from_tv_db(f64::INFINITY), None);
        // A non-finite dvlc never moves the laptop.
        let c = FakeClock::new(10.0);
        let mut s = VolumeSync::new();
        s.arm();
        assert_eq!(s.on_dvlc(f64::NAN, false, at(&c)), None);
    }

    #[test]
    fn muted_sends_minus_144() {
        for pct in [0, 1, 50, 100] {
            let v = TvVolume::from_laptop(lvl(pct, true));
            assert!(v.is_mute());
            assert_eq!(v.set_body(), b"volume: -144.000000\r\n");
        }
    }

    #[test]
    fn zero_pct_sends_minus_144() {
        assert!(TvVolume::from_laptop(lvl(0, false)).is_mute());
    }

    #[test]
    fn no_path_to_zero_db_without_laptop_100() {
        let mut max = vec![];
        for pct in 0..=100u8 {
            for muted in [false, true] {
                let v = TvVolume::from_laptop(lvl(pct, muted));
                assert!(v.db_x100() <= 0);
                assert!(v.is_mute() || (-3000..=0).contains(&v.db_x100()));
                if v.is_max() {
                    max.push((pct, muted));
                }
            }
        }
        assert_eq!(max, vec![(100, false)]);
        // ...and no BOOSTED level reaches it either: the guard used to stop
        // at 100 %, which is precisely where the clamp hid the hole.
        for raw_pct in [101u32, 120, 150, 153, 337, 1000] {
            for muted in [false, true] {
                let raw = (raw_pct * 65536 + 50) / 100;
                let l = LaptopLevel::from_pactl(&vol_out(raw), if muted { "Mute: yes" } else { "Mute: no" }).unwrap();
                assert_eq!(l.raw_pct(), raw_pct);
                let v = TvVolume::from_laptop(l);
                assert!(!v.is_max(), "{raw_pct} %{} reached AirPlay MAXIMUM", if muted { " muted" } else { "" });
                assert!(v.db_x100() < 0);
                assert!(v.is_mute() || v.db_x100() == TvVolume::JUST_UNDER_MAX);
            }
        }
        assert!(!TvVolume::mute().is_max());
        // Garbage and NaN never produce a level at all.
        assert!(LaptopLevel::from_pactl("Volume: front-left: nan / 0%", "Mute: no").is_none());
        assert!(LaptopLevel::from_pactl("", "").is_none());
    }

    #[test]
    fn set_body_exact_strings() {
        assert_eq!(TvVolume::from_laptop(lvl(1, false)).set_body(), b"volume: -29.700000\r\n");
        assert_eq!(TvVolume::from_laptop(lvl(17, false)).set_body(), b"volume: -24.900000\r\n");
        assert_eq!(TvVolume::from_laptop(lvl(50, false)).set_body(), b"volume: -15.000000\r\n");
        assert_eq!(TvVolume::from_laptop(lvl(99, false)).set_body(), b"volume: -0.300000\r\n");
        assert_eq!(TvVolume::from_laptop(lvl(100, false)).set_body(), b"volume: 0.000000\r\n");
        assert_eq!(volume_body_text(-2000), "volume: -20.000000\r\n");
        assert_eq!(volume_body_text(-3000), "volume: -30.000000\r\n");
    }

    #[test]
    fn tv_db_to_laptop_mapping() {
        assert_eq!(laptop_pct_from_tv_db(-144.0), Some((0, true)));
        assert_eq!(laptop_pct_from_tv_db(-30.6), Some((0, true)));
        assert_eq!(laptop_pct_from_tv_db(-30.0), Some((0, false)));
        assert_eq!(laptop_pct_from_tv_db(-24.9), Some((17, false)));
        assert_eq!(laptop_pct_from_tv_db(0.0), Some((100, false)));
        assert_eq!(laptop_pct_from_dvlc(0.18, false), Some((18, false)));
        assert_eq!(laptop_pct_from_dvlc(1.7, false), Some((100, false)));
        assert_eq!(laptop_pct_from_dvlc(-1.0, true), Some((0, true)));
    }

    /// Armed sync, TV at `pct` (as after on_start + arm), clock past the
    /// echo windows.
    fn armed_at(c: &FakeClock, pct: u8) -> VolumeSync {
        let mut s = VolumeSync::new();
        s.on_start(lvl(pct, false), at(c));
        s.arm();
        c.advance(5.0);
        s
    }

    #[test]
    fn own_echo_swallowed() {
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 30);
        // TV remote -> 45 %: the laptop is set...
        assert_eq!(s.on_dvlc(0.45, false, at(&c)), Some(VolAction::SetLaptop { pct: 45, muted: false }));
        // ...and pactl reports that change back to us: swallowed, no SET.
        c.advance(0.05);
        s.on_laptop_change(lvl(45, false), at(&c));
        c.advance(0.5);
        assert_eq!(s.on_tick(at(&c)), None);
    }

    #[test]
    fn dvlc_within_1pct_after_set_dropped() {
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 30);
        s.on_laptop_change(lvl(40, false), at(&c));
        c.advance(0.2);
        assert_eq!(s.on_tick(at(&c)), Some(VolAction::SetTv(TvVolume::from_laptop(lvl(40, false)))));
        // TV echoes 0.39..0.41 within 3 s: dropped.
        for v in [0.39, 0.40, 0.41] {
            c.advance(0.1);
            assert_eq!(s.on_dvlc(v, false, at(&c)), None, "{v}");
        }
        // A real remote press to 0.60 goes through.
        c.advance(0.1);
        assert_eq!(s.on_dvlc(0.60, false, at(&c)), Some(VolAction::SetLaptop { pct: 60, muted: false }));
    }

    #[test]
    fn update_info_zero_dropped() {
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 30);
        s.on_update_info(at(&c));
        c.advance(0.05);
        assert_eq!(s.on_dvlc(0.0, false, at(&c)), None);
        c.advance(0.2);
        assert_eq!(s.on_dvlc(0.25, false, at(&c)), Some(VolAction::SetLaptop { pct: 25, muted: false }));
    }

    #[test]
    fn unarmed_drops_all_dvlc() {
        let c = FakeClock::new(100.0);
        let mut s = VolumeSync::new();
        s.on_start(lvl(30, false), at(&c));
        for v in [0.0, 0.5, 1.0] {
            c.advance(1.0);
            assert_eq!(s.on_dvlc(v, false, at(&c)), None);
        }
        // Laptop changes before arming wait, and go out after arming.
        s.on_laptop_change(lvl(35, false), at(&c));
        c.advance(1.0);
        assert_eq!(s.on_tick(at(&c)), None);
        s.arm();
        assert_eq!(s.on_tick(at(&c)), Some(VolAction::SetTv(TvVolume::from_laptop(lvl(35, false)))));
    }

    #[test]
    fn burst_10hz_coalesces_to_trailing_edge() {
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 30);
        let mut sets = vec![];
        // A held key: 10 steps, 30 ms apart; tick every 10 ms.
        for i in 0..10u8 {
            s.on_laptop_change(lvl(31 + i, false), at(&c));
            for _ in 0..3 {
                c.advance(0.01);
                if let Some(a) = s.on_tick(at(&c)) {
                    sets.push(a);
                }
            }
        }
        for _ in 0..30 {
            c.advance(0.01);
            if let Some(a) = s.on_tick(at(&c)) {
                sets.push(a);
            }
        }
        assert!(sets.len() <= 2, "{sets:?}");
        assert_eq!(sets.last(), Some(&VolAction::SetTv(TvVolume::from_laptop(lvl(40, false)))));
        // And a 10 Hz burst (100 ms apart) never sends more than one SET per step.
        let mut s = armed_at(&c, 30);
        let mut n = 0;
        for i in 0..10u8 {
            s.on_laptop_change(lvl(50 + i, false), at(&c));
            for _ in 0..10 {
                c.advance(0.01);
                n += s.on_tick(at(&c)).is_some() as u32;
            }
        }
        for _ in 0..20 {
            c.advance(0.01);
            n += s.on_tick(at(&c)).is_some() as u32;
        }
        assert!(n <= 10, "{n}");
        assert_eq!(s.believed_tv_x100(), Some(TvVolume::from_laptop(lvl(59, false)).db_x100()));
    }

    #[test]
    fn ping_pong_settles_within_one_round_trip() {
        // Laptop -> TV SET, TV echoes dvlc, echo would set laptop, laptop
        // change would SET TV ... must stop after the first SET.
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 30);
        let mut tv_sets = 0;
        let mut laptop_sets = 0;
        s.on_laptop_change(lvl(62, false), at(&c));
        for _ in 0..300 {
            c.advance(0.01);
            if let Some(VolAction::SetTv(v)) = s.on_tick(at(&c)) {
                tv_sets += 1;
                // The TV echoes with its own quantisation (61.9 %).
                let echo = (v.db() + 30.0) / 30.0 - 0.001;
                c.advance(0.2);
                if let Some(VolAction::SetLaptop { pct, muted }) = s.on_dvlc(echo, false, at(&c)) {
                    laptop_sets += 1;
                    s.on_laptop_change(lvl(pct, muted), at(&c));
                }
            }
        }
        assert_eq!((tv_sets, laptop_sets), (1, 0));
        // And the other way: remote -> laptop set -> pactl echo -> nothing.
        c.advance(5.0);
        let a = s.on_dvlc(0.20, false, at(&c));
        assert_eq!(a, Some(VolAction::SetLaptop { pct: 20, muted: false }));
        s.on_laptop_change(lvl(20, false), at(&c));
        for _ in 0..100 {
            c.advance(0.01);
            assert_eq!(s.on_tick(at(&c)), None);
        }
    }

    #[test]
    fn tv_mute_mutes_laptop_and_echo_is_swallowed() {
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 30);
        assert_eq!(s.on_dvlc(0.3, true, at(&c)), Some(VolAction::SetLaptop { pct: 30, muted: true }));
        // pactl reads the old slider position, muted: same laptop state.
        s.on_laptop_change(lvl(30, true), at(&c));
        c.advance(1.0);
        assert_eq!(s.on_tick(at(&c)), None);
        // Laptop mute key -> TV -144.
        c.advance(5.0);
        s.on_laptop_change(lvl(30, false), at(&c));
        c.advance(0.2);
        assert!(matches!(s.on_tick(at(&c)), Some(VolAction::SetTv(v)) if !v.is_mute()));
        c.advance(5.0);
        s.on_laptop_change(lvl(30, true), at(&c));
        c.advance(0.2);
        assert!(matches!(s.on_tick(at(&c)), Some(VolAction::SetTv(v)) if v.is_mute()));
    }

    // ---- the driver, with fakes

    #[derive(Default)]
    struct TvLog {
        gets: u32,
        sets: Vec<i32>,
        fail_get: bool,
        db: f64,
    }
    struct FakeTv(Arc<Mutex<TvLog>>);
    impl TvVolumeTransport for FakeTv {
        fn get(&mut self) -> io::Result<f64> {
            let mut l = self.0.lock().unwrap();
            l.gets += 1;
            if l.fail_get {
                Err(io::Error::other("fake GET failure"))
            } else {
                Ok(l.db)
            }
        }
        fn set(&mut self, v: &TvVolume) -> io::Result<u16> {
            let mut l = self.0.lock().unwrap();
            l.sets.push(v.db_x100());
            l.db = v.db();
            Ok(500)
        }
    }
    struct FakeLaptop {
        level: Arc<Mutex<(u8, bool)>>,
        sets: Arc<Mutex<Vec<(u8, bool)>>>,
        rx: Option<Receiver<LaptopEvent>>,
    }
    impl LaptopVolume for FakeLaptop {
        fn read(&mut self) -> io::Result<LaptopLevel> {
            let (p, m) = *self.level.lock().unwrap();
            Ok(lvl(p, m))
        }
        fn set(&mut self, pct: u8, muted: bool) -> io::Result<()> {
            self.sets.lock().unwrap().push((pct, muted));
            let mut l = self.level.lock().unwrap();
            if muted {
                l.1 = true;
            } else {
                *l = (pct, false);
            }
            Ok(())
        }
        fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>> {
            Ok(self.rx.take().unwrap())
        }
        fn describe(&self) -> String {
            "fake".into()
        }
    }

    /// What a [`FixedLaptop`]'s `current_default()` answers, in order; the
    /// last entry repeats for every later call. A `None` entry is a read that
    /// FAILED (production's `resolve_output_sink()` erroring), which must
    /// read as "unknown", never as a name.
    type OutputScript = Arc<Mutex<Vec<Option<String>>>>;

    fn output_script(steps: &[Option<&str>]) -> OutputScript {
        Arc::new(Mutex::new(steps.iter().map(|s| s.map(str::to_string)).collect()))
    }

    /// A laptop bound to one sink we own (what `PactlVolume::for_sink` is in
    /// production), whose "is it still the output?" answer can be flipped.
    struct FixedLaptop {
        inner: FakeLaptop,
        sink: String,
        is_default: Arc<AtomicBool>,
        /// `None`: this fake has no notion of a default at all (the shape
        /// every test had before the pre-handover check existed).
        output: Option<OutputScript>,
    }
    impl LaptopVolume for FixedLaptop {
        fn current_default(&mut self) -> Option<String> {
            let mut s = self.output.as_ref()?.lock().unwrap();
            match s.len() {
                0 => None,
                1 => s[0].clone(),
                _ => s.remove(0),
            }
        }
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
            Some(self.is_default.load(Ordering::SeqCst))
        }
        fn describe(&self) -> String {
            format!("fake fixed to {}", self.sink)
        }
    }

    fn fast() -> VolumeTiming {
        VolumeTiming {
            start_delay: Duration::from_millis(30),
            readback_delay: Duration::from_millis(10),
            arm_grace: Duration::from_millis(10),
            tick: Duration::from_millis(5),
        }
    }

    fn wait_for(mut f: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(3);
        while !f() {
            assert!(Instant::now() < end, "timed out");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn get_failure_disables_sync() {
        let tv = Arc::new(Mutex::new(TvLog { fail_get: true, ..Default::default() }));
        let (_ltx, lrx) = mpsc::channel();
        let laptop = FakeLaptop { level: Arc::new(Mutex::new((40, false))), sets: Default::default(), rx: Some(lrx) };
        let (etx, erx) = mpsc::sync_channel(8);
        let (atx, arx) = mpsc::channel();
        let status: StatusSink = Default::default();
        let h = spawn_volume_sync(Box::new(laptop), Box::new(FakeTv(tv.clone())), erx, arx, Arc::new(crate::clock::BoottimeClock), status.clone(), fast());
        atx.send(crate::audio::AudioEvent::FirstPacketSent(crate::clock::BoottimeClock.read())).unwrap();
        wait_for(|| status.lock().unwrap().state.starts_with("disabled"));
        etx.send(crate::session::ReceiverEvent::Volume { v: 0.9, muted: false }).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let st = h.join(Duration::from_secs(2));
        assert!(st.state.starts_with("disabled: GET failed"), "{}", st.state);
        assert!(tv.lock().unwrap().sets.is_empty(), "nothing is ever SET after a failed GET");
        assert_eq!(st.sets_to_laptop, 0);
    }

    #[test]
    fn driver_start_then_two_way() {
        let tv = Arc::new(Mutex::new(TvLog { db: -20.4, ..Default::default() }));
        let (ltx, lrx) = mpsc::channel();
        let level = Arc::new(Mutex::new((17u8, false)));
        let lsets = Arc::new(Mutex::new(vec![]));
        let laptop = FakeLaptop { level: level.clone(), sets: lsets.clone(), rx: Some(lrx) };
        let (etx, erx) = mpsc::sync_channel(8);
        let (atx, arx) = mpsc::channel();
        let status: StatusSink = Default::default();
        let h = spawn_volume_sync(Box::new(laptop), Box::new(FakeTv(tv.clone())), erx, arx, Arc::new(crate::clock::BoottimeClock), status.clone(), fast());
        // Nothing before the first audio packet.
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(tv.lock().unwrap().gets, 0);
        atx.send(crate::audio::AudioEvent::FirstPacketSent(crate::clock::BoottimeClock.read())).unwrap();
        wait_for(|| status.lock().unwrap().state == "armed");
        assert_eq!(tv.lock().unwrap().sets, vec![-2490], "the TV took the laptop's 17 %");
        assert_eq!(tv.lock().unwrap().gets, 2, "GET, then read-back");
        // Laptop key -> TV.
        *level.lock().unwrap() = (50, false);
        ltx.send(LaptopEvent::Change).unwrap();
        wait_for(|| tv.lock().unwrap().sets.len() == 2);
        assert_eq!(tv.lock().unwrap().sets[1], -1500);
        // TV echo of that SET -> nothing.
        etx.send(crate::session::ReceiverEvent::Volume { v: 0.5, muted: false }).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(lsets.lock().unwrap().is_empty());
        // TV remote -> laptop, and the laptop's own change event is swallowed.
        std::thread::sleep(Duration::from_millis(10));
        etx.send(crate::session::ReceiverEvent::Volume { v: 0.8, muted: false }).unwrap();
        wait_for(|| !lsets.lock().unwrap().is_empty());
        ltx.send(LaptopEvent::Change).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(*lsets.lock().unwrap(), vec![(80, false)]);
        assert_eq!(tv.lock().unwrap().sets.len(), 2, "no SET echoed back to the TV");
        let st = h.join(Duration::from_secs(2));
        assert_eq!((st.sets_to_tv, st.sets_to_laptop), (2, 1));
        assert!(!tv.lock().unwrap().sets.contains(&0), "never 0 dB");
    }

    // ---- M4 review fixes: policy

    #[test]
    fn request_timeout_below_join_bound() {
        // A volume request in flight ends before the session stops waiting
        // for the volume thread (and before TEARDOWN wants the control lock).
        assert!(VOLUME_REQUEST_TIMEOUT < VOLUME_JOIN_BOUND);
    }

    #[test]
    fn readback_comparison() {
        let v = TvVolume::from_laptop(lvl(17, false)); // -24.9
        assert!(readback_matches(&v, -24.9));
        assert!(readback_matches(&v, -24.5));
        assert!(!readback_matches(&v, 0.0), "TV still at maximum");
        assert!(!readback_matches(&v, -20.4));
        assert!(!readback_matches(&v, f64::NAN));
        let m = TvVolume::mute();
        assert!(readback_matches(&m, -144.0));
        assert!(!readback_matches(&m, -30.0), "-30 is audible, not mute");
        assert!(!readback_matches(&m, 0.0));
    }

    #[test]
    fn late_start_echo_does_not_move_the_laptop() {
        // Probe run 163229: SET -24.9 dB, echo dvlc 0.18 about 6 s later,
        // i.e. after arming (start + 2 s).
        let c = FakeClock::new(100.0);
        let mut s = VolumeSync::new();
        s.on_start(lvl(17, false), at(&c));
        c.advance(2.0);
        s.arm();
        c.advance(4.03);
        assert_eq!(s.on_dvlc(0.18, false, at(&c)), None);
        assert_eq!(s.believed_tv_x100(), Some(-2490));
        // 3.7 s (run 163129) as well.
        let mut s = VolumeSync::new();
        s.on_start(lvl(33, false), at(&c));
        s.arm();
        c.advance(3.7);
        assert_eq!(s.on_dvlc(0.32, false, at(&c)), None);
    }

    #[test]
    fn stale_echo_after_a_burst_cannot_jump_the_tv() {
        let c = FakeClock::new(100.0);
        let mut s = VolumeSync::new();
        s.on_start(lvl(80, false), at(&c));
        s.arm();
        c.advance(0.5);
        s.on_laptop_change(lvl(20, false), at(&c));
        c.advance(0.2);
        assert_eq!(s.on_tick(at(&c)), Some(VolAction::SetTv(TvVolume::from_laptop(lvl(20, false)))));
        // The 80 % echo arrives 3.7 s after its SET: still our echo.
        c.advance(3.0);
        assert_eq!(s.on_dvlc(0.80, false, at(&c)), None);
        assert_eq!(s.believed_tv_x100(), Some(-2400), "bookkeeping not rewritten by a stale echo");
        // The next key press moves the TV by one step, not from 20 % to 75 %.
        c.advance(1.0);
        s.on_laptop_change(lvl(25, false), at(&c));
        c.advance(0.2);
        assert_eq!(s.on_tick(at(&c)), Some(VolAction::SetTv(TvVolume::from_laptop(lvl(25, false)))));
    }

    #[test]
    fn remote_back_to_an_old_remote_value_is_honoured() {
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 50);
        assert_eq!(s.on_dvlc(0.30, false, at(&c)), Some(VolAction::SetLaptop { pct: 30, muted: false }));
        s.on_laptop_change(lvl(30, false), at(&c)); // our echo
        c.advance(5.0);
        s.on_laptop_change(lvl(35, false), at(&c));
        c.advance(0.2);
        assert_eq!(s.on_tick(at(&c)), Some(VolAction::SetTv(TvVolume::from_laptop(lvl(35, false)))));
        c.advance(0.5);
        assert_eq!(s.on_dvlc(0.35, false, at(&c)), None, "echo of the 35 SET");
        c.advance(600.0);
        assert_eq!(s.on_dvlc(0.30, false, at(&c)), Some(VolAction::SetLaptop { pct: 30, muted: false }));
        assert_eq!(s.believed_tv_x100(), Some(-2100));
        // Mute variant: remote mute, laptop unmute, remote mute again.
        let mut s = armed_at(&c, 50);
        assert_eq!(s.on_dvlc(0.5, true, at(&c)), Some(VolAction::SetLaptop { pct: 50, muted: true }));
        c.advance(5.0);
        s.on_laptop_change(lvl(50, false), at(&c));
        c.advance(0.2);
        assert_eq!(s.on_tick(at(&c)), Some(VolAction::SetTv(TvVolume::from_laptop(lvl(50, false)))));
        c.advance(3600.0);
        assert_eq!(s.on_dvlc(0.5, true, at(&c)), Some(VolAction::SetLaptop { pct: 50, muted: true }));
    }

    #[test]
    fn spurious_zero_after_update_info_dropped_even_late() {
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 30);
        s.on_update_info(at(&c));
        c.advance(0.15); // past the 100 ms guard (e.g. a Wi-Fi retransmit)
        assert_eq!(s.on_dvlc(0.0, false, at(&c)), None);
        c.advance(0.2);
        assert_eq!(s.on_dvlc(0.25, false, at(&c)), Some(VolAction::SetLaptop { pct: 25, muted: false }));
        // The first dvlc after an updateInfo, however late, if it is 0.0.
        s.on_update_info(at(&c));
        c.advance(30.0);
        assert_eq!(s.on_dvlc(0.0, false, at(&c)), None);
        // A later genuine remote-to-zero is honoured.
        c.advance(30.0);
        assert_eq!(s.on_dvlc(0.0, false, at(&c)), Some(VolAction::SetLaptop { pct: 0, muted: false }));
        // Recorded before arming (the driver records updateInfo while idle).
        let mut s = VolumeSync::new();
        s.on_start(lvl(50, false), at(&c));
        s.on_update_info(at(&c));
        c.advance(0.5);
        s.arm();
        assert_eq!(s.on_dvlc(0.0, false, at(&c)), None);
    }

    #[test]
    fn sink_switch_rebaselines_and_never_sends_its_level() {
        let c = FakeClock::new(100.0);
        let mut s = armed_at(&c, 30);
        // New default output at 100 %: NOT a key press.
        s.on_target_changed(lvl(100, false));
        s.on_laptop_change(lvl(100, false), at(&c));
        for _ in 0..50 {
            c.advance(0.01);
            assert_eq!(s.on_tick(at(&c)), None);
        }
        assert_eq!(s.believed_tv_x100(), Some(-2100));
        // A queued key press from before the switch is dropped too.
        let mut s = armed_at(&c, 30);
        s.on_laptop_change(lvl(35, false), at(&c));
        s.on_target_changed(lvl(100, false));
        c.advance(0.5);
        assert_eq!(s.on_tick(at(&c)), None);
        // A key press on the new sink does drive the TV (its absolute level).
        s.on_laptop_change(lvl(95, false), at(&c));
        c.advance(0.2);
        assert_eq!(s.on_tick(at(&c)), Some(VolAction::SetTv(TvVolume::from_laptop(lvl(95, false)))));
    }

    #[test]
    fn restore_level_only_undoes_the_tv_remote() {
        let c = FakeClock::new(100.0);
        // Remote moved the laptop; the user did not touch it after: restore.
        let mut s = armed_at(&c, 40);
        s.on_dvlc(1.0, false, at(&c));
        assert_eq!(s.restore_level(lvl(100, false)), Some((40, false)));
        // The user moved it afterwards: leave it.
        assert_eq!(s.restore_level(lvl(70, false)), None);
        // The remote muted it: unmute back.
        let mut s = armed_at(&c, 40);
        s.on_dvlc(0.4, true, at(&c));
        assert_eq!(s.restore_level(lvl(40, true)), Some((40, false)));
        // The remote never moved it: nothing.
        let s = armed_at(&c, 40);
        assert_eq!(s.restore_level(lvl(40, false)), None);
        // A key press after a remote change is the user's choice.
        let mut s = armed_at(&c, 40);
        s.on_dvlc(0.8, false, at(&c));
        c.advance(5.0);
        s.on_laptop_change(lvl(60, false), at(&c));
        assert_eq!(s.restore_level(lvl(60, false)), None);
        // After a sink switch the saved level belongs to another sink.
        let mut s = armed_at(&c, 40);
        s.on_dvlc(1.0, false, at(&c));
        s.on_target_changed(lvl(100, false));
        assert_eq!(s.restore_level(lvl(100, false)), None);
    }

    // ---- M4 review fixes: the driver, the audio gate

    #[derive(Clone, Debug, PartialEq)]
    enum Wire {
        Get,
        Set(i32),
        /// One frame as it would leave the sender: real (non-zero) or silence.
        Frame { real: bool },
    }

    /// A TV that logs into the same ordered log as the fake audio sender.
    struct OrderTv {
        log: Arc<Mutex<Vec<Wire>>>,
        db: Arc<Mutex<f64>>,
        /// SETs are acknowledged (500) but not applied.
        deaf: bool,
        /// GET number n (1-based) and later fail.
        fail_get_from: Option<u32>,
        gets: u32,
    }
    impl TvVolumeTransport for OrderTv {
        fn get(&mut self) -> io::Result<f64> {
            self.gets += 1;
            self.log.lock().unwrap().push(Wire::Get);
            if self.fail_get_from.is_some_and(|n| self.gets >= n) {
                return Err(io::Error::other("fake GET timeout"));
            }
            Ok(*self.db.lock().unwrap())
        }
        fn set(&mut self, v: &TvVolume) -> io::Result<u16> {
            self.log.lock().unwrap().push(Wire::Set(v.db_x100()));
            if !self.deaf {
                *self.db.lock().unwrap() = v.db();
            }
            Ok(500)
        }
    }

    /// What audio.rs does per frame: real capture if the gate is open, else
    /// zeroed PCM; the first frame sent reports FirstPacketSent.
    fn fake_sender(
        gate: AudioGate,
        log: Arc<Mutex<Vec<Wire>>>,
        atx: mpsc::Sender<crate::audio::AudioEvent>,
        stop: Arc<AtomicBool>,
    ) -> JoinHandle<mpsc::Sender<crate::audio::AudioEvent>> {
        std::thread::spawn(move || {
            let mut first = true;
            while !stop.load(Ordering::SeqCst) {
                let mut pcm = [0x55u8; crate::audio::PCM_FRAME_BYTES]; // loud capture
                if !gate.is_open() {
                    pcm.fill(0);
                }
                log.lock().unwrap().push(Wire::Frame { real: pcm.iter().any(|&b| b != 0) });
                if first {
                    first = false;
                    let _ = atx.send(crate::audio::AudioEvent::FirstPacketSent(crate::clock::BoottimeClock.read()));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            atx
        })
    }

    struct GateRig {
        log: Arc<Mutex<Vec<Wire>>>,
        status: StatusSink,
        gate: AudioGate,
        h: VolumeHandle,
        sender_stop: Arc<AtomicBool>,
        sender: Option<JoinHandle<mpsc::Sender<crate::audio::AudioEvent>>>,
        etx: mpsc::SyncSender<crate::session::ReceiverEvent>,
        ltx: mpsc::Sender<LaptopEvent>,
        lsets: Arc<Mutex<Vec<(u8, bool)>>>,
        level: Arc<Mutex<(u8, bool)>>,
    }

    fn gate_rig(tv_db: f64, deaf: bool, fail_get_from: Option<u32>, laptop_pct: u8) -> GateRig {
        gate_rig_bound(tv_db, deaf, fail_get_from, laptop_pct, SinkBinding::default(), None)
    }

    /// [`gate_rig`] with a sink binding, and optionally a laptop that is
    /// bound to a sink and can stop being the default output.
    fn gate_rig_bound(
        tv_db: f64,
        deaf: bool,
        fail_get_from: Option<u32>,
        laptop_pct: u8,
        binding: SinkBinding,
        fixed: Option<(&str, Arc<AtomicBool>)>,
    ) -> GateRig {
        gate_rig_output(tv_db, deaf, fail_get_from, laptop_pct, binding, fixed, None)
    }

    /// [`gate_rig_bound`] whose fixed laptop also answers `current_default()`
    /// from a script, so the pre-handover output check can be driven.
    #[allow(clippy::too_many_arguments)]
    fn gate_rig_output(
        tv_db: f64,
        deaf: bool,
        fail_get_from: Option<u32>,
        laptop_pct: u8,
        binding: SinkBinding,
        fixed: Option<(&str, Arc<AtomicBool>)>,
        output: Option<OutputScript>,
    ) -> GateRig {
        let log = Arc::new(Mutex::new(vec![]));
        let tv = OrderTv { log: log.clone(), db: Arc::new(Mutex::new(tv_db)), deaf, fail_get_from, gets: 0 };
        let (ltx, lrx) = mpsc::channel();
        let level = Arc::new(Mutex::new((laptop_pct, false)));
        let lsets = Arc::new(Mutex::new(vec![]));
        let inner = FakeLaptop { level: level.clone(), sets: lsets.clone(), rx: Some(lrx) };
        let laptop: Box<dyn LaptopVolume> = match fixed {
            None => Box::new(inner),
            Some((sink, is_default)) => Box::new(FixedLaptop { inner, sink: sink.to_string(), is_default, output }),
        };
        let (etx, erx) = mpsc::sync_channel(8);
        let (atx, arx) = mpsc::channel();
        let status: StatusSink = Default::default();
        let gate = AudioGate::held(crate::audio::GATE_WAITING_FOR_VOLUME);
        // The sender starts FIRST, as in the session.
        let sender_stop = Arc::new(AtomicBool::new(false));
        let sender = fake_sender(gate.clone(), log.clone(), atx, sender_stop.clone());
        let h = spawn_volume_sync_gated(
            laptop,
            Box::new(tv),
            erx,
            arx,
            Arc::new(crate::clock::BoottimeClock),
            status.clone(),
            fast(),
            gate.clone(),
            binding,
        );
        GateRig { log, status, gate, h, sender_stop, sender: Some(sender), etx, ltx, lsets, level }
    }

    impl GateRig {
        fn state(&self) -> String {
            self.status.lock().unwrap().state.clone()
        }
        fn stop_sender(&mut self) -> mpsc::Sender<crate::audio::AudioEvent> {
            self.sender_stop.store(true, Ordering::SeqCst);
            self.sender.take().unwrap().join().unwrap()
        }
        fn real_frames(&self) -> usize {
            self.log.lock().unwrap().iter().filter(|w| **w == Wire::Frame { real: true }).count()
        }
    }

    #[test]
    fn no_real_sample_before_the_start_set_is_read_back() {
        // The TV starts at 0 dB (AirPlay MAXIMUM); the laptop is at 17 %.
        let mut r = gate_rig(0.0, false, None, 17);
        wait_for(|| r.state() == "armed");
        std::thread::sleep(Duration::from_millis(30));
        let _atx = r.stop_sender();
        let log = r.log.lock().unwrap().clone();
        let first_real = log.iter().position(|w| *w == Wire::Frame { real: true }).expect("real audio once established");
        let set = log.iter().position(|w| *w == Wire::Set(-2490)).expect("the start SET");
        let readback = set + 1 + log[set + 1..].iter().position(|w| *w == Wire::Get).expect("the read-back GET");
        assert!(set < readback && readback < first_real, "SET at {set}, read-back at {readback}, first real frame at {first_real}");
        assert!(log[..first_real].contains(&Wire::Frame { real: false }), "silence was streamed meanwhile");
        assert!(log[first_real..].iter().all(|w| *w != Wire::Frame { real: false }), "real audio from then on");
        assert!(r.gate.is_open());
        let tv_ops: Vec<&Wire> = log.iter().filter(|w| !matches!(w, Wire::Frame { .. })).collect();
        assert_eq!(tv_ops, [&Wire::Get, &Wire::Set(-2490), &Wire::Get]);
    }

    #[test]
    fn unapplied_start_set_keeps_the_session_silent() {
        // The TV acknowledges (500) but stays at 0 dB.
        let mut r = gate_rig(0.0, true, None, 17);
        wait_for(|| r.state().starts_with("error"));
        std::thread::sleep(Duration::from_millis(50));
        let _atx = r.stop_sender();
        assert!(r.state().starts_with("error: TV volume not established"), "{}", r.state());
        assert!(r.state().contains("audio held silent"));
        assert_eq!(r.real_frames(), 0, "no real sample ever reached the TV");
        assert!(!r.gate.is_open());
        let sets: Vec<Wire> = r.log.lock().unwrap().iter().filter(|w| matches!(w, Wire::Set(_))).cloned().collect();
        assert_eq!(sets, [Wire::Set(-2490), Wire::Set(-2490)], "one retry, then stop");
        assert_eq!(r.status.lock().unwrap().tv_volume_db, Some(0.0));
    }

    #[test]
    fn failed_readback_or_get_keeps_the_session_silent() {
        for (from, want) in [(Some(2), "error: read-back GET failed"), (Some(1), "disabled: GET failed")] {
            let mut r = gate_rig(-20.0, false, from, 40);
            wait_for(|| r.state().starts_with(want));
            std::thread::sleep(Duration::from_millis(50));
            let _atx = r.stop_sender();
            assert_eq!(r.real_frames(), 0, "{want}");
            assert!(!r.gate.is_open());
            assert!(r.gate.reason().unwrap().contains(want), "{:?}", r.gate.reason());
        }
    }

    #[test]
    fn gate_held_again_when_sync_stops() {
        let mut r = gate_rig(-20.0, false, None, 40);
        wait_for(|| r.state() == "armed");
        assert!(r.gate.is_open());
        let _atx = r.stop_sender();
        let GateRig { h, gate, .. } = r;
        h.join(Duration::from_secs(2));
        assert!(!gate.is_open(), "no real audio once volume sync is gone");
    }

    /// Sink mode: nothing runs unless the laptop transport is bound to the
    /// sink we published. A wrong binding is a silent session, never a write
    /// to whatever sink the transport happens to be following.
    #[test]
    fn volume_sync_refuses_to_run_unless_bound_to_our_sink() {
        let binding = SinkBinding { require_sink: Some("airplay-sink.x".into()), ..Default::default() };
        // The default FakeLaptop follows the output: bound_sink() is None.
        let mut r = gate_rig_bound(-20.0, false, None, 40, binding, None);
        wait_for(|| r.state().starts_with("disabled"));
        assert!(r.state().contains("not bound") && r.state().contains("airplay-sink.x"), "{}", r.state());
        r.ltx.send(LaptopEvent::Change).unwrap();
        r.etx.send(crate::session::ReceiverEvent::Volume { v: 0.9, muted: false }).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let _atx = r.stop_sender();
        assert!(!r.gate.is_open(), "the gate must stay held");
        assert_eq!(r.real_frames(), 0, "audio held silent");
        assert!(r.log.lock().unwrap().iter().all(|w| !matches!(w, Wire::Set(_) | Wire::Get)), "nothing was sent to the TV");
        assert!(r.lsets.lock().unwrap().is_empty(), "nothing was written to the laptop");
    }

    /// The handover happens exactly once, and only after the gate opened.
    #[test]
    fn gate_open_hands_the_output_over_exactly_once() {
        let opens = Arc::new(Mutex::new(Vec::<bool>::new()));
        let o = opens.clone();
        let handed = Arc::new(AtomicBool::new(false));
        let h2 = handed.clone();
        let is_default = Arc::new(AtomicBool::new(true));
        let binding = SinkBinding {
            require_sink: Some("airplay-sink.x".into()),
            expected_default: None,
            on_open: Some(Box::new(move || {
                o.lock().unwrap().push(true);
                h2.store(true, Ordering::SeqCst);
                Ok(())
            })),
            ..Default::default()
        };
        let mut r = gate_rig_bound(-20.0, false, None, 40, binding, Some(("airplay-sink.x", is_default.clone())));
        // The output is not taken before the TV's level is established.
        assert!(!handed.load(Ordering::SeqCst), "the output was taken before the gate opened");
        wait_for(|| r.state() == "armed");
        assert!(r.gate.is_open());
        assert!(handed.load(Ordering::SeqCst), "the output was not taken when the gate opened");
        // More laptop changes must not hand it over again.
        *r.level.lock().unwrap() = (55, false);
        r.ltx.send(LaptopEvent::Change).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let _atx = r.stop_sender();
        assert_eq!(opens.lock().unwrap().len(), 1, "the output was handed over more than once");

        // And the detach hook: the user picks another output mid-session.
        let detached = Arc::new(Mutex::new(0usize));
        let d = detached.clone();
        let is_default = Arc::new(AtomicBool::new(true));
        let binding = SinkBinding {
            require_sink: Some("airplay-sink.x".into()),
            expected_default: None,
            on_open: Some(Box::new(|| Ok(()))),
            on_detach: Some(Box::new(move || *d.lock().unwrap() += 1)),
        };
        let mut r = gate_rig_bound(-20.0, false, None, 40, binding, Some(("airplay-sink.x", is_default.clone())));
        wait_for(|| r.state() == "armed");
        let sets_before = r.log.lock().unwrap().iter().filter(|w| matches!(w, Wire::Set(_))).count();
        is_default.store(false, Ordering::SeqCst);
        *r.level.lock().unwrap() = (100, false);
        r.ltx.send(LaptopEvent::DefaultChanged).unwrap();
        wait_for(|| r.state().starts_with("detached"));
        r.etx.send(crate::session::ReceiverEvent::Volume { v: 0.5, muted: false }).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let _atx = r.stop_sender();
        assert_eq!(*detached.lock().unwrap(), 1, "the detach hook must fire exactly once");
        assert!(!r.gate.is_open(), "the gate is held once the output is somebody else's");
        assert_eq!(
            r.log.lock().unwrap().iter().filter(|w| matches!(w, Wire::Set(_))).count(),
            sets_before,
            "a detached session sent the TV a level (100 % would be 0 dB, AirPlay MAX)"
        );
        assert!(r.lsets.lock().unwrap().is_empty(), "a detached session wrote a laptop sink");
    }

    /// An output the user chose DURING the gate window is never taken from him.
    ///
    /// The gate window is seconds wide in production (first packet + start
    /// delay + GET + SET + read-back) and it is exactly when a headphone
    /// plug-in or a deliberate pick moves the default. Before this check the
    /// handover asked nothing and simply seized it — and silently, because
    /// afterwards `still_default()` answers "ours" and the detach rule in
    /// `steady()` can never fire.
    #[test]
    fn an_output_chosen_during_the_gate_window_is_left_alone() {
        let opened = Arc::new(AtomicBool::new(false));
        let o = opened.clone();
        let detached = Arc::new(Mutex::new(0usize));
        let d = detached.clone();
        let binding = SinkBinding {
            require_sink: Some("airplay-sink.x".into()),
            expected_default: None,
            on_open: Some(Box::new(move || {
                o.store(true, Ordering::SeqCst);
                Ok(())
            })),
            on_detach: Some(Box::new(move || *d.lock().unwrap() += 1)),
        };
        // Read 1 (the snapshot, before the start sequence): the speakers.
        // Read 2 (just before the handover): the user moved to the headphones.
        let script = output_script(&[Some("alsa_output.speakers"), Some("alsa_output.headphones")]);
        let mut r = gate_rig_output(
            -20.0,
            false,
            None,
            40,
            binding,
            Some(("airplay-sink.x", Arc::new(AtomicBool::new(true)))),
            Some(script),
        );
        wait_for(|| r.state().starts_with("detached"));
        std::thread::sleep(Duration::from_millis(60));
        let _atx = r.stop_sender();
        assert!(!opened.load(Ordering::SeqCst), "the output was taken from a user who had just chosen another one");
        assert_eq!(*detached.lock().unwrap(), 1, "the claim must be dropped so teardown cannot undo his choice");
        assert!(r.state().contains("alsa_output.headphones"), "{}", r.state());
        assert!(!r.gate.is_open(), "the gate must stay held");
        assert_eq!(r.real_frames(), 0, "audio must stay silent");
        assert!(r.lsets.lock().unwrap().is_empty(), "nothing was written to a laptop sink");
    }

    /// The window this driver cannot see on its own: the output moves between
    /// `AirPlaySink::publish` and this thread starting.
    ///
    /// A baseline sampled HERE would already be the new device, the check
    /// would compare it with itself, and the handover would go ahead — taking
    /// the output the user had just moved to, and then, at the end, putting the
    /// PRE-session sink back over his newer choice. The baseline therefore
    /// comes from the sink (`expected_default`), which recorded it at publish
    /// and is the value teardown will restore: one fact, checked against
    /// itself, instead of two samples taken at different times.
    #[test]
    fn an_output_moved_before_the_driver_started_is_not_taken_either() {
        let opened = Arc::new(AtomicBool::new(false));
        let o = opened.clone();
        let detached = Arc::new(Mutex::new(0usize));
        let d = detached.clone();
        let binding = SinkBinding {
            require_sink: Some("airplay-sink.x".into()),
            // What the sink recorded at publish, and will put back.
            expected_default: Some("alsa_output.speakers".into()),
            on_open: Some(Box::new(move || {
                o.store(true, Ordering::SeqCst);
                Ok(())
            })),
            on_detach: Some(Box::new(move || *d.lock().unwrap() += 1)),
        };
        // EVERY read this thread makes — including the one it would have used
        // as its own baseline — already says the headphones. Only the sink's
        // record still knows the session began on the speakers.
        let script = output_script(&[Some("alsa_output.headphones")]);
        let mut r = gate_rig_output(
            -20.0,
            false,
            None,
            40,
            binding,
            Some(("airplay-sink.x", Arc::new(AtomicBool::new(true)))),
            Some(script),
        );
        wait_for(|| r.state().starts_with("detached"));
        std::thread::sleep(Duration::from_millis(60));
        let _atx = r.stop_sender();
        assert!(
            !opened.load(Ordering::SeqCst),
            "the output moved before this thread started, and the handover took it anyway"
        );
        assert_eq!(*detached.lock().unwrap(), 1, "his choice must be left alone, claim dropped");
        assert!(r.state().contains("alsa_output.headphones"), "{}", r.state());
        assert!(!r.gate.is_open(), "the gate must stay held");
        assert_eq!(r.real_frames(), 0, "audio must stay silent");
    }

    /// The same check, unable to answer: neither seize the output on a guess
    /// nor drop a claim that describes nothing we touched.
    #[test]
    fn an_unreadable_output_is_not_taken_and_not_disowned() {
        let opened = Arc::new(AtomicBool::new(false));
        let o = opened.clone();
        let detached = Arc::new(Mutex::new(0usize));
        let d = detached.clone();
        let binding = SinkBinding {
            require_sink: Some("airplay-sink.x".into()),
            expected_default: None,
            on_open: Some(Box::new(move || {
                o.store(true, Ordering::SeqCst);
                Ok(())
            })),
            on_detach: Some(Box::new(move || *d.lock().unwrap() += 1)),
        };
        // Snapshot fine; every later read fails (the retries too).
        let script = output_script(&[Some("alsa_output.speakers"), None]);
        let mut r = gate_rig_output(
            -20.0,
            false,
            None,
            40,
            binding,
            Some(("airplay-sink.x", Arc::new(AtomicBool::new(true)))),
            Some(script),
        );
        wait_for(|| r.state().starts_with("error: could not read which output"));
        std::thread::sleep(Duration::from_millis(60));
        let _atx = r.stop_sender();
        assert!(!opened.load(Ordering::SeqCst), "an unknown output must never be seized on a guess");
        assert_eq!(*detached.lock().unwrap(), 0, "nothing was taken, so nothing may be disowned");
        assert!(r.state().contains("keeps its output"), "{}", r.state());
        assert!(!r.gate.is_open());
        assert_eq!(r.real_frames(), 0);
    }

    /// And the check does not stand in the way of the ordinary session: an
    /// output that never moved is handed over exactly as before.
    #[test]
    fn an_unmoved_output_is_still_handed_over() {
        let opened = Arc::new(AtomicBool::new(false));
        let o = opened.clone();
        let binding = SinkBinding {
            require_sink: Some("airplay-sink.x".into()),
            expected_default: None,
            on_open: Some(Box::new(move || {
                o.store(true, Ordering::SeqCst);
                Ok(())
            })),
            ..Default::default()
        };
        // One entry: every read answers the same sink.
        let script = output_script(&[Some("alsa_output.speakers")]);
        let mut r = gate_rig_output(
            -20.0,
            false,
            None,
            40,
            binding,
            Some(("airplay-sink.x", Arc::new(AtomicBool::new(true)))),
            Some(script),
        );
        wait_for(|| r.state() == "armed");
        let _atx = r.stop_sender();
        assert!(opened.load(Ordering::SeqCst), "an unmoved output must still be handed over");
        assert!(r.gate.is_open());
    }

    /// The handover fails (something else owns the output): the gate is held,
    /// so the session is silent rather than playing somewhere unknown.
    #[test]
    fn a_failed_handover_holds_the_gate() {
        let binding = SinkBinding {
            require_sink: Some("airplay-sink.x".into()),
            expected_default: None,
            on_open: Some(Box::new(|| Err("the default output reads \"alsa_output.hdmi\"".into()))),
            ..Default::default()
        };
        let is_default = Arc::new(AtomicBool::new(true));
        let mut r = gate_rig_bound(-20.0, false, None, 40, binding, Some(("airplay-sink.x", is_default)));
        wait_for(|| r.state().starts_with("error: could not hand the output to the AirPlay sink"));
        std::thread::sleep(Duration::from_millis(60));
        let _atx = r.stop_sender();
        assert!(!r.gate.is_open(), "the gate must be held again after a failed handover");
        assert_eq!(r.real_frames(), 0, "audio must stay silent");
        assert!(r.state().contains("keeps its output"), "{}", r.state());
    }

    #[test]
    fn audio_death_stops_both_directions() {
        let mut r = gate_rig(-20.0, false, None, 17);
        wait_for(|| r.state() == "armed");
        let atx = r.stop_sender();
        atx.send(crate::audio::AudioEvent::SourceError("pipewire core error EPIPE".into())).unwrap();
        wait_for(|| r.state().starts_with("disabled: audio stopped"));
        assert!(r.state().contains("EPIPE"), "{}", r.state());
        let sets_before = r.log.lock().unwrap().iter().filter(|w| matches!(w, Wire::Set(_))).count();
        *r.level.lock().unwrap() = (50, false);
        r.ltx.send(LaptopEvent::Change).unwrap();
        r.etx.send(crate::session::ReceiverEvent::Volume { v: 0.8, muted: false }).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(r.log.lock().unwrap().iter().filter(|w| matches!(w, Wire::Set(_))).count(), sets_before);
        assert!(r.lsets.lock().unwrap().is_empty());
        assert!(!r.gate.is_open());
        // And a sender that just goes away (capture Ended) counts too.
        let mut r = gate_rig(-20.0, false, None, 17);
        wait_for(|| r.state() == "armed");
        drop(r.stop_sender());
        wait_for(|| r.state().starts_with("disabled: audio stopped (the audio sender ended)"));
    }

    /// A laptop whose followed sink switches on refresh_target.
    struct SwitchLaptop {
        levels: [(u8, bool); 2],
        cur: Arc<Mutex<usize>>,
        rx: Option<Receiver<LaptopEvent>>,
        sets: Arc<Mutex<Vec<(u8, bool)>>>,
    }
    impl LaptopVolume for SwitchLaptop {
        fn read(&mut self) -> io::Result<LaptopLevel> {
            let (p, m) = self.levels[*self.cur.lock().unwrap()];
            Ok(lvl(p, m))
        }
        fn set(&mut self, pct: u8, muted: bool) -> io::Result<()> {
            self.sets.lock().unwrap().push((pct, muted));
            Ok(())
        }
        fn subscribe(&mut self) -> io::Result<Receiver<LaptopEvent>> {
            Ok(self.rx.take().unwrap())
        }
        fn refresh_target(&mut self) -> bool {
            let mut c = self.cur.lock().unwrap();
            let was = *c;
            *c = 1;
            was != 1
        }
        fn describe(&self) -> String {
            "fake switch".into()
        }
    }

    #[test]
    fn default_sink_switch_to_100_sends_nothing() {
        let tv = Arc::new(Mutex::new(TvLog { db: -20.0, ..Default::default() }));
        let (ltx, lrx) = mpsc::channel();
        let cur = Arc::new(Mutex::new(0usize));
        let lsets = Arc::new(Mutex::new(vec![]));
        let laptop = SwitchLaptop { levels: [(30, false), (100, false)], cur: cur.clone(), rx: Some(lrx), sets: lsets.clone() };
        let (etx, erx) = mpsc::sync_channel(8);
        let (atx, arx) = mpsc::channel();
        let status: StatusSink = Default::default();
        let h = spawn_volume_sync(Box::new(laptop), Box::new(FakeTv(tv.clone())), erx, arx, Arc::new(crate::clock::BoottimeClock), status.clone(), fast());
        atx.send(crate::audio::AudioEvent::FirstPacketSent(crate::clock::BoottimeClock.read())).unwrap();
        wait_for(|| status.lock().unwrap().state == "armed");
        assert_eq!(tv.lock().unwrap().sets, vec![-2100]);
        ltx.send(LaptopEvent::DefaultChanged).unwrap();
        wait_for(|| *cur.lock().unwrap() == 1);
        std::thread::sleep(Duration::from_millis(300));
        ltx.send(LaptopEvent::Change).unwrap(); // pactl re-reports the new sink
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(tv.lock().unwrap().sets, vec![-2100], "a sink switch is not a key press");
        assert_eq!(status.lock().unwrap().laptop_pct, Some(100));
        let st = h.join(Duration::from_secs(2));
        assert_eq!(st.sets_to_tv, 1);
        assert!(lsets.lock().unwrap().is_empty(), "no restore onto a different sink");
        drop((etx, atx));
    }

    #[test]
    fn tv_remote_change_undone_at_session_end() {
        let tv = Arc::new(Mutex::new(TvLog { db: -20.0, ..Default::default() }));
        let (_ltx, lrx) = mpsc::channel();
        let level = Arc::new(Mutex::new((40u8, false)));
        let lsets = Arc::new(Mutex::new(vec![]));
        let laptop = FakeLaptop { level: level.clone(), sets: lsets.clone(), rx: Some(lrx) };
        let (etx, erx) = mpsc::sync_channel(8);
        let (atx, arx) = mpsc::channel();
        let status: StatusSink = Default::default();
        let h = spawn_volume_sync(Box::new(laptop), Box::new(FakeTv(tv.clone())), erx, arx, Arc::new(crate::clock::BoottimeClock), status.clone(), fast());
        atx.send(crate::audio::AudioEvent::FirstPacketSent(crate::clock::BoottimeClock.read())).unwrap();
        wait_for(|| status.lock().unwrap().state == "armed");
        etx.send(crate::session::ReceiverEvent::Volume { v: 1.0, muted: false }).unwrap();
        wait_for(|| !lsets.lock().unwrap().is_empty());
        assert_eq!(*level.lock().unwrap(), (100, false));
        h.join(Duration::from_secs(2));
        assert_eq!(*level.lock().unwrap(), (40, false), "the laptop is back where the user left it");
        assert_eq!(*lsets.lock().unwrap(), vec![(100, false), (40, false)]);
        drop(atx);
    }

    #[test]
    fn update_info_during_start_is_recorded() {
        // Frozen clock: had the updateInfo been recorded, the dvlc 0.0 right
        // after it is inside every guard. The old driver discarded it.
        let tv = Arc::new(Mutex::new(TvLog { db: -15.0, ..Default::default() }));
        let (_ltx, lrx) = mpsc::channel();
        let lsets = Arc::new(Mutex::new(vec![]));
        let laptop = FakeLaptop { level: Arc::new(Mutex::new((50, false))), sets: lsets.clone(), rx: Some(lrx) };
        let (etx, erx) = mpsc::sync_channel(8);
        let (atx, arx) = mpsc::channel();
        let status: StatusSink = Default::default();
        let clock = Arc::new(FakeClock::new(1000.0));
        let mut t = fast();
        t.arm_grace = Duration::from_millis(300);
        let h = spawn_volume_sync(Box::new(laptop), Box::new(FakeTv(tv.clone())), erx, arx, clock, status.clone(), t);
        atx.send(crate::audio::AudioEvent::FirstPacketSent(crate::clock::BoottimeClock.read())).unwrap();
        wait_for(|| tv.lock().unwrap().gets >= 2); // read-back done: in arm_grace now
        etx.send(crate::session::ReceiverEvent::UpdateInfo).unwrap();
        wait_for(|| status.lock().unwrap().state == "armed");
        etx.send(crate::session::ReceiverEvent::Volume { v: 0.0, muted: false }).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(lsets.lock().unwrap().is_empty(), "the spurious 0.0 set the laptop to 0 %");
        h.join(Duration::from_secs(2));
        drop(atx);
    }
}
