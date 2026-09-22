//! audio: the type-96 ALAC audio stream, sender side. Ported from
//! probe.alac_uncompressed_frame / probe.AudioSender (probe.py 506-620).
//!
//! This module is the packet layer: pure functions for the ALAC "escape"
//! frame, the RTP header, the ChaCha20-Poly1305 seal and the control-port
//! TimeAnnounce/sync packet, plus [`AudioTimeline`], the one and only producer
//! of audio RTP. All of it is pinned byte-for-byte to the probe by
//! `tests/vectors/audio-packets.json` (see `tests/vectors.rs`).
//!
//! # The silent-audio bug, and why it cannot happen here
//!
//! The probe's first version sent its anchoring TimeAnnounce (0x90) when the
//! sender thread started; `parec` then took hundreds of ms to deliver the first
//! sample, so every packet reached the TV after its play-out time and the TV
//! silently dropped all of them. The fix is to anchor RTP to the clock at the
//! moment the FIRST SAMPLE IS ACTUALLY SENT, and to re-anchor after a stall.
//!
//! Here that is structural rather than a convention:
//! * [`AudioTimeline`] has no public way to set its clock mapping.
//! * [`AudioTimeline::emit`] is the only function that returns audio RTP bytes,
//!   and it returns them together with the sync packet that must precede them,
//!   in one [`Emitted`] value. On the first frame that sync is always a 0x90.
//! * `emit` takes a [`ClockReading`], which only a [`SenderClock`] read can
//!   produce, and a full PCM frame. A caller therefore has to have a frame in
//!   hand before it can have a timestamp for it: capture start-up time cannot
//!   enter the timeline.
//! * A frame that would arrive late against its deadline (or after a gap
//!   of more than 250 ms, e.g. a capture stall or a suspend, which BOOTTIME counts)
//!   re-anchors instead of being sent late.
//! * A periodic 0x80 never silently moves the receiver's timeline by more
//!   than [`PERIODIC_STEP_MAX`]; a bigger step becomes a 0x90 on the next
//!   frame. The sender drops a queued backlog before a gap/late anchor and
//!   drops frames more than [`EARLY_MAX`] ahead of the clock, so a backlog is
//!   never burst at the receiver.
//!
//! # Volume safety
//!
//! The production sender is gated by an [`AudioGate`]: it sends digital
//! silence (real packets, zeroed PCM, same timeline) until whoever sets the
//! receiver's volume opens the gate. Nothing in this module opens it.
//!
//! [`SenderClock`]: crate::clock::SenderClock

use crate::clock::ClockReading;
use crate::timing::NtpTimestamp;
use std::time::Duration;

/// Samples per ALAC frame (re-exported from `session`, not duplicated).
pub const ALAC_SPF: usize = crate::session::ALAC_SPF as usize;
/// Audio sample rate, Hz.
pub const AUDIO_RATE: u32 = crate::session::AUDIO_RATE;
/// One frame of s16le stereo PCM: 352 samples x 2 channels x 2 bytes.
pub const PCM_FRAME_BYTES: usize = ALAC_SPF * 4;
/// One uncompressed ALAC frame: 23 header bits + 11264 sample bits + 3-bit
/// end tag, padded to a byte.
pub const ALAC_FRAME_BYTES: usize = 1412;
/// 12-byte RTP header + sealed ALAC + 16-byte tag + 8-byte clear nonce.
pub const RTP_PACKET_BYTES: usize = 12 + ALAC_FRAME_BYTES + 16 + 8;
/// A send gap longer than this re-anchors the timeline (probe: `> 0.25`).
pub const REANCHOR_GAP: Duration = Duration::from_millis(250);
/// A frame that would reach its deadline with less than this margin re-anchors.
///
/// MUST stay below 100 ms: the probe's `sequence_small_gap_no_reanchor` vector
/// (a 200 ms stall with 300 ms latency, i.e. 100 ms of slack left) is required
/// NOT to re-anchor, and `tests/vectors.rs` pins that.
pub const LATE_MARGIN: Duration = Duration::from_millis(50);
/// Period of the 0x80 sync packets (probe: `now - last_sync >= 1.0`).
pub const SYNC_INTERVAL: Duration = Duration::from_secs(1);
/// Payload type of the audio RTP stream.
pub const RTP_PAYLOAD_TYPE: u8 = 0x60;
/// Control-port TimeAnnounce/sync packet type.
pub const SYNC_PACKET_TYPE: u8 = 0xD4;

/// The most a periodic sync may move the implied play-out time of the next
/// RTP (compared with the mapping the receiver already holds) and still go
/// out as a plain 0x80. A bigger step (a backlog burst after an anchor, or an
/// accumulated sub-gap stall) is announced honestly: the 0x80 is withheld and
/// the NEXT frame carries a 0x90 ([`AnchorReason::Step`]).
///
/// Well above the steady-state step (one frame, ~8 ms, inherited from the
/// probe and pinned by the golden vectors) and capture quantum jitter; well
/// below the 250 ms gap rule.
pub const PERIODIC_STEP_MAX: Duration = Duration::from_millis(100);
/// A frame whose place on the current mapping is more than this far AHEAD of
/// the clock (a backlog released faster than real time, e.g. a source that
/// catches up after a suspend) is dropped by the sender instead of sent, so a
/// backlog can never flood the receiver or pile up in its buffer.
pub const EARLY_MAX: Duration = REANCHOR_GAP;
/// On a gap/late re-anchor the sender drops at most this many queued frames
/// (about 6 s) so the anchor maps the NEWEST audio to now. Bounded so a source
/// that can produce frames without limit cannot spin the sender forever.
pub const MAX_BACKLOG_DRAIN: u64 = 750;
/// The only audio latency proven clean on the Frame over Wi-Fi (85 ms broke
/// up). Anything the receiver is told below this is UNPROVEN.
pub const PROVEN_LATENCY_MS: u32 = 300;

const _: () = assert!(PCM_FRAME_BYTES == 1408);
const _: () = assert!(RTP_PACKET_BYTES == 1448);
const _: () = assert!(LATE_MARGIN.as_millis() < 100);
const _: () = assert!(PERIODIC_STEP_MAX.as_millis() > 20 && PERIODIC_STEP_MAX.as_millis() < REANCHOR_GAP.as_millis());

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AudioError {
    #[error("A/V offset {0} ms is outside the allowed range {min}..={max} ms", min = AV_OFFSET_MIN_MS, max = AV_OFFSET_MAX_MS)]
    AvOffsetOutOfRange(i32),
}

// --------------------------------------------------------------------------
// Latency: one value for SETUP latencyMax and every sync packet
// --------------------------------------------------------------------------

/// Latency in samples: `ms * 44100 / 1000`, integer.
///
/// The probe computes `int(ms / 1000 * 44100)` in floats, which disagrees with
/// the exact integer for some inputs (e.g. 350 ms -> 15434 vs 15435, 570 ms ->
/// 25136 vs 25137). The integer form is what `build_audio_setup_plist` has
/// always sent, it agrees at the proven 300 ms (13230), and because both the
/// SETUP and the sync packets take their value from [`AudioLatency::samples`],
/// the receiver can never be told two different numbers.
pub fn latency_samples(ms: u32) -> u32 {
    (ms as u64 * AUDIO_RATE as u64 / 1000) as u32
}

pub const EFFECTIVE_LATENCY_MIN_MS: u32 = 200;
pub const EFFECTIVE_LATENCY_MAX_MS: u32 = 2000;
pub const AV_OFFSET_MIN_MS: i32 = -100;
pub const AV_OFFSET_MAX_MS: i32 = 1500;

/// The audio latency the receiver is told to buffer, including the A/V offset.
///
/// `effective = base + av_offset`, clamped to
/// [`EFFECTIVE_LATENCY_MIN_MS`]..=[`EFFECTIVE_LATENCY_MAX_MS`]. The offset is
/// only ever applied here, inside the latency the receiver was told about, so
/// it never puts timestamps in the future and never makes audio late.
///
/// 85 ms is known to break up on Wi-Fi and 300 ms is proven clean; the 200 ms
/// floor is UNPROVEN on the TV (callers should warn below 300).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioLatency {
    base_ms: u32,
    av_offset_ms: i32,
}

impl AudioLatency {
    /// Rejects an A/V offset outside `-100..=1500` ms; clamps the effective
    /// latency into `200..=2000` ms.
    pub fn new(base_ms: u32, av_offset_ms: i32) -> Result<Self, AudioError> {
        if !(AV_OFFSET_MIN_MS..=AV_OFFSET_MAX_MS).contains(&av_offset_ms) {
            return Err(AudioError::AvOffsetOutOfRange(av_offset_ms));
        }
        Ok(AudioLatency {
            base_ms,
            av_offset_ms,
        })
    }

    pub fn base_ms(&self) -> u32 {
        self.base_ms
    }

    pub fn av_offset_ms(&self) -> i32 {
        self.av_offset_ms
    }

    /// `base + offset`, clamped to 200..=2000 ms.
    pub fn effective_ms(&self) -> u32 {
        let e = self.base_ms as i64 + self.av_offset_ms as i64;
        e.clamp(EFFECTIVE_LATENCY_MIN_MS as i64, EFFECTIVE_LATENCY_MAX_MS as i64) as u32
    }

    /// THE latency value: SETUP `latencyMax` and every sync packet's latency
    /// field come from here.
    pub fn samples(&self) -> u32 {
        latency_samples(self.effective_ms())
    }

    /// True when the EFFECTIVE latency (what the receiver is actually told,
    /// offset included) is below [`PROVEN_LATENCY_MS`]. Callers must warn on
    /// this, not on the base value: `--latency 300 --av-offset -100` tells
    /// the TV 200 ms.
    pub fn below_proven(&self) -> bool {
        self.effective_ms() < PROVEN_LATENCY_MS
    }
}

/// A/V offset default for a receiver model.
///
/// UNCALIBRATED. This Frame ignores video PTS and adds ~400 ms of its own
/// buffering; the right value can only be measured on the TV with a listener present.
/// Every entry is 0 with `calibrated: false` until someone measures it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AvOffset {
    /// Milliseconds added to the audio latency (positive = audio later).
    pub ms: i32,
    /// False until measured on that receiver.
    pub calibrated: bool,
    /// Where the value came from, for `status`.
    pub source: &'static str,
}

/// Per-model A/V offset table. See [`AvOffset`]: UNCALIBRATED, needs the TV.
pub fn av_offset_default(model: &str) -> AvOffset {
    match model {
        // Samsung The Frame, the only receiver milestone 4 targets. Calibrated
        // BY EAR on 2026-09-21 against the office Frame, mirroring a screen
        // with video playing: the tester reported "seems like a tiny fraction behind…
        // so close that it's hard to tell which is ahead or behind". That puts
        // it inside the window where lip sync reads as synchronised (roughly
        // 45 ms of sound-early to 125 ms of sound-late), so 0 is right and the
        // knob is not hiding work that is owed.
        //
        // The limits of that, stated plainly: this is one person, one session,
        // one piece of content, and it cannot resolve a small constant offset
        // or say which direction the residue runs. A measurement — a synced
        // flash and click filmed off the screen — would, and would also cover
        // whether the offset holds at other frame rates. Worth doing only if
        // sync ever reads as wrong; until then this is calibrated enough to
        // believe, and honest about how.
        "LS03F" => AvOffset {
            ms: 0,
            calibrated: true,
            source: "by ear on the office Frame, 2026-09-21: inside the perceptual window",
        },
        _ => AvOffset {
            ms: 0,
            calibrated: false,
            source: "default (uncalibrated)",
        },
    }
}

// --------------------------------------------------------------------------
// Pure packet functions
// --------------------------------------------------------------------------

/// ALAC frame header, 23 bits: channel tag 1 (stereo pair, 3 bits), instance 0
/// (4), 12 unused bits, has-size 0, 2 unused, not-compressed 1.
const ALAC_HEADER: u32 = (1 << 20) | 1;
const ALAC_HEADER_BITS: usize = 23;
const ALAC_END_TAG: u32 = 0b111;

/// Wrap 352 stereo s16le samples in an uncompressed ("escape") ALAC frame:
/// the 23-bit header, the samples big-endian, then end tag 7, zero padded.
/// Port of probe.alac_uncompressed_frame.
pub fn alac_escape_frame(pcm: &[u8; PCM_FRAME_BYTES]) -> [u8; ALAC_FRAME_BYTES] {
    let mut out = [0u8; ALAC_FRAME_BYTES];
    let mut bit = 0usize;
    let mut put = |value: u32, nbits: usize| {
        for i in (0..nbits).rev() {
            if value >> i & 1 == 1 {
                out[bit / 8] |= 0x80 >> (bit % 8);
            }
            bit += 1;
        }
    };
    put(ALAC_HEADER, ALAC_HEADER_BITS);
    for s in pcm.as_chunks::<2>().0 {
        // s16le -> the same 16 bits big-endian.
        put(u16::from_le_bytes([s[0], s[1]]) as u32, 16);
    }
    put(ALAC_END_TAG, 3);
    out
}

/// Inverse of [`alac_escape_frame`], for tests and the fake receiver. None
/// unless the header, end tag and padding are exactly what we emit.
pub fn alac_escape_decode(alac: &[u8; ALAC_FRAME_BYTES]) -> Option<[u8; PCM_FRAME_BYTES]> {
    let mut bit = 0usize;
    let mut get = |nbits: usize| -> u32 {
        let mut v = 0u32;
        for _ in 0..nbits {
            v = v << 1 | ((alac[bit / 8] >> (7 - bit % 8)) & 1) as u32;
            bit += 1;
        }
        v
    };
    if get(ALAC_HEADER_BITS) != ALAC_HEADER {
        return None;
    }
    let mut pcm = [0u8; PCM_FRAME_BYTES];
    for s in pcm.as_chunks_mut::<2>().0 {
        s.copy_from_slice(&(get(16) as u16).to_le_bytes());
    }
    if get(3) != ALAC_END_TAG {
        return None;
    }
    let pad = ALAC_FRAME_BYTES * 8 - ALAC_HEADER_BITS - PCM_FRAME_BYTES * 8 - 3;
    if get(pad) != 0 {
        return None;
    }
    Some(pcm)
}

/// `80 60 seq(BE16) rtp(BE32) 00000000` (version 2, PT 96, SSRC 0).
pub fn rtp_header(seq: u16, rtp: u32) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0] = 0x80;
    h[1] = RTP_PAYLOAD_TYPE;
    h[2..4].copy_from_slice(&seq.to_be_bytes());
    h[4..8].copy_from_slice(&rtp.to_be_bytes());
    h
}

/// One audio RTP packet: header ++ ChaCha20-Poly1305(shk, nonce_counter(counter),
/// aad = header[4..12]) of the ALAC frame (ciphertext ++ 16-byte tag) ++
/// LE64(counter) in clear.
pub fn audio_rtp_packet(
    seq: u16,
    rtp: u32,
    counter: u64,
    shk: &[u8; 32],
    alac: &[u8; ALAC_FRAME_BYTES],
) -> [u8; RTP_PACKET_BYTES] {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    let header = rtp_header(seq, rtp);
    let mut pkt = [0u8; RTP_PACKET_BYTES];
    pkt[..12].copy_from_slice(&header);
    let body = &mut pkt[12..12 + ALAC_FRAME_BYTES];
    body.copy_from_slice(alac);
    let nonce = crate::crypto::nonce_counter(counter);
    let tag = ChaCha20Poly1305::new(shk.into())
        .encrypt_in_place_detached((&nonce).into(), &header[4..12], body)
        .expect("ChaCha20Poly1305 seal of 1412 bytes");
    pkt[12 + ALAC_FRAME_BYTES..12 + ALAC_FRAME_BYTES + 16].copy_from_slice(&tag);
    pkt[RTP_PACKET_BYTES - 8..].copy_from_slice(&counter.to_le_bytes());
    pkt
}

/// Control-port TimeAnnounce/sync:
/// `[0x90 first | 0x80] d4 0004 (rtp_now - latency)(BE32) ntp(BE64) rtp_now(BE32)`.
/// Port of probe.AudioSender._sync.
pub fn time_announce(first: bool, rtp_now: u32, latency_samples: u32, ntp: NtpTimestamp) -> [u8; 20] {
    let mut p = [0u8; 20];
    p[0] = if first { 0x90 } else { 0x80 };
    p[1] = SYNC_PACKET_TYPE;
    p[2..4].copy_from_slice(&4u16.to_be_bytes());
    p[4..8].copy_from_slice(&rtp_now.wrapping_sub(latency_samples).to_be_bytes());
    p[8..16].copy_from_slice(&ntp.to_be_bytes());
    p[16..20].copy_from_slice(&rtp_now.to_be_bytes());
    p
}

/// One frame of the probe's test tone starting at absolute sample `t`: an
/// 880 Hz sine at `level` (0..1), gated to a 150 ms beep each second,
/// duplicated to both channels. Float order and truncation follow probe's
/// numpy expression exactly (`(level*sin(2*pi*880*n/44100)*beep*32767)` cast
/// to int16 toward zero).
pub fn tone_frame(t: u64, level: f64) -> [u8; PCM_FRAME_BYTES] {
    let mut out = [0u8; PCM_FRAME_BYTES];
    let k = 2.0 * std::f64::consts::PI * 880.0;
    for j in 0..ALAC_SPF {
        let n = t + j as u64;
        let phase = (n % AUDIO_RATE as u64) as f64 / AUDIO_RATE as f64;
        let beep = if phase < 0.15 { 1.0 } else { 0.0 };
        let wave = level * (k * n as f64 / AUDIO_RATE as f64).sin() * beep;
        let s = ((wave * 32767.0) as i16).to_le_bytes();
        out[j * 4..j * 4 + 2].copy_from_slice(&s);
        out[j * 4 + 2..j * 4 + 4].copy_from_slice(&s);
    }
    out
}

/// Duration of `samples` at 44.1 kHz.
pub fn samples_to_duration(samples: u32) -> Duration {
    Duration::from_nanos(samples as u64 * 1_000_000_000 / AUDIO_RATE as u64)
}

// --------------------------------------------------------------------------
// The timeline: the only producer of audio RTP
// --------------------------------------------------------------------------

/// Why a frame carried a 0x90 anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorReason {
    /// The first frame of the stream.
    First,
    /// The send gap before this frame (> [`REANCHOR_GAP`]).
    Gap(Duration),
    /// How far past `deadline - LATE_MARGIN` this frame would have been sent.
    Late(Duration),
    /// The sender could not deliver the previous sync packet (a send error),
    /// so the receiver's mapping is unknown: anchor afresh.
    Forced,
    /// The periodic sync would have moved the implied play-out of the next
    /// RTP by this much (more than [`PERIODIC_STEP_MAX`]); instead of a silent
    /// 0x80 step, this frame re-anchors.
    Step(Duration),
}

/// What [`AudioTimeline::emit`] produced for one frame. Send `sync` (if any)
/// to the receiver's control port FIRST, then `rtp` to its data port.
#[derive(Clone, Debug)]
pub struct Emitted {
    pub sync: Option<[u8; 20]>,
    pub rtp: [u8; RTP_PACKET_BYTES],
    pub anchored: Option<AnchorReason>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AudioStats {
    pub packets: u64,
    /// 0x90 packets (first + re-anchors).
    pub anchors: u64,
    /// All sync packets, 0x90 and 0x80.
    pub syncs: u64,
    pub gap_reanchors: u64,
    pub late_reanchors: u64,
    /// Re-anchors forced by [`AudioTimeline::force_reanchor`] (a sync packet
    /// that could not be sent).
    pub forced_reanchors: u64,
    /// Re-anchors that replaced a periodic 0x80 which would have stepped the
    /// mapping by more than [`PERIODIC_STEP_MAX`].
    pub step_reanchors: u64,
}

#[derive(Clone, Copy, Debug)]
struct Mapping {
    at: ClockReading,
    rtp: u32,
}

/// Sequence/RTP/nonce state plus the RTP<->clock mapping the receiver was
/// last told about. See the module docs for the anchor invariant.
pub struct AudioTimeline {
    shk: [u8; 32],
    latency_samples: u32,
    latency: Duration,
    seq: u16,
    rtp: u32,
    counter: u64,
    mapping: Option<Mapping>,
    last_send: Option<ClockReading>,
    last_sync: Option<ClockReading>,
    /// Set by [`periodic`](AudioTimeline::periodic) when a 0x80 would have
    /// stepped the mapping too far: the next frame anchors instead.
    pending_step: Option<Duration>,
    stats: AudioStats,
}

impl AudioTimeline {
    /// `seq0`/`rtp0` are the stream's random starting values (the probe uses
    /// `getrandbits(16)` / `getrandbits(32)`). No mapping exists yet, so the
    /// first [`emit`](Self::emit) always anchors.
    pub fn new(shk: [u8; 32], latency: &AudioLatency, seq0: u16, rtp0: u32) -> Self {
        let latency_samples = latency.samples();
        AudioTimeline {
            shk,
            latency_samples,
            latency: samples_to_duration(latency_samples),
            seq: seq0,
            rtp: rtp0,
            counter: 0,
            mapping: None,
            last_send: None,
            last_sync: None,
            pending_step: None,
            stats: AudioStats::default(),
        }
    }

    /// The latency value written into every sync packet.
    pub fn latency_samples(&self) -> u32 {
        self.latency_samples
    }

    /// RTP timestamp the next frame will carry.
    pub fn next_rtp(&self) -> u32 {
        self.rtp
    }

    /// Play-out deadline of RTP `rtp` under the current mapping.
    fn deadline(&self, m: &Mapping, rtp: u32) -> Duration {
        m.at.boot() + samples_to_duration(rtp.wrapping_sub(m.rtp)) + self.latency
    }

    /// Whether a frame emitted at `now` would carry a 0x90, and why. Pure:
    /// [`emit`](Self::emit) uses exactly this decision. The sender peeks it to
    /// drop a queued backlog BEFORE a gap/late anchor, so the anchor maps the
    /// newest audio (not the oldest) to `now`.
    pub fn anchor_due(&self, now: ClockReading) -> Option<AnchorReason> {
        match (&self.mapping, &self.last_send) {
            (None, None) => Some(AnchorReason::First),
            (None, Some(_)) => Some(AnchorReason::Forced),
            (_, None) => Some(AnchorReason::First),
            (Some(m), Some(last)) => {
                let gap = now.since(last);
                if gap > REANCHOR_GAP {
                    Some(AnchorReason::Gap(gap))
                } else if let Some(step) = self.pending_step {
                    Some(AnchorReason::Step(step))
                } else {
                    let deadline = self.deadline(m, self.rtp);
                    let send_by = deadline.saturating_sub(LATE_MARGIN);
                    if now.boot() > send_by {
                        Some(AnchorReason::Late(now.boot() - send_by))
                    } else {
                        None
                    }
                }
            }
        }
    }

    /// How far the next frame's place on the current mapping (the clock time
    /// its first sample corresponds to) lies AHEAD of `now`. `None` without a
    /// mapping or when the frame is not ahead. A real-time capture can never
    /// run ahead by more than its delivery quantum; a large value means a
    /// backlog is being released faster than real time.
    pub fn ahead_of(&self, now: ClockReading) -> Option<Duration> {
        let m = self.mapping.as_ref()?;
        let place = m.at.boot() + samples_to_duration(self.rtp.wrapping_sub(m.rtp));
        place.checked_sub(now.boot()).filter(|d| !d.is_zero())
    }

    /// Packetise one frame read at `now`. `now` must be read AFTER the frame
    /// was obtained from the capture (that is what makes start-up latency
    /// unable to enter the timeline).
    pub fn emit(&mut self, pcm: &[u8; PCM_FRAME_BYTES], now: ClockReading) -> Emitted {
        let reason = self.anchor_due(now);
        let sync = reason.map(|r| {
            match r {
                AnchorReason::Gap(_) => self.stats.gap_reanchors += 1,
                AnchorReason::Late(_) => self.stats.late_reanchors += 1,
                AnchorReason::Forced => self.stats.forced_reanchors += 1,
                AnchorReason::Step(_) => self.stats.step_reanchors += 1,
                AnchorReason::First => {}
            }
            self.pending_step = None;
            self.mapping = Some(Mapping { at: now, rtp: self.rtp });
            self.last_sync = Some(now);
            self.stats.anchors += 1;
            self.stats.syncs += 1;
            time_announce(true, self.rtp, self.latency_samples, now.ntp())
        });
        let alac = alac_escape_frame(pcm);
        let rtp = audio_rtp_packet(self.seq, self.rtp, self.counter, &self.shk, &alac);
        self.seq = self.seq.wrapping_add(1);
        self.rtp = self.rtp.wrapping_add(ALAC_SPF as u32);
        self.counter += 1;
        self.last_send = Some(now);
        self.stats.packets += 1;
        Emitted {
            sync,
            rtp,
            anchored: reason,
        }
    }

    /// Call after sending each frame. Once [`SYNC_INTERVAL`] has passed since
    /// the last sync, returns a 0x80 sync whose rtp_now is the NEXT frame's
    /// RTP, and moves the mapping there (probe behaviour). Never produces
    /// anything before the first anchor.
    ///
    /// A 0x80 never silently moves the receiver's timeline by more than
    /// [`PERIODIC_STEP_MAX`]: if remapping the next RTP to `now` would move its
    /// implied play-out further than that (e.g. a backlog burst after an
    /// anchor left RTP far ahead of the clock), no 0x80 is sent and the next
    /// [`emit`](Self::emit) re-anchors with a 0x90 ([`AnchorReason::Step`]),
    /// the same wire form as every other anchor (0x90 right before the RTP it
    /// names).
    pub fn periodic(&mut self, now: ClockReading) -> Option<[u8; 20]> {
        let last = self.last_sync?;
        if now.since(&last) < SYNC_INTERVAL || self.pending_step.is_some() {
            return None;
        }
        if let Some(m) = &self.mapping {
            let place = m.at.boot() + samples_to_duration(self.rtp.wrapping_sub(m.rtp));
            let step = place.abs_diff(now.boot());
            if step > PERIODIC_STEP_MAX {
                self.pending_step = Some(step);
                return None;
            }
        }
        self.mapping = Some(Mapping { at: now, rtp: self.rtp });
        self.last_sync = Some(now);
        self.stats.syncs += 1;
        Some(time_announce(false, self.rtp, self.latency_samples, now.ntp()))
    }

    pub fn stats(&self) -> AudioStats {
        self.stats
    }

    /// Forget the RTP<->clock mapping, so the next [`emit`](Self::emit)
    /// carries a 0x90 again ([`AnchorReason::Forced`]). The sender calls this
    /// when a sync packet could not be sent: the receiver may then hold a
    /// mapping we no longer describe, and the only safe move is a new anchor.
    /// RTP, sequence and nonce continue unchanged.
    pub fn force_reanchor(&mut self) {
        self.mapping = None;
        self.last_sync = None;
        self.pending_step = None;
    }
}

// --------------------------------------------------------------------------
// The sender thread
// --------------------------------------------------------------------------

use crate::audiocapture::{CaptureError, CaptureStats, PcmSource};
use crate::clock::SenderClock;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

/// How long one `next_frame` call may block. It bounds how quickly the
/// sender notices its stop flag.
pub const CAPTURE_POLL: Duration = Duration::from_millis(50);
/// Default bound on [`AudioHandle::join`] and on the join in its `Drop`.
pub const AUDIO_JOIN_BOUND: Duration = Duration::from_secs(2);

/// Everything the sender needs from the audio SETUP.
#[derive(Clone, Debug)]
pub struct AudioStreamParams {
    /// The SETUP `shk`: the ChaCha20-Poly1305 key for every RTP packet.
    pub shk: [u8; 32],
    /// The latency the SETUP declared; every sync carries the same value.
    pub latency: AudioLatency,
    pub receiver: IpAddr,
    /// The receiver's type-96 `dataPort` (RTP goes here).
    pub receiver_data_port: u16,
    /// The receiver's type-96 `controlPort` (syncs go here).
    pub receiver_control_port: u16,
}

/// Our two UDP sockets. The control socket's port is what the audio SETUP
/// advertises as `controlPort` (timing_port + 1, as the probe did); the data
/// socket is bound at timing_port + 2 (probe). Bound BEFORE the SETUP so a
/// port clash fails the bring-up instead of producing a silent stream.
#[derive(Debug)]
pub struct AudioSockets {
    pub control: UdpSocket,
    pub data: UdpSocket,
}

impl AudioSockets {
    /// `0.0.0.0:timing_port+1` (control) and `0.0.0.0:timing_port+2` (data).
    pub fn bind(timing_port: u16) -> io::Result<Self> {
        let cp = timing_port.checked_add(1).ok_or_else(|| io::Error::other("timing port too high"))?;
        let dp = timing_port.checked_add(2).ok_or_else(|| io::Error::other("timing port too high"))?;
        Ok(AudioSockets {
            control: UdpSocket::bind(("0.0.0.0", cp))?,
            data: UdpSocket::bind(("0.0.0.0", dp))?,
        })
    }

    /// TEST ONLY: two ephemeral 127.0.0.1 sockets.
    #[doc(hidden)]
    pub fn bind_ephemeral_for_test() -> io::Result<Self> {
        Ok(AudioSockets {
            control: UdpSocket::bind("127.0.0.1:0")?,
            data: UdpSocket::bind("127.0.0.1:0")?,
        })
    }

    /// The local control port (what the SETUP must advertise).
    pub fn control_port(&self) -> io::Result<u16> {
        Ok(self.control.local_addr()?.port())
    }
}

/// Whether real PCM may reach the receiver.
///
/// THE VOLUME-SAFETY GATE. The receiver applies its OWN last volume (the
/// Frame has been seen at 100 %) to everything it plays until our volume SET
/// lands, and the only proven SET form goes out seconds after the first audio
/// packet. So a gated sender sends DIGITAL SILENCE — real packets with zeroed
/// PCM, through the same timeline, so the receiver's clock mapping and the
/// 0x90 anchor are established exactly as for real audio — for as long as the
/// gate is held, and switches to the real capture only once whoever owns the
/// volume (the volume driver) calls [`open`](Self::open) after the TV's
/// volume has been set from the laptop's level.
///
/// Fail-safe by construction: a gate starts held, and nothing in this module
/// ever opens it. If the volume can never be established the stream simply
/// stays silent, and the report says so ([`AudioReport::gate_open`],
/// [`AudioReport::gate_reason`]). [`hold`](Self::hold) can put it back to
/// silence at any time (e.g. a later volume failure).
#[derive(Clone, Debug)]
pub struct AudioGate {
    inner: Arc<GateInner>,
}

#[derive(Debug)]
struct GateInner {
    open: AtomicBool,
    reason: Mutex<String>,
}

impl AudioGate {
    /// A gate that sends silence until [`open`](Self::open) is called.
    pub fn held(reason: impl Into<String>) -> Self {
        AudioGate {
            inner: Arc::new(GateInner {
                open: AtomicBool::new(false),
                reason: Mutex::new(reason.into()),
            }),
        }
    }

    /// A gate that is open from the start: real audio at whatever volume the
    /// receiver is at. Only for tests against fake receivers, and for an
    /// explicit, warned `--no-volume-sync`.
    pub fn ungated() -> Self {
        let g = AudioGate::held("ungated");
        g.open();
        g
    }

    /// Let real audio through. Call ONLY once the receiver's volume has been
    /// set from the laptop's level (and read back where possible).
    pub fn open(&self) {
        self.inner.open.store(true, Ordering::SeqCst);
    }

    /// Back to silence, with the reason status should show.
    pub fn hold(&self, reason: impl Into<String>) {
        *self.inner.reason.lock().unwrap_or_else(|p| p.into_inner()) = reason.into();
        self.inner.open.store(false, Ordering::SeqCst);
    }

    pub fn is_open(&self) -> bool {
        self.inner.open.load(Ordering::SeqCst)
    }

    /// Why the gate is held (`None` while open).
    pub fn reason(&self) -> Option<String> {
        if self.is_open() {
            None
        } else {
            Some(self.inner.reason.lock().unwrap_or_else(|p| p.into_inner()).clone())
        }
    }
}

/// Reason a production gate starts with.
pub const GATE_WAITING_FOR_VOLUME: &str = "silence until the TV volume is set from the laptop";

/// One frame of digital silence (what a held gate sends).
const SILENCE: [u8; PCM_FRAME_BYTES] = [0u8; PCM_FRAME_BYTES];

/// What the sender thread reports as it goes. Sent with `Sender::send` on an
/// unbounded channel, so the sender never blocks on a slow consumer.
#[derive(Clone, Debug)]
pub enum AudioEvent {
    /// The first RTP packet (and its 0x90 before it) left the socket; the
    /// reading is the clock read that anchored it.
    FirstPacketSent(ClockReading),
    /// A re-anchor after the first one.
    Anchored(AnchorReason),
    /// The capture failed; the sender has stopped (video continues).
    SourceError(String),
}

/// Coarse sender state for status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SenderState {
    #[default]
    Starting,
    Streaming,
    /// No frame for longer than [`REANCHOR_GAP`] (the next one re-anchors).
    Stalled,
    Error,
    Stopped,
}

impl SenderState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SenderState::Starting => "starting",
            SenderState::Streaming => "streaming",
            SenderState::Stalled => "stalled",
            SenderState::Error => "error",
            SenderState::Stopped => "stopped",
        }
    }
}

/// A snapshot of the sender, for status and the end-of-run ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AudioReport {
    pub timeline: AudioStats,
    pub capture: CaptureStats,
    /// "pipewire", "parec", "tone" or "scripted".
    pub capture_kind: &'static str,
    pub state: SenderState,
    /// Datagrams that arrived on our control socket (retransmit requests,
    /// or anything else); counted and dropped, never acted on.
    pub control_rx: u64,
    /// `send_to` failures (either socket).
    pub send_errors: u64,
    /// RTP packets actually handed to the data socket. Can be below
    /// `timeline.packets`: a frame whose anchor could not be sent is
    /// packetised but deliberately NOT sent.
    pub rtp_sent: u64,
    /// The last capture error, if the sender stopped on one.
    pub error: Option<String>,
    /// Whether the volume gate currently lets real audio through.
    pub gate_open: bool,
    /// Why the gate is held (None while open).
    pub gate_reason: Option<String>,
    /// Frames sent as digital silence because the gate was held.
    pub silenced_frames: u64,
    /// Queued frames dropped before a gap/late re-anchor (a backlog).
    pub backlog_dropped: u64,
    /// Frames dropped for being more than [`EARLY_MAX`] ahead of the clock.
    pub early_dropped: u64,
}

/// The sender thread outlived its join bound and was detached.
#[derive(Debug, thiserror::Error)]
#[error("audio sender did not stop within {0:?}; detached")]
pub struct JoinTimeout(pub Duration);

/// "Stop that sender", and nothing else: see [`AudioHandle::stopper`].
#[derive(Clone)]
pub struct AudioStopper {
    stop: Arc<AtomicBool>,
    stopper: Arc<dyn Fn() + Send + Sync>,
}

impl AudioStopper {
    /// Ask the sender to stop and unblock its capture. Idempotent, and safe
    /// after the sender has already gone.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        (self.stopper)();
    }
}

/// Handle to a running sender. `stop` + `join`, or just drop it: `Drop`
/// stops the source (kills parec / quits the PipeWire loop / wakes a fake)
/// and joins for at most [`AUDIO_JOIN_BOUND`], detaching after that, so a
/// wedged source can never hang the session's teardown.
pub struct AudioHandle {
    stop: Arc<AtomicBool>,
    stopper: Arc<dyn Fn() + Send + Sync>,
    join: Option<JoinHandle<()>>,
    report: Arc<Mutex<AudioReport>>,
    gate: AudioGate,
}

impl AudioHandle {
    /// Ask the sender to stop and unblock its capture. Idempotent.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        (self.stopper)();
    }

    /// A cloneable, `Send` handle that can do nothing but [`Self::stop`].
    ///
    /// For a watchdog that must END the stream from another thread — the
    /// session's sink watch, when the published sink node dies under a running
    /// session. It carries no ability to read, join or restart anything, so
    /// handing it out cannot extend the sender's life or race its teardown.
    pub fn stopper(&self) -> AudioStopper {
        AudioStopper {
            stop: self.stop.clone(),
            stopper: self.stopper.clone(),
        }
    }

    /// Current snapshot.
    pub fn report(&self) -> AudioReport {
        self.report.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Timeline counters.
    pub fn stats(&self) -> AudioStats {
        self.report().timeline
    }

    /// The volume gate this sender honours (a clone; opening it lets real
    /// audio through).
    pub fn gate(&self) -> AudioGate {
        self.gate.clone()
    }

    /// Stop, then wait at most `bound` for the thread. On timeout the thread
    /// is detached (it still exits on its own once the source unblocks, and
    /// drops the sockets then).
    pub fn join(mut self, bound: Duration) -> Result<AudioReport, JoinTimeout> {
        self.join_inner(bound)
    }

    fn join_inner(&mut self, bound: Duration) -> Result<AudioReport, JoinTimeout> {
        self.stop();
        let Some(h) = self.join.take() else {
            return Ok(self.report());
        };
        let deadline = Instant::now() + bound;
        while !h.is_finished() {
            if Instant::now() >= deadline {
                eprintln!("audio: sender thread did not stop within {bound:?}; detaching it");
                return Err(JoinTimeout(bound));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if h.join().is_err() {
            // The thread body catches its own panics; this is a panic in the
            // source's Drop or the final bookkeeping. Never report it as clean.
            let mut r = self.report.lock().unwrap_or_else(|p| p.into_inner());
            r.state = SenderState::Error;
            if r.error.is_none() {
                r.error = Some("audio sender thread panicked".into());
            }
        }
        Ok(self.report())
    }
}

impl Drop for AudioHandle {
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = self.join_inner(AUDIO_JOIN_BOUND);
        }
    }
}

/// Start the sender thread.
///
/// The thread loops `src.next_frame(50 ms)`. Only once a full frame is in
/// hand does it read `clock`, and that reading is what the frame (and its
/// sync, if any) is stamped with — so however long the capture takes to
/// start, that time never enters the timeline. For each frame it sends the
/// [`Emitted::sync`] (if any) from the control socket to the receiver's
/// control port FIRST, then the RTP from the data socket to the data port,
/// then any periodic 0x80. A sync that cannot be sent forces the next frame
/// to re-anchor. The control socket is drained non-blocking every loop.
///
/// UNGATED: real audio from the first packet, at whatever volume the receiver
/// is at. For tests against fake receivers; production uses
/// [`spawn_audio_sender_gated`] / [`spawn_audio_sender_into`].
pub fn spawn_audio_sender(
    p: AudioStreamParams,
    s: AudioSockets,
    src: Box<dyn PcmSource>,
    clock: Arc<dyn SenderClock>,
    events: Option<Sender<AudioEvent>>,
) -> AudioHandle {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    // probe: random.getrandbits(16) / getrandbits(32)
    let seq0: u16 = rng.gen();
    let rtp0: u32 = rng.gen();
    spawn_audio_sender_with_start(p, s, src, clock, events, seq0, rtp0)
}


/// [`spawn_audio_sender`] with explicit starting sequence number and RTP
/// timestamp (tests use this to cross the wraps deterministically). UNGATED,
/// like [`spawn_audio_sender`].
#[doc(hidden)]
pub fn spawn_audio_sender_with_start(
    p: AudioStreamParams,
    s: AudioSockets,
    src: Box<dyn PcmSource>,
    clock: Arc<dyn SenderClock>,
    events: Option<Sender<AudioEvent>>,
    seq0: u16,
    rtp0: u32,
) -> AudioHandle {
    spawn_inner(p, s, src, clock, events, Arc::default(), AudioGate::ungated(), seq0, rtp0)
}

/// The production entry point: [`spawn_audio_sender`], publishing its
/// [`AudioReport`] into `report` (which a status writer already holds), and
/// GATED: it sends digital silence until the gate returned by
/// [`AudioHandle::gate`] is opened. Nothing here opens it, so a caller that
/// never establishes the receiver's volume gets a silent stream, never real
/// audio at an unknown level. Prefer [`spawn_audio_sender_gated`] so the gate
/// exists (and can be handed to the volume driver) before the first packet.
pub fn spawn_audio_sender_into(
    p: AudioStreamParams,
    s: AudioSockets,
    src: Box<dyn PcmSource>,
    clock: Arc<dyn SenderClock>,
    events: Option<Sender<AudioEvent>>,
    report: Arc<Mutex<AudioReport>>,
) -> AudioHandle {
    spawn_audio_sender_gated(p, s, src, clock, events, report, AudioGate::held(GATE_WAITING_FOR_VOLUME))
}

/// [`spawn_audio_sender_into`] with a caller-made gate: silence while `gate`
/// is held, the real capture while it is open. Create the gate with
/// [`AudioGate::held`], give a clone to whoever sets the receiver's volume,
/// and let only that party [`open`](AudioGate::open) it.
pub fn spawn_audio_sender_gated(
    p: AudioStreamParams,
    s: AudioSockets,
    src: Box<dyn PcmSource>,
    clock: Arc<dyn SenderClock>,
    events: Option<Sender<AudioEvent>>,
    report: Arc<Mutex<AudioReport>>,
    gate: AudioGate,
) -> AudioHandle {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let (seq0, rtp0) = (rng.gen(), rng.gen());
    spawn_inner(p, s, src, clock, events, report, gate, seq0, rtp0)
}

#[allow(clippy::too_many_arguments)]
fn spawn_inner(
    p: AudioStreamParams,
    s: AudioSockets,
    mut src: Box<dyn PcmSource>,
    clock: Arc<dyn SenderClock>,
    events: Option<Sender<AudioEvent>>,
    report: Arc<Mutex<AudioReport>>,
    gate: AudioGate,
    seq0: u16,
    rtp0: u32,
) -> AudioHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let stopper: Arc<dyn Fn() + Send + Sync> = Arc::from(src.stopper());
    {
        let mut r = report.lock().unwrap_or_else(|e| e.into_inner());
        *r = AudioReport {
            capture_kind: src.kind(),
            gate_open: gate.is_open(),
            gate_reason: gate.reason(),
            ..Default::default()
        };
    }
    let (stop_t, report_t, gate_t) = (stop.clone(), report.clone(), gate.clone());
    let join = std::thread::Builder::new()
        .name("airplay-audio".into())
        .spawn(move || {
            let ctx = LoopCtx {
                p: &p,
                s: &s,
                clock: clock.as_ref(),
                events: events.as_ref(),
                stop: &stop_t,
                report: &report_t,
                gate: &gate_t,
            };
            // A panic anywhere in the loop (a source, the seal) must not leave
            // status at "streaming" with a clean join: catch it and report it
            // exactly like a capture failure.
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sender_loop(&ctx, src.as_mut(), seq0, rtp0)
            }));
            if let Err(payload) = res {
                let what = payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".into());
                ctx.fail(format!("audio sender thread panicked: {what}"));
            }
            // Drop the source HERE, on this thread, before the sockets: a
            // PipeWire source joins its loop thread in Drop.
            let cap = src.stats();
            drop(src);
            let mut r = report_t.lock().unwrap_or_else(|e| e.into_inner());
            r.capture = cap;
            if r.state != SenderState::Error {
                r.state = SenderState::Stopped;
            }
        })
        .expect("spawn audio sender thread");
    AudioHandle {
        stop,
        stopper,
        join: Some(join),
        report,
        gate,
    }
}

/// What the sender loop shares with its thread wrapper.
struct LoopCtx<'a> {
    p: &'a AudioStreamParams,
    s: &'a AudioSockets,
    clock: &'a dyn SenderClock,
    events: Option<&'a Sender<AudioEvent>>,
    stop: &'a AtomicBool,
    report: &'a Mutex<AudioReport>,
    gate: &'a AudioGate,
}

impl LoopCtx<'_> {
    /// The sender is stopping on a failure: log it, tell the event listener
    /// (the volume driver stops on this), and leave status at Error.
    fn fail(&self, msg: String) {
        eprintln!("audio: {msg}; audio stops, video continues");
        if let Some(ev) = self.events {
            let _ = ev.send(AudioEvent::SourceError(msg.clone()));
        }
        let mut r = self.report.lock().unwrap_or_else(|e| e.into_inner());
        r.state = SenderState::Error;
        r.error = Some(msg);
    }
}

/// Counters the loop publishes into the report.
#[derive(Default)]
struct LoopCounters {
    control_rx: u64,
    send_errors: u64,
    rtp_sent: u64,
    silenced: u64,
    backlog_dropped: u64,
    early_dropped: u64,
}

fn sender_loop(ctx: &LoopCtx<'_>, src: &mut dyn PcmSource, seq0: u16, rtp0: u32) {
    let (p, s, clock, events, stop) = (ctx.p, ctx.s, ctx.clock, ctx.events, ctx.stop);
    let ctrl_dst = SocketAddr::new(p.receiver, p.receiver_control_port);
    let data_dst = SocketAddr::new(p.receiver, p.receiver_data_port);
    let _ = s.control.set_nonblocking(true);
    let mut tl = AudioTimeline::new(p.shk, &p.latency, seq0, rtp0);
    let mut first_sent = false;
    let mut c = LoopCounters::default();
    let mut last_frame = Instant::now();
    let mut drain = [0u8; 2048];
    // An error met while dropping a backlog, handled on the next turn.
    let mut deferred: Option<CaptureError> = None;
    let mut gate_was_open: Option<bool> = None;
    let publish = |tl: &AudioTimeline, state: SenderState, c: &LoopCounters, cap: CaptureStats| {
        let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
        r.timeline = tl.stats();
        r.state = state;
        r.control_rx = c.control_rx;
        r.send_errors = c.send_errors;
        r.rtp_sent = c.rtp_sent;
        r.silenced_frames = c.silenced;
        r.backlog_dropped = c.backlog_dropped;
        r.early_dropped = c.early_dropped;
        r.gate_open = ctx.gate.is_open();
        r.gate_reason = ctx.gate.reason();
        r.capture = cap;
    };
    let mut last_publish = Instant::now();
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let got = match deferred.take() {
            Some(e) => Err(e),
            None => src.next_frame(CAPTURE_POLL),
        };
        // Drain whatever the receiver sent to our control port.
        while let Ok(_n) = s.control.recv(&mut drain) {
            c.control_rx += 1;
        }
        let mut block = match got {
            Ok(Some(b)) => b,
            Ok(None) => {
                if first_sent && last_frame.elapsed() > REANCHOR_GAP {
                    publish(&tl, SenderState::Stalled, &c, src.stats());
                }
                continue;
            }
            Err(CaptureError::Stopped) => break,
            // A source that closes while nobody asked it to stop (parec
            // exiting because pipewire-pulse restarted, its monitor source
            // vanishing, ...) is a FAILURE, not a clean stop. The one
            // exception is the scripted test fake, whose script simply ends.
            Err(CaptureError::Ended) if stop.load(Ordering::SeqCst) || src.kind() == "scripted" => break,
            Err(CaptureError::Ended) => {
                publish(&tl, SenderState::Error, &c, src.stats());
                ctx.fail(format!("capture ended unexpectedly (the {} source closed)", src.kind()));
                return;
            }
            Err(e) => {
                publish(&tl, SenderState::Error, &c, src.stats());
                ctx.fail(format!("capture failed: {e}"));
                return;
            }
        };
        if stop.load(Ordering::SeqCst) {
            break;
        }
        last_frame = Instant::now();
        // A gap/late re-anchor maps the frame in hand to `now`. If more frames
        // are already queued behind it (a backlog that built up while this
        // thread was stalled), anchoring the OLDEST one and then bursting the
        // rest would leave RTP ahead of the clock, and the next periodic sync
        // would silently move the receiver's timeline back by the backlog.
        // Drop the backlog instead: anchor the NEWEST frame.
        //
        // The same holds for the FIRST anchor of a real capture: whatever the
        // capture had queued when it started (measured: 110-180 ms from a
        // PipeWire monitor) would otherwise be anchored oldest-first and
        // burst out, leaving RTP that far ahead of the clock by the first
        // periodic sync, which would then have to re-anchor (Step). Only a
        // source that timestamps its frames (a live capture or the tone) is
        // drained at the start; an untimed scripted source keeps every frame.
        let drain = match tl.anchor_due(clock.read()) {
            Some(AnchorReason::Gap(_) | AnchorReason::Late(_)) => first_sent,
            Some(AnchorReason::First) => !first_sent && block.boot_ns.is_some(),
            _ => false,
        };
        if drain {
            let mut n = 0u64;
            while n < MAX_BACKLOG_DRAIN {
                match src.next_frame(Duration::ZERO) {
                    Ok(Some(b)) => {
                        block = b;
                        n += 1;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        deferred = Some(e);
                        break;
                    }
                }
            }
            if n > 0 {
                c.backlog_dropped += n;
                eprintln!("audio: dropped {n} queued frame(s) before {}", if first_sent { "re-anchoring" } else { "the first anchor" });
            }
        }
        // THE clock read for this frame: after the frame is in hand.
        let now = clock.read();
        // A frame far AHEAD of the clock on the current mapping is a backlog
        // released faster than real time (not a capture: a capture cannot
        // deliver the future). Drop it rather than flood the receiver.
        if tl.anchor_due(now).is_none() && tl.ahead_of(now).is_some_and(|a| a > EARLY_MAX) {
            c.early_dropped += 1;
            continue;
        }
        // The volume gate: silence (real packets, same timeline) until the
        // receiver's volume has been established.
        let open = ctx.gate.is_open();
        if gate_was_open != Some(open) {
            if open {
                eprintln!("audio: volume established; sending real audio");
            } else {
                eprintln!(
                    "audio: sending silence ({})",
                    ctx.gate.reason().unwrap_or_else(|| "gate held".into())
                );
            }
            gate_was_open = Some(open);
        }
        let pcm = if open {
            &block.pcm
        } else {
            c.silenced += 1;
            &SILENCE
        };
        let e = tl.emit(pcm, now);
        let mut sync_ok = true;
        if let Some(sync) = &e.sync {
            if s.control.send_to(sync, ctrl_dst).is_err() {
                c.send_errors += 1;
                sync_ok = false;
            }
        }
        if !sync_ok {
            // Never send RTP the receiver has no (or a stale) anchor for.
            tl.force_reanchor();
            continue;
        }
        match s.data.send_to(&e.rtp, data_dst) {
            Ok(_) => c.rtp_sent += 1,
            Err(_) => c.send_errors += 1,
        }
        if !first_sent {
            // emit() guarantees this frame carried a 0x90 (the first frame
            // of a timeline always anchors), and it went out first.
            debug_assert!(e.anchored.is_some());
            first_sent = true;
            if let Some(ev) = events {
                let _ = ev.send(AudioEvent::FirstPacketSent(now));
            }
        } else if let Some(r) = e.anchored {
            eprintln!("audio: re-anchored ({r:?})");
            if let Some(ev) = events {
                let _ = ev.send(AudioEvent::Anchored(r));
            }
        }
        if let Some(sync) = tl.periodic(now) {
            if s.control.send_to(&sync, ctrl_dst).is_err() {
                c.send_errors += 1;
                tl.force_reanchor();
            }
        }
        if last_publish.elapsed() >= Duration::from_millis(200) || tl.stats().packets == 1 {
            publish(&tl, SenderState::Streaming, &c, src.stats());
            last_publish = Instant::now();
        }
    }
    publish(&tl, SenderState::Stopped, &c, src.stats());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{FakeClock, SenderClock};

    const KEY: [u8; 32] = [7u8; 32];

    fn tl() -> AudioTimeline {
        AudioTimeline::new(KEY, &AudioLatency::new(300, 0).unwrap(), 0, 0)
    }
    fn spf() -> f64 {
        ALAC_SPF as f64 / AUDIO_RATE as f64
    }
    fn sync_ntp(p: &[u8; 20]) -> u64 {
        u64::from_be_bytes(p[8..16].try_into().unwrap())
    }

    #[test]
    fn first_frame_700ms_after_spawn_anchors_at_700ms() {
        let clock = FakeClock::new(1000.0);
        let spawn = clock.read();
        let mut t = tl();
        clock.advance(0.7); // capture start-up
        let now = clock.read();
        let e = t.emit(&[0u8; PCM_FRAME_BYTES], now);
        assert_eq!(e.anchored, Some(AnchorReason::First));
        let s = e.sync.expect("first frame carries a sync");
        assert_eq!(s[0], 0x90);
        assert_eq!(sync_ntp(&s), now.ntp().0);
        assert!(sync_ntp(&s) >= spawn.ntp().0 + (7u64 << 32) / 10);
    }

    #[test]
    fn no_rtp_before_first_anchor() {
        // Pseudo-random schedules: whatever the timing, the first Emitted of
        // every timeline carries a 0x90 whose rtp_now equals its RTP.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..200 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let clock = FakeClock::new(50.0 + (x % 100_000) as f64 / 7.0);
            let mut t = AudioTimeline::new(KEY, &AudioLatency::new(300, 0).unwrap(), x as u16, (x >> 16) as u32);
            // periodic before anything was sent must not produce a packet
            assert!(t.periodic(clock.read()).is_none());
            clock.advance((x % 5000) as f64 / 1000.0);
            let e = t.emit(&[1u8; PCM_FRAME_BYTES], clock.read());
            let s = e.sync.unwrap();
            assert_eq!(s[0], 0x90);
            assert_eq!(&s[16..20], &e.rtp[4..8]);
        }
    }

    fn run(gap_at: usize, gap: f64, frames: usize) -> AudioTimeline {
        let clock = FakeClock::new(1000.0);
        let mut t = tl();
        for i in 0..frames {
            clock.advance(spf());
            if i == gap_at {
                clock.advance(gap);
            }
            let now = clock.read();
            t.emit(&[0u8; PCM_FRAME_BYTES], now);
            t.periodic(now);
        }
        t
    }

    #[test]
    fn gap_300ms_reanchors() {
        let s = run(10, 0.3, 20).stats();
        assert_eq!((s.anchors, s.gap_reanchors, s.late_reanchors), (2, 1, 0));
    }

    #[test]
    fn gap_200ms_does_not() {
        let s = run(10, 0.2, 20).stats();
        assert_eq!((s.anchors, s.gap_reanchors, s.late_reanchors), (1, 0, 0));
    }

    #[test]
    fn late_frame_reanchors_before_gap_threshold() {
        // Burst-starved capture: three 240 ms gaps in a row, each below the
        // 250 ms gap rule, so the timeline falls further behind each time.
        // With 300 ms latency, the second one leaves < 50 ms of slack.
        let clock = FakeClock::new(1000.0);
        let mut t = tl();
        let mut reasons = vec![];
        for _ in 0..4 {
            let now = clock.read();
            reasons.push(t.emit(&[0u8; PCM_FRAME_BYTES], now).anchored);
            clock.advance(0.24);
        }
        assert_eq!(reasons[0], Some(AnchorReason::First));
        assert_eq!(reasons[1], None); // 232 ms behind, 68 ms of slack
        assert!(matches!(reasons[2], Some(AnchorReason::Late(_))), "{reasons:?}");
        assert_eq!(t.stats().gap_reanchors, 0);
        assert_eq!(t.stats().late_reanchors, 1);
    }

    #[test]
    fn periodic_0x80_every_second_carries_next_rtp() {
        let clock = FakeClock::new(1000.0);
        let mut t = tl();
        let mut syncs = vec![];
        for _ in 0..(3 * 44100 / ALAC_SPF + 1) {
            clock.advance(spf());
            let now = clock.read();
            t.emit(&[0u8; PCM_FRAME_BYTES], now);
            if let Some(p) = t.periodic(now) {
                assert_eq!(p[0], 0x80);
                assert_eq!(u32::from_be_bytes(p[16..20].try_into().unwrap()), t.next_rtp());
                syncs.push(now);
            }
        }
        assert_eq!(syncs.len(), 2); // 1 s and 2 s after the anchor, run is ~3 s
        let d = syncs[1].since(&syncs[0]);
        assert!(d >= SYNC_INTERVAL && d < SYNC_INTERVAL + Duration::from_millis(9));
        assert_eq!(t.stats().anchors, 1);
        assert_eq!(t.stats().syncs, 3);
    }

    #[test]
    fn latency_field_equals_setup_latency_for_all_offsets() {
        for base in [0u32, 85, 150, 200, 300, 350, 570, 1999, 5000] {
            for off in [-100, -37, 0, 1, 75, 400, 1500] {
                let lat = AudioLatency::new(base, off).unwrap();
                let clock = FakeClock::new(10.0);
                let mut t = AudioTimeline::new(KEY, &lat, 0, 12345);
                let s = t.emit(&[0u8; PCM_FRAME_BYTES], clock.read()).sync.unwrap();
                let field = 12345u32.wrapping_sub(u32::from_be_bytes(s[4..8].try_into().unwrap()));
                assert_eq!(field, lat.samples());
                assert_eq!(field, latency_samples(lat.effective_ms()));
            }
        }
        assert_eq!(latency_samples(300), 13230);
    }

    #[test]
    fn av_offset_clamps_effective_latency_floor() {
        assert_eq!(AudioLatency::new(300, -100).unwrap().effective_ms(), 200);
        assert_eq!(AudioLatency::new(150, 0).unwrap().effective_ms(), 200);
        assert_eq!(AudioLatency::new(1900, 1500).unwrap().effective_ms(), 2000);
        assert_eq!(AudioLatency::new(300, 0).unwrap().effective_ms(), 300);
        assert_eq!(AudioLatency::new(300, 400).unwrap().samples(), latency_samples(700));
        assert_eq!(AudioLatency::new(300, -101), Err(AudioError::AvOffsetOutOfRange(-101)));
        assert_eq!(AudioLatency::new(300, 1501), Err(AudioError::AvOffsetOutOfRange(1501)));
        // The Frame is calibrated by ear at 0 (see av_offset_default); an
        // unknown model is not, and must keep saying so.
        let d = av_offset_default("LS03F");
        assert_eq!((d.ms, d.calibrated), (0, true));
        assert!(!av_offset_default("anything").calibrated);
    }

    #[test]
    fn seq_rtp_counter_wrap() {
        let clock = FakeClock::new(10.0);
        let mut t = AudioTimeline::new(KEY, &AudioLatency::new(300, 0).unwrap(), 0xFFFF, 0xFFFF_FF00);
        let a = t.emit(&[0u8; PCM_FRAME_BYTES], clock.read());
        clock.advance(spf());
        let b = t.emit(&[0u8; PCM_FRAME_BYTES], clock.read());
        assert_eq!(&a.rtp[2..8], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert_eq!(&b.rtp[2..8], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x60]);
        assert_eq!(&a.rtp[1440..], &0u64.to_le_bytes());
        assert_eq!(&b.rtp[1440..], &1u64.to_le_bytes());
        assert!(b.anchored.is_none(), "rtp wrap must not look like a late frame");
    }

    #[test]
    fn suspend_counts_as_gap() {
        // BOOTTIME jumps across a suspend; the next frame re-anchors.
        let clock = FakeClock::new(1000.0);
        let mut t = tl();
        t.emit(&[0u8; PCM_FRAME_BYTES], clock.read());
        clock.advance(3600.0);
        let e = t.emit(&[0u8; PCM_FRAME_BYTES], clock.read());
        assert!(matches!(e.anchored, Some(AnchorReason::Gap(g)) if g > Duration::from_secs(3599)));
        assert_eq!(e.sync.unwrap()[0], 0x90);
    }

    /// Implied play-out time (NTP seconds) of RTP `r` under sync packet `p`.
    fn implied_playout(p: &[u8; 20], r: u32) -> f64 {
        let ntp = sync_ntp(p);
        let secs = (ntp >> 32) as f64 + (ntp & 0xFFFF_FFFF) as f64 / 4_294_967_296.0;
        let rtp_now = u32::from_be_bytes(p[16..20].try_into().unwrap());
        secs + r.wrapping_sub(rtp_now) as i32 as f64 / AUDIO_RATE as f64
    }

    #[test]
    fn backlog_burst_never_steps_the_mapping_with_a_silent_0x80() {
        // The review's repro: 200 steady frames, a 400 ms sender stall, 50
        // backlog frames at one instant, then steady frames. Before the fix
        // the next 0x80 moved play-out of a fixed RTP back ~399 ms, silently.
        let clock = FakeClock::new(1000.0);
        let mut t = tl();
        let mut syncs: Vec<[u8; 20]> = vec![];
        let mut reasons = vec![];
        let mut step = |t: &mut AudioTimeline, now: ClockReading, syncs: &mut Vec<[u8; 20]>| {
            let e = t.emit(&[0u8; PCM_FRAME_BYTES], now);
            if let Some(s) = e.sync {
                syncs.push(s);
            }
            if let Some(r) = e.anchored {
                reasons.push(r);
            }
            if let Some(s) = t.periodic(now) {
                syncs.push(s);
            }
        };
        for _ in 0..200 {
            clock.advance(spf());
            step(&mut t, clock.read(), &mut syncs);
        }
        clock.advance(0.4);
        for _ in 0..50 {
            step(&mut t, clock.read(), &mut syncs);
        }
        for _ in 0..300 {
            clock.advance(spf());
            step(&mut t, clock.read(), &mut syncs);
        }
        let r = 88_000u32;
        for w in syncs.windows(2) {
            if w[1][0] == 0x80 {
                let d = (implied_playout(&w[1], r) - implied_playout(&w[0], r)).abs();
                assert!(
                    d <= PERIODIC_STEP_MAX.as_secs_f64(),
                    "a 0x80 moved play-out by {:.1} ms without an anchor",
                    d * 1e3
                );
            }
        }
        assert!(reasons.iter().any(|r| matches!(r, AnchorReason::Step(d) if *d > Duration::from_millis(350))), "{reasons:?}");
        let st = t.stats();
        assert_eq!((st.gap_reanchors, st.step_reanchors), (1, 1), "{st:?}");
        assert_eq!(st.anchors, 3);
    }

    #[test]
    fn steady_stream_never_step_reanchors() {
        // 10 s of perfectly paced frames: every 0x80 stays within the limit.
        let clock = FakeClock::new(1000.0);
        let mut t = tl();
        for _ in 0..(10 * AUDIO_RATE as usize / ALAC_SPF) {
            clock.advance(spf());
            let now = clock.read();
            t.emit(&[0u8; PCM_FRAME_BYTES], now);
            t.periodic(now);
        }
        let st = t.stats();
        assert_eq!((st.anchors, st.step_reanchors), (1, 0));
        assert!(st.syncs >= 10);
    }

    #[test]
    fn ahead_of_measures_backlog() {
        let clock = FakeClock::new(1000.0);
        let mut t = tl();
        assert_eq!(t.ahead_of(clock.read()), None);
        for _ in 0..40 {
            t.emit(&[0u8; PCM_FRAME_BYTES], clock.read());
        }
        let a = t.ahead_of(clock.read()).unwrap();
        assert!((a.as_secs_f64() - 40.0 * spf()).abs() < 1e-6, "{a:?}");
        assert!(t.anchor_due(clock.read()).is_none());
    }

    #[test]
    fn effective_latency_below_proven_is_flagged() {
        assert!(AudioLatency::new(300, -100).unwrap().below_proven());
        assert!(AudioLatency::new(300, -1).unwrap().below_proven());
        assert!(!AudioLatency::new(300, 0).unwrap().below_proven());
        assert!(!AudioLatency::new(200, 100).unwrap().below_proven());
    }

    // ---- sender thread, loopback only (127.0.0.1 fake receiver) ----

    use crate::audiocapture::{PcmBlock, ScriptedSource};
    use std::sync::mpsc;

    fn frame_dur() -> Duration {
        samples_to_duration(ALAC_SPF as u32)
    }

    fn loud(k: u64) -> [u8; PCM_FRAME_BYTES] {
        let mut out = [0u8; PCM_FRAME_BYTES];
        for (i, b) in out.iter_mut().enumerate() {
            *b = (k as usize * 13 + i * 7 + 1) as u8 | 1;
        }
        out
    }

    /// A fake receiver on 127.0.0.1: collects data packets on a thread.
    struct Rx {
        control: UdpSocket,
        data_port: u16,
        got: mpsc::Receiver<Vec<u8>>,
    }

    fn rx() -> Rx {
        let control = UdpSocket::bind("127.0.0.1:0").unwrap();
        let data = UdpSocket::bind("127.0.0.1:0").unwrap();
        let data_port = data.local_addr().unwrap().port();
        data.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (tx, got) = mpsc::channel();
        std::thread::spawn(move || {
            let mut b = [0u8; 2048];
            while let Ok(n) = data.recv(&mut b) {
                if tx.send(b[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Rx { control, data_port, got }
    }

    fn params(r: &Rx) -> AudioStreamParams {
        AudioStreamParams {
            shk: KEY,
            latency: AudioLatency::new(300, 0).unwrap(),
            receiver: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            receiver_data_port: r.data_port,
            receiver_control_port: r.control.local_addr().unwrap().port(),
        }
    }

    fn open_pcm(pkt: &[u8]) -> [u8; PCM_FRAME_BYTES] {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        use chacha20poly1305::ChaCha20Poly1305;
        assert_eq!(pkt.len(), RTP_PACKET_BYTES);
        let counter = u64::from_le_bytes(pkt[RTP_PACKET_BYTES - 8..].try_into().unwrap());
        let mut body: [u8; ALAC_FRAME_BYTES] = pkt[12..12 + ALAC_FRAME_BYTES].try_into().unwrap();
        let tag: [u8; 16] = pkt[12 + ALAC_FRAME_BYTES..12 + ALAC_FRAME_BYTES + 16].try_into().unwrap();
        let nonce = crate::crypto::nonce_counter(counter);
        ChaCha20Poly1305::new((&KEY).into())
            .decrypt_in_place_detached((&nonce).into(), &pkt[4..12], &mut body, (&tag).into())
            .expect("authentic packet");
        alac_escape_decode(&body).expect("escape frame")
    }

    fn scripted_loud(n: u64) -> ScriptedSource {
        ScriptedSource::new((0..n).map(|k| (if k == 0 { Duration::ZERO } else { frame_dur() }, loud(k))).collect(), false)
    }

    fn wait_state(h: &AudioHandle, want: SenderState) {
        let end = Instant::now() + Duration::from_secs(10);
        while h.report().state != want {
            assert!(Instant::now() < end, "state {:?}, wanted {want:?}", h.report().state);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn held_gate_sends_only_silence_until_opened() {
        let r = rx();
        let gate = AudioGate::held(GATE_WAITING_FOR_VOLUME);
        let h = spawn_audio_sender_gated(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(scripted_loud(80)),
            Arc::new(crate::clock::BoottimeClock),
            None,
            Arc::default(),
            gate.clone(),
        );
        // Everything received before we open the gate must be digital silence.
        let mut before = vec![];
        while before.len() < 20 {
            before.push(r.got.recv_timeout(Duration::from_secs(5)).expect("silent packets flow"));
        }
        let rep = h.report();
        assert!(!rep.gate_open);
        assert_eq!(rep.gate_reason.as_deref(), Some(GATE_WAITING_FOR_VOLUME));
        gate.open();
        wait_state(&h, SenderState::Stopped);
        let rep = h.join(Duration::from_secs(2)).unwrap();
        let mut after = vec![];
        while let Ok(p) = r.got.recv_timeout(Duration::from_millis(300)) {
            after.push(p);
        }
        for (i, p) in before.iter().enumerate() {
            assert_eq!(open_pcm(p), SILENCE, "packet {i} left before the gate opened and was not silent");
        }
        let all: Vec<[u8; PCM_FRAME_BYTES]> = before.iter().chain(&after).map(|p| open_pcm(p)).collect();
        assert_eq!(all.len(), 80);
        let first_real = all.iter().position(|p| *p != SILENCE).expect("real audio after open");
        assert!(first_real >= 20);
        // Once open, the real capture flows, frame for frame.
        for (k, p) in all.iter().enumerate().skip(first_real) {
            assert_eq!(*p, loud(k as u64), "frame {k}");
        }
        assert_eq!(rep.silenced_frames, first_real as u64);
        assert!(rep.gate_open && rep.gate_reason.is_none());
        assert_eq!(rep.timeline.anchors, 1, "silence and audio share one timeline");
    }

    #[test]
    fn gate_never_opened_means_never_audible() {
        let r = rx();
        let report: Arc<Mutex<AudioReport>> = Arc::default();
        let h = spawn_audio_sender_into(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(scripted_loud(40)),
            Arc::new(crate::clock::BoottimeClock),
            None,
            report.clone(),
        );
        assert!(!h.gate().is_open(), "the production entry point starts held");
        wait_state(&h, SenderState::Stopped);
        let rep = h.join(Duration::from_secs(2)).unwrap();
        let mut n = 0;
        while let Ok(p) = r.got.recv_timeout(Duration::from_millis(300)) {
            assert_eq!(open_pcm(&p), SILENCE);
            n += 1;
        }
        assert_eq!(n, 40, "silence still keeps the stream (and its anchor) alive");
        assert_eq!(rep.silenced_frames, 40);
        assert!(!rep.gate_open);
        assert_eq!(report.lock().unwrap().silenced_frames, 40);
    }

    #[test]
    fn gate_can_be_held_again() {
        let g = AudioGate::held("a");
        assert_eq!(g.reason().as_deref(), Some("a"));
        g.open();
        assert!(g.is_open() && g.reason().is_none());
        g.hold("volume SET failed");
        assert!(!g.is_open());
        assert_eq!(g.reason().as_deref(), Some("volume SET failed"));
        assert!(AudioGate::ungated().is_open());
    }

    /// A source with a fixed release schedule (offsets from its first call),
    /// then optionally `Err(Ended)`; reports itself as `kind`.
    struct Sched {
        kind: &'static str,
        at: Vec<Duration>,
        t0: Option<Instant>,
        i: usize,
        end: bool,
        panic_at: Option<usize>,
        stop: Arc<AtomicBool>,
        /// Stamp frames with `boot_ns` like a live capture does.
        timed: bool,
    }

    impl Sched {
        fn new(kind: &'static str, at: Vec<Duration>, end: bool) -> Self {
            Sched { kind, at, t0: None, i: 0, end, panic_at: None, stop: Arc::default(), timed: false }
        }
    }

    impl PcmSource for Sched {
        fn next_frame(&mut self, timeout: Duration) -> Result<Option<PcmBlock>, CaptureError> {
            let t0 = *self.t0.get_or_insert_with(Instant::now);
            let deadline = Instant::now() + timeout;
            loop {
                if self.stop.load(Ordering::SeqCst) {
                    return Err(CaptureError::Stopped);
                }
                if self.panic_at == Some(self.i) {
                    panic!("simulated panic in a capture source");
                }
                let Some(d) = self.at.get(self.i) else {
                    if self.end {
                        return Err(CaptureError::Ended);
                    }
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                if Instant::now() >= t0 + *d {
                    self.i += 1;
                    let boot_ns = self.timed.then(|| crate::clock::BoottimeClock.read().boot().as_nanos() as u64);
                    return Ok(Some(PcmBlock { pcm: loud(self.i as u64), boot_ns, mono_ns: None, discontinuity: None }));
                }
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep((t0 + *d).saturating_duration_since(Instant::now()).min(Duration::from_millis(2)));
            }
        }
        fn stopper(&self) -> Box<dyn Fn() + Send + Sync> {
            let s = self.stop.clone();
            Box::new(move || s.store(true, Ordering::SeqCst))
        }
        fn stats(&self) -> CaptureStats {
            CaptureStats::default()
        }
        fn kind(&self) -> &'static str {
            self.kind
        }
    }

    fn paced(n: usize, from: Duration) -> impl Iterator<Item = Duration> {
        (0..n).map(move |k| from + frame_dur() * k as u32)
    }

    #[test]
    fn capture_that_ends_without_stop_is_an_error_not_a_clean_stop() {
        let r = rx();
        let (tx, erx) = mpsc::channel();
        let h = spawn_audio_sender(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(Sched::new("parec", paced(10, Duration::ZERO).collect(), true)),
            Arc::new(crate::clock::BoottimeClock),
            Some(tx),
        );
        wait_state(&h, SenderState::Error);
        let rep = h.join(Duration::from_secs(2)).unwrap();
        assert_eq!(rep.state, SenderState::Error);
        assert!(rep.error.as_deref().unwrap().contains("ended unexpectedly"), "{:?}", rep.error);
        assert_eq!(rep.rtp_sent, 10);
        let ev: Vec<AudioEvent> = erx.try_iter().collect();
        assert!(ev.iter().any(|e| matches!(e, AudioEvent::SourceError(m) if m.contains("ended unexpectedly"))), "{ev:?}");
    }

    #[test]
    fn capture_that_ends_after_stop_is_a_clean_stop() {
        let r = rx();
        let src = Sched::new("parec", vec![], false);
        let h = spawn_audio_sender(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(src),
            Arc::new(crate::clock::BoottimeClock),
            None,
        );
        std::thread::sleep(Duration::from_millis(60));
        let rep = h.join(Duration::from_secs(2)).unwrap();
        assert_eq!((rep.state, rep.error), (SenderState::Stopped, None));
    }

    #[test]
    fn a_panicking_sender_reports_error_not_streaming() {
        let r = rx();
        let (tx, erx) = mpsc::channel();
        let mut src = Sched::new("parec", paced(50, Duration::ZERO).collect(), false);
        src.panic_at = Some(3);
        let h = spawn_audio_sender(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(src),
            Arc::new(crate::clock::BoottimeClock),
            Some(tx),
        );
        wait_state(&h, SenderState::Error);
        let rep = h.join(Duration::from_secs(2)).unwrap();
        assert_eq!(rep.state, SenderState::Error);
        assert!(rep.error.as_deref().unwrap().contains("panicked"), "{:?}", rep.error);
        assert!(erx.try_iter().any(|e| matches!(e, AudioEvent::SourceError(_))));
    }

    #[test]
    fn sender_drops_a_backlog_before_a_gap_reanchor() {
        // 30 paced frames; the sender is then "stalled" for 400 ms while 50
        // frames queue up (all due at once), then paced frames again.
        let r = rx();
        let stall_end = frame_dur() * 30 + Duration::from_millis(400);
        let mut at: Vec<Duration> = paced(30, Duration::ZERO).collect();
        at.extend(std::iter::repeat_n(stall_end, 50));
        at.extend(paced(150, stall_end + frame_dur()));
        let (tx, erx) = mpsc::channel();
        let h = spawn_audio_sender(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(Sched::new("scripted", at, true)),
            Arc::new(crate::clock::BoottimeClock),
            Some(tx),
        );
        wait_state(&h, SenderState::Stopped);
        let rep = h.join(Duration::from_secs(2)).unwrap();
        assert_eq!(rep.timeline.gap_reanchors, 1, "{rep:?}");
        assert_eq!(rep.backlog_dropped, 49, "the anchor maps the newest queued frame");
        assert_eq!(rep.timeline.step_reanchors, 0, "no backlog left to step over");
        assert_eq!(rep.rtp_sent, 30 + 1 + 150);
        assert!(erx.try_iter().any(|e| matches!(e, AudioEvent::Anchored(AnchorReason::Gap(_)))));
    }

    /// A live capture starts with frames already queued (measured 110-180 ms
    /// from a PipeWire monitor). Anchoring the oldest and bursting the rest
    /// left RTP ahead of the clock, and the first periodic sync then had to
    /// Step re-anchor (tests/audio_capture_live.rs end_to_end_*_reanchor saw
    /// 4 anchors, not 3). The first anchor maps the newest queued frame.
    #[test]
    fn a_live_capture_start_backlog_is_dropped_before_the_first_anchor() {
        let schedule = || {
            let mut at: Vec<Duration> = vec![Duration::ZERO; 20];
            at.extend(paced(150, frame_dur()));
            at
        };
        let r = rx();
        let mut src = Sched::new("timed", schedule(), true);
        src.timed = true;
        let h = spawn_audio_sender(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(src),
            Arc::new(crate::clock::BoottimeClock),
            None,
        );
        wait_state(&h, SenderState::Error); // a non-scripted source that ends
        let rep = h.join(Duration::from_secs(2)).unwrap();
        assert_eq!(rep.backlog_dropped, 19, "{rep:?}");
        assert_eq!((rep.timeline.anchors, rep.timeline.step_reanchors), (1, 0), "{rep:?}");
        assert_eq!(rep.rtp_sent, 1 + 150);

        // An untimed (scripted) source keeps every frame.
        let r = rx();
        let h = spawn_audio_sender(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(Sched::new("scripted", schedule(), true)),
            Arc::new(crate::clock::BoottimeClock),
            None,
        );
        wait_state(&h, SenderState::Stopped);
        let rep = h.join(Duration::from_secs(2)).unwrap();
        assert_eq!(rep.backlog_dropped, 0);
        assert_eq!(rep.rtp_sent, 170);
    }

    #[test]
    fn sender_drops_frames_far_ahead_of_the_clock() {
        // A source that releases 400 frames (3.2 s) at once with no stall,
        // like a tone generator catching up: at most EARLY_MAX of it is sent.
        // Frames may flow again only as real time catches up with the mapping,
        // so the cap is EARLY_MAX plus however long the run took.
        let r = rx();
        let t0 = Instant::now();
        let h = spawn_audio_sender(
            params(&r),
            AudioSockets::bind_ephemeral_for_test().unwrap(),
            Box::new(Sched::new("scripted", vec![Duration::ZERO; 400], true)),
            Arc::new(crate::clock::BoottimeClock),
            None,
        );
        wait_state(&h, SenderState::Stopped);
        let took = t0.elapsed();
        let rep = h.join(Duration::from_secs(2)).unwrap();
        let cap = ((EARLY_MAX + took).as_secs_f64() / frame_dur().as_secs_f64()).ceil() as u64 + 2;
        assert!(took < Duration::from_secs(1), "{took:?}");
        assert!(rep.rtp_sent <= cap, "{} sent in {took:?}, cap {cap}", rep.rtp_sent);
        assert!(rep.early_dropped > 250, "{rep:?}");
        assert_eq!(rep.rtp_sent + rep.early_dropped, 400);
    }

    #[test]
    fn alac_roundtrip_and_rejects_corruption() {
        let mut pcm = [0u8; PCM_FRAME_BYTES];
        for (i, b) in pcm.iter_mut().enumerate() {
            *b = (i * 31 + 7) as u8;
        }
        let a = alac_escape_frame(&pcm);
        assert_eq!(&a[..3], &[0x20, 0x00, 0x02 | (pcm[1] >> 7)]);
        assert_eq!(alac_escape_decode(&a), Some(pcm));
        let mut bad = a;
        bad[ALAC_FRAME_BYTES - 1] ^= 0x01; // padding bit
        assert_eq!(alac_escape_decode(&bad), None);
        let mut bad = a;
        bad[0] ^= 0x80; // header
        assert_eq!(alac_escape_decode(&bad), None);
    }
}
