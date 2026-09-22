//! airplay-rs: a Rust AirPlay session-core library, ported faithfully from the
//! reference Python probe (`probe.py` in the omarchy-airplay-probe repo).
//!
//! This crate is organised one module per wire component. The modules are fully
//! ported: discovery, TLV8, HAP crypto, binary plist, pairing (transient + PIN),
//! RTSP transport, timing, the session bring-up, and the mirror video path are
//! all implemented, and their on-wire behaviour is pinned byte-for-byte to the
//! probe by the golden vectors under `tests/vectors/`.
//!
//! [`virtualoutput`] adds Extend: a Hyprland headless output driven as a second
//! desktop that exists only on the TV, created and removed around a mirror run.
//! It sits strictly above the wire modules — it produces nothing but a
//! [`capture::CaptureSource`], so no byte on the wire depends on it.
//!
//! [`signals`] is what makes that removal survive Ctrl-C: SIGINT/SIGTERM/SIGHUP
//! set a flag the streaming loops poll, so an interrupted run returns through
//! its destructors instead of being killed on the spot. That flag is also what
//! ends an indefinite run ([`pipeline::RunLimit::UntilStopped`], the CLI's
//! `--seconds 0`), where no clock will.
//!
//! [`audio`] is the type-96 ALAC audio stream's packet layer (ALAC escape
//! frames, RTP + ChaCha20-Poly1305, TimeAnnounce/sync) and the anchor
//! timeline; [`clock`] is the single BOOTTIME sender clock it reads;
//! [`audiocapture`] produces its PCM frames (PipeWire monitor capture, parec
//! fallback, tone); [`volume`] is the laptop <-> TV volume policy.
//!
//! [`audiosink`] is the macOS-style half of that: while a session runs it
//! publishes the sender's own PipeWire sink named after the receiver, takes
//! the laptop's output, and gives it back at the end — so the sound goes to
//! the TV *instead of* to the speakers, and [`audiocapture`] taps that sink's
//! own (pre-volume) monitor. The node dies with this process, so a SIGKILL
//! leaves no orphan; the persistent configured-default does not, which is
//! what its claim file and sweep are for.
//!
//! [`sessionstate`] records which session is running, for `airplay status` —
//! kept deliberately separate from [`virtualoutput`]'s ownership claim, whose
//! other job is making a phantom output reclaimable.

pub mod discovery;
pub mod tlv8;
pub mod crypto;
pub mod bplist;
pub mod pairing;
pub mod rtsp;
pub mod timing;
pub mod session;
pub mod video;
pub mod testpattern;
pub mod capture;
pub mod encoder;
pub mod pipeline;
pub mod virtualoutput;
pub mod sessionstate;
pub mod signals;
pub mod clock;
pub mod audio;
pub mod audiocapture;
pub mod audiosink;
pub mod volume;
