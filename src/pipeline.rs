//! The join: Wayland capture on its own thread, hardware encode on the caller's,
//! and the encoded access units handed straight to
//! [`crate::video::MirrorStreamer`].
//!
//! # Why the capture runs on its own thread
//!
//! The Python probe measured this directly: doing the colour conversion on the
//! capture thread capped the whole pipeline at ~20 fps, because a capture only
//! completes when the compositor has something new to copy and every
//! millisecond spent converting is a millisecond not spent waiting for the next
//! `ready`. So [`FramePump`] owns the `Capture` and does nothing but copy each
//! frame out of the shm mapping (1.72 ms median, measured) into a pooled
//! buffer; the encoder thread takes whatever the newest one is.
//!
//! # Newest-wins, not a queue
//!
//! The mailbox holds exactly one frame. If the pump produces a second frame
//! before the encoder has taken the first, the first is *dropped* and counted —
//! it is stale by definition, and a mirroring pipeline that queues stale frames
//! trades latency for nothing. `PipelineStats::dropped` is therefore a real
//! signal (at `--fps 30` against a 60 Hz compositor it should be about half the
//! produced count), not an error.
//!
//! # What is deliberately NOT here
//!
//! No second keepalive. [`crate::capture::Capture`] already re-emits the last
//! frame as [`FrameKind::Repeat`] every 250 ms of stillness, and re-encoding it
//! costs 657 bytes under CQP — cheaper than the bookkeeping of re-sending the
//! previous access unit, and it yields a clean P frame. Adding another one here
//! would double-feed the receiver.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::capture::{
    BufferMode, Capture, CaptureConfig, CaptureError, CaptureStats, CaptureSource, DmabufImage,
    FrameData, FrameFormat, FrameKind, PixelFormat, ZeroCopy,
};
use crate::encoder::{
    fit_source_to_receiver, AccessUnit, Encoder, EncoderConfig, EncoderError, EncoderInfo,
    EncoderKind, EncoderStats,
};
use crate::video::MirrorStreamer;

// ==================================================================== errors

/// The stage prefixes here are the whole point of the type: a failure needs to
/// say whether the compositor, the encoder or the socket gave up.
///
/// The inner errors are deliberately NOT `#[from]`/`#[source]`. thiserror would
/// then expose them through `Error::source`, and `anyhow`'s `{:#}` chain
/// formatting prints the source after the message — which for these
/// self-describing inner messages reads as `capture: no output named "x": no
/// output named "x"`. The manual `From` impls below keep the conversion
/// ergonomics without the doubled text.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("capture: {0}")]
    Capture(CaptureError),
    #[error("encoder: {0}")]
    Encoder(EncoderError),
    #[error("io: {0}")]
    Io(io::Error),
    #[error("capture thread stopped: {0}")]
    PumpStopped(String),
    #[error("capture thread vanished before reporting a result")]
    PumpVanished,
    /// The compositor is handing out rotated or flipped buffers.
    ///
    /// Nothing downstream un-rotates them: the VA-API chain scales but does not
    /// transpose, and for transform 1/3 the buffer's width/height are swapped
    /// relative to the displayed aspect, so `fit_source_to_receiver` would fit
    /// the wrong box as well. Mirroring would therefore put a rotated picture
    /// on the TV with no warning anywhere, which is the one outcome worth
    /// refusing. Rotation support is a milestone of its own.
    #[error("capture: output transform {0} (rotated or flipped) is not supported")]
    UnsupportedTransform(u32),
}

impl From<CaptureError> for PipelineError {
    fn from(e: CaptureError) -> Self {
        PipelineError::Capture(e)
    }
}
impl From<EncoderError> for PipelineError {
    fn from(e: EncoderError) -> Self {
        PipelineError::Encoder(e)
    }
}
impl From<io::Error> for PipelineError {
    fn from(e: io::Error) -> Self {
        PipelineError::Io(e)
    }
}

// ================================================================ frame buffer

/// One captured frame's pixels, in whatever form crosses the thread boundary.
///
/// On the shm path that means a copy out of the mapping, because the mapping is
/// only stable until the next capture starts. On the zero-copy path it means a
/// refcounted handle: the capture layer will not re-use that buffer as a target
/// while this is alive, so the 9.2 MB memcpy simply does not happen.
#[derive(Debug)]
pub enum FramePixels {
    Shm(Vec<u8>),
    Dmabuf(Arc<DmabufImage>),
}

impl FramePixels {
    /// The copied pixels, or `None` on the zero-copy path.
    pub fn shm(&self) -> Option<&[u8]> {
        match self {
            FramePixels::Shm(v) => Some(v),
            FramePixels::Dmabuf(_) => None,
        }
    }
    pub fn mode(&self) -> BufferMode {
        match self {
            FramePixels::Shm(_) => BufferMode::Shm,
            FramePixels::Dmabuf(_) => BufferMode::Dmabuf,
        }
    }
}

/// One captured frame, in a form that can cross a thread boundary. shm buffers
/// are pooled and recycled, so a steady-state run allocates nothing; dmabuf
/// handles are not pooled because there is nothing to reuse — the buffer itself
/// belongs to the capture layer's own rotating set.
#[derive(Debug)]
pub struct FrameBuf {
    pub pixels: FramePixels,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: PixelFormat,
    /// The buffer's `wl_output.transform`, straight from the frame. 0 is the
    /// only value the encode path can handle — see
    /// [`PipelineError::UnsupportedTransform`].
    pub transform: u32,
    pub kind: FrameKind,
    /// CLOCK_MONOTONIC ns from the compositor's `presentation_time`, or "now"
    /// for a keepalive repeat. This is the encoder's PTS source.
    pub timestamp_ns: u64,
    /// When the pump finished copying it. Only used to measure
    /// capture -> encoded latency; never for PTS.
    pub copied_at: Instant,
}

impl FrameBuf {
    fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

// ==================================================================== mailbox

#[derive(Debug, Default)]
struct Inner {
    newest: Option<FrameBuf>,
    pool: Vec<FrameBuf>,
    produced: u64,
    dropped: u64,
    /// How many of the dropped frames were keepalive repeats. Tracked because
    /// the alternative is assuming a repeat is never superseded, which is false
    /// the moment the capture layer outruns the consumer.
    dropped_repeats: u64,
    capture: CaptureStats,
    /// `Some` once the pump thread has exited; `Ok(())` for a clean stop.
    finished: Option<Result<(), String>>,
}

#[derive(Debug, Default)]
struct Shared {
    inner: Mutex<Inner>,
    cv: Condvar,
    stop: AtomicBool,
    /// The same flag as `stop`, in the shape `CaptureConfig::cancel` wants: the
    /// capture thread parks in `poll()` inside wayland-rs, so the stop flag on
    /// its own is only seen between frames. This one is handed to the capture
    /// layer, which slices its poll while it is present.
    cancel: Arc<AtomicBool>,
}

/// How many spare buffers to keep. One is in the mailbox, one is with the
/// encoder, one is being filled — anything beyond that is a queue, which is
/// exactly what this design refuses to build.
const POOL_CAP: usize = 3;

impl Shared {
    fn publish(&self, buf: FrameBuf, stats: CaptureStats) {
        let mut g = self.inner.lock().expect("mailbox poisoned");
        if let Some(stale) = g.newest.take() {
            g.dropped += 1;
            g.dropped_repeats += u64::from(stale.kind == FrameKind::Repeat);
            Self::pool_push(&mut g, stale);
        }
        g.produced += 1;
        g.capture = stats;
        g.newest = Some(buf);
        drop(g);
        self.cv.notify_all();
    }

    fn finish(&self, result: Result<(), String>) {
        let mut g = self.inner.lock().expect("mailbox poisoned");
        g.finished = Some(result);
        drop(g);
        self.cv.notify_all();
    }

    /// Return a buffer to the pool, or drop it if the pool is already at its
    /// cap. The cap lives here so `publish` (displacing a stale frame) and
    /// `FramePump::recycle` (the consumer finishing with one) cannot disagree.
    fn recycle(&self, buf: FrameBuf) {
        let mut g = self.inner.lock().expect("mailbox poisoned");
        Self::pool_push(&mut g, buf);
    }

    /// Park a buffer for reuse, or drop it if the pool is full.
    ///
    /// A dmabuf handle is always dropped: there is nothing in it to reuse, and
    /// parking one would keep the capture layer from re-using that buffer as a
    /// target — a pool that quietly starved the capture set would be a very
    /// hard bug to see.
    fn pool_push(g: &mut Inner, buf: FrameBuf) {
        if matches!(buf.pixels, FramePixels::Dmabuf(_)) {
            return;
        }
        if g.pool.len() < POOL_CAP {
            g.pool.push(buf);
        }
    }

    /// An shm buffer sized for `fmt`, recycled if one is available.
    fn checkout(&self, fmt: FrameFormat) -> FrameBuf {
        let want = fmt.len();
        let mut g = self.inner.lock().expect("mailbox poisoned");
        if let Some(mut buf) = g.pool.pop() {
            drop(g);
            if let FramePixels::Shm(v) = &mut buf.pixels {
                // NOT `clear(); resize(want, 0)`: clear() drops the length to 0,
                // so the resize memsets all 9.2 MB — on the capture thread, with
                // no capture in flight — and `Shared::run` then overwrites every
                // one of those bytes. Same guard the copy site already uses.
                if v.len() != want {
                    v.resize(want, 0);
                }
            }
            buf.width = fmt.width;
            buf.height = fmt.height;
            buf.stride = fmt.stride;
            buf.format = fmt.format;
            return buf;
        }
        drop(g);
        FrameBuf {
            pixels: FramePixels::Shm(vec![0u8; want]),
            width: fmt.width,
            height: fmt.height,
            stride: fmt.stride,
            format: fmt.format,
            transform: 0,
            kind: FrameKind::Fresh,
            timestamp_ns: 0,
            copied_at: Instant::now(),
        }
    }
}

// ================================================================== the pump

/// The capture thread. Opens the `Capture` on the thread that uses it (the
/// wayland connection never crosses a thread boundary), then copies every frame
/// into the newest-wins mailbox until stopped.
pub struct FramePump {
    shared: Arc<Shared>,
    join: Option<JoinHandle<()>>,
    format: FrameFormat,
    label: String,
    mode: BufferMode,
    zero_copy_note: Option<String>,
}

/// What the pump reports back once its session is up. Sent through a one-shot
/// channel so `FramePump::start` can fail with the real `CaptureError` instead
/// of a stringified one.
struct PumpHello {
    format: FrameFormat,
    label: String,
    /// What the capture layer actually allocated. Never inferred from the
    /// request: `ZeroCopy::Auto` is allowed to say no.
    mode: BufferMode,
    /// Why it is not dmabuf, when it is not.
    zero_copy_note: Option<String>,
}

impl FramePump {
    /// Open the capture session and start pumping. Returns once the compositor
    /// has sent the session's buffer constraints, so [`FramePump::format`] is
    /// valid immediately.
    pub fn start(config: CaptureConfig) -> Result<Self, PipelineError> {
        let shared = Arc::new(Shared::default());
        // Always this pump's OWN flag, overwriting whatever the caller passed:
        // `restart` hands us a config that was built for the pump we just
        // joined, and inheriting its raised flag would stillbirth the new one.
        let config = CaptureConfig {
            cancel: Some(shared.cancel.clone()),
            ..config
        };
        let (tx, rx): (_, Receiver<Result<PumpHello, CaptureError>>) = sync_channel(1);
        let pump_shared = shared.clone();
        let hello_timeout = config.first_frame_timeout + Duration::from_secs(2);

        let join = std::thread::Builder::new()
            .name("airplay-capture".into())
            .spawn(move || {
                let mut cap = match Capture::open(config) {
                    Ok(c) => c,
                    Err(e) => {
                        // The receiver may already be gone if start() timed out;
                        // either way there is nothing else to do.
                        let _ = tx.send(Err(e));
                        return;
                    }
                };
                let fmt = cap.format();
                if tx
                    .send(Ok(PumpHello {
                        format: fmt,
                        label: cap.label().to_string(),
                        mode: cap.buffer_mode(),
                        zero_copy_note: cap.zero_copy_note().map(str::to_string),
                    }))
                    .is_err()
                {
                    return;
                }
                drop(tx);
                pump_shared.run(&mut cap);
            })
            .map_err(PipelineError::Io)?;

        // Bounded. `Capture::open`'s registry handshake blocks in wayland-rs's
        // `poll(.., None)`, so a wedged or restarting compositor would otherwise
        // park here forever — and in `mirror` that is AFTER pairing, RTSP setup
        // and the NTP/event threads are live. On elapse the thread is left
        // detached: it dies when its capture errors or the channel send fails.
        let hello = match rx.recv_timeout(hello_timeout) {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                let _ = join.join();
                return Err(PipelineError::Capture(e));
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err(PipelineError::Capture(CaptureError::Timeout(
                    "the compositor's capture session",
                )));
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = join.join();
                return Err(PipelineError::PumpVanished);
            }
        };

        Ok(FramePump {
            shared,
            join: Some(join),
            format: hello.format,
            label: hello.label,
            mode: hello.mode,
            zero_copy_note: hello.zero_copy_note,
        })
    }

    /// Which kind of buffer the capture session came up on.
    pub fn buffer_mode(&self) -> BufferMode {
        self.mode
    }

    /// Why zero-copy is not in use, when it was asked for and did not happen.
    pub fn zero_copy_note(&self) -> Option<&str> {
        self.zero_copy_note.as_deref()
    }

    /// Geometry and pixel format of the capture buffers. On a resize this is the
    /// size the session STARTED at; the live size travels on each
    /// [`FrameBuf`], which is what the reconfigure check uses.
    pub fn format(&self) -> FrameFormat {
        self.format
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// Take the newest frame, waiting up to `timeout`. `Ok(None)` means nothing
    /// arrived in time — not an error: an idle screen only produces the 250 ms
    /// keepalive repeats.
    pub fn next(&self, timeout: Duration) -> Result<Option<FrameBuf>, PipelineError> {
        let deadline = Instant::now() + timeout;
        let mut g = self.shared.inner.lock().expect("mailbox poisoned");
        loop {
            if let Some(buf) = g.newest.take() {
                return Ok(Some(buf));
            }
            if let Some(result) = &g.finished {
                return match result {
                    Ok(()) => Ok(None),
                    Err(msg) => Err(PipelineError::PumpStopped(msg.clone())),
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let (next, _) = self
                .shared
                .cv
                .wait_timeout(g, deadline - now)
                .expect("mailbox poisoned");
            g = next;
        }
    }

    /// Hand a buffer back for reuse. Dropping it instead is safe, just wasteful.
    pub fn recycle(&self, buf: FrameBuf) {
        self.shared.recycle(buf);
    }

    /// Exact counters. `capture` is the capture layer's own snapshot as of the
    /// last published frame.
    pub fn stats(&self) -> PumpStats {
        let g = self.shared.inner.lock().expect("mailbox poisoned");
        PumpStats {
            produced: g.produced,
            dropped: g.dropped,
            dropped_repeats: g.dropped_repeats,
            capture: g.capture,
            pending: g.newest.is_some() as u64,
            pending_repeat: g
                .newest
                .as_ref()
                .map_or(0, |b| u64::from(b.kind == FrameKind::Repeat)),
            stopped: g.finished.is_some(),
        }
    }

    /// Signal the thread to stop and join it. The flag is also handed to the
    /// capture layer as [`CaptureConfig::cancel`], which slices its wayland
    /// poll while one is set, so this returns within about 50 ms plus whatever
    /// the pump is doing with the frame in hand — including before the first
    /// frame and in the middle of a session restart, which used to mean waiting
    /// out `first_frame_timeout` (5 s) or a 5 s constraints wait.
    pub fn stop(mut self) {
        self.shutdown();
    }

    /// Stop this pump and bring a fresh capture session up in its place.
    ///
    /// Only used by the CPU-encoder fallback: libx264 cannot read a dmabuf, so
    /// the capture has to be re-opened with [`ZeroCopy::Off`] before a CPU
    /// encoder can be built. The old session is fully joined first — two live
    /// capture sessions on one compositor is not a state worth inventing.
    fn restart(&mut self, config: CaptureConfig) -> Result<(), PipelineError> {
        self.shutdown();
        *self = FramePump::start(config)?;
        Ok(())
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.cancel.store(true, Ordering::SeqCst);
        self.shared.cv.notify_all();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for FramePump {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Shared {
    /// The pump loop. Nothing here touches the encoder: a copy out of the
    /// mapping and a publish, then straight back to waiting on the compositor.
    fn run(&self, cap: &mut Capture) {
        loop {
            if self.stop.load(Ordering::SeqCst) {
                self.finish(Ok(()));
                return;
            }
            // Scoped so the `CapturedFrame` borrow of `cap` ends before the
            // stats snapshot below, which needs `cap` back. The geometry is
            // taken from the frame rather than from `cap.format()` because a
            // `buffer_constraints` renegotiation (output mode/scale change, or
            // any toplevel resize) can have reallocated underneath us.
            let buf = {
                let frame = match cap.next_frame() {
                    Ok(f) => f,
                    // Our own `shutdown` raised the flag: a clean stop, not a
                    // capture failure. Anything else is real.
                    Err(CaptureError::Cancelled) => {
                        self.finish(Ok(()));
                        return;
                    }
                    Err(e) => {
                        self.finish(Err(e.to_string()));
                        return;
                    }
                };
                let fmt = FrameFormat {
                    width: frame.width,
                    height: frame.height,
                    stride: frame.stride,
                    format: frame.format,
                };
                let mut buf = match &frame.data {
                    FrameData::Shm(pixels) => {
                        let mut buf = self.checkout(fmt);
                        let need = fmt.len();
                        if let FramePixels::Shm(v) = &mut buf.pixels {
                            if v.len() != need {
                                v.resize(need, 0);
                            }
                            v[..need].copy_from_slice(&pixels[..need]);
                        }
                        buf
                    }
                    // Zero-copy: cloning the handle IS the frame. Nothing is
                    // read, so there is no 1.7 ms memcpy and no pooled Vec.
                    FrameData::Dmabuf(image) => FrameBuf {
                        pixels: FramePixels::Dmabuf(image.clone()),
                        width: fmt.width,
                        height: fmt.height,
                        stride: fmt.stride,
                        format: fmt.format,
                        transform: frame.transform,
                        kind: frame.kind,
                        timestamp_ns: frame.timestamp_ns,
                        copied_at: Instant::now(),
                    },
                };
                buf.width = fmt.width;
                buf.height = fmt.height;
                buf.stride = fmt.stride;
                buf.format = fmt.format;
                buf.transform = frame.transform;
                buf.kind = frame.kind;
                buf.timestamp_ns = frame.timestamp_ns;
                buf.copied_at = Instant::now();
                buf
            };
            self.publish(buf, cap.stats());
        }
    }
}

/// Exact pump counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PumpStats {
    /// Frames copied out of the mapping and published.
    pub produced: u64,
    /// Frames replaced in the mailbox before the encoder took them. Expected to
    /// be non-zero whenever the requested fps is below the compositor's damage
    /// rate; that is the newest-wins policy working, not a fault.
    pub dropped: u64,
    /// How many of `dropped` were keepalive repeats rather than fresh captures.
    /// Without this the keepalive ledger can only be closed by assuming a
    /// repeat is never superseded — which is simply untrue once the capture
    /// layer outruns the consumer, and on the zero-copy path it does.
    pub dropped_repeats: u64,
    pub capture: CaptureStats,
    /// Frames sitting in the mailbox, taken by nobody: 0 or 1, never more.
    /// Present so the ledger closes exactly —
    /// `produced == dropped + encoded + pending` — instead of "within one".
    pub pending: u64,
    /// Whether that pending frame is a keepalive repeat.
    pub pending_repeat: u64,
    pub stopped: bool,
}

// ================================================================== pipeline

/// How to run capture -> encode.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub capture: CaptureConfig,
    pub encoder: EncoderKind,
    /// The receiver's `/info` display size. The coded size is
    /// [`fit_source_to_receiver`] of the capture buffer INTO this — never a
    /// remembered constant (milestone-1 bug #2).
    pub receiver: (u32, u32),
    pub fps: u32,
    pub qp: u32,
    pub keyframe_seconds: f64,
    pub device: String,
    /// Report whether the driver has a low-power encode entrypoint. Never used
    /// to configure the encoder — `low_power` is not passed either way.
    pub probe_low_power: bool,
}

impl PipelineConfig {
    pub fn new(source: CaptureSource, receiver: (u32, u32)) -> Self {
        PipelineConfig {
            capture: CaptureConfig::new(source),
            encoder: EncoderKind::Gpu,
            receiver,
            fps: 60,
            qp: 25,
            keyframe_seconds: 5.0,
            device: "/dev/dri/renderD128".to_string(),
            probe_low_power: false,
        }
    }
}

/// One encoded picture plus the bookkeeping the caller needs.
#[derive(Debug)]
pub struct Encoded {
    pub units: Vec<AccessUnit>,
    pub kind: FrameKind,
    /// Capture timestamp of the source frame (CLOCK_MONOTONIC ns).
    pub capture_ns: u64,
    /// Copy-out to encoded-packet wall time. This is the pipeline's own latency
    /// contribution; it does not include the compositor or the receiver.
    pub latency: Duration,
    /// The encoder was rebuilt for a new capture size before this frame.
    pub reconfigured: bool,
}

/// Capture thread + encoder, joined. Call [`ScreenPipeline::next_encoded`] in a
/// loop, or hand the whole thing to [`run_stream`].
pub struct ScreenPipeline {
    pump: FramePump,
    enc: Encoder,
    cfg: PipelineConfig,
    source: (u32, u32),
    target: (u32, u32),
    /// The pixel format the encoder's conversion stage was built for. A
    /// renegotiation (or a `fall_back_to_shm`, where the shm and dmabuf arms
    /// choose their format independently) can flip Xrgb8888 <-> Argb8888 at the
    /// same geometry, and a VPP graph built for `bgr0` must not be fed `bgra`.
    source_format: PixelFormat,
    /// Which input stage the encoder was built with. Compared against every
    /// frame, because the capture layer is allowed to fall back to shm
    /// mid-stream and an encoder built for dmabuf would then refuse every frame.
    dmabuf_input: bool,
    /// Why the encoder in use is not the one that was asked for, when it is not.
    encoder_note: Option<String>,
    reconfigures: u64,
    encoded: u64,
    latencies: Vec<Duration>,
}

/// What building the encoder actually produced. Every field can differ from
/// what was requested, because the CPU fallback may re-open the capture at a
/// different geometry — never assume the request was honoured.
struct EncoderBuild {
    enc: Encoder,
    source: (u32, u32),
    target: (u32, u32),
    format: PixelFormat,
    dmabuf_input: bool,
    note: Option<String>,
}

impl ScreenPipeline {
    /// Start the capture thread, then build the encoder around the size the
    /// compositor actually reported.
    pub fn start(mut cfg: PipelineConfig) -> Result<Self, PipelineError> {
        let mut pump = FramePump::start(cfg.capture.clone())?;
        let fmt = pump.format();
        let source = (fmt.width, fmt.height);
        let target = fit_source_to_receiver(source, cfg.receiver);
        let dmabuf_input = pump.buffer_mode() == BufferMode::Dmabuf;
        let build = Self::build_encoder_or_cpu(
            &mut cfg,
            Some(&mut pump),
            source,
            target,
            fmt.format,
            dmabuf_input,
        )?;
        Ok(ScreenPipeline {
            pump,
            enc: build.enc,
            cfg,
            source: build.source,
            target: build.target,
            source_format: build.format,
            dmabuf_input: build.dmabuf_input,
            encoder_note: build.note,
            reconfigures: 0,
            encoded: 0,
            latencies: Vec::new(),
        })
    }

    /// Build the encoder, and when the GPU back-end refuses to open, fall back
    /// to the CPU one instead of killing a session the user has already been
    /// told to watch. The reason is kept in `encoder_note` — the same discipline
    /// `buffer_mode()` uses: report what opened, never what was requested.
    ///
    /// `pump` is `Some` only at start-up. libx264 cannot read a dmabuf (and
    /// `Encoder::new` rejects the combination outright), so a zero-copy capture
    /// has to be re-opened on shm before a CPU encoder can be built; mid-stream
    /// there is no pump to restart, so a dmabuf input still propagates the
    /// error.
    fn build_encoder_or_cpu(
        cfg: &mut PipelineConfig,
        pump: Option<&mut FramePump>,
        source: (u32, u32),
        target: (u32, u32),
        format: PixelFormat,
        dmabuf_input: bool,
    ) -> Result<EncoderBuild, PipelineError> {
        let err = match Self::build_encoder(cfg, source, target, format, dmabuf_input) {
            Ok(enc) => {
                return Ok(EncoderBuild {
                    enc,
                    source,
                    target,
                    format,
                    dmabuf_input,
                    note: None,
                })
            }
            Err(e) => e,
        };
        if cfg.encoder != EncoderKind::Gpu {
            return Err(err);
        }
        let restart = match (dmabuf_input, pump) {
            (true, Some(p)) => Some(p),
            (true, None) => return Err(err),
            (false, _) => None,
        };
        let note = format!("{err}; fell back to the cpu encoder");
        // Stick the fallback in the config so every later rebuild agrees.
        cfg.encoder = EncoderKind::Cpu;
        let (source, target, format) = match restart {
            Some(p) => {
                cfg.capture.zero_copy = ZeroCopy::Off;
                p.restart(cfg.capture.clone())?;
                let fmt = p.format();
                let source = (fmt.width, fmt.height);
                (
                    source,
                    fit_source_to_receiver(source, cfg.receiver),
                    fmt.format,
                )
            }
            None => (source, target, format),
        };
        let enc = Self::build_encoder(cfg, source, target, format, false)?;
        Ok(EncoderBuild {
            enc,
            source,
            target,
            format,
            dmabuf_input: false,
            note: Some(note),
        })
    }

    fn build_encoder(
        cfg: &PipelineConfig,
        source: (u32, u32),
        target: (u32, u32),
        format: PixelFormat,
        dmabuf_input: bool,
    ) -> Result<Encoder, PipelineError> {
        let mut ecfg = EncoderConfig::new(source, target);
        ecfg.kind = cfg.encoder;
        ecfg.source_format = format;
        ecfg.dmabuf_input = dmabuf_input;
        ecfg.fps = cfg.fps;
        ecfg.qp = cfg.qp;
        ecfg.keyframe_seconds = cfg.keyframe_seconds;
        ecfg.device = cfg.device.clone();
        ecfg.probe_low_power = cfg.probe_low_power;
        Ok(Encoder::new(ecfg)?)
    }

    pub fn source_size(&self) -> (u32, u32) {
        self.source
    }
    pub fn target_size(&self) -> (u32, u32) {
        self.target
    }
    pub fn label(&self) -> &str {
        self.pump.label()
    }
    /// Which kind of capture buffer is feeding the encoder right now.
    pub fn buffer_mode(&self) -> BufferMode {
        if self.dmabuf_input {
            BufferMode::Dmabuf
        } else {
            BufferMode::Shm
        }
    }
    pub fn zero_copy_note(&self) -> Option<&str> {
        self.pump.zero_copy_note()
    }
    /// Why the encoder back-end in use is not the one that was configured, when
    /// it is not. `None` means the request was honoured.
    pub fn encoder_note(&self) -> Option<&str> {
        self.encoder_note.as_deref()
    }
    pub fn encoder_info(&self) -> &EncoderInfo {
        self.enc.info()
    }
    pub fn encoder_stats(&self) -> EncoderStats {
        self.enc.stats()
    }
    pub fn pump_stats(&self) -> PumpStats {
        self.pump.stats()
    }

    /// Exact counters for the whole join.
    pub fn stats(&self) -> PipelineStats {
        let pump = self.pump.stats();
        let enc = self.enc.stats();
        PipelineStats {
            produced: pump.produced,
            dropped: pump.dropped,
            dropped_repeats: pump.dropped_repeats,
            encoded: self.encoded,
            pending: pump.pending,
            pending_repeat: pump.pending_repeat,
            reconfigures: self.reconfigures,
            capture: pump.capture,
            encoder: enc,
            latency_ms: percentiles_ms(&self.latencies),
        }
    }

    /// Wait for the newest frame and encode it. `Ok(None)` means no frame
    /// arrived within `timeout` — the caller should keep its heartbeat going and
    /// come back.
    pub fn next_encoded(&mut self, timeout: Duration) -> Result<Option<Encoded>, PipelineError> {
        let buf = match self.pump.next(timeout)? {
            Some(b) => b,
            None => return Ok(None),
        };

        // The frame's transform is carried all the way here precisely so it
        // cannot be dropped on the floor. A change mid-run (tablet-mode
        // rotation, a re-plugged monitor) is caught on the very next frame,
        // which is why this is tested per frame and not once at start-up —
        // `start` has no frame to look at.
        if buf.transform != 0 {
            let t = buf.transform;
            self.pump.recycle(buf);
            return Err(PipelineError::UnsupportedTransform(t));
        }

        // A `buffer_constraints` renegotiation changes the capture size under
        // us. The encoder refuses to silently rescale (EncoderError::FormatChanged),
        // so rebuild it around the new size and force a keyframe — the receiver
        // needs fresh parameter sets for the new geometry.
        //
        // The buffer KIND can change under us too: `ZeroCopy::Auto` falls back
        // to shm if the compositor starts failing dmabuf captures, and an
        // encoder built for `av_hwframe_map` would then reject every frame.
        //
        // The pixel FORMAT can change at the same geometry as well, which the
        // size check alone would miss.
        let want_dmabuf = buf.pixels.mode() == BufferMode::Dmabuf;
        let mut reconfigured = false;
        if buf.size() != self.source
            || buf.format != self.source_format
            || want_dmabuf != self.dmabuf_input
        {
            // Build into a local FIRST and commit only on success. Committing
            // the geometry before the fallible build would leave
            // `self.source`/`self.target` describing an encoder that was never
            // built, with the old encoder still in place — and the reconfigure
            // guard would never fire again, so every later frame would fail.
            // The frame also has to go back to the pool on that path, or the
            // `produced == dropped + encoded + pending` ledger is off by one for
            // a reason that is a state bug, not a lost frame.
            let new_source = buf.size();
            let new_target = fit_source_to_receiver(new_source, self.cfg.receiver);
            let build = match Self::build_encoder_or_cpu(
                &mut self.cfg,
                None,
                new_source,
                new_target,
                buf.format,
                want_dmabuf,
            ) {
                Ok(b) => b,
                Err(e) => {
                    self.pump.recycle(buf);
                    return Err(e);
                }
            };
            self.source = build.source;
            self.target = build.target;
            self.source_format = build.format;
            self.dmabuf_input = build.dmabuf_input;
            self.enc = build.enc;
            if build.note.is_some() {
                self.encoder_note = build.note;
            }
            self.enc.force_idr();
            self.reconfigures += 1;
            reconfigured = true;
        }

        let result = match &buf.pixels {
            FramePixels::Shm(pixels) => {
                self.enc
                    .encode(pixels, buf.stride, buf.size(), buf.timestamp_ns)
            }
            FramePixels::Dmabuf(image) => {
                self.enc
                    .encode_dmabuf(image, buf.size(), buf.timestamp_ns)
            }
        };
        let latency = buf.copied_at.elapsed();
        let kind = buf.kind;
        let capture_ns = buf.timestamp_ns;
        self.pump.recycle(buf);

        let units = result?;
        self.encoded += 1;
        self.latencies.push(latency);
        Ok(Some(Encoded {
            units,
            kind,
            capture_ns,
            latency,
            reconfigured,
        }))
    }

    /// Stop the capture thread. The encoder is dropped with `self`.
    pub fn stop(self) {
        self.pump.stop();
    }

    /// Stop the capture thread and THEN snapshot the counters.
    ///
    /// [`ScreenPipeline::stats`] reads a still-running pump, so `produced` can
    /// tick up between two reads and the frame ledger only balances to within a
    /// frame or two. Stopping first makes it exact, which is the whole point:
    /// `produced == dropped + encoded + pending`, with no slack for a bug to
    /// hide in.
    pub fn finish(mut self) -> PipelineStats {
        self.pump.shutdown();
        self.stats()
    }
}

/// Exact counters for a whole run. Every field is a count or a measured
/// percentile; there is no threshold anywhere.
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    pub produced: u64,
    pub dropped: u64,
    /// See [`PumpStats::dropped_repeats`].
    pub dropped_repeats: u64,
    pub encoded: u64,
    /// See [`PumpStats::pending`]. `produced == dropped + encoded + pending`.
    pub pending: u64,
    /// See [`PumpStats::pending_repeat`].
    pub pending_repeat: u64,
    pub reconfigures: u64,
    pub capture: CaptureStats,
    pub encoder: EncoderStats,
    /// (min, median, p95, max) capture-copy -> encoded-packet, in ms.
    pub latency_ms: (f64, f64, f64, f64),
}

fn percentiles_ms(samples: &[Duration]) -> (f64, f64, f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let mut v: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1e3).collect();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a Duration"));
    let at = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)];
    (v[0], at(0.5), at(0.95), v[v.len() - 1])
}

// ============================================================ the stream loop

/// How long a run lasts: a fixed wall-clock budget, or until something stops it.
///
/// `--seconds 0` on the CLI is [`RunLimit::UntilStopped`], which is a genuinely
/// different question from "zero seconds" and so is a different value rather
/// than a sentinel inside the `f64`. A plugin-started session needs to outlive
/// any timer, and the only things that may end it are a stop signal, the
/// receiver going away, or a fatal error.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RunLimit {
    /// Run for this long and then stop. `0.0` here really is zero seconds.
    Seconds(f64),
    /// Run until a signal, a dead receiver or a fatal error ends it.
    UntilStopped,
}

impl RunLimit {
    /// Parse a `--seconds` value the way every command in the CLI must:
    /// `0` means run until stopped, a negative is an error (never a second
    /// spelling of "indefinite"), and anything else is a fixed budget.
    pub fn parse(s: &str) -> Result<RunLimit, String> {
        let v: f64 = s
            .trim()
            .parse()
            .map_err(|_| format!("--seconds must be a number, got {s:?}"))?;
        if v.is_nan() {
            return Err(format!("--seconds must be a number, got {s:?}"));
        }
        if v < 0.0 {
            return Err(format!(
                "--seconds must not be negative (got {s:?}); use 0 to run until stopped \
                 (Ctrl-C or SIGTERM), or leave it out for the default"
            ));
        }
        if v == 0.0 {
            // Also catches `-0`, which parses to a negative zero that is not
            // `< 0.0`. Treating it as indefinite matches `0`.
            return Ok(RunLimit::UntilStopped);
        }
        if v.is_infinite() {
            return Err(format!(
                "--seconds must be finite (got {s:?}); use 0 to run until stopped"
            ));
        }
        Ok(RunLimit::Seconds(v))
    }

    /// The wall-clock budget, or `None` when there is none. Every loop that
    /// used to compare against a `Duration` asks this instead, so "indefinite"
    /// is one `Option` rather than a magic number in each of them.
    pub fn budget(&self) -> Option<Duration> {
        match self {
            RunLimit::Seconds(s) => Some(Duration::from_secs_f64(s.max(0.0))),
            RunLimit::UntilStopped => None,
        }
    }

    pub fn is_until_stopped(&self) -> bool {
        matches!(self, RunLimit::UntilStopped)
    }

    /// True while a run started at `elapsed == 0` still has time left.
    pub fn still_running(&self, elapsed: Duration) -> bool {
        self.budget().is_none_or(|total| elapsed < total)
    }
}

impl std::fmt::Display for RunLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunLimit::Seconds(s) => write!(f, "{s}s"),
            RunLimit::UntilStopped => write!(f, "until stopped"),
        }
    }
}

/// How to drive [`run_stream`].
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub limit: RunLimit,
    /// The mirror channel's keepalive. The probe sends one per second.
    pub heartbeat: Duration,
    /// Zero the SPS `constraint_set` byte before forwarding. Our encoder writes
    /// `67 64 0c 2a` (codec string `avc1.640c2a`) while the Frame advertises
    /// `avc1.64002a`; `constraint_set4|5` are strictly STRONGER constraints so a
    /// conforming decoder must accept ours, but this TV has a history of
    /// accepting a stream and rendering black. This is the one-flag escape hatch
    /// so a black screen costs a flag flip rather than a round trip.
    pub sps_zero_constraints: bool,
}

impl RunOptions {
    /// A fixed-duration run. `new(0.0)` is still zero seconds — the CLI's
    /// `--seconds 0` becomes [`RunLimit::UntilStopped`] before it gets here, so
    /// no caller has to know a sentinel.
    pub fn new(seconds: f64) -> Self {
        RunOptions::with_limit(RunLimit::Seconds(seconds))
    }

    /// Run until a signal, a dead receiver or a fatal error ends it.
    pub fn until_stopped() -> Self {
        RunOptions::with_limit(RunLimit::UntilStopped)
    }

    pub fn with_limit(limit: RunLimit) -> Self {
        RunOptions {
            limit,
            heartbeat: Duration::from_secs(1),
            sps_zero_constraints: false,
        }
    }
}

/// What one run sent.
#[derive(Debug, Clone, Default)]
pub struct StreamRun {
    /// Access units forwarded to the streamer. Equals
    /// `PipelineStats::encoded` whenever every encode produced exactly one
    /// unit, which is the invariant both back-ends hold.
    pub access_units: u64,
    pub idr_units: u64,
    pub heartbeats: u64,
    /// Annex-B bytes forwarded (before the avcC repack and the AEAD tag).
    pub bytes: u64,
    /// Units that came from a keepalive repeat rather than a fresh capture.
    pub repeat_units: u64,
    /// **Measured** wall-clock seconds of the run, from `Instant::elapsed` — not
    /// the duration that was requested. Every rate below divides by this, which
    /// is what keeps an interrupted or indefinite run's ledger finite instead of
    /// `inf`/`NaN`.
    pub seconds: f64,
    /// The run ended because a stop signal arrived, not because the clock ran
    /// out. **Not an error**: the real use case (cameras on the TV) is
    /// open-ended, so Ctrl-C is the expected way to finish. Recorded so the
    /// ledger can say why `seconds` is short of what was asked for.
    pub interrupted: bool,
}

impl StreamRun {
    pub fn megabits_per_second(&self) -> f64 {
        if self.seconds <= 0.0 {
            return 0.0;
        }
        (self.bytes as f64 * 8.0) / self.seconds / 1e6
    }
    pub fn fps(&self) -> f64 {
        if self.seconds <= 0.0 {
            return 0.0;
        }
        self.access_units as f64 / self.seconds
    }
}

/// Drive the pipeline into a [`MirrorStreamer`] for `opts.limit`.
///
/// Generic over the sink so the live path (a TCP socket with the ChaCha video
/// cipher) and the offline bench (a counting sink, no receiver) run the exact
/// same loop — the milestone-1 lesson being that the only code worth trusting is
/// the code the TV test actually exercised.
///
/// `annexb_tap`, when given, receives every forwarded access unit verbatim, so a
/// dry run produces a file `ffmpeg -err_detect explode` can check.
pub fn run_stream<W: Write>(
    pipe: &mut ScreenPipeline,
    streamer: &mut MirrorStreamer<W>,
    opts: &RunOptions,
    mut annexb_tap: Option<&mut dyn Write>,
) -> Result<StreamRun, PipelineError> {
    let started = Instant::now();
    // `None` is `--seconds 0`: no clock ends this run. Nothing else about the
    // loop changes — in particular the stop-flag check below is untouched, and
    // it is now the ONLY way out of an indefinite run short of an error, which
    // is why it stays exactly where it is (at the top, ahead of every
    // `continue`).
    let total: Option<Duration> = opts.limit.budget();
    let frame_gap = Duration::from_secs_f64(1.0 / pipe.cfg.fps.max(1) as f64);
    // Armed by the first forwarded access unit, never at `started`: the probe
    // only starts its heartbeat once a video frame has actually gone out, so a
    // type 0x02 packet can never reach a stream the receiver has no parameter
    // sets for — which is what a slow first capture would otherwise produce.
    let mut next_heartbeat: Option<Instant> = None;
    let mut next_due = started;
    let mut run = StreamRun::default();

    loop {
        let now = Instant::now();
        if total.is_some_and(|total| now.duration_since(started) >= total) {
            break;
        }
        // Checked here, at the top, so every `continue` below re-checks it: the
        // pacing nap, the heartbeat resync and the empty-mailbox path are all
        // `continue`s, and a check placed after any of them would be skipped by
        // the others. Responsiveness is bounded by the 100 ms `next_encoded`
        // budget further down, so teardown starts within ~100 ms of the signal.
        if crate::signals::interrupted() {
            run.interrupted = true;
            break;
        }
        if next_heartbeat.is_some_and(|due| now >= due) {
            streamer.send_heartbeat()?;
            run.heartbeats += 1;
            // Resynchronise, do not accumulate: `+= heartbeat` after a stall
            // longer than one interval fires a catch-up train of heartbeats,
            // one per loop iteration, instead of costing one heartbeat.
            next_heartbeat = Some(now + opts.heartbeat);
            continue;
        }
        let until_heartbeat =
            next_heartbeat.map_or(Duration::MAX, |due| due.saturating_duration_since(now));
        // Pace to the requested fps by NOT asking for a frame yet. Frames the
        // compositor produces meanwhile are replaced in the mailbox, so what we
        // take next is always the newest — never a backlog.
        if now < next_due {
            let nap = (next_due - now).min(until_heartbeat);
            std::thread::sleep(nap.min(Duration::from_millis(20)));
            continue;
        }

        // Cap the wait so the heartbeat stays punctual on a completely still
        // screen (where the only frames are the 250 ms keepalives).
        let budget = until_heartbeat.min(Duration::from_millis(100));
        let encoded = match pipe.next_encoded(budget)? {
            Some(e) => e,
            None => continue,
        };
        // Pace on an absolute tick, the way `Session::stream_test_pattern`
        // does. Measuring the next due time from the END of the encode makes
        // the achieved period `frame_gap + service_time`: at --fps 60 (16.67 ms)
        // with 5-8 ms of measured encode work that is a ~40-45 fps ceiling
        // against a 60 Hz compositor. Advancing the tick lets the gap ABSORB the
        // encode instead of following it.
        next_due += frame_gap;
        let serviced = Instant::now();
        if next_due < serviced {
            // Badly behind — a stall, or service time above the gap. Snap
            // forward so the loop runs flat out rather than chasing a backlog
            // of due ticks it can never catch.
            next_due = serviced;
        }

        if encoded.reconfigured {
            let (w, h) = pipe.target_size();
            streamer.set_dimensions(w, h);
        }
        for unit in &encoded.units {
            // Borrow by default: the copy is only needed for the in-place SPS
            // rewrite, and both the tap and the streamer take `&[u8]`.
            let rewritten;
            let data: &[u8] = if opts.sps_zero_constraints {
                rewritten = {
                    let mut d = unit.data.clone();
                    crate::encoder::zero_sps_constraints(&mut d);
                    d
                };
                &rewritten
            } else {
                &unit.data
            };
            if let Some(tap) = annexb_tap.as_deref_mut() {
                tap.write_all(data)?;
            }
            streamer.forward_access_unit(data)?;
            run.access_units += 1;
            run.idr_units += unit.is_idr as u64;
            run.bytes += data.len() as u64;
            run.repeat_units += (encoded.kind == FrameKind::Repeat) as u64;
        }
        if next_heartbeat.is_none() && run.access_units > 0 {
            next_heartbeat = Some(Instant::now() + opts.heartbeat);
        }
    }

    run.seconds = started.elapsed().as_secs_f64();
    Ok(run)
}

// ==================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_exact_positions_not_interpolations() {
        let s: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        let (min, med, p95, max) = percentiles_ms(&s);
        assert_eq!(min, 1.0);
        assert_eq!(med, 51.0);
        assert_eq!(p95, 96.0);
        assert_eq!(max, 100.0);
    }

    #[test]
    fn an_empty_latency_set_is_zero_not_a_panic() {
        assert_eq!(percentiles_ms(&[]), (0.0, 0.0, 0.0, 0.0));
    }

    #[test]
    fn the_mailbox_keeps_only_the_newest_frame_and_counts_the_rest_as_dropped() {
        let shared = Shared::default();
        let fmt = FrameFormat {
            width: 4,
            height: 2,
            stride: 16,
            format: PixelFormat::Xrgb8888,
        };
        for n in 0..5u64 {
            let mut buf = shared.checkout(fmt);
            buf.timestamp_ns = n;
            shared.publish(buf, CaptureStats::default());
        }
        let g = shared.inner.lock().unwrap();
        assert_eq!(g.produced, 5);
        assert_eq!(g.dropped, 4, "four frames were superseded before being taken");
        assert_eq!(
            g.newest.as_ref().map(|b| b.timestamp_ns),
            Some(4),
            "the survivor must be the newest, not the oldest"
        );
    }

    /// An un-drained pump ping-pongs between exactly TWO allocations: it
    /// checks one out, publishes it, and the displaced one goes back to the
    /// pool for the next checkout. This asserts the exact number — the first
    /// version of this test guessed "2 in the pool after 3 publishes" and was
    /// wrong, which is precisely why these are exact values and not bounds.
    #[test]
    fn an_undrained_pump_ping_pongs_between_exactly_two_buffers() {
        let shared = Shared::default();
        let fmt = FrameFormat {
            width: 8,
            height: 4,
            stride: 32,
            format: PixelFormat::Xrgb8888,
        };
        let mut allocations = std::collections::BTreeSet::new();
        for n in 0..50 {
            let buf = shared.checkout(fmt);
            let shm = buf.pixels.shm().expect("checkout always hands back an shm buffer");
            assert_eq!(shm.len(), fmt.len());
            allocations.insert(shm.as_ptr() as usize);
            shared.publish(buf, CaptureStats::default());
            // After the first publish there is one in the mailbox and one in
            // the pool — the displaced predecessor. Never a third.
            assert_eq!(shared.inner.lock().unwrap().pool.len(), usize::from(n > 0));
        }
        assert_eq!(
            allocations.len(),
            2,
            "50 frames must reuse two buffers, not allocate 50"
        );
    }

    /// With the consumer also holding a buffer and recycling it, the pool still
    /// cannot grow past its cap however hard it is pushed.
    #[test]
    fn the_pool_never_grows_into_a_queue() {
        let shared = Shared::default();
        let fmt = FrameFormat {
            width: 2,
            height: 2,
            stride: 8,
            format: PixelFormat::Xrgb8888,
        };
        // Hand back far more buffers than the pipeline could ever hold. The
        // surplus must be dropped, not accumulated: a growing pool IS a queue.
        for n in 0..50u64 {
            let mut buf = shared.checkout(fmt);
            buf.timestamp_ns = n;
            shared.recycle(buf);
            // checkout() pops one and recycle() pushes it back, so the pool only
            // grows from these extras — which is what the cap must stop.
            let extra = FrameBuf {
                pixels: FramePixels::Shm(vec![0u8; fmt.len()]),
                width: fmt.width,
                height: fmt.height,
                stride: fmt.stride,
                format: fmt.format,
                transform: 0,
                kind: FrameKind::Fresh,
                timestamp_ns: n,
                copied_at: Instant::now(),
            };
            shared.recycle(extra);
        }
        assert_eq!(shared.inner.lock().unwrap().pool.len(), POOL_CAP);
    }

    #[test]
    fn stream_run_rates_are_plain_arithmetic() {
        let run = StreamRun {
            access_units: 600,
            bytes: 1_250_000,
            seconds: 10.0,
            ..Default::default()
        };
        assert_eq!(run.fps(), 60.0);
        assert_eq!(run.megabits_per_second(), 1.0);
        assert_eq!(StreamRun::default().fps(), 0.0);
        assert_eq!(StreamRun::default().megabits_per_second(), 0.0);
    }

    /// `--seconds 0` is "run until stopped", a negative is an error, and
    /// neither is a number the rate arithmetic ever sees.
    #[test]
    fn run_limit_parses_zero_as_indefinite_and_refuses_a_negative() {
        assert_eq!(RunLimit::parse("30").unwrap(), RunLimit::Seconds(30.0));
        assert_eq!(RunLimit::parse("2.5").unwrap(), RunLimit::Seconds(2.5));
        assert_eq!(RunLimit::parse("0").unwrap(), RunLimit::UntilStopped);
        assert_eq!(RunLimit::parse("0.0").unwrap(), RunLimit::UntilStopped);
        assert_eq!(RunLimit::parse("-0").unwrap(), RunLimit::UntilStopped);
        for bad in ["-1", "-0.5", "-30"] {
            let e = RunLimit::parse(bad).expect_err("a negative must be refused");
            assert!(
                e.contains("must not be negative") && e.contains("0 to run until stopped"),
                "{bad:?} gave {e:?}"
            );
        }
        for bad in ["", "abc", "1s", "NaN", "inf"] {
            assert!(RunLimit::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// The property the ledger depends on: an indefinite run has no budget, so
    /// nothing can divide by a requested duration of zero.
    #[test]
    fn an_indefinite_limit_has_no_budget_and_never_expires() {
        let l = RunLimit::UntilStopped;
        assert_eq!(l.budget(), None);
        assert!(l.is_until_stopped());
        assert!(l.still_running(Duration::from_secs(0)));
        assert!(l.still_running(Duration::from_secs(86_400)));
        assert_eq!(l.to_string(), "until stopped");

        let l = RunLimit::Seconds(2.0);
        assert_eq!(l.budget(), Some(Duration::from_secs(2)));
        assert!(!l.is_until_stopped());
        assert!(l.still_running(Duration::from_millis(1999)));
        assert!(!l.still_running(Duration::from_secs(2)));
        assert_eq!(l.to_string(), "2s");

        // `RunOptions::new(0.0)` stays literal zero seconds: the sentinel lives
        // only in the CLI's `--seconds` parse, so no library caller inherits it.
        assert_eq!(RunOptions::new(0.0).limit, RunLimit::Seconds(0.0));
        assert_eq!(RunOptions::new(0.0).limit.budget(), Some(Duration::ZERO));
        assert_eq!(RunOptions::until_stopped().limit, RunLimit::UntilStopped);
    }
}
