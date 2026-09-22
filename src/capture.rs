//! Live screen capture over `ext-image-copy-capture-v1`, spoken directly to the
//! compositor with `wayland-client` — no portal, no PipeWire, no
//! wayland-scanner step.
//!
//! The wire behaviour is a port of the reference probe's
//! `wlcapture.py` in the omarchy-airplay-probe repo and of the milestone-2 capture
//! spike, both of which were measured on this machine (Hyprland 0.56.2,
//! eDP-1 1920x1200@60): 60.0 fps sustained, median inter-frame gap 16.67 ms =
//! exactly one vblank, `presentation_time` delivered per frame as
//! CLOCK_MONOTONIC ns.
//!
//! Three protocol rules are load-bearing and easy to get wrong:
//!
//! 1. New object ids must reach the server in INCREASING order, so every id is
//!    allocated immediately before the request that creates it. In wayland-rs
//!    that means: never build a proxy "early" and send it later.
//! 2. Each capture needs its own `session.create_frame()` before
//!    `attach_buffer` / `damage_buffer` / `capture`; a second `create_frame`
//!    before the previous frame object is destroyed is a `duplicate_frame`
//!    protocol error.
//! 3. `wayland_client::event_created_child!` is MANDATORY for
//!    `ext_foreign_toplevel_list_v1`'s `toplevel` event. Without it the code
//!    compiles cleanly and panics at runtime. Requests that create objects do
//!    not need it; events do.
//!
//! ## Idle screens
//!
//! A capture completes only when the image CHANGED, so an idle desktop yields
//! nothing at all — the spike measured 50 gaps over 100 ms in 30 s of ordinary
//! use, max 940 ms. The receiver starves if that reaches it, so [`Capture`]
//! re-emits the last frame with a fresh timestamp after
//! [`CaptureConfig::keepalive`] (~250 ms) of stillness, marked
//! [`FrameKind::Repeat`]. The in-flight capture is NOT cancelled to do this: it
//! keeps waiting, and the keepalive is served from a buffer the compositor is
//! not writing into.
//!
//! ## Zero-copy
//!
//! [`CaptureConfig::zero_copy`] chooses what the compositor blits into.
//!
//! * **shm** (`ZeroCopy::Off`) — two memfd buffers, ping-ponged. The caller
//!   gets `&[u8]` into the mapping and has to copy it out before the next
//!   capture starts. Measured here: 1.7 ms of memcpy per 1920x1200 frame, plus
//!   a further ~5 ms for the encoder to upload the same 9.2 MB to the GPU.
//! * **dmabuf** (`ZeroCopy::On`/`Auto`) — four LINEAR gbm buffers on the render
//!   node the session named, wrapped as `wl_buffer`s through
//!   `zwp_linux_dmabuf_v1`. The caller gets a refcounted [`DmabufImage`] the
//!   encoder maps straight into a VA-API surface. Nothing is read on the CPU at
//!   all; measured at 0.003 ms per frame against the shm path's 5.05 ms, and
//!   6.4% of one core against 25.3% over a matched 60 s run.
//!
//! What makes the zero-copy path sound is that the buffer the caller holds is
//! never the buffer the compositor is writing: a capture target is chosen only
//! from buffers whose [`DmabufImage`] handle nobody else holds, and never the
//! front buffer. The shm path needs no such check because the caller copies
//! before the next capture is submitted.
//!
//! `Auto` is the default and it degrades rather than failing: no
//! `zwp_linux_dmabuf_v1`, no LINEAR modifier on offer, no gbm device, a
//! compositor that answers the import with `failed`, or captures that start
//! failing mid-stream all fall back to shm, record why in
//! [`Capture::zero_copy_note`] and count it in
//! [`CaptureStats::zero_copy_fallbacks`]. `On` turns each of those into an
//! error instead, which is what the tests use.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wayland_client::globals::{registry_queue_init, GlobalError, GlobalList, GlobalListContents};
use wayland_client::protocol::{
    wl_buffer::WlBuffer,
    wl_callback::{self, WlCallback},
    wl_output::{self, WlOutput},
    wl_registry::WlRegistry,
    wl_shm::{self, WlShm},
    wl_shm_pool::WlShmPool,
};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle, WEnum};

use wayland_protocols::ext::foreign_toplevel_list::v1::client::{
    ext_foreign_toplevel_handle_v1::{self, ExtForeignToplevelHandleV1},
    ext_foreign_toplevel_list_v1::{self, ExtForeignToplevelListV1},
};
use wayland_protocols::ext::image_capture_source::v1::client::{
    ext_foreign_toplevel_image_capture_source_manager_v1::ExtForeignToplevelImageCaptureSourceManagerV1,
    ext_image_capture_source_v1::ExtImageCaptureSourceV1,
    ext_output_image_capture_source_manager_v1::ExtOutputImageCaptureSourceManagerV1,
};
use wayland_protocols::ext::image_copy_capture::v1::client::{
    ext_image_copy_capture_frame_v1::{self, ExtImageCopyCaptureFrameV1, FailureReason},
    ext_image_copy_capture_manager_v1::{ExtImageCopyCaptureManagerV1, Options},
    ext_image_copy_capture_session_v1::{self, ExtImageCopyCaptureSessionV1},
};
use wayland_protocols::wp::linux_dmabuf::zv1::client::{
    zwp_linux_buffer_params_v1::{self, ZwpLinuxBufferParamsV1},
    zwp_linux_dmabuf_v1::ZwpLinuxDmabufV1,
};

// ===================================================================== errors

/// Everything that can go wrong bringing up or running a capture.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("connect to the wayland compositor: {0}")]
    Connect(#[from] wayland_client::ConnectError),
    #[error("wayland protocol error: {0}")]
    Protocol(String),
    #[error("compositor does not advertise {0} (needed for screen capture)")]
    MissingGlobal(&'static str),
    #[error("no output named {0:?}")]
    NoSuchOutput(String),
    #[error("no window matching {0:?}")]
    NoSuchWindow(String),
    #[error("bad capture source {0:?} (expected `output:NAME` or `window:TEXT`)")]
    BadSource(String),
    #[error("compositor offered no XRGB8888/ARGB8888 shm format (offered {0:?})")]
    NoShmFormat(Vec<u32>),
    #[error("the capture session stopped (source gone, window closed, or compositor policy)")]
    Stopped,
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    /// [`CaptureConfig::cancel`] was raised while a call was blocked. Not a
    /// failure: it is how a shutdown gets out of a wait that would otherwise
    /// run to [`CaptureConfig::first_frame_timeout`].
    #[error("capture cancelled")]
    Cancelled,
    /// Anything that stopped the zero-copy path from coming up. On
    /// [`ZeroCopy::Auto`] this is caught and turned into an shm session; on
    /// [`ZeroCopy::On`] it is returned.
    #[error("zero-copy (dmabuf) capture: {0}")]
    Dmabuf(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<wayland_client::DispatchError> for CaptureError {
    fn from(e: wayland_client::DispatchError) -> Self {
        CaptureError::Protocol(e.to_string())
    }
}
impl From<GlobalError> for CaptureError {
    fn from(e: GlobalError) -> Self {
        CaptureError::Protocol(e.to_string())
    }
}
impl From<wayland_client::globals::BindError> for CaptureError {
    fn from(e: wayland_client::globals::BindError) -> Self {
        CaptureError::Protocol(e.to_string())
    }
}

// =============================================================== public types

/// What to capture. `output:` is a monitor (including a headless/virtual one),
/// `window:` is a single toplevel matched by a case-insensitive substring of
/// its title or app_id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureSource {
    Output(String),
    Window(String),
}

impl CaptureSource {
    /// Parse the CLI spelling. A bare string with no `kind:` prefix is an
    /// output name, which is what `airplay mirror --output eDP-1` wants.
    pub fn parse(spec: &str) -> Result<Self, CaptureError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(CaptureError::BadSource(spec.to_string()));
        }
        match spec.split_once(':') {
            Some(("output", rest)) if !rest.is_empty() => Ok(CaptureSource::Output(rest.into())),
            Some(("window", rest)) if !rest.is_empty() => Ok(CaptureSource::Window(rest.into())),
            Some(_) => Err(CaptureError::BadSource(spec.to_string())),
            None => Ok(CaptureSource::Output(spec.into())),
        }
    }
}

impl std::fmt::Display for CaptureSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureSource::Output(n) => write!(f, "output:{n}"),
            CaptureSource::Window(n) => write!(f, "window:{n}"),
        }
    }
}

/// The only two shm formats this path accepts. Both are 4 bytes/pixel and both
/// arrive as little-endian `0xAARRGGBB`, i.e. BYTES B,G,R,A — which is
/// ffmpeg's `bgr0`/`bgra` and VA-API's `VA_FOURCC_BGRX`/`BGRA`. Getting the
/// channel order wrong here is invisible until a human looks at a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// wl_shm format 1, DRM `XR24`.
    Xrgb8888,
    /// wl_shm format 0, DRM `AR24`.
    Argb8888,
}

impl PixelFormat {
    pub const fn bytes_per_pixel(self) -> u32 {
        4
    }
    /// wl_shm's own numbering (0 = ARGB8888, 1 = XRGB8888; everything else is
    /// a DRM fourcc).
    pub const fn wl_shm_code(self) -> u32 {
        match self {
            PixelFormat::Argb8888 => 0,
            PixelFormat::Xrgb8888 => 1,
        }
    }
    /// DRM fourcc, which is what a dmabuf import and VA-API want.
    pub const fn drm_fourcc(self) -> u32 {
        match self {
            // 'XR24'
            PixelFormat::Xrgb8888 => 0x3432_5258,
            // 'AR24'
            PixelFormat::Argb8888 => 0x3432_5241,
        }
    }
    /// The libav pixel-format name for the same byte order.
    pub const fn ffmpeg_name(self) -> &'static str {
        match self {
            PixelFormat::Xrgb8888 => "bgr0",
            PixelFormat::Argb8888 => "bgra",
        }
    }
    const fn to_wl(self) -> wl_shm::Format {
        match self {
            PixelFormat::Xrgb8888 => wl_shm::Format::Xrgb8888,
            PixelFormat::Argb8888 => wl_shm::Format::Argb8888,
        }
    }
}

/// Geometry and format of the buffers this session produces. Note that for a
/// scaled output this is the PHYSICAL size (eDP-1 at scale 1.5 reports
/// 1920x1200, not the 1280x800 logical size), so anything cross-referenced with
/// `hyprctl` must be multiplied by the output scale first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameFormat {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: PixelFormat,
}

impl FrameFormat {
    pub const fn len(&self) -> usize {
        (self.stride as usize) * (self.height as usize)
    }
    pub const fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// Whether the frame is newly copied by the compositor or the previous frame
/// re-emitted to keep an idle receiver fed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Fresh,
    Repeat,
}

/// Where a frame's pixels actually live.
///
/// This enum is the whole zero-copy layer in one type. `Shm` borrows the
/// mapping the compositor blitted into; `Dmabuf` is a GPU buffer the CPU never
/// reads. Both arms carry identical geometry, so everything downstream is the
/// same code except the encoder's input stage, which either uploads
/// (`av_hwframe_transfer_data`, ~5 ms for 1920x1200 BGRX) or maps
/// (`av_hwframe_map(DIRECT)`, 0.031 ms measured).
pub enum FrameData<'a> {
    /// The shm mapping, borrowed. No copy has been made.
    Shm(&'a [u8]),
    /// A dmabuf the compositor blitted into. The handle is refcounted, and
    /// [`Capture`] will not re-use a buffer as a capture target while any clone
    /// of its handle is alive — that is what makes the zero-copy path sound
    /// with a consumer on another thread.
    Dmabuf(Arc<DmabufImage>),
}

impl FrameData<'_> {
    /// The mapped pixels, or `None` on the zero-copy path, where there are none
    /// and reading them would be the very cost the path exists to avoid.
    pub fn shm(&self) -> Option<&[u8]> {
        match self {
            FrameData::Shm(p) => Some(p),
            FrameData::Dmabuf(_) => None,
        }
    }
    /// The dmabuf handle, or `None` on the shm path.
    pub fn dmabuf(&self) -> Option<&Arc<DmabufImage>> {
        match self {
            FrameData::Shm(_) => None,
            FrameData::Dmabuf(i) => Some(i),
        }
    }
    pub fn mode(&self) -> BufferMode {
        match self {
            FrameData::Shm(_) => BufferMode::Shm,
            FrameData::Dmabuf(_) => BufferMode::Dmabuf,
        }
    }
}

/// One frame. Nothing here is copied: `data` either borrows the shm mapping or
/// carries a refcounted handle to the dmabuf the compositor wrote.
pub struct CapturedFrame<'a> {
    /// CLOCK_MONOTONIC nanoseconds. For a [`FrameKind::Fresh`] frame this is
    /// the compositor's `presentation_time` when it sent one; for a
    /// [`FrameKind::Repeat`] it is "now", so PTS keeps advancing.
    pub timestamp_ns: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: PixelFormat,
    pub kind: FrameKind,
    /// 0 for an untransformed buffer; a `wl_output.transform` value otherwise.
    /// Hyprland reports 0 on eDP-1.
    pub transform: u32,
    pub data: FrameData<'a>,
}

/// What the compositor said it can hand out as dmabuf: the render node to
/// allocate on and the (fourcc, modifiers) it will blit into.
#[derive(Debug, Clone, Default)]
pub struct DmabufConstraints {
    /// `dev_t` of the DRM node buffers must be allocated on.
    pub device: Option<u64>,
    /// (DRM fourcc, modifiers).
    pub formats: Vec<(u32, Vec<u64>)>,
}

/// Whether to capture straight into GPU buffers the encoder can map, instead of
/// shm buffers it has to upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZeroCopy {
    /// Try dmabuf; on any failure fall back to shm and record why. This is the
    /// default because a working picture beats a fast one: every failure mode
    /// here (missing global, no LINEAR modifier, no gbm, a compositor that
    /// rejects the import) degrades instead of breaking mirroring.
    #[default]
    Auto,
    /// Require dmabuf. A failed negotiation is an error, not a fallback — for
    /// tests and for proving the path is actually live.
    On,
    /// shm only.
    Off,
}

impl ZeroCopy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(ZeroCopy::Auto),
            "on" | "yes" | "true" | "1" | "dmabuf" => Some(ZeroCopy::On),
            "off" | "no" | "false" | "0" | "shm" => Some(ZeroCopy::Off),
            _ => None,
        }
    }
}

impl std::fmt::Display for ZeroCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ZeroCopy::Auto => "auto",
            ZeroCopy::On => "on",
            ZeroCopy::Off => "off",
        })
    }
}

/// What a live session actually ended up allocating. Read it from
/// [`Capture::buffer_mode`] rather than assuming the request was honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferMode {
    Shm,
    Dmabuf,
}

impl std::fmt::Display for BufferMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BufferMode::Shm => "shm",
            BufferMode::Dmabuf => "dmabuf",
        })
    }
}

/// One dmabuf, described exactly as `av_hwframe_map` needs it.
///
/// The fd is owned here and closed when the last handle drops. That is
/// deliberate: the GPU buffer object and the `wl_buffer` are owned by the
/// capture thread and destroyed there, but the fd can outlive them on the
/// consumer's thread, and a dmabuf's pages stay alive as long as any reference
/// to them does. So a shutdown race leaves the encoder holding a valid buffer
/// rather than a dangling one.
pub struct DmabufImage {
    /// Unique for the life of the process, never re-used. The encoder caches
    /// its VA-API surface mapping under this, which is what turns a per-frame
    /// import into a once-per-buffer one.
    pub id: u64,
    pub width: u32,
    pub height: u32,
    /// DRM fourcc (`XR24`/`AR24`).
    pub fourcc: u32,
    /// Always `DRM_FORMAT_MOD_LINEAR` here — see [`choose_dmabuf_format`].
    pub modifier: u64,
    pub offset: u32,
    pub stride: u32,
    /// Total size of the backing object, from `lseek(fd, 0, SEEK_END)`. libav's
    /// `AVDRMObjectDescriptor` wants it and gets it wrong if guessed.
    pub size: usize,
    fd: OwnedFd,
}

impl DmabufImage {
    /// The PRIME fd. Borrowed: the handle owns it.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl std::fmt::Debug for DmabufImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmabufImage")
            .field("id", &self.id)
            .field("size", &format_args!("{}x{}", self.width, self.height))
            .field("fourcc", &fourcc_name(self.fourcc))
            .field("modifier", &format_args!("0x{:016x} ({})", self.modifier, modifier_name(self.modifier)))
            .field("stride", &self.stride)
            .field("offset", &self.offset)
            .field("bytes", &self.size)
            .field("fd", &self.fd.as_raw_fd())
            .finish()
    }
}

/// Counters for the bench command and the live test. Every one is an exact
/// count, never a threshold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureStats {
    pub fresh: u64,
    pub repeats: u64,
    pub failures: u64,
    pub reallocations: u64,
    pub session_restarts: u64,
    /// How many timestamps had to be nudged forward to stay strictly
    /// increasing. See [`enforce_monotonic`]; measured at 1 per 122 frames in a
    /// 20 s desktop run, so this is a real case, not a theoretical one.
    pub pts_fixups: u64,
    /// Zero-copy only: how many times a capture could not be submitted because
    /// every dmabuf in the set was still held downstream. Each one costs a
    /// keepalive repeat instead of a fresh frame, so a non-zero count here
    /// means the set is too small for the consumer's hold time.
    pub buffer_starved: u64,
    /// How many times the session gave up on dmabuf and (re)allocated shm
    /// buffers. 0 on a healthy zero-copy run, 1 when the negotiation failed at
    /// open, more if the compositor started failing dmabuf captures mid-stream.
    pub zero_copy_fallbacks: u64,
}

/// How to open a capture.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub source: CaptureSource,
    /// Ask the compositor to composite the cursor into the capture.
    pub paint_cursors: bool,
    /// Re-emit the last frame after this much stillness. The probe's measured
    /// figure is ~250 ms.
    pub keepalive: Duration,
    /// How long to wait for the very first frame before giving up. The first
    /// capture in a session completes immediately by spec, so this only fires
    /// when something is actually wrong.
    pub first_frame_timeout: Duration,
    /// Capture into GPU buffers instead of shm. See [`ZeroCopy`].
    pub zero_copy: ZeroCopy,
    /// Raised by the owner to ask a blocked call to return promptly.
    ///
    /// Without it the only way out of [`Capture::next_frame`] is a completed
    /// capture or a timeout, so a shutdown has to wait out the keepalive —
    /// or, before the first frame or during a session restart,
    /// [`Self::first_frame_timeout`]. It is checked at the top of every
    /// `advance` iteration and inside every poll, so the bound becomes
    /// [`CANCEL_POLL_SLICE`] instead.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl CaptureConfig {
    pub fn new(source: CaptureSource) -> Self {
        CaptureConfig {
            source,
            paint_cursors: true,
            keepalive: Duration::from_millis(250),
            first_frame_timeout: Duration::from_secs(5),
            zero_copy: ZeroCopy::default(),
            cancel: None,
        }
    }
}

/// One monitor, as the compositor describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputInfo {
    pub name: String,
    pub width: i32,
    pub height: i32,
    /// Refresh rate in mHz, as wl_output reports it (60000 = 60.000 Hz).
    pub refresh_mhz: i32,
}

/// One toplevel window, as `ext_foreign_toplevel_list_v1` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToplevelInfo {
    pub app_id: String,
    pub title: String,
}

/// What is available to capture right now.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub outputs: Vec<OutputInfo>,
    pub toplevels: Vec<ToplevelInfo>,
    /// (interface, version) for the globals this module cares about.
    pub globals: Vec<(String, u32)>,
}

// ================================================================ pure helpers

/// Pick the shm format to allocate. XRGB is preferred over ARGB: the alpha
/// channel is meaningless for a screen capture and `bgr0` is one less thing for
/// the VPP stage to think about.
pub fn choose_pixel_format(offered: &[u32]) -> Result<PixelFormat, CaptureError> {
    if offered.contains(&PixelFormat::Xrgb8888.wl_shm_code()) {
        Ok(PixelFormat::Xrgb8888)
    } else if offered.contains(&PixelFormat::Argb8888.wl_shm_code()) {
        Ok(PixelFormat::Argb8888)
    } else {
        Err(CaptureError::NoShmFormat(offered.to_vec()))
    }
}

/// `DRM_FORMAT_MOD_LINEAR`. The only modifier this path ever asks for.
pub const DRM_FORMAT_MOD_LINEAR: u64 = 0;

/// Pick the dmabuf format to allocate, from what the session advertised.
///
/// LINEAR only, and XRGB before ARGB for the same reason the shm path prefers
/// it. This compositor also advertises `4_TILED_MTL_RC_CCS_CC` — the compressed
/// modifier that killed gpu-screen-recorder's PipeWire path with
/// `alloc buffers: -22`. In ext-image-copy-capture the CLIENT allocates and so
/// the CLIENT picks the modifier, which means that trap is not something to
/// defend against: it is simply never chosen.
pub fn choose_dmabuf_format(offered: &[(u32, Vec<u64>)]) -> Option<PixelFormat> {
    [PixelFormat::Xrgb8888, PixelFormat::Argb8888]
        .into_iter()
        .find(|want| {
            offered.iter().any(|(fourcc, mods)| {
                *fourcc == want.drm_fourcc() && mods.contains(&DRM_FORMAT_MOD_LINEAR)
            })
        })
}

/// Resolve the session's `dmabuf_device` to the DRM node with that device
/// number, by comparing `st_rdev` rather than by guessing at `renderD128`.
pub fn render_node_path(dev: u64) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let mut found = None;
    for entry in std::fs::read_dir("/dev/dri").ok()?.flatten() {
        let path = entry.path();
        let Ok(md) = std::fs::metadata(&path) else { continue };
        if md.rdev() == dev {
            // Prefer a render node over a primary node if both somehow match.
            let is_render = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("renderD"));
            if is_render {
                return Some(path);
            }
            found = Some(path);
        }
    }
    found
}

/// Stride and total byte length for a tightly packed 4-bytes-per-pixel buffer.
pub fn plane_geometry(width: u32, height: u32, format: PixelFormat) -> (u32, usize) {
    let stride = width * format.bytes_per_pixel();
    (stride, stride as usize * height as usize)
}

/// Reassemble the split 64-bit seconds + nanoseconds of a
/// `presentation_time` event into CLOCK_MONOTONIC nanoseconds.
pub fn presentation_ns(tv_sec_hi: u32, tv_sec_lo: u32, tv_nsec: u32) -> u64 {
    let secs = ((tv_sec_hi as u64) << 32) | tv_sec_lo as u64;
    secs * 1_000_000_000 + tv_nsec as u64
}

/// `dmabuf_device` arrives as a `dev_t` in a raw byte array in host byte order.
pub fn dev_t_from_bytes(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    Some(u64::from_ne_bytes(buf))
}

/// glibc's `major()`/`minor()` decomposition of a `dev_t`.
pub fn dev_major_minor(dev: u64) -> (u32, u32) {
    let major = ((dev >> 8) & 0xfff) | (((dev >> 32) as u32 as u64) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major as u32, minor as u32)
}

/// Window matching: case-insensitive substring over either title or app_id.
pub fn window_matches(app_id: &str, title: &str, needle: &str) -> bool {
    let needle = needle.to_lowercase();
    app_id.to_lowercase().contains(&needle) || title.to_lowercase().contains(&needle)
}

/// Human-readable name for a wl_shm format code.
pub fn shm_format_name(code: u32) -> String {
    match code {
        0 => "ARGB8888 (shm 0)".to_string(),
        1 => "XRGB8888 (shm 1)".to_string(),
        other => fourcc_name(other),
    }
}

/// Render a DRM fourcc as its four ASCII characters plus the raw value.
pub fn fourcc_name(code: u32) -> String {
    let s: String = code
        .to_le_bytes()
        .iter()
        .map(|&c| if c.is_ascii_graphic() { c as char } else { '?' })
        .collect();
    format!("{s} (0x{code:08x})")
}

/// Names for the DRM format modifiers this machine's compositor advertises.
pub fn modifier_name(m: u64) -> &'static str {
    match m {
        0x00ff_ffff_ffff_ffff => "DRM_FORMAT_MOD_INVALID",
        0 => "LINEAR",
        0x0100_0000_0000_0001 => "I915_FORMAT_MOD_X_TILED",
        0x0100_0000_0000_0002 => "I915_FORMAT_MOD_Y_TILED",
        0x0100_0000_0000_0009 => "I915_FORMAT_MOD_4_TILED",
        0x0100_0000_0000_000d => "I915_FORMAT_MOD_4_TILED_MTL_RC_CCS",
        0x0100_0000_0000_000e => "I915_FORMAT_MOD_4_TILED_MTL_MC_CCS",
        0x0100_0000_0000_000f => "I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC",
        0x0100_0000_0000_0010 => "I915_FORMAT_MOD_4_TILED_LNL_CCS",
        0x0100_0000_0000_0011 => "I915_FORMAT_MOD_4_TILED_BMG_CCS",
        _ => "?",
    }
}

/// Force a timestamp to be strictly greater than the previous one, returning
/// the timestamp to use and whether it had to be changed.
///
/// This is not theoretical tidiness. A [`FrameKind::Repeat`] is stamped "now",
/// while a [`FrameKind::Fresh`] carries the compositor's `presentation_time` —
/// the moment the frame was PUT ON THE SCREEN, which is in the past. So a
/// keepalive followed by a fresh frame can legitimately step backwards (it
/// happened once in a 20 s desktop run here). H.264 PTS must increase, so the
/// capture layer guarantees that and counts the fixups rather than leaving a
/// landmine for the encoder.
pub fn enforce_monotonic(previous: Option<u64>, raw: u64) -> (u64, bool) {
    match previous {
        Some(prev) if raw <= prev => (prev + 1, true),
        _ => (raw, false),
    }
}

/// CLOCK_MONOTONIC now, in nanoseconds — the same clock the compositor's
/// `presentation_time` uses, so a keepalive timestamp is comparable with a real
/// one.
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec and CLOCK_MONOTONIC always exists.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

// ============================================================ protocol state

/// Buffer constraints as they arrive from the session. Accumulated into
/// `pending` and swapped into `current` on `done`, because the compositor may
/// re-send the whole set at any time (output mode/scale change, or any toplevel
/// resize in window mode).
#[derive(Default, Debug, Clone)]
struct Constraints {
    size: Option<(u32, u32)>,
    shm_formats: Vec<u32>,
    dmabuf: DmabufConstraints,
}

/// Geometry of the shm buffers a set of constraints calls for.
fn shm_format_of(c: &Constraints) -> Result<FrameFormat, CaptureError> {
    let (width, height) = c
        .size
        .ok_or(CaptureError::Protocol("session sent no buffer_size".into()))?;
    let format = choose_pixel_format(&c.shm_formats)?;
    let (stride, _len) = plane_geometry(width, height, format);
    Ok(FrameFormat { width, height, stride, format })
}

#[derive(Default)]
struct FrameState {
    ready: bool,
    failed: Option<FailureReason>,
    transform: u32,
    damage: Vec<(i32, i32, i32, i32)>,
    presentation_ns: Option<u64>,
}

/// Everything the dispatch callbacks write into.
#[derive(Default)]
struct State {
    /// Parallel to the bound wl_output proxies; indexed by the dispatch udata.
    outputs: Vec<(WlOutput, Option<String>, i32, i32, i32)>,
    toplevels: Vec<(ExtForeignToplevelHandleV1, Option<String>, Option<String>, bool)>,
    /// The toplevel being captured, in window mode. Held so the `closed`
    /// handler can tell the capture target apart from every other window,
    /// whose handle it destroys and forgets.
    target_toplevel: Option<ExtForeignToplevelHandleV1>,
    /// Set when `target_toplevel` reports `closed`. Authoritative once the
    /// handle has been destroyed and its slot pruned.
    target_closed: bool,
    pending: Constraints,
    current: Option<Constraints>,
    /// Bumped on every session `done`, so a re-negotiation is detectable
    /// without comparing contents.
    generation: u64,
    /// Result of the in-flight `zwp_linux_buffer_params_v1.create`:
    /// `Ok(buffer)` from `created`, `Err(())` from `failed`. Exactly one
    /// params object is ever in flight, so one slot is enough.
    params: Option<Result<WlBuffer, ()>>,
    session_stopped: bool,
    frame: FrameState,
    /// Bumped by every `wl_display.sync` callback, so [`bounded_roundtrip`] can
    /// tell its own sync from an earlier one without holding the proxy.
    sync_done: u64,
}

macro_rules! ignore_events {
    ($($t:ty),* $(,)?) => {$(
        impl Dispatch<$t, ()> for State {
            fn event(_: &mut Self, _: &$t, _: <$t as Proxy>::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {}
        }
    )*};
}
ignore_events!(
    WlShm,
    WlShmPool,
    WlBuffer,
    ZwpLinuxDmabufV1,
    ExtImageCaptureSourceV1,
    ExtOutputImageCaptureSourceManagerV1,
    ExtForeignToplevelImageCaptureSourceManagerV1,
    ExtImageCopyCaptureManagerV1,
);

impl Dispatch<WlCallback, ()> for State {
    fn event(
        state: &mut Self,
        _: &WlCallback,
        event: wl_callback::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_callback::Event::Done { .. } = event {
            state.sync_done += 1;
        }
    }
}

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: <WlRegistry as Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlOutput, usize> for State {
    fn event(
        state: &mut Self,
        _: &WlOutput,
        event: wl_output::Event,
        idx: &usize,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(slot) = state.outputs.get_mut(*idx) else { return };
        match event {
            wl_output::Event::Name { name } => slot.1 = Some(name),
            wl_output::Event::Mode { flags: WEnum::Value(f), width, height, refresh }
                if f.contains(wl_output::Mode::Current) =>
            {
                slot.2 = width;
                slot.3 = height;
                slot.4 = refresh;
            }
            _ => {}
        }
    }
}

impl Dispatch<ExtImageCopyCaptureSessionV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ExtImageCopyCaptureSessionV1,
        event: ext_image_copy_capture_session_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_image_copy_capture_session_v1::Event as E;
        match event {
            E::BufferSize { width, height } => state.pending.size = Some((width, height)),
            E::ShmFormat { format } => state.pending.shm_formats.push(u32::from(format)),
            E::DmabufDevice { device } => state.pending.dmabuf.device = dev_t_from_bytes(&device),
            E::DmabufFormat { format, modifiers } => {
                let mods = modifiers
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|c| u64::from_ne_bytes(*c))
                    .collect();
                state.pending.dmabuf.formats.push((format, mods));
            }
            E::Done => {
                state.current = Some(std::mem::take(&mut state.pending));
                state.generation += 1;
            }
            E::Stopped => state.session_stopped = true,
            _ => {}
        }
    }
}

impl Dispatch<ExtImageCopyCaptureFrameV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ExtImageCopyCaptureFrameV1,
        event: ext_image_copy_capture_frame_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_image_copy_capture_frame_v1::Event as E;
        match event {
            E::Ready => state.frame.ready = true,
            E::Failed { reason } => {
                state.frame.failed = Some(Result::from(reason).unwrap_or(FailureReason::Unknown));
            }
            E::Transform { transform } => state.frame.transform = u32::from(transform),
            E::Damage { x, y, width, height } => state.frame.damage.push((x, y, width, height)),
            E::PresentationTime { tv_sec_hi, tv_sec_lo, tv_nsec } => {
                state.frame.presentation_ns = Some(presentation_ns(tv_sec_hi, tv_sec_lo, tv_nsec));
            }
            _ => {}
        }
    }
}

impl Dispatch<ZwpLinuxBufferParamsV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ZwpLinuxBufferParamsV1,
        event: zwp_linux_buffer_params_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            zwp_linux_buffer_params_v1::Event::Created { buffer } => {
                state.params = Some(Ok(buffer))
            }
            // `failed` is the whole reason this path uses `create` and not
            // `create_immed`: create_immed answers an import the compositor
            // dislikes with a FATAL protocol error, which kills the connection
            // and takes mirroring with it. `create` answers with this event, so
            // a rejected modifier costs one fallback to shm.
            zwp_linux_buffer_params_v1::Event::Failed => state.params = Some(Err(())),
            _ => {}
        }
    }

    // The `created` event carries a new wl_buffer object, so it needs the
    // specialisation. Without it this compiles and panics at runtime.
    wayland_client::event_created_child!(State, ZwpLinuxBufferParamsV1, [
        zwp_linux_buffer_params_v1::EVT_CREATED_OPCODE => (WlBuffer, ()),
    ]);
}

impl Dispatch<ExtForeignToplevelListV1, ()> for State {
    fn event(
        state: &mut Self,
        list: &ExtForeignToplevelListV1,
        event: ext_foreign_toplevel_list_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_foreign_toplevel_list_v1::Event::Toplevel { toplevel } => {
                state.toplevels.push((toplevel, None, None, false));
            }
            // The compositor has stopped sending toplevel events and is
            // waiting for the object to go away. Ignoring it leaks the list.
            ext_foreign_toplevel_list_v1::Event::Finished => list.destroy(),
            _ => {}
        }
    }

    // MANDATORY: without this the crate panics at runtime with
    // "Missing event_created_child specialization for event opcode 0".
    wayland_client::event_created_child!(State, ExtForeignToplevelListV1, [
        ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE => (ExtForeignToplevelHandleV1, ()),
    ]);
}

impl Dispatch<ExtForeignToplevelHandleV1, ()> for State {
    fn event(
        state: &mut Self,
        handle: &ExtForeignToplevelHandleV1,
        event: ext_foreign_toplevel_handle_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // The window went away: the session will stop too, but knowing the
        // toplevel is gone is what stops us trying to re-open it.
        //
        // `ext-foreign-toplevel-list-v1` is explicit that the client should
        // destroy the handle here, and the list is bound for the whole life of
        // a window capture — so without this every window the user opens and
        // closes during a session leaves a live proxy and its strings behind,
        // and the linear scans below grow with them.
        if matches!(event, ext_foreign_toplevel_handle_v1::Event::Closed) {
            if state.target_toplevel.as_ref() == Some(handle) {
                // Remembered separately, because the slot is about to go: this
                // is what `restart_session` reads to refuse a dead window.
                state.target_closed = true;
                state.target_toplevel = None;
            }
            handle.destroy();
            state.toplevels.retain(|t| &t.0 != handle);
            return;
        }
        let Some(slot) = state.toplevels.iter_mut().find(|t| &t.0 == handle) else { return };
        match event {
            ext_foreign_toplevel_handle_v1::Event::Title { title } => slot.1 = Some(title),
            ext_foreign_toplevel_handle_v1::Event::AppId { app_id } => slot.2 = Some(app_id),
            _ => {}
        }
    }
}

// ==================================================================== gbm

/// The slice of libgbm this needs. Hand-written rather than pulled in as a
/// crate: it is nine symbols, and `gbm` is already a hard runtime dependency of
/// every Wayland compositor this can possibly run under.
mod gbm {
    use std::os::raw::{c_int, c_void};

    #[link(name = "gbm")]
    unsafe extern "C" {
        pub fn gbm_create_device(fd: c_int) -> *mut c_void;
        pub fn gbm_device_destroy(dev: *mut c_void);
        pub fn gbm_bo_create(dev: *mut c_void, w: u32, h: u32, format: u32, flags: u32) -> *mut c_void;
        pub fn gbm_bo_destroy(bo: *mut c_void);
        pub fn gbm_bo_get_fd(bo: *mut c_void) -> c_int;
        pub fn gbm_bo_get_plane_count(bo: *mut c_void) -> c_int;
        pub fn gbm_bo_get_stride_for_plane(bo: *mut c_void, plane: c_int) -> u32;
        pub fn gbm_bo_get_offset(bo: *mut c_void, plane: c_int) -> u32;
        pub fn gbm_bo_get_modifier(bo: *mut c_void) -> u64;
        pub fn gbm_bo_map(
            bo: *mut c_void,
            x: u32,
            y: u32,
            width: u32,
            height: u32,
            flags: u32,
            stride: *mut u32,
            map_data: *mut *mut c_void,
        ) -> *mut c_void;
        pub fn gbm_bo_unmap(bo: *mut c_void, map_data: *mut c_void);
    }

    pub const GBM_BO_USE_RENDERING: u32 = 1 << 2;
    pub const GBM_BO_USE_LINEAR: u32 = 1 << 4;
    pub const GBM_BO_TRANSFER_READ_WRITE: u32 = 3;
}

/// Unique, never re-used buffer ids. The encoder caches a VA-API surface per
/// id, so re-using one would silently hand it the wrong memory.
static NEXT_DMABUF_ID: AtomicU64 = AtomicU64::new(1);

/// The smallest row pitch alignment the VA-API import will actually honour.
///
/// This is a MEASURED number, not a guess, and it is the whole reason
/// [`STRIDE_REQUEST_ALIGN`] exists. Capturing a 1884-pixel-wide window
/// (1256 logical on a scale-1.5 panel) gives gbm the tight stride 1884*4 =
/// 7536. The compositor blits into that buffer perfectly — mmapping the PRIME
/// fd and reading it back at 7536 gives a pixel-exact picture — but
/// `av_hwframe_map(DRM_PRIME -> VAAPI, DIRECT)` then reads it at a pitch of
/// its own, and the encoded frame comes out DIAGONALLY SHEARED.
///
/// Measured on this machine (Intel iHD, Hyprland, XR24/LINEAR), same window,
/// `mirror-bench --window foot --zero-copy on`, decoded frame inspected:
///
/// | stride | 64-aligned | decoded picture |
/// |--------|-----------|-----------------|
/// | 7536   | no (mod 48) | sheared       |
/// | 7568   | no (mod 16) | sheared       |
/// | 7584   | no (mod 32) | sheared       |
/// | 7552   | YES         | correct       |
/// | 7680   | YES         | correct       |
///
/// So the importer honours the pitch it is given as long as it is a multiple
/// of 64 bytes, and substitutes its own when it is not. The shm path is
/// unaffected — it goes through `sws`/`av_hwframe_transfer_data`, which handle
/// any linesize — which is why `--zero-copy off` was always correct, and why a
/// 1920-wide output (1920*4 = 7680, already aligned) hid this from milestone 2
/// until the first window capture.
pub const STRIDE_HONOURED_ALIGN: u32 = 64;

/// What the dmabuf allocation asks gbm to pad each row to.
///
/// A multiple of [`STRIDE_HONOURED_ALIGN`], with margin: 256 is the alignment
/// DRM scanout and the other common drivers want, it costs at most 252 bytes
/// per row (about 1 MB across the whole four-buffer set at 1125 rows), and it
/// is a no-op for the widths that were already aligned — 1920*4 = 7680 is a
/// multiple of 256, so whole-screen capture allocates exactly what it always
/// did. `Gbm::allocate` checks what came back against
/// [`STRIDE_HONOURED_ALIGN`] rather than against this, so a driver that
/// ignores the padded request still gets a correct picture (via the shm
/// fallback) instead of a sheared one.
const STRIDE_REQUEST_ALIGN: u32 = 256;

/// An owned `gbm_bo`.
struct Bo(*mut c_void);

impl Drop for Bo {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live bo from gbm_bo_create, destroyed once.
        unsafe { gbm::gbm_bo_destroy(self.0) }
    }
}

/// An open gbm device on the render node the compositor named.
struct Gbm {
    dev: *mut c_void,
    /// Kept open: gbm_create_device does not take ownership of the fd.
    _node: std::fs::File,
    path: std::path::PathBuf,
}

impl Gbm {
    fn open(path: &std::path::Path) -> Result<Self, CaptureError> {
        let node = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| CaptureError::Dmabuf(format!("open {}: {e}", path.display())))?;
        // SAFETY: a valid, open DRM node fd that outlives the device.
        let dev = unsafe { gbm::gbm_create_device(node.as_raw_fd()) };
        if dev.is_null() {
            return Err(CaptureError::Dmabuf(format!(
                "gbm_create_device({}) returned null",
                path.display()
            )));
        }
        Ok(Gbm { dev, _node: node, path: path.to_path_buf() })
    }

    /// Allocate one LINEAR buffer and export it as a PRIME fd.
    ///
    /// LINEAR and `GBM_BO_USE_RENDERING` are exactly what the encoder spike
    /// proved importable (`Map DRM object to VAAPI as BGRX / Direct mapping
    /// possible`). Anything else the driver might pick is rejected here rather
    /// than discovered as an EINVAL inside libav.
    fn allocate(&self, width: u32, height: u32, format: PixelFormat) -> Result<(Bo, Arc<DmabufImage>), CaptureError> {
        let fourcc = format.drm_fourcc();
        // Ask for a bo whose rows are padded to STRIDE_REQUEST_ALIGN. gbm
        // hands back the tight stride for the width it is given, so the only
        // way to get an aligned stride out of it is to ask for an aligned
        // WIDTH; the wl_buffer and the DRM descriptor then both carry the real
        // `width` with that padded stride, which is exactly what
        // `zwp_linux_buffer_params_v1.add` and `AVDRMPlaneDescriptor` are for.
        // See [`STRIDE_HONOURED_ALIGN`] for why this is not cosmetic.
        let bpp = format.bytes_per_pixel();
        let alloc_width = (width * bpp).next_multiple_of(STRIDE_REQUEST_ALIGN) / bpp;
        // SAFETY: `self.dev` is a live gbm device.
        let raw = unsafe {
            gbm::gbm_bo_create(
                self.dev,
                alloc_width,
                height,
                fourcc,
                gbm::GBM_BO_USE_LINEAR | gbm::GBM_BO_USE_RENDERING,
            )
        };
        if raw.is_null() {
            return Err(CaptureError::Dmabuf(format!(
                "gbm_bo_create({} {width}x{height}, LINEAR) on {} returned null",
                fourcc_name(fourcc),
                self.path.display()
            )));
        }
        let bo = Bo(raw);
        // SAFETY: `bo` is live for all of these.
        let (planes, modifier, stride, offset) = unsafe {
            (
                gbm::gbm_bo_get_plane_count(bo.0),
                gbm::gbm_bo_get_modifier(bo.0),
                gbm::gbm_bo_get_stride_for_plane(bo.0, 0),
                gbm::gbm_bo_get_offset(bo.0, 0),
            )
        };
        if planes != 1 {
            return Err(CaptureError::Dmabuf(format!(
                "gbm gave {planes} planes for {}; this path handles single-plane RGB only",
                fourcc_name(fourcc)
            )));
        }
        if modifier != DRM_FORMAT_MOD_LINEAR {
            return Err(CaptureError::Dmabuf(format!(
                "gbm gave modifier 0x{modifier:016x} ({}) but only LINEAR was negotiated",
                modifier_name(modifier)
            )));
        }
        // A bo narrower than asked for would have every row after the first
        // read out of the previous row's tail. gbm does not do this; assert it
        // rather than discover it as a sheared picture.
        if stride < width * bpp {
            return Err(CaptureError::Dmabuf(format!(
                "gbm gave stride {stride} for a {width}-pixel row of {}, which needs at least {}",
                fourcc_name(fourcc),
                width * bpp
            )));
        }
        // The padded request above is only a request. If the driver did not
        // honour it, refuse the buffer: the caller then falls back to shm (a
        // correct, slower picture) or fails outright under `--zero-copy on`.
        // Never proceed with a stride the importer will silently replace.
        if !stride.is_multiple_of(STRIDE_HONOURED_ALIGN) {
            return Err(CaptureError::Dmabuf(format!(
                "gbm gave stride {stride} for {}x{height} {}, which is not a multiple of \
                 {STRIDE_HONOURED_ALIGN}; the VA-API import would ignore it and shear the picture",
                alloc_width,
                fourcc_name(fourcc),
            )));
        }
        // SAFETY: `bo` is live; the returned fd is owned by us.
        let fd = unsafe { gbm::gbm_bo_get_fd(bo.0) };
        if fd < 0 {
            return Err(CaptureError::Dmabuf("gbm_bo_get_fd failed".into()));
        }
        // SAFETY: a fresh, owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: a valid fd; SEEK_END on a dmabuf reports its size.
        let size = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_END) };
        if size <= 0 {
            return Err(CaptureError::Dmabuf(
                "lseek(dmabuf, SEEK_END) reported no size".into(),
            ));
        }
        // libav hands this size to the driver as `AVDRMObjectDescriptor.size`,
        // so an object that does not actually cover every row is a read past
        // the end of the buffer, not a cosmetic mismatch.
        let need = offset as usize + stride as usize * height as usize;
        if (size as usize) < need {
            return Err(CaptureError::Dmabuf(format!(
                "gbm object is {size} bytes but {height} rows of stride {stride} at offset \
                 {offset} need {need}"
            )));
        }
        let image = Arc::new(DmabufImage {
            id: NEXT_DMABUF_ID.fetch_add(1, Ordering::Relaxed),
            width,
            height,
            fourcc,
            modifier,
            offset,
            stride,
            size: size as usize,
            fd,
        });
        Ok((bo, image))
    }
}

impl Drop for Gbm {
    fn drop(&mut self) {
        // SAFETY: destroyed once, after every bo made from it (field order in
        // `Capture` puts `buffers` before `gbm`).
        unsafe { gbm::gbm_device_destroy(self.dev) }
    }
}

// SAFETY: the gbm device pointer is owned exclusively by this struct and only
// touched through `&self`/`&mut self` on whichever thread owns the `Capture`.
unsafe impl Send for Gbm {}

/// One dmabuf allocated by [`allocate_dmabuf`], with the gbm bo and device it
/// came from kept alive behind it. Field order IS the drop order: the image
/// (which owns the PRIME fd) goes first, then the bo, then the device.
pub struct StandaloneDmabuf {
    pub image: Arc<DmabufImage>,
    _bo: Bo,
    _gbm: Gbm,
}

/// Allocate one dmabuf on `node` exactly the way a zero-copy capture session
/// allocates its capture targets — same gbm flags, same stride padding, same
/// checks — but with no wayland session attached.
///
/// This exists so the zero-copy ENCODE path can be exercised on its own. The
/// stride shear this crate shipped for two milestones was invisible to every
/// test because proving it needs a buffer whose width is not stride-aligned,
/// and going through a compositor to get one means creating an output or
/// resizing somebody's window. See [`STRIDE_HONOURED_ALIGN`].
pub fn allocate_dmabuf(
    node: &std::path::Path,
    width: u32,
    height: u32,
    format: PixelFormat,
) -> Result<StandaloneDmabuf, CaptureError> {
    let gbm = Gbm::open(node)?;
    let (bo, image) = gbm.allocate(width, height, format)?;
    Ok(StandaloneDmabuf { image, _bo: bo, _gbm: gbm })
}

impl StandaloneDmabuf {
    /// Give `paint` a CPU view of the buffer, through gbm's OWN mapping, and
    /// hand back what it returns. The closure gets the bytes and the stride
    /// the mapping uses, which is the stride it must paint at.
    ///
    /// Production never writes a capture buffer from the CPU — the
    /// compositor's GPU blit fills it — so this exists only so a test can put
    /// a picture it knows into a real dmabuf. It is a method here, and not
    /// `mmap` on the PRIME fd in the test, because on this hardware the
    /// low-level route is WRONG and fails silently:
    ///
    /// `mmap(prime_fd)` on i915 hands back a plain write-back CACHED mapping
    /// of the object's shmem pages, and `DMA_BUF_IOCTL_SYNC(SYNC_END)` around
    /// the write does NOT write those dirty cache lines back on an Arrow Lake
    /// iGPU. The CPU then reads its own correct picture out of its own cache
    /// while the GPU reads whatever reached DRAM — a drifting mix of painted
    /// pixels and the buffer's initial zeros, which arrives as black dashes,
    /// differs from frame to frame as lines are evicted, and cannot be caught
    /// by reading the buffer back through the same mapping. Measured: nine
    /// encodes of one static picture coded to 661511 bytes that way and to
    /// 179127 bytes once the lines were forced out, which is what a static
    /// picture should cost.
    ///
    /// `gbm_bo_map` is the allocator's own answer to that question, and the
    /// driver decides how to honour it: on this one it hands back a staging
    /// buffer at its own tight pitch and blits it into the bo on
    /// `gbm_bo_unmap`, so the picture is in the GPU's copy before this
    /// returns, and a later map reads it back out of the GPU's copy rather
    /// than out of a private cached one. That is why `paint` is given the
    /// stride to paint at instead of being expected to use
    /// [`DmabufImage::stride`]: the two are not the same number here (7536 vs
    /// 7680 for a 1884-pixel row), and painting at the wrong one puts a
    /// diagonally sheared picture in the buffer by hand.
    pub fn with_cpu_map<T>(
        &self,
        paint: impl FnOnce(&mut [u8], u32) -> T,
    ) -> Result<T, CaptureError> {
        let (w, h) = (self.image.width, self.image.height);
        let bpp = 4u32;
        let mut stride: u32 = 0;
        let mut map_data: *mut c_void = std::ptr::null_mut();
        // SAFETY: `self._bo` is a live bo; `stride` and `map_data` are valid
        // out-parameters; the mapping is released by `gbm_bo_unmap` below.
        let ptr = unsafe {
            gbm::gbm_bo_map(
                self._bo.0,
                0,
                0,
                w,
                h,
                gbm::GBM_BO_TRANSFER_READ_WRITE,
                &mut stride,
                &mut map_data,
            )
        };
        if ptr.is_null() || ptr == usize::MAX as *mut c_void {
            return Err(CaptureError::Dmabuf(format!(
                "gbm_bo_map({w}x{h}, READ_WRITE) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if stride < w * bpp {
            // SAFETY: the mapping made just above, released once.
            unsafe { gbm::gbm_bo_unmap(self._bo.0, map_data) };
            return Err(CaptureError::Dmabuf(format!(
                "gbm_bo_map gave stride {stride} for a {w}-pixel row, which needs {}",
                w * bpp
            )));
        }
        // The last row is only `w * bpp` long: the mapping is not promised to
        // cover the padding after it.
        let len = stride as usize * (h as usize - 1) + (w * bpp) as usize;
        // SAFETY: `ptr` is a live mapping of at least `len` bytes (gbm mapped
        // rows 0..h of `stride` bytes each), exclusively borrowed for the call
        // below and never aliased.
        let out = paint(unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, len) }, stride);
        // SAFETY: the mapping made above, released exactly once. This is the
        // point at which the write becomes visible to the GPU.
        unsafe { gbm::gbm_bo_unmap(self._bo.0, map_data) };
        Ok(out)
    }
}

/// One capture target on the zero-copy path: the GPU buffer, the `wl_buffer`
/// the compositor blits into, and the refcounted handle the consumer holds.
struct DmabufBuffer {
    buffer: WlBuffer,
    image: Arc<DmabufImage>,
    /// Dropped after `buffer`, and before the `Gbm` that made it.
    _bo: Bo,
}

impl Drop for DmabufBuffer {
    fn drop(&mut self) {
        self.buffer.destroy();
    }
}

// SAFETY: as for ShmBuffer — the only non-Send member is the gbm bo pointer,
// which belongs to the process and is owned solely by this struct.
unsafe impl Send for DmabufBuffer {}

/// How many dmabufs a zero-copy session keeps.
///
/// Four is the analysed minimum and not a round number: at any moment the set
/// holds the front buffer (the last completed frame, re-emitted by the
/// keepalive), the in-flight capture target, one frame sitting in the
/// pipeline's mailbox and one being encoded. Three would starve every time the
/// consumer was busy; [`CaptureStats::buffer_starved`] counts it if four ever
/// turns out not to be enough.
const DMABUF_BUFFERS: usize = 4;

/// Wrap one dmabuf as a `wl_buffer`, using the two-step `create` so that a
/// compositor which dislikes the import answers with `failed` instead of
/// killing the connection.
fn dmabuf_wl_buffer(
    conn: &Connection,
    queue: &mut EventQueue<State>,
    state: &mut State,
    qh: &QueueHandle<State>,
    mgr: &ZwpLinuxDmabufV1,
    image: &DmabufImage,
    cancel: Option<&AtomicBool>,
) -> Result<WlBuffer, CaptureError> {
    // Allocate the params id immediately before the request that creates it.
    let params = mgr.create_params(qh, ());
    params.add(
        image.fd.as_fd(),
        0,
        image.offset,
        image.stride,
        (image.modifier >> 32) as u32,
        image.modifier as u32,
    );
    state.params = None;
    params.create(
        image.width as i32,
        image.height as i32,
        image.fourcc,
        zwp_linux_buffer_params_v1::Flags::empty(),
    );
    conn.flush().map_err(|e| CaptureError::Protocol(e.to_string()))?;

    let deadline = Instant::now() + Duration::from_secs(2);
    let got = pump(conn, queue, state, deadline, cancel, |s| s.params.is_some())?;
    let result = state.params.take();
    params.destroy();
    match (got, result) {
        (_, Some(Ok(buffer))) => Ok(buffer),
        (_, Some(Err(()))) => Err(CaptureError::Dmabuf(format!(
            "compositor rejected the import ({} {}x{} modifier 0x{:016x}): zwp_linux_buffer_params_v1.failed",
            fourcc_name(image.fourcc),
            image.width,
            image.height,
            image.modifier
        ))),
        _ => Err(CaptureError::Timeout("zwp_linux_buffer_params_v1.created")),
    }
}

// ================================================================= shm buffer

/// A memfd-backed wl_shm buffer plus its mapping.
struct ShmBuffer {
    buffer: WlBuffer,
    map: *mut u8,
    len: usize,
}

impl ShmBuffer {
    fn new(shm: &WlShm, qh: &QueueHandle<State>, format: FrameFormat) -> Result<Self, CaptureError> {
        let len = format.len();
        let name = std::ffi::CString::new("airplay-capture").expect("no interior NUL");
        // SAFETY: `name` is a valid NUL-terminated string for the duration of the call.
        let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if raw < 0 {
            return Err(CaptureError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: memfd_create returned a fresh, owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: `fd` is a valid memfd we exclusively own.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), len as i64) } < 0 {
            return Err(CaptureError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: mapping `len` bytes of a memfd sized to exactly `len`.
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return Err(CaptureError::Io(std::io::Error::last_os_error()));
        }
        let pool = shm.create_pool(fd.as_fd(), len as i32, qh, ());
        let buffer = pool.create_buffer(
            0,
            format.width as i32,
            format.height as i32,
            format.stride as i32,
            format.format.to_wl(),
            qh,
            (),
        );
        pool.destroy();
        Ok(ShmBuffer { buffer, map: map as *mut u8, len })
    }

    /// The mapped pixels.
    ///
    /// SAFETY of the underlying pointer: the mapping lives as long as `self`,
    /// and the caller only ever gets this for the buffer that is NOT attached
    /// to the in-flight capture frame, so the compositor is not writing it.
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `map` is a valid mapping of exactly `len` bytes owned by self.
        unsafe { std::slice::from_raw_parts(self.map, self.len) }
    }
}

// SAFETY: the only non-Send field is the mmap pointer. An mmap belongs to the
// process, not to a thread, and `ShmBuffer` is the sole owner of this one — it
// is created, read and unmapped through `&self`/`&mut self` only. Making this
// Send is what lets a `Capture` move onto the streaming thread.
unsafe impl Send for ShmBuffer {}

impl Drop for ShmBuffer {
    fn drop(&mut self) {
        self.buffer.destroy();
        // SAFETY: `map`/`len` are exactly what mmap returned and nothing else
        // holds a reference — `as_slice` borrows from `&self`.
        unsafe { libc::munmap(self.map as *mut libc::c_void, self.len) };
    }
}

// =================================================================== plumbing

/// How long a single `poll` may block once a cancellation flag is in play.
/// Nothing wakes the wayland fd when another thread raises the flag, so the
/// wait is sliced and the flag re-read; this is the real bound on how long a
/// shutdown can take.
const CANCEL_POLL_SLICE: Duration = Duration::from_millis(50);

fn cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::SeqCst))
}

/// Dispatch events until `done` is satisfied or the deadline passes. Returns
/// false on deadline. This is the only place that blocks.
///
/// `cancel`, when given, is checked before every wait and after every slice of
/// one, and turns into [`CaptureError::Cancelled`].
fn pump(
    conn: &Connection,
    queue: &mut EventQueue<State>,
    state: &mut State,
    deadline: Instant,
    cancel: Option<&AtomicBool>,
    done: impl Fn(&State) -> bool,
) -> Result<bool, CaptureError> {
    loop {
        queue.dispatch_pending(state)?;
        if done(state) {
            return Ok(true);
        }
        if cancelled(cancel) {
            return Err(CaptureError::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let Some(guard) = queue.prepare_read() else { continue };
        conn.flush().map_err(|e| CaptureError::Protocol(e.to_string()))?;
        let backend = conn.backend();
        let fd: BorrowedFd = backend.poll_fd();
        let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let mut wait = deadline - now;
        if cancel.is_some() {
            wait = wait.min(CANCEL_POLL_SLICE);
        }
        let ms = wait.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one initialised pollfd, count 1.
        let n = unsafe { libc::poll(&mut pfd, 1, ms.max(1)) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(CaptureError::Io(e));
        }
        if n == 0 {
            drop(guard);
            queue.dispatch_pending(state)?;
            if done(state) {
                return Ok(true);
            }
            // A slice ran out, not the deadline: go back and wait out the rest.
            if Instant::now() < deadline {
                continue;
            }
            return Ok(false);
        }
        guard.read().map_err(|e| CaptureError::Protocol(e.to_string()))?;
    }
}

/// How long the connection handshake may take before it is called wedged.
/// Matches `CaptureConfig::first_frame_timeout`'s default, and exists for the
/// same reason: a compositor that has not answered `wl_display.sync` in five
/// seconds is not going to.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// `EventQueue::roundtrip`, but with a deadline and a cancellation flag.
///
/// wayland-rs's own roundtrip blocks in `poll(.., None)`, so a wedged or
/// restarting compositor parks the caller forever — and in `mirror` this runs
/// AFTER pairing, RTSP setup and the NTP/event threads are live. The semantics
/// are otherwise identical: issue a `wl_display.sync` and dispatch until its
/// `done` comes back.
fn bounded_roundtrip(
    conn: &Connection,
    queue: &mut EventQueue<State>,
    state: &mut State,
    cancel: Option<&AtomicBool>,
    what: &'static str,
) -> Result<(), CaptureError> {
    let want = state.sync_done + 1;
    conn.display().sync(&queue.handle(), ());
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    if pump(conn, queue, state, deadline, cancel, |s| s.sync_done >= want)? {
        Ok(())
    } else {
        Err(CaptureError::Timeout(what))
    }
}

fn bind_global<I>(globals: &GlobalList, qh: &QueueHandle<State>, what: &'static str) -> Result<I, CaptureError>
where
    I: Proxy + 'static,
    State: Dispatch<I, ()>,
{
    globals
        .bind::<I, _, _>(qh, 1..=1, ())
        .map_err(|_| CaptureError::MissingGlobal(what))
}

/// Connect, bind every wl_output, and settle the registry. Shared by
/// [`list`] and [`Capture::open`].
fn connect(
    cancel: Option<&AtomicBool>,
) -> Result<(Connection, EventQueue<State>, GlobalList, State), CaptureError> {
    let conn = Connection::connect_to_env()?;
    let (globals, mut queue) = registry_queue_init::<State>(&conn)?;
    let qh = queue.handle();
    let mut state = State::default();

    let output_globals: Vec<(u32, u32)> = globals.contents().with_list(|list| {
        list.iter()
            .filter(|g| g.interface == "wl_output")
            .map(|g| (g.name, g.version))
            .collect()
    });
    for (name, version) in &output_globals {
        let idx = state.outputs.len();
        // Allocate the id immediately before the request that creates it.
        let out: WlOutput = globals.registry().bind(*name, (*version).min(4), &qh, idx);
        state.outputs.push((out, None, 0, 0, 0));
    }
    // Two roundtrips: the first delivers the output events, the second settles
    // anything they in turn produced. Bounded, so a wedged compositor is an
    // error and not a hang.
    let what = "the compositor's registry handshake";
    bounded_roundtrip(&conn, &mut queue, &mut state, cancel, what)?;
    bounded_roundtrip(&conn, &mut queue, &mut state, cancel, what)?;
    Ok((conn, queue, globals, state))
}

fn bind_toplevels(
    conn: &Connection,
    globals: &GlobalList,
    qh: &QueueHandle<State>,
    queue: &mut EventQueue<State>,
    state: &mut State,
    cancel: Option<&AtomicBool>,
) -> Result<ExtForeignToplevelListV1, CaptureError> {
    let list: ExtForeignToplevelListV1 = bind_global(globals, qh, "ext_foreign_toplevel_list_v1")?;
    let what = "the compositor's toplevel list";
    bounded_roundtrip(conn, queue, state, cancel, what)?;
    bounded_roundtrip(conn, queue, state, cancel, what)?;
    Ok(list)
}

/// Enumerate what can be captured: outputs, toplevel windows, and the capture
/// globals the compositor advertises.
pub fn list() -> Result<Inventory, CaptureError> {
    let (conn, mut queue, globals, mut state) = connect(None)?;
    let qh = queue.handle();

    let mut inv = Inventory::default();
    globals.contents().with_list(|l| {
        for g in l {
            if g.interface.starts_with("ext_")
                || g.interface == "wl_shm"
                || g.interface == "zwp_linux_dmabuf_v1"
            {
                inv.globals.push((g.interface.clone(), g.version));
            }
        }
    });
    inv.globals.sort();

    for (_, name, w, h, r) in &state.outputs {
        inv.outputs.push(OutputInfo {
            name: name.clone().unwrap_or_default(),
            width: *w,
            height: *h,
            refresh_mhz: *r,
        });
    }

    // Missing toplevel support is not fatal for `list` — outputs still work.
    if bind_toplevels(&conn, &globals, &qh, &mut queue, &mut state, None).is_ok() {
        for (_, title, app_id, closed) in &state.toplevels {
            if *closed {
                continue;
            }
            inv.toplevels.push(ToplevelInfo {
                app_id: app_id.clone().unwrap_or_default(),
                title: title.clone().unwrap_or_default(),
            });
        }
    }
    Ok(inv)
}

// ==================================================================== capture

/// The resolved capture target, kept so the session can be re-created if the
/// compositor stops it.
enum Target {
    Output(WlOutput),
    Window(ExtForeignToplevelHandleV1),
}

/// The allocated capture targets. Both arms are addressed by the same `front`
/// / `back` indices, so the state machine above them does not branch.
enum Buffers {
    Shm(Vec<ShmBuffer>),
    Dma(Vec<DmabufBuffer>),
}

impl Buffers {
    fn len(&self) -> usize {
        match self {
            Buffers::Shm(v) => v.len(),
            Buffers::Dma(v) => v.len(),
        }
    }
    fn wl(&self, index: usize) -> &WlBuffer {
        match self {
            Buffers::Shm(v) => &v[index].buffer,
            Buffers::Dma(v) => &v[index].buffer,
        }
    }
    fn mode(&self) -> BufferMode {
        match self {
            Buffers::Shm(_) => BufferMode::Shm,
            Buffers::Dma(_) => BufferMode::Dmabuf,
        }
    }
}

/// The last good frame, kept alive across a re-allocation.
///
/// A renegotiation, a session restart and an shm fallback all destroy the
/// buffer set, which would otherwise leave nothing to re-emit: the next
/// [`Capture::advance`] falls back to the first-frame timeout and, on a still
/// or blanked screen, that timeout is fatal and the pump never comes back. So
/// the front buffer is snapshotted first and keeps feeding the receiver as
/// [`FrameKind::Repeat`] until the new session produces a frame of its own.
///
/// The shm arm is a copy (the mapping is unmapped with the buffer). The dmabuf
/// arm is not: the PRIME fd inside [`DmabufImage`] holds the pages alive on its
/// own, so retaining the handle out of the retiring set costs nothing.
struct Carry {
    /// The geometry the snapshot was taken at. A re-allocation that lands on a
    /// different one drops the carry rather than lying about it.
    format: FrameFormat,
    data: CarryData,
}

enum CarryData {
    Shm(Vec<u8>),
    Dma(Arc<DmabufImage>),
}

impl Carry {
    fn mode(&self) -> BufferMode {
        match self.data {
            CarryData::Shm(_) => BufferMode::Shm,
            CarryData::Dma(_) => BufferMode::Dmabuf,
        }
    }
}

/// A live capture session. Call [`Capture::next_frame`] in a loop.
pub struct Capture {
    conn: Connection,
    queue: EventQueue<State>,
    qh: QueueHandle<State>,
    state: State,

    shm: WlShm,
    capture_mgr: ExtImageCopyCaptureManagerV1,
    output_mgr: Option<ExtOutputImageCaptureSourceManagerV1>,
    window_mgr: Option<ExtForeignToplevelImageCaptureSourceManagerV1>,
    _toplevel_list: Option<ExtForeignToplevelListV1>,

    target: Target,
    source: ExtImageCaptureSourceV1,
    session: ExtImageCopyCaptureSessionV1,
    inflight: Option<ExtImageCopyCaptureFrameV1>,

    /// Declared before `gbm` so every buffer object is destroyed before the
    /// device that made it.
    buffers: Buffers,
    /// Open only on the zero-copy path, and only once — re-negotiation reuses it.
    gbm: Option<Gbm>,
    dmabuf_mgr: Option<ZwpLinuxDmabufV1>,
    /// The live policy, which starts as [`CaptureConfig::zero_copy`] and is
    /// latched to [`ZeroCopy::Off`] the moment dmabuf fails. Without the latch a
    /// compositor that rejects the import would be re-asked on every
    /// renegotiation.
    zero_copy: ZeroCopy,
    /// Why the session is not on dmabuf, in the compositor's own terms. `None`
    /// when it is, or when it was never asked for.
    zero_copy_note: Option<String>,
    /// Index of the buffer holding the most recent completed frame.
    front: usize,
    /// Index the in-flight capture is writing into.
    back: usize,
    have_frame: bool,
    /// Survives a re-allocation so a still screen cannot turn one into a fatal
    /// first-frame timeout. See [`Carry`].
    carry: Option<Carry>,
    /// Last timestamp handed out, so the next one can be forced past it.
    last_timestamp_ns: Option<u64>,
    /// `State::generation` the current buffers were sized for.
    alloc_generation: u64,
    restarts_left: u32,
    last_transform: u32,
    next_keepalive: Instant,

    config: CaptureConfig,
    format: FrameFormat,
    dmabuf: DmabufConstraints,
    stats: CaptureStats,
    label: String,
}

/// What [`Capture::advance`] resolved to: which buffer to hand out and how.
struct Emission {
    /// Index into the live buffer set, or `None` to emit the [`Carry`].
    index: Option<usize>,
    timestamp_ns: u64,
    kind: FrameKind,
    transform: u32,
}

impl Capture {
    /// Open a capture session and allocate its buffers. Returns once the
    /// compositor has sent the session's buffer constraints.
    pub fn open(config: CaptureConfig) -> Result<Self, CaptureError> {
        let (conn, mut queue, globals, mut state) = connect(config.cancel.as_deref())?;
        let qh = queue.handle();

        let shm: WlShm = bind_global(&globals, &qh, "wl_shm")?;
        let capture_mgr: ExtImageCopyCaptureManagerV1 =
            bind_global(&globals, &qh, "ext_image_copy_capture_manager_v1")?;

        let mut output_mgr = None;
        let mut window_mgr = None;
        let mut toplevel_list = None;

        let (target, label) = match &config.source {
            CaptureSource::Output(want) => {
                let mgr: ExtOutputImageCaptureSourceManagerV1 =
                    bind_global(&globals, &qh, "ext_output_image_capture_source_manager_v1")?;
                let (out, name, w, h, r) = state
                    .outputs
                    .iter()
                    .find(|o| o.1.as_deref() == Some(want.as_str()))
                    .ok_or_else(|| CaptureError::NoSuchOutput(want.clone()))?
                    .clone();
                output_mgr = Some(mgr);
                (
                    Target::Output(out),
                    format!(
                        "output {} {}x{}@{:.2}",
                        name.unwrap_or_default(),
                        w,
                        h,
                        r as f64 / 1000.0
                    ),
                )
            }
            CaptureSource::Window(want) => {
                toplevel_list = Some(bind_toplevels(
                    &conn,
                    &globals,
                    &qh,
                    &mut queue,
                    &mut state,
                    config.cancel.as_deref(),
                )?);
                let mgr: ExtForeignToplevelImageCaptureSourceManagerV1 = bind_global(
                    &globals,
                    &qh,
                    "ext_foreign_toplevel_image_capture_source_manager_v1",
                )?;
                let (handle, title, app_id, _) = state
                    .toplevels
                    .iter()
                    .find(|t| {
                        !t.3 && window_matches(
                            t.2.as_deref().unwrap_or(""),
                            t.1.as_deref().unwrap_or(""),
                            want,
                        )
                    })
                    .ok_or_else(|| CaptureError::NoSuchWindow(want.clone()))?
                    .clone();
                window_mgr = Some(mgr);
                // Remembered so the `closed` handler can destroy every OTHER
                // window's handle without touching the capture target's.
                state.target_toplevel = Some(handle.clone());
                (
                    Target::Window(handle),
                    format!(
                        "window {:?} {:?}",
                        app_id.unwrap_or_default(),
                        title.unwrap_or_default()
                    ),
                )
            }
        };

        // The source id, then the session id — in that order, each allocated
        // immediately before the request that creates it.
        let source = Self::create_source(&target, output_mgr.as_ref(), window_mgr.as_ref(), &qh)?;
        let options = if config.paint_cursors { Options::PaintCursors } else { Options::empty() };
        let session = capture_mgr.create_session(&source, options, &qh, ());

        let constraints =
            Self::await_constraints(&conn, &mut queue, &mut state, 0, config.cancel.as_deref())?;
        let state_generation = state.generation;

        // Bind the dmabuf factory before the first allocation, and only if
        // zero-copy was asked for: a compositor without it is a fallback, not
        // an error.
        let dmabuf_mgr = if config.zero_copy == ZeroCopy::Off {
            None
        } else {
            globals.bind::<ZwpLinuxDmabufV1, _, _>(&qh, 1..=4, ()).ok()
        };

        let zero_copy = config.zero_copy;
        let mut cap = Capture {
            conn,
            queue,
            qh,
            state,
            shm,
            capture_mgr,
            output_mgr,
            window_mgr,
            _toplevel_list: toplevel_list,
            target,
            source,
            session,
            inflight: None,
            buffers: Buffers::Shm(Vec::new()),
            gbm: None,
            dmabuf_mgr,
            zero_copy,
            zero_copy_note: None,
            front: 0,
            back: 0,
            have_frame: false,
            carry: None,
            last_timestamp_ns: None,
            alloc_generation: state_generation,
            restarts_left: MAX_SESSION_RESTARTS,
            last_transform: 0,
            next_keepalive: Instant::now() + config.keepalive,
            // Replaced by `allocate`, which is the only thing that decides a
            // format: the dmabuf and shm paths can pick different ones.
            format: FrameFormat { width: 0, height: 0, stride: 0, format: PixelFormat::Xrgb8888 },
            dmabuf: constraints.dmabuf.clone(),
            config,
            stats: CaptureStats::default(),
            label,
        };
        cap.allocate(&constraints)?;
        Ok(cap)
    }

    /// Which kind of buffer this session actually allocated. Read it; do not
    /// assume the request was honoured.
    pub fn buffer_mode(&self) -> BufferMode {
        self.buffers.mode()
    }

    /// Why the session is on shm despite being asked for dmabuf, if it is.
    pub fn zero_copy_note(&self) -> Option<&str> {
        self.zero_copy_note.as_deref()
    }

    /// How many capture targets are allocated: 2 on the shm ping-pong,
    /// [`DMABUF_BUFFERS`] on the zero-copy path.
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    /// Geometry and pixel format of the frames this session produces.
    pub fn format(&self) -> FrameFormat {
        self.format
    }

    /// What the compositor offered for dmabuf buffers. Unused on the shm path;
    /// this is the input to the zero-copy layer.
    pub fn dmabuf_constraints(&self) -> &DmabufConstraints {
        &self.dmabuf
    }

    /// Exact counters, for the bench command and the tests.
    pub fn stats(&self) -> CaptureStats {
        self.stats
    }

    /// Human-readable description of what is being captured.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The next frame: either a freshly copied one, or the previous one
    /// re-emitted with a new timestamp after [`CaptureConfig::keepalive`] of
    /// stillness. The returned borrow keeps the buffer stable; drop it before
    /// asking for the next frame.
    pub fn next_frame(&mut self) -> Result<CapturedFrame<'_>, CaptureError> {
        let e = self.advance()?;
        let format = self.format;
        let data = match e.index {
            Some(i) => match &self.buffers {
                Buffers::Shm(v) => FrameData::Shm(v[i].as_slice()),
                // Cloning the handle is what tells `submit` this buffer is
                // spoken for; it goes back into rotation when the consumer
                // drops it.
                Buffers::Dma(v) => FrameData::Dmabuf(v[i].image.clone()),
            },
            // The live set was just re-allocated and has produced nothing yet;
            // `settle_carry` has already checked this snapshot still matches
            // `self.format`.
            None => match &self
                .carry
                .as_ref()
                .ok_or_else(|| CaptureError::Protocol("carry-over frame vanished".into()))?
                .data
            {
                CarryData::Shm(v) => FrameData::Shm(&v[..]),
                CarryData::Dma(i) => FrameData::Dmabuf(i.clone()),
            },
        };
        Ok(CapturedFrame {
            timestamp_ns: e.timestamp_ns,
            width: format.width,
            height: format.height,
            stride: format.stride,
            format: format.format,
            kind: e.kind,
            transform: e.transform,
            data,
        })
    }
}

impl Capture {
    fn create_source(
        target: &Target,
        output_mgr: Option<&ExtOutputImageCaptureSourceManagerV1>,
        window_mgr: Option<&ExtForeignToplevelImageCaptureSourceManagerV1>,
        qh: &QueueHandle<State>,
    ) -> Result<ExtImageCaptureSourceV1, CaptureError> {
        match target {
            Target::Output(out) => {
                let mgr = output_mgr
                    .ok_or(CaptureError::MissingGlobal("ext_output_image_capture_source_manager_v1"))?;
                Ok(mgr.create_source(out, qh, ()))
            }
            Target::Window(handle) => {
                let mgr = window_mgr.ok_or(CaptureError::MissingGlobal(
                    "ext_foreign_toplevel_image_capture_source_manager_v1",
                ))?;
                Ok(mgr.create_source(handle, qh, ()))
            }
        }
    }

    /// Wait for a session `done` newer than `min_generation`. Returns
    /// immediately if one already arrived, which is what makes a
    /// re-negotiation safe regardless of whether the compositor sent the new
    /// constraints before or after the `failed` event.
    fn await_constraints(
        conn: &Connection,
        queue: &mut EventQueue<State>,
        state: &mut State,
        min_generation: u64,
        cancel: Option<&AtomicBool>,
    ) -> Result<Constraints, CaptureError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let got = pump(conn, queue, state, deadline, cancel, |s| {
            s.generation > min_generation || s.session_stopped
        })?;
        if state.session_stopped {
            return Err(CaptureError::Stopped);
        }
        if !got {
            return Err(CaptureError::Timeout("the session's buffer constraints"));
        }
        state
            .current
            .clone()
            .ok_or(CaptureError::Timeout("the session's buffer constraints"))
    }

    /// Allocate the capture targets for `c`, preferring dmabuf when the policy
    /// allows it and falling back to shm on any failure.
    ///
    /// This is the only place that decides a [`FrameFormat`], because the two
    /// paths can legitimately land on different strides: shm is always tightly
    /// packed, while gbm is free to pad a row.
    fn allocate(&mut self, c: &Constraints) -> Result<(), CaptureError> {
        let (width, height) = c
            .size
            .ok_or(CaptureError::Protocol("session sent no buffer_size".into()))?;

        // Free the previous set FIRST. The frame object that referenced it has
        // already been retired by every caller, and holding two sets of
        // 1920x1200 buffers doubles peak memory for no reason.
        self.buffers = Buffers::Shm(Vec::new());

        if self.zero_copy != ZeroCopy::Off {
            match self.allocate_dmabuf(width, height, c) {
                Ok((set, format)) => {
                    self.buffers = Buffers::Dma(set);
                    self.format = format;
                    self.zero_copy_note = None;
                    return Ok(());
                }
                Err(e) => {
                    if self.zero_copy == ZeroCopy::On {
                        return Err(e);
                    }
                    // Latched, so a renegotiation does not re-ask a compositor
                    // that has already said no.
                    self.zero_copy = ZeroCopy::Off;
                    self.zero_copy_note = Some(e.to_string());
                    self.stats.zero_copy_fallbacks += 1;
                }
            }
        }

        let format = shm_format_of(c)?;
        self.buffers = Buffers::Shm(vec![
            ShmBuffer::new(&self.shm, &self.qh, format)?,
            ShmBuffer::new(&self.shm, &self.qh, format)?,
        ]);
        self.format = format;
        Ok(())
    }

    /// The zero-copy allocation, every failure of which is recoverable.
    fn allocate_dmabuf(
        &mut self,
        width: u32,
        height: u32,
        c: &Constraints,
    ) -> Result<(Vec<DmabufBuffer>, FrameFormat), CaptureError> {
        let Some(mgr) = self.dmabuf_mgr.clone() else {
            return Err(CaptureError::Dmabuf(
                "compositor does not advertise zwp_linux_dmabuf_v1".into(),
            ));
        };
        let pixel = choose_dmabuf_format(&c.dmabuf.formats).ok_or_else(|| {
            let offered: Vec<String> = c
                .dmabuf
                .formats
                .iter()
                .map(|(f, _)| fourcc_name(*f))
                .collect();
            CaptureError::Dmabuf(format!(
                "session offered no XR24/AR24 with a LINEAR modifier (offered {offered:?})"
            ))
        })?;
        let dev = c.dmabuf.device.ok_or_else(|| {
            CaptureError::Dmabuf("session sent no dmabuf_device".into())
        })?;
        if self.gbm.is_none() {
            let path = render_node_path(dev).ok_or_else(|| {
                let (major, minor) = dev_major_minor(dev);
                CaptureError::Dmabuf(format!(
                    "no DRM node under /dev/dri with dev_t {dev} ({major}:{minor})"
                ))
            })?;
            self.gbm = Some(Gbm::open(&path)?);
        }

        // Disjoint field borrows: the gbm device, the wayland connection and
        // the event queue are all touched inside the loop.
        let cancel = self.config.cancel.clone();
        let Capture { gbm, conn, queue, state, qh, .. } = self;
        let gbm = gbm.as_ref().expect("just opened");

        let mut set: Vec<DmabufBuffer> = Vec::with_capacity(DMABUF_BUFFERS);
        for _ in 0..DMABUF_BUFFERS {
            let (bo, image) = gbm.allocate(width, height, pixel)?;
            // One FrameFormat describes the whole set, so gbm handing back a
            // different stride for an identical request would make every frame
            // after the first lie about its geometry. It does not happen here;
            // assert it rather than quietly using the last one.
            if let Some(first) = set.first() {
                if image.stride != first.image.stride {
                    return Err(CaptureError::Dmabuf(format!(
                        "gbm gave inconsistent strides for identical requests ({} then {})",
                        first.image.stride, image.stride
                    )));
                }
            }
            let buffer = dmabuf_wl_buffer(conn, queue, state, qh, &mgr, &image, cancel.as_deref())?;
            set.push(DmabufBuffer { buffer, image, _bo: bo });
        }
        let stride = set
            .first()
            .ok_or_else(|| CaptureError::Dmabuf("empty dmabuf set".into()))?
            .image
            .stride;
        Ok((set, FrameFormat { width, height, stride, format: pixel }))
    }

    /// Pick the buffer to capture into: never the front one (the consumer may
    /// be re-reading it as a keepalive), and on the zero-copy path never one a
    /// consumer still holds a handle to.
    ///
    /// The shm path has nothing to check — the pump copies out of the mapping
    /// before the next capture can start, so two buffers ping-pong safely.
    fn pick_back(&self) -> Option<usize> {
        match &self.buffers {
            Buffers::Shm(v) => (v.len() == 2).then_some(1 - self.front),
            Buffers::Dma(v) => v
                .iter()
                .enumerate()
                .find(|(i, b)| *i != self.front && Arc::strong_count(&b.image) == 1)
                .map(|(i, _)| i),
        }
    }

    /// Start one capture into a free buffer. One frame object per capture,
    /// created only after the previous one has been destroyed.
    ///
    /// Returns `false` when the zero-copy set is entirely spoken for. That is
    /// not an error: the caller waits out the keepalive and re-emits the front
    /// buffer, which is exactly what it would do on a still screen.
    fn submit(&mut self) -> Result<bool, CaptureError> {
        let Some(back) = self.pick_back() else {
            self.stats.buffer_starved += 1;
            return Ok(false);
        };
        self.back = back;
        self.state.frame = FrameState::default();
        let frame = self.session.create_frame(&self.qh, ());
        frame.attach_buffer(self.buffers.wl(back));
        frame.damage_buffer(0, 0, self.format.width as i32, self.format.height as i32);
        frame.capture();
        self.conn.flush().map_err(|e| CaptureError::Protocol(e.to_string()))?;
        self.inflight = Some(frame);
        Ok(true)
    }

    /// Apply [`enforce_monotonic`] and remember the result.
    fn stamp(&mut self, raw: u64) -> u64 {
        let (ts, fixed) = enforce_monotonic(self.last_timestamp_ns, raw);
        if fixed {
            self.stats.pts_fixups += 1;
        }
        self.last_timestamp_ns = Some(ts);
        ts
    }

    /// Destroy the in-flight frame object (required after ready or failed) and
    /// clear its accumulated state.
    fn retire_frame(&mut self) {
        if let Some(f) = self.inflight.take() {
            f.destroy();
        }
        self.state.frame = FrameState::default();
    }

    /// True when [`CaptureConfig::cancel`] has been raised.
    fn is_cancelled(&self) -> bool {
        cancelled(self.config.cancel.as_deref())
    }

    /// Snapshot the front buffer, just before a re-allocation frees it. See
    /// [`Carry`]. Call BEFORE `allocate`.
    fn stash_front(&mut self) {
        if !self.have_frame {
            return;
        }
        let data = match &self.buffers {
            Buffers::Shm(v) => v.get(self.front).map(|b| CarryData::Shm(b.as_slice().to_vec())),
            Buffers::Dma(v) => v.get(self.front).map(|b| CarryData::Dma(b.image.clone())),
        };
        if let Some(data) = data {
            self.carry = Some(Carry { format: self.format, data });
        }
    }

    /// Keep the snapshot only if the new buffer set agrees with it. A genuine
    /// geometry or buffer-mode change would make it a lie downstream — and a
    /// change that big has damaged the screen anyway, so a fresh frame is
    /// imminent and there is nothing to bridge. Call AFTER `allocate`.
    fn settle_carry(&mut self) {
        let keep = self
            .carry
            .as_ref()
            .is_some_and(|c| c.format == self.format && c.mode() == self.buffers.mode());
        if !keep {
            self.carry = None;
        }
        self.next_keepalive = Instant::now() + self.config.keepalive;
    }

    /// Re-allocate after a `buffer_constraints` failure: output mode/scale
    /// change, or (in window mode) any toplevel resize.
    fn renegotiate(&mut self) -> Result<(), CaptureError> {
        self.retire_frame();
        let cancel = self.config.cancel.clone();
        let c = Self::await_constraints(
            &self.conn,
            &mut self.queue,
            &mut self.state,
            self.alloc_generation,
            cancel.as_deref(),
        )?;
        // Record the generation these constraints came from BEFORE allocating.
        // Allocating a dmabuf set dispatches wayland events (the buffer-params
        // handshake), so the compositor can send a newer set while we are
        // inside it; stamping the generation afterwards would swallow that and
        // leave the session allocated for geometry that is already stale.
        self.alloc_generation = self.state.generation;
        // The frame object that referenced the old buffers is gone, so they can
        // be replaced. The new buffers hold nothing worth re-emitting, so keep
        // the outgoing front frame to bridge the gap.
        self.stash_front();
        self.allocate(&c)?;
        self.dmabuf = c.dmabuf.clone();
        self.front = 0;
        self.back = 0;
        self.have_frame = false;
        self.settle_carry();
        self.stats.reallocations += 1;
        Ok(())
    }

    /// Tear down and re-create the session after `stopped`. A closed window
    /// cannot come back, so that case is terminal.
    fn restart_session(&mut self) -> Result<(), CaptureError> {
        self.retire_frame();
        if let Target::Window(handle) = &self.target {
            // `target_closed` is the authority: the `closed` handler destroys
            // the handle and prunes its slot, so a missing slot alone no longer
            // distinguishes "gone" from "never seen".
            let closed = self.state.target_closed
                || self
                    .state
                    .toplevels
                    .iter()
                    .find(|t| &t.0 == handle)
                    .map(|t| t.3)
                    .unwrap_or(true);
            if closed {
                return Err(CaptureError::Stopped);
            }
        }
        if self.restarts_left == 0 {
            return Err(CaptureError::Stopped);
        }
        self.restarts_left -= 1;

        self.session.destroy();
        self.source.destroy();
        self.state.session_stopped = false;
        self.state.pending = Constraints::default();
        self.state.current = None;
        let before = self.state.generation;

        self.source = Self::create_source(
            &self.target,
            self.output_mgr.as_ref(),
            self.window_mgr.as_ref(),
            &self.qh,
        )?;
        let options =
            if self.config.paint_cursors { Options::PaintCursors } else { Options::empty() };
        self.session = self.capture_mgr.create_session(&self.source, options, &self.qh, ());

        let cancel = self.config.cancel.clone();
        let c = Self::await_constraints(
            &self.conn,
            &mut self.queue,
            &mut self.state,
            before,
            cancel.as_deref(),
        )?;
        self.alloc_generation = self.state.generation;
        self.stash_front();
        self.allocate(&c)?;
        self.dmabuf = c.dmabuf.clone();
        self.front = 0;
        self.back = 0;
        self.have_frame = false;
        self.settle_carry();
        self.stats.session_restarts += 1;
        Ok(())
    }

    /// Give up on dmabuf mid-stream and re-allocate as shm.
    ///
    /// This is the last line of the fallback story. The negotiation can succeed
    /// and the captures still fail — a compositor is allowed to accept the
    /// import and then refuse to blit into it — and a mirroring session that
    /// dies for that is worse than a slower one.
    fn fall_back_to_shm(&mut self, why: String) -> Result<(), CaptureError> {
        self.retire_frame();
        let c = self
            .state
            .current
            .clone()
            .ok_or(CaptureError::Timeout("the session's buffer constraints"))?;
        self.zero_copy = ZeroCopy::Off;
        self.zero_copy_note = Some(why);
        self.stats.zero_copy_fallbacks += 1;
        self.alloc_generation = self.state.generation;
        self.stash_front();
        self.allocate(&c)?;
        self.front = 0;
        self.back = 0;
        self.have_frame = false;
        self.settle_carry();
        Ok(())
    }

    /// The state machine behind [`Capture::next_frame`]. Split out so the
    /// returned borrow of a buffer does not have to survive the loop.
    fn advance(&mut self) -> Result<Emission, CaptureError> {
        let mut start = Instant::now();
        let mut consecutive_failures = 0u32;
        let mut reallocations = 0u32;
        loop {
            if self.is_cancelled() {
                return Err(CaptureError::Cancelled);
            }
            if self.state.session_stopped {
                self.restart_session()?;
                start = Instant::now();
                continue;
            }
            // Either the live set has a frame in it or the carry does; both
            // give the keepalive something to re-emit.
            let can_repeat = self.have_frame || self.carry.is_some();
            if self.inflight.is_none() && !self.submit()? {
                // Every zero-copy buffer is still held downstream. Fall through
                // to the keepalive wait; the consumer will release one.
                if !can_repeat {
                    return Err(CaptureError::Protocol(
                        "no free capture buffer before the first frame".into(),
                    ));
                }
            }

            // While there is nothing at all to re-emit, wait out the
            // first-frame timeout instead of the keepalive.
            let deadline = if can_repeat {
                self.next_keepalive
            } else {
                start + self.config.first_frame_timeout
            };
            let cancel = self.config.cancel.clone();
            let got = pump(
                &self.conn,
                &mut self.queue,
                &mut self.state,
                deadline,
                cancel.as_deref(),
                |s| s.frame.ready || s.frame.failed.is_some() || s.session_stopped,
            )?;

            if !got {
                if !can_repeat {
                    // Worth naming the usual cause: a compositor whose output
                    // is DPMS-off renders nothing at all, so the session comes
                    // up cleanly and then never completes a capture. It looks
                    // exactly like a broken client.
                    return Err(CaptureError::Timeout(
                        "the first captured frame (a blanked/DPMS-off output renders nothing,                          so the session comes up and no capture ever completes)",
                    ));
                }
                // Stillness. Leave the capture in flight — it completes when
                // the screen next changes — and re-emit the front buffer, or
                // the carry-over frame while a re-allocated set warms up.
                self.stats.repeats += 1;
                self.next_keepalive = Instant::now() + self.config.keepalive;
                let ts = self.stamp(monotonic_ns());
                return Ok(Emission {
                    index: self.have_frame.then_some(self.front),
                    timestamp_ns: ts,
                    kind: FrameKind::Repeat,
                    transform: self.last_transform,
                });
            }

            if self.state.frame.ready {
                let ts = self.stamp(self.state.frame.presentation_ns.unwrap_or_else(monotonic_ns));
                let transform = self.state.frame.transform;
                self.retire_frame();
                self.front = self.back;
                self.have_frame = true;
                // The live set can feed the keepalive again: release the
                // snapshot (and, on the zero-copy path, its retained fd).
                self.carry = None;
                self.last_transform = transform;
                self.restarts_left = MAX_SESSION_RESTARTS;
                self.stats.fresh += 1;
                self.next_keepalive = Instant::now() + self.config.keepalive;
                return Ok(Emission {
                    index: Some(self.front),
                    timestamp_ns: ts,
                    kind: FrameKind::Fresh,
                    transform,
                });
            }

            match self.state.frame.failed {
                Some(FailureReason::BufferConstraints) => {
                    // Bounded for the same reason the unknown-reason arm is: a
                    // compositor that answers every capture with
                    // `buffer_constraints` while still sending new `done`
                    // generations (a sustained drag-resize in window mode does
                    // exactly this) would otherwise spin here forever, tearing
                    // down and rebuilding the whole buffer set each time and
                    // never returning to the caller.
                    reallocations += 1;
                    if reallocations > MAX_REALLOCATIONS {
                        return Err(CaptureError::Protocol(format!(
                            "{MAX_REALLOCATIONS} buffer_constraints re-negotiations \
                             without a captured frame"
                        )));
                    }
                    self.renegotiate()?;
                    start = Instant::now();
                }
                Some(FailureReason::Stopped) => {
                    self.restart_session()?;
                    start = Instant::now();
                }
                Some(reason) => {
                    // Unknown failure: retire and retry with a fresh frame.
                    // Bounded, so a compositor that fails every capture
                    // instantly reports an error instead of spinning a core.
                    self.stats.failures += 1;
                    consecutive_failures += 1;
                    if self.buffers.mode() == BufferMode::Dmabuf
                        && self.config.zero_copy == ZeroCopy::Auto
                        && consecutive_failures >= DMABUF_FAILURE_FALLBACK
                    {
                        self.fall_back_to_shm(format!(
                            "{consecutive_failures} consecutive dmabuf capture failures \
                             ({reason:?}); re-allocated as shm"
                        ))?;
                        consecutive_failures = 0;
                        start = Instant::now();
                        continue;
                    }
                    if consecutive_failures > MAX_CONSECUTIVE_FAILURES {
                        return Err(CaptureError::Protocol(format!(
                            "{MAX_CONSECUTIVE_FAILURES} consecutive capture failures"
                        )));
                    }
                    self.retire_frame();
                }
                None => {
                    // The predicate fired on session_stopped.
                    self.restart_session()?;
                    start = Instant::now();
                }
            }
        }
    }
}

/// How many times a `stopped` session is re-created before giving up. Reset on
/// every successfully captured frame, so this only bites when restarts fail to
/// produce anything.
const MAX_SESSION_RESTARTS: u32 = 3;

/// How many unexplained frame failures one `next_frame` call tolerates before
/// giving up (the counter is per call, so a success resets it by returning), so a compositor that fails instantly cannot spin a
/// core forever.
const MAX_CONSECUTIVE_FAILURES: u32 = 60;

/// How many `buffer_constraints` re-negotiations one `next_frame` call
/// tolerates before giving up. Per call, like [`MAX_CONSECUTIVE_FAILURES`], so
/// any captured frame resets it by returning.
const MAX_REALLOCATIONS: u32 = 8;

/// How many unexplained failures on the zero-copy path before giving up on it
/// and re-allocating shm. Deliberately small: if the compositor cannot blit
/// into these buffers it will not start, and 3 wasted captures is ~50 ms.
const DMABUF_FAILURE_FALLBACK: u32 = 3;

impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(f) = self.inflight.take() {
            f.destroy();
        }
        self.session.destroy();
        self.source.destroy();
        let _ = self.conn.flush();
    }
}

// ====================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_spec_parsing() {
        assert_eq!(
            CaptureSource::parse("output:eDP-1").unwrap(),
            CaptureSource::Output("eDP-1".into())
        );
        assert_eq!(
            CaptureSource::parse("window:foot").unwrap(),
            CaptureSource::Window("foot".into())
        );
        // A bare name is an output, so `--source eDP-1` works.
        assert_eq!(
            CaptureSource::parse("eDP-1").unwrap(),
            CaptureSource::Output("eDP-1".into())
        );
        // A window title may itself contain a colon once the kind is given.
        assert_eq!(
            CaptureSource::parse("window:Omarchy: AirPlay").unwrap(),
            CaptureSource::Window("Omarchy: AirPlay".into())
        );
        assert!(matches!(
            CaptureSource::parse("monitor:eDP-1"),
            Err(CaptureError::BadSource(_))
        ));
        assert!(matches!(CaptureSource::parse(""), Err(CaptureError::BadSource(_))));
        assert!(matches!(CaptureSource::parse("output:"), Err(CaptureError::BadSource(_))));
        assert_eq!(CaptureSource::Output("eDP-1".into()).to_string(), "output:eDP-1");
        assert_eq!(CaptureSource::Window("foot".into()).to_string(), "window:foot");
    }

    #[test]
    fn shm_format_choice_prefers_xrgb() {
        // Hyprland 0.56.2 offers exactly [ARGB8888, XRGB8888] on this machine.
        assert_eq!(choose_pixel_format(&[0, 1]).unwrap(), PixelFormat::Xrgb8888);
        assert_eq!(choose_pixel_format(&[1, 0]).unwrap(), PixelFormat::Xrgb8888);
        assert_eq!(choose_pixel_format(&[0]).unwrap(), PixelFormat::Argb8888);
        match choose_pixel_format(&[0x3231_564e]) {
            Err(CaptureError::NoShmFormat(offered)) => assert_eq!(offered, vec![0x3231_564e]),
            other => panic!("expected NoShmFormat, got {other:?}"),
        }
    }

    #[test]
    fn pixel_format_constants_match_drm_and_libav() {
        // The bytes in memory are B,G,R,X — proven by dumping a frame to PPM.
        assert_eq!(&PixelFormat::Xrgb8888.drm_fourcc().to_le_bytes(), b"XR24");
        assert_eq!(&PixelFormat::Argb8888.drm_fourcc().to_le_bytes(), b"AR24");
        assert_eq!(PixelFormat::Xrgb8888.ffmpeg_name(), "bgr0");
        assert_eq!(PixelFormat::Argb8888.ffmpeg_name(), "bgra");
        assert_eq!(PixelFormat::Xrgb8888.wl_shm_code(), 1);
        assert_eq!(PixelFormat::Argb8888.wl_shm_code(), 0);
        assert_eq!(fourcc_name(0x3432_5258), "XR24 (0x34325258)");
        assert_eq!(shm_format_name(1), "XRGB8888 (shm 1)");
        assert_eq!(shm_format_name(0), "ARGB8888 (shm 0)");
        assert_eq!(shm_format_name(0x3231_564e), "NV12 (0x3231564e)");
    }

    #[test]
    fn buffer_geometry_matches_the_measured_session() {
        // eDP-1 is 1920x1200 physical (scale 1.5 does not shrink buffer_size),
        // and the spike allocated stride 7680 / 9,216,000 bytes.
        let (stride, len) = plane_geometry(1920, 1200, PixelFormat::Xrgb8888);
        assert_eq!(stride, 7680);
        assert_eq!(len, 9_216_000);
        let f = FrameFormat { width: 1920, height: 1200, stride, format: PixelFormat::Xrgb8888 };
        assert_eq!(f.len(), 9_216_000);
        assert!(!f.is_empty());
        // The window-capture case measured on a foot toplevel.
        assert_eq!(plane_geometry(1884, 1125, PixelFormat::Xrgb8888), (7536, 8_478_000));
    }

    #[test]
    fn presentation_time_reassembles_exactly() {
        // The first presentation_time the spike logged on this machine.
        assert_eq!(presentation_ns(0, 25_404, 669_195_733), 25_404_669_195_733);
        // The high word must actually be used: 2^32 seconds.
        assert_eq!(presentation_ns(1, 0, 0), 4_294_967_296_000_000_000);
        assert_eq!(presentation_ns(0, 0, 999_999_999), 999_999_999);
    }

    #[test]
    fn dmabuf_device_decodes_to_the_render_node() {
        // dev_t 57984 == 226:128 == /dev/dri/renderD128, which is the same
        // render node the VA-API encoder opens.
        let le = 57_984u64.to_ne_bytes();
        assert_eq!(dev_t_from_bytes(&le), Some(57_984));
        assert_eq!(dev_major_minor(57_984), (226, 128));
        // Short arrays are zero-extended; an empty one is "not sent".
        assert_eq!(dev_t_from_bytes(&[0x80, 0xe2]), Some(57_984));
        assert_eq!(dev_t_from_bytes(&[]), None);
    }

    #[test]
    fn window_matching_is_case_insensitive_over_both_fields() {
        assert!(window_matches("foot", "\u{25d1} Omarchy Airplay", "foot"));
        assert!(window_matches("foot", "\u{25d1} Omarchy Airplay", "FOOT"));
        assert!(window_matches("foot", "\u{25d1} Omarchy Airplay", "omarchy"));
        assert!(window_matches("brave-origin", "", "brave"));
        assert!(!window_matches("foot", "\u{25d1} Omarchy Airplay", "chrome"));
        // An empty needle matching everything is a footgun; the source parser
        // rejects `window:` before it can get here.
        assert!(window_matches("foot", "", ""));
    }

    #[test]
    fn dmabuf_format_choice_takes_linear_and_prefers_xrgb() {
        // Exactly what the session advertises on this machine: both formats,
        // each with LINEAR plus four Intel tiled/compressed modifiers.
        let intel = |extra: &[u64]| {
            let mut v = vec![
                0x0100_0000_0000_0001,
                0x0100_0000_0000_0009,
                0x0100_0000_0000_000d,
                0x0100_0000_0000_000f,
                0x00ff_ffff_ffff_ffff,
            ];
            v.extend_from_slice(extra);
            v
        };
        let both = vec![
            (PixelFormat::Argb8888.drm_fourcc(), intel(&[DRM_FORMAT_MOD_LINEAR])),
            (PixelFormat::Xrgb8888.drm_fourcc(), intel(&[DRM_FORMAT_MOD_LINEAR])),
        ];
        assert_eq!(choose_dmabuf_format(&both), Some(PixelFormat::Xrgb8888));

        // ARGB only -> ARGB.
        assert_eq!(
            choose_dmabuf_format(&both[..1]),
            Some(PixelFormat::Argb8888)
        );

        // The trap that broke gpu-screen-recorder: every modifier on offer is a
        // tiled/compressed one. There is nothing safe to pick, so pick nothing
        // and let the caller fall back to shm.
        let tiled_only = vec![
            (PixelFormat::Xrgb8888.drm_fourcc(), intel(&[])),
            (PixelFormat::Argb8888.drm_fourcc(), intel(&[])),
        ];
        assert_eq!(choose_dmabuf_format(&tiled_only), None);

        // A format we cannot describe as one RGB plane, even with LINEAR.
        let nv12 = vec![(0x3231_564e, vec![DRM_FORMAT_MOD_LINEAR])];
        assert_eq!(choose_dmabuf_format(&nv12), None);
        assert_eq!(choose_dmabuf_format(&[]), None);
    }

    #[test]
    fn zero_copy_flag_parses_every_spelling_the_cli_accepts() {
        assert_eq!(ZeroCopy::parse("auto"), Some(ZeroCopy::Auto));
        assert_eq!(ZeroCopy::parse(" ON "), Some(ZeroCopy::On));
        assert_eq!(ZeroCopy::parse("dmabuf"), Some(ZeroCopy::On));
        assert_eq!(ZeroCopy::parse("off"), Some(ZeroCopy::Off));
        assert_eq!(ZeroCopy::parse("shm"), Some(ZeroCopy::Off));
        assert_eq!(ZeroCopy::parse("maybe"), None);
        // The default is Auto, not On: a failed negotiation must degrade.
        assert_eq!(ZeroCopy::default(), ZeroCopy::Auto);
        assert_eq!(CaptureConfig::new(CaptureSource::Output("x".into())).zero_copy, ZeroCopy::Auto);
        assert_eq!(ZeroCopy::Auto.to_string(), "auto");
        assert_eq!(BufferMode::Dmabuf.to_string(), "dmabuf");
        assert_eq!(BufferMode::Shm.to_string(), "shm");
    }

    #[test]
    fn modifier_names_cover_what_this_compositor_advertises() {
        // Exactly the set the session advertised for AR24/XR24 here.
        assert_eq!(modifier_name(0), "LINEAR");
        assert_eq!(modifier_name(0x0100_0000_0000_0001), "I915_FORMAT_MOD_X_TILED");
        assert_eq!(modifier_name(0x0100_0000_0000_0009), "I915_FORMAT_MOD_4_TILED");
        assert_eq!(modifier_name(0x0100_0000_0000_000d), "I915_FORMAT_MOD_4_TILED_MTL_RC_CCS");
        assert_eq!(modifier_name(0x0100_0000_0000_000f), "I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC");
        assert_eq!(modifier_name(0x00ff_ffff_ffff_ffff), "DRM_FORMAT_MOD_INVALID");
        assert_eq!(modifier_name(0xdead_beef), "?");
    }

    #[test]
    fn shm_format_of_needs_both_a_size_and_a_usable_format() {
        let mut c = Constraints { size: Some((1920, 1200)), shm_formats: vec![0, 1], ..Default::default() };
        let f = shm_format_of(&c).unwrap();
        assert_eq!(
            f,
            FrameFormat { width: 1920, height: 1200, stride: 7680, format: PixelFormat::Xrgb8888 }
        );
        c.size = None;
        assert!(matches!(shm_format_of(&c), Err(CaptureError::Protocol(_))));
        c.size = Some((1920, 1200));
        c.shm_formats.clear();
        assert!(matches!(shm_format_of(&c), Err(CaptureError::NoShmFormat(_))));
    }

    #[test]
    fn monotonic_clock_advances_and_is_in_the_same_domain_as_presentation_time() {
        let a = monotonic_ns();
        let b = monotonic_ns();
        assert!(b >= a, "CLOCK_MONOTONIC went backwards: {a} -> {b}");
        // Sanity: uptime, not the unix epoch. Anything past ~317 years of
        // uptime means we read the wrong clock.
        assert!(a < 10_000_000_000_000_000_000);
    }

    #[test]
    fn timestamps_are_forced_strictly_increasing() {
        assert_eq!(enforce_monotonic(None, 27_029_986_476_735), (27_029_986_476_735, false));
        assert_eq!(enforce_monotonic(Some(100), 101), (101, false));
        // A keepalive stamped "now" followed by a fresh frame whose
        // presentation_time is 5 ms in the past: the real inversion seen here.
        assert_eq!(enforce_monotonic(Some(100_000_000), 95_000_000), (100_000_001, true));
        // Equal is not increasing.
        assert_eq!(enforce_monotonic(Some(100), 100), (101, true));
    }

    #[test]
    fn a_capture_can_move_to_the_streaming_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<Capture>();
        assert_send::<CaptureConfig>();
        assert_send::<CaptureStats>();
    }

    #[test]
    fn default_config_matches_the_probes_measured_keepalive() {
        let c = CaptureConfig::new(CaptureSource::Output("eDP-1".into()));
        assert_eq!(c.keepalive, Duration::from_millis(250));
        assert_eq!(c.first_frame_timeout, Duration::from_secs(5));
        assert!(c.paint_cursors);
    }
}
