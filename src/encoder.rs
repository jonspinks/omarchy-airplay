//! H.264 encoding for the live-screen mirror path.
//!
//! Two back-ends behind one API:
//!
//! * [`EncoderKind::Gpu`] — `h264_vaapi` on a DRM render node, fed through a
//!   `scale_vaapi` GPU VPP stage that does BGR0/BGRA -> NV12 **and** the
//!   fit-to-receiver downscale in one pass. This is the shipping path.
//! * [`EncoderKind::Cpu`] — `libx264`, fed through `swscale`. The fallback, and
//!   the deliberate multi-slice control: `-tune zerolatency` turns on sliced
//!   threads, so one picture arrives as many slice NALs. That is milestone-1
//!   bug #1 in a bottle, and the access-unit tests use it on purpose.
//!
//! Both accept the capture layer's BGR0/BGRA buffers directly — no CPU colour
//! conversion on the GPU path — and emit Annex-B access units, **one per
//! picture**, with in-band SPS/PPS.
//!
//! ## Two ways in, one way through
//!
//! The GPU back-end has two input stages and they converge immediately:
//!
//! * [`Encoder::encode`] takes the shm mapping and uploads it with
//!   `av_hwframe_transfer_data` (measured ~5 ms for 1920x1200 BGRX — about 40%
//!   of the whole per-frame cost).
//! * [`Encoder::encode_dmabuf`] takes a [`DmabufImage`] the compositor blitted
//!   into and maps it with `av_hwframe_map(DIRECT)` (measured 0.031 ms, and
//!   once per buffer rather than once per frame, because the mapping is
//!   cached).
//!
//! From the VA-API surface onwards the filter graph and the encoder are
//! byte-identical, which is the point: switching input stages cannot change the
//! bitstream.
//!
//! ## Configuration, and why
//!
//! Every knob below was measured on this hardware (Arrow Lake-U, iHD 26.2.4,
//! VA-API 1.24) before it was written down:
//!
//! * `rc_mode=CQP` — CBR/VBR spend the configured bitrate on a still desktop
//!   (6.13 and 1.98 Mb/s measured against CQP's 0.83 Mb/s for the same picture).
//! * `async_depth=1` — the encoder holds zero frames, so the first packet comes
//!   back from the frame that was just submitted. This is the whole of the
//!   probe's 81 ms -> 48 ms win.
//! * `sei=0` — no SEI, no HRD, no `pic_struct`; the timing model invites the
//!   receiver to buffer.
//! * `profile=high`, `level=4.2` — the Frame's decoder is `avc1.64002a`.
//! * **BT.709 limited, converted AND declared.** Both conversion stages are
//!   configured for it (`scale_vaapi out_color_matrix=bt709:out_range=tv`;
//!   `sws_setColorspaceDetails(SWS_CS_ITU709)`) and the codec context carries
//!   the four colour fields, so the VUI says what the pixels are. Left
//!   untagged, `matrix_coefficients` reads "unspecified" and every receiver
//!   resolves that at HD frame size to BT.709 — which is how BT.601 pixels
//!   reach the TV with shifted, desaturated greens and reds while greys stay
//!   right. Measured, not reasoned: decoded output fits the BT.709 limited
//!   matrix to within 0.2 of prediction on all three input paths.
//! * **No rate ceiling, deliberately, and it is measured rather than assumed.**
//!   `rc_mode=CQP` has none: `encode-bench --frames 300` on the synthetic moving
//!   pattern reports 23.41 Mb/s mean with a 154517 B picture — a 74.2 Mb/s
//!   instantaneous burst against the 62.5 Mb/s this stream's own level 4.2
//!   declares ([`LEVEL42_MAX_MBPS`]). The bench prints that peak and says so.
//!   Both ways of capping it were tried on this machine and both change more
//!   than the ceiling: `h264_vaapi` rejects `max_frame_size` outright in CQP
//!   mode ("Max frame size is invalid in CQP rate control mode", avcodec_open2
//!   -22), and QVBR — the only mode that accepts it — targets its bitrate
//!   rather than merely capping at it. Same source, same qp 25, 300 frames of
//!   testsrc2 at 1728x1080: CQP 13.24 Mb/s / 51424 B peak; QVBR b=20M 19.76
//!   Mb/s / 80308 B; QVBR b=40M 23.60 Mb/s / 43.4 Mb/s peak. Capping the peak
//!   that way costs 50% more average bitrate, which is the opposite of what
//!   milestone 1 needed from the link. A real ceiling therefore means picking a
//!   QVBR target BELOW CQP's natural rate (b=8M measured 8.31 Mb/s, 18.5 Mb/s
//!   peak) — a quality decision that has to be made in front of the TV, not
//!   here.
//! * `gop = fps * 5` plus a wall-clock IDR forcer; 1 s keyframes visibly stutter.
//! * `max_b_frames=0` and `AV_CODEC_FLAG_GLOBAL_HEADER` explicitly cleared, so
//!   SPS/PPS are repeated in-band ahead of every IDR (the receiver has no
//!   out-of-band channel for them, and `extradata_size` must stay 0).
//! * **`low_power` is never passed.** intel-media-driver 26.2.4 on this device
//!   advertises no `VAEntrypointEncSliceLP` for any profile, and `avcodec_open2`
//!   hard-fails with ENOSYS rather than degrading. [`probe_low_power`] answers
//!   the question on a new machine instead of assuming either way.
//!
//! ## Unsafe
//!
//! ffmpeg-next has no safe API for hardware device/frames contexts, `sw_pix_fmt`,
//! `hw_frames_ctx`, buffersrc/buffersink or swscale. All of that is raw
//! `ffmpeg_next::ffi` and it is contained in this file: the raw pointers are
//! private to the [`BufRef`], [`AvFrame`], [`Graph`] and [`SwsContext`]
//! newtypes, each owning exactly one allocation with a `Drop`.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_int, c_uint, c_void};
use std::ptr;

use ffmpeg_next as ff;
use ff::ffi as sys;

use crate::capture::{DmabufImage, PixelFormat};

// =============================================================== fit-to-receiver

/// H.264 level 4.2 allows 8192 macroblocks per frame. 1920x1080 is 8160 (fits);
/// the laptop panel's native 1920x1200 is 9000, which forces level 5.0 — the
/// Frame accepts that and renders black.
pub const MAX_MACROBLOCKS: u32 = 8192;

/// What level 4.2 promises about the RATE, as the macroblock budget promises
/// about the SIZE. High profile scales the level's MaxBR by 1.25, so 50 Mb/s
/// becomes 62.5 — and the SPS this encoder emits advertises exactly that level,
/// so a stream that exceeds it is non-conformant to its own declaration. There
/// is no HRD in the bitstream (`sei=0`, deliberately) for a receiver to police
/// it with, which is the reason to police it here.
pub const LEVEL42_MAX_MBPS: f64 = 62.5;

/// The biggest a single coded picture may be at `fps` before the stream's
/// instantaneous rate goes over [`LEVEL42_MAX_MBPS`]. One picture arrives at the
/// receiver as one burst, so this — not the mean — is the number a link and a
/// decoder feel.
pub fn max_au_bytes(fps: u32) -> usize {
    (LEVEL42_MAX_MBPS * 1e6 / 8.0 / f64::from(fps.max(1))) as usize
}

/// Macroblock count for a coded size.
pub const fn macroblocks(width: u32, height: u32) -> u32 {
    width.div_ceil(16) * height.div_ceil(16)
}

/// Fit a **capture buffer** into a **receiver display**, preserving the source
/// aspect ratio, forcing even dimensions (NV12 needs both even) and staying
/// inside the level-4.2 macroblock budget.
///
/// This is deliberately not [`crate::testpattern::fit_resolution`], which fits
/// the receiver into a fixed 1920x1080 box. Milestone-1 bug #2 was using the
/// probe's 1728x1080 *output* as the fit *box*, which scaled a 1080p receiver
/// down to 1728x972 for no reason. The box is the receiver; the thing being
/// fitted is the source.
///
/// A source that already fits is used verbatim: `((1920,1080),(1920,1080))`
/// returns `(1920,1080)`, never something smaller.
pub fn fit_source_to_receiver(source: (u32, u32), receiver: (u32, u32)) -> (u32, u32) {
    let (sw, sh) = source;
    if sw == 0 || sh == 0 {
        return (0, 0);
    }
    // Receiver dimensions of 0 mean "unknown"; fall back to the level budget
    // alone rather than collapsing to nothing.
    let rw = if receiver.0 == 0 { sw } else { receiver.0 };
    let rh = if receiver.1 == 0 { sh } else { receiver.1 };

    let even_down = |v: f64| -> u32 {
        let n = v.round().max(2.0) as u32;
        if n % 2 == 1 {
            n - 1
        } else {
            n
        }
    };

    // Step 1: never upscale, and never exceed the receiver's box.
    let scale = f64::min(1.0, f64::min(rw as f64 / sw as f64, rh as f64 / sh as f64));
    let mut w = even_down(sw as f64 * scale);
    let mut h = even_down(sh as f64 * scale);

    // Step 2: shrink on the source aspect until the macroblock budget is met.
    // Stepping the width by 2 keeps both dimensions even and terminates.
    while macroblocks(w, h) > MAX_MACROBLOCKS && w > 2 {
        w -= 2;
        h = even_down(w as f64 * sh as f64 / sw as f64);
    }
    (w.max(2), h.max(2))
}

// =============================================================== public types

#[derive(Debug, thiserror::Error)]
pub enum EncoderError {
    #[error("libav: {what} failed: {code} ({msg})")]
    Av {
        what: &'static str,
        code: i32,
        msg: String,
    },
    #[error("encoder {0:?} is not available in this libavcodec build")]
    NoCodec(&'static str),
    #[error("{0}")]
    Setup(String),
    #[error("frame is {got} bytes but the format needs {want} (stride {stride}, height {height})")]
    ShortFrame {
        got: usize,
        want: usize,
        stride: u32,
        height: u32,
    },
    #[error("encoder configured for {want:?} but was handed a {got:?} frame")]
    FormatChanged { want: (u32, u32), got: (u32, u32) },
}

fn av(what: &'static str, code: i32) -> EncoderError {
    let mut buf = [0i8; 256];
    let msg = unsafe {
        sys::av_strerror(code, buf.as_mut_ptr(), buf.len());
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    };
    EncoderError::Av { what, code, msg }
}

fn check(what: &'static str, code: i32) -> Result<i32, EncoderError> {
    if code < 0 {
        Err(av(what, code))
    } else {
        Ok(code)
    }
}

/// Which back-end to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderKind {
    /// `h264_vaapi` + `scale_vaapi`.
    Gpu,
    /// `libx264` + `swscale`.
    Cpu,
}

impl EncoderKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "gpu" | "vaapi" | "hw" | "h264_vaapi" => Some(EncoderKind::Gpu),
            "cpu" | "x264" | "libx264" | "sw" => Some(EncoderKind::Cpu),
            _ => None,
        }
    }
    pub const fn codec_name(self) -> &'static str {
        match self {
            EncoderKind::Gpu => "h264_vaapi",
            EncoderKind::Cpu => "libx264",
        }
    }
}

impl std::fmt::Display for EncoderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EncoderKind::Gpu => "gpu",
            EncoderKind::Cpu => "cpu",
        })
    }
}

/// How to open an encoder.
#[derive(Debug, Clone)]
pub struct EncoderConfig {
    pub kind: EncoderKind,
    /// Capture buffer size, i.e. what [`encode`](Encoder::encode) is handed.
    pub source: (u32, u32),
    /// Coded size. Use [`fit_source_to_receiver`]; do not hardcode a number.
    pub target: (u32, u32),
    /// Byte order of the source buffer (`bgr0` / `bgra`).
    pub source_format: PixelFormat,
    /// Nominal frame rate. Only sets the declared rate and the GOP backstop —
    /// the pipeline is driven by whatever the capture layer yields, which on a
    /// still screen is 4 keepalives per second, not 60 frames.
    pub fps: u32,
    /// Constant quantiser. 25 measured 0.83 Mb/s on an idle desktop and
    /// 37.9 Mb/s on a deliberately high-entropy synthetic pattern.
    pub qp: u32,
    /// Wall-clock IDR interval. 5 s; 1 s keyframe spikes stutter over Wi-Fi.
    pub keyframe_seconds: f64,
    /// DRM render node for the GPU path.
    pub device: String,
    /// GPU path only: ask the driver for a low-power entrypoint before opening,
    /// purely to report whether one exists. Never used to configure the encoder.
    pub probe_low_power: bool,
    /// CPU path only: force exactly this many slices per picture via x264
    /// sliced threads. `None` lets x264 choose (which is what produced the
    /// 14-slices-per-frame stream that broke milestone 1).
    pub cpu_slices: Option<u32>,
    /// GPU path only: build the zero-copy input stage instead of the upload
    /// one. The encoder then accepts [`Encoder::encode_dmabuf`] and refuses
    /// [`Encoder::encode`], and vice versa — a mismatch is an error rather
    /// than a silent slow path, because silently slow is exactly what nobody
    /// would notice.
    pub dmabuf_input: bool,
}

impl EncoderConfig {
    pub fn new(source: (u32, u32), target: (u32, u32)) -> Self {
        EncoderConfig {
            kind: EncoderKind::Gpu,
            source,
            target,
            source_format: PixelFormat::Xrgb8888,
            fps: 60,
            qp: 25,
            keyframe_seconds: 5.0,
            device: "/dev/dri/renderD128".to_string(),
            probe_low_power: false,
            cpu_slices: None,
            dmabuf_input: false,
        }
    }
}

/// One coded picture, Annex-B, start codes intact, ready for
/// [`crate::video::MirrorStreamer::forward_access_unit`].
#[derive(Debug, Clone)]
pub struct AccessUnit {
    pub data: Vec<u8>,
    /// Capture timestamp this picture came from (CLOCK_MONOTONIC ns).
    pub timestamp_ns: u64,
    /// Encoder timebase PTS, microseconds since the first frame.
    pub pts_us: i64,
    pub is_idr: bool,
    /// How many VCL NALs this picture is made of. `1` for `h264_vaapi`; x264
    /// with sliced threads emits many, and they all belong to THIS one unit.
    pub slices: u32,
    pub has_sps: bool,
    pub has_pps: bool,
}

/// Exact counters. No thresholds: the milestone-1 lesson is that a lower bound
/// hid a 14x over-split.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncoderStats {
    pub frames_in: u64,
    pub packets_out: u64,
    /// Pictures found by re-scanning the emitted bitstream. Must equal
    /// `packets_out`; anything else means a packet held 0 or 2+ pictures.
    pub pictures_out: u64,
    pub vcl_nals_out: u64,
    pub idr_out: u64,
    pub sps_out: u64,
    pub pps_out: u64,
    /// Type-6 NALs seen. `sei=0` means this must stay 0.
    pub sei_out: u64,
    /// Type-9 NALs seen. `aud=0` means this must stay 0. Counted here rather
    /// than only by re-scanning a retained stream, so a bench that throws the
    /// access units away still reports a real number instead of a zero that
    /// merely means "not measured".
    pub aud_out: u64,
    pub bytes_out: u64,
    pub forced_idr: u64,
    /// Per-stage wall time, summed over every call. The GPU path's three stages
    /// are getting the pixels into a VA-API surface (an upload on the shm path,
    /// a cached `av_hwframe_map` on the zero-copy one — the same stage either
    /// way, which is what makes the two directly comparable), the GPU VPP
    /// convert+scale, and the encode itself; the CPU path only has convert and
    /// encode. Kept as sums so a caller can divide by `frames_in` and get a
    /// mean without the encoder owning a histogram.
    pub upload_us: u64,
    pub convert_us: u64,
    pub encode_us: u64,
}

/// What actually opened, read back from the codec context rather than assumed.
#[derive(Debug, Clone)]
pub struct EncoderInfo {
    pub kind: EncoderKind,
    pub codec: String,
    pub source: (u32, u32),
    pub target: (u32, u32),
    pub macroblocks: u32,
    /// `av_opt_get` readback of the options that were requested, so a silently
    /// dropped option is visible instead of assumed.
    pub options: Vec<(String, String)>,
    /// `extradata_size` after open. Must be 0: parameter sets in-band only.
    pub extradata_len: usize,
    /// `Some(false)` means the driver was asked for a low-power entrypoint and
    /// refused. `None` means it was never asked.
    pub low_power_available: Option<bool>,
    /// True when the input stage is `av_hwframe_map` rather than an upload.
    pub dmabuf_input: bool,
}

// =============================================================== bitstream scan

/// What one Annex-B buffer contains. The picture rule is the same one
/// [`crate::testpattern::split_access_units`] uses: a VCL NAL whose
/// `first_mb_in_slice == 0` starts a picture, and `first_mb_in_slice` is the
/// first Exp-Golomb value of the slice header, so a leading 1 bit (0x80) means
/// zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuScan {
    pub pictures: u32,
    pub vcl_nals: u32,
    pub idr_slices: u32,
    pub sps: u32,
    pub pps: u32,
    pub sei: u32,
    pub aud: u32,
}

pub fn scan_annexb(data: &[u8]) -> AuScan {
    let mut s = AuScan::default();
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if !(data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1) {
            i += 1;
            continue;
        }
        let hdr = i + 3;
        if hdr >= data.len() {
            break;
        }
        let nal_type = data[hdr] & 0x1F;
        match nal_type {
            1 | 5 => {
                s.vcl_nals += 1;
                if nal_type == 5 {
                    s.idr_slices += 1;
                }
                if hdr + 1 < data.len() && (data[hdr + 1] & 0x80) != 0 {
                    s.pictures += 1;
                }
            }
            6 => s.sei += 1,
            7 => s.sps += 1,
            8 => s.pps += 1,
            9 => s.aud += 1,
            _ => {}
        }
        i = hdr;
    }
    s
}

/// Zero the `constraint_set` flags byte of every SPS in an Annex-B buffer,
/// returning how many were edited.
///
/// `h264_vaapi` writes `67 64 0c 2a`: profile_idc 100 (High), constraint bits
/// `0x0c` = constraint_set4|5, level_idc 42. That is codec string
/// `avc1.640c2a`, while the Frame advertises `avc1.64002a`. Those two flags mean
/// "frame_mbs_only" and "no B slices" — STRICTER than plain High@4.2, so a
/// conforming decoder must accept the stream. Milestone 1's whole lesson,
/// though, is that this TV accepts things and then renders black, so this is the
/// pre-built escape hatch: byte 2 of the SPS NAL sits between profile_idc and
/// level_idc, it is a whole byte, and zeroing it shifts no subsequent bit
/// offset — the SPS stays exactly as long and every later field parses
/// identically.
///
/// Nothing calls this unless `--sps-zero-constraints` is passed.
pub fn zero_sps_constraints(data: &mut [u8]) -> u32 {
    let mut edited = 0;
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if !(data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1) {
            i += 1;
            continue;
        }
        let hdr = i + 3;
        if hdr < data.len() && data[hdr] & 0x1F == 7 && hdr + 2 < data.len() && data[hdr + 2] != 0 {
            data[hdr + 2] = 0;
            edited += 1;
        }
        i = hdr;
    }
    edited
}

// =============================================================== raw wrappers

/// An owned `AVBufferRef` (hardware device or frames context).
struct BufRef(*mut sys::AVBufferRef);

impl BufRef {
    fn as_ptr(&self) -> *mut sys::AVBufferRef {
        self.0
    }
    /// A new reference, for handing to libav structures that take ownership.
    fn new_ref(&self) -> *mut sys::AVBufferRef {
        unsafe { sys::av_buffer_ref(self.0) }
    }
}

impl Drop for BufRef {
    fn drop(&mut self) {
        unsafe { sys::av_buffer_unref(&mut self.0) }
    }
}

// The pointers are owned exclusively and libav's refcounting is atomic.
unsafe impl Send for BufRef {}

/// An owned `AVFrame`.
struct AvFrame(*mut sys::AVFrame);

impl AvFrame {
    fn alloc() -> Result<Self, EncoderError> {
        let p = unsafe { sys::av_frame_alloc() };
        if p.is_null() {
            Err(EncoderError::Setup("av_frame_alloc returned null".into()))
        } else {
            Ok(AvFrame(p))
        }
    }
    fn as_ptr(&self) -> *mut sys::AVFrame {
        self.0
    }
}

impl Drop for AvFrame {
    fn drop(&mut self) {
        unsafe { sys::av_frame_free(&mut self.0) }
    }
}

unsafe impl Send for AvFrame {}

/// An owned filter graph plus its source and sink. Freeing the graph frees
/// every filter instance in it, so the two context pointers are borrowed, not
/// owned.
struct Graph {
    graph: *mut sys::AVFilterGraph,
    src: *mut sys::AVFilterContext,
    sink: *mut sys::AVFilterContext,
}

impl Drop for Graph {
    fn drop(&mut self) {
        unsafe { sys::avfilter_graph_free(&mut self.graph) }
    }
}

unsafe impl Send for Graph {}

/// An owned `SwsContext`.
struct SwsContext(*mut sys::SwsContext);

impl Drop for SwsContext {
    fn drop(&mut self) {
        unsafe { sys::sws_freeContext(self.0) }
    }
}

unsafe impl Send for SwsContext {}

// =============================================================== helpers

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no interior NUL in a configuration string")
}

/// `av_opt_get` on an opened codec context, so what is reported is what stuck.
fn opt_readback(ctx: *mut sys::AVCodecContext, name: &str) -> String {
    let c = cstr(name);
    let mut out: *mut u8 = ptr::null_mut();
    unsafe {
        let rc = sys::av_opt_get(
            ctx as *mut c_void,
            c.as_ptr(),
            sys::AV_OPT_SEARCH_CHILDREN,
            &mut out,
        );
        if rc < 0 || out.is_null() {
            return format!("<unset {rc}>");
        }
        let s = CStr::from_ptr(out as *const i8)
            .to_string_lossy()
            .into_owned();
        sys::av_free(out as *mut c_void);
        s
    }
}

fn sw_pixel(format: PixelFormat) -> sys::AVPixelFormat {
    match format {
        PixelFormat::Xrgb8888 => sys::AVPixelFormat::AV_PIX_FMT_BGR0,
        PixelFormat::Argb8888 => sys::AVPixelFormat::AV_PIX_FMT_BGRA,
    }
}

/// `ff::init()` exactly once, and quieten libav's default INFO chatter (a
/// library has no business writing to the process's stderr). `AIRPLAY_AVLOG`
/// raises it again: 32 = verbose, 48 = debug, 56 = trace.
fn init_libav() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = ff::init();
        let level = std::env::var("AIRPLAY_AVLOG")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(sys::AV_LOG_ERROR);
        unsafe { sys::av_log_set_level(level) };
    });
}

/// Ask the driver for a low-power H.264 entrypoint. Returns `false` when
/// `avcodec_open2` refuses (ENOSYS on intel-media-driver 26.2.4 here — it does
/// not degrade, so code that passes `low_power=1` unconditionally simply fails
/// to open). Never used to configure the real encoder; it exists so a future
/// driver that grows `VAEntrypointEncSliceLP` is visible rather than assumed.
pub fn probe_low_power(device: &str, size: (u32, u32), fps: u32) -> bool {
    init_libav();
    let Some(codec) = ff::encoder::find_by_name("h264_vaapi") else {
        return false;
    };
    let mut dev: *mut sys::AVBufferRef = ptr::null_mut();
    let cdev = cstr(device);
    let rc = unsafe {
        sys::av_hwdevice_ctx_create(
            &mut dev,
            sys::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI,
            cdev.as_ptr(),
            ptr::null_mut(),
            0,
        )
    };
    if rc < 0 {
        return false;
    }
    let dev = BufRef(dev);
    let Ok(frames) = alloc_frames_ctx(&dev, sys::AVPixelFormat::AV_PIX_FMT_NV12, size, 2) else {
        return false;
    };
    let ctx = ff::codec::context::Context::new_with_codec(codec);
    let Ok(mut enc) = ctx.encoder().video() else {
        return false;
    };
    enc.set_width(size.0);
    enc.set_height(size.1);
    enc.set_format(ff::format::Pixel::VAAPI);
    enc.set_time_base(ff::Rational(1, fps.max(1) as i32));
    unsafe {
        let p = enc.as_mut_ptr();
        (*p).sw_pix_fmt = sys::AVPixelFormat::AV_PIX_FMT_NV12;
        (*p).hw_frames_ctx = frames.new_ref();
    }
    let mut opts = ff::Dictionary::new();
    opts.set("low_power", "1");
    opts.set("profile", "high");
    // A silent probe: the failure is expected and its log line is noise.
    let saved = unsafe { sys::av_log_get_level() };
    unsafe { sys::av_log_set_level(sys::AV_LOG_QUIET) };
    let ok = enc.open_with(opts).is_ok();
    unsafe { sys::av_log_set_level(saved) };
    ok
}

fn alloc_frames_ctx(
    device: &BufRef,
    sw_format: sys::AVPixelFormat,
    size: (u32, u32),
    pool: i32,
) -> Result<BufRef, EncoderError> {
    let p = unsafe { sys::av_hwframe_ctx_alloc(device.as_ptr()) };
    if p.is_null() {
        return Err(EncoderError::Setup(
            "av_hwframe_ctx_alloc returned null".into(),
        ));
    }
    let frames = BufRef(p);
    unsafe {
        let fc = (*p).data as *mut sys::AVHWFramesContext;
        (*fc).format = sys::AVPixelFormat::AV_PIX_FMT_VAAPI;
        (*fc).sw_format = sw_format;
        (*fc).width = size.0 as i32;
        (*fc).height = size.1 as i32;
        (*fc).initial_pool_size = pool;
    }
    check("av_hwframe_ctx_init", unsafe { sys::av_hwframe_ctx_init(p) })?;
    Ok(frames)
}

// =============================================================== the encoder

/// How pixels get into a VA-API surface. Both arms end with a surface holding
/// the capture's own byte order at capture size, so everything after this point
/// is identical.
enum GpuInput {
    /// shm: a BGR0 pool the mapping is copied into.
    Upload { src_frames: BufRef },
    /// dmabuf: the imported fd, mapped straight into a VA-API surface.
    Dmabuf {
        /// The DRM device the descriptors are interpreted against. Held only to
        /// keep `drm_frames` alive.
        _drm_device: BufRef,
        drm_frames: BufRef,
        /// Derived FROM `drm_frames` with `MAP_DIRECT|MAP_READ`, which is what
        /// `vf_hwmap(derive_device=vaapi)` does. A hand-built standalone
        /// VAAPI/BGR0 frames context also compiles, also logs `Create surface`,
        /// and then returns EINVAL — the spike lost real time to exactly that.
        va_frames: BufRef,
        /// VA-API surface per capture buffer id. ext-image-copy-capture rotates
        /// a small fixed set, so this turns a per-frame import into a
        /// per-buffer one.
        cache: HashMap<u64, AvFrame>,
    },
}

enum Backend {
    Gpu {
        /// Order matters for teardown: the graph and the encoder both hold
        /// references into these, and `BufRef` only drops its own reference.
        _device: BufRef,
        input: GpuInput,
        graph: Graph,
    },
    Cpu {
        sws: SwsContext,
    },
}

/// How many mapped surfaces to keep before starting over. A capture session
/// rotates four buffers, so this is only reached if a renegotiation swaps the
/// whole set out several times under one encoder — buffer ids are never
/// re-used, so without a cap the map would grow without bound.
const DMABUF_CACHE_CAP: usize = 16;

/// Import one dmabuf as a VA-API surface.
///
/// Two traps live in these twenty lines, both of the "compiles fine, returns
/// -22, logs something that looks like success" class:
///
/// 1. The descriptor MUST sit in a refcounted `AVBufferRef` at `frame->buf[0]`,
///    with `frame->data[0]` pointing at it. `ff_hwframe_map_create` calls
///    `av_frame_ref` on the source, and a non-refcounted frame makes that
///    attempt a deep copy — impossible for a hardware pixel format.
/// 2. The destination frames context must be the DERIVED one (see
///    [`GpuInput::Dmabuf::va_frames`]).
///
/// The source frame is dropped on return, which is safe: the map holds its own
/// reference to it.
fn map_dmabuf(
    drm_frames: &BufRef,
    va_frames: &BufRef,
    image: &DmabufImage,
    size: (u32, u32),
) -> Result<AvFrame, EncoderError> {
    // The importer silently substitutes a pitch of its own for one it does not
    // like, which does not fail, does not log, and shears every row of the
    // picture progressively sideways. Refusing the frame here is the second
    // half of the guarantee `Gbm::allocate` makes: the capture layer allocates
    // an aligned stride, and this is the check that no OTHER source of
    // dmabufs — a future compositor-allocated buffer, a different allocator —
    // can reach the encoder without one. See `capture::STRIDE_HONOURED_ALIGN`.
    if !image.stride.is_multiple_of(crate::capture::STRIDE_HONOURED_ALIGN) {
        return Err(EncoderError::Setup(format!(
            "dmabuf stride {} is not a multiple of {}; the VA-API import would ignore it and \
             shear the picture (buffer id {}, {}x{})",
            image.stride,
            crate::capture::STRIDE_HONOURED_ALIGN,
            image.id,
            image.width,
            image.height,
        )));
    }

    let src = AvFrame::alloc()?;
    let mapped = AvFrame::alloc()?;

    let desc_buf = unsafe { sys::av_buffer_alloc(std::mem::size_of::<sys::AVDRMFrameDescriptor>()) };
    if desc_buf.is_null() {
        return Err(EncoderError::Setup(
            "av_buffer_alloc(AVDRMFrameDescriptor) returned null".into(),
        ));
    }
    unsafe {
        let desc = (*desc_buf).data as *mut sys::AVDRMFrameDescriptor;
        ptr::write(desc, std::mem::zeroed::<sys::AVDRMFrameDescriptor>());
        (*desc).nb_objects = 1;
        (*desc).objects[0].fd = image.fd();
        (*desc).objects[0].size = image.size;
        (*desc).objects[0].format_modifier = image.modifier;
        (*desc).nb_layers = 1;
        (*desc).layers[0].format = image.fourcc;
        (*desc).layers[0].nb_planes = 1;
        (*desc).layers[0].planes[0].object_index = 0;
        (*desc).layers[0].planes[0].offset = image.offset as isize;
        (*desc).layers[0].planes[0].pitch = image.stride as isize;

        let p = src.as_ptr();
        (*p).format = sys::AVPixelFormat::AV_PIX_FMT_DRM_PRIME as c_int;
        (*p).width = size.0 as c_int;
        (*p).height = size.1 as c_int;
        // Ownership of `desc_buf` moves to the frame; av_frame_free unrefs it.
        (*p).buf[0] = desc_buf;
        (*p).data[0] = (*desc_buf).data;
        (*p).hw_frames_ctx = drm_frames.new_ref();

        let q = mapped.as_ptr();
        (*q).format = sys::AVPixelFormat::AV_PIX_FMT_VAAPI as c_int;
        (*q).width = size.0 as c_int;
        (*q).height = size.1 as c_int;
        (*q).hw_frames_ctx = va_frames.new_ref();
    }
    check("av_hwframe_map(DRM_PRIME -> VAAPI, DIRECT)", unsafe {
        sys::av_hwframe_map(
            mapped.as_ptr(),
            src.as_ptr(),
            (sys::AV_HWFRAME_MAP_DIRECT as c_uint | sys::AV_HWFRAME_MAP_READ as c_uint) as c_int,
        )
    })?;
    Ok(mapped)
}

/// One frame's worth of input, in whichever form the caller has it.
enum Input<'a> {
    Pixels { pixels: &'a [u8], stride: u32 },
    Dmabuf(&'a DmabufImage),
}

/// A configured, open H.264 encoder.
pub struct Encoder {
    cfg: EncoderConfig,
    info: EncoderInfo,
    enc: ff::codec::encoder::video::Encoder,
    backend: Backend,
    stats: EncoderStats,
    /// CLOCK_MONOTONIC ns of the first frame; PTS is measured from it.
    epoch_ns: Option<u64>,
    last_pts_us: i64,
    /// Timestamp of the last IDR, for the wall-clock keyframe interval.
    last_idr_ns: Option<u64>,
    force_idr: bool,
}

impl Encoder {
    /// Open an encoder. Fails rather than silently degrading: a rejected option
    /// is a configuration bug, not something to shrug at.
    pub fn new(cfg: EncoderConfig) -> Result<Self, EncoderError> {
        init_libav();
        if !cfg.target.0.is_multiple_of(2) || !cfg.target.1.is_multiple_of(2) {
            return Err(EncoderError::Setup(format!(
                "target {}x{} must be even in both dimensions (NV12)",
                cfg.target.0, cfg.target.1
            )));
        }
        let mbs = macroblocks(cfg.target.0, cfg.target.1);
        if mbs > MAX_MACROBLOCKS {
            return Err(EncoderError::Setup(format!(
                "target {}x{} is {mbs} macroblocks, over the level-4.2 budget of {MAX_MACROBLOCKS}; \
                 use fit_source_to_receiver()",
                cfg.target.0, cfg.target.1
            )));
        }
        if cfg.dmabuf_input && cfg.kind != EncoderKind::Gpu {
            return Err(EncoderError::Setup(
                "dmabuf input needs the gpu back-end; libx264 has no way to read a DRM buffer"
                    .into(),
            ));
        }
        match cfg.kind {
            EncoderKind::Gpu => Self::new_gpu(cfg, mbs),
            EncoderKind::Cpu => Self::new_cpu(cfg, mbs),
        }
    }

    fn common_setup(
        enc: &mut ff::encoder::video::Video,
        cfg: &EncoderConfig,
        pix: ff::format::Pixel,
    ) {
        enc.set_width(cfg.target.0);
        enc.set_height(cfg.target.1);
        enc.set_format(pix);
        // Microsecond timebase: the capture layer's PTS is a real monotonic
        // clock and the yield rate is not a constant 60 fps (a still screen
        // gives 4 keepalives a second), so quantising to 1/fps would lie.
        enc.set_time_base(ff::Rational(1, 1_000_000));
        enc.set_frame_rate(Some(ff::Rational(cfg.fps.max(1) as i32, 1)));
        enc.set_gop((cfg.fps.max(1) as f64 * cfg.keyframe_seconds).round() as u32);
        enc.set_max_b_frames(0);
        unsafe {
            let p = enc.as_mut_ptr();
            (*p).max_b_frames = 0;
            // In-band SPS/PPS. There is no container here, so nothing else would
            // ever carry the parameter sets and the receiver would never decode.
            (*p).flags &= !(sys::AV_CODEC_FLAG_GLOBAL_HEADER as i32);
            // Colour, declared in the VUI. Both conversion stages below are
            // configured to produce BT.709 limited-range YUV; these four fields
            // are what says so in the bitstream. Without them
            // video_signal_type_present_flag is 0, the matrix reads
            // "unspecified", and every modern TV resolves unspecified at HD
            // frame size to BT.709 -- so untagged BT.601 pixels come back with
            // shifted, desaturated greens and reds. The VUI is written
            // independently of `sei=0`.
            (*p).color_range = sys::AVColorRange::AVCOL_RANGE_MPEG;
            (*p).colorspace = sys::AVColorSpace::AVCOL_SPC_BT709;
            (*p).color_primaries = sys::AVColorPrimaries::AVCOL_PRI_BT709;
            (*p).color_trc = sys::AVColorTransferCharacteristic::AVCOL_TRC_BT709;
        }
    }

    fn new_gpu(cfg: EncoderConfig, mbs: u32) -> Result<Self, EncoderError> {
        let low_power_available = if cfg.probe_low_power {
            Some(probe_low_power(&cfg.device, cfg.target, cfg.fps))
        } else {
            None
        };

        // --- VAAPI device
        let mut dev: *mut sys::AVBufferRef = ptr::null_mut();
        let cdev = cstr(&cfg.device);
        check("av_hwdevice_ctx_create(VAAPI)", unsafe {
            sys::av_hwdevice_ctx_create(
                &mut dev,
                sys::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI,
                cdev.as_ptr(),
                ptr::null_mut(),
                0,
            )
        })?;
        let device = BufRef(dev);

        // --- input stage: a surface pool to upload into, or a DRM->VAAPI
        // mapping to import through. Either way what comes out is a VA-API
        // surface holding the capture's own byte order at capture size; the
        // colour conversion is the GPU VPP's job, never swscale's.
        let input = if cfg.dmabuf_input {
            let mut drm: *mut sys::AVBufferRef = ptr::null_mut();
            check("av_hwdevice_ctx_create(DRM)", unsafe {
                sys::av_hwdevice_ctx_create(
                    &mut drm,
                    sys::AVHWDeviceType::AV_HWDEVICE_TYPE_DRM,
                    cdev.as_ptr(),
                    ptr::null_mut(),
                    0,
                )
            })?;
            let drm_device = BufRef(drm);

            let frames = unsafe { sys::av_hwframe_ctx_alloc(drm_device.as_ptr()) };
            if frames.is_null() {
                return Err(EncoderError::Setup(
                    "av_hwframe_ctx_alloc(DRM) returned null".into(),
                ));
            }
            let drm_frames = BufRef(frames);
            unsafe {
                let fc = (*frames).data as *mut sys::AVHWFramesContext;
                (*fc).format = sys::AVPixelFormat::AV_PIX_FMT_DRM_PRIME;
                (*fc).sw_format = sw_pixel(cfg.source_format);
                (*fc).width = cfg.source.0 as c_int;
                (*fc).height = cfg.source.1 as c_int;
            }
            check("av_hwframe_ctx_init(DRM)", unsafe {
                sys::av_hwframe_ctx_init(frames)
            })?;

            let mut va: *mut sys::AVBufferRef = ptr::null_mut();
            check("av_hwframe_ctx_create_derived(DRM -> VAAPI)", unsafe {
                sys::av_hwframe_ctx_create_derived(
                    &mut va,
                    sys::AVPixelFormat::AV_PIX_FMT_VAAPI,
                    device.as_ptr(),
                    drm_frames.as_ptr(),
                    (sys::AV_HWFRAME_MAP_DIRECT as c_uint | sys::AV_HWFRAME_MAP_READ as c_uint)
                        as c_int,
                )
            })?;
            GpuInput::Dmabuf {
                _drm_device: drm_device,
                drm_frames,
                va_frames: BufRef(va),
                cache: HashMap::new(),
            }
        } else {
            GpuInput::Upload {
                src_frames: alloc_frames_ctx(&device, sw_pixel(cfg.source_format), cfg.source, 4)?,
            }
        };

        // --- buffersrc -> scale_vaapi -> buffersink
        let src_frames = match &input {
            GpuInput::Upload { src_frames } => src_frames,
            GpuInput::Dmabuf { va_frames, .. } => va_frames,
        };
        let graph = build_vaapi_graph(&device, src_frames, &cfg)?;
        let sink_frames = unsafe { sys::av_buffersink_get_hw_frames_ctx(graph.sink) };
        if sink_frames.is_null() {
            return Err(EncoderError::Setup(
                "buffersink produced no hw_frames_ctx (scale_vaapi did not initialise)".into(),
            ));
        }

        // --- encoder, fed from the filter's own NV12 pool
        let codec =
            ff::encoder::find_by_name("h264_vaapi").ok_or(EncoderError::NoCodec("h264_vaapi"))?;
        let ctx = ff::codec::context::Context::new_with_codec(codec);
        let mut enc = ctx
            .encoder()
            .video()
            .map_err(|e| EncoderError::Setup(format!("encoder().video(): {e}")))?;
        Self::common_setup(&mut enc, &cfg, ff::format::Pixel::VAAPI);
        unsafe {
            let p = enc.as_mut_ptr();
            (*p).sw_pix_fmt = sys::AVPixelFormat::AV_PIX_FMT_NV12;
            (*p).hw_frames_ctx = sys::av_buffer_ref(sink_frames);
        }

        let wanted: Vec<(&str, String)> = vec![
            // Constant quality. CBR/VBR pad an idle desktop to 6.13 / 1.98 Mb/s
            // against CQP's 0.83 Mb/s, which is what "felt laggy over Wi-Fi".
            ("rc_mode", "CQP".into()),
            ("qp", cfg.qp.to_string()),
            // No SEI => no HRD, no pic_struct, no invitation to buffer.
            ("sei", "0".into()),
            // The encoder holds zero frames. This alone is the 81 -> 48 ms win.
            ("async_depth", "1".into()),
            ("profile", "high".into()),
            ("level", "4.2".into()),
            // Every I frame is an IDR, so a forced keyframe really resets.
            ("idr_interval", "0".into()),
            ("aud", "0".into()),
            // NOTE: low_power is deliberately absent. See the module docs.
        ];
        let mut opts = ff::Dictionary::new();
        for (k, v) in &wanted {
            opts.set(k, v);
        }
        let mut enc = enc
            .open_with(opts)
            .map_err(|e| EncoderError::Setup(format!("avcodec_open2(h264_vaapi): {e}")))?;

        let (options, extradata_len) = unsafe {
            let p = enc.as_mut_ptr();
            let opts = wanted
                .iter()
                .map(|(k, _)| ((*k).to_string(), opt_readback(p, k)))
                .collect();
            (opts, (*p).extradata_size as usize)
        };

        Ok(Encoder {
            info: EncoderInfo {
                kind: EncoderKind::Gpu,
                codec: "h264_vaapi".into(),
                source: cfg.source,
                target: cfg.target,
                macroblocks: mbs,
                options,
                extradata_len,
                low_power_available,
                dmabuf_input: cfg.dmabuf_input,
            },
            enc,
            backend: Backend::Gpu {
                _device: device,
                input,
                graph,
            },
            cfg,
            stats: EncoderStats::default(),
            epoch_ns: None,
            last_pts_us: -1,
            last_idr_ns: None,
            force_idr: false,
        })
    }

    fn new_cpu(cfg: EncoderConfig, mbs: u32) -> Result<Self, EncoderError> {
        let codec =
            ff::encoder::find_by_name("libx264").ok_or(EncoderError::NoCodec("libx264"))?;
        let ctx = ff::codec::context::Context::new_with_codec(codec);
        let mut enc = ctx
            .encoder()
            .video()
            .map_err(|e| EncoderError::Setup(format!("encoder().video(): {e}")))?;
        Self::common_setup(&mut enc, &cfg, ff::format::Pixel::YUV420P);

        let keyint = (cfg.fps.max(1) as f64 * cfg.keyframe_seconds).round().max(1.0) as u32;
        let mut x264_params = format!(
            "keyint={keyint}:min-keyint={keyint}:bframes=0:repeat-headers=1:annexb=1:scenecut=0"
        );
        if let Some(n) = cfg.cpu_slices {
            // Deterministic slice count: x264 sliced threads emit exactly one
            // slice per thread. This is how the multi-slice access-unit test
            // gets an exact expected value instead of "whatever this CPU does".
            x264_params.push_str(&format!(":sliced-threads=1:threads={n}"));
        }
        let wanted: Vec<(&str, String)> = vec![
            ("preset", "ultrafast".into()),
            ("tune", "zerolatency".into()),
            ("profile", "high".into()),
            ("level", "4.2".into()),
            // Constant QP, matching the GPU path's CQP semantics.
            ("qp", cfg.qp.to_string()),
            ("x264-params", x264_params),
        ];
        let mut opts = ff::Dictionary::new();
        for (k, v) in &wanted {
            opts.set(k, v);
        }
        let mut enc = enc
            .open_with(opts)
            .map_err(|e| EncoderError::Setup(format!("avcodec_open2(libx264): {e}")))?;

        let (options, extradata_len) = unsafe {
            let p = enc.as_mut_ptr();
            let opts = wanted
                .iter()
                .map(|(k, _)| ((*k).to_string(), opt_readback(p, k)))
                .collect();
            (opts, (*p).extradata_size as usize)
        };

        // BGR0/BGRA -> YUV420P + the fit-to-receiver scale, on the CPU. Bilinear
        // is what the GPU VPP does too.
        let sws = unsafe {
            sys::sws_getContext(
                cfg.source.0 as c_int,
                cfg.source.1 as c_int,
                sw_pixel(cfg.source_format),
                cfg.target.0 as c_int,
                cfg.target.1 as c_int,
                sys::AVPixelFormat::AV_PIX_FMT_YUV420P,
                sys::SwsFlags::SWS_BILINEAR as c_int,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if sws.is_null() {
            return Err(EncoderError::Setup("sws_getContext returned null".into()));
        }
        // swscale's default is BT.601 limited, which is what the GPU path used
        // to emit too: pure green came out Y=144 instead of the BT.709 limited
        // 172. The VUI written in common_setup says BT.709, so the conversion
        // has to be BT.709 as well. Source is full-range RGB, destination is
        // limited-range YUV.
        check("sws_setColorspaceDetails", unsafe {
            sys::sws_setColorspaceDetails(
                sws,
                sys::sws_getCoefficients(sys::SWS_CS_ITU709),
                1,
                sys::sws_getCoefficients(sys::SWS_CS_ITU709),
                0,
                0,
                1 << 16,
                1 << 16,
            )
        })?;

        Ok(Encoder {
            info: EncoderInfo {
                kind: EncoderKind::Cpu,
                codec: "libx264".into(),
                source: cfg.source,
                target: cfg.target,
                macroblocks: mbs,
                options,
                extradata_len,
                low_power_available: None,
                dmabuf_input: false,
            },
            enc,
            backend: Backend::Cpu {
                sws: SwsContext(sws),
            },
            cfg,
            stats: EncoderStats::default(),
            epoch_ns: None,
            last_pts_us: -1,
            last_idr_ns: None,
            force_idr: false,
        })
    }

    pub fn info(&self) -> &EncoderInfo {
        &self.info
    }
    pub fn stats(&self) -> EncoderStats {
        self.stats
    }
    pub fn config(&self) -> &EncoderConfig {
        &self.cfg
    }

    /// Make the next picture an IDR (with `idr_interval=0`, every forced I frame
    /// is one). Used on a receiver reconnect and by the wall-clock keyframe
    /// timer.
    pub fn force_idr(&mut self) {
        self.force_idr = true;
    }

    /// Encode one captured buffer from a CPU mapping.
    ///
    /// `pixels` is the capture layer's shm mapping, borrowed for the duration of
    /// the call and never retained: the GPU path uploads it with
    /// `av_hwframe_transfer_data`, which is synchronous, and the CPU path
    /// converts it with `sws_scale`, likewise.
    ///
    /// Returns **one access unit per picture**. Both back-ends emit one packet
    /// per picture — h264_vaapi produces a single slice, x264 with sliced
    /// threads produces many — and either way every slice of the picture is in
    /// the same returned unit.
    pub fn encode(
        &mut self,
        pixels: &[u8],
        stride: u32,
        size: (u32, u32),
        timestamp_ns: u64,
    ) -> Result<Vec<AccessUnit>, EncoderError> {
        self.encode_input(Input::Pixels { pixels, stride }, size, timestamp_ns)
    }

    /// Encode one captured buffer straight from the compositor's dmabuf.
    ///
    /// Nothing is copied and nothing is read on the CPU: the fd is mapped into
    /// a VA-API surface once per buffer and re-used for every frame the
    /// compositor blits into it.
    pub fn encode_dmabuf(
        &mut self,
        image: &DmabufImage,
        size: (u32, u32),
        timestamp_ns: u64,
    ) -> Result<Vec<AccessUnit>, EncoderError> {
        self.encode_input(Input::Dmabuf(image), size, timestamp_ns)
    }

    fn encode_input(
        &mut self,
        input: Input<'_>,
        size: (u32, u32),
        timestamp_ns: u64,
    ) -> Result<Vec<AccessUnit>, EncoderError> {
        if size != self.cfg.source {
            return Err(EncoderError::FormatChanged {
                want: self.cfg.source,
                got: size,
            });
        }
        // Per-input validation comes AFTER the size check: a wrong size also
        // makes the length check fail, and `ShortFrame` would be the wrong
        // answer to "you gave me a 1920x1200 frame for a 1280x800 encoder".
        match &input {
            Input::Pixels { pixels, stride } => {
                let need = *stride as usize * size.1 as usize;
                if pixels.len() < need {
                    return Err(EncoderError::ShortFrame {
                        got: pixels.len(),
                        want: need,
                        stride: *stride,
                        height: size.1,
                    });
                }
            }
            Input::Dmabuf(image) => {
                if (image.width, image.height) != size {
                    return Err(EncoderError::FormatChanged {
                        want: size,
                        got: (image.width, image.height),
                    });
                }
            }
        }
        let epoch = *self.epoch_ns.get_or_insert(timestamp_ns);
        let pts_us = ((timestamp_ns.saturating_sub(epoch)) / 1_000) as i64;
        // The encoder rejects a non-increasing PTS. Capture guarantees strictly
        // increasing nanoseconds, but the microsecond division could collapse two
        // frames onto the same tick.
        let pts_us = pts_us.max(self.last_pts_us + 1);
        self.last_pts_us = pts_us;

        // Wall-clock keyframes: the pipeline is not a fixed 60 fps, so a GOP
        // counted in frames would put 5 s of keyframe interval anywhere between
        // 5 s and 75 s depending on how still the screen is.
        let idr_due = match self.last_idr_ns {
            None => true,
            Some(prev) => {
                (timestamp_ns.saturating_sub(prev)) as f64 / 1e9 >= self.cfg.keyframe_seconds
            }
        };
        let want_idr = self.force_idr || idr_due;
        if self.force_idr {
            self.stats.forced_idr += 1;
        }
        self.force_idr = false;

        // A view onto the caller's mapping, for the two CPU-fed arms. No copy,
        // no ownership (`buf[0]` stays null), so nothing can outlive the borrow.
        let sw_frame = |pixels: &[u8], stride: u32| -> Result<AvFrame, EncoderError> {
            let src = AvFrame::alloc()?;
            unsafe {
                let p = src.as_ptr();
                (*p).format = sw_pixel(self.cfg.source_format) as c_int;
                (*p).width = size.0 as c_int;
                (*p).height = size.1 as c_int;
                (*p).data[0] = pixels.as_ptr() as *mut u8;
                (*p).linesize[0] = stride as c_int;
                (*p).pts = pts_us;
            }
            tag_source_colour(src.as_ptr());
            Ok(src)
        };
        let target = self.cfg.target;

        // `self.backend` is borrowed mutably below, so the counters travel on
        // their own borrow rather than through `self`.
        let stats = &mut self.stats;
        let ready = match (&mut self.backend, input) {
            (Backend::Gpu { input: GpuInput::Upload { src_frames }, graph, .. }, Input::Pixels { pixels, stride }) => {
                // Upload BGR0 -> a VAAPI BGR0 surface. Synchronous, and the one
                // stage the zero-copy arm below deletes outright.
                let src = sw_frame(pixels, stride)?;
                let t0 = std::time::Instant::now();
                let hw = AvFrame::alloc()?;
                check("av_hwframe_get_buffer", unsafe {
                    sys::av_hwframe_get_buffer(src_frames.as_ptr(), hw.as_ptr(), 0)
                })?;
                check("av_hwframe_transfer_data", unsafe {
                    sys::av_hwframe_transfer_data(hw.as_ptr(), src.as_ptr(), 0)
                })?;
                unsafe { (*hw.as_ptr()).pts = pts_us };
                tag_source_colour(hw.as_ptr());
                stats.upload_us += t0.elapsed().as_micros() as u64;

                // GPU VPP: colour convert + fit-to-receiver scale in one pass.
                // buffersrc takes the reference; the emptied AVFrame is still
                // ours to free.
                let t1 = std::time::Instant::now();
                check("av_buffersrc_add_frame_flags", unsafe {
                    sys::av_buffersrc_add_frame_flags(graph.src, hw.as_ptr(), 0)
                })?;
                let nv = AvFrame::alloc()?;
                check("av_buffersink_get_frame", unsafe {
                    sys::av_buffersink_get_frame(graph.sink, nv.as_ptr())
                })?;
                stats.convert_us += t1.elapsed().as_micros() as u64;
                nv
            }
            (Backend::Gpu { input: GpuInput::Dmabuf { drm_frames, va_frames, cache, .. }, graph, .. }, Input::Dmabuf(image)) => {
                let t0 = std::time::Instant::now();
                if cache.len() >= DMABUF_CACHE_CAP && !cache.contains_key(&image.id) {
                    cache.clear();
                }
                let mapped = match cache.entry(image.id) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(map_dmabuf(drm_frames, va_frames, image, size)?)
                    }
                };
                unsafe { (*mapped.as_ptr()).pts = pts_us };
                tag_source_colour(mapped.as_ptr());
                stats.upload_us += t0.elapsed().as_micros() as u64;

                // KEEP_REF because the mapped frame is cached: buffersrc takes
                // its own reference instead of consuming ours.
                let t1 = std::time::Instant::now();
                check("av_buffersrc_add_frame_flags", unsafe {
                    sys::av_buffersrc_add_frame_flags(
                        graph.src,
                        mapped.as_ptr(),
                        sys::AV_BUFFERSRC_FLAG_KEEP_REF as c_int,
                    )
                })?;
                let nv = AvFrame::alloc()?;
                check("av_buffersink_get_frame", unsafe {
                    sys::av_buffersink_get_frame(graph.sink, nv.as_ptr())
                })?;
                stats.convert_us += t1.elapsed().as_micros() as u64;
                nv
            }
            (Backend::Cpu { sws }, Input::Pixels { pixels, stride }) => {
                let src = sw_frame(pixels, stride)?;
                let t1 = std::time::Instant::now();
                let dst = AvFrame::alloc()?;
                unsafe {
                    let p = dst.as_ptr();
                    (*p).format = sys::AVPixelFormat::AV_PIX_FMT_YUV420P as c_int;
                    (*p).width = target.0 as c_int;
                    (*p).height = target.1 as c_int;
                    check("av_frame_get_buffer", sys::av_frame_get_buffer(p, 0))?;
                    let sp = src.as_ptr();
                    check(
                        "sws_scale",
                        sys::sws_scale(
                            sws.0,
                            (*sp).data.as_ptr() as *const *const u8,
                            (*sp).linesize.as_ptr(),
                            0,
                            size.1 as c_int,
                            (*p).data.as_ptr(),
                            (*p).linesize.as_ptr(),
                        ),
                    )?;
                    (*p).pts = pts_us;
                }
                stats.convert_us += t1.elapsed().as_micros() as u64;
                dst
            }
            // A mismatch is a wiring bug, and a silent slow path is precisely
            // the kind of thing that ships unnoticed.
            (_, Input::Dmabuf(_)) => {
                return Err(EncoderError::Setup(
                    "encode_dmabuf on an encoder built for uploaded frames \
                     (set EncoderConfig::dmabuf_input)"
                        .into(),
                ))
            }
            (_, Input::Pixels { .. }) => {
                return Err(EncoderError::Setup(
                    "encode() on an encoder built for dmabuf input \
                     (clear EncoderConfig::dmabuf_input)"
                        .into(),
                ))
            }
        };

        unsafe {
            let p = ready.as_ptr();
            // Set the picture type on the frame that actually reaches the
            // encoder: the VPP copies props, but relying on that is the kind of
            // assumption this project keeps getting burned by.
            (*p).pict_type = if want_idr {
                sys::AVPictureType::AV_PICTURE_TYPE_I
            } else {
                sys::AVPictureType::AV_PICTURE_TYPE_NONE
            };
        }

        let t2 = std::time::Instant::now();
        check("avcodec_send_frame", unsafe {
            sys::avcodec_send_frame(self.enc.as_mut_ptr(), ready.as_ptr())
        })?;
        self.stats.frames_in += 1;

        let units = self.drain(timestamp_ns)?;
        self.stats.encode_us += t2.elapsed().as_micros() as u64;
        if units.iter().any(|u| u.is_idr) {
            self.last_idr_ns = Some(timestamp_ns);
        }
        Ok(units)
    }

    /// Collect whatever the encoder is ready to hand back. With `async_depth=1`
    /// and no B frames this is exactly one packet per submitted frame.
    fn drain(&mut self, timestamp_ns: u64) -> Result<Vec<AccessUnit>, EncoderError> {
        let mut out = Vec::new();
        loop {
            let mut pkt = ff::codec::packet::Packet::empty();
            match self.enc.receive_packet(&mut pkt) {
                Ok(()) => {
                    let data = pkt.data().unwrap_or(&[]).to_vec();
                    let scan = scan_annexb(&data);
                    self.stats.packets_out += 1;
                    self.stats.pictures_out += scan.pictures as u64;
                    self.stats.vcl_nals_out += scan.vcl_nals as u64;
                    self.stats.idr_out += (scan.idr_slices > 0) as u64;
                    self.stats.sps_out += scan.sps as u64;
                    self.stats.pps_out += scan.pps as u64;
                    self.stats.sei_out += scan.sei as u64;
                    self.stats.aud_out += scan.aud as u64;
                    self.stats.bytes_out += data.len() as u64;
                    out.push(AccessUnit {
                        timestamp_ns,
                        pts_us: pkt.pts().unwrap_or(0),
                        is_idr: scan.idr_slices > 0,
                        slices: scan.vcl_nals,
                        has_sps: scan.sps > 0,
                        has_pps: scan.pps > 0,
                        data,
                    });
                }
                Err(ff::Error::Other { errno }) if errno == libc::EAGAIN => break,
                Err(ff::Error::Eof) => break,
                Err(e) => return Err(EncoderError::Setup(format!("receive_packet: {e}"))),
            }
        }
        Ok(out)
    }

    /// Flush the encoder at end of stream. With `async_depth=1` this normally
    /// returns nothing, which is the point of `async_depth=1`.
    pub fn flush(&mut self) -> Result<Vec<AccessUnit>, EncoderError> {
        check("avcodec_send_frame(EOF)", unsafe {
            sys::avcodec_send_frame(self.enc.as_mut_ptr(), ptr::null())
        })?;
        let ts = self.last_idr_ns.unwrap_or(0);
        self.drain(ts)
    }
}

// The encoder owns its libav allocations exclusively and hands out no pointers.
unsafe impl Send for Encoder {}

/// Tag a frame on its way into the VPP as full-range BGR0/BGRA with BT.709
/// primaries.
///
/// `out_color_matrix=bt709` on `scale_vaapi` is silently ignored by iHD unless
/// the INPUT frame says what it is: with an untagged source the driver falls
/// back to its BT.601 default and pure green still comes out Y=144 instead of
/// the BT.709 limited 172. The capture layer's buffers are full-range RGB, so
/// that is what this declares.
fn tag_source_colour(p: *mut sys::AVFrame) {
    unsafe {
        (*p).color_range = sys::AVColorRange::AVCOL_RANGE_JPEG;
        (*p).colorspace = sys::AVColorSpace::AVCOL_SPC_BT709;
        (*p).color_primaries = sys::AVColorPrimaries::AVCOL_PRI_BT709;
        (*p).color_trc = sys::AVColorTransferCharacteristic::AVCOL_TRC_BT709;
    }
}

/// `buffer(VAAPI) -> scale_vaapi(w,h,format=nv12) -> buffersink`.
///
/// Built with the ffmpeg 8/9 API shape, which is NOT the one most examples use:
/// `AVFilterGraph.hw_device_ctx` no longer exists, so the device goes on the
/// filter instance, which means alloc -> configure -> `avfilter_init_str` rather
/// than `avfilter_graph_create_filter`. Likewise the buffersrc needs its
/// `hw_frames_ctx` through `av_buffersrc_parameters_set` BEFORE init, because a
/// hardware pix_fmt in the args string is rejected while `hw_frames_ctx` is null.
fn build_vaapi_graph(
    device: &BufRef,
    src_frames: &BufRef,
    cfg: &EncoderConfig,
) -> Result<Graph, EncoderError> {
    let graph_ptr = unsafe { sys::avfilter_graph_alloc() };
    if graph_ptr.is_null() {
        return Err(EncoderError::Setup("avfilter_graph_alloc null".into()));
    }
    // Own it immediately so every `?` below frees the graph.
    let mut graph = Graph {
        graph: graph_ptr,
        src: ptr::null_mut(),
        sink: ptr::null_mut(),
    };
    unsafe { (*graph.graph).nb_threads = 1 };

    let alloc = |name: &str, label: &str| -> Result<*mut sys::AVFilterContext, EncoderError> {
        let cname = cstr(name);
        let clabel = cstr(label);
        let f = unsafe { sys::avfilter_get_by_name(cname.as_ptr()) };
        if f.is_null() {
            return Err(EncoderError::Setup(format!(
                "libavfilter has no {name} filter"
            )));
        }
        let c = unsafe { sys::avfilter_graph_alloc_filter(graph_ptr, f, clabel.as_ptr()) };
        if c.is_null() {
            return Err(EncoderError::Setup(format!(
                "avfilter_graph_alloc_filter({name}) null"
            )));
        }
        Ok(c)
    };

    // --- source
    let src = alloc("buffer", "in")?;
    unsafe {
        let par = sys::av_buffersrc_parameters_alloc();
        if par.is_null() {
            return Err(EncoderError::Setup("av_buffersrc_parameters_alloc".into()));
        }
        (*par).format = sys::AVPixelFormat::AV_PIX_FMT_VAAPI as c_int;
        (*par).width = cfg.source.0 as c_int;
        (*par).height = cfg.source.1 as c_int;
        (*par).time_base = sys::AVRational {
            num: 1,
            den: 1_000_000,
        };
        (*par).frame_rate = sys::AVRational {
            num: cfg.fps.max(1) as c_int,
            den: 1,
        };
        (*par).sample_aspect_ratio = sys::AVRational { num: 1, den: 1 };
        // Full-range RGB in, so scale_vaapi's out_color_matrix is honoured
        // rather than silently falling back to the driver's BT.601 default.
        (*par).color_range = sys::AVColorRange::AVCOL_RANGE_JPEG;
        (*par).color_space = sys::AVColorSpace::AVCOL_SPC_BT709;
        (*par).hw_frames_ctx = src_frames.new_ref();
        let rc = sys::av_buffersrc_parameters_set(src, par);
        // `hw_frames_ctx` here is a reference the CALLER owns:
        // av_buffersrc_parameters_set takes its own with av_buffer_ref, and
        // av_free frees the struct without unreffing the field. Dropping it on
        // the floor pins the input AVHWFramesContext -- and its
        // initial_pool_size VA-API surfaces -- for the life of the process, on
        // every encoder open, and next_encoded() rebuilds the encoder on every
        // capture reconfigure (each toplevel resize in --window mode).
        let mut owned = (*par).hw_frames_ctx;
        sys::av_buffer_unref(&mut owned);
        sys::av_free(par as *mut c_void);
        check("av_buffersrc_parameters_set", rc)?;
    }
    check("avfilter_init_str(buffer)", unsafe {
        sys::avfilter_init_str(src, ptr::null())
    })?;

    // --- scale_vaapi: colour convert AND fit-to-receiver, one GPU pass
    let vpp = alloc("scale_vaapi", "vpp")?;
    unsafe { (*vpp).hw_device_ctx = device.new_ref() };
    let args = cstr(&format!(
        "w={}:h={}:format=nv12:out_color_matrix=bt709:out_range=tv",
        cfg.target.0, cfg.target.1
    ));
    check("avfilter_init_str(scale_vaapi)", unsafe {
        sys::avfilter_init_str(vpp, args.as_ptr())
    })?;

    // --- sink
    let sink = alloc("buffersink", "out")?;
    check("avfilter_init_str(buffersink)", unsafe {
        sys::avfilter_init_str(sink, ptr::null())
    })?;

    check("avfilter_link(in -> vpp)", unsafe {
        sys::avfilter_link(src, 0, vpp, 0)
    })?;
    check("avfilter_link(vpp -> out)", unsafe {
        sys::avfilter_link(vpp, 0, sink, 0)
    })?;
    check("avfilter_graph_config", unsafe {
        sys::avfilter_graph_config(graph.graph, ptr::null_mut())
    })?;

    graph.src = src;
    graph.sink = sink;
    Ok(graph)
}

// =============================================================== synthetic input

/// Paint one synthetic BGR0/BGRA frame into `buf` — a moving gradient, fine
/// diagonal stripes and a travelling solid box.
///
/// This exists so the encoder can be proved without a compositor: the L2 gate
/// is "400 synthetic frames in, exactly 400 access units out", and it has to be
/// reproducible on a machine with no Wayland session. The content is
/// deliberately high-entropy and genuinely moving, so motion estimation has real
/// work to do and a stuck frame would show up as a suspiciously small packet.
///
/// Byte order is B,G,R,X — the same order the capture layer's shm mapping uses,
/// so what the encoder sees here is what it sees in production.
pub fn paint_bgr0(buf: &mut [u8], width: u32, height: u32, stride: u32, t: u32) {
    let (w, h, t) = (width as i32, height as i32, t as i32);
    for y in 0..h {
        let row = &mut buf[(y as u32 * stride) as usize..][..(w as usize) * 4];
        for x in 0..w {
            let r = ((x * 255 / w + t * 3).rem_euclid(256)) as u8;
            let g = ((y * 255 / h + t * 5).rem_euclid(256)) as u8;
            let b = if (x + y - t * 6).rem_euclid(48) < 6 { 240u8 } else { 40u8 };
            let px = &mut row[(x as usize) * 4..(x as usize) * 4 + 4];
            px[0] = b;
            px[1] = g;
            px[2] = r;
            px[3] = 0;
        }
    }
    let (bw, bh) = (320i32.min(w / 4), 200i32.min(h / 4));
    let bx = (t * 17).rem_euclid((w - bw).max(1));
    let by = (t * 11).rem_euclid((h - bh).max(1));
    for y in by..by + bh {
        let row = &mut buf[(y as u32 * stride) as usize..][..(w as usize) * 4];
        for x in bx..bx + bw {
            row[(x as usize) * 4..(x as usize) * 4 + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0x00]);
        }
    }
}

// =============================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_source_to_receiver_exact_values() {
        // The real case: the 1920x1200 panel onto a 1080p receiver. 1728x1080.
        assert_eq!(fit_source_to_receiver((1920, 1200), (1920, 1080)), (1728, 1080));
        // A 720p receiver.
        assert_eq!(fit_source_to_receiver((1920, 1200), (1280, 720)), (1152, 720));
        // Milestone-1 bug #2: a 1080p source on a 1080p receiver must NOT be
        // scaled down to fit some remembered 1728-wide box.
        assert_eq!(fit_source_to_receiver((1920, 1080), (1920, 1080)), (1920, 1080));
        // Never upscale a small source onto a big receiver.
        assert_eq!(fit_source_to_receiver((1280, 800), (1920, 1080)), (1280, 800));
        // A window capture with an odd size lands on even dimensions.
        assert_eq!(fit_source_to_receiver((1884, 1125), (1920, 1080)), (1808, 1080));
    }

    #[test]
    fn extend_is_a_one_to_one_passthrough() {
        // The Extend guarantee. `virtualoutput::extend_mode` creates the
        // headless output at `fit_source_to_receiver(display, display)`, so the
        // size the compositor renders at IS the size the encoder codes at: no
        // VPP scale pass, no silent softening of UniFi Protect camera text, and
        // no wire byte that differs from Mirror.
        assert_eq!(fit_source_to_receiver((1920, 1080), (1920, 1080)), (1920, 1080));
        // And the fit is idempotent, which is what makes that true for any
        // receiver, not just this 1080p Frame.
        for d in [(1920, 1080), (3840, 2160), (3440, 1440), (1920, 1200)] {
            let created = fit_source_to_receiver(d, d);
            assert_eq!(fit_source_to_receiver(created, d), created, "not 1:1 for {d:?}");
        }
    }

    #[test]
    fn fit_respects_the_level_budget_even_when_the_receiver_is_huge() {
        // A 4K receiver cannot lift the level-4.2 macroblock ceiling: 1920x1200
        // is 9000 macroblocks and must still come down.
        let r = fit_source_to_receiver((1920, 1200), (3840, 2160));
        assert_eq!(r, (1818, 1136));
        assert_eq!(macroblocks(1920, 1200), 9000);
        assert_eq!(macroblocks(r.0, r.1), 8094);
    }

    #[test]
    fn every_fit_is_even_inside_the_budget_and_keeps_aspect() {
        let sources = [(1920, 1200), (1920, 1080), (3840, 2160), (1884, 1125), (800, 600)];
        let receivers = [(1920, 1080), (1280, 720), (3840, 2160), (1920, 1200), (640, 480)];
        for s in sources {
            for r in receivers {
                let (w, h) = fit_source_to_receiver(s, r);
                assert_eq!(w % 2, 0, "{s:?}->{r:?} gave odd width {w}");
                assert_eq!(h % 2, 0, "{s:?}->{r:?} gave odd height {h}");
                assert!(
                    macroblocks(w, h) <= MAX_MACROBLOCKS,
                    "{s:?}->{r:?} gave {w}x{h} = {} macroblocks, over {MAX_MACROBLOCKS}",
                    macroblocks(w, h)
                );
                assert!(w <= s.0 && h <= s.1, "{s:?}->{r:?} upscaled to {w}x{h}");
                let sa = s.0 as f64 / s.1 as f64;
                let da = w as f64 / h as f64;
                assert!(
                    (sa - da).abs() / sa < 0.01,
                    "{s:?}->{r:?} gave {w}x{h}, aspect {da:.4} vs source {sa:.4}"
                );
            }
        }
    }

    #[test]
    fn macroblock_count_matches_the_receiver_limit() {
        assert_eq!(macroblocks(1920, 1080), 8160); // fits 8192
        assert_eq!(macroblocks(1920, 1200), 9000); // does not
        assert_eq!(macroblocks(1728, 1080), 7344);
        assert_eq!(macroblocks(1152, 720), 3240);
    }

    #[test]
    fn scan_counts_pictures_not_slices() {
        let sc = [0u8, 0, 0, 1];
        let mut s = Vec::new();
        for nal in [
            &[0x67u8, 0xAA][..],       // SPS
            &[0x68, 0xBB][..],         // PPS
            &[0x65, 0x88, 0x02][..],   // IDR, first_mb_in_slice == 0
            &[0x65, 0x11][..],         // IDR, continuation slice
            &[0x65, 0x21][..],         // IDR, continuation slice
            &[0x41, 0x99][..],         // next picture, first slice
            &[0x41, 0x11][..],         // continuation
        ] {
            s.extend_from_slice(&sc);
            s.extend_from_slice(nal);
        }
        let scan = scan_annexb(&s);
        assert_eq!(scan.pictures, 2);
        assert_eq!(scan.vcl_nals, 5);
        assert_eq!(scan.idr_slices, 3);
        assert_eq!(scan.sps, 1);
        assert_eq!(scan.pps, 1);
        assert_eq!(scan.sei, 0);
    }

    #[test]
    fn encoder_kind_parses_both_spellings() {
        assert_eq!(EncoderKind::parse("gpu"), Some(EncoderKind::Gpu));
        assert_eq!(EncoderKind::parse("CPU"), Some(EncoderKind::Cpu));
        assert_eq!(EncoderKind::parse("vaapi"), Some(EncoderKind::Gpu));
        assert_eq!(EncoderKind::parse("x264"), Some(EncoderKind::Cpu));
        assert_eq!(EncoderKind::parse("nvenc"), None);
    }

    #[test]
    fn oversized_target_is_refused_rather_than_silently_encoded() {
        let mut cfg = EncoderConfig::new((1920, 1200), (1920, 1200));
        cfg.kind = EncoderKind::Cpu;
        match Encoder::new(cfg) {
            Err(EncoderError::Setup(m)) => assert!(
                m.contains("9000 macroblocks"),
                "wrong refusal message: {m}"
            ),
            other => panic!("expected a macroblock-budget refusal, got {other:?}", other = other.map(|_| "an open encoder")),
        }
    }

    #[test]
    fn odd_target_is_refused() {
        let mut cfg = EncoderConfig::new((1920, 1200), (1727, 1080));
        cfg.kind = EncoderKind::Cpu;
        assert!(matches!(Encoder::new(cfg), Err(EncoderError::Setup(_))));
    }
}
