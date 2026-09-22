//! Live capture tests. These need a running Wayland compositor that speaks
//! `ext-image-copy-capture-v1` (Hyprland 0.56.2 here), so they are `#[ignore]`d
//! and run explicitly:
//!
//! ```text
//! mise exec -- cargo test --test capture_live -- --ignored --nocapture
//! ```
//!
//! The output defaults to `eDP-1`; override with `AIRPLAY_CAPTURE_OUTPUT`.
//!
//! Every assertion here is an exact value or an exact count. The milestone-1
//! lesson is that `aus.len() >= 30` let a 14x over-split through, so there are
//! deliberately no `frames >= N` style assertions: an idle screen legitimately
//! produces no fresh frames at all, and the thing that must hold regardless is
//! that the iterator still yields exactly what was asked for.

use std::time::{Duration, Instant};

use airplay_rs::capture::{
    self, BufferMode, Capture, CaptureConfig, CaptureSource, FrameKind, PixelFormat, ZeroCopy,
};

fn wanted_output() -> String {
    std::env::var("AIRPLAY_CAPTURE_OUTPUT").unwrap_or_else(|_| "eDP-1".to_string())
}

/// Cheap content fingerprint over a strided sample, used to prove that a
/// keepalive really re-emits the previous frame and not a torn or empty buffer.
fn fingerprint(pixels: &[u8]) -> (u64, usize) {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut nonzero = 0usize;
    for &b in pixels.iter().step_by(997) {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
        if b != 0 {
            nonzero += 1;
        }
    }
    (h, nonzero)
}

#[test]
#[ignore = "needs a live wayland compositor with ext-image-copy-capture-v1"]
fn live_capture_yields_exactly_the_frames_asked_for() {
    const N: usize = 60;
    let want = wanted_output();

    let inv = capture::list().expect("enumerate wayland outputs");
    let out = inv
        .outputs
        .iter()
        .find(|o| o.name == want)
        .unwrap_or_else(|| panic!("no output named {want:?}; found {:?}", inv.outputs));
    println!("output {want}: {}x{} @ {} mHz", out.width, out.height, out.refresh_mhz);

    // Explicitly the shm path: this test reads pixels, and the whole point of
    // the zero-copy path is that there are none to read.
    let mut cfg = CaptureConfig::new(CaptureSource::Output(want.clone()));
    cfg.zero_copy = ZeroCopy::Off;
    let mut cap = Capture::open(cfg).expect("open capture session");
    assert_eq!(cap.buffer_mode(), BufferMode::Shm);
    assert_eq!(cap.buffer_count(), 2, "the shm path ping-pongs between exactly two buffers");
    let fmt = cap.format();
    println!("session: {fmt:?} ({} bytes)", fmt.len());

    // buffer_size is the PHYSICAL mode size. eDP-1 runs at scale 1.5 here, and
    // the capture is 1920x1200, not the 1280x800 logical size — which is why
    // fitting to the receiver is mandatory (1920x1200 is 9000 macroblocks, over
    // the Frame's 8192 limit).
    assert_eq!(
        (fmt.width, fmt.height),
        (out.width as u32, out.height as u32),
        "buffer_size must equal the output's physical mode size"
    );
    assert_eq!(fmt.format, PixelFormat::Xrgb8888);
    assert_eq!(fmt.stride, fmt.width * 4);
    assert_eq!(fmt.len(), fmt.stride as usize * fmt.height as usize);

    // The dmabuf constraints are what the zero-copy layer will need; assert
    // they actually arrived rather than discovering later that they did not.
    let dma = cap.dmabuf_constraints().clone();
    let device = dma.device.expect("session advertised no dmabuf_device");
    let (major, minor) = capture::dev_major_minor(device);
    println!("dmabuf device {major}:{minor}, {} format(s)", dma.formats.len());
    assert!(
        dma.formats.iter().any(|(f, mods)| *f == PixelFormat::Xrgb8888.drm_fourcc()
            && mods.contains(&0)),
        "expected XR24 + LINEAR among the dmabuf formats, got {:?}",
        dma.formats
            .iter()
            .map(|(f, _)| capture::fourcc_name(*f))
            .collect::<Vec<_>>()
    );

    let mut kinds: Vec<FrameKind> = Vec::with_capacity(N);
    let mut prints: Vec<(u64, usize)> = Vec::with_capacity(N);
    let mut prev_ts = 0u64;
    let mut first_ts = 0u64;

    for i in 0..N {
        let f = cap.next_frame().expect("next_frame");
        let pixels = f.data.shm().expect("this session was opened on the shm path");
        assert_eq!(pixels.len(), fmt.len(), "frame {i} has the wrong buffer length");
        assert_eq!((f.width, f.height, f.stride), (fmt.width, fmt.height, fmt.stride));
        assert_eq!(f.format, fmt.format);
        assert_eq!(f.transform, 0, "frame {i}: unexpected buffer transform");
        assert!(
            f.timestamp_ns > prev_ts,
            "frame {i}: timestamp {} did not advance past {prev_ts}",
            f.timestamp_ns
        );
        prev_ts = f.timestamp_ns;
        if i == 0 {
            first_ts = f.timestamp_ns;
        }

        let fp = fingerprint(pixels);
        if f.kind == FrameKind::Repeat {
            assert_eq!(
                fp,
                *prints.last().unwrap(),
                "frame {i}: a keepalive must re-emit the previous frame unchanged"
            );
        }
        prints.push(fp);
        kinds.push(f.kind);
    }

    // The first capture in a session completes immediately by spec (the
    // "wait for the source to change" rule applies only afterwards).
    assert_eq!(kinds[0], FrameKind::Fresh);
    // A captured screen that is entirely zero means the copy silently did
    // nothing — the exact failure a frame count would hide. (A blanked or
    // locked screen will legitimately fail this; unlock and re-run.)
    assert!(prints[0].1 > 0, "the first captured frame is entirely black");

    // Timestamps are CLOCK_MONOTONIC, the same clock the compositor's
    // presentation_time uses, so "now" must be at or past the last one.
    let now = capture::monotonic_ns();
    assert!(
        prev_ts <= now && now - first_ts < 120_000_000_000,
        "timestamps are not in the CLOCK_MONOTONIC domain: first {first_ts}, last {prev_ts}, now {now}"
    );

    let s = cap.stats();
    println!("stats: {s:?}");
    assert_eq!(kinds.len(), N);
    assert_eq!(s.fresh + s.repeats, N as u64, "every emission must be counted exactly once");
    assert_eq!(
        s.fresh as usize,
        kinds.iter().filter(|k| **k == FrameKind::Fresh).count()
    );
    assert_eq!(
        s.repeats as usize,
        kinds.iter().filter(|k| **k == FrameKind::Repeat).count()
    );
    assert_eq!(s.failures, 0, "capture failures");
    assert_eq!(s.session_restarts, 0, "the session should not have stopped");
}

#[test]
#[ignore = "needs a live wayland compositor with ext-image-copy-capture-v1"]
fn live_keepalive_feeds_the_receiver_while_the_screen_is_still() {
    const N: usize = 30;
    let mut cfg = CaptureConfig::new(CaptureSource::Output(wanted_output()));
    // 5 ms instead of the production 250 ms so the test is quick; the code path
    // is identical.
    cfg.keepalive = Duration::from_millis(5);
    cfg.zero_copy = ZeroCopy::Off;

    let mut cap = Capture::open(cfg).expect("open capture session");
    let started = Instant::now();
    for i in 0..N {
        let f = cap.next_frame().expect("next_frame");
        let len = f.data.shm().expect("shm path").len();
        assert_eq!(len, cap.format().len(), "frame {i}");
    }
    let elapsed = started.elapsed();
    let s = cap.stats();
    println!("{N} frames in {elapsed:?}: {s:?}");

    assert_eq!(s.fresh + s.repeats, N as u64);
    assert_eq!(s.failures, 0);
    // Without the keepalive these 30 frames would be damage-limited: 30 vblanks
    // is 500 ms at 60 Hz, and on a still screen it is unbounded. Finishing well
    // inside that is what proves the re-emit path fired.
    assert!(
        elapsed < Duration::from_millis(300),
        "{N} frames took {elapsed:?}; the keepalive did not fire"
    );
}

/// The zero-copy path, end to end at the capture layer.
///
/// This asserts the two invariants that make handing a compositor buffer
/// straight to the encoder sound, and they are invariants rather than
/// thresholds: a fresh frame never lands in the buffer that was just handed
/// out, and a keepalive repeat always re-emits exactly the buffer before it.
/// Get either wrong and the encoder reads a buffer the compositor is
/// concurrently blitting into — which would look like tearing on the TV and
/// like nothing at all in a test that only counted frames.
#[test]
#[ignore = "needs a live wayland compositor with ext-image-copy-capture-v1 and a DRM render node"]
fn zero_copy_capture_hands_out_linear_dmabufs_and_never_reuses_a_live_one() {
    const N: usize = 40;
    let mut cfg = CaptureConfig::new(CaptureSource::Output(wanted_output()));
    cfg.zero_copy = ZeroCopy::On;
    cfg.keepalive = Duration::from_millis(20);

    let mut cap = Capture::open(cfg).expect("open a dmabuf capture session");
    assert_eq!(
        cap.buffer_mode(),
        BufferMode::Dmabuf,
        "ZeroCopy::On must not fall back: {:?}",
        cap.zero_copy_note()
    );
    assert_eq!(cap.buffer_count(), 4, "the zero-copy set is exactly four buffers");
    assert_eq!(cap.zero_copy_note(), None);
    let fmt = cap.format();
    println!("session: {fmt:?} on {} dmabufs", cap.buffer_count());

    // (id, kind) for each emitted frame, so the rotation can be checked exactly.
    let mut seen: Vec<(u64, FrameKind)> = Vec::with_capacity(N);
    let mut ids = std::collections::BTreeSet::new();
    let mut prev_ts = 0u64;

    for i in 0..N {
        let f = cap.next_frame().expect("next_frame");
        assert!(
            f.data.shm().is_none(),
            "frame {i}: the zero-copy path must not produce a CPU mapping"
        );
        let image = f.data.dmabuf().expect("a dmabuf handle").clone();

        assert_eq!((image.width, image.height), (fmt.width, fmt.height), "frame {i}");
        assert_eq!(image.stride, fmt.stride, "frame {i}");
        assert_eq!(
            image.modifier,
            capture::DRM_FORMAT_MOD_LINEAR,
            "frame {i}: only LINEAR is ever negotiated — a tiled buffer is the \
             gpu-screen-recorder failure"
        );
        assert_eq!(image.fourcc, PixelFormat::Xrgb8888.drm_fourcc(), "frame {i}");
        assert!(
            image.size >= (image.stride as usize) * (image.height as usize),
            "frame {i}: the object is smaller than the picture it claims to hold"
        );
        assert!(image.fd() >= 0, "frame {i}");
        assert_eq!((f.width, f.height, f.stride), (fmt.width, fmt.height, fmt.stride));
        assert_eq!(f.format, fmt.format);
        assert!(f.timestamp_ns > prev_ts, "frame {i}: PTS did not advance");
        prev_ts = f.timestamp_ns;

        if let Some(&(prev_id, _)) = seen.last() {
            match f.kind {
                // The capture target is chosen from the buffers nobody holds,
                // and the front buffer is always excluded.
                FrameKind::Fresh => assert_ne!(
                    image.id, prev_id,
                    "frame {i}: a fresh capture landed in the buffer just handed out"
                ),
                // A keepalive is the SAME buffer again, by definition.
                FrameKind::Repeat => assert_eq!(
                    image.id, prev_id,
                    "frame {i}: a keepalive must re-emit the previous buffer"
                ),
            }
        }
        ids.insert(image.id);
        seen.push((image.id, f.kind));
    }

    let s = cap.stats();
    println!("{N} frames: {s:?}, distinct buffers used {}", ids.len());
    assert_eq!(s.fresh + s.repeats, N as u64);
    assert_eq!(s.failures, 0);
    assert_eq!(s.zero_copy_fallbacks, 0, "ZeroCopy::On never falls back");
    assert_eq!(s.reallocations, 0);
    assert_eq!(s.session_restarts, 0);
    assert!(
        ids.len() <= cap.buffer_count(),
        "more distinct buffers ({}) than the set holds",
        ids.len()
    );
    assert_eq!(
        seen.iter().filter(|(_, k)| *k == FrameKind::Fresh).count() as u64,
        s.fresh,
        "the emitted kinds must agree with the counters"
    );
}

/// `ZeroCopy::Off` is not just a preference: it must produce a session with no
/// dmabuf machinery in it at all.
#[test]
#[ignore = "needs a live wayland compositor with ext-image-copy-capture-v1"]
fn zero_copy_off_gives_the_two_buffer_shm_session() {
    let mut cfg = CaptureConfig::new(CaptureSource::Output(wanted_output()));
    cfg.zero_copy = ZeroCopy::Off;
    let mut cap = Capture::open(cfg).expect("open capture session");
    assert_eq!(cap.buffer_mode(), BufferMode::Shm);
    assert_eq!(cap.buffer_count(), 2);
    assert_eq!(cap.zero_copy_note(), None, "nothing failed; nothing was asked for");
    let f = cap.next_frame().expect("next_frame");
    assert!(f.data.dmabuf().is_none());
    assert_eq!(f.data.shm().expect("shm pixels").len(), cap.format().len());
    assert_eq!(cap.stats().zero_copy_fallbacks, 0);
}
