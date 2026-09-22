//! VA-API encoder tests. These need a DRM render node with an H.264 encode
//! entrypoint (`/dev/dri/renderD128`, intel-media-driver here), so they are
//! `#[ignore]`d and run explicitly:
//!
//! ```text
//! mise exec -- cargo test --test encoder_vaapi -- --ignored --nocapture
//! ```
//!
//! Override the node with `AIRPLAY_VAAPI_DEVICE`.
//!
//! Every count below is exact. A 120-frame run cannot show the second IDR of a
//! 5 s keyframe interval at 60 fps, which is why the main run is 400 frames:
//! the libva spike found a DPB bug that a single-GOP test sailed straight past,
//! and a lower-bound assertion here would do the same thing.

use std::process::Command;

use airplay_rs::encoder::{
    fit_source_to_receiver, macroblocks, paint_bgr0, probe_low_power, scan_annexb, Encoder,
    EncoderConfig, EncoderKind, MAX_MACROBLOCKS,
};
use airplay_rs::testpattern::split_access_units;

/// The real shape of this machine: the eDP-1 capture buffer onto a 1080p Frame.
const SOURCE: (u32, u32) = (1920, 1200);
const RECEIVER: (u32, u32) = (1920, 1080);
const TARGET: (u32, u32) = (1728, 1080);

fn device() -> String {
    std::env::var("AIRPLAY_VAAPI_DEVICE").unwrap_or_else(|_| "/dev/dri/renderD128".to_string())
}

fn gpu_config(frames_per_second: u32, keyframe_seconds: f64) -> EncoderConfig {
    let target = fit_source_to_receiver(SOURCE, RECEIVER);
    assert_eq!(target, TARGET);
    let mut cfg = EncoderConfig::new(SOURCE, target);
    cfg.kind = EncoderKind::Gpu;
    cfg.fps = frames_per_second;
    cfg.keyframe_seconds = keyframe_seconds;
    cfg.device = device();
    cfg
}

#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn four_hundred_frames_give_exactly_four_hundred_single_slice_access_units() {
    const FRAMES: u32 = 400;
    const FPS: u32 = 60;
    let mut enc = Encoder::new(gpu_config(FPS, 5.0)).expect("open h264_vaapi");

    let info = enc.info().clone();
    println!("opened {} -> {:?}", info.codec, info.target);
    for (k, v) in &info.options {
        println!("  opt {k} = {v}");
    }
    assert_eq!(info.target, TARGET);
    assert_eq!(info.macroblocks, 7344);
    assert!(info.macroblocks <= MAX_MACROBLOCKS);
    assert_eq!(
        info.extradata_len, 0,
        "parameter sets must be in-band only; extradata means the receiver never gets them"
    );
    // Read back from the opened context, not from what was requested.
    let opts: std::collections::BTreeMap<&str, &str> = info
        .options
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(opts["rc_mode"], "1", "1 == CQP; CBR/VBR pad an idle desktop");
    assert_eq!(opts["qp"], "25");
    assert_eq!(opts["sei"], "0x00000000", "no SEI means no HRD and no pic_struct");
    assert_eq!(opts["async_depth"], "1", "the encoder must hold zero frames");
    assert_eq!(opts["profile"], "100", "High");
    assert_eq!(opts["level"], "42", "4.2");
    assert_eq!(opts["idr_interval"], "0", "every I frame must be an IDR");

    let stride = SOURCE.0 * 4;
    let mut buf = vec![0u8; (stride * SOURCE.1) as usize];
    let mut stream = Vec::new();
    let mut idr_at = Vec::new();
    let mut sps_at = Vec::new();
    let mut pps_at = Vec::new();
    let mut hist: std::collections::BTreeMap<u32, usize> = Default::default();
    let mut n = 0u32;
    let mut first_packet_after = None;

    for t in 0..FRAMES {
        paint_bgr0(&mut buf, SOURCE.0, SOURCE.1, stride, t);
        let units = enc
            .encode(&buf, stride, SOURCE, t as u64 * (1_000_000_000 / FPS as u64))
            .expect("encode");
        if !units.is_empty() && first_packet_after.is_none() {
            first_packet_after = Some(t);
        }
        for u in units {
            *hist.entry(u.slices).or_default() += 1;
            if u.is_idr {
                idr_at.push(n);
            }
            if u.has_sps {
                sps_at.push(n);
            }
            if u.has_pps {
                pps_at.push(n);
            }
            stream.extend_from_slice(&u.data);
            n += 1;
        }
    }
    let tail = enc.flush().expect("flush");

    // async_depth=1 means the packet for frame 0 comes back from frame 0, and
    // there is nothing left to flush at the end.
    assert_eq!(first_packet_after, Some(0), "async_depth=1 must hold zero frames");
    assert!(tail.is_empty(), "async_depth=1 left {} frames queued", tail.len());

    let stats = enc.stats();
    println!(
        "stages (mean): upload {:.3} ms | convert+scale {:.3} ms | encode {:.3} ms",
        stats.upload_us as f64 / FRAMES as f64 / 1e3,
        stats.convert_us as f64 / FRAMES as f64 / 1e3,
        stats.encode_us as f64 / FRAMES as f64 / 1e3
    );
    assert_eq!(stats.frames_in, FRAMES as u64);
    assert_eq!(stats.packets_out, FRAMES as u64);
    assert_eq!(n, FRAMES, "one access unit per picture");
    assert_eq!(stats.pictures_out, FRAMES as u64);
    assert_eq!(stats.vcl_nals_out, FRAMES as u64);
    assert_eq!(
        hist,
        [(1u32, FRAMES as usize)].into_iter().collect(),
        "h264_vaapi emits ONE slice per picture; anything else changes the AU rule"
    );
    assert_eq!(idr_at, vec![0, 300], "5 s at 60 fps is an IDR at 0 and 300, exactly");
    assert_eq!(sps_at, vec![0, 300], "SPS must be repeated in-band at every IDR");
    assert_eq!(pps_at, vec![0, 300]);
    assert_eq!(stats.sei_out, 0, "sei=0 must leave no SEI NALs at all");

    let whole = scan_annexb(&stream);
    assert_eq!(whole.pictures, FRAMES);
    assert_eq!(whole.sei, 0);
    assert_eq!(whole.aud, 0, "aud=0");
    assert_eq!(
        split_access_units(&stream).len(),
        FRAMES as usize,
        "the crate's own picture-boundary rule must agree 1:1 with the packet count"
    );
}

#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn the_decoded_picture_lands_where_the_fit_says_it_should() {
    // The cheapest stand-in for the TV, and the one that would have caught both
    // milestone-1 bugs: encode a frame whose content is known exactly, decode it
    // back, and check the geometry and the colours in pixels.
    const FPS: u32 = 60;
    const T: u32 = 60;
    let mut enc = Encoder::new(gpu_config(FPS, 5.0)).expect("open h264_vaapi");
    let stride = SOURCE.0 * 4;
    let mut buf = vec![0u8; (stride * SOURCE.1) as usize];
    let mut stream = Vec::new();
    for t in 0..=T {
        paint_bgr0(&mut buf, SOURCE.0, SOURCE.1, stride, t);
        for u in enc
            .encode(&buf, stride, SOURCE, t as u64 * (1_000_000_000 / FPS as u64))
            .expect("encode")
        {
            stream.extend_from_slice(&u.data);
        }
    }

    let dir = std::env::temp_dir();
    let h264 = dir.join(format!("airplay-enc-{}.h264", std::process::id()));
    let rgb = dir.join(format!("airplay-enc-{}.rgb", std::process::id()));
    std::fs::write(&h264, &stream).expect("write stream");

    // Decode with `-err_detect explode`: a stream that merely "plays" is not
    // enough, the decoder must find nothing wrong with it.
    let out = Command::new("ffmpeg")
        .args(["-v", "error", "-err_detect", "explode", "-y", "-i"])
        .arg(&h264)
        .args([
            "-vf",
            &format!("select=eq(n\\,{T})"),
            "-vframes",
            "1",
            "-pix_fmt",
            "rgb24",
            "-f",
            "rawvideo",
        ])
        .arg(&rgb)
        .output()
        .expect("run ffmpeg (needed to decode the encoder's own output)");
    assert!(
        out.status.success() && out.stderr.is_empty(),
        "decode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let px = std::fs::read(&rgb).expect("read decoded frame");
    let _ = std::fs::remove_file(&h264);
    let _ = std::fs::remove_file(&rgb);

    let (w, h) = (TARGET.0 as usize, TARGET.1 as usize);
    assert_eq!(px.len(), w * h * 3, "decoded frame is not {w}x{h} rgb24");
    let at = |x: usize, y: usize| -> (u8, u8, u8) {
        let i = (y * w + x) * 3;
        (px[i], px[i + 1], px[i + 2])
    };

    // The travelling white box at t=60 is at (1020,660) size 320x200 in the
    // 1920x1200 source, so at 1728x1080 it must be at (918,594) size 288x180.
    let longest_white_run = |y: usize| -> (usize, usize) {
        let (mut run, mut start, mut best) = (0usize, 0usize, (0usize, 0usize));
        for x in 0..w {
            let (r, g, b) = at(x, y);
            if r > 235 && g > 235 && b > 235 {
                if run == 0 {
                    start = x;
                }
                run += 1;
                if run > best.0 {
                    best = (run, start);
                }
            } else {
                run = 0;
            }
        }
        best
    };
    let rows: Vec<usize> = (0..h).filter(|&y| longest_white_run(y).0 > 200).collect();
    assert_eq!(
        (rows.first().copied(), rows.last().copied()),
        (Some(594), Some(773)),
        "the white box's vertical span is wrong: the fit-scale is off, or the frame is cropped"
    );
    let (len, start) = longest_white_run(rows[rows.len() / 2]);
    assert_eq!(
        (start, len),
        (918, 288),
        "the white box's horizontal span is wrong"
    );

    // Colour order: BGR0 in, so a pixel painted with a high blue must decode
    // blue, not red. QP25 on a fine stripe pattern moves values a little, hence
    // the tolerance -- but a channel swap is a ~200 error, not a 12 one.
    for (x, y) in [(100usize, 100usize), (900, 200), (1600, 900)] {
        let sx = x * SOURCE.0 as usize / w;
        let sy = y * SOURCE.1 as usize / h;
        let want = (
            ((sx * 255 / SOURCE.0 as usize + (T as usize) * 3) % 256) as i32,
            ((sy * 255 / SOURCE.1 as usize + (T as usize) * 5) % 256) as i32,
            if (sx as i32 + sy as i32 - (T as i32) * 6).rem_euclid(48) < 6 {
                240
            } else {
                40
            },
        );
        let got = at(x, y);
        let d = (
            (got.0 as i32 - want.0).abs(),
            (got.1 as i32 - want.1).abs(),
            (got.2 as i32 - want.2).abs(),
        );
        assert!(
            d.0 < 40 && d.1 < 40 && d.2 < 60,
            "pixel ({x},{y}) decoded {got:?} but was painted {want:?} -- channel order?"
        );
    }
}

#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn low_power_is_reported_rather_than_assumed() {
    // The milestone brief names "VA-API + low_power + async_depth=1" as the
    // target. On this driver there is no VAEntrypointEncSliceLP for any profile
    // and avcodec_open2 hard-fails with ENOSYS -- it does not degrade. The
    // encoder therefore never passes low_power, and this test asserts only that
    // the question is asked and answered, so a future driver that grows the
    // entrypoint shows up as a changed line of output rather than a surprise.
    let available = probe_low_power(&device(), TARGET, 60);
    println!("VAEntrypointEncSliceLP for H.264 High: {available}");

    let mut cfg = gpu_config(60, 5.0);
    cfg.probe_low_power = true;
    let enc = Encoder::new(cfg).expect("the encoder must open WITHOUT low_power either way");
    assert_eq!(enc.info().low_power_available, Some(available));
    assert!(
        !enc.info().options.iter().any(|(k, _)| k == "low_power"),
        "low_power must never be passed to the encoder"
    );
}

#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn a_1080p_source_on_a_1080p_receiver_is_not_needlessly_scaled() {
    // Milestone-1 bug #2, in the encoder rather than in a helper: the coded size
    // must come from the receiver, not from the 1728 that a previous run
    // happened to produce.
    let target = fit_source_to_receiver((1920, 1080), (1920, 1080));
    assert_eq!(target, (1920, 1080));
    assert_eq!(macroblocks(1920, 1080), 8160);
    let mut cfg = EncoderConfig::new((1920, 1080), target);
    cfg.kind = EncoderKind::Gpu;
    cfg.device = device();
    let mut enc = Encoder::new(cfg).expect("open h264_vaapi at 1920x1080");
    assert_eq!(enc.info().target, (1920, 1080));

    let stride = 1920 * 4;
    let mut buf = vec![0u8; stride * 1080];
    paint_bgr0(&mut buf, 1920, 1080, stride as u32, 3);
    let units = enc
        .encode(&buf, stride as u32, (1920, 1080), 0)
        .expect("encode");
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].slices, 1);
    assert!(units[0].is_idr && units[0].has_sps);
}

#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn the_sps_is_byte_exact_so_a_profile_change_cannot_happen_quietly() {
    // The receiver advertises avc1.64002a. Our SPS is 67 64 0c 2a, i.e.
    // avc1.640c2a: constraint_set4 and constraint_set5 are set, meaning
    // frame_mbs_only and no-B-slices. Those are STRICTLY STRONGER constraints,
    // so a conforming High@4.2 decoder must accept the stream -- but milestone 1
    // was exactly a case of this TV accepting something and rendering black, so
    // the bytes are pinned here and the session layer keeps an escape hatch: the
    // constraint byte sits at a fixed offset (immediately after profile_idc,
    // before level_idc) and zeroing it shifts no subsequent bit offsets.
    let mut enc = Encoder::new(gpu_config(60, 5.0)).expect("open h264_vaapi");
    let stride = SOURCE.0 * 4;
    let mut buf = vec![0u8; (stride * SOURCE.1) as usize];
    paint_bgr0(&mut buf, SOURCE.0, SOURCE.1, stride, 0);
    let units = enc.encode(&buf, stride, SOURCE, 0).expect("encode");
    assert_eq!(units.len(), 1);

    let nals = airplay_rs::video::split_annexb(&units[0].data);
    let sps = nals
        .iter()
        .find(|n| n[0] & 0x1F == 7)
        .expect("the first access unit must carry an SPS");
    assert_eq!(
        &sps[..4],
        &[0x67, 0x64, 0x0c, 0x2a],
        "SPS header changed: profile_idc/constraint flags/level_idc are \
         nal=0x67 profile=100(High) constraints=0x0c(set4|set5) level=42(4.2), \
         which is codec string avc1.640c2a"
    );
    // And the avcC the mirror channel will actually send is built from those
    // same three bytes, so a change here changes what the receiver is told.
    let pps = nals.iter().find(|n| n[0] & 0x1F == 8).expect("PPS");
    let avcc = airplay_rs::video::build_avcc(sps, pps);
    assert_eq!(&avcc[..4], &[1, 0x64, 0x0c, 0x2a]);
}

#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn a_still_screen_costs_almost_nothing_which_is_why_the_rate_control_is_cqp() {
    // The capture layer emits the previous frame every 250 ms when nothing
    // moves. Each one must still come back as exactly one access unit -- a
    // swallowed keepalive starves the receiver -- and under CQP the repeats
    // must collapse to nearly nothing. CBR/VBR pad an idle desktop to 6.13 and
    // 1.98 Mb/s respectively; that padding is what "felt laggy over Wi-Fi".
    const KEEPALIVES: u64 = 20;
    let mut enc = Encoder::new(gpu_config(60, 60.0)).expect("open h264_vaapi");
    let stride = SOURCE.0 * 4;
    let mut buf = vec![0u8; (stride * SOURCE.1) as usize];
    paint_bgr0(&mut buf, SOURCE.0, SOURCE.1, stride, 11);

    let mut sizes = Vec::new();
    for i in 0..KEEPALIVES {
        let units = enc
            .encode(&buf, stride, SOURCE, i * 250_000_000)
            .expect("encode");
        assert_eq!(units.len(), 1, "keepalive {i} produced {} units", units.len());
        assert_eq!(units[0].slices, 1);
        sizes.push(units[0].data.len());
    }
    let idr = sizes[0];
    let repeats: u64 = sizes[1..].iter().map(|&n| n as u64).sum();
    let mean_repeat = repeats as f64 / (KEEPALIVES - 1) as f64;
    println!(
        "idle: IDR {idr} B, mean repeat {mean_repeat:.0} B -> {:.3} Mb/s at 4 keepalives/s",
        mean_repeat * 4.0 * 8.0 / 1e6
    );
    assert_eq!(enc.stats().packets_out, KEEPALIVES);
    assert_eq!(enc.stats().pictures_out, KEEPALIVES);
    assert_eq!(enc.stats().idr_out, 1, "only the first picture is an IDR here");
    assert!(
        mean_repeat * 100.0 < idr as f64,
        "a repeated frame under CQP should be <1% of the IDR; got {mean_repeat:.0} B vs {idr} B \
         (padding means the rate control is not CQP)"
    );
}

/// An encoder built for `av_hwframe_map` must refuse a CPU mapping, and one
/// built for uploads must refuse a dmabuf.
///
/// This is the wiring the pipeline relies on when the capture layer falls back
/// from dmabuf to shm mid-stream: it rebuilds the encoder on the kind change,
/// and this test is what makes a missed rebuild an error rather than a picture
/// that is subtly wrong.
#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn an_encoder_only_accepts_the_input_kind_it_was_built_for() {
    let mut cfg = gpu_config(60, 5.0);
    cfg.dmabuf_input = true;
    let mut enc = Encoder::new(cfg).expect("open h264_vaapi with a DRM->VAAPI import stage");
    assert!(enc.info().dmabuf_input);
    // The graph really did come up around the derived frames context.
    assert_eq!(enc.info().target, TARGET);
    assert_eq!(enc.info().extradata_len, 0);

    let stride = SOURCE.0 * 4;
    let buf = vec![0u8; (stride * SOURCE.1) as usize];
    let err = enc
        .encode(&buf, stride, SOURCE, 0)
        .expect_err("a dmabuf encoder must refuse a CPU mapping");
    assert!(
        err.to_string().contains("dmabuf input"),
        "unhelpful message: {err}"
    );
    assert_eq!(enc.stats().frames_in, 0, "a refused frame must not be counted");

    // And the other way round.
    let mut upload = match Encoder::new(gpu_config(60, 5.0)) {
        Ok(e) => e,
        Err(e) => panic!("open h264_vaapi: {e}"),
    };
    assert!(!upload.info().dmabuf_input);
    assert_eq!(
        upload.encode(&buf, stride, SOURCE, 0).expect("a real frame").len(),
        1,
        "the upload encoder still works"
    );
}

/// Read this process's resident set, in kB.
fn vm_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .expect("/proc/self/status")
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next().and_then(|n| n.parse().ok()))
        .expect("VmRSS line")
}

/// Opening and dropping an encoder must return everything it took.
///
/// `build_vaapi_graph` hands `av_buffersrc_parameters_set` a NEW reference to
/// the filter's input `AVHWFramesContext` and then frees only the parameters
/// struct, which does not drop that reference — so the frames context, its
/// VA-API surface pool and the device behind it stayed alive for the life of the
/// process, at ~1 MB of host RSS per open (plus GPU memory the RSS never shows).
/// A mirror session rebuilds its encoder on every capture renegotiation, so this
/// is a per-resize leak, not a one-off.
#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn opening_and_dropping_encoders_does_not_leak_the_hardware_frames_context() {
    // RSS is a PROCESS number, so any other test allocating in parallel lands in
    // it: measured alongside the colour test this read +12 MB of "leak" that was
    // a 9.2 MB source buffer in another thread. Re-run this one test in a child
    // of its own, where the only thing allocating is the encoder.
    const CHILD: &str = "AIRPLAY_LEAK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let exe = std::env::current_exe().expect("this test binary's path");
        let out = Command::new(exe)
            .args([
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "opening_and_dropping_encoders_does_not_leak_the_hardware_frames_context",
            ])
            .env(CHILD, "1")
            .output()
            .expect("re-run this test in a child process");
        print!("{}", String::from_utf8_lossy(&out.stdout));
        assert!(
            out.status.success(),
            "the isolated run failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    const OPENS: usize = 12;
    let mut rss_after: Vec<u64> = Vec::new();
    for _ in 0..OPENS {
        {
            let enc = Encoder::new(gpu_config(60, 5.0)).expect("open h264_vaapi");
            std::hint::black_box(enc.info().macroblocks);
        }
        rss_after.push(vm_rss_kb());
    }
    // From the SECOND open onwards: the first one pays for libva, the driver's
    // shared objects and the allocator's first arenas, none of which is a leak.
    let base = rss_after[1] as i64;
    let last = rss_after[OPENS - 1] as i64;
    let growth = last - base;
    println!(
        "rss after each open (kB): {rss_after:?} -> {growth} kB over {} opens",
        OPENS - 2
    );
    assert!(
        growth < 2048,
        "{growth} kB of RSS growth over {} encoder opens ({:.0} kB each) — the \
         input AVHWFramesContext reference is being leaked again",
        OPENS - 2,
        growth as f64 / (OPENS - 2) as f64
    );
}

/// The pixels must be BT.709 limited AND the bitstream must say so.
///
/// Untagged, `matrix_coefficients` reads "unspecified" and every modern receiver
/// resolves that at HD frame size to BT.709 — so BT.601 pixels (swscale's and
/// iHD's default) reach the TV with a 709 inverse applied: greys stay right
/// while saturated greens and reds shift hue and lose saturation. It compiles,
/// every count test passes, and it only shows on the screen. This checks the
/// conversion and the declaration separately, because either one alone is the
/// bug.
#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn the_conversion_is_bt709_limited_and_the_vui_declares_it() {
    const FPS: u32 = 60;
    const T: u32 = 60;
    let mut enc = Encoder::new(gpu_config(FPS, 5.0)).expect("open h264_vaapi");
    let stride = SOURCE.0 * 4;
    let mut buf = vec![0u8; (stride * SOURCE.1) as usize];
    let mut stream = Vec::new();
    for t in 0..=T {
        paint_bgr0(&mut buf, SOURCE.0, SOURCE.1, stride, t);
        for u in enc
            .encode(&buf, stride, SOURCE, t as u64 * (1_000_000_000 / FPS as u64))
            .expect("encode")
        {
            stream.extend_from_slice(&u.data);
        }
    }
    // `buf` still holds the frame that was encoded last, which is the one
    // decoded below: the prediction is computed from the very same pixels.

    let dir = std::env::temp_dir();
    let h264 = dir.join(format!("airplay-colour-{}.h264", std::process::id()));
    let yuv = dir.join(format!("airplay-colour-{}.yuv", std::process::id()));
    std::fs::write(&h264, &stream).expect("write stream");

    // --- what the bitstream DECLARES, read back with ffprobe.
    let probe = Command::new("ffprobe")
        .args([
            "-v", "error", "-select_streams", "v:0", "-show_entries",
            "stream=color_range,color_space,color_primaries,color_transfer",
            "-of", "default=noprint_wrappers=1",
        ])
        .arg(&h264)
        .output()
        .expect("run ffprobe");
    let probe = String::from_utf8_lossy(&probe.stdout).to_string();
    println!("VUI: {}", probe.replace('\n', " "));
    for want in ["color_range=tv", "color_space=bt709"] {
        assert!(
            probe.contains(want),
            "the SPS VUI must carry {want}; ffprobe says:\n{probe}"
        );
    }

    // --- what the PIXELS are, decoded back.
    let out = Command::new("ffmpeg")
        .args(["-v", "error", "-err_detect", "explode", "-y", "-i"])
        .arg(&h264)
        .args([
            "-vf",
            &format!("select=eq(n\\,{T})"),
            "-vframes",
            "1",
            "-pix_fmt",
            "yuv420p",
            "-f",
            "rawvideo",
        ])
        .arg(&yuv)
        .output()
        .expect("run ffmpeg");
    assert!(
        out.status.success() && out.stderr.is_empty(),
        "decode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let px = std::fs::read(&yuv).expect("read decoded frame");
    let _ = std::fs::remove_file(&h264);
    let _ = std::fs::remove_file(&yuv);

    let (w, h) = (TARGET.0 as usize, TARGET.1 as usize);
    assert_eq!(px.len(), w * h * 3 / 2, "decoded frame is not {w}x{h} yuv420p");
    let y_at = |x: usize, y: usize| px[y * w + x] as f64;
    let u_at = |x: usize, y: usize| px[w * h + (y / 2) * (w / 2) + x / 2] as f64;
    let v_at = |x: usize, y: usize| px[w * h + (w / 2) * (h / 2) + (y / 2) * (w / 2) + x / 2] as f64;

    // The travelling white box at t=60 covers (918,594)..(1206,774) in the coded
    // picture. Well inside it, full white must land on LIMITED-range white:
    // 235/128/128. Full range would read 255, and the receiver would clip.
    let (mut ys, mut us, mut vs, mut n) = (0.0, 0.0, 0.0, 0.0);
    for y in 620..750 {
        for x in 950..1180 {
            ys += y_at(x, y);
            us += u_at(x, y);
            vs += v_at(x, y);
            n += 1.0;
        }
    }
    let (wy, wu, wv) = (ys / n, us / n, vs / n);
    println!("white box: Y {wy:.2} U {wu:.2} V {wv:.2} (limited-range white is 235/128/128)");
    assert!(
        (wy - 235.0).abs() < 1.5,
        "white decoded to Y {wy:.2}, not the limited-range 235 — the range is wrong"
    );
    assert!(
        (wu - 128.0).abs() < 1.5 && (wv - 128.0).abs() < 1.5,
        "white decoded to U {wu:.2} V {wv:.2}, not neutral 128/128"
    );

    // Which MATRIX produced the luma, predicted from the source pixels that
    // were actually encoded. The two matrices differ by ~7 over this region;
    // scaling is linear, so the region mean survives it.
    let y0 = 400usize;
    let sy0 = y0 * SOURCE.1 as usize / h;
    let (mut p601, mut p709, mut m) = (0.0f64, 0.0f64, 0.0f64);
    for sy in sy0..SOURCE.1 as usize {
        let row = sy * stride as usize;
        for sx in 0..SOURCE.0 as usize {
            let (b, g, r) = (
                buf[row + sx * 4] as f64,
                buf[row + sx * 4 + 1] as f64,
                buf[row + sx * 4 + 2] as f64,
            );
            // Full-range RGB in, limited-range Y out — what the VPP is told.
            p601 += 16.0 + (0.2568 * r + 0.5041 * g + 0.0979 * b);
            p709 += 16.0 + (0.1826 * r + 0.6142 * g + 0.0620 * b);
            m += 1.0;
        }
    }
    let (p601, p709) = (p601 / m, p709 / m);
    let (mut got, mut k) = (0.0f64, 0.0f64);
    for y in y0..h {
        for x in 0..w {
            got += y_at(x, y);
            k += 1.0;
        }
    }
    let got = got / k;
    println!(
        "rows {y0}..{h}: decoded mean Y {got:.3} | BT.709 predicts {p709:.3} | \
         BT.601 predicts {p601:.3}"
    );
    assert!(
        (p709 - p601).abs() > 3.0,
        "this picture cannot tell the two matrices apart ({p709:.3} vs {p601:.3})"
    );
    assert!(
        (got - p709).abs() < 2.0,
        "decoded mean Y {got:.3} is not BT.709's {p709:.3} (BT.601 would be \
         {p601:.3}) — the conversion stage is converting with the wrong matrix"
    );
}

// ======================================================= zero-copy stride

/// The dmabuf stride shear, in one test.
///
/// A window 1256 logical pixels wide on a scale-1.5 monitor captures at 1884
/// physical pixels, whose tightly packed stride is 1884*4 = 7536 — NOT a
/// multiple of 64. `av_hwframe_map(DRM_PRIME -> VAAPI, DIRECT)` silently
/// substitutes a pitch of its own for one it does not like, and the decoded
/// picture comes out diagonally sheared: every row displaced sideways a little
/// further than the one above it, which turns text into diagonal streaks.
///
/// This shipped for two milestones because every test used a 1920-wide source,
/// where 1920*4 = 7680 is aligned by accident. So the width here is the point
/// of the test, and the assertions are on decoded PIXELS, because the geometry,
/// the sizes and the counters are all perfectly correct while the picture is
/// ruined.
///
/// The comparison is the two paths against each other: the same painted frame
/// encoded from a dmabuf and from a CPU buffer must decode to the same picture.
/// The shm path is the control — it goes through `av_hwframe_transfer_data`,
/// which honours any linesize, which is why `--zero-copy off` was always right.
#[test]
#[ignore = "needs a VA-API render node with an H.264 encode entrypoint"]
fn a_non_aligned_width_decodes_the_same_through_dmabuf_and_shm() {
    use airplay_rs::capture::{allocate_dmabuf, PixelFormat, STRIDE_HONOURED_ALIGN};

    // 1884x1125: the real shape of a 1256x750 window on a scale-1.5 panel.
    const SRC: (u32, u32) = (1884, 1125);
    // Frame T is decoded; the frames before it give the decoder a P-frame
    // chain to walk, as a real stream would.
    const T: u32 = 8;
    const FPS: u32 = 60;

    let tight = SRC.0 * 4;
    assert_eq!(tight, 7536);
    assert!(
        !tight.is_multiple_of(STRIDE_HONOURED_ALIGN) && !tight.is_multiple_of(256),
        "this test is pointless unless {tight} is a stride the VA-API import will NOT \
         honour: a 1920-wide source (7680, aligned by accident) proves nothing"
    );

    let target = fit_source_to_receiver(SRC, RECEIVER);
    assert_eq!(target, (1808, 1080));

    let node = device();
    let dma = match allocate_dmabuf(std::path::Path::new(&node), SRC.0, SRC.1, PixelFormat::Xrgb8888)
    {
        Ok(d) => d,
        Err(e) => panic!("allocate a linear dmabuf on {node}: {e}"),
    };
    let image = &dma.image;
    println!("dmabuf: {image:?}");
    assert_eq!((image.width, image.height), SRC, "the image must describe the real picture");
    assert!(image.stride >= tight, "stride {} cannot hold a {}-pixel row", image.stride, SRC.0);

    // --- paint the picture into the dmabuf through a CPU mapping.
    //
    // Production never does this (the compositor's GPU blit fills the buffer),
    // and a CPU fill needs care the blit does not. The care is all inside
    // `StandaloneDmabuf::with_cpu_map`, which is a gbm mapping and not an
    // mmap of the PRIME fd for a measured reason: on this hardware an mmap of
    // the fd is a write-back CACHED mapping, `DMA_BUF_IOCTL_SYNC(SYNC_END)`
    // does not write those lines back, and the GPU then reads a drifting mix
    // of painted pixels and the buffer's initial zeros — black dashes that
    // changed from frame to frame and made nine encodes of one static picture
    // cost 661511 bytes instead of 179127.
    //
    // The paint and the read-back are therefore two separate maps: the second
    // begins after `gbm_bo_unmap` finished the first, so what it reads is what
    // the GPU will read, and it is not a private cached copy of our own
    // writes. That read-back is the precondition for everything below — the
    // buffer holds exactly the intended picture, so any difference later is
    // the encoder's input stage.
    //
    // Painted ONCE, before the first encode, then encoded T+1 times: repainting
    // a single buffer the GPU is still reading races it (production rotates
    // four for exactly that reason), and the shear is a property of the pitch,
    // not of the content moving.
    dma.with_cpu_map(|gpu, stride| paint_bgr0(gpu, SRC.0, SRC.1, stride, T))
        .expect("map the dmabuf (needed to paint a known picture into it)");
    let wrong = dma
        .with_cpu_map(|gpu, stride| {
            let mut want = vec![0u8; stride as usize * SRC.1 as usize];
            paint_bgr0(&mut want, SRC.0, SRC.1, stride, T);
            (0..SRC.1 as usize)
                .flat_map(|y| {
                    let row = y * stride as usize;
                    row..row + tight as usize
                })
                .filter(|&i| gpu[i] != want[i])
                .count()
        })
        .expect("map the dmabuf again (to read back what the GPU will see)");
    assert_eq!(wrong, 0, "the dmabuf does not hold the painted picture");

    let mut cfg = EncoderConfig::new(SRC, target);
    cfg.kind = EncoderKind::Gpu;
    cfg.fps = FPS;
    cfg.keyframe_seconds = 5.0;
    cfg.device = node.clone();
    cfg.dmabuf_input = true;
    let mut enc = Encoder::new(cfg).expect("open h264_vaapi for dmabuf input");
    let mut dmabuf_stream = Vec::new();
    for t in 0..=T {
        for u in enc
            .encode_dmabuf(image, SRC, t as u64 * (1_000_000_000 / FPS as u64))
            .expect("encode_dmabuf")
        {
            dmabuf_stream.extend_from_slice(&u.data);
        }
    }
    drop(enc);

    // --- the control: the same picture in a CPU buffer at the TIGHT stride,
    // which is what an shm capture really hands over, through the upload path.
    let mut cfg = EncoderConfig::new(SRC, target);
    cfg.kind = EncoderKind::Gpu;
    cfg.fps = FPS;
    cfg.keyframe_seconds = 5.0;
    cfg.device = node.clone();
    let mut enc = Encoder::new(cfg).expect("open h264_vaapi for shm input");
    let mut cpu = vec![0u8; tight as usize * SRC.1 as usize];
    paint_bgr0(&mut cpu, SRC.0, SRC.1, tight, T);
    let mut shm_stream = Vec::new();
    for t in 0..=T {
        for u in enc
            .encode(&cpu, tight, SRC, t as u64 * (1_000_000_000 / FPS as u64))
            .expect("encode")
        {
            shm_stream.extend_from_slice(&u.data);
        }
    }
    drop(enc);

    let (w, h) = (target.0 as usize, target.1 as usize);
    let from_dmabuf = decode_frame_rgb24(&dmabuf_stream, T, target, "dmabuf");
    let from_shm = decode_frame_rgb24(&shm_stream, T, target, "shm");

    // --- 1. the two pictures must be the same picture.
    //
    // Both encoders saw identical pixels at QP 25, so the only thing that can
    // make them differ is the input stage. Measured with the fix and the gbm
    // mapping above, over the whole gated suite run back to back: 0.000 every
    // time — the two annex-b streams come out byte for byte identical. (The
    // bound stays at 2.0 rather than 0.0 because what is being asserted is
    // "the same picture", not "the same bitstream".) A shear moves the whole
    // stripe pattern sideways and measures far above the bound: 49.823 with
    // the stride padding and the two alignment refusals taken back out.
    let (mut sum, mut worst, mut worst_at) = (0.0f64, 0i32, (0usize, 0usize));
    for y in 0..h {
        for x in 0..w {
            let i = (y * w + x) * 3;
            for c in 0..3 {
                let d = (from_dmabuf[i + c] as i32 - from_shm[i + c] as i32).abs();
                sum += d as f64;
                if d > worst {
                    worst = d;
                    worst_at = (x, y);
                }
            }
        }
    }
    let mean = sum / (w * h * 3) as f64;
    println!("dmabuf vs shm: mean abs error {mean:.3} per channel, worst {worst} at {worst_at:?}");

    // --- 2. and the dmabuf picture must be the RIGHT picture, not merely one
    // that agrees with the control. Predicted from `paint_bgr0`: the white box
    // at t=8 is at (136,88) size 320x200 in the 1884x1125 source, so at
    // 1808x1080 its left edge is at x = 136*1808/1884 = 130.5, and it spans
    // rows 88*0.96 = 84.5 .. 288*0.96 = 276.5.
    let longest_white_run = |px: &[u8], y: usize| -> (usize, usize) {
        let (mut run, mut start, mut best) = (0usize, 0usize, (0usize, 0usize));
        for x in 0..w {
            let i = (y * w + x) * 3;
            if px[i] > 235 && px[i + 1] > 235 && px[i + 2] > 235 {
                if run == 0 {
                    start = x;
                }
                run += 1;
                if run > best.0 {
                    best = (run, start);
                }
            } else {
                run = 0;
            }
        }
        best
    };
    // Every row inside the box must start at the SAME x: a shear is exactly
    // the failure of that. Rows 90..270 are well inside the predicted span.
    let starts: Vec<usize> = (90..270)
        .map(|y| longest_white_run(&from_dmabuf, y))
        .filter(|&(len, _)| len > 200)
        .map(|(_, start)| start)
        .collect();
    let on_edge = starts.iter().filter(|&&s| (128..=133).contains(&s)).count();
    println!(
        "white box: {} of 180 rows found, {on_edge} start at x 128..=133 (predicted 130.5)",
        starts.len()
    );

    assert!(
        mean < 2.0,
        "the zero-copy picture does not match the shm picture (mean abs error {mean:.3} per \
         channel, worst {worst} at {worst_at:?}). A progressive sideways displacement per row \
         is the dmabuf stride being re-interpreted by the VA-API import"
    );
    assert!(
        on_edge >= 175,
        "only {on_edge} of the 180 rows inside the white box start at its predicted left edge \
         (x 128..=133) in the zero-copy picture: its edge wanders row by row, which is a \
         sheared frame"
    );

    // --- 3. the mechanism. Last, so that on unfixed code the test fails on
    // the pictures above rather than on a number.
    assert!(
        image.stride.is_multiple_of(STRIDE_HONOURED_ALIGN),
        "dmabuf stride {} is not a multiple of {STRIDE_HONOURED_ALIGN}; the VA-API import \
         will read it at a pitch of its own and shear the picture",
        image.stride
    );
}

/// Decode frame `n` of an annex-b stream to rgb24, with `-err_detect explode`
/// so a stream that merely plays is not good enough.
fn decode_frame_rgb24(stream: &[u8], n: u32, size: (u32, u32), tag: &str) -> Vec<u8> {
    let dir = std::env::temp_dir();
    let h264 = dir.join(format!("airplay-{tag}-{}.h264", std::process::id()));
    let rgb = dir.join(format!("airplay-{tag}-{}.rgb", std::process::id()));
    std::fs::write(&h264, stream).expect("write stream");
    let out = Command::new("ffmpeg")
        .args(["-v", "error", "-err_detect", "explode", "-y", "-i"])
        .arg(&h264)
        .args([
            "-vf",
            &format!("select=eq(n\\,{n})"),
            "-vframes",
            "1",
            "-pix_fmt",
            "rgb24",
            "-f",
            "rawvideo",
        ])
        .arg(&rgb)
        .output()
        .expect("run ffmpeg (needed to decode the encoder's own output)");
    assert!(
        out.status.success() && out.stderr.is_empty(),
        "decoding the {tag} stream failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let px = std::fs::read(&rgb).expect("read decoded frame");
    let _ = std::fs::remove_file(&h264);
    let _ = std::fs::remove_file(&rgb);
    assert_eq!(
        px.len(),
        size.0 as usize * size.1 as usize * 3,
        "the decoded {tag} frame is not {}x{} rgb24",
        size.0,
        size.1
    );
    px
}
