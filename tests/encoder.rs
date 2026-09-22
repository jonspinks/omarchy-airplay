//! Encoder tests that need no GPU and no compositor: the `libx264` back-end,
//! driven with synthetic BGR0 frames.
//!
//! These exist mainly to nail down **milestone-1 bug #1**. `libx264 -tune
//! zerolatency` turns on sliced threads and emits many slice NALs per picture
//! (14 per frame at 1080p on this machine). Treating each slice as its own
//! access unit sent 1/14th of a picture per "frame" and the receiver rendered
//! the top band followed by noise — after the code compiled and every unit test
//! passed. So the CPU path is deliberately configured to produce a multi-slice
//! picture here, and the assertions are exact counts: the failure that got
//! through last time was hidden by `aus.len() >= 30`.
//!
//! The VA-API path is in `tests/encoder_vaapi.rs`; it needs a render node, so it
//! is `#[ignore]`d.

use airplay_rs::encoder::{
    fit_source_to_receiver, paint_bgr0, scan_annexb, Encoder, EncoderConfig, EncoderError,
    EncoderKind,
};
use airplay_rs::testpattern::split_access_units;
use airplay_rs::video::split_annexb;

/// A small frame so the whole suite stays quick; the slicing behaviour under
/// test is a property of x264's threading, not of the resolution.
const SOURCE: (u32, u32) = (640, 400);
const RECEIVER: (u32, u32) = (640, 360);

fn cpu_config(fps: u32, keyframe_seconds: f64, slices: Option<u32>) -> EncoderConfig {
    let target = fit_source_to_receiver(SOURCE, RECEIVER);
    assert_eq!(target, (576, 360), "the fit is part of what is under test");
    let mut cfg = EncoderConfig::new(SOURCE, target);
    cfg.kind = EncoderKind::Cpu;
    cfg.fps = fps;
    cfg.keyframe_seconds = keyframe_seconds;
    cfg.cpu_slices = slices;
    cfg
}

struct Synth {
    buf: Vec<u8>,
    stride: u32,
}

impl Synth {
    fn new() -> Self {
        let stride = SOURCE.0 * 4;
        Synth {
            buf: vec![0u8; (stride * SOURCE.1) as usize],
            stride,
        }
    }
    fn frame(&mut self, t: u32) -> (&[u8], u32) {
        paint_bgr0(&mut self.buf, SOURCE.0, SOURCE.1, self.stride, t);
        (&self.buf, self.stride)
    }
}

#[test]
fn a_multi_slice_picture_stays_exactly_one_access_unit() {
    const FRAMES: u32 = 30;
    const SLICES: u32 = 4;
    let mut enc = Encoder::new(cpu_config(30, 5.0, Some(SLICES))).expect("open libx264");
    let mut synth = Synth::new();
    let mut units = Vec::new();
    let mut stream = Vec::new();

    for t in 0..FRAMES {
        let ns = t as u64 * 33_333_333;
        let (px, stride) = synth.frame(t);
        for u in enc.encode(px, stride, SOURCE, ns).expect("encode") {
            stream.extend_from_slice(&u.data);
            units.push(u);
        }
    }
    for u in enc.flush().expect("flush") {
        stream.extend_from_slice(&u.data);
        units.push(u);
    }

    let stats = enc.stats();
    assert_eq!(stats.frames_in, FRAMES as u64);
    assert_eq!(stats.packets_out, FRAMES as u64, "one packet per picture");
    assert_eq!(units.len(), FRAMES as usize, "one access unit per picture");

    // The whole point: many slices, one picture, one access unit.
    assert_eq!(
        stats.vcl_nals_out,
        (FRAMES * SLICES) as u64,
        "expected {SLICES} slice NALs per picture"
    );
    assert_eq!(
        stats.pictures_out, FRAMES as u64,
        "the bitstream must contain exactly one picture per packet"
    );
    let hist: std::collections::BTreeMap<u32, usize> =
        units.iter().fold(Default::default(), |mut m, u| {
            *m.entry(u.slices).or_default() += 1;
            m
        });
    assert_eq!(
        hist,
        [(SLICES, FRAMES as usize)].into_iter().collect(),
        "slices-per-picture histogram must be exactly {{{SLICES}: {FRAMES}}}"
    );

    // And the crate's own picture-boundary rule must agree, 1:1, over the
    // concatenated stream. This is the assertion that would have caught the
    // 14x over-split: a `>= FRAMES` here is worthless.
    assert_eq!(
        split_access_units(&stream).len(),
        FRAMES as usize,
        "split_access_units disagreed with the packet count"
    );

    // Every slice of a picture must be inside its own unit, and only one of
    // them may be the first slice of the picture.
    for (i, u) in units.iter().enumerate() {
        let nals = split_annexb(&u.data);
        let vcl: Vec<&&[u8]> = nals.iter().filter(|n| matches!(n[0] & 0x1F, 1 | 5)).collect();
        assert_eq!(vcl.len(), SLICES as usize, "AU {i} has {} slices", vcl.len());
        let firsts = vcl.iter().filter(|n| n[1] & 0x80 != 0).count();
        assert_eq!(firsts, 1, "AU {i} must contain exactly one first_mb_in_slice==0 slice");
    }

    // The first unit carries the parameter sets and the IDR, in that order.
    let first: Vec<u8> = split_annexb(&units[0].data)
        .iter()
        .map(|n| n[0] & 0x1F)
        .collect();
    assert_eq!(first, vec![7, 8, 6, 5, 5, 5, 5], "AU 0 NAL types");
    assert!(units[0].is_idr && units[0].has_sps && units[0].has_pps);
    assert!(!units[1].is_idr, "AU 1 must be a P picture");
}

#[test]
fn parameter_sets_are_in_band_never_in_extradata() {
    let mut enc = Encoder::new(cpu_config(30, 5.0, Some(2))).expect("open libx264");
    assert_eq!(
        enc.info().extradata_len,
        0,
        "AV_CODEC_FLAG_GLOBAL_HEADER leaked: the receiver would never see SPS/PPS"
    );
    let mut synth = Synth::new();
    let (px, stride) = synth.frame(0);
    let units = enc.encode(px, stride, SOURCE, 0).expect("encode");
    assert_eq!(units.len(), 1);
    assert!(units[0].has_sps && units[0].has_pps && units[0].is_idr);
}

#[test]
fn idr_interval_is_wall_clock_not_a_frame_count() {
    // The distinguishing case, and the reason a 60 fps assumption is wrong: a
    // still screen yields the capture layer's 250 ms keepalives, 4 a second. The
    // encoder is configured for 60 fps and a 1 s keyframe interval, so a GOP
    // counted in FRAMES would put the second IDR 60 frames (15 seconds) away,
    // while the wall clock puts it 4 frames away. 13 frames therefore separate
    // the two answers completely: [0, 4, 8, 12] against [0].
    const FRAMES: u32 = 13;
    let mut enc = Encoder::new(cpu_config(60, 1.0, Some(2))).expect("open libx264");
    let mut synth = Synth::new();
    let mut idr_at = Vec::new();
    let mut sps_at = Vec::new();
    let mut n = 0u32;
    for t in 0..FRAMES {
        let (px, stride) = synth.frame(t);
        for u in enc
            .encode(px, stride, SOURCE, t as u64 * 250_000_000)
            .expect("encode")
        {
            if u.is_idr {
                idr_at.push(n);
            }
            if u.has_sps {
                sps_at.push(n);
            }
            n += 1;
        }
    }
    assert_eq!(n, FRAMES, "one access unit per frame");
    assert_eq!(
        idr_at,
        vec![0, 4, 8, 12],
        "IDRs must follow the wall clock (1 s at 4 frames/s), not the frame count"
    );
    assert_eq!(sps_at, idr_at, "SPS must be repeated in-band at every IDR");
}

#[test]
fn a_still_screen_keepalive_still_produces_one_access_unit_per_call() {
    // The capture layer re-emits the previous pixels every 250 ms with a fresh
    // timestamp. Re-encoding one is cheap and yields a small P picture; what
    // must NOT happen is the encoder swallowing the frame, because the receiver
    // then starves. 4 emissions per second is the real idle rate.
    let mut enc = Encoder::new(cpu_config(60, 5.0, Some(2))).expect("open libx264");
    let mut synth = Synth::new();
    let (px, stride) = synth.frame(7);
    let mut sizes = Vec::new();
    for i in 0..5u64 {
        let units = enc
            .encode(px, stride, SOURCE, i * 250_000_000)
            .expect("encode");
        assert_eq!(units.len(), 1, "keepalive {i} produced {} units", units.len());
        sizes.push(units[0].data.len());
    }
    assert!(
        sizes[0] > sizes[1..].iter().copied().max().unwrap(),
        "the IDR should dwarf the repeats, got {sizes:?}"
    );
    let stats = enc.stats();
    assert_eq!(stats.frames_in, 5);
    assert_eq!(stats.packets_out, 5);
    assert_eq!(stats.pictures_out, 5);
}

#[test]
fn force_idr_takes_effect_on_the_very_next_picture() {
    let mut enc = Encoder::new(cpu_config(60, 60.0, Some(2))).expect("open libx264");
    let mut synth = Synth::new();
    let mut kinds = Vec::new();
    for t in 0..6u32 {
        if t == 3 {
            enc.force_idr();
        }
        let (px, stride) = synth.frame(t);
        for u in enc
            .encode(px, stride, SOURCE, t as u64 * 16_666_666)
            .expect("encode")
        {
            kinds.push(u.is_idr);
        }
    }
    assert_eq!(
        kinds,
        vec![true, false, false, true, false, false],
        "a forced IDR must appear at exactly the frame it was asked for"
    );
    assert_eq!(enc.stats().forced_idr, 1);
}

#[test]
fn the_cpu_fallback_produces_the_stream_shape_milestone_1_proved_on_the_tv() {
    // Deliberately pinned: the milestone-1 test pattern went through
    // `-preset ultrafast -tune zerolatency`, which turns CABAC off, so the
    // stream probes as Constrained Baseline even though `profile=high` is
    // requested (the option is a ceiling, not a floor). That exact shape was
    // decoded by a real Samsung Frame, so it stays until something proves
    // otherwise -- but it is asserted, not assumed.
    let enc = Encoder::new(cpu_config(60, 5.0, None)).expect("open libx264");
    let opts: std::collections::BTreeMap<&str, &str> = enc
        .info()
        .options
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(opts.get("preset"), Some(&"ultrafast"));
    assert_eq!(opts.get("tune"), Some(&"zerolatency"));
    assert_eq!(opts.get("profile"), Some(&"high"));
    assert_eq!(opts.get("level"), Some(&"4.2"));
    assert_eq!(opts.get("qp"), Some(&"25"));
    assert_eq!(
        opts.get("x264-params"),
        Some(&"keyint=300:min-keyint=300:bframes=0:repeat-headers=1:annexb=1:scenecut=0")
    );
}

#[test]
fn a_frame_of_the_wrong_size_or_length_is_refused() {
    let mut enc = Encoder::new(cpu_config(60, 5.0, Some(2))).expect("open libx264");
    let stride = SOURCE.0 * 4;
    let buf = vec![0u8; (stride * SOURCE.1) as usize];
    assert!(matches!(
        enc.encode(&buf, stride, (1920, 1200), 0),
        Err(EncoderError::FormatChanged { .. })
    ));
    assert!(matches!(
        enc.encode(&buf[..buf.len() - 4], stride, SOURCE, 0),
        Err(EncoderError::ShortFrame { .. })
    ));
    assert_eq!(enc.stats().frames_in, 0, "a refused frame must not be counted");
}

#[test]
fn the_synthetic_painter_writes_bgr0_in_the_capture_layers_byte_order() {
    // If this is backwards then every visual check downstream is inverted and
    // nobody notices until a human looks at the TV.
    let (w, h, t) = (64u32, 64u32, 1u32);
    let mut buf = vec![0u8; (w * 4 * h) as usize];
    paint_bgr0(&mut buf, w, h, w * 4, t);
    // x=0,y=0: r = 0*255/64 + 3 = 3, g = 0 + 5 = 5, and (0+0-6).rem_euclid(48)
    // = 42, so no stripe -> background blue 40. The travelling box is at
    // (17,11) for t=1, well clear of the origin.
    assert_eq!(&buf[0..4], &[40, 5, 3, 0], "bytes are B,G,R,X (bgr0)");
    // x=8,y=0: (8-6) = 2 < 6 -> stripe, blue 240; r = 8*255/64 + 3 = 34.
    assert_eq!(&buf[32..36], &[240, 5, 34, 0]);
}

#[test]
fn scan_agrees_with_split_access_units_on_real_encoder_output() {
    // Cross-check the two independent implementations of the picture-boundary
    // rule against a real multi-slice stream, rather than against a synthetic
    // NAL soup.
    let mut enc = Encoder::new(cpu_config(30, 5.0, Some(3))).expect("open libx264");
    let mut synth = Synth::new();
    let mut stream = Vec::new();
    for t in 0..12u32 {
        let (px, stride) = synth.frame(t);
        for u in enc
            .encode(px, stride, SOURCE, t as u64 * 33_333_333)
            .expect("encode")
        {
            stream.extend_from_slice(&u.data);
        }
    }
    let scan = scan_annexb(&stream);
    assert_eq!(scan.pictures, 12);
    assert_eq!(scan.vcl_nals, 36, "3 slices x 12 pictures");
    assert_eq!(scan.sps, 1);
    assert_eq!(scan.pps, 1);
    assert_eq!(scan.idr_slices, 3, "the first picture's three slices");
    assert_eq!(split_access_units(&stream).len(), scan.pictures as usize);
}

/// The zero-copy input stage is a GPU-only thing, and asking for it on the
/// software back-end has to fail loudly at open. libx264 has no way to read a
/// DRM buffer, so the alternative to an error is a silent CPU copy — which is
/// exactly the sort of quiet degradation that ships unnoticed.
#[test]
fn the_cpu_back_end_refuses_dmabuf_input_instead_of_quietly_copying() {
    let mut cfg = cpu_config(60, 5.0, Some(2));
    cfg.dmabuf_input = true;
    let msg = match Encoder::new(cfg) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("libx264 must not open with a dmabuf input stage"),
    };
    assert!(msg.contains("gpu back-end"), "unhelpful message: {msg}");
}
