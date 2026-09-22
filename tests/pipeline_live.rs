//! Live join tests: Wayland capture -> hardware encode -> `MirrorStreamer`.
//!
//! These need a running compositor that speaks `ext-image-copy-capture-v1` AND a
//! VA-API render node with an H.264 encode entrypoint, so they are `#[ignore]`d:
//!
//! ```text
//! mise exec -- cargo test --test pipeline_live -- --ignored --nocapture
//! ```
//!
//! Override the source with `AIRPLAY_CAPTURE_OUTPUT` (default `eDP-1`).
//!
//! # What these assert, and what they deliberately do not
//!
//! An idle desktop produces no fresh frames at all, so there is no honest lower
//! bound on the frame count from a fresh capture, and none is asserted against
//! one. That blind spot is exactly where a pacing bug hid: the loop measured its
//! next due time from the END of the encode, so the achieved period was
//! `frame_gap + service_time` and `--fps 60` delivered ~43. So one test here
//! DOES assert a real frame rate, by making the frames itself — it turns the
//! capture layer's keepalive up to ~125 Hz so a frame is always available
//! without touching the user's screen, and then requires the achieved rate to be
//! the requested one. See
//! [`the_pacing_loop_hits_the_requested_fps_instead_of_self_throttling`].
//!
//! What IS exact regardless of how still the screen is:
//!
//! * the frame ledger closes: `produced == dropped + encoded + pending`;
//! * one access unit per encode, one picture per packet, one slice per picture
//!   on the GPU back-end;
//! * SPS and PPS appear in-band at exactly the IDRs and nowhere else;
//! * zero SEI NALs;
//! * every forwarded unit re-scans to the same structure the encoder reported.
//!
//! That last point is the milestone-1 lesson in test form: `aus.len() >= 30` let
//! a 14x over-split through, so nothing here is a threshold.

use airplay_rs::capture::CaptureSource;
use airplay_rs::encoder;
use airplay_rs::pipeline::{run_stream, PipelineConfig, RunOptions, ScreenPipeline};
use airplay_rs::video::{MirrorStreamer, VideoCipher};

fn source() -> CaptureSource {
    CaptureSource::Output(std::env::var("AIRPLAY_CAPTURE_OUTPUT").unwrap_or_else(|_| "eDP-1".into()))
}

/// Stands in for the receiver's data socket. Counts what the mirror channel
/// would have put on the wire so the cipher and header path really run.
#[derive(Default)]
struct CountingSink {
    bytes: u64,
    writes: u64,
}

impl std::io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes += buf.len() as u64;
        self.writes += 1;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn streamer(w: u32, h: u32) -> MirrorStreamer<CountingSink> {
    MirrorStreamer::new(
        CountingSink::default(),
        VideoCipher::ChaCha20Poly1305,
        &[0x5au8; 64],
        0x0123_4567_89ab_cdef,
        &[0x3cu8; 16],
        w,
        h,
        0.075,
    )
}

#[test]
#[ignore = "needs a live wayland compositor and a VA-API H.264 encode entrypoint"]
fn the_join_forwards_exactly_one_access_unit_per_encoded_picture() {
    let receiver = (1920, 1080);
    let mut cfg = PipelineConfig::new(source(), receiver);
    cfg.fps = 60;

    let mut pipe = ScreenPipeline::start(cfg).expect("start the pipeline");
    let (sw, sh) = pipe.source_size();
    let (tw, th) = pipe.target_size();
    println!("capturing {} : {sw}x{sh} -> {tw}x{th}", pipe.label());

    // The fit is computed from the live capture size, never a remembered number.
    assert_eq!(
        (tw, th),
        encoder::fit_source_to_receiver((sw, sh), receiver),
        "the coded size must be fit_source_to_receiver of the ACTUAL capture size"
    );
    assert!(
        encoder::macroblocks(tw, th) <= encoder::MAX_MACROBLOCKS,
        "{tw}x{th} is {} macroblocks, over the level-4.2 budget",
        encoder::macroblocks(tw, th)
    );
    assert_eq!(tw % 2, 0, "NV12 needs an even width");
    assert_eq!(th % 2, 0, "NV12 needs an even height");
    assert_eq!(
        pipe.encoder_info().extradata_len,
        0,
        "parameter sets must be in-band only"
    );

    // Tap every forwarded unit so the bitstream can be re-scanned end to end.
    let mut tap: Vec<u8> = Vec::new();
    let mut sink = streamer(tw, th);
    let run = run_stream(&mut pipe, &mut sink, &RunOptions::new(6.0), Some(&mut tap))
        .expect("run the stream");
    let wire = sink.sink().bytes;
    let stats = pipe.finish();

    println!(
        "forwarded {} AUs ({} IDR, {} repeats), ledger {}={}+{}+{}, {wire} wire bytes",
        run.access_units,
        run.idr_units,
        run.repeat_units,
        stats.produced,
        stats.dropped,
        stats.encoded,
        stats.pending
    );

    // --- the frame ledger closes exactly. No frame is invented or lost.
    assert_eq!(
        stats.produced,
        stats.dropped + stats.encoded + stats.pending,
        "every captured frame is either dropped as stale, encoded, or still in the mailbox"
    );
    assert!(stats.pending <= 1, "the mailbox holds one frame, never a queue");

    // --- one unit per encode, one picture per packet.
    assert_eq!(stats.encoded, run.access_units, "one AU forwarded per encode");
    assert_eq!(stats.encoder.packets_out, stats.encoded);
    assert_eq!(
        stats.encoder.pictures_out, stats.encoder.packets_out,
        "a packet holding 0 or 2+ pictures is the milestone-1 bug"
    );
    assert_eq!(
        stats.encoder.vcl_nals_out, run.access_units,
        "h264_vaapi emits exactly one slice per picture"
    );
    assert_eq!(stats.encoder.sei_out, 0, "sei=0 means no SEI NALs at all");
    assert_eq!(stats.encoder.sps_out, run.idr_units, "SPS in-band at every IDR");
    assert_eq!(stats.encoder.pps_out, run.idr_units, "PPS in-band at every IDR");
    assert_eq!(stats.encoder.idr_out, run.idr_units);
    assert_eq!(stats.reconfigures, 0, "nothing resized during the test");
    assert_eq!(stats.capture.failures, 0);

    // --- the tapped bitstream agrees with the counters, independently.
    let whole = encoder::scan_annexb(&tap);
    assert_eq!(
        whole.pictures as u64, run.access_units,
        "re-scanning the forwarded stream must find the same picture count"
    );
    assert_eq!(whole.vcl_nals as u64, run.access_units);
    assert_eq!(whole.sps as u64, run.idr_units);
    assert_eq!(whole.pps as u64, run.idr_units);
    assert_eq!(whole.sei, 0);
    assert_eq!(whole.aud, 0, "aud=0 means no access-unit delimiters");
    assert_eq!(tap.len() as u64, run.bytes);

    // --- the streamer really wrote. The exact write count pins a behaviour that
    // is easy to get wrong in the reconfigure path: `forward_access_unit` emits
    // a codec packet once per DISTINCT parameter-set pair, not once per IDR. A
    // steady stream therefore sends SPS/PPS to the receiver exactly once however
    // many keyframes it contains.
    assert!(wire > run.bytes, "the wire carries the payload plus headers");
    let distinct_param_sets = {
        let nals = airplay_rs::video::split_annexb(&tap);
        let mut seen: std::collections::BTreeSet<(Vec<u8>, Vec<u8>)> = Default::default();
        let mut sps: Option<Vec<u8>> = None;
        for n in nals {
            match n[0] & 0x1F {
                7 => sps = Some(n.to_vec()),
                8 => {
                    if let Some(s) = &sps {
                        seen.insert((s.clone(), n.to_vec()));
                    }
                }
                _ => {}
            }
        }
        seen.len() as u64
    };
    assert_eq!(
        distinct_param_sets, 1,
        "every IDR in one run must repeat the SAME SPS/PPS"
    );
    assert_eq!(
        sink.sink().writes,
        run.access_units + distinct_param_sets + run.heartbeats,
        "one write per frame (header + sealed body in a single packet), one per \
         codec packet, one per heartbeat — the probe's `sendall(header + body)`, \
         not a header segment followed by a body segment"
    );

    // --- the capture layer's own accounting, cross-checked.
    assert_eq!(
        stats.capture.fresh + stats.capture.repeats,
        stats.produced,
        "every published frame was either a fresh capture or a keepalive repeat"
    );
    // Every keepalive the capture layer emitted is accounted for: sent, or
    // superseded in the mailbox by something newer, or still sitting in it.
    // Nothing else can have happened to one, and nothing invents one.
    //
    // The earlier form of this asserted `repeat_units == capture.repeats`, which
    // silently assumed a repeat is never the frame that gets dropped. That is
    // false as soon as the capture layer outruns the consumer — it held only
    // because the shm path was slow enough to hide it.
    assert_eq!(
        stats.capture.repeats,
        run.repeat_units + stats.dropped_repeats + stats.pending_repeat,
        "an idle receiver is fed by keepalives and nothing else, so every one \
         must be sent, superseded, or pending"
    );
    assert!(
        stats.dropped_repeats <= stats.dropped,
        "more repeats dropped than frames dropped"
    );
}

/// The pacing loop must deliver the fps it was asked for.
///
/// A still desktop damages nothing, so the frames here come from the capture
/// layer's own keepalive with its interval turned down to 8 ms: that is a real
/// capture, a real dmabuf import and a real hardware encode per frame, at a rate
/// the pipeline cannot outrun, and it needs no damage on the user's screen.
///
/// The number is asserted, not printed. `>= anything` is what let the loop pace
/// from the end of the encode — 5.6 ms of service time on top of a 16.67 ms gap
/// is 43 fps, and every structural test still passed.
#[test]
#[ignore = "needs a live wayland compositor and a VA-API H.264 encode entrypoint"]
fn the_pacing_loop_hits_the_requested_fps_instead_of_self_throttling() {
    const FPS: u32 = 60;
    let mut cfg = PipelineConfig::new(source(), (1920, 1080));
    cfg.fps = FPS;
    cfg.capture.keepalive = std::time::Duration::from_millis(8);

    let mut pipe = ScreenPipeline::start(cfg).expect("start the pipeline");
    let (tw, th) = pipe.target_size();
    let mut sink = streamer(tw, th);
    let run = run_stream(&mut pipe, &mut sink, &RunOptions::new(5.0), None).expect("run");
    let stats = pipe.finish();

    let supply = stats.produced as f64 / run.seconds;
    println!(
        "asked {FPS} fps, got {:.2} fps ({} AUs in {:.2} s); the capture supplied \
         {supply:.1} frames/s, encode p95 {:.2} ms",
        run.fps(),
        run.access_units,
        run.seconds,
        stats.latency_ms.2
    );

    // The premise first: if the source could not supply 60 frames/s this test
    // would be measuring the compositor, not the pacing.
    assert!(
        supply >= FPS as f64,
        "the capture only supplied {supply:.1} frames/s, so this cannot say \
         anything about pacing"
    );
    assert!(
        run.fps() >= FPS as f64 - 2.0,
        "asked for {FPS} fps with frames always available and got {:.2} — the \
         loop is pacing from the end of the encode again",
        run.fps()
    );
    assert!(
        run.fps() <= FPS as f64 + 1.0,
        "{:.2} fps is faster than the {FPS} fps asked for: the pacing tick is \
         not being honoured",
        run.fps()
    );
    assert_eq!(
        stats.produced,
        stats.dropped + stats.encoded + stats.pending,
        "the ledger must still close at full rate"
    );
    assert_eq!(stats.capture.failures, 0);
}

#[test]
#[ignore = "needs a live wayland compositor and a VA-API H.264 encode entrypoint"]
fn a_slow_consumer_drops_stale_frames_instead_of_queueing_them() {
    // The capture layer emits a keepalive repeat every 250 ms, so even a
    // perfectly still screen produces 4 frames/s. Asking for 1 fps therefore
    // guarantees the producer outruns the consumer, which is the condition the
    // newest-wins mailbox exists for.
    let mut cfg = PipelineConfig::new(source(), (1920, 1080));
    cfg.fps = 1;

    let mut pipe = ScreenPipeline::start(cfg).expect("start the pipeline");
    let (tw, th) = pipe.target_size();
    let mut sink = streamer(tw, th);
    let run = run_stream(&mut pipe, &mut sink, &RunOptions::new(6.0), None).expect("run");
    let stats = pipe.finish();

    println!(
        "1 fps for {:.1}s: produced {} dropped {} encoded {} pending {}",
        run.seconds, stats.produced, stats.dropped, stats.encoded, stats.pending
    );

    assert_eq!(
        stats.produced,
        stats.dropped + stats.encoded + stats.pending,
        "the ledger must close even when most frames are discarded"
    );
    assert_ne!(
        stats.dropped, 0,
        "a 1 fps consumer against a >=4 fps keepalive MUST be discarding frames; \
         if it is not, the capture thread is being throttled by the encoder"
    );
    assert_eq!(
        stats.encoded, run.access_units,
        "dropping happens in the mailbox, never between encode and the wire"
    );
    assert_eq!(stats.encoder.sei_out, 0);
    assert_eq!(stats.capture.failures, 0);
}

#[test]
#[ignore = "needs a live wayland compositor and a VA-API H.264 encode entrypoint"]
fn the_sps_constraint_escape_hatch_changes_four_bytes_and_nothing_else() {
    let mut cfg = PipelineConfig::new(source(), (1920, 1080));
    cfg.fps = 60;

    // Two short runs, identical but for the flag. Only the SPS may differ.
    let mut plain: Vec<u8> = Vec::new();
    let mut pipe = ScreenPipeline::start(cfg.clone()).expect("start");
    let (tw, th) = pipe.target_size();
    let mut sink = streamer(tw, th);
    run_stream(&mut pipe, &mut sink, &RunOptions::new(2.0), Some(&mut plain)).expect("run");
    pipe.finish();

    let mut zeroed: Vec<u8> = Vec::new();
    let mut pipe = ScreenPipeline::start(cfg).expect("start");
    let mut sink = streamer(tw, th);
    let mut opts = RunOptions::new(2.0);
    opts.sps_zero_constraints = true;
    run_stream(&mut pipe, &mut sink, &opts, Some(&mut zeroed)).expect("run");
    pipe.finish();

    let sps_of = |s: &[u8]| -> Vec<u8> {
        let i = s
            .windows(4)
            .position(|w| w == [0x00, 0x00, 0x01, 0x67])
            .expect("an SPS in-band");
        s[i + 3..i + 7].to_vec()
    };
    let a = sps_of(&plain);
    let b = sps_of(&zeroed);
    println!("SPS plain {a:02x?} -> zeroed {b:02x?}");

    // The exact bytes, pinned. A profile or level change cannot happen quietly.
    assert_eq!(a, vec![0x67, 0x64, 0x0c, 0x2a], "avc1.640c2a");
    assert_eq!(b, vec![0x67, 0x64, 0x00, 0x2a], "avc1.64002a, what the Frame advertises");
    assert_eq!(a[1], b[1], "profile_idc must not move");
    assert_eq!(a[3], b[3], "level_idc must not move: the edit shifts no bit offsets");
    assert!(!plain.is_empty() && !zeroed.is_empty(), "both runs produced a stream");
}

/// The L5 gate: the zero-copy path must change the pipeline's COST and nothing
/// else about its OUTPUT.
///
/// Two runs of the same pipeline differing only in where the pixels come from.
/// Everything structural is asserted equal between them — including the SPS and
/// PPS byte for byte, which is the strongest available statement that the
/// receiver cannot tell the two apart. The only thing allowed to differ is the
/// per-frame import cost, and that is asserted too, because a zero-copy path
/// that silently degraded to an upload would pass every other assertion here.
#[test]
#[ignore = "needs a live wayland compositor, a DRM render node and a VA-API H.264 encode entrypoint"]
fn zero_copy_and_shm_produce_the_same_stream_and_only_the_import_cost_differs() {
    use airplay_rs::capture::{BufferMode, ZeroCopy};

    /// Everything about a run that must not depend on the buffer kind.
    #[derive(Debug, PartialEq, Eq)]
    struct Shape {
        target: (u32, u32),
        extradata_len: usize,
        access_units: u64,
        encoded: u64,
        packets: u64,
        pictures: u64,
        vcl_nals: u64,
        sei: u64,
        sps: u64,
        pps: u64,
        idr: u64,
        reconfigures: u64,
        capture_failures: u64,
        parameter_sets: Vec<Vec<u8>>,
    }

    let run_once = |zero_copy: ZeroCopy| -> (Shape, BufferMode, f64, u64) {
        let mut cfg = PipelineConfig::new(source(), (1920, 1080));
        cfg.fps = 60;
        cfg.capture.zero_copy = zero_copy;
        let mut pipe = ScreenPipeline::start(cfg).expect("start the pipeline");
        let mode = pipe.buffer_mode();
        assert_eq!(
            pipe.encoder_info().dmabuf_input,
            mode == BufferMode::Dmabuf,
            "the encoder's input stage must match the capture's buffer kind"
        );
        if zero_copy == ZeroCopy::On {
            assert_eq!(mode, BufferMode::Dmabuf, "{:?}", pipe.zero_copy_note());
        }
        if zero_copy == ZeroCopy::Off {
            assert_eq!(mode, BufferMode::Shm);
        }
        let (tw, th) = pipe.target_size();
        let mut tap: Vec<u8> = Vec::new();
        let mut sink = streamer(tw, th);
        let run = run_stream(&mut pipe, &mut sink, &RunOptions::new(5.0), Some(&mut tap))
            .expect("run the stream");
        let extradata_len = pipe.encoder_info().extradata_len;
        let stats = pipe.finish();

        // The decoder only ever sees these bytes, so comparing them compares
        // the two paths at the only place the receiver can tell them apart.
        let mut parameter_sets: Vec<Vec<u8>> = Vec::new();
        for n in airplay_rs::video::split_annexb(&tap) {
            if matches!(n[0] & 0x1F, 7 | 8) && !parameter_sets.iter().any(|p| p == n) {
                parameter_sets.push(n.to_vec());
            }
        }

        // The ledger has to close on both paths — on the zero-copy one a leaked
        // handle would quietly starve the capture set instead of erroring.
        assert_eq!(
            stats.produced,
            stats.dropped + stats.encoded + stats.pending,
            "{mode}: the frame ledger must close"
        );
        assert_eq!(
            stats.capture.fresh + stats.capture.repeats,
            stats.produced,
            "{mode}: every published frame was a capture or a keepalive"
        );
        let per_frame_import_ms =
            stats.encoder.upload_us as f64 / stats.encoder.frames_in.max(1) as f64 / 1e3;
        println!(
            "{mode}: {} AUs, {} fresh + {} repeats, import {per_frame_import_ms:.3} ms/frame, \
             {} starved, {} fallbacks",
            run.access_units,
            stats.capture.fresh,
            stats.capture.repeats,
            stats.capture.buffer_starved,
            stats.capture.zero_copy_fallbacks
        );

        (
            Shape {
                target: (tw, th),
                extradata_len,
                // Counts are compared to each OTHER within a run, never between
                // runs: an idle desktop produces a different number of frames
                // every time and pretending otherwise would be a flaky lie.
                access_units: run.access_units - run.access_units,
                encoded: stats.encoded - run.access_units,
                packets: stats.encoder.packets_out - stats.encoded,
                pictures: stats.encoder.pictures_out - stats.encoder.packets_out,
                vcl_nals: stats.encoder.vcl_nals_out - run.access_units,
                sei: stats.encoder.sei_out,
                sps: stats.encoder.sps_out - run.idr_units,
                pps: stats.encoder.pps_out - run.idr_units,
                idr: stats.encoder.idr_out - run.idr_units,
                reconfigures: stats.reconfigures,
                capture_failures: stats.capture.failures,
                parameter_sets,
            },
            mode,
            per_frame_import_ms,
            stats.capture.zero_copy_fallbacks,
        )
    };

    let (dma_shape, dma_mode, dma_import, dma_fallbacks) = run_once(ZeroCopy::On);
    let (shm_shape, shm_mode, shm_import, _) = run_once(ZeroCopy::Off);

    assert_eq!(dma_mode, BufferMode::Dmabuf);
    assert_eq!(shm_mode, BufferMode::Shm);
    assert_eq!(dma_fallbacks, 0);

    // Every structural identity holds on both paths, and holds identically.
    let zero = Shape {
        target: dma_shape.target,
        extradata_len: 0,
        access_units: 0,
        encoded: 0,
        packets: 0,
        pictures: 0,
        vcl_nals: 0,
        sei: 0,
        sps: 0,
        pps: 0,
        idr: 0,
        reconfigures: 0,
        capture_failures: 0,
        parameter_sets: dma_shape.parameter_sets.clone(),
    };
    assert_eq!(dma_shape, zero, "zero-copy run: structure");
    assert_eq!(
        shm_shape, dma_shape,
        "the two paths must produce the same stream shape and the same parameter sets"
    );
    assert_eq!(
        dma_shape.parameter_sets.len(),
        2,
        "one SPS and one PPS, repeated unchanged at every IDR"
    );
    assert_eq!(dma_shape.parameter_sets[0][0] & 0x1F, 7);
    assert_eq!(
        &dma_shape.parameter_sets[0][..4],
        &[0x67, 0x64, 0x0c, 0x2a],
        "High@4.2 with the constraint flags, on both paths"
    );

    // ...and the whole point: the import stage. 9.2 MB of BGRX per frame either
    // crosses the bus or it does not, and the measured gap here is ~5.7 ms
    // against ~0.002 ms. A factor of ten is three orders of magnitude of slack.
    println!("import per frame: dmabuf {dma_import:.4} ms vs shm {shm_import:.4} ms");
    assert!(
        dma_import * 10.0 < shm_import,
        "the zero-copy import ({dma_import:.4} ms) is not decisively cheaper than \
         the shm upload ({shm_import:.4} ms) — the map has silently become a copy"
    );
}
