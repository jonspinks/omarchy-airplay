//! cli-testpattern: generate a short H.264 test pattern with the installed
//! ffmpeg CLI (SMPTE HD bars + a moving marker + "Omarchy AirPlay" text) as an
//! Annex-B elementary stream, split it into access units, and pace them over the
//! video data channel. Milestone-1 source path for `MirrorStreamer` (probe.py
//! streams a libx264-encoded `TestPattern`; here the CLI has no libav binding, so
//! it pre-generates the stream offline with ffmpeg, exactly as the probe's
//! milestone-1 note describes).

use std::io::{self, Read};
use std::path::Path;
use std::process::Command;

/// Level 4.2 allows 8192 macroblocks/frame; 1920x1080 is 8160, so a 1080p
/// receiver is streamed at its native size. Larger displays scale down; the Frame is happy with
/// it and it keeps libx264 within the negotiated level. Wider/taller displays are
/// scaled down to fit while preserving aspect ratio.
pub const MAX_FIT_WIDTH: u32 = 1920;
pub const MAX_FIT_HEIGHT: u32 = 1080;

/// Fit a receiver display size into the level-4.2 budget, preserving aspect
/// ratio and forcing even dimensions (yuv420p needs even width/height). A
/// display already within the budget is used verbatim (rounded to even).
///
/// This is the TEST-PATTERN path's fit, and only that: the pattern is generated
/// at the size this returns, so the thing being fitted is the receiver itself.
/// Live screen capture is the other way round — the source is a 1920x1200
/// capture buffer and the receiver is the box — so it uses
/// [`crate::encoder::fit_source_to_receiver`]. Mixing the two up is milestone-1
/// bug #2.
pub fn fit_resolution(display: (u32, u32)) -> (u32, u32) {
    let (dw, dh) = display;
    if dw == 0 || dh == 0 {
        return (MAX_FIT_WIDTH, MAX_FIT_HEIGHT);
    }
    let scale = f64::min(
        1.0,
        f64::min(
            MAX_FIT_WIDTH as f64 / dw as f64,
            MAX_FIT_HEIGHT as f64 / dh as f64,
        ),
    );
    let even = |v: f64| -> u32 {
        let mut n = v.round().max(2.0) as u32;
        if n % 2 == 1 {
            n -= 1;
        }
        n.max(2)
    };
    (even(dw as f64 * scale), even(dh as f64 * scale))
}

/// Locate a usable TrueType font for drawtext. Falls back to a known Liberation
/// path if fontconfig is unavailable.
fn resolve_font() -> String {
    if let Ok(out) = Command::new("fc-match").args(["-f", "%{file}", "sans"]).output() {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() && Path::new(&p).exists() {
                return p;
            }
        }
    }
    "/usr/share/fonts/liberation/LiberationSans-Regular.ttf".to_string()
}

/// Generate an Annex-B H.264 test pattern to `out_path`. `keyframe_seconds` sets
/// the GOP so IIDR frames recur (5s per the layer spec); `repeat-headers=1`
/// guarantees SPS/PPS precede each IDR so a codec packet is always emitted.
/// Returns the raw stream bytes.
pub fn generate(
    out_path: &Path,
    width: u32,
    height: u32,
    fps: u32,
    seconds: f64,
    keyframe_seconds: f64,
) -> io::Result<Vec<u8>> {
    let font = resolve_font();
    let keyint = ((fps as f64) * keyframe_seconds).round().max(1.0) as u32;
    // A moving yellow marker (drawbox with a time-based x), the product name, and
    // a live frame counter over SMPTE HD bars. Commas inside expressions are
    // escaped (\,) so they are not read as filtergraph separators.
    let vf = format!(
        "drawbox=x='mod(t*400\\,w-160)':y=h-200:w=140:h=140:color=yellow@0.85:t=fill,\
         drawtext=fontfile={font}:text='Omarchy AirPlay':fontsize=96:fontcolor=white:\
         borderw=5:bordercolor=black:x=(w-text_w)/2:y=90,\
         drawtext=fontfile={font}:text='frame %{{n}}':fontsize=48:fontcolor=white:\
         borderw=3:bordercolor=black:x=(w-text_w)/2:y=h-90",
        font = font,
    );
    let x264 = format!(
        "keyint={keyint}:min-keyint={keyint}:bframes=0:repeat-headers=1:annexb=1"
    );
    let status = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            &format!("smptehdbars=size={width}x{height}:rate={fps}"),
            "-t",
            &format!("{seconds}"),
            "-vf",
            &vf,
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-tune",
            "zerolatency",
            "-profile:v",
            "high",
            "-level",
            "4.2",
            "-pix_fmt",
            "yuv420p",
            "-x264-params",
            &x264,
            "-f",
            "h264",
        ])
        .arg(out_path)
        .status()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to launch ffmpeg (is it installed?): {e}"),
            )
        })?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "ffmpeg exited with {status} generating the test pattern"
        )));
    }
    let mut f = std::fs::File::open(out_path)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Err(io::Error::other("ffmpeg produced an empty test pattern"));
    }
    Ok(bytes)
}

/// Group an Annex-B elementary stream into access units, each returned as a
/// contiguous slice **with its start codes intact** so it can be fed straight to
/// `MirrorStreamer::forward_access_unit`.
///
/// Boundary rule (mirrors probe.ScreenSource.packets): a new access unit begins
/// at a VCL NAL whose `first_mb_in_slice == 0` — i.e. the first bit of the slice
/// header is set — or at a non-VCL NAL (SEI/SPS/PPS/AUD), and only once the
/// current unit already holds a VCL NAL, so leading SPS/PPS/SEI attach to the
/// picture that follows.
///
/// One picture is often MANY NALs: libx264 with `-tune zerolatency` enables
/// sliced threads, which emitted 14 slices per frame for the 1080p test pattern.
/// Treating each slice as its own access unit sends 1/14th of a picture per
/// "frame"; the receiver renders the top band and then decodes garbage.
pub fn split_access_units(stream: &[u8]) -> Vec<&[u8]> {
    // Offsets of each `00 00 01` start-code triplet.
    let mut starts: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i + 3 <= stream.len() {
        if stream[i] == 0 && stream[i + 1] == 0 && stream[i + 2] == 1 {
            starts.push(i);
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut aus: Vec<&[u8]> = Vec::new();
    let mut au_start: Option<usize> = None;
    let mut seen_vcl = false;
    for &pos in &starts {
        if pos + 3 >= stream.len() {
            continue;
        }
        let nal_type = stream[pos + 3] & 0x1F;
        let is_vcl = nal_type == 1 || nal_type == 5;
        // first_mb_in_slice is the first Exp-Golomb value of the slice header; a
        // leading 1 bit means the value is 0, i.e. this slice starts a picture.
        let starts_picture =
            is_vcl && pos + 4 < stream.len() && (stream[pos + 4] & 0x80) != 0;
        let boundary = starts_picture || matches!(nal_type, 6..=9);
        match au_start {
            None => {
                au_start = Some(pos);
                seen_vcl = false;
            }
            Some(start) if seen_vcl && boundary => {
                aus.push(&stream[start..pos]);
                au_start = Some(pos);
                seen_vcl = false;
            }
            _ => {}
        }
        if is_vcl {
            seen_vcl = true;
        }
    }
    if let Some(start) = au_start {
        aus.push(&stream[start..]);
    }
    aus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_scales_down_preserving_aspect() {
        assert_eq!(fit_resolution((3840, 2160)), (1920, 1080));
        assert_eq!(fit_resolution((1920, 1080)), (1920, 1080));
        assert_eq!(fit_resolution((1280, 720)), (1280, 720));
        assert_eq!(fit_resolution((0, 0)), (MAX_FIT_WIDTH, MAX_FIT_HEIGHT));
    }

    /// End-to-end pipeline check that actually runs ffmpeg and pushes the
    /// generated stream through `MirrorStreamer` into an in-memory sink. Ignored
    /// by default so the normal test run needs neither ffmpeg nor a receiver;
    /// run with `cargo test -- --ignored generate_and_stream`.
    #[test]
    #[ignore]
    fn generate_and_stream_test_pattern() {
        use crate::video::{MirrorStreamer, VideoCipher};
        let tmp = std::env::temp_dir().join("airplay-testpattern-selfcheck.h264");
        let bytes = generate(&tmp, 1728, 1080, 30, 2.0, 5.0).expect("ffmpeg generate");
        let _ = std::fs::remove_file(&tmp);
        let aus = split_access_units(&bytes);
        // Must be one access unit PER PICTURE, not per slice: libx264 -tune
        // zerolatency uses sliced threads (14 slices/frame at 1080p), and a
        // lower-bound-only assertion here previously let a 14x over-split pass,
        // which rendered the top band then garbage on a real receiver.
        assert!(
            (58..=62).contains(&aus.len()),
            "2s@30fps must yield ~60 access units (one per picture), got {}",
            aus.len()
        );
        // And each AU must carry every slice of its picture.
        let slices_in_second_au = crate::video::split_annexb(aus[1])
            .iter()
            .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
            .count();
        assert!(
            slices_in_second_au > 1,
            "expected a multi-slice picture in one AU, got {slices_in_second_au} slice(s)"
        );
        // First AU must carry SPS+PPS (repeat-headers) so a codec packet fires.
        let first_types: Vec<u8> = crate::video::split_annexb(aus[0])
            .iter()
            .map(|n| n[0] & 0x1F)
            .collect();
        assert!(first_types.contains(&7) && first_types.contains(&8) && first_types.contains(&5));

        let shared = [0x11u8; 32];
        let sink: Vec<u8> = Vec::new();
        let mut s = MirrorStreamer::new(
            sink,
            VideoCipher::ChaCha20Poly1305,
            &shared,
            1234567,
            &[0u8; 16],
            1728,
            1080,
            0.075,
        );
        for au in &aus {
            s.forward_access_unit(au).expect("forward AU");
        }
        s.send_heartbeat().expect("heartbeat");
    }

    #[test]
    fn access_units_group_headers_with_picture() {
        // SPS(7) PPS(8) IDR-first-slice(5) + 2 continuation slices, then the next
        // picture's first slice. 0x80 in the byte after the NAL header marks
        // first_mb_in_slice == 0; without it the slice continues the current one.
        let sc = [0u8, 0, 0, 1];
        let mut s = Vec::new();
        s.extend_from_slice(&sc);
        s.extend_from_slice(&[0x67, 0xAA]); // SPS
        s.extend_from_slice(&sc);
        s.extend_from_slice(&[0x68, 0xBB]); // PPS
        s.extend_from_slice(&sc);
        s.extend_from_slice(&[0x65, 0x88, 0x02]); // IDR, first slice of picture
        s.extend_from_slice(&sc);
        s.extend_from_slice(&[0x65, 0x11]); // IDR, continuation slice
        s.extend_from_slice(&sc);
        s.extend_from_slice(&[0x65, 0x21]); // IDR, continuation slice
        s.extend_from_slice(&sc);
        s.extend_from_slice(&[0x41, 0x99]); // next picture, first slice
        let aus = split_access_units(&s);
        assert_eq!(
            aus.len(),
            2,
            "a multi-slice picture is ONE access unit, not one per slice"
        );
        // First AU carries the parameter sets plus all three slices of picture 1.
        let first = crate::video::split_annexb(aus[0]);
        let types: Vec<u8> = first.iter().map(|n| n[0] & 0x1F).collect();
        assert_eq!(types, vec![7, 8, 5, 5, 5]);
        let second = crate::video::split_annexb(aus[1]);
        assert_eq!(second.len(), 1);
    }
}
