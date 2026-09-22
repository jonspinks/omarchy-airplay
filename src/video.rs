//! video-packets: the AirPlay mirror data-channel. 128-byte headers, avcC/frame/
//! heartbeat packets, and the chacha/aesctr/raw cipher schemes. Ported from
//! probe.MirrorStreamer / probe.build_avcc / probe.split_annexb (probe.py).

use std::io::{self, Write};

pub const MIRROR_HEADER_LEN: usize = 128;

/// Video data-channel key/cipher scheme (probe MirrorStreamer.__init__).
pub enum VideoCipher {
    ChaCha20Poly1305,
    AesCtr,
    Raw,
}

// --------------------------------------------------------------------------- derivations

pub fn chacha_video_key(shared: &[u8], stream_id: u64) -> [u8; 32] {
    crate::crypto::hkdf_sha512_32(
        shared,
        &format!("DataStream-Salt{stream_id}"),
        "DataStream-Output-Encryption-Key",
    )
}

pub fn aesctr_video_key_iv(shk: &[u8], stream_id: u64) -> ([u8; 16], [u8; 16]) {
    use sha2::{Digest, Sha512};
    let mut hk = Sha512::new();
    hk.update(format!("AirPlayStreamKey{stream_id}").as_bytes());
    hk.update(shk);
    let key_digest = hk.finalize();
    let mut hi = Sha512::new();
    hi.update(format!("AirPlayStreamIV{stream_id}").as_bytes());
    hi.update(shk);
    let iv_digest = hi.finalize();
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&key_digest[..16]);
    iv.copy_from_slice(&iv_digest[..16]);
    (key, iv)
}

pub fn nonce_counter(n: u64) -> [u8; 12] {
    crate::crypto::nonce_counter(n)
}

pub fn build_avcc(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&[1, sps[1], sps[2], sps[3], 0xFF, 0xE1]);
    r.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    r.extend_from_slice(sps);
    r.push(0x01);
    r.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    r.extend_from_slice(pps);
    r.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // trailer observed from Apple senders
    r
}

/// 4-byte big-endian length-prefixed concat of the VCL NALs.
pub fn avcc_frame<'a>(vcl_nals: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for nal in vcl_nals {
        out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        out.extend_from_slice(nal);
    }
    out
}

/// Annex-B split, start codes removed (mirrors probe.split_annexb).
pub fn split_annexb(data: &[u8]) -> Vec<&[u8]> {
    // Collect the byte offset just past each `00 00 01` start code.
    let mut starts: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut nals: Vec<&[u8]> = Vec::new();
    for (index, &start) in starts.iter().enumerate() {
        let has_next = index + 1 < starts.len();
        let mut end = if has_next {
            starts[index + 1] - 3
        } else {
            data.len()
        };
        // Strip the trailing 0x00 that is the 4th byte of the next 4-byte start
        // code (only when a next NAL exists and the slice ends in 0x00).
        if has_next && end > start && data[end - 1] == 0 {
            end -= 1;
        }
        if end > start {
            nals.push(&data[start..end]);
        }
    }
    nals
}

// --------------------------------------------------------------------------- headers

pub fn codec_header(avcc_len: u32, ts: u64, width: f32, height: f32) -> [u8; MIRROR_HEADER_LEN] {
    let mut hdr = [0u8; MIRROR_HEADER_LEN];
    hdr[0..4].copy_from_slice(&avcc_len.to_le_bytes());
    hdr[4] = 0x01;
    hdr[5] = 0x00;
    hdr[6] = 0x16;
    hdr[7] = 0x01;
    hdr[8..16].copy_from_slice(&ts.to_le_bytes());
    for &offset in &[16usize, 40, 56] {
        hdr[offset..offset + 4].copy_from_slice(&width.to_le_bytes());
        hdr[offset + 4..offset + 8].copy_from_slice(&height.to_le_bytes());
    }
    hdr
}

pub fn frame_header(size_field: u32, ts: u64, idr: bool) -> [u8; MIRROR_HEADER_LEN] {
    let mut hdr = [0u8; MIRROR_HEADER_LEN];
    hdr[0..4].copy_from_slice(&size_field.to_le_bytes());
    hdr[4] = 0x00;
    hdr[5] = if idr { 0x10 } else { 0x00 };
    hdr[8..16].copy_from_slice(&ts.to_le_bytes());
    hdr
}

pub fn heartbeat_packet() -> [u8; MIRROR_HEADER_LEN] {
    let mut hdr = [0u8; MIRROR_HEADER_LEN];
    hdr[4] = 0x02;
    hdr[6] = 0x1E;
    hdr
}

// --------------------------------------------------------------------------- streamer

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

enum CipherState {
    ChaCha { key: [u8; 32] },
    AesCtr { ctr: Box<Aes128Ctr> },
    Raw,
}

pub struct MirrorStreamer<W: Write> {
    sink: W,
    state: CipherState,
    nonce_n: u64,
    last_ts: u64,
    width: u32,
    height: u32,
    lead_seconds: f64,
    sent_params: Option<(Vec<u8>, Vec<u8>)>,
    /// The sender clock every presentation timestamp is read from — the same
    /// one the audio timeline and the timing responder read (see
    /// [`crate::clock`]). Defaults to [`crate::clock::BoottimeClock`].
    clock: std::sync::Arc<dyn crate::clock::SenderClock>,
}

impl<W: Write> MirrorStreamer<W> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sink: W,
        cipher: VideoCipher,
        shared: &[u8],
        stream_id: u64,
        shk: &[u8],
        width: u32,
        height: u32,
        lead_seconds: f64,
    ) -> Self {
        let state = match cipher {
            VideoCipher::ChaCha20Poly1305 => CipherState::ChaCha {
                key: chacha_video_key(shared, stream_id),
            },
            VideoCipher::AesCtr => {
                use ctr::cipher::KeyIvInit;
                let (key, iv) = aesctr_video_key_iv(shk, stream_id);
                CipherState::AesCtr {
                    ctr: Box::new(Aes128Ctr::new((&key).into(), (&iv).into())),
                }
            }
            VideoCipher::Raw => CipherState::Raw,
        };
        MirrorStreamer {
            sink,
            state,
            nonce_n: 0,
            last_ts: 0,
            width,
            height,
            lead_seconds,
            sent_params: None,
            clock: std::sync::Arc::new(crate::clock::BoottimeClock),
        }
    }

    /// Stamp frames from `clock` instead of a private BOOTTIME read, so video
    /// and audio share one sender clock. The conversion is identical, so the
    /// wire bytes are too.
    pub fn set_clock(&mut self, clock: std::sync::Arc<dyn crate::clock::SenderClock>) {
        self.clock = clock;
    }

    /// The sink, for callers that wrote to something inspectable — the offline
    /// bench counts the bytes the mirror channel would have put on the wire.
    pub fn sink(&self) -> &W {
        &self.sink
    }

    /// Change the size reported in the codec header. Live capture can be
    /// renegotiated mid-stream (an output mode/scale change, or any toplevel
    /// resize in window mode), which re-fits the encode and produces a new SPS;
    /// `forward_access_unit` then re-sends the codec packet, and it must carry
    /// the new geometry rather than the size the session opened at.
    pub fn set_dimensions(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
    }

    pub fn send_codec(&mut self, sps: &[u8], pps: &[u8]) -> io::Result<()> {
        let payload = build_avcc(sps, pps);
        let ts = self.next_timestamp();
        let header = codec_header(
            payload.len() as u32,
            ts,
            self.width as f32,
            self.height as f32,
        );
        // One packet, header and body together, exactly as probe.MirrorStreamer
        // ._write does: a separate small write for the 128-byte header would go
        // out as its own TCP segment (the socket is TCP_NODELAY) and the
        // receiver could not act on it until the body's segment landed.
        let mut pkt = Vec::with_capacity(MIRROR_HEADER_LEN + payload.len());
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&payload); // codec body is never encrypted
        self.sink.write_all(&pkt)?;
        Ok(())
    }

    pub fn send_frame(&mut self, avcc_payload: &[u8], idr: bool) -> io::Result<()> {
        let ts = self.next_timestamp();
        let is_chacha = matches!(self.state, CipherState::ChaCha { .. });
        let size = avcc_payload.len() + if is_chacha { crate::crypto::HAP_TAG_LEN } else { 0 };
        let header = frame_header(size as u32, ts, idr);
        let body = match &mut self.state {
            CipherState::ChaCha { key } => {
                use chacha20poly1305::aead::{Aead, KeyInit, Payload};
                use chacha20poly1305::ChaCha20Poly1305;
                let cipher = ChaCha20Poly1305::new((&*key).into());
                let nonce = nonce_counter(self.nonce_n);
                let ct = cipher
                    .encrypt(
                        (&nonce).into(),
                        Payload {
                            msg: avcc_payload,
                            aad: &header,
                        },
                    )
                    .expect("chacha frame seal");
                self.nonce_n += 1;
                ct
            }
            CipherState::AesCtr { ctr } => {
                use ctr::cipher::StreamCipher;
                let mut buf = avcc_payload.to_vec();
                ctr.apply_keystream(&mut buf);
                buf
            }
            CipherState::Raw => avcc_payload.to_vec(),
        };
        // Single write: header + sealed body in one packet (see send_codec).
        let mut pkt = Vec::with_capacity(MIRROR_HEADER_LEN + body.len());
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&body);
        self.sink.write_all(&pkt)?;
        Ok(())
    }

    pub fn send_heartbeat(&mut self) -> io::Result<()> {
        self.sink.write_all(&heartbeat_packet())
    }

    pub fn forward_access_unit(&mut self, annexb: &[u8]) -> io::Result<()> {
        let nals = split_annexb(annexb);
        let sps = nals.iter().find(|x| x[0] & 0x1F == 7).copied();
        let pps = nals.iter().find(|x| x[0] & 0x1F == 8).copied();
        if let (Some(sps), Some(pps)) = (sps, pps) {
            let pair = (sps.to_vec(), pps.to_vec());
            if self.sent_params.as_ref() != Some(&pair) {
                self.send_codec(sps, pps)?;
                self.sent_params = Some(pair);
            }
        }
        let vcl: Vec<&[u8]> = nals
            .iter()
            .filter(|x| matches!(x[0] & 0x1F, 1 | 5))
            .copied()
            .collect();
        if !vcl.is_empty() && self.sent_params.is_some() {
            let idr = vcl.iter().any(|x| x[0] & 0x1F == 5);
            let payload = avcc_frame(vcl);
            self.send_frame(&payload, idr)?;
        }
        Ok(())
    }

    fn next_timestamp(&mut self) -> u64 {
        let now = self.clock.read().ntp().0;
        let lead = (self.lead_seconds * (1u64 << 32) as f64) as u64;
        let ts = now.saturating_add(lead).max(self.last_ts + 1);
        self.last_ts = ts;
        ts
    }
}
