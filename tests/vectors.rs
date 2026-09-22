//! Golden-vector harness. Each pure-function module has a test that loads its
//! JSON fixture from `tests/vectors/*.json` and asserts byte-for-byte against
//! the probe-generated vectors.
//!
//! These are active, byte-exact checks, not skeleton stubs: every test runs on
//! `cargo test` and must stay green. They pin the on-wire behaviour (TLV8, HAP
//! crypto, RTSP framing, SETUP plists, timing packets, pairing/SRP) to the
//! reference probe, so any change that alters wire bytes will fail here.
//! Run a single one with `cargo test --test vectors tlv8_vectors`.

use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn load(name: &str) -> serde_json::Value {
    let path = vectors_dir().join(name);
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid lowercase hex")
}

#[test]
fn tlv8_vectors() {
    use airplay_rs::tlv8::{tlv_decode, tlv_encode};
    let doc = load("tlv8.json");
    for v in doc["vectors"].as_array().unwrap() {
        let kind = v["kind"].as_str().unwrap();
        if kind == "encode" || kind == "roundtrip" {
            let items: Vec<(u8, Vec<u8>)> = v["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p[0].as_u64().unwrap() as u8, unhex(p[1].as_str().unwrap())))
                .collect();
            let refs: Vec<(u8, &[u8])> = items.iter().map(|(t, val)| (*t, val.as_slice())).collect();
            assert_eq!(tlv_encode(&refs), unhex(v["encoded_hex"].as_str().unwrap()));
        }
        if kind == "decode" || kind == "roundtrip" {
            let input = if kind == "decode" {
                unhex(v["input_hex"].as_str().unwrap())
            } else {
                unhex(v["encoded_hex"].as_str().unwrap())
            };
            let got = tlv_decode(&input);
            for (tag, val) in v["decoded"].as_object().unwrap() {
                let tag: u8 = tag.parse().unwrap();
                assert_eq!(got.get(tag), Some(unhex(val.as_str().unwrap()).as_slice()));
            }
        }
    }
}

#[test]
fn hap_crypto_vectors() {
    use airplay_rs::crypto::{hkdf_sha512_32, nonce_counter, nonce_label, HapCipher};
    let doc = load("hap-crypto.json");

    let hkdf_block = &doc["hkdf"];
    let ikm = unhex(hkdf_block["ikm_hex"].as_str().unwrap());
    for e in hkdf_block["expansions"].as_array().unwrap() {
        let okm = hkdf_sha512_32(&ikm, e["salt"].as_str().unwrap(), e["info"].as_str().unwrap());
        assert_eq!(&okm[..], unhex(e["okm_hex"].as_str().unwrap()).as_slice());
    }
    for e in doc["nonce_counter"].as_array().unwrap() {
        let n = e["n"].as_u64().unwrap();
        assert_eq!(&nonce_counter(n)[..], unhex(e["nonce_hex"].as_str().unwrap()).as_slice());
    }
    for e in doc["nonce_label"].as_array().unwrap() {
        let label = e["label"].as_str().unwrap();
        assert_eq!(&nonce_label(label)[..], unhex(e["nonce_hex"].as_str().unwrap()).as_slice());
    }
    let hc = &doc["hap_cipher"];
    let wk: [u8; 32] = unhex(hc["write_key_hex"].as_str().unwrap()).try_into().unwrap();
    let rk: [u8; 32] = unhex(hc["read_key_hex"].as_str().unwrap()).try_into().unwrap();
    let plaintext = unhex(hc["plaintext_hex"].as_str().unwrap());
    let mut cipher = HapCipher::new(wk, rk);
    let sealed = cipher.seal(&plaintext);
    assert_eq!(sealed, unhex(hc["sealed_hex"].as_str().unwrap()));
    assert_eq!(sealed.len(), hc["sealed_total_len"].as_u64().unwrap() as usize);

    // Per-frame decomposition, and an open() round-trip. The frames were sealed
    // with write_key, so the opener's read_key must be write_key.
    let mut opener = HapCipher::new([0u8; 32], wk);
    let mut recovered = Vec::new();
    let mut off = 0usize;
    for fr in hc["frames"].as_array().unwrap() {
        let expected = unhex(fr["sealed_frame_hex"].as_str().unwrap());
        assert_eq!(&sealed[off..off + expected.len()], expected.as_slice());
        let aad = unhex(fr["aad_hex"].as_str().unwrap());
        let opened = opener.open(&aad, &expected[2..]).unwrap();
        recovered.extend_from_slice(&opened);
        off += expected.len();
    }
    assert_eq!(recovered, plaintext);
}

#[test]
fn timing_vectors() {
    use airplay_rs::timing::{build_reply, build_request, NtpTimestamp};
    let doc = load("timing-ntp.json");
    for c in doc["timestamp_conversion_vectors"].as_array().unwrap() {
        let secs = c["boottime_seconds"].as_f64().unwrap();
        let ts = NtpTimestamp::from_boottime_parts(secs as u64, secs.fract());
        assert_eq!(ts.0, c["ntp64"].as_u64().unwrap());
        assert_eq!(&ts.to_be_bytes()[..], unhex(c["ntp64_hex"].as_str().unwrap()).as_slice());
    }
    for p in doc["packet_vectors"].as_array().unwrap() {
        // The transmit timestamp is given directly as client_transmit_ntp; when
        // boottime seconds are also present, cross-check the conversion.
        let transmit_ntp = p["client_transmit_ntp"].as_u64().unwrap();
        if let Some(secs) = p.get("client_boottime_seconds").and_then(|v| v.as_f64()) {
            let ts = NtpTimestamp::from_boottime_parts(secs as u64, secs.fract());
            assert_eq!(ts.0, transmit_ntp);
        }
        let ts = NtpTimestamp(transmit_ntp);
        let req = build_request(p["seq"].as_u64().unwrap() as u16, ts);
        assert_eq!(&req[..], unhex(p["request_hex"].as_str().unwrap()).as_slice());
        if let Some(reply_hex) = p.get("reply_hex").and_then(|v| v.as_str()) {
            let now = NtpTimestamp(p["server_now_ntp"].as_u64().unwrap());
            let reply = build_reply(&req, now).unwrap();
            assert_eq!(&reply[..], unhex(reply_hex).as_slice());
        }
    }
}

/// A fake in-memory stream: reads drain `to_read`, writes append to `written`.
struct FakeStream {
    to_read: std::io::Cursor<Vec<u8>>,
    written: Vec<u8>,
}
impl std::io::Read for FakeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.to_read.read(buf)
    }
}
impl std::io::Write for FakeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn rtsp_transport_vectors() {
    use airplay_rs::crypto::HapCipher;
    use airplay_rs::rtsp::{build_request, try_parse_message, RtspConnection};
    let doc = load("rtsp-transport.json");

    // --- plaintext request building ---
    for r in doc["plaintext_requests"].as_array().unwrap() {
        let method = r["method"].as_str().unwrap();
        let uri = r["uri"].as_str().unwrap();
        let cseq = r["cseq"].as_u64().unwrap() as u32;
        let defaults: Vec<(String, String)> = r
            .get("default_headers")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let extra: Vec<(String, String)> = r["extra_headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        let ct = r["content_type"].as_str();
        let body = unhex(r["body_hex"].as_str().unwrap());
        let got = build_request(method, uri, cseq, &defaults, &extra, ct, &body);
        assert_eq!(
            got,
            unhex(r["request_hex"].as_str().unwrap()),
            "request {}",
            r["name"].as_str().unwrap()
        );
    }

    // --- response parsing (with trailing leftover) ---
    let rp = &doc["response_parse"];
    let input = unhex(rp["input_hex"].as_str().unwrap());
    let (msg, consumed) = try_parse_message(&input).unwrap();
    assert_eq!(msg.first_line, rp["status_line"].as_str().unwrap());
    for (k, v) in rp["parsed_headers"].as_object().unwrap() {
        assert_eq!(msg.header(k), Some(v.as_str().unwrap()));
    }
    assert_eq!(msg.body, unhex(rp["body_hex"].as_str().unwrap()));
    assert_eq!(&input[consumed..], unhex(rp["leftover_buffer_hex"].as_str().unwrap()).as_slice());

    // --- encrypted seal of a request ---
    let enc = &doc["encrypted"];
    let wk: [u8; 32] = unhex(enc["write_key_hex"].as_str().unwrap()).try_into().unwrap();
    let rk: [u8; 32] = unhex(enc["read_key_hex"].as_str().unwrap()).try_into().unwrap();
    let sr = &enc["sealed_request"];
    let mut cipher = HapCipher::new(wk, rk);
    let sealed = cipher.seal(&unhex(sr["plaintext_hex"].as_str().unwrap()));
    assert_eq!(sealed, unhex(sr["sealed_hex"].as_str().unwrap()));

    // --- encrypted read: single frame ---
    // The response frames were sealed by the reverse-direction peer, so our
    // read_key must be the peer's write_key = this vector's write_key.
    let sf = &enc["decode_single_frame"];
    let stream = FakeStream {
        to_read: std::io::Cursor::new(unhex(sf["sealed_hex"].as_str().unwrap())),
        written: Vec::new(),
    };
    let mut conn = RtspConnection::new(stream);
    conn.set_cipher(HapCipher::new(wk, rk));
    let m = conn.read_message().unwrap();
    assert_eq!(m.first_line, sf["decoded_status_line"].as_str().unwrap());
    for (k, v) in sf["decoded_headers"].as_object().unwrap() {
        assert_eq!(m.header(k), Some(v.as_str().unwrap()));
    }
    assert_eq!(m.body, unhex(sf["decoded_body_hex"].as_str().unwrap()));

    // --- encrypted read: multi frame ---
    let mf = &enc["decode_multi_frame"];
    let stream = FakeStream {
        to_read: std::io::Cursor::new(unhex(mf["sealed_hex"].as_str().unwrap())),
        written: Vec::new(),
    };
    let mut conn = RtspConnection::new(stream);
    conn.set_cipher(HapCipher::new(wk, rk));
    let m = conn.read_message().unwrap();
    assert_eq!(m.first_line, mf["decoded_status_line"].as_str().unwrap());
    for (k, v) in mf["decoded_headers"].as_object().unwrap() {
        assert_eq!(m.header(k), Some(v.as_str().unwrap()));
    }
    assert_eq!(m.body, unhex(mf["decoded_body_hex"].as_str().unwrap()));
}

#[test]
fn pairing_vectors() {
    use airplay_rs::pairing::{
        control_keys, events_keys, hkdf, nonce_counter, nonce_label, opack_name_field, SrpClient,
    };
    use airplay_rs::tlv8::{tlv_decode, tlv_encode};
    let doc = load("pairing.json");

    // --- TLV shapes ---
    let tlv = &doc["tlv"];
    assert_eq!(
        tlv_encode(&[(0x00, &[0x00][..]), (0x06, &[0x01][..]), (0x13, &[0x10][..])]),
        unhex(tlv["m1_transient"].as_str().unwrap())
    );
    assert_eq!(
        tlv_encode(&[(0x00, &[0x00][..]), (0x06, &[0x01][..])]),
        unhex(tlv["m1_pin"].as_str().unwrap())
    );
    assert_eq!(
        opack_name_field("Omarchy probe"),
        unhex(tlv["name_field_value"].as_str().unwrap())
    );
    assert_eq!(
        airplay_rs::pairing::SCREEN_CAPTURE_ACL,
        unhex(tlv["screen_capture_acl"].as_str().unwrap()).as_slice()
    );
    assert_eq!(
        tlv_encode(&[(0x06, &[][..])]),
        unhex(tlv["empty_value_tag0x06"].as_str().unwrap())
    );
    // chunk_500: a 500-byte 0xab value under tag 0x03 splits 255 + 245.
    let v500 = vec![0xabu8; 500];
    assert_eq!(
        tlv_encode(&[(0x03, v500.as_slice())]),
        unhex(tlv["chunk_500_tag0x03"].as_str().unwrap())
    );
    // fragmented decode reassembly.
    let frag = &tlv["decode_fragmented_reassembled"];
    let dec = tlv_decode(&unhex(tlv["chunk_500_tag0x03"].as_str().unwrap()));
    assert_eq!(dec.get(0x03), Some(unhex(frag["3"].as_str().unwrap()).as_slice()));

    // --- nonces ---
    let nonce = &doc["nonce"];
    for label in ["PS-Msg05", "PS-Msg06", "PV-Msg02", "PV-Msg03"] {
        assert_eq!(&nonce_label(label)[..], unhex(nonce[label].as_str().unwrap()).as_slice());
    }
    assert_eq!(&nonce_counter(0)[..], unhex(nonce["counter_0"].as_str().unwrap()).as_slice());
    assert_eq!(&nonce_counter(1)[..], unhex(nonce["counter_1"].as_str().unwrap()).as_slice());
    assert_eq!(&nonce_counter(258)[..], unhex(nonce["counter_258"].as_str().unwrap()).as_slice());

    // --- SRP-6a with pinned private exponent a = 01*32 ---
    let srp = &doc["srp"];
    let salt = unhex(srp["input_salt_hex"].as_str().unwrap());
    let b = unhex(srp["input_server_public_B_hex"].as_str().unwrap());
    let a: [u8; 32] = unhex(srp["input_client_private_a_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let mut client = SrpClient::new(srp["pin"].as_str().unwrap(), Some(a));
    assert_eq!(
        client.public_a(),
        unhex(srp["client_public_A_hex"].as_str().unwrap())
    );
    let (a_pub, m1) = client.process(&salt, &b).unwrap();
    assert_eq!(a_pub, unhex(srp["client_public_A_hex"].as_str().unwrap()));
    assert_eq!(m1, unhex(srp["client_proof_M1_hex"].as_str().unwrap()));
    assert_eq!(
        client.session_key(),
        unhex(srp["session_key_K_hex"].as_str().unwrap()).as_slice()
    );
    assert!(client.verify_server_proof(&unhex(srp["expected_server_proof_M2_hex"].as_str().unwrap())));
    assert!(!client.verify_server_proof(&[0u8; 64]));

    // --- HKDF derivations (all pairing + transport labels) ---
    let hk = &doc["hkdf"];
    let setup = unhex(hk["setup_secret_hex"].as_str().unwrap());
    let verify = unhex(hk["verify_secret_hex"].as_str().unwrap());
    let cases: &[(&str, &str, &str, &[u8])] = &[
        ("pair_setup_encrypt", "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", &setup),
        ("pair_setup_controller_sign", "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info", &setup),
        ("pair_setup_accessory_sign", "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info", &setup),
        ("pair_verify_encrypt", "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", &verify),
    ];
    for (key, salt, info, ikm) in cases {
        assert_eq!(&hkdf(ikm, salt, info)[..], unhex(hk[*key].as_str().unwrap()).as_slice(), "{key}");
    }
    // Transport channel keys derived off the verify secret.
    let (cw, cr) = control_keys(&verify);
    assert_eq!(&cw[..], unhex(hk["control_write"].as_str().unwrap()).as_slice());
    assert_eq!(&cr[..], unhex(hk["control_read"].as_str().unwrap()).as_slice());
    let (er, ew) = events_keys(&verify);
    assert_eq!(&er[..], unhex(hk["events_read"].as_str().unwrap()).as_slice());
    assert_eq!(&ew[..], unhex(hk["events_write"].as_str().unwrap()).as_slice());

    // --- M5: seal the sub-TLV and build the outer M5 body ---
    let m5 = &doc["m5"];
    let setup_key: [u8; 32] = unhex(m5["setup_key_hex"].as_str().unwrap()).try_into().unwrap();
    let sub = unhex(m5["sub_tlv_plaintext_hex"].as_str().unwrap());
    let sealed = {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::ChaCha20Poly1305;
        let cipher = ChaCha20Poly1305::new((&setup_key).into());
        let nonce = nonce_label("PS-Msg05");
        cipher.encrypt((&nonce).into(), sub.as_slice()).unwrap()
    };
    assert_eq!(sealed, unhex(m5["sealed_hex"].as_str().unwrap()));
    let outer = tlv_encode(&[(0x06, &[0x05][..]), (0x05, sealed.as_slice())]);
    assert_eq!(outer, unhex(m5["m5_outer_tlv_hex"].as_str().unwrap()));
}

#[test]
fn video_vectors() {
    use airplay_rs::video::{
        aesctr_video_key_iv, avcc_frame, build_avcc, chacha_video_key, codec_header, frame_header,
        heartbeat_packet, nonce_counter, split_annexb,
    };
    let doc = load("video-packets.json");
    let inp = &doc["inputs"];
    let sps = unhex(inp["sps_hex"].as_str().unwrap());
    let pps = unhex(inp["pps_hex"].as_str().unwrap());
    let width = inp["width"].as_u64().unwrap() as f32;
    let height = inp["height"].as_u64().unwrap() as f32;
    let ts = inp["fixed_timestamp_le64"].as_u64().unwrap();
    let stream_id = inp["stream_id"].as_u64().unwrap();

    // avcC record
    let avcc = build_avcc(&sps, &pps);
    assert_eq!(avcc, unhex(doc["avcc_record_hex"].as_str().unwrap()));

    // key derivations
    let shared = unhex(inp["shared_secret_hex"].as_str().unwrap());
    assert_eq!(
        &chacha_video_key(&shared, stream_id)[..],
        unhex(doc["chacha_video_key_hex"].as_str().unwrap()).as_slice()
    );
    let shk = unhex(inp["stream_key_shk_hex"].as_str().unwrap());
    let (k, iv) = aesctr_video_key_iv(&shk, stream_id);
    assert_eq!(&k[..], unhex(doc["aesctr"]["key_hex"].as_str().unwrap()).as_slice());
    assert_eq!(&iv[..], unhex(doc["aesctr"]["iv_hex"].as_str().unwrap()).as_slice());

    // nonce_counter map
    for (n, hexs) in doc["nonce_counter"].as_object().unwrap() {
        let n: u64 = n.parse().unwrap();
        assert_eq!(&nonce_counter(n)[..], unhex(hexs.as_str().unwrap()).as_slice());
    }

    // codec packet = header ++ avcC payload
    let cp = &doc["codec_packet"];
    let ch = codec_header(avcc.len() as u32, ts, width, height);
    assert_eq!(&ch[..], unhex(cp["header_hex"].as_str().unwrap()).as_slice());
    let mut codec_full = ch.to_vec();
    codec_full.extend_from_slice(&unhex(cp["payload_hex"].as_str().unwrap()));
    assert_eq!(codec_full.len(), cp["full_len"].as_u64().unwrap() as usize);

    // frame packet (IDR, chacha): header size = payload + 16 (poly tag)
    let fi = &doc["frame_packet_idr_chacha"];
    let idr_payload = unhex(fi["avcc_payload_hex"].as_str().unwrap());
    let fh = frame_header((idr_payload.len() + 16) as u32, ts, true);
    assert_eq!(&fh[..], unhex(fi["header_hex"].as_str().unwrap()).as_slice());
    // Encrypt with the derived chacha key, AAD = header -> body must match.
    {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::ChaCha20Poly1305;
        let key = chacha_video_key(&shared, stream_id);
        let cipher = ChaCha20Poly1305::new((&key).into());
        let nonce = nonce_counter(0);
        let body = cipher
            .encrypt((&nonce).into(), Payload { msg: &idr_payload, aad: &fh })
            .unwrap();
        assert_eq!(body, unhex(fi["body_hex"].as_str().unwrap()));
    }

    // frame packet (non-IDR, raw): full packet = header ++ payload
    let fr = &doc["frame_packet_nonidr_raw"];
    let raw_payload = unhex(fr["avcc_payload_hex"].as_str().unwrap());
    let rfh = frame_header(raw_payload.len() as u32, ts, false);
    let mut raw_full = rfh.to_vec();
    raw_full.extend_from_slice(&raw_payload);
    assert_eq!(raw_full, unhex(fr["packet_hex"].as_str().unwrap()));

    // heartbeat
    assert_eq!(
        &heartbeat_packet()[..],
        unhex(doc["heartbeat_packet"]["packet_hex"].as_str().unwrap()).as_slice()
    );

    // sanity: avcc_frame / split_annexb round-trip through a single VCL NAL
    let one: &[u8] = &[0x65, 0xaa, 0xbb, 0xcc, 0xdd];
    let framed = avcc_frame(std::iter::once(one));
    assert_eq!(&framed[..4], &(one.len() as u32).to_be_bytes());
    let annexb: Vec<u8> = [0, 0, 1].iter().chain(one.iter()).copied().collect();
    assert_eq!(split_annexb(&annexb), vec![one]);
}

#[test]
fn discovery_info_vectors() {
    use airplay_rs::discovery::{
        decode_features_ex, info_screen_fit, parse_avahi_line, parse_info, Features,
    };
    let doc = load("discovery-info.json");

    // --- feature bitfield ---
    let fb = &doc["feature_bits"];
    let feats = Features(fb["features_uint64"].as_u64().unwrap());
    assert_eq!(feats.lo32() as u64, u64::from_str_radix(fb["lo32_hex"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap());
    assert_eq!(feats.hi32() as u64, u64::from_str_radix(fb["hi32_hex"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap());
    let want_bits: Vec<u8> = fb["set_bit_indices"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
    assert_eq!(feats.set_bits(), want_bits);
    assert_eq!(feats.set_bits().len(), fb["set_bit_count"].as_u64().unwrap() as usize);
    // little-endian bytes
    assert_eq!(feats.0.to_le_bytes().to_vec(), unhex(fb["features_le_bytes_hex"].as_str().unwrap()));

    // --- featuresEx decode ---
    let fx = &doc["features_ex"];
    let (features, ext) = decode_features_ex(fx["featuresEx_str"].as_str().unwrap()).unwrap();
    let mut decoded = features.to_le_bytes().to_vec();
    decoded.extend_from_slice(&ext);
    assert_eq!(decoded, unhex(fx["decoded_hex"].as_str().unwrap()));
    assert_eq!(features, fb["features_uint64"].as_u64().unwrap());
    assert_eq!(decoded.len(), fx["decoded_len"].as_u64().unwrap() as usize);

    // --- parse the real /info fixture ---
    let body = std::fs::read(vectors_dir().join("office-info.bin")).unwrap();
    let info = parse_info(&body).unwrap();
    let sc = &doc["scalars"];
    assert_eq!(info.name, sc["name"].as_str().unwrap());
    assert_eq!(info.source_version, sc["sourceVersion"].as_str().unwrap());
    assert_eq!(info.protocol_version, sc["protocolVersion"].as_str().unwrap());
    assert_eq!(info.status_flags as u64, sc["statusFlags"].as_u64().unwrap());
    assert_eq!(info.volume_control_type as u64, sc["volumeControlType"].as_u64().unwrap());
    assert_eq!(info.active_interface_type as u64, sc["activeInterfaceType"].as_u64().unwrap());
    assert_eq!(info.device_id, sc["deviceID"].as_str().unwrap());
    assert_eq!(info.pi, sc["pi"].as_str().unwrap());
    assert_eq!(info.model, sc["model"].as_str().unwrap());
    assert_eq!(info.manufacturer, sc["manufacturer"].as_str().unwrap());
    assert_eq!(info.displays.len(), sc["num_displays"].as_u64().unwrap() as usize);
    assert_eq!(info.audio_latencies.len(), sc["num_audioLatencies"].as_u64().unwrap() as usize);
    // features from the plist matches the bitfield vector
    assert_eq!(info.features.0, fb["features_uint64"].as_u64().unwrap());

    // --- display0 ---
    let d0 = &doc["display0"];
    let disp = &info.displays[0];
    assert_eq!(disp.width_pixels as u64, d0["widthPixels"].as_u64().unwrap());
    assert_eq!(disp.height_pixels as u64, d0["heightPixels"].as_u64().unwrap());
    assert_eq!(disp.width_pixels_max.unwrap() as u64, d0["widthPixelsMax"].as_u64().unwrap());
    assert_eq!(disp.height_pixels_max.unwrap() as u64, d0["heightPixelsMax"].as_u64().unwrap());
    assert_eq!(disp.max_fps.unwrap() as u64, d0["maxFPS"].as_u64().unwrap());
    assert_eq!(disp.uuid.as_deref().unwrap(), d0["uuid"].as_str().unwrap());
    assert_eq!(disp.hdr_supported_modes.len(), d0["num_HDRSupportedModes"].as_u64().unwrap() as usize);
    // screen fit reads display0
    assert_eq!(info_screen_fit(&info), (disp.width_pixels, disp.height_pixels));

    // --- avahi row parsing (synthetic, per spec §1) ---
    let line = "=;eth0;IPv4;Office\\032TV;_airplay._tcp;local;localhost.local;192.0.2.50;7000;\"srcvers=377.40.00\" \"deviceid=02:1A:2B:3C:4D:5E\" \"model=LS03F\"";
    let rec = parse_avahi_line(line).expect("resolved IPv4 row");
    assert_eq!(rec.name, "Demo TV"); // \032 -> space
    assert_eq!(rec.host, "192.0.2.50"); // A-record IP, never the SRV hostname
    assert_eq!(rec.port, 7000);
    assert_eq!(rec.txt.get("srcvers").map(String::as_str), Some("377.40.00"));
    assert_eq!(rec.txt.get("model").map(String::as_str), Some("LS03F"));
    // non-resolved / non-IPv4 rows are rejected
    assert!(parse_avahi_line("+;eth0;IPv4;Office;_airplay._tcp;local").is_none());
    assert!(parse_avahi_line("=;eth0;IPv6;Office;_airplay._tcp;local;h;::1;7000;\"\"").is_none());
}

#[test]
fn session_setup_vectors() {
    use airplay_rs::session::{
        build_audio_setup_plist, build_control_setup_plist, build_video_setup_plist,
        clamp_volume_db, event_channel_keys, event_ok_reply, hkdf_key, record_headers,
        set_parameter_volume_body, volume_success, SessionIds, TimingProtocol,
    };
    let doc = load("setup-events-feedback.json");
    let inp = &doc["inputs"];
    let shared = unhex(inp["shared_secret_hex"].as_str().unwrap());

    // --- HKDF keys (control + reversed events) ---
    let hk = &doc["hkdf_keys"];
    let control_write = hkdf_key(&shared, "Control-Salt", "Control-Write-Encryption-Key");
    let control_read = hkdf_key(&shared, "Control-Salt", "Control-Read-Encryption-Key");
    assert_eq!(&control_write[..], unhex(hk["control_write"].as_str().unwrap()).as_slice());
    assert_eq!(&control_read[..], unhex(hk["control_read"].as_str().unwrap()).as_slice());
    let ev = event_channel_keys(&shared);
    // events are REVERSED: write uses the Read label, read uses the Write label.
    assert_eq!(&ev.write_key[..], unhex(hk["events_write"].as_str().unwrap()).as_slice());
    assert_eq!(&ev.read_key[..], unhex(hk["events_read"].as_str().unwrap()).as_slice());
    assert_eq!(ev.write_key, hkdf_key(&shared, "Events-Salt", "Events-Read-Encryption-Key"));
    assert_eq!(ev.read_key, hkdf_key(&shared, "Events-Salt", "Events-Write-Encryption-Key"));

    // --- control SETUP plist (byte-exact) ---
    let ids = SessionIds {
        session_uuid: inp["session_uuid"].as_str().unwrap().to_string(),
        audio_sc_id: inp["audio_stream_connection_id"].as_u64().unwrap(),
        video_sc_id: inp["video_stream_connection_id"].as_u64().unwrap(),
        mac: inp["mac"].as_str().unwrap().to_string(),
    };
    let control = build_control_setup_plist(&ids, TimingProtocol::Ntp, inp["timing_port"].as_u64().unwrap() as u16);
    assert_eq!(
        hex::encode(&control),
        doc["control_setup_plist"]["binary_plist_hex"].as_str().unwrap()
    );
    assert_eq!(control.len(), doc["control_setup_plist"]["binary_plist_len"].as_u64().unwrap() as usize);

    // --- audio SETUP plist (byte-exact) ---
    let shk32: [u8; 32] = (0x40u8..0x60).collect::<Vec<u8>>().try_into().unwrap();
    let audio = build_audio_setup_plist(
        ids.audio_sc_id,
        (inp["timing_port"].as_u64().unwrap() as u16) + 1,
        inp["audio_latency_ms"].as_u64().unwrap() as u32,
        &shk32,
    );
    assert_eq!(hex::encode(&audio), doc["audio_setup_plist"]["binary_plist_hex"].as_str().unwrap());

    // --- video SETUP plist (byte-exact) ---
    let vshk: [u8; 16] = control_write[..16].try_into().unwrap();
    let vshiv: [u8; 16] = control_read[..16].try_into().unwrap();
    assert_eq!(hex::encode(vshk), doc["video_setup_plist"]["shk_hex"].as_str().unwrap());
    assert_eq!(hex::encode(vshiv), doc["video_setup_plist"]["shiv_hex"].as_str().unwrap());
    let video = build_video_setup_plist(ids.video_sc_id, &vshk, &vshiv);
    assert_eq!(hex::encode(&video), doc["video_setup_plist"]["binary_plist_hex"].as_str().unwrap());

    // --- event reply + record headers + volume ---
    let er = event_ok_reply("0");
    assert_eq!(hex::encode(&er), doc["event_reply"]["example_cseq_0_hex"].as_str().unwrap());
    let rh = record_headers(inp["session_uuid"].as_str().unwrap());
    assert_eq!(rh[0], ("Session".into(), inp["session_uuid"].as_str().unwrap().to_string()));
    assert_eq!(rh[1], ("Range".into(), "npt=0-".to_string()));
    assert_eq!(rh[2], ("RTP-Info".into(), "seq=0;rtptime=0".to_string()));

    let vb = set_parameter_volume_body(inp["volume_db"].as_f64().unwrap() as f32);
    assert_eq!(hex::encode(&vb), doc["set_parameter_volume"]["body_hex"].as_str().unwrap());
    assert!(volume_success(200) && volume_success(500) && !volume_success(400));
    assert_eq!(clamp_volume_db(5.0), 0.0);
    assert_eq!(clamp_volume_db(-99.0), -30.0);
}

/// A fake stream whose writes land in a shared buffer we can inspect after the
/// (consuming) event-channel loop finishes.
struct SharedStream {
    to_read: std::io::Cursor<Vec<u8>>,
    written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}
impl std::io::Read for SharedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.to_read.read(buf)
    }
}
impl std::io::Write for SharedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn event_channel_answers_200() {
    use airplay_rs::crypto::HapCipher;
    use airplay_rs::session::{event_channel_keys, EventChannel, EventChannelConn};

    let shared: Vec<u8> = (0u8..32).collect();
    let keys = event_channel_keys(&shared);
    // The receiver (peer) writes with OUR read key and reads with OUR write key.
    let mut peer = HapCipher::new(keys.read_key, keys.write_key);

    // Peer sends a POST /command with CSeq 7; sealed as HAP frames.
    let request = b"POST /command RTSP/1.0\r\nCSeq: 7\r\nContent-Length: 0\r\n\r\n";
    let sealed_request = peer.seal(request);

    let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stream = SharedStream {
        to_read: std::io::Cursor::new(sealed_request),
        written: written.clone(),
    };
    let ev = EventChannelConn::new(stream, &shared);
    // Runs until EOF (ConnectionClosed) -> Ok(()).
    ev.run().unwrap();

    // Decrypt what the channel wrote back: must be a sealed 200 echoing CSeq 7.
    let out = written.lock().unwrap().clone();
    assert!(out.len() >= 2 + 16);
    let aad = &out[..2];
    let size = u16::from_le_bytes([out[0], out[1]]) as usize;
    let sealed = &out[2..2 + size + 16];
    let plain = peer.open(aad, sealed).expect("reply opens with peer read key");
    assert_eq!(
        plain,
        b"RTSP/1.0 200 OK\r\nCSeq: 7\r\nContent-Length: 0\r\n\r\n"
    );
}

#[test]
fn control_setup_plist_roundtrips_through_plist_crate() {
    use airplay_rs::session::{
        build_control_setup_plist, parse_control_setup_response, SessionIds, TimingProtocol,
    };
    // Generated ids (random) must still produce a structurally valid plist that
    // the plist crate can decode, and our response parser tolerates a body with
    // no ports.
    let ids = SessionIds::generate();
    assert!(ids.audio_sc_id < (1u64 << 63));
    assert!(ids.video_sc_id < (1u64 << 63));
    assert!(ids.mac.starts_with("02:") && ids.mac.len() == 17);
    assert_eq!(ids.session_uuid, ids.session_uuid.to_ascii_uppercase());

    let body = build_control_setup_plist(&ids, TimingProtocol::Ntp, 60000);
    // Decodes as a plist dictionary with the fixed fields.
    let val = plist::Value::from_reader(std::io::Cursor::new(&body)).unwrap();
    let d = val.as_dictionary().unwrap();
    assert_eq!(d.get("sourceVersion").unwrap().as_string(), Some("980.71.1"));
    assert_eq!(d.get("timingProtocol").unwrap().as_string(), Some("NTP"));
    assert_eq!(d.get("timingPort").unwrap().as_unsigned_integer(), Some(60000));
    assert_eq!(d.get("deviceID").unwrap().as_string(), Some(ids.mac.as_str()));

    // A response body without eventPort/timingPort/skipRecord -> all defaults.
    let empty = airplay_rs::bplist::encode(&airplay_rs::bplist::Node::Dict(vec![]));
    let r = parse_control_setup_response(&empty);
    assert!(r.event_port.is_none() && r.timing_port.is_none() && !r.skip_record);
}

// ---------------------------------------------------------------------------
// Audio (Milestone 4): tests/vectors/audio-packets.json, generated by RUNNING
// probe.py's alac_uncompressed_frame / AudioSender.run / AudioSender._sync
// with fake sockets and a fake clock (tests/vectors/gen_audio_vectors.py).
// ---------------------------------------------------------------------------

fn audio_doc() -> serde_json::Value {
    load("audio-packets.json")
}

fn audio_shk(doc: &serde_json::Value) -> [u8; 32] {
    unhex(doc["inputs"]["shk_hex"].as_str().unwrap()).try_into().unwrap()
}

/// The generator's deterministic PCM: n = frame*352 + j;
/// L = i16((n*7919) mod 65536); R = i16((n*104729+12345) mod 65536).
fn formula_pcm(frame: u64) -> [u8; 1408] {
    let mut out = [0u8; 1408];
    for j in 0..352u64 {
        let n = frame * 352 + j;
        let l = ((n * 7919) & 0xFFFF) as u16;
        let r = ((n * 104729 + 12345) & 0xFFFF) as u16;
        let o = j as usize * 4;
        out[o..o + 2].copy_from_slice(&l.to_le_bytes());
        out[o + 2..o + 4].copy_from_slice(&r.to_le_bytes());
    }
    out
}

#[test]
fn audio_alac_vectors() {
    use airplay_rs::audio::{alac_escape_decode, alac_escape_frame};
    let doc = audio_doc();
    let cases = doc["alac_frames"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for c in cases {
        let pcm: [u8; 1408] = unhex(c["pcm_s16le_hex"].as_str().unwrap()).try_into().unwrap();
        let got = alac_escape_frame(&pcm);
        assert_eq!(hex::encode(got), c["alac_hex"].as_str().unwrap(), "case {}", c["name"]);
        assert_eq!(alac_escape_decode(&got), Some(pcm), "roundtrip {}", c["name"]);
    }
    // The generator's formula PCM is the same function the sequences use.
    let f0 = cases.iter().find(|c| c["name"] == "formula_frame0").unwrap();
    assert_eq!(hex::encode(formula_pcm(0)), f0["pcm_s16le_hex"].as_str().unwrap());
}

#[test]
fn audio_sync_vectors() {
    use airplay_rs::audio::time_announce;
    use airplay_rs::clock::ClockReading;
    let doc = audio_doc();
    let syncs = doc["sync_packets"].as_array().unwrap();
    assert_eq!(syncs.len(), 5);
    for s in syncs {
        let reading = ClockReading::from_boottime_secs_f64(s["boottime"].as_f64().unwrap());
        assert_eq!(reading.ntp().0, s["ntp"].as_u64().unwrap(), "ntp conversion {s}");
        let got = time_announce(
            s["first"].as_bool().unwrap(),
            s["rtp_now"].as_u64().unwrap() as u32,
            s["latency_samples"].as_u64().unwrap() as u32,
            reading.ntp(),
        );
        assert_eq!(hex::encode(got), s["hex"].as_str().unwrap(), "sync {s}");
    }
}

/// Replay one probe AudioSender trace through AudioTimeline, driving the clock
/// with the trace's own per-frame times (boot = mono + offset, as the probe's
/// patched clock_gettime did), and assert the produced packet stream equals the
/// trace event for event: every sync byte-exact, every data packet by sha256
/// (and full hex where the vector carries it), same order.
fn replay_audio_sequence(
    doc: &serde_json::Value,
    seqdoc: &serde_json::Value,
    pcm_for: impl Fn(u64) -> [u8; 1408],
) -> airplay_rs::audio::AudioStats {
    use airplay_rs::audio::{AudioLatency, AudioTimeline};
    use airplay_rs::clock::ClockReading;
    use sha2::Digest;
    let inp = &doc["inputs"];
    let offset = inp["boottime_minus_monotonic"].as_f64().unwrap();
    let latency = AudioLatency::new(inp["latency_ms"].as_u64().unwrap() as u32, 0).unwrap();
    assert_eq!(latency.samples() as u64, inp["latency_samples"].as_u64().unwrap());
    let mut tl = AudioTimeline::new(
        audio_shk(doc),
        &latency,
        seqdoc["seq0"].as_u64().unwrap() as u16,
        seqdoc["rtp0"].as_u64().unwrap() as u32,
    );
    let events = seqdoc["events"].as_array().unwrap();
    let data: Vec<&serde_json::Value> = events.iter().filter(|e| e["kind"] == "data").collect();
    let frames = seqdoc["frames"].as_u64().unwrap();
    assert_eq!(data.len() as u64, frames);

    // (kind, bytes) in the order the sender would put them on the wire.
    let mut produced: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for (i, ev) in data.iter().enumerate() {
        assert_eq!(ev["frame"].as_u64().unwrap(), i as u64);
        let now = ClockReading::from_boottime_secs_f64(ev["mono"].as_f64().unwrap() + offset);
        let e = tl.emit(&pcm_for(i as u64), now);
        if let Some(s) = e.sync {
            produced.push(("sync", s.to_vec()));
        }
        produced.push(("data", e.rtp.to_vec()));
        if let Some(s) = tl.periodic(now) {
            produced.push(("sync", s.to_vec()));
        }
    }

    assert_eq!(produced.len(), events.len(), "event count");
    for (k, ((kind, bytes), ev)) in produced.iter().zip(events).enumerate() {
        assert_eq!(*kind, ev["kind"].as_str().unwrap(), "event {k} kind");
        if *kind == "sync" {
            assert_eq!(hex::encode(bytes), ev["hex"].as_str().unwrap(), "event {k} sync bytes");
            assert_eq!(ev["dest_port"], inp["receiver_control_port"]);
        } else {
            assert_eq!(bytes.len() as u64, ev["len"].as_u64().unwrap());
            assert_eq!(hex::encode(&bytes[..12]), ev["header_hex"].as_str().unwrap(), "event {k} header");
            assert_eq!(
                hex::encode(sha2::Sha256::digest(bytes)),
                ev["sha256"].as_str().unwrap(),
                "event {k} (frame {}) sha256",
                ev["frame"]
            );
            if let Some(h) = ev.get("hex") {
                assert_eq!(hex::encode(bytes), h.as_str().unwrap(), "event {k} full hex");
            }
            assert_eq!(ev["dest_port"], inp["receiver_data_port"]);
        }
    }
    let st = tl.stats();
    let want = &seqdoc["stats"];
    assert_eq!(st.packets, want["packets"].as_u64().unwrap());
    assert_eq!(st.syncs, want["syncs"].as_u64().unwrap());
    assert_eq!(st.anchors, want["anchors"].as_u64().unwrap());
    st
}

#[test]
fn audio_sequence_stall_reanchor() {
    let doc = audio_doc();
    let seq = &doc["sequence_stall_reanchor"];
    let st = replay_audio_sequence(&doc, seq, formula_pcm);
    assert_eq!((st.anchors, st.syncs, st.gap_reanchors, st.late_reanchors), (2, 3, 1, 0));

    // Spot checks on the shape the plan pins: 0x90 before frame 0, 0x80 right
    // after frame 126 carrying rtp 0xaca0, 0x90 right before frame 200 carrying
    // rtp 0x11100 (rtp continuous across the re-anchor; only the NTP jumps).
    let ev = seq["events"].as_array().unwrap();
    let pos = |f: u64| ev.iter().position(|e| e["kind"] == "data" && e["frame"] == f).unwrap();
    assert_eq!(pos(0), 1);
    assert!(ev[0]["first"].as_bool().unwrap());
    let after126 = &ev[pos(126) + 1];
    assert_eq!((after126["kind"].as_str(), after126["first"].as_bool()), (Some("sync"), Some(false)));
    assert_eq!(after126["rtp_now"].as_u64(), Some(0xaca0));
    let before200 = &ev[pos(200) - 1];
    assert_eq!((before200["kind"].as_str(), before200["first"].as_bool()), (Some("sync"), Some(true)));
    assert_eq!(before200["rtp_now"].as_u64(), Some(0x11100));
    assert_eq!(ev[pos(200)]["rtp"].as_u64(), Some(0x11100));
}

#[test]
fn audio_sequence_small_gap_no_reanchor() {
    // A 200 ms stall at 300 ms latency leaves 100 ms of slack: neither the gap
    // rule (> 250 ms) nor the lateness guard (LATE_MARGIN = 50 ms) may fire.
    let doc = audio_doc();
    let st = replay_audio_sequence(&doc, &doc["sequence_small_gap_no_reanchor"], formula_pcm);
    assert_eq!((st.anchors, st.gap_reanchors, st.late_reanchors), (1, 0, 0));
}

#[test]
fn audio_sequence_tone() {
    // The probe's real tone generator (AudioSender._frames tone path).
    use airplay_rs::audio::{tone_frame, ALAC_SPF};
    let doc = audio_doc();
    let seq = &doc["sequence_tone"];
    let level = seq["tone_level"].as_f64().unwrap();
    let st = replay_audio_sequence(&doc, seq, |i| tone_frame(i * ALAC_SPF as u64, level));
    assert_eq!(st.anchors, 1);
}

#[test]
fn audio_latency_single_source() {
    use airplay_rs::audio::{latency_samples, AudioLatency};
    use airplay_rs::session::{build_audio_setup_plist, build_audio_setup_plist_latency};
    let doc = audio_doc();
    let inp = &doc["inputs"];
    assert_eq!(latency_samples(300) as u64, inp["latency_samples"].as_u64().unwrap());
    assert_eq!(latency_samples(300), 13230);
    for s in doc["sync_packets"].as_array().unwrap() {
        assert_eq!(s["latency_samples"].as_u64().unwrap(), 13230);
    }

    // The latency-object SETUP builder is byte-identical to the existing
    // golden audio SETUP plist at offset 0.
    let setup = load("setup-events-feedback.json");
    let sin = &setup["inputs"];
    let shk32: [u8; 32] = (0x40u8..0x60).collect::<Vec<u8>>().try_into().unwrap();
    assert_eq!(shk32, audio_shk(&doc));
    let ms = sin["audio_latency_ms"].as_u64().unwrap() as u32;
    let sc = sin["audio_stream_connection_id"].as_u64().unwrap();
    let port = (sin["timing_port"].as_u64().unwrap() as u16) + 1;
    let via_latency = build_audio_setup_plist_latency(sc, port, &AudioLatency::new(ms, 0).unwrap(), &shk32);
    assert_eq!(hex::encode(&via_latency), setup["audio_setup_plist"]["binary_plist_hex"].as_str().unwrap());
    assert_eq!(via_latency, build_audio_setup_plist(sc, port, ms, &shk32));

    // With an A/V offset, SETUP latencyMax and the sync latency field move
    // together (SETUP value read back through the plist crate).
    for off in [-100, 0, 250, 1500] {
        let lat = AudioLatency::new(300, off).unwrap();
        let body = build_audio_setup_plist_latency(sc, port, &lat, &shk32);
        let v = plist::Value::from_reader(std::io::Cursor::new(body)).unwrap();
        let lm = v.as_dictionary().unwrap()["streams"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap()["latencyMax"]
            .as_unsigned_integer()
            .unwrap();
        assert_eq!(lm, lat.samples() as u64, "offset {off}");
    }
}

#[test]
fn audio_rtsp_volume_vectors() {
    // The Rust volume requests are byte-identical to what the probe's
    // RtspConnection._request put on the wire for the proven form: audio URI,
    // text/parameters, NO Session header. Replies 200 and 500 both count.
    use airplay_rs::rtsp::build_request;
    use airplay_rs::session::volume_success;
    use airplay_rs::volume::{
        parse_get_parameter_volume, volume_body_text, volume_get_request, volume_set_request, LaptopLevel, TvVolume,
        VOLUME_CONTENT_TYPE,
    };
    let doc = audio_doc();
    let cases = doc["rtsp_volume"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    let mut reachable = 0;
    for c in cases {
        let uri = c["uri"].as_str().unwrap();
        let want = unhex(c["request_hex"].as_str().unwrap());
        let reply = unhex(c["reply_hex"].as_str().unwrap());
        let (msg, used) = airplay_rs::rtsp::try_parse_message(&reply).unwrap();
        assert_eq!(used, reply.len());
        assert_eq!(msg.status_code() as u64, c["status"].as_u64().unwrap());
        assert!(volume_success(msg.status_code()), "{} counts as success", msg.status_code());
        match c["method"].as_str().unwrap() {
            "GET_PARAMETER" => {
                assert_eq!(volume_get_request(uri, 1), want);
                assert_eq!(parse_get_parameter_volume(&msg.body), Some(-20.4));
            }
            "SET_PARAMETER" => {
                // Body text: the dB value the probe sent.
                let body = &want[want.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
                let db: f64 = std::str::from_utf8(body).unwrap().trim().strip_prefix("volume: ").unwrap().parse().unwrap();
                let x100 = (db * 100.0).round() as i32;
                assert_eq!(volume_body_text(x100).as_bytes(), body);
                assert_eq!(
                    build_request("SET_PARAMETER", uri, 1, &[], &[], Some(VOLUME_CONTENT_TYPE), volume_body_text(x100).as_bytes()),
                    want
                );
                // Where the policy can produce this value, the TvVolume path
                // produces exactly these bytes. (-30 and -20 are deliberately
                // unreachable: 0 % sends -144, and 33.3 % is not a percent.)
                let hit = (0..=100u8).flat_map(|p| [(p, false), (p, true)]).find_map(|(p, m)| {
                    let raw = (p as u32 * 65536 + 50) / 100;
                    let l = LaptopLevel::from_pactl(
                        &format!("Volume: front-left: {raw} / {p}% / 0 dB,   front-right: {raw} / {p}% / 0 dB"),
                        if m { "Mute: yes" } else { "Mute: no" },
                    )
                    .unwrap();
                    let v = TvVolume::from_laptop(l);
                    (v.db_x100() == x100).then_some(v)
                });
                match hit {
                    Some(v) => {
                        reachable += 1;
                        assert_eq!(volume_set_request(uri, 1, &v), want);
                    }
                    None => assert!(x100 == -3000 || x100 == -2000, "{x100} should be reachable"),
                }
            }
            m => panic!("method {m}"),
        }
    }
    assert_eq!(reachable, 3, "-144, -24.9 and -15 are produced by the policy");
}

/// SYNTHETIC: the dvlc body is built with plistlib from the decoded dict the
/// probe logged, not the TV's raw bytes. Proves the event channel still
/// answers byte-identically and forwards the parsed volume.
#[test]
fn dvlc_event_synthetic_parses() {
    use airplay_rs::crypto::HapCipher;
    use airplay_rs::session::{event_channel_keys, event_ok_reply, EventChannel, EventChannelConn, ReceiverEvent};

    let doc = audio_doc();
    let body = unhex(doc["dvlc_event"]["binary_plist_hex"].as_str().unwrap());
    let shared: Vec<u8> = (0u8..32).collect();
    let keys = event_channel_keys(&shared);
    let mut peer = HapCipher::new(keys.read_key, keys.write_key);
    let mut req = format!("POST /command RTSP/1.0\r\nCSeq: 9\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    req.extend_from_slice(&body);
    let mut update = b"POST /command RTSP/1.0\r\nCSeq: 10\r\nContent-Length: ".to_vec();
    let mut ui = Vec::new();
    plist::to_writer_binary(&mut ui, &plist::Value::Dictionary({
        let mut d = plist::Dictionary::new();
        d.insert("type".into(), "updateInfo".into());
        d
    }))
    .unwrap();
    update.extend_from_slice(format!("{}\r\n\r\n", ui.len()).as_bytes());
    update.extend_from_slice(&ui);
    let mut wire = peer.seal(&req);
    wire.extend(peer.seal(&update));

    let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stream = SharedStream { to_read: std::io::Cursor::new(wire), written: written.clone() };
    let (tx, rx) = std::sync::mpsc::sync_channel(4);
    EventChannelConn::with_events(stream, &shared, tx).run().unwrap();

    // Replies: byte-identical to event_ok_reply, in order.
    let out = written.lock().unwrap().clone();
    let mut off = 0;
    for cseq in ["9", "10"] {
        let size = u16::from_le_bytes([out[off], out[off + 1]]) as usize;
        let plain = peer.open(&out[off..off + 2], &out[off + 2..off + 2 + size + 16]).unwrap();
        assert_eq!(plain, event_ok_reply(cseq));
        off += 2 + size + 16;
    }
    assert_eq!(off, out.len());
    let evs: Vec<ReceiverEvent> = rx.try_iter().collect();
    assert_eq!(evs, vec![ReceiverEvent::Volume { v: 0.18, muted: false }, ReceiverEvent::UpdateInfo]);
}
