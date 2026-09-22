//! TEST ONLY: a fake AirPlay receiver on 127.0.0.1 that speaks the PAIRING
//! endpoints — `/pair-pin-start`, `/pair-setup` and `/pair-verify` — and
//! nothing else worth the name.
//!
//! It implements the accessory half of pair-verify for real (X25519, the
//! `PV-Msg02` seal, an Ed25519 signature over `tv_eph || tv_id || our_eph`),
//! so a test can prove that a session ACCEPTED stored credentials rather than
//! merely that it sent them: once M4 is answered the fake switches to the
//! control cipher derived from the same secret, and any request it can read
//! after that could only have been sealed with matching keys.
//!
//! It does NOT implement the SRP server, so transient pairing can only be
//! refused here. That is deliberate — transient SUCCESS is the path with
//! years of mileage against the real receiver, and these tests are about the
//! refusals.
#![allow(dead_code)]

use airplay_rs::crypto::HapCipher;
use airplay_rs::pairing::{tlv8, Credentials};
use airplay_rs::rtsp::RtspConnection;
use airplay_rs::session::SessionConfig;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq)]
pub enum Verify {
    /// A receiver that knows us: real signature, real shared secret.
    Accept,
    /// A receiver that has forgotten us (reset, pairings cleared) — its
    /// signature is made with a key our credentials do not name. Indistinguishable
    /// from a corrupt credential, and handled the same way.
    Stale,
    /// A receiver that answers M2 with a HAP error.
    Error(u8),
}

#[derive(Clone, Copy, PartialEq)]
pub enum Transient {
    /// "Wrong PIN" — what a receiver with an AirPlay code set says to the
    /// transient `3939`.
    Refused,
    /// A receiver that is simply not well.
    Unavailable,
}

pub struct Fake {
    pub port: u16,
    /// Every request URI, in arrival order across every connection.
    seen: Arc<Mutex<Vec<String>>>,
    /// The same, tagged with which connection carried it. `pair --interactive`
    /// lives or dies on the whole exchange being on ONE connection, so the
    /// tests need to be able to say so.
    seen_by_conn: Arc<Mutex<Vec<(usize, String)>>>,
    /// The TV's long-term key, for building the credentials a test hands in.
    tv_ltpk_hex: String,
    tv_id: String,
    stop: Arc<AtomicBool>,
    accept_join: Option<std::thread::JoinHandle<()>>,
}

/// The listening socket is released when the fake goes out of scope, not when
/// the process ends. Two tests in one binary both want port 7000, and a
/// listener left running would fail the second with "address already in use" —
/// which is a harness bug wearing an environment bug's clothes.
impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the blocking `accept` with one throwaway connection.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(j) = self.accept_join.take() {
            let _ = j.join();
        }
    }
}

impl Fake {
    /// On an ephemeral port, for tests that inject the dialler.
    pub fn start(verify: Verify, transient: Transient) -> Fake {
        Fake::start_on(0, verify, transient)
    }

    /// On a named port. Only the CLI tests need this — the `airplay` binary
    /// dials 7000 and the AirPlay port is not configurable, deliberately.
    pub fn start_on(want_port: u16, verify: Verify, transient: Transient) -> Fake {
        use ed25519_dalek::SigningKey;
        let tv_ltsk = SigningKey::generate(&mut rand::rngs::OsRng);
        let tv_ltpk_hex = hex::encode(tv_ltsk.verifying_key().to_bytes());
        let tv_id = "AA:BB:CC:DD:EE:FF".to_string();

        let listener = TcpListener::bind(("127.0.0.1", want_port)).unwrap_or_else(|e| {
            panic!(
                "fake receiver cannot bind 127.0.0.1:{want_port} ({e}). \
                 Something else on this machine is listening there \
                 (`ss -ltnp | grep {want_port}`); this test needs it free."
            )
        });
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_conn: Arc<Mutex<Vec<(usize, String)>>> = Arc::new(Mutex::new(Vec::new()));

        let stop = Arc::new(AtomicBool::new(false));
        let (seen_t, tv_id_t, stop_t) = (seen.clone(), tv_id.clone(), stop.clone());
        let by_conn_t = seen_by_conn.clone();
        let next_conn = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accept_join = std::thread::spawn(move || {
            // One thread per connection: `run_session` opens a fresh one per
            // attempt, exactly as the probe does.
            while let Ok((sock, _)) = listener.accept() {
                if stop_t.load(Ordering::SeqCst) {
                    return;
                }
                let (seen_c, tv_id_c) = (seen_t.clone(), tv_id_t.clone());
                let by_conn_c = by_conn_t.clone();
                let id = next_conn.fetch_add(1, Ordering::SeqCst);
                let signing = SigningKey::from_bytes(&tv_ltsk.to_bytes());
                std::thread::spawn(move || {
                    serve(sock, verify, transient, signing, tv_id_c, seen_c, by_conn_c, id);
                });
            }
        });
        Fake {
            port,
            seen,
            seen_by_conn,
            tv_ltpk_hex,
            tv_id,
            stop,
            accept_join: Some(accept_join),
        }
    }

    /// Credentials naming THIS fake's long-term key.
    pub fn credentials(&self) -> Credentials {
        use ed25519_dalek::SigningKey;
        let ours = SigningKey::generate(&mut rand::rngs::OsRng);
        Credentials {
            hkp: 3,
            pairing_id: "11111111-2222-3333-4444-555555555555".into(),
            ltsk: hex::encode(ours.to_bytes()),
            tv_id: self.tv_id.clone(),
            tv_ltpk: self.tv_ltpk_hex.clone(),
            host: None,
        }
    }

    pub fn config(&self, creds: Option<Credentials>) -> SessionConfig {
        let mut cfg = SessionConfig::new("127.0.0.1");
        cfg.credentials = creds;
        cfg
    }

    pub fn dial(&self) -> impl Fn(&str) -> std::io::Result<RtspConnection<TcpStream>> {
        let port = self.port;
        move |_host: &str| {
            let s = TcpStream::connect(("127.0.0.1", port))?;
            s.set_nodelay(true)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            Ok(RtspConnection::new(s))
        }
    }

    pub fn uris(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    /// `(connection index, uri)` in arrival order.
    pub fn uris_by_conn(&self) -> Vec<(usize, String)> {
        self.seen_by_conn.lock().unwrap().clone()
    }

    /// How many connections have carried at least one request.
    pub fn connections_used(&self) -> usize {
        let log = self.seen_by_conn.lock().unwrap();
        let mut ids: Vec<usize> = log.iter().map(|(i, _)| *i).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }
}

fn reply(status: u16, cseq: &str, body: &[u8]) -> Vec<u8> {
    let reason = if status == 200 { "OK" } else { "Error" };
    let mut r = format!(
        "RTSP/1.0 {status} {reason}\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn seal(key: &[u8; 32], label: &str, plain: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    let nonce = airplay_rs::pairing::nonce_label(label);
    ChaCha20Poly1305::new(key.into()).encrypt((&nonce).into(), plain).unwrap()
}

fn serve(
    sock: TcpStream,
    verify: Verify,
    transient: Transient,
    tv_ltsk: ed25519_dalek::SigningKey,
    tv_id: String,
    seen: Arc<Mutex<Vec<String>>>,
    seen_by_conn: Arc<Mutex<Vec<(usize, String)>>>,
    conn_id: usize,
) {
    use ed25519_dalek::{Signer, SigningKey};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let mut conn: RtspConnection<TcpStream> = RtspConnection::new(sock);
    // Set once the verify handshake completes, so everything after M4 is on
    // the encrypted control channel the session expects.
    let mut pending_cipher: Option<HapCipher> = None;

    loop {
        let Ok(msg) = conn.read_message() else { return };
        let mut parts = msg.first_line.split_whitespace();
        let _method = parts.next().unwrap_or("");
        let uri = parts.next().unwrap_or("").to_string();
        let cseq = msg.header("cseq").unwrap_or("0").to_string();
        seen.lock().unwrap().push(uri.clone());
        seen_by_conn.lock().unwrap().push((conn_id, uri.clone()));

        let out = match uri.as_str() {
            "/pair-pin-start" => reply(200, &cseq, &[]),
            "/pair-setup" => {
                let m = tlv8::decode(&msg.body);
                let state = m.get(&tlv8::STATE).and_then(|v| v.first().copied()).unwrap_or(0);
                // The transient M1 carries the FLAGS tag; the PIN M1 does not.
                // That is the only thing that tells the two flows apart on the
                // wire, and it is how a real receiver tells them apart too.
                let is_transient = m.contains_key(&tlv8::FLAGS);
                if state == 0x01 && is_transient {
                    // Refuse, in one of the two ways that matter.
                    let code = match transient {
                        Transient::Refused => 2u8,   // kTLVError_Authentication
                        Transient::Unavailable => 6, // kTLVError_Unavailable
                    };
                    reply(
                        200,
                        &cseq,
                        &tlv8::encode(&[(tlv8::STATE, &[0x02]), (tlv8::ERROR, &[code])]),
                    )
                } else if state == 0x01 {
                    // PIN M1 -> a well-formed M2. The SRP server is not
                    // implemented — salt and B are random — so the client's
                    // proof can never match and M4 always refuses. That is
                    // enough for every test here: what is under test is the
                    // ORDER of events around the human, not the arithmetic,
                    // which the golden vectors already pin.
                    use rand::RngCore;
                    let mut salt = [0u8; 16];
                    let mut b = [0u8; 384];
                    rand::rngs::OsRng.fill_bytes(&mut salt);
                    rand::rngs::OsRng.fill_bytes(&mut b);
                    reply(
                        200,
                        &cseq,
                        &tlv8::encode(&[
                            (tlv8::STATE, &[0x02]),
                            (tlv8::SALT, &salt),
                            (tlv8::PUBLIC_KEY, &b),
                        ]),
                    )
                } else {
                    // M3 -> M4: the proof is wrong, because it must be.
                    reply(
                        200,
                        &cseq,
                        &tlv8::encode(&[(tlv8::STATE, &[0x04]), (tlv8::ERROR, &[2])]),
                    )
                }
            }
            "/pair-verify" => {
                let m = tlv8::decode(&msg.body);
                let state = m.get(&tlv8::STATE).and_then(|v| v.first().copied()).unwrap_or(0);
                if state == 0x01 {
                    if let Verify::Error(code) = verify {
                        reply(
                            200,
                            &cseq,
                            &tlv8::encode(&[(tlv8::STATE, &[0x02]), (tlv8::ERROR, &[code])]),
                        )
                    } else {
                        let their_eph: [u8; 32] = m
                            .get(&tlv8::PUBLIC_KEY)
                            .and_then(|v| v.as_slice().try_into().ok())
                            .expect("M1 carries a 32-byte public key");
                        let eph = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
                        let eph_pub = PublicKey::from(&eph).to_bytes();
                        let shared = eph.diffie_hellman(&PublicKey::from(their_eph)).to_bytes();
                        let vkey = airplay_rs::pairing::hkdf(
                            &shared,
                            "Pair-Verify-Encrypt-Salt",
                            "Pair-Verify-Encrypt-Info",
                        );

                        let mut smsg = eph_pub.to_vec();
                        smsg.extend_from_slice(tv_id.as_bytes());
                        smsg.extend_from_slice(&their_eph);
                        // A stale receiver signs with a key our credentials do
                        // not name, which is exactly what a reset TV looks like.
                        let signer = match verify {
                            Verify::Stale => SigningKey::generate(&mut rand::rngs::OsRng),
                            _ => SigningKey::from_bytes(&tv_ltsk.to_bytes()),
                        };
                        let sig = signer.sign(&smsg).to_bytes();
                        let inner = tlv8::encode(&[
                            (tlv8::IDENTIFIER, tv_id.as_bytes()),
                            (tlv8::SIGNATURE, &sig),
                        ]);
                        let sealed = seal(&vkey, "PV-Msg02", &inner);

                        // The session's control keys come off this secret; the
                        // receiver's read key is the sender's write key.
                        let (cw, cr) = airplay_rs::pairing::control_keys(&shared);
                        pending_cipher = Some(HapCipher::new(cr, cw));

                        reply(
                            200,
                            &cseq,
                            &tlv8::encode(&[
                                (tlv8::STATE, &[0x02]),
                                (tlv8::PUBLIC_KEY, &eph_pub),
                                (tlv8::ENCRYPTED, &sealed),
                            ]),
                        )
                    }
                } else {
                    // M3 -> M4: accepted. Everything after this is encrypted.
                    let out = reply(200, &cseq, &tlv8::encode(&[(tlv8::STATE, &[0x04])]));
                    if conn.send_sealed(&out).is_err() {
                        return;
                    }
                    if let Some(c) = pending_cipher.take() {
                        conn.set_cipher(c);
                    }
                    continue;
                }
            }
            // Past pairing. Answering /info at all proves the encrypted channel
            // came up — this request arrived sealed with keys derived from the
            // pair-verify secret and was decrypted here. 503 stops the session
            // one step later, with an error that names exactly that step.
            "/info" => reply(503, &cseq, &[]),
            _ => reply(200, &cseq, &[]),
        };
        if conn.send_sealed(&out).is_err() {
            return;
        }
    }
}

