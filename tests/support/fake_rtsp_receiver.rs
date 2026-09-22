//! TEST ONLY: a fake AirPlay control endpoint on 127.0.0.1.
//!
//! Speaks just enough of the encrypted RTSP control protocol for
//! `Session::bring_up` and the audio/volume paths: GET /info, control SETUP,
//! RECORD, audio (type 96) and video (type 110) SETUP, POST /feedback,
//! GET_PARAMETER / SET_PARAMETER volume (answering SET with 500, like the
//! Frame), TEARDOWN. Optionally it offers an event port and, as the receiver
//! does, connects nothing itself: the sender connects to it, and the test
//! pushes events (e.g. a `dvlc`) down that connection.
//!
//! Every request is logged with its BOOTTIME arrival. Nothing here talks to
//! anything but 127.0.0.1.
#![allow(dead_code)]

use airplay_rs::crypto::HapCipher;
use airplay_rs::rtsp::RtspConnection;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Req {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// CLOCK_BOOTTIME seconds at arrival.
    pub at: f64,
}

impl Req {
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    pub fn plist(&self) -> Option<plist::Dictionary> {
        plist::Value::from_reader(std::io::Cursor::new(&self.body)).ok()?.into_dictionary()
    }
    /// The `streams[0]` dictionary of a stream SETUP.
    pub fn stream0(&self) -> Option<plist::Dictionary> {
        self.plist()?.get("streams")?.as_array()?.first()?.as_dictionary().cloned()
    }
}

pub struct Behaviour {
    /// (dataPort, controlPort) to answer the type-96 SETUP with.
    pub audio_ports: (u16, u16),
    pub audio_status: u16,
    pub video_status: u16,
    pub offer_event_port: bool,
    /// Initial TV volume in dB, as GET_PARAMETER reports it.
    pub volume_db: f64,
    /// false: a deaf TV that answers SET_PARAMETER but never applies it.
    pub apply_volume_set: bool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Behaviour {
            audio_ports: (0, 0),
            audio_status: 200,
            video_status: 200,
            offer_event_port: false,
            volume_db: -20.4,
            apply_volume_set: true,
        }
    }
}

pub struct FakeRtspReceiver {
    pub port: u16,
    pub log: Arc<Mutex<Vec<Req>>>,
    pub volume_db: Arc<Mutex<f64>>,
    event_tx: Option<mpsc::Sender<Vec<u8>>>,
    event_replies: Arc<Mutex<Vec<u16>>>,
    threads: Vec<JoinHandle<()>>,
}

fn boot() -> f64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

fn plist_bin(v: plist::Value) -> Vec<u8> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &v).unwrap();
    out
}

fn dict(entries: Vec<(&str, plist::Value)>) -> plist::Value {
    let mut d = plist::Dictionary::new();
    for (k, v) in entries {
        d.insert(k.into(), v);
    }
    plist::Value::Dictionary(d)
}

fn reply(status: u16, cseq: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let mut r = format!("RTSP/1.0 {status} {reason}\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}

impl FakeRtspReceiver {
    pub fn start(shared: &[u8], b: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let volume_db = Arc::new(Mutex::new(b.volume_db));
        let (cw, cr) = airplay_rs::crypto::control_keys(shared);
        let mut threads = vec![];

        // Event port (the receiver is the RTSP client on it).
        let mut event_port = None;
        let mut event_tx = None;
        let event_replies = Arc::new(Mutex::new(vec![]));
        if b.offer_event_port {
            let el = TcpListener::bind("127.0.0.1:0").unwrap();
            event_port = Some(el.local_addr().unwrap().port());
            let (tx, rx) = mpsc::channel::<Vec<u8>>();
            event_tx = Some(tx);
            let keys = airplay_rs::session::event_channel_keys(shared);
            let replies = event_replies.clone();
            threads.push(std::thread::spawn(move || {
                let Ok((sock, _)) = el.accept() else { return };
                let mut conn = RtspConnection::new(sock);
                conn.set_cipher(HapCipher::new(keys.read_key, keys.write_key));
                for body in rx {
                    match conn.request(
                        "POST",
                        "/command",
                        &[],
                        Some("application/x-apple-binary-plist"),
                        &body,
                        Some(Duration::from_secs(2)),
                    ) {
                        Ok((st, _)) => replies.lock().unwrap().push(st),
                        Err(_) => return,
                    }
                }
            }));
        }

        let (log_t, vol_t) = (log.clone(), volume_db.clone());
        threads.push(std::thread::spawn(move || {
            let Ok((sock, _)) = listener.accept() else { return };
            let mut conn: RtspConnection<TcpStream> = RtspConnection::new(sock);
            // Receiver side: writes with the sender's read key.
            conn.set_cipher(HapCipher::new(cr, cw));
            loop {
                let Ok(msg) = conn.read_message() else { return };
                let mut parts = msg.first_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let uri = parts.next().unwrap_or("").to_string();
                let req = Req { method: method.clone(), uri, headers: msg.headers.clone(), body: msg.body.clone(), at: boot() };
                let cseq = msg.header("cseq").unwrap_or("0").to_string();
                log_t.lock().unwrap().push(req.clone());
                let out = match method.as_str() {
                    "GET" => reply(
                        200,
                        &cseq,
                        &plist_bin(dict(vec![
                            ("model", "LS03F".into()),
                            (
                                "displays",
                                plist::Value::Array(vec![dict(vec![
                                    ("widthPixels", 1920u64.into()),
                                    ("heightPixels", 1080u64.into()),
                                ])]),
                            ),
                        ])),
                    ),
                    "SETUP" => {
                        let ty = req.stream0().and_then(|s| s.get("type").and_then(|t| t.as_unsigned_integer()));
                        match ty {
                            None => {
                                let mut e = vec![];
                                if let Some(p) = event_port {
                                    e.push(("eventPort", (p as u64).into()));
                                }
                                reply(200, &cseq, &plist_bin(dict(e)))
                            }
                            Some(96) => {
                                if b.audio_status != 200 {
                                    reply(b.audio_status, &cseq, &[])
                                } else {
                                    let s = dict(vec![
                                        ("type", 96u64.into()),
                                        ("dataPort", (b.audio_ports.0 as u64).into()),
                                        ("controlPort", (b.audio_ports.1 as u64).into()),
                                    ]);
                                    reply(200, &cseq, &plist_bin(dict(vec![("streams", plist::Value::Array(vec![s]))])))
                                }
                            }
                            Some(_) => {
                                if b.video_status != 200 {
                                    reply(b.video_status, &cseq, &[])
                                } else {
                                    let s = dict(vec![("type", 110u64.into()), ("dataPort", 1u64.into())]);
                                    reply(200, &cseq, &plist_bin(dict(vec![("streams", plist::Value::Array(vec![s]))])))
                                }
                            }
                        }
                    }
                    "GET_PARAMETER" => {
                        let v = *vol_t.lock().unwrap();
                        reply(200, &cseq, format!("volume: {v:.6}\r\n").as_bytes())
                    }
                    "SET_PARAMETER" => {
                        let text = String::from_utf8_lossy(&msg.body).to_string();
                        if !b.apply_volume_set {
                            // Deaf: acknowledged, never applied.
                        } else if let Some(v) = text.trim().strip_prefix("volume: ").and_then(|v| v.parse::<f64>().ok()) {
                            *vol_t.lock().unwrap() = v;
                        }
                        // The Frame applies it and answers 500.
                        reply(500, &cseq, &[])
                    }
                    _ => reply(200, &cseq, &[]),
                };
                if conn.send_sealed(&out).is_err() {
                    return;
                }
                if method == "TEARDOWN" {
                    return;
                }
            }
        }));
        FakeRtspReceiver { port, log, volume_db, event_tx, event_replies, threads }
    }

    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }

    /// Push one event (a binary plist body) down the event channel.
    pub fn send_event(&self, body: Vec<u8>) {
        self.event_tx.as_ref().expect("event port offered").send(body).unwrap();
    }

    pub fn event_replies(&self) -> Vec<u16> {
        self.event_replies.lock().unwrap().clone()
    }

    pub fn dvlc(v: f64, muted: bool) -> Vec<u8> {
        plist_bin(dict(vec![
            ("volume", v.into()),
            ("isMuted", muted.into()),
            ("type", "sendMediaRemoteCommand".into()),
            ("value", "dvlc".into()),
        ]))
    }

    pub fn connect(&self) -> RtspConnection<TcpStream> {
        let s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        s.set_nodelay(true).unwrap();
        RtspConnection::new(s)
    }
}
