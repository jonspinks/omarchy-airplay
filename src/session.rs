//! setup-events-feedback: control-channel session bring-up (SETUP -> RECORD ->
//! event channel -> audio/video SETUP -> feedback -> volume). Ported from
//! probe.run / probe.EventChannel / probe.FeedbackLoop / probe.volume_probe.

use std::time::Duration;

pub const SOURCE_VERSION: &str = "980.71.1";
pub const SENDER_NAME: &str = "Omarchy probe";
pub const ALAC_SPF: u32 = 352;
pub const AUDIO_RATE: u32 = 44100;
pub const AUDIO_FORMAT: u32 = 0x40000;
pub const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// HKDF-SHA512, len 32 (probe.hkdf).
pub fn hkdf_key(secret: &[u8], salt: &str, info: &str) -> [u8; 32] {
    crate::crypto::hkdf_sha512_32(secret, salt, info)
}

/// Timing protocol selector for control SETUP.
pub enum TimingProtocol {
    Ntp,
    Ptp,
}

/// Session-scoped identifiers, generated once per session.
pub struct SessionIds {
    pub session_uuid: String,
    pub audio_sc_id: u64,
    pub video_sc_id: u64,
    pub mac: String,
}

impl SessionIds {
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mask63 = (1u64 << 63) - 1;
        SessionIds {
            session_uuid: uuid::Uuid::new_v4()
                .to_string()
                .to_ascii_uppercase(),
            audio_sc_id: rng.gen::<u64>() & mask63,
            video_sc_id: rng.gen::<u64>() & mask63,
            mac: random_mac(&mut rng),
        }
    }
}

/// `"02:XX:XX:XX:XX:XX"` (locally-administered), port of probe.random_mac.
fn random_mac(rng: &mut impl rand::Rng) -> String {
    let octets: [u8; 6] = [
        0x02,
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
    ];
    octets
        .iter()
        .map(|o| format!("{o:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A fresh 63-bit stream-connection id (`random.getrandbits(63)`).
fn random_id63() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen::<u64>() & ((1u64 << 63) - 1)
}

/// A fresh random 32-byte stream key (`os.urandom(32)`).
fn random_shk() -> [u8; 32] {
    use rand::RngCore;
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

/// `rtsp://host:7000/{id}`.
pub fn audio_uri(host: &str, audio_sc_id: u64) -> String {
    format!("rtsp://{host}:7000/{audio_sc_id}")
}

/// Build the control-SETUP binary plist body (NTP path). Field order is fixed.
pub fn build_control_setup_plist(
    ids: &SessionIds,
    timing: TimingProtocol,
    timing_port: u16,
) -> Vec<u8> {
    use crate::bplist::Node;
    let timing_str = match timing {
        TimingProtocol::Ntp => "NTP",
        TimingProtocol::Ptp => "PTP",
    };
    // Insertion order mirrors probe.py; the writer sorts keys, but we keep the
    // reference order for readability.
    let mut fields: Vec<(String, Node)> = vec![
        ("deviceID".into(), Node::str(&ids.mac)),
        ("macAddress".into(), Node::str(&ids.mac)),
        ("sessionUUID".into(), Node::str(&ids.session_uuid)),
        ("sourceVersion".into(), Node::str(SOURCE_VERSION)),
        ("isScreenMirroringSession".into(), Node::boolean(true)),
        ("timingProtocol".into(), Node::str(timing_str)),
        ("osBuildVersion".into(), Node::str("13F69")),
        ("model".into(), Node::str("Linux")),
        ("name".into(), Node::str(SENDER_NAME)),
        ("updateSessionRequest".into(), Node::boolean(false)),
        (
            "combinedGetInfoWithControlSetup".into(),
            Node::boolean(true),
        ),
    ];
    // NTP appends timingPort; PTP would append timingPeerInfo/List (milestone).
    if matches!(timing, TimingProtocol::Ntp) {
        fields.push(("timingPort".into(), Node::int(timing_port as u64)));
    }
    crate::bplist::encode(&Node::Dict(fields))
}

/// Parsed subset of the control-SETUP response we act on.
pub struct ControlSetupResponse {
    pub event_port: Option<u16>,
    pub timing_port: Option<u16>,
    pub skip_record: bool,
}

pub fn parse_control_setup_response(plist_body: &[u8]) -> ControlSetupResponse {
    let dict = plist::Value::from_reader(std::io::Cursor::new(plist_body))
        .ok()
        .and_then(|v| v.into_dictionary());
    let port_of = |d: &plist::Dictionary, k: &str| -> Option<u16> {
        d.get(k).and_then(|v| {
            v.as_unsigned_integer()
                .map(|u| u as u16)
                .or_else(|| v.as_signed_integer().map(|i| i as u16))
        })
    };
    match dict {
        Some(d) => {
            let skip_record = d
                .get("skipRecord")
                .map(|v| {
                    v.as_boolean().unwrap_or(false)
                        || v.as_unsigned_integer().map(|u| u != 0).unwrap_or(false)
                })
                .unwrap_or(false);
            ControlSetupResponse {
                event_port: port_of(&d, "eventPort"),
                timing_port: port_of(&d, "timingPort"),
                skip_record,
            }
        }
        None => ControlSetupResponse {
            event_port: None,
            timing_port: None,
            skip_record: false,
        },
    }
}

/// RECORD request headers (sent unless skip_record).
pub fn record_headers(session_uuid: &str) -> Vec<(String, String)> {
    vec![
        ("Session".into(), session_uuid.to_string()),
        ("Range".into(), "npt=0-".into()),
        ("RTP-Info".into(), "seq=0;rtptime=0".into()),
    ]
}

/// Audio SETUP (type 96 ALAC). `latency_max = ms/1000*44100`.
pub fn build_audio_setup_plist(
    audio_sc_id: u64,
    control_port: u16,
    latency_ms: u32,
    shk: &[u8; 32],
) -> Vec<u8> {
    // AUDIO_LATENCY_SAMPLES; integer form, see audio::latency_samples.
    audio_setup_plist_body(audio_sc_id, control_port, crate::audio::latency_samples(latency_ms), shk)
}

/// Audio SETUP whose `latencyMax` is [`crate::audio::AudioLatency::samples`],
/// the same value every sync packet carries (base latency + A/V offset). With
/// `AudioLatency::new(ms, 0)` the bytes equal [`build_audio_setup_plist`]`(.., ms, ..)`.
pub fn build_audio_setup_plist_latency(
    audio_sc_id: u64,
    control_port: u16,
    latency: &crate::audio::AudioLatency,
    shk: &[u8; 32],
) -> Vec<u8> {
    audio_setup_plist_body(audio_sc_id, control_port, latency.samples(), shk)
}

fn audio_setup_plist_body(audio_sc_id: u64, control_port: u16, latency_max: u32, shk: &[u8; 32]) -> Vec<u8> {
    use crate::bplist::Node;
    let latency_max = latency_max as u64;
    let desc = Node::Dict(vec![
        ("type".into(), Node::int(96)),
        ("streamConnectionID".into(), Node::int(audio_sc_id)),
        ("ct".into(), Node::int(2)),
        ("spf".into(), Node::int(ALAC_SPF as u64)),
        ("sr".into(), Node::int(AUDIO_RATE as u64)),
        ("audioFormat".into(), Node::int(AUDIO_FORMAT as u64)),
        ("audioMode".into(), Node::str("default")),
        ("usingScreen".into(), Node::boolean(true)),
        ("latencyMin".into(), Node::int(0)),
        ("latencyMax".into(), Node::int(latency_max)),
        ("controlPort".into(), Node::int(control_port as u64)),
        ("shk".into(), Node::data(shk.to_vec())),
    ]);
    let root = Node::Dict(vec![("streams".into(), Node::Array(vec![desc]))]);
    crate::bplist::encode(&root)
}

/// Video SETUP (type 110). shk=control_write[:16], shiv=control_read[:16].
pub fn build_video_setup_plist(video_sc_id: u64, shk: &[u8; 16], shiv: &[u8; 16]) -> Vec<u8> {
    build_video_setup_plist_with_latency(video_sc_id, shk, shiv, 75)
}

/// As [`build_video_setup_plist`], with the declared `latencyMs` chosen by the
/// caller. The 3-argument form keeps the probe's 75 and is what the golden
/// vector pins, so the wire bytes for the proven path cannot drift.
pub fn build_video_setup_plist_with_latency(
    video_sc_id: u64,
    shk: &[u8; 16],
    shiv: &[u8; 16],
    latency_ms: u32,
) -> Vec<u8> {
    use crate::bplist::Node;
    let timestamp_info = Node::Array(
        ["SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc"]
            .iter()
            .map(|n| Node::Dict(vec![("name".into(), Node::str(*n))]))
            .collect(),
    );
    let stream = Node::Dict(vec![
        ("type".into(), Node::int(110)),
        ("streamConnectionID".into(), Node::int(video_sc_id)),
        ("latencyMs".into(), Node::int(latency_ms as u64)),
        ("timestampInfo".into(), timestamp_info),
        ("shk".into(), Node::data(shk.to_vec())),
        ("shiv".into(), Node::data(shiv.to_vec())),
    ]);
    let root = Node::Dict(vec![("streams".into(), Node::Array(vec![stream]))]);
    crate::bplist::encode(&root)
}

/// Extract dataPort for a given stream `type` from a SETUP response plist.
pub fn stream_data_port(plist_body: &[u8], stream_type: u32) -> Option<u16> {
    let dict = plist::Value::from_reader(std::io::Cursor::new(plist_body))
        .ok()?
        .into_dictionary()?;
    let streams = dict.get("streams")?.as_array()?;
    for st in streams {
        let sd = match st.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        let ty = sd
            .get("type")
            .and_then(|v| v.as_unsigned_integer().or_else(|| v.as_signed_integer().map(|i| i as u64)));
        if ty == Some(stream_type as u64) {
            return sd.get("dataPort").and_then(|v| {
                v.as_unsigned_integer()
                    .map(|u| u as u16)
                    .or_else(|| v.as_signed_integer().map(|i| i as u16))
            });
        }
    }
    None
}

/// `(dataPort, controlPort)` of the stream of `stream_type` in a SETUP reply.
/// None unless both are present and non-zero: an audio stream without the
/// receiver's control port cannot be anchored, so it must not be started.
pub fn stream_ports(plist_body: &[u8], stream_type: u32) -> Option<(u16, u16)> {
    let dict = plist::Value::from_reader(std::io::Cursor::new(plist_body))
        .ok()?
        .into_dictionary()?;
    let as_u64 = |v: &plist::Value| v.as_unsigned_integer().or_else(|| v.as_signed_integer().map(|i| i as u64));
    for st in dict.get("streams")?.as_array()? {
        let Some(sd) = st.as_dictionary() else { continue };
        if sd.get("type").and_then(as_u64) != Some(stream_type as u64) {
            continue;
        }
        let port = |k: &str| sd.get(k).and_then(as_u64).filter(|p| (1..=65535).contains(p)).map(|p| p as u16);
        return Some((port("dataPort")?, port("controlPort")?));
    }
    None
}

/// Something the receiver told us on the event channel.
#[derive(Clone, Debug, PartialEq)]
pub enum ReceiverEvent {
    /// `sendMediaRemoteCommand` / `dvlc`: the TV's own volume (0..1) changed.
    Volume { v: f64, muted: bool },
    /// `updateInfo` (the Frame sends a spurious `dvlc 0.0` right after it).
    UpdateInfo,
    /// Anything else, by its `type`.
    Other(String),
}

/// Parse an event-channel request body (binary plist). None when it is not a
/// plist dictionary.
pub fn parse_receiver_event(body: &[u8]) -> Option<ReceiverEvent> {
    let v = plist::Value::from_reader(std::io::Cursor::new(body)).ok()?;
    let d = v.as_dictionary()?;
    let ty = d.get("type").and_then(|t| t.as_string()).unwrap_or("");
    let value = d.get("value").and_then(|t| t.as_string());
    Some(match (ty, value) {
        ("sendMediaRemoteCommand", Some("dvlc")) => {
            let vol = d.get("volume").and_then(|x| {
                x.as_real()
                    .or_else(|| x.as_signed_integer().map(|i| i as f64))
                    .or_else(|| x.as_unsigned_integer().map(|u| u as f64))
            });
            match vol {
                Some(v) => ReceiverEvent::Volume {
                    v,
                    muted: d.get("isMuted").and_then(|m| m.as_boolean()).unwrap_or(false),
                },
                None => ReceiverEvent::Other("dvlc without volume".into()),
            }
        }
        ("updateInfo", _) => ReceiverEvent::UpdateInfo,
        (other, _) => ReceiverEvent::Other(other.to_string()),
    })
}

/// Event channel keys: REVERSED vs control (receiver is client here).
pub struct EventChannelKeys {
    pub write_key: [u8; 32],
    pub read_key: [u8; 32],
}

pub fn event_channel_keys(shared: &[u8]) -> EventChannelKeys {
    let (write_key, read_key) = crate::crypto::events_keys(shared);
    EventChannelKeys { write_key, read_key }
}

/// The reply we seal for every request on the event channel.
pub fn event_ok_reply(cseq: &str) -> Vec<u8> {
    format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: 0\r\n\r\n").into_bytes()
}

/// Drive the event channel: read request -> send event_ok_reply, forever.
pub trait EventChannel {
    fn run(self) -> std::io::Result<()>;
}

/// Event channel over a byte stream with the REVERSED cipher keys. The receiver
/// is the client here, so it drives requests and we answer 200. Generic over
/// the stream so it can be driven by an in-memory stream in tests; production
/// uses `std::net::TcpStream`.
pub struct EventChannelConn<S: std::io::Read + std::io::Write> {
    conn: crate::rtsp::RtspConnection<S>,
    events: Option<std::sync::mpsc::SyncSender<ReceiverEvent>>,
}

impl<S: std::io::Read + std::io::Write> EventChannelConn<S> {
    /// Wrap an already-connected stream to the receiver's event port and attach
    /// the reversed HAP cipher derived from `shared`.
    pub fn new(sock: S, shared: &[u8]) -> Self {
        let keys = event_channel_keys(shared);
        let mut conn = crate::rtsp::RtspConnection::new(sock);
        conn.set_cipher(crate::crypto::HapCipher::new(keys.write_key, keys.read_key));
        EventChannelConn { conn, events: None }
    }

    /// As [`new`](Self::new), and also forward each request's parsed body to
    /// `events`. The reply is written FIRST, byte-identical to
    /// [`event_ok_reply`], and the forward is a `try_send` that never blocks:
    /// a slow or absent consumer cannot delay the receiver's 200.
    pub fn with_events(sock: S, shared: &[u8], events: std::sync::mpsc::SyncSender<ReceiverEvent>) -> Self {
        let mut ev = Self::new(sock, shared);
        ev.events = Some(events);
        ev
    }
}

impl<S: std::io::Read + std::io::Write> EventChannel for EventChannelConn<S> {
    fn run(mut self) -> std::io::Result<()> {
        loop {
            // Read one request the receiver sends us; answer every one with a
            // sealed 200, echoing its CSeq (probe.py EventChannel.run).
            let msg = match self.conn.read_message() {
                Ok(m) => m,
                Err(crate::rtsp::RtspError::ConnectionClosed) => return Ok(()),
                Err(crate::rtsp::RtspError::Io(e)) => return Err(e),
                Err(e) => {
                    return Err(std::io::Error::other(e.to_string()))
                }
            };
            let cseq = msg.header("cseq").unwrap_or("0");
            let reply = event_ok_reply(cseq);
            // Sealing + write go through the connection's cipher.
            self.conn.send_sealed(&reply)?;
            // Only after the reply is on its way: parse and forward.
            if let Some(tx) = &self.events {
                if !msg.body.is_empty() {
                    if let Some(ev) = parse_receiver_event(&msg.body) {
                        let _ = tx.try_send(ev);
                    }
                }
            }
        }
    }
}

/// Feedback: POST /feedback, empty body, every 2s on the control connection.
pub const FEEDBACK_INTERVAL: Duration = Duration::from_secs(2);

/// Shared handle to the encrypted control connection the feedback loop and the
/// session driver both use. (`Arc<Mutex<..>>` so the loop can run on its own
/// thread while the main flow keeps issuing SETUP/RECORD/volume requests.)
///
/// The frozen skeleton typed this as a unit struct placeholder; a real feedback
/// loop needs the connection, so it now carries the shared handle — the
/// signature `spawn_feedback_loop(ControlConn) -> FeedbackHandle` is unchanged.
#[derive(Clone)]
pub struct ControlConn(
    pub std::sync::Arc<std::sync::Mutex<crate::rtsp::RtspConnection<std::net::TcpStream>>>,
);

/// Handle to a running feedback loop; drop or call `stop()` to end it.
pub struct FeedbackHandle {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl FeedbackHandle {
    pub fn stop(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// Signal and wait for the loop thread to finish.
    pub fn join(mut self) {
        self.stop();
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

impl Drop for FeedbackHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn the feedback loop: POST /feedback (empty body) every 2s on the control
/// connection, starting immediately. Port of probe.FeedbackLoop.
pub fn spawn_feedback_loop(conn: ControlConn) -> FeedbackHandle {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let join = std::thread::spawn(move || {
        use std::sync::atomic::Ordering;
        while !stop_thread.load(Ordering::SeqCst) {
            {
                let mut c = match conn.0.lock() {
                    Ok(c) => c,
                    Err(_) => return,
                };
                if c.request("POST", "/feedback", &[], None, &[], Some(TIMEOUT_FEEDBACK))
                    .is_err()
                {
                    return;
                }
            }
            // stop.wait(2): sleep in short slices so stop() is responsive.
            let mut waited = Duration::ZERO;
            while waited < FEEDBACK_INTERVAL && !stop_thread.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(100));
                waited += Duration::from_millis(100);
            }
        }
    });
    FeedbackHandle {
        stop,
        join: Some(join),
    }
}

/// dB in [-30, 0]; 0 is MAX so never emit it as a "quiet" value.
pub fn clamp_volume_db(db: f32) -> f32 {
    db.clamp(-30.0, 0.0)
}

/// `volume: {db:.6}\r\n`, content-type text/parameters.
pub fn set_parameter_volume_body(db: f32) -> Vec<u8> {
    format!("volume: {db:.6}\r\n").into_bytes()
}

/// True for 200 AND 500 (Frame applies volume but replies 500).
pub fn volume_success(http_status: u16) -> bool {
    http_status == 200 || http_status == 500
}

// --------------------------------------------------------------------------- orchestration

use crate::pairing::{self, PairError, PairTransport};
use crate::rtsp::{RtspConnection, RtspError, SocketTimeout, CT_BINARY_PLIST, CT_OCTET_STREAM, DEFAULT_TIMEOUT};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};

// Per-request timeouts mirroring the probe's explicit values (probe.py).
const TIMEOUT_INFO: Duration = Duration::from_secs(10); // GET /info (probe line 1221)
const TIMEOUT_SETUP: Duration = Duration::from_secs(10); // SETUP (args.setup_timeout default 10)
const TIMEOUT_FEEDBACK: Duration = Duration::from_secs(5); // /feedback (probe line 1115)
const TIMEOUT_TEARDOWN: Duration = Duration::from_secs(5); // TEARDOWN (probe line 1461)

/// RTSP-over-TCP is the pairing transport. Every pairing POST carries the
/// `X-Apple-HKP` header and an octet-stream TLV8 body (probe RtspConnection).
/// `SocketTimeout` is required because `request` bounds each exchange.
impl<S: Read + Write + SocketTimeout> PairTransport for RtspConnection<S> {
    fn post(&mut self, uri: &str, hkp: u8, body: &[u8]) -> Result<(u16, Vec<u8>), PairError> {
        let headers = [("X-Apple-HKP".to_string(), hkp.to_string())];
        // Pairing POSTs use the probe's default 15s timeout.
        match self.request("POST", uri, &headers, Some(CT_OCTET_STREAM), body, Some(DEFAULT_TIMEOUT)) {
            Ok((status, msg)) => Ok((status, msg.body)),
            Err(RtspError::Io(e)) => Err(PairError::Transport(e)),
            Err(RtspError::ConnectionClosed) => Err(PairError::Transport(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection closed by receiver",
            ))),
            Err(RtspError::Decrypt) => Err(PairError::Crypto(crate::crypto::CryptoError::Auth)),
            Err(RtspError::Malformed(s)) => {
                Err(PairError::Transport(std::io::Error::new(std::io::ErrorKind::InvalidData, s)))
            }
            Err(RtspError::Desynced(s)) => {
                Err(PairError::Transport(std::io::Error::new(std::io::ErrorKind::InvalidData, s)))
            }
        }
    }
}

/// Session driver options (defaults mirror the probe CLI).
pub struct SessionConfig {
    pub host: String,
    pub timing_port: u16,
    pub audio_latency_ms: u32,
    pub volume_db: f32,
    /// Opt-in volume probing. When true, bring_up performs a type-96 audio
    /// SETUP and, only if it succeeds, sends one volume SET_PARAMETER (probe's
    /// `--volume-probe`, which requires audio ports). Off by default so the
    /// proven no-audio path is unchanged and 0 dB (= max) is never emitted.
    pub volume_probe: bool,
    /// Optional PIN enabling the pair-setup + pair-verify fallback in
    /// `run_session` when transient pairing fails (probe's `--pairing auto`).
    pub pin: Option<String>,
    /// Long-term credentials for this receiver, if we hold any. When present
    /// `run_session` spends them on pair-verify BEFORE trying transient, which
    /// is the whole point of keeping them: a receiver that would otherwise put
    /// a code on its screen every single time recognises us instead.
    ///
    /// Passed in rather than read from disk here on purpose — the library does
    /// no filesystem lookup of its own, so a test can hand it a credential and
    /// the CLI stays the only thing that decides where credentials live
    /// ([`crate::pairing::store`]).
    pub credentials: Option<pairing::Credentials>,
    /// X-Apple-HKP type for the PIN fallback (probe default: screen capture, 5).
    pub hkp: u8,
    /// `latencyMs` declared in the type-110 video SETUP, and the matching lead
    /// added to every frame's presentation timestamp (`lead_seconds`). The probe
    /// used 75 ms for both and that is the default.
    ///
    /// Adjustable because a receiver may or may not honour the timestamp: if it
    /// does, the delay tracks this value and lowering it claws latency back; if
    /// it free-runs on its own buffer, moving this changes nothing and the
    /// remaining delay is the receiver's, not ours. That is a measurement, not
    /// an assumption — change it and watch.
    pub video_latency_ms: u32,
    /// Presentation lead in seconds. Defaults to `video_latency_ms / 1000`.
    /// May be negative, which timestamps frames in the past and asks the
    /// receiver to present them as soon as they arrive.
    pub video_lead_seconds: Option<f64>,
    /// Send system audio (or the probe's tone) alongside the video. Off by
    /// default: turning it on moves the TV's volume (see [`crate::volume`]),
    /// and the proven video-only path stays byte-identical when it is off.
    pub audio: AudioMode,
    /// A/V offset in ms, added to the audio latency (SETUP `latencyMax` and
    /// every sync). None = the receiver model's default from
    /// [`crate::audio::av_offset_default`] — which is UNCALIBRATED (0) for
    /// every model until measured on the TV.
    pub av_offset_ms: Option<i32>,
    /// Two-way laptop <-> TV volume sync while audio is on (default true).
    pub volume_sync: bool,
    /// What to call the receiver in the user's output menu, e.g. `75" The Frame`
    /// — the AirPlay sink is published as `AirPlay: <this>`. `None` falls
    /// back to the receiver's model and then to its address, which is
    /// legible but ugly; the CLI sets the discovered name.
    pub receiver_name: Option<String>,
}

/// Which PCM source feeds the audio stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CaptureBackend {
    /// The sender's **own published sink** ([`crate::audiosink`]), captured
    /// pre-volume from that sink's monitor: the laptop's output moves to the
    /// TV while the session runs and comes back at the end, so the sound
    /// plays on the TV *instead of* the speakers — macOS-style. The volume
    /// keys drive that sink, and the level is applied exactly once, at the
    /// TV.
    #[default]
    Sink,
    /// Native PipeWire stream on the **default sink's** monitor: the sound
    /// plays on the laptop AND the TV, slightly out of step. Kept as a real
    /// mode — it is the one way to hear the TV's delay in the room, and the
    /// path with the most mileage if sink mode misbehaves.
    Pipewire,
    /// `parec -d @DEFAULT_MONITOR@` (what the probe proved).
    Parec,
}

impl CaptureBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaptureBackend::Sink => "sink",
            CaptureBackend::Pipewire => "pipewire",
            CaptureBackend::Parec => "parec",
        }
    }
}

/// Whether, and what, audio goes to the receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AudioMode {
    /// No audio stream (the proven M1-M3 path).
    #[default]
    None,
    /// The laptop's system audio.
    System { capture: CaptureBackend },
    /// The probe's 880 Hz beep, once a second.
    Tone,
}

impl AudioMode {
    pub fn is_on(&self) -> bool {
        !matches!(self, AudioMode::None)
    }

    /// "none", "system" or "tone".
    pub fn as_str(&self) -> &'static str {
        match self {
            AudioMode::None => "none",
            AudioMode::System { .. } => "system",
            AudioMode::Tone => "tone",
        }
    }

    /// "pipewire", "parec", "tone", or "none".
    pub fn capture_str(&self) -> &'static str {
        match self {
            AudioMode::None => "none",
            AudioMode::System { capture } => capture.as_str(),
            AudioMode::Tone => "tone",
        }
    }
}

impl SessionConfig {
    pub fn new(host: impl Into<String>) -> Self {
        SessionConfig {
            host: host.into(),
            timing_port: 60000,
            audio_latency_ms: 300,
            volume_db: -20.0,
            volume_probe: false,
            pin: None,
            credentials: None,
            hkp: pairing::HKP_SCREEN_CAPTURE,
            video_latency_ms: 75,
            video_lead_seconds: None,
            audio: AudioMode::None,
            av_offset_ms: None,
            volume_sync: true,
            receiver_name: None,
        }
    }
}

/// Open a TCP RTSP connection to `host:7000`, TCP_NODELAY set (probe.py:195-196).
/// Uses a bounded 10s connect timeout so an unreachable receiver fails fast
/// instead of blocking on the OS default (probe: `create_connection(timeout=10)`).
pub fn connect(host: &str) -> std::io::Result<RtspConnection<TcpStream>> {
    use std::net::ToSocketAddrs;
    let addr = format!("{host}:{}", crate::discovery::AIRPLAY_PORT);
    let sockaddr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address for host"))?;
    let sock = TcpStream::connect_timeout(&sockaddr, Duration::from_secs(10))?;
    sock.set_nodelay(true)?;
    Ok(RtspConnection::new(sock))
}

/// Try transient pairing, returning the 32-byte-derivable shared secret (the
/// 64-byte SRP K). Faithful to probe.run's transient-first attempt.
pub fn pair_transient_on(conn: &mut RtspConnection<TcpStream>) -> Result<Vec<u8>, PairError> {
    pairing::pair_transient(conn)
}

/// How a live session got its shared secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingMethod {
    /// Stored long-term credentials + pair-verify: no code, no prompt on the
    /// receiver's screen.
    Verified,
    /// Transient pair-setup with the fixed `3939` PIN.
    Transient,
    /// PIN pair-setup this run, then pair-verify.
    Pin,
}

impl PairingMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            PairingMethod::Verified => "verified",
            PairingMethod::Transient => "transient",
            PairingMethod::Pin => "pin",
        }
    }
}

impl std::fmt::Display for PairingMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A live session bound to one receiver: encrypted control connection, timing
/// responder, optional event channel, and a running feedback loop.
pub struct Session {
    pub host: String,
    /// How this session paired — set by [`run_session`], which is the only
    /// thing that chooses.
    pub pairing: PairingMethod,
    pub ids: SessionIds,
    pub control: ControlConn,
    pub shared: Vec<u8>,
    pub control_write: [u8; 32],
    pub control_read: [u8; 32],
    /// Receiver display size fit into the level-4.2 encode budget (from the
    /// encrypted GET /info displays[0], defaulting when absent). This is the
    /// TEST-PATTERN path's generation size.
    pub fit: (u32, u32),
    /// The receiver's raw `/info` display size, unfitted. This is the box the
    /// live capture buffer is fitted INTO by
    /// [`crate::encoder::fit_source_to_receiver`].
    pub display: (u32, u32),
    /// dataPort of the type-110 video stream from the SETUP response, if any.
    pub video_data_port: Option<u16>,
    /// Presentation lead applied to every frame timestamp, in seconds. Taken
    /// from [`SessionConfig::video_lead_seconds`], defaulting to the declared
    /// `video_latency_ms`.
    pub video_lead_seconds: f64,
    timing: Arc<TimingShared>,
    timing_join: Option<std::thread::JoinHandle<()>>,
    /// A clone of the event-channel TcpStream, kept so shutdown can `shutdown()`
    /// it and unblock the event thread's blocking `recv` (probe closes the event
    /// conn in its `finally`).
    event_sock: Option<TcpStream>,
    event_join: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    feedback: Option<FeedbackHandle>,
    /// The receiver's `/info` model ("LS03F" for the Frame), "" if unknown.
    pub model: String,
    /// What this receiver is called in the user's output menu: the name the CLI
    /// discovered ([`SessionConfig::receiver_name`]), else the model, else
    /// the address. The AirPlay sink is published as `AirPlay: <this>`.
    pub receiver: String,
    /// THE sender clock: video PTS, audio syncs and timing replies all read it.
    clock: Arc<dyn crate::clock::SenderClock>,
    audio: Mutex<AudioRuntime>,
}

/// What an audio-on session knows up front, for status.
#[derive(Clone, Debug, PartialEq)]
pub struct AudioSessionInfo {
    pub mode: AudioMode,
    pub latency_ms: u32,
    pub av_offset_ms: i32,
    /// False until the offset has been measured on this receiver model.
    pub av_offset_calibrated: bool,
    pub av_offset_source: &'static str,
    pub effective_latency_ms: u32,
    pub volume_sync: bool,
}

/// Shared, cloneable view of a session's audio for a status writer: the
/// static info plus the live counters the audio and volume threads update.
#[derive(Clone)]
pub struct AudioMonitor {
    pub info: AudioSessionInfo,
    report: Arc<Mutex<crate::audio::AudioReport>>,
    volume: crate::volume::StatusSink,
    started: Arc<std::sync::atomic::AtomicBool>,
    sink: Arc<Mutex<Option<AudioSinkInfo>>>,
    /// The capture that actually opened. It can differ from `info.mode`'s
    /// backend: sink mode falls back to the default sink's monitor rather
    /// than ship audio that is quietly attenuated twice, and this is where
    /// that shows.
    capture: Arc<Mutex<Option<CaptureBackend>>>,
}

/// The sender's own published sink, for status. `None` in every mode but
/// `--audio-capture sink`.
///
/// Written at the three moments it changes — published, output taken,
/// output given up — so a status writer never has to poll `pactl` to know
/// what is true.
#[derive(Clone, Debug, PartialEq)]
pub struct AudioSinkInfo {
    /// `node.name`, e.g. `airplay-sink.75_the_frame`.
    pub node_name: String,
    /// `node.description`, e.g. `AirPlay: 75" The Frame`.
    pub label: String,
    /// The sink that comes back when the session ends.
    pub previous_output: String,
    /// Is our sink the laptop's output right now? False before the volume
    /// gate opens (the speakers are still playing then, deliberately) and
    /// false again if the user picks another output himself.
    pub is_default: bool,
}

/// Which capture backend may actually run, given whether the volume driver
/// will run at all. Returns the mode to use and whether it was degraded.
///
/// `--no-volume-sync` with sink mode is the one combination in which NOTHING
/// in the chain can attenuate and nothing in the room can tell:
///
/// * the tap is provably pre-volume (publish refuses the sink path unless
///   `monitor.channel-volumes=false` took), so our sink's slider — which is
///   where the volume keys land, by the naming rule — is inert;
/// * no SET is ever sent, so the TV plays at its own level, seen at 100 % on
///   the Frame; and
/// * the output has moved to our sink, so the speakers are silent and there
///   is no cue at all that anything is loud.
///
/// The old monitor path keeps whatever attenuation the default sink carries
/// and leaves the sound audible on the laptop, so degrade to it. The flag is
/// still honoured — nothing is sent to the TV — but it no longer costs the user
/// his only means of turning the volume down.
pub(crate) fn capture_without_volume_sync(mode: AudioMode, volume_sync: bool) -> (AudioMode, bool) {
    if !volume_sync && matches!(mode, AudioMode::System { capture: CaptureBackend::Sink }) {
        return (AudioMode::System { capture: CaptureBackend::Pipewire }, true);
    }
    (mode, false)
}

/// A `require_sink` no PipeWire node can answer to, so the volume driver's
/// binding check can only refuse. Our node names are `airplay-sink.<slug>`.
pub(crate) const SINK_MODE_WITHOUT_A_SINK: &str = "<sink mode asked for, but no sink was recorded>";

/// What the volume driver may read and write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VolumeBinding {
    /// No sink of ours: follow, read and write the laptop's own output. The
    /// old model — `--audio-capture pipewire`, `parec`, tone.
    FollowOutput,
    /// Bind to exactly this node, the sink we published, and nothing else.
    OurSink(String),
    /// Sink mode survived (nothing fell back), yet no sink was recorded.
    /// Refuse.
    Refuse,
}

/// Decide the binding from what the session ACTUALLY has.
///
/// The point of the `Refuse` arm: deriving `require_sink` from `rt.sink`
/// alone makes the driver's binding check tautological — both operands come
/// from the same `Option`, so it can never fire, and in particular it cannot
/// see the one case it reads as if it were guarding. Sink mode with no sink
/// would silently fall through to `PactlVolume::follow_output()`, and a
/// `dvlc` from the TV remote would then write the desk speakers: exactly what
/// sink mode exists to make impossible. Taking `sink_mode` from the mode and
/// `our_sink` from the runtime makes the two operands independent, so a
/// wiring slip between them is a silent session instead.
pub(crate) fn volume_binding(sink_mode: bool, our_sink: Option<&str>) -> VolumeBinding {
    match (sink_mode, our_sink) {
        (_, Some(n)) => VolumeBinding::OurSink(n.to_string()),
        (true, None) => VolumeBinding::Refuse,
        (false, None) => VolumeBinding::FollowOutput,
    }
}

impl AudioMonitor {
    /// Sender/capture counters (all zero before the stream starts).
    pub fn report(&self) -> crate::audio::AudioReport {
        self.report.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn volume(&self) -> crate::volume::VolumeStatus {
        self.volume.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The sender's own published sink, once it exists (sink mode only).
    pub fn sink(&self) -> Option<AudioSinkInfo> {
        self.sink.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The capture backend that actually opened, once the stream started.
    pub fn capture_backend(&self) -> Option<CaptureBackend> {
        *self.capture.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn set_capture(&self, c: Option<CaptureBackend>) {
        *self.capture.lock().unwrap_or_else(|p| p.into_inner()) = c;
    }

    fn set_sink(&self, s: Option<AudioSinkInfo>) {
        *self.sink.lock().unwrap_or_else(|p| p.into_inner()) = s;
    }

    /// Record that our sink is (or is no longer) the laptop's output.
    fn set_sink_default(&self, is_default: bool) {
        if let Some(s) = self.sink.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
            s.is_default = is_default;
        }
    }

    /// Has [`Session::start_audio`] run (i.e. streaming began)?
    pub fn started(&self) -> bool {
        self.started.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The audio side of a live session. Field order is drop order: volume sync
/// first (it talks over the control connection), then the sender, and the
/// published sink LAST of all.
#[derive(Default)]
struct AudioRuntime {
    volume: Option<crate::volume::VolumeHandle>,
    handle: Option<crate::audio::AudioHandle>,
    /// Parameters + bound sockets from the audio SETUP, consumed by
    /// `start_audio`.
    pending: Option<(crate::audio::AudioStreamParams, crate::audio::AudioSockets)>,
    events_rx: Option<std::sync::mpsc::Receiver<ReceiverEvent>>,
    monitor: Option<AudioMonitor>,
    mode: AudioMode,
    volume_sync: bool,
    /// The sender's own PipeWire sink (sink mode only).
    ///
    /// **Last**, because field order is drop order: the capture is pinned to
    /// this sink's monitor and the volume driver is bound to its level, so
    /// both must have stopped before the node it taps disappears. Its `Drop`
    /// is what gives the laptop's output back.
    ///
    /// Behind an `Arc<Mutex<_>>` only so the volume driver's gate-open and
    /// detach hooks can reach it; they hold a `Weak`, never a strong
    /// reference, so a volume thread that had to be detached can never keep
    /// the node alive past the session.
    sink: Option<Arc<Mutex<crate::audiosink::AirPlaySink>>>,
    /// Watches that sink for a fatal error while the session runs. Listed
    /// AFTER `sink` in the struct only because it holds a `Weak`: it never
    /// keeps the node alive, and `stop_audio` stops it before the node goes.
    sink_watch: Option<SinkWatch>,
}

/// The thread that notices the published sink node dying UNDER a running
/// session, and what it does about it.
///
/// The failure it exists for is silent by nature: the capture is pinned to
/// that node with `node.dont-fallback`, so when the node dies the capture
/// simply stops delivering, and "no samples" is exactly what nothing playing
/// looks like. Before this, a session in that state kept sending — the gate
/// was already open — and the only symptom was the sender reporting "stalled"
/// while the TV played silence and the speakers stayed quiet, with the output
/// still pointed at a node that was gone.
///
/// The response is deliberately not a reconnect and not a fallback to the
/// default monitor: a sink that comes back has a new id and has already lost
/// the output and the streams that followed it, and capturing the default
/// monitor instead would silently reintroduce the double attenuation the sink
/// path exists to avoid. It holds the gate, says why, and ends the audio
/// stream. The output itself is given back by the sink's own teardown, which
/// keeps its claim on anything unsettled.
struct SinkWatch {
    stop: Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

/// How often the sink watch asks. The node dying is rare and not urgent to the
/// millisecond; this is far below any human notice and costs one atomic load.
const SINK_WATCH_TICK: Duration = Duration::from_millis(200);

impl SinkWatch {
    fn spawn(
        sink: &Arc<Mutex<crate::audiosink::AirPlaySink>>,
        gate: crate::audio::AudioGate,
        stopper: crate::audio::AudioStopper,
        monitor: AudioMonitor,
    ) -> SinkWatch {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (stop_t, weak) = (stop.clone(), Arc::downgrade(sink));
        let join = std::thread::Builder::new()
            .name("airplay-sink-watch".into())
            .spawn(move || {
                while !stop_t.load(std::sync::atomic::Ordering::SeqCst) {
                    // The session ended and the sink was dropped: nothing to
                    // watch, and nothing to report.
                    let Some(s) = weak.upgrade() else { return };
                    // Copied out, and the guard dropped, before anything below
                    // blocks: the volume driver's hooks take this same lock.
                    let fatal = s.lock().unwrap_or_else(|p| p.into_inner()).fatal();
                    drop(s);
                    if let Some(why) = fatal {
                        eprintln!(
                            "audio: the AirPlay sink node died under the session ({why});                              holding the audio silent and ending the stream —                              NOT falling back to the laptop's own monitor, which would send                              the room to the TV and attenuate it twice"
                        );
                        gate.hold(format!("the AirPlay sink node died ({why})"));
                        {
                            let mut r = monitor.report.lock().unwrap_or_else(|p| p.into_inner());
                            r.state = crate::audio::SenderState::Error;
                            r.error = Some(format!("the AirPlay sink node died ({why})"));
                        }
                        monitor.set_sink_default(false);
                        stopper.stop();
                        return;
                    }
                    std::thread::sleep(SINK_WATCH_TICK);
                }
            })
            .expect("spawn sink watch");
        SinkWatch { stop, join: Some(join) }
    }

    fn stop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

impl Drop for SinkWatch {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The timing UDP socket is shared by the responder thread and the prober.
struct TimingShared {
    sock: UdpSocket,
    stop: std::sync::atomic::AtomicBool,
    clock: Arc<dyn crate::clock::SenderClock>,
}

/// Cleanup guard covering every early `?`/`Err` exit in `bring_up` once the
/// timing socket is bound and (later) the event thread is spawned. On drop it
/// stops timing, shuts down the event socket to unblock its thread, and joins
/// both — so an error path never leaks a thread or socket (probe.run's
/// unconditional `finally`). The success path calls `disarm()` to hand the
/// live resources to the `Session` instead.
struct BringUpGuard {
    timing: Option<Arc<TimingShared>>,
    timing_join: Option<std::thread::JoinHandle<()>>,
    event_sock: Option<TcpStream>,
    event_join: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

impl BringUpGuard {
    fn new(timing: Arc<TimingShared>, timing_join: std::thread::JoinHandle<()>) -> Self {
        BringUpGuard {
            timing: Some(timing),
            timing_join: Some(timing_join),
            event_sock: None,
            event_join: None,
        }
    }

    /// Take the live resources for the `Session`, disarming cleanup on drop.
    #[allow(clippy::type_complexity)]
    fn disarm(
        mut self,
    ) -> (
        Arc<TimingShared>,
        Option<std::thread::JoinHandle<()>>,
        Option<TcpStream>,
        Option<std::thread::JoinHandle<std::io::Result<()>>>,
    ) {
        (
            self.timing.take().expect("timing present until disarm"),
            self.timing_join.take(),
            self.event_sock.take(),
            self.event_join.take(),
        )
    }
}

impl Drop for BringUpGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if let Some(t) = &self.timing {
            t.stop.store(true, Ordering::SeqCst);
        }
        if let Some(s) = &self.event_sock {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        if let Some(j) = self.timing_join.take() {
            let _ = j.join();
        }
        if let Some(j) = self.event_join.take() {
            let _ = j.join();
        }
    }
}

impl Session {
    /// Full bring-up on an already-connected, paired control connection whose
    /// cipher is set. Ports probe.run steps [2]-[3]-[3b]-[4]-feedback for the
    /// NTP path. Best-effort: control SETUP failures propagate; optional stages
    /// (event channel, RECORD, video) are attempted and logged into the return.
    pub fn bring_up(
        mut conn: RtspConnection<TcpStream>,
        shared: Vec<u8>,
        config: &SessionConfig,
    ) -> Result<Session, SessionError> {
        let (control_write, control_read) = crate::crypto::control_keys(&shared);
        // Cipher must already be attached before calling; attach if not.
        conn.set_cipher(crate::crypto::HapCipher::new(control_write, control_read));

        // [2] Encrypted GET /info sanity check. The body carries displays[] which
        // fixes the mirror resolution (probe.py lines 1388-1396).
        let (status, info_msg) = conn
            .request("GET", "/info", &[], None, &[], Some(TIMEOUT_INFO))
            .map_err(SessionError::Rtsp)?;
        if status != 200 {
            return Err(SessionError::Status("encrypted GET /info", status));
        }
        // `display` is the receiver's own panel size, kept RAW. `fit` is the
        // test-pattern path's generation size (the receiver fitted into the
        // level-4.2 box). Live capture needs the raw number, because there the
        // receiver is the BOX and the capture buffer is the thing being fitted —
        // conflating the two is milestone-1 bug #2, so both are stored rather
        // than one being re-derived from the other.
        let parsed_info = crate::discovery::parse_info(&info_msg.body).ok();
        let model = parsed_info.as_ref().map(|i| i.model.clone()).unwrap_or_default();
        let display = match &parsed_info {
            Some(info) => crate::discovery::info_screen_fit(info),
            None => (
                crate::testpattern::MAX_FIT_WIDTH,
                crate::testpattern::MAX_FIT_HEIGHT,
            ),
        };
        let fit = crate::testpattern::fit_resolution(display);

        let mut ids = SessionIds::generate();

        // Timing: bind the base UDP socket, start the responder thread. From
        // here on a cleanup guard covers every early return so the timing
        // thread/socket (and later the event thread/socket) never leak.
        let sock = UdpSocket::bind(("0.0.0.0", config.timing_port))
            .map_err(SessionError::Io)?;
        // One clock for the whole session (see crate::clock).
        let clock: Arc<dyn crate::clock::SenderClock> = Arc::new(crate::clock::BoottimeClock);
        let timing = Arc::new(TimingShared {
            sock,
            stop: std::sync::atomic::AtomicBool::new(false),
            clock: clock.clone(),
        });
        let timing_join = spawn_timing_responder(timing.clone());
        let mut guard = BringUpGuard::new(timing.clone(), timing_join);

        // [3] Control SETUP (NTP).
        let audio_uri = audio_uri(&config.host, ids.audio_sc_id);
        let body = build_control_setup_plist(&ids, TimingProtocol::Ntp, config.timing_port);
        let (status, msg) = conn
            .request("SETUP", &audio_uri, &[], Some(CT_BINARY_PLIST), &body, Some(TIMEOUT_SETUP))
            .map_err(SessionError::Rtsp)?;
        if status != 200 {
            return Err(SessionError::Status("control SETUP", status));
        }
        let resp = parse_control_setup_response(&msg.body);

        // Probe the receiver's timing port back (NTP).
        if let Some(tp) = resp.timing_port {
            let _ = probe_timing(&timing.sock, &config.host, tp, timing.clock.as_ref());
        }

        // Receiver events feed the volume sync (audio on + sync on only).
        let (events_tx, events_rx) = if config.audio.is_on() && config.volume_sync {
            let (tx, rx) = std::sync::mpsc::sync_channel(64);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        // Event channel: reversed keys on a new TCP connection. Keep a clone of
        // the socket in the guard so an error below (or shutdown later) can
        // unblock the event thread.
        if let Some(ep) = resp.event_port {
            if let Ok(sock) = TcpStream::connect((config.host.as_str(), ep)) {
                let _ = sock.set_nodelay(true);
                let sock_clone = sock.try_clone().ok();
                let ev = match events_tx {
                    Some(tx) => EventChannelConn::with_events(sock, &shared, tx),
                    None => EventChannelConn::new(sock, &shared),
                };
                let jh = std::thread::spawn(move || ev.run());
                guard.event_sock = sock_clone;
                guard.event_join = Some(jh);
            }
        }

        // RECORD unless the receiver said skipRecord.
        if !resp.skip_record {
            let _ = conn.request(
                "RECORD",
                &audio_uri,
                &record_headers(&ids.session_uuid),
                None,
                &[],
                Some(DEFAULT_TIMEOUT),
            );
        }

        // [3b] Optional audio SETUP (type 96 ALAC), only when volume probing is
        // opted in. Its success is what gates the later volume SET_PARAMETER;
        // this is NOT part of the proven no-audio path (probe: audio == "none"
        // by default, so no audio SETUP runs).
        let mut audio_setup_ok = false;
        let mut audio_pending = None;
        let mut audio_info = None;
        if config.audio.is_on() {
            // Bind our ports BEFORE the SETUP advertises them, so a clash
            // fails here rather than producing a stream nobody can anchor.
            let sockets = crate::audio::AudioSockets::bind(config.timing_port).map_err(|e| {
                SessionError::Audio(format!(
                    "cannot bind audio UDP ports {}/{}: {e}",
                    config.timing_port as u32 + 1,
                    config.timing_port as u32 + 2
                ))
            })?;
            let def = crate::audio::av_offset_default(&model);
            let (offset, calibrated, source) = match config.av_offset_ms {
                Some(ms) => (ms, false, "--av-offset (uncalibrated)"),
                None => (def.ms, def.calibrated, def.source),
            };
            let latency = crate::audio::AudioLatency::new(config.audio_latency_ms, offset)
                .map_err(|e| SessionError::Audio(e.to_string()))?;
            let shk = random_shk();
            let abody = build_audio_setup_plist_latency(ids.audio_sc_id, config.timing_port + 1, &latency, &shk);
            let (astatus, amsg) = conn
                .request("SETUP", &audio_uri, &[], Some(CT_BINARY_PLIST), &abody, Some(TIMEOUT_SETUP))
                .map_err(SessionError::Rtsp)?;
            if astatus != 200 {
                return Err(SessionError::Audio(format!(
                    "audio SETUP returned {astatus}; retry with --audio none"
                )));
            }
            let (data_port, control_port) = stream_ports(&amsg.body, 96).ok_or_else(|| {
                SessionError::Audio(
                    "audio SETUP reply has no type-96 dataPort/controlPort; retry with --audio none".into(),
                )
            })?;
            let receiver = resolve_ip(&config.host).map_err(SessionError::Io)?;
            audio_info = Some(AudioSessionInfo {
                mode: config.audio,
                latency_ms: latency.base_ms(),
                av_offset_ms: latency.av_offset_ms(),
                av_offset_calibrated: calibrated,
                av_offset_source: source,
                effective_latency_ms: latency.effective_ms(),
                volume_sync: config.volume_sync,
            });
            audio_pending = Some((
                crate::audio::AudioStreamParams {
                    shk,
                    latency,
                    receiver,
                    receiver_data_port: data_port,
                    receiver_control_port: control_port,
                },
                sockets,
            ));
        } else if config.volume_probe {
            let audio_key = random_shk();
            let abody = build_audio_setup_plist(
                ids.audio_sc_id,
                config.timing_port + 1,
                config.audio_latency_ms,
                &audio_key,
            );
            if let Ok((astatus, amsg)) = conn.request(
                "SETUP",
                &audio_uri,
                &[],
                Some(CT_BINARY_PLIST),
                &abody,
                Some(TIMEOUT_SETUP),
            ) {
                audio_setup_ok = astatus == 200 && stream_data_port(&amsg.body, 96).is_some();
            }
        }

        // [4] Video SETUP (type 110), shk/shiv from the control keys.
        let vshk: [u8; 16] = control_write[..16].try_into().unwrap();
        let vshiv: [u8; 16] = control_read[..16].try_into().unwrap();
        let vbody =
            build_video_setup_plist_with_latency(ids.video_sc_id, &vshk, &vshiv, config.video_latency_ms);
        let video_uri = |sc_id: u64| {
            format!(
                "rtsp://{}:{}/{}",
                config.host,
                crate::discovery::AIRPLAY_PORT,
                sc_id
            )
        };
        let (vstatus, vmsg) = conn
            .request(
                "SETUP",
                &video_uri(ids.video_sc_id),
                &[],
                Some(CT_BINARY_PLIST),
                &vbody,
                Some(TIMEOUT_SETUP),
            )
            .map_err(SessionError::Rtsp)?;
        let mut video_data_port = if vstatus == 200 {
            stream_data_port(&vmsg.body, 110)
        } else {
            None
        };

        // [4b] Video rejected alone: add a type-96 ALAC audio stream first, then
        // rebuild and resend the video SETUP (probe.py lines 1326-1341). The
        // audio latencyMax is the fixed int(0.085*44100) = 3748 samples, a fresh
        // random 32-byte shk, controlPort = timing_port + 1. The retried video
        // SETUP uses a freshly generated streamConnectionID (probe's video_setup
        // regenerates it), which becomes the id used downstream.
        if vstatus != 200 && config.audio.is_on() {
            // [4b] would re-SETUP audio with a new key and 85 ms latency
            // underneath the stream we just set up; the probe only ever ran
            // it with audio "none". Say so instead.
            return Err(SessionError::Audio(format!(
                "video SETUP rejected ({vstatus}) with audio on; retry with --audio none"
            )));
        }
        if vstatus != 200 {
            let shk = random_shk();
            let abody = build_audio_setup_plist(ids.audio_sc_id, config.timing_port + 1, 85, &shk);
            let _ = conn.request(
                "SETUP",
                &audio_uri,
                &[],
                Some(CT_BINARY_PLIST),
                &abody,
                Some(TIMEOUT_SETUP),
            );
            ids.video_sc_id = random_id63();
            let vbody2 =
                build_video_setup_plist_with_latency(ids.video_sc_id, &vshk, &vshiv, config.video_latency_ms);
            if let Ok((vstatus2, vmsg2)) = conn.request(
                "SETUP",
                &video_uri(ids.video_sc_id),
                &[],
                Some(CT_BINARY_PLIST),
                &vbody2,
                Some(TIMEOUT_SETUP),
            ) {
                if vstatus2 == 200 {
                    video_data_port = stream_data_port(&vmsg2.body, 110);
                }
            }
        }

        // Move the control connection under a shared lock for feedback + volume.
        let control = ControlConn(Arc::new(Mutex::new(conn)));

        // Feedback loop on the control connection, every 2s.
        let feedback = spawn_feedback_loop(control.clone());

        // Volume: SET_PARAMETER (Frame replies 500 but applies it). Only when
        // volume probing was opted in AND the audio SETUP that provides ports
        // succeeded — never emit a volume by default, and never 0 dB (= max).
        if config.volume_probe && audio_setup_ok && !config.audio.is_on() {
            let db = clamp_volume_db(config.volume_db);
            let vbody = set_parameter_volume_body(db);
            if let Ok(mut c) = control.0.lock() {
                let hdrs = [("Session".to_string(), ids.session_uuid.clone())];
                let _ = c.request(
                    "SET_PARAMETER",
                    &audio_uri,
                    &hdrs,
                    Some("text/parameters"),
                    &vbody,
                    Some(DEFAULT_TIMEOUT),
                );
            }
        }

        // Success: hand the live timing/event resources to the Session so the
        // guard's drop-cleanup does not tear them down.
        let (timing, timing_join, event_sock, event_join) = guard.disarm();

        Ok(Session {
            host: config.host.clone(),
            // `bring_up` is handed a shared secret and is not told where it
            // came from; `run_session` overwrites this with what it actually
            // did. Transient is the honest default because it is what every
            // caller that does its own pairing (the loopback harnesses) uses.
            pairing: PairingMethod::Transient,
            ids,
            control,
            shared,
            control_write,
            control_read,
            fit,
            display,
            video_data_port,
            video_lead_seconds: config
                .video_lead_seconds
                .unwrap_or(config.video_latency_ms as f64 / 1000.0),
            timing,
            timing_join,
            event_sock,
            event_join,
            feedback: Some(feedback),
            receiver: config
                .receiver_name
                .clone()
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| if model.is_empty() { config.host.clone() } else { model.clone() }),
            model,
            audio: Mutex::new(AudioRuntime {
                monitor: audio_info.map(|info| AudioMonitor {
                    info,
                    report: Default::default(),
                    volume: Default::default(),
                    started: Default::default(),
                    sink: Default::default(),
                    capture: Default::default(),
                }),
                pending: audio_pending,
                events_rx,
                mode: config.audio,
                volume_sync: config.volume_sync,
                ..Default::default()
            }),
            clock,
        })
    }

    /// The session's sender clock.
    pub fn clock(&self) -> Arc<dyn crate::clock::SenderClock> {
        self.clock.clone()
    }

    /// A handle for status writers; None when audio is off.
    pub fn audio_monitor(&self) -> Option<AudioMonitor> {
        self.audio.lock().unwrap_or_else(|p| p.into_inner()).monitor.clone()
    }

    /// Start the audio stream (no-op when audio is off or already started).
    /// Called by the stream functions right after the video data socket is
    /// connected. A capture that cannot be opened is reported and leaves the
    /// video running: audio is never allowed to take the mirror down.
    pub fn start_audio(&self) {
        self.start_audio_inner(None, crate::volume::VolumeTiming::default(), None, None)
    }

    /// TEST ONLY: [`start_audio`](Self::start_audio) with an injected laptop
    /// side and start-sequence timing, so the whole path can run against a
    /// fake receiver without touching the machine's real sink.
    #[doc(hidden)]
    pub fn start_audio_with(&self, laptop: Box<dyn crate::volume::LaptopVolume>, timing: crate::volume::VolumeTiming) {
        self.start_audio_inner(Some(laptop), timing, None, None)
    }

    /// TEST ONLY: as [`start_audio_with`](Self::start_audio_with), with the
    /// capture replaced by a caller-supplied source.
    ///
    /// The blast proof needs a source that is audible in EVERY frame. The
    /// built-in tone is not: `tone_frame` beeps for only the first 150 ms of
    /// each second, so a test that just looks for the first non-silent packet
    /// can be satisfied by the tone's own quiet phase rather than by the gate,
    /// and would still pass if the gate opened before the start SET. With a
    /// continuously loud source, "first non-silent packet" is exactly "the
    /// moment the gate opened", which is the property being proved.
    #[doc(hidden)]
    pub fn start_audio_with_source(
        &self,
        src: Box<dyn crate::audiocapture::PcmSource>,
        laptop: Box<dyn crate::volume::LaptopVolume>,
        timing: crate::volume::VolumeTiming,
    ) {
        self.start_audio_inner(Some(laptop), timing, Some(src), None)
    }

    /// TEST ONLY: as [`start_audio_with_source`](Self::start_audio_with_source),
    /// carrying the [`crate::volume::SinkBinding`] the driver is handed.
    ///
    /// Without this seam the blast proofs cannot reach the sink path at all:
    /// they all inject a source, and the injecting arm deliberately never
    /// publishes a sink (a real node, taking the user's output, in the middle of
    /// `cargo test`), so `rt.sink` is always `None` and the binding always
    /// `SinkBinding::default()` — `require_sink` unset, `on_open`/`on_detach`
    /// absent. Everything the sink model promises at session level lives in
    /// those three fields, so offline they would be proved by nothing.
    #[doc(hidden)]
    pub fn start_audio_with_source_and_binding(
        &self,
        src: Box<dyn crate::audiocapture::PcmSource>,
        laptop: Box<dyn crate::volume::LaptopVolume>,
        timing: crate::volume::VolumeTiming,
        binding: crate::volume::SinkBinding,
    ) {
        self.start_audio_inner(Some(laptop), timing, Some(src), Some(binding))
    }

    /// Sink mode: publish the sender's own sink and capture **its own**
    /// monitor, which carries no channel volumes — so the level the user sets is
    /// applied exactly once, at the TV.
    ///
    /// Two things are checked rather than assumed, and either one falls back
    /// to the default sink's monitor (the old, proven behaviour: sound on the
    /// laptop as well) rather than take a worse path quietly:
    ///
    /// 1. the sink can be published at all, and
    /// 2. its monitor really is pre-volume — if `monitor.channel-volumes=false`
    ///    did not take, capturing it would attenuate twice and ship audio
    ///    that is too soft at every setting.
    ///
    /// The output is **not** taken here. That happens when the volume gate
    /// opens; until then the speakers keep playing.
    fn open_sink_capture(
        &self,
        rt: &mut AudioRuntime,
        monitor: &AudioMonitor,
        clock: &Arc<dyn crate::clock::SenderClock>,
    ) -> Result<Box<dyn crate::audiocapture::PcmSource>, crate::audiocapture::CaptureError> {
        use crate::audiocapture as cap;
        use crate::audiosink::{AirPlaySink, SinkOpts};

        let sink = match AirPlaySink::publish(SinkOpts::for_receiver(&self.receiver)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("audio: cannot publish the AirPlay sink ({e})");
                return self.fallback_capture(rt, monitor, clock);
            }
        };
        if !sink.monitor_is_pre_volume() {
            eprintln!(
                "audio: {}'s monitor carries the sink's own volume, so capturing it would apply the level twice",
                sink.node_name()
            );
            // Dropping it here removes the node; the output was never taken.
            drop(sink);
            return self.fallback_capture(rt, monitor, clock);
        }
        eprintln!(
            "audio: publishing {:?} ({}); the laptop's output moves there when the TV's volume is established, and {} comes back at the end",
            sink.label(),
            sink.node_name(),
            sink.previous_default()
        );
        let info = AudioSinkInfo {
            node_name: sink.node_name().to_string(),
            label: sink.label().to_string(),
            previous_output: sink.previous_default().to_string(),
            // Deliberately false: the speakers are still the output until the
            // gate opens.
            is_default: false,
        };
        let opts = sink.capture_opts();
        match cap::PipewireSource::new(opts, clock.clone()) {
            Ok(s) => {
                monitor.set_capture(Some(CaptureBackend::Sink));
                monitor.set_sink(Some(info));
                rt.sink = Some(Arc::new(Mutex::new(sink)));
                Ok(Box::new(s) as _)
            }
            // `sink` drops here: the node goes, and nothing was ever taken.
            Err(e) => Err(e),
        }
    }

    /// The old monitor path, taken when sink mode cannot be trusted. Says so
    /// loudly: the model is different (sound on the laptop too, and the
    /// laptop's output is not touched at all).
    fn fallback_capture(
        &self,
        rt: &mut AudioRuntime,
        monitor: &AudioMonitor,
        clock: &Arc<dyn crate::clock::SenderClock>,
    ) -> Result<Box<dyn crate::audiocapture::PcmSource>, crate::audiocapture::CaptureError> {
        use crate::audiocapture as cap;
        eprintln!(
            "audio: WARNING falling back to the DEFAULT sink's monitor: the sound will play on the laptop as well as on the TV, \
             and the laptop's output is left alone"
        );
        rt.mode = AudioMode::System { capture: CaptureBackend::Pipewire };
        monitor.set_capture(Some(CaptureBackend::Pipewire));
        monitor.set_sink(None);
        cap::PipewireSource::new(cap::PwCaptureOpts::default(), clock.clone()).map(|s| Box::new(s) as _)
    }

    fn start_audio_inner(
        &self,
        laptop: Option<Box<dyn crate::volume::LaptopVolume>>,
        timing: crate::volume::VolumeTiming,
        src_override: Option<Box<dyn crate::audiocapture::PcmSource>>,
        binding_override: Option<crate::volume::SinkBinding>,
    ) {
        use crate::audiocapture as cap;
        let mut rt = self.audio.lock().unwrap_or_else(|p| p.into_inner());
        let Some((params, sockets)) = rt.pending.take() else { return };
        let Some(monitor) = rt.monitor.clone() else { return };
        monitor.started.store(true, std::sync::atomic::Ordering::SeqCst);
        let clock = self.clock.clone();
        let injected = src_override.is_some();
        // `--no-volume-sync` and sink mode is the one combination with no
        // attenuation ANYWHERE, and no way to notice. The tap is provably
        // pre-volume (publish refuses the sink path unless it is), so our
        // slider is inert; no SET is ever sent, so the TV plays at its own
        // level, which has been seen at 100 % on the Frame; and the output
        // has moved, so the speakers are silent and there is no cue in the
        // room. The volume keys land on our sink and do nothing at all.
        //
        // The old monitor path at least keeps whatever attenuation the
        // default sink carries and leaves sound audible on the laptop, so
        // degrade to it rather than take the speakers away with nothing in
        // the chain. Say so: a silent degrade would be its own surprise.
        if !injected {
            let (mode, degraded) = capture_without_volume_sync(rt.mode, rt.volume_sync);
            if degraded {
                eprintln!(
                    "audio: WARNING --no-volume-sync cannot be used with the AirPlay sink: the sink's monitor is \
                     pre-volume, so its slider (and the volume keys) would do nothing at all while the speakers \
                     were silent. Using the default sink's monitor instead: the sound plays on the laptop too, \
                     at the laptop's level, and the laptop's output is left alone."
                );
            }
            rt.mode = mode;
        }
        let mode = rt.mode;
        // NOTE: the AirPlay sink is published on THIS arm only — the
        // `src_override` branch above is how the offline tests inject their
        // own source, and a sink created there would publish a real node and
        // take the user's default output in the middle of `cargo test`.
        // `offline_sessions_publish_no_sink` is the alarm on that.
        let src: Result<Box<dyn cap::PcmSource>, cap::CaptureError> = match src_override {
            Some(s) => Ok(s),
            None => match mode {
                AudioMode::None => return,
                AudioMode::System { capture: CaptureBackend::Sink } => {
                    self.open_sink_capture(&mut rt, &monitor, &clock)
                }
                AudioMode::System { capture: CaptureBackend::Pipewire } => {
                    monitor.set_capture(Some(CaptureBackend::Pipewire));
                    cap::PipewireSource::new(cap::PwCaptureOpts::default(), clock.clone()).map(|s| Box::new(s) as _)
                }
                AudioMode::System { capture: CaptureBackend::Parec } => {
                    monitor.set_capture(Some(CaptureBackend::Parec));
                    cap::ParecSource::new(cap::PAREC_DEFAULT_DEVICE, clock.clone()).map(|s| Box::new(s) as _)
                }
                AudioMode::Tone => Ok(Box::new(cap::ToneSource::new(clock.clone(), cap::TONE_LEVEL)) as _),
            },
        };
        let src = match src {
            Ok(s) => s,
            Err(e) => {
                eprintln!("audio: cannot open the {} capture: {e}; video continues without audio", rt.mode.capture_str());
                let mut r = monitor.report.lock().unwrap_or_else(|p| p.into_inner());
                r.state = crate::audio::SenderState::Error;
                r.error = Some(e.to_string());
                return;
            }
        };
        let (atx, arx) = std::sync::mpsc::channel();
        // ONE gate shared by the sender and the volume driver. With volume
        // sync on, the sender streams digital silence (real packets, zeroed
        // PCM) until the driver has SET the TV from the laptop level and read
        // it back; every failure path below leaves it held, so the session
        // is silent rather than playing at the TV's own (possibly maximum)
        // level. Only an explicit --no-volume-sync opens it up front.
        let gate = if rt.volume_sync {
            crate::audio::AudioGate::held(crate::audio::GATE_WAITING_FOR_VOLUME)
        } else {
            eprintln!(
                "audio: WARNING --no-volume-sync: nothing is sent to the TV, so the audio plays at the \
                 TV's OWN volume, which can be its maximum, and the laptop's volume keys will not \
                 change it. The laptop keeps its output and its own level, so the sound in the room \
                 is still yours to turn down."
            );
            crate::audio::AudioGate::ungated()
        };
        rt.handle = Some(crate::audio::spawn_audio_sender_gated(
            params,
            sockets,
            src,
            clock.clone(),
            Some(atx),
            monitor.report.clone(),
            gate.clone(),
        ));
        // Sink mode only: from here until `stop_audio`, something is watching
        // the node we published. See `SinkWatch` for why a dead sink is
        // otherwise indistinguishable from nothing playing.
        if let (Some(s), Some(h)) = (rt.sink.as_ref(), rt.handle.as_ref()) {
            rt.sink_watch = Some(SinkWatch::spawn(s, gate.clone(), h.stopper(), monitor.clone()));
        }
        if !rt.volume_sync {
            // Defensive only: sink mode and `--no-volume-sync` are refused
            // above, so `rt.sink` is None here. Kept so that if that ever
            // changes the handover still happens through the one method that
            // writes a claim first.
            if let Some(s) = rt.sink.clone() {
                let mut sink = s.lock().unwrap_or_else(|p| p.into_inner());
                match sink.take_default() {
                    Ok(()) => monitor.set_sink_default(true),
                    // "It stays where it is" is true of every outcome but one.
                    // `TookUnsettled` means the machine ACCEPTED the handover —
                    // the configured default names our sink — and only the
                    // active default has not followed, so the output may
                    // already be ours and the claim is deliberately kept.
                    // Reporting that as "unchanged" would tell the user their sound is
                    // where it was while it is in fact in mid-air.
                    Err(e @ crate::audiosink::SinkError::TookUnsettled { .. }) => {
                        monitor.set_sink_default(true);
                        eprintln!(
                            "audio: the output was handed to the AirPlay sink but has not settled ({e}); \
                             the claim is kept, and it is given back at the end or by `airplay audio --cleanup`"
                        );
                    }
                    Err(e) => eprintln!("audio: could not hand the output to the AirPlay sink ({e}); it stays where it is"),
                }
            }
            monitor.volume.lock().unwrap_or_else(|p| p.into_inner()).state =
                "off (--no-volume-sync): audio at the TV's own volume".into();
            return;
        }
        let Some(events_rx) = rt.events_rx.take() else {
            gate.hold("volume: no event channel (audio held silent)");
            monitor.volume.lock().unwrap_or_else(|p| p.into_inner()).state =
                "disabled: no event channel (audio held silent)".into();
            return;
        };
        // Which sink the volume driver may read and write. In sink mode it is
        // OUR sink and nothing else: `for_sink` is fixed, so `refresh_target`
        // is a permanent no-op and a `dvlc` from the TV remote can only ever
        // move our own slider. That is the user's rule — "change the headphones'
        // volume instead" — made structural rather than hoped for.
        //
        // The decision is taken from what the session ENDED UP with, not from
        // what it set out to do: `rt.mode` is re-read here, after
        // `open_sink_capture` has run, because `fallback_capture` rewrites it
        // to `Pipewire` and a legitimate fallback must not be treated as a
        // wiring slip. `injected` excludes the test-injection arm, which
        // never publishes a sink on purpose.
        let decision = volume_binding(
            !injected && matches!(rt.mode, AudioMode::System { capture: CaptureBackend::Sink }),
            rt.sink.as_ref().map(|s| s.lock().unwrap_or_else(|p| p.into_inner()).node_name().to_string()).as_deref(),
        );
        let laptop: Box<dyn crate::volume::LaptopVolume> = match (laptop, &decision) {
            (Some(l), _) => l,
            (None, VolumeBinding::OurSink(name)) => Box::new(crate::volume::PactlVolume::for_sink(name)),
            // Sink mode, and no sink: NOT the hardware output. Binding there
            // would let a `dvlc` from the TV remote write the desk speakers.
            (None, VolumeBinding::Refuse) => {
                gate.hold(format!("volume: {SINK_MODE_WITHOUT_A_SINK} (audio held silent)"));
                monitor.volume.lock().unwrap_or_else(|p| p.into_inner()).state =
                    format!("disabled: {SINK_MODE_WITHOUT_A_SINK} (audio held silent)");
                return;
            }
            (None, VolumeBinding::FollowOutput) => match crate::volume::PactlVolume::follow_output() {
                Ok(l) => Box::new(l),
                Err(e) => {
                    gate.hold(format!("volume: cannot resolve the laptop output ({e}) (audio held silent)"));
                    monitor.volume.lock().unwrap_or_else(|p| p.into_inner()).state =
                        format!("disabled: cannot resolve the laptop output ({e}) (audio held silent)");
                    return;
                }
            },
        };
        let tv = crate::volume::RtspTvVolume::new(self.control.clone(), audio_uri(&self.host, self.ids.audio_sc_id));
        let binding = match (binding_override, &decision) {
            (Some(b), _) => b,
            (None, VolumeBinding::FollowOutput) => crate::volume::SinkBinding::default(),
            // Reached only with an injected laptop (the arm above returns
            // otherwise). A name no node can have, so the driver's binding
            // check refuses and the session is silent rather than bound to
            // something that is not ours.
            (None, VolumeBinding::Refuse) => crate::volume::SinkBinding {
                require_sink: Some(SINK_MODE_WITHOUT_A_SINK.to_string()),
                expected_default: None,
                on_open: None,
                on_detach: None,
            },
            (None, VolumeBinding::OurSink(name)) => {
                let name = name.clone();
                let s = rt.sink.as_ref().expect("OurSink implies a published sink");
                // The baseline the handover is checked against, taken from the
                // sink itself rather than sampled by the volume thread: it is
                // the output the sink will put back, sampled at publish, so
                // an output change between publish and this thread starting is
                // seen as the change it is instead of being baked in.
                let expected_default =
                    Some(s.lock().unwrap_or_else(|p| p.into_inner()).previous_default().to_string());
                // WEAK, never strong: a volume thread that had to be detached
                // (it outran its join bound) must not be able to keep the
                // node alive, or to take the output after the session ended.
                let (open_sink, detach_sink) = (Arc::downgrade(s), Arc::downgrade(s));
                let (open_mon, detach_mon) = (monitor.clone(), monitor.clone());
                crate::volume::SinkBinding {
                    require_sink: Some(name),
                    expected_default,
                    on_open: Some(Box::new(move || {
                        let s = open_sink.upgrade().ok_or("the AirPlay sink is already gone")?;
                        let mut sink = s.lock().unwrap_or_else(|p| p.into_inner());
                        match sink.take_default() {
                            Ok(()) => {
                                open_mon.set_sink_default(true);
                                Ok(())
                            }
                            // The machine accepted the handover (the CONFIGURED
                            // default names our sink) and only the active one
                            // has not followed. The gate still holds — the TV
                            // would hear nothing anyway — but the status must
                            // not say the speakers still have it, because the
                            // sink is keeping its claim to give it back.
                            Err(e @ crate::audiosink::SinkError::TookUnsettled { .. }) => {
                                open_mon.set_sink_default(true);
                                Err(e.to_string())
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    })),
                    // Detach is the end of the sink, not just of the claim.
                    // After this the sender is gated to digital silence for
                    // good, so a node still called "AirPlay: <TV>" in the
                    // output menu is a trap: picking it — the obvious reaction
                    // to the TV going quiet — routes everything into a sink
                    // that makes no sound anywhere. `disown_default` first, so
                    // that whatever output the user chose is left alone, and
                    // only then take the node down.
                    on_detach: Some(Box::new(move || {
                        if let Some(s) = detach_sink.upgrade() {
                            let mut sink = s.lock().unwrap_or_else(|p| p.into_inner());
                            sink.disown_default();
                            sink.unpublish();
                        }
                        detach_mon.set_sink_default(false);
                        detach_mon.set_sink(None);
                    })),
                }
            }
        };
        rt.volume = Some(crate::volume::spawn_volume_sync_gated(
            laptop,
            Box::new(tv),
            events_rx,
            arx,
            clock,
            monitor.volume.clone(),
            timing,
            gate,
            binding,
        ));
    }

    /// Stop volume sync, then the audio sender (bounded joins). Idempotent;
    /// part of `shutdown`, and what `Drop` of the runtime does otherwise.
    fn stop_audio(&self) {
        let mut rt = self.audio.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(v) = rt.volume.take() {
            let st = v.join(crate::volume::VOLUME_JOIN_BOUND);
            eprintln!("audio: volume sync ended ({}; {} SET to TV, {} to laptop)", st.state, st.sets_to_tv, st.sets_to_laptop);
        }
        if let Some(h) = rt.handle.take() {
            match h.join(crate::audio::AUDIO_JOIN_BOUND) {
                Ok(r) => eprintln!(
                    "audio: sender stopped ({} packets, {} anchors, {} syncs, {} late / {} gap / {} forced / {} step re-anchors, {} silenced frames, {} backlog / {} early dropped, {} control packets in, {} send errors)",
                    r.timeline.packets,
                    r.timeline.anchors,
                    r.timeline.syncs,
                    r.timeline.late_reanchors,
                    r.timeline.gap_reanchors,
                    r.timeline.forced_reanchors,
                    r.timeline.step_reanchors,
                    r.silenced_frames,
                    r.backlog_dropped,
                    r.early_dropped,
                    r.control_rx,
                    r.send_errors
                ),
                Err(e) => eprintln!("audio: {e}"),
            }
        }
        rt.pending = None;
        // Before the node goes: otherwise the watch would see the teardown it
        // is standing next to and report it as a failure.
        if let Some(mut w) = rt.sink_watch.take() {
            w.stop();
        }
        // LAST, and only now: the volume driver has stopped and the capture
        // pinned to this sink's monitor has stopped, so the node may go.
        // Dropping it is what hands the laptop's output back — unless the
        // user took it himself mid-session, in which case the sink knows not
        // to touch it.
        if let Some(sink) = rt.sink.take() {
            drop(sink);
            if let Some(m) = rt.monitor.as_ref() {
                m.set_sink(None);
            }
        }
    }

    /// Connect the type-110 video data socket and wrap it in a mirror streamer.
    ///
    /// Shared by the test-pattern path and the live-screen path so there is
    /// exactly one place that knows the connect timeout, TCP_NODELAY, the video
    /// cipher and the 75 ms presentation lead. `width`/`height` are what the
    /// codec header will advertise, i.e. the CODED size.
    fn connect_video_stream(
        &self,
        width: u32,
        height: u32,
    ) -> Result<crate::video::MirrorStreamer<TcpStream>, SessionError> {
        use std::net::ToSocketAddrs;

        let data_port = self
            .video_data_port
            .ok_or(SessionError::Status("video SETUP (no dataPort)", 0))?;

        // Bounded 5s connect timeout (probe: `create_connection(timeout=5)`),
        // plus a write timeout so a wedged receiver surfaces an io error instead
        // of hanging on send.
        let data_addr = (self.host.as_str(), data_port)
            .to_socket_addrs()
            .map_err(SessionError::Io)?
            .next()
            .ok_or(SessionError::Status("video data socket (no address)", 0))?;
        let data_sock = TcpStream::connect_timeout(&data_addr, Duration::from_secs(5))
            .map_err(SessionError::Io)?;
        data_sock.set_nodelay(true).ok();
        data_sock
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok();

        // ChaCha video cipher; key derived from `shared` + the video stream id.
        let mut streamer = crate::video::MirrorStreamer::new(
            data_sock,
            crate::video::VideoCipher::ChaCha20Poly1305,
            &self.shared,
            self.ids.video_sc_id,
            &self.control_write[..16],
            width,
            height,
            self.video_lead_seconds,
        );
        // Video PTS from the same clock the audio syncs read.
        streamer.set_clock(self.clock.clone());
        Ok(streamer)
    }

    /// Mirror the live screen: Wayland capture on its own thread, hardware
    /// H.264 encode fitted to the receiver's `/info` display, and the resulting
    /// access units forwarded over the same ChaCha20-Poly1305 mirror channel the
    /// test pattern uses.
    ///
    /// Sits alongside [`Session::stream_test_pattern`] rather than replacing it:
    /// the test pattern is the known-good control for when the TV misbehaves,
    /// and keeping both is how a black screen gets bisected into "the pipeline"
    /// or "the receiver".
    ///
    /// The coded size is [`crate::encoder::fit_source_to_receiver`] of the
    /// capture buffer into `self.display` — the RAW receiver size, not
    /// `self.fit`, and never a remembered 1728.
    pub fn stream_screen(&self, cfg: &ScreenStreamConfig) -> Result<ScreenStats, SessionError> {
        use crate::pipeline::{run_stream, PipelineConfig, RunOptions, ScreenPipeline};

        if self.video_data_port.is_none() {
            return Err(SessionError::Status("video SETUP (no dataPort)", 0));
        }

        let mut pcfg = PipelineConfig::new(cfg.source.clone(), self.display);
        pcfg.capture.paint_cursors = cfg.paint_cursors;
        pcfg.capture.zero_copy = cfg.zero_copy;
        if let Some(k) = cfg.keepalive {
            pcfg.capture.keepalive = k;
        }
        pcfg.encoder = cfg.encoder;
        pcfg.fps = cfg.fps;
        pcfg.qp = cfg.qp;
        pcfg.keyframe_seconds = cfg.keyframe_seconds;
        pcfg.device = cfg.device.clone();

        let mut pipe = ScreenPipeline::start(pcfg).map_err(SessionError::Pipeline)?;
        let (w, h) = pipe.target_size();
        let source = pipe.source_size();
        let label = pipe.label().to_string();
        let buffers = pipe.buffer_mode();
        let zero_copy_note = pipe.zero_copy_note().map(str::to_string);

        // Only now open the data socket: a capture or encoder failure should not
        // have left a half-used stream on the receiver.
        let mut streamer = match self.connect_video_stream(w, h) {
            Ok(s) => s,
            Err(e) => {
                pipe.stop();
                return Err(e);
            }
        };
        self.start_audio();

        let mut opts = RunOptions::with_limit(cfg.limit);
        opts.sps_zero_constraints = cfg.sps_zero_constraints;
        let run = run_stream(&mut pipe, &mut streamer, &opts, None);
        // Read after the run, not before it: the encoder can fall back to the
        // CPU on a mid-stream rebuild too.
        let encoder_note = pipe.encoder_note().map(str::to_string);
        // Stop first, then snapshot: a running pump makes the frame ledger
        // approximate, and approximate counters are how milestone 1's bugs hid.
        let stats = pipe.finish();
        let run = run.map_err(SessionError::Pipeline)?;

        Ok(ScreenStats {
            label,
            source,
            width: w,
            height: h,
            buffers,
            zero_copy_note,
            encoder_note,
            run,
            pipeline: stats,
        })
    }

    /// Connect the type-110 video data socket (TCP_NODELAY), generate the ffmpeg
    /// test pattern fit to the receiver display, and stream it access-unit by
    /// access-unit over the ChaCha20-Poly1305 mirror data channel for `limit`
    /// at `fps`, sending a heartbeat every second. `RunLimit::UntilStopped`
    /// loops the pattern until a signal arrives. Ports probe.run step [5] for
    /// the `--source test pattern` path. Requires a live receiver + ffmpeg.
    pub fn stream_test_pattern(
        &self,
        limit: crate::pipeline::RunLimit,
        fps: u32,
    ) -> Result<VideoStats, SessionError> {
        use std::time::{Duration, Instant};

        // Fail before spending ffmpeg time on a pattern that cannot be sent.
        if self.video_data_port.is_none() {
            return Err(SessionError::Status("video SETUP (no dataPort)", 0));
        }

        // Generate the pattern (bounded clip, looped to fill the duration).
        let (w, h) = self.fit;
        // The clip is LOOPED to fill the run, so its length is only a cost/RAM
        // trade-off, never the run's duration. An indefinite run takes the same
        // 20 s clip any run of 20 s or more gets.
        let gen_seconds = match limit {
            crate::pipeline::RunLimit::Seconds(s) => s.clamp(1.0, 20.0),
            crate::pipeline::RunLimit::UntilStopped => 20.0,
        };
        let tmp = std::env::temp_dir().join(format!(
            "airplay-testpattern-{}-{w}x{h}.h264",
            std::process::id()
        ));
        let stream_bytes =
            crate::testpattern::generate(&tmp, w, h, fps, gen_seconds, 5.0).map_err(SessionError::Io)?;
        let _ = std::fs::remove_file(&tmp);
        let aus = crate::testpattern::split_access_units(&stream_bytes);
        if aus.is_empty() {
            return Err(SessionError::Status("test pattern (no access units)", 0));
        }

        let mut streamer = self.connect_video_stream(w, h)?;
        self.start_audio();

        let started = Instant::now();
        let frame_dur = Duration::from_secs_f64(1.0 / fps as f64);
        let mut next_heartbeat = started + Duration::from_secs(1);
        let mut sent = 0u64;
        let mut idr = 0u64;
        let mut heartbeats = 0u64;
        let mut idx = 0usize;
        let mut interrupted = false;

        // `RunLimit::UntilStopped` has no budget, so this is `true` forever and
        // the signal check below is the only way out — exactly as in
        // `pipeline::run_stream`.
        while limit.still_running(started.elapsed()) {
            // Uniform with the live-screen loop: Ctrl-C ends the run normally so
            // the caller's teardown — including an Extend output's `Drop` guard —
            // actually runs. The pacing sleep below is at most one frame time, so
            // this is noticed within ~1/fps of the signal.
            if crate::signals::interrupted() {
                interrupted = true;
                break;
            }
            let au = aus[idx % aus.len()];
            // IDR detection for stats: any VCL NAL of type 5.
            let is_idr = crate::video::split_annexb(au)
                .iter()
                .any(|n| n[0] & 0x1F == 5);
            streamer.forward_access_unit(au).map_err(SessionError::Io)?;
            sent += 1;
            idr += is_idr as u64;
            idx += 1;

            if Instant::now() >= next_heartbeat {
                streamer.send_heartbeat().map_err(SessionError::Io)?;
                heartbeats += 1;
                next_heartbeat += Duration::from_secs(1);
            }

            // Pace to the target frame time. `checked_mul` rather than `*`
            // because an indefinite run has no bound on `idx`: at 60 fps a
            // `u32` frame counter lasts over two years, but a panic in the
            // pacing arithmetic is not an acceptable way to find that out.
            let target = u32::try_from(idx)
                .ok()
                .and_then(|n| frame_dur.checked_mul(n))
                .map(|d| started + d);
            if let Some(d) = target.and_then(|t| t.checked_duration_since(Instant::now())) {
                std::thread::sleep(d);
            }
        }

        Ok(VideoStats {
            frames: sent,
            idr_frames: idr,
            heartbeats,
            width: w,
            height: h,
            seconds: started.elapsed().as_secs_f64(),
            interrupted,
        })
    }

    /// Tear down the session: best-effort TEARDOWN, then stop the feedback loop,
    /// timing responder, and event channel, joining every thread. Ports
    /// probe.run's `finally` (TEARDOWN on the audio URI, close the event conn to
    /// unblock its blocking recv, stop timing).
    pub fn shutdown(mut self) {
        // Volume sync first (it issues control requests), then the audio
        // sender (bounded joins, never hangs).
        self.stop_audio();
        // Stop the feedback loop so it stops issuing control requests.
        if let Some(fb) = self.feedback.take() {
            fb.join();
        }

        // Best-effort, bounded TEARDOWN on the audio URI (probe.py line 1461).
        let audio_uri = audio_uri(&self.host, self.ids.audio_sc_id);
        if let Ok(mut c) = self.control.0.lock() {
            let hdrs = [("Session".to_string(), self.ids.session_uuid.clone())];
            let _ = c.request(
                "TEARDOWN",
                &audio_uri,
                &hdrs,
                None,
                &[],
                Some(TIMEOUT_TEARDOWN),
            );
        }

        // Stop timing and join its thread.
        self.timing.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(j) = self.timing_join.take() {
            let _ = j.join();
        }

        // Close the event socket to unblock the event thread's blocking recv,
        // then join it (the probe closes the event conn in its finally).
        if let Some(sock) = self.event_sock.take() {
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
        if let Some(j) = self.event_join.take() {
            let _ = j.join();
        }
    }
}

fn spawn_timing_responder(timing: Arc<TimingShared>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::sync::atomic::Ordering;
        let _ = timing
            .sock
            .set_read_timeout(Some(Duration::from_millis(500)));
        let mut buf = [0u8; 256];
        loop {
            if timing.stop.load(Ordering::SeqCst) {
                return;
            }
            match timing.sock.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    let data = &buf[..n];
                    if crate::timing::is_timing_request(data) {
                        if let Some(reply) = crate::timing::build_reply(
                            data,
                            timing.clock.read().ntp(),
                        ) {
                            let _ = timing.sock.send_to(&reply, addr);
                        }
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(_) => return,
            }
        }
    })
}

/// Send seq 1..=3 0xd2 requests, 100ms apart (probe.probe_receiver).
fn resolve_ip(host: &str) -> std::io::Result<IpAddr> {
    host.parse().or_else(|_| {
        // Resolve if a hostname was given.
        use std::net::ToSocketAddrs;
        (host, 0)
            .to_socket_addrs()?
            .next()
            .map(|s| s.ip())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))
    })
}

fn probe_timing(sock: &UdpSocket, host: &str, port: u16, clock: &dyn crate::clock::SenderClock) -> std::io::Result<()> {
    let ip = resolve_ip(host)?;
    for seq in 1u16..4 {
        let req = crate::timing::build_request(seq, clock.read().ntp());
        sock.send_to(&req, (ip, port))?;
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// Summary of a completed test-pattern stream.
#[derive(Debug, Clone)]
pub struct VideoStats {
    pub frames: u64,
    pub idr_frames: u64,
    pub heartbeats: u64,
    pub width: u32,
    pub height: u32,
    pub seconds: f64,
    /// The run stopped on a signal rather than on the clock. See
    /// [`crate::pipeline::StreamRun::interrupted`].
    pub interrupted: bool,
}

/// How to mirror the live screen. Defaults match the measured operating point:
/// the GPU encoder, CQP 25, a 5 s wall-clock keyframe interval, and the cursor
/// composited in.
#[derive(Debug, Clone)]
pub struct ScreenStreamConfig {
    pub source: crate::capture::CaptureSource,
    /// How long to run: a fixed number of seconds, or
    /// [`crate::pipeline::RunLimit::UntilStopped`] for `--seconds 0`, where only
    /// a signal, a dead receiver or a fatal error ends the session.
    pub limit: crate::pipeline::RunLimit,
    /// Upper bound on how often a frame is taken from the capture thread. The
    /// pipeline is damage-driven, so a still screen sends the 250 ms keepalive
    /// repeats and nothing else regardless of this number.
    pub fps: u32,
    pub encoder: crate::encoder::EncoderKind,
    pub qp: u32,
    pub keyframe_seconds: f64,
    pub device: String,
    pub paint_cursors: bool,
    /// Capture into GPU buffers the encoder maps instead of shm buffers it has
    /// to upload. Defaults to [`crate::capture::ZeroCopy::Auto`], which falls
    /// back to shm rather than failing.
    pub zero_copy: crate::capture::ZeroCopy,
    /// See [`crate::encoder::zero_sps_constraints`] — the pre-built escape hatch
    /// for a TV that accepts `avc1.640c2a` and renders black.
    pub sps_zero_constraints: bool,
    /// How often the capture re-emits the front buffer when nothing has been
    /// damaged. `None` keeps the capture layer's own default (250 ms), which
    /// makes the stream's rate follow the compositor's damage and therefore
    /// wander — 17 fps idle, 51 fps under mouse movement, measured.
    ///
    /// Setting it to one frame interval instead gives the receiver a CONSTANT
    /// cadence, the way macOS paces off its display link. That matters for a TV
    /// doing motion interpolation: fed a variable-rate stream it has to guess at
    /// varying intervals and overshoots, which reads as a floaty, drifting
    /// cursor. Repeat frames are nearly free — a 60 fps run measured 0.29 Mb/s.
    pub keepalive: Option<std::time::Duration>,
}

impl ScreenStreamConfig {
    pub fn new(source: crate::capture::CaptureSource, limit: crate::pipeline::RunLimit) -> Self {
        ScreenStreamConfig {
            source,
            limit,
            fps: 60,
            encoder: crate::encoder::EncoderKind::Gpu,
            qp: 25,
            keyframe_seconds: 5.0,
            device: "/dev/dri/renderD128".to_string(),
            paint_cursors: true,
            zero_copy: crate::capture::ZeroCopy::default(),
            sps_zero_constraints: false,
            keepalive: None,
        }
    }
}

/// Summary of a completed live-screen stream. Every number is measured: no
/// field is a target, a threshold or a nominal rate.
#[derive(Debug, Clone)]
pub struct ScreenStats {
    /// What was captured, as the compositor described it.
    pub label: String,
    /// Capture buffer size (the PHYSICAL panel size on a scaled output).
    pub source: (u32, u32),
    /// Coded size actually sent.
    pub width: u32,
    pub height: u32,
    /// Which kind of capture buffer fed the encoder. Reported, not requested:
    /// `ZeroCopy::Auto` is allowed to fall back.
    pub buffers: crate::capture::BufferMode,
    /// Why it is not dmabuf, when it is not.
    pub zero_copy_note: Option<String>,
    /// Why the encoder that ran is not the one that was asked for, when it is
    /// not — a GPU-to-CPU fallback, at start-up or mid-stream. Reported the
    /// same way `zero_copy_note` is: a silent degrade is the thing to avoid.
    pub encoder_note: Option<String>,
    pub run: crate::pipeline::StreamRun,
    pub pipeline: crate::pipeline::PipelineStats,
}

/// Errors from the session bring-up.
#[derive(Debug)]
pub enum SessionError {
    Pair(PairError),
    Rtsp(RtspError),
    Io(std::io::Error),
    Status(&'static str, u16),
    /// Capture or encode failed on the live-screen path.
    Pipeline(crate::pipeline::PipelineError),
    /// The audio stream could not be set up (with the reason and what to do).
    Audio(String),
    /// Every pairing route was refused in the one specific way that means the
    /// receiver wants the code off its own screen. Kept apart from
    /// `Pair` because it is the one pairing failure with an ACTION attached —
    /// a UI can offer "enter the code" instead of shrugging — and because the
    /// CLI turns it into its own exit code.
    NeedsCode {
        host: String,
        /// The underlying refusal, for the log. Never shown as the headline.
        detail: String,
    },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Pair(e) => write!(f, "pairing: {e}"),
            SessionError::Rtsp(e) => write!(f, "rtsp: {e}"),
            SessionError::Io(e) => write!(f, "io: {e}"),
            SessionError::Status(what, code) => write!(f, "{what} returned {code}"),
            SessionError::Pipeline(e) => write!(f, "pipeline: {e}"),
            SessionError::Audio(e) => write!(f, "audio: {e}"),
            SessionError::NeedsCode { host, detail } => write!(
                f,
                "this receiver needs an AirPlay code (run: airplay pair {host} --pin CODE) [{detail}]"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<PairError> for SessionError {
    fn from(e: PairError) -> Self {
        SessionError::Pair(e)
    }
}

/// Connect, pair, and bring up the full NTP session. This is the end-to-end
/// entry point used by the CLI's `mirror` command (best-effort: requires a live
/// receiver at `config.host`).
///
/// Three attempts, in this order, each on its own fresh connection (the probe
/// uses one per attempt and so do we):
///
/// 0. **Stored credentials + pair-verify**, when [`SessionConfig::credentials`]
///    is set. This is the attempt that stops a receiver with an AirPlay code
///    set from prompting on every single session, and it is FIRST because it is
///    also the quietest: no `/pair-pin-start`, so nothing appears on the TV.
/// 1. **Transient** pair-setup with the fixed `3939` PIN — probe.run's
///    `--pairing auto` first attempt, and what every receiver without a code
///    set accepts.
/// 2. **PIN pair-setup + pair-verify**, only when a PIN is supplied in the
///    config; the probe's PIN attempt likewise needs a code read off the TV.
///
/// Credentials that do not verify are NOT fatal and are NOT deleted: a receiver
/// that has forgotten us (factory reset, pairings cleared) produces exactly the
/// same `BadSignature` as a corrupt file, and in both cases the right move is
/// to carry on to transient and let the user re-pair when they choose. The
/// failure is said out loud on stderr, because a silent fall-back to transient
/// is how "my credentials are not being used" hides for a month.
///
/// If every route is refused in the specific way that means "the receiver wants
/// the code off its screen" ([`pairing::code_required`]), the error is
/// [`SessionError::NeedsCode`] rather than a generic pairing failure — that
/// distinction is the one a panel can act on.
pub fn run_session(config: &SessionConfig) -> Result<Session, SessionError> {
    run_session_with(config, connect)
}

/// [`run_session`] with the dialler injected.
///
/// The attempt order — credentials, then transient, then PIN — is the thing
/// worth testing, and testing it against [`connect`] would mean a fake
/// receiver squatting on port 7000 (the AirPlay port is not configurable, and
/// should not become so for a test's sake). So the one line that opens a socket
/// is a parameter, and the loopback tests hand it a closure pointing at an
/// ephemeral port. Production passes `connect` and nothing else.
pub fn run_session_with(
    config: &SessionConfig,
    connect_to: impl Fn(&str) -> std::io::Result<RtspConnection<TcpStream>>,
) -> Result<Session, SessionError> {
    // Attempt 0: the credentials we already hold.
    if let Some(creds) = &config.credentials {
        match connect_to(&config.host) {
            Ok(mut verify_conn) => match pairing::pair_verify(&mut verify_conn, creds) {
                Ok(shared) => {
                    let mut session = Session::bring_up(verify_conn, shared.to_vec(), config)?;
                    session.pairing = PairingMethod::Verified;
                    return Ok(session);
                }
                Err(e) => eprintln!(
                    "pairing: stored credentials for {} did not verify ({e}); \
                     falling back to transient pairing — re-pair with \
                     `airplay pair {} --pin CODE` if this receiver keeps asking for a code",
                    config.host, config.host
                ),
            },
            Err(e) => eprintln!(
                "pairing: could not open a connection to {} for pair-verify ({e}); \
                 retrying with transient pairing",
                config.host
            ),
        }
    }

    // Attempt 1: transient.
    let mut conn = connect_to(&config.host).map_err(SessionError::Io)?;
    match pair_transient_on(&mut conn) {
        Ok(shared) => Session::bring_up(conn, shared, config),
        Err(transient_err) => match &config.pin {
            // Attempt 2: PIN pair-setup, then reconnect for pair-verify (the
            // probe closes the setup connection and reconnects before verify).
            Some(pin) => {
                let mut setup_conn = connect_to(&config.host).map_err(SessionError::Io)?;
                let creds = pairing::pair_setup_pin(
                    &mut setup_conn,
                    config.hkp,
                    SENDER_NAME,
                    || pin.clone(),
                )
                .map_err(SessionError::Pair)?;
                let mut verify_conn = connect_to(&config.host).map_err(SessionError::Io)?;
                let shared = pairing::pair_verify(&mut verify_conn, &creds)
                    .map_err(SessionError::Pair)?;
                let mut session = Session::bring_up(verify_conn, shared.to_vec(), config)?;
                session.pairing = PairingMethod::Pin;
                Ok(session)
            }
            None if pairing::code_required(&transient_err) => Err(SessionError::NeedsCode {
                host: config.host.clone(),
                detail: transient_err.to_string(),
            }),
            None => Err(SessionError::Pair(transient_err)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plist_bin(v: plist::Value) -> Vec<u8> {
        let mut out = Vec::new();
        plist::to_writer_binary(&mut out, &v).unwrap();
        out
    }

    fn streams(entries: Vec<Vec<(&str, plist::Value)>>) -> Vec<u8> {
        let arr = entries
            .into_iter()
            .map(|e| {
                let mut d = plist::Dictionary::new();
                for (k, v) in e {
                    d.insert(k.into(), v);
                }
                plist::Value::Dictionary(d)
            })
            .collect();
        let mut root = plist::Dictionary::new();
        root.insert("streams".into(), plist::Value::Array(arr));
        plist_bin(plist::Value::Dictionary(root))
    }

    #[test]
    fn stream_ports_parses_frame_reply() {
        // The shape the Frame answered the probe's audio SETUP with.
        let body = streams(vec![vec![
            ("type", 96u64.into()),
            ("dataPort", 44636u64.into()),
            ("controlPort", 51158u64.into()),
        ]]);
        assert_eq!(stream_ports(&body, 96), Some((44636, 51158)));
        assert_eq!(stream_data_port(&body, 96), Some(44636));
        assert_eq!(stream_ports(&body, 110), None);
        // No control port (or 0): cannot be anchored, so None.
        let body = streams(vec![vec![("type", 96u64.into()), ("dataPort", 44636u64.into())]]);
        assert_eq!(stream_ports(&body, 96), None);
        let body = streams(vec![vec![
            ("type", 96u64.into()),
            ("dataPort", 44636u64.into()),
            ("controlPort", 0u64.into()),
        ]]);
        assert_eq!(stream_ports(&body, 96), None);
        assert_eq!(stream_ports(b"not a plist", 96), None);
    }

    #[test]
    fn receiver_events_parse() {
        let mut d = plist::Dictionary::new();
        d.insert("type".into(), "sendMediaRemoteCommand".into());
        d.insert("value".into(), "dvlc".into());
        d.insert("volume".into(), 0.9f64.into());
        d.insert("isMuted".into(), true.into());
        assert_eq!(
            parse_receiver_event(&plist_bin(plist::Value::Dictionary(d))),
            Some(ReceiverEvent::Volume { v: 0.9, muted: true })
        );
        let mut d = plist::Dictionary::new();
        d.insert("type".into(), "updateInfo".into());
        d.insert("value".into(), plist::Value::Dictionary(Default::default()));
        assert_eq!(parse_receiver_event(&plist_bin(plist::Value::Dictionary(d))), Some(ReceiverEvent::UpdateInfo));
        assert_eq!(parse_receiver_event(b"garbage"), None);
    }

    /// A stream that records writes and yields a scripted read, then EOF.
    struct Scripted {
        read: std::io::Cursor<Vec<u8>>,
        log: Arc<Mutex<Vec<(&'static str, usize)>>>,
    }
    impl Read for Scripted {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let n = self.read.read(b)?;
            if n > 0 {
                self.log.lock().unwrap().push(("read", n));
            }
            Ok(n)
        }
    }
    impl Write for Scripted {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.log.lock().unwrap().push(("write", b.len()));
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn event_reply_written_before_parse() {
        // The consumer's channel is FULL (capacity 1, already holding one
        // event): the reply must still be written, and the loop must not
        // block on the forward.
        let shared: Vec<u8> = (0u8..32).collect();
        let keys = event_channel_keys(&shared);
        let mut peer = crate::crypto::HapCipher::new(keys.read_key, keys.write_key);
        let mut d = plist::Dictionary::new();
        d.insert("type".into(), "updateInfo".into());
        let body = plist_bin(plist::Value::Dictionary(d));
        let mut wire = Vec::new();
        for cseq in 1..=3 {
            let mut req = format!("POST /command RTSP/1.0\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            req.extend_from_slice(&body);
            wire.extend(peer.seal(&req));
        }
        let log = Arc::new(Mutex::new(vec![]));
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        tx.send(ReceiverEvent::Other("pre-filled".into())).unwrap();
        let s = Scripted { read: std::io::Cursor::new(wire), log: log.clone() };
        EventChannelConn::with_events(s, &shared, tx).run().unwrap();
        let writes = log.lock().unwrap().iter().filter(|(k, _)| *k == "write").count();
        assert_eq!(writes, 3, "every request answered even with the consumer full");
        assert_eq!(rx.try_iter().count(), 1, "forwards were dropped, never blocked on");
    }

    #[test]
    fn audio_mode_defaults_off() {
        let c = SessionConfig::new("192.0.2.1");
        assert_eq!(c.audio, AudioMode::None);
        assert!(!c.audio.is_on());
        assert_eq!(c.audio_latency_ms, 300);
        assert_eq!(c.av_offset_ms, None);
        assert!(!c.volume_probe);
    }
}

// --------------------------------------------------------------------------
// The volume binding decision (pure: no PipeWire, no pactl, no receiver)
// --------------------------------------------------------------------------

#[cfg(test)]
mod binding_tests {
    use super::*;

    /// The ordinary paths.
    #[test]
    fn a_published_sink_binds_the_driver_to_it_and_nothing_else() {
        assert_eq!(
            volume_binding(true, Some("airplay-sink.frame")),
            VolumeBinding::OurSink("airplay-sink.frame".into())
        );
    }

    #[test]
    fn without_sink_mode_the_driver_follows_the_laptop_output() {
        assert_eq!(volume_binding(false, None), VolumeBinding::FollowOutput);
    }

    /// THE GUARD. Sink mode asked for, nothing recorded: the driver must be
    /// refused, not quietly pointed at the hardware default.
    ///
    /// This is the case a `require_sink` derived from `rt.sink` alone can
    /// never see — both operands would come from the same `Option`, so the
    /// check would compare a value with itself. With `rt.sink` `None` and no
    /// refusal, the session would take `PactlVolume::follow_output()` and a
    /// `dvlc` from the TV remote would write the desk speakers.
    #[test]
    fn sink_mode_without_a_sink_is_refused_never_the_hardware_output() {
        assert_eq!(volume_binding(true, None), VolumeBinding::Refuse);
        assert_ne!(volume_binding(true, None), VolumeBinding::FollowOutput);
    }

    /// A fallback is NOT a wiring slip. `fallback_capture` rewrites the mode
    /// to `Pipewire` before returning, so by the time the decision is taken
    /// `sink_mode` is false and the session follows the output as the old
    /// model does. If the decision were ever taken from the mode SNAPSHOT
    /// instead, every legitimate fallback would become a silent session.
    #[test]
    fn a_fallback_to_the_monitor_path_is_not_refused() {
        let asked_for = AudioMode::System { capture: CaptureBackend::Sink };
        assert!(matches!(asked_for, AudioMode::System { capture: CaptureBackend::Sink }));
        // What fallback_capture does to rt.mode before returning.
        let rt_mode = AudioMode::System { capture: CaptureBackend::Pipewire };
        let sink_mode = matches!(rt_mode, AudioMode::System { capture: CaptureBackend::Sink });
        assert_eq!(volume_binding(sink_mode, None), VolumeBinding::FollowOutput);
    }

    /// The sentinel must be something no node can be called, or the refusal
    /// could be satisfied by a real sink.
    #[test]
    fn the_refusal_sentinel_cannot_be_a_node_name() {
        assert!(SINK_MODE_WITHOUT_A_SINK.starts_with('<'));
        assert!(SINK_MODE_WITHOUT_A_SINK.contains(' '));
        assert!(!SINK_MODE_WITHOUT_A_SINK.starts_with("airplay-sink."));
    }

    /// `--no-volume-sync` must never be the mode that ALSO takes the
    /// speakers away. In sink mode the tap is pre-volume, so our slider and
    /// the volume keys do nothing; no SET is sent, so the TV plays at its own
    /// level; and the output has moved, so the room is silent and there is no
    /// cue. Degrade to the monitor path, which at least keeps the default
    /// sink's attenuation and audible sound on the laptop.
    #[test]
    fn no_volume_sync_never_gets_the_sink_that_cannot_attenuate() {
        let sink = AudioMode::System { capture: CaptureBackend::Sink };
        let (mode, degraded) = capture_without_volume_sync(sink, false);
        assert!(degraded, "--no-volume-sync kept sink mode: nothing in the chain can attenuate");
        assert_eq!(mode, AudioMode::System { capture: CaptureBackend::Pipewire });
        assert_ne!(mode, sink);
    }

    /// With the volume driver running, sink mode is exactly what was asked
    /// for and must be left alone — degrading it would throw away the whole
    /// point of the feature.
    #[test]
    fn volume_sync_leaves_every_mode_alone() {
        for m in [
            AudioMode::System { capture: CaptureBackend::Sink },
            AudioMode::System { capture: CaptureBackend::Pipewire },
            AudioMode::System { capture: CaptureBackend::Parec },
            AudioMode::Tone,
            AudioMode::None,
        ] {
            assert_eq!(capture_without_volume_sync(m, true), (m, false), "{m:?}");
        }
    }

    /// And without it, only the sink backend is touched: the other modes
    /// already keep their attenuation and their sound in the room.
    #[test]
    fn no_volume_sync_touches_nothing_but_sink_mode() {
        for m in [
            AudioMode::System { capture: CaptureBackend::Pipewire },
            AudioMode::System { capture: CaptureBackend::Parec },
            AudioMode::Tone,
            AudioMode::None,
        ] {
            assert_eq!(capture_without_volume_sync(m, false), (m, false), "{m:?}");
        }
    }
}
