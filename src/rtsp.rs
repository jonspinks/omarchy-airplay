//! rtsp-transport: RTSP-over-TCP request framing and (optionally) HAP-sealed
//! transport. Ported from probe.RtspConnection (probe.py lines 194-277).

use crate::crypto as hap;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::time::Duration;

/// Per-request read/write timeout default, matching the probe's
/// `RtspConnection.request(timeout=15)` (probe.py line 250).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

pub const USER_AGENT: &str = "AirPlay/935.7.1";
pub const RTSP_VERSION: &str = "RTSP/1.0";
pub const CT_BINARY_PLIST: &str = "application/x-apple-binary-plist";
pub const CT_OCTET_STREAM: &str = "application/octet-stream";

/// A parsed RTSP message (request or response). Header keys are lowercased.
#[derive(Debug, Clone)]
pub struct RtspMessage {
    pub first_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RtspMessage {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Parses "content-length", default 0.
    pub fn content_length(&self) -> usize {
        self.header("content-length")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }

    /// `split_whitespace()[1]`, 0 if non-numeric.
    pub fn status_code(&self) -> u16 {
        self.first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}

/// Build outbound request bytes exactly as probe.RtspConnection._request.
pub fn build_request(
    method: &str,
    uri: &str,
    cseq: u32,
    default_headers: &[(String, String)],
    headers: &[(String, String)],
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    // Merge {**default_headers, **headers}: Python dict-merge keeps a key in the
    // position of its first insertion (default_headers first), with the
    // per-request value winning on collision.
    let mut merged: Vec<(String, String)> = Vec::new();
    for (k, v) in default_headers.iter().chain(headers.iter()) {
        if let Some(slot) = merged
            .iter_mut()
            .find(|(mk, _)| mk.eq_ignore_ascii_case(k))
        {
            slot.1 = v.clone();
        } else {
            merged.push((k.clone(), v.clone()));
        }
    }

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("{method} {uri} {RTSP_VERSION}"));
    lines.push(format!("CSeq: {cseq}"));
    lines.push(format!("User-Agent: {USER_AGENT}"));
    for (k, v) in &merged {
        lines.push(format!("{k}: {v}"));
    }
    // Content-Type only when BOTH a content_type is given AND the body is non-empty.
    if let Some(ct) = content_type {
        if !body.is_empty() {
            lines.push(format!("Content-Type: {ct}"));
        }
    }
    // Content-Length always present.
    lines.push(format!("Content-Length: {}", body.len()));

    let mut raw = (lines.join("\r\n") + "\r\n\r\n").into_bytes();
    raw.extend_from_slice(body);
    raw
}

/// Split a full head+body pair from a byte buffer, returning the message and
/// bytes consumed, or None if the buffer does not yet hold a complete message.
pub fn try_parse_message(buf: &[u8]) -> Option<(RtspMessage, usize)> {
    // Find the first \r\n\r\n separating head from body.
    let sep = find_subslice(buf, b"\r\n\r\n")?;
    let head = &buf[..sep];
    let rest = &buf[sep + 4..];

    // Decode head as latin-1 (each byte is its own code point) and split on \r\n.
    let head_str: String = head.iter().map(|&b| b as char).collect();
    let mut lines = head_str.split("\r\n");
    let first_line = lines.next().unwrap_or("").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some(idx) = line.find(':') {
            let k = line[..idx].trim().to_ascii_lowercase();
            let v = line[idx + 1..].trim().to_string();
            headers.push((k, v));
        }
    }

    let length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);

    // Need the whole declared body before we can return a complete message.
    if rest.len() < length {
        return None;
    }
    let body = rest[..length].to_vec();
    let consumed = sep + 4 + length;
    Some((
        RtspMessage {
            first_line,
            headers,
            body,
        },
        consumed,
    ))
}

/// First index of `needle` within `hay`, or None.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Streams that can report their local socket address (production: `TcpStream`).
/// Lets `local_ip` stay on the generic connection without forcing every test
/// stub to implement addressing.
pub trait HasLocalAddr {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr>;
}

impl HasLocalAddr for std::net::TcpStream {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        std::net::TcpStream::local_addr(self)
    }
}

/// Streams whose read/write timeout can be bounded per request (production:
/// `TcpStream`). The probe calls `self.sock.settimeout(timeout)` before each
/// send+read (probe.py line 263), which bounds both directions; `set_read_timeout`
/// / `set_write_timeout` mirror that. Kept off the generic `RtspConnection` so
/// in-memory test streams need not implement it.
pub trait SocketTimeout {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
}

impl SocketTimeout for std::net::TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        std::net::TcpStream::set_write_timeout(self, dur)
    }
}

/// The transport, generic over a byte stream.
pub struct RtspConnection<S: Read + Write> {
    sock: S,
    cseq: u32,
    cipher: Option<hap::HapCipher>,
    buf: Vec<u8>,
    default_headers: Vec<(String, String)>,
    /// Set when the byte stream can no longer be trusted to line up with
    /// requests: a failed or partial write (the HAP nonce already advanced), a
    /// read error part-way through a HAP frame, a failed open(), or a reply
    /// whose CSeq is AHEAD of ours. Every later `request` fails with
    /// [`RtspError::Desynced`] instead of misattributing a reply.
    poisoned: Option<String>,
}

impl<S: Read + Write> RtspConnection<S> {
    pub fn new(sock: S) -> Self {
        RtspConnection {
            sock,
            cseq: 0,
            cipher: None,
            buf: Vec::new(),
            default_headers: Vec::new(),
            poisoned: None,
        }
    }

    pub fn set_cipher(&mut self, cipher: hap::HapCipher) {
        self.cipher = Some(cipher);
    }

    pub fn set_default_headers(&mut self, h: Vec<(String, String)>) {
        self.default_headers = h;
    }

    pub fn local_ip(&self) -> std::io::Result<IpAddr>
    where
        S: HasLocalAddr,
    {
        self.sock.local_addr().map(|a| a.ip())
    }

    /// Why the connection is no longer usable, if it is not.
    pub fn poisoned(&self) -> Option<&str> {
        self.poisoned.as_deref()
    }

    fn poison(&mut self, why: String) {
        if self.poisoned.is_none() {
            self.poisoned = Some(why);
        }
    }

    /// Increment cseq, build, seal when a cipher is set, send, read the
    /// response to THIS request. Returns (status, response-message).
    ///
    /// Replies are matched by CSeq: a reply with a LOWER CSeq is the late
    /// answer to an earlier request that timed out, and is discarded. A reply
    /// with no CSeq header is accepted as-is (as before). A clean read timeout
    /// (no byte of the next HAP frame read) leaves the connection usable, and
    /// the late reply is dropped by the next request; anything that leaves the
    /// stream out of step poisons the connection (see `poisoned`).
    ///
    /// `timeout` bounds the send+read for this one request; `None` leaves the
    /// socket blocking. The probe sets `self.sock.settimeout(timeout)` before
    /// the send and read (probe.py line 263) with a 15s default, so a wedged or
    /// silent receiver surfaces an io timeout instead of hanging forever.
    pub fn request(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(String, String)],
        content_type: Option<&str>,
        body: &[u8],
        timeout: Option<Duration>,
    ) -> Result<(u16, RtspMessage), RtspError>
    where
        S: SocketTimeout,
    {
        if let Some(why) = &self.poisoned {
            return Err(RtspError::Desynced(why.clone()));
        }
        // Increment cseq BEFORE building (probe.py line 255).
        self.cseq += 1;
        let raw = build_request(
            method,
            uri,
            self.cseq,
            &self.default_headers,
            headers,
            content_type,
            body,
        );
        // Seal when a cipher is attached, else send plaintext (probe.py line 265).
        let wire = match self.cipher.as_mut() {
            Some(c) => c.seal(&raw),
            None => raw,
        };
        // Bound both directions before the exchange (probe.py line 263).
        self.sock.set_read_timeout(timeout)?;
        self.sock.set_write_timeout(timeout)?;
        // A failed write may have sent part of the frame, and a sealed frame
        // has already advanced the cipher's nonce: the stream is out of step.
        if let Err(e) = self.sock.write_all(&wire).and_then(|_| self.sock.flush()) {
            self.poison(format!("{method} write failed: {e}"));
            return Err(e.into());
        }
        let want = self.cseq;
        loop {
            let msg = self.read_message()?;
            match msg.header("cseq").map(|c| c.trim().parse::<u32>()) {
                None => return Ok((msg.status_code(), msg)),
                Some(Ok(c)) if c == want => return Ok((msg.status_code(), msg)),
                // Late reply to an earlier, timed-out request: drop it.
                Some(Ok(c)) if c < want => continue,
                Some(other) => {
                    let why = format!("{method} CSeq {want} got a reply with CSeq {other:?}");
                    self.poison(why.clone());
                    return Err(RtspError::Desynced(why));
                }
            }
        }
    }

    /// Send a raw message (a server-directed response, e.g. the event-channel
    /// 200 reply), sealing it when a cipher is attached. Unlike `request`, this
    /// does not touch `cseq` or read a reply. Mirrors the probe's
    /// `self.conn.sock.sendall(self.conn.cipher.seal(reply))`.
    pub fn send_sealed(&mut self, raw: &[u8]) -> std::io::Result<()> {
        let wire = match self.cipher.as_mut() {
            Some(c) => c.seal(raw),
            None => raw.to_vec(),
        };
        self.sock.write_all(&wire)?;
        self.sock.flush()
    }

    /// Read exactly one message, filling `buf` as needed (plaintext recv, or
    /// 2-byte-LE-len + ciphertext+16-tag HAP frames when encrypted).
    pub fn read_message(&mut self) -> Result<RtspMessage, RtspError> {
        loop {
            if let Some((msg, consumed)) = try_parse_message(&self.buf) {
                // Keep bytes beyond this message for the next call.
                self.buf.drain(..consumed);
                return Ok(msg);
            }
            self.fill()?;
        }
    }

    /// One fill step: plaintext recv, or a single HAP frame when encrypted.
    /// Mirrors probe RtspConnection._fill (probe.py 222-231).
    fn fill(&mut self) -> Result<(), RtspError> {
        match self.cipher.as_mut() {
            None => {
                let mut chunk = [0u8; 65536];
                let n = self.sock.read(&mut chunk)?;
                if n == 0 {
                    return Err(RtspError::ConnectionClosed);
                }
                self.buf.extend_from_slice(&chunk[..n]);
            }
            Some(_) => {
                // Read the 2-byte LE length AAD, then size+16 bytes, then open().
                // An error before the first byte of the frame is clean (the
                // frame is still whole on the wire); once any byte of it has
                // been consumed, or open() fails, the stream is out of step.
                let mut started = false;
                let aad = match read_exact_track(&mut self.sock, 2, &mut started) {
                    Ok(a) => a,
                    Err(e) => {
                        if started {
                            self.poison(format!("read failed part-way through a HAP frame: {e}"));
                        }
                        return Err(e);
                    }
                };
                let size = u16::from_le_bytes([aad[0], aad[1]]) as usize;
                let sealed = match read_exact_alloc(&mut self.sock, size + HAP_TAG_LEN) {
                    Ok(s) => s,
                    Err(e) => {
                        self.poison(format!("read failed part-way through a HAP frame: {e}"));
                        return Err(e);
                    }
                };
                let cipher = self.cipher.as_mut().unwrap();
                let plain = match cipher.open(&aad, &sealed) {
                    Ok(p) => p,
                    Err(_) => {
                        self.poison("HAP open() failed".into());
                        return Err(RtspError::Decrypt);
                    }
                };
                self.buf.extend_from_slice(&plain);
            }
        }
        Ok(())
    }
}

const HAP_TAG_LEN: usize = 16;

/// Read exactly `n` bytes, looping until gathered; errors on early close
/// (probe RtspConnection._recv_exact, probe.py 213-220).
fn read_exact_alloc<R: Read>(sock: &mut R, n: usize) -> Result<Vec<u8>, RtspError> {
    let mut started = false;
    read_exact_track(sock, n, &mut started)
}

/// [`read_exact_alloc`] that sets `started` once any byte has been read.
fn read_exact_track<R: Read>(sock: &mut R, n: usize, started: &mut bool) -> Result<Vec<u8>, RtspError> {
    let mut data = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        let got = sock.read(&mut data[filled..])?;
        if got == 0 {
            return Err(RtspError::ConnectionClosed);
        }
        *started = true;
        filled += got;
    }
    Ok(data)
}

#[derive(Debug)]
pub enum RtspError {
    ConnectionClosed,
    Io(std::io::Error),
    Decrypt,
    Malformed(String),
    /// The connection is out of step with the receiver (see
    /// `RtspConnection::poisoned`) and was not used.
    Desynced(String),
}

impl std::fmt::Display for RtspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RtspError::ConnectionClosed => write!(f, "connection closed by receiver"),
            RtspError::Io(e) => write!(f, "io error: {e}"),
            RtspError::Decrypt => write!(f, "HAP open() failed"),
            RtspError::Malformed(s) => write!(f, "malformed message: {s}"),
            RtspError::Desynced(s) => write!(f, "connection out of step, not reused: {s}"),
        }
    }
}

impl std::error::Error for RtspError {}

impl From<std::io::Error> for RtspError {
    fn from(e: std::io::Error) -> Self {
        RtspError::Io(e)
    }
}

#[cfg(test)]
mod desync_tests {
    //! CSeq matching and poisoning, against an in-memory scripted stream (no
    //! sockets). Finding #14: a timed-out volume request must not make the
    //! next request (/feedback, TEARDOWN) read the stale reply as its own.
    use super::*;
    use std::collections::VecDeque;
    use std::io::ErrorKind;

    /// Each read returns the next chunk, or a timeout when the script says so
    /// (or when it is empty). Writes are recorded.
    #[derive(Default)]
    struct Scripted {
        reads: VecDeque<Option<Vec<u8>>>,
        written: Vec<u8>,
        fail_write: bool,
    }

    impl Read for Scripted {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            match self.reads.pop_front() {
                Some(Some(mut c)) => {
                    let n = c.len().min(out.len());
                    out[..n].copy_from_slice(&c[..n]);
                    if n < c.len() {
                        c.drain(..n);
                        self.reads.push_front(Some(c));
                    }
                    Ok(n)
                }
                _ => Err(std::io::Error::new(ErrorKind::WouldBlock, "timed out")),
            }
        }
    }

    impl Write for Scripted {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.fail_write {
                return Err(std::io::Error::new(ErrorKind::WouldBlock, "write timed out"));
            }
            self.written.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SocketTimeout for Scripted {
        fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn reply(cseq: u32, body: &str) -> Vec<u8> {
        format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    fn get(c: &mut RtspConnection<Scripted>, what: &str) -> Result<(u16, RtspMessage), RtspError> {
        c.request("GET_PARAMETER", what, &[], None, b"volume\r\n", Some(Duration::from_millis(1)))
    }

    #[test]
    fn late_reply_to_a_timed_out_request_is_discarded() {
        let mut s = Scripted::default();
        s.reads.push_back(None); // request 1 times out
        s.reads.push_back(Some(reply(1, "volume: -30.0\r\n"))); // its late reply
        s.reads.push_back(Some(reply(2, "feedback")));
        let mut c = RtspConnection::new(s);
        assert!(matches!(get(&mut c, "/a"), Err(RtspError::Io(_))));
        assert!(c.poisoned().is_none(), "a clean timeout keeps the connection");
        let (st, msg) = get(&mut c, "/b").unwrap();
        assert_eq!(st, 200);
        assert_eq!(msg.header("cseq"), Some("2"));
        assert_eq!(msg.body, b"feedback");
    }

    #[test]
    fn a_reply_without_cseq_is_still_accepted() {
        let mut s = Scripted::default();
        s.reads.push_back(Some(b"RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()));
        let mut c = RtspConnection::new(s);
        assert_eq!(get(&mut c, "/a").unwrap().0, 200);
    }

    #[test]
    fn a_reply_ahead_of_our_cseq_poisons_the_connection() {
        let mut s = Scripted::default();
        s.reads.push_back(Some(reply(5, "")));
        let mut c = RtspConnection::new(s);
        assert!(matches!(get(&mut c, "/a"), Err(RtspError::Desynced(_))));
        let before = c.sock.written.len();
        assert!(matches!(get(&mut c, "/b"), Err(RtspError::Desynced(_))));
        assert_eq!(c.sock.written.len(), before, "a poisoned connection sends nothing");
    }

    #[test]
    fn a_failed_write_poisons_the_connection() {
        let s = Scripted { fail_write: true, ..Default::default() };
        let mut c = RtspConnection::new(s);
        assert!(matches!(get(&mut c, "/a"), Err(RtspError::Io(_))));
        c.sock.fail_write = false;
        assert!(matches!(get(&mut c, "/b"), Err(RtspError::Desynced(_))));
        assert!(c.sock.written.is_empty());
    }

    fn pair() -> (hap::HapCipher, hap::HapCipher) {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        (hap::HapCipher::new(a, b), hap::HapCipher::new(b, a))
    }

    #[test]
    fn a_timeout_part_way_through_a_hap_frame_poisons_the_connection() {
        let (ours, mut theirs) = pair();
        let sealed = theirs.seal(&reply(1, "volume: -24.9\r\n"));
        let mut s = Scripted::default();
        s.reads.push_back(Some(sealed[..10].to_vec())); // half a frame, then timeout
        s.reads.push_back(None);
        s.reads.push_back(Some(sealed[10..].to_vec()));
        let mut c = RtspConnection::new(s);
        c.set_cipher(ours);
        assert!(matches!(get(&mut c, "/a"), Err(RtspError::Io(_))));
        assert!(c.poisoned().is_some());
        let before = c.sock.written.len();
        assert!(matches!(get(&mut c, "/b"), Err(RtspError::Desynced(_))));
        assert_eq!(c.sock.written.len(), before);
    }

    #[test]
    fn a_timeout_inside_the_hap_length_prefix_poisons_the_connection() {
        let (ours, mut theirs) = pair();
        let sealed = theirs.seal(&reply(1, "x"));
        let mut s = Scripted::default();
        s.reads.push_back(Some(sealed[..1].to_vec())); // one of the two length bytes
        s.reads.push_back(None);
        s.reads.push_back(Some(sealed[1..].to_vec()));
        let mut c = RtspConnection::new(s);
        c.set_cipher(ours);
        assert!(matches!(get(&mut c, "/a"), Err(RtspError::Io(_))));
        assert!(c.poisoned().is_some());
        assert!(matches!(get(&mut c, "/b"), Err(RtspError::Desynced(_))));
    }

    #[test]
    fn a_clean_hap_timeout_then_late_reply_is_discarded() {
        let (ours, mut theirs) = pair();
        let mut s = Scripted::default();
        s.reads.push_back(None); // request 1: nothing yet
        s.reads.push_back(Some(theirs.seal(&reply(1, "late"))));
        s.reads.push_back(Some(theirs.seal(&reply(2, "mine"))));
        let mut c = RtspConnection::new(s);
        c.set_cipher(ours);
        assert!(matches!(get(&mut c, "/a"), Err(RtspError::Io(_))));
        assert!(c.poisoned().is_none());
        let (_, msg) = get(&mut c, "/b").unwrap();
        assert_eq!(msg.body, b"mine");
    }
}
