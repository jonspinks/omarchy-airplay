//! timing-ntp: AirPlay NTP timing side-channel (0xd2 request / 0xd3 reply).
//! Ported from probe.boot_ntp_timestamp / probe.TimingResponder (probe.py).

use std::net::{IpAddr, UdpSocket};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicBool;

/// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
pub const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// 64-bit NTP timestamp in 32.32 fixed point (big-endian on the wire).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtpTimestamp(pub u64);

impl NtpTimestamp {
    /// Read CLOCK_BOOTTIME and convert (port of `boot_ntp_timestamp()`).
    pub fn now_from_boottime() -> Self {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid timespec pointer, well-defined clock id.
        unsafe {
            libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts);
        }
        let seconds = ts.tv_sec as u64;
        let subsec = ts.tv_nsec as f64 / 1_000_000_000.0;
        Self::from_boottime_parts(seconds, subsec)
    }

    /// Deterministic core of the conversion — the unit-testable part.
    /// `seconds` = integer boottime seconds, `subsec` its fractional part [0,1).
    pub fn from_boottime_parts(seconds: u64, subsec: f64) -> Self {
        let fraction = ((subsec * (1u64 << 32) as f64) as u64) & 0xFFFF_FFFF;
        NtpTimestamp(((seconds + NTP_EPOCH_OFFSET) << 32) | fraction)
    }

    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    pub fn from_be_bytes(b: [u8; 8]) -> Self {
        NtpTimestamp(u64::from_be_bytes(b))
    }
}

/// Fixed 32-byte timing packet (request or reply share the layout).
pub type TimingPacket = [u8; 32];

/// Build a 0xd2 request for a sequence number and client transmit timestamp.
pub fn build_request(seq: u16, transmit: NtpTimestamp) -> TimingPacket {
    let mut pkt = [0u8; 32];
    pkt[0] = 0x80;
    pkt[1] = 0xD2;
    pkt[2..4].copy_from_slice(&seq.to_be_bytes());
    pkt[24..32].copy_from_slice(&transmit.to_be_bytes());
    pkt
}

/// Build the 0xd3 reply from a received request and the server's current time.
/// Returns None if `request` is not a valid 0xd2 timing request.
pub fn build_reply(request: &[u8], now: NtpTimestamp) -> Option<TimingPacket> {
    if !is_timing_request(request) {
        return None;
    }
    let mut reply = [0u8; 32];
    // Copy the request's first 32 bytes, then overwrite byte 1 and 8..32.
    reply.copy_from_slice(&request[..32]);
    reply[1] = 0xD3;
    let now_be = now.to_be_bytes();
    reply[8..16].copy_from_slice(&request[24..32]); // originate
    reply[16..24].copy_from_slice(&now_be); // receive
    reply[24..32].copy_from_slice(&now_be); // transmit
    Some(reply)
}

/// True if `data` is a well-formed 0xd2 timing request.
pub fn is_timing_request(data: &[u8]) -> bool {
    data.len() >= 32 && data[0] == 0x80 && data[1] == 0xD2
}

/// Responder: answers 0xd2 with 0xd3, counts traffic. Mirrors
/// TimingResponder's request/other counters and source-IP set.
pub struct TimingResponder {
    sock: UdpSocket,
    stop: AtomicBool,
    requests: AtomicU64,
    other: AtomicU64,
    sources: std::sync::Mutex<std::collections::HashSet<IpAddr>>,
}

impl TimingResponder {
    pub fn new(sock: UdpSocket) -> Self {
        TimingResponder {
            sock,
            stop: AtomicBool::new(false),
            requests: AtomicU64::new(0),
            other: AtomicU64::new(0),
            sources: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Loop with a 0.5s read timeout; returns on socket error.
    pub fn run(&mut self) {
        use std::sync::atomic::Ordering;
        let _ = self
            .sock
            .set_read_timeout(Some(std::time::Duration::from_millis(500)));
        let mut buf = [0u8; 256];
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return;
            }
            match self.sock.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    let data = &buf[..n];
                    self.sources.lock().unwrap().insert(addr.ip());
                    if is_timing_request(data) {
                        self.requests.fetch_add(1, Ordering::SeqCst);
                        if let Some(reply) = build_reply(data, NtpTimestamp::now_from_boottime()) {
                            let _ = self.sock.send_to(&reply, addr);
                        }
                    } else {
                        self.other.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => return,
            }
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn requests(&self) -> u64 {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn other(&self) -> u64 {
        self.other.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Prober: send seq 1..=3, sleeping 100ms between, each with a fresh
    /// boottime transmit timestamp. Port of `probe_receiver`.
    pub fn probe_receiver(&self, host: IpAddr, port: u16) -> std::io::Result<()> {
        for seq in 1u16..4 {
            let req = build_request(seq, NtpTimestamp::now_from_boottime());
            self.sock.send_to(&req, (host, port))?;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(())
    }
}
