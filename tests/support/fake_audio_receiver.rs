//! TEST ONLY: a fake AirPlay audio receiver on 127.0.0.1.
//!
//! Binds a control and a data UDP socket on ephemeral loopback ports and
//! records every datagram with its KERNEL receive timestamp (SO_TIMESTAMPNS),
//! converted to CLOCK_BOOTTIME seconds, so arrival order and arrival time are
//! facts measured by the kernel, not by which reader thread woke up first.
//! [`decrypt`] opens a sender packet the way a receiver must: ChaCha20-Poly1305
//! with the SETUP `shk`, AAD = packet[4..12], nonce = 00000000 ++ packet[1440..1448],
//! then undoes the ALAC escape framing.
//!
//! Nothing here talks to anything but 127.0.0.1.
#![allow(dead_code)]

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Rx {
    /// Kernel receive time, CLOCK_BOOTTIME seconds.
    pub at: f64,
    pub bytes: Vec<u8>,
}

pub struct FakeAirplayAudioReceiver {
    pub control_port: u16,
    pub data_port: u16,
    control: Arc<Mutex<Vec<Rx>>>,
    data: Arc<Mutex<Vec<Rx>>>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

fn clock_ns(id: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

/// CLOCK_BOOTTIME now, seconds.
pub fn boottime_secs() -> f64 {
    clock_ns(libc::CLOCK_BOOTTIME) as f64 / 1e9
}

fn setsockopt_int(fd: i32, opt: i32, v: i32) {
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &v as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    assert_eq!(r, 0, "setsockopt {opt}: {}", std::io::Error::last_os_error());
}

/// recvmsg with the SCM_TIMESTAMPNS control message; returns (bytes, realtime ns).
fn recv_stamped(sock: &UdpSocket, buf: &mut [u8]) -> std::io::Result<(usize, i128)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cbuf = [0u64; 16];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut stamp = None;
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_TIMESTAMPNS {
                let ts = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::timespec);
                stamp = Some(ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128);
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Ok((n as usize, stamp.expect("kernel receive timestamp (SO_TIMESTAMPNS)")))
}

impl FakeAirplayAudioReceiver {
    pub fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        // realtime -> boottime, sampled once (loopback only; µs-level error).
        let boot_minus_real = clock_ns(libc::CLOCK_BOOTTIME) - clock_ns(libc::CLOCK_REALTIME);
        let mut threads = vec![];
        let mut open = |store: Arc<Mutex<Vec<Rx>>>| -> u16 {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = sock.as_raw_fd();
            setsockopt_int(fd, libc::SO_TIMESTAMPNS, 1);
            setsockopt_int(fd, libc::SO_RCVBUF, 4 << 20);
            sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let port = sock.local_addr().unwrap().port();
            let stop = stop.clone();
            threads.push(std::thread::spawn(move || {
                let mut buf = vec![0u8; 4096];
                while !stop.load(Ordering::SeqCst) {
                    match recv_stamped(&sock, &mut buf) {
                        Ok((n, real_ns)) => store.lock().unwrap().push(Rx {
                            at: (real_ns + boot_minus_real) as f64 / 1e9,
                            bytes: buf[..n].to_vec(),
                        }),
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(e) => panic!("fake receiver recv: {e}"),
                    }
                }
            }));
            port
        };
        let control = Arc::new(Mutex::new(vec![]));
        let data = Arc::new(Mutex::new(vec![]));
        let control_port = open(control.clone());
        let data_port = open(data.clone());
        FakeAirplayAudioReceiver {
            control_port,
            data_port,
            control,
            data,
            stop,
            threads,
        }
    }

    /// Stop the reader threads (after a short drain) and return
    /// (control, data) datagrams in kernel-arrival order.
    pub fn finish(mut self) -> (Vec<Rx>, Vec<Rx>) {
        std::thread::sleep(Duration::from_millis(100));
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            t.join().unwrap();
        }
        let mut c = self.control.lock().unwrap().clone();
        let mut d = self.data.lock().unwrap().clone();
        c.sort_by(|a, b| a.at.partial_cmp(&b.at).unwrap());
        d.sort_by(|a, b| a.at.partial_cmp(&b.at).unwrap());
        (c, d)
    }
}

impl Drop for FakeAirplayAudioReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// A decrypted audio packet.
#[derive(Debug)]
pub struct Opened {
    pub seq: u16,
    pub rtp: u32,
    pub counter: u64,
    pub pcm: [u8; 1408],
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    Length(usize),
    Header,
    Auth,
    Alac,
}

/// Open one audio RTP packet as a receiver would.
pub fn decrypt(pkt: &[u8], shk: &[u8; 32]) -> Result<Opened, OpenError> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    if pkt.len() != 1448 {
        return Err(OpenError::Length(pkt.len()));
    }
    if pkt[0] != 0x80 || pkt[1] != 0x60 || pkt[8..12] != [0, 0, 0, 0] {
        return Err(OpenError::Header);
    }
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&pkt[1440..1448]);
    let mut body = pkt[12..12 + 1412].to_vec();
    let tag = &pkt[12 + 1412..1440];
    ChaCha20Poly1305::new(shk.into())
        .decrypt_in_place_detached((&nonce).into(), &pkt[4..12], &mut body, tag.into())
        .map_err(|_| OpenError::Auth)?;
    let alac: [u8; 1412] = body.try_into().unwrap();
    let pcm = airplay_rs::audio::alac_escape_decode(&alac).ok_or(OpenError::Alac)?;
    Ok(Opened {
        seq: u16::from_be_bytes([pkt[2], pkt[3]]),
        rtp: u32::from_be_bytes(pkt[4..8].try_into().unwrap()),
        counter: u64::from_le_bytes(pkt[1440..1448].try_into().unwrap()),
        pcm,
    })
}

/// A parsed control-port sync packet.
#[derive(Clone, Copy, Debug)]
pub struct Sync {
    pub first: bool,
    pub rtp_now: u32,
    pub latency_samples: u32,
    /// The packet's NTP time as CLOCK_BOOTTIME seconds.
    pub boot: f64,
    pub at: f64,
}

pub fn parse_sync(rx: &Rx) -> Option<Sync> {
    let b = &rx.bytes;
    if b.len() != 20 || (b[0] != 0x90 && b[0] != 0x80) || b[1] != 0xD4 || b[2..4] != [0, 4] {
        return None;
    }
    let rtp_minus_lat = u32::from_be_bytes(b[4..8].try_into().unwrap());
    let ntp = u64::from_be_bytes(b[8..16].try_into().unwrap());
    let rtp_now = u32::from_be_bytes(b[16..20].try_into().unwrap());
    Some(Sync {
        first: b[0] == 0x90,
        rtp_now,
        latency_samples: rtp_now.wrapping_sub(rtp_minus_lat),
        boot: ((ntp >> 32) - 2_208_988_800) as f64 + (ntp & 0xFFFF_FFFF) as f64 / 4294967296.0,
        at: rx.at,
    })
}

impl Sync {
    /// When the receiver must play RTP `rtp` under this mapping (boot secs).
    pub fn playout(&self, rtp: u32) -> f64 {
        let d = rtp.wrapping_sub(self.rtp_now) as i32 as f64;
        self.boot + (d + self.latency_samples as f64) / 44100.0
    }
}
