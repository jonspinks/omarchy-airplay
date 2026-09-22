#!/usr/bin/env python3
# Generator for tests/vectors/audio-packets.json (airplay-rs Milestone 4, audio).
#
# Runs the REAL probe code (probe.py, from the omarchy-airplay-probe repo) in
# that repo's venv. Point AIRPLAY_PROBE at your checkout:
#   AIRPLAY_PROBE=~/src/omarchy-airplay-probe \
#     $AIRPLAY_PROBE/.venv/bin/python tests/vectors/gen_audio_vectors.py
# It makes NO network access: socket.socket and socket.create_connection are
# replaced before probe is imported, and every UDP/TCP endpoint is a fake that
# records bytes. Output is deterministic (fixed key, fixed RNG seed, fake clock);
# re-running it must reproduce audio-packets.json byte-for-byte.
"""Generate golden vectors for airplay-rs Milestone 4 (audio) by RUNNING probe.py code.
No network: socket constructors are disabled before probe is imported; all I/O goes to fakes."""
import hashlib, json, os, plistlib, socket, sys, time
socket.socket = None  # any attempt to open a real socket crashes
socket.create_connection = None
sys.path.insert(0, os.environ.get("AIRPLAY_PROBE", "../omarchy-airplay-probe"))
import numpy as np
import probe

KEY = bytes(range(0x40, 0x60))  # same shk as audio_setup_plist vector
LAT_MS = 300
probe.AUDIO_LATENCY_SAMPLES = int(LAT_MS / 1000 * probe.AUDIO_RATE)

def pcm_formula(frame):
    n = np.arange(frame * 352, frame * 352 + 352, dtype=np.int64)
    L = ((n * 7919) & 0xFFFF).astype(np.uint16).view(np.int16)
    R = ((n * 104729 + 12345) & 0xFFFF).astype(np.uint16).view(np.int16)
    return np.stack([L, R], axis=1).astype("<i2").tobytes()

# ---------------------------------------------------------------- ALAC
alac = []
rng = np.random.default_rng(20260919)
cases = {
    "zeros": bytes(1408),
    "max_min": np.tile(np.array([32767, -32768], dtype="<i2"), 352).tobytes(),
    "minus_one": np.full(704, -1, dtype="<i2").tobytes(),
    "ramp": np.arange(704, dtype=np.int16).astype("<i2").tobytes(),
    "formula_frame0": pcm_formula(0),
    "random_seed20260919": rng.integers(-32768, 32768, 704, dtype=np.int64).astype("<i2").tobytes(),
}
for name, pcm in cases.items():
    out = probe.alac_uncompressed_frame(pcm)
    assert len(out) == 1412
    alac.append({"name": name, "pcm_s16le_hex": pcm.hex(), "alac_hex": out.hex()})

# ---------------------------------------------------------------- fake clock
class Clock:
    t = 5000.0
clk = Clock()
time.monotonic = lambda: clk.t
def fake_sleep(d):
    if d > 0: clk.t += d
time.sleep = fake_sleep
BOOT_OFFSET = 100000.0  # CLOCK_BOOTTIME = monotonic + offset
real_cg = time.clock_gettime
time.clock_gettime = lambda cid: clk.t + BOOT_OFFSET

class FakeUdp:
    def __init__(self, name, trace): self.name, self.trace = name, trace
    def setblocking(self, b): pass
    def sendto(self, data, addr):
        self.trace.append({"sock": self.name, "mono": clk.t, "addr_port": addr[1], "hex": data.hex()})
    def recv(self, n): raise BlockingIOError

def drive(mode, n_frames, seq0, rtp0, stall_at=None, stall_s=0.0, frames_override=True):
    trace = []
    bits = iter([seq0, rtp0])
    probe.random.getrandbits = lambda k: next(bits)
    s = probe.AudioSender("192.0.2.1", 50002, 50001, FakeUdp("data", trace), FakeUdp("ctrl", trace), KEY, mode)
    s.tone_level = 0.3
    if frames_override:
        def frames():
            for i in range(n_frames):
                clk.t += 352 / 44100  # capture pacing (parec delivers one frame per period)
                if i == stall_at: clk.t += stall_s
                yield pcm_formula(i)
            s.stop.set()
        s._frames = frames
    else:
        orig = s._frames
        def frames():
            for i, f in enumerate(orig()):
                if i >= n_frames: s.stop.set(); return
                yield f
        s._frames = frames
    s.run()
    return s, trace

def summarize(trace, full_frames):
    out, frame = [], 0
    for e in trace:
        d = bytes.fromhex(e["hex"])
        if e["sock"] == "ctrl":
            out.append({"kind": "sync", "mono": e["mono"], "boottime": e["mono"] + BOOT_OFFSET,
                        "first": d[0] == 0x90, "hex": e["hex"],
                        "rtp_minus_latency": int.from_bytes(d[4:8], "big"),
                        "ntp": int.from_bytes(d[8:16], "big"), "rtp_now": int.from_bytes(d[16:20], "big"),
                        "dest_port": e["addr_port"]})
        else:
            rec = {"kind": "data", "frame": frame, "mono": e["mono"], "len": len(d),
                   "header_hex": d[:12].hex(), "seq": int.from_bytes(d[2:4], "big"),
                   "rtp": int.from_bytes(d[4:8], "big"), "nonce": int.from_bytes(d[-8:], "little"),
                   "sha256": hashlib.sha256(d).hexdigest(), "dest_port": e["addr_port"]}
            if frame in full_frames: rec["hex"] = e["hex"]
            out.append(rec); frame += 1
    return out

# sequence A: system-style pacing, seq/rtp near wrap, a 400 ms stall at frame 200 -> re-anchor
clk.t = 5000.0
sA, tA = drive("system", 320, 0xFFFE, 0xFFFFFE00, stall_at=200, stall_s=0.4)
seqA = summarize(tA, {0, 1, 2, 199, 200, 319})
# sequence B: a stall of exactly 0.2 s (below the 0.25 threshold) -> must NOT re-anchor
clk.t = 7000.0
sB, tB = drive("system", 40, 100, 1000, stall_at=20, stall_s=0.2)
seqB = summarize(tB, {0})
# sequence C: real tone generator (probe._frames tone path, wall-clock paced by run())
clk.t = 9000.0
sC, tC = drive("tone", 8, 0, 0, frames_override=False)
seqC = summarize(tC, {0, 1, 7})

# direct _sync vectors (real AudioSender._sync, boot clock injected)
syncs = []
for first, rtp_now, boot in [(True, 0, 1000.0), (False, 0, 1000.5), (True, 13229, 123456.25),
                             (True, 13230, 123456.25), (False, 0xFFFFFFFF, 99999.999)]:
    tr = []
    s = probe.AudioSender("192.0.2.1", 1, 2, FakeUdp("data", tr), FakeUdp("ctrl", tr), KEY, "system")
    clk.t = boot - BOOT_OFFSET
    s._sync(rtp_now, first)
    syncs.append({"first": first, "rtp_now": rtp_now, "latency_samples": probe.AUDIO_LATENCY_SAMPLES,
                  "boottime": boot, "ntp": probe.boot_ntp_timestamp(), "hex": tr[0]["hex"]})
time.clock_gettime = real_cg

# ---------------------------------------------------------------- RTSP volume requests (real _request)
class FakeTcp:
    def __init__(self, reply): self.sent, self.reply = b"", reply
    def settimeout(self, t): pass
    def sendall(self, d): self.sent += d
    def recv(self, n):
        r, self.reply = self.reply[:n], self.reply[n:]; return r
def rtsp_exchange(method, uri, headers, body, ctype, reply):
    c = object.__new__(probe.RtspConnection)
    c.host, c.port, c.label, c.cseq, c.cipher, c._buf = "192.0.2.1", 7000, "control", 0, None, b""
    c.default_headers = {}
    import threading; c.lock = threading.Lock()
    c.sock = FakeTcp(reply)
    status, rh, rb = c.request(method, uri, headers, body, ctype, quiet=True)
    return {"method": method, "uri": uri, "request_hex": c.sock.sent.hex(),
            "request_text": c.sock.sent.decode(), "reply_hex": reply.hex(), "status": status,
            "reply_body": rb.decode()}
uri = "rtsp://192.0.2.1:7000/5124095576030430"
rtsp = [
    rtsp_exchange("GET_PARAMETER", uri, {}, b"volume\r\n", "text/parameters",
                  b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 20\r\n\r\nvolume: -20.400000\r\n"),
]
for db in (-144.0, -30.0, -24.9, -15.0, -20.0):
    rtsp.append(rtsp_exchange("SET_PARAMETER", uri, {}, f"volume: {db:.6f}\r\n".encode(), "text/parameters",
                              b"RTSP/1.0 500 Internal Server Error\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n"))

# ---------------------------------------------------------------- dvlc event (SYNTHETIC body)
dvlc_dict = {"volume": 0.18, "isMuted": False, "type": "sendMediaRemoteCommand", "value": "dvlc"}
dvlc_bplist = plistlib.dumps(dvlc_dict, fmt=plistlib.FMT_BINARY)

doc = {
    "_note": "Golden vectors for airplay-rs audio (Milestone 4). Generated by RUNNING probe.py code in its venv: "
             "alac_uncompressed_frame, AudioSender.run/_sync (fake UDP sockets, fake monotonic/sleep/CLOCK_BOOTTIME, "
             "random.getrandbits injected), boot_ntp_timestamp, RtspConnection._request (fake TCP). "
             "socket.socket was disabled; nothing touched the network. All hex lowercase. Do not hand-edit.",
    "inputs": {"shk_hex": KEY.hex(), "latency_ms": LAT_MS, "latency_samples": probe.AUDIO_LATENCY_SAMPLES,
               "alac_spf": probe.ALAC_SPF, "audio_rate": probe.AUDIO_RATE, "boottime_minus_monotonic": BOOT_OFFSET,
               "pcm_formula": "n = frame*352 + j; L = i16((n*7919) mod 65536); R = i16((n*104729+12345) mod 65536); interleaved s16le L,R",
               "capture_pacing": "fake monotonic advances 352/44100 s before each frame is yielded (plus stall_s at stall_at)",
               "receiver_data_port": 50002, "receiver_control_port": 50001},
    "alac_frames": alac,
    "sync_packets": syncs,
    "sequence_stall_reanchor": {"seq0": 0xFFFE, "rtp0": 0xFFFFFE00, "frames": 320, "stall_at": 200, "stall_s": 0.4,
                                "stats": sA.stats, "events": seqA},
    "sequence_small_gap_no_reanchor": {"seq0": 100, "rtp0": 1000, "frames": 40, "stall_at": 20, "stall_s": 0.2,
                                       "stats": sB.stats, "events": seqB},
    "sequence_tone": {"seq0": 0, "rtp0": 0, "frames": 8, "tone_level": 0.3, "stats": sC.stats, "events": seqC},
    "rtsp_volume": rtsp,
    "dvlc_event": {"_synthetic": "body built with plistlib from the decoded dict logged in "
                                 "runs/20260915-163229-ntp-transient/log.txt; NOT the TV's raw bytes (float width/key order unverified)",
                   "dict": dvlc_dict, "binary_plist_hex": dvlc_bplist.hex()},
}
import os
json.dump(doc, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "audio-packets.json"), "w"), indent=1)
print("written")
