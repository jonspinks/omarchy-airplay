//! HAP TLV8 encode/decode, ported byte-for-byte from probe.tlv_encode /
//! probe.tlv_decode (probe.py lines 93-116).

use indexmap::IndexMap;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlvType {
    Method = 0x00,
    Identifier = 0x01,
    Salt = 0x02,
    PublicKey = 0x03,
    Proof = 0x04,
    EncryptedData = 0x05,
    State = 0x06, // a.k.a. SeqNo
    Error = 0x07,
    RetryDelay = 0x08,
    Signature = 0x0A,
    Name = 0x11,
    Acl = 0x12,
    Flags = 0x13,
}

impl TlvType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<TlvType> {
        Some(match v {
            0x00 => TlvType::Method,
            0x01 => TlvType::Identifier,
            0x02 => TlvType::Salt,
            0x03 => TlvType::PublicKey,
            0x04 => TlvType::Proof,
            0x05 => TlvType::EncryptedData,
            0x06 => TlvType::State,
            0x07 => TlvType::Error,
            0x08 => TlvType::RetryDelay,
            0x0A => TlvType::Signature,
            0x11 => TlvType::Name,
            0x12 => TlvType::Acl,
            0x13 => TlvType::Flags,
            _ => return None,
        })
    }
}

/// Value carried inside a Flags TLV (probe.py line 80). NOT a type number.
pub const FLAG_TRANSIENT: u8 = 0x10;

/// Pre-baked OPACK dict `{"com.apple.ScreenCapture": true}` carried verbatim as
/// the ACL (0x12) value (probe.py line 82).
pub const SCREEN_CAPTURE_ACL: &[u8] = b"\xe1\x57com.apple.ScreenCapture\x01";

/// Encode an ordered list of `(tag, value)`. Empty value -> `[tag,0]`; values
/// are chunked at 255 with NO trailing zero-length separator on exact
/// multiples. Never fails.
pub fn tlv_encode(items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(tag, value) in items {
        // Empty-value special case: emit a single zero-length entry.
        if value.is_empty() {
            out.push(tag);
            out.push(0);
        }
        // Then chunk at 255 with NO trailing zero-length separator on exact
        // multiples (an empty value produces nothing here).
        let mut i = 0usize;
        while i < value.len() {
            let end = (i + 255).min(value.len());
            let chunk = &value[i..end];
            out.push(tag);
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
            i += 255;
        }
    }
    out
}

/// Ergonomic typed wrapper delegating to [`tlv_encode`].
pub fn encode(items: &[(TlvType, &[u8])]) -> Vec<u8> {
    let raw: Vec<(u8, &[u8])> = items.iter().map(|(t, v)| (t.as_u8(), *v)).collect();
    tlv_encode(&raw)
}

/// Decode: consecutive same-tag entries concatenate; a tag repeated after an
/// intervening different tag overwrites. Trailing/overrunning partial entry is
/// ignored. Preserves first-appearance order.
pub fn tlv_decode(data: &[u8]) -> TlvMap {
    let mut result: IndexMap<u8, Vec<u8>> = IndexMap::new();
    let mut last: Option<u8> = None;
    let mut i = 0usize;
    while i + 2 <= data.len() {
        let tag = data[i];
        let length = data[i + 1] as usize;
        // Python slice semantics: short value if fewer than `length` remain.
        let end = (i + 2 + length).min(data.len());
        let value = &data[i + 2..end];
        if last == Some(tag) && result.contains_key(&tag) {
            result.get_mut(&tag).unwrap().extend_from_slice(value);
        } else {
            result.insert(tag, value.to_vec());
        }
        last = Some(tag);
        i += 2 + length;
    }
    TlvMap(result)
}

/// Insertion-ordered map keyed by raw u8 tag.
#[derive(Debug, Clone, Default)]
pub struct TlvMap(IndexMap<u8, Vec<u8>>);

impl TlvMap {
    pub fn new() -> Self {
        TlvMap(IndexMap::new())
    }

    pub fn get(&self, tag: u8) -> Option<&[u8]> {
        self.0.get(&tag).map(|v| v.as_slice())
    }

    pub fn get_type(&self, t: TlvType) -> Option<&[u8]> {
        self.get(t.as_u8())
    }

    pub fn contains(&self, tag: u8) -> bool {
        self.0.contains_key(&tag)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u8, &[u8])> {
        self.0.iter().map(|(k, v)| (*k, v.as_slice()))
    }
}

/// HAP error-code lookup (probe.py line 74-77).
pub fn hap_error_str(code: u8) -> &'static str {
    match code {
        1 => "Unknown",
        2 => "Authentication (wrong PIN?)",
        3 => "BackOff",
        4 => "MaxPeers",
        5 => "MaxTries",
        6 => "Unavailable",
        7 => "Busy",
        _ => "unknown",
    }
}
