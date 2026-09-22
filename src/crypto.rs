//! hap-crypto: HKDF-SHA512 key derivation, nonces, and the HAP framed transport
//! cipher. Ported from probe.hkdf / probe.nonce_counter / probe.nonce_label /
//! probe.HapCipher (probe.py lines 119-192).

pub const HAP_FRAME_SIZE: usize = 1024;
pub const HAP_TAG_LEN: usize = 16;

/// HKDF-SHA512, 32-byte output. `salt`/`info` are the ASCII label strings
/// exactly as passed in probe.py (NOT length-prefixed). Ports probe.hkdf.
pub fn hkdf_sha512_32(ikm: &[u8], salt: &str, info: &str) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha512>::new(Some(salt.as_bytes()), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 <= 255*64 output length");
    okm
}

/// 12-byte nonce: 4 zero bytes ++ LE64(counter). Ports probe.nonce_counter.
pub fn nonce_counter(n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&n.to_le_bytes());
    out
}

/// 12-byte nonce: 4 zero bytes ++ ASCII(label). label must be <= 8 bytes.
/// Ports probe.nonce_label.
pub fn nonce_label(label: &str) -> [u8; 12] {
    let mut out = [0u8; 12];
    let b = label.as_bytes();
    out[4..4 + b.len()].copy_from_slice(b);
    out
}

/// Control channel keys: salt `"Control-Salt"`, info Write/Read. Returns
/// (write_key, read_key). IKM = pair-verify shared secret.
pub fn control_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    (
        hkdf_sha512_32(shared, "Control-Salt", "Control-Write-Encryption-Key"),
        hkdf_sha512_32(shared, "Control-Salt", "Control-Read-Encryption-Key"),
    )
}

/// Events channel keys: the direction is deliberately reversed relative to
/// control (probe.py line 483-486). Returns (write_key, read_key).
pub fn events_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    (
        hkdf_sha512_32(shared, "Events-Salt", "Events-Read-Encryption-Key"),
        hkdf_sha512_32(shared, "Events-Salt", "Events-Write-Encryption-Key"),
    )
}

/// HAP framed transport cipher (ChaCha20-Poly1305, 1024-byte frames, 2-byte LE
/// length AAD, LE64 counter nonces). Ports probe.HapCipher.
pub struct HapCipher {
    write_key: [u8; 32],
    read_key: [u8; 32],
    write_n: u64,
    read_n: u64,
}

impl HapCipher {
    pub fn new(write_key: [u8; 32], read_key: [u8; 32]) -> Self {
        HapCipher {
            write_key,
            read_key,
            write_n: 0,
            read_n: 0,
        }
    }

    /// Split into <=1024B frames; each -> aad(2 LE len) ++ ct ++ tag(16).
    /// Advances the write counter one per frame. Concatenated result.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::ChaCha20Poly1305;
        let cipher = ChaCha20Poly1305::new((&self.write_key).into());
        let mut out = Vec::new();
        // Split into <=1024B frames (last may be shorter). An empty plaintext
        // yields no frames, matching Python's chunked range.
        let mut i = 0usize;
        while i < plaintext.len() {
            let end = (i + HAP_FRAME_SIZE).min(plaintext.len());
            let frame = &plaintext[i..end];
            let aad = (frame.len() as u16).to_le_bytes();
            let nonce = nonce_counter(self.write_n);
            let ct = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: frame,
                        aad: &aad,
                    },
                )
                .expect("ChaCha20Poly1305 seal");
            out.extend_from_slice(&aad);
            out.extend_from_slice(&ct);
            self.write_n += 1;
            i += HAP_FRAME_SIZE;
        }
        out
    }

    /// Decrypt one frame: `aad` is the 2 length bytes, `sealed` is ct++tag.
    /// Advances the read counter. Errors on auth failure.
    pub fn open(&mut self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::ChaCha20Poly1305;
        if sealed.len() < HAP_TAG_LEN {
            return Err(CryptoError::ShortFrame);
        }
        let cipher = ChaCha20Poly1305::new((&self.read_key).into());
        let nonce = nonce_counter(self.read_n);
        let pt = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: sealed,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Auth)?;
        self.read_n += 1;
        Ok(pt)
    }
}

#[derive(Debug)]
pub enum CryptoError {
    Auth,
    ShortFrame,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Auth => write!(f, "AEAD authentication failed"),
            CryptoError::ShortFrame => write!(f, "frame shorter than the 16-byte tag"),
        }
    }
}

impl std::error::Error for CryptoError {}
