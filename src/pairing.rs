//! pairing: HAP Pair-Setup (transient + PIN) and Pair-Verify, plus the SRP-6a
//! exchange and transport key derivation. Ported from probe.pair_transient /
//! probe.pair_setup_pin / probe.pair_verify / probe.srp_exchange (probe.py).

use crate::crypto::CryptoError;
use num_bigint_dig::BigUint;
use sha2::{Digest, Sha512};

// --------------------------------------------------------------------------- errors

#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("HAP error {0}: {1}")]
    Hap(u8, &'static str),
    #[error("unexpected HTTP status {0}")]
    Status(u16),
    #[error("receiver SRP proof (M2) did not verify")]
    SrpProof,
    #[error("SRP: server public key B is zero mod N")]
    SrpBadServerPublic,
    #[error("receiver signature invalid (stale credentials?)")]
    BadSignature,
    #[error("missing TLV tag 0x{0:02x}")]
    MissingTag(u8),
    /// No code was supplied, so no proof was sent. Raised by a fallible PIN
    /// supplier ([`pair_setup_pin_with`]) when the human never typed, closed
    /// the input, or cancelled.
    ///
    /// It matters that this is an error and not an empty PIN: an empty PIN is
    /// a WRONG PIN, and a wrong PIN spends one of the receiver's small number
    /// of attempts before it starts answering BackOff and MaxTries. Giving up
    /// must cost nothing.
    #[error("no AirPlay code was entered ({0})")]
    NoCode(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Transport(#[from] std::io::Error),
}

// --------------------------------------------------------------------------- tlv8

pub mod tlv8 {
    pub const METHOD: u8 = 0x00;
    pub const IDENTIFIER: u8 = 0x01;
    pub const SALT: u8 = 0x02;
    pub const PUBLIC_KEY: u8 = 0x03;
    pub const PROOF: u8 = 0x04;
    pub const ENCRYPTED: u8 = 0x05;
    pub const STATE: u8 = 0x06;
    pub const ERROR: u8 = 0x07;
    pub const SIGNATURE: u8 = 0x0A;
    pub const NAME: u8 = 0x11;
    pub const ACL: u8 = 0x12;
    pub const FLAGS: u8 = 0x13;

    /// Ordered encode; delegates to the crate's byte-faithful [`crate::tlv8`].
    pub fn encode(items: &[(u8, &[u8])]) -> Vec<u8> {
        crate::tlv8::tlv_encode(items)
    }

    /// Decode into a plain HashMap (consecutive same-tag records concatenate;
    /// last non-consecutive tag wins).
    pub fn decode(data: &[u8]) -> std::collections::HashMap<u8, Vec<u8>> {
        crate::tlv8::tlv_decode(data)
            .iter()
            .map(|(tag, val)| (tag, val.to_vec()))
            .collect()
    }
}

// --------------------------------------------------------------------------- hkdf / nonces

/// HKDF-SHA512, 32-byte output; salt & info are the ASCII label strings.
pub fn hkdf(secret: &[u8], salt: &str, info: &str) -> [u8; 32] {
    crate::crypto::hkdf_sha512_32(secret, salt, info)
}

pub fn nonce_label(label: &str) -> [u8; 12] {
    crate::crypto::nonce_label(label)
}

pub fn nonce_counter(n: u64) -> [u8; 12] {
    crate::crypto::nonce_counter(n)
}

pub const HKP_PIN: u8 = 3;
pub const HKP_TRANSIENT: u8 = 4;
pub const HKP_SCREEN_CAPTURE: u8 = 5;
pub const FLAG_TRANSIENT: u8 = 0x10;
pub const TRANSIENT_PIN: &str = "3939";
pub const SCREEN_CAPTURE_ACL: &[u8] = b"\xe1\x57com.apple.ScreenCapture\x01";

/// OPACK small-string (probe.py opack_small_string, line 132): `0x40+len` prefix
/// then UTF-8, length capped at 0x20.
fn opack_small_string(s: &str) -> Vec<u8> {
    let mut raw = s.as_bytes().to_vec();
    if raw.len() > 0x20 {
        raw.truncate(0x20);
    }
    let mut out = Vec::with_capacity(raw.len() + 1);
    out.push(0x40 + raw.len() as u8);
    out.extend_from_slice(&raw);
    out
}

/// NAME TLV value: `0xe1 0x44 "name"` ++ opack_small_string(sender_name).
pub fn opack_name_field(sender_name: &str) -> Vec<u8> {
    let mut out = b"\xe1\x44name".to_vec();
    out.extend_from_slice(&opack_small_string(sender_name));
    out
}

// --------------------------------------------------------------------------- SRP-6a

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RFC 5054 3072-bit modulus (`constants.PRIME_3072`).
const PRIME_3072_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

/// Byte length of N (3072 bits = 384 bytes); PAD width for k and u.
const N_LEN: usize = 384;

fn group_n() -> BigUint {
    BigUint::parse_bytes(PRIME_3072_HEX.as_bytes(), 16).expect("valid prime hex")
}

/// Left-pad a BigUint's big-endian bytes to exactly `N_LEN` bytes. Saturating:
/// a value with more than `N_LEN` bytes (only reachable for an un-reduced input)
/// keeps its low `N_LEN` bytes instead of underflowing the padding width and
/// panicking. Callers reduce modulo N first, so in practice `raw.len() <= N_LEN`.
fn pad_be(x: &BigUint) -> Vec<u8> {
    let raw = x.to_bytes_be();
    if raw.len() >= N_LEN {
        return raw[raw.len() - N_LEN..].to_vec();
    }
    let mut out = vec![0u8; N_LEN - raw.len()];
    out.extend_from_slice(&raw);
    out
}

/// Minimal big-endian bytes of a BigUint (0 -> single 0x00), matching Python's
/// `int.to_bytes(minimal)` behaviour used for A, B, S, N in K/M1.
fn min_be(x: &BigUint) -> Vec<u8> {
    let raw = x.to_bytes_be();
    if raw.is_empty() {
        vec![0]
    } else {
        raw
    }
}

/// SRP-6a client: 3072-bit group, SHA-512, username "Pair-Setup".
pub struct SrpClient {
    pin: String,
    a: BigUint,
    a_pub: BigUint,
    k: Option<[u8; 64]>,  // session key K = SHA512(S)
    m1: Option<[u8; 64]>, // client proof
    a_bytes: Vec<u8>,     // A on the wire (minimal BE)
}

impl SrpClient {
    /// `a` lets tests pin the private exponent; production passes None (random 32 B).
    pub fn new(pin: &str, a: Option<[u8; 32]>) -> Self {
        let a_bytes = match a {
            Some(fixed) => fixed.to_vec(),
            None => {
                use rand::RngCore;
                let mut buf = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut buf);
                buf.to_vec()
            }
        };
        let a = BigUint::from_bytes_be(&a_bytes);
        let n = group_n();
        let g = BigUint::from(5u32);
        let a_pub = g.modpow(&a, &n); // A = g^a mod N
        let wire = min_be(&a_pub);
        SrpClient {
            pin: pin.to_string(),
            a,
            a_pub,
            k: None,
            m1: None,
            a_bytes: wire,
        }
    }

    /// A, big-endian (minimal, as sent as PUBLIC_KEY in M3).
    pub fn public_a(&self) -> Vec<u8> {
        self.a_bytes.clone()
    }

    /// Consume M2 (salt, B); compute K, M1. Returns (A, M1).
    pub fn process(
        &mut self,
        salt: &[u8],
        server_public_b: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PairError> {
        let n = group_n();
        let g = BigUint::from(5u32);
        // Reduce B modulo N before use so pad_be always receives a value < N
        // (finding 9). For a well-behaved server B is already < N, so this is
        // identity and the M1 hash bytes are unchanged.
        let b = BigUint::from_bytes_be(server_public_b) % &n;
        // srptools rejects B ≡ 0 (mod N): a zero shared base is unusable and a
        // sign the server public is malformed/hostile (finding 8).
        if b == BigUint::from(0u32) {
            return Err(PairError::SrpBadServerPublic);
        }

        // k = SHA512(PAD(N) || PAD(g))  (g padded to N_LEN)
        let k = BigUint::from_bytes_be(&sha512(&[&pad_be(&n), &pad_be(&g)]));

        // x = SHA512(salt || SHA512(user ":" pin))
        let user = b"Pair-Setup";
        let inner = sha512(&[user, b":", self.pin.as_bytes()]);
        let x = BigUint::from_bytes_be(&sha512(&[salt, &inner]));

        // u = SHA512(PAD(A) || PAD(B))
        let u = BigUint::from_bytes_be(&sha512(&[&pad_be(&self.a_pub), &pad_be(&b)]));

        // S = (B - k*g^x)^(a + u*x) mod N
        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        // base = (B - kgx) mod N, kept non-negative
        let base = ((&b % &n) + &n - kgx) % &n;
        let exp = &self.a + &u * &x;
        let s = base.modpow(&exp, &n);

        // K = SHA512(S)  (S minimal BE, NOT padded)
        let big_k = sha512(&[&min_be(&s)]);

        // M1 = SHA512( (SHA512(N) XOR SHA512(g)) || SHA512(user) || salt || A || B || K )
        let hn = sha512(&[&min_be(&n)]);
        let hg = sha512(&[&[5u8]]); // g hashed as the single minimal byte 0x05
        let hxor: Vec<u8> = hn.iter().zip(hg.iter()).map(|(a, b)| a ^ b).collect();
        let huser = sha512(&[user]);
        let m1 = sha512(&[
            &hxor,
            &huser,
            salt,
            &min_be(&self.a_pub),
            &min_be(&b),
            &big_k,
        ]);

        self.k = Some(big_k);
        self.m1 = Some(m1);
        Ok((self.a_bytes.clone(), m1.to_vec()))
    }

    /// K (64 B).
    pub fn session_key(&self) -> &[u8] {
        self.k.as_ref().expect("process() must run first")
    }

    /// H(A||M1||K).
    pub fn verify_server_proof(&self, m2: &[u8]) -> bool {
        let (k, m1) = match (self.k.as_ref(), self.m1.as_ref()) {
            (Some(k), Some(m1)) => (k, m1),
            _ => return false,
        };
        let expected = sha512(&[&min_be(&self.a_pub), m1, k]);
        expected.as_slice() == m2
    }
}

// --------------------------------------------------------------------------- credentials

/// Long-term pairing credentials for one receiver: what PIN pair-setup earns
/// and what pair-verify spends. `ltsk` is a SECRET (the controller's Ed25519
/// private key, hex) — see the redacting [`std::fmt::Debug`] impl below, and
/// never put this struct, or any of its fields but `hkp`, in a message.
///
/// The on-disk shape is exactly probe.py's (`hkp`, `pairing_id`, `ltsk`,
/// `tv_id`, `tv_ltpk`), so a file written by either side is readable by the
/// other. `host` is an ADDITION, defaulted and omitted when absent, so files
/// written before it existed still load.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Credentials {
    pub hkp: u8,
    pub pairing_id: String,
    pub ltsk: String,
    pub tv_id: String,
    pub tv_ltpk: String,
    /// The receiver these belong to, as the store keyed them. Informational:
    /// the file name is still the key, and this is what lets `pair --list`
    /// print a host whose name does not survive being made filesystem-safe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Redacted on purpose: `ltsk` is a private key and this type ends up in error
/// paths and log lines. There is no way to print the secret through `{:?}`.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("hkp", &self.hkp)
            .field("host", &self.host)
            .field("pairing_id", &"<redacted>")
            .field("ltsk", &"<redacted>")
            .field("tv_id", &"<redacted>")
            .field("tv_ltpk", &"<redacted>")
            .finish()
    }
}

impl Credentials {
    /// Structural check, run on every load so a truncated, hand-edited or
    /// half-written file degrades to "not paired" instead of failing later
    /// inside pair-verify with a crypto error nobody can act on.
    ///
    /// Returns the reason as a short static string, which is safe to print:
    /// it names the field, never its contents.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(self.hkp, HKP_PIN | HKP_TRANSIENT | HKP_SCREEN_CAPTURE) {
            return Err("hkp is not 3, 4 or 5");
        }
        if self.pairing_id.is_empty() {
            return Err("pairing_id is empty");
        }
        if self.tv_id.is_empty() {
            return Err("tv_id is empty");
        }
        let ltsk = hex::decode(&self.ltsk).map_err(|_| "ltsk is not hex")?;
        if ltsk.len() != 32 {
            return Err("ltsk is not 32 bytes");
        }
        let ltpk = hex::decode(&self.tv_ltpk).map_err(|_| "tv_ltpk is not hex")?;
        let ltpk: [u8; 32] = ltpk.as_slice().try_into().map_err(|_| "tv_ltpk is not 32 bytes")?;
        // A public key that is not on the curve can never verify anything, so
        // it is a dead credential however well-formed the file is.
        ed25519_dalek::VerifyingKey::from_bytes(&ltpk).map_err(|_| "tv_ltpk is not a valid key")?;
        Ok(())
    }
}

/// Does this failure mean "the receiver wants the code from its screen"?
///
/// The distinction the panel needs: a receiver with an AirPlay code set
/// refuses the transient PIN (`3939`) rather than the connection, so the
/// failure arrives as an SRP/authentication rejection, not as a network error.
/// Two shapes are known to mean it and one is assumed:
///
/// * `Hap(2, …)` — kTLVError_Authentication, the receiver rejecting our proof.
/// * `SrpProof` — the receiver's own M4 proof does not match, i.e. it computed
///   the session key from a different PIN than the transient one.
/// * `Status(470)` — "Connection Authorization Required", Apple's spelling of
///   the same refusal at the HTTP layer. **Unproven here**: no receiver on this
///   network has answered 470, so it is included on the strength of the
///   protocol, not of a capture.
///
/// Everything else — a closed connection, a timeout, a malformed reply, MaxTries
/// or BackOff — is NOT this, because telling the user to fetch a code from the
/// TV when the TV is unreachable is worse than saying nothing.
pub fn code_required(err: &PairError) -> bool {
    matches!(err, PairError::Hap(2, _) | PairError::SrpProof | PairError::Status(470))
}

// --------------------------------------------------------------------------- flows

/// Transport used by the flows (impl over the RTSP connection).
pub trait PairTransport {
    fn post(&mut self, uri: &str, hkp: u8, body: &[u8]) -> Result<(u16, Vec<u8>), PairError>;
}

fn tlv_err(map: &std::collections::HashMap<u8, Vec<u8>>) -> Option<PairError> {
    map.get(&tlv8::ERROR).and_then(|v| v.first()).map(|&code| {
        PairError::Hap(code, crate::tlv8::hap_error_str(code))
    })
}

fn require(
    map: &std::collections::HashMap<u8, Vec<u8>>,
    tag: u8,
) -> Result<&Vec<u8>, PairError> {
    map.get(&tag).ok_or(PairError::MissingTag(tag))
}

/// Shared SRP portion of pair-setup (M1..M4). Returns the 64-byte session key K.
fn srp_exchange<T: PairTransport>(
    t: &mut T,
    hkp: u8,
    m1_items: &[(u8, &[u8])],
    pin_supplier: impl FnOnce() -> Result<String, PairError>,
) -> Result<Vec<u8>, PairError> {
    // M1
    let (status, body) = t.post("/pair-setup", hkp, &tlv8::encode(m1_items))?;
    if status != 200 {
        return Err(PairError::Status(status));
    }
    let m2 = tlv8::decode(&body);
    if let Some(e) = tlv_err(&m2) {
        return Err(e);
    }
    let salt = require(&m2, tlv8::SALT)?.clone();
    let server_public = require(&m2, tlv8::PUBLIC_KEY)?.clone();

    // The one place a human can be in the loop. Asking here, AFTER M2, is what
    // the probe does, and it is also what keeps the whole exchange on one
    // connection: the receiver's pair-setup state — including which code it is
    // expecting — lives on this socket and cannot be resumed by a later
    // process. A supplier that gives up returns an error and no M3 is sent.
    let pin = pin_supplier()?;
    let mut srp = SrpClient::new(&pin, None);
    let (a_pub, m1_proof) = srp.process(&salt, &server_public)?;

    // M3
    let (status, body) = t.post(
        "/pair-setup",
        hkp,
        &tlv8::encode(&[
            (tlv8::STATE, &[0x03]),
            (tlv8::PUBLIC_KEY, &a_pub),
            (tlv8::PROOF, &m1_proof),
        ]),
    )?;
    if status != 200 {
        return Err(PairError::Status(status));
    }
    let m4 = tlv8::decode(&body);
    if let Some(e) = tlv_err(&m4) {
        return Err(e);
    }
    let server_proof = require(&m4, tlv8::PROOF)?;
    if !srp.verify_server_proof(server_proof) {
        return Err(PairError::SrpProof);
    }
    Ok(srp.session_key().to_vec())
}

/// Transient pair-setup; returns the 64-byte SRP session key.
pub fn pair_transient<T: PairTransport>(t: &mut T) -> Result<Vec<u8>, PairError> {
    // POST /pair-pin-start, empty body.
    t.post("/pair-pin-start", HKP_TRANSIENT, &[])?;
    srp_exchange(
        t,
        HKP_TRANSIENT,
        &[
            (tlv8::METHOD, &[0x00]),
            (tlv8::STATE, &[0x01]),
            (tlv8::FLAGS, &[FLAG_TRANSIENT]),
        ],
        || Ok(TRANSIENT_PIN.to_string()),
    )
}

/// Ask the receiver to put its AirPlay code on screen, and stop there.
///
/// This is pair-setup's own first step — `POST /pair-pin-start` — sent on its
/// own. It is a complete request/response, so stopping here leaves nothing
/// half-open on either side.
///
/// **It cannot be used to prompt for a code that a LATER process will submit.**
/// Proven on the Frame on 2026-09-21: `request_code` put 1878 on the screen,
/// and a second `airplay pair --pin 1878` — a new process, a new connection,
/// its own `/pair-pin-start` — was refused with HAP error 2, because the
/// receiver had by then issued a fresh code. Pair-setup state, including which
/// code is expected, belongs to the CONNECTION. Anything that asks a human to
/// read the screen must therefore hold one connection open across the reading:
/// that is what `pair --interactive` does, and it is the only shape that
/// works. This function is kept for a caller that only wants to wake the
/// screen — a UI that will then run the interactive flow itself, say — and for
/// the tests.
pub fn request_code<T: PairTransport>(t: &mut T, hkp: u8) -> Result<(), PairError> {
    let (status, _) = t.post("/pair-pin-start", hkp, &[])?;
    if status != 200 {
        return Err(PairError::Status(status));
    }
    Ok(())
}

/// PIN pair-setup (M1..M6) with an infallible code supplier.
///
/// The supplier runs between M2 and M3, on this connection, which is what lets
/// a human read the code off the screen without the exchange being restarted
/// under them. A supplier that may give up wants [`pair_setup_pin_with`].
pub fn pair_setup_pin<T: PairTransport>(
    t: &mut T,
    hkp: u8,
    sender_name: &str,
    pin_supplier: impl FnOnce() -> String,
) -> Result<Credentials, PairError> {
    pair_setup_pin_with(t, hkp, sender_name, || Ok(pin_supplier()))
}

/// PIN pair-setup (M1..M6) with a supplier that may fail.
///
/// Failing costs nothing: the error is returned before M3 is built, so no
/// proof is sent and none of the receiver's small allowance of attempts is
/// spent. That is the difference between "the user walked away" and "the user
/// typed the wrong code" — the second one is what eventually earns BackOff and
/// MaxTries from the receiver.
pub fn pair_setup_pin_with<T: PairTransport>(
    t: &mut T,
    hkp: u8,
    sender_name: &str,
    pin_supplier: impl FnOnce() -> Result<String, PairError>,
) -> Result<Credentials, PairError> {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    // Status deliberately ignored, as the probe ignores it: this is the byte
    // sequence that has paired the Frame, and `request_code`'s stricter check
    // is for callers that want to know the prompt went up.
    t.post("/pair-pin-start", hkp, &[])?;
    let k = srp_exchange(
        t,
        hkp,
        &[(tlv8::METHOD, &[0x00]), (tlv8::STATE, &[0x01])],
        pin_supplier,
    )?;

    // Controller long-term key + identity.
    let ltsk = SigningKey::generate(&mut rand::rngs::OsRng);
    let ltpk = ltsk.verifying_key();
    let ltpk_bytes = ltpk.to_bytes();
    let pairing_id = uuid::Uuid::new_v4()
        .to_string()
        .to_uppercase()
        .into_bytes();

    let controller_x = hkdf(&k, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info");
    let mut sign_msg = controller_x.to_vec();
    sign_msg.extend_from_slice(&pairing_id);
    sign_msg.extend_from_slice(&ltpk_bytes);
    let signature = ltsk.sign(&sign_msg).to_bytes();

    let name_field = opack_name_field(sender_name);
    let mut sub: Vec<(u8, &[u8])> = vec![
        (tlv8::IDENTIFIER, &pairing_id),
        (tlv8::PUBLIC_KEY, &ltpk_bytes),
        (tlv8::SIGNATURE, &signature),
        (tlv8::NAME, &name_field),
    ];
    if hkp == HKP_SCREEN_CAPTURE {
        sub.push((tlv8::ACL, SCREEN_CAPTURE_ACL));
    }

    let setup_key = hkdf(&k, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info");
    let sealed = seal(&setup_key, "PS-Msg05", &tlv8::encode(&sub))?;

    // M5
    let (status, body) = t.post(
        "/pair-setup",
        hkp,
        &tlv8::encode(&[(tlv8::STATE, &[0x05]), (tlv8::ENCRYPTED, &sealed)]),
    )?;
    let m6 = tlv8::decode(&body);
    if status != 200 {
        return Err(PairError::Status(status));
    }
    if let Some(e) = tlv_err(&m6) {
        return Err(e);
    }

    // M6: decrypt accessory sub-TLV and verify its signature.
    let encrypted = require(&m6, tlv8::ENCRYPTED)?;
    let accessory_plain = open(&setup_key, "PS-Msg06", encrypted)?;
    let accessory = tlv8::decode(&accessory_plain);
    let tv_id = require(&accessory, tlv8::IDENTIFIER)?.clone();
    let tv_ltpk = require(&accessory, tlv8::PUBLIC_KEY)?.clone();
    let tv_sig = require(&accessory, tlv8::SIGNATURE)?.clone();

    let accessory_x = hkdf(&k, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info");
    let mut verify_msg = accessory_x.to_vec();
    verify_msg.extend_from_slice(&tv_id);
    verify_msg.extend_from_slice(&tv_ltpk);
    let tv_key = VerifyingKey::from_bytes(
        tv_ltpk.as_slice().try_into().map_err(|_| PairError::BadSignature)?,
    )
    .map_err(|_| PairError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_slice(&tv_sig).map_err(|_| PairError::BadSignature)?;
    tv_key
        .verify_strict(&verify_msg, &sig)
        .map_err(|_| PairError::BadSignature)?;

    Ok(Credentials {
        hkp,
        pairing_id: String::from_utf8_lossy(&pairing_id).into_owned(),
        ltsk: hex::encode(ltsk.to_bytes()),
        tv_id: String::from_utf8_lossy(&tv_id).into_owned(),
        tv_ltpk: hex::encode(&tv_ltpk),
        // Filled in by the store, which is the only thing that knows under
        // which host key these were filed.
        host: None,
    })
}

/// Pair-verify (M1..M4); returns the 32-byte X25519 shared secret.
pub fn pair_verify<T: PairTransport>(
    t: &mut T,
    creds: &Credentials,
) -> Result<[u8; 32], PairError> {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let eph = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph);
    let eph_pub_bytes = eph_pub.to_bytes();

    // M1
    let (status, body) = t.post(
        "/pair-verify",
        creds.hkp,
        &tlv8::encode(&[(tlv8::STATE, &[0x01]), (tlv8::PUBLIC_KEY, &eph_pub_bytes)]),
    )?;
    let m2 = tlv8::decode(&body);
    if status != 200 {
        return Err(PairError::Status(status));
    }
    if let Some(e) = tlv_err(&m2) {
        return Err(e);
    }
    let tv_eph = require(&m2, tlv8::PUBLIC_KEY)?.clone();
    let tv_eph_arr: [u8; 32] = tv_eph
        .as_slice()
        .try_into()
        .map_err(|_| PairError::MissingTag(tlv8::PUBLIC_KEY))?;
    let shared = eph.diffie_hellman(&PublicKey::from(tv_eph_arr)).to_bytes();

    let verify_key = hkdf(&shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info");
    let inner_plain = open(&verify_key, "PV-Msg02", require(&m2, tlv8::ENCRYPTED)?)?;
    let inner = tlv8::decode(&inner_plain);
    let inner_id = require(&inner, tlv8::IDENTIFIER)?.clone();
    let inner_sig = require(&inner, tlv8::SIGNATURE)?.clone();

    // Verify receiver signature over tv_eph || inner_id || eph_pub.
    let mut vmsg = tv_eph.clone();
    vmsg.extend_from_slice(&inner_id);
    vmsg.extend_from_slice(&eph_pub_bytes);
    let tv_ltpk = hex::decode(&creds.tv_ltpk).map_err(|_| PairError::BadSignature)?;
    let tv_key = VerifyingKey::from_bytes(
        tv_ltpk.as_slice().try_into().map_err(|_| PairError::BadSignature)?,
    )
    .map_err(|_| PairError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_slice(&inner_sig).map_err(|_| PairError::BadSignature)?;
    tv_key
        .verify_strict(&vmsg, &sig)
        .map_err(|_| PairError::BadSignature)?;

    // M3: sign eph_pub || pairing_id || tv_eph with our long-term key.
    let ltsk_bytes = hex::decode(&creds.ltsk).map_err(|_| PairError::BadSignature)?;
    let ltsk = SigningKey::from_bytes(
        ltsk_bytes.as_slice().try_into().map_err(|_| PairError::BadSignature)?,
    );
    let pairing_id = creds.pairing_id.as_bytes();
    let mut smsg = eph_pub_bytes.to_vec();
    smsg.extend_from_slice(pairing_id);
    smsg.extend_from_slice(&tv_eph);
    let our_sig = ltsk.sign(&smsg).to_bytes();
    let sealed = seal(
        &verify_key,
        "PV-Msg03",
        &tlv8::encode(&[(tlv8::IDENTIFIER, pairing_id), (tlv8::SIGNATURE, &our_sig)]),
    )?;

    let (status, body) = t.post(
        "/pair-verify",
        creds.hkp,
        &tlv8::encode(&[(tlv8::STATE, &[0x03]), (tlv8::ENCRYPTED, &sealed)]),
    )?;
    let m4 = tlv8::decode(&body);
    if status != 200 {
        return Err(PairError::Status(status));
    }
    if let Some(e) = tlv_err(&m4) {
        return Err(e);
    }
    Ok(shared)
}

// --------------------------------------------------------------------------- AEAD single-shot

/// ChaCha20-Poly1305 single-shot seal with a label nonce and no AAD
/// (probe.py: `ChaCha20Poly1305(key).encrypt(nonce_label(label), pt, None)`).
fn seal(key: &[u8; 32], label: &str, plaintext: &[u8]) -> Result<Vec<u8>, PairError> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce_label(label);
    cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|_| PairError::Crypto(CryptoError::Auth))
}

/// ChaCha20-Poly1305 single-shot open with a label nonce and no AAD.
fn open(key: &[u8; 32], label: &str, sealed: &[u8]) -> Result<Vec<u8>, PairError> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce_label(label);
    cipher
        .decrypt((&nonce).into(), sealed)
        .map_err(|_| PairError::Crypto(CryptoError::Auth))
}

// --------------------------------------------------------------------------- transport keys

/// Control-Salt keys. Returns (write, read).
pub fn control_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    crate::crypto::control_keys(shared)
}

/// Events-Salt keys. Returns (write, read), direction reversed vs control: the
/// write key derives from the `Events-Read-Encryption-Key` label and the read
/// key from `Events-Write-Encryption-Key`, because the receiver is the client on
/// the event channel.
pub fn events_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    crate::crypto::events_keys(shared)
}

// --------------------------------------------------------------------------- store

/// On-disk credential store: one JSON file per receiver, so a session can
/// pair-verify instead of asking the TV for its code again.
///
/// **Plaintext, deliberately, for now.** The `ltsk` in these files is a private
/// key; moving them into gnome-keyring is a later job and is not pretended at
/// here. What IS done is the cheap part that has to be right either way: the
/// directory is 0700, the files are 0600 (enforced on write AND repaired on
/// read, because an older build wrote them at the umask's mercy), writes are
/// atomic, and a file that is missing, truncated, hand-edited or simply not
/// ours reads back as "not paired" rather than as an error that kills a
/// session.
///
/// Every function comes in two spellings: the plain one, which uses [`dir`],
/// and an `_in` one taking the directory, which is what the tests use so they
/// never touch `$HOME` and never have to mutate the environment.
pub mod store {
    use super::Credentials;
    use std::io;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// Mode of the credentials directory: owner only.
    pub const DIR_MODE: u32 = 0o700;
    /// Mode of each credentials file: owner read/write only.
    pub const FILE_MODE: u32 = 0o600;

    /// One host's stored pairing, as `pair --list` reports it. No secrets: the
    /// host, the HKP type it was paired under, and where the file is.
    #[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
    pub struct Paired {
        pub host: String,
        pub hkp: u8,
    }

    /// `$AIRPLAY_RS_CREDENTIALS_DIR`, else `$XDG_CONFIG_HOME/airplay-rs/credentials`,
    /// else `$HOME/.config/airplay-rs/credentials`, else a temp directory.
    ///
    /// The env override matches the `AIRPLAY_RS_STATE_DIR` / `AIRPLAY_RS_RUNTIME_DIR`
    /// convention the rest of the crate uses, and exists for the same reason:
    /// so a test, or a second machine's config, can be pointed somewhere else
    /// without a rebuild.
    pub fn dir() -> PathBuf {
        if let Ok(d) = std::env::var("AIRPLAY_RS_CREDENTIALS_DIR") {
            if !d.is_empty() {
                return PathBuf::from(d);
            }
        }
        if let Ok(d) = std::env::var("XDG_CONFIG_HOME") {
            if !d.is_empty() {
                return PathBuf::from(d).join("airplay-rs").join("credentials");
            }
        }
        if let Ok(h) = std::env::var("HOME") {
            if !h.is_empty() {
                return PathBuf::from(h).join(".config/airplay-rs/credentials");
            }
        }
        std::env::temp_dir().join("airplay-rs-credentials")
    }

    /// The file name a host is filed under: everything but `[A-Za-z0-9.-]`
    /// becomes `_`, so an IPv6 address or a receiver name cannot escape the
    /// directory or collide with a path separator.
    pub fn file_name(host: &str) -> String {
        let safe: String = host
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
            .collect();
        format!("{safe}.json")
    }

    pub fn path_in(dir: &Path, host: &str) -> PathBuf {
        dir.join(file_name(host))
    }

    pub fn path(host: &str) -> PathBuf {
        path_in(&dir(), host)
    }

    /// Best-effort 0600. A store on a filesystem with no Unix modes, or a file
    /// someone else owns, is not worth failing a read over — but it IS worth
    /// not silently leaving a world-readable private key behind, which is what
    /// the write path uses this for.
    fn tighten(path: &Path) {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o777 != FILE_MODE {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(FILE_MODE));
            }
        }
    }

    /// Load one host's credentials, or `None`.
    ///
    /// `None` covers every way this can go wrong — no file, no permission,
    /// truncated JSON, the wrong JSON, a key that is not a key — because from
    /// the caller's side they are all the same fact: there is nothing here to
    /// pair-verify with, so pair transiently instead. Nothing is printed and
    /// nothing is deleted; a file that fails to parse is left exactly as it is
    /// for a human to look at.
    pub fn load_in(dir: &Path, host: &str) -> Option<Credentials> {
        let path = path_in(dir, host);
        let raw = std::fs::read_to_string(&path).ok()?;
        let mut creds: Credentials = serde_json::from_str(&raw).ok()?;
        creds.validate().ok()?;
        // Repair the mode of a file an older build wrote at 0644.
        tighten(&path);
        if creds.host.is_none() {
            creds.host = Some(host.to_string());
        }
        Some(creds)
    }

    pub fn load(host: &str) -> Option<Credentials> {
        load_in(&dir(), host)
    }

    /// Why a load returned nothing, for a human. Separate from [`load_in`] so
    /// the hot path stays allocation-free and total, and so the CLI can say
    /// "credentials for X are corrupt" without the library deciding to print.
    pub fn why_not_in(dir: &Path, host: &str) -> Option<String> {
        let path = path_in(dir, host);
        match std::fs::read_to_string(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => Some(format!("{} cannot be read ({e})", path.display())),
            Ok(raw) => match serde_json::from_str::<Credentials>(&raw) {
                Err(e) => Some(format!("{} is not valid credentials JSON ({e})", path.display())),
                Ok(c) => c.validate().err().map(|w| format!("{} is unusable: {w}", path.display())),
            },
        }
    }

    pub fn why_not(host: &str) -> Option<String> {
        why_not_in(&dir(), host)
    }

    /// Write one host's credentials, 0600, atomically.
    ///
    /// Atomic because the alternative — truncate, then write — turns a crash
    /// mid-write into a zero-length file, which is exactly the "corrupt
    /// credentials" case this store otherwise has to tolerate. The temp file
    /// is created 0600 by `mode()`, so the secret is never on disk under a
    /// looser mode, not even for the instant before a chmod.
    pub fn save_in(dir: &Path, host: &str, creds: &Credentials) -> io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE));

        let mut stored = creds.clone();
        stored.host = Some(host.to_string());
        let json = serde_json::to_string_pretty(&stored)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let final_path = path_in(dir, host);
        let tmp = dir.join(format!(".{}.{}.tmp", file_name(host), std::process::id()));
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_all()?;
        }
        // An existing file may be 0644 from an older build; the rename
        // replaces it wholesale, so the new mode is the temp file's.
        if let Err(e) = std::fs::rename(&tmp, &final_path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        tighten(&final_path);
        Ok(final_path)
    }

    pub fn save(host: &str, creds: &Credentials) -> io::Result<PathBuf> {
        save_in(&dir(), host, creds)
    }

    /// Every host we hold usable credentials for, sorted by host.
    ///
    /// Files that do not load are skipped rather than reported as paired: the
    /// list answers "which receivers can I reach without a code", and a corrupt
    /// file cannot. Temp files (`.…tmp`) are skipped by extension.
    pub fn list_in(dir: &Path) -> Vec<Paired> {
        let mut out: Vec<Paired> = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return out,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) if !s.starts_with('.') => s.to_string(),
                _ => continue,
            };
            let creds = match std::fs::read_to_string(&path)
                .ok()
                .and_then(|raw| serde_json::from_str::<Credentials>(&raw).ok())
            {
                Some(c) if c.validate().is_ok() => c,
                _ => continue,
            };
            // The host inside the file wins: the file NAME has been through
            // `file_name`, which is lossy for anything but a plain IPv4
            // address or a hostname.
            out.push(Paired { host: creds.host.unwrap_or(stem), hkp: creds.hkp });
        }
        out.sort_by(|a, b| a.host.cmp(&b.host));
        out
    }

    pub fn list() -> Vec<Paired> {
        list_in(&dir())
    }

    /// Remove one host's credentials. `Ok(false)` if there were none.
    pub fn forget_in(dir: &Path, host: &str) -> io::Result<bool> {
        match std::fs::remove_file(path_in(dir, host)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn forget(host: &str) -> io::Result<bool> {
        forget_in(&dir(), host)
    }
}
