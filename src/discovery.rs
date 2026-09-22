//! discovery-info: mDNS discovery and the unauthenticated GET /info binary
//! plist. Ported from probe.discover / probe.decode_plist (probe.py).

use std::collections::{BTreeMap, HashMap};

pub const AIRPLAY_PORT: u16 = 7000;
pub const AIRPLAY_SERVICE: &str = "_airplay._tcp";

// --------------------------------------------------------------------------- mDNS

#[derive(Debug, Clone)]
pub struct MdnsRecord {
    /// `\DDD`-unescaped instance name.
    pub name: String,
    /// Resolved A-record IP (NEVER the SRV hostname).
    pub host: String,
    pub port: u16,
    pub txt: HashMap<String, String>,
}

/// Un-escape avahi's `\DDD` decimal escapes (probe.py: `re.sub(r"\\(\d{3})", ...)`).
///
/// The escapes are **bytes**, not code points: avahi escapes every non-printable
/// byte of the UTF-8 instance name separately, so `the user’s Mac Studio` arrives as
/// `Owner\226\128\153s\032Mac\032Studio` — the three bytes `e2 80 99` of U+2019.
/// Decoding each `\DDD` to a `char` therefore has to be wrong: it reads the name
/// as Latin-1 and re-encodes it, which is what turned that name into
/// `the userâ€™s Mac Studio` in the human output. So the escapes are decoded into a
/// BYTE buffer and the whole thing is interpreted as UTF-8 at the end, which is
/// what it is. A name that is genuinely not valid UTF-8 (nothing on this network
/// produces one) keeps the replacement character rather than failing the row:
/// losing a receiver over one bad byte in its name would be worse.
fn unescape_avahi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
        {
            let n = (bytes[i + 1] - b'0') as u32 * 100
                + (bytes[i + 2] - b'0') as u32 * 10
                + (bytes[i + 3] - b'0') as u32;
            if let Ok(b) = u8::try_from(n) {
                out.push(b);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the `"k=v" "k2=v2"` TXT blob of avahi field[9] into a map. Mirrors
/// `dict(re.findall(r'"([^"=]+)=([^"]*)"', field))`.
fn parse_txt(field: &str) -> HashMap<String, String> {
    let mut txt = HashMap::new();
    let bytes = field.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        // Find the closing quote.
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() && bytes[j] != b'"' {
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        let token = &field[start..j];
        // key = up to first '=', value = the rest; require an '=' and a
        // key that itself has no '=' (matches `[^"=]+=[^"]*`).
        if let Some(eq) = token.find('=') {
            let key = &token[..eq];
            if !key.is_empty() {
                txt.insert(key.to_string(), token[eq + 1..].to_string());
            }
        }
        i = j + 1;
    }
    txt
}

/// Parse one resolved `avahi-browse -rpt _airplay._tcp` line. Returns None for
/// non-`=` rows, rows whose resolved address is not IPv4, and rows with <10
/// `;`-separated fields.
///
/// The IPv4 test is on the **address** (field 7), not on avahi's protocol column
/// (field 2). They are different facts: the protocol column says which
/// interface record the answer came in on, and this network answers for the
/// Frame over the IPv6 socket while resolving it to an A record —
/// `=;wlp0s20f3;IPv6;Demo\032TV;…;192.0.2.187;7000;…`. Keying on the column
/// dropped that receiver from `discover` entirely while `mirror 192.0.2.187`
/// worked fine. An `::1`-style row still parses to `None`, because the address
/// is what is checked and the session layer only speaks IPv4.
pub fn parse_avahi_line(line: &str) -> Option<MdnsRecord> {
    let fields: Vec<&str> = line.split(';').collect();
    if fields.len() < 10 || fields[0] != "=" {
        return None;
    }
    if !matches!(fields[7].parse::<std::net::IpAddr>(), Ok(std::net::IpAddr::V4(_))) {
        return None;
    }
    let name = unescape_avahi(fields[3]);
    let host = fields[7].to_string();
    let port = fields[8].parse::<u16>().unwrap_or(AIRPLAY_PORT);
    let txt = parse_txt(fields[9]);
    Some(MdnsRecord {
        name,
        host,
        port,
        txt,
    })
}

// ------------------------------------------------------- machine-readable form

/// One receiver as `airplay discover --json` prints it.
///
/// `model` and `srcvers` are `Option` and **omitted** when the receiver does not
/// advertise them, rather than serialised as `""`: an empty string would claim
/// the receiver said its model was empty, which is a different fact from not
/// having said. A consumer therefore tests for the key's presence, not for a
/// sentinel.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Receiver {
    /// The human name, correct UTF-8, as the receiver advertises it: it can
    /// contain apostrophes, quotes and non-ASCII, and `serde_json` escapes
    /// whatever needs escaping.
    pub name: String,
    /// The resolved A-record address. Never the SRV hostname.
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srcvers: Option<String>,
}

/// The whole `--json` document: one object with one key, never a stream.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Discovery {
    pub receivers: Vec<Receiver>,
}

impl Discovery {
    /// One line of compact JSON, newline-terminated, and nothing else.
    pub fn to_json_line(&self) -> String {
        // Infallible for this shape (no map with non-string keys, no NaN), but
        // a panic on stdout formatting would be a poor trade either way.
        match serde_json::to_string(self) {
            Ok(s) => format!("{s}\n"),
            Err(_) => "{\"receivers\":[]}\n".to_string(),
        }
    }
}

impl From<&MdnsRecord> for Receiver {
    fn from(rec: &MdnsRecord) -> Self {
        // `filter(|v| !v.is_empty())`: an advertised-but-empty TXT value is
        // treated as absent, because "model=" tells a UI nothing it could show.
        let txt = |k: &str| {
            rec.txt
                .get(k)
                .map(String::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        Receiver {
            name: rec.name.clone(),
            host: rec.host.clone(),
            port: rec.port,
            model: txt("model"),
            srcvers: txt("srcvers"),
        }
    }
}

/// Every receiver in a `avahi-browse -rpt` dump whose name matches `pattern`,
/// de-duplicated, in the order the rows appeared.
///
/// De-duplication is not cosmetic: avahi resolves the same service once per
/// interface record, so a receiver reachable over both commonly appears twice
/// with the identical address — and a UI listing the Frame twice would be a bug
/// in this function, not in the UI. The key is `(name, host, port)`, i.e. the
/// identity a caller would act on; a second row for the same key only fills in
/// TXT fields the first was missing.
pub fn receivers(browse_output: &str, pattern: &str) -> Vec<Receiver> {
    let needle = pattern.to_lowercase();
    let mut out: Vec<Receiver> = Vec::new();
    for line in browse_output.lines() {
        let Some(rec) = parse_avahi_line(line) else { continue };
        if !needle.is_empty() && !rec.name.to_lowercase().contains(&needle) {
            continue;
        }
        let r = Receiver::from(&rec);
        match out
            .iter_mut()
            .find(|k| k.name == r.name && k.host == r.host && k.port == r.port)
        {
            Some(kept) => {
                if kept.model.is_none() {
                    kept.model = r.model;
                }
                if kept.srcvers.is_none() {
                    kept.srcvers = r.srcvers;
                }
            }
            None => out.push(r),
        }
    }
    out
}

/// First record whose name matches `pattern` (case-insensitive substring; an
/// empty pattern matches the first record). Mirrors probe.discover's
/// `re.search(name_pattern, name, re.I)` for the common plain-text patterns.
pub fn discover(browse_output: &str, pattern: &str) -> Option<MdnsRecord> {
    let needle = pattern.to_ascii_lowercase();
    for line in browse_output.lines() {
        if let Some(rec) = parse_avahi_line(line) {
            if needle.is_empty() || rec.name.to_ascii_lowercase().contains(&needle) {
                return Some(rec);
            }
        }
    }
    None
}

// --------------------------------------------------------------------------- GET /info

#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub source_version: String,
    pub protocol_version: String,
    pub model: String,
    pub manufacturer: String,
    pub device_id: String,
    pub pi: String,
    pub status_flags: u32,
    pub volume_control_type: u32,
    pub active_interface_type: u32,
    pub features: Features,
    pub features_ex: Option<String>,
    pub displays: Vec<Display>,
    pub audio_latencies: Vec<AudioLatency>,
    pub playback_capabilities: BTreeMap<String, plist::Value>,
    /// Remaining string/bool fields carried opaquely.
    pub extra: BTreeMap<String, plist::Value>,
}

#[derive(Debug, Clone)]
pub struct Display {
    pub width_pixels: u32,
    pub height_pixels: u32,
    pub width_pixels_max: Option<u32>,
    pub height_pixels_max: Option<u32>,
    pub max_fps: Option<u32>,
    pub uuid: Option<String>,
    pub hdr_supported_modes: Vec<HdrMode>,
}

#[derive(Debug, Clone)]
pub struct HdrMode {
    pub codec_strings: Vec<String>,
    pub hdr_mode: String,
    pub kind: u32,
    pub receiver_hdr_capability: String,
}

#[derive(Debug, Clone)]
pub struct AudioLatency {
    pub kind: u32,
    pub audio_type: Option<String>,
    pub input_latency_micros: u32,
    pub output_latency_micros: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct Features(pub u64);

impl Features {
    pub fn is_set(self, bit: u8) -> bool {
        debug_assert!(bit < 64);
        (self.0 >> bit) & 1 == 1
    }

    pub fn set_bits(self) -> Vec<u8> {
        (0u8..64).filter(|&b| self.is_set(b)).collect()
    }

    pub fn lo32(self) -> u32 {
        self.0 as u32
    }

    pub fn hi32(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

#[derive(Debug)]
pub enum FeatureExError {
    Base64,
    TooShort,
}

impl std::fmt::Display for FeatureExError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeatureExError::Base64 => write!(f, "featuresEx is not valid base64url"),
            FeatureExError::TooShort => write!(f, "featuresEx shorter than 8 bytes"),
        }
    }
}

impl std::error::Error for FeatureExError {}

/// Decode featuresEx (base64url, no pad) -> (features u64, extended-word bytes).
/// bytes[0..8) are the little-endian `features`; bytes[8..] the extended word.
pub fn decode_features_ex(s: &str) -> Result<(u64, Vec<u8>), FeatureExError> {
    use base64::Engine;
    // The fixture string uses the STANDARD alphabet ("/"), but AirPlay
    // advertisements are nominally base64url. Python's `urlsafe_b64decode`
    // simply translates `-_` -> `+/` and standard-decodes, accepting both; do
    // the same so either alphabet round-trips (probe generated the vector this
    // way).
    let normalized: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(normalized.as_bytes())
        .map_err(|_| FeatureExError::Base64)?;
    if raw.len() < 8 {
        return Err(FeatureExError::TooShort);
    }
    let mut le = [0u8; 8];
    le.copy_from_slice(&raw[..8]);
    let features = u64::from_le_bytes(le);
    Ok((features, raw[8..].to_vec()))
}

// --------------------------------------------------------------------------- plist helpers

fn as_u32(v: &plist::Value) -> Option<u32> {
    v.as_unsigned_integer()
        .map(|u| u as u32)
        .or_else(|| v.as_signed_integer().map(|i| i as u32))
}

fn as_u64(v: &plist::Value) -> Option<u64> {
    v.as_unsigned_integer()
        .or_else(|| v.as_signed_integer().map(|i| i as u64))
}

fn dict_u32(d: &plist::Dictionary, key: &str) -> u32 {
    d.get(key).and_then(as_u32).unwrap_or(0)
}

fn dict_string(d: &plist::Dictionary, key: &str) -> String {
    d.get(key)
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string()
}

fn parse_hdr_mode(v: &plist::Value) -> HdrMode {
    let d = v.as_dictionary();
    let codec_strings = d
        .and_then(|d| d.get("codecStrings"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_string().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    HdrMode {
        codec_strings,
        hdr_mode: d.map(|d| dict_string(d, "HDRMode")).unwrap_or_default(),
        kind: d.map(|d| dict_u32(d, "type")).unwrap_or(0),
        receiver_hdr_capability: d
            .map(|d| dict_string(d, "receiverHDRCapability"))
            .unwrap_or_default(),
    }
}

fn parse_display(v: &plist::Value) -> Display {
    let d = v.as_dictionary();
    let hdr_supported_modes = d
        .and_then(|d| d.get("HDRSupportedModes"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(parse_hdr_mode).collect())
        .unwrap_or_default();
    Display {
        width_pixels: d.map(|d| dict_u32(d, "widthPixels")).unwrap_or(0),
        height_pixels: d.map(|d| dict_u32(d, "heightPixels")).unwrap_or(0),
        width_pixels_max: d.and_then(|d| d.get("widthPixelsMax")).and_then(as_u32),
        height_pixels_max: d.and_then(|d| d.get("heightPixelsMax")).and_then(as_u32),
        max_fps: d.and_then(|d| d.get("maxFPS")).and_then(as_u32),
        uuid: d
            .and_then(|d| d.get("uuid"))
            .and_then(|v| v.as_string())
            .map(str::to_string),
        hdr_supported_modes,
    }
}

fn parse_audio_latency(v: &plist::Value) -> AudioLatency {
    let d = v.as_dictionary();
    AudioLatency {
        kind: d.map(|d| dict_u32(d, "type")).unwrap_or(0),
        audio_type: d
            .and_then(|d| d.get("audioType"))
            .and_then(|v| v.as_string())
            .map(str::to_string),
        input_latency_micros: d.map(|d| dict_u32(d, "inputLatencyMicros")).unwrap_or(0),
        output_latency_micros: d.map(|d| dict_u32(d, "outputLatencyMicros")).unwrap_or(0),
    }
}

/// Keys extracted into typed fields; everything else lands in `extra`.
const TYPED_KEYS: &[&str] = &[
    "name",
    "sourceVersion",
    "protocolVersion",
    "model",
    "manufacturer",
    "deviceID",
    "pi",
    "statusFlags",
    "volumeControlType",
    "activeInterfaceType",
    "features",
    "featuresEx",
    "displays",
    "audioLatencies",
    "playbackCapabilities",
];

/// Parse a `bplist00` /info body (plist crate).
pub fn parse_info(body: &[u8]) -> Result<Info, plist::Error> {
    let value = plist::Value::from_reader(std::io::Cursor::new(body))?;
    // A healthy receiver returns a dict; a non-dict body decodes to an empty
    // Info (mirrors probe.decode_plist tolerance) rather than an error.
    let dict = value.into_dictionary().unwrap_or_default();

    let features = Features(dict.get("features").and_then(as_u64).unwrap_or(0));

    let displays = dict
        .get("displays")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(parse_display).collect())
        .unwrap_or_default();

    let audio_latencies = dict
        .get("audioLatencies")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(parse_audio_latency).collect())
        .unwrap_or_default();

    let playback_capabilities = dict
        .get("playbackCapabilities")
        .and_then(|v| v.as_dictionary())
        .map(|d| {
            d.iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    let mut extra = BTreeMap::new();
    for (k, v) in dict.iter() {
        if !TYPED_KEYS.contains(&k.as_str()) {
            extra.insert(k.to_string(), v.clone());
        }
    }

    Ok(Info {
        name: dict_string(&dict, "name"),
        source_version: dict_string(&dict, "sourceVersion"),
        protocol_version: dict_string(&dict, "protocolVersion"),
        model: dict_string(&dict, "model"),
        manufacturer: dict_string(&dict, "manufacturer"),
        device_id: dict_string(&dict, "deviceID"),
        pi: dict_string(&dict, "pi"),
        status_flags: dict_u32(&dict, "statusFlags"),
        volume_control_type: dict_u32(&dict, "volumeControlType"),
        active_interface_type: dict_u32(&dict, "activeInterfaceType"),
        features,
        features_ex: dict
            .get("featuresEx")
            .and_then(|v| v.as_string())
            .map(str::to_string),
        displays,
        audio_latencies,
        playback_capabilities,
        extra,
    })
}

/// Screen fit; defaults to 1920x1080 when `displays` is absent (probe.py
/// lines 1388-1396).
pub fn info_screen_fit(info: &Info) -> (u32, u32) {
    match info.displays.first() {
        Some(d) => (d.width_pixels, d.height_pixels),
        None => (1920, 1080),
    }
}

// ===================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim rows from `avahi-browse -rpt _airplay._tcp` on the user's laptop,
    /// TXT trimmed to the keys the JSON carries. Note the two things that broke
    /// the human output and are now pinned here: the Frame answers on the
    /// **IPv6** interface record while resolving to an A record, and the Mac
    /// Studio's name is UTF-8 escaped byte by byte.
    const BROWSE: &str = concat!(
        "+;wlp0s20f3;IPv4;Demo\\032TV;AirPlay Remote Video;local\n",
        "=;wlp0s20f3;IPv6;Demo\\032TV;AirPlay Remote Video;local;localhost.local;",
        "192.0.2.187;7000;\"model=LS03F\" \"srcvers=377.40.00\"\n",
        "=;wlp0s20f3;IPv4;Owner\\226\\128\\153s\\032Mac\\032Studio;AirPlay Remote Video;local;",
        "Owners-Mac-Studio.local;198.51.100.247;7000;\"model=Mac16,9\" \"srcvers=980.77.5\"\n",
        "=;wlp0s20f3;IPv6;Owner\\226\\128\\153s\\032Mac\\032Studio;AirPlay Remote Video;local;",
        "Owners-Mac-Studio.local;198.51.100.247;7000;\"model=Mac16,9\" \"srcvers=980.77.5\"\n",
        "=;wlp0s20f3;IPv4;Spare;AirPlay Remote Video;local;Spare.local;203.0.113.178;7000;\"\"\n",
    );

    #[test]
    fn avahi_escapes_are_bytes_so_a_utf8_name_survives() {
        assert_eq!(unescape_avahi("Demo\\032TV"), "Demo TV");
        // The bug this replaced: `\226\128\153` is the three UTF-8 bytes of
        // U+2019, not three code points.
        assert_eq!(
            unescape_avahi("Owner\\226\\128\\153s\\032Mac\\032Studio"),
            "Owner\u{2019}s Mac Studio"
        );
        assert_eq!(unescape_avahi("Demo\\032\\0402\\041"), "Demo (2)");
        // An apostrophe and a quote are ordinary characters here; escaping them
        // is the JSON writer's job, not this function's.
        assert_eq!(unescape_avahi("Owner\\039s \\034TV\\034"), "Owner's \"TV\"");
        // Not an escape: left exactly as it came.
        assert_eq!(unescape_avahi("100% \\12 \\abc"), "100% \\12 \\abc");
    }

    #[test]
    fn a_resolved_row_is_taken_on_its_address_not_on_avahis_protocol_column() {
        // The Frame, answered over IPv6, resolved to an A record.
        let rec = parse_avahi_line(BROWSE.lines().nth(1).unwrap()).expect("an A record row");
        assert_eq!(rec.name, "Demo TV");
        assert_eq!(rec.host, "192.0.2.187");
        assert_eq!(rec.port, 7000);
        // A real IPv6 address is still refused: the session layer only speaks v4.
        assert!(parse_avahi_line(
            "=;eth0;IPv6;Demo;_airplay._tcp;local;h;fe80::1;7000;\"\""
        )
        .is_none());
        assert!(parse_avahi_line(
            "=;eth0;IPv4;Demo;_airplay._tcp;local;h;not-an-ip;7000;\"\""
        )
        .is_none());
        // Unresolved (`+`) rows carry no address at all.
        assert!(parse_avahi_line(BROWSE.lines().next().unwrap()).is_none());
    }

    #[test]
    fn receivers_are_deduplicated_across_interface_records() {
        let rs = receivers(BROWSE, "");
        assert_eq!(
            rs.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["Demo TV", "Owner\u{2019}s Mac Studio", "Spare"],
            "the Mac Studio resolves on two interface records and is ONE receiver"
        );
        // An absent TXT key is absent, not "".
        assert_eq!(rs[2].model, None);
        assert_eq!(rs[2].srcvers, None);
        assert_eq!(rs[0].model.as_deref(), Some("LS03F"));
        assert_eq!(rs[0].srcvers.as_deref(), Some("377.40.00"));

        // The pattern filters on the human name, case-insensitively.
        assert_eq!(receivers(BROWSE, "demo").len(), 1);
        assert_eq!(receivers(BROWSE, "mac").len(), 1);
        assert_eq!(receivers(BROWSE, "nothing-here").len(), 0);
    }

    /// The CLI contract, byte for byte. A parallel consumer (the user's Quickshell
    /// bar plugin) parses exactly this, so the key order, the omission of
    /// absent optionals and the UTF-8 escaping are all pinned.
    #[test]
    fn the_json_document_is_one_object_with_one_key() {
        let doc = Discovery { receivers: receivers(BROWSE, "demo tv") };
        assert_eq!(
            doc.to_json_line(),
            "{\"receivers\":[{\"name\":\"Demo TV\",\"host\":\"192.0.2.187\",\"port\":7000,\
             \"model\":\"LS03F\",\"srcvers\":\"377.40.00\"}]}\n"
        );

        // Nothing found is an empty array, never a missing key or a null.
        assert_eq!(
            Discovery { receivers: vec![] }.to_json_line(),
            "{\"receivers\":[]}\n"
        );

        // A name with an apostrophe, a quote and non-ASCII: the apostrophe is
        // literal in JSON, the quote is backslash-escaped, and the U+2019 is
        // emitted as UTF-8 rather than a \u escape.
        let doc = Discovery {
            receivers: vec![Receiver {
                name: "Owner\u{2019}s \"TV\"".into(),
                host: "198.51.100.247".into(),
                port: 7000,
                model: None,
                srcvers: Some("980.77.5".into()),
            }],
        };
        assert_eq!(
            doc.to_json_line(),
            "{\"receivers\":[{\"name\":\"Owner\u{2019}s \\\"TV\\\"\",\"host\":\"198.51.100.247\",\
             \"port\":7000,\"srcvers\":\"980.77.5\"}]}\n"
        );
        // And it round-trips, so the shape is not just printable but readable.
        let back: Discovery = serde_json::from_str(doc.to_json_line().trim()).expect("round-trip");
        assert_eq!(back, doc);
    }
}
