//! The credential store, offline and complete: round trip, file modes, the
//! ways a file can be unusable, and the classifier that decides whether a
//! pairing failure means "the receiver wants its code typed in".
//!
//! Nothing here touches `$HOME`, the network or any receiver: every case runs
//! against a directory under `target/`, passed explicitly to the `_in`
//! spellings, so no environment variable is mutated and the tests can run in
//! parallel with everything else.

use airplay_rs::pairing::{store, Credentials, PairError};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A throwaway directory, removed on drop.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "airplay-creds-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn dir(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A well-formed credential with real keys, so `validate` has something that
/// genuinely passes rather than a string that happens to be 64 hex digits.
fn good_creds() -> Credentials {
    use ed25519_dalek::SigningKey;
    let ltsk = SigningKey::generate(&mut rand::rngs::OsRng);
    let tv = SigningKey::generate(&mut rand::rngs::OsRng);
    Credentials {
        hkp: 3,
        pairing_id: "6F9619FF-8B86-D011-B42D-00CF4FC964FF".into(),
        ltsk: hex::encode(ltsk.to_bytes()),
        tv_id: "02:1A:2B:3C:4D:5F".into(),
        tv_ltpk: hex::encode(tv.verifying_key().to_bytes()),
        host: None,
    }
}

fn mode_of(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_saved_credential_comes_back_exactly() {
    let tmp = Tmp::new("roundtrip");
    let creds = good_creds();
    let path = store::save_in(tmp.dir(), "192.0.2.187", &creds).unwrap();
    assert_eq!(path, tmp.dir().join("192.0.2.187.json"));

    let back = store::load_in(tmp.dir(), "192.0.2.187").expect("loads");
    assert_eq!(back.hkp, creds.hkp);
    assert_eq!(back.pairing_id, creds.pairing_id);
    assert_eq!(back.ltsk, creds.ltsk);
    assert_eq!(back.tv_id, creds.tv_id);
    assert_eq!(back.tv_ltpk, creds.tv_ltpk);
    // The store stamps the host it filed them under.
    assert_eq!(back.host.as_deref(), Some("192.0.2.187"));
    assert!(store::why_not_in(tmp.dir(), "192.0.2.187").is_none());
}

/// The on-disk shape stays probe.py's, so a file written by either side is
/// readable by the other. `host` is an addition and must not be required.
#[test]
fn the_file_is_the_probes_shape_and_an_older_file_still_loads() {
    let tmp = Tmp::new("shape");
    let creds = good_creds();
    store::save_in(tmp.dir(), "tv.local", &creds).unwrap();
    let raw = std::fs::read_to_string(tmp.dir().join("tv.local.json")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    for key in ["hkp", "pairing_id", "ltsk", "tv_id", "tv_ltpk"] {
        assert!(doc.get(key).is_some(), "{key} missing from the saved file");
    }

    // A file written before `host` existed: no such key, still loads, and the
    // host is filled in from the name it was found under.
    let older = serde_json::json!({
        "hkp": creds.hkp,
        "pairing_id": creds.pairing_id,
        "ltsk": creds.ltsk,
        "tv_id": creds.tv_id,
        "tv_ltpk": creds.tv_ltpk,
    });
    std::fs::write(tmp.dir().join("older.json"), older.to_string()).unwrap();
    let back = store::load_in(tmp.dir(), "older").expect("older file loads");
    assert_eq!(back.host.as_deref(), Some("older"));
}

#[test]
fn the_directory_is_0700_and_the_file_0600() {
    let tmp = Tmp::new("modes");
    let dir = tmp.dir().join("nested").join("credentials");
    let path = store::save_in(&dir, "192.0.2.187", &good_creds()).unwrap();
    assert_eq!(mode_of(&dir), store::DIR_MODE, "credentials directory mode");
    assert_eq!(mode_of(&path), store::FILE_MODE, "credentials file mode");
    // Nothing is left behind by the atomic write.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "192.0.2.187.json")
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
}

/// The case that exists on this machine: a file an older build wrote with
/// `fs::write`, at the umask's mercy. Reading it puts the mode right.
#[test]
fn a_loose_file_is_tightened_on_read_and_on_overwrite() {
    let tmp = Tmp::new("tighten");
    let creds = good_creds();
    let path = tmp.dir().join("192.0.2.187.json");
    std::fs::write(&path, serde_json::to_string(&creds).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(mode_of(&path), 0o644);

    assert!(store::load_in(tmp.dir(), "192.0.2.187").is_some());
    assert_eq!(mode_of(&path), store::FILE_MODE, "read did not tighten the mode");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    store::save_in(tmp.dir(), "192.0.2.187", &creds).unwrap();
    assert_eq!(mode_of(&path), store::FILE_MODE, "overwrite did not tighten the mode");
}

/// Every way a file can be unusable degrades to "not paired" — never a panic,
/// never an error that reaches a session.
#[test]
fn a_broken_file_reads_as_not_paired() {
    let tmp = Tmp::new("broken");
    let good = good_creds();

    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("truncated", "{\"hkp\":3,\"pairing_".to_string()),
        ("not-json", "this is not json at all".to_string()),
        ("wrong-json", "[1,2,3]".to_string()),
        (
            "bad-hkp",
            serde_json::to_string(&Credentials { hkp: 9, ..good.clone() }).unwrap(),
        ),
        (
            "ltsk-not-hex",
            serde_json::to_string(&Credentials { ltsk: "zzzz".into(), ..good.clone() }).unwrap(),
        ),
        (
            "ltsk-short",
            serde_json::to_string(&Credentials { ltsk: hex::encode([7u8; 16]), ..good.clone() })
                .unwrap(),
        ),
        (
            "ltpk-short",
            serde_json::to_string(&Credentials { tv_ltpk: hex::encode([3u8; 31]), ..good.clone() })
                .unwrap(),
        ),
        (
            "ltpk-not-a-key",
            // A 32-byte string that is not a point on the curve: y = 2 has no
            // corresponding x, so this cannot be decompressed and could never
            // verify a signature. (Most random 32-byte strings CAN be
            // decompressed, which is why this one is pinned rather than made
            // up on the spot.)
            serde_json::to_string(&Credentials {
                tv_ltpk: "0200000000000000000000000000000000000000000000000000000000000000".into(),
                ..good.clone()
            })
            .unwrap(),
        ),
        (
            "empty-pairing-id",
            serde_json::to_string(&Credentials { pairing_id: String::new(), ..good.clone() }).unwrap(),
        ),
    ];

    for (name, body) in &cases {
        std::fs::write(tmp.dir().join(format!("{name}.json")), body).unwrap();
        assert!(
            store::load_in(tmp.dir(), name).is_none(),
            "{name} should not load"
        );
        assert!(
            store::why_not_in(tmp.dir(), name).is_some(),
            "{name} should explain itself"
        );
        // The file is left alone for a human to look at.
        assert!(tmp.dir().join(format!("{name}.json")).exists(), "{name} was deleted");
    }

    // A host we have never paired with is not an error and has nothing to say.
    assert!(store::load_in(tmp.dir(), "10.0.0.1").is_none());
    assert!(store::why_not_in(tmp.dir(), "10.0.0.1").is_none());
    // Neither is a directory that does not exist at all.
    let missing = tmp.dir().join("nope");
    assert!(store::load_in(&missing, "10.0.0.1").is_none());
    assert!(store::list_in(&missing).is_empty());
}

/// The reason a corrupt file must never be listed: `pair --list` answers
/// "which receivers can I reach without a code", and a file that cannot be
/// loaded cannot.
#[test]
fn list_shows_only_usable_credentials_sorted() {
    let tmp = Tmp::new("list");
    store::save_in(tmp.dir(), "192.0.2.242", &good_creds()).unwrap();
    store::save_in(tmp.dir(), "192.0.2.187", &Credentials { hkp: 5, ..good_creds() }).unwrap();
    std::fs::write(tmp.dir().join("broken.json"), "{").unwrap();
    std::fs::write(tmp.dir().join("notes.txt"), "not a credential").unwrap();
    std::fs::write(tmp.dir().join(".192.0.2.1.json.99.tmp"), "{").unwrap();

    let list = store::list_in(tmp.dir());
    assert_eq!(
        list,
        vec![
            store::Paired { host: "192.0.2.187".into(), hkp: 5 },
            store::Paired { host: "192.0.2.242".into(), hkp: 3 },
        ]
    );
    // And no secret is anywhere near the serialised form.
    let json = serde_json::to_string(&list).unwrap();
    assert!(!json.contains("ltsk"), "list JSON leaks a key field: {json}");
}

#[test]
fn forget_removes_one_host_and_is_quiet_about_a_host_we_never_had() {
    let tmp = Tmp::new("forget");
    store::save_in(tmp.dir(), "192.0.2.187", &good_creds()).unwrap();
    assert!(store::forget_in(tmp.dir(), "192.0.2.187").unwrap());
    assert!(store::load_in(tmp.dir(), "192.0.2.187").is_none());
    assert!(!store::forget_in(tmp.dir(), "192.0.2.187").unwrap());
}

/// A host is a key, not a path: nothing a receiver can advertise may put a
/// file outside the store.
#[test]
fn a_hostile_host_cannot_escape_the_directory() {
    for host in ["../escape", "/etc/passwd", "fe80::1%wlan0", "a/b/c", "..", "tv name"] {
        let name = store::file_name(host);
        assert!(!name.contains('/'), "{host} -> {name}");
        assert!(name.ends_with(".json"));
        assert_eq!(
            store::path_in(Path::new("/store"), host).parent(),
            Some(Path::new("/store")),
            "{host} escaped the store directory"
        );
    }
}

/// The distinction the whole exercise is about: which failures mean "fetch the
/// code off the TV" and which do not.
#[test]
fn only_an_authentication_refusal_counts_as_needing_a_code() {
    assert!(airplay_rs::pairing::code_required(&PairError::Hap(
        2,
        "Authentication (wrong PIN?)"
    )));
    assert!(airplay_rs::pairing::code_required(&PairError::SrpProof));
    assert!(airplay_rs::pairing::code_required(&PairError::Status(470)));

    // Everything else is a different problem and must not be dressed up as
    // this one: a user sent to the TV for a code it is not showing is stuck.
    for e in [
        PairError::Hap(3, "BackOff"),
        PairError::Hap(5, "MaxTries"),
        PairError::Hap(6, "Unavailable"),
        PairError::Hap(7, "Busy"),
        PairError::Status(500),
        PairError::Status(404),
        PairError::BadSignature,
        PairError::SrpBadServerPublic,
        PairError::MissingTag(0x03),
        PairError::Transport(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out")),
    ] {
        assert!(!airplay_rs::pairing::code_required(&e), "{e} must not mean 'needs a code'");
    }
}

/// `ltsk` is a private key and this type turns up in error paths. `{:?}` must
/// not be a way to spill it.
#[test]
fn debug_redacts_the_secret() {
    let creds = good_creds();
    let printed = format!("{creds:?}");
    assert!(!printed.contains(&creds.ltsk), "Debug printed the private key");
    assert!(!printed.contains(&creds.pairing_id), "Debug printed the pairing id");
    assert!(printed.contains("hkp: 3"), "Debug should still carry the HKP type");
}
