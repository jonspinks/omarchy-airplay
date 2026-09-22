//! The `airplay pair` / `airplay mirror` contract as the user's bar panel sees it:
//! the exact JSON on stdout, nothing else on stdout, the exit codes, and the
//! one stderr line a script is invited to match.
//!
//! These run the real binary. The credential store is redirected with
//! `$AIRPLAY_RS_CREDENTIALS_DIR` **on the child process only**, so this
//! machine's own `~/.config/airplay-rs/credentials` is never read or written.
//!
//! One test needs a receiver on the fixed AirPlay port (7000) because that is
//! what the binary dials; it binds `127.0.0.1:7000` for a moment and takes it
//! down again. The others touch no socket at all, or dial `127.0.0.2`, where
//! nothing is listening.

#[path = "support/fake_pairing_receiver.rs"]
mod fake_pairing;

use fake_pairing::{Fake, Transient, Verify};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_airplay");

/// Serialises the tests that bind the fixed AirPlay port.
static PORT_7000: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "airplay-cli-{}-{tag}-{}",
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

fn run(store: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("AIRPLAY_RS_CREDENTIALS_DIR", store)
        .stdin(Stdio::null())
        .output()
        .expect("the airplay binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// A credential file for `host`, written the way the CLI writes them.
fn plant(store: &Path, host: &str, hkp: u8) {
    use ed25519_dalek::SigningKey;
    let ours = SigningKey::generate(&mut rand::rngs::OsRng);
    let tv = SigningKey::generate(&mut rand::rngs::OsRng);
    let creds = airplay_rs::pairing::Credentials {
        hkp,
        pairing_id: "11111111-2222-3333-4444-555555555555".into(),
        ltsk: hex::encode(ours.to_bytes()),
        tv_id: "AA:BB:CC:DD:EE:FF".into(),
        tv_ltpk: hex::encode(tv.verifying_key().to_bytes()),
        host: None,
    };
    airplay_rs::pairing::store::save_in(store, host, &creds).unwrap();
}

// --------------------------------------------------------------- pair --list

/// The panel asks "which receivers am I paired with" and gets exactly this,
/// byte for byte. No receiver is contacted and no mDNS browse is run, so it is
/// safe to poll.
#[test]
fn pair_list_json_is_one_line_and_holds_no_secrets() {
    let tmp = Tmp::new("list");
    let out = run(tmp.dir(), &["pair", "--list", "--json"]);
    assert!(out.status.success(), "empty store should succeed: {}", stderr(&out));
    assert_eq!(stdout(&out), "{\"paired\":[]}\n");

    plant(tmp.dir(), "192.0.2.187", 3);
    plant(tmp.dir(), "192.0.2.242", 5);
    // A corrupt file is not a paired receiver.
    std::fs::write(tmp.dir().join("10.0.0.9.json"), "{ broken").unwrap();

    let out = run(tmp.dir(), &["pair", "--list", "--json"]);
    assert!(out.status.success());
    assert_eq!(
        stdout(&out),
        "{\"paired\":[{\"host\":\"192.0.2.187\",\"hkp\":3},\
         {\"host\":\"192.0.2.242\",\"hkp\":5}]}\n"
    );
    let text = stdout(&out) + &stderr(&out);
    for secret in ["ltsk", "pairing_id", "tv_ltpk"] {
        assert!(!text.contains(secret), "{secret} leaked into the output: {text}");
    }
}

#[test]
fn pair_list_human_mode_says_where_and_what() {
    let tmp = Tmp::new("list-human");
    let out = run(tmp.dir(), &["pair", "--list"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no stored credentials"), "{}", stdout(&out));

    plant(tmp.dir(), "192.0.2.187", 3);
    let out = run(tmp.dir(), &["pair", "--list"]);
    assert!(stdout(&out).contains("192.0.2.187"), "{}", stdout(&out));
    assert!(stdout(&out).contains("HKP 3"), "{}", stdout(&out));
}

#[test]
fn forget_removes_a_hosts_credentials() {
    let tmp = Tmp::new("forget");
    plant(tmp.dir(), "192.0.2.187", 3);
    let out = run(tmp.dir(), &["pair", "192.0.2.187", "--forget"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&run(tmp.dir(), &["pair", "--list", "--json"])), "{\"paired\":[]}\n");
}

// ------------------------------------------------------------ pair failures

/// A receiver that cannot be reached is `network`, never `bad_pin`: the panel
/// must not put a code box in front of someone whose TV is off.
#[test]
fn an_unreachable_receiver_is_reported_as_network_in_json_and_exits_1() {
    let tmp = Tmp::new("unreachable");
    // 127.0.0.2 is local and listening on nothing: connection refused, fast.
    let out = run(tmp.dir(), &["pair", "127.0.0.2", "--pin", "1234", "--json"]);
    assert_eq!(out.status.code(), Some(1), "ok:false still exits non-zero");

    let doc: serde_json::Value = serde_json::from_str(stdout(&out).trim())
        .unwrap_or_else(|e| panic!("stdout is not one JSON object ({e}): {:?}", stdout(&out)));
    assert_eq!(doc["ok"], serde_json::json!(false));
    assert_eq!(doc["reason"], serde_json::json!("network"));
    assert_eq!(doc["host"], serde_json::json!("127.0.0.2"));
    assert!(doc["error"].as_str().is_some_and(|s| !s.is_empty()));
    // Exactly one object, and nothing else, on stdout.
    assert_eq!(stdout(&out).lines().count(), 1, "stdout: {:?}", stdout(&out));
}

#[test]
fn a_bad_flag_is_caught_at_the_keyboard() {
    let tmp = Tmp::new("badflag");
    let out = run(tmp.dir(), &["pair", "192.0.2.187", "--pim", "1234"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("unknown flag --pim"), "{}", stderr(&out));
    assert!(stdout(&out).is_empty(), "nothing should reach stdout: {:?}", stdout(&out));

    let out = run(tmp.dir(), &["pair"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("missing <ip>"), "{}", stderr(&out));

    let out = run(tmp.dir(), &["pair", "1.2.3.4", "--hkp", "9"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--hkp must be 3"), "{}", stderr(&out));
}

/// `pair <ip> --json` with no `--pin` wakes the receiver's screen and stops
/// there: one request, one JSON object, no pair-setup started.
///
/// It is kept for compatibility and for waking the screen, NOT as the first
/// half of a pairing — the Frame issues a fresh code for the next pair-setup,
/// so the number this puts up cannot be submitted by a later process. The
/// warning to that effect is part of the contract here.
#[test]
fn pair_json_without_a_pin_asks_the_receiver_to_show_its_code() {
    let _guard = PORT_7000.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = Tmp::new("prompt");
    let fake = Fake::start_on(7000, Verify::Accept, Transient::Refused);

    let out = run(tmp.dir(), &["pair", "127.0.0.1", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(stdout(&out).trim())
        .unwrap_or_else(|e| panic!("stdout is not one JSON object ({e}): {:?}", stdout(&out)));
    assert_eq!(doc["ok"], serde_json::json!(true));
    assert_eq!(doc["prompt_shown"], serde_json::json!(true));
    assert_eq!(doc["host"], serde_json::json!("127.0.0.1"));
    // Nothing claims a pairing happened.
    assert!(doc.get("paired").is_none(), "a prompt is not a pairing: {doc}");
    assert_eq!(stdout(&out).lines().count(), 1);

    // Exactly one request, and no pair-setup left half-open on the receiver.
    assert_eq!(fake.uris(), vec!["/pair-pin-start"]);
    assert!(
        stderr(&out).contains("--interactive"),
        "it must warn that a later --pin call gets a new code: {}",
        stderr(&out)
    );

    // `--show-code` is the same thing for a human.
    let out = run(tmp.dir(), &["pair", "127.0.0.1", "--show-code"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("show its AirPlay code"),
        "stdout: {}",
        stdout(&out)
    );
    assert_eq!(fake.uris().len(), 2);
}

// ---------------------------------------------------------- pair --interactive

/// What the panel does with the child's stdin once the prompt line arrives.
enum Input<'a> {
    /// Write these digits and a newline.
    Code(&'a str),
    /// Close it — the documented cancel.
    Close,
    /// Hold it open and type nothing, so the deadline is what ends the run.
    Hold,
}

/// Drive `pair --interactive --json` the way the panel will: read the first
/// line, THEN act on stdin, then read the second line. Returns
/// (prompt line, final line, exit status).
fn drive_interactive(
    store: &Path,
    args: &[&str],
    input: Input<'_>,
) -> (String, String, std::process::ExitStatus) {
    use std::io::{BufRead, BufReader, Write};
    let mut child = Command::new(BIN)
        .args(args)
        .env("AIRPLAY_RS_CREDENTIALS_DIR", store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the airplay binary runs");

    let mut out = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut first = String::new();
    out.read_line(&mut first).expect("a first line");

    // Only now does the code go in: if the binary had buffered its prompt
    // until exit, the read above would have blocked for ever and this test
    // would hang rather than quietly pass.
    // Held across the second read, so `Hold` really does leave the pipe open
    // for the whole wait rather than closing it at the end of this match.
    let mut held = None;
    match input {
        Input::Code(c) => {
            let mut stdin = child.stdin.take().expect("piped stdin");
            writeln!(stdin, "{c}").expect("write the code");
            stdin.flush().unwrap();
        }
        // Dropping stdin closes it, which is the documented cancel.
        Input::Close => drop(child.stdin.take()),
        Input::Hold => held = child.stdin.take(),
    }

    let mut second = String::new();
    out.read_line(&mut second).expect("a second line");
    drop(held);
    let status = child.wait().expect("the child exits");
    (first, second, status)
}

/// The fix for the two-step flow the Frame refused: one process, one
/// connection, the human in the middle. The prompt line must arrive BEFORE the
/// code is typed — which this test enforces by not typing until it has read it.
#[test]
fn interactive_emits_the_prompt_before_it_reads_and_stays_on_one_connection() {
    let _guard = PORT_7000.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = Tmp::new("interactive");
    let fake = Fake::start_on(7000, Verify::Accept, Transient::Refused);

    let (first, second, status) = drive_interactive(
        tmp.dir(),
        &["pair", "127.0.0.1", "--interactive", "--json", "--timeout", "20"],
        Input::Code("1878"),
    );

    let prompt: serde_json::Value = serde_json::from_str(first.trim())
        .unwrap_or_else(|e| panic!("first line is not JSON ({e}): {first:?}"));
    assert_eq!(prompt["ok"], serde_json::json!(true));
    assert_eq!(prompt["prompt_shown"], serde_json::json!(true));
    assert_eq!(prompt["host"], serde_json::json!("127.0.0.1"));

    // The fake cannot know the code (its SRP server is not real), so the only
    // possible outcome is a refusal — which is the shape a wrong code has.
    let done: serde_json::Value = serde_json::from_str(second.trim())
        .unwrap_or_else(|e| panic!("second line is not JSON ({e}): {second:?}"));
    assert_eq!(done["ok"], serde_json::json!(false));
    assert_eq!(done["reason"], serde_json::json!("bad_pin"));
    assert!(
        done["error"].as_str().is_some_and(|s| s.contains("--interactive")),
        "a refusal should point at running it again: {done}"
    );
    assert_eq!(status.code(), Some(1));

    // THE point of the exercise: pin-start, M1 and M3 all on ONE connection.
    let by_conn = fake.uris_by_conn();
    assert_eq!(
        by_conn,
        vec![
            (0, "/pair-pin-start".to_string()),
            (0, "/pair-setup".to_string()),
            (0, "/pair-setup".to_string()),
        ],
        "the whole exchange must stay on one connection: {by_conn:?}"
    );
    assert_eq!(fake.connections_used(), 1);
}

/// Giving up must cost nothing. A timeout, and a closed stdin, both end the
/// run without sending M3 — so none of the receiver's small allowance of
/// attempts is spent on someone who walked away.
#[test]
fn interactive_giving_up_sends_no_proof() {
    let _guard = PORT_7000.lock().unwrap_or_else(|p| p.into_inner());

    // (a) nobody types: the deadline ends it.
    let tmp = Tmp::new("timeout");
    let fake = Fake::start_on(7000, Verify::Accept, Transient::Refused);
    let (first, second, status) = drive_interactive(
        tmp.dir(),
        // A short deadline: the behaviour is the same at 120 s, and a test
        // must not sit for two minutes to prove it.
        &["pair", "127.0.0.1", "--interactive", "--json", "--timeout", "1"],
        // stdin stays OPEN and empty: only the deadline can end this.
        Input::Hold,
    );
    assert!(first.contains("prompt_shown"), "{first:?}");
    let done: serde_json::Value = serde_json::from_str(second.trim()).expect("JSON");
    assert_eq!(done["ok"], serde_json::json!(false));
    assert_eq!(done["reason"], serde_json::json!("other"));
    assert!(
        done["error"].as_str().is_some_and(|s| s.contains("nothing was typed within")),
        "a timeout should say so: {done}"
    );
    assert_eq!(status.code(), Some(1));
    // pin-start and M1 went out; M3 did NOT.
    assert_eq!(
        fake.uris(),
        vec!["/pair-pin-start", "/pair-setup"],
        "no proof may be sent when nobody typed"
    );
    drop(fake);

    // (b) the UI withdraws the prompt by closing stdin.
    let tmp = Tmp::new("cancel");
    let fake = Fake::start_on(7000, Verify::Accept, Transient::Refused);
    let (first, second, status) = drive_interactive(
        tmp.dir(),
        &["pair", "127.0.0.1", "--interactive", "--json", "--timeout", "20"],
        Input::Close,
    );
    assert!(first.contains("prompt_shown"), "{first:?}");
    let done: serde_json::Value = serde_json::from_str(second.trim()).expect("JSON");
    assert_eq!(done["ok"], serde_json::json!(false));
    assert_eq!(done["reason"], serde_json::json!("other"));
    assert!(
        done["error"].as_str().is_some_and(|s| s.contains("stdin closed")),
        "cancel should say so: {done}"
    );
    assert_eq!(status.code(), Some(1));
    assert_eq!(fake.uris(), vec!["/pair-pin-start", "/pair-setup"]);
}

/// A bare `pair <ip>` — a person at a terminal, no code in hand — is the same
/// single-connection flow, prompting on stderr instead of emitting JSON. One
/// implementation, not two that can drift.
#[test]
fn a_bare_pair_prompts_on_stderr_and_uses_the_same_one_connection_flow() {
    let _guard = PORT_7000.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = Tmp::new("bare");
    let fake = Fake::start_on(7000, Verify::Accept, Transient::Refused);

    let mut child = Command::new(BIN)
        .args(["pair", "127.0.0.1", "--timeout", "1"])
        .env("AIRPLAY_RS_CREDENTIALS_DIR", tmp.dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the airplay binary runs");
    // Nothing is typed; the deadline ends it.
    let held = child.stdin.take();
    let out = child.wait_with_output().expect("the child exits");
    drop(held);

    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("Enter the code shown on 127.0.0.1's screen"),
        "the human prompt is missing: {err}"
    );
    assert!(err.contains("no AirPlay code was entered"), "{err}");
    assert_eq!(out.status.code(), Some(1));
    // Same shape as --interactive: one connection, and no proof sent.
    assert_eq!(fake.connections_used(), 1);
    assert_eq!(fake.uris(), vec!["/pair-pin-start", "/pair-setup"]);
}

/// A receiver that cannot be reached at all produces ONE line — the failure —
/// and no prompt line, because nothing was ever put on a screen.
#[test]
fn interactive_failing_before_the_prompt_emits_only_the_failure() {
    let tmp = Tmp::new("interactive-network");
    let out = run(tmp.dir(), &["pair", "127.0.0.2", "--interactive", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out).lines().count(), 1, "stdout: {:?}", stdout(&out));
    let doc: serde_json::Value = serde_json::from_str(stdout(&out).trim()).expect("JSON");
    assert_eq!(doc["ok"], serde_json::json!(false));
    assert_eq!(doc["reason"], serde_json::json!("network"));
}

#[test]
fn interactive_refuses_the_flags_it_cannot_honour() {
    let tmp = Tmp::new("interactive-flags");
    for extra in [
        vec!["--pin", "1878"],
        vec!["--show-code"],
        vec!["--forget"],
    ] {
        let mut args = vec!["pair", "127.0.0.1", "--interactive"];
        args.extend(extra.iter().copied());
        let out = run(tmp.dir(), &args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&out).contains("cannot be combined"),
            "{args:?} -> {}",
            stderr(&out)
        );
    }
    let out = run(tmp.dir(), &["pair", "127.0.0.1", "--interactive", "--timeout", "0"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--timeout must be"), "{}", stderr(&out));
}

// ------------------------------------------------------------ the exit code

/// The point of the exercise: a receiver that wants a code from its screen is
/// a DIFFERENT failure from every other failure, and `mirror` says so with a
/// distinct exit status and one matchable line.
#[test]
fn mirror_against_a_receiver_that_wants_a_code_exits_4_with_the_documented_line() {
    let _guard = PORT_7000.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = Tmp::new("needscode");
    // No credentials in the store: straight to transient, which this receiver
    // refuses as an authentication failure.
    let fake = Fake::start_on(7000, Verify::Accept, Transient::Refused);
    assert_eq!(fake.port, 7000);

    let out = run(
        tmp.dir(),
        &["mirror", "127.0.0.1", "--test-pattern", "--seconds", "1"],
    );
    assert_eq!(
        out.status.code(),
        Some(4),
        "expected the needs-a-code exit code.\nstdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).lines().any(|l| l
            == "error: this receiver needs an AirPlay code (run: airplay pair 127.0.0.1 --pin CODE)"),
        "the documented line is missing from stderr:\n{}",
        stderr(&out)
    );
    // It got there by trying transient, having nothing better.
    assert_eq!(fake.uris(), vec!["/pair-pin-start", "/pair-setup"]);
}

/// And with credentials on disk, `mirror` spends them: pair-verify first, no
/// `/pair-pin-start`, so nothing appears on the receiver's screen. (The run
/// then stops at the fake's 503 on `/info`, which is a plain exit 1 — not the
/// needs-a-code code.)
#[test]
fn mirror_uses_stored_credentials_before_transient() {
    let _guard = PORT_7000.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = Tmp::new("uses-creds");
    let fake = Fake::start_on(7000, Verify::Accept, Transient::Refused);
    let creds = fake.credentials();
    airplay_rs::pairing::store::save_in(tmp.dir(), "127.0.0.1", &creds).unwrap();

    let out = run(
        tmp.dir(),
        &["mirror", "127.0.0.1", "--test-pattern", "--seconds", "1"],
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("pairing with stored credentials for 127.0.0.1"),
        "the run should say it is using them:\n{}",
        stderr(&out)
    );
    let uris = fake.uris();
    assert_eq!(
        uris,
        vec!["/pair-verify", "/pair-verify", "/info"],
        "the binary must not fall back to transient when the credentials work: {uris:?}"
    );
}

/// A corrupt file is not a session-killer: it is reported and the run carries
/// on to transient pairing.
#[test]
fn mirror_with_a_corrupt_credential_file_says_so_and_falls_back() {
    let _guard = PORT_7000.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = Tmp::new("corrupt");
    std::fs::write(tmp.dir().join("127.0.0.1.json"), "{\"hkp\":3,\"pair").unwrap();
    let fake = Fake::start_on(7000, Verify::Accept, Transient::Refused);

    let out = run(
        tmp.dir(),
        &["mirror", "127.0.0.1", "--test-pattern", "--seconds", "1"],
    );
    assert!(
        stderr(&out).contains("stored credentials unusable"),
        "the corruption should be named, not swallowed:\n{}",
        stderr(&out)
    );
    // It fell back to transient rather than dying on the bad file.
    assert_eq!(fake.uris(), vec!["/pair-pin-start", "/pair-setup"]);
    assert_eq!(out.status.code(), Some(4), "and then reported the real problem");
}
