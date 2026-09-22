//! `run_session`'s pairing ladder, against the fake pairing receiver on
//! 127.0.0.1 (tests/support/fake_pairing_receiver.rs): stored credentials
//! first, transient second, and the one refusal that means "the code is on my
//! screen" reported as itself rather than as a shrug.
//!
//! Nothing binds port 7000 and nothing leaves the loopback interface: the
//! dialler is injected through `run_session_with`.

#[path = "support/fake_pairing_receiver.rs"]
mod fake_pairing;

use airplay_rs::session::{PairingMethod, SessionError};
use fake_pairing::{Fake, Transient, Verify};
use std::time::Duration;

// ------------------------------------------------------------------- tests

/// The gap this closes: credentials on disk are SPENT. Pair-verify is tried
/// first, transient is never reached, and the session gets far enough to send
/// an encrypted request the receiver can read — which is only possible if both
/// ends derived the same secret.
#[test]
fn stored_credentials_are_used_and_transient_is_never_tried() {
    let fake = Fake::start(Verify::Accept, Transient::Refused);
    let creds = fake.credentials();
    let cfg = fake.config(Some(creds));

    let err = airplay_rs::session::run_session_with(&cfg, fake.dial()).err().expect("503 on /info");
    match err {
        SessionError::Status(what, 503) => assert_eq!(what, "encrypted GET /info"),
        other => panic!("expected the session to reach the encrypted GET /info, got {other}"),
    }

    let uris = fake.uris();
    assert_eq!(
        uris,
        vec!["/pair-verify", "/pair-verify", "/info"],
        "pair-verify M1/M3 then the encrypted control request, and nothing else"
    );
    assert!(
        !uris.iter().any(|u| u == "/pair-pin-start" || u == "/pair-setup"),
        "transient pairing must not be attempted when credentials work: {uris:?}"
    );
    assert_eq!(PairingMethod::Verified.as_str(), "verified");
}

/// Credentials the receiver rejects are not fatal: the run falls back to
/// transient, in that order, on a fresh connection.
#[test]
fn stale_credentials_fall_back_to_transient() {
    let fake = Fake::start(Verify::Stale, Transient::Unavailable);
    let cfg = fake.config(Some(fake.credentials()));

    let err = airplay_rs::session::run_session_with(&cfg, fake.dial()).err().expect("both refused");
    // Unavailable is NOT a missing code, so it stays a plain pairing failure.
    match err {
        SessionError::Pair(e) => assert!(
            e.to_string().contains("Unavailable"),
            "expected the transient refusal to be reported, got {e}"
        ),
        other => panic!("expected a pairing error, got {other}"),
    }

    let uris = fake.uris();
    assert_eq!(
        uris,
        vec!["/pair-verify", "/pair-pin-start", "/pair-setup"],
        "verify is tried first, then transient: {uris:?}"
    );
}

/// A receiver that answers pair-verify with a HAP error — another way to be
/// forgotten — takes the same fall-back.
#[test]
fn a_receiver_that_errors_on_verify_falls_back_too() {
    let fake = Fake::start(Verify::Error(6), Transient::Unavailable);
    let cfg = fake.config(Some(fake.credentials()));
    let err = airplay_rs::session::run_session_with(&cfg, fake.dial()).err().expect("both refused");
    assert!(matches!(err, SessionError::Pair(_)), "got {err}");
    assert_eq!(fake.uris(), vec!["/pair-verify", "/pair-pin-start", "/pair-setup"]);
}

/// The distinct failure the panel needs: transient refused as an
/// authentication failure means the code is on the TV's screen, and says so in
/// those words — with the command to run in it.
#[test]
fn a_receiver_that_wants_a_code_says_so_in_its_own_error() {
    let fake = Fake::start(Verify::Accept, Transient::Refused);
    // No credentials at all: the state a first-ever session is in.
    let cfg = fake.config(None);

    let err = airplay_rs::session::run_session_with(&cfg, fake.dial()).err().expect("refused");
    match &err {
        SessionError::NeedsCode { host, detail } => {
            assert_eq!(host, "127.0.0.1");
            assert!(detail.contains("Authentication"), "detail should carry the HAP reason: {detail}");
        }
        other => panic!("expected NeedsCode, got {other}"),
    }
    // The message a script is invited to match.
    let shown = err.to_string();
    assert!(
        shown.starts_with("this receiver needs an AirPlay code (run: airplay pair 127.0.0.1 --pin CODE)"),
        "wrong headline: {shown}"
    );

    // With no credentials nothing is verified: straight to transient.
    assert_eq!(fake.uris(), vec!["/pair-pin-start", "/pair-setup"]);
}

/// The other half of the distinction: a receiver that is merely unwell must
/// NOT be reported as wanting a code, or the user is sent to stare at a TV
/// showing nothing.
#[test]
fn an_unwell_receiver_is_not_reported_as_wanting_a_code() {
    let fake = Fake::start(Verify::Accept, Transient::Unavailable);
    let cfg = fake.config(None);
    let err = airplay_rs::session::run_session_with(&cfg, fake.dial()).err().expect("refused");
    assert!(
        !matches!(err, SessionError::NeedsCode { .. }),
        "Unavailable must not be dressed up as a missing code"
    );
}

/// `request_code` is one request and stops there: it wakes the screen without
/// starting an SRP exchange, so nothing is left half-finished on the receiver.
/// (It cannot be used to prompt for a code a LATER process will submit — the
/// receiver issues a fresh one per pair-setup. That is what
/// `pair --interactive` is for.)
#[test]
fn asking_for_the_code_sends_exactly_one_request() {
    let fake = Fake::start(Verify::Accept, Transient::Refused);
    let mut conn = (fake.dial())("127.0.0.1").unwrap();
    airplay_rs::pairing::request_code(&mut conn, airplay_rs::pairing::HKP_PIN).unwrap();
    // Give the fake's thread a moment to log it.
    for _ in 0..50 {
        if !fake.uris().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fake.uris(), vec!["/pair-pin-start"]);
}
