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

/// The marketplace review's case (omacom/omarchy-plugin-marketplace#8984): a
/// device at a paired receiver's address that signs with a key our credentials
/// don't name. It must get nothing. Transient pairing is never tried, because
/// its PIN is public and the device would simply accept it; the run ends as
/// `Unverified`, which says how to re-pair or forget.
#[test]
fn credentials_that_dont_verify_end_the_run_and_transient_is_never_tried() {
    let fake = Fake::start(Verify::Stale, Transient::Refused);
    let cfg = fake.config(Some(fake.credentials()));

    let err = airplay_rs::session::run_session_with(&cfg, fake.dial()).err().expect("unverified");
    match &err {
        SessionError::Unverified { host, .. } => assert_eq!(host, "127.0.0.1"),
        other => panic!("expected Unverified, got {other}"),
    }
    let shown = err.to_string();
    assert!(shown.contains("airplay pair 127.0.0.1 --pin CODE"), "says how to re-pair: {shown}");
    assert!(shown.contains("airplay pair 127.0.0.1 --forget"), "says how to forget: {shown}");

    assert_eq!(fake.uris(), vec!["/pair-verify"], "pair-verify, and nothing after it");
    assert_eq!(fake.connections_used(), 1);
}

/// A receiver that answers pair-verify with a HAP error is no better proven,
/// and ends the same way.
#[test]
fn a_receiver_that_errors_on_verify_is_not_trusted_either() {
    let fake = Fake::start(Verify::Error(6), Transient::Unavailable);
    let cfg = fake.config(Some(fake.credentials()));
    let err = airplay_rs::session::run_session_with(&cfg, fake.dial()).err().expect("unverified");
    assert!(matches!(err, SessionError::Unverified { .. }), "got {err}");
    assert_eq!(fake.uris(), vec!["/pair-verify"]);
}

/// Refusing the first connection must not steer the run past verification: a
/// failed connect for pair-verify ends it, rather than moving on to transient
/// on the next connection.
#[test]
fn a_refused_verify_connection_does_not_lead_to_transient() {
    let fake = Fake::start(Verify::Accept, Transient::Refused);
    let cfg = fake.config(Some(fake.credentials()));
    let dial = fake.dial();
    let calls = std::cell::Cell::new(0);
    let flaky = |host: &str| {
        calls.set(calls.get() + 1);
        if calls.get() == 1 {
            Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"))
        } else {
            dial(host)
        }
    };
    let err = airplay_rs::session::run_session_with(&cfg, flaky).err().expect("io");
    assert!(matches!(err, SessionError::Io(_)), "got {err}");
    assert_eq!(calls.get(), 1, "no second connection");
    assert!(fake.uris().is_empty());
}

/// With a code read off the real screen, a receiver that has forgotten us is
/// paired again directly: PIN pair-setup on the next connection, with no
/// transient attempt in between (the old order spent one connection on it).
#[test]
fn a_pin_after_failed_verification_goes_straight_to_pin_pairing() {
    let fake = Fake::start(Verify::Stale, Transient::Unavailable);
    let mut cfg = fake.config(Some(fake.credentials()));
    cfg.pin = Some("1234".into());
    let err = airplay_rs::session::run_session_with(&cfg, fake.dial()).err().expect("setup refused");
    assert!(matches!(err, SessionError::Pair(_)), "got {err}");
    let by_conn = fake.uris_by_conn();
    assert_eq!(by_conn.first().map(|(c, u)| (*c, u.as_str())), Some((0, "/pair-verify")));
    assert_eq!(fake.connections_used(), 2, "verify, then PIN setup, and no transient: {by_conn:?}");
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
