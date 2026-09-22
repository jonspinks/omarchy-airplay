//! `airplay` CLI. Commands:
//!   airplay discover [pattern] [--json] [--timeout SECONDS]
//!   airplay status [--json]
//!   airplay pair <ip> [--pin CODE] [--name NAME]   (PIN pair-setup, persists creds)
//!   airplay mirror <ip> --output eDP-1 | --window TEXT | --extend [NAME] | --test-pattern
//!   airplay mirror-bench [--output eDP-1] [--out FILE.h264]   (no receiver needed)
//!   airplay extend [--status|--cleanup]            (the Extend output escape hatch)
//!   airplay capture-list
//!   airplay capture-bench [output:eDP-1|window:TEXT] [--seconds N]
//!   airplay encode-bench  [--encoder cpu|gpu] [--frames N] ...
//!
//! Discovery and the on-wire behaviour are ported from the reference probe; the
//! mirror path brings up an encrypted control session, negotiates the type-110
//! video stream, and streams an ffmpeg-generated test pattern over the data
//! channel with the 128-byte mirror headers + ChaCha20-Poly1305.
//!
//! `encode-bench` is the encoder layer's offline gate: synthetic BGR0 frames in,
//! Annex-B access units out, every count exact and no receiver involved.

use std::process::ExitCode;

fn usage() -> &'static str {
    "\
airplay — Rust AirPlay session-core CLI

USAGE:
    airplay discover [pattern] [--json] [--timeout SECONDS]
    airplay status [--json]
    airplay pair <ip> [--pin CODE] [--name NAME] [--hkp 3|5] [--json]
    airplay pair <ip> --interactive [--json] [--timeout SECONDS]
    airplay pair <ip> --show-code [--json]
    airplay pair --list [--json]
    airplay pair <ip> --forget [--json]
    airplay mirror <ip> --output NAME  [--seconds N] [--fps N] [--encoder gpu|cpu]
    airplay mirror <ip> --window TEXT  [--qp N] [--keyint SEC] [--no-cursors]
                                       [--zero-copy auto|on|off]
                                       [--sps-zero-constraints] [--device NODE]
                                       [--keepalive MS]
    airplay mirror <ip> --extend [NAME] [--seconds N] [--fps N] ...   (second desktop)
    airplay mirror <ip> --test-pattern [--seconds N] [--fps N]
    airplay mirror <ip> ... [--audio none|system|tone] [--no-audio]
                            [--audio-capture sink|pipewire|parec] [--audio-latency MS]
                            [--av-offset MS] [--no-volume-sync]
    airplay mirror-bench [--output NAME|--window TEXT|--extend [NAME]] [--receiver WxH]
                         [--seconds N]
                         [--fps N] [--encoder gpu|cpu] [--qp N] [--keyint SEC]
                         [--no-cursors] [--sps-zero-constraints] [--out FILE.h264]
                         [--keepalive MS]
    airplay extend [--status|--cleanup]
    airplay audio  [--status|--cleanup]
    airplay capture-list
    airplay capture-bench [output:NAME|window:TEXT] [--seconds N] [--keepalive MS]
                          [--zero-copy auto|on|off]
                          [--no-cursors] [--dump FILE.ppm]
    airplay encode-bench  [--encoder cpu|gpu] [--source WxH] [--receiver WxH]
                          [--frames N] [--fps N] [--qp N] [--keyint SEC]
                          [--slices N] [--device NODE] [--no-probe] [--out FILE.h264]

NOTES:
    --seconds 0 means RUN UNTIL STOPPED, on every mirror source mode and on
    mirror-bench and capture-bench: the run ends on SIGINT/SIGTERM/SIGHUP, on
    the receiver going away, or on a fatal error, and prints the same full
    ledger it prints for a run whose clock ran out. Leaving --seconds out keeps
    the default (30 s for mirror), and a NEGATIVE --seconds is an error rather
    than a second spelling of 0.

    discover --json prints ONE JSON object on stdout and nothing else —
    {\"receivers\":[{\"name\":…,\"host\":…,\"port\":…,\"model\":…,\"srcvers\":…}]} — with
    model and srcvers omitted entirely when the receiver does not advertise
    them. Diagnostics go to stderr. --timeout bounds the mDNS browse (default
    5 s) so a UI can do a fast first scan and a longer one on demand.

    status [--json] answers \"what is running right now\", read-only, for a panel
    to poll: {\"session\":{\"kind\":…,\"receiver\":…,\"name\":…,\"workspace\":…,
    \"pid\":…},\"orphan\":null}, where session is null when nothing is running and
    orphan is non-null when an Extend output's owner is dead but its output is
    still up (the case `extend --cleanup` fixes). kind is extend, output,
    window or test-pattern. It takes no lock and writes nothing, so polling it
    every couple of seconds cannot disturb a live session.

    mirror --output/--window streams the LIVE screen: wayland capture on its own
    thread, h264 hardware encode fitted to the receiver's /info display, over the
    same mirror data channel the test pattern uses. --test-pattern is kept as the
    known-good control.

    mirror-bench runs the identical capture -> encode -> MirrorStreamer path with
    no receiver, so the join can be checked (and a decodable .h264 written out)
    without touching the TV.

    --sps-zero-constraints zeroes the SPS constraint_set byte, turning the codec
    string avc1.640c2a into avc1.64002a. Try it if the TV renders black.

    --extend creates a Hyprland headless output placed to the right of your
    panel and mirrors THAT, so the TV is a second desktop rather than a copy of
    your screen. Drag a window onto it, or move the mouse right off your panel.
    Unlike a shared single window, a window on a real output keeps rendering when
    its workspace is hidden. The output is created at the receiver's own size so
    the desktop is encoded 1:1 with no scaling, and is removed again when the run
    ends or fails. A window still on it comes back to your panel on a new
    workspace, and the Omarchy bar and wallpaper render on the TV too.

    A bare --extend APPENDS: the TV takes the workspace one past the greater of
    your highest in-use workspace and the five buttons the Omarchy bar always
    draws. So workspaces 1, 2, 4, 6 give workspace 7, and 1, 2, 4 give 6 — not
    5, because 5 is one of those five permanent slots and landing there would
    put the TV inside the default range instead of after it. Either way it is
    the LAST button on the bar. (Left to itself Hyprland hands a new output the
    lowest free id — 3 in both cases — wedging the TV into the middle of your
    set, which is what made the bar's screen selector ambiguous.) The output is
    named after its workspace, AIRPLAY-<N>, because the workspace rule that pins
    N cannot be cleared while Hyprland is up, so the name has to vary with it.

    Omarchy's bar only renders workspace ids 1-10. If 6-10 are all in use the TV
    falls back to the highest free id at or below 5 and says so, since a visible
    button that is not last still beats no button. If all ten are in use
    --extend stops rather than putting the TV where the bar cannot draw it:
    close the windows on one workspace and try again.

    --extend NAME still takes an explicit AIRPLAY-… name, and then the name is
    the request: AIRPLAY-7 asks for workspace 7. If workspace 7 is IN USE the
    run is REFUSED rather than reinterpreted — pinning it would carry those
    windows onto the TV, and quietly not pinning it is no safer (see below). Use
    a bare --extend, which picks a free workspace for you, or name a free id. An
    id above 10 is honoured if free, with a warning that it gets no bar button.

    Prefer a bare --extend. Letting Hyprland choose is not neutral: it remembers
    which workspace an output NAME last displayed and restores that pairing when
    the name comes back, so a name with no number in it — AIRPLAY-tv — can pull
    a workspace you are now using, windows and all, onto the TV for the length
    of the run. That form still works, and warns; the windows return when the
    output is removed. A bare --extend avoids it entirely by claiming a free
    workspace up front.

    Ctrl-C is the normal way to end an --extend run: SIGINT, SIGTERM and SIGHUP
    stop the stream, print the full ledger, close the session and remove the
    output, exiting 0. Press Ctrl-C a SECOND time and the process dies on the
    spot instead (so it can never appear to ignore you during pairing or
    bring-up, which do not poll the flag) — that one, and a SIGKILL or a crash,
    leaves the output behind. `airplay extend --cleanup` removes it, the next
    --extend run reclaims it automatically, and `airplay extend --status` shows
    whether one is outstanding. An output this program did not create is never
    removed by any of those paths.

    --audio system sends the laptop's system audio to the TV with the video
    (ALAC 44.1 kHz stereo, encrypted); --audio tone sends the probe's 880 Hz
    beep instead. The DEFAULT IS --audio none (--no-audio is the same): with
    audio on the session moves the TV's volume, and the Rust audio path has
    not yet been checked on the TV. --audio-latency MS (default 300) is what the
    TV is told to buffer; 85 ms broke up on Wi-Fi, 300 is proven clean, and
    below 300 is unproven (warned). --av-offset MS (-100..1500) is ADDED to
    that latency to delay audio against video. It is UNCALIBRATED: this Frame
    ignores video timestamps and adds ~400 ms of its own, so the right value
    can only be measured on the TV; the per-model default is 0.

    --audio-capture picks where those samples come from, and it decides
    whether the sound still plays on the laptop:

      sink      (DEFAULT) The sender publishes its OWN PipeWire sink, named
                after the receiver — `AirPlay: 75\" The Frame` — and the
                laptop's output moves to it, so the sound goes to the TV
                INSTEAD OF the speakers, as on a Mac. The previous output
                comes back when the run ends. The handover waits for the TV's
                volume to be established, so the speakers keep playing right
                up to the moment the TV starts making sound, and if the TV's
                volume can never be set the output is never taken at all. The
                volume keys drive that sink and the sender maps it to the
                TV's dB; samples are taken BEFORE the sink's own volume, so
                the level is applied exactly once, at the TV — which means
                that slider has no local effect. The sink node is owned by
                this process: kill it and the node is gone. Only the
                REMEMBERED default outlives a kill, and `airplay audio
                --cleanup` puts that right.
      pipewire  The DEFAULT sink's monitor: the sound plays on the laptop AND
                on the TV, slightly out of step. Nothing is published and the
                laptop's output is not touched. This is the one way to hear
                the TV's delay in the room, and the path with the most
                mileage — use it if sink mode misbehaves.
      parec     `parec -d @DEFAULT_MONITOR@`, the fallback the probe proved.

    Sink mode does not take that path blind: it reads `monitor.channel-volumes`
    back off the node and requires an explicit `false` — an unknown, or a
    host-side rule that overrode what we asked for, falls back to pipewire
    rather than ship audio that is quietly attenuated twice. (The read-back is
    of the property list we supplied, so it proves nothing was overridden, not
    that PipeWire honoured it; that proof is behavioural and lives in the
    hardware-gated tests.) The same fallback covers a sink that cannot be
    published at all. `airplay status --json` reports the capture that actually
    opened, not the one asked for.

    airplay audio --status shows whether a crashed sender left the output
    configured for a sink that no longer exists, and --cleanup puts the
    previous output back. Neither touches a sink this program did not publish.
    Unlike --extend there is nothing visible to clean up: the node itself dies
    with its process, so the only rot is the remembered default.

    With audio on, the TV takes the laptop's volume at session start (linear:
    -30 dB + 30 dB x laptop %, a muted or 0 % laptop sends mute, 100 % sends
    0 dB = AirPlay MAX), then the laptop volume keys drive the TV and the TV
    remote moves the laptop slider. Until that start volume has been set and
    read back, the TV is sent digital silence; if it cannot be set, the audio
    stays silent for the whole session. --no-volume-sync turns all of that off:
    no volume is sent, and audio PLAYS AT THE TV'S OWN VOLUME, which can be its
    maximum. It cannot be combined with `--audio-capture sink` — that pair
    leaves nothing anywhere that can turn the sound down, and no cue in the
    room, so the run says so and uses the pipewire capture instead (the laptop
    keeps its output, and its own level still applies).

    pair persists long-term credentials to a plain JSON file under
    $XDG_CONFIG_HOME/airplay-rs/credentials (secure storage via gnome-keyring is
    the daemon's job, not this CLI's). The directory is 0700 and each file 0600,
    enforced on write and repaired on read. $AIRPLAY_RS_CREDENTIALS_DIR moves
    the whole store.

    mirror USES them: when a file exists for the receiver, the session pairs
    with pair-verify instead of transient pairing, so a receiver set to ask for
    an AirPlay code stops asking on every session. Credentials that do not
    verify — stale, corrupt, or a TV that has been reset — are reported on
    stderr and the run falls back to transient pairing rather than failing.

    If transient pairing is then refused in the way that means \"this receiver
    wants the code off its screen\", mirror exits 4 (not 1) and prints exactly:

        error: this receiver needs an AirPlay code (run: airplay pair <ip> --pin CODE)

    so a panel can offer the code box instead of a shrug. Any other failure is
    still exit 1.

    pair --json prints ONE JSON object on stdout and nothing else; every
    diagnostic, including the saved-to path, goes to stderr:

      pair <ip> --pin CODE --json  -> {\"ok\":true,\"paired\":true,\"host\":…,\"name\":…}
                                      One shot, for a code you already have.

      pair <ip> --interactive --json
                                   -> TWO lines, each flushed as it is written:
                                      {\"ok\":true,\"prompt_shown\":true,…} the
                                      instant it starts waiting, then
                                      {\"ok\":true,\"paired\":true,…} or a failure
                                      object. Write the 4 digits and a newline
                                      to its STDIN after the first line; an
                                      empty line, or closing stdin, cancels
                                      without spending one of the receiver's
                                      pairing attempts. --timeout SECONDS
                                      (default 120) bounds the wait.

                                      THIS is the flow a UI wants. The code
                                      CANNOT be fetched by one command and
                                      submitted by another: pair-setup state
                                      belongs to the connection, and a receiver
                                      issues a FRESH code for each new
                                      pair-setup, so the number a separate
                                      `--show-code` put on screen is already
                                      spent. (Proven on the Frame: 1878 shown,
                                      then refused with HAP error 2 by a second
                                      process.) One attempt per run — if the
                                      code is refused, run it again and use the
                                      NEW number.

      pair <ip> --show-code [--json]
                                   -> {\"ok\":true,\"prompt_shown\":true,…} — wakes
                                      the screen and stops. Useful only to
                                      make the code appear; see above for why
                                      it cannot be completed by a later call.
                                      A bare `pair <ip> --json` with no --pin
                                      does the same, for compatibility.
      failure                      -> {\"ok\":false,\"error\":…,\"reason\":…,\"host\":…}
                                      reason is bad_pin (the code was rejected),
                                      no_prompt (the receiver would not show
                                      one), network (it could not be reached)
                                      or other — which also covers giving up
                                      (timeout, cancel, closed stdin) in
                                      --interactive. Exit is 0 for ok:true and
                                      1 for ok:false — the JSON is the answer,
                                      the status is only a shell's courtesy.

      pair --list [--json]         -> {\"paired\":[{\"host\":…,\"hkp\":…}]} — which
                                      receivers we hold credentials for, so a
                                      panel can show \"paired\" against one. It
                                      reads only the store: no mDNS browse, no
                                      receiver contacted, safe to poll. Files
                                      that do not load are not listed.
      pair <ip> --forget [--json]  -> deletes that host's credentials.

    NOTE: `airplay status --json` is UNCHANGED — its bytes are a pinned
    contract and the paired list lives in `pair --list --json` instead.

    Without --pin and without --json, pair reads the code from the terminal on
    one held-open connection — the same flow as --interactive, prompting on
    stderr instead of emitting JSON.

    Secrets never reach stdout, stderr or the JSON: the stored `ltsk` is a
    private key, and the only credential fact any of them carry is the HKP type.
"
}

fn main() -> ExitCode {
    // FIRST, before anything that could allocate a guard. SIGINT/SIGTERM/SIGHUP
    // become a flag the streaming loops poll, so an interrupted run returns
    // through its destructors — which is the only reason `--extend` can promise
    // to remove its output on Ctrl-C. A failure to install is worth saying out
    // loud but not worth refusing to run over: the fallback is exactly the old
    // behaviour, plus `airplay extend --cleanup`.
    //
    // Do NOT add `std::process::exit` anywhere in this file. It runs no
    // destructors and would silently disable the whole guard layer; `main`
    // returns `ExitCode` for precisely that reason.
    if let Err(e) = airplay_rs::signals::install() {
        eprintln!("warning: could not install signal handlers ({e}); Ctrl-C will kill the \
                   process outright and `airplay extend --cleanup` may be needed");
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match args.first() {
        Some(c) => c.as_str(),
        None => {
            eprint!("{}", usage());
            return ExitCode::FAILURE;
        }
    };

    let rest = &args[1..];
    let result: anyhow::Result<()> = match cmd {
        // Not `rest.first()`: the first argument can now be a flag
        // (`discover --json`), and taking it as the name pattern would silently
        // match nothing.
        "discover" => cmd_discover(rest),
        "status" => cmd_status(rest),
        // No positional check here: `pair --list` and `pair --help`-shaped
        // mistakes are the command's own business, and it can say something
        // better than a wall of usage.
        "pair" => cmd_pair(rest),
        "mirror" => match positional(rest) {
            Some(ip) => cmd_mirror(ip, rest),
            None => {
                eprintln!("mirror: missing <ip>\n{}", usage());
                return ExitCode::FAILURE;
            }
        },
        "mirror-bench" => cmd_mirror_bench(rest),
        "extend" => cmd_extend(rest),
        "audio" => cmd_audio(rest),
        "capture-list" => cmd_capture_list(),
        "capture-bench" => cmd_capture_bench(rest),
        "encode-bench" => cmd_encode_bench(rest),
        "-h" | "--help" | "help" => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown command: {other}\n{}", usage());
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        // "The receiver wants the code off its own screen" gets its own exit
        // code AND its own one-line spelling, with nothing prepended to it, so
        // a script can match the line and a panel can branch on the status
        // without either of them parsing the rest of the error chain.
        Err(e) if e.downcast_ref::<NeedsCode>().is_some() => {
            eprintln!("error: {}", e.downcast_ref::<NeedsCode>().expect("just checked"));
            ExitCode::from(EXIT_NEEDS_CODE)
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// First non-flag argument (the `<ip>` positional).
fn positional(rest: &[String]) -> Option<&str> {
    rest.iter().find(|a| !a.starts_with('-')).map(String::as_str)
}

/// Value following `--flag`, if present.
fn flag_value<'a>(rest: &'a [String], flag: &str) -> Option<&'a str> {
    rest.iter()
        .position(|a| a == flag)
        .and_then(|i| rest.get(i + 1))
        .map(String::as_str)
}

/// A flag whose value is optional: both `--extend` and `--extend NAME` parse.
///
/// `None` = absent. `Some(None)` = present with no value, i.e. the next argument
/// is missing or is itself a flag — so `--extend --fps 30` must not swallow
/// `--fps`. `Some(Some(v))` = present with a value.
fn optional_flag_value<'a>(rest: &'a [String], flag: &str) -> Option<Option<&'a str>> {
    let i = rest.iter().position(|a| a == flag)?;
    match rest.get(i + 1) {
        Some(v) if !v.starts_with('-') => Some(Some(v.as_str())),
        _ => Some(None),
    }
}

/// What `--extend [NAME]` asked for, before the compositor is consulted.
///
/// The two cases are genuinely different questions, which is why this is not
/// just an `Option<String>` with a default filled in. A bare `--extend` asks
/// "put the TV after my last workspace", and the answer depends on live state;
/// `--extend NAME` asks for a specific name and can be answered offline.
#[derive(Debug, Clone, PartialEq)]
enum ExtendRequest {
    /// Bare `--extend`: append. The name is `AIRPLAY-<max workspace + 1>`,
    /// resolved once against the live compositor by [`resolve_extend`].
    Append,
    /// `--extend NAME`: exactly this name, already validated.
    Named(String),
}

/// `--extend [NAME]` decoded once, so `mirror`, `mirror-bench` and
/// `capture_source_from` cannot disagree about what was asked for. The name is
/// validated here, at the keyboard, rather than after the TV has been woken.
fn extend_request_from(rest: &[String]) -> anyhow::Result<Option<ExtendRequest>> {
    use airplay_rs::virtualoutput as vo;
    match optional_flag_value(rest, "--extend") {
        None => Ok(None),
        Some(None) => Ok(Some(ExtendRequest::Append)),
        Some(Some(name)) => {
            vo::validate_name(name).map_err(|e| anyhow::anyhow!("--extend: {e}"))?;
            Ok(Some(ExtendRequest::Named(name.to_string())))
        }
    }
}

/// Turn a request into the one concrete output name the run will use.
///
/// Called **once** per run, by `screen_flags`, and the answer is then carried in
/// `ScreenFlags` rather than recomputed. That is not an optimisation: with
/// `Append` the name encodes the workspace, so two calls straddling a workspace
/// change would create an output under one name and capture another.
fn resolve_extend(req: &ExtendRequest) -> anyhow::Result<String> {
    match req {
        ExtendRequest::Named(name) => Ok(name.clone()),
        // The name is `AIRPLAY-<N>` because the workspace rule that pins N
        // cannot be cleared for Hyprland's uptime, so the name has to vary with
        // the number or the first run's rule wins forever. See the note above
        // `next_workspace_id`.
        ExtendRequest::Append => {
            use airplay_rs::virtualoutput as vo;
            let a = vo::append().map_err(|e| anyhow::anyhow!("--extend: {e}"))?;
            // The one case where the TV is NOT at the end of the bar. Said out
            // loud, because otherwise the number looks simply wrong: it lands
            // inside the five slots the bar always draws, and the reason is
            // that every id above them was taken.
            if a.squeezed {
                println!(
                    "extend: workspaces {}-{} are all in use, so the TV takes workspace {} \
                     instead — inside the bar's {} default buttons rather than after them",
                    vo::BAR_DEFAULT_WORKSPACES + 1,
                    vo::BAR_MAX_WORKSPACE,
                    a.workspace,
                    vo::BAR_DEFAULT_WORKSPACES
                );
            }
            Ok(a.name)
        }
    }
}

/// How long a browse may take when `--timeout` is not given.
///
/// `avahi-browse -t` terminates itself once the cache is exhausted — measured at
/// 30 ms on this machine — so this is a safety net rather than the normal exit,
/// and it exists because a UI polling a command with no upper bound is a hang
/// waiting to happen.
const DISCOVER_TIMEOUT_DEFAULT: f64 = 5.0;

/// Shell out to `avahi-browse -rpt _airplay._tcp` (probe.discover), bounded.
///
/// `Err` means the browse could not be run at all — a fact worth an exit code,
/// because "avahi is not installed" and "no receivers on this network" are
/// different answers and a UI must not conflate them. A timeout is NOT an
/// error: whatever rows arrived before the deadline are real, so they are
/// returned with a note on stderr.
fn avahi_browse(timeout: std::time::Duration) -> anyhow::Result<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new("avahi-browse")
        .args(["-rpt", airplay_rs::discovery::AIRPLAY_SERVICE])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not run avahi-browse: {e}"))?;

    // Read on this thread while the child runs: a piped stdout nobody drains
    // deadlocks on the 64 KiB pipe buffer, and a full house of receivers with
    // their TXT records is not far off it.
    //
    // The read is what the deadline is enforced around, by killing the child —
    // which closes the pipe and ends the read — from a watchdog thread.
    let mut stdout = child.stdout.take().expect("piped stdout");
    let pid = child.id();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let done = std::sync::Arc::clone(&done);
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + timeout;
            while std::time::Instant::now() < deadline {
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if done.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            // SAFETY: our own child. It has not been reaped — `wait` below runs
            // only after this thread is joined — so the pid cannot have been
            // recycled onto an unrelated process.
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            true
        })
    };

    let mut out = String::new();
    let read = stdout.read_to_string(&mut out);
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let timed_out = watchdog.join().unwrap_or(false);
    let _ = child.wait();
    if let Err(e) = read {
        return Err(anyhow::anyhow!("could not read avahi-browse output: {e}"));
    }
    if timed_out {
        eprintln!(
            "discover: stopped the browse after {:.1}s; reporting what had answered by then",
            timeout.as_secs_f64()
        );
    }
    Ok(out)
}

/// The name pattern in `discover`'s arguments: the first argument that is
/// neither a flag nor a flag's own value.
///
/// `positional` is not enough here, because `discover --timeout 3` would make
/// `3` the pattern and search for a receiver called "3" — finding nothing, with
/// no hint as to why.
fn discover_pattern(rest: &[String]) -> Option<&str> {
    let timeout_value = rest.iter().position(|a| a == "--timeout").map(|i| i + 1);
    rest.iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with('-') && Some(*i) != timeout_value)
        .map(|(_, a)| a.as_str())
}

/// `--timeout SECONDS` for `discover`.
fn discover_timeout(rest: &[String]) -> anyhow::Result<std::time::Duration> {
    let secs = match flag_value(rest, "--timeout") {
        Some(v) => {
            let s: f64 = v
                .parse()
                .map_err(|_| anyhow::anyhow!("--timeout must be a number of seconds, got {v:?}"))?;
            if !(s.is_finite() && s > 0.0) {
                anyhow::bail!("--timeout must be a positive number of seconds, got {v:?}");
            }
            s
        }
        None => DISCOVER_TIMEOUT_DEFAULT,
    };
    Ok(std::time::Duration::from_secs_f64(secs))
}

/// A resolved target: where to connect, and what the receiver calls itself.
struct Resolved {
    host: String,
    /// The receiver's OWN advertised name (`75" The Frame`), not the pattern
    /// that matched it — `airplay mirror Frame` should still publish a sink
    /// called `AirPlay: 75" The Frame`. `None` when the target was a literal
    /// IP, because nothing was browsed and nothing may be guessed.
    name: Option<String>,
}

/// Resolve a `target` to a connectable host IP. A literal IP is used verbatim
/// (probe-by-IP fallback); otherwise browse mDNS and match by name, connecting to
/// the resolved A-record IP (never the SRV hostname — the Frame lies with
/// `localhost.local`).
fn resolve_target(target: &str) -> anyhow::Result<Resolved> {
    if target.parse::<std::net::IpAddr>().is_ok() {
        return Ok(Resolved { host: target.to_string(), name: None });
    }
    let out = avahi_browse(std::time::Duration::from_secs_f64(DISCOVER_TIMEOUT_DEFAULT))
        .unwrap_or_default();
    match airplay_rs::discovery::discover(&out, target) {
        Some(rec) => {
            eprintln!(
                "discover: {} at {} (srcvers {:?})",
                rec.name,
                rec.host,
                rec.txt.get("srcvers")
            );
            Ok(Resolved { host: rec.host, name: Some(rec.name) })
        }
        None => anyhow::bail!("no AirPlay receiver matching {target:?} found via mDNS"),
    }
}

/// `airplay discover [pattern] [--json] [--timeout SECONDS]`.
///
/// In `--json` mode stdout carries exactly one JSON object and nothing else —
/// no log lines, no progress, no "no receivers found" — because the consumer is
/// a parser, not a reader. Every diagnostic goes to stderr, including the ones
/// the human mode prints on stdout.
fn cmd_discover(rest: &[String]) -> anyhow::Result<()> {
    use airplay_rs::discovery::{receivers, Discovery};

    let json = rest.iter().any(|a| a == "--json");
    // `--timeout`'s own value is skipped, so `--timeout -1` is reported as the
    // bad timeout it is rather than as an unknown flag called `-1`.
    let timeout_value = rest.iter().position(|a| a == "--timeout").map(|i| i + 1);
    if let Some((_, bad)) = rest
        .iter()
        .enumerate()
        .filter(|(i, a)| a.starts_with('-') && Some(*i) != timeout_value)
        .find(|(_, a)| *a != "--json" && *a != "--timeout")
    {
        anyhow::bail!("discover: unknown flag {bad} (want --json or --timeout SECONDS)");
    }
    let pattern = discover_pattern(rest).unwrap_or("");
    let timeout = discover_timeout(rest)?;

    // A browse that could not run at all is an error in both modes: nothing on
    // stdout, a message on stderr, exit 1. A browse that ran and found nothing
    // is an empty list, which is an answer.
    let out = avahi_browse(timeout)?;
    if out.trim().is_empty() {
        eprintln!("discover: avahi-browse produced no output (is avahi-daemon running?)");
    }
    let found = receivers(&out, pattern);

    if json {
        print!("{}", Discovery { receivers: found }.to_json_line());
        return Ok(());
    }

    for r in &found {
        println!(
            "{}  {}:{}  srcvers={}  model={}",
            r.name,
            r.host,
            r.port,
            r.srcvers.as_deref().unwrap_or("?"),
            r.model.as_deref().unwrap_or("?"),
        );
    }
    if found.is_empty() {
        println!("discover: no receivers matching {pattern:?}");
    }
    Ok(())
}

/// `airplay status [--json]` — what is running right now, read-only.
///
/// Two facts, and they are independent: `session` is the run this machine has
/// going, and `orphan` is an Extend output whose owner is dead but which is
/// still on the desktop. A SIGKILLed run leaves the second with the first
/// absent, which is precisely the state `extend --cleanup` exists for.
///
/// **Read-only means read-only.** This takes no exclusive lock, writes no file
/// and creates no directory, so a panel polling it every couple of seconds
/// cannot disturb a live session. (That is not hypothetical: an earlier
/// `extend --status` took the real `flock` to answer "is anyone holding it",
/// which failed any `--extend` that tried to start inside that window — after
/// the TV had been woken. The probe now used here is a non-blocking `LOCK_SH`
/// that an exclusive holder rejects without either side waiting.)
fn cmd_status(rest: &[String]) -> anyhow::Result<()> {
    use airplay_rs::sessionstate::{self as ss, SessionKind, SessionRecord, StatusReport};
    use airplay_rs::virtualoutput as vo;

    let json = rest.iter().any(|a| a == "--json");
    if let Some(bad) = rest.iter().find(|a| a.starts_with('-') && *a != "--json") {
        anyhow::bail!("status: unknown flag {bad} (want --json)");
    }
    if let Some(bad) = rest.iter().find(|a| !a.starts_with('-')) {
        anyhow::bail!("status: unexpected argument {bad:?} (want --json)");
    }

    // --- the live session. A record whose pid is gone describes a run that
    // --- died without running its destructors; it is not a session.
    let recorded = ss::read();
    let stale_pid = recorded
        .as_ref()
        .map(|f| f.session.pid)
        .filter(|pid| !ss::pid_alive(*pid));
    let mut session = recorded
        .map(|f| f.session)
        .filter(|s| ss::pid_alive(s.pid));

    // Everything Hyprland can tell us, or why it could not. Read-only:
    // `vo::status` shells out to `hyprctl monitors all -j`, reads the claim
    // file, and probes the lock without taking it.
    let hypr = vo::status();
    let instance = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok();

    // --- Fall back to the Extend ownership claim when there is no session
    // --- record: a run started by an older build wrote one but not the other,
    // --- and reporting "nothing is running" over a live stream would be worse
    // --- than reporting it with a couple of fields unknown.
    if session.is_none() {
        if let Ok(st) = &hypr {
            if let Some(c) = st.claimed.as_ref().filter(|c| ss::pid_alive(c.pid)) {
                session = Some(SessionRecord {
                    kind: SessionKind::Extend,
                    // Not recorded in the claim, which predates this command.
                    receiver: None,
                    name: Some(c.name.clone()),
                    workspace: c.workspace,
                    pid: c.pid,
                    audio: None,
                });
            }
        }
    }

    // --- the orphan: our own claim, for THIS compositor, whose output is still
    // --- live and headless, with no live owner. All four conditions, because
    // --- each one on its own describes something `--cleanup` would not fix.
    let orphan = match &hypr {
        Ok(st) => st.claimed.as_ref().and_then(|c| {
            let ours = instance.as_deref() == Some(c.instance.as_str());
            let live_headless = st.live.as_ref().is_some_and(vo::is_headless);
            let owner_gone = !ss::pid_alive(c.pid) && !st.lock_held_elsewhere;
            (ours && live_headless && owner_gone).then(|| SessionRecord {
                kind: SessionKind::Extend,
                receiver: None,
                name: Some(c.name.clone()),
                workspace: c.workspace,
                pid: c.pid,
                audio: None,
            })
        }),
        Err(e) => {
            // Said out loud rather than reported as "no orphan": without the
            // compositor there is no way to know whether an output is up.
            eprintln!("status: cannot read Hyprland ({e}); an orphaned output cannot be detected");
            None
        }
    };

    let report = StatusReport { session, orphan };
    if json {
        print!("{}", report.to_json_line());
        return Ok(());
    }

    match &report.session {
        None => println!("session                  : none"),
        Some(s) => {
            println!("session                  : {} (pid {})", s.kind, s.pid);
            println!("  receiver               : {}", s.receiver.as_deref().unwrap_or("unknown"));
            println!("  source                 : {}", s.name.as_deref().unwrap_or("n/a"));
            match s.workspace {
                Some(w) => println!("  workspace              : {w}"),
                None => println!("  workspace              : n/a"),
            }
            match &s.audio {
                None => println!("  audio                  : off"),
                Some(a) => {
                    println!(
                        "  audio                  : {} via {}, {} ({} packets, {} anchors, {} late re-anchors)",
                        a.mode, a.capture, a.state, a.packets, a.anchors, a.late_reanchors
                    );
                    println!(
                        "  audio latency          : {} ms + A/V offset {} ms = {} ms{}",
                        a.latency_ms,
                        a.av_offset_ms,
                        a.effective_latency_ms,
                        if a.av_offset_calibrated { "" } else { " (offset UNCALIBRATED)" }
                    );
                    println!(
                        "  volume sync            : {}{}",
                        a.volume_state,
                        match (a.tv_volume_db, a.laptop_pct) {
                            (Some(db), Some(p)) => format!(" (TV {db:.1} dB, laptop {p}%)"),
                            (Some(db), None) => format!(" (TV {db:.1} dB)"),
                            _ => String::new(),
                        }
                    );
                }
            }
        }
    }
    match &report.orphan {
        None => println!("orphaned extend output   : none"),
        Some(o) => println!(
            "orphaned extend output   : {} (from pid {}, now gone) — \
             run `airplay extend --cleanup`",
            o.name.as_deref().unwrap_or("?"),
            o.pid
        ),
    }
    if let Some(pid) = stale_pid {
        println!(
            "note                     : a session record from pid {pid} is left over; that \
             process is gone, so nothing is running"
        );
    }
    Ok(())
}

// --------------------------------------------------------------------------- creds

/// Exit code for "this receiver needs an AirPlay code". Distinct from the
/// blanket 1 so a script or a panel can branch on it without parsing prose;
/// `mirror` is the command that can raise it.
const EXIT_NEEDS_CODE: u8 = 4;

/// The one stderr line a script is invited to match, and the carrier that gets
/// `mirror` to [`EXIT_NEEDS_CODE`]. Its `Display` IS the contract line, minus
/// the `error: ` prefix `main` adds to every failure.
#[derive(Debug)]
struct NeedsCode {
    host: String,
}

impl std::fmt::Display for NeedsCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this receiver needs an AirPlay code (run: airplay pair {} --pin CODE)",
            self.host
        )
    }
}

impl std::error::Error for NeedsCode {}

/// `{"ok":true,…}` for `pair --json`. Key order is the contract, so this is a
/// struct with fields in that order and not a `serde_json::json!` map (which
/// would sort them). Absent facts are omitted entirely rather than sent as
/// `null`, exactly as `discover --json` omits a model it was not told.
#[derive(serde::Serialize)]
struct PairOkJson<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    paired: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt_shown: Option<bool>,
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

/// `{"ok":false,"error":…,"reason":…}` for `pair --json`. `reason` is the
/// machine-readable half and is one of exactly four strings; `error` is the
/// human half and may say anything. `host` is extra, so a panel firing several
/// pairings at once can tell the answers apart.
#[derive(serde::Serialize)]
struct PairErrJson<'a> {
    ok: bool,
    error: String,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
}

/// `{"paired":[…]}` for `pair --list --json`.
#[derive(serde::Serialize)]
struct PairListJson {
    paired: Vec<airplay_rs::pairing::store::Paired>,
}

/// Which of the four contract reasons a pairing failure is.
///
/// `bad_pin` is the actionable one and is deliberately narrow: the receiver
/// rejecting our authentication (HAP error 2) or its own M4 proof not matching
/// ours, which is what a wrong code produces. BackOff (3) and MaxTries (5) are
/// NOT bad_pin — the code may well have been right and the receiver has simply
/// stopped listening — so they land in `other` with the HAP name in `error`.
fn pair_reason(e: &airplay_rs::pairing::PairError) -> &'static str {
    use airplay_rs::pairing::PairError;
    match e {
        PairError::Hap(2, _) | PairError::SrpProof => "bad_pin",
        PairError::Transport(_) => "network",
        _ => "other",
    }
}

/// One JSON object on stdout, and a `false` `ok` is still a successful answer
/// to the panel — but the process still exits non-zero, so a shell caller that
/// only checks `$?` is not told everything went fine.
fn pair_fail_json(host: Option<&str>, reason: &'static str, error: String) -> anyhow::Error {
    let doc = PairErrJson { ok: false, error: error.clone(), reason, host };
    match serde_json::to_string(&doc) {
        Ok(s) => println!("{s}"),
        // Unreachable for these types; if it ever happens, say so on stdout in
        // the shape the panel expects rather than printing nothing at all.
        Err(_) => println!("{{\"ok\":false,\"error\":\"serialisation failed\",\"reason\":\"other\"}}"),
    }
    anyhow::anyhow!("{error}")
}

/// The receiver's advertised name for a host we only know as an address, so
/// `pair 192.0.2.187 --json` can still answer with `"name":"Demo TV"`.
/// Best-effort and quiet: a browse that fails, or finds nothing, yields `None`
/// and the `name` key is simply absent.
fn discovered_name_for(host: &str) -> Option<String> {
    let out = avahi_browse(std::time::Duration::from_secs_f64(DISCOVER_TIMEOUT_DEFAULT)).ok()?;
    airplay_rs::discovery::receivers(&out, "")
        .into_iter()
        .find(|r| r.host == host)
        .map(|r| r.name)
}

/// How long `pair --interactive` waits for the code to arrive on stdin before
/// giving up. The probe waited 180 s for a PIN written to a file; 120 s is the
/// same order and leaves headroom under any idle timeout the receiver may
/// apply to a half-finished pair-setup connection — which is itself unmeasured
/// (see the note on [`pair_interactive`]).
const PAIR_CODE_TIMEOUT_DEFAULT: f64 = 120.0;

/// Read one line from stdin, or give up.
///
/// `Err` is the REASON, and it is a reason not to send anything: giving up
/// must not cost one of the receiver's few pairing attempts, so the caller
/// turns this into `PairError::NoCode` and no M3 goes out.
///
/// Everything that is not a digit is stripped, the way the probe stripped it
/// (`re.sub(r"\D", "", …)`), so `1878\n`, ` 1878 ` and `1-8-7-8` are the same
/// code. An empty line is a CANCEL, not an empty code, and so is a closed
/// stdin — which is how a UI withdraws a prompt the user dismissed.
///
/// The reading thread is left blocked on a timeout. That is deliberate and
/// safe here: the process is about to exit, and there is no portable way to
/// interrupt a blocking stdin read.
fn read_code_from_stdin(timeout: std::time::Duration) -> Result<String, String> {
    let (tx, rx) = std::sync::mpsc::channel::<Result<String, String>>();
    std::thread::spawn(move || {
        let mut line = String::new();
        let outcome = match std::io::stdin().read_line(&mut line) {
            Ok(0) => Err("stdin closed without a code".to_string()),
            Ok(_) => Ok(line),
            Err(e) => Err(format!("stdin could not be read: {e}")),
        };
        let _ = tx.send(outcome);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(line)) => {
            let digits: String = line.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                Err("a line with no digits in it: cancelled".to_string())
            } else {
                Ok(digits)
            }
        }
        Ok(Err(why)) => Err(why),
        Err(_) => Err(format!("nothing was typed within {:.0}s", timeout.as_secs_f64())),
    }
}

/// `pair <ip> --interactive [--json]`: the code-reading flow, on ONE
/// connection held open across the human reading the screen.
///
/// **Why it has to be this way.** Pair-setup state belongs to the connection,
/// and a receiver issues a fresh code for each new pair-setup. Proven on the
/// Frame on 2026-09-21: `pair --json` put 1878 on the screen, and a second
/// process running `pair --pin 1878` was refused with HAP error 2, because its
/// own `/pair-pin-start` had made the receiver show a new number. The same day,
/// a single `pair --pin 0988` invocation succeeded — one process, one
/// connection, its own prompt. So "show the code now, send it later" cannot be
/// split across processes, and this function does not try: it sends
/// `/pair-pin-start`, runs M1/M2, says on stdout that it is waiting, reads the
/// code, and finishes M3..M6 on the same socket.
///
/// **Output, line-delimited and flushed per line**, because a UI reads it as it
/// arrives rather than at exit:
///
/// 1. `{"ok":true,"prompt_shown":true,"host":…,"name":…}` — emitted the
///    instant before stdin is read, so its arrival means "the code is up and I
///    am waiting for it". A failure BEFORE this point (unreachable receiver,
///    a refusal at M1/M2) produces only the failure line, with no prompt line.
/// 2. `{"ok":true,"paired":true,…}` or `{"ok":false,"error":…,"reason":…}`.
///
/// **One attempt per run.** If the code is refused the run ends; the panel
/// starts another `--interactive`, which prompts again and the receiver shows
/// a new number. Retrying inside one connection is NOT attempted, and that is
/// a decision rather than an omission: it would mean replaying M1 on a socket
/// whose state machine has just rejected a proof, which no capture here
/// covers, and every wasted attempt takes the receiver closer to the BackOff
/// (HAP 3) and MaxTries (HAP 5) it can answer with instead. Restarting is
/// known to work; retrying is not.
///
/// **Unmeasured:** whether the receiver holds a half-finished pair-setup
/// connection open for the full `--timeout`. Nobody has left one waiting on the
/// Frame for two minutes. If it drops, it surfaces as a transport error after
/// the code is typed, and the panel should simply start another run.
fn pair_interactive(
    host: &str,
    name: Option<&str>,
    hkp: u8,
    sender_name: &str,
    timeout: std::time::Duration,
    json: bool,
) -> anyhow::Result<()> {
    use airplay_rs::pairing::{self, store, PairError};
    use std::io::Write;

    let mut conn = match airplay_rs::session::connect(host) {
        Ok(c) => c,
        Err(e) if json => {
            return Err(pair_fail_json(Some(host), "network", format!("cannot reach {host}: {e}")))
        }
        Err(e) => return Err(anyhow::anyhow!("cannot reach {host}: {e}")),
    };

    let result = pairing::pair_setup_pin_with(&mut conn, hkp, sender_name, || {
        // The prompt line goes out BEFORE the read blocks, and is flushed, so
        // a UI cannot be waiting on a line that is sitting in a buffer.
        if json {
            let doc = PairOkJson {
                ok: true,
                paired: None,
                prompt_shown: Some(true),
                host,
                name,
            };
            match serde_json::to_string(&doc) {
                Ok(s) => println!("{s}"),
                Err(_) => println!("{{\"ok\":true,\"prompt_shown\":true}}"),
            }
        } else {
            eprint!("Enter the code shown on {host}'s screen: ");
        }
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        read_code_from_stdin(timeout).map_err(PairError::NoCode)
    });

    let creds = match result {
        Ok(c) => c,
        Err(e) => {
            let reason = pair_reason(&e);
            let msg = match &e {
                // The actionable one: the number was wrong, or was the number
                // from a previous prompt. Either way the next run shows a new
                // one, so say that rather than "wrong PIN".
                PairError::Hap(2, _) | PairError::SrpProof => format!(
                    "{host} refused that code ({e}). It shows a NEW code each time pairing \
                     starts, so run `airplay pair {host} --interactive` again and use the \
                     number that appears then"
                ),
                _ => format!("pairing with {host} failed: {e}"),
            };
            if json {
                return Err(pair_fail_json(Some(host), reason, msg));
            }
            return Err(anyhow::anyhow!("{msg}"));
        }
    };

    let path = match store::save(host, &creds) {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("paired with {host} but could not save credentials: {e}");
            if json {
                return Err(pair_fail_json(Some(host), "other", msg));
            }
            return Err(anyhow::anyhow!("{msg}"));
        }
    };

    if json {
        let doc = PairOkJson {
            ok: true,
            paired: Some(true),
            prompt_shown: None,
            host,
            name,
        };
        println!("{}", serde_json::to_string(&doc)?);
        let _ = std::io::stdout().flush();
        eprintln!("pair: credentials saved to {} (plaintext; gnome-keyring later)", path.display());
    } else {
        println!(
            "pair: {host} OK — credentials saved to {} (plaintext, 0600; gnome-keyring later)",
            path.display()
        );
    }
    Ok(())
}

/// `airplay pair <ip> [--pin CODE] [--show-code] [--name NAME] [--hkp 3|5] [--json]`
/// `airplay pair --list [--json]`
/// `airplay pair <ip> --forget [--json]`
///
/// Four modes, because a panel and a person want different things:
///
/// * `--list` — which receivers we hold credentials for. Offline: no mDNS
///   browse, no receiver contacted, so it is safe to poll.
/// * `--pin CODE` — the real thing: PIN pair-setup, credentials saved.
/// * no `--pin`, with `--json` or `--show-code` — ask the receiver to put its
///   code on screen and stop there, so a UI can show its input box at the same
///   moment the TV shows the code.
/// * no `--pin`, no `--json` — the original interactive flow: the code goes up
///   and the PIN is read from the terminal.
///
/// `--forget` deletes a host's credentials, which is the other half of being
/// able to hold them: a receiver that has been reset will never verify again
/// and its file is dead weight.
fn cmd_pair(rest: &[String]) -> anyhow::Result<()> {
    use airplay_rs::pairing::{self, store};

    let json = rest.iter().any(|a| a == "--json");
    let list = rest.iter().any(|a| a == "--list");
    let forget = rest.iter().any(|a| a == "--forget");
    let show_code = rest.iter().any(|a| a == "--show-code");
    let interactive = rest.iter().any(|a| a == "--interactive");
    let pin_flag = flag_value(rest, "--pin").map(str::to_string);

    // Flag hygiene, at the keyboard, before anything is dialled. The value of
    // a value-taking flag is skipped so `--pin --json` is reported as the
    // missing PIN it is rather than as an unknown flag.
    let known = [
        "--json",
        "--list",
        "--forget",
        "--show-code",
        "--interactive",
        "--pin",
        "--name",
        "--hkp",
        "--timeout",
    ];
    let value_slots: Vec<usize> = ["--pin", "--name", "--hkp", "--timeout"]
        .iter()
        .filter_map(|f| rest.iter().position(|a| a == f).map(|i| i + 1))
        .collect();
    if let Some((_, bad)) = rest
        .iter()
        .enumerate()
        .filter(|(i, a)| a.starts_with('-') && !value_slots.contains(i))
        .find(|(_, a)| !known.contains(&a.as_str()))
    {
        anyhow::bail!("pair: unknown flag {bad} (want one of {})", known.join(", "));
    }
    // `--interactive` IS the code-reading flow, so it cannot be combined with
    // a code already in hand, with the stop-after-the-prompt flow, or with the
    // two offline modes.
    if interactive && (pin_flag.is_some() || show_code || list || forget) {
        anyhow::bail!(
            "pair --interactive cannot be combined with --pin, --show-code, --list or --forget: \
             it asks the receiver for a code and reads the answer from stdin itself"
        );
    }

    // --- pair --list: offline, no receiver touched.
    if list {
        if forget || pin_flag.is_some() || show_code {
            anyhow::bail!("pair --list takes no other flag than --json");
        }
        let paired = store::list();
        if json {
            let doc = PairListJson { paired };
            println!("{}", serde_json::to_string(&doc)?);
            return Ok(());
        }
        if paired.is_empty() {
            println!("pair: no stored credentials ({})", store::dir().display());
        } else {
            println!("credentials in {}:", store::dir().display());
            for p in &paired {
                println!("  {} (X-Apple-HKP {})", p.host, p.hkp);
            }
        }
        return Ok(());
    }

    let target = match positional(rest) {
        Some(t) => t,
        None => anyhow::bail!("pair: missing <ip> (or use `pair --list`)"),
    };

    // --- pair <ip> --forget: also offline. The host is used verbatim, NOT
    // --- resolved, so a receiver that is switched off can still be forgotten.
    if forget {
        let existed = store::forget(target)?;
        if json {
            let doc = PairOkJson {
                ok: true,
                paired: Some(false),
                prompt_shown: None,
                host: target,
                name: None,
            };
            println!("{}", serde_json::to_string(&doc)?);
        } else if existed {
            println!("pair: forgot credentials for {target}");
        } else {
            println!("pair: no stored credentials for {target}");
        }
        return Ok(());
    }

    // `--hkp`: 5 (screen capture, with the ScreenCapture ACL in M5) is what the
    // probe defaults to; 3 is plain PIN pairing and is what this CLI wrote
    // before, so it stays the default here — changing it would strand the
    // credentials already on disk, which verify and work.
    let hkp = match flag_value(rest, "--hkp") {
        None => pairing::HKP_PIN,
        Some("3") => pairing::HKP_PIN,
        Some("5") => pairing::HKP_SCREEN_CAPTURE,
        Some(other) => anyhow::bail!("pair: --hkp must be 3 (pin) or 5 (screen capture), not {other}"),
    };
    let sender_name = flag_value(rest, "--name").unwrap_or(airplay_rs::session::SENDER_NAME);
    let timeout = match flag_value(rest, "--timeout") {
        None => std::time::Duration::from_secs_f64(PAIR_CODE_TIMEOUT_DEFAULT),
        Some(v) => {
            let secs: f64 = v
                .parse()
                .map_err(|_| anyhow::anyhow!("pair: --timeout must be a number of seconds"))?;
            if !(secs.is_finite() && secs > 0.0 && secs <= 900.0) {
                anyhow::bail!("pair: --timeout must be between 0 and 900 seconds, not {v}");
            }
            std::time::Duration::from_secs_f64(secs)
        }
    };

    // Resolving can browse mDNS, which prints to stderr — never stdout, so the
    // one-JSON-object promise holds.
    let resolved = match resolve_target(target) {
        Ok(r) => r,
        Err(e) if json => return Err(pair_fail_json(Some(target), "network", e.to_string())),
        Err(e) => return Err(e),
    };
    let host = resolved.host;
    // A target given as an address carries no name; look one up so the panel
    // gets something to label the row with. Best-effort, never fatal.
    let name = resolved.name.or_else(|| discovered_name_for(&host));

    // --- pair <ip> --interactive: ONE process, ONE connection, the human in
    // --- the middle of it. The only shape that works (see `pair_interactive`).
    //
    // A bare `pair <ip>` — no code in hand, no --json, no --show-code — is the
    // same flow with a terminal on the other end, and goes through the same
    // function rather than a second copy of it.
    if interactive || (pin_flag.is_none() && !json && !show_code) {
        return pair_interactive(&host, name.as_deref(), hkp, sender_name, timeout, json);
    }

    // --- pair <ip> [--json] with no PIN: put the code on the screen, stop.
    if pin_flag.is_none() && (json || show_code) {
        let mut conn = match airplay_rs::session::connect(&host) {
            Ok(c) => c,
            Err(e) if json => {
                return Err(pair_fail_json(Some(&host), "network", format!("cannot reach {host}: {e}")))
            }
            Err(e) => return Err(anyhow::anyhow!("cannot reach {host}: {e}")),
        };
        match pairing::request_code(&mut conn, hkp) {
            Ok(()) => {
                // Said every time, because the obvious next step does not
                // work: the receiver issues a FRESH code for the next
                // pair-setup, so the number now on screen is spent the moment
                // this process exits. Proven on the Frame, 2026-09-21.
                eprintln!(
                    "pair: WARNING: the code now on {host}'s screen cannot be submitted by a \
                     LATER `pair --pin` call — that call starts its own pair-setup and the \
                     receiver shows a new number. Use `airplay pair {host} --interactive --json` \
                     instead, which holds the connection open and reads the code from stdin."
                );
                if json {
                    let doc = PairOkJson {
                        ok: true,
                        paired: None,
                        prompt_shown: Some(true),
                        host: &host,
                        name: name.as_deref(),
                    };
                    println!("{}", serde_json::to_string(&doc)?);
                } else {
                    println!("pair: asked {host} to show its AirPlay code");
                }
                return Ok(());
            }
            Err(e) => {
                let reason = match pair_reason(&e) {
                    "network" => "network",
                    _ => "no_prompt",
                };
                let msg = format!("{host} would not show a code: {e}");
                if json {
                    return Err(pair_fail_json(Some(&host), reason, msg));
                }
                return Err(anyhow::anyhow!("{msg}"));
            }
        }
    }

    // --- pair <ip> --pin CODE: one shot, for a code already in hand. Every
    // --- other combination has been dealt with above, so the PIN is present.
    let pin = pin_flag.expect("every no-PIN path returned above");
    let mut conn = match airplay_rs::session::connect(&host) {
        Ok(c) => c,
        Err(e) if json => {
            return Err(pair_fail_json(Some(&host), "network", format!("cannot reach {host}: {e}")))
        }
        Err(e) => return Err(anyhow::anyhow!("cannot reach {host}: {e}")),
    };

    let creds = match pairing::pair_setup_pin(&mut conn, hkp, sender_name, || pin) {
        Ok(c) => c,
        Err(e) => {
            let reason = pair_reason(&e);
            // This is the shape that PAIRED the Frame — one process sending
            // its own pin-start and the code together. If it is refused, the
            // likely cause is that the code came from somewhere else and the
            // receiver has since moved on.
            let msg = match &e {
                pairing::PairError::Hap(2, _) | pairing::PairError::SrpProof => format!(
                    "{host} refused that code ({e}). If it came from an earlier command, it is \
                     stale — the receiver shows a new one for each pairing. Use \
                     `airplay pair {host} --interactive`, which prompts and submits on one \
                     connection"
                ),
                _ => format!("PIN pairing with {host} failed: {e}"),
            };
            if json {
                return Err(pair_fail_json(Some(&host), reason, msg));
            }
            return Err(anyhow::anyhow!("{msg}"));
        }
    };

    // Keyed by the RESOLVED host, because that is what a session is opened
    // against: filing `Demo TV` under the pattern that matched it would save
    // a credential no session would ever look up.
    let path = match store::save(&host, &creds) {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("paired with {host} but could not save credentials: {e}");
            if json {
                return Err(pair_fail_json(Some(&host), "other", msg));
            }
            return Err(anyhow::anyhow!("{msg}"));
        }
    };

    if json {
        let doc = PairOkJson {
            ok: true,
            paired: Some(true),
            prompt_shown: None,
            host: &host,
            name: name.as_deref(),
        };
        println!("{}", serde_json::to_string(&doc)?);
        eprintln!("pair: credentials saved to {} (plaintext; gnome-keyring later)", path.display());
    } else {
        println!(
            "pair: {host} OK — credentials saved to {} (plaintext, 0600; gnome-keyring later)",
            path.display()
        );
    }
    Ok(())
}

/// The `--output NAME` / `--window TEXT` / `--extend [NAME]` trio, shared by
/// `mirror` and `mirror-bench` so the two commands cannot drift apart.
///
/// `--extend` yields exactly the source `--output NAME` would: the Extend output
/// is a real Wayland output by the time anything captures it, so nothing below
/// this function — not `session.rs`, not `pipeline.rs`, not `capture.rs` — needs
/// to know Extend exists.
/// `extend` is the **already-resolved** name from [`resolve_extend`], passed in
/// rather than recomputed so the source and the output that gets created are
/// guaranteed to be the same string.
fn capture_source_from(
    rest: &[String],
    extend: Option<&str>,
) -> anyhow::Result<airplay_rs::capture::CaptureSource> {
    use airplay_rs::capture::CaptureSource;
    let extend = extend.map(str::to_string);
    match (flag_value(rest, "--output"), flag_value(rest, "--window"), extend) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
            anyhow::bail!("--output, --window and --extend are mutually exclusive")
        }
        (Some(name), None, None) => Ok(CaptureSource::Output(name.to_string())),
        (None, Some(text), None) => Ok(CaptureSource::Window(text.to_string())),
        (None, None, Some(name)) => Ok(CaptureSource::Output(name)),
        (None, None, None) => {
            // Naming the alternatives beats "missing argument": the whole point
            // of capture-list is that output names are machine-specific.
            let listed = airplay_rs::capture::list()
                .map(|inv| {
                    inv.outputs
                        .iter()
                        .map(|o| format!("--output {}", o.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            if listed.is_empty() {
                anyhow::bail!(
                    "choose a source: --output NAME, --window TEXT, --extend [NAME], \
                     or --test-pattern"
                );
            }
            anyhow::bail!(
                "choose a source: --output NAME, --window TEXT, --extend [NAME], \
                 or --test-pattern (available here: {listed})"
            )
        }
    }
}

/// Everything `mirror` and `mirror-bench` both need to configure the pipeline.
struct ScreenFlags {
    source: airplay_rs::capture::CaptureSource,
    /// `--seconds N`, or [`RunLimit::UntilStopped`] for `--seconds 0`. Never a
    /// bare `f64`, so no site downstream can divide by a requested duration of
    /// zero.
    limit: airplay_rs::pipeline::RunLimit,
    fps: u32,
    encoder: airplay_rs::encoder::EncoderKind,
    qp: u32,
    keyint: f64,
    device: Option<String>,
    paint_cursors: bool,
    zero_copy: airplay_rs::capture::ZeroCopy,
    sps_zero_constraints: bool,
    keepalive_ms: Option<u64>,
    /// `Some(name)` when `--extend` was given: create a Hyprland headless output
    /// under that name and mirror it. Already resolved — a bare `--extend` has
    /// become a concrete `AIRPLAY-<N>` by the time it lands here — and `source`
    /// is the matching `CaptureSource::Output(name)`, so this field says only
    /// *who creates it*.
    extend: Option<String>,
}

/// `--zero-copy auto|on|off`. Shared by every command that opens a capture, so
/// they cannot drift apart.
fn zero_copy_flag(rest: &[String]) -> anyhow::Result<airplay_rs::capture::ZeroCopy> {
    use airplay_rs::capture::ZeroCopy;
    match flag_value(rest, "--zero-copy") {
        Some(v) => ZeroCopy::parse(v)
            .ok_or_else(|| anyhow::anyhow!("--zero-copy must be auto, on or off, got {v:?}")),
        None => Ok(ZeroCopy::default()),
    }
}

/// `--seconds` for every command that streams: `0` is run-until-stopped, a
/// negative is refused, absent is the command's own default.
///
/// One function so the four source modes of `mirror`, plus `mirror-bench` and
/// `capture-bench`, cannot disagree about what `--seconds 0` means.
fn seconds_flag(
    rest: &[String],
    default_seconds: f64,
) -> anyhow::Result<airplay_rs::pipeline::RunLimit> {
    use airplay_rs::pipeline::RunLimit;
    match flag_value(rest, "--seconds") {
        Some(v) => RunLimit::parse(v).map_err(|e| anyhow::anyhow!("{e}")),
        None => Ok(RunLimit::Seconds(default_seconds)),
    }
}

/// How a run's duration is described on stdout: `for 30s`, or the phrase that
/// says the only things that will end it.
fn run_phrase(limit: airplay_rs::pipeline::RunLimit) -> String {
    use airplay_rs::pipeline::RunLimit;
    match limit {
        RunLimit::Seconds(s) => format!("for {s}s"),
        RunLimit::UntilStopped => {
            "until stopped (Ctrl-C, SIGTERM, or the receiver going away)".to_string()
        }
    }
}

fn screen_flags(rest: &[String], default_seconds: f64) -> anyhow::Result<ScreenFlags> {
    use airplay_rs::encoder::EncoderKind;
    // Resolved once, here, and then only carried. A bare `--extend` becomes a
    // concrete `AIRPLAY-<N>` at this single point — and this is also where a
    // desktop with all ten bar-renderable workspaces in use refuses the run,
    // which is before pairing and before the TV is woken.
    let extend = extend_request_from(rest)?.as_ref().map(resolve_extend).transpose()?;
    Ok(ScreenFlags {
        source: capture_source_from(rest, extend.as_deref())?,
        limit: seconds_flag(rest, default_seconds)?,
        fps: flag_value(rest, "--fps")
            .map(str::parse)
            .transpose()
            .map_err(|_| anyhow::anyhow!("--fps must be an integer"))?
            .unwrap_or(60),
        encoder: match flag_value(rest, "--encoder") {
            Some(v) => EncoderKind::parse(v)
                .ok_or_else(|| anyhow::anyhow!("--encoder must be cpu or gpu, got {v:?}"))?,
            None => EncoderKind::Gpu,
        },
        qp: flag_value(rest, "--qp")
            .map(str::parse)
            .transpose()
            .map_err(|_| anyhow::anyhow!("--qp must be an integer"))?
            .unwrap_or(25),
        keyint: flag_value(rest, "--keyint")
            .map(str::parse)
            .transpose()
            .map_err(|_| anyhow::anyhow!("--keyint must be a number"))?
            .unwrap_or(5.0),
        device: flag_value(rest, "--device").map(str::to_string),
        paint_cursors: !rest.iter().any(|a| a == "--no-cursors"),
        zero_copy: zero_copy_flag(rest)?,
        sps_zero_constraints: rest.iter().any(|a| a == "--sps-zero-constraints"),
        keepalive_ms: flag_value(rest, "--keepalive")
            .map(str::parse)
            .transpose()
            .map_err(|_| anyhow::anyhow!("--keepalive must be an integer (ms)"))?,
        extend,
    })
}

/// Everything about `--extend` that is decidable read-only, before the TV is
/// woken.
///
/// `virtualoutput::preflight` covers the environment (`hyprctl` on PATH,
/// running under Hyprland, `monitors all -j` parsing). The two failures that
/// actually happen are the other two — another `airplay --extend` holding the
/// lock, and the name already being taken — and neither is reached until
/// `VirtualOutput::create`, which runs after pairing, after RTSP bring-up and
/// after the video SETUP check, i.e. with the Frame already awake. `status()`
/// answers all three in a single `hyprctl` call and takes nothing it keeps.
///
/// Advisory only, and deliberately permissive: the authoritative checks stay
/// inside `create`, under the lock. Nothing here may refuse a run that `create`
/// would have accepted — in particular a name the claim file records as ours,
/// which `create`'s reclaim sweep removes and recreates rather than refusing.
fn preflight_extend(name: &str) -> anyhow::Result<()> {
    use airplay_rs::virtualoutput as vo;
    // Re-asked here even though `resolve_extend` already picked the name: the
    // workspace set can change between the two, and this is the last read-only
    // moment before the TV is woken. `create` re-checks a third time, under the
    // lock, because it can change again.
    vo::preflight_workspace(name).map_err(|e| anyhow::anyhow!("--extend: {e}"))?;
    let st = vo::status().map_err(|e| anyhow::anyhow!("--extend is unavailable: {e}"))?;
    if st.lock_held_elsewhere {
        anyhow::bail!(
            "--extend is unavailable: another `airplay --extend` is running \
             (see `airplay extend --status`)"
        );
    }
    if let Some(m) = vo::find(&st.monitors, name) {
        let headless = vo::is_headless(m);
        // Ours-and-still-headless is left to `create`, which reclaims it under
        // the lock; refusing it here would break runs that succeed today.
        let reclaimable = headless && st.claimed.as_ref().is_some_and(|c| c.name == name);
        if !reclaimable {
            anyhow::bail!(
                "--extend: output {name} already exists ({}x{}, headless={headless}) and was not \
                 created by this tool; it will not be touched — pick another name with \
                 `--extend NAME`, or see `airplay extend --status`",
                m.width,
                m.height
            );
        }
    }
    Ok(())
}

fn cmd_mirror(target: &str, rest: &[String]) -> anyhow::Result<()> {
    let test_pattern = rest.iter().any(|a| a == "--test-pattern");

    // `--test-pattern` sets `screen = None` just below, and every --extend
    // decision downstream is gated on `screen` — so without this the flag would
    // be dropped in silence: no output created, its name never even validated,
    // a full-screen pattern streamed instead of the mode that was asked for.
    // `capture_source_from` makes every other conflicting source combination a
    // hard error; this one is no different. The name is decoded first, so
    // `--extend BADNAME --test-pattern` still reports the bad name exactly as
    // it does without `--test-pattern`.
    if test_pattern && extend_request_from(rest)?.is_some() {
        anyhow::bail!("--test-pattern and --extend are mutually exclusive");
    }

    // Parse the source flags BEFORE bringing a session up, so a typo costs a
    // message rather than a pairing round trip with the TV.
    let screen = if test_pattern {
        None
    } else {
        Some(screen_flags(rest, 30.0)?)
    };
    // `--test-pattern` parses its own `--seconds` (there are no screen flags to
    // carry it), through the same function, so `--seconds 0` means the same
    // thing in all four source modes.
    let limit = match &screen {
        Some(f) => f.limit,
        None => seconds_flag(rest, 30.0)?,
    };
    // The audio flags too: a typo in --audio / --av-offset must cost a
    // message here, before the capture probe, the Extend pre-flight or a
    // pairing round trip with the TV.
    let audio = audio_flags(rest)?;
    // The test pattern is generated at a fixed rate; live capture is
    // damage-driven and takes --fps as a ceiling.
    let fps: u32 = match &screen {
        Some(f) => f.fps,
        None => flag_value(rest, "--fps")
            .map(|s| s.parse())
            .transpose()
            .map_err(|_| anyhow::anyhow!("--fps must be an integer"))?
            .unwrap_or(30),
    };

    // Open the capture BEFORE pairing, and throw it away. The on-TV test is
    // expensive for the user, so a typo'd output name must cost a message here
    // rather than a full pairing round trip that then fails at the last step.
    //
    // --extend cannot take that probe: the output does not exist yet, and its
    // size is not knowable until the receiver has told us its display. So it
    // gets the read-only pre-flight in `preflight_extend` in the same slot
    // instead — the environment, the lock and the name — which preserves the
    // discipline (fail at the keyboard, not at the TV) for the part of --extend
    // that CAN be checked early. The real capture probe happens below, the
    // moment the output exists and still before a byte is streamed.
    if let Some(name) = screen.as_ref().and_then(|f| f.extend.as_deref()) {
        preflight_extend(name)?;
    }
    if let Some(f) = screen.as_ref().filter(|f| f.extend.is_none()) {
        let mut probe = airplay_rs::capture::CaptureConfig::new(f.source.clone());
        probe.paint_cursors = f.paint_cursors;
        // Probe the configuration the session is about to use, not the default
        // one: validating a different zero-copy policy than the run will take
        // proves nothing about that run, and costs gbm/PRIME allocations the
        // caller asked not to make.
        probe.zero_copy = f.zero_copy;
        let cap = airplay_rs::capture::Capture::open(probe)
            .map_err(|e| anyhow::anyhow!("cannot capture {}: {e}", f.source))?;
        let fmt = cap.format();
        let mode = cap.buffer_mode();
        match cap.zero_copy_note() {
            None => println!(
                "mirror: {} is capturable ({}x{} {}, {} x{} buffers, zero-copy {})",
                f.source,
                fmt.width,
                fmt.height,
                fmt.format.ffmpeg_name(),
                mode,
                cap.buffer_count(),
                f.zero_copy
            ),
            Some(why) => println!(
                "mirror: {} is capturable ({}x{} {}, {} x{} buffers, zero-copy {}; dmabuf unavailable: {why})",
                f.source,
                fmt.width,
                fmt.height,
                fmt.format.ffmpeg_name(),
                mode,
                cap.buffer_count(),
                f.zero_copy
            ),
        }
    }

    let resolved = resolve_target(target)?;
    let host = resolved.host;
    let mut config = airplay_rs::session::SessionConfig::new(host.clone());
    // What the receiver is called in the user's output menu: its own advertised
    // name, not the pattern that matched it, so `mirror Frame` still publishes
    // `AirPlay: 75" The Frame`. A target given as a bare IP leaves this None
    // and the session falls back to the model and then the address.
    config.receiver_name = resolved.name;
    // `--video-latency MS` is what we DECLARE in video SETUP; `--lead MS` is the
    // presentation lead we actually stamp on each frame, and may be negative to
    // ask the receiver to present on arrival. They default together at 75.
    if let Some(v) = flag_value(rest, "--video-latency") {
        config.video_latency_ms = v
            .parse()
            .map_err(|_| anyhow::anyhow!("--video-latency must be an integer (ms)"))?;
    }
    if let Some(v) = flag_value(rest, "--lead") {
        let ms: f64 = v
            .parse()
            .map_err(|_| anyhow::anyhow!("--lead must be a number (ms, may be negative)"))?;
        config.video_lead_seconds = Some(ms / 1000.0);
    }
    config.audio = audio.mode;
    config.audio_latency_ms = audio.latency_ms;
    config.av_offset_ms = audio.av_offset_ms;
    config.volume_sync = audio.volume_sync;
    if audio.mode.is_on() {
        if !audio.volume_sync {
            eprintln!(
                "mirror: WARNING: --no-volume-sync: no volume is sent and audio is not held silent, \
                 so it plays at the TV's own volume, which can be its MAXIMUM (the Frame has been \
                 seen to start sessions at 100%). With --audio-capture sink it is also refused as a \
                 pair: the pipewire capture is used instead, so the laptop keeps its output and its \
                 own level still attenuates"
            );
        }
        if let Some(eff) = audio.clamped_effective_ms() {
            eprintln!(
                "mirror: warning: --audio-latency {} + --av-offset {} is outside 200..2000 ms; \
                 the TV is told {eff} ms",
                audio.latency_ms,
                audio.av_offset_ms.unwrap_or(0)
            );
        }
        if let Some(eff) = audio.below_proven_latency_ms() {
            eprintln!(
                "mirror: warning: the TV is told {eff} ms (--audio-latency {} + --av-offset {}), \
                 below the proven 300 ms (85 ms broke up on Wi-Fi; 200 ms is untested)",
                audio.latency_ms,
                audio.av_offset_ms.unwrap_or(0)
            );
        }
        println!(
            "mirror: audio {} via {} (latency {} ms{})",
            audio.mode.as_str(),
            audio.mode.capture_str(),
            audio.latency_ms,
            match audio.av_offset_ms {
                Some(ms) => format!(", A/V offset {ms} ms UNCALIBRATED"),
                None => String::new(),
            }
        );
    }
    // The credentials, if we hold any. Loaded HERE rather than inside the
    // library so the session layer does no filesystem lookup of its own, and
    // said out loud either way: a stored credential that is quietly not used,
    // or quietly unreadable, is exactly the bug this whole path exists to fix.
    config.credentials = airplay_rs::pairing::store::load(&host);
    match (&config.credentials, airplay_rs::pairing::store::why_not(&host)) {
        (Some(_), _) => eprintln!("mirror: pairing with stored credentials for {host} (pair-verify)"),
        (None, Some(why)) => eprintln!(
            "mirror: stored credentials unusable — {why}; pairing transiently. \
             Re-pair with `airplay pair {host} --pin CODE`"
        ),
        (None, None) => {}
    }

    let session = match airplay_rs::session::run_session(&config) {
        Ok(s) => s,
        // The one failure with an action attached. `NeedsCode` carries the
        // message and the exit code; `main` prints it verbatim.
        Err(airplay_rs::session::SessionError::NeedsCode { host, detail }) => {
            eprintln!("mirror: pairing refused: {detail}");
            return Err(anyhow::Error::new(NeedsCode { host }));
        }
        Err(e) => return Err(anyhow::anyhow!("session bring-up failed: {e}")),
    };

    println!("mirror: paired with {host} via {}", session.pairing);
    println!(
        "mirror: {host} session up (audio_sc_id={}, video_sc_id={}, display={}x{}, fit={}x{}, dataPort={:?})",
        session.ids.audio_sc_id,
        session.ids.video_sc_id,
        session.display.0,
        session.display.1,
        session.fit.0,
        session.fit.1,
        session.video_data_port,
    );

    if session.video_data_port.is_none() {
        eprintln!("mirror: receiver returned no video dataPort; nothing to stream");
        session.shutdown();
        anyhow::bail!("no video dataPort");
    }

    // --- Extend: create the output AFTER bring-up (its size comes from the
    // --- receiver) and BEFORE stream_screen.
    //
    // This binding must outlive the `stream_screen` call below and must NOT be
    // `let _ = ...`, which would drop the guard — and remove the output —
    // immediately. Declared here, it is dropped strictly after `outcome`, i.e.
    // after ScreenPipeline and FramePump have been joined inside stream_screen:
    // removing an output while a capture is bound to it is a fatal Wayland
    // protocol error, and this ordering makes that impossible by construction
    // rather than by comment.
    let mut extend_guard = match screen.as_ref().and_then(|f| f.extend.as_deref()) {
        None => None,
        Some(name) => {
            // NOT the receiver's raw display size: the fixed point of the fit
            // against itself, so the size the compositor renders at IS the size
            // the encoder codes at for every receiver, not just this 1080p
            // Frame. See `virtualoutput::extend_mode`.
            let size = airplay_rs::virtualoutput::extend_mode(session.display);
            let fps = screen.as_ref().map_or(60, |f| f.fps);
            match airplay_rs::virtualoutput::VirtualOutput::create(name, size, fps) {
                Ok(vo) => {
                    println!(
                        "mirror: extend desktop {} up at {}x{}@{fps}, right of your panel — \
                         drag a window onto it, or move the mouse right off the panel edge",
                        vo.name(),
                        vo.size().0,
                        vo.size().1
                    );
                    // Only claim "the last button" when it actually is one:
                    // a workspace inside the bar's always-drawn range is not,
                    // and `resolve_extend` has already explained why.
                    match vo.workspace() {
                        Some(ws)
                            if ws > airplay_rs::virtualoutput::BAR_DEFAULT_WORKSPACES =>
                        {
                            println!(
                                "mirror: it owns workspace {ws} — the last button on the bar"
                            )
                        }
                        Some(ws) => println!("mirror: it owns workspace {ws}"),
                        None => println!(
                            "mirror: Hyprland chose its workspace; it may not be the last \
                             button on the bar, and may be one you are already using — it \
                             comes back when the run ends"
                        ),
                    }
                    println!("mirror: (Ctrl-C ends the run and removes it)");
                    Some(vo)
                }
                Err(e) => {
                    // `?` here would skip `shutdown` — `Session` has no `Drop`
                    // and `shutdown` consumes it — leaving the receiver holding
                    // a session it will only time out of.
                    session.shutdown();
                    anyhow::bail!("extend: {e}");
                }
            }
        }
    };

    // The capture probe --extend could not have before the output existed. It
    // is the one place a size disagreement is catchable before a byte reaches
    // the TV, and every number printed is the one the CAPTURE reported, never
    // the one we asked for.
    if let (Some(vo), Some(f)) = (extend_guard.as_ref(), screen.as_ref()) {
        report_extend_fit(vo, f, session.display);
    }

    // Record this session so `airplay status` can see it — every kind, not just
    // `--extend`. Written here, with the Extend output already created, so the
    // workspace in the record is the CONFIRMED one rather than the one asked
    // for; removed by the guard's `Drop`, which the signal path runs like any
    // other exit. See `sessionstate` for why this is not a field on the Extend
    // ownership claim.
    let audio_monitor = session.audio_monitor();
    let post_volume = PostVolumeProbe::start(config.audio);
    let mut record = session_record(screen.as_ref(), extend_guard.as_ref(), &host);
    record.audio = audio_monitor.as_ref().map(|m| audio_status(m, post_volume.value));
    let _session_record = airplay_rs::sessionstate::SessionClaim::new(record);
    // Declared AFTER the claim, so it is dropped (and stops writing) BEFORE
    // the claim removes the record.
    let _audio_status_writer = audio_monitor.map(|m| AudioStatusWriter::start(m, post_volume));

    let outcome = match screen {
        None => {
            println!(
                "mirror: streaming test pattern {} at {fps}fps — watch the TV",
                run_phrase(limit)
            );
            let stats = session.stream_test_pattern(limit, fps);
            if let Ok(s) = &stats {
                println!(
                    "mirror: streamed {} frames ({} IDR), {} heartbeats, {}x{} over {:.1}s{}",
                    s.frames,
                    s.idr_frames,
                    s.heartbeats,
                    s.width,
                    s.height,
                    s.seconds,
                    if s.interrupted {
                        format!(
                            " (interrupted by {})",
                            airplay_rs::signals::signal_name().unwrap_or("a signal")
                        )
                    } else {
                        String::new()
                    }
                );
            }
            stats.map(|_| ())
        }
        Some(flags) => {
            let mut cfg =
                airplay_rs::session::ScreenStreamConfig::new(flags.source.clone(), limit);
            cfg.fps = flags.fps;
            cfg.encoder = flags.encoder;
            cfg.qp = flags.qp;
            cfg.keyframe_seconds = flags.keyint;
            cfg.paint_cursors = flags.paint_cursors;
            cfg.zero_copy = flags.zero_copy;
            cfg.sps_zero_constraints = flags.sps_zero_constraints;
            cfg.keepalive = flags.keepalive_ms.map(std::time::Duration::from_millis);
            if let Some(d) = flags.device {
                cfg.device = d;
            }
            println!(
                "mirror: capturing {} with the {} encoder {} (<= {}fps, qp {}, keyint {}s, zero-copy {}){}",
                flags.source,
                flags.encoder,
                run_phrase(limit),
                flags.fps,
                flags.qp,
                flags.keyint,
                flags.zero_copy,
                if cfg.sps_zero_constraints { ", SPS constraints zeroed" } else { "" },
            );
            let stats = session.stream_screen(&cfg);
            if let Ok(s) = &stats {
                print_screen_stats(s);
            }
            stats.map(|_| ())
        }
    };

    if let Err(e) = &outcome {
        eprintln!("mirror: streaming ended: {e}");
    }
    session.shutdown();
    println!("mirror: session closed");
    // Explicit teardown on the path that can still report, so a failure to
    // remove the output is an error the user SEES rather than a line `Drop`
    // printed into a closing terminal. `Drop` remains the backstop for every
    // path that does not reach here.
    if let Some(vo) = extend_guard.take() {
        finish_extend(vo);
    }
    outcome.map_err(|e| anyhow::anyhow!("{e}"))
}

/// The audio flags of `mirror`, parsed and validated before any pairing.
#[derive(Debug, Clone, PartialEq)]
struct AudioFlags {
    mode: airplay_rs::session::AudioMode,
    latency_ms: u32,
    av_offset_ms: Option<i32>,
    volume_sync: bool,
}

impl AudioFlags {
    /// `Some(effective)` when `latency + offset` falls outside the 200..2000 ms
    /// the session clamps to, so the CLI can say what the TV is really told.
    /// Uses the explicit offset only; the per-model default is 0 (uncalibrated).
    fn clamped_effective_ms(&self) -> Option<u32> {
        let off = self.av_offset_ms.unwrap_or(0);
        let lat = airplay_rs::audio::AudioLatency::new(self.latency_ms, off).ok()?;
        let asked = self.latency_ms as i64 + off as i64;
        (lat.effective_ms() as i64 != asked).then(|| lat.effective_ms())
    }

    /// The effective latency the TV is told (base + A/V offset, clamped — the
    /// value `SETUP latencyMax` and every sync packet carry), when it is below
    /// the proven 300 ms. Checks the EFFECTIVE value, not the base: a
    /// negative `--av-offset` takes a 300 ms base down to 200 ms.
    fn below_proven_latency_ms(&self) -> Option<u32> {
        let eff = match airplay_rs::audio::AudioLatency::new(self.latency_ms, self.av_offset_ms.unwrap_or(0)) {
            Ok(l) => l.effective_ms(),
            Err(_) => self.latency_ms,
        };
        (eff < 300).then_some(eff)
    }
}

fn audio_flags(rest: &[String]) -> anyhow::Result<AudioFlags> {
    use airplay_rs::session::{AudioMode, CaptureBackend};
    let no_audio = rest.iter().any(|a| a == "--no-audio");
    if rest.iter().any(|a| a == "--audio") && flag_value(rest, "--audio").is_none() {
        anyhow::bail!("--audio needs a value: none, system or tone");
    }
    // `sink` is the default: the laptop's output MOVES to the TV, macOS-style,
    // and comes back at the end. `pipewire` is the old behaviour (the sound
    // plays on the laptop as well) and is kept reachable — it is the only way
    // to hear the TV's delay in the room, and the path with the most mileage.
    let capture = match flag_value(rest, "--audio-capture") {
        None | Some("sink") => CaptureBackend::Sink,
        Some("pipewire") => CaptureBackend::Pipewire,
        Some("parec") => CaptureBackend::Parec,
        Some(other) => anyhow::bail!("--audio-capture must be sink, pipewire or parec, not {other:?}"),
    };
    let mode = match flag_value(rest, "--audio") {
        None | Some("none") => AudioMode::None,
        Some("system") => AudioMode::System { capture },
        Some("tone") => AudioMode::Tone,
        Some(other) => anyhow::bail!("--audio must be none, system or tone, not {other:?}"),
    };
    if no_audio && mode.is_on() {
        anyhow::bail!("--no-audio and --audio {} contradict each other", mode.as_str());
    }
    if flag_value(rest, "--audio-capture").is_some() && !matches!(mode, AudioMode::System { .. }) {
        anyhow::bail!("--audio-capture only applies to --audio system");
    }
    let latency_ms = match flag_value(rest, "--audio-latency") {
        None => 300,
        Some(v) => v
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("--audio-latency must be a whole number of ms"))?,
    };
    let av_offset_ms = flag_value(rest, "--av-offset")
        .map(|v| v.parse::<i32>().map_err(|_| anyhow::anyhow!("--av-offset must be a whole number of ms (may be negative)")))
        .transpose()?;
    if let Some(off) = av_offset_ms {
        // Same bounds the session enforces; checked here so a typo costs a
        // message, not a pairing round trip.
        airplay_rs::audio::AudioLatency::new(latency_ms, off).map_err(|e| anyhow::anyhow!("--av-offset: {e}"))?;
    }
    if !mode.is_on() && (av_offset_ms.is_some() || flag_value(rest, "--audio-latency").is_some()) {
        anyhow::bail!("--audio-latency / --av-offset need --audio system or --audio tone");
    }
    Ok(AudioFlags {
        mode,
        latency_ms,
        av_offset_ms,
        volume_sync: !rest.iter().any(|a| a == "--no-volume-sync"),
    })
}

/// The `audio` object of the session record, from the live monitor.
fn audio_status(
    m: &airplay_rs::session::AudioMonitor,
    capture_post_volume: Option<bool>,
) -> airplay_rs::sessionstate::AudioStatus {
    let r = m.report();
    let v = m.volume();
    // The sink is written by the session at the three moments it changes
    // (published, output taken, output given up), so nothing here polls
    // `pactl`. It is `None` in every mode but sink, AND when sink mode fell
    // back to the default monitor — which is exactly the case `capture` below
    // distinguishes.
    let sink = m.sink();
    airplay_rs::sessionstate::AudioStatus {
        mode: m.info.mode.as_str().into(),
        // The capture that actually OPENED, not the one asked for:
        // `info.mode` is fixed at bring-up and still says "sink" after a
        // fallback. Before the stream starts there is nothing to report but
        // the request.
        capture: m
            .capture_backend()
            .map(|c| c.as_str())
            .unwrap_or_else(|| m.info.mode.capture_str())
            .into(),
        latency_ms: m.info.latency_ms,
        av_offset_ms: m.info.av_offset_ms,
        av_offset_calibrated: m.info.av_offset_calibrated,
        effective_latency_ms: m.info.effective_latency_ms,
        volume_sync: m.info.volume_sync,
        volume_state: if m.info.volume_sync {
            if v.state.is_empty() { "not started".into() } else { v.state.clone() }
        } else {
            "off".into()
        },
        tv_volume_db: v.tv_volume_db,
        tv_muted: v.tv_muted,
        laptop_pct: v.laptop_pct,
        capture_post_volume,
        output_sink: sink.as_ref().map(|s| s.node_name.clone()),
        output_sink_label: sink.as_ref().map(|s| s.label.clone()),
        output_is_default: sink.as_ref().map(|s| s.is_default),
        previous_output: sink.as_ref().map(|s| s.previous_output.clone()),
        packets: r.rtp_sent,
        anchors: r.timeline.anchors,
        syncs: r.timeline.syncs,
        late_reanchors: r.timeline.late_reanchors,
        discontinuities: r.capture.discontinuities,
        // A streaming sender whose gate is held is sending digital silence
        // (the TV volume is not established); say so rather than "streaming".
        state: if r.state == airplay_rs::audio::SenderState::Streaming && !r.gate_open {
            "silent".into()
        } else {
            r.state.as_str().into()
        },
    }
}

/// The captured sink's `monitor.channel-volumes` flag for status, kept in
/// step with the sink actually being captured — which is the whole point of
/// it: a value that describes a monitor nobody captures is worse than `null`.
///
/// Three shapes, picked from the capture that really opened rather than the
/// one asked for:
///
/// * **sink** — we tap a sink this process publishes, so the value is that
///   sink's own flag, measured once per sink name. It is also a *checked*
///   precondition of the sink path (the session refuses sink mode when it is
///   true), so here it is reporting, not deciding.
/// * **pipewire** — the capture follows the DEFAULT sink, so the value is
///   re-measured whenever `pactl get-default-sink` changes. This is also
///   where a sink-mode run lands after falling back.
/// * **parec** — pinned to the monitor it opened, so measured once at start.
///
/// Read-only throughout: one `pactl` call and, at most, one `pw-dump`.
struct PostVolumeProbe {
    /// Follows the default sink (PipeWire capture only). The tracker owns the
    /// re-read rate and the "only `pw-dump` when the sink name changed" rule,
    /// so there is one implementation of both. Created lazily, because a sink
    /// run that falls back needs one it was not started with.
    tracker: Option<airplay_rs::audiocapture::PostVolumeTracker>,
    /// The sink name already measured in sink mode, so the `pw-dump` runs
    /// once and not twice a second.
    measured_sink: Option<String>,
    value: Option<bool>,
}

impl PostVolumeProbe {
    /// How often the default sink name is re-read (one `pactl` call).
    const EVERY: std::time::Duration = std::time::Duration::from_secs(2);

    fn start(mode: airplay_rs::session::AudioMode) -> Self {
        use airplay_rs::audiocapture::PostVolumeTracker;
        use airplay_rs::session::{AudioMode, CaptureBackend};
        let blank = PostVolumeProbe { tracker: None, measured_sink: None, value: None };
        match mode {
            // Sink mode taps a sink this process publishes, not the default
            // one, so the default sink's monitor describes nothing we
            // capture. Unknown until the session has published the sink and
            // `refresh` can read its name off the monitor.
            AudioMode::System { capture: CaptureBackend::Sink } => blank,
            AudioMode::System { capture } => PostVolumeProbe {
                tracker: (capture == CaptureBackend::Pipewire).then(|| PostVolumeTracker::new(Self::EVERY)),
                value: airplay_rs::audiocapture::default_sink_monitor_is_post_volume(),
                ..blank
            },
            _ => blank,
        }
    }

    /// Re-measure if due, against the capture that actually opened. A sink
    /// that cannot be read reports `None`, never the old sink's value. Cheap
    /// to call often: sink mode measures once per sink, and the tracker
    /// rate-limits itself to [`Self::EVERY`].
    fn refresh(&mut self, m: &airplay_rs::session::AudioMonitor) {
        use airplay_rs::audiocapture::PostVolumeTracker;
        use airplay_rs::session::CaptureBackend;
        match m.capture_backend() {
            Some(CaptureBackend::Sink) => {
                // `sink()` is written before the capture is reported, so by
                // the time the backend says Sink there is a name here.
                if let Some(info) = m.sink() {
                    if self.measured_sink.as_deref() != Some(info.node_name.as_str()) {
                        self.value = airplay_rs::audiocapture::sink_monitor_is_post_volume(&info.node_name);
                        self.measured_sink = Some(info.node_name);
                    }
                }
            }
            // Asked for, or fallen back to. Either way the capture follows
            // the default sink from here, so start tracking it even if this
            // run began as a sink run.
            Some(CaptureBackend::Pipewire) => {
                self.measured_sink = None;
                let t = self.tracker.get_or_insert_with(|| PostVolumeTracker::new(Self::EVERY));
                self.value = t.get();
            }
            // parec is pinned to the monitor it opened: measured once at
            // start. `None` is "the stream has not started yet".
            Some(CaptureBackend::Parec) | None => {}
        }
    }
}

/// Rewrites `session.json`'s audio object while the session runs (twice a
/// second, only when something changed). Stops and joins on drop.
struct AudioStatusWriter {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl AudioStatusWriter {
    fn start(m: airplay_rs::session::AudioMonitor, mut post_volume: PostVolumeProbe) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop_t = stop.clone();
        let join = std::thread::spawn(move || {
            let pid = std::process::id();
            let mut last = None;
            while !stop_t.load(Ordering::SeqCst) {
                // Rate-limited inside the probe: sink mode measures once per
                // sink name, and the default-sink tracker re-reads the name
                // every 2 s (one `pactl` call), running `pw-dump` only when
                // that name actually changed.
                post_volume.refresh(&m);
                let now = Some(audio_status(&m, post_volume.value));
                if now != last {
                    if let Err(e) = airplay_rs::sessionstate::update_audio(pid, now.clone()) {
                        eprintln!("warning: could not update the session record ({e})");
                    }
                    last = now;
                }
                for _ in 0..5 {
                    if stop_t.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        });
        AudioStatusWriter { stop, join: Some(join) }
    }
}

impl Drop for AudioStatusWriter {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// What this run is, for the record `airplay status` reads.
///
/// `screen` is `None` for `--test-pattern`, which has no capture source of its
/// own; `extend` is `Some` only once the headless output actually exists, and
/// its `workspace()` is the confirmed one, so a bare `--extend` records the
/// number Hyprland really gave it.
fn session_record(
    screen: Option<&ScreenFlags>,
    extend: Option<&airplay_rs::virtualoutput::VirtualOutput>,
    host: &str,
) -> airplay_rs::sessionstate::SessionRecord {
    use airplay_rs::capture::CaptureSource;
    use airplay_rs::sessionstate::{SessionKind, SessionRecord};

    let (kind, name, workspace) = match (screen, extend) {
        (Some(_), Some(vo)) => (
            SessionKind::Extend,
            Some(vo.name().to_string()),
            vo.workspace(),
        ),
        (Some(f), None) => match &f.source {
            CaptureSource::Output(n) => (SessionKind::Output, Some(n.clone()), None),
            CaptureSource::Window(t) => (SessionKind::Window, Some(t.clone()), None),
        },
        // `--test-pattern`: generated, so there is no source to name.
        (None, _) => (SessionKind::TestPattern, None, None),
    };
    SessionRecord {
        kind,
        receiver: Some(host.to_string()),
        name,
        workspace,
        pid: std::process::id(),
        audio: None,
    }
}

/// Prove — not assume — that the Extend desktop is encoded 1:1.
///
/// The output was created at `extend_mode(display)`, which is the fixed point of
/// the fit, so the coded size should equal the created size. That holds unless
/// something outside this process has a say: a `monitor=` rule in the user's
/// Hyprland config matching the name and applying a scale would make the capture
/// buffer a different size than the mode we asked for. `fit_source_to_receiver`
/// handles that correctly and the declared coded size stays consistent, so it is
/// a loud warning and not a failure — but it must be loud, because a silent
/// downscale is exactly what makes UniFi Protect camera text soft.
///
/// Everything printed is measured from what the capture actually opened.
fn report_extend_fit(
    vo: &airplay_rs::virtualoutput::VirtualOutput,
    flags: &ScreenFlags,
    display: (u32, u32),
) {
    let mut probe = airplay_rs::capture::CaptureConfig::new(vo.source());
    probe.paint_cursors = flags.paint_cursors;
    probe.zero_copy = flags.zero_copy;
    let cap = match airplay_rs::capture::Capture::open(probe) {
        Ok(c) => c,
        Err(e) => {
            // Not fatal: stream_screen opens its own capture and will fail
            // there with a better error if this was real.
            eprintln!("extend: WARNING — could not probe {}: {e}", vo.name());
            return;
        }
    };
    let fmt = cap.format();
    let opened = (fmt.width, fmt.height);
    let coded = airplay_rs::encoder::fit_source_to_receiver(opened, display);
    if opened != vo.size() {
        println!(
            "extend: WARNING — {} came up {}x{}, not the {}x{} requested; coded {}x{} \
             (a monitor= rule in your Hyprland config matching this name?)",
            vo.name(),
            opened.0,
            opened.1,
            vo.size().0,
            vo.size().1,
            coded.0,
            coded.1
        );
    } else if coded != opened {
        println!(
            "extend: WARNING — {} is {}x{} but codes at {}x{}; the desktop is being scaled",
            vo.name(),
            opened.0,
            opened.1,
            coded.0,
            coded.1
        );
    } else {
        println!(
            "extend: {} is 1:1 — {}x{} desktop -> {}x{} coded, no scaling ({} x{} buffers)",
            vo.name(),
            opened.0,
            opened.1,
            coded.0,
            coded.1,
            cap.buffer_mode(),
            cap.buffer_count()
        );
    }
}

/// Remove the Extend output and say what happened.
fn finish_extend(vo: airplay_rs::virtualoutput::VirtualOutput) {
    let name = vo.name().to_string();
    // Read-only. We never MOVE a window: `hl.dsp.window.move` acts on whatever
    // is focused, which is one focus change away from throwing an unrelated
    // window onto the TV. Hyprland migrates it back by itself.
    if vo.occupants() > 0 {
        println!(
            "extend: a window is still on {name}; it will come back to your panel \
             on a new workspace"
        );
    }
    match vo.remove_and_report() {
        Ok(true) => println!("extend: removed virtual output {name}"),
        Ok(false) => println!("extend: virtual output {name} was already gone"),
        Err(e) => {
            eprintln!("extend: could not remove {name}: {e} — run `airplay extend --cleanup`")
        }
    }
}

/// `airplay audio --status` (read-only) / `airplay audio --cleanup`, plus the
/// hidden `--hold SECONDS`.
///
/// The audio half of `airplay extend`, and for the same reason: a SIGKILLed
/// sender leaves nothing behind that a user can see — the sink NODE dies with
/// the process — but it does leave `default.configured.audio.sink` naming a
/// sink that no longer exists, and that survives a reboot. Audio keeps working
/// (WirePlumber elects the next sink by priority), so the only symptom is that
/// the output the user had before the crash never came back. `--cleanup` puts it
/// back; `--status` says whether there is anything to put back.
///
/// `--hold` publishes the sink, takes the output and gives it back after
/// SECONDS. No receiver, no network, no video: it is how the handover can be
/// heard — the speakers going quiet and coming back — without a TV in the
/// room, and how the SIGKILL path can be exercised against a real process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AudioCmd {
    Status,
    Cleanup,
    Hold(u64),
}

/// Parsed on its own, so the argument rules are checked without a PipeWire
/// graph to talk to.
fn audio_cmd(rest: &[String]) -> anyhow::Result<AudioCmd> {
    let hold = rest.iter().any(|a| a == "--hold");
    let cleanup = rest.iter().any(|a| a == "--cleanup");
    if hold && cleanup {
        anyhow::bail!("audio: --hold and --cleanup contradict each other");
    }
    if hold {
        let Some(v) = flag_value(rest, "--hold") else {
            anyhow::bail!("--hold needs a value: the number of seconds to hold the output");
        };
        let secs: u64 = v
            .parse()
            .map_err(|_| anyhow::anyhow!("--hold must be a whole number of seconds, not {v:?}"))?;
        if secs == 0 {
            anyhow::bail!("--hold 0 would take the output and give it straight back; give it a number of seconds");
        }
        return Ok(AudioCmd::Hold(secs));
    }
    if cleanup {
        // `--cleanup` acts. Anything else on the line is a typo, and a typo on
        // a line that changes the output should stop rather than be ignored.
        if let Some(bad) = rest.iter().find(|a| a.as_str() != "--cleanup") {
            anyhow::bail!("audio: --cleanup takes no other arguments, got {bad}");
        }
        return Ok(AudioCmd::Cleanup);
    }
    if let Some(bad) = rest.iter().find(|a| a.as_str() != "--status") {
        anyhow::bail!("audio: unknown argument {bad} (want --status, --cleanup or --hold SECONDS)");
    }
    Ok(AudioCmd::Status)
}

fn cmd_audio(rest: &[String]) -> anyhow::Result<()> {
    match audio_cmd(rest)? {
        AudioCmd::Hold(secs) => audio_hold(secs),
        AudioCmd::Cleanup => cmd_audio_cleanup(),
        AudioCmd::Status => cmd_audio_status(),
    }
}

fn cmd_audio_cleanup() -> anyhow::Result<()> {
    use airplay_rs::audiosink::Repair;
    match airplay_rs::audiosink::reclaim_orphan()? {
        Some(Repair::RestoredDefault { from, to }) => {
            println!("audio: the output was still pointed at the dead sink {from}; restored it to {to}")
        }
        Some(Repair::ClearedStaleClaim) => {
            println!("audio: cleared a stale claim; the output was already yours")
        }
        Some(Repair::Nothing) => {
            println!("audio: a sink of that name is still live; left it and the output alone")
        }
        // NOT the same message: nothing was read, so nothing is known. Saying
        // "still live" here would report a fact nobody established, and would
        // read as "all is well" when the right answer is "try again".
        Some(Repair::CouldNotTell) => {
            println!(
                "audio: could not list the sinks, so nothing is known about the claim; \
                 left the claim and the output alone — run this again"
            )
        }
        None => println!("audio: nothing to clean up"),
    }
    Ok(())
}

/// Read-only: no lock taken, nothing published, nothing written.
fn cmd_audio_status() -> anyhow::Result<()> {
    use airplay_rs::audiosink as asink;

    let st = asink::status();
    match &st.claimed {
        None => println!("claim                    : none"),
        Some(c) => println!(
            "claim                    : {} ({:?}, pid {}, {}s ago){}{}",
            c.node_name,
            c.label,
            c.pid,
            asink::state::now_unix().saturating_sub(c.created_unix),
            if c.took_default { ", took the output" } else { "" },
            if c.restore_default { "" } else { ", output disowned" },
        ),
    }
    if st.claimed.is_some() {
        println!(
            "claimed sink live        : {}",
            match st.claimed_is_live {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown (the sink listing could not be read)",
            }
        );
    }
    println!(
        "another sender running   : {}",
        if st.lock_held_elsewhere { "yes" } else { "no" }
    );
    println!(
        "output (now)             : {}",
        st.default_sink.as_deref().unwrap_or("unknown")
    );
    println!(
        "output (configured)      : {}",
        st.configured_default
            .as_deref()
            .unwrap_or("none — WirePlumber is electing one")
    );
    println!("AirPlay sinks live ({}):", st.airplay_sinks.len());
    for s in &st.airplay_sinks {
        println!("  {s}");
    }
    // The one thing worth acting on: a claim whose sink is gone, whose owner
    // is gone, and whose name is still what the machine is configured to use.
    // Everything else about a dead run is self-healing.
    if let Some(c) = &st.claimed {
        // `Some(false)`, never `None`: advice to repair the output is given
        // only when the sink was READ and was not there.
        if st.claimed_is_live == Some(false)
            && !st.lock_held_elsewhere
            && st.configured_default.as_deref() == Some(c.node_name.as_str())
            && c.restore_default
        {
            println!(
                "--- the output is still configured for a sink that no longer exists: \
                 `airplay audio --cleanup` puts {} back",
                c.previous_default
            );
        }
    }
    Ok(())
}

/// `airplay audio --hold SECONDS` — no receiver, no network, no video.
fn audio_hold(secs: u64) -> anyhow::Result<()> {
    use airplay_rs::audiosink as asink;

    let mut sink = asink::AirPlaySink::publish(asink::SinkOpts::for_receiver("(no receiver)"))?;
    println!(
        "audio: published {:?} ({}); your output is {}",
        sink.label(),
        sink.node_name(),
        sink.previous_default()
    );
    sink.take_default()?;
    println!(
        "audio: the output is now the AirPlay sink — the speakers are quiet, and nothing is \
         being sent anywhere. Holding {secs}s; Ctrl-C gives it back early."
    );
    // The signal handlers installed in `main` turn Ctrl-C into a flag rather
    // than a kill, so an interrupted hold returns through the destructor that
    // gives the output back. Polled, not slept through, for exactly that.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < until && !airplay_rs::signals::interrupted() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let back = sink.previous_default().to_string();
    drop(sink);
    println!("audio: gave the output back to {back}");
    Ok(())
}

/// `airplay extend --status` (read-only) / `airplay extend --cleanup`.
///
/// The escape hatch the user runs instead of hand-deleting a monitor from his
/// desktop. `--cleanup` removes **only** a name our own state file claims, for
/// the current Hyprland instance, that is still headless — an output some other
/// tool created is never touched by any path in this program.
fn cmd_extend(rest: &[String]) -> anyhow::Result<()> {
    use airplay_rs::virtualoutput as vo;

    if rest.iter().any(|a| a == "--cleanup") {
        match vo::reclaim_orphan()? {
            Some(name) => println!("extend: removed orphaned output {name}"),
            None => println!("extend: nothing to clean up"),
        }
        return Ok(());
    }
    if let Some(bad) = rest.iter().find(|a| a.starts_with('-') && *a != "--status") {
        anyhow::bail!("extend: unknown flag {bad} (want --status or --cleanup)");
    }

    let st = vo::status()?;
    match &st.claimed {
        None => println!("claim                    : none"),
        Some(c) => println!(
            "claim                    : {} (pid {}, instance {}, {}s ago)",
            c.name,
            c.pid,
            c.instance,
            vo::state::now_unix().saturating_sub(c.created_unix)
        ),
    }
    match &st.live {
        None => println!("claimed output live      : no"),
        Some(m) => println!(
            "claimed output live      : yes — {}x{}@{:.2} scale {:.2} at +{},+{} (headless {})",
            m.width,
            m.height,
            m.refresh_hz,
            m.scale,
            m.x,
            m.y,
            vo::is_headless(m)
        ),
    }
    println!(
        "another --extend running : {}",
        if st.lock_held_elsewhere { "yes" } else { "no" }
    );
    println!("monitors ({}):", st.monitors.len());
    for m in &st.monitors {
        println!(
            "  {:<12} {}x{}@{:.2} scale {:.2} at +{},+{}  {}{}",
            m.name,
            m.width,
            m.height,
            m.refresh_hz,
            m.scale,
            m.x,
            m.y,
            if vo::is_headless(m) { "headless" } else { "physical" },
            if m.focused { ", focused" } else { "" },
        );
    }
    if st.claimed.is_some() && st.live.is_some() && !st.lock_held_elsewhere {
        println!("--- a claimed output is live with no owner: `airplay extend --cleanup`");
    }
    Ok(())
}

/// Everything measured about a live-screen run. Every line is a count or a
/// measured percentile — there is no nominal fps anywhere.
fn print_screen_stats(s: &airplay_rs::session::ScreenStats) {
    let r = &s.run;
    let p = &s.pipeline;
    let (lmin, lmed, lp95, lmax) = p.latency_ms;
    println!("---");
    println!("captured                 : {} ({}x{})", s.label, s.source.0, s.source.1);
    println!("coded size               : {}x{}", s.width, s.height);
    match &s.zero_copy_note {
        None => println!("capture buffers          : {}", s.buffers),
        Some(why) => println!("capture buffers          : {} (zero-copy unavailable: {why})", s.buffers),
    }
    if let Some(why) = &s.encoder_note {
        println!("encoder fallback         : {why}");
    }
    println!(
        "access units sent        : {}  ({} IDR, {} from keepalive repeats)",
        r.access_units, r.idr_units, r.repeat_units
    );
    println!("heartbeats               : {}", r.heartbeats);
    println!(
        "frames captured          : {} fresh + {} repeats  (capture failures {}, reallocations {})",
        p.capture.fresh, p.capture.repeats, p.capture.failures, p.capture.reallocations
    );
    println!(
        "frames published/dropped : {} / {}  (newest-wins; dropped is the fps cap working)",
        p.produced, p.dropped
    );
    println!("encoder reconfigures     : {}", p.reconfigures);
    println!(
        "pictures / packets       : {} / {}  (must be equal, and equal to the AUs sent)",
        p.encoder.pictures_out, p.encoder.packets_out
    );
    println!(
        "VCL NALs / SPS / PPS/ SEI: {} / {} / {} / {}  (SEI must be 0)",
        p.encoder.vcl_nals_out, p.encoder.sps_out, p.encoder.pps_out, p.encoder.sei_out
    );
    println!(
        "measured rate            : {:.2} fps, {:.3} Mb/s over {:.1}s ({} bytes)",
        r.fps(),
        r.megabits_per_second(),
        r.seconds,
        r.bytes
    );
    let n = p.encoder.frames_in.max(1) as f64;
    println!(
        "encode stage means       : upload {:.2} ms | convert+scale {:.2} ms | encode {:.2} ms",
        p.encoder.upload_us as f64 / n / 1e3,
        p.encoder.convert_us as f64 / n / 1e3,
        p.encoder.encode_us as f64 / n / 1e3
    );
    println!(
        "capture->encoded latency : min {lmin:.2} median {lmed:.2} p95 {lp95:.2} max {lmax:.2} ms"
    );
    if r.interrupted {
        // Success, not failure: the run was asked to stop and did, in time to
        // run every teardown below. Printed so a short `seconds` above is
        // explained rather than looking like a stall.
        println!(
            "interrupted              : yes ({}) — stopped early and shut down cleanly",
            airplay_rs::signals::signal_name().unwrap_or("signal")
        );
    }
}

/// Counts what the mirror channel would have written, without a receiver.
#[derive(Default)]
struct CountingSink {
    bytes: u64,
    writes: u64,
}

impl std::io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes += buf.len() as u64;
        self.writes += 1;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The join's offline gate: capture -> encode -> MirrorStreamer, no receiver.
///
/// This runs the SAME `run_stream` loop the live path runs, with the same
/// ChaCha video cipher, into a counting sink instead of a socket — so the only
/// thing the TV adds is the socket. `--out` writes the forwarded access units as
/// Annex-B so `ffmpeg -err_detect explode` (and a human looking at a decoded
/// frame) can check them.
fn cmd_mirror_bench(rest: &[String]) -> anyhow::Result<()> {
    use airplay_rs::pipeline::{run_stream, PipelineConfig, RunOptions, ScreenPipeline};
    use airplay_rs::video::{MirrorStreamer, VideoCipher};

    let flags = screen_flags(rest, 10.0)?;
    let receiver = match flag_value(rest, "--receiver") {
        Some(v) => {
            let (w, h) = v
                .split_once(['x', 'X'])
                .ok_or_else(|| anyhow::anyhow!("--receiver expects WxH, got {v:?}"))?;
            (w.trim().parse()?, h.trim().parse()?)
        }
        None => (1920, 1080),
    };
    let out_path = flag_value(rest, "--out").map(str::to_string);

    let mut cfg = PipelineConfig::new(flags.source.clone(), receiver);
    cfg.capture.paint_cursors = flags.paint_cursors;
    cfg.capture.zero_copy = flags.zero_copy;
    cfg.encoder = flags.encoder;
    cfg.fps = flags.fps;
    cfg.qp = flags.qp;
    cfg.keyframe_seconds = flags.keyint;
    cfg.probe_low_power = flags.encoder == airplay_rs::encoder::EncoderKind::Gpu
        && !rest.iter().any(|a| a == "--no-probe");
    if let Some(d) = flags.device {
        cfg.device = d;
    }
    // Capture is damage-driven, so a still desktop cannot supply more than a few
    // frames/s however good the pacing is. Turning the keepalive down makes the
    // capture layer re-emit the front buffer at a chosen rate — a real capture,
    // a real import and a real encode per frame — so the pacing loop can be
    // measured against a supply it cannot outrun, without damaging the screen.
    if let Some(v) = flag_value(rest, "--keepalive") {
        let ms: u64 = v
            .parse()
            .map_err(|_| anyhow::anyhow!("--keepalive must be an integer (ms)"))?;
        cfg.capture.keepalive = std::time::Duration::from_millis(ms);
    }

    println!("== mirror-bench ==");
    println!("duration                 : {}", flags.limit);

    // --extend here exercises the whole Extend path with the TV off: create the
    // output at the fit's fixed point for the ASSUMED receiver, capture it,
    // encode it, tear it down. Declared before `pipe` so it is dropped after it
    // — removing the output while a capture is bound is a fatal Wayland
    // protocol error.
    let mut extend_guard = match &flags.extend {
        None => None,
        Some(name) => {
            let size = airplay_rs::virtualoutput::extend_mode(receiver);
            let vo = airplay_rs::virtualoutput::VirtualOutput::create(name, size, flags.fps)
                .map_err(|e| anyhow::anyhow!("extend: {e}"))?;
            println!(
                "extend desktop           : {} at {}x{}@{}",
                vo.name(),
                vo.size().0,
                vo.size().1,
                flags.fps
            );
            // The confirmed workspace, so the ledger records what actually
            // happened rather than what was asked for.
            println!(
                "extend workspace         : {}",
                match vo.workspace() {
                    Some(ws) if ws > airplay_rs::virtualoutput::BAR_DEFAULT_WORKSPACES =>
                        format!("{ws}  (appended; the last button on the bar)"),
                    Some(ws) => format!("{ws}  (inside the bar's default buttons)"),
                    None => "chosen by Hyprland (not pinned)".to_string(),
                }
            );
            Some(vo)
        }
    };

    println!("source                   : {}", flags.source);
    println!("receiver (assumed)       : {}x{}", receiver.0, receiver.1);
    println!(
        "capture keepalive        : {:.0} ms (supply floor {:.0} frames/s)",
        cfg.capture.keepalive.as_secs_f64() * 1e3,
        1.0 / cfg.capture.keepalive.as_secs_f64()
    );

    let open0 = std::time::Instant::now();
    let mut pipe = ScreenPipeline::start(cfg)?;
    println!("pipeline open            : {:.1} ms", open0.elapsed().as_secs_f64() * 1e3);
    println!("captured                 : {}", pipe.label());
    match pipe.zero_copy_note() {
        None => println!("capture buffers          : {} (--zero-copy {})", pipe.buffer_mode(), flags.zero_copy),
        Some(why) => println!(
            "capture buffers          : {} (--zero-copy {}; dmabuf unavailable: {why})",
            pipe.buffer_mode(),
            flags.zero_copy
        ),
    }
    let (sw, sh) = pipe.source_size();
    let (tw, th) = pipe.target_size();
    println!(
        "fit                      : {sw}x{sh} -> {tw}x{th}  ({} macroblocks, budget {})",
        airplay_rs::encoder::macroblocks(tw, th),
        airplay_rs::encoder::MAX_MACROBLOCKS
    );
    if let Some(vo) = &extend_guard {
        // Reported from what the capture opened, never from what was requested.
        println!(
            "extend 1:1               : {}  (desktop {sw}x{sh}, coded {tw}x{th}, requested {}x{})",
            if (sw, sh) == (tw, th) && (sw, sh) == vo.size() {
                "yes — no scale pass"
            } else {
                "NO — the desktop is being scaled"
            },
            vo.size().0,
            vo.size().1,
        );
    }
    let info = pipe.encoder_info().clone();
    println!("encoder                  : {} ({})", info.kind, info.codec);
    if let Some(why) = pipe.encoder_note() {
        println!("encoder fallback         : {why}");
    }
    println!("extradata after open     : {} bytes (must be 0: SPS/PPS in-band)", info.extradata_len);
    match info.low_power_available {
        Some(true) => println!("low_power entrypoint     : AVAILABLE (still not used)"),
        Some(false) => println!("low_power entrypoint     : absent"),
        None => println!("low_power entrypoint     : not probed"),
    }

    // The real cipher over a fake socket: a throwaway shared secret is enough to
    // exercise the exact seal-and-frame path the receiver would see.
    let shared = [0x5au8; 64];
    let shk = [0x3cu8; 16];
    let mut streamer = MirrorStreamer::new(
        CountingSink::default(),
        VideoCipher::ChaCha20Poly1305,
        &shared,
        0x0123_4567_89ab_cdef,
        &shk,
        tw,
        th,
        0.075,
    );

    let mut file = match &out_path {
        Some(p) => Some(std::io::BufWriter::new(std::fs::File::create(p)?)),
        None => None,
    };

    let mut opts = RunOptions::with_limit(flags.limit);
    opts.sps_zero_constraints = flags.sps_zero_constraints;
    let cpu0 = cpu_seconds();
    let run = match &mut file {
        Some(f) => run_stream(&mut pipe, &mut streamer, &opts, Some(f)),
        None => run_stream(&mut pipe, &mut streamer, &opts, None),
    }?;
    let cpu = cpu_seconds() - cpu0;
    // Sticky, and re-read here because a rebuild mid-run can set it after the
    // open-time line above was printed.
    let encoder_note = pipe.encoder_note().map(str::to_string);
    // Read RSS while the pipeline is still up: after finish() the VA-API surface
    // pools are gone and the number would flatter the steady state by ~40 MB.
    let rss = vm_rss_kb();
    let stats = pipe.finish();
    if let Some(f) = &mut file {
        use std::io::Write;
        f.flush()?;
    }

    let (lmin, lmed, lp95, lmax) = stats.latency_ms;
    println!("---");
    if let Some(why) = &encoder_note {
        println!("encoder fallback         : {why}");
    }
    println!(
        "access units forwarded   : {}  ({} IDR, {} from keepalive repeats)",
        run.access_units, run.idr_units, run.repeat_units
    );
    println!(
        "encodes / packets / pics : {} / {} / {}  (all three must be equal)",
        stats.encoded, stats.encoder.packets_out, stats.encoder.pictures_out
    );
    println!(
        "VCL NALs / SPS / PPS/ SEI: {} / {} / {} / {}  (SEI must be 0)",
        stats.encoder.vcl_nals_out, stats.encoder.sps_out, stats.encoder.pps_out,
        stats.encoder.sei_out
    );
    println!(
        "frames captured          : {} fresh + {} repeats  (failures {}, reallocations {}, pts fixups {})",
        stats.capture.fresh, stats.capture.repeats, stats.capture.failures,
        stats.capture.reallocations, stats.capture.pts_fixups
    );
    println!(
        "zero-copy                : {} fallbacks, {} starved submissions (a starve costs a keepalive, not a frame)",
        stats.capture.zero_copy_fallbacks, stats.capture.buffer_starved
    );
    println!(
        "published / dropped      : {} / {}  ({} of them keepalive repeats; +{} pending; \
         produced == dropped + encoded + pending)",
        stats.produced, stats.dropped, stats.dropped_repeats, stats.pending
    );
    println!(
        "  ledger                 : {} == {} + {} + {}  -> {}",
        stats.produced,
        stats.dropped,
        stats.encoded,
        stats.pending,
        if stats.produced == stats.dropped + stats.encoded + stats.pending {
            "balances"
        } else {
            "MISMATCH — a frame went missing"
        }
    );
    println!("encoder reconfigures     : {}", stats.reconfigures);
    println!("heartbeats               : {}", run.heartbeats);
    println!(
        "measured rate            : {:.2} fps, {:.3} Mb/s over {:.1}s ({} annex-b bytes)",
        run.fps(),
        run.megabits_per_second(),
        run.seconds,
        run.bytes
    );
    if run.interrupted {
        println!(
            "interrupted              : yes ({}) — stopped early and shut down cleanly",
            airplay_rs::signals::signal_name().unwrap_or("signal")
        );
    }
    println!(
        "mirror channel wrote     : {} bytes in {} writes (headers + sealed avcC)",
        streamer.sink().bytes,
        streamer.sink().writes
    );
    let n = stats.encoder.frames_in.max(1) as f64;
    println!(
        "encode stage means       : {} {:.2} ms | convert+scale {:.2} ms | encode {:.2} ms",
        if info.dmabuf_input { "map    " } else { "upload " },
        stats.encoder.upload_us as f64 / n / 1e3,
        stats.encoder.convert_us as f64 / n / 1e3,
        stats.encoder.encode_us as f64 / n / 1e3
    );
    println!(
        "capture->encoded latency : min {lmin:.2} median {lmed:.2} p95 {lp95:.2} max {lmax:.2} ms"
    );
    println!(
        "process CPU              : {cpu:.3} s over {:.1} s = {:.1}% of one core",
        run.seconds,
        cpu / run.seconds.max(1e-9) * 100.0
    );
    println!(
        "VmRSS while streaming    : {rss} kB (flat across a run means no leak; \
         {} kB after teardown)",
        vm_rss_kb()
    );
    if let Some(p) = out_path {
        println!("wrote                    : {p} (annex-b; check with ffmpeg -err_detect explode)");
    }
    if let Some(vo) = extend_guard.take() {
        finish_extend(vo);
    }
    Ok(())
}

// ------------------------------------------------------------------- capture

fn cmd_capture_list() -> anyhow::Result<()> {
    let inv = airplay_rs::capture::list()?;
    println!("globals of interest:");
    for (iface, version) in &inv.globals {
        println!("  {iface:<58} v{version}");
    }
    println!("\noutputs:");
    for o in &inv.outputs {
        println!(
            "  output:{:<10} {}x{}@{:.2}",
            o.name,
            o.width,
            o.height,
            o.refresh_mhz as f64 / 1000.0
        );
    }
    println!("\ntoplevels (ext_foreign_toplevel_list_v1):");
    for t in &inv.toplevels {
        println!("  window:{:<20} title={:?}", t.app_id, t.title);
    }
    Ok(())
}

/// min / median / p95 / max of a sample set, in ms. Reported as exact
/// percentiles, never as a pass/fail threshold.
fn stat_ms(v: &mut [f64]) -> String {
    if v.is_empty() {
        return "n/a".into();
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)];
    format!("min {:.2} median {:.2} p95 {:.2} max {:.2} ms", v[0], p(0.5), p(0.95), v[v.len() - 1])
}

fn cmd_capture_bench(rest: &[String]) -> anyhow::Result<()> {
    use airplay_rs::capture::{Capture, CaptureConfig, CaptureSource};
    use std::time::{Duration, Instant};

    let spec = rest
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(String::as_str)
        .unwrap_or("output:eDP-1");
    // Same `--seconds` contract as `mirror`: 0 runs until stopped, a negative
    // is refused. A bench that cannot be left running is a bench you cannot
    // watch a leak on.
    let limit = seconds_flag(rest, 10.0)?;
    let keepalive_ms: u64 = flag_value(rest, "--keepalive")
        .map(|s| s.parse())
        .transpose()
        .map_err(|_| anyhow::anyhow!("--keepalive must be an integer (ms)"))?
        .unwrap_or(250);
    let dump = flag_value(rest, "--dump").map(str::to_string);

    let mut config = CaptureConfig::new(CaptureSource::parse(spec)?);
    config.paint_cursors = !rest.iter().any(|a| a == "--no-cursors");
    config.keepalive = Duration::from_millis(keepalive_ms);
    config.zero_copy = zero_copy_flag(rest)?;

    let mut cap = Capture::open(config.clone())?;
    let fmt = cap.format();
    println!("== capturing {} (paint_cursors={}) ==", cap.label(), config.paint_cursors);
    println!(
        "buffer                   : {}x{} stride {} {:?} ({} bytes, libav {})",
        fmt.width,
        fmt.height,
        fmt.stride,
        fmt.format,
        fmt.len(),
        fmt.format.ffmpeg_name()
    );
    let mode = cap.buffer_mode();
    match cap.zero_copy_note() {
        None => println!(
            "capture buffers          : {} x{} (--zero-copy {})",
            cap.buffer_count(),
            mode,
            config.zero_copy
        ),
        Some(why) => println!(
            "capture buffers          : {} x{} (--zero-copy {}; dmabuf unavailable: {why})",
            cap.buffer_count(),
            mode,
            config.zero_copy
        ),
    }
    let dma = cap.dmabuf_constraints().clone();
    match dma.device {
        Some(dev) => {
            let (major, minor) = airplay_rs::capture::dev_major_minor(dev);
            println!("dmabuf_device            : dev_t={dev} ({major}:{minor})");
        }
        None => println!("dmabuf_device            : (not sent)"),
    }
    for (f, mods) in &dma.formats {
        println!("dmabuf_format            : {}", airplay_rs::capture::fourcc_name(*f));
        for m in mods {
            println!("    modifier 0x{m:016x}  {}", airplay_rs::capture::modifier_name(*m));
        }
    }

    let mut scratch = vec![0u8; fmt.len()];
    let mut rotation = std::collections::BTreeSet::new();
    let mut gaps: Vec<f64> = Vec::new();
    let mut copies: Vec<f64> = Vec::new();
    let mut nonblack = 0usize;
    let mut first_pts = None;
    let mut last_pts = 0u64;
    let mut pts_backwards = 0usize;
    let mut last_emit: Option<Instant> = None;
    let mut fresh_gaps: Vec<f64> = Vec::new();
    let mut last_fresh: Option<Instant> = None;

    let started = Instant::now();
    let mut n = 0usize;
    let mut interrupted = false;
    // `--seconds 0` has no budget, so this is `true` forever and the stop-flag
    // check below is the only way out.
    while limit.still_running(started.elapsed()) {
        // Every loop in this binary polls the stop flag, not just the ones that
        // hold a teardown guard: with handlers installed, a loop that does NOT
        // poll it looks to the user like a process ignoring Ctrl-C.
        if airplay_rs::signals::interrupted() {
            interrupted = true;
            break;
        }
        let frame = cap.next_frame()?;
        let now = Instant::now();
        if frame.timestamp_ns < last_pts {
            pts_backwards += 1;
        }
        last_pts = frame.timestamp_ns;
        if first_pts.is_none() {
            first_pts = Some((frame.timestamp_ns, frame.kind));
        }
        if let Some(prev) = last_emit {
            gaps.push((now - prev).as_secs_f64() * 1e3);
        }
        last_emit = Some(now);
        if frame.kind == airplay_rs::capture::FrameKind::Fresh {
            if let Some(prev) = last_fresh {
                fresh_gaps.push((now - prev).as_secs_f64() * 1e3);
            }
            last_fresh = Some(now);
        }

        match frame.data.shm() {
            Some(pixels) => {
                // Time a full copy out of the mapping: this is the cost the shm
                // arm of the encoder pays, and the number dmabuf deletes.
                // Size from the frame, not from the format the session opened
                // with: `buffer_constraints` can re-allocate the capture to a
                // new geometry mid-run, and a fixed-size copy_from_slice would
                // panic on exactly the resize this bench exists to measure.
                let need = pixels.len();
                if scratch.len() < need {
                    scratch.resize(need, 0);
                }
                let t0 = Instant::now();
                scratch[..need].copy_from_slice(pixels);
                copies.push(t0.elapsed().as_secs_f64() * 1e3);
                if scratch[..need].iter().step_by(997).any(|&b| b != 0) {
                    nonblack += 1;
                }
                if n == 0 {
                    if let Some(path) = &dump {
                        write_ppm(path, pixels, frame.width, frame.height, frame.stride)?;
                        println!("wrote first frame to {path}");
                    }
                }
            }
            None => {
                // Zero-copy: there is nothing on the CPU to read, count or
                // dump, and reading it would be exactly the cost this path
                // exists to avoid. Record which buffer came back instead, so a
                // set that never rotates is visible.
                if let Some(image) = frame.data.dmabuf() {
                    if n == 0 {
                        println!("first dmabuf             : {image:?}");
                    }
                    rotation.insert(image.id);
                }
            }
        }
        n += 1;
    }
    let elapsed = started.elapsed().as_secs_f64();
    let s = cap.stats();

    println!("\n== results over {elapsed:.1} s ==");
    if interrupted {
        println!(
            "interrupted              : yes ({}) — measured up to the signal",
            airplay_rs::signals::signal_name().unwrap_or("signal")
        );
    }
    println!("frames emitted           : {n}  (fresh {} + repeats {})", s.fresh, s.repeats);
    println!("frames non-black         : {nonblack} / {n}");
    println!("capture failures         : {}", s.failures);
    println!("buffer re-allocations    : {}", s.reallocations);
    println!("session restarts         : {}", s.session_restarts);
    println!("timestamps going backward: {pts_backwards}  (pts fixups applied: {})", s.pts_fixups);
    println!("effective rate           : {:.1} frames/s", n as f64 / elapsed);
    println!(
        "fresh-frame rate         : {:.1} frames/s  (damage-limited: an idle screen yields none)",
        s.fresh as f64 / elapsed
    );
    println!("inter-emission gap       : {}", stat_ms(&mut gaps));
    let vblanks = fresh_gaps.iter().filter(|g| (15.5..=17.9).contains(*g)).count();
    println!(
        "fresh-frame gap          : {}   one-vblank gaps (15.5-17.9 ms): {} / {}",
        stat_ms(&mut fresh_gaps),
        vblanks,
        fresh_gaps.len()
    );
    match mode {
        airplay_rs::capture::BufferMode::Shm => {
            println!("copy out of shm          : {}", stat_ms(&mut copies))
        }
        airplay_rs::capture::BufferMode::Dmabuf => println!(
            "copy out of shm          : none — {} distinct dmabufs rotated, 0 bytes read on the CPU",
            rotation.len()
        ),
    }
    println!(
        "zero-copy                : {} fallbacks, {} starved submissions",
        s.zero_copy_fallbacks, s.buffer_starved
    );
    println!(
        "first frame              : {:?}",
        first_pts.map(|(ts, k)| format!("{k:?} pts={ts} ns (CLOCK_MONOTONIC)"))
    );
    Ok(())
}

/// Dump a frame as a PPM so a human can look at it. shm XRGB8888 is
/// little-endian 0xXXRRGGBB, i.e. bytes B,G,R,X.
fn write_ppm(path: &str, data: &[u8], w: u32, h: u32, stride: u32) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = Vec::with_capacity((w * h * 3 + 32) as usize);
    write!(out, "P6\n{w} {h}\n255\n")?;
    for y in 0..h as usize {
        let row = &data[y * stride as usize..y * stride as usize + w as usize * 4];
        for px in row.as_chunks::<4>().0 {
            out.extend_from_slice(&[px[2], px[1], px[0]]);
        }
    }
    std::fs::write(path, out)
}

/// `airplay encode-bench` — the offline encoder gate. No compositor and no
/// receiver: synthetic BGR0 frames go in, Annex-B access units come out, and
/// every count printed is exact. This is the cheapest place to catch a
/// mis-sliced or mis-sized stream before it costs a trip to the TV.
fn cmd_encode_bench(rest: &[String]) -> anyhow::Result<()> {
    use airplay_rs::encoder::{
        self, Encoder, EncoderConfig, EncoderKind, LEVEL42_MAX_MBPS, MAX_MACROBLOCKS,
    };
    use std::time::Instant;

    let parse_size = |s: &str| -> anyhow::Result<(u32, u32)> {
        let (w, h) = s
            .split_once(['x', 'X'])
            .ok_or_else(|| anyhow::anyhow!("expected WxH, got {s:?}"))?;
        Ok((w.trim().parse()?, h.trim().parse()?))
    };

    let kind = match flag_value(rest, "--encoder") {
        Some(s) => EncoderKind::parse(s)
            .ok_or_else(|| anyhow::anyhow!("--encoder must be cpu or gpu, got {s:?}"))?,
        None => EncoderKind::Gpu,
    };
    let source = match flag_value(rest, "--source") {
        Some(s) => parse_size(s)?,
        None => (1920, 1200),
    };
    let receiver = match flag_value(rest, "--receiver") {
        Some(s) => parse_size(s)?,
        None => (1920, 1080),
    };
    let frames: u32 = flag_value(rest, "--frames")
        .map(str::parse)
        .transpose()?
        .unwrap_or(400);
    let fps: u32 = flag_value(rest, "--fps").map(str::parse).transpose()?.unwrap_or(60);
    let qp: u32 = flag_value(rest, "--qp").map(str::parse).transpose()?.unwrap_or(25);
    let keyint: f64 = flag_value(rest, "--keyint")
        .map(str::parse)
        .transpose()?
        .unwrap_or(5.0);
    let out_path = flag_value(rest, "--out").map(str::to_string);
    // The bench normally keeps every access unit so the whole stream can be
    // re-split and written out. --no-retain drops them instead, which is what
    // makes a long run a usable leak check: otherwise RSS grows by the bitrate.
    let retain = out_path.is_some() || !rest.iter().any(|a| a == "--no-retain");

    let target = encoder::fit_source_to_receiver(source, receiver);
    let mut cfg = EncoderConfig::new(source, target);
    cfg.kind = kind;
    cfg.fps = fps;
    cfg.qp = qp;
    cfg.keyframe_seconds = keyint;
    cfg.probe_low_power = kind == EncoderKind::Gpu && !rest.iter().any(|a| a == "--no-probe");
    cfg.cpu_slices = flag_value(rest, "--slices").map(str::parse).transpose()?;
    if let Some(d) = flag_value(rest, "--device") {
        cfg.device = d.to_string();
    }

    println!("== encode-bench ==");
    println!("encoder                  : {kind} ({})", kind.codec_name());
    println!(
        "source -> target         : {}x{} -> {}x{}  ({} macroblocks, budget {MAX_MACROBLOCKS})",
        source.0,
        source.1,
        target.0,
        target.1,
        encoder::macroblocks(target.0, target.1)
    );

    let open0 = Instant::now();
    let mut enc = Encoder::new(cfg)?;
    let open_ms = open0.elapsed().as_secs_f64() * 1e3;
    let info = enc.info().clone();
    println!("open                     : {open_ms:.1} ms");
    println!("extradata after open     : {} bytes (must be 0: SPS/PPS in-band)", info.extradata_len);
    match info.low_power_available {
        Some(true) => println!("low_power entrypoint     : AVAILABLE (still not used; see module docs)"),
        Some(false) => println!("low_power entrypoint     : absent (driver has no VAEntrypointEncSliceLP)"),
        None => println!("low_power entrypoint     : not probed"),
    }
    for (k, v) in &info.options {
        println!("    opt {k:<12} = {v}");
    }

    // Synthetic BGR0 at the capture layer's byte order and stride.
    let stride = source.0 * 4;
    let mut buf = vec![0u8; (stride * source.1) as usize];

    let mut stream: Vec<u8> = Vec::new();
    let mut per_frame: Vec<f64> = Vec::new();
    let mut paint: Vec<f64> = Vec::new();
    let mut slice_hist: std::collections::BTreeMap<u32, u32> = Default::default();
    let mut idr_at: Vec<u32> = Vec::new();
    let mut sps_at: Vec<u32> = Vec::new();
    let mut pps_at: Vec<u32> = Vec::new();
    let mut au_index = 0u32;
    let mut au_sizes: Vec<usize> = Vec::new();

    let frame_ns = 1_000_000_000u64 / fps.max(1) as u64;
    let mut encode_cpu = 0.0f64;
    let cpu0 = cpu_seconds();
    let wall0 = Instant::now();
    let mut interrupted = false;
    for t in 0..frames {
        // Same reason as capture-bench: a loop that does not poll the flag would
        // appear to ignore the first Ctrl-C. `t > 0` keeps at least one frame in
        // the latency vectors, which the percentile closure below indexes
        // unconditionally.
        if t > 0 && airplay_rs::signals::interrupted() {
            interrupted = true;
            break;
        }
        let p0 = Instant::now();
        airplay_rs::encoder::paint_bgr0(&mut buf, source.0, source.1, stride, t);
        paint.push(p0.elapsed().as_secs_f64() * 1e3);

        let (e0, c0) = (Instant::now(), process_cpu_seconds());
        let units = enc.encode(&buf, stride, source, t as u64 * frame_ns)?;
        per_frame.push(e0.elapsed().as_secs_f64() * 1e3);
        encode_cpu += process_cpu_seconds() - c0;

        for u in units {
            *slice_hist.entry(u.slices).or_default() += 1;
            if u.is_idr {
                idr_at.push(au_index);
            }
            if u.has_sps {
                sps_at.push(au_index);
            }
            if u.has_pps {
                pps_at.push(au_index);
            }
            au_sizes.push(u.data.len());
            if retain {
                stream.extend_from_slice(&u.data);
            }
            au_index += 1;
        }
    }
    for u in enc.flush()? {
        *slice_hist.entry(u.slices).or_default() += 1;
        au_sizes.push(u.data.len());
        stream.extend_from_slice(&u.data);
        au_index += 1;
    }
    let wall = wall0.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu0;
    let paint_total: f64 = paint.iter().sum::<f64>() / 1e3;

    let stats = enc.stats();
    let split = airplay_rs::testpattern::split_access_units(&stream);
    let whole = airplay_rs::encoder::scan_annexb(&stream);

    let pct = |v: &mut Vec<f64>, p: usize| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[(v.len() * p / 100).min(v.len() - 1)]
    };
    let mut pf = per_frame.clone();
    let mut pn = paint.clone();

    println!("---");
    if interrupted {
        println!(
            "interrupted              : yes ({}) — fewer frames than --frames asked for",
            airplay_rs::signals::signal_name().unwrap_or("signal")
        );
    }
    println!("frames submitted         : {}", stats.frames_in);
    println!("packets out              : {}", stats.packets_out);
    println!("access units returned    : {au_index}");
    println!("pictures in the bitstream: {}  (must equal packets)", stats.pictures_out);
    if retain {
        println!("split_access_units() says: {}  (must equal packets)", split.len());
    } else {
        println!("split_access_units() says: (not retained)");
    }
    // Retention-independent: accumulated per packet in `Encoder::drain`, so it
    // is exact under --no-retain too. Never print a literal 0 for a count that
    // was not measured.
    println!("VCL NALs                 : {}", stats.vcl_nals_out);
    println!("slices per picture       : {slice_hist:?}");
    println!("IDR access units at      : {idr_at:?}");
    println!("SPS at                   : {sps_at:?}");
    println!("PPS at                   : {pps_at:?}");
    println!("SEI NALs                 : {}  (sei=0 means 0)", stats.sei_out);
    println!("AUD NALs                 : {}  (aud=0 means 0)", stats.aud_out);
    if retain {
        assert_eq!(
            whole.aud as u64, stats.aud_out,
            "the re-scan and the encoder's own AUD count must agree"
        );
    }
    println!(
        "bytes                    : {}  ({:.2} Mb/s at {fps} fps)",
        stats.bytes_out,
        stats.bytes_out as f64 * 8.0 / (frames as f64 / fps as f64) / 1e6
    );
    let au_max = au_sizes.iter().max().copied().unwrap_or(0);
    println!(
        "AU size                  : min {} max {} distinct {}",
        au_sizes.iter().min().copied().unwrap_or(0),
        au_max,
        au_sizes.iter().collect::<std::collections::BTreeSet<_>>().len()
    );
    // The ceiling, next to the mean above. A single picture this big arrives at
    // the receiver as one burst, so the rate that matters to a link is the peak
    // one, not the average — and under CQP nothing bounds it. Level 4.2 declares
    // MaxBR 62.5 Mb/s, and the stream advertises level 4.2.
    let peak_mbps = au_max as f64 * 8.0 * fps as f64 / 1e6;
    let ceiling = airplay_rs::encoder::max_au_bytes(fps);
    println!(
        "peak instantaneous rate  : {peak_mbps:.2} Mb/s (biggest AU x {fps} fps) -> {}",
        if au_max <= ceiling {
            format!("within the level-4.2 {:.1} Mb/s budget", LEVEL42_MAX_MBPS)
        } else {
            format!(
                "OVER the level-4.2 {LEVEL42_MAX_MBPS:.1} Mb/s budget ({au_max} B > {ceiling} B)"
            )
        }
    );
    println!(
        "encode per frame         : median {:.3} ms  p95 {:.3} ms  max {:.3} ms",
        pct(&mut pf, 50),
        pct(&mut pf, 95),
        pf[pf.len() - 1]
    );
    println!("paint (not encode cost)  : median {:.3} ms", pct(&mut pn, 50));
    let n = stats.frames_in.max(1) as f64;
    println!(
        "  stage means            : upload {:.3} ms | convert+scale {:.3} ms | encode {:.3} ms",
        stats.upload_us as f64 / n / 1e3,
        stats.convert_us as f64 / n / 1e3,
        stats.encode_us as f64 / n / 1e3
    );
    println!(
        "wall                     : {wall:.3} s total, {:.3} s excluding paint -> {:.1} fps of capacity",
        wall - paint_total,
        frames as f64 / (wall - paint_total)
    );
    println!(
        "process CPU (incl. paint): {cpu:.3} s -> {:.2} ms/frame",
        cpu / frames as f64 * 1e3
    );
    println!(
        "CPU inside encode() only : {encode_cpu:.3} s -> {:.2} ms/frame, {:.1}% of one core at {fps} fps",
        encode_cpu / frames as f64 * 1e3,
        encode_cpu / frames as f64 * fps as f64 * 100.0
    );

    println!("VmRSS now                : {} kB (a long --no-retain run must be flat)", vm_rss_kb());

    if let Some(p) = out_path {
        std::fs::write(&p, &stream)?;
        println!("wrote                    : {p} ({} bytes)", stream.len());
    }
    Ok(())
}

/// Current resident set size in kB, for leak-watching a long run.
fn vm_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

/// Process CPU seconds at nanosecond resolution, for bracketing a single call.
/// /proc/self/stat only has 10 ms ticks, which is useless per frame.
fn process_cpu_seconds() -> f64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: writing a timespec we own; CLOCK_PROCESS_CPUTIME_ID is always valid.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) } != 0 {
        return 0.0;
    }
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

/// Process CPU seconds (user+sys) from /proc/self/stat.
fn cpu_seconds() -> f64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/stat") else {
        return 0.0;
    };
    let Some(after_comm) = s.rfind(')').map(|i| &s[i + 1..]) else {
        return 0.0;
    };
    let f: Vec<&str> = after_comm.split_whitespace().collect();
    let get = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    // utime and stime are fields 14 and 15 (1-based); after comm they are 11 and 12.
    (get(11) + get(12)) / 100.0
}

// ===================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    fn args(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn optional_flag_value_absent_is_none() {
        assert_eq!(optional_flag_value(&args(&["--fps", "30"]), "--extend"), None);
    }

    #[test]
    fn optional_flag_value_bare_flag_is_some_none() {
        assert_eq!(optional_flag_value(&args(&["--extend"]), "--extend"), Some(None));
        assert_eq!(
            optional_flag_value(&args(&["--extend", "--fps", "30"]), "--extend"),
            Some(None),
            "a bare --extend must not swallow the flag that follows it"
        );
    }

    #[test]
    fn optional_flag_value_with_a_value() {
        assert_eq!(
            optional_flag_value(&args(&["--extend", "AIRPLAY-2", "--fps", "30"]), "--extend"),
            Some(Some("AIRPLAY-2"))
        );
    }

    #[test]
    fn extend_request_distinguishes_append_from_a_name_and_validates() {
        assert_eq!(extend_request_from(&args(&[])).unwrap(), None);
        // A bare `--extend` is `Append`, NOT a default name: the name is
        // `AIRPLAY-<next workspace>` and only the live compositor knows which,
        // so it stays unresolved until `resolve_extend`. That is the whole
        // reason this is an enum and not an `Option<String>` with a constant
        // in it.
        assert_eq!(
            extend_request_from(&args(&["--extend"])).unwrap(),
            Some(ExtendRequest::Append)
        );
        assert_eq!(
            extend_request_from(&args(&["--extend", "AIRPLAY-tv"])).unwrap(),
            Some(ExtendRequest::Named("AIRPLAY-tv".into()))
        );
        // An explicit name is resolvable with no compositor at all.
        assert_eq!(
            resolve_extend(&ExtendRequest::Named("AIRPLAY-7".into())).unwrap(),
            "AIRPLAY-7"
        );
        // The name reaches a Lua string literal and an argv. `eDP-1` is the user's
        // actual panel and must be unreachable from every path in this program.
        for bad in ["eDP-1", "HEADLESS-1", "../x", "AIRPLAY-$(x)", "AIRPLAY-1\"})--"] {
            assert!(
                extend_request_from(&args(&["--extend", bad])).is_err(),
                "--extend {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn capture_source_from_extend_yields_an_output_source() {
        use airplay_rs::capture::CaptureSource;
        // Identical to what --output NAME yields: below this point nothing
        // knows Extend exists. The name is passed in already resolved, which is
        // what guarantees the source and the created output are one string —
        // and lets this stay an offline test now that a bare `--extend` needs
        // the compositor.
        assert_eq!(
            capture_source_from(&args(&["--extend"]), Some("AIRPLAY-7")).unwrap(),
            CaptureSource::Output("AIRPLAY-7".to_string())
        );
        assert_eq!(
            capture_source_from(&args(&["--extend", "AIRPLAY-2"]), Some("AIRPLAY-2")).unwrap(),
            capture_source_from(&args(&["--output", "AIRPLAY-2"]), None).unwrap()
        );
    }

    #[test]
    fn capture_source_from_sources_are_mutually_exclusive() {
        for pair in [
            vec!["--output", "eDP-1", "--window", "brave"],
            vec!["--output", "eDP-1", "--extend"],
            vec!["--window", "brave", "--extend"],
            vec!["--output", "eDP-1", "--window", "brave", "--extend", "AIRPLAY-2"],
        ] {
            // `--extend` in the pair is already resolved to a name by the time
            // it reaches here, so the exclusion is checked on the resolved form.
            let extend = pair.contains(&"--extend").then_some("AIRPLAY-7");
            let e = capture_source_from(&args(&pair), extend).expect_err("must be rejected");
            assert!(
                e.to_string().contains("mutually exclusive"),
                "{pair:?} gave {e}"
            );
        }
    }

    #[test]
    fn screen_flags_carries_the_extend_name_alongside_the_source() {
        use airplay_rs::capture::CaptureSource;
        let f = screen_flags(&args(&["--extend", "AIRPLAY-2", "--fps", "30"]), 10.0).unwrap();
        assert_eq!(f.extend.as_deref(), Some("AIRPLAY-2"));
        assert_eq!(f.source, CaptureSource::Output("AIRPLAY-2".to_string()));
        assert_eq!(f.fps, 30, "--extend NAME must not eat the flags after it");

        // And --output leaves it unset, so the non-extend paths cannot acquire
        // an output-creating side effect by accident.
        let f = screen_flags(&args(&["--output", "eDP-1"]), 10.0).unwrap();
        assert_eq!(f.extend, None);
    }

    /// `--seconds 0` is "run until stopped" in every source mode, the default
    /// survives its absence, and a negative is refused at the keyboard.
    #[test]
    fn seconds_zero_is_indefinite_in_every_source_mode() {
        use airplay_rs::pipeline::RunLimit;

        // `--output`, `--window` and `--extend NAME` all reach the same parse;
        // `--test-pattern` has no screen flags and is checked separately below.
        for source in [
            vec!["--output", "eDP-1"],
            vec!["--window", "brave"],
            vec!["--extend", "AIRPLAY-2"],
        ] {
            let mut zero = source.clone();
            zero.extend_from_slice(&["--seconds", "0"]);
            assert_eq!(
                screen_flags(&args(&zero), 30.0).unwrap().limit,
                RunLimit::UntilStopped,
                "{source:?} --seconds 0 must run until stopped"
            );

            // Absent keeps the command's default. Indefinite is NOT the default.
            assert_eq!(
                screen_flags(&args(&source), 30.0).unwrap().limit,
                RunLimit::Seconds(30.0),
                "{source:?} with no --seconds must keep the 30 s default"
            );

            let mut fixed = source.clone();
            fixed.extend_from_slice(&["--seconds", "7.5"]);
            assert_eq!(
                screen_flags(&args(&fixed), 30.0).unwrap().limit,
                RunLimit::Seconds(7.5)
            );

            // A negative is an error with a message that says what to use
            // instead, never a second spelling of "indefinite".
            let mut neg = source.clone();
            neg.extend_from_slice(&["--seconds", "-5"]);
            let msg = match screen_flags(&args(&neg), 30.0) {
                Err(e) => e.to_string(),
                Ok(_) => panic!("{source:?} --seconds -5 must be refused"),
            };
            assert!(
                msg.contains("must not be negative") && msg.contains("0 to run until stopped"),
                "{source:?} gave {msg:?}"
            );

            let mut bad = source.clone();
            bad.extend_from_slice(&["--seconds", "soon"]);
            assert!(screen_flags(&args(&bad), 30.0).is_err());
        }

        // The `--test-pattern` path, which parses `--seconds` on its own.
        assert_eq!(
            seconds_flag(&args(&["--test-pattern", "--seconds", "0"]), 30.0).unwrap(),
            RunLimit::UntilStopped
        );
        assert_eq!(
            seconds_flag(&args(&["--test-pattern"]), 30.0).unwrap(),
            RunLimit::Seconds(30.0)
        );
        assert!(seconds_flag(&args(&["--test-pattern", "--seconds", "-1"]), 30.0).is_err());

        // What the run prints about itself, so a short ledger is explained.
        assert_eq!(run_phrase(RunLimit::Seconds(30.0)), "for 30s");
        assert!(run_phrase(RunLimit::UntilStopped).starts_with("until stopped"));
    }

    /// `discover`'s pattern is a name, and neither a flag nor a flag's value
    /// may be mistaken for one.
    #[test]
    fn discover_separates_the_name_pattern_from_its_flags() {
        assert_eq!(discover_pattern(&args(&[])), None);
        assert_eq!(discover_pattern(&args(&["office"])), Some("office"));
        assert_eq!(discover_pattern(&args(&["--json"])), None);
        assert_eq!(discover_pattern(&args(&["--json", "office"])), Some("office"));
        // The one that would otherwise search for a receiver called "3".
        assert_eq!(discover_pattern(&args(&["--timeout", "3"])), None);
        assert_eq!(
            discover_pattern(&args(&["--timeout", "3", "office"])),
            Some("office")
        );
        assert_eq!(
            discover_pattern(&args(&["office", "--timeout", "3", "--json"])),
            Some("office")
        );

        // The timeout itself: a positive number of seconds, or an error.
        assert_eq!(
            discover_timeout(&args(&[])).unwrap(),
            std::time::Duration::from_secs_f64(DISCOVER_TIMEOUT_DEFAULT)
        );
        assert_eq!(
            discover_timeout(&args(&["--timeout", "0.5"])).unwrap(),
            std::time::Duration::from_millis(500)
        );
        for bad in ["0", "-1", "abc", "inf"] {
            assert!(
                discover_timeout(&args(&["--timeout", bad])).is_err(),
                "--timeout {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn audio_flags_default_off_and_validate() {
        use airplay_rs::session::{AudioMode, CaptureBackend};
        let f = audio_flags(&args(&["--output", "eDP-1"])).unwrap();
        assert_eq!(f, AudioFlags { mode: AudioMode::None, latency_ms: 300, av_offset_ms: None, volume_sync: true });
        assert_eq!(audio_flags(&args(&["--no-audio"])).unwrap().mode, AudioMode::None);
        // `--audio system` alone now means SINK mode: the laptop's output
        // moves to the TV. The old behaviour — the sound on the laptop too —
        // is still reachable, by name.
        assert_eq!(
            audio_flags(&args(&["--audio", "system"])).unwrap().mode,
            AudioMode::System { capture: CaptureBackend::Sink }
        );
        for (want, backend) in [
            ("sink", CaptureBackend::Sink),
            ("pipewire", CaptureBackend::Pipewire),
            ("parec", CaptureBackend::Parec),
        ] {
            assert_eq!(
                audio_flags(&args(&["--audio", "system", "--audio-capture", want])).unwrap().mode,
                AudioMode::System { capture: backend },
                "--audio-capture {want}"
            );
            // The spelling the flag takes is the spelling status reports.
            assert_eq!(backend.as_str(), want);
        }
        let f = audio_flags(&args(&["--audio", "tone", "--av-offset", "-40", "--audio-latency", "400", "--no-volume-sync"])).unwrap();
        assert_eq!(f, AudioFlags { mode: AudioMode::Tone, latency_ms: 400, av_offset_ms: Some(-40), volume_sync: false });
        // 300 + 0 is inside the clamp; 100 + 0 and 1900 + 500 are not.
        assert_eq!(audio_flags(&args(&["--audio", "system"])).unwrap().clamped_effective_ms(), None);
        assert_eq!(
            audio_flags(&args(&["--audio", "system", "--audio-latency", "100"])).unwrap().clamped_effective_ms(),
            Some(200)
        );
        assert_eq!(
            audio_flags(&args(&["--audio", "tone", "--audio-latency", "1900", "--av-offset", "500"]))
                .unwrap()
                .clamped_effective_ms(),
            Some(2000)
        );
        for bad in [
            &["--audio", "loud"][..],
            &["--audio"],
            &["--audio", "system", "--no-audio"],
            &["--audio", "system", "--audio-capture", "alsa"],
            &["--audio-capture", "parec"],
            &["--audio", "system", "--av-offset", "2000"],
            &["--audio", "system", "--av-offset", "x"],
            &["--av-offset", "100"],
            &["--audio-latency", "300"],
        ] {
            assert!(audio_flags(&args(bad)).is_err(), "{bad:?} should be rejected");
        }
    }

    /// `airplay audio`'s own flags. `--status` is read-only and `--cleanup`
    /// CHANGES THE OUTPUT, so a typo on a `--cleanup` line must stop rather
    /// than be ignored — that is the asymmetry this pins.
    #[test]
    fn audio_subcommand_flags() {
        assert_eq!(audio_cmd(&args(&[])).unwrap(), AudioCmd::Status);
        assert_eq!(audio_cmd(&args(&["--status"])).unwrap(), AudioCmd::Status);
        assert_eq!(audio_cmd(&args(&["--cleanup"])).unwrap(), AudioCmd::Cleanup);
        assert_eq!(audio_cmd(&args(&["--hold", "30"])).unwrap(), AudioCmd::Hold(30));

        for bad in [
            &["--hold"][..],
            &["--hold", "soon"],
            // Would take the output and give it straight back — a no-op that
            // looks like a hang.
            &["--hold", "0"],
            &["--hold", "-1"],
            &["--hold", "30", "--cleanup"],
            // A typo on the line that changes the output.
            &["--cleanup", "--dry-run"],
            &["--cleanup", "--status"],
            &["--clean"],
            &["--status", "extra"],
        ] {
            assert!(audio_cmd(&args(bad)).is_err(), "audio {bad:?} should be rejected");
        }
    }

    #[test]
    fn below_proven_latency_checks_the_effective_value() {
        let w = |a: &[&str]| audio_flags(&args(a)).unwrap().below_proven_latency_ms();
        // The bug: base 300 + offset -100 tells the TV 200 ms and was silent.
        assert_eq!(w(&["--audio", "system", "--av-offset", "-100"]), Some(200));
        assert_eq!(w(&["--audio", "system", "--audio-latency", "250"]), Some(250));
        assert_eq!(w(&["--audio", "system", "--audio-latency", "100"]), Some(200));
        assert_eq!(w(&["--audio", "system"]), None);
        assert_eq!(w(&["--audio", "system", "--audio-latency", "250", "--av-offset", "50"]), None);
    }

    /// The `status` record is derived from what the run actually is, including
    /// for the two kinds that never wrote one before.
    #[test]
    fn a_session_record_is_written_for_every_source_kind() {
        use airplay_rs::sessionstate::SessionKind;

        let f = screen_flags(&args(&["--output", "eDP-1"]), 30.0).unwrap();
        let r = session_record(Some(&f), None, "192.0.2.187");
        assert_eq!(r.kind, SessionKind::Output);
        assert_eq!(r.name.as_deref(), Some("eDP-1"));
        assert_eq!(r.workspace, None);
        assert_eq!(r.receiver.as_deref(), Some("192.0.2.187"));
        assert_eq!(r.pid, std::process::id());

        let f = screen_flags(&args(&["--window", "Brave"]), 30.0).unwrap();
        let r = session_record(Some(&f), None, "192.0.2.187");
        assert_eq!(r.kind, SessionKind::Window);
        assert_eq!(r.name.as_deref(), Some("Brave"));

        // `--test-pattern` has no screen flags at all.
        let r = session_record(None, None, "192.0.2.187");
        assert_eq!(r.kind, SessionKind::TestPattern);
        assert_eq!(r.name, None);
        assert_eq!(r.workspace, None);
        // The `--extend` case needs a live `VirtualOutput`, so it is covered by
        // the hardware-gated `status` test in tests/virtualoutput_live.rs.
    }
}
