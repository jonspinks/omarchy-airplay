//! SIGINT / SIGTERM / SIGHUP turned into a **flag**, so the stream loop returns
//! normally and every `Drop` guard runs.
//!
//! Rust installs no handler of its own: the default disposition kills the
//! process outright. Measured on this crate before this module existed, with the
//! binary signalled directly (not through a shell wrapper — see the note below):
//! `kill -INT` gave exit 130 and `kill -TERM` exit 143, in both cases with *zero*
//! destructors run. On the `--extend` path that means
//! [`crate::virtualoutput::VirtualOutput::drop`] never fires and a phantom
//! monitor is left on the desktop.
//!
//! So: the handler sets an `AtomicBool` and nothing else. It does not print, it
//! does not allocate, and above all it does not spawn `hyprctl` — `fork`/`exec`
//! is not async-signal-safe, and neither is Rust's allocator. The loops in
//! [`crate::pipeline::run_stream`] and `Session::stream_test_pattern` poll
//! [`interrupted`] and break, which unwinds the ordinary way: the pipeline is
//! joined, the session is torn down, and the virtual output is removed.
//!
//! **The second signal still kills.** A flag is only honoured by code that polls
//! it, and this binary spends real time in places that do not — pairing, session
//! bring-up, ffmpeg's test-pattern generation. Swallowing SIGINT there would
//! leave the user holding Ctrl-C at a process that appears to ignore him, which is
//! worse than the leak. So the first signal sets the flag and the second one
//! restores the default disposition and re-raises, killing the process with the
//! correct status. The phantom that leaves behind is covered by the third
//! teardown layer: `airplay extend --cleanup`, and the automatic reclaim on the
//! next `--extend` run.
//!
//! One measured caveat on that escape hatch: SIGINT is a **standard** signal, so
//! it is not queued. Two `kill()`s issued back to back from another process can
//! collapse into a single delivery while the first is still pending — measured
//! here, where `kill -INT` twice in immediate succession produced one handler
//! call and a perfectly clean shutdown. A human pressing Ctrl-C twice is
//! hundreds of milliseconds apart and sees the documented behaviour; a *script*
//! wanting the hard kill should send SIGKILL, or leave a gap.
//!
//! ## Measuring this
//!
//! Backgrounding with `&` inside a shell and then `kill -INT $!` signals the
//! **shell wrapper**, not the binary: the binary is reparented and runs happily
//! to completion while `wait` reports 143. Two measurements were wrong that way
//! before anyone noticed. Signal the binary:
//!
//! ```text
//! setsid ./airplay mirror-bench --extend ... & sleep 3
//! kill -INT "$(pgrep -x airplay)"
//! ```

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

use libc::c_int;

/// Set by the first handled signal, never cleared except by [`reset`].
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
/// Which signal it was, for the ledger line.
static SIGNO: AtomicI32 = AtomicI32::new(0);
/// How many handled signals have arrived. The second one is fatal by design.
static COUNT: AtomicU32 = AtomicU32::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// The three signals a user or a service manager sends to mean "stop now".
///
/// Deliberately *not* SIGSEGV/SIGABRT: a handler that runs `hyprctl` from a
/// corrupted process is a worse idea than the reclaim-on-next-start sweep that
/// already covers those.
const HANDLED: [c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The handler. **Async-signal-safe only**: atomic stores, `sigaction(2)` and
/// `raise(3)`, all of which POSIX lists as safe. Nothing else belongs here.
extern "C" fn handler(sig: c_int) {
    if COUNT.fetch_add(1, Ordering::SeqCst) >= 1 {
        // Asked twice: stop pretending to be polite. Put the default
        // disposition back and re-raise, so the process dies right now and with
        // the status the shell expects, rather than looking wedged.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut act.sa_mask);
            libc::sigaction(sig, &act, std::ptr::null_mut());
            libc::raise(sig);
        }
        return;
    }
    SIGNO.store(sig, Ordering::SeqCst);
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// SAFETY: installs a process-wide disposition; `handler` is `extern "C"` and
/// async-signal-safe.
unsafe fn install_one(sig: c_int) -> io::Result<()> {
    let mut act: libc::sigaction = std::mem::zeroed();
    act.sa_sigaction = handler as *const () as usize;
    libc::sigemptyset(&mut act.sa_mask);
    // SA_RESTART: restart interrupted syscalls rather than fail them with
    // EINTR. Every blocking call in this crate — the RTSP socket reads, the
    // Wayland poll, the mirror-channel writes — predates this module and none
    // of them retry on EINTR, so without SA_RESTART a Ctrl-C would turn a clean
    // shutdown into a spray of io errors from three threads at once.
    act.sa_flags = libc::SA_RESTART;
    if libc::sigaction(sig, &act, std::ptr::null_mut()) != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Install the handlers. Idempotent, and safe to call from `main` before
/// anything else exists.
///
/// An error here is worth reporting but not worth refusing to run over: the only
/// consequence is that Ctrl-C reverts to killing the process outright, which is
/// exactly what it did before this module.
pub fn install() -> io::Result<()> {
    if INSTALLED.load(Ordering::SeqCst) {
        return Ok(());
    }
    for sig in HANDLED {
        // SAFETY: see `install_one`.
        unsafe { install_one(sig)? };
    }
    INSTALLED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Has a stop signal arrived? Polled by the streaming loops.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Which signal set the flag, as a name — `"SIGINT"`, `"SIGTERM"`, `"SIGHUP"` —
/// or `None` if none has.
pub fn signal_name() -> Option<&'static str> {
    match SIGNO.load(Ordering::SeqCst) {
        libc::SIGINT => Some("SIGINT"),
        libc::SIGTERM => Some("SIGTERM"),
        libc::SIGHUP => Some("SIGHUP"),
        _ => None,
    }
}

/// Clear the flag. **Tests only** — a run that has been asked to stop should
/// stop, not be talked out of it.
pub fn reset() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    SIGNO.store(0, Ordering::SeqCst);
    COUNT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, not four.
    ///
    /// The flag, the count and the handler disposition are all process-wide, and
    /// cargo runs tests in threads of a single process. Split across several
    /// `#[test]` functions these would flap against each other — and worse, a
    /// second `raise` while `COUNT` was already 1 would take the
    /// "asked twice, die now" branch and kill the whole test binary.
    #[test]
    fn a_raised_signal_sets_the_flag_without_killing_the_process() {
        reset();
        assert!(!interrupted(), "the flag starts clear");
        assert_eq!(signal_name(), None);

        install().expect("handlers install");
        // Idempotent: a second call must not re-enter the install loop or fail.
        install().expect("installing twice is fine");
        assert!(INSTALLED.load(Ordering::SeqCst));

        // `raise` targets the calling thread, so only this test's thread runs
        // the handler. Exactly one — two would restore SIG_DFL and abort the
        // run, which is the documented escape hatch and not what we want here.
        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);

        assert!(interrupted(), "SIGINT must set the flag, not kill the process");
        assert_eq!(signal_name(), Some("SIGINT"));
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);

        reset();
        assert!(!interrupted());
        assert_eq!(signal_name(), None);

        second_signal_kills_outright();
    }

    /// The escape hatch, proved in a **forked child** because the thing being
    /// tested is that the process dies — which is not observable from inside it.
    ///
    /// The child only calls `raise` and `_exit`, both async-signal-safe, so
    /// forking a multi-threaded test binary is safe here. `raise` also makes the
    /// test deterministic where two `kill()`s from outside are not: `raise`
    /// delivers the signal before it returns, so the handler has finished and
    /// `COUNT` is 1 by the time the second one is sent. Nothing coalesces.
    fn second_signal_kills_outright() {
        assert_eq!(COUNT.load(Ordering::SeqCst), 0, "the child must inherit a clean count");

        // SAFETY: the child touches nothing but `raise` and `_exit`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                libc::raise(libc::SIGINT); // first: sets the flag, returns
                libc::raise(libc::SIGINT); // second: SIG_DFL + re-raise, dies here
                libc::_exit(7); // reached only if the hatch failed
            }
        }

        let mut status: libc::c_int = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid, "waitpid");
        assert!(
            libc::WIFSIGNALED(status),
            "the second signal must kill the child, not be swallowed (status {status:#x}, \
             exit code {})",
            libc::WEXITSTATUS(status)
        );
        assert_eq!(
            libc::WTERMSIG(status),
            libc::SIGINT,
            "and it must die from the ORIGINAL signal, so the shell sees 130"
        );
    }
}
