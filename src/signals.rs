//! Synchronous signal delivery via `signalfd`.
//!
//! The signals we care about are blocked process-wide and consumed through a
//! file descriptor, so the event loops wait for them with `poll()` alongside
//! their other descriptors instead of relying on syscalls returning `EINTR`.
//!
//! This matters: glibc's `signal()` installs handlers with `SA_RESTART`, so a
//! blocking `waitpid()` is silently restarted after the handler runs and never
//! reports `EINTR`. Consuming signals through a descriptor also closes the race
//! between testing a shutdown flag and entering a blocking wait, because a
//! blocked signal stays pending — and therefore readable — until we read it.

use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

pub struct SignalFd {
    fd: RawFd,
}

impl SignalFd {
    /// Block `signals` for the calling process and return a descriptor that
    /// becomes readable when one of them is delivered.
    /// # Errors
    ///
    /// If the signal mask cannot be applied, or the descriptor not created.
    pub fn new(signals: &[libc::c_int]) -> io::Result<Self> {
        let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
        unsafe { libc::sigemptyset(&raw mut mask) };
        for &sig in signals {
            unsafe { libc::sigaddset(&raw mut mask, sig) };
        }

        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, ptr::null_mut()) } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let fd =
            unsafe { libc::signalfd(-1, &raw const mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(SignalFd { fd })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Drain every signal currently pending on the descriptor.
    /// # Errors
    ///
    /// If reading the descriptor fails for a reason other than it being empty
    /// or the read being interrupted, both of which are handled here.
    pub fn read_pending(&self) -> io::Result<Vec<libc::c_int>> {
        let mut signals = Vec::new();
        loop {
            let mut info: libc::signalfd_siginfo = unsafe { mem::zeroed() };
            let n = unsafe {
                libc::read(
                    self.fd,
                    (&raw mut info).cast::<libc::c_void>(),
                    mem::size_of::<libc::signalfd_siginfo>(),
                )
            };

            if n < 0 {
                let err = io::Error::last_os_error();
                match err.kind() {
                    io::ErrorKind::WouldBlock => break,
                    io::ErrorKind::Interrupted => continue,
                    _ => return Err(err),
                }
            }
            if n == 0 {
                break;
            }
            // Signal numbers are small positive integers, so this cannot wrap.
            #[allow(clippy::cast_possible_wrap)]
            signals.push(info.ssi_signo as libc::c_int);
        }
        Ok(signals)
    }

    /// Release the descriptor inherited by a forked child.
    ///
    /// A `fork()`ed child gets its own copy of the descriptor, which would then
    /// compete for that child's signals. Call this immediately after `fork()`
    /// in the child, which must go on to `_exit()` so `Drop` never runs and the
    /// descriptor is not closed twice.
    pub fn close_in_child(&self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Drop for SignalFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Restore an empty signal mask, undoing the blocking done by [`SignalFd::new`].
/// A forked child inherits the parent's mask and needs its own disposition.
/// # Errors
///
/// If the signal mask cannot be applied.
pub fn unblock_all() -> io::Result<()> {
    let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
    unsafe { libc::sigemptyset(&raw mut mask) };
    if unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const mask, ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait for a single descriptor to become readable. A negative timeout blocks.
/// # Errors
///
/// If `poll` fails, including with `EINTR`.
pub fn poll_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret > 0 && (pfd.revents & libc::POLLIN) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// The signal mask is per-thread and every test runs on its own thread, so
    /// blocking a signal here cannot leak into another test. `raise()` is
    /// thread-directed for the same reason, which keeps delivery on the thread
    /// that owns the descriptor.
    ///
    /// SIGUSR1/SIGUSR2 stand in for the real SIGTERM/SIGINT: the mechanism is
    /// identical and the test harness has no use for them, so a mistake here
    /// cannot be confused with a genuine shutdown request.
    const TEST_SIGNALS: [libc::c_int; 2] = [libc::SIGUSR1, libc::SIGUSR2];

    fn is_blocked(sig: libc::c_int) -> bool {
        let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
        unsafe { libc::sigemptyset(&raw mut mask) };
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, ptr::null(), &raw mut mask) },
            0
        );
        (unsafe { libc::sigismember(&raw const mask, sig) }) == 1
    }

    /// Blocking is the whole point: an unblocked signal would run its default
    /// disposition and kill the process instead of landing on the descriptor.
    #[test]
    fn creating_the_descriptor_blocks_its_signals() {
        assert!(!is_blocked(libc::SIGUSR1), "precondition");

        let _signals = SignalFd::new(&TEST_SIGNALS).unwrap();

        assert!(is_blocked(libc::SIGUSR1));
        assert!(is_blocked(libc::SIGUSR2));
    }

    #[test]
    fn a_raised_signal_becomes_readable_and_is_reported() {
        let signals = SignalFd::new(&[libc::SIGUSR1]).unwrap();
        assert!(
            !poll_readable(signals.as_raw_fd(), 0).unwrap(),
            "nothing pending yet"
        );

        unsafe { libc::raise(libc::SIGUSR1) };

        assert!(poll_readable(signals.as_raw_fd(), 1000).unwrap());
        assert_eq!(signals.read_pending().unwrap(), vec![libc::SIGUSR1]);
    }

    #[test]
    fn every_pending_signal_is_drained_in_one_read() {
        let signals = SignalFd::new(&TEST_SIGNALS).unwrap();

        unsafe { libc::raise(libc::SIGUSR1) };
        unsafe { libc::raise(libc::SIGUSR2) };

        let mut pending = signals.read_pending().unwrap();
        pending.sort_unstable();
        let mut expected = TEST_SIGNALS.to_vec();
        expected.sort_unstable();
        assert_eq!(pending, expected);

        // Draining leaves the descriptor idle rather than blocking on it.
        assert!(signals.read_pending().unwrap().is_empty());
        assert!(!poll_readable(signals.as_raw_fd(), 0).unwrap());
    }

    /// The descriptor is opened non-blocking, so the event loop can drain it
    /// without knowing how many signals are waiting.
    #[test]
    fn reading_an_idle_descriptor_returns_nothing_instead_of_blocking() {
        let signals = SignalFd::new(&[libc::SIGUSR1]).unwrap();

        let started = Instant::now();
        assert!(signals.read_pending().unwrap().is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "read_pending must not block"
        );
    }

    /// A signal raised before the loop reaches its `poll()` must still be seen:
    /// blocked signals stay pending, which is what closes the race between
    /// testing a shutdown flag and entering a blocking wait.
    #[test]
    fn a_signal_raised_before_polling_is_not_lost() {
        let signals = SignalFd::new(&[libc::SIGUSR1]).unwrap();
        unsafe { libc::raise(libc::SIGUSR1) };

        // Whatever the loop was doing in between, the signal is still there.
        std::thread::sleep(Duration::from_millis(20));

        assert!(poll_readable(signals.as_raw_fd(), 0).unwrap());
        assert_eq!(signals.read_pending().unwrap(), vec![libc::SIGUSR1]);
    }

    #[test]
    fn polling_an_idle_descriptor_waits_out_the_timeout() {
        let signals = SignalFd::new(&[libc::SIGUSR1]).unwrap();

        let started = Instant::now();
        assert!(!poll_readable(signals.as_raw_fd(), 50).unwrap());
        assert!(
            started.elapsed() >= Duration::from_millis(45),
            "poll returned early"
        );
    }

    /// A forked worker inherits the supervisor's mask and would otherwise be
    /// deaf to the SIGTERM the supervisor sends it.
    #[test]
    fn unblocking_restores_an_empty_mask() {
        let signals = SignalFd::new(&TEST_SIGNALS).unwrap();
        assert!(is_blocked(libc::SIGUSR1));
        drop(signals);

        unblock_all().unwrap();

        assert!(!is_blocked(libc::SIGUSR1));
        assert!(!is_blocked(libc::SIGUSR2));
        assert!(!is_blocked(libc::SIGTERM));
    }
}
