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
    pub fn new(signals: &[libc::c_int]) -> io::Result<Self> {
        let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
        unsafe { libc::sigemptyset(&mut mask) };
        for &sig in signals {
            unsafe { libc::sigaddset(&mut mask, sig) };
        }

        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(SignalFd { fd })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Drain every signal currently pending on the descriptor.
    pub fn read_pending(&self) -> io::Result<Vec<libc::c_int>> {
        let mut signals = Vec::new();
        loop {
            let mut info: libc::signalfd_siginfo = unsafe { mem::zeroed() };
            let n = unsafe {
                libc::read(
                    self.fd,
                    &mut info as *mut libc::signalfd_siginfo as *mut libc::c_void,
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
pub fn unblock_all() -> io::Result<()> {
    let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
    unsafe { libc::sigemptyset(&mut mask) };
    if unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &mask, ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait for a single descriptor to become readable. A negative timeout blocks.
pub fn poll_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret > 0 && (pfd.revents & libc::POLLIN) != 0)
}
