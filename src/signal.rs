//! Signal handling via the self-pipe trick (ADR-011): handlers only write one
//! tag byte to a non-blocking pipe — the only async-signal-safe thing we do —
//! and the poll loop drains it.

use crate::sys::Fd;
use std::sync::atomic::{AtomicI32, Ordering};

pub const SIG_TERM: u8 = 1;
pub const SIG_INT: u8 = 2;
pub const SIG_HUP: u8 = 3;
pub const SIG_USR1: u8 = 4;

static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(sig: libc::c_int) {
    let tag = match sig {
        libc::SIGTERM => SIG_TERM,
        libc::SIGINT => SIG_INT,
        libc::SIGHUP => SIG_HUP,
        libc::SIGUSR1 => SIG_USR1,
        _ => return,
    };
    let fd = PIPE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) is async-signal-safe; one byte to a valid fd,
        // errors ignored (a full pipe just drops the byte, next pending
        // signal re-delivers it).
        unsafe { libc::write(fd, &tag as *const u8 as *const libc::c_void, 1) };
    }
}

/// Installed signal set: SIGTERM/SIGINT (shutdown), SIGHUP (log reopen),
/// SIGUSR1 (stats dump). The read end is non-blocking and closed on drop.
pub struct Signals {
    read_fd: Fd,
}

impl Signals {
    pub fn install() -> Result<Signals, std::io::Error> {
        let mut fds = [0i32; 2];
        // SAFETY: pipe(2) with the standard two-slot array.
        unsafe {
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        for fd in fds {
            // SAFETY: freshly created pipe fds; F_GETFL/F_SETFL pair.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                let e = std::io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(e);
            }
        }
        PIPE_WRITE.store(fds[1], Ordering::Relaxed);

        // SAFETY: sigaction with a plain handler (no SA_SIGINFO); the mask is
        // initialized empty; sa_flags field type differs per OS but the
        // constant matches it.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = libc::SA_RESTART;
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGUSR1] {
                if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                    let e = std::io::Error::last_os_error();
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                    PIPE_WRITE.store(-1, Ordering::Relaxed);
                    return Err(e);
                }
            }
        }
        // The write end outlives the program; do not drop-close it.
        std::mem::forget(unsafe { Fd::from_raw(fds[1]) });
        // SAFETY: fds[0] was just created by pipe(2) above and is owned here.
        Ok(Signals {
            read_fd: unsafe { Fd::from_raw(fds[0]) },
        })
    }

    pub fn read_fd(&self) -> i32 {
        self.read_fd.0
    }

    /// Drain all pending tag bytes (non-blocking).
    pub fn drain(&self) -> Vec<u8> {
        let mut tags = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: read(2) on our own non-blocking pipe fd.
            let n = unsafe { libc::read(self.read_fd.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break; // EAGAIN / EOF
            }
            tags.extend_from_slice(&buf[..n as usize]);
        }
        tags
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        PIPE_WRITE.store(-1, Ordering::Relaxed);
    }
}
