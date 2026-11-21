//! stdio semantics replicated from the C original (DECISIONS ADR-007).
//!
//! stdout is block-buffered (8 KiB, like glibc stdio) and flushed only on exit
//! paths; stderr is written through raw `write(2)` ignoring errors, because the
//! daemon closes its stdio (`fclose(stdin/stdout/stderr)`) and C's `perror`
//! silently fails there while Rust's `eprintln!` would panic.

use std::ffi::CStr;
use std::io::{BufWriter, Write};

pub struct Out {
    buf: BufWriter<std::io::Stdout>,
}

impl Out {
    pub fn new() -> Self {
        Self {
            buf: BufWriter::with_capacity(8192, std::io::stdout()),
        }
    }

    /// C `printf` to stdout; the original discards printf's return value, so errors are ignored.
    pub fn print(&mut self, s: &str) {
        let _ = self.buf.write_all(s.as_bytes());
    }

    /// C `exit()` flushes stdio.
    pub fn flush(&mut self) {
        let _ = self.buf.flush();
    }
}

impl Default for Out {
    fn default() -> Self {
        Self::new()
    }
}

/// Emit a message line to the error channel (stderr default; routed through
/// the global log when `--log` is set).
pub fn eprint_raw(s: &str) {
    crate::log::note(s);
}

/// Current errno value.
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `strerror(3)` text for an errno value (glibc-exact strings, needed for perror parity).
pub fn strerror(err: i32) -> String {
    let p = unsafe { libc::strerror(err) };
    if p.is_null() {
        return format!("Unknown error {err}");
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// C `perror(prefix)`: writes `prefix + ": " + strerror(errno) + "\n"` to the
/// error channel. The prefix may itself end in `\n` (the original does that);
/// the output then spans two lines exactly like the C program.
pub fn perror(prefix: &str, err: i32) {
    crate::log::err(prefix, err);
}
