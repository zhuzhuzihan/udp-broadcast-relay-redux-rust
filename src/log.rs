//! Error/warning channel routing (ADR-014).
//!
//! Default is stderr through raw write(2) — byte-faithful to the original
//! (which also means: silent after the daemon closes its fds, exactly like C).
//! `--log syslog` routes to syslog(3), `--log file=PATH` appends to a file.
//! The global is initialized once from the pre-scanned `--log` value, before
//! any message can be emitted.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::OnceLock;

#[derive(Debug)]
enum Target {
    Stderr,
    Syslog { ident: CString },
    File { path: PathBuf, fd: AtomicI32 },
}

static LOG: OnceLock<Target> = OnceLock::new();

/// Initialize the global log from a `--log` spec ("stderr" | "syslog" |
/// "file=PATH"). Errors return a translated message from the caller.
pub fn init(spec: &str, program: &str) -> Result<(), String> {
    let target = match spec {
        "stderr" | "" => Target::Stderr,
        "syslog" => Target::Syslog {
            ident: CString::new(program).map_err(|_| "invalid log ident".to_string())?,
        },
        f if f.starts_with("file=") => {
            let path = PathBuf::from(&f["file=".len()..]);
            if path.as_os_str().is_empty() {
                return Err("empty log file path".to_string());
            }
            Target::File {
                path,
                fd: AtomicI32::new(-1),
            }
        }
        other => {
            return Err(format!(
                "invalid log target: {other} (expected: stderr, syslog, file=PATH)"
            ))
        }
    };
    if let Target::Syslog { ident } = &target {
        // SAFETY: ident is a valid NUL-terminated string that outlives the
        // program; openlog keeps the pointer per POSIX.
        unsafe {
            libc::openlog(
                ident.as_ptr(),
                libc::LOG_PID | libc::LOG_NDELAY,
                libc::LOG_DAEMON,
            );
        }
    }
    let _ = LOG.set(target);
    Ok(())
}

fn write_raw(bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: plain write(2) to fd 2; errors ignored (closed stderr in
        // daemon mode must stay silent, like C's perror).
        let n = unsafe { libc::write(2, bytes[off..].as_ptr().cast(), bytes.len() - off) };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

fn append_file(path: &std::path::Path, fd_cell: &AtomicI32, bytes: &[u8]) {
    let mut fd = fd_cell.load(Ordering::Relaxed);
    if fd < 0 {
        // SAFETY: open(2) with append/create mode for our own log file.
        fd = unsafe {
            libc::open(
                CString::new(path.as_os_str().to_string_lossy().as_bytes())
                    .unwrap_or_default()
                    .as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                0o644,
            )
        };
        if fd < 0 {
            // Fall back to stderr so the message is not lost.
            write_raw(bytes);
            return;
        }
        fd_cell.store(fd, Ordering::Relaxed);
    }
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: write(2) on our own log fd.
        let n = unsafe { libc::write(fd, bytes[off..].as_ptr().cast(), bytes.len() - off) };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

fn syslog_msg(msg: &str) {
    let c = CString::new(msg).unwrap_or_default();
    // SAFETY: both strings are valid NUL-terminated C strings; syslog is
    // called with a "%s" format so the message is never interpreted.
    unsafe {
        libc::syslog(libc::LOG_ERR, b"%s\0".as_ptr().cast(), c.as_ptr());
    }
}

/// Emit a plain line (already newline-terminated) to the error channel.
pub fn note(msg: &str) {
    match LOG.get() {
        None | Some(Target::Stderr) => write_raw(msg.as_bytes()),
        Some(Target::File { path, fd }) => append_file(path, fd, msg.as_bytes()),
        Some(Target::Syslog { .. }) => {
            let trimmed = msg.trim_end_matches('\n');
            syslog_msg(trimmed);
        }
    }
}

/// perror-equivalent: `prefix + ": " + strerror(errno) + "\n"`.
pub fn err(prefix: &str, errno: i32) {
    note(&format!("{prefix}: {}\n", crate::out::strerror(errno)));
}

/// SIGHUP: close and reopen the file target (log rotation).
pub fn reopen() {
    if let Some(Target::File { path, fd }) = LOG.get() {
        // SAFETY: closing our own log fd; the next append reopens it.
        let prev = fd.swap(-1, Ordering::Relaxed);
        if prev >= 0 {
            unsafe { libc::close(prev) };
        }
        note(&format!("log reopened: {}\n", path.display()));
    }
}
