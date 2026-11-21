//! Isolated libc FFI layer. Every unsafe block carries a SAFETY comment; the
//! rest of the program never touches raw pointers (ADR-003).

use std::mem::size_of;

/// Owning raw fd, closed on drop (mirrors the original's explicit close paths).
pub struct Fd(pub i32);

impl Fd {
    pub fn close(&mut self) {
        if self.0 >= 0 {
            // SAFETY: valid fd owned by this value; close(2) has no side effects beyond release.
            unsafe { libc::close(self.0) };
            self.0 = -1;
        }
    }

    /// SAFETY: takes ownership of a raw fd previously created elsewhere.
    pub unsafe fn from_raw(fd: i32) -> Fd {
        Fd(fd)
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        self.close();
    }
}

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
pub fn raw_socket() -> Result<Fd, std::io::Error> {
    // SAFETY: plain socket(2) call with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        Err(last_error())
    } else {
        Ok(Fd(fd))
    }
}

/// socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
pub fn udp_socket() -> Result<Fd, std::io::Error> {
    // SAFETY: plain socket(2) call with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        Err(last_error())
    } else {
        Ok(Fd(fd))
    }
}

/// setsockopt(fd, level, opt, int value)
pub fn setsockopt_int(fd: i32, level: i32, opt: i32, value: i32) -> Result<(), std::io::Error> {
    // SAFETY: fd is a live socket; the option is an int as documented per optname.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            std::ptr::addr_of!(value).cast::<libc::c_void>(),
            size_of::<i32>() as u32,
        )
    };
    if rc < 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

/// setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name with NUL) — Linux only
/// (macOS has no SO_BINDTODEVICE; its per-interface binding uses IP_BOUND_IF,
/// which the original also does not use).
#[cfg(target_os = "linux")]
pub fn setsockopt_bind_to_device(fd: i32, name: &str) -> Result<(), std::io::Error> {
    let mut buf = Vec::with_capacity(name.len() + 1);
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);
    // SAFETY: buf is NUL-terminated and lives across the call, as setsockopt requires.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            buf.as_ptr().cast(),
            buf.len() as u32,
        )
    };
    if rc < 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

/// Zeroed `struct ifreq` with the interface name copied in (strncpy semantics:
/// truncate at 16 bytes, zero-pad the remainder — a 16+ char name stays
/// unterminated, exactly like the original).
fn make_ifreq(name: &str) -> libc::ifreq {
    // SAFETY: ifreq is a plain-old-data C struct; zeroed is a valid all-zero value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = name.as_bytes();
    let n = name_bytes.len().min(16);
    // SAFETY: write name bytes into the fixed-size ifr_name array
    // ([c_char; 16]; c_char and u8 share size/alignment).
    unsafe {
        let dst = req.ifr_name.as_mut_ptr().cast::<u8>();
        std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), dst, n);
    }
    req
}

/// ioctl request argument type: `int` on musl, `unsigned long` elsewhere.
#[cfg(target_env = "musl")]
pub type IoctlReq = libc::c_int;
#[cfg(not(target_env = "musl"))]
pub type IoctlReq = libc::c_ulong;

/// Interface ioctl requests. libc covers Linux and Apple; FreeBSD ships only
/// SIOCGIFADDR in libc 0.2, so the sibling requests are spelled with the same
/// `_IOWR('i', n, struct ifreq)` encoding (verified against SIOCGIFADDR =
/// 0xc020_6921: size 0x20 << 16 | 'i' << 8 | request number).
#[cfg(all(target_os = "linux", target_env = "musl"))]
pub const SIOCGIFINDEX: IoctlReq = libc::SIOCGIFINDEX as IoctlReq;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub const SIOCGIFINDEX: IoctlReq = libc::SIOCGIFINDEX;

#[cfg(all(target_os = "linux", target_env = "musl"))]
pub const SIOCGIFFLAGS: IoctlReq = libc::SIOCGIFFLAGS as IoctlReq;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub const SIOCGIFFLAGS: IoctlReq = libc::SIOCGIFFLAGS;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const SIOCGIFFLAGS: IoctlReq = libc::SIOCGIFFLAGS;
#[cfg(target_os = "freebsd")]
pub const SIOCGIFFLAGS: IoctlReq = 0xc020_6945;

#[cfg(all(target_os = "linux", target_env = "musl"))]
pub const SIOCGIFADDR: IoctlReq = libc::SIOCGIFADDR as IoctlReq;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub const SIOCGIFADDR: IoctlReq = libc::SIOCGIFADDR;
#[cfg(target_os = "freebsd")]
pub const SIOCGIFADDR: IoctlReq = libc::SIOCGIFADDR;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const SIOCGIFADDR: IoctlReq = libc::SIOCGIFADDR;

#[cfg(all(target_os = "linux", target_env = "musl"))]
pub const SIOCGIFBRDADDR: IoctlReq = libc::SIOCGIFBRDADDR as IoctlReq;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub const SIOCGIFBRDADDR: IoctlReq = libc::SIOCGIFBRDADDR;
#[cfg(target_os = "freebsd")]
pub const SIOCGIFBRDADDR: IoctlReq = 0xc020_6923;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const SIOCGIFBRDADDR: IoctlReq = libc::SIOCGIFBRDADDR;

#[cfg(all(target_os = "linux", target_env = "musl"))]
pub const SIOCGIFDSTADDR: IoctlReq = libc::SIOCGIFDSTADDR as IoctlReq;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub const SIOCGIFDSTADDR: IoctlReq = libc::SIOCGIFDSTADDR;
#[cfg(target_os = "freebsd")]
pub const SIOCGIFDSTADDR: IoctlReq = 0xc020_6922;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const SIOCGIFDSTADDR: IoctlReq = libc::SIOCGIFDSTADDR;

/// ioctl(fd, request, struct ifreq*) — result read from the same struct.
pub fn ioctl_ifreq(
    fd: i32,
    request: IoctlReq,
    req: &mut libc::ifreq,
) -> Result<(), std::io::Error> {
    // SAFETY: req is a valid, fully initialized ifreq owned by the caller; this is
    // the documented SIOCGIF* calling convention (kernel fills the union).
    let rc = unsafe { libc::ioctl(fd, request, req as *mut libc::ifreq) };
    if rc < 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

pub fn new_ifreq(name: &str) -> libc::ifreq {
    make_ifreq(name)
}

/// Read the IPv4 address stored in a `struct sockaddr` (bytes 4..8, network order)
/// as the numeric (host-assembled) form.
///
/// # Safety
/// `sa` must point to at least 8 readable bytes of a sockaddr family record.
pub unsafe fn sockaddr_to_addr(sa: &libc::sockaddr) -> u32 {
    let b = sa.sa_data.as_ptr().cast::<u8>().add(2);
    let mut four = [0u8; 4];
    std::ptr::copy_nonoverlapping(b, four.as_mut_ptr(), 4);
    u32::from_be_bytes(four)
}

/// `if_nametoindex` (BSD/macOS branch of the original).
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn if_nametoindex(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: c is a valid NUL-terminated string for the duration of the call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// Build a sockaddr_in for sendto(). BSD-family sockets carry sin_len; the
/// original leaves it uninitialized stack garbage, we set the size (0 works
/// as well on the receiving path — documented in docs/PORTING.md).
pub fn sockaddr_in(addr_numeric: u32, port: u16) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain old data; zeroed is the all-zero value.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = port.to_be();
    sa.sin_addr = libc::in_addr {
        // s_addr holds the network-order bytes; numeric → byte-swapped on LE hosts.
        s_addr: addr_numeric.swap_bytes(),
    };
    sa
}

/// sendto(fd, buf, sockaddr_in)
pub fn sendto_in(fd: i32, buf: &[u8], sa: &libc::sockaddr_in) -> Result<usize, std::io::Error> {
    // SAFETY: sa is a fully initialized sockaddr_in; buf lives across the call.
    let rc = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr().cast(),
            buf.len(),
            0,
            sa as *const libc::sockaddr_in as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if rc < 0 {
        Err(last_error())
    } else {
        Ok(rc as usize)
    }
}

/// recvmsg with one iovec into `payload`, control buffer `ctrl`, name into
/// `name`. Returns (length, control bytes actually received).
pub fn recvmsg_into(
    fd: i32,
    payload: &mut [u8],
    ctrl: &mut [u8],
    name: &mut libc::sockaddr_in,
) -> Result<(isize, usize), std::io::Error> {
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: msghdr is zeroed then every field the kernel reads is initialized;
    // all pointed-to buffers outlive the call.
    let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
    mh.msg_name = name as *mut libc::sockaddr_in as *mut libc::c_void;
    mh.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    mh.msg_iov = &mut iov;
    mh.msg_iovlen = 1;
    mh.msg_control = ctrl.as_mut_ptr().cast();
    mh.msg_controllen = ctrl.len() as _;
    // SAFETY: all buffers are valid and sized as set above.
    let n = unsafe { libc::recvmsg(fd, &mut mh, 0) };
    if n < 0 {
        Err(last_error())
    } else {
        Ok((n, mh.msg_controllen as usize))
    }
}

/// fork(2). Returns Some(pid) for the parent (>0), None for the child (0).
/// A fork failure (-1) mirrors the original: treated as "child path" and the
/// process keeps running in the foreground.
pub fn fork() -> Option<i32> {
    // SAFETY: single-threaded process at this point (created before any thread
    // could exist); the child only performs async-signal-safe setup by design.
    let pid = unsafe { libc::fork() };
    if pid > 0 {
        Some(pid)
    } else {
        None
    }
}

pub fn close_fd(fd: i32) {
    // SAFETY: closing a live fd; called only for 0/1/2 after the final flush.
    unsafe { libc::close(fd) };
}

pub fn close(fd: &mut Fd) {
    fd.close();
}

/// poll(2): wait for readiness on the given fds. Returns the ready count.
pub fn poll(fds: &mut [libc::pollfd], timeout_ms: i32) -> Result<usize, std::io::Error> {
    // SAFETY: fds is a valid, correctly-sized slice for the call.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if rc < 0 {
        Err(last_error())
    } else {
        Ok(rc as usize)
    }
}
