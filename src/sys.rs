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

/// NETLINK_ROUTE socket subscribed to link / IPv4-address groups (Linux).
#[cfg(target_os = "linux")]
pub fn netlink_route(groups: u32) -> Result<Fd, std::io::Error> {
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: sockaddr_nl zeroed then every real field initialized.
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    sa.nl_pid = 0;
    sa.nl_groups = groups;
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        let e = last_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(Fd(fd))
}

/// socket(AF_INET6, SOCK_DGRAM, 0)
pub fn udp6_socket() -> Result<Fd, std::io::Error> {
    // SAFETY: plain socket(2) call with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        Err(last_error())
    } else {
        Ok(Fd(fd))
    }
}

/// socket(AF_INET6, SOCK_RAW, IPPROTO_RAW) — full-header IPv6 send socket.
pub fn raw6_socket() -> Result<Fd, std::io::Error> {
    // SAFETY: plain socket(2) call with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        Err(last_error())
    } else {
        Ok(Fd(fd))
    }
}

/// IPV6_RECVPKTINFO / IPV6_RECVHOPLIMIT (IPPROTO_IPV6 level).
pub fn setsockopt6_int(fd: i32, opt: i32, value: i32) -> Result<(), std::io::Error> {
    // SAFETY: int-valued IPv6 socket option.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
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

/// IPV6_JOIN_GROUP on the receive socket.
pub fn join6(fd: i32, group: [u8; 16], ifindex: u32) -> Result<(), ()> {
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr { s6_addr: group },
        ipv6mr_interface: ifindex,
    };
    // Linux names it IPV6_ADD_MEMBERSHIP (20); BSD/macOS IPV6_JOIN_GROUP (12).
    // Some embedded kernels only implement the BSD number — fall back on
    // ENOPROTOOPT (observed on an Android kernel).
    #[cfg(target_os = "linux")]
    let opt = libc::IPV6_ADD_MEMBERSHIP;
    #[cfg(not(target_os = "linux"))]
    let opt = libc::IPV6_JOIN_GROUP;
    // SAFETY: mreq is fully initialized; the kernel reads it inline.
    let mut rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            opt,
            &mreq as *const libc::ipv6_mreq as *const libc::c_void,
            size_of::<libc::ipv6_mreq>() as u32,
        )
    };
    #[cfg(target_os = "linux")]
    if rc < 0 && last_error().raw_os_error() == Some(libc::ENOPROTOOPT) {
        // BSD number (12) — not exported by the linux-gnu libc crate.
        const IPV6_JOIN_GROUP: i32 = 12;
        rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IPV6_JOIN_GROUP,
                &mreq as *const libc::ipv6_mreq as *const libc::c_void,
                size_of::<libc::ipv6_mreq>() as u32,
            )
        };
    }
    if rc < 0 {
        Err(())
    } else {
        Ok(())
    }
}

/// sendmsg on a raw IPv6 socket: the kernel builds the IPv6 header (Linux has
/// no full-header mode for AF_INET6 raw); source address, outgoing interface
/// and hop limit come from IPV6_PKTINFO / IPV6_HOPLIMIT ancillary data.
pub fn sendmsg6(
    fd: i32,
    seg: &[u8],
    dst: [u8; 16],
    port: u16,
    hop_limit: u8,
    src: [u8; 16],
    ifindex: u32,
) -> Result<usize, std::io::Error> {
    // SAFETY: every pointed-to buffer is initialized and outlives sendmsg.
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_port = port.to_be();
    sa.sin6_addr = libc::in6_addr { s6_addr: dst };
    sa.sin6_scope_id = ifindex;

    // ancillary data: IPV6_PKTINFO (in6_pktinfo) + IPV6_HOPLIMIT (int)
    let mut cmsg = [0u8; 64];
    let mut off = 0usize;
    let mut put = |off: &mut usize, level: i32, ty: i32, data: &[u8]| {
        let len = 16 + data.len(); // cmsghdr 16 + data; padded to sizeof(long)
        let padded = (len + 7) & !7;
        // cmsghdr: len (size_t), level (int), type (int)
        let hdr = (len as u64).to_ne_bytes();
        cmsg[*off..*off + 8].copy_from_slice(&hdr);
        cmsg[*off + 8..*off + 12].copy_from_slice(&level.to_ne_bytes());
        cmsg[*off + 12..*off + 16].copy_from_slice(&ty.to_ne_bytes());
        cmsg[*off + 16..*off + 16 + data.len()].copy_from_slice(data);
        *off += padded;
    };
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr { s6_addr: src },
        ipi6_ifindex: ifindex,
    };
    // SAFETY: plain POD struct copy.
    let pkt_bytes: [u8; 20] = unsafe { std::mem::transmute(pktinfo) };
    put(&mut off, libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &pkt_bytes);
    put(
        &mut off,
        libc::IPPROTO_IPV6,
        libc::IPV6_HOPLIMIT,
        &[hop_limit, 0, 0, 0],
    );

    let mut iov = libc::iovec {
        iov_base: seg.as_ptr() as *mut libc::c_void,
        iov_len: seg.len(),
    };
    let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
    mh.msg_name = &sa as *const libc::sockaddr_in6 as *mut libc::c_void;
    mh.msg_namelen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    mh.msg_iov = &mut iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cmsg.as_mut_ptr().cast();
    mh.msg_controllen = off as _;
    let rc = unsafe { libc::sendmsg(fd, &mh, 0) };
    if rc < 0 {
        Err(last_error())
    } else {
        Ok(rc as usize)
    }
}

/// Bind an IPv6 socket to [::]:port.
pub fn bind6(fd: i32, port: u16) -> Result<(), std::io::Error> {
    // SAFETY: sockaddr_in6 fully initialized; bind(2) with the right size.
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_port = port.to_be();
    sa.sin6_addr = libc::in6_addr { s6_addr: [0u8; 16] };
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
            size_of::<libc::sockaddr_in6>() as u32,
        )
    };
    if rc < 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

/// recvmsg with an IPv6 name buffer.
pub fn recvmsg_into6(
    fd: i32,
    payload: &mut [u8],
    ctrl: &mut [u8],
    name: &mut libc::sockaddr_in6,
) -> Result<(isize, usize), std::io::Error> {
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: msghdr zeroed then all fields the kernel reads initialized.
    let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
    mh.msg_name = name as *mut libc::sockaddr_in6 as *mut libc::c_void;
    mh.msg_namelen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    mh.msg_iov = &mut iov;
    mh.msg_iovlen = 1;
    mh.msg_control = ctrl.as_mut_ptr().cast();
    mh.msg_controllen = ctrl.len() as _;
    // SAFETY: buffers valid and sized as set above.
    let n = unsafe { libc::recvmsg(fd, &mut mh, 0) };
    if n < 0 {
        Err(last_error())
    } else {
        Ok((n, mh.msg_controllen as usize))
    }
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
