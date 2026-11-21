//! Interface enumeration and per-interface raw sockets, mirroring the ioctl
//! flow of the C original (SIOCGIFINDEX / SIOCGIFFLAGS / SIOCGIFADDR /
//! SIOCGIFBRDADDR / SIOCGIFDSTADDR).

use crate::i18n::{ipv4_str, I18n};
use crate::out::{self, Out};
use crate::sys;

/// One managed interface: addresses in numeric form, kernel index, raw socket.
pub struct Iface {
    pub dstaddr: u32,
    pub ifaddr: u32,
    pub ifindex: i32,
    pub raw_socket: sys::Fd,
}

/// Set up one interface; `Ok(None)` = skipped (down or loopback).
/// `Err(())` = fatal: the perror line has already been written, the caller
/// flushes and exits 1 — preserving the original's output order.
pub fn setup(
    tmp_fd: i32,
    name: &str,
    ttl: u8,
    debug: bool,
    out_stream: &mut Out,
    t: &I18n,
) -> Result<Option<Iface>, ()> {
    #[cfg(target_os = "linux")]
    {
        setup_linux(tmp_fd, name, ttl, debug, out_stream, t)
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        setup_bsd(tmp_fd, name, ttl, debug, out_stream, t)
    }
}

fn fatal_perror<T>(prefix: &str) -> Result<T, ()> {
    out::perror(prefix, out::errno());
    Err(())
}

#[cfg(target_os = "linux")]
fn setup_linux(
    tmp_fd: i32,
    name: &str,
    ttl: u8,
    debug: bool,
    out_stream: &mut Out,
    t: &I18n,
) -> Result<Option<Iface>, ()> {
    // Interface index.
    let mut req = sys::new_ifreq(name);
    if sys::ioctl_ifreq(tmp_fd, sys::SIOCGIFINDEX, &mut req).is_err() {
        return fatal_perror("ioctl(SIOCGIFINDEX)");
    }
    // SAFETY: SIOCGIFINDEX filled ifr_ifru.ifr_ifindex on success.
    let ifindex = unsafe { req.ifr_ifru.ifru_ifindex };

    // Flags.
    let mut req = sys::new_ifreq(name);
    if sys::ioctl_ifreq(tmp_fd, sys::SIOCGIFFLAGS, &mut req).is_err() {
        return fatal_perror("ioctl(SIOCGIFFLAGS)");
    }
    // SAFETY: SIOCGIFFLAGS filled ifr_flags on success.
    #[cfg(target_os = "freebsd")]
    let flags = unsafe { req.ifr_ifru.ifru_flags[0] };
    #[cfg(not(target_os = "freebsd"))]
    let flags = unsafe { req.ifr_ifru.ifru_flags };

    // Skip interfaces that are down or loopback.
    if (flags & libc::IFF_UP as i16) == 0 || (flags & libc::IFF_LOOPBACK as i16) != 0 {
        return Ok(None);
    }

    // Local address.
    let mut req = sys::new_ifreq(name);
    if sys::ioctl_ifreq(tmp_fd, sys::SIOCGIFADDR, &mut req).is_err() {
        return fatal_perror("ioctl(SIOCGIFADDR)");
    }
    // SAFETY: ifr_addr holds a sockaddr_in after SIOCGIFADDR.
    let ifaddr = unsafe { sys::sockaddr_to_addr(&req.ifr_ifru.ifru_addr) };

    // Broadcast address (or point-to-point destination; the original prints
    // the SIOCGIFBRDADDR label in both failure paths — quirk preserved).
    let mut req = sys::new_ifreq(name);
    if (flags & libc::IFF_BROADCAST as i16) != 0 {
        if sys::ioctl_ifreq(tmp_fd, sys::SIOCGIFBRDADDR, &mut req).is_err() {
            return fatal_perror("ioctl(SIOCGIFBRDADDR)");
        }
        // SAFETY: ifr_broadaddr holds a sockaddr_in after SIOCGIFBRDADDR.
        let dstaddr = unsafe { sys::sockaddr_to_addr(&req.ifr_ifru.ifru_broadaddr) };
        finish(
            tmp_fd,
            name,
            &req.ifr_name,
            ifindex,
            ifaddr,
            dstaddr,
            ttl,
            debug,
            out_stream,
            t,
        )
        .map(Some)
    } else {
        if sys::ioctl_ifreq(tmp_fd, sys::SIOCGIFDSTADDR, &mut req).is_err() {
            return fatal_perror("ioctl(SIOCGIFBRDADDR)");
        }
        // SAFETY: ifr_dstaddr holds a sockaddr_in after SIOCGIFDSTADDR.
        let dstaddr = unsafe { sys::sockaddr_to_addr(&req.ifr_ifru.ifru_dstaddr) };
        finish(
            tmp_fd,
            name,
            &req.ifr_name,
            ifindex,
            ifaddr,
            dstaddr,
            ttl,
            debug,
            out_stream,
            t,
        )
        .map(Some)
    }
}

/// Common tail: debug print, raw socket + options (Linux: SO_BINDTODEVICE).
#[cfg(target_os = "linux")]
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the original's single-function flow"
)]
fn finish(
    _tmp_fd: i32,
    name: &str,
    ifr_name: &[libc::c_char; 16],
    ifindex: i32,
    ifaddr: u32,
    dstaddr: u32,
    _ttl: u8,
    debug: bool,
    out_stream: &mut Out,
    t: &I18n,
) -> Result<Iface, ()> {
    // The original prints the (truncated) ifr_name, not the raw argument.
    // SAFETY: reading the fixed-size name array; c_char and u8 share layout.
    let printed_name: &[u8] = unsafe {
        let p = ifr_name.as_ptr().cast::<u8>();
        std::slice::from_raw_parts(p, 16)
    };
    let end = printed_name.iter().position(|c| *c == 0).unwrap_or(16);
    let printed = String::from_utf8_lossy(&printed_name[..end]);

    if debug {
        out_stream.print(&t.debug_iface(&printed, ifindex, &ipv4_str(ifaddr), &ipv4_str(dstaddr)));
    }

    // One raw socket per interface for sending.
    let raw = match sys::raw_socket() {
        Ok(fd) => fd,
        Err(_) => return fatal_perror("socket"),
    };
    let fd = raw.0;
    if sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1).is_err() {
        return fatal_perror("setsockopt SO_BROADCAST");
    }
    if sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_HDRINCL, 1).is_err() {
        return fatal_perror("setsockopt IP_HDRINCL");
    }
    if sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1).is_err() {
        return fatal_perror("setsockopt SO_REUSEPORT");
    }
    // Bind the socket to the NIC, overriding the routing table.
    if sys::setsockopt_bind_to_device(fd, name).is_err() {
        return fatal_perror("setsockopt SO_BINDTODEVICE");
    }
    Ok(Iface {
        dstaddr,
        ifaddr,
        ifindex,
        raw_socket: raw,
    })
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn setup_bsd(
    _tmp_fd: i32,
    name: &str,
    ttl: u8,
    debug: bool,
    out_stream: &mut Out,
    t: &I18n,
) -> Result<Option<Iface>, ()> {
    // The original uses if_nametoindex on Apple ("supposedly this works for
    // all OS, including non-Apple") — this port follows the Apple branch; the
    // FreeBSD branch of the original is out of scope (see docs/PORTING.md).
    let ifindex = match sys::if_nametoindex(name) {
        Some(i) => i as i32,
        None => return fatal_perror("if_nametoindex"),
    };

    let mut req = sys::new_ifreq(name);
    if sys::ioctl_ifreq(_tmp_fd, sys::SIOCGIFFLAGS, &mut req).is_err() {
        return fatal_perror("ioctl(SIOCGIFFLAGS)");
    }
    // SAFETY: SIOCGIFFLAGS filled ifr_flags on success.
    #[cfg(target_os = "freebsd")]
    let flags = unsafe { req.ifr_ifru.ifru_flags[0] };
    #[cfg(not(target_os = "freebsd"))]
    let flags = unsafe { req.ifr_ifru.ifru_flags };
    if (flags & libc::IFF_UP as i16) == 0 || (flags & libc::IFF_LOOPBACK as i16) != 0 {
        return Ok(None);
    }

    let mut req = sys::new_ifreq(name);
    if sys::ioctl_ifreq(_tmp_fd, sys::SIOCGIFADDR, &mut req).is_err() {
        return fatal_perror("ioctl(SIOCGIFADDR)");
    }
    // SAFETY: ifr_addr holds a sockaddr_in after SIOCGIFADDR.
    let ifaddr = unsafe { sys::sockaddr_to_addr(&req.ifr_ifru.ifru_addr) };

    let mut req = sys::new_ifreq(name);
    if (flags & libc::IFF_BROADCAST as i16) != 0 {
        if sys::ioctl_ifreq(_tmp_fd, sys::SIOCGIFBRDADDR, &mut req).is_err() {
            return fatal_perror("ioctl(SIOCGIFBRDADDR)");
        }
        // SAFETY: ifr_broadaddr holds a sockaddr_in after SIOCGIFBRDADDR.
        let dstaddr = unsafe { sys::sockaddr_to_addr(&req.ifr_ifru.ifru_broadaddr) };
        return finish_bsd(name, ifindex, ifaddr, dstaddr, ttl, debug, out_stream, t).map(Some);
    }
    if sys::ioctl_ifreq(_tmp_fd, sys::SIOCGIFDSTADDR, &mut req).is_err() {
        return fatal_perror("ioctl(SIOCGIFBRDADDR)");
    }
    // SAFETY: ifr_dstaddr holds a sockaddr_in after SIOCGIFDSTADDR.
    let dstaddr = unsafe { sys::sockaddr_to_addr(&req.ifr_ifru.ifru_dstaddr) };
    finish_bsd(name, ifindex, ifaddr, dstaddr, ttl, out_stream, t).map(Some)
}

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the original's single-function flow"
)]
fn finish_bsd(
    name: &str,
    ifindex: i32,
    ifaddr: u32,
    dstaddr: u32,
    ttl: u8,
    debug: bool,
    out_stream: &mut Out,
    t: &I18n,
) -> Result<Iface, ()> {
    if debug {
        out_stream.print(&t.debug_iface(name, ifindex, &ipv4_str(ifaddr), &ipv4_str(dstaddr)));
    }

    let mut raw = match sys::raw_socket() {
        Ok(fd) => fd,
        Err(_) => return fatal_perror("socket"),
    };
    let fd = raw.0;
    if sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1).is_err() {
        return fatal_perror("setsockopt SO_BROADCAST");
    }
    if sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_HDRINCL, 1).is_err() {
        return fatal_perror("setsockopt IP_HDRINCL");
    }
    if sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1).is_err() {
        return fatal_perror("setsockopt SO_REUSEPORT");
    }
    // The BSD branch of the original keeps running when these three fail:
    if sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 0).is_err() {
        out::perror("setsockopt IP_MULTICAST_LOOP", out::errno());
    }
    {
        // SAFETY: passing the interface address as IP_MULTICAST_IF, as in the original.
        let ia = libc::in_addr {
            s_addr: ifaddr.swap_bytes(),
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_IF,
                &ia as *const libc::in_addr as *const libc::c_void,
                std::mem::size_of::<libc::in_addr>() as u32,
            )
        };
        if rc < 0 {
            out::perror("setsockopt IP_MULTICAST_IF", out::errno());
        }
    }
    if sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, i32::from(ttl)).is_err() {
        out::perror("setsockopt IP_MULTICAST_TTL", out::errno());
    }
    Ok(Iface {
        dstaddr,
        ifaddr,
        ifindex,
        raw_socket: raw,
    })
}
