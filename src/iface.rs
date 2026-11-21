//! Interface enumeration and per-interface raw sockets.
//!
//! `probe` gathers a candidate (index/flags/addresses) through one socket —
//! plain DGRAM ioctls need no root, so `--list-interfaces` reuses it while
//! the daemon path keeps the original's raw-socket requirement for sending.
//! Error labels reproduce the C original, including the copy-paste quirk of
//! reporting `ioctl(SIOCGIFBRDADDR)` when `SIOCGIFDSTADDR` fails.

use crate::i18n::{ipv4_str, I18n};
use crate::out::{self, Out};
use crate::sys;

/// One probed interface candidate.
pub struct Candidate {
    /// The (possibly truncated) name the original would print.
    pub printed_name: String,
    pub ifindex: i32,
    pub flags: i16,
    /// IPv4 address in numeric form; None with `ifaddr_errno` when unavailable.
    pub ifaddr: Option<u32>,
    pub ifaddr_errno: i32,
    /// Broadcast (or point-to-point peer) address; only fetched for up,
    /// non-loopback candidates — matching the original's order.
    pub dstaddr: Option<u32>,
    pub dstaddr_errno: i32,
    /// Why setup would skip this candidate ("down" / "loopback").
    pub skip_reason: Option<&'static str>,
}

pub struct ProbeError {
    pub label: &'static str,
    pub errno: i32,
}

/// One managed interface: addresses in numeric form, kernel index, raw socket.
pub struct Iface {
    pub name: String,
    pub dstaddr: u32,
    pub ifaddr: u32,
    pub ifindex: i32,
    pub raw_socket: sys::Fd,
    /// Raw IPv6 send socket (`--ipv6` only).
    pub raw6_socket: Option<sys::Fd>,
    /// Packets successfully forged out of this interface (SIGUSR1 dump).
    pub sent: std::sync::atomic::AtomicU64,
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

/// Read the IPv4 address stored in a `struct sockaddr` (bytes 4..8, network
/// order) as the numeric (host-assembled) form.
///
/// # Safety
/// `sa` must point to at least 8 readable bytes of a sockaddr family record.
unsafe fn sockaddr_to_addr(sa: &libc::sockaddr) -> u32 {
    let b = sa.sa_data.as_ptr().cast::<u8>().add(2);
    let mut four = [0u8; 4];
    std::ptr::copy_nonoverlapping(b, four.as_mut_ptr(), 4);
    u32::from_be_bytes(four)
}

/// The truncated name inside ifr_name (lossy for >=16-char names, where the
/// C original reads past the array — undefined behavior there).
fn printed_ifr_name(ifr_name: &[libc::c_char; 16]) -> String {
    // SAFETY: reading the fixed-size name array; c_char and u8 share layout.
    let bytes: &[u8] = unsafe {
        let p = ifr_name.as_ptr().cast::<u8>();
        std::slice::from_raw_parts(p, 16)
    };
    let end = bytes.iter().position(|c| *c == 0).unwrap_or(16);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Probe one interface: index, flags, address, broadcast/ptp destination.
/// Fetch order mirrors the original: INDEX → FLAGS → (skip decision) →
/// ADDR → BRDADDR/DSTADDR. `Err` = a fatal ioctl failure with its perror label.
pub fn probe(fd: i32, name: &str) -> Result<Candidate, ProbeError> {
    #[cfg(target_os = "linux")]
    let ifindex = {
        let mut req = make_ifreq(name);
        sys::ioctl_ifreq(fd, sys::SIOCGIFINDEX, &mut req).map_err(|_| ProbeError {
            label: "ioctl(SIOCGIFINDEX)",
            errno: out::errno(),
        })?;
        // SAFETY: SIOCGIFINDEX filled ifru_ifindex on success.
        unsafe { req.ifr_ifru.ifru_ifindex }
    };
    #[cfg(not(target_os = "linux"))]
    let ifindex = sys::if_nametoindex(name).unwrap_or(0) as i32;

    let mut req = make_ifreq(name);
    sys::ioctl_ifreq(fd, sys::SIOCGIFFLAGS, &mut req).map_err(|_| ProbeError {
        label: "ioctl(SIOCGIFFLAGS)",
        errno: out::errno(),
    })?;
    // SAFETY: SIOCGIFFLAGS filled ifru_flags on success.
    #[cfg(target_os = "freebsd")]
    let flags = unsafe { req.ifr_ifru.ifru_flags[0] };
    #[cfg(not(target_os = "freebsd"))]
    let flags = unsafe { req.ifr_ifru.ifru_flags };

    let skip_reason = if (flags & libc::IFF_UP as i16) == 0 {
        Some("down")
    } else if (flags & libc::IFF_LOOPBACK as i16) != 0 {
        Some("loopback")
    } else {
        None
    };

    // Local address. The original dies here on failure (label kept for setup);
    // the list view shows it as "-" instead.
    let mut req = make_ifreq(name);
    let (ifaddr, ifaddr_errno) = match sys::ioctl_ifreq(fd, sys::SIOCGIFADDR, &mut req) {
        Ok(()) => (
            // SAFETY: ifru_addr holds a sockaddr_in after SIOCGIFADDR.
            Some(unsafe { sockaddr_to_addr(&req.ifr_ifru.ifru_addr) }),
            0,
        ),
        Err(_) => (None, out::errno()),
    };

    // Broadcast / point-to-point destination, only for up non-loopback
    // interfaces (the original's order). Its failure label is
    // "ioctl(SIOCGIFBRDADDR)" in both branches — quirk preserved.
    let mut dstaddr = None;
    let mut dstaddr_errno = 0;
    if skip_reason.is_none() {
        let mut req = make_ifreq(name);
        if (flags & libc::IFF_BROADCAST as i16) != 0 {
            match sys::ioctl_ifreq(fd, sys::SIOCGIFBRDADDR, &mut req) {
                Ok(()) => {
                    // SAFETY: ifru_broadaddr holds a sockaddr_in after SIOCGIFBRDADDR.
                    dstaddr = Some(unsafe { sockaddr_to_addr(&req.ifr_ifru.ifru_broadaddr) });
                }
                Err(_) => dstaddr_errno = out::errno(),
            }
        } else {
            match sys::ioctl_ifreq(fd, sys::SIOCGIFDSTADDR, &mut req) {
                Ok(()) => {
                    // SAFETY: ifru_dstaddr holds a sockaddr_in after SIOCGIFDSTADDR.
                    dstaddr = Some(unsafe { sockaddr_to_addr(&req.ifr_ifru.ifru_dstaddr) });
                }
                Err(_) => dstaddr_errno = out::errno(),
            }
        }
    }

    Ok(Candidate {
        printed_name: printed_ifr_name(&make_ifreq(name).ifr_name),
        ifindex,
        flags,
        ifaddr,
        ifaddr_errno,
        dstaddr,
        dstaddr_errno,
        skip_reason,
    })
}

/// Setup failure kinds. `MissingDev` means "interface does not exist (yet)" —
/// the caller may defer it to the netlink monitor; `Fatal` means the perror
/// line was already written and the caller must exit like the original.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupErr {
    MissingDev,
    Fatal,
}

/// Set up one managed interface; `Ok(None)` = skipped (down or loopback).
/// `Err(Fatal)` = the perror line has already been written, the caller
/// flushes and exits 1 — preserving the original's output order.
/// `Err(MissingDev)` = ENODEV, perror suppressed for the deferral path.
pub fn setup(
    tmp_fd: i32,
    name: &str,
    #[cfg_attr(target_os = "linux", allow(unused_variables))] ttl: u8,
    debug: bool,
    ipv6: bool,
    out_stream: &mut Out,
    t: &I18n,
) -> Result<Option<Iface>, SetupErr> {
    let c = probe(tmp_fd, name).map_err(|e| {
        if e.label == "ioctl(SIOCGIFINDEX)" && e.errno == libc::ENODEV {
            SetupErr::MissingDev
        } else {
            out::perror(e.label, e.errno);
            SetupErr::Fatal
        }
    })?;
    if c.skip_reason.is_some() {
        return Ok(None);
    }
    let Some(ifaddr) = c.ifaddr else {
        out::perror("ioctl(SIOCGIFADDR)", c.ifaddr_errno);
        return Err(SetupErr::Fatal);
    };
    let Some(dstaddr) = c.dstaddr else {
        out::perror("ioctl(SIOCGIFBRDADDR)", c.dstaddr_errno);
        return Err(SetupErr::Fatal);
    };

    if debug {
        out_stream.print(&t.debug_iface(
            &c.printed_name,
            c.ifindex,
            &ipv4_str(ifaddr),
            &ipv4_str(dstaddr),
        ));
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
    #[cfg(target_os = "linux")]
    {
        // Bind the socket to the NIC, overriding the routing table.
        if sys::setsockopt_bind_to_device(fd, name).is_err() {
            return fatal_perror("setsockopt SO_BINDTODEVICE");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
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
        if sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, i32::from(ttl))
            .is_err()
        {
            out::perror("setsockopt IP_MULTICAST_TTL", out::errno());
        }
    }
    // Raw IPv6 send socket for --ipv6 relay. Linux builds the IPv6 header
    // itself; IP_TRANSPARENT lets the forged (foreign) source address pass
    // non-local validation — same effect the v4 raw+HDRINCL path has.
    let raw6 = if ipv6 {
        match sys::raw6_socket() {
            Ok(fd) => {
                #[cfg(target_os = "linux")]
                {
                    if sys::setsockopt_bind_to_device(fd.0, name).is_err() {
                        out::perror("setsockopt SO_BINDTODEVICE", out::errno());
                    }
                    // SAFETY: int-valued transparent-socket option; needs CAP_NET_RAW.
                    let one: i32 = 1;
                    let rc = unsafe {
                        libc::setsockopt(
                            fd.0,
                            libc::SOL_IP,
                            libc::IP_TRANSPARENT,
                            std::ptr::addr_of!(one).cast::<libc::c_void>(),
                            std::mem::size_of::<i32>() as u32,
                        )
                    };
                    if rc < 0 {
                        out::perror("setsockopt IP_TRANSPARENT", out::errno());
                    }
                }
                // Socket-level hop limit for the degraded bare-sendto path.
                if sys::setsockopt6_multicast_hops(fd.0, i32::from(ttl)).is_err() {
                    out::perror("setsockopt IPV6_MULTICAST_HOPS", out::errno());
                }
                Some(fd)
            }
            Err(_) => {
                out::perror("socket", out::errno());
                None
            }
        }
    } else {
        None
    };
    Ok(Some(Iface {
        name: name.to_string(),
        dstaddr,
        ifaddr,
        ifindex: c.ifindex,
        raw_socket: raw,
        raw6_socket: raw6,
        sent: std::sync::atomic::AtomicU64::new(0),
    }))
}

fn fatal_perror<T>(prefix: &str) -> Result<T, SetupErr> {
    out::perror(prefix, out::errno());
    Err(SetupErr::Fatal)
}

/// `if_nametoindex` (BSD/macOS fallback used by probe).
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn if_nametoindex(name: &str) -> Option<u32> {
    sys::if_nametoindex(name)
}

/// Enumerate every system interface (via /sys/class/net) as list rows.
/// `selected` marks the names requested with `--dev`.
pub fn list_rows(selected: &std::collections::HashSet<String>, t: &I18n) -> String {
    // A plain DGRAM socket is enough for the SIOCGIF* ioctls — no root needed.
    let Ok(fd) = sys::udp_socket() else {
        return t.list_header();
    };
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();

    let mut out = t.list_header();
    for name in names {
        let (addr, dst, state) = match probe(fd.0, &name) {
            Ok(c) => {
                let addr = c.ifaddr.map(ipv4_str).unwrap_or_else(|| "-".into());
                let dst = c.dstaddr.map(ipv4_str).unwrap_or_else(|| "-".into());
                let state = if let Some(reason) = c.skip_reason {
                    reason.to_string()
                } else if c.ifaddr.is_none() {
                    "no-ipv4".to_string()
                } else if (c.flags & libc::IFF_BROADCAST as i16) == 0 {
                    "ptp".to_string()
                } else {
                    "up".to_string()
                };
                (addr, dst, state)
            }
            Err(_) => ("-".into(), "-".into(), "error".to_string()),
        };
        let sel = if selected.contains(&name) {
            "yes"
        } else {
            "no"
        };
        out.push_str(&t.list_row(&name, probe_index(fd.0, &name), &addr, &dst, &state, sel));
    }
    out
}

/// The index row for the list view (0 when the probe failed).
fn probe_index(fd: i32, name: &str) -> i32 {
    probe(fd, name).map(|c| c.ifindex).unwrap_or(0)
}
