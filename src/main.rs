//! udp-broadcast-relay-redux (Rust port)
//!
//! Relays UDP broadcasts to other networks, forging the sender address.
//! Port of the C original at github.com/udp-redux/udp-broadcast-relay-redux,
//! proved against 207 recorded behavior cases (see docs/PORTING.md) with
//! optional i18n (`--lang en|zh`, ADR-005).
//!
//! Copyright (c) 2017 UDP Broadcast Relay Redux Contributors
//! Copyright (c) 2003 Joachim Breitner
//! Copyright (C) 2002 Nathan O'Sullivan
//! GPL-2.0-or-later (see LICENSE).

mod cli;
mod i18n;
mod iface;
mod out;
mod packet;
mod relay;
mod sys;

use i18n::I18n;
use out::Out;

fn main() {
    let argv: Vec<String> = std::env::args().collect();

    // i18n resolution happens first: `--lang` is pre-scanned and stripped so
    // the faithful parser sees exactly the original's argument set.
    let scan = match i18n::scan_lang(&argv) {
        Ok(scan) => scan,
        Err(msg) => {
            out::eprint_raw(&msg);
            std::process::exit(1);
        }
    };
    let t = I18n::new(scan.lang);
    let mut out_stream = Out::new();

    let opts = match cli::parse(&scan.program, &scan.args, &mut out_stream, &t) {
        Ok(o) => o,
        Err(code) => {
            out_stream.flush();
            std::process::exit(code);
        }
    };

    // u_char ttl = id + TTL_ID_OFFSET (id ≤ 99, so the sum fits a u8).
    let ttl = opts.id + packet::TTL_ID_OFFSET;
    if opts.debug {
        out_stream.print(&t.debug_id_ttl_port(
            u32::from(opts.id),
            u32::from(ttl),
            u32::from(opts.port),
        ));
    }

    // Temporary socket used to query interface addresses (closed right after).
    let mut tmp_fd = match sys::raw_socket() {
        Ok(fd) => fd,
        Err(_) => {
            out::perror("socket", out::errno());
            out::eprint_raw(&t.must_be_root());
            out_stream.flush();
            std::process::exit(1);
        }
    };

    // Set up one raw sending socket per requested interface.
    let mut ifaces: Vec<iface::Iface> = Vec::new();
    for name in &opts.interfaces {
        match iface::setup(tmp_fd.0, name, ttl, &mut out_stream, &t) {
            Ok(Some(iface)) => ifaces.push(iface),
            Ok(None) => {} // down or loopback: silently skipped
            Err(()) => {
                // perror already written; exit like the original.
                out_stream.flush();
                std::process::exit(1);
            }
        }
    }

    if opts.debug {
        out_stream.print(&t.debug_found(ifaces.len()));
    }

    sys::close(&mut tmp_fd);

    // Broadcast receiving socket.
    let rcv = match setup_receiver(&opts, &ifaces, &mut out_stream, &t) {
        Ok(rcv) => rcv,
        Err(()) => {
            out_stream.flush();
            std::process::exit(1);
        }
    };

    if opts.debug {
        out_stream.print(&t.debug_done());
    }

    // Fork to background: the parent exits 0; in non-debug mode the daemon
    // closes stdin/stdout/stderr exactly like the original's fcloses.
    if !opts.debug {
        if opts.forking && sys::fork().is_some() {
            out_stream.flush();
            std::process::exit(0);
        }
        out_stream.flush();
        sys::close_fd(0);
        sys::close_fd(1);
        sys::close_fd(2);
    }

    let mut gram = packet::new_gram();
    relay::run(&opts, &ifaces, &rcv, &mut gram, &mut out_stream, &t);
}

/// Create the receiving socket: SO_BROADCAST, SO_REUSEPORT, TTL/PKTINFO
/// reception (Linux) or TTL/IF/DSTADDR reception (BSD/macOS), multicast
/// membership per (--multicast × managed interface), then bind to 0.0.0.0:port.
/// All failures print perror and return Err(()) — caller exits 1.
fn setup_receiver(
    opts: &cli::Options,
    ifaces: &[iface::Iface],
    out_stream: &mut Out,
    t: &I18n,
) -> Result<sys::Fd, ()> {
    let rcv = match sys::udp_socket() {
        Ok(fd) => fd,
        Err(_) => return fatal_perror("socket"),
    };
    let fd = rcv.0;
    if sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1).is_err() {
        return fatal_perror("SO_BROADCAST on rcv");
    }
    if sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1).is_err() {
        return fatal_perror("SO_REUSEPORT on rcv");
    }
    #[cfg(target_os = "linux")]
    {
        if sys::setsockopt_int(fd, libc::SOL_IP, libc::IP_RECVTTL, 1).is_err() {
            return fatal_perror("IP_RECVTTL on rcv");
        }
        if sys::setsockopt_int(fd, libc::SOL_IP, libc::IP_PKTINFO, 1).is_err() {
            return fatal_perror("IP_PKTINFO on rcv");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1).is_err() {
            return fatal_perror("IP_RECVTTL on rcv");
        }
        if sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVIF, 1).is_err() {
            return fatal_perror("IP_RECVIF on rcv");
        }
        if sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVDSTADDR, 1).is_err() {
            return fatal_perror("IP_RECVDSTADDR on rcv");
        }
    }

    for mcast in &opts.multicast {
        for iface in ifaces {
            let multi = cli::inet_addr(mcast); // unchecked in the original; invalid → join fails
            if opts.debug {
                // The original prints this before the setsockopt, per pair.
                let line = t.debug_add_membership(&i18n::ipv4_str(iface.ifaddr), mcast);
                out_stream.print(&line);
            }
            let mreq = libc::ip_mreq {
                imr_multiaddr: libc::in_addr {
                    s_addr: multi.swap_bytes(),
                },
                imr_interface: libc::in_addr {
                    s_addr: iface.ifaddr.swap_bytes(),
                },
            };
            // SAFETY: mreq is fully initialized; IP_ADD_MEMBERSHIP reads it inline.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_ADD_MEMBERSHIP,
                    &mreq as *const libc::ip_mreq as *const libc::c_void,
                    std::mem::size_of::<libc::ip_mreq>() as u32,
                )
            };
            if rc < 0 {
                return fatal_perror("IP_ADD_MEMBERSHIP on rcv");
            }
        }
    }

    let bind_addr = sys::sockaddr_in(0, opts.port); // INADDR_ANY
                                                    // SAFETY: bind with a fully initialized sockaddr_in.
    let rc = unsafe {
        libc::bind(
            fd,
            &bind_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if rc < 0 {
        out::perror("bind", out::errno());
        out::eprint_raw(&t.rcv_bind());
        return Err(());
    }
    Ok(rcv)
}

fn fatal_perror(prefix: &str) -> Result<sys::Fd, ()> {
    out::perror(prefix, out::errno());
    Err(())
}
