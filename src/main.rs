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
mod event;
mod i18n;
mod iface;
mod log;
mod out;
mod packet;
mod relay;
mod signal;
mod stats;
mod sys;

use i18n::I18n;
use out::Out;
use stats::Stats;
use std::collections::HashSet;

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

    // Pre-scanned operational flags (new; never disturb the original's
    // argument semantics). Order: log target → help → version → list.
    let mut log_spec = None;
    let mut help = false;
    let mut version = false;
    let mut list = false;
    let mut selected_devs = std::collections::HashSet::new();
    // Args the faithful parser still sees: everything except `--log` and its
    // value (-h/--version/--list-interfaces short-circuit before parsing).
    let mut work: Vec<String> = Vec::with_capacity(scan.args.len());
    {
        let args = &scan.args;
        let mut i = 0usize;
        while i < args.len() {
            let a = args[i].as_str();
            match a {
                "--log" => {
                    log_spec = args.get(i + 1).cloned();
                    i += 2;
                    continue; // stripped from the parser's view, value included
                }
                "-h" | "--help" => help = true,
                "--version" => version = true,
                "--list-interfaces" => list = true,
                "--dev" => {
                    if let Some(v) = args.get(i + 1) {
                        selected_devs.insert(v.clone());
                    }
                }
                _ => {}
            }
            work.push(args[i].clone());
            i += 1;
        }
    }
    if let Some(spec) = log_spec {
        if let Err(_msg) = log::init(&spec, &scan.program) {
            out::eprint_raw(&t.invalid_log(&spec));
            std::process::exit(1);
        }
    }
    if help {
        out_stream.print(&t.extended_usage(&scan.program));
        out_stream.flush();
        std::process::exit(0);
    }
    if version {
        out_stream.print(&format!(
            "udp-broadcast-relay-redux {}\n",
            env!("CARGO_PKG_VERSION")
        ));
        out_stream.flush();
        std::process::exit(0);
    }
    if list {
        out_stream.print(&iface::list_rows(&selected_devs, &t));
        out_stream.flush();
        std::process::exit(0);
    }

    let opts = match cli::parse(&scan.program, &work, &mut out_stream, &t) {
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

    // Deduplicate --dev names: the original would create a second raw socket
    // for the same interface and forward duplicate copies back onto it.
    let mut seen_dev = HashSet::new();
    let mut dev_names = Vec::with_capacity(opts.interfaces.len());
    for name in &opts.interfaces {
        if seen_dev.insert(name.clone()) {
            dev_names.push(name.clone());
        } else {
            out::eprint_raw(&t.dup_dev(name));
        }
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

    // Set up one raw sending socket per requested interface. An interface
    // that does not exist at all (ENODEV) is deferred to the netlink monitor
    // when at least one other interface is usable (hot-plug workflow,
    // documented deviation #5); if every requested interface is missing, the
    // original's fatal behavior is preserved.
    let mut ifaces: Vec<iface::Iface> = Vec::new();
    let mut seen_idx = HashSet::new();
    let mut fatal_missing: Vec<String> = Vec::new();
    for name in &dev_names {
        match iface::setup(tmp_fd.0, name, ttl, opts.debug, &mut out_stream, &t) {
            Ok(Some(iface)) => {
                // Two different names can resolve to the same kernel index
                // (aliases): keep only the first.
                if seen_idx.insert(iface.ifindex) {
                    ifaces.push(iface);
                } else {
                    out::eprint_raw(&t.dup_iface(name, iface.ifindex));
                }
            }
            Ok(None) => {} // down or loopback: silently skipped
            Err(iface::SetupErr::MissingDev) => {
                // Interface not present at startup: defer to the netlink
                // monitor when at least one other interface is usable.
                fatal_missing.push(name.clone());
            }
            Err(iface::SetupErr::Fatal) => {
                // perror already written; exit like the original.
                out_stream.flush();
                std::process::exit(1);
            }
        }
    }
    // Every requested interface missing → the original's behavior (one
    // ENODEV perror per interface, then exit). Mixed case → defer.
    if ifaces.is_empty() && !fatal_missing.is_empty() {
        for _name in &fatal_missing {
            out::perror("ioctl(SIOCGIFINDEX)", libc::ENODEV);
        }
        out_stream.flush();
        std::process::exit(1);
    }

    if opts.debug {
        out_stream.print(&t.debug_found(ifaces.len()));
    }

    // Running with no managed interface would only bind the port and wait
    // forever (the original's zombie-daemon mode) — fail fast instead.
    if ifaces.is_empty() {
        out::eprint_raw(&t.no_interfaces());
        out_stream.flush();
        std::process::exit(1);
    }

    sys::close(&mut tmp_fd);

    // Broadcast receiving socket (+ the joined-membership table).
    let (rcv, mut joined) = match setup_receiver(&opts, &ifaces, &mut out_stream, &t) {
        Ok(v) => v,
        Err(()) => {
            out_stream.flush();
            std::process::exit(1);
        }
    };

    // Hot-plug monitoring (Linux): follow link/IPv4-address changes so the
    // managed set tracks reality instead of a one-shot startup snapshot.
    #[cfg(target_os = "linux")]
    let netlink = sys::netlink_route((libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR) as u32).ok();
    #[cfg(not(target_os = "linux"))]
    let netlink: Option<sys::Fd> = None;

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

    // Graceful shutdown / stats via the self-pipe (ADR-011). Installed after
    // the fork so only the (grand-)child that runs the loop owns them.
    let signals = match signal::Signals::install() {
        Ok(s) => s,
        Err(_) => {
            out::perror("sigaction", out::errno());
            std::process::exit(1);
        }
    };
    let stats = Stats::default();

    let mut gram = packet::new_gram();
    relay::run(
        &opts,
        &mut ifaces,
        &rcv,
        &mut gram,
        &mut out_stream,
        &t,
        &signals,
        &stats,
        &mut joined,
        netlink.as_ref(),
    );
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
) -> Result<(sys::Fd, std::collections::HashSet<(u32, u32)>), ()> {
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

    let mut joined = HashSet::new();
    for mcast in &opts.multicast {
        for iface in ifaces {
            let multi = cli::inet_addr(mcast); // unchecked in the original; invalid → join fails
                                               // The original would join the same (group, interface) pair twice
                                               // and die on EADDRINUSE — skip repeats instead.
            if !joined.insert((multi, iface.ifaddr)) {
                if opts.debug {
                    let line = t.dup_membership(mcast, &i18n::ipv4_str(iface.ifaddr));
                    out_stream.print(&line);
                }
                continue;
            }
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
    Ok((rcv, joined))
}

fn fatal_perror<T>(prefix: &str) -> Result<T, ()> {
    out::perror(prefix, out::errno());
    Err(())
}
