//! The relay loop: poll(2)-driven (ADR-011) receive/forward engine mirroring
//! the C original including its quirks (last-match interface lookup, echo
//! detection by TTL, perror without exit on sendto failures).

use crate::cli::{Options, INADDR_BROADCAST, SPOOF_IFACE_BCAST_PORT, SPOOF_IFACE_SRC_PORT};
use crate::i18n::{ipv4_str, I18n};
use crate::iface::Iface;
use crate::out::{self, Out};
use crate::packet::{forge, GRAM_SIZE, HEADER_LEN};
use crate::signal::{Signals, SIG_HUP, SIG_INT, SIG_TERM, SIG_USR1};
use crate::stats::Stats;
use crate::sys;

/// Control buffer size, as in the original (`u_char pkt_infos[16384]`).
const CTRL_SIZE: usize = 16384;

/// One control message: (level, type, data slice).
fn cmsg_iter(ctrl: &[u8]) -> Vec<(i32, i32, &[u8])> {
    let mut out = Vec::new();
    let hdr_size = std::mem::size_of::<libc::cmsghdr>();
    // CMSG_FIRSTHDR: needs at least a full header.
    let mut off = 0usize;
    while off + hdr_size <= ctrl.len() {
        // SAFETY: the header is fully inside ctrl; unaligned read is fine for POD.
        let h = unsafe { std::ptr::read_unaligned(ctrl[off..].as_ptr() as *const libc::cmsghdr) };
        let clen = h.cmsg_len as usize;
        if clen < hdr_size {
            break;
        }
        let data_start = off + hdr_size;
        let data_end = data_start.saturating_add(clen - hdr_size).min(ctrl.len());
        out.push((h.cmsg_level, h.cmsg_type, &ctrl[data_start..data_end]));
        // CMSG_NXTHDR: next header must still fit completely.
        let aligned = (clen + std::mem::size_of::<libc::c_long>() - 1)
            & !(std::mem::size_of::<libc::c_long>() - 1);
        let next = off + aligned;
        if next + hdr_size > ctrl.len() {
            break;
        }
        off = next;
    }
    out
}

/// Run the relay loop until a termination signal arrives.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit state handoff to the event loop"
)]
pub fn run(
    opts: &Options,
    ifaces: &[Iface],
    rcv: &sys::Fd,
    gram: &mut [u8; GRAM_SIZE],
    out_stream: &mut Out,
    t: &I18n,
    signals: &Signals,
    stats: &Stats,
) {
    let ttl = opts.id + crate::packet::TTL_ID_OFFSET;
    let mut ctrl = [0u8; CTRL_SIZE];
    let mut name: libc::sockaddr_in = unsafe { std::mem::zeroed() };

    // poll set: [0] = receiver, [1] = signal self-pipe. (netlink/v6 join later waves)
    let mut pollfds = [
        libc::pollfd {
            fd: rcv.0,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: signals.read_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        match sys::poll(&mut pollfds, -1) {
            Ok(_) => {}
            Err(_) => continue, // EINTR etc.: retry, like the original's `len <= 0`
        }

        if pollfds[1].revents & libc::POLLIN != 0 {
            let mut shutdown = false;
            for tag in signals.drain() {
                match tag {
                    SIG_TERM | SIG_INT => shutdown = true,
                    SIG_HUP => crate::log::reopen(),
                    SIG_USR1 => dump_stats(ifaces, stats, t),
                    _ => {}
                }
            }
            if shutdown {
                out::eprint_raw(&t.shutdown());
                out_stream.flush();
                std::process::exit(0);
            }
        }

        if pollfds[0].revents & libc::POLLIN != 0 {
            // Receive a broadcast packet (payload goes straight into the gram,
            // like the original's iovec pointing at gram + HEADER_LEN).
            let payload = &mut gram[HEADER_LEN..HEADER_LEN + crate::packet::MAX_PAYLOAD];
            let (len, ctrl_len) = match sys::recvmsg_into(rcv.0, payload, &mut ctrl, &mut name) {
                Ok(v) => v,
                Err(_) => continue, // broken packets / EINTR: ignored, like `len <= 0`
            };
            if len <= 0 {
                continue;
            }
            let len = len as usize;
            stats
                .received
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            relay_one(
                opts,
                ifaces,
                gram,
                out_stream,
                t,
                ttl,
                &ctrl[..ctrl_len],
                &mut name,
                len,
                stats,
            );
        }
    }
}

fn dump_stats(ifaces: &[Iface], stats: &Stats, t: &I18n) {
    let g = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
    out::eprint_raw(&t.stats_dump(
        g(&stats.received),
        g(&stats.forwarded),
        g(&stats.dropped_echo),
        g(&stats.dropped_not_managed),
        g(&stats.send_errors),
    ));
    for iface in ifaces {
        let n = g(&iface.sent);
        if n > 0 {
            out::eprint_raw(&t.stats_iface(&iface.name, n));
        }
    }
}

/// Process one received datagram: parse the control messages, find the source
/// interface, apply the rewrite rules and forward to every other interface.
#[allow(clippy::too_many_arguments)]
fn relay_one(
    opts: &Options,
    ifaces: &[Iface],
    gram: &mut [u8; GRAM_SIZE],
    out_stream: &mut Out,
    t: &I18n,
    ttl: u8,
    ctrl: &[u8],
    name: &mut libc::sockaddr_in,
    len: usize,
    stats: &Stats,
) {
    // Find the ttl and the receiving interface from the control messages.
    let mut rcv_ttl: i32 = 0;
    let mut rcv_ifindex: i32 = 0;
    let mut rcv_inaddr: u32 = 0;
    let mut found_rcv_if = false;
    let mut found_rcv_ip = false;
    for (level, ctype, data) in cmsg_iter(ctrl) {
        #[cfg(target_os = "linux")]
        {
            if level == libc::SOL_IP && ctype == libc::IP_TTL && data.len() >= 4 {
                rcv_ttl = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            }
            if level == libc::SOL_IP
                && ctype == libc::IP_PKTINFO
                && data.len() >= std::mem::size_of::<libc::in_pktinfo>()
            {
                // struct in_pktinfo { int ipi_ifindex; in_addr ipi_spec_dst; in_addr ipi_addr; }
                rcv_ifindex = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                rcv_inaddr = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                found_rcv_if = true;
                found_rcv_ip = true;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            if level == libc::IPPROTO_IP && ctype == libc::IP_RECVTTL && data.len() >= 4 {
                rcv_ttl = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            }
            if level == libc::IPPROTO_IP && ctype == libc::IP_RECVDSTADDR && data.len() >= 4 {
                rcv_inaddr = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                found_rcv_ip = true;
            }
            if level == libc::IPPROTO_IP && ctype == libc::IP_RECVIF && data.len() >= 4 {
                // struct sockaddr_dl: sdl_len(1) sdl_family(1) sdl_index(2) ...
                rcv_ifindex = u16::from_be_bytes([data[2], data[3]]) as i32;
                found_rcv_if = true;
            }
        }
    }

    // perror prefixes carry a trailing \n in the original: the printed error
    // spans two lines. Quirk preserved.
    if !found_rcv_ip {
        out::perror(t.perr_source_ip_missing(), out::errno());
        return;
    }
    if !found_rcv_if {
        out::perror(t.perr_iface_missing(), out::errno());
        return;
    }
    if rcv_ttl == 0 {
        out::perror(t.perr_ttl_missing(), out::errno());
        return;
    }

    // The original keeps overwriting fromIface while scanning, so the LAST
    // managed interface with a matching index wins.
    let mut from_idx: Option<usize> = None;
    for (idx, iface) in ifaces.iter().enumerate() {
        if iface.ifindex == rcv_ifindex {
            from_idx = Some(idx);
        }
    }

    // SAFETY-irrelevant: sockaddr was filled by recvmsg (msg_name).
    let orig_from_addr = name.sin_addr.s_addr.swap_bytes(); // numeric form
    let orig_from_port = u16::from_be(name.sin_port);
    let orig_to_addr = rcv_inaddr;
    let orig_to_port = opts.port;

    // gram[HEADER_LEN + len] = 0 (payload NUL terminator, kept for parity).
    if HEADER_LEN + len < GRAM_SIZE {
        gram[HEADER_LEN + len] = 0;
    }

    if opts.debug {
        out_stream.print(&t.debug_recv(
            &ipv4_str(orig_from_addr),
            u32::from(orig_from_port),
            &ipv4_str(orig_to_addr),
            u32::from(orig_to_port),
            rcv_ifindex,
            len,
            rcv_ttl,
        ));
    }

    if rcv_ttl == i32::from(ttl) {
        if opts.debug {
            out_stream.print(&t.debug_echo());
        }
        stats
            .dropped_echo
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }
    let Some(from_idx) = from_idx else {
        if opts.debug {
            out_stream.print(&t.debug_not_managed());
        }
        stats
            .dropped_not_managed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    };

    // Iterate through our interfaces and send the packet to each one.
    for (idx, iface) in ifaces.iter().enumerate() {
        // No bounces, please (pointer equality in C; index here).
        if idx == from_idx {
            continue;
        }

        let (from_addr, from_port) = if opts.spoof == SPOOF_IFACE_BCAST_PORT {
            (iface.ifaddr, opts.port)
        } else if opts.spoof == SPOOF_IFACE_SRC_PORT {
            (iface.ifaddr, orig_from_port)
        } else if opts.spoof != 0 {
            (opts.spoof, orig_from_port)
        } else {
            (orig_from_addr, orig_from_port)
        };

        let to_addr = if opts.target != 0 {
            // User instructed us to override the target IP address.
            if opts.target == INADDR_BROADCAST {
                // Rewrite to the new interface's broadcast address.
                iface.dstaddr
            } else {
                // Rewrite to the specified value.
                opts.target
            }
        } else if rcv_inaddr == INADDR_BROADCAST || rcv_inaddr == ifaces[from_idx].dstaddr {
            // Received on an interface broadcast address — rewrite to the
            // new interface's broadcast address.
            iface.dstaddr
        } else {
            // Send to whatever IP it was originally to.
            rcv_inaddr
        };
        let to_port = orig_to_port;

        if opts.debug {
            out_stream.print(&t.debug_send(
                &ipv4_str(from_addr),
                u32::from(from_port),
                &ipv4_str(to_addr),
                u32::from(to_port),
                iface.ifindex,
            ));
        }

        forge(gram, ttl, from_addr, to_addr, from_port, to_port, len);

        let sa = sys::sockaddr_in(to_addr, to_port);
        let total = HEADER_LEN + len;
        match sys::sendto_in(iface.raw_socket.0, &gram[..total], &sa) {
            Ok(_) => {
                stats
                    .forwarded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(_) => {
                out::perror("sendto", out::errno());
                stats
                    .send_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    if opts.debug {
        out_stream.print("\n");
    }
}
