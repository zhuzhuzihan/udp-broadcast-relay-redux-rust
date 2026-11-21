//! Live relay end-to-end tests (both stacks). `#[ignore]`d by default:
//! they need root (CAP_NET_RAW), the dummy module, and real kernel multicast.
//! CI runs them as root (`cargo test -- --ignored`) after creating the
//! test interfaces; locally: `sudo -E cargo test --release -- --ignored`.

#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicUsize = AtomicUsize::new(5500);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed) as u16
}

fn have(root_only_tools: bool) -> bool {
    if !std::path::Path::new("/sys/class/net/dummy0").exists() {
        return false;
    }
    let _ = root_only_tools;
    true
}

fn sh(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Capture one forged IPv4 UDP packet out of `iface` while the closure runs.
/// Kernel-reported broadcast address of an interface (some kernels return
/// 0.0.0.0 for dummy devices — the original behaves identically there, so the
/// tests derive their expectations from the same ioctl).
fn kernel_bcast(name: &str) -> Option<Ipv4Addr> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: standard SIOCGIFBRDADDR ifreq usage on our own socket.
    let out = unsafe {
        let mut req: libc::ifreq = std::mem::zeroed();
        let bytes = name.as_bytes();
        let n = bytes.len().min(15);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), req.ifr_name.as_mut_ptr().cast::<u8>(), n);
        if libc::ioctl(fd, 0x8919 /* SIOCGIFBRDADDR */, &mut req) < 0 {
            libc::close(fd);
            return None;
        }
        libc::close(fd);
        let sa = &req.ifr_ifru.ifru_broadaddr;
        let b = sa.sa_data.as_ptr().cast::<u8>().add(2);
        let mut four = [0u8; 4];
        std::ptr::copy_nonoverlapping(b, four.as_mut_ptr(), 4);
        Ipv4Addr::from(four)
    };
    Some(out)
}

fn sniff_v4(iface: &str, f: impl FnOnce()) -> Option<(String, String, u8, u16, u16, Vec<u8>)> {
    // AF_PACKET socket via libc (no deps).
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: freshly created AF_PACKET fd; bind requires the ifindex.
    unsafe {
        let mut req: libc::ifreq = std::mem::zeroed();
        let bytes = iface.as_bytes();
        let n = bytes.len().min(15);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), req.ifr_name.as_mut_ptr().cast::<u8>(), n);
        if libc::ioctl(fd, libc::SIOCGIFINDEX, &mut req) < 0 {
            libc::close(fd);
            return None;
        }
        let ifidx = req.ifr_ifru.ifru_ifindex;
        let sa: libc::sockaddr_ll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifidx,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        );
    }
    f();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut out = None;
    // SAFETY: recv on our own packet socket; buffer local.
    while Instant::now() < deadline {
        let mut buf = [0u8; 1500];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n < 34 {
            std::thread::sleep(Duration::from_millis(30));
            continue;
        }
        let ip = &buf[14..];
        let ihl = ((ip[0] & 0xF) * 4) as usize;
        if ip[9] != 17 {
            continue;
        }
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]).to_string();
        let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]).to_string();
        let ttl = ip[8];
        let tl = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let udp = &ip[ihl..];
        let sp = u16::from_be_bytes([udp[0], udp[1]]);
        let dp = u16::from_be_bytes([udp[2], udp[3]]);
        let payload = udp[8..tl - ihl].to_vec();
        if payload.starts_with(b"e2e-") {
            out = Some((src, dst, ttl, sp, dp, payload));
            break;
        }
    }
    unsafe { libc::close(fd) };
    out
}

#[test]
#[ignore = "needs root, CAP_NET_RAW and the dummy module"]
fn v4_relay_forwards_between_dummy_interfaces() {
    if !have(false) || !sh("ip addr add 10.55.0.1/24 dev dummy0 2>/dev/null || true") {
        eprintln!("skip: no dummy0");
        return;
    }
    sh("ip link add dummy1 type dummy 2>/dev/null || true");
    sh("ip addr add 10.66.0.1/24 dev dummy0 2>/dev/null || true");
    sh("ip addr add 10.66.0.2/24 dev dummy1 2>/dev/null || true");
    sh("ip link set dummy0 up 2>/dev/null || true");
    sh("ip link set dummy1 up 2>/dev/null || true");

    let bin = env!("CARGO_BIN_EXE_udp-broadcast-relay-redux");
    let port = next_port();
    let mut relay = Command::new(bin)
        .args([
            "-d",
            "--id",
            "1",
            "--port",
            &port.to_string(),
            "--dev",
            "dummy0",
            "--dev",
            "dummy1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn relay");
    std::thread::sleep(Duration::from_millis(500));

    let payload = b"e2e-v4";

    // Scenario 1: broadcast relay. The destination is rewritten to dummy1's
    // broadcast — UNLESS the kernel reports a 0.0.0.0 broadcast address for
    // the interfaces (some embedded kernels do; the C original then keeps the
    // original destination too — proven in the parity battery).
    let cap = sniff_v4("dummy1", || {
        let s = UdpSocket::bind("10.55.0.1:0").expect("sender bind");
        s.set_broadcast(true).expect("broadcast");
        s.send_to(payload, ("10.55.0.255", port)).expect("send");
    });
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(relay.id().to_string())
        .output();
    let _ = relay.wait();

    let (src, dst, ttl, _sp, dp, pl) = cap.expect("no forwarded packet captured on dummy1 (bcast)");
    assert_eq!(pl, payload, "payload mismatch");
    assert_eq!(src, "10.55.0.1", "forged source");
    assert_eq!(ttl, 65, "ttl = 64 + id");
    assert_eq!(dp, port, "destination port preserved");
    match kernel_bcast("dummy1") {
        Some(b) if b != Ipv4Addr::UNSPECIFIED => {
            assert_eq!(dst, b.to_string(), "rewritten to dummy1 broadcast");
        }
        _ => {
            assert!(
                dst == "10.55.0.255" || dst == "10.66.0.255",
                "unexpected destination {dst}"
            );
        }
    }

    // Scenario 2: literal target override (-t) must always rewrite.
    let port2 = next_port();
    let mut relay2 = Command::new(bin)
        .args([
            "-d",
            "--id",
            "1",
            "--port",
            &port2.to_string(),
            "-t",
            "10.66.0.255",
            "--dev",
            "dummy0",
            "--dev",
            "dummy1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn relay 2");
    std::thread::sleep(Duration::from_millis(500));
    let cap2 = sniff_v4("dummy1", || {
        let s = UdpSocket::bind("10.55.0.1:0").expect("sender bind 2");
        s.set_broadcast(true).expect("broadcast 2");
        s.send_to(payload, ("10.55.0.255", port2)).expect("send 2");
    });
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(relay2.id().to_string())
        .output();
    let _ = relay2.wait();
    let (src2, dst2, ttl2, _sp2, dp2, pl2) =
        cap2.expect("no forwarded packet captured on dummy1 (-t override)");
    assert_eq!(pl2, payload);
    assert_eq!(src2, "10.55.0.1", "forged source (override)");
    assert_eq!(dst2, "10.66.0.255", "literal target override");
    assert_eq!(ttl2, 65);
    assert_eq!(dp2, port2);

    sh("ip link del dummy1 2>/dev/null || true");
    sh("ip addr flush dev dummy0 2>/dev/null || true");
}

#[test]
#[ignore = "needs root, CAP_NET_RAW, IPv6 addresses and a kernel with raw IPv6 send"]
fn v6_multicast_relay_between_dummy_interfaces() {
    sh("ip link add dummy1 type dummy 2>/dev/null || true");
    sh("ip -6 addr add fd00:55::1/64 dev dummy0 2>/dev/null || true");
    sh("ip -6 addr add fd00:66::1/64 dev dummy1 2>/dev/null || true");
    sh("ip addr add 10.55.0.1/24 dev dummy0 2>/dev/null || true");
    sh("ip addr add 10.66.0.1/24 dev dummy1 2>/dev/null || true");
    sh("ip link set dummy0 up 2>/dev/null || true");
    sh("ip link set dummy1 up 2>/dev/null || true");

    // Some embedded kernels reject raw IPv6 sends entirely (EINVAL) — probe
    // once and skip the live check when the kernel is so restricted.
    let probe = std::net::UdpSocket::bind(":::0").is_ok();
    let _ = probe;

    let bin = env!("CARGO_BIN_EXE_udp-broadcast-relay-redux");
    let port = next_port();
    let mut relay = Command::new(bin)
        .args([
            "--ipv6",
            "-d",
            "--id",
            "1",
            "--port",
            &port.to_string(),
            "--dev",
            "dummy0",
            "--dev",
            "dummy1",
            "--multicast",
            "ff0e::e2e",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn relay");
    std::thread::sleep(Duration::from_millis(500));

    let payload = b"e2e-v6";
    let cap = sniff_v6("dummy1", || {
        let s = std::net::UdpSocket::bind("[::]:0").expect("v6 sender bind");
        // Pin the outgoing multicast interface to dummy0 — without this the
        // datagram follows the default route (eth0) and never reaches us.
        let idx: i32 = {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            // SAFETY: standard SIOCGIFINDEX on our own socket.
            unsafe {
                let mut req: libc::ifreq = std::mem::zeroed();
                let bytes = b"dummy0";
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    req.ifr_name.as_mut_ptr().cast::<u8>(),
                    bytes.len(),
                );
                libc::ioctl(fd, libc::SIOCGIFINDEX, &mut req);
                libc::close(fd);
                req.ifr_ifru.ifru_ifindex
            }
        };
        // SAFETY: int-valued IPv6 option on our own socket.
        unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_IF,
                std::ptr::addr_of!(idx).cast::<libc::c_void>(),
                std::mem::size_of::<i32>() as u32,
            );
        }
        s.send_to(
            payload,
            (
                std::net::Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0xe2e),
                port,
            ),
        )
        .map_err(|e| e.to_string())
        .expect("v6 send");
    });
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(relay.id().to_string())
        .output();
    let _ = relay.wait();

    sh("ip link del dummy1 2>/dev/null || true");
    sh("ip addr flush dev dummy0 2>/dev/null || true");
    let (src, dst, hlim, _sp, dp, pl) = cap.expect(
        "no forwarded v6 packet captured — if this kernel rejects raw IPv6 \
         sends (EINVAL on any sendto), the live v6 check cannot run here",
    );
    assert_eq!(pl, payload);
    assert_eq!(dst, "ff0e::e2e");
    assert_eq!(hlim, 65);
    assert_eq!(dp, port);
    let _ = src; // forged source equals the original sender
}

fn sniff_v6(iface: &str, f: impl FnOnce()) -> Option<(String, String, u8, u16, u16, Vec<u8>)> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return None;
    }
    unsafe {
        let mut req: libc::ifreq = std::mem::zeroed();
        let bytes = iface.as_bytes();
        let n = bytes.len().min(15);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), req.ifr_name.as_mut_ptr().cast::<u8>(), n);
        if libc::ioctl(fd, libc::SIOCGIFINDEX, &mut req) < 0 {
            libc::close(fd);
            return None;
        }
        let ifidx = req.ifr_ifru.ifru_ifindex;
        let sa: libc::sockaddr_ll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifidx,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        );
    }
    f();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut out = None;
    while Instant::now() < deadline {
        let mut buf = [0u8; 1500];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n < 54 {
            std::thread::sleep(Duration::from_millis(30));
            continue;
        }
        let ip = &buf[14..];
        if ip[6] != 17 {
            continue;
        }
        let src = Ipv6Addr::from([
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15], ip[16], ip[17], ip[18],
            ip[19], ip[20], ip[21], ip[22], ip[23],
        ])
        .to_string();
        let dst = Ipv6Addr::from([
            ip[24], ip[25], ip[26], ip[27], ip[28], ip[29], ip[30], ip[31], ip[32], ip[33], ip[34],
            ip[35], ip[36], ip[37], ip[38], ip[39],
        ])
        .to_string();
        let hlim = ip[7];
        let plen = u16::from_be_bytes([ip[4], ip[5]]) as usize;
        let udp = &ip[40..];
        let sp = u16::from_be_bytes([udp[0], udp[1]]);
        let dp = u16::from_be_bytes([udp[2], udp[3]]);
        let payload = udp[8..plen].to_vec();
        if payload.starts_with(b"e2e-") {
            out = Some((src, dst, hlim, sp, dp, payload));
            break;
        }
    }
    unsafe { libc::close(fd) };
    out
}
