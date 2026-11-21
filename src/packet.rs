//! The forged packet buffer ("gram") — IP + UDP header template and the
//! per-interface rewrite, byte-for-byte from the C original.

/// 4096, as in the original (`u_char gram[4096]`).
pub const GRAM_SIZE: usize = 4096;
pub const IPHEADER_LEN: usize = 20;
pub const UDPHEADER_LEN: usize = 8;
pub const HEADER_LEN: usize = IPHEADER_LEN + UDPHEADER_LEN;
/// C: `#define TTL_ID_OFFSET 64` — the instance id is encoded as IP TTL 64+id.
pub const TTL_ID_OFFSET: u8 = 64;
/// C: `iov.iov_len = 4006 - HEADER_LEN - 1`.
pub const MAX_PAYLOAD: usize = 4006 - HEADER_LEN - 1;

/// Initial gram content: IP header template (v4, DSCP 0, total length 0x26,
/// id 0x1234, no fragmentation, TTL 255, proto 17=UDP, zero checksum and
/// addresses), an 8-byte UDP header placeholder, and the "1234567890"
/// test payload that gets overwritten by received datagrams.
pub fn new_gram() -> [u8; GRAM_SIZE] {
    let mut gram = [0u8; GRAM_SIZE];
    let template: [u8; HEADER_LEN + 10] = [
        0x45, 0x00, 0x00, 0x26, 0x12, 0x34, 0x00, 0x00, 0xFF, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0x00, 0x12, 0x00, 0x00, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
        b'0',
    ];
    gram[..template.len()].copy_from_slice(&template);
    gram
}

/// Stamp the header fields for one forwarded copy. Addresses and ports are in
/// the numeric (host-assembled) form; bytes are written in network order.
/// `payload_len` is the received datagram length (`len` in the original).
#[allow(clippy::too_many_arguments)]
pub fn forge(
    gram: &mut [u8; GRAM_SIZE],
    ttl: u8,
    from_addr: u32,
    to_addr: u32,
    from_port: u16,
    to_port: u16,
    payload_len: usize,
) {
    gram[8] = ttl;
    gram[12..16].copy_from_slice(&from_addr.to_be_bytes());
    gram[16..20].copy_from_slice(&to_addr.to_be_bytes());
    gram[20..22].copy_from_slice(&from_port.to_be_bytes());
    gram[22..24].copy_from_slice(&to_port.to_be_bytes());
    gram[24..26].copy_from_slice(&((UDPHEADER_LEN as u16) + payload_len as u16).to_be_bytes());
    // IP total length. The original skips htons on FreeBSD ≤ 10 / Apple (the
    // value is stored in host byte order there); modern FreeBSD uses network
    // order like Linux, which is what we implement for non-macOS BSDs.
    let total = (HEADER_LEN + payload_len) as u16;
    #[cfg(target_os = "macos")]
    {
        gram[2..4].copy_from_slice(&total.to_ne_bytes());
    }
    #[cfg(not(target_os = "macos"))]
    {
        gram[2..4].copy_from_slice(&total.to_be_bytes());
    }
}

/// IPv6 payload limit: the gram holds the 40-byte IPv6 header.
pub const V6HEADER_LEN: usize = 40;

/// 16-bit ones' complement checksum with the IPv6 pseudo-header (mandatory
/// for raw IPv6 — the kernel does not fill UDP checksums for us).
pub fn udp_checksum(src: &[u8; 16], dst: &[u8; 16], udp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in src.chunks_exact(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    for pair in dst.chunks_exact(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    let len = udp.len() as u32;
    sum += len >> 16;
    sum += len & 0xFFFF;
    sum += 17; // next header = UDP
    let mut i = 0usize;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += u16::from_be_bytes([udp[i], 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a full IPv6 packet into the gram: fixed header + UDP with computed
/// checksum. This is what Linux raw IPv6 sockets with IPPROTO_RAW expect in
/// hdrincl mode (the default for IPPROTO_RAW): the kernel validates and
/// routes the header itself, no ancillary data needed.
pub fn forge6(
    gram: &mut [u8; GRAM_SIZE],
    hop_limit: u8,
    from: [u8; 16],
    to: [u8; 16],
    from_port: u16,
    to_port: u16,
    payload_len: usize,
) {
    gram[0] = 0x60; // version 6, traffic class 0, flow label 0
    gram[1..4].fill(0);
    gram[4..6].copy_from_slice(&((UDPHEADER_LEN as u16) + payload_len as u16).to_be_bytes());
    gram[6] = 17; // next header: UDP
    gram[7] = hop_limit;
    gram[8..24].copy_from_slice(&from);
    gram[24..40].copy_from_slice(&to);
    let seg_end = V6HEADER_LEN + UDPHEADER_LEN + payload_len;
    gram[40..42].copy_from_slice(&from_port.to_be_bytes());
    gram[42..44].copy_from_slice(&to_port.to_be_bytes());
    gram[44..46].copy_from_slice(&((UDPHEADER_LEN as u16) + payload_len as u16).to_be_bytes());
    gram[46..48].fill(0); // checksum field before computation
    let seg = gram[40..seg_end].to_vec();
    gram[46..48].copy_from_slice(&udp_checksum(&from, &to, &seg).to_be_bytes());
}

/// Build the UDP segment (header with checksum + payload) for a raw IPv6
/// send. Linux IPv6 raw sockets do NOT accept a full IPv6 header — the kernel
/// constructs it from the destination sockaddr plus IPV6_PKTINFO/IPV6_HOPLIMIT
/// ancillary data (see sys::sendmsg6), so only this segment goes on the wire.
pub fn udp_segment6(
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(UDPHEADER_LEN + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&((UDPHEADER_LEN as u16) + payload.len() as u16).to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(payload);
    let c = udp_checksum(&src, &dst, &seg);
    seg[6..8].copy_from_slice(&c.to_be_bytes());
    seg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_checksum_self_consistent() {
        // The canonical property: a segment carrying its own checksum
        // checksums to zero.
        let src = [0x20u8; 16];
        let dst = [0x01u8; 16];
        let mut seg = vec![0u8; 8 + 6];
        seg[0..2].copy_from_slice(&1234u16.to_be_bytes());
        seg[2..4].copy_from_slice(&5678u16.to_be_bytes());
        seg[4..6].copy_from_slice(&((8u16) + 6).to_be_bytes());
        seg[8..].copy_from_slice(b"payloa");
        let c = udp_checksum(&src, &dst, &seg);
        seg[6..8].copy_from_slice(&c.to_be_bytes());
        // recompute over the segment with checksum zeroed
        seg[6..8].fill(0);
        assert_eq!(udp_checksum(&src, &dst, &seg), c);
    }

    #[test]
    fn udp_segment6_layout() {
        let src = std::net::Ipv6Addr::LOCALHOST.octets();
        let dst = std::net::Ipv6Addr::LOCALHOST.octets();
        let seg = udp_segment6(src, dst, 1000, 2000, b"hello");
        assert_eq!(seg.len(), 8 + 5);
        assert_eq!(u16::from_be_bytes([seg[0], seg[1]]), 1000);
        assert_eq!(u16::from_be_bytes([seg[2], seg[3]]), 2000);
        assert_eq!(u16::from_be_bytes([seg[4], seg[5]]), 13);
        assert_ne!(&seg[6..8], &[0, 0]); // checksum present
        assert_eq!(&seg[8..], b"hello");
        // checksum property: zeroing the field and recomputing reproduces it
        let mut seg2 = seg.clone();
        seg2[6..8].fill(0);
        assert_eq!(
            udp_checksum(&src, &dst, &seg2),
            u16::from_be_bytes([seg[6], seg[7]])
        );
    }
}
