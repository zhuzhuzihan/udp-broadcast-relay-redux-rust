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
