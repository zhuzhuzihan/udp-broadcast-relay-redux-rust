//! Faithful CLI parsing (glibc-exact `atoi`/`inet_addr` semantics) and the
//! address-rewrite constants used by the relay loop.

use crate::i18n::I18n;
use crate::out::{self, Out};

pub const INADDR_NONE: u32 = u32::MAX;
/// 255.255.255.255 in the numeric (host-assembled) form.
pub const INADDR_BROADCAST: u32 = u32::MAX;
/// Magic spoof value: outgoing interface address + broadcast port.
pub const SPOOF_IFACE_BCAST_PORT: u32 = 0x0101_0101; // 1.1.1.1
/// Magic spoof value: outgoing interface address + original source port.
pub const SPOOF_IFACE_SRC_PORT: u32 = 0x0101_0102; // 1.1.1.2

/// Strict decimal number: pure ASCII digits, no sign/whitespace/empty, value
/// within `min..=max`. Replaces the original's atoi-truncation quirks
/// (intentional deviation, ADR-010 / docs/PORTING.md).
fn parse_strict_num(s: &str, min: u64, max: u64) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v: u64 = 0;
    for b in s.bytes() {
        v = v.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        if v > max {
            return None;
        }
    }
    if v < min {
        return None;
    }
    Some(v)
}

/// C `atoi`: `int strtol(const char*, ...)` cast to int.
/// - skips isspace (" \t\n\v\f\r"), optional +/- sign, then base-10 digits;
/// - value saturates at LONG_MAX/LONG_MIN like strtol, then truncates to int.
#[cfg_attr(not(test), allow(dead_code))]
pub fn c_atoi(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let neg = if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        let n = b[i] == b'-';
        i += 1;
        n
    } else {
        false
    };
    // Magnitude accumulates up to LONG_MAX+1 so that "-9223372036854775808"
    // lands exactly on LONG_MIN (strtol saturation), which truncates to int 0
    // like glibc. Positive values saturate at LONG_MAX.
    let mut mag: i128 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        mag = mag * 10 + i64::from(b[i] - b'0') as i128;
        if mag > i64::MAX as i128 + 1 {
            mag = i64::MAX as i128 + 1;
        }
        i += 1;
    }
    let acc: i128 = if neg {
        -mag.min(i64::MAX as i128 + 1)
    } else {
        mag.min(i64::MAX as i128)
    };
    (acc as i64) as i32
}

fn hex_val(c: u8) -> u64 {
    match c {
        b'0'..=b'9' => u64::from(c - b'0'),
        b'a'..=b'f' => u64::from(c - b'a') + 10,
        _ => u64::from(c - b'A') + 10,
    }
}

/// Parse one dotted part of an address, glibc `inet_aton` style.
/// Returns (value, bytes consumed, whether the part ended at a '.').
/// - "0x"/"0X" prefix → hexadecimal (needs at least one digit);
/// - leading '0' with more characters → octal (a non-octal digit is trailing garbage);
/// - otherwise decimal;
/// - overflow within a part is invalid (no wrapping).
fn parse_part(b: &[u8]) -> Option<(u64, usize, bool)> {
    let mut i = 0usize;
    let base: u64;
    // The leading '0' of an octal part IS its digit ("0.0.0.0" is valid,
    // "08" is trailing garbage, "0x" without a hex digit is invalid — three
    // different rules, all glibc-verified).
    let mut saw_digit;
    if b.len() >= 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        base = 16;
        i = 2;
        saw_digit = false;
        if i >= b.len() || !b[i].is_ascii_hexdigit() {
            return None; // "0x" / "0xg"
        }
    } else if b[0] == b'0' && b.len() > 1 {
        base = 8;
        i = 1;
        saw_digit = true;
    } else {
        base = 10;
        saw_digit = false;
    }
    let mut val: u64 = 0;
    while i < b.len() {
        let c = b[i];
        let dig = match base {
            16 if c.is_ascii_hexdigit() => hex_val(c),
            8 if (b'0'..=b'7').contains(&c) => u64::from(c - b'0'),
            10 if c.is_ascii_digit() => u64::from(c - b'0'),
            _ => break,
        };
        val = val.checked_mul(base)?.checked_add(dig)?;
        saw_digit = true;
        i += 1;
    }
    if !saw_digit {
        return None; // empty part ("1..2", ".", ".2") — glibc rejects these
    }
    let saw_dot = i < b.len() && b[i] == b'.';
    Some((val, i, saw_dot))
}

/// glibc `inet_aton`: 1-4 dot-separated parts.
/// - non-final parts must be ≤ 0xFF;
/// - the last part is limited to the remaining width (1 part: 32 bits,
///   2 parts: 24 bits, 3 parts: 16 bits, 4 parts: 8 bits);
/// - trailing whitespace (isspace) is allowed, any other trailing garbage is not;
/// - no leading whitespace, no trailing dot, no empty parts;
///
/// Returns the numeric (host-assembled) value a<<24|b<<16|c<<8|d.
pub fn inet_aton(s: &str) -> Option<u32> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    let mut parts: Vec<u64> = Vec::with_capacity(4);
    let mut rest = b;
    loop {
        let (val, consumed, saw_dot) = parse_part(rest)?;
        parts.push(val);
        if saw_dot {
            if parts.len() == 4 {
                return None; // a 5th part
            }
            rest = &rest[consumed + 1..];
            if rest.is_empty() {
                return None; // trailing dot / empty part
            }
        } else {
            rest = &rest[consumed..];
            break;
        }
    }
    // Only trailing whitespace survives here.
    if !rest
        .iter()
        .all(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
    {
        return None;
    }
    let n = parts.len();
    let last_limit: u64 = match n {
        1 => 0xFFFF_FFFF,
        2 => 0x00FF_FFFF,
        3 => 0x0000_FFFF,
        _ => 0x0000_00FF,
    };
    if parts[n - 1] > last_limit {
        return None;
    }
    for p in &parts[..n - 1] {
        if *p > 0xFF {
            return None;
        }
    }
    let v = match n {
        1 => parts[0] as u32,
        2 => ((parts[0] as u32) << 24) | (parts[1] as u32),
        3 => ((parts[0] as u32) << 24) | ((parts[1] as u32) << 16) | (parts[2] as u32),
        _ => {
            ((parts[0] as u32) << 24)
                | ((parts[1] as u32) << 16)
                | ((parts[2] as u32) << 8)
                | (parts[3] as u32)
        }
    };
    Some(v)
}

/// glibc `inet_addr`: the parsed value, or INADDR_NONE on failure
/// (a parsed 255.255.255.255 is indistinguishable from failure, exactly
/// like the original — callers compare against INADDR_NONE).
pub fn inet_addr(s: &str) -> u32 {
    inet_aton(s).unwrap_or(INADDR_NONE)
}

#[derive(Debug, Default)]
pub struct Options {
    pub debug: bool,
    pub forking: bool,
    pub port: u16,
    pub id: u8,
    pub multicast: Vec<String>,
    pub interfaces: Vec<String>,
    /// Numeric source address; 0 = use the original sender.
    pub spoof: u32,
    /// Numeric target override; 0 = use the original target.
    pub target: u32,
}

/// Value of `argv[i]` where the original would read past argv.
/// glibc would crash there; we substitute the empty string (a deterministic,
/// documented deviation — see docs/PORTING.md).
fn value_at(args: &[String], i: usize) -> &str {
    args.get(i).map(String::as_str).unwrap_or("")
}

/// Parse command-line arguments exactly like the C original:
/// 1. first loop scans for `-d` anywhere (its DPRINT is dead code there —
///    `debug` is still 0 at that point, so "Debugging Mode enabled" never
///    prints; replicated by omission);
/// 2. second loop handles flags in order; DPRINTs fire only when `-d` was
///    present anywhere; flag values are consumed blindly;
/// 3. a first non-flag argument breaks the loop and the rest is ignored;
/// 4. then id (1-99 after u8 truncation) and port (nonzero after u16
///    truncation) are validated;
///
/// On error the message is written to stderr and `Err(exit_code)` returned.
pub fn parse(
    program: &str,
    args: &[String],
    out_stream: &mut Out,
    t: &I18n,
) -> Result<Options, i32> {
    if args.is_empty() {
        // C prints usage to stderr and exits 1. stderr is unbuffered; nothing
        // is pending on stdout at this point.
        out::eprint_raw(&t.usage(program));
        return Err(1);
    }

    let debug = args.iter().any(|a| a == "-d");

    let mut opts = Options {
        debug,
        ..Options::default()
    };
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-d" {
            // Already handled by the first loop.
        } else if a == "-f" {
            if debug {
                out_stream.print(&t.debug_forking());
            }
            opts.forking = true;
        } else if a == "-s" {
            i += 1;
            let v = value_at(args, i);
            opts.spoof = inet_addr(v);
            if opts.spoof == INADDR_NONE {
                out::eprint_raw(&t.invalid_source_ip(v));
                return Err(1);
            }
            if debug {
                out_stream.print(&t.debug_source_ip(v));
            }
        } else if a == "-t" {
            i += 1;
            let v = value_at(args, i);
            match inet_aton(v) {
                Some(val) => opts.target = val,
                None => {
                    out::eprint_raw(&t.invalid_target_ip(v));
                    return Err(1);
                }
            }
            if debug {
                out_stream.print(&t.debug_target_ip(v));
            }
        } else if a == "--id" {
            i += 1;
            let v = value_at(args, i);
            match parse_strict_num(v, 1, 99) {
                Some(id) => opts.id = id as u8,
                None => {
                    out::eprint_raw(&t.invalid_id(v));
                    return Err(1);
                }
            }
            if debug {
                out_stream.print(&t.debug_id_set(u32::from(opts.id)));
            }
        } else if a == "--port" {
            i += 1;
            let v = value_at(args, i);
            match parse_strict_num(v, 1, 65535) {
                Some(p) => opts.port = p as u16,
                None => {
                    out::eprint_raw(&t.invalid_port(v));
                    return Err(1);
                }
            }
            if debug {
                out_stream.print(&t.debug_port_set(u32::from(opts.port)));
            }
        } else if a == "--dev" {
            i += 1;
            opts.interfaces.push(value_at(args, i).to_string());
        } else if a == "--multicast" {
            i += 1;
            opts.multicast.push(value_at(args, i).to_string());
        } else if a.starts_with('-') {
            out::eprint_raw(&t.unknown_arg(a));
            return Err(1);
        } else {
            break;
        }
        i += 1;
    }

    if opts.id < 1 || opts.id > 99 {
        out::eprint_raw(&t.id_not_between(u32::from(opts.id)));
        return Err(1);
    }
    if opts.port == 0 {
        out::eprint_raw(&t.port_not_valid());
        return Err(1);
    }
    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_numbers() {
        assert_eq!(parse_strict_num("1", 1, 99), Some(1));
        assert_eq!(parse_strict_num("99", 1, 99), Some(99));
        assert_eq!(parse_strict_num("0", 1, 99), None);
        assert_eq!(parse_strict_num("100", 1, 99), None);
        assert_eq!(parse_strict_num("abc", 1, 99), None);
        assert_eq!(parse_strict_num("", 1, 99), None);
        assert_eq!(parse_strict_num(" 5", 1, 99), None);
        assert_eq!(parse_strict_num("-5", 1, 99), None);
        assert_eq!(parse_strict_num("+5", 1, 99), None);
        assert_eq!(parse_strict_num("99999", 1, 65535), None);
        assert_eq!(parse_strict_num("65535", 1, 65535), Some(65535));
        assert_eq!(parse_strict_num("0", 1, 65535), None);
        // glibc-truncation values must now be REJECTED (ADR-010)
        assert_eq!(parse_strict_num("300", 1, 99), None);
        assert_eq!(parse_strict_num("99999999999999999999999", 1, 65535), None);
    }

    // Historical: values measured against glibc before strict parsing
    // (see docs/PORTING.md probe table). The quirks are intentionally gone.
    #[cfg_attr(not(test), allow(dead_code))]
    #[test]
    fn atoi_matches_glibc() {
        assert_eq!(c_atoi("0"), 0);
        assert_eq!(c_atoi("42"), 42);
        assert_eq!(c_atoi("2147483647"), i32::MAX);
        assert_eq!(c_atoi("2147483648"), -2147483648); // (int) truncation
        assert_eq!(c_atoi("4294967295"), -1);
        assert_eq!(c_atoi("9223372036854775807"), -1);
        assert_eq!(c_atoi("9223372036854775808"), -1); // strtol saturation → LONG_MAX
        assert_eq!(c_atoi("99999999999999999999999"), -1);
        assert_eq!(c_atoi("-1"), -1);
        assert_eq!(c_atoi("-5"), -5);
        assert_eq!(c_atoi("-2147483648"), -2147483648);
        assert_eq!(c_atoi("-4294967296"), 0);
        assert_eq!(c_atoi("-9223372036854775808"), 0); // LONG_MIN → (int) 0
        assert_eq!(c_atoi("-9223372036854775809"), 0); // saturation → LONG_MIN
        assert_eq!(c_atoi(" 42"), 42);
        assert_eq!(c_atoi("\t42"), 42);
        assert_eq!(c_atoi("+42"), 42);
        assert_eq!(c_atoi("-0"), 0);
        assert_eq!(c_atoi("abc"), 0);
        assert_eq!(c_atoi(""), 0);
        assert_eq!(c_atoi("12abc"), 12);
        assert_eq!(c_atoi("0x10"), 0); // stops at 'x'
        assert_eq!(c_atoi("007"), 7);
        assert_eq!(c_atoi("  -00012"), -12);
        // id / port truncation chain used by the parser
        assert_eq!(c_atoi("99999999999999999999999") as u16, 65535);
        assert_eq!(c_atoi("99999") as u16, 34463); // u16 wrap trap
        assert_eq!(c_atoi("-5") as u8, 251);
        assert_eq!(c_atoi("300") as u8, 44);
    }

    #[test]
    fn inet_aton_matches_glibc() {
        let ok = |s: &str, want: u32| assert_eq!(inet_aton(s), Some(want), "{s}");
        let bad = |s: &str| assert_eq!(inet_aton(s), None, "{s}");
        ok("0", 0);
        ok("1", 1);
        ok("4294967295", 0xFFFF_FFFF);
        bad("4294967296");
        bad("0x100000000");
        ok("017777777777", 0x7FFF_FFFF); // octal
        ok("1.2.3.4", 0x0102_0304);
        ok("1.2.3", 0x0102_0003); // c = 16-bit
        ok("1.2", 0x0100_0002); // b = 24-bit
        bad("1.2.3.4.5");
        bad("300.1.1.1");
        bad("1.2.3.400");
        ok("0x7f.1", 0x7F00_0001);
        ok("0x7f000001", 0x7F00_0001);
        bad("1..2");
        bad(".");
        bad("");
        bad("a");
        bad("1.a");
        bad("1.2.3.x");
        ok("010.1", 0x0800_0001); // octal 010 = 8
        ok("00.1", 0x0000_0001);
        bad("0x");
        bad("0xg");
        bad("1.2.3.4.abc");
        ok("1.2.3.04", 0x0102_0304); // octal 04
        ok("1.2.3.0x1f", 0x0102_031f);
        bad("+1.2.3.4");
        bad("-1.2.3.4");
        ok("255.255.255.255", 0xFFFF_FFFF);
        bad("256.1.1.1");
        bad("99999999999999999999999");
        bad("1.");
        bad("1.2.3.");
        bad("localhost");
        ok("127.1", 0x7F00_0001);
        ok("0377.0.0.1", 0xFF00_0001);
        bad("08"); // octal + non-octal digit
        bad("09");
        bad("08.1");
        bad("1.2.3.08");
        ok("0X7f", 0x7F); // uppercase X
        ok("0.0.0.0", 0);
        bad("040000000000"); // octal overflow
        bad("77777777777"); // decimal overflow
        bad("018");
        bad("0o10");
        bad("1_2");
        bad(" 1.2.3.4"); // no leading space
                         // trailing whitespace allowed (isspace)
        assert_eq!(inet_aton("1.2.3.4 "), Some(0x0102_0304));
        assert_eq!(inet_aton("1.2.3.4\t"), Some(0x0102_0304));
        assert_eq!(inet_aton("1.2.3.4\n"), Some(0x0102_0304));
        assert_eq!(inet_aton("1.2.3.4\r"), Some(0x0102_0304));
    }

    #[test]
    fn inet_addr_none_semantics() {
        // 255.255.255.255 parses, but inet_addr cannot distinguish it from
        // failure — the caller sees INADDR_NONE either way (glibc parity).
        assert_eq!(inet_addr("255.255.255.255"), INADDR_NONE);
        assert_eq!(inet_addr("999.1.1.1"), INADDR_NONE);
        assert_eq!(inet_addr("1.1.1.2"), SPOOF_IFACE_SRC_PORT);
        assert_eq!(inet_addr("1.1.1.1"), SPOOF_IFACE_BCAST_PORT);
    }
}
