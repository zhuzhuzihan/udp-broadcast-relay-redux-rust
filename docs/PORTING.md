# PORTING.md — 从 udp-broadcast-relay-redux (C) 到 Rust 的移植记录

Tooling: [rust-anything](https://github.com/erkamyaman/rust-anything) v2.1.0
(`analyze --whole-app`, `app record`, `app replay`), plus hand-driven porting.
Original: github.com/udp-redux/udp-broadcast-relay-redux, single file `main.c`
(571 LOC), CLI daemon shape. New crate: one pure-Rust binary, only runtime
dependency `libc`.

## 1. Ground truth

`rust-anything app record` captured **207 deterministic CLI cases** from the
compiled original: usage, flag validation errors, 205 generated argument traps
(non-ASCII, huge numbers, negatives, empty strings, unicode), ioctl error
paths. 13 cases that legitimately hang (valid args → daemon runs forever) were
reported `timed_out` and excluded by design. Noise: none; original replay
passed 207/207.

## 2. Behavior decisions (ADR summary)

| # | Decision |
|---|----------|
| 1 | Pure Rust CLI binary named `udp-broadcast-relay-redux` (argv[0] parity); hand-rolled parser to keep exact quirks (repeatable `--dev`/`--multicast`, positional break, blind value consumption). |
| 2 | English mode byte-identical on stdout/stderr/exit code; Chinese is an opt-in superset (`--lang zh` / `zh` locale). |
| 3 | Dependencies: `libc` only; `unsafe` isolated in `src/sys.rs` with SAFETY comments. |
| 4 | Platforms: Linux primary (gnu+musl); Apple branch mirrored; FreeBSD compiles with manually encoded `_IOWR` ioctl constants, CI-tested: no. |
| 5 | i18n: embedded catalogs, `--lang` flag + locale env, no gettext. |
| 6 | CI: GitHub Actions (fmt/clippy/behavior suite + build matrix + releases). |
| 7 | stdio semantics replicated: stdout block-buffered (8 KiB, flush on exit), stderr raw `write(2)` ignoring EBADF (daemon closes fds; Rust `eprintln!` would panic where C's perror silently fails). |
| 8 | fork/daemon: `libc::fork`, parent exits 0 after flush; child closes fds 0/1/2 like the original's `fclose`s. |
| 9 | Proof shape: direct port (the tool refuses to shim `main.c`'s `inet_ntoa2` — it passes `struct in_addr` by value), proved by replay + unit tests + live e2e. |

## 3. Faithfully preserved quirks (verified against the original)

- `Debugging Mode enabled` never prints: the first arg loop's DPRINT expands
  to `if (debug) printf` while `debug` is still 0. Replicated by omission;
  confirmed by the recorded `dummy0-ioctl-error` stdout.
- Debug prints fire when `-d` appears **anywhere** in argv (a separate first
  scan sets `debug` before the main loop), and `Forking Mode enabled` /
  `Outgoing source IP set to …` print the post-truncation values.
- glibc `atoi` semantics: strtol saturation at LONG_MAX/LONG_MIN then `(int)`
  truncation — `--port 99999999999999999999999` → 65535 (valid),
  `--id -9223372036854775808` → 0 (error), `--id -5` → 251 (error).
- glibc `inet_addr`/`inet_aton` semantics, measured by a C probe and locked by
  unit tests: `1.2.3` → `1.2.0.3`, `1.2` → `1.0.0.2`, octal `010.1` →
  `8.0.0.1`, `0377.0.0.1` → `255.0.0.1`, `0x` alone invalid, `08` invalid
  (octal + garbage), trailing whitespace allowed, leading whitespace not,
  `300.1.1.1` invalid, `4294967295` = 255.255.255.255 which is
  indistinguishable from `INADDR_NONE` (so `-s 255.255.255.255` is an error).
- u8/u16 truncation before validation: `--id 300` → id 44 (valid),
  `--port 99999` → 34463, `--port 0` only invalid port.
- perror prefixes with embedded `\n` produce two-line errors.
- The last matching managed interface wins the `fromIface` lookup; echo
  detection compares the packet's IP TTL against `64+id`.
- FreeBSD≤10/Apple total-length quirk: header length field written in host
  byte order (modern FreeBSD/Linux use network order; macOS keeps the quirk).
- The `ioctl(SIOCGIFBRDADDR)` perror label is printed even when the
  `SIOCGIFDSTADDR` call fails (copy-paste bug in the original).

## 4. Documented deviations

- Missing flag value at end of argv (`-s`, `--id`, … with no next argument):
  the C original dereferences NULL and crashes; the port treats it as the
  empty string (deterministic error paths instead of UB).
- More than 256 `--dev`/`--multicast` arguments: the C original overflows its
  fixed arrays (UB); the port uses `Vec` (works).
- macOS `sockaddr_in.sin_len`: left uninitialized garbage by the original;
  set to `sizeof(sockaddr_in)` by the port.

## 5. Proof results

- `rust-anything app replay --build <rust binary>`: **207/207 passed**
  (the `usage: <argv0>` occurrence in the usage line is normalized to `[..]`
  by the recorder's own rule — the only path-dependent bytes).
- Unit tests (`cargo test`): glibc-probe-locked `atoi`/`inet_aton` tables.
- Live e2e (dummy0=10.55.0.1/24 + dummy1=10.66.0.1/24, AF_PACKET sniffing,
  3 repetitions per scenario, both binaries): broadcast relay, unicast keep,
  multicast relay, spoof `1.1.1.1`/`1.1.1.2`/literal, target rewrite
  `255.255.255.255`/literal, echo suppression (TTL 65) — the Rust port's
  forged packets matched the C original's field-for-field
  (src/dst/sport/dport/TTL/payload) every time.
- Environment note: the recorded suite expects `dummy0` to exist, be up, and
  have no IPv4 address; CI recreates it (`ip link add dummy0 type dummy`).
  Two cases need CAP_NET_RAW, so the suite runs as root in CI.

## 6. Cross-platform compile status (cargo check)

| Target | Result |
|--------|--------|
| aarch64-unknown-linux-gnu (host) | clean |
| aarch64-unknown-linux-musl | clean |
| aarch64-apple-darwin | clean |
| x86_64-unknown-freebsd | clean (runtime untested) |

FreeBSD notes: libc 0.2 exposes only `SIOCGIFADDR`; `SIOCGIFFLAGS`
(0xc020_6945), `SIOCGIFBRDADDR` (0xc020_6923), `SIOCGIFDSTADDR` (0xc020_6922)
are defined with the documented `_IOWR('i', n, struct ifreq)` encoding, and
`ifru_flags` is `[c_short; 2]` (index `[0]`).
