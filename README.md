# udp-broadcast-relay-redux-rust

A Rust port of [udp-broadcast-relay-redux](https://github.com/udp-redux/udp-broadcast-relay-redux)
— relays UDP broadcasts to other networks, forging the sender address.

Same behavior, same command line, same wire format as the C original — proven by
a 207-case recorded behavior suite and live two-interface packet-capture parity
tests. On top of that it adds internationalization (English and Chinese).

> 本项目的中文说明见 [README.zh-CN.md](README.zh-CN.md)。

## Why

The original is a small C daemon used on OpenWrt/pfSense/DD-WRT style routers to
make UDP broadcast protocols (e.g. Chromecast/HDHomeRun discovery) work across
subnets. This repository re-implements it in safe-by-default Rust with `libc`
as the only runtime dependency, so it keeps the zero-fuss deployment of the
original while gaining memory safety, modern CI, and i18n.

## Usage

```
usage: udp-broadcast-relay-redux [-d] [-f] [-s IP] [-t IP] [--id id] [--port udp-port] [--dev dev1]... [--multicast ip]...
```

The program listens for broadcast packets on the specified UDP port and
forwards them to each other given interface. Packets are sent such that they
appear to have come from the original broadcaster, resp. from the spoofing IP
in case `-s` is used. When using multiple instances for the same port on the
same network, they must have a different id.

| Flag | Meaning |
|------|---------|
| `-d` | enables debugging |
| `-f` | forces forking to background |
| `-s IP` | sets the source IP of forwarded packets; otherwise the original sender's address is used. Setting to `1.1.1.1` uses outgoing interface address and broadcast port. Setting to `1.1.1.2` uses outgoing interface address and source port. |
| `-t IP` | sets the destination IP of forwarded packets; otherwise the original target is used. Setting to `255.255.255.255` uses the broadcast address of the outgoing interface. |
| `--id id` | instance id 1–99 (encoded as IP TTL `64+id` to detect relay echoes) |
| `--port udp-port` | UDP port to listen on |
| `--dev dev1` | interface to manage (repeatable) |
| `--multicast ip` | multicast group to join on every managed interface (repeatable) |
| `--lang en\|zh` | user-facing message language (new; see [i18n](#internationalization)) |

Requires root (raw sockets). HDHomeRun example:

```
udp-broadcast-relay-redux --id 1 --port 65001 --dev eth0 --dev wlan0 --multicast 239.255.255.250
```

## Internationalization

User-facing messages (usage, errors, debug logs) are available in English and
Chinese. The language is resolved in this order:

1. `--lang en` / `--lang zh` flag (highest priority),
2. `LC_ALL`, then `LC_MESSAGES`, then `LANG` environment variables
   (a locale starting with `zh` selects Chinese),
3. English as the default.

English output is byte-identical to the C original. See
[docs/i18n.md](docs/i18n.md) to add a language.

## Install

Prebuilt binaries (linux x86_64/aarch64 gnu+musl, macOS aarch64) are attached
to every GitHub release, or build from source:

```
cargo build --release
```

Docker:

```
docker build -t udp-broadcast-relay-redux .
docker run --rm --net=host udp-broadcast-relay-redux --id 1 --port 65001 --dev eth0 --dev wlan0
```

## Behavior guarantees

The port was driven by [rust-anything](https://github.com/erkamyaman/rust-anything):

- **207 recorded CLI cases** (usage, flag validation, argument traps,
  ioctl error paths) captured from the C original — the Rust binary replays
  them 207/207, byte-identical stdout/stderr and exit codes. The suite runs
  in CI (`tests/behavior_cases.rs`).
- **Live relay parity**: on a two-interface lab (`dummy0` + `dummy1`), the
  forged packets produced by the Rust port and the C original were captured
  with AF_PACKET and compared field by field (source/destination/ports/TTL/
  payload) across broadcast, unicast, multicast, spoof and target-rewrite
  scenarios — identical output.
- Faithfully preserved quirks include: `Debugging Mode enabled` never prints
  (the original's DPRINT evaluates `debug` before setting it), glibc
  `atoi`/`inet_addr` semantics incl. octal/hex/overflow handling, u8/u16
  argument truncation, the last-matching-interface lookup, echo detection by
  TTL, and perror labels.

Details, decisions and measured probes: [docs/PORTING.md](docs/PORTING.md).

## Platform support

- **Linux** (primary; gnu + musl, x86_64 + aarch64 in CI)
- **macOS** (Apple branch: `if_nametoindex`, `IP_RECVIF`-family socket options;
  compile-checked in CI, not runtime-tested)
- FreeBSD: the original has a FreeBSD branch; this port compiles the Apple
  path for it (missing ioctl constants are defined with the documented
  `_IOWR` encoding) but it is not CI-tested — see docs/PORTING.md.

## License

GPL-2.0-or-later, same as the original. Copyright (c) 2017 UDP Broadcast Relay
Redux Contributors; (c) 2003 Joachim Breitner; (C) 2002 Nathan O'Sullivan — see
[LICENSE](LICENSE).
