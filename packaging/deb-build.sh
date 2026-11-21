#!/bin/sh
# Build a Debian .deb from a prebuilt release binary.
# Usage: deb-build.sh <binary-path> <version> [arch]
# arch defaults to `dpkg --print-architecture`.
set -e

BIN="${1:?usage: deb-build.sh <binary> <version> [arch]}"
VER="${2:?usage: deb-build.sh <binary> <version> [arch]}"
ARCH="${3:-$(dpkg --print-architecture)}"
NAME="udp-broadcast-relay-redux"

PKGROOT="$(mktemp -d)/${NAME}_${VER}_${ARCH}"
mkdir -p "$PKGROOT/DEBIAN" \
         "$PKGROOT/usr/bin" \
         "$PKGROOT/usr/share/man/man1" \
         "$PKGROOT/usr/share/bash-completion/completions" \
         "$PKGROOT/usr/share/zsh/functions/Completion/Unix" \
         "$PKGROOT/usr/share/fish/vendor_completions.d" \
         "$PKGROOT/usr/share/doc/${NAME}"

install -m 755 "$BIN" "$PKGROOT/usr/bin/${NAME}"
install -m 644 "$(dirname "$0")/../docs/udp-broadcast-relay-redux.1" \
    "$PKGROOT/usr/share/man/man1/${NAME}.1"
install -m 644 "$(dirname "$0")/../completions/${NAME}.bash" \
    "$PKGROOT/usr/share/bash-completion/completions/${NAME}"
install -m 644 "$(dirname "$0")/../completions/_udp-broadcast-relay-redux.zsh" \
    "$PKGROOT/usr/share/zsh/functions/Completion/Unix/_udp-broadcast-relay-redux"
install -m 644 "$(dirname "$0")/../completions/${NAME}.fish" \
    "$PKGROOT/usr/share/fish/vendor_completions.d/${NAME}.fish"

cat > "$PKGROOT/DEBIAN/control" <<EOF
Package: ${NAME}
Version: ${VER}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: zhuzhuzihan <zhuzhuzihan@users.noreply.github.com>
Depends: libc6 (>= 2.17)
Description: Relay UDP broadcasts to other networks, forging the sender address
 Rust port of udp-broadcast-relay-redux: listens for UDP broadcast packets
 (and optionally IPv6 multicast with --ipv6) on one interface and forwards
 them to the others, making packets appear to come from the original sender.
 Requires root (raw sockets). Includes man page and shell completions.
EOF

install -m 644 "$(dirname "$0")/../LICENSE" "$PKGROOT/usr/share/doc/${NAME}/copyright"

dpkg-deb --root-owner-group --build "$PKGROOT" "$(pwd)/${NAME}_${VER}_${ARCH}.deb"
