FROM rust:1-alpine AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release && strip target/release/udp-broadcast-relay-redux

FROM alpine:3.19
COPY --from=builder /build/target/release/udp-broadcast-relay-redux /usr/local/bin/
# Raw sockets require CAP_NET_RAW — Docker's default capability set includes it.
ENTRYPOINT ["/usr/local/bin/udp-broadcast-relay-redux"]
