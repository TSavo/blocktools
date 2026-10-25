# Build: static musl binaries. Base images pinned by digest.
FROM rust:1.85-alpine3.20@sha256:4ec3fedc5eff0bc1ca3ce0e2abbd7190585627eb2b3eedc25e0bf0712b209cd7 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY tools tools
RUN cargo test --release --locked && cargo build --release --locked

# Runtime: a small Unix (busybox sh, coreutils) + the keyrescue toolset. No network tools.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN rm -f /usr/bin/wget /usr/bin/nc /bin/ping /usr/bin/ssl_client && \
    adduser -D -H -u 10001 kr
COPY --from=build /src/target/release/seed-repair /src/target/release/derive \
     /src/target/release/keystore-open /src/target/release/kr-redact /usr/local/bin/
COPY container/kr-run /usr/local/bin/kr-run
USER 10001:10001
WORKDIR /run/kr
ENTRYPOINT ["/usr/local/bin/kr-run"]
