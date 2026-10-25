# Build: static musl binaries. Base images pinned by digest.
FROM rust:1.85-alpine3.20@sha256:4ec3fedc5eff0bc1ca3ce0e2abbd7190585627eb2b3eedc25e0bf0712b209cd7 AS build
RUN apk add --no-cache musl-dev file
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY tools tools
COPY deps deps
COPY scripts/check-deps.sh scripts/check-deps.sh
RUN sh scripts/check-deps.sh && cargo test --release --locked && cargo build --release --locked
# Collect every binary and refuse to continue unless each one is statically linked.
RUN mkdir /out && for t in tools/*/; do n=$(basename "$t"); b=target/release/$n; \
      case "$n" in utxo-fetch|tx-broadcast) continue;; esac; \
      [ -x "$b" ] && cp "$b" /out/; done && \
    for b in /out/*; do file "$b"; file "$b" | grep -q "static" || { echo "NOT STATIC: $b"; exit 1; }; done

# Runtime: nothing but the static tools. No shell, no busybox, no wget, no libc.
# kr-run executes pipelines itself (no shell), so nothing else is needed.
FROM scratch
COPY --from=build /out/ /kr/
USER 10001:10001
WORKDIR /run/kr
ENTRYPOINT ["/kr/kr-run"]
