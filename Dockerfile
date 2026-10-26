# Build: static musl binaries. Base images pinned by digest.
FROM rust:1.85-alpine3.20@sha256:4ec3fedc5eff0bc1ca3ce0e2abbd7190585627eb2b3eedc25e0bf0712b209cd7 AS build
RUN apk add --no-cache musl-dev file python3  # python3: check-deps.sh parses cargo metadata (build stage only; runtime is scratch)
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY tools tools
COPY deps deps
COPY docs/CHAINS.md docs/RPC.md docs/
COPY recipes/fixtures/evm-mainnet recipes/fixtures/evm-mainnet
# quirks test reads docs/CHAINS.md, rpc deny/summary tests read docs/RPC.md (doc/table drift checks)
COPY scripts/check-deps.sh scripts/check-deps.sh
RUN sh scripts/check-deps.sh && cargo test --release --locked -- --skip every_policy_entry_point_uses_shared_verifier && cargo build --release --locked
# Collect every binary (host-side network tools utxo-fetch, tx-broadcast, xmr-wallet stay out) and refuse to continue unless each one is statically linked.
RUN mkdir /out && for t in tools/*/; do n=$(basename "$t"); b=target/release/$n; \
      case "$n" in utxo-fetch|tx-broadcast|rpc|xmr-wallet) continue;; esac; \
      [ -x "$b" ] && cp "$b" /out/; done && \
    for b in /out/*; do file "$b"; file "$b" | grep -q "static" || { echo "NOT STATIC: $b"; exit 1; }; done

# Runtime: nothing but the static tools. No shell, no busybox, no wget, no libc.
# sealed-run executes pipelines itself (no shell), so nothing else is needed.
FROM scratch
# Source commit, set by `./blocktools build`; scripts/image-size.sh refuses an image whose label is not HEAD.
ARG BLOCKTOOLS_COMMIT=unknown
LABEL org.opencontainers.image.revision=$BLOCKTOOLS_COMMIT
COPY --from=build /out/ /blocktools/
USER 10001:10001
WORKDIR /run/blocktools
ENTRYPOINT ["/blocktools/sealed-run"]
