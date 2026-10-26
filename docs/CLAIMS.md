# Claims

Generated from docs/claims.toml by `python3 scripts/claims-check.py --render`; do not edit by hand.
docs-check fails on any quantitative doc claim not registered there, on a stale or failing measurement,
and on a macOS claim marked measured without a successful macOS CI job.

## Measured

| id | kind | platform | status | statement | command | commit | date |
|---|---|---|---|---|---|---|---|
| fee-cap-evm-default | security | linux | measured | With no --max-fee, every signing route caps EVM total fee at 0.01 ETH-equivalent | `cargo test -q --release -p blocktools --test fee_cap_paths` | 3ec1d1a | 2026-10-25 |
| fee-cap-utxo-default | security | linux | measured | With no --max-fee, every signing route caps UTXO fee at max(100,000 base units, chain rate limit x vsize); 35 of 35 corpus sweeps pass (flat cap refused 9 of 35); cap+1 refused on each of 27 buildable chains; 240,000 sat on a 1-input BTC tx refused | `cargo test -q --release -p blocktools-tx --test fee_cap_chains` | 35557f7 | 2026-10-25 |
| scrypt-bounds | security | linux | measured | Keystore scrypt is bounded by 128*N*r <= 256 MiB and N*r*p <= 2^24; a hostile 8 GiB request is refused | `cargo test -q --release -p blocktools-secrets --all-features -- scrypt_bounds hostile_kdf` | fbcf2b3 | 2026-10-25 |
| prepush-2mb | security | linux | measured | prepush-check refuses any tracked file over 2 MB | `sh scripts/gate-negatives.sh P-large` | fbcf2b3 | 2026-10-25 |
| image-size-readme | number | linux | measured | Sealed runtime image (Dockerfile build, blocktools:local) is 33.3 MB = 33255936 bytes, instrument: docker save uncompressed layer bytes (store-independent by construction; verified on overlay2 only). Environment: docker 26.1.5+dfsg1, storage driver overlay2 (extfs), Linux box. docker image inspect .Size on the same image: 33232256 bytes (store-dependent; the reviewer's containerd-store daemon reported 56.2 MB, reviewer report, not reproduced by us) | `BLOCKTOOLS_DOCKER='sudo docker' sh scripts/image-size.sh` | 1e39a7f | 2026-10-25 |
| sealed-run-linux | security | linux | measured | ./blocktools run creates a container with network none, read-only rootfs, all capabilities dropped, read-only /in, and its agent output carries addresses and no secret material (Linux docker on the box) | `BLOCKTOOLS_DOCKER='sudo docker' sh scripts/sealed-check.sh` | 61ff186 | 2026-10-25 |
| exports-reference-executed | security | linux | measured | docs/EXPORTS-reference.md is generated from executed wasm calls; its input limits (blake2b personalization <= 16 bytes, memo 1..80 bytes, AccountInfo 80 bytes, PDA seeds <= 32 bytes) are boundary-tested in test.mjs, and its example outputs (1.0 ETH value, 9.99 ETH fee at 475714.285714286 gwei) are the recorded outputs | `sh scripts/wasm-check.sh` | a15504d | 2026-10-25 |

## Untested

| id | kind | platform | status | statement | command | commit | date |
|---|---|---|---|---|---|---|---|
| image-sealed-battleaxe | platform | docker | untested | Sealed run on Battleaxe at a15504d: build OK, 218 builder-stage tests pass, agent mode under --network none --read-only --cap-drop ALL prints seed and xprv as [REDACTED]; image inspect 56.2 MB (containerd image store). Reviewer report pasted by T, not reproduced by us | `-` | - | - |
| image-size-battleaxe-reviewer | number | docker | untested | docker image inspect 56.2 MB on Battleaxe (containerd image store) at a15504d; reviewer report, not reproduced by us | `-` | - | - |
| image-size-history | number | docker | untested | Historic image sizes in DESIGN (18.2, 40.4, 33.3 MB) | `-` | - | - |
| redact-512 | number | linux | untested | Redacted JSON lines are at most 512 bytes | `-` | - | - |
| read-file-64mib | number | linux | untested | read-file caps input at 64 MiB | `-` | - | - |
| net-8mib | number | linux | untested | Network body cap 8 MiB, 30 s timeout | `-` | - | - |
| tx-input-4mib | number | linux | untested | Transaction input limited to 4 MiB | `-` | - | - |
| wasm-size | number | linux | untested | wasm module size and crate count | `-` | - | - |
| armory-2mib | number | linux | untested | Armory reader limits | `-` | - | - |
| wheels-23mb | number | linux | untested | Historic Python wheels size | `-` | - | - |
| e2e-macos | platform | macos | untested | scripts/e2e-local.sh runs on Linux and macOS (macOS: last manual SwapChan run failed at tx-sign; no CI macOS job yet) | `-` | - | - |
| chains-fee-figures | number | linux | untested | Per-chain fee figures quoted in CHAINS/ROADMAP (from mainnet samples; no re-run command) | `-` | - | - |
| parity-1mb | number | linux | untested | ROADMAP-PARITY size figure | `-` | - | - |
| format-constants | number | any | unmeasurable | Protocol/format sizes (hash and key lengths, OP_RETURN limits, dust, checksum bytes) | `-` | - | - |
| prior-art | number | any | unmeasurable | Sizes quoted from third-party projects in a research note | `-` | - | - |
