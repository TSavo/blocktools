# Claims

Generated from docs/claims.toml by `python3 scripts/claims-check.py --render`; do not edit by hand.
docs-check fails on any quantitative doc claim not registered there, on a stale or failing measurement,
and on a macOS claim marked measured without a successful macOS CI job.

## Measured

| id | kind | platform | status | statement | command | commit | date |
|---|---|---|---|---|---|---|---|
| fee-cap-evm-default | security | linux | measured | With no --max-fee, every signing route caps EVM total fee at 0.01 ETH-equivalent | `cargo test -q --release -p blocktools --test fee_cap_paths` | fbcf2b3 | 2026-10-25 |
| fee-cap-utxo-default | security | linux | measured | With no --max-fee, every signing route caps UTXO fee at 100,000 base units | `cargo test -q --release -p blocktools --test fee_cap_paths` | fbcf2b3 | 2026-10-25 |
| scrypt-bounds | security | linux | measured | Keystore scrypt is bounded by 128*N*r <= 256 MiB and N*r*p <= 2^24; a hostile 8 GiB request is refused | `cargo test -q --release -p blocktools-secrets --all-features -- scrypt_bounds hostile_kdf` | fbcf2b3 | 2026-10-25 |
| prepush-2mb | security | linux | measured | prepush-check refuses any tracked file over 2 MB | `sh scripts/gate-negatives.sh P-large` | fbcf2b3 | 2026-10-25 |

## Untested

| id | kind | platform | status | statement | command | commit | date |
|---|---|---|---|---|---|---|---|
| image-size-readme | number | docker | untested | Sealed runtime image size. Never measured: the 33.3 MB once quoted came from image-size.sh's binary-sum fallback (non-root docker inspect failed), and blocktools:size-measure is a COPY-only image, not the sealed Dockerfile build. R2-1 builds and measures it. | `-` | - | - |
| image-sealed-battleaxe | platform | docker | untested | Image built and sealed run verified on Battleaxe (manual run, no recorded command) | `-` | - | - |
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
