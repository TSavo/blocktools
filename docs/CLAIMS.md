# Claims

Generated from docs/claims.toml by `python3 scripts/claims-check.py --render`; do not edit by hand.
docs-check fails on any quantitative doc claim not registered there, on a stale or failing measurement,
and on a macOS claim marked measured without a successful macOS CI job.

## Measured

| id | kind | platform | status | statement | command | commit | date |
|---|---|---|---|---|---|---|---|
| fee-cap-evm-default | security | linux | measured | With no --max-fee, every signing route caps EVM total fee at 0.01 ETH-equivalent | `cargo test -q --release -p blocktools --test fee_cap_paths` | 50f4f03 | 2026-10-26 |
| fee-cap-utxo-default | security | linux | measured | With no --max-fee, every signing route caps UTXO fee at max(100,000 base units, chain rate limit x vsize); 35 of 35 corpus sweeps pass (flat cap refused 9 of 35); cap+1 refused on each of 27 buildable chains; 240,000 sat on a 1-input BTC tx refused; fee over 10% of inputs refused without explicit --max-fee, 0 of 35 corpus sweeps trip it | `cargo test -q --release -p blocktools-tx --test fee_cap_chains` | c419553 | 2026-10-26 |
| scrypt-bounds | security | linux | measured | Keystore scrypt is bounded by 128*N*r <= 256 MiB and N*r*p <= 2^24; a hostile 8 GiB request is refused | `cargo test -q --release -p blocktools-secrets --all-features -- scrypt_bounds hostile_kdf` | fbcf2b3 | 2026-10-25 |
| prepush-2mb | security | linux | measured | prepush-check refuses any tracked file over 2 MB | `sh scripts/gate-negatives.sh P-large` | fbcf2b3 | 2026-10-25 |
| image-size-readme | number | linux | measured | Sealed runtime image (Dockerfile build, blocktools:local) is 38.8 MB = 38811136 bytes at the labelled commit, instrument: docker save uncompressed layer bytes (store-independent by construction; verified on overlay2 only). Environment: docker 26.1.5+dfsg1, storage driver overlay2 (extfs), Linux box. docker image inspect .Size on the same image: 38782360 bytes (store-dependent; the reviewer's containerd-store daemon reported 56.2 MB, reviewer report, not reproduced by us) | `BLOCKTOOLS_DOCKER='sudo docker' sh scripts/image-size.sh --build` | aea783f | 2026-10-26 |
| sealed-run-linux | security | linux | measured | ./blocktools run creates a container with network none, read-only rootfs, all capabilities dropped, read-only /in, and its agent output carries addresses and no secret material (Linux docker on the box) | `BLOCKTOOLS_DOCKER='sudo docker' sh scripts/sealed-check.sh` | aea783f | 2026-10-26 |
| exports-reference-executed | security | linux | measured | docs/EXPORTS-reference.md is generated from executed wasm calls; its input limits (blake2b personalization <= 16 bytes, memo 1..80 bytes, AccountInfo 80 bytes, PDA seeds <= 32 bytes) are boundary-tested in test.mjs, and its example outputs (1.0 ETH value, 9.99 ETH fee at 475714.285714286 gwei) are the recorded outputs | `sh scripts/wasm-check.sh` | a15504d | 2026-10-25 |
| rpc-response-size-cap | security | linux | measured | rpc reads at most 8 MiB of any response and refuses a 3xx instead of following it (in-process mock, Linux box) | `cargo test -q -p rpc --test cli redirect_not_followed_and_size_capped` | e85721e | 2026-10-26 |
| rpc-wallet-sign-summary | number | linux | measured | The --allow-wallet-sign summary in docs/RPC.md (ERC-20 transfer, selector 0xa9059cbb, 68 bytes) is the code's own output for that request | `cargo test -q -p rpc --lib summary_capture` | fe3cf73 | 2026-10-25 |
| rpc-deny-list | security | linux | measured | Secret export/import/unlock and wallet-signing methods exit 3 with a stable code and no request reaches the server; auth never appears in output (in-process mock, Linux box) | `cargo test -q -p rpc` | e85721e | 2026-10-26 |
| rpc-publicnode-read-linux | platform | linux | measured | Read-only eth_blockNumber and `rpc eth height` against https://ethereum-rpc.publicnode.com returned a block number (Linux 6.12.94+ x86_64 box, 2026-10-25 20:39 and 20:56 PDT; re-run 2026-10-26 00:18 PDT at e85721e); no broadcast was made | `echo '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \| ./target/release/rpc https://ethereum-rpc.publicnode.com` | e85721e | 2026-10-26 |
| forkid-signing | security | linux | measured | Fork-id sighash matches all 495 SIGHASH_FORKID rows of Bitcoin ABC sighash.json; BCH and BSV mainnet and Trust Wallet Core BTG signatures verify under it and not under the BTC sighash | `cargo test -q --release -p blocktools-tx --test forkid` | a4c5680 | 2026-10-26 |
| twc-evm-vectors | security | linux | measured | All 13 Trust Wallet Core EVM signer vectors (7 legacy EIP-155, 6 EIP-1559) parse, recover to their key and re-sign byte for byte | `cargo test -q --release -p blocktools-tx --features secrets --test twc_evm` | 728619c | 2026-10-26 |
| twc-message-vectors | security | linux | measured | Trust Wallet Core message-signer vectors: 4 Ethereum personal_sign and 3 Bitcoin signmessage signatures reproduced byte for byte, 6 Bitcoin verify vectors recovered, TWC negatives refused | `cargo test -q --release -p blocktools-tx --features secrets --test twc_message` | 28fa876 | 2026-10-26 |
| twc-cosmos-vectors | security | linux | measured | Trust Wallet Core Cosmos SDK MsgSend vectors (Cosmos Hub, Osmosis, Juno, Stargaze, Secret, Terra 2) decoded, verified and re-signed byte for byte; TWC IBC, MsgVote and CosmWasm vectors refused | `cargo test -q --release -p blocktools-acct --test twc_cosmos` | 3ed2edf | 2026-10-26 |

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
