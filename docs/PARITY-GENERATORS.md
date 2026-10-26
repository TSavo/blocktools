# Parity generators (dev oracles, not tools)

`tools/build-parity`, `tools/psbt-parity`, `tools/sol-v1` and `tools/verifier-parity` are **not**
blocktools commands and have no manual page on purpose. Each is a single TypeScript/JavaScript
script that runs a reference implementation and writes a JSON corpus to stdout. The corpus is
committed under `crates/blocktools/tests/data/` and a Rust test checks blocktools against it, so
the Rust side never needs Node to test. Nothing here is built by `cargo` or shipped in a release.

| Generator | Reference | Corpus (entries, counted 2026-10-26) | Rust test | Regenerable from this repo? |
|-----------|-----------|--------------------------------------|-----------|-----------------------------|
| `tools/build-parity/gen.ts` | viem 2.57.11 | `build-corpus.json` (129 `evm`, 40 `select`) | `build_parity` | yes: byte-identical, measured |
| `tools/sol-v1/gen.mjs` | @solana/kit 8.5 | `sol-v1.json` (3) | `sol_v1` | yes: byte-identical, measured |
| `tools/psbt-parity/gen.mts` | SwapChan `btc.ts` + bitcoinjs-lib | `psbt-memo-corpus.json` (151) | `psbt_memo_parity` | no: needs SwapChan's `btc.ts`, not in this repo |
| `tools/verifier-parity/gen.ts` | SwapChan `verifier.ts` + viem | `verifier-corpus.json` (1293 cases) | `verifier_parity` | no: needs SwapChan's `verifier.ts`, not in this repo |

Regenerate (in a scratch directory, never inside the repo's `node_modules`):

```sh
# build-parity
mkdir /tmp/bp && cp tools/build-parity/gen.ts /tmp/bp && cd /tmp/bp && npm i viem@2.57.11
node --experimental-strip-types gen.ts | cmp - "$OLDPWD/crates/blocktools/tests/data/build-corpus.json"
# sol-v1
mkdir /tmp/sv && cp tools/sol-v1/gen.mjs /tmp/sv && cd /tmp/sv && npm i @solana/kit@8.5
node gen.mjs | cmp - "$OLDPWD/crates/blocktools/tests/data/sol-v1.json"
```

Measured 2026-10-26 on Linux (Node 22): both `cmp` runs silent (identical), and
`cargo test --release -p blocktools --all-features --test build_parity|sol_v1|psbt_memo_parity|verifier_parity`
all pass. Untested: other viem or @solana/kit versions; the two SwapChan
generators cannot be re-run here, so those corpora are trusted as committed.
