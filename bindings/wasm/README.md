# blocktools wasm (TypeScript / JavaScript)

**Private package** (`"private": true`). Public-data API only: no private keys, no
signing of secret material, no wallet-file openers. Build: `sh scripts/wasm-check.sh`
from the repo root (also CI).

## Install (path / workspace)

```sh
# after wasm-check produces pkg/node and pkg/web
npm install ./bindings/wasm
```

```js
import init, {
  version, supportedChains, validateAddress, deriveFromXpub, checkTx,
} from "blocktools";
// Node: pkg/node is already wired via package.json "main".
// Web: await init() then call exports (see test-web.mjs).
```

## Stable exports

See [EXPORTS.md](../../EXPORTS.md). The wasm build is scanned so secrets-feature
symbols do not appear in the `.wasm`.

## Examples

- Validate: `validateAddress("btc", "bc1q...")`
- Watch-only: `deriveFromXpub(xpub, plan)` / path plans from the facade
- Policy: `checkTx(...)` fail-closed
- Builders: PSBT+memo, EVM transfer, Tron decode — public inputs only

## Security

Never pass mnemonics, WIF, or xprv into wasm. For recovery with secrets, use the
sealed CLIs (`./blocktools run`) on an offline machine ([docs/SECURITY.md](../../docs/SECURITY.md)).

## Reproducible build

`scripts/wasm-build.sh` builds the `.wasm` from a copy of the sources at one fixed path
(`/tmp/blocktools-wasm-build`, override with `BLOCKTOOLS_WASM_BUILD_DIR`), with the build path and
`$CARGO_HOME` remapped. Cause of the earlier drift (measured on Linux): this crate is its own cargo
workspace, so cargo put the absolute checkout path of `../../crates` into each crate's metadata hash.
`scripts/wasm-check.sh` does a clean rebuild from a second checkout at another path and fails if the
sha256 differs. Measured on Linux only. A different `CARGO_HOME`, toolchain or clang version is untested.
