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
