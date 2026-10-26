# Adding a chain

## 1. No code change: a chain spec

Most old Bitcoin-derived coins differ from Bitcoin only in version bytes. Write a
`blocktools-chain-spec/1` file (docs/CHAIN-SPEC.md) and pass `--chain-spec FILE` to any UTXO tool.
Every value must come from the coin's own source. Cite the file and line in `evidence`, and leave
out anything you cannot cite. A missing field refuses only the steps that need it.

Worked example, BitConnect (BCC), from bitconnectcoin/bitconnectcoin@3ab3d19:

| field | value | source |
|---|---|---|
| p2pkh | 18 | src/base58.h:279 PUBKEY_ADDRESS |
| p2sh | 85 | src/base58.h:280 SCRIPT_ADDRESS (= blk's p2sh, so `allow_collision`) |
| wif | 146 | src/base58.h:408 (128 + PUBKEY_ADDRESS) |
| checksum | sha256d | src/util.h:450 Hash(), src/base58.h:136/152 |
| sign | postime (not standard) | tx nTime, src/main.h:443 |
| decimals | 8 | src/util.h:38 COIN |
| ticker | BCC | src/qt/bitcoinunits.cpp:37 |
| slip44 | none | (268 is BCChain) |

Since `sign` is postime, the spec derives addresses but tx-build refuses (`spec_unsupported_sign`).
recipes/chain-bitconnect.md runs the whole flow, from wallet.dat to addresses. `chain-learn` can
draft a spec from a node or wallet you control. It marks every field it could not prove as unknown.

## 2. A built-in row (code change)

Add a row when the chain should be detected without a flag, or after it has been verified. The bcc
row touched 6 files (11 insertions, 5 deletions):

- crates/core/src/chains.rs: the `u(...)` row (unverified: `false`), plus the coin-type exception
  when there is no SLIP-44 entry, plus a KAT `(chain, address, wif)` from an independent tool
- crates/blocktools/tests/coins.rs: the chain count
- crates/schema/src/lib.rs: the chain list
- docs/CHAINS.md, EXPORTS.md: the table rows
- scripts/kat-chains.py: the independent KAT re-derivation

Then re-measure any claim whose count changed (docs/claims.toml), run
`python3 scripts/claims-check.py --render` and
`node bindings/wasm/gen-reference.mjs`, and run the full gate.

An unverified row never builds a transaction and is not used for detection.
