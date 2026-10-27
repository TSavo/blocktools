# Verb x chain coverage

Issue #11 asks for one verb per tool with the chain as a parameter. The matrix below is **measured**, not written by
hand: `scripts/coverage.py` runs each release binary (`--help`, and for chain-parameterised verbs a `--chain C` probe
that must reject `--chain bogus`) and `docs-check` fails if the table is stale (rule D-coverage). A cell served by two
or more tools is marked **(2+)** and must be listed under [Listed overlaps](#listed-overlaps) with a reason, or the
gate goes red; a listing that no longer matches the measurement is red too. `gate-negatives.sh` plants both
violations and requires the rule to fire.

Columns are chains with a transaction verb somewhere in blocktools. Tools with no transaction verb (address
derivation like `derive`/`key-to-addresses`, wallet-file readers, ABI tools, `msg-sign`/`msg-verify`, ...) are listed
in the script's `NO_TX_VERB`; a new tool binary in neither list fails the gate. `tools/sol-v1` is a dev oracle
(`gen.mjs`, no binary, no man page; see PARITY-GENERATORS.md), not a command.

<!-- coverage:begin -->
| verb | btc | ltc | doge | bch | zec | eth | sol | tron | xrp | xlm | algo | atom | ton | ada | dot | xmr |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| decode | tx-decode<br>tx-envelope **(2+)** | tx-decode<br>tx-envelope **(2+)** | tx-decode<br>tx-envelope **(2+)** | tx-decode<br>tx-envelope **(2+)** | tx-decode<br>tx-envelope **(2+)** | tx-decode<br>tx-envelope **(2+)** | tx-decode<br>sol-tron-tx<br>tx-envelope **(2+)** | tx-decode<br>sol-tron-tx<br>tx-envelope **(2+)** | tx-decode<br>xrp-tx **(2+)** | tx-decode<br>acct-tx **(2+)** | tx-decode<br>acct-tx **(2+)** | tx-decode<br>acct-tx **(2+)** | tx-decode<br>acct-tx **(2+)** | tx-decode<br>acct-tx **(2+)** | tx-decode<br>acct-tx **(2+)** | - |
| verify | tx-verify<br>tx-envelope **(2+)** | tx-verify<br>tx-envelope **(2+)** | tx-verify<br>tx-envelope **(2+)** | tx-verify<br>tx-envelope **(2+)** | tx-verify<br>tx-envelope **(2+)** | tx-verify<br>tx-envelope **(2+)** | sol-tron-tx<br>tx-envelope **(2+)** | sol-tron-tx | - | - | - | - | - | - | - | - |
| build | tx-build | tx-build | tx-build | tx-build | tx-build | tx-build | sol-tron-tx | sol-tron-tx | xrp-tx | acct-tx | acct-tx | acct-tx | acct-tx | acct-tx | acct-tx | - |
| sign | tx-sign | tx-sign | tx-sign | tx-sign | tx-sign | tx-sign | - | - | xrp-tx | acct-tx | acct-tx | acct-tx | acct-tx | acct-tx | acct-tx | - |
| broadcast | tx-broadcast | tx-broadcast | tx-broadcast | - | - | tx-broadcast | - | - | - | - | - | - | - | - | - | - |
| sweep | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | xmr-wallet |
| keys | - | - | - | - | zec-sapling | - | - | - | xrp-tx | - | - | acct-tx | - | - | - | xmr-keys |
<!-- coverage:end -->

## Listed overlaps

- `decode/xlm,algo,atom,ton,ada,dot`: acct-tx, tx-decode - alias: `tx-decode --chain C` runs `acct-tx decode --chain C` (same directory); stdout and exit status byte-identical (scripts/e2e.d/decode-verb.sh). acct-tx keeps its verb for existing scripts.
- `decode/sol,tron`: sol-tron-tx, tx-decode, tx-envelope - tx-decode is an alias for `sol-tron-tx decode --chain C` (decode-verb.sh); tx-envelope is the JSON face of the library API (C ABI `bt_envelope`, wasm, SwapChan), kept for EXPORTS.md.
- `decode/xrp`: tx-decode, xrp-tx - alias: `tx-decode --chain xrp` runs `xrp-tx decode` (decode-verb.sh).
- `decode/btc,ltc,doge,bch,zec,eth`: tx-decode, tx-envelope - same engine (`blocktools_tx::decode`); tx-envelope is the library API's JSON face (EXPORTS.md, vendored by SwapChan), tx-decode the CLI.
- `verify/btc,ltc,doge,bch,zec,eth`: tx-envelope, tx-verify - same engine; tx-envelope is the library API's JSON face.
- `verify/sol`: sol-tron-tx, tx-envelope - same engine; tx-envelope is the library API's JSON face. (tron verify: sol-tron-tx only; tx-envelope answers unsupported_family.)

## Findings from the audit

- `tx-decode --chain xmr` (and any chain-table name that is not a UTXO chain, zec, eth or a delegated chain) used to parse
  the bytes as a UTXO transaction; it now refuses with `unsupported_chain` before reading input (e2e tx-decode.sh).
- `tx-verify` and `tx-sign` take the chain from the tx file (`resolve_chain`), so they are listed from their
  documented chains, not probed: a dummy input fails on the bytes before the chain is checked.
- `tron verify` exists only in sol-tron-tx; `tx-envelope` refuses it.
- `broadcast` covers btc, ltc, doge, eth only (tx-broadcast --help); every other chain is decode/sign here and broadcast elsewhere.

## Model-divergent chains: unify or keep separate (proposal only, not implemented)

The rule "one verb per tool, chain as a parameter" fits chains that share a transaction model: UTXO (btc/ltc/doge/bch/zec
transparent) and EVM. Where the model differs the inputs differ too, and one tool that takes every chain's flags only
moves the split from the tool name into the help text. Proposal per tool:

| tool | proposal | rationale |
|---|---|---|
| sol-tron-tx | **unify decode (done, alias)**; keep build/verify separate | decode is input-only, so `tx-decode --chain sol|tron` forwards it with no new flags. build takes a `--plan` (Solana recent blockhash and account metas, Tron ref-block bytes) and verify takes `--expect`; neither is like a PSBT or `tx-build --utxos`. Moving them into tx-build/tx-verify would bring in a second flag set and a second policy engine. |
| xrp-tx | **unify decode (done, alias)**; keep keys/build/sign separate | XRP has an account sequence, a destination tag and X-addresses; its family seed is not BIP39/BIP32. tx-sign's `--expect-to`/typed-code flow could later take the xrp blob. That needs its own review because the signing path would get wider, so not now. |
| acct-tx | **unify decode (done, alias)**; keep build/sign as they are | acct-tx is already "one verb, chain as a parameter" for six account chains. Folding it into tx-build/tx-sign would mix account-sequence flags (`--seq`, `--seqno`, `--first-round`, `--ttl`) into the UTXO/EVM tools. |
| sol-v1 | **keep separate** (not a command) | It is a Node dev oracle (`gen.mjs`) that produces the Solana v1 parity corpus. It has no verb to unify. |
| zec-sapling | **keep separate** | Shielded key/address derivation (ZIP-32, unified addresses, viewing keys written to a 0600 file) is a different secret model from `derive`. Transparent zec already goes through tx-build/tx-decode/tx-verify/tx-sign. There is no shielded tx verb to unify. |
| xmr-keys / xmr-wallet | **keep separate** | Monero needs a view-key scan and builds transactions inside monero-wallet-rpc (ring signatures, decoys). xmr-wallet is host-side and needs the network, and sealed-run refuses it. Putting it under tx-build/tx-broadcast would put a networked tool in the sealed set's verbs. |

Net effect: `decode` is the one verb that takes every chain (tx-decode, measured above). build/sign/verify stay
grouped by transaction model, and the overlaps that remain are listed above with their reasons.
