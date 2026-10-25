# Parity roadmap: btcrecover, Trust Wallet Core, offline policy (2026-10-25)

T asked for an audit against three reference points, using only public descriptions (READMEs,
docs, published specs). No code or license-incompatible material is copied; each item gets its
own public test vectors.

## 1. Audit

### btcrecover breadth (seed and password recovery)
| capability (btcrecover, public docs) | blocktools today | gap |
|---|---|---|
| BIP39 seed typo repair (swap, replace, missing word) | `seed-repair` (nearest words, missing word, checksum filter) | word-order swaps, more than one missing word, Electrum v2 / Electrum 1.x seed checksums |
| Wallet-file password recovery from token lists and typo rules | file openers check one password (`dat-read`, `keystore-open`, `electrum-read`, `multibit-read`, `armory-read`) | no candidate generator, no bounded search loop |
| Address-database / known-address check | `derive` + `key-to-addresses` compare against an address | no "stop when this address is found" search over paths and indexes |
| Many wallet formats (Core, Electrum, MultiBit, Blockchain.com, Ethereum keystore, Armory, Coinomi...) | Core BDB/SQLite, Electrum, MultiBit/bitcoinj, Armory, Web3 keystore | Blockchain.com v2/v3 JSON, Coinomi, Exodus |
| BIP38 encrypted keys | none | BIP38 decrypt (spec vectors) |
| Derivation-path sweeps across wallets | `derive --count`, `mbhd` | per-wallet path tables (Ledger Live, Trezor, MEW, Exodus) as data |

### Trust Wallet Core (table-driven, multi-chain signing)
| capability (public docs) | blocktools today | gap |
|---|---|---|
| One registry describes every coin (curve, coin type, address encoder, signer) | `crates/core/src/chains.rs` CHAINS table (+ `Sign` kind) | the registry is not exported as data, and non-UTXO signers live in separate crates |
| Same signing input / output schema for every chain | per-family JSON lines (tx-build, acct-tx, xrp-tx) | no common "SigningInput" envelope |
| Builders for Solana and Tron | decode and verify only | builders (queue item 5) |
| C ABI and many language bindings | wasm only | C ABI + Python/Go/Zig/C++ (queue item 7) |
| Cross-implementation test vectors per coin | KAT table in docs/CHAINS.md (`tests/quirks.rs`) | none for the account chains in the same table |

### Offline policy layer (like Privy / Turnkey / Coinbase CDP policy engines)
| capability (public docs) | blocktools today | gap |
|---|---|---|
| Declarative rules evaluated before every signature | `Policy` flags on tx-verify / tx-sign (`--expect-to`, `--change`, `--chain-id`, `--max-fee`) | rules are per-call flags; no reusable policy file |
| Allowlists of recipients, contracts and chains | `--expect-to`, chain-id pin | no contract/method allowlist, no per-chain rules |
| Value limits (per tx) | fee cap only | no per-tx value cap, no token value cap |
| Deny by default; every decision explained | findings list (`chain_id_not_pinned`, ...) | no rule id in the refusal, no policy hash in the output |
| Same engine in every runtime | Rust + wasm `checkTx` | policy file not accepted by wasm |

## 2. Ranked plan (benefit to safety and recovery per unit of work)
1. **Offline policy file** (`--policy FILE` for tx-verify and tx-sign; wasm `checkTxPolicy`). JSON rules per chain: `chain_id`, `allow_to`, `max_value`, `max_fee`, `allow_contracts` (EVM `to` plus 4-byte selector), `deny_token_approve`, `max_outputs`. Deny by default for anything the file does not allow. Each refusal names its rule; the output carries the sha256 of the policy file. This is the largest safety gain for the least code, because it reuses `Decoded` and `policy::check`.
2. **Chain registry as data** (`chain-table` JSON from CHAINS, plus a wasm `chainTable`): curve, coin type, address kinds, signer kind, KAT test name. This is TW Core's main idea and it feeds the C ABI and the man pages.
3. **Password candidate generator** (`pw-candidates`, btcrecover-style token list plus typo rules, bounded count), piped into the existing openers. No new crypto.
4. **BIP38 decrypt** (spec vectors), then **Blockchain.com wallet JSON**.
5. **Seed repair breadth**: swapped words, two missing words, Electrum seed versions.
6. **Common signing envelope** across families, done together with the C ABI (queue item 7).
7. **Address-search mode** (stop when a known address appears in derive output).

Implemented in this order; each step ships with its own vectors and an entry below.

## 3. Status
- [x] 1 policy file: `crates/tx/src/policy_file.rs`, `tx-verify --policy`, `tx-sign --policy`, wasm `checkTxPolicy`, docs/POLICY.md. Tests: crates/tx/tests/policy_file.rs, e2e tx-sign.sh, test.mjs. Untested: real-world policy files, EVM e2e through tx-sign (only covered by the unit tests).
- [ ] 2 chain registry as data
- [ ] 3 pw-candidates
- [ ] 4 BIP38 / Blockchain.com
- [ ] 5 seed repair breadth
- [ ] 6 common envelope (with C ABI)
- [ ] 7 address search
