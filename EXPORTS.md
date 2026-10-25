# blocktools wasm / library exports (stable API, v0.1.0)

The rows below are checked by `scripts/wasm-check.sh`. The **exact** export set of the
`.wasm` is pinned there, so adding or removing an export fails CI. Every input is public: no
call accepts a private key, a seed, or a password, and the secret code paths are proven to be
absent from the binary (by checking the name section). Outputs are JSON strings unless noted.

## Stable API

| JS export | Rust (crate `blocktools`) | returns |
|---|---|---|
| `version()` | `blocktools::VERSION` | semver string |
| `supportedChains()` | `chains::CHAINS` where `verified` | `[{name,ticker,title,slip44,verified:true,sources:[{name,url,api,checked}]}]` |
| `unverifiedChains()` | `chains::CHAINS` where `!verified` | same shape, `verified:false` |
| `deriveFromXpub(chain, xpub, path, index)` | `derive::from_xpub(chain, xpub, path, index)` | `[{chain,kind,path,address}]`, one row per script kind; `path` is relative to the xpub and non-hardened ("", "m/0", "0/7"); throws `bad_xpub`, `bad_path`, or `unknown_or_unverified_chain` |
| `addressValidate(chain, addr)` | `address::validate(chain, addr)` | kind string (`P2pkh`, `P2sh`, `SegwitV0`, `Taproot`, `Eth`, …); throws when the address is invalid or the chain is unverified |
| `checkTx(json)` | `check::tx_json(json)` | see below; never throws |
| `detectAddress(addr)` | `address::detect(addr)` | `[{chain,kind}]`, one entry for **every** verified chain the address is valid on (and `zec`). Collisions such as DGB/DOGE 30, VIA/VTC 71, version 50 (MONA/MEC p2pkh, LTC/QTUM p2sh) and version 0 (BTC/BCH/BSV/TRC) all come back; `[]` means unrecognised |
| `detectAddressInfo(addr)` | `address::detect(addr)` | additive: `{candidates:[{chain,kind}], ambiguous, kinds_agree}`. `candidates` is exactly the detectAddress list. `ambiguous` = more than one chain; `kinds_agree` = all candidates have the same script kind (when false, convertAddress throws `ambiguous_address`) |
| `convertAddress(addr, to)` | `address::convert(addr, to)` | the same hash, re-encoded for `to`; throws `unrecognised_address`, `ambiguous_address` (candidates disagree on p2pkh vs p2sh), `unknown_or_unverified_chain` or `no_equivalent` |
| `convertAddressFrom(from, addr, to)` | `address::convert_from(from, addr, to)` | as above, with the source chain stated |
| `chainParams()` | `address::params_json()` | the full table: `[{name,ticker,title,slip44,verified,p2pkh:[bytes],p2sh:[bytes],hrp,wif,checksum,decimals,forkid,tx_format,sweep_build,sources}]` |
| `buildUnsignedSweep(chain, utxos, to, feeRate)` | `sweep::build_unsigned_sweep(...)` | `{chain,tx_format,psbt,unsigned_tx,inputs,amount,fee}`. `utxos` is JSON lines `{txid,vout,amount,address[,prev_tx]}`. Only the `legacy` and `forkid` formats are built; everything else throws `unsupported_tx_format:<fmt>` |

### detectAddress semantics

- It returns a **JSON string**, so call `JSON.parse` on it. Entries come in chain-table order (`chainParams()` order), not ranked by likelihood.
- More than one entry means the address is **ambiguous**: the same bytes are valid on several chains. For example, a Monacoin `M…` address is also a valid LTC/QTUM/MEC P2SH. Ask the user for the chain, or use `detectAddressInfo` for `ambiguous`/`kinds_agree`. There is no ranking.
- `zec` (transparent) appears in detect/validate only. It is **not** in `listChains`/`supportedChains`: ZEC is in `chains::EXCLUDED` (two-byte version prefixes, ZIP-243/244 sighash not implemented), so it has no derive or sweep. Groestlcoin stays out until there is a Groestl implementation with independent vectors.

### Loading the module

- `pkg/node` (CommonJS, the package `main`): synchronous. `const bt = require("blocktools")` and call right away.
- `pkg/web`: `import init, * as bt from "./pkg/web/blocktools_wasm.js"; await init();` (or `initSync({module: bytes})`) before any call.
- Bundlers: there is no `--target bundler` build. Use `pkg/web` and hand the wasm URL to init: `await init(new URL("blocktools_wasm_bg.wasm", import.meta.url))`. This works in Vite and webpack 5 (asset modules). UNTESTED in CI, which only runs pkg/node.
- Building it: `PATH=$HOME/.cargo/bin:$PATH bash scripts/wasm-check.sh` (needs rustup's wasm32 target and wasm-bindgen on PATH).

`addressValidate` also accepts `zec` (transparent t1/t3 only). Decode any built tx with `decodeTx(hex_or_psbt, chain)`.

Tx formats:
- `legacy`: Bitcoin format, including segwit where the chain has it.
- `forkid` (BCH/BSV/BTG): the unsigned bytes are the same as legacy, but the signer must use SIGHASH_FORKID with the input amounts, which the PSBT carries. Only the unsigned build is done here.
- `pos-ntime` (PPC/NVC/CLAM/BLK/RDD/POT): not built.
- `zcash-v5`: ZEC is address-only for now.
- `unknown` (QRK): not built.
- Groestlcoin (`grs`) is not in the table: it uses a Groestl base58 checksum and single-SHA256 txid/sighash, and there is no independent implementation to make a KAT from yet.

### checkTx (fail-closed)

In: `{"chain", "raw_tx_hex", "expected_outputs":[{"address","amount"?}], "max_fee", "owner_addr", "input_values"?:[...]}`.
Amounts are in base units (sats or wei), as an integer or a decimal string. `raw_tx_hex` may also be a PSBT or an EVM raw tx.

Out: `{"ok", "reasons":[...], "outputs":[{"address","amount"}], "fee", "inputs":[{"txid","vout","amount"}]}`. Amounts and the fee are decimal strings.

`ok` is true only when `reasons` is empty. Possible reasons:
- Input: `bad_json`, `chain_missing`, `unknown_chain`, `unverified_chain`, `raw_tx_hex_missing`, or a decoder error.
- Owner: `owner_addr_missing`, `owner_addr_invalid`.
- Fee: `max_fee_missing`, `fee_unknown`, `fee_above_max`. The fee comes from the PSBT, or from `input_values`, which must have one value per input.
- Expected outputs: `expected_outputs_missing`, `expected_output_bad`, `expected_address_invalid`, `expected_amount_bad`, `expected_output_missing`, `expected_amount_mismatch`.
- Other outputs: `unexpected_output`, meaning an output that is neither expected nor paid to `owner_addr`.
- Signing: `unsupported_sighash_for_chain`, for chains with fork-id, PoS-time, or unknown signing.
- `warning:<w>`, for any decoder warning except `unsigned` and `input_amounts_unknown`.
- EVM: the reasons from `tx::policy::check`.

## Legacy exports (kept, not part of the stable list above)

`validateAddress`, `listChains` (all rows, including unverified ones), `addressesFromXpub`, `explainPlan`, `decodeTx`, `describeTx`, `verifyTx`.

## Chain rows

Source tags: `blockbook`/`insight`/`qtuminfo`/`woc` sources give balance and UTXOs keyless (SwapChan probes, 2026-10-24). `cryptoid-balance` sources give the balance only; `unspent` needs an API key. A row with no source has no working public explorer (NMC, POT, MEC, ANC).

A row is `verified` when its version bytes match the coin's own source code and it has a SLIP-44 entry.
Any row marked "none listed" has no explorer that could be reached and checked from the build box. It is still verified from source.
Excluded, and never exported: `zec` (2-byte prefixes, ZIP-243/244 sighash) and `grs` (Groestl checksum). See docs/CHAINS.md.

### Supported (verified)

| name | ticker | SLIP-44 | p2pkh | p2sh | hrp | wif | checksum | decimals | forkid | tx format | sweep build | sources |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| btc | BTC | 0 | 00 | 05 | bc | 128 | sha256d | 8 | — | legacy | yes | esplora blockstream.info |
| ltc | LTC | 2 | 30 | 32 | ltc | 176 | sha256d | 8 | — | legacy | yes | esplora litecoinspace.org |
| doge | DOGE | 3 | 1e | 16 | — | 158 | sha256d | 8 | — | legacy | yes | none |
| eth | ETH | 60 | — | — | — | — | — | 18 | — | evm | no | none |
| tron | TRX | 195 | — | — | — | — | — | 6 | — | account | no | none |
| xrp | XRP | 144 | — | — | — | — | — | 6 | — | account | no | none |
| sol | SOL | 501 | — | — | — | — | — | 9 | — | account | no | none |
| qtum | QTUM | 2301 | 3a | 32 | qc | 128 | sha256d | 8 | — | legacy | yes | qtuminfo qtum.info |
| ftc | FTC | 8 | 0e | 05 | fc | 142 | sha256d | 8 | — | legacy | yes | none |
| nmc | NMC | 7 | 34 | 0d | nc | 180 | sha256d | 8 | — | legacy | yes | none |
| dash | DASH | 5 | 4c | 10 | — | 204 | sha256d | 8 | — | legacy | yes | blockbook blockbook.dash.zelcore.io; insight insight.dash.org |
| vtc | VTC | 28 | 47 | 05 | vtc | 128 | sha256d | 8 | — | legacy | yes | blockbook blockbook.vtc.zelcore.io |
| dgb | DGB | 20 | 1e | 3f | dgb | 128 | sha256d | 8 | — | legacy | yes | blockbook blockbook.dgb.zelcore.io |
| via | VIA | 14 | 47 | 21 | via | 199 | sha256d | 8 | — | legacy | yes | blockbook blockbook.viacoin.org |
| mona | MONA | 22 | 32 | 37 | mona | 176 | sha256d | 8 | — | legacy | yes | insight mona.insight.monaco-ex.org |
| rvn | RVN | 175 | 3c | 7a | — | 128 | sha256d | 8 | — | legacy | yes | blockbook blockbook.rvn.zelcore.io; blockbook blockbook.ravencoin.org |
| xpm | XPM | 24 | 17 | 53 | — | 151 | sha256d | 8 | — | legacy | yes | cryptoid chainz.cryptoid.info |
| trc | TRC | 83 | 00 | 05 | — | 128 | sha256d | 8 | — | legacy | yes | none |
| mec | MEC | 217 | 32 | 05 | mec | 178 | sha256d | 8 | — | legacy | yes | none |
| aur | AUR | 85 | 17 | 05 | — | 176 | sha256d | 8 | — | legacy | yes | cryptoid chainz.cryptoid.info |
| bch | BCH | 145 | 00 | 05 | — | 128 | sha256d | 8 | 0 | forkid | yes | none |
| bsv | BSV | 236 | 00 | 05 | — | 128 | sha256d | 8 | 0 | forkid | yes | woc whatsonchain.com |
| btg | BTG | 156 | 26 | 17 | btg | 128 | sha256d | 8 | 79 | forkid | yes | none |
| ppc | PPC | 6 | 37 | 75 | pc | 183 | sha256d | 6 | — | pos-ntime | no | blockbook blockbook.peercoin.net |
| nvc | NVC | 50 | 08 | 14 | — | 136 | sha256d | 6 | — | pos-ntime | no | cryptoid chainz.cryptoid.info |
| clam | CLAM | 23 | 89 | 0d | — | 133 | sha256d | 8 | — | pos-ntime | no | cryptoid chainz.cryptoid.info |
| blk | BLK | 10 | 19 | 55 | — | 153 | sha256d | 8 | — | pos-ntime | no | cryptoid chainz.cryptoid.info |
| rdd | RDD | 4 | 3d | 05 | rdd | 189 | sha256d | 8 | — | pos-ntime | no | blockbook blockbook.reddcoin.com |
| pot | POT | 81 | 37 | 6e | — | 183 | sha256d | 8 | — | pos-ntime | no | cryptoid chainz.cryptoid.info |
| qrk | QRK | 82 | 3a | 09 | — | 186 | sha256d | 8 | — | unknown | no | cryptoid chainz.cryptoid.info |
| zec | ZEC | 133 | 1cb8 | 1cbd | — | 128 | sha256d | 8 | — | zcash-v5 | no | none |

### Unverified (never returned as supported)

| name | ticker | SLIP-44 | p2pkh | p2sh | hrp | wif | checksum | decimals | forkid | tx format | sweep build | sources |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| wdc | WDC | 0 | 49 | 05 | — | 201 | sha256d | 8 | — | legacy | no | cryptoid chainz.cryptoid.info |
| anc | ANC | 0 | 17 | 0f | — | 151 | sha256d | 8 | — | legacy | no | none |
