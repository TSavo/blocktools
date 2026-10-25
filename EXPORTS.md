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

A row is `verified` when its version bytes match the coin's own source code and it has a SLIP-44 entry.
Any row marked "none listed" has no explorer that could be reached and checked from the build box. It is still verified from source.
Excluded, and never exported: `zec` (2-byte prefixes, ZIP-243/244 sighash) and `grs` (Groestl checksum). See docs/CHAINS.md.

| name | ticker | SLIP-44 | explorer/API sources (checked 2026-10-24) |
|---|---|---|---|
| btc | BTC | 0 | blockstream.info |
| ltc | LTC | 2 | litecoinspace.org |
| doge | DOGE | 3 | none listed |
| eth | ETH | 60 | none listed |
| tron | TRX | 195 | none listed |
| xrp | XRP | 144 | none listed |
| sol | SOL | 501 | none listed |
| qtum | QTUM | 2301 | none listed |
| ftc | FTC | 8 | none listed |
| nmc | NMC | 7 | none listed |
| dash | DASH | 5 | chainz.cryptoid.info |
| vtc | VTC | 28 | chainz.cryptoid.info |
| dgb | DGB | 20 | chainz.cryptoid.info |
| via | VIA | 14 | none listed |
| mona | MONA | 22 | none listed |
| rvn | RVN | 175 | blockbook.ravencoin.org |
| xpm | XPM | 24 | chainz.cryptoid.info |
| trc | TRC | 83 | none listed |
| mec | MEC | 217 | none listed |
| aur | AUR | 85 | chainz.cryptoid.info |
| bch | BCH | 145 | none listed |
| bsv | BSV | 236 | none listed |
| btg | BTG | 156 | none listed |
| ppc | PPC | 6 | chainz.cryptoid.info |
| nvc | NVC | 50 | chainz.cryptoid.info |
| clam | CLAM | 23 | chainz.cryptoid.info |
| blk | BLK | 10 | chainz.cryptoid.info |
| rdd | RDD | 4 | none listed |
| pot | POT | 81 | chainz.cryptoid.info |
| qrk | QRK | 82 | chainz.cryptoid.info |

### Unverified chains (, refused by every other call)

| name | ticker | SLIP-44 | sources |
|---|---|---|---|
| wdc | WDC | 0 | chainz.cryptoid.info |
| anc | ANC | 0 | none listed |
