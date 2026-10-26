# blocktools wasm / library exports (stable API, v0.1.0)

The rows below are checked by `scripts/wasm-check.sh`. The **exact** export set of the
`.wasm` is pinned there, so adding or removing an export fails CI. Every input is public: no
call accepts a private key, a seed, or a password, and the secret code paths are proven to be
absent from the binary (by checking the name section). Outputs are JSON strings unless noted.

Every export, with an executed example and its error code, is in the generated
[docs/EXPORTS-reference.md](docs/EXPORTS-reference.md).

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
| `detectAddressInfo(addr)` | `address::detect(addr)` | additive: `{candidates:[{chain,kind}], ambiguous, kinds_agree}`. `candidates` is the detectAddress list, except an XRP X-address (XLS-5d) reports kind `"xaddress"` (detectAddress/addressValidate keep `"Xrp"`; classic r-addresses stay `"Xrp"`). `ambiguous` = more than one chain; `kinds_agree` = all candidates have the same script kind (when false, convertAddress throws `ambiguous_address`) |
| `convertAddress(addr, to)` | `address::convert(addr, to)` | the same hash, re-encoded for `to`; throws `unrecognised_address`, `ambiguous_address` (candidates disagree on p2pkh vs p2sh), `unknown_or_unverified_chain` or `no_equivalent` |
| `convertAddressFrom(from, addr, to)` | `address::convert_from(from, addr, to)` | as above, with the source chain stated |
| `chainParams()` | `address::params_json()` | the full table: `[{name,ticker,title,slip44,verified,p2pkh:[bytes],p2sh:[bytes],hrp,wif,checksum,decimals,forkid,tx_format,sweep_build,fee_warn:{fee,rate,basis},sources}]`. `sweep_build` equals `chainTable().buildable` (see below). `slip44` is `null` when the registry has no SLIP-44 entry (wdc/anc; BTC remains `0`). Cosmos (`atom`) carries `hrp:"cosmos"`. `fee_warn` is the verifyTx limit: `high_fee` above `fee` base units, `high_fee_rate` above `rate` per vbyte (see docs/CHAINS.md "Fee-warning limits") |
| `buildUnsignedSweep(chain, utxos, to, feeRate)` | `sweep::build_unsigned_sweep(...)` | `{chain,tx_format,psbt,unsigned_tx,inputs,amount,fee}`. `utxos` is JSON lines `{txid,vout,amount,address[,prev_tx]}`. Only the `legacy`, `legacy-sha256` (GRS) and `forkid` formats are built; everything else throws `unsupported_tx_format:<fmt>` (pos-ntime: see `buildUnsignedSweepAt`) |
| _note_ | utxo lines | Legacy (non-witness-program, incl. bare P2SH) inputs must include `prev_tx`, or for P2SH a `redeem_script` hex that is a witness program hashing to the address (carried into the PSBT) (raw previous tx hex); otherwise these builders throw `legacy_input_needs_prev_tx`, and a `prev_tx` whose txid/output disagrees with `txid`/`vout`/`amount`/`address` throws. The PSBT carries `non_witness_utxo`; PoS `pos_prevouts[i]` carries `prev_tx`. Not required for zec. |
| `buildUnsignedSweepAt(chain, utxos, to, feeRate, time)` | `sweep::build_unsigned_sweep_at(...)` | As above plus tx `time` (unix s). pos-ntime chains return `{chain,tx_format:"pos-ntime",unsigned_tx,time,pos_prevouts:[{amount,script}],inputs,amount,fee}`; other chains ignore `time`. Throws `pos_ntime_needs_time` if time is 0 |
| `blake2b(dataHex, outLen, personal)` | `substrate::blake2b_hash` | hex digest; `outLen` 1..64; `personal` UTF-8 ≤16 bytes (`""` none); throws `bad_hex`, `bad_out_len`, `bad_personal` |
| `twox128(text)` | `substrate::twox128` | hex (16 bytes): xxh64 seed 0 ‖ seed 1, little-endian (Substrate pallet/storage prefixes) |
| `ss58Encode(accountHex, prefix)` | `substrate::ss58_encode` | SS58 string; prefix 0..16383 (one- and two-byte forms); throws `bad_hex`, `bad_account`, `bad_prefix` |
| `ss58Decode(addr)` | `substrate::ss58_decode` | `{prefix, account}` (account id hex); throws `bad_base58`, `bad_prefix`, `bad_length`, `bad_checksum` |
| `polkadotAccountStorageKey(account)` | `substrate::system_account_key` | hex key `twox128("System")‖twox128("Account")‖blake2_128(id)‖id`; `account` is an SS58 address (any prefix) or 32-byte hex (optional `0x`) |
| `decodeAccountInfo(hex)` | `substrate::decode_account_info` | `{nonce,consumers,providers,sufficients,data:{free,reserved,frozen,flags}}` from the 80-byte SCALE AccountInfo; u32 as numbers, u128 as decimal strings; throws `bad_hex`, `bad_length` |
| `base58Encode(hex)` / `base58Decode(s)` | `sol::b58enc` / `b58dec` | Bitcoin-alphabet base58, no checksum; decode returns hex; throws `bad_hex` / `bad_base58` |
| `solIsOnCurve(addr)` | `sol::is_on_curve` | `true` (ed25519 point: wallet key) / `false` (off-curve: PDA). Matches Solana's runtime (curve25519-dalek `decompress`): non-canonical y ≥ p and x = 0 with the sign bit set count as on curve (checked against solders); throws `bad_base58`, `bad_length` |
| `solFindProgramAddress(seedsJson, program)` | `sol::find_program_address` | `{address, bump}`; `seedsJson` is a JSON array of hex seeds (each ≤32 bytes, ≤15 seeds); throws `bad_seeds` |
| `solAssociatedTokenAddress(owner, mint, tokenProgram)` | `sol::associated_token_address` | `{address, bump}`; `tokenProgram` `""` = classic SPL Token, or the Token-2022 id |
| `solAnchorDiscriminator(name)` | `sol::anchor_discriminator` | 8-byte hex `sha256("global:"+name)[..8]` |
| `solDecodeTx(raw)` | `sol::decode_tx` | raw = hex or base64 wire tx (legacy, v0, or v1 / SIMD-0385 `0x81`). `{version:"legacy"\|0\|1, txid, fee_payer, recent_blockhash, num_required_signatures, accounts:[{pubkey,signer,writable}], address_table_lookups:[{table,writable:[u8],readonly:[u8]}], instructions:[{program, program_index, account_indexes:[u8], data_hex, kind, ...}], signatures:[{signer, status:"valid"\|"invalid"\|"unsigned"}], message_hex, config}`. `config` is null for legacy/v0; for v1 `{mask, priority_fee_lamports (decimal string)\|null, compute_unit_limit\|null, loaded_accounts_data_size_limit\|null, heap_size\|null}`. v1 sanitization per SIMD-0385 throws `v1_too_large`, `v1_limits`, `v1_unknown_config_bits`, `v1_priority_fee_bits`, `v1_heap_size`, `v1_duplicate_address`, `too_many_signatures` (>12), `bad_header`; any other `0x82..0xff` prefix throws `unsupported_version`. Kinds: `system_transfer{from,to,lamports}`, `system_create_account`, `system_assign`, `system_advance_nonce`, `system_authorize_nonce`, `system_other`, `token_transfer{source,destination,authority,amount}`, `token_transfer_checked{+mint,decimals}`, `token_approve`, `token_approve_checked`, `token_set_authority{account,authority_type,new_authority}`, `token_close_account{account,destination}`, `token_mint_to`, `token_burn`, `token_other`, `ata_create{payer,ata,owner,mint,idempotent}`, `compute_unit_limit{units}`, `compute_unit_price{micro_lamports}`, `memo{text}`, `unknown{accounts,data}`. Amounts are decimal strings. Throws `truncated`, `trailing_bytes`, `bad_shortvec`, `unsupported_version`, `bad_header`, `bad_account_index`, `signature_count_mismatch` |
| `solVerifyTx(raw, expectJson)` | `sol::verify_tx` | `expectJson` `{owner?, to?, lamports?, mint?, amount?, allow_programs?:[id]}` → `{ok, failures:[..], warnings:[..], txid, lamports, token_amount, signatures_valid, signatures_invalid, signatures_unsigned, fully_signed}`. Only signatures that ed25519-verify count in `signatures_valid`; any invalid one adds `bad_signature` (ok=false) and `fully_signed` is true only when every signature is valid; unsigned slots add warning `unsigned`. Fails closed on: invalid signature, fee payer ≠ owner, other recipients, recipient not paid, lamports/amount mismatch, wrong mint, approve, set_authority, assign, authorize_nonce, close_account to someone else, unknown program not in `allow_programs`. Warns on unresolved lookup tables and unchecked token transfers |
| `cashAddrDecode(addr)` | `cashaddr::decode` | `{prefix, type:"p2pkh"\|"p2sh"\|<n>, hash}` (prefix optional, default `bitcoincash`); throws `mixed_case`, `bad_char`, `too_short`, `bad_checksum`, `bad_padding`, `bad_version`, `bad_hash_length` |
| `cashAddrEncode(prefix, kind, hashHex)` | `cashaddr::encode` | CashAddr string; `kind` `"p2pkh"`/`"p2sh"`; throws `bad_type`, `bad_hash_length` |
| `cashAddrToLegacy(addr)` / `legacyToCashAddr(addr, prefix)` | `cashaddr::to_legacy` / `from_legacy` | address string; `prefix` `""` = `bitcoincash` (also `bchtest`, `ecash`) |
| `addressToScript(chain, addr)` | `cashaddr::address_to_script` | scriptPubKey hex (p2pkh, p2sh, p2wpkh, p2wsh, p2tr); bch accepts CashAddr; zec t-addresses; throws `unknown_chain`, `bad_address` |
| `scriptToAddress(chain, scriptHex)` | `cashaddr::script_to_address` | `{kind, address}` or `null` for non-standard (OP_RETURN, bare multisig) |
| `buildPsbtWithMemo(chain, utxos, to, amount, change, feeRate, memoHex, rbf?)` | `psbtmemo::build` / `psbtmemo::build_with` | Optional trailing `rbf` (default `false`): non-RBF nSequence `0xffffffff` on every input (THORChain inbound txs must not be RBF); `true` = `0xfffffffd`. Changed 2026-10-25: was always RBF. `{psbt (base64), fee, vsize, rbf, outputs:[{address\|null, script, value}]}`; outputs are `[to, change?, OP_RETURN memo?]` (THORChain UTXO order: vault VOUT0, change to VIN0 next, memo OP_RETURN after — dev.thorchain.org/concepts/sending-transactions.html); `amount` `""` = sweep (no change); memo 0..80 bytes, `""` = no OP_RETURN; vsize counts only selected inputs (11 + 68/in P2WPKH + 31/P2WPKH out + 9+script for OP_RETURN, i.e. 11+len, or 12+len above 75 bytes for OP_PUSHDATA1); RBF sequence, locktime 0, `witness_utxo` on every input; throws `memo_length`, `unknown_or_unverified_chain`, `not_utxo_chain`, UTXO-line errors, `insufficient funds`. Coin selection counts the memo output (like SwapChan btc.ts); change below 546 sats folds into the fee instead of failing; fails only if payment plus fee can't be funded or the fee rate exceeds the chain cap. |
| `tronTxId(rawDataHex)` | `tron::txid` | hex `sha256(raw_data)` |
| `tronDecodeTx(hex)` | `tron::decode` | raw_data hex or full Transaction hex → `{txid, ref_block_bytes, ref_block_hash, expiration, timestamp, fee_limit_sun, memo, contracts:[{type, type_id, owner, ...}], signatures (count), raw_data_hex}`. TransferContract adds `to, amount_sun`; TransferAssetContract `asset, to, amount`; TriggerSmartContract `contract, call_value_sun, data` and `trc20_transfer{to,amount}` / `trc20_approve{spender,amount}`; sun/amounts are decimal strings. Throws `truncated`, `bad_varint`, `bad_wire_type`, `no_parameter`, `no_contract` |
| `verifyRecovery(txJson, owner, nowS)` | `verifier::verify_recovery_json` | SwapChan `verifyRecovery` twin. `txJson` = `{"to","data","value"}` string; `nowS` unix seconds (must be > 0). → `{verified:true, call}` or `{verified:false, reason}`; reasons match the TS strings except viem decode errors (only the `unverifiable: ` prefix is stable). Throws `bad_json`, `bad_now` |
| `verifyRecoveryRaw(rawHex, owner, chainId, nowS)` | `verifier::verify_recovery_raw` | Same verdict on a raw signed/unsigned EVM tx (legacy/2930/1559), plus `tx:{kind, chainId, signed, from, to, value, data, txid}` (`from`/`txid` null when unsigned). Intentionally stricter than TS (corpus cases flagged `intentional_diff`): MultiSend leg length past the blob, sweep `value` that is an array/object (`unverifiable: value is not a scalar`), multicall nesting > 32, non-hex calldata — all refused. Fails closed on wrong/missing chainId, a signer other than `owner`, contract creation, undecodable bytes. Throws `bad_hex`, `bad_chain_id`, `bad_now` |
| `verifySweepTx(txJson, owner, chainId, token)` | `verifier::verify_sweep` | SwapChan `verifySweepTx` twin. `txJson` = `{from,to,value,data?,chainId}`; `token` = `""` for native. → `{verified, call|reason}` |
| `verifySweepRaw(rawHex, owner, chainId, token)` | `verifier::verify_sweep_raw` | `verifySweepTx` on raw tx hex; sender recovered from the signature, unsigned → `from is not the owner`. Same `tx` object as `verifyRecoveryRaw` |
| `recoveryTables()` | `verifier::tables` | `{standard_recovery:[{sig, selector, owners}], pinned:[{to, selector, call, rule}], multisend_call_only, pendle_router, exit_deadline_max_s}` |
| `buildEvmTransfer(reqJson)` | `build::build_evm_transfer` | Unsigned EIP-155 transfer for any EVM chain id (ETH forks, extra EVM). Request `{chainId, nonce, gas, gasPrice, to, value \| balance, token?, maxPriorityFeePerGas?, from?}` (integers: decimal or `0x` strings, or JSON numbers). `balance` = sweep (value = balance − gas×gasPrice). `token` → ERC-20 `transfer(to, value)`, native value 0. `maxPriorityFeePerGas` → type 2 with maxFeePerGas = gasPrice. → `{unsigned, sighash, kind:"legacy"\|"eip1559", chainId, nonce, gas, gasPrice, to, value, data, fee}` (+`maxPriorityFeePerGas`; token: `token, recipient, amount`; `from` echoed). Amounts are decimal strings. Throws `missing_*`, `bad_*`, `bad_gas` (outside 21000..30M), `value_and_balance`, `insufficient_balance`, `zero_value`, `tip_above_max_fee`, `fee_overflow` |
| `selectUtxos(utxosJson, scriptHex, feeRate)` | `build::select_utxos` | SwapChan coin selection. `utxosJson` = `[{txid, vout, value, script, ...}]`. Keeps own script (case-insensitive), drops value < rate×148×20 (spend fee > 5%), largest first (stable), cap 200. → `{selected:[...input objects], total, count, dropped_foreign, dropped_uneconomic, dropped_cap, min_value}` (`total`, `min_value` decimal strings). Throws `bad_utxos`, `bad_utxo`, `bad_utxo_value`, `bad_rate` |
| `checkTxPolicy(input, chain, policyJson)` | `tx::policy_file::check` | Offline policy file (docs/POLICY.md), deny by default. Uses the rule under `chains[chain]`. Returns `{ok, failures:["policy:<rule>"|base finding], warnings, policy_sha256}`. Throws on a bad tx or `policy_bad_*`. |
| `solBuildTransfer(planJson)` | `blocktools::sol::build_transfer` | Unsigned Solana legacy transfer (SOL send, sweep, SPL/Token-2022 transfer_checked + optional ATA create, priority fee). Byte-identical to @solana/kit 8.5 (tests/sol_build.rs). No keys. |
| `tronBuildTransfer(planJson)` | `blocktools::tron::build_transfer` | Unsigned Tron raw_data: TRX send, sweep (caller-chosen reserve), TRC-20 transfer. Reproduces mainnet raw_data bytes. No keys. |

### detectAddress semantics

- It returns a **JSON string**, so call `JSON.parse` on it. Entries come in chain-table order (`chainParams()` order), not ranked by likelihood.
- More than one entry means the address is **ambiguous**: the same bytes are valid on several chains. For example, a Monacoin `M…` address is also a valid LTC/QTUM/MEC P2SH. Ask the user for the chain, or use `detectAddressInfo` for `ambiguous`/`kinds_agree`. There is no ranking.
- `zec` (transparent) appears in detect/validate and, since 2026-10-24, in `buildUnsignedSweep` (v5, ZIP-244, mainnet branch id 0x37a5165b, fee = max(ZIP-317, size × rate)); the output is {unsigned_tx, zec_prevouts, branch_id, expiry_height} with no PSBT. Since 2026-10-25 it is in `listChains` and `supportedChains` (row has `scope:"transparent"`), based on the official ZIP-243/244 vectors, 7 mainnet txs and 21 mainnet script->address pairs (blockchair). Still no seed derive for zec (m/44'/133' untested) and no xpub. Rust also has `sweep::build_unsigned_zec_sweep(utxos, to, rate, branch_id, expiry)`. `grs` is in every list since 2026-10-24 (Groestl checksum and single-SHA-256 digests, independent KATs). Its `3…` P2SH does not collide with BTC: the checksum differs, so `detectAddress` returns `grs` only.

### Loading the module

- `pkg/node` (CommonJS, the package `main`): synchronous. `const bt = require("blocktools")` and call right away.
- `pkg/web` (ES module, the package `./web` export and the non-Node default): call init once before anything else. Browser: `import init, * as bt from "blocktools/web"; await init();` (fetches `blocktools_wasm_bg.wasm` next to the JS). Node/Deno or your own fetch: `await init({ module_or_path: wasmBytesOrUrlOrResponse })`. Synchronous: `initSync({ module: wasmBytes })`. Any export called before init throws. Same 48 functions as pkg/node (CI: `bindings/wasm/test-web.mjs` loads pkg/web with its wasm bytes, asserts the function set equals pkg/node's, and spot-checks results); wasm-check pins the exports of the pkg/web `.wasm`.
- Bundlers: there is no `--target bundler` build. Use `pkg/web` and hand the wasm URL to init: `await init(new URL("blocktools_wasm_bg.wasm", import.meta.url))`. This works in Vite and webpack 5 (asset modules). Bundler use is UNTESTED in CI (pkg/web itself is tested under Node).
- Building it: `PATH=$HOME/.cargo/bin:$PATH bash scripts/wasm-check.sh` (needs rustup's wasm32 target and wasm-bindgen on PATH).

`addressValidate` also accepts `zec` (transparent t1/t3 only). Decode any built tx with `decodeTx(hex_or_psbt, chain)`.

`serializeNvcTxFromJson(json: string, expected_txid: string) -> string` (raw hex; throws): rebuilds a Novacoin tx from api.novaco.in `/gettransaction/<txid>` decoded JSON (version, nTime, vin, vout sorted by `index`, locktime; values are integer base units, 1 NVC = 1e6, or a decimal NVC string with at most 6 decimals; a coinbase vin's `coinbase` is its scriptSig, hex-encoded twice by the API (verified on PoS coinbase 72b702b1…, block 1106297)). Fails closed unless reverse(sha256d(raw)) equals `expected_txid` and the JSON `txid`, and the length equals `size` when present. CLI: `tx-decode --nvc-json TXID < tx.json`.

Tx formats:
- `legacy`: Bitcoin format, including segwit where the chain has it.
- `forkid` (BCH/BSV/BTG): the unsigned bytes are the same as legacy, but the signer must use SIGHASH_FORKID with the input amounts, which the PSBT carries. Only the unsigned build is done here.
- `pos-ntime` (PPC/NVC/CLAM/RDD): built as raw tx + `pos_prevouts` (no PSBT exists for this format), only via `buildUnsignedSweepAt` with an explicit tx time; `buildUnsignedSweep` throws `pos_ntime_needs_time` on wasm. P2PKH inputs only. POT is still refused (no vector). BLK was reclassified to `legacy`: its mainnet v2 txs have no nTime (measured).
- `chainTable()`: the chain registry as a JSON array (same rows as the `chain-table` CLI / C ABI `bt_chain_table`; public data). Each row has `coin_type` (= `chainParams.slip44`, `null` when no SLIP-44 entry) and `buildable` (= `chainParams.sweep_build`).
- **`buildable` / `sweep_build` rule** (single source: `Chain::tx_format()` in `blocktools-core`): true only when an unsigned-sweep builder accepts the chain **and** a test covers it — verified UTXO `standard` / `forkid` / `legacy-sha256`, or `pos-ntime` with a listed layout (`ppc`/`nvc`/`clam`/`rdd`). False for EVM (`eth`, format `evm`; use `build_evm`), account-family, unverified rows (`wdc`/`anc`), and PoS without a layout (`pot`). Zcash transparent is outside `CHAINS` and reported only in `chainParams` (`sweep_build: true`). A drift test (`table_params_no_drift`) fails if the two exports disagree.
- `zcash-v5`: ZEC is address-only for now. Sapling (zs1) and unified (u1, `--unified`) addresses come from the CLI tool `zec-sapling` only; no wasm export.
- `unknown` (QRK): not built.
- `legacy-sha256` (GRS): since 2026-10-25 `addressesFromXpub(…, "grs")` expects the Groestl-checksummed xpub and GRS rows include `p2tr` (grs1p, address only; signing refused). Bitcoin serialization, but the txid and the legacy/BIP143 signature hashes use single SHA-256, and base58 uses a Groestl-512 double-hash checksum (`checksum: "groestl512d"`). Vectors: groestlcoinjs-lib (addresses, bip32), Electrum-GRS (WIF), and real GRS mainnet txs whose signatures verify only under our single-SHA-256 sighash. `deriveFromXpub` takes Bitcoin-checksummed xpubs only; Groestl-checksummed GRS xpubs are NOT supported. Taproot is off for GRS.

### Amounts above 2^53 (since 2026-10-25, additive)

`JSON.parse` rounds integers above 2^53 (an RDD sweep lost precision). Choice: **additive, no break.** Every `amount` / `fee` field, at any depth, in the output of `decodeTx`, `checkTx`, `buildUnsignedSweep` and `buildUnsignedSweepAt` now has a decimal-string twin `amount_str` / `fee_str`; the original fields are unchanged (sweep `amount`/`fee` were already strings; decode/check ones stay numbers). Use the `_str` fields for exact values. `pos_prevouts` / `zec_prevouts` entries carry `amount_str`, and the signers read `amount_str` first, so passing the parsed object back is exact. Inputs: `utxos` `amount` may be a JSON integer or a decimal string; the per-UTXO limit is now 2^63-1 (was 21,000,000 x 1e8, which refused large RDD/DOGE UTXOs; zec keeps 21M ZEC); totals are checked (`amount_overflow`). Tested: an RDD sweep of 9007199254740993 (2^53+1) sats round-trips exactly (bindings/wasm/test.mjs).

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

## EVM contract data (`blocktools::evm`)

Offline, no keys, no network, no chain list. Same code as the `sig-hash`, `abi-decode`, `abi-encode` and
`create-address` CLIs (`blocktools::evm::api`). Errors throw a short code string. Hex out is lowercase `0x…`;
addresses are EIP-55. ABI values: `uint*`/`int*` decimal strings, `address` EIP-55 string, `bool`,
`bytes`/`bytesN` `0x` hex, `string`, arrays and tuples JSON arrays.

| JS export | Rust (`blocktools::evm::api`) | returns |
|---|---|---|
| `evmKeccak256(dataHex)` | `keccak256_hex` | `"0x"` + 64 hex; throws `bad_hex`, `odd_length_hex` |
| `evmSigHash(signature)` | `sig_hash` | `{status:"ok", kind:"function"\|"event"\|"error"\|"constructor", signature (canonical), hash, selector}`; events give `topic` (and `anonymous:true`) instead of `selector`. Accepts `transfer(address,uint256)` or human-readable `function transfer(address to, uint amount) external returns (bool)` / `event …` / `error …`; tuples as `(…)` or `tuple(…)`. Throws on bad types (`uint7`, `bytes33`), names or brackets |
| `evmSigLookup(hashHex, sigsText)` | `load_sigs` + `lookup` | `{status:"ok"\|"no_match", query, matches:["error X()", …]}`. `sigsText` is ABI JSON (array or `{abi:[…]}`) or one signature per line (`#` comments). A 4-byte hash matches functions/errors, a 32-byte hash matches events. No built-in database |
| `evmAbiDecode(requestJson)` | `decode_json` | Request `{input, sig?, abi?, types?, output?}`: `input` is hex or a JSON-RPC object (tx with `input`, log with `topics`/`data`, `eth_call` result, `{result:…}` or `{error:{data}}` unwrapped); `sig` a signature string or array; `abi` ABI JSON or signature lines; `types` e.g. `"(uint256,address)"` for return data; `output:true` decodes a function's return values. Match: `{status:"ok", kind, signature, hash, selector\|topic, args:[{name?, type, value, components?, indexed?}]}` (`Panic` adds `panic_reason`; indexed dynamic event args give `value_hash`). Plain types: `{status:"ok", types, args}`. None: `{status:"no_match", selector\|topic}`. Throws on malformed or non-canonical encodings (strict decoder) |

## Legacy exports (kept, not part of the stable list above)

`validateAddress`, `listChains` (all rows, including unverified ones), `addressesFromXpub`, `explainPlan`, `decodeTx`, `describeTx`, `verifyTx`.

`verifyTx(input: string, chain: string, expect_to: string[], change: string[], chain_id: number | null, max_fee: string, allow_warnings: boolean, allow_value_with_token?: boolean | null): string`
returns `{"ok":bool,"failures":[..],"warnings":[..],"check_these":"..","fee_cap":{"chain","cap","source"}}`. Since 2026-10-25: `max_fee` "" on EVM means the tx-sign default
(0.01 ETH = 10^16 wei, failure `fee_above_cap`); UTXO "" means the per-chain default cap (docs/CHAINS.md "Default fee cap").
`fee_cap` (additive, 3ec1d1a) is the cap the verdict applied: `chain`, `cap` (decimal string, base units) and `source`
(`explicit` = your max_fee, `floor`, `chain_rate_x_vsize`, `default_evm`). The envelope `verify` result and tx-verify output carry the same object. A nonzero ETH `value` alongside ERC-20
`transfer` calldata fails with `eth_value_with_token_call` unless `allow_value_with_token` is true (CLI: `--allow-value-with-token`).

Account payments (xlm, algo, atom, ton, ada, dot) are CLI-only (`acct-tx`, crate blocktools-acct). There is no wasm export for them, and
the `sweep build` column below covers only the UTXO builder, so it stays `no` for those rows.

## Chain rows

Source tags: `blockbook`/`insight`/`qtuminfo`/`woc` sources give balance and UTXOs keyless (SwapChan probes, 2026-10-24). `cryptoid-balance` sources give the balance only; `unspent` needs an API key. A row with no source has no working public explorer (NMC, POT, MEC, ANC).

A row is `verified` when its version bytes match the coin's own source code and it has a SLIP-44 entry.
Any row marked "none listed" has no explorer that could be reached and checked from the build box. It is still verified from source.
Outside the chain table: `zec` (2-byte prefixes), handled by the blocktools-tx zcash module (transparent only). See docs/CHAINS.md.

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
| atom | ATOM | 118 | — | — | cosmos | — | — | 6 | — | account | no | none |
| algo | ALGO | 283 | — | — | — | — | — | 6 | — | account | no | none |
| ada | ADA | 1815 | — | — | — | — | — | 6 | — | account | no | none |
| ton | TON | 607 | — | — | — | — | — | 9 | — | account | no | none |
| dot | DOT | 354 | — | — | — | — | — | 10 | — | account | no | none |
| xlm | XLM | 148 | — | — | — | — | — | 7 | — | account | no | none |
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
| ppc | PPC | 6 | 37 | 75 | pc | 183 | sha256d | 6 | — | pos-ntime | yes | blockbook blockbook.peercoin.net |
| nvc | NVC | 50 | 08 | 14 | — | 136 | sha256d | 6 | — | pos-ntime | yes | cryptoid chainz.cryptoid.info |
| clam | CLAM | 23 | 89 | 0d | — | 133 | sha256d | 8 | — | pos-ntime | yes | cryptoid chainz.cryptoid.info |
| blk | BLK | 10 | 19 | 55 | — | 153 | sha256d | 8 | — | legacy | yes | cryptoid chainz.cryptoid.info |
| rdd | RDD | 4 | 3d | 05 | rdd | 189 | sha256d | 8 | — | pos-ntime | yes | blockbook blockbook.reddcoin.com |
| pot | POT | 81 | 37 | 6e | — | 183 | sha256d | 8 | — | pos-ntime | no | cryptoid chainz.cryptoid.info |
| qrk | QRK | 82 | 3a | 09 | — | 186 | sha256d | 5 | — | legacy | yes | cryptoid chainz.cryptoid.info |
| zec | ZEC | 133 | 1cb8 | 1cbd | — | 128 | sha256d | 8 | — | zcash-v5 | yes (transparent P2PKH) | none |
| grs | GRS | 17 | 24 | 05 | grs | 128 | groestl512d | 8 | — | legacy-sha256 | yes | none listed |

### Unverified (never returned as supported)

| name | ticker | SLIP-44 | p2pkh | p2sh | hrp | wif | checksum | decimals | forkid | tx format | sweep build | sources |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| wdc | WDC | — (null) | 49 | 05 | — | 201 | sha256d | 8 | — | legacy | no | cryptoid chainz.cryptoid.info |
| anc | ANC | — (null) | 17 | 0f | — | 151 | sha256d | 8 | — | legacy | no | none |
| bcc | BCC | — (null) | 12 | 55 | — | 146 | sha256d | 8 | — | pos-ntime | no | none |

- Monero scan/sweep is host-only (`tools/xmr-wallet`, CLI JSON lines kinds `scan`, `received`, `sweep-plan`, `sweep-relayed`); not exported to wasm.

## C ABI (`blocktools-c`, secrets-off)

Native `cdylib`/`staticlib` in `crates/cabi`. Header: `crates/cabi/include/blocktools.h`.

| C symbol | Rust | Notes |
|---|---|---|
| `bt_version` | `CARGO_PKG_VERSION` | Static string; do not free |
| `bt_chain_table` | `chains::table_json` | Heap JSON array; free with `bt_free` |
| `bt_envelope` | `blocktools::envelope::run` | `blocktools.sign/v1` JSON in/out; free with `bt_free` |
| `bt_free` | `CString::from_raw` | No-op on NULL |

Same public-data rules as wasm: no private keys, no network. CLI twin: `tx-envelope`.

### `blocktools.sign/v1` envelope responses (executed)

Run through both `bt_envelope` (C, Linux `.so`) and `tx-envelope` with the same requests; the
responses matched. Every response has `envelope`, `status` (`ok` or `error`), `op` and `chain`.
An ok response adds `result` (and `family`, except for `chain_table`); an error adds `error`.
`tx-envelope` exits 0 for error responses too, so read `status`, not the exit code.

| Request | Response |
|---|---|
| `{"op":"chain_table","chain":"_"}` | ok, `result` is the chain table array |
| `{"op":"decode","chain":"btc","tx":HEX}` | ok, `result` keys: chain, inputs, locktime, outputs, rbf, role, signed, status, tool, txid, type, vsize, warnings |
| `{"op":"verify","chain":"btc"\|"eth",...}` | ok, `result` keys: check_these, **findings**, max_fee, ok, summary |
| `{"op":"check","chain":"btc","tx":HEX}` | ok, `result` keys: fee, inputs, ok, outputs, reasons |
| `{"op":"decode","chain":"xlm","tx":"00"}` | error `unsupported_family` |
| `{"op":"nope","chain":"btc"}` | error `unknown_op` |
| `{"envelope":"other/v1",...}` | error `unsupported_envelope` |
| `not json` | error `bad_json` |
| `bt_envelope(NULL)` (C only) | error `null_input` |

Naming difference: envelope `verify` reports refusals in `findings`; wasm `verifyTx` reports the
same check in `failures`. `bt_free(NULL)` is documented as a no-op in the header but is not exercised.
`.dylib` (macOS) is untested.

## Language wrappers (`bindings/`, secrets-off)

Thin wrappers over `libblocktools_c` + `blocktools.h` (same symbols as the C ABI table above).
See `bindings/README.md`. Measured smoke tests: Python ctypes, Go cgo, C++ header, Zig (`-dynamic` shared link). Not published to language registries.
