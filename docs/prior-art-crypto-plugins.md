# Prior art: wopr-network/crypto-plugins and platform-crypto-server

Read-only review (2026-10-24) of T's own TypeScript repos, shallow clones of `main`. Neither has a license file; both are T's.
Paths: `CP/` = crypto-plugins, `PCS/` = platform-crypto-server. No secrets or credentials are reproduced here. The only key material quoted is public: the BIP-39 "abandon … about" test mnemonic, xpubs, and addresses.

## 1. Architecture worth copying

- **Two-axis registry** (`PCS/src/plugin/interfaces.ts`, `CP/src/*/index.ts`):
  - `ICurveDeriver { derivePublicKey(chain, index); getCurve(): secp256k1|ed25519 }`
  - `IAddressEncoder { encode(pubkey, params); encodingType() }`, with `EncodingParams { hrp?, version? }` (strings, e.g. `version: "0x1e"`)
  - `IChainPlugin { pluginId, supportedCurve, encoders: {name→encoder}, createWatcher, createSweeper, version }`
  - `ISweepStrategy { scan(keys, treasury) → DepositInfo[]; sweep(keys, treasury, dryRun) → SweepResult[] }`. **scan/sweep split plus dry-run by default** (`SWEEP_DRY_RUN` must be `"false"` to send).
  - `IChainWatcher { init, poll, setWatchedAddresses, getCursor, stop }` plus `IWatcherCursorStore` (cursor and per-txKey confirmation counts).
  → blocktools: `derive` = curve deriver × encoder table; sweep = scan, then a plan, then sign.
- **The chain is a data row, not code.** In the DB `payment_methods` row: `coin_type, curve, encoding, encoding_params(JSON), xpub, rpc_url, rpc_headers, contract_address, decimals, confirmations` (`PCS/src/db/schema.ts`, `CP/src/sweep/index.ts`). Adding a chain is an INSERT. The sweeper groups methods by `coin_type` into a family (`0,2,3→utxo; 60→evm; 195→tron; 501→solana`).
- **Key rings** (`schema.ts key_rings`): `curve`, `derivation_scheme` (`bip32|slip10|ed25519-hd`), `derivation_mode` (`on-demand|pre-derived`), coin_type, account_index. `/admin/next-path` hands out `m/44'/{coin}'/{n}'`.
- **Ed25519 can't use xpubs**, so Solana and TON use a **pre-derived address pool**. An offline tool uploads `{index, public_key, address}`. The server **re-encodes public_key and rejects a mismatch** ("Address mismatch", `PCS/src/__tests__/key-server.test.ts:523`). This integrity check is worth copying for `derive` output.
- **Shared xpub across EVM chains** (coin 60): a unique-constraint collision (PG `23505`, including when Drizzle wraps it in `err.cause.code`) triggers a retry with the next index (`PCS/src/server.ts`).
- **Address normalisation**: lowercase bech32 and EVM before storing; never lowercase Base58.
- **Zero-dependency primitives**: hand-written SHA-256, RIPEMD-160, base58, bech32 polymod and CRC16-XMODEM (`CP/src/bitcoin/encoder.ts`, `CP/src/solana/encoder.ts`, `CP/src/ton/encoder.ts`). Duplicated across files; fits our minimal-crates rule for the small ones.

## 2. Derivation

| Item | Detail | File |
|---|---|---|
| Server | xpub only: deposits `xpub/0/i`, **treasury `xpub/1/0`** | `PCS/src/address-gen.ts` |
| Sweeper | mnemonic on **stdin** → `bip39.validateMnemonic` → seed → `m/44'/{coin}'/0'/{0,1}/i`, default 200 indices (`MAX_ADDRESSES`) | `CP/src/sweep/index.ts` |
| Purposes | **Only `44'`** for every chain, including BTC/LTC bech32. Funds sit at `m/44'/0'/0'/0/i` **as P2WPKH**, which standard wallets won't scan. Recovery therefore needs a purpose × script-type cross-product. | |
| xpub check | `isValidXpub`: `xpub` prefix and a successful parse; no ypub/zpub/tpub | `address-gen.ts` |
| Solana | SLIP-0010 ed25519 (HMAC key `"ed25519 seed"`, hardened only), path **`m/44'/501'/i'/0'`** | `CP/src/__tests__/sweep-key-parity.test.ts` |
| TON | ed25519 pubkey → **wallet v4r2** StateInit hash (wallet_id `698983191 + workchain`) | `CP/src/ton/encoder.ts` |
| Seeds | BIP39 only; no passphrase, no Electrum | |

## 3. Encoders

- **BTC/LTC**: hash160(compressed pubkey), witness v0, bech32 (no bech32m, no taproot). hrp defaults to `bc` in CP but is *required* in PCS. LTC uses `ltc`, testnet `tb`.
- **DOGE**: base58check p2pkh; version byte default `0x1e` (required in PCS).
- **EVM**: decompress → keccak(uncompressed[1:]) → last 20 bytes → EIP-55.
- **Tron**: `0x41` ‖ the EVM 20 bytes → base58check.
  - `tronToHex` checks the `T` prefix and the checksum.
  - `hexToTron` accepts the hex with or without `0x`.
  - `isTronAddress` only checks prefix and length 33–35, with no checksum check.
- **Solana**: base58 of the 32-byte pubkey; other lengths are rejected.
- **TON**: base64url(tag ‖ wc ‖ hash32 ‖ CRC16-XMODEM BE), 48 characters. Tag `0x11` is bounceable (`EQ`), `0x51` non-bounceable (`UQ`, the default). The repo includes a minimal BOC parser and cell hasher with the v4r2 code embedded.
- **Missing**: Solana ATA/PDA derivation, taproot, P2SH-P2WPKH, uncompressed keys, XRP.

## 4. Network shapes

| Chain | Read | Build / broadcast | Confirmations | File |
|---|---|---|---|---|
| BTC/LTC/DOGE | bitcoind JSON-RPC 1.0; basic auth parsed from URL userinfo (URL-decoded); `getdescriptorinfo addr(X)`→`importdescriptors` (fallback `importaddress`); `listreceivedbyaddress 0 false true`; `gettransaction txid true`, details filtered to category `receive` | sweeper is a stub (use Electrum/Sparrow) | per-tx count, re-emitted on each increment | `CP/src/shared/utxo/{rpc,watcher}.ts` |
| EVM | `eth_getBalance`, ERC-20 `balanceOf` (viem) | gas 21000 native, 65000 per ERC-20; **treasury pre-funds gas** to token-only deposit addresses | native: `eth_getBlockByNumber(n,true)` in batches of 5, stopping at the first failure; tokens: `eth_getLogs` with Transfer topic `0xddf252ad…b3ef`, topic[2] = padded `to` | `CP/src/sweep/evm-sweeper.ts`, `CP/src/evm/watcher.ts` |
| Tron | `/wallet/getaccount`, `/wallet/triggerconstantcontract balanceOf(address)` | `/wallet/createtransaction`, `/wallet/triggersmartcontract transfer(address,uint256)` with fee_limit 1e8; sign the txID with secp256k1, lowS, 65-byte r‖s‖v; `/wallet/broadcasttransaction`; header `TRON-PRO-API-KEY` | watcher uses TronGrid's EVM-compatible `eth_getLogs`, converting hex↔T at the boundary | `CP/src/sweep/tron-sweeper.ts`, `CP/src/tron/watcher.ts` |
| Solana | `getBalance`, `getTokenAccountsByOwner {mint} jsonParsed` | hand-built legacy message; System transfer ix 2 + u64 LE; SPL Transfer ix 3; `getLatestBlockhash finalized`; `sendTransaction` base58; fee 5000 lamports | `getSignaturesForAddress` limit 100 + `getTransaction` (maxSupportedTransactionVersion 0); pre/post balance diff; cursor advances on finalized only | `CP/src/solana/{sweeper,watcher}.ts` |
| TON | toncenter v2 `getTransactions` (`X-API-Key`), v3 `/jetton/transfers` | none | cursor = `lt`; skips outgoing, zero-value and aborted transfers | `CP/src/ton/watcher.ts` |

- **Confirmation defaults**: ETH 12, Base 1, Arbitrum 1, Polygon 32 (`PCS/src/chains/evm/config.ts`).
- **Idempotency key**: `txid`, `txhash:logIndex` or `sig:to`. The cursor only advances past confirmed blocks, and a failed write does not advance it.
- **Money**: integer-only (cents × micro-dollar prices, bigint raw amounts).
- **Credentials**: env only. `rpc_url` may carry userinfo, so our tools must strip and redact it.

## 5. Unit-test catalogue (both repos, about 280 cases)

### Patterns worth copying
1. **Table-driven chain configs**: one array `{name, coinType, addressType, params, addrRegex}` drives the same tests for every chain (`PCS/src/__tests__/address-gen.test.ts:35`, `CP/src/__tests__/sweep-key-parity.test.ts`). In Rust: a `const CASES: &[ChainCase]` table.
2. **Parity tests (best idea)**: the seed→privkey path and the xpub→pubkey path give the same address for indices 0–4 (EVM 0–9) and for the treasury. EVM is cross-checked with an independent library (viem).
3. **Property invariants**:
   - Determinism, and distinct indices give distinct addresses.
   - Charset, regex and length checks: Tron 34, LTC 43, TON 48, DOGE 33–34.
   - Round trips: hex↔T, and TON output never contains `+`, `/` or `=`.
4. **Error-substring contracts**: "hrp", "version", "Unknown address type", "Invalid", "32-byte", "Not a Tron address", "Invalid hex address length". Map these to our stable status codes.
5. **Mock RPC keyed by method name**, with these watcher cases:
   - empty watch set
   - stop()
   - cursor restore
   - no double emit
   - re-emit when the confirmation count rises
   - errored tx skipped
   - a failing write does not mark the tx processed (`PCS/src/chains/evm/__tests__/eth-watcher.test.ts:155`)
6. **No golden files exist.** Most encoder tests check the format only, with no exact BTC, LTC, DOGE, TON or Solana-from-mnemonic strings. We should add a golden vector file.

### Known-answer vectors (all public)

Mnemonic **M** = `abandon` ×11 + `about` (the BIP-39 test vector), no passphrase.

| Chain | Input | Expected | Source |
|---|---|---|---|
| Tron | M, `m/44'/195'/0'/0/0` | `TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH` | `PCS/src/__tests__/address-gen.test.ts:180` |
| Tron | M, `m/44'/195'/0'/0/1` | `TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK` | `:185` |
| Tron | xpub `xpub6BnqJwdqnXEZdkynN5CsrYZr3MULY933SdLrswFfKPDFandTXPQDWY225FveTPUJXS8D91Ddp7FEfaGrvVxuMBGQsyoBYRLu6VMB3Ni2H2Z` `/0/0` | `TDTkBJWfXqfCPhNAgHxmgPNHigJEg4ghww` | `CP/src/__tests__/tron-encoder.test.ts:23` (the same xpub drives the LTC and DOGE tests) |
| Tron hex | `TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW` ↔ `0x5a523b449890854c8fc460ab602df9f31fe4293f` | identity both ways, with or without `0x` | `PCS/src/chains/tron/__tests__/address-convert.test.ts` |
| Tron reject | last character changed to `X` → checksum error; `0x1234` and `D7abc123` → "Not a Tron address"; `hexToTron("0x1234")` → "Invalid hex address length"; isTronAddress is false for `0x1234…5678`, `D7abcdef` and `bc1qtest` | | same file and `CP/src/__tests__/tron-encoder.test.ts` |
| BTC | M, `m/44'/0'/0'/0/0`, hrp bc/tb | regex `^bc1q[a-z0-9]{38,42}$` and `^tb1q` (no exact string) | `PCS/src/__tests__/address-gen.test.ts:205` |
| BTC enc | 33-byte pubkey `02 01 02 … 20` | `bc1q…`, length 42–62 (no exact string) | `CP/src/__tests__/bitcoin-encoder.test.ts:28` |
| LTC | xpub above, hrp `ltc` | `ltc1q…`, length 43 | `CP/src/__tests__/litecoin-encoder.test.ts` |
| DOGE | xpub above, version 0x1e | `D…`, length 33–34 | `CP/src/__tests__/dogecoin-encoder.test.ts` |
| EVM | M, `m/44'/60'/0'/0/0..9` and `/1/0` | address from the privkey == address from the xpub | `PCS :148`, `CP sweep-key-parity` |
| Solana | ed25519 secret `00…01` | pubkey `4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29`; address = base58 of it | `CP/src/__tests__/solana-encoder.test.ts:65` |
| Solana | M, SLIP-10 `m/44'/501'/i'/0'`, i=0..4 | distinct, valid, sign/verify works | `CP sweep-key-parity :249` |
| base58 | `[0xff]`→`5Q`; `[0,0,0]`→`111`; `[1]`→`2` | | `CP/src/__tests__/solana-encoder.test.ts:90` |
| Length rejects | Solana/TON pubkey of 0, 20 or 33 bytes; TON hash of 16 or 64 bytes | "32-byte" | encoder tests |
| TON | pubkeys 32×`01`, 32×`ab`, and ed25519(`00…01`) | 48 characters, `UQ` prefix (or `EQ` bounceable), no exact string | `CP/src/__tests__/ton-encoder.test.ts` |
| Server errors | index −1 → "Invalid"; type `foo` → "Unknown address type"; bech32 without hrp, and p2pkh or keccak-b58check without version, all throw | | `PCS address-gen.test.ts:223` |
| xpub | valid → true; garbage and `""` → false | | `:252` |
| Money | $50 at $3,500 → `14285714285714285` wei; $50 at $65k → `76923` sats; $100 at $2k → `5e16` wei; converting back gives 4999 cents (truncation); 1000 cents at $100k → 10000 sats | | `PCS/src/oracle/__tests__/convert.test.ts`, `PCS/src/chains/btc/__tests__/config.test.ts` |
| EIP-55 | USDC Base `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, USDT Base `0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2`, DAI Base `0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb`, USDC ETH `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`, USDT ETH `0xdAC17F958D2ee523a2206206994597C13D831ec7` | checksum round-trip | `PCS/src/chains/evm/__tests__/config.test.ts` |

Standard companion vectors (from the BIP-84 spec and common wallets; verify when porting): M `m/84'/0'/0'/0/0` → `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`; M `m/44'/60'/0'/0/0` → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`.

## 6. Bugs and gaps (don't copy)
- `isTronAddress` has no checksum check. The tron-sweeper `base58decode` pads to a fixed 25 bytes and then also adds leading-zero bytes.
- The EVM sweeper hardcodes `chainId: 1` for every chain (wrong EIP-155 signatures on L2s), uses legacy gasPrice, and formats amounts with floats.
- The Solana sweep can't create the receiver ATA. The UTXO sweeper is a stub, and TON has no sweeper.
- The UTXO watcher calls `listreceivedbyaddress` with minconf 0.
