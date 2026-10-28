---
name: cross-chain-swap
description: >-
  Swap, convert, or bridge one coin into another — same-chain or cross-chain —
  through THORChain, and register or alias a THORName, using blocktools as the
  self-custody signer. Use when the user wants to swap/convert/bridge an asset
  (e.g. BTCB→DOGE, DOGE→RUNE, ETH→BTC), do a THORChain swap, deposit into a
  THORChain vault with a swap memo, or register/alias/manage a THORName
  affiliate name. blocktools are offline Rust Unix-filter tools (a self-custody
  wallet) that build, DECODE, VERIFY and sign transactions behind a sealed
  boundary; the companion SwapChan service (mcp server `swapchan`, swapchan.com)
  finds routes and builds the UNSIGNED swap tx but never holds keys or signs.
  Pattern: SwapChan-builds-unsigned → blocktools-verifies-and-signs-sealed →
  relay-broadcasts, with human sign-off on every tx. Covers EVM deposits
  (depositWithExpiry), UTXO OP_RETURN inbounds, and native RUNE MsgDeposit.
---

# cross-chain-swap

Swap one coin for another through **THORChain**, and register/alias a **THORName**,
keeping the blocktools sealed-boundary wallet discipline: build the unsigned tx,
DECODE and VERIFY it offline, sign it sealed behind a typed code, then broadcast
from the host. blocktools has no network. SwapChan (and/or a THORChain node) is
the eyes on the network; blocktools is the hands on the keys.

## Mental model: a THORChain swap is a send + a memo

A THORChain swap is not an exchange call. It is **sending your input asset to the
current THORChain inbound vault with a MEMO that encodes the swap**. The memo is
the instruction; the network reads it and pays the destination asset out on its
own chain. The shape depends on the input chain:

- **EVM chain** (BNB, Ethereum, Avalanche, ...) → a `depositWithExpiry` contract
  call to the THORChain **router**: `router.depositWithExpiry(vault, asset,
  amount, memo, expiry)`. For an ERC-20 you first `approve` the router, then
  deposit. See `recipes/thorchain-swap-evm.md`.
- **UTXO chain** (DOGE, LTC, BCH, BTC) → a normal send to the vault with the memo
  in a zero-value `OP_RETURN` output, in THORChain's inbound order
  `[vault, change, OP_RETURN memo]`. See `recipes/thorchain-swap-utxo.md`.
- **Native RUNE action** (swap-from-RUNE, THORName, liquidity) → a Cosmos
  `MsgDeposit` of RUNE whose memo carries the action: `acct-tx --chain rune`.
  See `recipes/chain-thorchain.md`.

Swap memo grammar (UTXO/short form): `=:ASSET:DEST:LIMIT[/...][:AFFILIATE:FEE]`
— e.g. `=:ETH.ETH:0xADDR:0` or `=:r:thor1...` (RUNE). A THORName action memo is
`~:NAME:CHAIN:...` (see below).

## The two dangers unique to swaps

Both silently lose funds. blocktools `verify` + `--expect-memo` is the guard; use it.

1. **Rotated / stale vault.** THORChain inbound vaults **ROTATE**. You must
   re-fetch the current `inbound_address` / `router` **before every swap** — from
   a fresh THORChain quote (`/thorchain/quote/swap`) or SwapChan. A vault address
   reused from an earlier swap can be retired, and coin sent there is gone. Verify
   the recipient against the vault the *current* quote named: `tx-verify
   --expect-to VAULT` (UTXO) / `--expect-to ROUTER` (EVM).
2. **Wrong memo.** One wrong byte in the memo — wrong destination, wrong asset,
   dropped limit — and the network cannot route it; funds are lost or refunded at
   best. The memo must be checked **byte-for-byte**. `tx-sign --expect-memo` (and
   `tx-verify --expect-memo` / `acct-tx sign --expect-memo`) refuse to sign unless
   the memo in the tx equals yours exactly, and print it on `/dev/tty` so you
   confirm before typing the code.

## Division of trust

| Step | Who | Tooling |
|------|-----|---------|
| quote → current vault, router, memo, expiry | **host / network** | SwapChan `get_quote` / `compare_routes`, or `rpc NODE /thorchain/quote/swap?...` |
| build the UNSIGNED tx + a `verify_tx` summary | **SwapChan** (keyless) | `build_swap_tx`, `verify_tx` |
| independently DECODE & VERIFY (right vault, right memo, right amount, fee cap) | **blocktools** (offline) | `abi-decode` / `tx-envelope verify_thor_send` / `tx-verify` / `acct-tx decode` |
| sign (sealed, typed-code, memo shown) | **blocktools** (sealed) | `tx-sign` / `acct-tx sign` with `--expect-to` + `--expect-memo` |
| broadcast | **host / network** | `tx-broadcast` / `rpc NODE /cosmos/tx/v1beta1/txs` |

SwapChan builds; blocktools **does not trust SwapChan's summary** — it decodes the
raw unsigned tx itself and re-derives the vault, memo, amount and fee cap. **Human
or agent sign-off on EVERY tx**, one at a time; no blanket approval. Verify before
sign: expected recipient = the vault/router the *current* quote names, memo exact.
Signing is sealed — never `./blocktools reveal`. Quote, vault-fetch and broadcast
are ordinary host/network steps.

## Skeleton 1 — EVM token into a swap (approve + depositWithExpiry)

Quote gives `router`, `inbound_address` (vault), `memo`, `expiry`. Decode the
deposit calldata offline and confirm the vault, the exact amount, and the memo's
destination before you sign anything:

```
abi-decode --sig 'depositWithExpiry(address,address,uint256,string,uint256)' 0xDEPOSIT_CALLDATA
```

Approve the router, then deposit. Both are contract calls, so blocktools refuses
them unless a `--policy` `allow_calls` entry authorizes exactly that `(to,
selector)` — `(token, 0x095ea7b3)` for the approve, `(router, 0x44bc937b)` for
the deposit:

```
tx-build --chain eth --chain-id 56 --nonce 1 --max-fee-per-gas 1000000000 \
  --priority-fee 1000000000 --gas 250000 --to ROUTER --data 0xDEPOSIT_CALLDATA \
  | tx-verify --chain-id 56 --expect-to ROUTER --policy /in/thor-deposit-policy.json
tx-sign --tx deposit.json --chain-id 56 --expect-to ROUTER \
  --policy /in/thor-deposit-policy.json < key
tx-broadcast --chain eth --url NODE < deposit.signed
```

Wait for the approve to confirm before the deposit (it reverts until then, so set
gas generously, ~120k–250k). The EVM side shows only the token leaving; the
destination asset arrives on its own chain — expected, not a failure. Full flow and
the policy JSON: `recipes/thorchain-swap-evm.md`.

## Skeleton 2 — UTXO coin into a swap (vault + change + OP_RETURN memo)

Quote gives `inbound_address` (vault) and `memo`. Build, verify the THORChain
shape, verify the policy, then sign with the memo shown:

```
tx-build --chain doge --utxos /in/u-doge.json --to VAULT --send AMOUNT \
  --change YOUR_ADDR --fee-rate RATE --memo '=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu' > inbound.json

tx-envelope --json '{"op":"verify_thor_send","chain":"doge","tx":"'"$(jq -r .psbt inbound.json)"'","vault":"VAULT","memo":"=:r:thor1...","amount":"AMOUNT","change":"YOUR_ADDR","taker":"YOUR_ADDR"}'

tx-verify --chain doge --expect-to VAULT --change YOUR_ADDR \
  --expect-memo '=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu'

tx-sign --tx inbound.json --chain doge --expect-to VAULT --change YOUR_ADDR \
  --expect-memo '=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu' < key   # memo shown; type the code
tx-broadcast --chain doge --url NODE < inbound.signed
```

`verify_thor_send` enforces the exact `[vault, optional change, OP_RETURN memo]`
shape, non-RBF, proven input values and a fee cap. A second `OP_RETURN`, an
`OP_RETURN` carrying value, or a memo that differs from `--expect-memo` by one
byte is refused. Memo is capped at the chain's relay limit (BCH 220 bytes, else
80). Full flow: `recipes/thorchain-swap-utxo.md`.

## Skeleton 3 — native RUNE MsgDeposit / THORName (acct-tx --chain rune)

A swap-from-RUNE or a THORName action is a `MsgDeposit` of RUNE carrying the memo
(`thorchain-1`, SIGN_MODE_DIRECT, secp256k1, signer `thor1...`). Fetch
`account_number`/`sequence` from a node first (blocktools has no network). Amounts
are RUNE base units (1 RUNE = 1e8). THORName memos:

```
register 1 year:   ~:NAME:THOR:OWNER_thor1:OWNER_thor1:PREFERRED_ASSET
add/replace alias: ~:NAME:CHAIN:ADDRESS            (CHAIN = ETH, BTC, BSC, ...)
```

```
acct-tx build --chain rune --from thor1... --pubkey HEX33 --amount 1105120000 \
  --memo '~:swapchan:THOR:thor1...:thor1...:ETH.ETH' --sequence 0 --account-number N > reg.json
acct-tx decode --chain rune < reg.json                                  # public round-trip
acct-tx sign   --chain rune --tx reg.json \
  --expect-memo '~:swapchan:THOR:thor1...:thor1...:ETH.ETH' < thor-key.hex > reg.signed   # memo shown; type the code
```

Broadcast `reg.signed`'s `signed` (base64 TxRaw) as `tx_bytes`; simulate first so
a malformed deposit is rejected before any RUNE moves:

```
rpc NODE /cosmos/tx/v1beta1/simulate '{"tx_bytes":"<base64>"}'          # gas_used, no error = valid
rpc NODE /cosmos/tx/v1beta1/txs '{"tx_bytes":"<base64>","mode":"BROADCAST_MODE_SYNC"}'   # code 0 = accepted
```

`PREFERRED_ASSET` (e.g. `ETH.ETH`) is what affiliate fees auto-swap to; add the
matching chain alias (`~:NAME:ETH:0xYOUR_EVM_ADDRESS`, next sequence) to receive
on that chain. Gas is not priced by THORChain (default limit 20000000). Full flow:
`recipes/thorchain-thorname.md`; the MsgDeposit itself: `recipes/chain-thorchain.md`.

## Notes

- Re-fetch the vault/router per swap; never reuse a stale one.
- Track the cross-chain leg at `/thorchain/tx/status/<inbound-hash>`; your input
  chain only shows the coin leaving to the vault.
- An EVM simulation shows only the token leaving — that is expected for a
  cross-chain swap, not a revert.
- Signing is sealed and gated by a typed code with the memo on screen. Never
  `./blocktools reveal`.

## See also

- `send-and-sign` — the build → verify → sign-sealed → broadcast pattern these
  swaps are built on.
- `evm-contracts` — the `tx-build --data` + `--policy allow_calls` path the EVM
  deposit uses.
- `recipes/thorchain-swap-evm.md`, `recipes/thorchain-swap-utxo.md`,
  `recipes/thorchain-thorname.md`, `recipes/chain-thorchain.md`,
  `recipes/chain-cosmos.md` — the full worked flows.
- `man/man1/acct-tx.1`, `man/man1/tx-build.1`, `man/man1/tx-verify.1`,
  `man/man1/tx-sign.1` — the tool flags (`--expect-memo`, `verify_thor_send`).
