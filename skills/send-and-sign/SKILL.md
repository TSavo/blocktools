---
name: send-and-sign
description: >-
  Use when the user wants to send, pay, transfer, or sweep a coin on any supported chain, or to
  sign and broadcast a transaction they have already prepared. Covers Bitcoin and its forks (LTC,
  DOGE, BCH, BSV, BTG, ZEC transparent, PoS coins), Ethereum and EVM chains, Cosmos/ATOM and other
  account chains (XLM, ALGO, TON), XRP, and Solana/Tron transfer building. Drives blocktools'
  build-unsigned -> decode and verify -> sign (sealed, behind a typed code) -> verify the signed
  bytes -> broadcast (host) loop, with an offline policy file as the hard gate. Triggers: "send
  BTC", "pay this address", "sweep my wallet to a new address", "move my ETH/USDT", "sign this
  PSBT", "broadcast my signed tx", "transfer ATOM/XRP". This is the core of the blocktools wallet.
---

# send-and-sign

Move a coin with blocktools by building the transaction unsigned, reading exactly what it does,
signing it behind the sealed boundary with a human-typed code, reading the signed bytes again, and
only then broadcasting on the host. Every tool is a small Rust Unix filter that reads one JSON
object (or hex) per line and prints a JSON status line; the last line's `status` and exit code tell
you what happened (`docs/EXIT-CODES.md`, `docs/REFUSALS.md`).

> DANGEROUS: used incorrectly (wrong address, huge fee, lost keys, wrong chain) you lose funds.
> Read and audit anything that signs before trusting it with real money. Unit tests are evidence,
> not a substitute for your own review.

## The sealed boundary (keys never cross)

Secrets run inside `./blocktools run '<pipeline>'`, which executes offline with `--network none`:
keys are derived and piped straight into the signer in memory, never written to disk, and anything
that looks like a key comes back `[REDACTED]`. Network tools — `utxo-fetch`, `tx-broadcast`, and any
RPC — are **not** in the sealed image; `sealed-run` refuses them, so they run on the host and are
given public data only (addresses, public keys, the signed transaction). `tx-sign` and the account
signers need a human to read a summary and type a code on `/dev/tty`; with no terminal they abort and
nothing is signed. Never run `./blocktools reveal` to print a key unless the user is the one driving
that step on their own machine.

## The core loop — no exceptions

```
keys (sealed) -> build UNSIGNED -> decode + verify against intent -> sign (sealed, typed code)
             -> decode + verify the SIGNED bytes again -> broadcast (host, second code)
```

1. **Build** the unsigned transaction offline from UTXO/nonce/account files and flags (`tx-build`,
   `acct-tx build`, `xrp-tx build`, `sol-tron-tx build --plan`). It never touches the network.
2. **Decode the exact bytes you will sign:** `tx-decode --text` (or the builder's `decode`
   subcommand). Read every output address character by character against where you meant to send,
   the amount, the fee, and — for EVM — the chain id and token. Stop on any warning you do not
   understand.
3. **Verify as a hard gate:** `tx-verify` with `--expect-to`, a fee cap, the chain id, and a
   `--policy` file. It exits 0 / `status: "ok"` only when every check passes; otherwise `failed`,
   exit 1. Do not proceed on a failure.
4. **Sign** inside the seal (`tx-sign`, `acct-tx sign`, `xrp-tx sign`). It re-runs the checks, prints
   the decoded summary on your terminal, and only signs after the human types the code it shows.
5. **Decode the signed output again** and confirm the outputs, fee, and (EVM) `from` match step 2.
6. **Broadcast** on the host (`tx-broadcast`), which asks for a second typed code and verifies the
   returned id equals the id it computed locally.

Never sign bytes you have not decoded and compared to intent.

## The policy file is the hard gate (`docs/POLICY.md`)

A declarative JSON file turns verify from advice into a refusal. `tx-verify --policy FILE` and
`tx-sign --policy FILE` check it **before** signing, and `tx-sign` checks it again on the signed
bytes. Deny by default: a chain with no entry is refused (`policy:no_rule_for_chain`). Unknown keys
are errors, so a typo cannot silently drop a rule. `tx-verify` reports the file's sha256 so you know
which policy made each decision. The file can only *add* refusals; base checks
(`no_replay_protection`, `has_warnings`, `fee_unknown`, ...) always apply.

```json
{"version": 1, "chains": {
  "btc": {"allow_to": ["bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"],
          "change": ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],
          "max_value": 5000000, "max_fee": 20000, "max_outputs": 2},
  "bsc": {"chain_id": 56, "allow_to": ["0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"],
          "max_value": "1000000000000000000",
          "allow_tokens": ["0x55d398326f99059fF775485246999027B3197955"],
          "allow_calls": [{"to": "0x111...", "selector": "0x095ea7b3"}]}
}}
```

Keys: `allow_to` (every non-change recipient), `change` (allowed, not counted toward `max_value`),
`max_value` (non-change output sum in sats, or EVM wei / token base units), `max_fee`, `max_outputs`,
`chain_id` (required and matched for EVM), `allow_tokens` (ERC-20 `transfer()` contracts),
`allow_calls` (other contract calls, as `{to, selector}`). A file-allowed contract call still needs
`--call SIGNATURE` (or `--abi FILE`) so the calldata decodes exactly; contract creation is approved
with `--create-hash KECCAK`, not the file.

## Chain-family map (which tool builds and signs)

| Family | Chains | Build / sign tools |
|---|---|---|
| UTXO | BTC and forks (LTC, DOGE, BCH, BSV, BTG), ZEC transparent (t1), PoS coins (PPC, NVC, CLAM, RDD) | `tx-build` -> `tx-verify` -> `tx-sign` -> `tx-broadcast` (PSBT; sweep fully built for btc/ltc/doge) |
| EVM | Ethereum and any EVM chain via `--chain-id` + RPC | `tx-build` (EIP-1559 or `--legacy`) -> `tx-verify --chain-id` -> `tx-sign` -> `tx-broadcast` |
| Account | ATOM / Cosmos Hub, XLM, ALGO, TON (ADA, DOT not built) | `acct-tx keys` / `build` / `decode` / `sign` (ATOM send built; broadcast not automated) |
| XRP | XRP Ledger | `xrp-tx keys` / `build` / `decode` / `sign` (submit the `tx_blob` yourself; not automated) |
| Solana / Tron | SOL, TRX/TRC-20 | `sol-tron-tx build --plan` / `decode` / `verify` builds and reads UNSIGNED only; **signing and broadcast NOT BUILT** — a human imports the key into the coin's own wallet |

Addresses are derived with `derive --chain <coin>` (via `seed-repair | seed-to-master`) or a key
reader; see the `wallet-keys` skill. Solana and Tron CLI can derive addresses and build/verify an
unsigned transfer, but cannot sign — do not promise an end-to-end send there.

## Worked pipelines

Ground every flag in the man pages and recipes; do not invent flags. Addresses below are public
BIP/spec test vectors.

### 1. Bitcoin sweep (UTXO) — `recipes/goal-sweep.md`, `recipes/chain-bitcoin.md`

```sh
# Host: public chain data for the funded addresses (writes UTXO lines tx-build reads).
utxo-fetch --chain btc bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 > utxos.jsonl

# Offline: build the UNSIGNED PSBT (fee-rate in sat/vB), then read it.
tx-build --chain btc --utxos utxos.jsonl \
    --to bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 --sweep --fee-rate 5 > unsigned.json
tx-decode --text < unsigned.json

# Hard gate: destination + fee cap + policy (a PSBT carries input amounts, so the fee is checkable).
tx-verify --expect-to bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 \
    --max-fee 20000 --policy policy.json < unsigned.json

# Sealed: derive the key and sign behind a typed code; keys arrive on stdin and never touch disk.
./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc \
    | tx-sign --tx /in/unsigned.json \
        --expect-to bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 \
        --max-fee 20000 --policy /in/policy.json' > signed.json

# Verify the SIGNED bytes again, then broadcast on the host (second typed code).
tx-decode --text < signed.json
tx-broadcast --chain btc < signed.json
```

### 2. ERC-20 transfer (EVM) — `recipes/chain-ethereum.md`

ERC-20 sends need native gas at the sending address; build a `--topup` first if it is dry. Pin the
chain id everywhere — an EVM tx with no chain id is replayable (`no_replay_protection`, refused).

```sh
# Host: account object (nonce, gas, chain_id) for the from address.
utxo-fetch --chain eth --url https://your-rpc 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 > acct.json

# Offline: build an EIP-1559 ERC-20 transfer (token amount in base units).
tx-build --chain eth --chain-id 1 --account acct.json --gas 60000 --max-fee-per-gas 2000000000 \
    --token 0x55d398326f99059fF775485246999027B3197955 --token-amount 1000000 \
    --to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF > unsigned.json
tx-decode --text < unsigned.json

# Gate: chain id + recipient + the token call must decode exactly, plus the policy file.
tx-verify --chain-id 1 --expect-to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF \
    --call 'transfer(address,uint256)' --policy policy.json < unsigned.json

# Sealed sign (typed code), then re-verify and broadcast on the host.
./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain eth \
    | tx-sign --tx /in/unsigned.json --chain-id 1 \
        --expect-to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF \
        --call "transfer(address,uint256)" --policy /in/policy.json' > signed.json
tx-decode --text < signed.json
tx-broadcast --chain eth --url https://your-rpc < signed.json
```

For a plain ETH send use `--send WEI` (or `--sweep [--balance WEI]`) and drop `--call`. For any other
contract call, pass `--call SIGNATURE` / `--abi FILE`; an unknown selector is refused
(`unknown_contract_call`). Contract creation uses `--create-hash KECCAK` instead of `--expect-to`.

### 3. Cosmos / ATOM transfer (account) — `recipes/chain-cosmos.md`

One bank `MsgSend` in `uatom`, `SIGN_MODE_DIRECT`. Gas is not estimated — pass `--gas` yourself
(200000 covers a plain send). Read `--pubkey` from `acct-tx keys` on your own machine (the sealed
boundary drops the 33-byte pubkey as secret-looking); that output is public only.

```sh
# Host: balance, account_number, sequence (and pubkey once the account has signed).
utxo-fetch --chain atom cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c > acct.json

# Build the unsigned SignDoc, then decode it (public fields only: from, to, amount, fee, signed=false).
acct-tx build --chain atom --from cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c \
    --pubkey 0279be667ef9dcbbac...1798 \
    --to cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys5 \
    --sweep --balance 1000000 --fee 5000 --gas 200000 --sequence 7 --account-number 123456 > u.json
acct-tx decode --chain atom < u.json

# Sealed sign: re-checks the destination and waits for a typed code on /dev/tty.
./blocktools run 'acct-tx sign --chain atom --tx /in/u.json \
    --expect-to cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys5 < /in/key.txt' > signed.json
```

`acct-tx decode` refuses any message that is not a single ATOM `MsgSend`, a from address that does
not match the signer key, extra coins, or timeout/granter/extension fields — it never silently drops
them. A missing memo is warned about (exchanges credit by memo). ATOM network submit is not
automated; broadcast `signed.json` with your own node.

### 4. XRP Payment sweep (account) — `recipes/xrp.md`

```sh
./blocktools run xrp-tx keys < seed.txt          # public: classic + X-address, public key
# Look up Balance and Sequence for the account on any rippled/Clio server (not automated).
./blocktools run xrp-tx build --account rYOUR... --to X7Acg...or_r... [--destination-tag N] \
    --sweep --balance DROPS [--reserve 1000000] --fee 12 --sequence N --last-ledger N > unsigned.json
./blocktools run xrp-tx decode < unsigned.json
./blocktools run xrp-tx sign --tx unsigned.json --expect-to X7Acg... < seed.txt > signed.json
# Submit signed.json's tx_blob with rippled `submit` (not automated).
```

The base reserve (default 1 XRP, `--reserve`) stays locked. A missing destination tag is warned
about; an X-address carries the tag and `build` refuses a conflicting `--destination-tag`. Only XRP
Payments are encoded — issued currencies and paths are refused.

## Refusals you will meet, and what they mean (`docs/REFUSALS.md`)

- `aborted` — no terminal or wrong code; nothing was signed. Run in a real terminal and type the code.
- `fee_unknown` / `input_amounts_unknown` — a raw UTXO tx carries no input amounts; verify the PSBT
  from `tx-build`, which does.
- `fee_above_cap` / `fee_over_10pct_of_inputs` — rebuild with a lower fee; raise `--max-fee` only if
  you truly meant to pay that much.
- `no_replay_protection` / `no_chain_id` / `chain_id_mismatch` / `chain_id_not_pinned` — always pass
  `--chain-id` and rebuild for the chain you meant.
- `token_call_not_transfer` / `unlimited_approve` — the calldata is an approval, not a send; it grants
  spending rights. Do not sign unless you set it up yourself.
- `unknown_contract_call` / `unknown_calldata` — blocktools cannot tell what it does; supply `--call`
  or do not sign.
- `unexpected_output` / `destination_not_expected` / `expected_destination_missing` — an address does
  not match `--expect-to`/`--change`; check it character by character, it may have been swapped.
- `input_without_key` — the key signs none of the inputs; supply the key for the address the coins
  are on.
- `eth_value_with_token_call` — a token transfer also sends ETH to the token contract; that ETH is
  lost. Rebuild with value 0.

Exit codes: `0` = ok/done/valid; `1` = failed / refused / aborted (and most refusals); `2` =
bad_input / unsupported. Measured on Linux; always read the last JSON status line.

## See also

- Companion skills: `wallet-keys` (derive addresses and open wallet files), `evm-contracts`
  (calldata, ABI, approvals, contract creation), `cross-chain-swap`.
- Authoritative sources: `recipes/goal-verify-and-offline.md`, `recipes/decode-a-transaction.md`,
  `recipes/goal-sweep.md`, the per-chain recipes (`recipes/chain-bitcoin.md`,
  `recipes/chain-ethereum.md`, `recipes/chain-cosmos.md`, `recipes/xrp.md`,
  `recipes/chain-solana.md`, `recipes/chain-tron.md`); `man/man1/tx-build.1`, `tx-verify.1`,
  `tx-sign.1`, `tx-broadcast.1`, `acct-tx.1`, `xrp-tx.1`, `sol-tron-tx.1`, `utxo-fetch.1`;
  `docs/POLICY.md`, `docs/EXIT-CODES.md`, `docs/REFUSALS.md`.
