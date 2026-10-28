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

The whole wallet is **four moves** (see the `smart-wallet` hub): **1. wallet → chain state** (read),
**2. chain state → unsigned transaction** (build, no key), **3. secret → signed transaction** (sign,
sealed/offline), **4. signed transaction → network** (broadcast, host). This skill is **moves 2 → 3 →
4**, consuming the state that move 1 already read. Build the transaction unsigned (move 2), read
exactly what it does, sign it behind the sealed boundary with a human-typed code (move 3), read the
signed bytes again, and only then broadcast it through the user's own node (move 4). **Verify is the
glue** that sits between 2 → 3 and 3 → 4, with a policy file as the hard gate. Every tool is a small
Rust Unix filter that reads one JSON object (or hex) per line and prints a JSON status line; the last
line's `status` and exit code tell you what happened (`docs/EXIT-CODES.md`, `docs/REFUSALS.md`).

## Precondition: move 1 (read) via `rpc`

Moves 2 → 4 are useless without move 1's state. **`rpc` is how you get data out of the chain** —
balance and unspent outputs for a UTXO chain, the account's nonce/gas/`chain_id` for an EVM chain, the
sequence/account number for an account chain. **Point `rpc --url` at the user's OWN node**: an old
bitcoind fork still running in a corner, or a full Ethereum node. For an obscure coin with no public
indexer, that local daemon is the only way to read state; for ETH it is the private, authoritative
one. `utxo-fetch` is the UTXO-specific convenience on top of `rpc`; the worked pipelines below use it
to produce the UTXO/account files move 2 reads. This read is a **host** step and needs no key — and
re-read right before you build, because a stale nonce or UTXO set loses money. Deriving the addresses
to query (move 1a) is the `wallet-keys` skill. → hub skill **smart-wallet**, **wallet-keys**.

> DANGEROUS: used incorrectly (wrong address, huge fee, lost keys, wrong chain) you lose funds.
> Read and audit anything that signs before trusting it with real money. Unit tests are evidence,
> not a substitute for your own review.

## Move 3's sealed boundary (keys never cross)

Move 3 — **secret → signed transaction** — is the only move that touches a key, and it runs inside
`./blocktools run '<pipeline>'`, which executes offline with `--network none`: the key is derived and
piped straight into the signer in memory, never written to disk, and anything that looks like a key
comes back `[REDACTED]`. The host-side moves — move 1's `rpc`/`utxo-fetch` read and move 4's
`tx-broadcast` — are **not** in the sealed image; `sealed-run` refuses them, so they run on the host
and are given public data only (addresses, public keys, the signed transaction). `tx-sign` and the
account signers need a human to read a summary and type a code on `/dev/tty`; with no terminal they
abort and nothing is signed. Never run `./blocktools reveal` to print a key unless the user is the one
driving that step on their own machine. The secret that feeds move 3 comes from `wallet-keys` (a seed
or key you hold) or `recover-funds` (an old or damaged wallet).

## The core loop — moves 2 → 3 → 4, no exceptions

```
move 1 (read via rpc, host) -> move 2 build UNSIGNED -> VERIFY (decode + gate vs intent)
    -> move 3 sign (sealed, typed code) -> VERIFY the SIGNED bytes again
    -> move 4 broadcast (host, through the user's own node, second code)
```

1. **(move 1 — precondition)** The state is already read: the UTXO/nonce/account file from `rpc` /
   `utxo-fetch` against the user's own node. Re-read it if it may be stale.
2. **Build (move 2)** the unsigned transaction offline from that state and your intent — recipient,
   amount, memo, fee (`tx-build`, `acct-tx build`, `xrp-tx build`, `sol-tron-tx build --plan`). No key
   is involved and it never touches the network.
3. **Verify (glue, 2 → 3), decode the exact bytes you will sign:** `tx-decode --text` (or the
   builder's `decode` subcommand). Read every output address character by character against where you
   meant to send, the amount, the fee, and — for EVM — the chain id and token. Stop on any warning you
   do not understand. Then `tx-verify` as the hard gate with `--expect-to`, a fee cap, the chain id,
   and a `--policy` file: it exits 0 / `status: "ok"` only when every check passes; otherwise
   `failed`, exit 1. Do not proceed on a failure.
4. **Sign (move 3)** inside the seal (`tx-sign`, `acct-tx sign`, `xrp-tx sign`). It re-runs the checks,
   prints the decoded summary on your terminal, and only signs after the human types the code it shows.
5. **Verify (glue, 3 → 4), decode the signed output again** and confirm the outputs, fee, and (EVM)
   `from` match step 3.
6. **Broadcast (move 4)** on the host, through **the same node you read in move 1**: `tx-broadcast`
   wraps `sendrawtransaction` on a bitcoind fork or `eth_sendRawTransaction` on an ETH node, asks for a
   second typed code, and verifies the returned id equals the id it computed locally. For a self-hosted
   fork, that local daemon is the only path out, just as it was the only path in.

Never sign bytes you have not decoded and compared to intent.

## Thinking in plans (what a plain send actually is)

A send is the **general case** of the plan model that `cross-chain-swap` specializes.
Underneath the four moves is one object: the **plan**. A plan is *durable intent plus
assertions*, held apart from the *ephemeral chain state* it runs against. "Send 0.5
BTC to `bc1q…`, fee ≤ F" is the plan — and it is true no matter what today's UTXO set,
nonce or fee rate happens to be. The swap is only a plan whose move-2 build also
attaches a memo; strip the memo and the vault, and you are left with exactly this —
intent (`expect_to` the recipient, `expect_out` the amount, `cap_fee`) checked against
live state.

Read the four moves as operations on that one object:

- **The plan is durable intent + assertions.** Written once, before you touch the
  chain: *who* (`expect_to` — the recipient; for UTXO also the `change` address),
  *how much* (`expect_out` — the non-change amount), *what it may cost* (`cap_fee`),
  and, for EVM, the chain id and the token/call. These are the questions move 2 → 3's
  verify will ask; the plan is where their answers live.
- **Move 1 (`rpc`) supplies the ephemeral state.** The UTXO set, the account nonce and
  gas, the sequence/account number, the fee rate — the moving facts, read fresh from
  the user's own node. None of this belongs in the plan; it is what the plan is
  resolved *against*.
- **Move 2 resolves the plan against that state into unsigned bytes.** `tx-build` (or
  `acct-tx`/`xrp-tx`/`sol-tron-tx build`) takes the durable intent and the live state
  and produces one unsigned transaction — the plan made concrete for *this* UTXO set
  and *this* nonce. Resolve, don't author: the recipient and amount come from the plan,
  the inputs and fee arithmetic from the state.
- **Verify is the mechanical check, not a vibe check.** It asks exactly: *"does the
  resolved tx satisfy every assertion the plan declared?"* `tx-decode --text` lets you
  read it; `tx-verify --expect-to … --max-fee … --chain-id …` answers the question with
  an exit code. A swapped destination or an inflated fee is caught here precisely
  because the *intended* recipient and cap live in the plan and the resolved bytes are
  checked against them.
- **The policy file is that same check made a deny-by-default HARD GATE.** Everything
  in the plan — `allow_to`, `max_value`, `max_fee`, `chain_id`, `allow_tokens`,
  `allow_calls` — written to `docs/POLICY.md` form so a refusal, not your attention, is
  what stops a bad resolve. See the next section.

Two consequences you lean on the whole time:

- **Intent and state stay apart — never bake a live fact into the plan.** The nonce,
  the UTXO set and the fee rate move; the plan does not. So you **re-read (move 1) and
  re-resolve (move 2) every time**, and let verify reconcile the two right before the
  key touches anything. A plan that has yesterday's nonce frozen into it is not a plan,
  it is a stale transaction waiting to fail or double-spend.
- **The assertions are the plan's whole safety value.** A resolve with no assertions is
  just bytes; the `expect_to`/`expect_out`/`cap_fee` (and the policy that hardens them)
  are what make "verify" a question with a yes/no answer instead of a judgement call.

**Doctrine — CLIs are lib users.** `tx-build`, `tx-verify` and `tx-sign` are *thin
users* of one underlying transaction library: build resolves, verify checks assertions,
sign resolves-then-signs — three skins over the same resolve/assert core, which is why
the same `--expect-to`/`--max-fee`/`--chain-id`/`--policy` vocabulary runs through all
of them. `tx-plan` (the `blocktools-plan` crate) is the **declarative plan skin over that same
library**: one plan object — intent + assertions — that it resolves against move-1 state
and feeds down the identical verify/sign path, on any of the three chain families. It is
opt-in at signing: `tx-sign --plan FILE` (EVM/UTXO) derives the signer's guards from the
plan's assertions and signs **only if** the resolved tx satisfies them — the same check
`tx-plan check` runs, fail-closed — so a passing `tx-plan check` and what `tx-sign --plan`
enforces are the identical assertions by construction (`tx-verify --plan` reads the same
way). You can still write the plan by hand as the build flags plus the verify/policy
assertions; the model does not change, only how first-class the plan object is.

## The policy file is the hard gate between move 2 and move 3 (`docs/POLICY.md`)

A declarative JSON file turns verify — the glue between build (move 2) and sign (move 3) — from
advice into a refusal. `tx-verify --policy FILE` and
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

## Chain-family map (which tool does moves 2 build / 3 sign / 4 broadcast)

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

Each pipeline is the four moves end to end: `utxo-fetch`/`rpc` reads state from the user's node
(move 1), `tx-build` builds unsigned (move 2), `tx-decode`/`tx-verify` gate it, `./blocktools run ...
tx-sign` signs sealed (move 3), and `tx-broadcast` sends through that same node (move 4). Ground every
flag in the man pages and recipes; do not invent flags. Addresses below are public BIP/spec test
vectors.

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

- Hub: `smart-wallet` — the four moves (1 read, 2 build, 3 sign, 4 broadcast) this skill is 2 → 3 → 4
  of. Companion skills: `wallet-keys` (move 1a: derive addresses and open wallet files; and the move-3
  secret you hold), `evm-contracts` (move 2 for calldata, ABI, approvals, contract creation),
  `cross-chain-swap` (the same four moves where move 1 also fetches the vault and move 2 attaches the
  memo), `recover-funds` (recovers the move-3 secret from an old or damaged wallet).
- Authoritative sources: `recipes/goal-verify-and-offline.md`, `recipes/decode-a-transaction.md`,
  `recipes/goal-sweep.md`, the per-chain recipes (`recipes/chain-bitcoin.md`,
  `recipes/chain-ethereum.md`, `recipes/chain-cosmos.md`, `recipes/xrp.md`,
  `recipes/chain-solana.md`, `recipes/chain-tron.md`); `man/man1/tx-build.1`, `tx-verify.1`,
  `tx-sign.1`, `tx-broadcast.1`, `acct-tx.1`, `xrp-tx.1`, `sol-tron-tx.1`, `utxo-fetch.1`;
  `docs/POLICY.md`, `docs/EXIT-CODES.md`, `docs/REFUSALS.md`.
