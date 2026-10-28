---
name: smart-wallet
description: >-
  Turn blocktools into a self-custody crypto wallet you drive from the command
  line, offline. Use when the user wants to install blocktools, or to hold keys,
  check a balance, send or swap coins, call a contract, sign a message, or
  recover an old wallet — on Bitcoin and forks, Ethereum and EVM chains, Solana,
  Tron, XRP, Cosmos/THORChain, Cardano, Polkadot, TON, Stellar, Algorand, Monero,
  Zcash and ~25 legacy coins. This is the entry point: it installs the tools and
  routes to the task-specific skills (wallet-keys, send-and-sign, evm-contracts,
  cross-chain-swap, recover-funds). blocktools never holds keys and never
  broadcasts on its own; it builds and signs transactions and you verify every one.
---

# blocktools as a smart wallet

blocktools is a set of small Rust **Unix filters** — one JSON object per line on
stdin/stdout — that you chain into pipelines to recover keys, derive addresses,
and **build, verify, and sign transactions offline**. There is no daemon, no
account, no stored key. You are the wallet; the tools are the primitives.

> ⚠️ **Dangerous by nature.** These tools open hostile wallet files, extract
> secrets, and sign transactions. Used wrong they *destroy money*: signing to the
> wrong address, paying a huge fee, sending on the wrong chain, leaking a key.
> **You verify every transaction before it is signed, and verify again before it
> is broadcast.** The tests are evidence, not a substitute for your own review.
> Read `docs/SECURITY.md` before trusting it with real funds.

## The one rule that makes it a wallet: the sealed boundary

Anything that touches a secret (a seed, a key, a password, an encrypted wallet
file) runs **sealed and offline**. The `./blocktools run '<pipeline>'` wrapper
executes the pipeline in a container with `--network none`, a read-only root
filesystem, all capabilities dropped, a non-root user, and memory/pid limits.
Its stdout passes through `sealed-run agent`, which replaces every key field with
`[REDACTED]` and drops any line that fails its leak check. So what crosses the
boundary back to you — or to an AI agent driving the wallet — is **addresses,
derivation paths, unsigned/signed transaction bytes, and statuses only, never a
key**.

- `./in` is mounted read-only at `/in` (put wallet files here); `./secrets` at
  `/secrets` (passwords, one per file). `BLOCKTOOLS_IN` / `BLOCKTOOLS_SECRETS`
  move them.
- `./blocktools reveal` is the human-only escape hatch: it needs a real terminal
  and a typed code, then prints real keys. An agent must **never** need it.
- **Network tools run on the host, after the sealed steps**, never inside the
  seal: `utxo-fetch` (pull UTXOs), `tx-broadcast` (send a signed tx), `rpc` (node
  RPC). `sealed-run` refuses them (status `unsupported`, exit 2).

Honest status (do not overstate to the user): the sealed container flags are
checked by `scripts/sealed-check.sh` on Linux Docker only; the macOS sealed path
and `./blocktools reveal` under Docker on a real terminal are **not yet tested**.
Without Docker, `sealed-run agent '<pipeline>'` gives the same output redaction
but **no container isolation** — use it only on an already-offline machine.

## Install

Pick one. Releases are built for **Linux x86_64** only; on macOS, Windows, or ARM,
build from source.

**Debian / Ubuntu (apt, amd64)** — needs glibc 2.34+ (Debian 12, Ubuntu 22.04+);
the sealed `sealed-run` needs glibc 2.39+ (Ubuntu 24.04):

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo wget -O /etc/apt/keyrings/blocktools-archive-keyring.asc \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/apt/blocktools-archive-keyring.asc
echo "deb [signed-by=/etc/apt/keyrings/blocktools-archive-keyring.asc] https://tsavo.github.io/blocktools/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/blocktools.list
sudo apt update && sudo apt install blocktools
```

**Alpine (apk, x86_64)** — static musl binaries:

```sh
wget -O /etc/apk/keys/blocktools@tsavo-2026.rsa.pub \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub
echo https://tsavo.github.io/blocktools/alpine >> /etc/apk/repositories
apk update && apk add blocktools
```

**Release tarball (Linux x86_64)** — always verify the checksum; an archive that
fails `sha256sum -c` must not be run:

```sh
gh release download v0.1.0 -R TSavo/blocktools    # or download from the Releases page
sha256sum -c SHA256SUMS                           # must print: ...-linux-x86_64.tar.gz: OK
tar xzf blocktools-v0.1.0-linux-x86_64.tar.gz && cd blocktools-v0.1.0-linux-x86_64
export PATH=$PWD/bin:$PATH MANPATH=$PWD/share/man:
man blocktools
```

**From source (any platform with a Rust toolchain):**

```sh
git clone https://github.com/TSavo/blocktools && cd blocktools
cargo build --locked --release --workspace        # tools land in target/release/
```

**The sealed image** (needed for `./blocktools run`; needs a *local* Docker host —
the wrapper refuses an `ssh://`/`tcp://` engine unless `BLOCKTOOLS_ALLOW_REMOTE=1`):

```sh
./blocktools build                                 # builds image blocktools:local
./blocktools run 'seed-to-master < /in/seed.txt | derive --chain btc --count 1'
```

Verify the install: `man blocktools` lists every tool; `./blocktools run
'classify /in/<file>'` names an unknown wallet file.

## Common tasks (copy, run)

Put the wallet/seed in `./in` and any password in `./secrets`. These are the
everyday asks; each links to the skill and recipe with the full story.

**Get the balance of a wallet.** Runs the right reader, keeps public addresses
only, asks the chain (Esplora for btc/ltc/doge, JSON-RPC for eth). Exit 0 = funds
found, 4 = nothing, 3 = no balance lookup for that chain:

```sh
recipes/recover.sh /in/seed.txt - --goal balance        # add --count 50 to look at more addresses
```

Balance lookups are built only for **btc/ltc/doge and eth**. Tron, Solana, XRP,
Qtum, old coins, and Monero have none here — each chain's recipe says what to do
instead. → skill **wallet-keys** (to list the addresses), **send-and-sign**.

**Find all the coins on a wallet.** List the addresses this wallet controls on
each chain, then check balances where a lookup exists:

```sh
./blocktools run 'seed-to-master < /in/seed.txt | derive --chain btc --count 20 --public-only' | redact
./blocktools run 'seed-to-master < /in/seed.txt | derive --chain eth --count 20 --public-only' | redact
```

For a *cross-chain* sweep of forgotten/unclaimed money (old DeFi contracts,
airdrops, dust across 20+ chains and L2s), that discovery job is the companion
**SwapChan** service (`find_money` on a wallet address) — blocktools then verifies
and signs whatever claim/withdraw tx it builds. → skill **cross-chain-swap**.

**Send from a wallet to an address (sweep everything to DEST).** `classify` picks
the reader, funded outputs come back from the chain, `tx-build --sweep` makes an
**unsigned** PSBT, `tx-decode --text` shows it, `tx-sign --expect-to DEST`
re-checks the destination, and `tx-broadcast` sends it — each signing/broadcast
step shows the decoded tx and waits for a typed confirmation code (so this flow
needs a real terminal; a wrong code aborts with nothing sent):

```sh
recipes/recover.sh in/WALLET DEST --chain btc [--password-file secrets/pw] [--fee-rate N]
```

For an **agent-driven** send (explicit build → verify → sign → broadcast with a
policy file as the gate, no interactive codes), → skill **send-and-sign**. A
watch-only input (xpub/address) is refused for a send (exit 3).

**Do a swap (one coin → another, across chains).** SwapChan builds the unsigned
swap tx and a quote; blocktools independently verifies the vault, memo, amount and
fee cap, then signs it sealed; a relay broadcasts it. → skill
**cross-chain-swap** (THORChain swaps and THORName).

> Honest note: a live-network sweep by `recover.sh` is **untested** (the e2e test
> drives the whole flow against a `127.0.0.1` mock chain with the confirmation
> codes typed by a harness). Verify every decoded transaction yourself before you
> type a code. See `recipes/goal-verify-and-offline.md`.

## The whole wallet is four moves

You do not need a recipe memorized for every task. A smart wallet is the
composition of four independent primitives; give an agent these and it can *figure
out* how to check a balance, find every coin, send, swap, or sweep a recovered
wallet by chaining them. Keep them separate — each has a different input, a
different trust level, and a different place it runs — and let **verify** sit
between them. Nothing crosses a boundary you have not read.

**1. Wallet → chain state** (read). This is two halves, and the first half is the
hard one.

*1a. Wallet → addresses.* "My wallet" is any of ~60 things — a bare address, an
xpub/ypub/zpub, a seed phrase, a keystore, a `wallet.dat`, an Electrum file, a raw
key or WIF, a brainwallet, an xprv — and each must be turned into **the set of
addresses to query** before you can read anything. The combinatorics are the
whole problem: input format × chain × script type (legacy / wrapped-segwit /
native-segwit / taproot) × derivation scheme (BIP44/49/84/86, Electrum, old
paths) × gap limit. Get any of them wrong and **you silently miss the money** —
the coins are there, you just asked about the wrong addresses. **`derive` is the engine for this half** — it
walks the script types, schemes and gap limits and emits the address set;
`classify` names an unknown input, `seed-to-master` / the format openers /
`xpub-addresses` feed it, and `recipes/recover.sh` auto-routes the ~60 forms. This
half is **public-only** — no private key — so it runs on the host (or sealed for an
encrypted file, with only addresses crossing back).

At the limit, you don't even know *which* phrase or path is the wallet — then 1a
becomes a **search** over the candidate space: `phrase-to-key` / `pw-candidates`
expand what the user half-remembers, and `wallet-finder` tests every candidate
against an offline `utxo-set` dump (hits print phrase, scheme, address and
balance, never a key). Same move — secret → addresses → funded? — just enumerated.

*1b. Addresses → state.* Now ask the chain what those addresses hold: balance and
unspent outputs for a UTXO chain, the account's nonce, token balances and gas for
an EVM chain, the sequence/account number for an account chain, the *current*
THORChain inbound vault for a swap. **`rpc` is how you get data out of the chain** —
one host-side pipe filter that speaks to EVM nodes, bitcoind and forks, Solana,
Tron, Cosmos LCD, Esplora and Blockbook, and that **refuses any key-export,
unlock, or signing method by default**, so a read is only ever a read
(`docs/RPC.md`). (`utxo-fetch` is the UTXO-specific convenience on top of it.)

**Point `rpc --url` at the user's own node.** This is the whole game for people who
run their own infrastructure: an old `feathercoind` (or any bitcoind fork) still
running in a corner, or a full, up-to-date Ethereum node. `rpc` talks straight to
it — `getbalance` / `listunspent` on the fork, `eth_getBalance` / the account
nonce on the ETH node. For an obscure old coin with *no* public indexer, that
local daemon is the **only** way to read its state; for ETH it's the private,
authoritative one. Everything downstream is only as good as this read, so re-read
right before you build — a stale vault or nonce is how money is lost. This is a
**host** step, never inside the seal, and it needs no key.
   → skills **send-and-sign**, **evm-contracts**, **cross-chain-swap**

**2. Chain state → transaction** (build the *unsigned* tx). Combine the state from
move 1 with your intent — recipient, amount, memo, fee — into **unsigned**
transaction bytes. No key is involved, so this runs anywhere; `tx-build` /
`acct-tx` / `xrp-tx` / `sol-tron-tx` (and, soon, the unified `tx-plan`).
   → skills **send-and-sign**, **evm-contracts**, **cross-chain-swap**

**3. Secret → signed transaction** (recovery material → key → signature,
**sealed**). Take whatever secret you hold — a recovery phrase, a keystore, an old
wallet file, a raw key — turn it into the master secret, derive the private key
for the right path, and sign the unsigned tx from move 2. This whole move runs
**inside the seal** (`./blocktools run`): the key is re-derived and piped straight
into `tx-sign` / the account signer, never written to disk, and what comes back
out is the *signed transaction bytes*, never the key. (This is also the move that
turns a recovered wallet into a spendable one — recovery *is* the secret side.)
   → skills **wallet-keys** (seed/key you have), **recover-funds** (old/damaged/
   forgotten wallet)

**4. Signed transaction → network** (broadcast). Get the signed bytes onto the
chain — and you broadcast through **the same node you read in move 1**: `rpc
--url <their-node>` running `sendrawtransaction` on a bitcoind fork or
`eth_sendRawTransaction` on an ETH node (`tx-broadcast` wraps this for the common
chains; a THORChain swap just broadcasts the source-chain deposit and the network
relays the rest). For an old self-hosted fork, that local daemon is the only path
*out* just as it was the only path *in*. This is a **host** step, after the seal;
decode and verify the *signed* tx one last time before it goes.
   → skills **send-and-sign** (and each chain recipe names its broadcast path)

**Verify is the glue.** Between move 2 and move 3, decode the unsigned bytes and
check them against intent — recipient, amount, fee cap, chain id, memo — with a
policy file (`docs/POLICY.md`) as a hard gate. Between move 3 and move 4, decode
the signed tx and check it again. **Never sign, and never broadcast, bytes you
have not decoded and compared to what you meant.** That is the entire safety
story; everything else is detail.

Read this way, the common tasks above are just subsets of the four moves: *balance*
is move 1 alone; *find all the coins* is move 1 over many derived addresses; *send*
is 1→2→3→4; *recover and sweep* is move 3 (recover the secret) then 1→2→3→4; *swap*
is 1→2→3→4 where move 1 also fetches the vault and move 2 attaches the memo.

## Two worked examples (the four moves, end to end)

### Sweep: move everything from a recovered wallet to DEST

The one-liner wraps all four moves (`recipes/goal-sweep.md`); it needs a real
terminal because moves 3 and 4 each show the decoded tx and wait for a typed code:

```sh
recipes/recover.sh in/WALLET DEST --chain btc [--password-file secrets/pw] [--fee-rate N]
```

What it is doing, move by move:

1. **Read** — `classify` picks the reader for `WALLET`; `derive --public-only`
   lists the addresses; the chain returns the funded UTXOs (public addresses only
   leave the sealed step).
2. **Build** — `tx-build --sweep` makes an **unsigned** PSBT spending those UTXOs
   to `DEST`.
3. **Verify + sign (sealed)** — `tx-decode --text` shows the PSBT; `tx-sign
   --expect-to DEST` re-checks the destination, re-derives the key *inside the
   seal* (never to disk), prints the decoded tx, and waits for your code.
4. **Broadcast** — `tx-broadcast` shows it once more and sends on your second code.

A watch-only input (xpub/address, no key) is refused (exit 3). A live-network
sweep by this script is **untested** — verify every decoded tx before you type a
code.

### Swap: BTC → ETH across chains via THORChain

A swap is the same four moves; the chain-crossing is done *by THORChain* once your
deposit lands, so from the wallet's side it is just "send to the vault with the
right memo." Full flow and exact flags: `recipes/thorchain-swap-utxo.md`.

1. **Read** — fetch the **current** THORChain inbound vault and the swap quote
   (`rpc` against the THORChain inbound-addresses endpoint), and your BTC UTXOs.
   *The vault rotates — a stale one burns the funds, so read it fresh every time.*
2. **Build** — `tx-build` a normal BTC send **to that vault**, carrying the swap
   as an OP_RETURN memo (`--op-return`), e.g. `=:ETH.ETH:<your-eth-address>:<limit>`
   — the memo is what tells THORChain what to swap into and where to deliver it.
   Output is unsigned.
3. **Verify + sign (sealed)** — verify the vault, memo and amount with the
   THORChain check (`tx-envelope verify_thor_send`, memo matched exactly via
   `--expect-memo`); then `tx-sign` inside the seal. *The two silent money-losers
   are a rotated vault and a byte-wrong memo — this step is the guard.*
4. **Broadcast** — `tx-broadcast` the signed BTC tx. THORChain observes the
   deposit, performs the cross-chain swap, and pays ETH to your address; track it
   by the swap's outbound.

(On an EVM source chain the deposit is a `depositWithExpiry` contract call to the
router instead of an OP_RETURN send; on native RUNE it is an `acct-tx --chain rune`
MsgDeposit. Same four moves — see `recipes/thorchain-swap-evm.md` and the
**cross-chain-swap** skill.)

### A full journey: old LTC in a JSON wallet → USDC in a fresh ETH wallet

"I have a bunch of old LTC in a JSON wallet. Make a new ETH wallet, send it there
as USDC." One sentence, four skills, and a boundary worth knowing:

1. **Recover the LTC secret** (skill **recover-funds**; the secret side of move 3).
   `classify /in/wallet.json` names the format, the matching opener (sealed) yields
   the master, `derive --chain ltc --public-only` lists the LTC addresses. The key
   never leaves the seal.
2. **Read the LTC state** (move 1). `rpc` / `utxo-fetch` against those addresses
   returns the UTXOs — confirm there really is "a bunch" before building anything.
3. **Mint the new ETH wallet** (skill **wallet-keys**). blocktools makes it:
   `new-seed --words 24 | seed-to-master | derive --chain eth --count 1` generates
   a fresh BIP39 mnemonic from the OS CSPRNG and derives its ETH address. The
   mnemonic is a secret — it comes back `[REDACTED]` to an agent (the address in
   clear), and is revealed to a *human* to write down and back up via
   `./blocktools reveal`. Good practice before you fund it: prove the address
   derives from the secret you just generated.
4. **One swap plan: LTC → USDC, to that address** (skill **cross-chain-swap**).
   THORChain collapses the cross-chain leg, so this is a *single* plan, not a
   chain: move 1 reads the current LTC inbound vault; move 2 builds an LTC send to
   that vault with the memo `=:ETH.USDC-0x…:0xNEWADDR:<limit>` (the exact
   `ETH.USDC-0x…` asset id comes from the quote); move 3 verifies vault + memo +
   amount and signs sealed with the *recovered LTC* key; move 4 broadcasts the LTC
   deposit and THORChain pays USDC to the new ETH address.

The lesson the journey teaches: the wallet **recovers, mints and signs** — one tool
chain turns an old JSON file into recovered LTC and a fresh mnemonic into a new ETH
destination, and the cross-chain delivery is a single plan because THORChain does
the far leg. (If the target asset had no direct route, step 4 would become a
dependent chain of plans — see **cross-chain-swap**.)

### Many chains → one asset: a series of transactions

"Sweep my DOGE, LTC and BTC all into Ethereum" has no single transaction that does
it. **It is a series** — one independent swap per source chain, each the full four
moves, each delivering to the same ETH address:

```
plan 1:  DOGE → ETH.ETH:<your-eth-address>     (read DOGE vault+UTXOs → build → sign → broadcast)
plan 2:  LTC  → ETH.ETH:<your-eth-address>     (read LTC  vault+UTXOs → build → sign → broadcast)
plan 3:  BTC  → ETH.ETH:<your-eth-address>     (read BTC  vault+UTXOs → build → sign → broadcast)
```

This is the core idea the wallet runs on: **a wallet action is a list of plans,
and you execute each plan through the same four moves.** The three here are
independent — different source chains, different vaults, different UTXO sets, their
own fees — so each gets its *own* move-1 read (every vault fetched fresh) and its
*own* move-3 verify (every memo `=:ETH.ETH:<addr>:<limit>` checked byte-for-byte).
Because they're independent you can run them in parallel; they all converge as ETH
at one address once THORChain settles each deposit.

Three things follow, and the skill must teach all three:

- **Decompose by source.** A multi-asset or multi-chain goal splits into one plan
  per (source asset, source chain). There is no combined signature across chains —
  each chain signs with its own key, in its own move 3.
- **Each plan is the four moves, in full.** No shortcut skips the per-chain read or
  the per-chain verify; a shared destination does not mean a shared vault or memo.
- **Keep the plans explicit as a list.** The coming `tx-plan` tool makes this first
  class — a chain of plans across chains that you resolve, verify, sign and
  broadcast one by one — but the idea holds today with the per-chain build tools:
  loop the four moves over your list of source assets.

A recovered wallet that holds coins on several chains is the same shape: move 3
recovers the one secret, then you emit one plan per chain it has a balance on.

## The tools, placed by move

There are ~50 tools; this is how to not get lost in them. Every tool belongs to a
move (or to verify, the glue). When you reach for one, know which move you're in
and where it runs.

| Move | Tools | Runs |
|---|---|---|
| **mint — a new wallet** | `new-seed` (fresh BIP39 mnemonic → `seed-to-master` → `derive`) | **sealed**; mnemonic `[REDACTED]` to agents, revealed to a human to back up |
| **1 read — wallet → addresses** | `classify`, `derive`, `seed-to-master`, `key-to-addresses`, `xpub-addresses`, `phrase-to-key`, `pw-candidates`, `seed-repair`, the openers (`dat-read`, `electrum-read`, `armory-read`, `multibit-read`, `keystore-open`, `bip38-open`, `blockchain-read`, `read-file`), `wallet-finder` + `utxo-set`, `recover.sh` | public-only; host, or sealed for an encrypted file |
| **1 read — addresses → state** | `rpc`, `utxo-fetch` | host (deny-by-default on sign/unlock) |
| **2 build** | `tx-build`, `acct-tx`, `xrp-tx`, `sol-tron-tx`, `abi-encode`, `tx-envelope` (and the coming `tx-plan`) | anywhere; no key |
| **3 sign** | `tx-sign`, `acct-tx`/`xrp-tx`/`sol-tron-tx` (sign mode), `msg-sign` | **sealed**, offline |
| **4 broadcast** | `tx-broadcast`, `rpc` | host |
| **verify (glue)** | `tx-verify`, `tx-decode`, `abi-decode`, `abi-inspect`, `sig-hash`, `bytecode-inspect`, `log-decode`, `create-address`, `typed-data-verify`, `msg-verify`, `contract-call`/`contract-trace` (read) | read-only; host or sealed |

## Where to go next (router)

| The user wants to… | Skill |
|---|---|
| Get addresses from a seed/key/xprv/wallet file; prove they control an address | **wallet-keys** |
| Send / pay / transfer a coin on any chain; build-verify-sign-broadcast | **send-and-sign** |
| Call or deploy an EVM contract; decode calldata, logs, reverts, typed data | **evm-contracts** |
| Swap one coin for another across chains (THORChain); register a THORName | **cross-chain-swap** |
| Recover an old, forgotten, or damaged wallet; find which phrase is funded | **recover-funds** |

Underneath the skills, the repo's own references are authoritative and CI-tested:

- **Recipes** (`recipes/`) — executable, by input / chain / goal; every tested
  example is run verbatim in CI. Start at `recipes/README.md`; the index by
  wallet/chain/goal is `docs/cookbook.md`.
- **Man pages** (`man/`) — generated from each tool's `--help`; CI fails if stale.
  `man -l man/man7/blocktools.7` is the tool overview.
- **Chains** (`docs/CHAINS.md`), **policy files** (`docs/POLICY.md`), **refusal
  codes** (`docs/REFUSALS.md`), **exit codes** (`docs/EXIT-CODES.md`), **RPC**
  (`docs/RPC.md`).

> Forward note: a `tx-plan` tool (the `blocktools-plan` crate) is landing that
> unifies step 2 — it builds any transaction, on any of the three chain families,
> from one declarative plan, and feeds the same verify/sign path. Until it ships,
> use the per-chain build tools the skills name (`tx-build`, `acct-tx`, `xrp-tx`,
> `sol-tron-tx`). The verify-every-tx rule does not change.
