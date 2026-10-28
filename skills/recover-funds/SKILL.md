---
name: recover-funds
description: >-
  Offline recovery of coins from an old, forgotten, damaged, or unknown wallet with blocktools
  (github.com/TSavo/blocktools). Use when the user has a wallet file they can't open or identify
  (Bitcoin Core wallet.dat, Electrum seed or wallet file, Armory .wallet, MultiBit/bitcoinj,
  Ethereum keystore or presale JSON, BIP38, blockchain.com backup, raw key or WIF, xprv), a seed
  phrase with a typo, a swapped pair, or one missing word, a half-remembered wallet password, a
  pre-BIP39 brainwallet or WarpWallet phrase, or a pile of old notes/phrases/addresses and wants to
  learn which one still holds a balance — all without going online. Every secret is opened inside a
  sealed, network-isolated container; only addresses, paths, and balances come back, keys stay
  [REDACTED], brainwallet hits go to a private file. This is the secret side of the hub's move 3 and
  the hard SEARCH form of move 1a; it recovers and finds funds, then hands off to send-and-sign to
  sweep them.
---

# recover-funds

Recover coins from a wallet you can no longer open — a corrupted or unidentified file, a seed with a
typo or a missing word, a forgotten password, an old brainwallet — and find which of many phrases or
addresses is actually funded. All of it runs **offline**, inside a sealed container, with blocktools
(`github.com/TSavo/blocktools`): small Rust Unix-filter tools that read one JSON object per line and
act as a self-custody wallet.

## The sealed boundary — read this first

These tools exist to open **hostile** wallet files and pull secrets out of them. A `wallet.dat`, a
keystore, an Armory file is attacker-controlled input until proven otherwise; opening it is exactly
the operation that can read a file it shouldn't, phone home, or leak the key it just decrypted. That
is why recovery runs sealed and offline, and why the two defenses that matter are `--network none`
and output redaction. Never run a recovery any other way.

- Run every secret-touching step inside the container: `./blocktools run '<pipeline>'`. It executes
  `--network none`, read-only root filesystem, all capabilities dropped, non-root. What crosses back
  is **public only** — addresses, derivation paths, status lines; every key field prints
  `[REDACTED]`. The redaction is why opening a hostile file is safe to do with an agent watching:
  the thing the file is trying to exfiltrate never reaches the boundary.
- Put the hostile wallet file in `./in` (mounted read-only at `/in`). Put its password in
  `./secrets` (`/secrets`), one secret per file, ending in a newline. `read-file /secrets/x.pw
  /in/file` joins the password line and the file on stdin for the opener — the sealed image has no
  shell, so **passwords never go on argv**; flags are public, secrets are stdin.
- **Never** run `./blocktools reveal`. That is the human-only escape hatch: it needs a real terminal
  and a typed code, then prints real keys, for the wallet's **owner** doing a backup — never for an
  agent, and never as a step in a pipeline.
- A brainwallet phrase **is** a secret. `wallet-finder` prints the matching phrase (not a key, but
  the phrase reconstructs the key), so send its stdout to a private file under `/secrets`, **never**
  to a terminal log, a transcript, or back to an agent.
- `utxo-set` and `wallet-finder` run on the **host**, not in the sealed image — they open no network
  connection (they read a local dump), so there is nothing to seal; the redaction rule still binds.

## Where this sits in the four moves

The hub (**smart-wallet**) teaches the whole wallet as four moves: **1** wallet → chain state (read;
**1a** wallet → addresses, **1b** addresses → state via `rpc`), **2** build the unsigned tx, **3**
secret → signed tx (sealed), **4** broadcast. recover-funds is two of those at once:

- It is the **secret side of move 3.** Move 3 is "recovery material → key → signature." Recovery
  *is* the first half of that: turning a phrase, a keystore, an old file into the master secret able
  to sign. What this skill produces — the secret and its address set — is exactly what moves
  1→2→3→4 consume to sweep. The opener's unlock is literally the start of move 3; it just stops at
  addresses instead of continuing to a signature.
- It is the **hard, SEARCH form of move 1a.** Move 1a (wallet → addresses) is already the hub's
  "~60 ways" combinatorics problem. recover-funds is that problem pushed to its limit: you don't
  even know *which* phrase, password, or path is the wallet, so 1a stops being a lookup and becomes
  an **enumeration over a candidate space** — expand what's half-remembered, derive each candidate's
  addresses, ask an offline dump which addresses are funded.

Flow below: **classify → the matching opener (sealed) → master → derive**, or **seed-repair /
pw-candidates first** for damaged or half-remembered input, or **wallet-finder against utxo-set** when
you don't know which candidate it is. Then hand the recovered secret and funded addresses to
**send-and-sign** for moves 2→3→4. A recovered wallet funded on several chains is the hub's
**series**: recover the *one* secret, then emit **one plan per funded chain**, each its own four moves.

## Thinking in candidates (what you actually reason about)

Underneath the openers is one object: the **candidate space**. "I lost my wallet" is never a single
known secret — it is a *set* of possible secrets (every repair of a typo'd seed, every rule-expansion
of a half-remembered password, every window of a notes file), crossed with the *set* of ways each
could derive addresses (script type × BIP44/49/84/86 or Electrum or an old path × gap limit). You are
not opening a wallet; you are **searching a space and asking which point in it is funded**.

Two consequences you lean on the whole time:

- **The funded check is the oracle, and it must not leak.** The question "is this candidate the
  wallet?" is answered by *"does any address it derives hold a balance?"* — and the honest way to ask
  that about thousands of guesses is an **offline** `utxo-set` dump from your own node, not a block
  explorer. An explorer answers the same question but records every guess you made; against a
  brainwallet search that is how someone *else* finds the funded phrase first. Offline, the oracle is
  free and private. This is the recovery analog of the hub's "verify is the glue": here the check that
  sits between enumerate and claim is *funded?*, and keeping it local is the whole safety story of a
  search.
- **Shrink the space before you search it, because wrong narrows silently.** Every known constraint —
  which word is missing (`?` cuts 25,000 tries to 2,048), the address you expect (`derive --match`
  prints only the hit), the right scheme — collapses the space. The danger is the mirror image: a
  candidate *is* the wallet but you derived the wrong script type or scheme, so its funded address is
  never in the set you checked, and the search reports "nothing" over real money. A null result is
  only as wide as the space you actually enumerated — widen the derivation (`--count`, more script
  types, `--scheme any`) before you believe "empty."

So recovery is: **define the candidate space from what the user half-knows → derive each candidate's
addresses → ask the offline oracle which is funded → hand the funded secret to the sweep.** The openers
below are the easy case (the space is one point: you have the file and its password). `seed-repair`,
`pw-candidates` and `wallet-finder` are the general case, where the space is large and the art is
making it *small and complete* at once.

## Honest limits — do not promise recovery

Per the repo's own `docs/SECURITY.md`: blocktools is tested only against **self-made, throwaway
synthetic fixtures generated at test time — no real lost wallet and no real key has ever been run
through it.** Parsers are checked against known-answer vectors and size bounds, not fuzzed and not
externally reviewed. So:

- It can fail on a file a real client wrote differently from the fixture. Altcoin `wallet.dat` and
  Armory versions other than the one fixtured are explicitly **UNTESTED**.
- **Not covered at all:** on-disk / byte-level file *damage* (the openers expect well-formed files —
  a truncated or corrupted file is out of scope), MetaMask and other browser-vault wallets, Exodus,
  hardware-wallet passphrases, multisig / lockbox / watch-only wallets (refused), Electrum `BIE2`
  files, wallet versions other than those named, and home-made brainwallet variants ("sha256 twice",
  salted schemes, the brainwallet.org Armory/Electrum tabs).
- Seed repair handles a typo, one swapped pair, one missing word, or up to two `?` wildcards under a
  bounded iteration budget — it **may miss**. A phrase two full words short is **not** expanded.
- `utxo-set` / `wallet-finder` answer "funded" only against the dump you hand them; a balance moved
  after that dump was taken is invisible, and they are Bitcoin-only (the layouts Core writes). Sweeps
  are exercised only against a `127.0.0.1` mock chain — a live-network sweep is untested.

Report what the tool actually returns (`status`, the address, the balance). **Do not infer success**,
and do not tell a user their coins are recoverable before a tool says an address is funded.

## Step 1 (move 1a) — name an unknown file

If you don't know what it is, classify it. `classify` names the type and, for a secret, prints only a
short fingerprint (first/last 4 hex of a SHA-256) — never the secret, and nothing for password files.
It echoes public items (an address, an xpub) as themselves.

```
./blocktools run 'classify /in/wallet.dat'
```

Route to the opener for that class (Step 2), or let the front door pick the whole pipeline and stop
at addresses:

```
recipes/recover.sh /in/wallet.dat - --goal addresses --password-file /secrets/wallet.pw
```

`recover.sh FILE DEST` auto-routes by class: `--goal addresses` prints public addresses (pass `-` for
DEST), `--goal balance` also asks the chain, and the default `sweep` goes all the way to a signed,
human-confirmed send. See `recipes/input-unknown.md`.

## Step 2 (move 1a, and the unlock that starts move 3) — open by format

Each opener reads the encrypted file (via `read-file`, password from `/secrets`) and pipes to
`key-to-addresses` (loose keys) or `seed-to-master | derive` (HD seeds). Decrypting is where the
**secret first comes out**: it stays inside the seal, and only the address set it derives (move 1a's
output) crosses back — the same arrangement move 3 relies on when it later re-derives that key to sign.

| Input | Class | Opener pipeline (inside `./blocktools run`) |
|-------|-------|---------------------------------------------|
| Bitcoin Core / altcoin `wallet.dat` | `wallet_dat` | `read-file /secrets/wallet.pw /in/wallet.dat \| dat-read \| derive --chain btc --count 1` |
| Electrum 2.x seed | `electrum_seed` | `seed-to-master < /in/seed.txt \| derive --chain btc --count 1` |
| Electrum wallet file | `electrum_wallet` | `read-file /secrets/electrum.pw /in/wallet \| electrum-read \| seed-to-master \| derive --chain btc` |
| Armory `.wallet` | `armory_wallet` | `read-file /secrets/armory.pw /in/armory.wallet \| armory-read \| key-to-addresses --chain btc` |
| MultiBit `.key` / bitcoinj `.wallet` | `multibit_key` / `bitcoinj_wallet` | `read-file /secrets/multibit.pw /in/multibit.key \| multibit-read \| key-to-addresses --chain btc` |
| Ethereum keystore / presale JSON | `keystore_v3` / `eth_presale` | `read-file /secrets/keystore.pw /in/keystore.json \| keystore-open` |
| BIP38 encrypted key | `bip38` | `read-file /secrets/bip38.pw /in/key.txt \| bip38-open \| key-to-addresses --chain btc` |
| blockchain.com backup | `blockchain_wallet` | `read-file /secrets/bc.pw /in/wallet.aes.json \| blockchain-read \| key-to-addresses --chain btc` |
| Raw private key / WIF / xprv | `wif` / `hex_key` / `xprv` | `key-to-addresses --chain btc < /in/key.hex` (xprv → `derive`) |

A wrong password returns `wrong_password` (openers check the derived key against stored public data),
never a bogus key — a keystore has a MAC, a presale wallet has none so it checks the derived address
against `ethaddr`. The keystore example unlocks to `0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b`. See
`recipes/input-wallet-dat.md`, `input-electrum.md`, `input-armory.md`, `input-multibit.md`,
`input-keystore.md`.

## Step 3 (move 1a as a search) — damaged seeds and half-remembered passwords

This is where the candidate space opens up. Shrink it with every constraint you have.

**Seed with a typo, a swapped pair, or one missing word** — `seed-repair` enumerates repairs and lets
only checksum-valid candidates through to `seed-to-master`:

```
./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain eth --count 1 --match /in/targets-eth.txt'
```

Write `?` for a word you know is missing (2,048 tries instead of ~25,000). If you don't know which
position, `seed-repair --max 5000` retries every word at every position (checksum-valid only). `--match`
collapses the result to the single candidate that reproduces an address you expect — this is the
constraint that turns a search into a lookup. Electrum 2.x: `seed-repair --scheme electrum` (or `any`).
Two `?` wildcards run under a bounded budget and **may miss**; a phrase two words short is not expanded.
See `recipes/offline-recovery-guide.md` and `recipes/input-seed-phrase.md`.

**Half-remembered wallet password** — expand a token list into candidates with `pw-candidates`
(rules `case,swap,typo,digit`) and feed each candidate, then the wallet, into an opener:

```
./blocktools run 'pw-candidates --rules case,swap,digit /in/tokens.txt | while read p; do printf "%s\n" "$p"; cat /in/wallet.dat; done | dat-read | derive --chain btc --count 1'
```

## Step 4 (move 1a) — brainwallets and old Electrum seeds

**Brainwallet** (pre-BIP39: the private key is SHA-256 of the phrase bytes, **byte for byte** — spaces,
case and punctuation all matter) — `phrase-to-key`, then `key-to-addresses`. Every phrase yields a
valid key, so a wrong phrase gives a valid but *empty* address, not an error: check against the address
you funded.

```
./blocktools run 'phrase-to-key < /in/brainwallet.txt | key-to-addresses --chain btc'
```

The xkcd "correct horse battery staple" phrase derives `1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T` (drained in
2013). WarpWallet: input `{"phrase":"...","salt":"you@example.com"}` with `phrase-to-key --scheme
warpwallet` (scrypt, ~1 s and ~¼ GB per candidate); `--scheme all` tries both. See
`recipes/input-brainwallet.md`.

**Electrum 1.x / "old" seed** (12 words from Electrum's own 1626-word list, or the hex seed) —
`seed-to-master` directly, then `derive` (it walks the non-BIP32 old paths). See
`recipes/input-electrum.md`.

## Step 5 (move 1a at the limit — the search) — which phrase/address is actually funded (offline)

The candidate space pushed all the way: you don't know which guess *is* the wallet, so you enumerate
and let the **offline oracle** decide. Take a snapshot of the whole UTXO set from **your own** Bitcoin
Core node (public chain data, no keys) and test candidates against it locally — no guess ever leaves
the machine.

```
bitcoin-cli dumptxoutset /path/utxo.dat          # Core 25+; public chain data, no keys
```

(Or `rpc --allow-unlisted --auth-file ~/.bitcoin/.cookie http://127.0.0.1:8332 dumptxoutset
'["/path/utxo.dat"]'` — it writes on the node host; copy the file to where the tools run. Core 25–27 and
Core 28+ layouts are both auto-detected; addresses are matched by scriptPubKey, so no `--chain` needed.)

Ask whether specific addresses are funded — one JSON line each, with `value_sat`:

```
utxo-set --dump /in/utxo.dat < /in/addresses.txt
```

Search a pile of your own text for a funded brainwallet. Every line, every sentence and every 1–6 word
window becomes a candidate; each candidate's five address shapes (p2pkh, p2pkh-uncompressed,
p2sh-p2wpkh, p2wpkh, p2tr) are looked up in the set. A hit prints **phrase / scheme / address / balance
— no key, nothing signed**; the phrase reconstructs the key, so stdout goes to a private file:

```
wallet-finder --dump /in/utxo.dat < /in/notes.txt > /secrets/hits.jsonl
```

Exit 0 = at least one hit, 1 = none (like `grep`); the hit count goes to stderr. Widen the space with
`--window N` and `--rules case,swap,typo,digit`; WarpWallet with `--scheme warpwallet --salt EMAIL`.
Turn a hit into a key yourself, sealed, with `phrase-to-key`. A dump answers only for the chain state it
captured, and only for Bitcoin. See `recipes/goal-find-funded-phrase.md`.

## Step 6 (hand off to moves 2→3→4) — move the recovered funds

Recovering (move 1a / the secret side of move 3) and spending (moves 2→3→4) are separate skills. Once
you hold a funded address and the secret able to sign, hand off to **send-and-sign**, which builds the
unsigned sweep (move 2), signs it sealed behind a typed code (move 3), and broadcasts it (move 4),
decoding and human-confirming at each gate. `recover.sh FILE DEST` (default goal `sweep`, for
btc/ltc/doge/eth) runs the whole 1→2→3→4 path itself: `classify` → the right reader → funded addresses
→ `tx-build --sweep` an unsigned PSBT → `tx-decode --text` on `/dev/tty` → `tx-sign --expect-to DEST`
and `tx-broadcast`, each waiting for a one-time code on the owner's own terminal. A watch-only input
(xpub, address) is refused for a sweep (exit 3). That flow is `recipes/goal-sweep.md`.

**Recovered on several chains? Emit one plan per funded chain (the hub's series).** A recovered secret
is one secret, but the coins may sit on BTC, LTC, DOGE and ETH at once, and there is **no single sweep
across chains**: move 3 recovers the one secret, then you produce **one plan per chain that has a
balance** — each the full four moves (its own move-1b read, its own build, its own sealed sign with
that chain's key, its own broadcast), all paying the same destination. They are independent; run them
in parallel. See the series in **smart-wallet** and the per-chain recipes.

## The tools, by step

| Step | Tools | Runs |
|---|---|---|
| classify an unknown file | `classify` | sealed (public-only out) |
| open by format | `read-file`, `dat-read`, `electrum-read`, `armory-read`, `multibit-read`, `keystore-open`, `bip38-open`, `blockchain-read`, then `seed-to-master`/`derive` or `key-to-addresses` | sealed |
| repair / expand (the search) | `seed-repair`, `pw-candidates`, `phrase-to-key` | sealed |
| funded? (the oracle) | `utxo-set`, `wallet-finder` (+ `bitcoin-cli dumptxoutset` on your node) | host, offline |
| strip secrets for output | `redact` | sealed |
| hand off (moves 2→3→4) | `recover.sh`, and → **send-and-sign** (`tx-build`, `tx-decode`, `tx-sign`, `tx-broadcast`) | build anywhere; sign sealed; broadcast host |

## See also

- `smart-wallet` — the hub: the four moves (1 read / 2 build / 3 sign / 4 broadcast), move 1a's
  derivation combinatorics, and the many-chains series this skill plugs into.
- `wallet-keys` — the **easy** case of move 1a: derive and inspect addresses/paths from a key or seed
  you already hold, where the candidate space is a single point.
- `send-and-sign` — moves 2→3→4: build, sign sealed, and broadcast the sweep that actually moves the
  recovered funds.
- `recipes/offline-recovery-guide.md`, `recipes/input-unknown.md`, `recipes/input-wallet-dat.md`,
  `recipes/input-electrum.md`, `recipes/input-armory.md`, `recipes/input-multibit.md`,
  `recipes/input-keystore.md`, `recipes/input-brainwallet.md`, `recipes/input-seed-phrase.md`,
  `recipes/goal-find-funded-phrase.md`, `recipes/goal-sweep.md`, and `recipes/recover.sh` (the
  auto-picker).
- `man/` pages: `classify`, `read-file`, `dat-read`, `electrum-read`, `armory-read`, `multibit-read`,
  `keystore-open`, `bip38-open`, `blockchain-read`, `seed-repair`, `pw-candidates`, `phrase-to-key`,
  `seed-to-master`, `key-to-addresses`, `wallet-finder`, `utxo-set`, `recover.sh`
  (`github.com/TSavo/blocktools`).
</content>
</invoke>
