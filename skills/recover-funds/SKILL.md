---
name: recover-funds
description: >-
  Offline recovery of coins from an old, forgotten, damaged, or unknown wallet with blocktools
  (github.com/TSavo/blocktools). Use when the user has a wallet file they can't open or identify
  (Bitcoin Core wallet.dat, Electrum seed or wallet file, Armory .wallet, MultiBit/bitcoinj,
  Ethereum keystore/presale JSON, BIP38, blockchain.com backup), a seed phrase with a typo,
  swapped words, or one missing word, a half-remembered wallet password, a pre-BIP39 brainwallet
  phrase, a raw private key or WIF, or a pile of old notes/phrases/addresses and wants to learn
  which one still holds a balance — all without going online. Every secret is opened inside a
  sealed, network-isolated container; only addresses, paths, and balances come back, keys stay
  [REDACTED]. Recovers and finds funds; handing off to send-and-sign actually moves them.
---

# recover-funds

Recover coins from a wallet you can no longer open — a corrupted or unidentified file, a seed
with a typo or a missing word, a forgotten password, an old brainwallet — and find which of many
phrases or addresses is actually funded. All of it runs **offline**, in a sealed container, with
blocktools (`github.com/TSavo/blocktools`): a set of small Rust Unix-filter tools that read one
JSON object per line and act as a self-custody wallet.

## The sealed boundary — read this first

These tools exist to open **hostile** wallet files and extract secrets from them. That is exactly
why they run sealed and offline. Never run a recovery any other way.

- Run every secret-touching step inside the container: `./blocktools run '<pipeline>'`. It runs
  `--network none`, read-only filesystem, no capabilities. What comes back is **public only** —
  addresses, derivation paths, status lines. Every key field prints as `[REDACTED]`.
- Put the hostile wallet file in `./in` (seen as `/in`). Put its password in `./secrets` (seen as
  `/secrets`), one secret per file, ending in a newline. `read-file /secrets/x.pw /in/file`
  joins the password line and the file on stdin for the opener (the sealed image has no shell, so
  passwords never go on argv — flags are public).
- **Never** run `./blocktools reveal`. That path prints real keys at a human terminal after a
  typed code; it is for the wallet's owner, not an agent.
- A brainwallet phrase itself is a secret: `wallet-finder` prints matching phrases, so send its
  stdout to a private file under `/secrets`, never to a terminal log or back to an agent.

## Honest limits — do not promise recovery

Per the repo's own `docs/SECURITY.md`: blocktools is tested only against **self-made, throwaway
synthetic fixtures generated at test time — no real lost wallet or real key has ever been run
through it.** Parsers are checked against known-answer vectors and size bounds, not fuzzed, and
not externally reviewed. So:

- It can fail on a file a real client wrote differently from the fixture (altcoin `wallet.dat`,
  other Armory versions, and similar are explicitly UNTESTED).
- **Not covered at all:** on-disk / byte-level file damage (the openers expect well-formed files),
  MetaMask and other browser-vault wallets, Exodus, hardware-wallet passphrases, multisig /
  lockbox / watch-only wallets (refused), Electrum `BIE2` files, and home-made brainwallet
  variants. Seed repair handles one missing word or up to two `?` wildcards under a bounded budget
  (may miss); a phrase two full words short is **not** expanded.
- `utxo-set` / `wallet-finder` answer "funded" only against the dump you hand them; funds moved
  after that dump was taken are invisible. Sweeps are exercised only against a mock chain.

Report what the tool actually returns (`status`, the address, the balance). Do not infer success.

## Step 1 — name an unknown file

If you don't know what the file is, classify it. `classify` names the type and, for a secret,
prints only a short fingerprint — never the secret (and nothing for password files).

```
./blocktools run 'classify /in/wallet.dat'
```

Then route to the opener for that class (below). Or let the auto-picker choose the whole pipeline
and stop at addresses:

```
recipes/recover.sh /in/wallet.dat - --goal addresses --password-file /secrets/wallet.pw
```

`recover.sh FILE DEST` is the front door: `--goal addresses` prints public addresses (pass `-`
for DEST), `--goal balance` also checks the chain, and the default `sweep` goes all the way to a
signed, human-confirmed send. It auto-routes by class and picks the pipeline for you.

## Step 2 — open by format

Each opener reads the encrypted file (via `read-file`, password from `/secrets`) and pipes to
`key-to-addresses` (loose keys) or `seed-to-master | derive` (HD seeds).

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
| Raw private key / WIF | `wif` / `hex_key` | `key-to-addresses --chain btc < /in/key.hex` |

A wrong password returns `wrong_password` (openers check the derived key against stored public
data), never a bogus key. See `recipes/input-wallet-dat.md`, `input-electrum.md`, `input-armory.md`,
`input-multibit.md`, `input-keystore.md`, and `recipes/input-unknown.md`.

## Step 3 — damaged seeds and half-remembered passwords

**Seed with a typo, a swapped pair, or one missing word** — run `seed-repair` first; only
checksum-valid candidates go on to `seed-to-master`:

```
./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain eth --count 1 --match /in/targets-eth.txt'
```

Write `?` for a word you know is missing (2048 tries instead of ~25,000); `--match` prints only
the candidate that reproduces an address you expect. Electrum 2.x seeds: `seed-repair --scheme
electrum` (or `any`). See `recipes/offline-recovery-guide.md` and `recipes/input-seed-phrase.md`.

**Half-remembered wallet password** — expand a token list into candidates with `pw-candidates`
(rules `case,swap,typo,digit`) and feed each one, followed by the wallet file, into an opener:

```
./blocktools run 'pw-candidates --rules case,swap,digit /in/tokens.txt | while read p; do printf "%s\n" "$p"; cat /in/wallet.dat; done | dat-read | derive --chain btc --count 1'
```

## Step 4 — brainwallets and old Electrum seeds

**Brainwallet** (pre-BIP39: the private key is SHA-256 of the phrase bytes, byte-for-byte) —
`phrase-to-key`, then `key-to-addresses`. A wrong phrase yields a valid but empty address, so
check against the address you funded:

```
./blocktools run 'phrase-to-key < /in/brainwallet.txt | key-to-addresses --chain btc'
```

WarpWallet: input `{"phrase":"...","salt":"you@example.com"}` with `phrase-to-key --scheme
warpwallet` (`--scheme all` tries both). See `recipes/input-brainwallet.md`.

**Electrum 1.x / "old" seed** (12 words from Electrum's own 1626-word list, or the hex seed) —
`seed-to-master` directly, then `derive` (it walks the non-BIP32 old paths). See
`recipes/input-electrum.md`.

## Step 5 — find which phrase/address is actually funded (offline)

To learn which of many candidates holds a balance without leaking a single guess to a block
explorer, test them against a snapshot of the whole UTXO set taken from **your own** Bitcoin Core
node (`bitcoin-cli dumptxoutset /path/utxo.dat` — public chain data, no keys). Copy that dump to
where the tools run. `utxo-set` and `wallet-finder` are host-side offline tools (they open no
network connection and are not in the sealed image).

Ask whether specific addresses are funded — one JSON line each, with `value_sat`:

```
utxo-set --dump /in/utxo.dat < /in/addresses.txt
```

Search a pile of your own text for a funded brainwallet (every line, sentence, and 1–6 word window
becomes a candidate; each is tested against the set). A hit prints **phrase / scheme / address /
balance — never a key, nothing signed**; send stdout to a private file:

```
wallet-finder --dump /in/utxo.dat < /in/notes.txt > /secrets/hits.jsonl
```

Exit 0 = at least one hit, 1 = none (like `grep`). Widen with `--window N` and `--rules
case,swap,typo,digit`; WarpWallet with `--scheme warpwallet --salt EMAIL`. Turn a hit into a key
yourself, sealed, with `phrase-to-key`. See `recipes/goal-find-funded-phrase.md`.

## Step 6 — move the recovered funds

Recovering funds and spending them are separate skills. Once you have a funded address (and, for a
spend, the key still sealed), hand off to the **send-and-sign** skill, which builds, decodes, and
human-confirms a transaction. `recover.sh FILE DEST` (default goal `sweep`, for btc/ltc/doge/eth)
runs that whole path — build an unsigned sweep, decode it on screen, then sign and broadcast only
after the owner types a one-time code on their own terminal. That sweep is `recipes/goal-sweep.md`.

## See also

- `wallet-keys` — derive and inspect addresses/paths from a key or seed you already hold.
- `send-and-sign` — build, sign, and broadcast the sweep that actually moves recovered funds.
- `recipes/offline-recovery-guide.md`, `recipes/recover.sh` (the auto-picker), and the `man/`
  pages (`classify`, `dat-read`, `electrum-read`, `armory-read`, `multibit-read`, `keystore-open`,
  `bip38-open`, `blockchain-read`, `seed-repair`, `pw-candidates`, `seed-to-master`,
  `key-to-addresses`, `wallet-finder`, `utxo-set`) in `github.com/TSavo/blocktools`.
