---
name: wallet-keys
description: >-
  Turn whatever the user calls their wallet into the set of addresses to query (move 1a), mint a brand
  new wallet, and prove control of an address, using blocktools' offline Rust filters. Use this when you
  have a seed phrase, a raw private key (hex/WIF/base58/base64), a BIP32 master key (xprv/yprv/zprv), an
  xpub/ypub/zpub, or a wallet file, and you need the addresses it produces on BTC, ETH, Tron, Solana, XRP
  and other chains; when you need to MAKE a new wallet (blocktools mints a fresh BIP39 mnemonic from the
  OS CSPRNG via `new-seed`); when you need to know which derivation path a wallet used (match known public
  addresses); or when you need to sign or verify a text message to prove an address belongs to someone
  (Bitcoin signmessage, Ethereum personal_sign). This is the public-only derivation that every chain read
  starts from and the signer re-does inside the seal. Addresses and paths come back; keys stay [REDACTED]
  (a new mnemonic is revealed to a human to back up via `./blocktools reveal`). Not for building, signing
  or broadcasting transactions (see send-and-sign) or for scanning a wallet for funds (see recover-funds).
---

# blocktools: wallet → addresses (move 1a), mint a new wallet, and proof of control

blocktools is a set of small Rust Unix filters — one JSON object per line on stdin/stdout. The whole
wallet is **four moves** (see the `smart-wallet` hub): (1) wallet → chain state (read), (2) chain state
→ unsigned transaction (build), (3) secret → signed transaction (sign, sealed), (4) signed transaction
→ network (broadcast), with **verify** as the glue between 2→3 and 3→4.

This skill is essentially **move 1a: wallet → addresses** — turning whatever the user calls their
wallet (seed, key, xprv, xpub, wallet file) into **the set of addresses to query**, public-only, before
any chain read. It is also the derivation the signer re-does *inside the seal* for **move 3** (secret →
signed transaction): the same `seed-to-master` / `derive` path that produces an address here produces,
sealed, the private key that signs. Get move 1a wrong and every later move asks about the wrong
addresses — so this half is the hard one, and it lives here. Two more capabilities live here because
they are the same key machinery pointed a different way: **minting** a new wallet (make the secret, then
derive its address) and **proving control** of an address by signing a text message. Both stand alone.

Ground every command against the repo's own recipes and man pages (linked at the end) rather than
memory. The repo is scrupulous about marking things tested vs untested vs not-built; keep that tone
and do not claim a chain or path works unless the recipe shows it.

## The one rule that makes it a wallet: the sealed boundary

Move 1a is **public-only** — it needs no private key — so address derivation can run on the host. But
the same pipelines also re-derive the key inside the seal for move 3, and any input that *is* a secret
(a seed, a raw key, an xprv, an encrypted wallet file, **a freshly minted mnemonic**) touches a secret
the moment it exists. So run these pipelines sealed and offline via `./blocktools run '<pipeline>'`
(`--network none`, read-only root, capabilities dropped). Its stdout passes through `sealed-run agent`,
which replaces every key field with `[REDACTED]`; only addresses, paths and status lines cross back.
That is what keeps move 1a honest: you get the address set out, never the key.

- `./in` -> `/in` holds wallet files and inputs (`seed.txt`, `key.hex`, `xprv.txt`, `xpub.txt`), one per file, newline-terminated.
- `./secrets` -> `/secrets` holds passwords, one per file.
- Flags carry **public parameters only** — mnemonics, passphrases and keys never go on argv; they arrive on stdin.

Agents **never** use `./blocktools reveal`. Reveal is the human-only path that prints real keys (and a
newly minted mnemonic) at a terminal after a typed code; it is not for automation. If a step needs a
cleartext key, that is a human step, not yours.

**Doctrine: the CLIs are thin users of one key library.** `derive`, `new-seed`, `seed-to-master`,
`key-to-addresses` and `msg-sign` are not separate implementations — they are small front-ends over the
same vetted key/BIP32/BIP39 core. `new-seed` is that core's CSPRNG entry point; `derive` is its path
walker; the signer is the same derivation re-run behind the seal. So "mint", "derive" and "sign" are one
body of code seen from three sides, which is why the address you derive here is byte-identical to the one
the sealed signer will use, and why minting a wallet is a first-class operation, not a bolt-on.

## Deriving addresses (move 1a) is walking a combinatorial space — and the failure is silent

"My wallet" is any of **~60 things** — a bare address, an xpub/ypub/zpub, a seed phrase, a keystore, a
`wallet.dat`, an Electrum file, a raw key or WIF, a brainwallet, an xprv. None of them *is* an address;
each one **names a set** of addresses, and that set is the point of every later move. The set is a
product over five independent axes:

    addresses(wallet) =
        input-format            (seed / xprv / xpub / keystore / raw key / …  — which opener)
      × chain                   (btc, eth, ltc, doge, tron, sol, xrp, …)
      × script-type             (legacy P2PKH / wrapped-segwit P2SH / native-segwit bech32 / taproot)
      × derivation-scheme       (BIP44 m/44' / BIP49 m/49' / BIP84 m/84' / BIP86 m/86' / Electrum / old)
      × { index × change }      up to a gap-limit

A seed on BTC alone is already legacy×BIP44, wrapped×BIP49, native×BIP84, taproot×BIP86, each an
unbounded index/change branch — and that is *one* chain. The user holds coins at **some point** in this
space; your job is to make the query set a superset of that point. **The failure mode is silent.** Pick
the wrong script-type or scheme or stop one index too early and `derive` emits perfectly valid addresses,
the chain answers "balance 0" for every one of them, and you report "empty wallet" while the coins sit at
an address you never generated. There is no error. The only evidence of the mistake is money you cannot
see, so the reasoning has to be done *before* you trust a zero.

### `derive` is the engine that walks the space; everything else feeds it

`derive` enumerates the product: give it the chains, script-types, schemes and a gap-limit and it emits
the address set. The other tools exist to hand it a correct starting point and to narrow the walk:

- `classify` — names an unknown input (`mnemonic` / `hex_key` / `xprv` / `xpub` …) so you pick the right **input-format** axis instead of guessing.
- `seed-to-master` / the format openers (`dat-read`, `electrum-read`, `keystore-open`, …) — collapse the input-format axis to a single master key that `derive` can walk.
- `xpub-addresses` — walks the script-type × index × change axes for a **watch-only** xpub/ypub/zpub (the scheme is fixed by the SLIP-132 version byte).
- `derive`'s **presets** — package the common (input-format × scheme) corners so you don't hand-build a path: `common` covers the mainstream BIP44/49/84/86 corners, `exhaustive` widens the walk, and the wallet-specific presets (`exodus`, `tronlink`, `ledger-live`, `electrum`, `legacy-hd`, `scan-js`) jump straight to the corner a given app actually used.

So the reasoning is: **shrink the space with what you know, widen the walk where you don't, and never
let the walk be narrower than the place the money could be.** A preset that matches the wallet's origin
app collapses most axes at once (that is the fast path); absent that, `exhaustive` + a generous
gap-limit keeps the space able to *contain* the answer, at the cost of more addresses to query.

First, if unsure what the input is, classify it (prints a class/fingerprint, never the secret):

    ./blocktools run 'classify /in/seed.txt'

Classes you will see include `mnemonic`, `hex_key`, `xprv`, `xpub`. Then:

**A seed phrase (BIP39, 12–24 words, possibly with typos).** `seed-repair` fixes misspelt words and
checks the checksum; `seed-to-master` turns it into a master key; `derive` walks a plan of paths. First
address of several chains at once:

    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc,eth,tron,sol,xrp --count 1'

**A raw private key (hex, WIF, base58, base64).** `key-to-addresses` tries every encoding that yields
32 bytes and prints addresses on every chain in the table, compressed and uncompressed. Narrow with
`--chain`:

    ./blocktools run 'key-to-addresses --chain btc < /in/key.wif'

(`phrase-to-key` emits a `{"key":...}` line from a passphrase-style input that `key-to-addresses` then
consumes — see the recipe before using it.)

**A BIP32 master key (xprv).** Wrap the one-line `xprv…` as `{"xprv":…}` and pipe into `derive`; SLIP-132
`yprv/zprv/Yprv/Zprv` are accepted as the same key. `--chain` and the presets below apply. Account-level
xprvs are UNTESTED; `yprv/zprv/tprv` *version-byte* conversion is NOT BUILT (convert yourself). See
input-xprv.md.

**An xpub/ypub/zpub or a bare address (watch-only — cannot sign).** `xpub-addresses` lists addresses;
`ypub/zpub` are SLIP-132 converted and pick their script type:

    ./blocktools run 'xpub-addresses --chain btc --change 0,1 --count 1 < /in/xpub.txt'

**A wallet file** (`wallet.dat`, keystore, Electrum, MultiBit, Armory): copy it into `./in/`, its password
into `./secrets/`, and follow that file type's recipe — those produce a master key that feeds `derive`
the same way.

### "Which derivation path did this wallet use?" — turning the walk into a search

When you *do* know a public address the wallet held, you can collapse the whole space to the one corner
that reproduces it. Put the known addresses in `./in/targets.txt`, one per line, and let `derive` walk a
wide plan but print only the hits, each with its `chain`, `kind` and `path`:

    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --preset exhaustive --chain all --match /in/targets.txt'

A hit tells you the exact script-type × scheme × index the wallet uses, which you then reuse (narrowly)
for the chains you *don't* have a sample address for. No match prints
`{"status":"no_candidates","count":N}` — and here is the discipline that makes a null mean something: a
no-match is only informative if the walk could have *contained* the address. If `--preset exhaustive`
and a generous `--gap-limit` still miss, the address is from a scheme outside the plan (a custom path, a
non-BIP wallet) — not proof the seed is wrong. `--gap-limit N` keeps scanning a branch until N
consecutive misses; raise it when a wallet is known to have sparse, high-index usage. `--stop-on-match`
halts after the first hit.

### derive flags worth knowing (confirm in man derive)

- `--chain LIST` (default `btc,eth`), `--count N` (= index `0..N-1`), `--index 0..9`, `--change 0,1`, `--account RANGE` — ranges are inclusive (`0..9`, `2-4`, `0,1,5`).
- `--preset NAME`: `common` (default), `exhaustive`, `recovery`, `exodus`, `tronlink`, `ledger-live`, `electrum`, `legacy-hd`, `scan-js`. `derive --list-presets` and `derive --explain` print the plan with no keys and no stdin — read the plan first to confirm the space it will walk actually covers where the money could be.
- `--path TEMPLATE` / `--purpose` / `--coin-type` / `--address-type` for custom paths; `--uncompressed` for 2011-era keys; `--curve ed25519` for Solana-only.
- **Output safety:** `derive` output CONTAINS SECRETS (`wif`/`private_key`) unless you pass `--explain`, `--list-presets`, `--public-only`, or `--address-list`. The sealed boundary redacts keys anyway, but prefer `--public-only` (drops the key field entirely) or `--address-list` (one `label<TAB>path<TAB>address` line) when you only want addresses:

    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc --count 1 --public-only'

Note: in v0.1.0 `derive --address-list` through `redact` comes back empty (getting-started.md names the
`--public-only | jq` workaround); `--address-list` is a post-v0.1.0 source build.

## Minting a new wallet: `new-seed` makes the secret, `derive` proves the address

blocktools **mints wallets.** `new-seed` draws fresh entropy from the OS CSPRNG and emits a valid BIP39
mnemonic — the same key library's entropy entry point, so the mnemonic it makes feeds `seed-to-master |
derive` exactly like a user-supplied one. `--words 12` or `--words 24` picks the entropy (128 vs 256
bits; prefer 24 for a long-lived wallet). Make a new ETH wallet in one sealed pipeline:

    ./blocktools run 'new-seed --words 24 | seed-to-master | derive --chain eth --count 1 --public-only'

What crosses the sealed boundary is the **address, in the clear** — that is what you give the user to
receive funds. The **mnemonic is a secret** and comes back `[REDACTED]`: you never see it, and you must
not try to. The person who owns the wallet backs up the mnemonic themselves, at a terminal, via the
human-only reveal path:

    ./blocktools reveal        # human types the code; the fresh mnemonic prints for them to write down

So minting splits cleanly along the boundary: the agent gets a usable receive address, the human gets
the recovery words, and no secret ever transits the agent. (Need a key on a chain whose address `derive`
doesn't print directly? Mint the seed once, then derive each chain's address from the same `new-seed`
output within the one sealed run — a wallet is one secret, many addresses.)

### Good practice: prove an address before you trust it with money

Minting is one case of a rule that applies to **every** new or claimed address: before you send funds to
an address, prove it derives from a secret its owner actually holds. An address alone is an assertion;
derivation from the secret is the proof. Two shapes:

- **A wallet you just minted, or a key/seed the user gives you as the destination.** Re-derive and
  compare: `seed-to-master | derive --chain eth --public-only` (or `key-to-addresses`) on the secret must
  reproduce the exact address you are about to fund. If it doesn't match, the address and the secret are
  not the same wallet — stop. (This is the check the `smart-wallet` hub's "new ETH wallet" journey step 3
  performs before any USDC is sent.)
- **An address whose owner only has the public side (watch-only), or a counterparty's address.** You
  cannot derive it, so fall back to **proof of control**: have them sign a message (below) and verify it.

The point is the same either way: a destination address is trustworthy only once you have mechanically
tied it to a secret or a signature, never because it was pasted to you.

## Proving control of an address: sign / verify a text message (its own capability)

This is not part of the four transaction moves — it is a separate capability of the secret side: a
signature over a text message that proves the holder of a key controls an address, with no transaction
built or broadcast. `msg-verify` is pure read (public-only); `msg-sign` touches the key, so it signs
sealed, the same boundary move 3 signs behind.

**Verifying** reads no keys, so run it freely (sealed or not). The chain is detected from the address
(`0x`+40 hex = Ethereum EIP-191 `personal_sign`; base58 P2PKH starting with `1` = Bitcoin Core
`signmessage`). Output is `{"status":"ok"|"signer_mismatch","chain","address","recovered"}`; exit 0 only
on `ok`:

    msg-verify --address 19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X --message "test signature" --sig ILH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo=

**Signing** touches keys, so it runs sealed — but `msg-sign` also shows the message and asks for a
one-time code on `/dev/tty` before it emits the signature. Without a terminal (as under `./blocktools run`)
it prints only `aborted`. So completing a signature is a **human step at a terminal**; your job is to
prepare the exact `--address` and `--message`/`--message-file`, hand them over, and then `msg-verify` the
signature that comes back. Keys arrive only on stdin (WIF or 64-hex, or JSON with `wif`/`private_key`/`key`/`secret`):

    msg-sign --address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH --message "I control this address" < keys   # asks for a code on the terminal

`msg-sign` refuses, before reading keys: a bare 32-byte hash (blind-hash signing), anything that decodes
as a transaction or PSBT, non-UTF-8 or empty or >64 KiB messages, segwit/taproot addresses (BIP137/BIP322
unsupported), other chains' prefixes, and EIP-712 typed data. Ethereum `--v` is `legacy` (27/28, default),
`raw` (0/1), or `eip155:N`. Both tools are checked byte-exact against Trust Wallet Core vectors.

Scope note: message signing is Bitcoin P2PKH and Ethereum only. EIP-712 typed data is not signed here —
`typed-data-verify` only verifies it.

## See also

- **smart-wallet** — the hub: the four moves (1 read, 2 build, 3 sign, 4 broadcast) and verify as the
  glue. This skill is move 1a (wallet → addresses), the derivation move 3 re-does inside the seal, plus
  minting (`new-seed`) and proof of control. The hub's full-journey example mints a fresh ETH wallet at
  step 3 exactly this way.
- **send-and-sign** — moves 2–4: build the unsigned tx (move 2), sign it sealed (move 3), broadcast via
  the user's own node (move 4). The addresses from here are the inputs; move 1b (addresses → state, via
  `rpc`) feeds the build.
- **recover-funds** — the hard cases of move 1a: scan a derived wallet for balances and sweep, and
  search the candidate space when you don't even know which phrase or path is the wallet.
- Authoritative sources in the repo: `recipes/derive.md`, `recipes/input-seed-phrase.md`,
  `recipes/input-raw-key.md`, `recipes/input-xprv.md`, `recipes/input-xpub-address.md`,
  `docs/getting-started.md`, `docs/cookbook.md`; man pages `derive(1)`, `new-seed(1)`,
  `seed-to-master(1)`, `key-to-addresses(1)`, `xpub-addresses(1)`, `phrase-to-key(1)`, `msg-sign(1)`,
  `msg-verify(1)`. Read the recipe over copying a snippet — its tested examples are run verbatim in e2e.
