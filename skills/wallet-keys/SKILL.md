---
name: wallet-keys
description: >-
  Derive crypto wallet addresses from a secret and prove control of an address, using blocktools'
  offline Rust filters. Use this when you have a seed phrase, a raw private key (hex/WIF/base58/base64),
  a BIP32 master key (xprv/yprv/zprv), an xpub/ypub/zpub, or a wallet file, and you need the addresses
  it produces on BTC, ETH, Tron, Solana, XRP and other chains; when you need to know which derivation
  path a wallet used (match known public addresses); or when you need to sign or verify a text message
  to prove an address belongs to someone (Bitcoin signmessage, Ethereum personal_sign). These are the
  sealed-boundary primitives every other wallet skill builds on. Addresses and paths come back; keys
  stay [REDACTED]. Not for building, signing or broadcasting transactions (see send-and-sign) or for
  scanning a wallet for funds (see recover-funds).
---

# blocktools: addresses from a secret, and proof of control

blocktools is a set of small Rust Unix filters — one JSON object per line on stdin/stdout. This
skill covers the two primitives at the sealed edge of the wallet: turning a secret (seed, key, xprv,
wallet file) into **addresses and derivation paths**, and proving an address is yours by **signing a
text message**. Everything else (balances, unsigned transactions, sweeps) builds on the addresses you
get here.

Ground every command against the repo's own recipes and man pages (linked at the end) rather than
memory. The repo is scrupulous about marking things tested vs untested vs not-built; keep that tone
and do not claim a chain or path works unless the recipe shows it.

## The one rule that makes it a wallet: the sealed boundary

Anything that touches a secret runs sealed and offline via `./blocktools run '<pipeline>'`
(`--network none`, read-only root, capabilities dropped). Its stdout passes through `sealed-run agent`,
which replaces every key field with `[REDACTED]`; only addresses, paths and status lines cross back.

- `./in` -> `/in` holds wallet files and inputs (`seed.txt`, `key.hex`, `xprv.txt`, `xpub.txt`), one per file, newline-terminated.
- `./secrets` -> `/secrets` holds passwords, one per file.
- Flags carry **public parameters only** — mnemonics, passphrases and keys never go on argv; they arrive on stdin.

Agents **never** use `./blocktools reveal`. Reveal is the human-only path that prints real keys at a
terminal after a typed code; it is not for automation. If a step needs a cleartext key, that is a human
step, not yours.

## Deriving addresses — pick the pipeline by what you hold

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

### "Which derivation path did this wallet use?"

Put the *public* addresses you know the wallet held in `./in/targets.txt`, one per line, and let `derive`
print only the hits, each with its `chain`, `kind` and `path`:

    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --preset exhaustive --chain all --match /in/targets.txt'

No match prints `{"status":"no_candidates","count":N}`. `--gap-limit N` keeps scanning a branch until N
misses; `--stop-on-match` halts after the first hit.

### derive flags worth knowing (confirm in man derive)

- `--chain LIST` (default `btc,eth`), `--count N` (= index `0..N-1`), `--index 0..9`, `--change 0,1`, `--account RANGE` — ranges are inclusive (`0..9`, `2-4`, `0,1,5`).
- `--preset NAME`: `common` (default), `exhaustive`, `recovery`, `exodus`, `tronlink`, `ledger-live`, `electrum`, `legacy-hd`, `scan-js`. `derive --list-presets` and `derive --explain` print the plan with no keys and no stdin.
- `--path TEMPLATE` / `--purpose` / `--coin-type` / `--address-type` for custom paths; `--uncompressed` for 2011-era keys; `--curve ed25519` for Solana-only.
- **Output safety:** `derive` output CONTAINS SECRETS (`wif`/`private_key`) unless you pass `--explain`, `--list-presets`, `--public-only`, or `--address-list`. The sealed boundary redacts keys anyway, but prefer `--public-only` (drops the key field entirely) or `--address-list` (one `label<TAB>path<TAB>address` line) when you only want addresses:

    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc --count 1 --public-only'

Note: in v0.1.0 `derive --address-list` through `redact` comes back empty (getting-started.md names the
`--public-only | jq` workaround); `--address-list` is a post-v0.1.0 source build.

## Proving control of an address: sign / verify a text message

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

- **send-and-sign** — build, verify and sign transactions (the addresses from here are the inputs).
- **recover-funds** — scan a derived wallet for balances and sweep.
- Authoritative sources in the repo: `recipes/derive.md`, `recipes/input-seed-phrase.md`,
  `recipes/input-raw-key.md`, `recipes/input-xprv.md`, `recipes/input-xpub-address.md`,
  `docs/getting-started.md`, `docs/cookbook.md`; man pages `derive(1)`, `seed-to-master(1)`,
  `key-to-addresses(1)`, `xpub-addresses(1)`, `phrase-to-key(1)`, `msg-sign(1)`, `msg-verify(1)`.
  Read the recipe over copying a snippet — its tested examples are run verbatim in e2e.
