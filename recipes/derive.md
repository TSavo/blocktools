# Recipe: find which derivation path a wallet used

Everything below runs inside the sealed container through `sealed-run` (the agent sees
addresses and paths only) or, for a human at the terminal, via `./blocktools reveal`.
Flags carry public parameters only; the seed phrase arrives on stdin.

## 1. See the plan first (no keys involved)

    derive --explain --preset recovery --chain all
    derive --list-presets

## 2. "Which path produces this address?"

Put the *public* addresses you know the wallet had in `targets.txt`, one per line:

    seed-repair < /in/seed.txt | seed-to-master | derive --preset exhaustive --chain all --match /in/targets.txt

Only hits are printed, each with `chain`, `kind` and `path`. If nothing matches,
`{"status":"no_candidates","count":N}` says how many derivations were tried.

## 3. Common one-liners

| Want | Flags |
|------|-------|
| First 200 native-segwit receive + change | `--chain btc --address-type p2wpkh --change 0,1 --index 0..199` |
| A custom path | `--chain btc --path "m/0'/0'/{i}'" --both` |
| BIP44 paths encoded as bech32 | `--chain btc --purpose 44 --address-type p2wpkh` |
| Litecoin with a non-standard coin type | `--chain ltc --coin-type 0` |
| Ledger Live ETH accounts 0..9 | `--chain eth --preset ledger-live --index 0..9` |
| TronLink | `--chain tron --preset tronlink` |
| Public addresses only (no key field in the JSON) | `--public-only` |

## 4. A plain address list (SwapChan SCAN_JS layout)

`--preset scan-js` is the same wallet path table as SwapChan's SCAN_JS script: the same wallet
names, paths and order, 20 addresses each, over eth, tron, sol, btc, ltc, doge, bch and btg.
`--address-list` prints one `label<TAB>path<TAB>address` line per address and no key material
(status lines go to stderr). To also try passphrases, put one per line in a file:

    seed-to-master --passphrase-file /in/passphrases.txt < /in/seed.txt | derive --preset scan-js --address-list

The empty passphrase is tried first, then each non-empty line; rows from line N get
`[passphrase #N]` after the path, as SCAN_JS prints them. Without `--chain` the preset uses all
eight chains above; with `--chain` it keeps only the rows for those chains.
| Solana only | `--curve ed25519 --chain sol` |
| Keep scanning while hits continue | `--match targets.txt --gap-limit 20` |
| Stop at first known address | `--match targets.txt --stop-on-match` |
| Uncompressed (2011-era) keys | `--chain btc --address-type p2pkh --uncompressed` |

Ranges are inclusive: `0..9`, `2-4`, `0,1,5`, `0..2,7`.

## Planned (not built yet)
* `--preset electrum-old`, TON addresses from `derive` (`derive --chain ton` gives `no_candidates`).

A BIP39 passphrase is typed with `seed-to-master --passphrase-prompt` (built: it reads `/dev/tty`, not echoed, empty = none; checked on a pty 2026-10-26). It cannot be combined with `--passphrase-file` or a stdin passphrase.

## Tested examples

<!-- e2e: expect="path":"m/49'/0'/0'/0/0" ; expect=37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --preset exhaustive --chain btc --match /in/targets.txt'

<!-- e2e: expect="preset":"legacy-hd" -->
    ./blocktools run 'derive --list-presets'
