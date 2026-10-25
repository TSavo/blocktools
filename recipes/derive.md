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
| Solana only | `--curve ed25519 --chain sol` |
| Keep scanning while hits continue | `--match targets.txt --gap-limit 20` |
| Stop at first known address | `--match targets.txt --stop-on-match` |
| Uncompressed (2011-era) keys | `--chain btc --address-type p2pkh --uncompressed` |

Ranges are inclusive: `0..9`, `2-4`, `0,1,5`, `0..2,7`.

## Planned (not built yet)
* `--preset electrum-old`, TON addresses, `seed-to-master --passphrase-prompt`.

## Tested examples

<!-- e2e: expect="path":"m/49'/0'/0'/0/0" ; expect=37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --preset exhaustive --chain btc --match /in/targets.txt'

<!-- e2e: expect="preset":"legacy-hd" -->
    ./blocktools run 'derive --list-presets'
