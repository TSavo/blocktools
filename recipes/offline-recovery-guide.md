# Offline recovery guide (seed phrase or private key → addresses)

This page replaces hand-written recovery scripts (for example SwapChan's embedded JS/Python snippets):
every step that touches a seed or key runs inside blocktools, offline. Build or download blocktools
(README.md), disconnect from the network, put the secret in a file under `in/`, and run the commands
below. `./blocktools run` prints public data only (addresses, paths); keys appear as `[REDACTED]`.

All expected values below come from outside sources: the BIP44/49/84/86 test vectors for the phrase
"abandon ×11 about", MetaMask (EVM), TronLink (Tron), and Ian Coleman's BIP39 tool (LTC, DOGE).

## Seed phrase → EVM, Tron, BTC, LTC, DOGE addresses

<!-- e2e: expect=0x9858EfFD232B4033E47d90003D41EC34EcaEda94 ; expect=TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH ; expect=1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA ; expect=37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf ; expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu ; expect=LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez ; expect=DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain eth,tron,btc,ltc,doge --count 1'

`--count 20` scans the first 20 addresses of each path; a BIP39 passphrase is in input-seed-phrase.md §3.
Odd derivation paths: derive.md.

## One word missing (position unknown)

An 11-word phrase (or 14/17/20/23) is retried with every one of the 2048 words at every position;
only checksum-valid phrases go on. Give the address you expect in `in/targets.txt`, and `derive --match`
prints only the hit:

<!-- e2e: expect=0x9858EfFD232B4033E47d90003D41EC34EcaEda94 ; expect="count":1 -->
    ./blocktools run 'seed-repair --max 5000 < /in/seed-missing.txt | seed-to-master | derive --chain eth --count 1 --match /in/targets-eth.txt'

If you know which word is missing, write `?` in its place (2048 tries instead of ~25,000):

<!-- e2e: expect=0x9858EfFD232B4033E47d90003D41EC34EcaEda94 -->
    ./blocktools run 'seed-repair < /in/seed-unknown.txt | seed-to-master | derive --chain eth --count 1 --match /in/targets-eth.txt'

Typos (misspelt words, any swapped pair) are fixed by the same `seed-repair` step. Electrum 2.x
seeds use `seed-repair --scheme electrum` (or `any`). Two `?` wildcards are searched under a
200k-iteration budget (may miss); a phrase two words short is not expanded.

## Private key → BTC addresses

<!-- e2e: expect=1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH ; expect=1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm ; expect=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 -->
    ./blocktools run 'key-to-addresses --chain btc < /in/key.hex'

Key 1 (the secp256k1 generator) gives the well-known compressed/uncompressed P2PKH and P2WPKH addresses.
A WIF works the same way (input-raw-key.md).

## Keystore (geth/MyEtherWallet JSON) and presale wallets

input-keystore.md (password typed at the prompt or read from a file; never on the command line).

## Next: balance and sweep

goal-check-balance.md, then goal-sweep.md.
