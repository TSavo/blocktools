# Input: a BIP39 seed phrase (12–24 words), possibly with typos

Put the phrase in `in/seed.txt`. The agent-safe commands below run in the sealed image through
`./blocktools run`, which prints public data only (addresses and paths, with every key replaced by `[REDACTED]`).

## 1. Is it a seed? (classify prints a fingerprint, never the words)

<!-- e2e: expect="class":"mnemonic" -->
    ./blocktools run 'classify /in/seed.txt'

## 2. Repair typos and list addresses on every chain

`seed-repair` fixes misspelt words and checks the checksum. Test vector: the BIP39/BIP84 spec phrase
"abandon ×11 about" with two typos.

<!-- e2e: expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu ; expect=1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA ; expect=0x9858EfFD232B4033E47d90003D41EC34EcaEda94 ; expect=TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH ; expect=HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk ; expect=rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3 -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc,eth,tron,sol,xrp --count 1'

Each expected address comes from an outside source: the BIP44/84 spec, MetaMask's address for this phrase, TronLink, Phantom (`m/44'/501'/0'/0'`) and the XRPL BIP44 vector.

## 3. With a BIP39 passphrase ("25th word")

Put `{"passphrase":"..."}` on the first line of the input, or let the human type it
(`seed-to-master --passphrase-prompt`, via `./blocktools reveal`). A wrong passphrase still
gives valid but empty addresses, so check balances (goal-check-balance.md).

## 4. Front door: balance, then sweep

<!-- e2e: expect=candidate addresses on btc ; expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu ; fund=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu -->
    recipes/recover.sh /in/seed.txt - --goal balance

The sweep (`recipes/recover.sh in/seed.txt DEST`) is in goal-sweep.md. If the wallet used odd paths, see derive.md.
