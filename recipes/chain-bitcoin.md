# Chain: Bitcoin

Fully built: addresses (p2pkh, p2sh-p2wpkh, p2wpkh, p2tr), UTXO fetch (Esplora), PSBT sweep,
decode, verify, sign behind a typed code, and broadcast behind a second code.

<!-- e2e: expect=bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr ; expect=37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc --count 1'

(BIP86 and BIP49 spec vectors.) Full sweep: goal-sweep.md. Default Esplora: blockstream.info; use
`--url` for your own node's Esplora.

## Round trip, run in the gate

`recipes/paths/utxo-sweep.sh` goes from a saved real RPC response, through the tools, to a local mock chain. It is run by `scripts/e2e.d/paths.sh` (Linux). See [docs/PATHS.md](../docs/PATHS.md) for what is checked and what is not run against a real network.
