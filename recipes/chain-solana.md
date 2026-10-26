# Chain: Solana

Addresses only. Phantom/Solflare path `m/44'/501'/{i}'/0'` (SLIP-10 ed25519); `derive --curve ed25519`
also tries the other common layouts.

<!-- e2e: expect=HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain sol --count 1'

<!-- e2e: rc=3 ; expect=HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk ; expect=sweep is not built -->
    recipes/recover.sh /in/seed.txt - --chain sol --count 1

A raw 32-byte key is treated as an ed25519 seed (`key-to-addresses --chain sol`). Sollet-style 64-byte
keypair arrays are not parsed yet. The CLI has NO Solana builder or signer (NOT BUILT). The wasm export
`solBuildTransfer` builds an UNSIGNED SOL/SPL transfer and `solVerifyTx` checks it; see
[docs/PATHS.md](../docs/PATHS.md) path 6. Signing, broadcast and balance lookup: NOT BUILT.

## Round trip, run in the gate

`recipes/paths/sol-transfer.sh` goes from a saved real RPC response, through the tools, to a local mock chain. It is run by `scripts/e2e.d/paths.sh` (Linux). See [docs/PATHS.md](../docs/PATHS.md) for what is checked and what is not run against a real network.
