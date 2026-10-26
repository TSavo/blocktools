# Chain: Tron

Addresses only (`T...`, base58check of 0x41 + keccak address). TronLink paths are a derive preset.

<!-- e2e: expect=TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain tron --preset tronlink --index 0..1'

<!-- e2e: rc=3 ; expect=TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC ; expect=sweep is not built -->
    recipes/recover.sh /in/key.hex - --chain tron

`sol-tron-tx build --plan` (CLI) and the wasm export `tronBuildTransfer` build an UNSIGNED TRX/TRC-20
transfer; `sol-tron-tx decode` / `tronDecodeTx` read it back; see [docs/PATHS.md](../docs/PATHS.md) path 7.
`sol-tron-tx verify --expect '{"owner":…,"to":…,"amount_sun"|"amount":…,"contract":…}'` checks one TRX or
TRC-20 transfer and recovers every signature (must be the owner; multisig `permission_id` is refused). Measured on
two mainnet transactions (Linux). Signing, broadcast and balance lookup: NOT BUILT. To move funds, a human
imports the key into TronLink (`./blocktools reveal`).

## Round trip, run in the gate

`recipes/paths/tron-transfer.sh` goes from a saved real RPC response, through the tools, to a local mock chain. It is run by `scripts/e2e.d/paths.sh` (Linux). See [docs/PATHS.md](../docs/PATHS.md) for what is checked and what is not run against a real network.
