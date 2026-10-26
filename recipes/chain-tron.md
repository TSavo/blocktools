# Chain: Tron

Addresses only (`T...`, base58check of 0x41 + keccak address). TronLink paths are a derive preset.

<!-- e2e: expect=TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain tron --preset tronlink --index 0..1'

<!-- e2e: rc=3 ; expect=TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC ; expect=sweep is not built -->
    recipes/recover.sh /in/key.hex - --chain tron

The CLI has NO Tron builder (NOT BUILT). The wasm export `tronBuildTransfer` builds an UNSIGNED TRX/TRC-20
transfer and `tronDecodeTx` reads it back; see [docs/PATHS.md](../docs/PATHS.md) path 7. Signing,
verify-with-expectations, broadcast and balance lookup: NOT BUILT. To move funds, a human
imports the key into TronLink (`./blocktools reveal`).
