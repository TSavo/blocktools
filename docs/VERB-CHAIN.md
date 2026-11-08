# Verb x chain coverage

Parent verbs (`tx-decode`, `tx-build`, `tx-sign`, `tx-verify`, `tx-broadcast`) take `--chain`.
They either handle that chain themselves or exec an existing backend from the same directory.
They do not invent a signer, a verifier, or a broadcaster that does not already exist.

This table is the list that `scripts/verb-chain-check.py` enforces: a new split `*-tx`
backend (anything under `tools/` that ends in `-tx` and is not named `tx-*`) must appear
here, or the check goes red.

| chain | decode | build | sign | verify | broadcast |
|---|---|---|---|---|---|
| UTXO rows (`btc`, `ltc`, `doge`, forks, PoS nTime) | `tx-decode` | `tx-build` | `tx-sign` | `tx-verify` | `tx-broadcast` |
| `eth` | `tx-decode` | `tx-build` | `tx-sign` | `tx-verify` | `tx-broadcast` |
| `zec` (transparent v5) | `tx-decode` | `tx-build` (`--sweep`) | `tx-sign` (refuses shielded components) | `tx-verify` | `tx-broadcast` (existing path) |
| `sol`, `tron` | `tx-decode` -> `sol-tron-tx decode` | `tx-build` -> `sol-tron-tx build` | `signing_not_available` (`sol-tron-tx` takes no keys) | `tx-verify` -> `sol-tron-tx verify` (`--expect` JSON) | `broadcast_not_available` |
| `xrp` | `tx-decode` -> `xrp-tx decode` | `tx-build` -> `xrp-tx build` | `tx-sign` -> `xrp-tx sign` | `verify_not_available` | `broadcast_not_available` |
| `xlm`, `algo`, `atom`, `ton`, `ada`, `dot`, `rune` | `tx-decode` -> `acct-tx decode` | `tx-build` -> `acct-tx build` | `tx-sign` -> `acct-tx sign` | `verify_not_available` | `broadcast_not_available` |
| `xmr` | (not via `tx-decode`) | `xmr_requires_wallet_rpc` | `xmr_requires_wallet_rpc` | `xmr_requires_wallet_rpc` | `broadcast_not_available` |

## Split backends (must stay named above)

- `sol-tron-tx`: unsigned build, decode, and verify for Solana and Tron. Takes no keys and signs nothing.
- `xrp-tx`: build, decode, and sign for XRP. `--chain` is stripped when `tx-build`/`tx-sign` exec it, because `xrp-tx` does not take `--chain`.
- `acct-tx`: build, decode, and sign for `xlm`, `algo`, `atom`, `ton`, `ada`, `dot`, `rune`.
- `xmr-wallet`: host-side driver for local `monero-wallet-rpc` (loopback only). It is not in the sealed image. `tx-sign --chain xmr` does not exec it.
- `xmr-keys`: public Monero address derivation, not a transaction verb.
- `zec-sapling`: Sapling/unified address derivation from a mnemonic (public rows). Not a transaction builder or signer. Transparent ZEC stays on `tx-build`/`tx-sign --chain zec`.

Sibling exec uses `blocktools_io::sibling_exit` (same directory as the parent binary, stdin/stdout/stderr inherited). A missing backend is `delegate_missing`.

## EVM-only verbs (deliberate boundary)

These are the EVM contract family, not a hidden gap:

- `contract-call`: `eth_call` (host-side).
- `log-decode`: decode event logs.
- `contract-trace`: trace/simulate through a node (host-side).

They take an EVM chain id, not `--chain sol|xrp|xmr`.
