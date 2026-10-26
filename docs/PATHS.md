# Paths: RPC in, tools piped, RPC out

Each path is a short `sh` script in [recipes/paths/](../recipes/paths/) with numbered stages. Data comes
from a node, moves through blocktools on stdout and files, and when a broadcaster exists it goes back to a
node. Pick the row for your chain and job.

| # | Path | Chain family | Script | Ends in |
|---|------|--------------|--------|---------|
| 1 | fetch utxos → build → verify → sign → decode → broadcast | Bitcoin-style (btc, ltc, doge) | [utxo-sweep.sh](../recipes/paths/utxo-sweep.sh) | broadcast |
| 2 | fetch account → build → verify → sign → decode → broadcast | EVM, any chain id (1, 8453 Base, ...) | [evm-sweep.sh](../recipes/paths/evm-sweep.sh) | broadcast |
| 3 | fetch utxos → build → decode → verify (no key) | Bitcoin-style | [utxo-inspect.sh](../recipes/paths/utxo-inspect.sh) | a checked unsigned PSBT |
| 4 | fetch tx → rebuild → decode → verify (chain id) | EVM ERC-20 transfer | [evm-inspect.sh](../recipes/paths/evm-inspect.sh) | a verdict |
| 5 | keys → build → decode → sign → decode | Cosmos (atom) | [cosmos-send.sh](../recipes/paths/cosmos-send.sh) | signed tx; broadcast **NOT BUILT** |
| 6 | fetch blockhash → build → decode → verify | Solana | [sol-transfer.sh](../recipes/paths/sol-transfer.sh) | unsigned tx; sign **NOT BUILT** |
| 7 | fetch block → build → decode → txid | Tron | [tron-transfer.sh](../recipes/paths/tron-transfer.sh) | unsigned tx; verify and sign **NOT BUILT** |
| 8 | fetch tx → abi-decode | EVM, any contract call | not written | pending: abi-decode has not landed |

Paths 4, 6 and 7 call the wasm exports (`node`, `bindings/wasm/pkg/node`, built by `sh scripts/wasm-check.sh`)
because the CLI has no Solana or Tron builder. The gaps are in [FINDINGS.md](FINDINGS.md) (D1-9, D1-10).

## How they are tested (Linux)

`scripts/e2e.d/paths.sh` runs every script above in the e2e gate stage:

- **Fetch** stages read saved real responses from [recipes/paths/fixtures/](../recipes/paths/fixtures/)
  (Bitcoin Esplora UTXOs, an Ethereum USDC transfer, a Solana blockhash, a Tron block), served on
  127.0.0.1 by `scripts/e2e-only/replay-rpc.py`. Paths 1, 2 and 5 fetch from the local mock instead.
- **Broadcast** stages post to `scripts/mock-chain.py` on 127.0.0.1, which logs the request. The test
  checks the logged body equals the signed bytes exactly: for Bitcoin, the network tx extracted from the
  signed PSBT by an independent extractor (`scripts/e2e-only/psbt-extract.py`); for EVM, the
  `eth_sendRawTransaction` parameter against tx-sign's `signed_tx`, on chain ids 1 and 8453.
- **Keys** are public throwaway keys (the integer 1 as a private key). No real secret, no real network.
- tx-sign and tx-broadcast want a human to type a code; the test answers through a pty
  (`TTY_DRIVE`). Run by hand, the scripts ask you on your terminal.

## The real-network leg: untested

No path has been run against a real node with real funds. That is the untested step. A human runs it with
their own node and key, for example:

    RPC=https://your-esplora.example KEY=/path/to/key sh recipes/paths/utxo-sweep.sh btc FROM_ADDR TO_ADDR

    RPC=https://your-node.example KEY=/path/to/key sh recipes/paths/evm-sweep.sh 1 FROM_ADDR TO_ADDR

Read [SECURITY.md](SECURITY.md) before using a real key; running these scripts inside `./blocktools run` is
not tested. Both scripts stop for a typed code before signing and again before broadcasting.

Known trap on path 2: tx-build does not compare the fetched account's chain id with `--chain-id`
(FINDINGS D1-11). Check `chain_id` in stage 1's output yourself.
