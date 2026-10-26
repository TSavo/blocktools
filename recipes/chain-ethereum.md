# Chain: Ethereum (and EVM chains via --chain-id)

Built: addresses, keystore-open, EIP-1559 and legacy transactions, ETH sweep, ERC-20 transfer
with a gas top-up, decode/verify with the chain id, sign and broadcast behind typed codes.

<!-- e2e: expect=0x9858EfFD232B4033E47d90003D41EC34EcaEda94 -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain eth --count 1'

<!-- e2e: expect=0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf -->
    recipes/recover.sh /in/key.hex - --chain eth --goal addresses

Sweep: `recipes/recover.sh in/keystore.json 0xDEST --password-file secrets/keystore.pw --chain-id 1 --url RPC`.
The e2e test sweeps the keystore vector against a mock RPC. Other EVM chains: pass their `--chain-id` and RPC.
UNTESTED against live networks other than reads.

## Round trip, run in the gate

`recipes/paths/evm-sweep.sh` goes from a saved real RPC response, through the tools, to a local mock chain. It is run by `scripts/e2e.d/paths.sh` (Linux). See [docs/PATHS.md](../docs/PATHS.md) for what is checked and what is not run against a real network.
