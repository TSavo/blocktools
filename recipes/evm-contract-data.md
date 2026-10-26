# Contract data (EVM): selectors, calldata, logs, returndata, reverts, deploy addresses

> ⚠️ DANGEROUS: use at your own risk. Code that handles keys and signs transactions should
> always be read and audited by you before you trust it with real funds. Used incorrectly,
> it can destroy your money.

Tiny offline stdin→stdout filters: `sig-hash`, `abi-decode`, `abi-encode`, `create-address`.
No network client, no project, no config, no built-in chain list and no signature database:
you fetch the JSON-RPC response yourself (any EVM chain, any RPC) and pipe it in.

Every tested example below runs on raw Ethereum mainnet JSON-RPC responses recorded in
[fixtures/evm-mainnet/](fixtures/evm-mainnet/); the exact request (curl, URL, UTC time, block) for each
file is in [fixtures/evm-mainnet/PROVENANCE.md](fixtures/evm-mainnet/PROVENANCE.md). The live `curl` steps
are shown for your own RPC (`$RPC`) and are UNTESTED here: CI never touches the network.

## (b) An unknown selector, confirmed with sig-hash

A revert came back as bare `0x5bf6f916` (fixture `04e-custom-error-eth_call.json`, request
"04e" in PROVENANCE.md: `eth_call` of Universal Router `execute(bytes,bytes[],uint256)` with
deadline 1). `sig-hash` has no database, so you supply candidates, here the errors typed from the
router's source ([fixtures/evm/candidate-errors.txt](fixtures/evm/candidate-errors.txt)):

<!-- e2e: expect="matches":["error TransactionDeadlinePassed()"] ; expect="status":"ok" ; rc=0 -->
    sig-hash --lookup "$(jq -r .error.data recipes/fixtures/evm-mainnet/04e-custom-error-eth_call.json)" --sigs recipes/fixtures/evm/candidate-errors.txt

Forward direction, to check a single guess:

<!-- e2e: expect="selector":"0x5bf6f916" ; rc=0 -->
    sig-hash 'error TransactionDeadlinePassed()'

Live (UNTESTED here): `curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x…","data":"0x…"},"latest"]}' "$RPC" | jq -r .error.data`
