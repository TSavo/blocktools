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

## (a) Transaction input → arguments

`01a-erc20-transfer-tx.json` is the `eth_getTransactionByHash` response for a USDC transfer (request "01a" in
PROVENANCE.md). Pull `input` out with `jq` and give `abi-decode` the signature:

<!-- e2e: expect="signature":"transfer(address,uint256)" ; expect="value":"0x264bd8291fAE1D75DB2c5F573b07faA6715997B5" ; expect="value":"5050510000" ; rc=0 -->
    jq -r .result.input recipes/fixtures/evm-mainnet/01a-erc20-transfer-tx.json | abi-decode --sig 'transfer(address,uint256)'

The whole response works too (`result.input` is found on its own). Without a matching signature it
answers `no_match` with the selector (exit 0; exit 2 is malformed input) and never guesses.

<!-- e2e: expect="status":"no_match" ; expect="selector":"0xa9059cbb" ; rc=0 -->
    abi-decode --sig 'approve(address,uint256)' < recipes/fixtures/evm-mainnet/01a-erc20-transfer-tx.json

Live (UNTESTED here): `curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0x…"]}' "$RPC" | jq -r .result.input | abi-decode --sig 'transfer(address,uint256)'`

## (c) Logs: `eth_getLogs` Transfer events

`01c-usdc-transfer-getLogs.json` (request "01c") is an `eth_getLogs` result; each log becomes one JSON line, with
indexed topics decoded:

<!-- e2e: expect="signature":"Transfer(address,address,uint256)" ; expect="indexed":true ; expect="value":"154943368057" ; rc=0 -->
    abi-decode --sig 'event Transfer(address indexed from, address indexed to, uint256 value)' < recipes/fixtures/evm-mainnet/01c-usdc-transfer-getLogs.json

## (d) Return data: `balanceOf`

`03c-usdc-balanceOf.json` (request "03c") is an `eth_call` result. Give the output types (USDC uses six decimals,
see `03a`):

<!-- e2e: expect="value":"58142937468866" ; rc=0 -->
    abi-decode --types uint256 < recipes/fixtures/evm-mainnet/03c-usdc-balanceOf.json

## (e) Reverts: `Error(string)` and a custom error

`Error(string)` and `Panic(uint256)` are decoded with no signature. `04d` (request "04d") is a
`transferFrom` without allowance:

<!-- e2e: expect="signature":"Error(string)" ; expect="value":"ERC20: transfer amount exceeds allowance" ; rc=0 -->
    jq .error recipes/fixtures/evm-mainnet/04d-error-string-eth_call.json | abi-decode

A custom error needs its declaration (from section (b)):

<!-- e2e: expect="signature":"TransactionDeadlinePassed()" ; expect="kind":"error" ; rc=0 -->
    jq .error recipes/fixtures/evm-mainnet/04e-custom-error-eth_call.json | abi-decode --abi recipes/fixtures/evm/candidate-errors.txt

## (g) Arguments → calldata, and back

`abi-encode` is the inverse of `abi-decode`. The Solidity ABI spec example `baz(uint32,bool)` with
`69, true` gives selector `0xcdcd77c0`:

<!-- e2e: expect="selector":"0xcdcd77c0" ; rc=0 -->
    abi-encode 'baz(uint32,bool)' 69 true | jq -c '{signature,selector}'

Re-encoding the decoded arguments of `01a` gives its `input` byte for byte:

<!-- e2e: expect="value":"5050510000" ; rc=0 -->
    abi-encode --raw 'transfer(address,uint256)' 0x264bd8291fae1d75db2c5f573b07faa6715997b5 5050510000 | abi-decode --sig 'transfer(address,uint256)'

Live (UNTESTED here): `D=$(abi-encode --raw 'balanceOf(address)' 0x…); curl -s -X POST -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0x…\",\"data\":\"$D\"},\"latest\"]}" "$RPC" | abi-decode --sig 'balanceOf(address) returns (uint256)' --output`
