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

`log-decode` does the same and keeps where each log came from (`address`, `block_number`, `log_index`,
`transaction_hash`); it also reads receipts (their `logs`), JSON lines, and filters with `--address`/`--only-matched`.
Logs whose topic0 matches none of your signatures are printed as `no_match` lines, never guessed:

<!-- e2e: expect="event":"Transfer" ; expect="block_number": ; expect="value":"154943368057" ; rc=0 -->
    log-decode --only-matched --sig 'Transfer(address indexed from, address indexed to, uint256 value)' recipes/fixtures/evm-mainnet/01c-usdc-transfer-getLogs.json

## (d) Return data: `balanceOf`

`03c-usdc-balanceOf.json` (request "03c") is an `eth_call` result. Give the output types (USDC uses six decimals,
see `03a`):

<!-- e2e: expect="value":"58142937468866" ; rc=0 -->
    abi-decode --types uint256 < recipes/fixtures/evm-mainnet/03c-usdc-balanceOf.json

### Calling the contract yourself: `contract-call`

`contract-call` sends the `eth_call` for you (host-side, network; it goes through `rpc`'s read allowlist and secret
checks), reads the chain id from the endpoint first and prints it on every line, then decodes the return data with
the `returns (...)` part of the signature. Here the endpoint is a local mock answering with the recorded `03a`
fixture; on a real node give its URL (any EVM chain; `--chain-id N` refuses any other chain):

<!-- e2e: expect="chain_id":1 ; expect="function":"decimals()" ; expect="value":"6" ; rc=0 -->
    contract-call $ETH/03a 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 'decimals() returns (uint8)'

With `--abi FILE --read` it calls every view/pure function that takes no inputs (a one-shot state read); `--block`
pins a block number, tag or block hash. A revert comes back decoded (`Error(string)`, `Panic`, custom errors from
`--abi`/`--error`) with exit 1; an empty `0x` reply to a function that declares returns is `empty_return` (no code
at that address on that chain, or no such function), never a zero.

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

## (f) Contract addresses: CREATE and CREATE2

CREATE: the address is `keccak256(rlp([deployer, nonce]))`. `05a` (request "05a") is a deployment tx;
create-address reads `from` and `nonce` from it, and the result matches `contractAddress` in its receipt `05b`:

<!-- e2e: expect="address":"0x0a0e5274D286A72614a4E4015370395Ef9E42EEd" ; rc=0 -->
    create-address < recipes/fixtures/evm-mainnet/05a-create-tx.json

CREATE2 (EIP-1014): `keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))`. `05c`/`05d` (requests
"05c", "05d") create the Uniswap V3 USDT pool with token0 `0x3246…8edb`, token1 USDT, fee 100. The factory
salt is `keccak256(abi.encode(token0, token1, fee))` and the init-code hash is the factory's fixed
`POOL_INIT_CODE_HASH` from Uniswap's `PoolAddress.sol` (not fetched). The result matches the pool address in
the `PoolCreated` log of `05d`:

<!-- e2e: expect="address":"0x7fF72b3aab6db0398e7fbCaB8efcd37159323EcF" ; rc=0 -->
    abi-encode --raw '(address,address,uint24)' 0x3246806c924fab68dd6db5d39b516ade72618edb 0xdac17f958d2ee523a2206206994597c13d831ec7 100 | sig-hash --keccak | jq -c '{deployer: "0x1F98431c8aD98523631AE4a59f267346ea31F984", salt: .keccak256, init_code_hash: "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54"}' | create-address | jq -c '{scheme,address}'

<!-- e2e: expect=0x7ff72b3aab6db0398e7fbcab8efcd37159323ecf ; rc=0 -->
    jq -r '.result.logs[0].data' recipes/fixtures/evm-mainnet/05d-create2-pool-receipt.json | abi-decode --types '(int24,address)' | jq -r '.args[1].value' | tr A-F a-f

Live (UNTESTED here): `curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0x…"]}' "$RPC" | create-address`

## (h) What an ABI implements, and selector collisions

`recipes/fixtures/evm/erc20-plus-collision.txt` is the EIP-20 function list plus `gasprice_bit_ether(int128)`,
whose selector is also `0x23b872dd` (`transferFrom`). abi-inspect reports the collision and that ERC-20 is complete:

<!-- e2e: expect="selector":"0x23b872dd" ; rc=0 -->
    abi-inspect recipes/fixtures/evm/erc20-plus-collision.txt | jq -c .selector_collisions

<!-- e2e: expect="complete":true,"interface":"ERC-20" ; rc=0 -->
    abi-inspect recipes/fixtures/evm/erc20-plus-collision.txt | jq -c '.interfaces[0]'

A compiler artifact (`{"abi": [...]}`) or a bare ABI array works the same. Live (UNTESTED here): an explorer's
verified-ABI download, e.g. `curl -s "$EXPLORER_ABI_URL" | jq -r .result | abi-inspect`.

## (i) What is deployed: `eth_getCode`

`06` (request "06") is the runtime code of a small mainnet contract. bytecode-inspect reads the response as-is;
the Solidity metadata trailer says solc 0.8.20, and the dispatcher's PUSH4/EQ constants are listed as
selector candidates (a heuristic: confirm each with `sig-hash --lookup` and a signature file you trust):

<!-- e2e: expect="solc":"0.8.20" ; expect="0x8da5cb5b" ; rc=0 -->
    bytecode-inspect < recipes/fixtures/evm-mainnet/06-getCode-small.json | jq -c '{kind, size, exceeds_eip170, solc: .metadata.solc, selector_candidates}'

`0x8da5cb5b` is `owner()`:

<!-- e2e: expect="owner()" ; rc=0 -->
    sig-hash 'owner()'

An EIP-1167 minimal proxy (the reference code from the EIP) gives its implementation:

<!-- e2e: expect="kind":"eip1167_proxy" ; rc=0 -->
    bytecode-inspect 0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3 | jq -c '{kind, implementation}'

Live (UNTESTED here): `curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0x…","latest"]}' "$RPC" | bytecode-inspect`

## (j) What a typed-data signature commits to: EIP-712

`eip712-mail-signed.json` is the Mail example from the EIP-712 specification with its published signature.
typed-data-verify prints the domain separator, message hash and digest (compare them with what a wallet
shows) and recovers the signer:

<!-- e2e: expect="status":"valid" ; expect=0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826 ; rc=0 -->
    typed-data-verify recipes/fixtures/evm/eip712-mail-signed.json | jq -c '{primary_type, chain_id, recovered, status}'

A different expected signer is a mismatch (exit 1):

<!-- e2e: expect=signer_mismatch ; rc=1 -->
    typed-data-verify --signer 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB recipes/fixtures/evm/eip712-mail-signed.json

An `eth_signTypedData_v4` request (`{"params": [address, typedData]}`) can be piped in as-is with `--sig`;
its address becomes the expected signer. Live (UNTESTED here): capture the request a dapp sends and the
signature the wallet returns, then `typed-data-verify --sig 0x… request.json`.
