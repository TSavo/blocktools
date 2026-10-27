# EVM contract calls and contract creation: build, verify, sign, broadcast

Works on any EVM chain: the chain is the `--chain-id N` you pin (tx-build writes it into the
transaction, tx-verify and tx-sign refuse any other). BlockTools has no compiler and no
deploy/project management: you bring the calldata's function signature, or the init code bytes.

## Contract call

1. Calldata from a signature and arguments with `abi-encode`, then an unsigned tx with
   `tx-build --data` (`--gas` is required: estimate it with your node, nothing is guessed;
   `--send WEI` adds value for payable functions). 2. Re-verify it: `tx-verify --call SIGNATURE`
   decodes the calldata strictly (it must re-encode byte for byte) and prints the function and
   arguments; only an exact match lifts the generic `unknown_contract_call` refusal, and the
   destination must still be your `--expect-to` (the contract):

<!-- e2e: expect="signature":"setValue(uint256)" ; expect="value":"42" ; expect="status":"ok" ; rc=0 -->
    tx-build --chain eth --chain-id 8453 --nonce 3 --max-fee-per-gas 2000000000 --gas 60000 --to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF --data $(abi-encode 'setValue(uint256)' 42 | jq -r .data) | tx-verify --chain-id 8453 --expect-to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF --call 'setValue(uint256)'

Without a matching `--call` (or `--abi FILE`), the selector is flagged and the tx is refused:

<!-- e2e: expect="status":"unknown_selector" ; expect=unknown_contract_call ; rc=1 -->
    tx-build --chain eth --chain-id 1 --nonce 3 --max-fee-per-gas 2000000000 --gas 60000 --to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF --data $(abi-encode 'setValue(uint256)' 42 | jq -r .data) | tx-verify --chain-id 1 --expect-to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF

3. Sign with the same assertions; the terminal summary shows `Contract call: setValue(uint256)`
   and each argument before you type the code:

    tx-sign --tx unsigned.json --chain-id 8453 --expect-to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF --call 'setValue(uint256)' < key

4. Broadcast: `tx-broadcast --chain eth --url URL < signed.json` (it shows the tx and asks for its own code).

## Contract creation

`tx-build --create INITCODE_HEX` (or `@FILE`) builds a tx with no `to` and prints
`initcode_keccak256`. tx-verify and tx-sign approve a creation only with `--create-hash` equal to
keccak256 of the exact init code (no `--expect-to`: there is no destination yet):

<!-- e2e: expect="kind":"create" ; expect="status":"ok" ; rc=0 -->
    tx-build --chain eth --chain-id 1 --nonce 0 --max-fee-per-gas 2000000000 --gas 100000 --create 600a600c600039600a6000f3602a60005260206000f3 | tx-verify --chain-id 1 --create-hash $(sig-hash --keccak 600a600c600039600a6000f3602a60005260206000f3 | jq -r .keccak256)

The tx-sign summary then shows the init code size and hash and `New contract address:` (CREATE from
the signer and nonce; cross-check with `create-address --deployer ADDR --nonce N`).

Tested end to end (sign through a pty, broadcast to a local mock node) by `scripts/e2e.d/contract-tx.sh`.
Measured against mocks only, not a live node.
