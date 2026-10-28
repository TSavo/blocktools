---
name: evm-contracts
description: >-
  Call or deploy an EVM/Ethereum contract offline, and decode or encode its
  data. Use when the user wants to build a contract-call or contract-creation
  transaction, turn a function signature and arguments into calldata, decode
  tx input / eth_getLogs events / eth_call return data / revert reasons
  (Error, Panic, custom errors), look up an unknown 4-byte selector, compute a
  CREATE or CREATE2 contract address, inspect an ABI (selectors, collisions,
  ERC-165/ERC-20) or deployed bytecode (proxy, EOF, compiler, size), or verify
  EIP-712 (eth_signTypedData_v4) typed data — digest, signer, verdict. The
  offline read-and-build layer for EVM, feeding the build -> verify -> sign
  loop. blocktools, self-custody, keys never leave the sealed boundary.
---

# EVM contracts

blocktools is a set of offline Rust Unix filters: one JSON object per line, stdin to
stdout, no network, no config, no built-in signature database and no compiler. This skill
is the EVM **read-and-build layer**: it turns signatures, arguments, RPC responses and
bytecode into decoded facts and into calldata, then hands a contract-call or
contract-creation transaction to the same `tx-build -> tx-verify -> tx-sign -> broadcast`
loop every other blocktools wallet uses. You bring the function signature or the init
code; it does the ABI work.

The full worked flows live in two recipes; read them before running anything real:

- `recipes/evm-contract-data.md` — the decode/encode toolkit, sections (a)..(j).
- `recipes/evm-contract-tx.md` — the contract-call and contract-creation transaction flow.

## Offline decoders vs the signing path vs host network tools

- **Read-only, offline, never touch a key** — `sig-hash`, `abi-decode`, `abi-encode`,
  `abi-inspect`, `bytecode-inspect`, `log-decode`, `create-address`, `typed-data-verify`.
  Pure filters: you feed them a signature, a JSON-RPC response you fetched yourself, or
  bytecode. They run sealed or on the host; they decode, they never sign or send.
- **Signing path** — `tx-build`, `tx-verify`, `tx-sign`. A contract-call or creation tx
  goes through the sealed boundary exactly like a transfer: build unsigned, verify it
  (`--call` decodes the calldata back to signature + args; `--create-hash` pins the init
  code), sign sealed, verify again, then broadcast. The private key enters only `tx-sign`,
  inside the sealed run, and comes back `[REDACTED]`.
- **HOST network tools, NOT in the sealed image** — `contract-call`, `contract-trace` and
  `rpc`. They need the network by design, so `sealed-run` refuses them. Run them on the
  host and give them public data only (addresses, public keys). They send only through
  `rpc`'s read allowlist and secret checks.

Rules that carry over from the hub: **verify every transaction** before you sign it, keep
keys inside the sealed boundary, and **never `./blocktools reveal`**. blocktools has no
chain list baked in — you fetch the JSON-RPC response yourself from whatever EVM chain and
RPC you choose, and pin the chain with `--chain-id N`.

## Jobs → tool

| You have | You want | Tool |
|---|---|---|
| An unknown 4-byte selector / revert selector | its signature | `sig-hash --lookup … --sigs FILE` (you supply candidates) |
| Tx `input` / calldata | the arguments | `abi-decode --sig 'f(...)'` |
| `eth_getLogs` / receipt logs | decoded event fields | `abi-decode --sig 'event …'` or `log-decode` (keeps address/block/log_index) |
| `eth_call` return data | the values | `abi-decode --types '(…)'` or `--sig '… returns (…)' --output` |
| Revert data | `Error(string)` / `Panic` / custom error | `abi-decode` (built-ins) / `abi-decode --abi FILE` |
| A signature + arguments | calldata | `abi-encode` (`--raw` for bare hex) |
| A deployment tx | the CREATE address | `create-address` (reads `from`+`nonce`) |
| factory + salt + init-code hash | the CREATE2 address | `abi-encode --raw` → `sig-hash --keccak` → `create-address` |
| An ABI | selectors, collisions, ERC-165/ERC-20 | `abi-inspect` |
| `eth_getCode` | proxy / EOF / compiler / size | `bytecode-inspect` |
| EIP-712 typed data / `eth_signTypedData_v4` | digest, signer, verdict | `typed-data-verify` |
| signature + args | a signed contract-call tx | `abi-encode` → `tx-build --data` → `tx-verify --call` → `tx-sign --call` → broadcast |
| init code | a signed contract-creation tx | `tx-build --create` → `tx-verify --create-hash` → `tx-sign` |

`abi-decode` never guesses: a selector or topic0 that matches none of your signatures is
reported `no_match` with the selector (exit 0; malformed input is `bad_input`, exit 2).
`sig-hash` has no database, so you always supply the candidate signatures.

## Illustrative pipelines

Decode a USDC transfer's calldata (you pulled the tx with your own RPC):

```
jq -r .result.input tx.json | abi-decode --sig 'transfer(address,uint256)'
```

Decode an `eth_getLogs` result, keeping provenance, matched events only:

```
log-decode --only-matched \
  --sig 'Transfer(address indexed from, address indexed to, uint256 value)' getLogs.json
```

Turn a revert into a reason (`Error`/`Panic` are built in; a custom error needs its decl):

```
jq .error eth_call.json | abi-decode                       # Error(string) / Panic
jq .error eth_call.json | abi-decode --abi candidate-errors.txt   # custom error
```

CREATE2 address from a salt preimage, a factory and a fixed init-code hash:

```
abi-encode --raw '(address,address,uint24)' 0xTOKEN0 0xTOKEN1 100 \
  | sig-hash --keccak \
  | jq -c '{deployer:"0xFACTORY", salt:.keccak256, init_code_hash:"0x…"}' \
  | create-address | jq -c '{scheme,address}'
```

A full contract call: signature + args → calldata → unsigned tx → decoded re-verify.
`--gas` is required and comes from your node's `eth_estimateGas`, never a constant; the
chain is whatever you pin with `--chain-id`:

```
tx-build --chain eth --chain-id 8453 --nonce 3 --max-fee-per-gas 2000000000 --gas <estimate> \
  --to 0xCONTRACT --data $(abi-encode 'setValue(uint256)' 42 | jq -r .data) \
  | tx-verify --chain-id 8453 --expect-to 0xCONTRACT --call 'setValue(uint256)'
```

Without a matching `--call` (or `--abi`), `tx-verify` flags the selector and refuses the tx
(`unknown_contract_call` / `unknown_selector`). Then sign sealed with the same assertions —
the terminal summary shows `Contract call: setValue(uint256)` and each argument before you
type the code:

```
tx-sign --tx unsigned.json --chain-id 8453 --expect-to 0xCONTRACT --call 'setValue(uint256)' < key
```

Contract creation has no `to`: `tx-build --create INITCODE_HEX` (or `@FILE`) prints
`initcode_keccak256`, and `tx-verify` / `tx-sign` approve it only with
`--create-hash $(sig-hash --keccak INITCODE | jq -r .keccak256)`. The sign summary prints
the new contract address (cross-check with `create-address --deployer ADDR --nonce N`).
Broadcast on the host: `tx-broadcast --chain eth --url URL < signed.json`.

## See also

- **send-and-sign** — the general build → verify → sign → broadcast loop and the sealed
  boundary this skill plugs into.
- **cross-chain-swap** — swaps and routes when the contract call is a DEX interaction.
- `recipes/evm-contract-tx.md` and `recipes/evm-contract-data.md` — the authoritative,
  CI-tested worked flows. Prefer them over snippets pasted from chat.
- `man/man1/`: `abi-encode.1`, `abi-decode.1`, `abi-inspect.1`, `sig-hash.1`,
  `create-address.1`, `bytecode-inspect.1`, `log-decode.1`, `typed-data-verify.1`,
  `contract-call.1`, `contract-trace.1`, `tx-build.1`, `tx-verify.1`, `tx-sign.1`.
