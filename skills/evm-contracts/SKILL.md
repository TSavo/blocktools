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
stdout, no network, no config, no built-in signature database and no compiler. The hub
(**smart-wallet**) frames the whole wallet as four moves: **(1) wallet → chain state**
(read), **(2) chain state → unsigned transaction** (build, no key), **(3) secret → signed
transaction** (sign, sealed), **(4) signed transaction → network** (broadcast), with
**verify** as the glue between them and read-only offline decoders living inside verify.

This skill spans two of those roles for EVM:

- Its **read/decode tools are move 1 and verify** — they pull and decode chain state
  (`eth_call` / `eth_getLogs` / `eth_getCode` fetched through `rpc` against your own node),
  and they decode unsigned/signed bytes back to facts so you can compare against intent.
- Its **contract-CALL transaction is moves 2 → 3 → 4** — `abi-encode` the calldata (move 2
  input), `tx-build --data` the unsigned tx (move 2), verify it, `tx-sign --call` sealed
  (move 3), then broadcast (move 4), exactly the path **send-and-sign** runs for a transfer.

You bring the function signature or the init code; it does the ABI work.

Doctrine: these CLIs are **thin users of the evm/abi library**. `abi-encode`,
`abi-decode`, `tx-build --call`, `tx-verify --call` are not separate implementations of
ABI coding — they are one encode/decode core exposed at the command line, which is why
encoding intent and decoding it back are guaranteed to be inverses and the round-trip
check above actually proves something.

The full worked flows live in two recipes; read them before running anything real:

- `recipes/evm-contract-data.md` — the decode/encode toolkit, sections (a)..(j).
- `recipes/evm-contract-tx.md` — the contract-call and contract-creation transaction flow.

## Thinking in plans: calldata is the payload, decode is verify

The hub frames every wallet action as a **plan** — *durable intent plus assertions*,
held apart from the *ephemeral chain state* it runs against. A contract call is exactly
that, and naming its parts is what keeps you from signing the wrong thing.

**The intent of a contract-call plan is a triple: `(to, function signature, args)`.**
"Call `setValue(uint256)` on `0xCONTRACT` with `42`" is the plan, and it is true no matter
what today's nonce, gas price or chain fee happens to be. That intent is not yet bytes —
an EVM contract cannot read a signature or a decimal arg; it reads **calldata**, a
selector (first 4 bytes, `keccak256` of the signature text) followed by the ABI-encoded
arguments.

**`abi-encode` is how you RESOLVE intent into the plan's payload.** It turns
`(signature, args)` into the calldata hex — the concrete thing `tx-build --data` carries
as move 2. So the move-1/verify decoder `abi-encode` is *also* the resolver that produces
move 2's input: the one bridge from durable intent to the bytes that will actually execute.
Nothing else in the tx (recipient, value, gas) encodes *what the contract will do* — only
the calldata does. That is why it is the payload, and why it is the dangerous part: a tx to
the right contract with one wrong arg byte sends your money to a correct address and a wrong
outcome.

**The plan's assertions are checked by DECODING the resolved calldata back and comparing
to intent — decode-as-verify is literally how you confirm the plan.** A contract-call plan
carries three assertions, each a question you answer mechanically against the resolved tx,
not a vibe check:

- `expect_to` — is the tx going to the contract the intent named? (`tx-verify --expect-to`)
- the **args you intended** — `tx-verify --call 'f(...)'` / `tx-sign --call 'f(...)'` runs
  `abi-decode` on the tx's own `input` field, recovering the selector and every argument,
  and refuses the tx if the selector matches no `--call`/`--abi` you supplied
  (`unknown_contract_call` / `unknown_selector`). You then read the decoded args back and
  confirm each one *is* what you meant — the recipient inside a `transfer`, the amount, the
  spender inside an `approve`. Encoding went intent → bytes; **verify runs bytes → intent
  and checks they still agree.** The round trip closing is the proof.
- `cap_fee` — is the fee within the plan's cap? (the policy gate / `--max-fee-per-gas` you
  chose from a move-1 `eth_estimateGas` read, never a constant)

Two consequences you lean on the whole time, the same two the swap skill names:

- **The plan is what you verify against.** The intended `(to, sig, args)` live in the plan;
  the resolved calldata lives in the bytes; verify is the mechanical reconciliation of the
  two, right before the key touches anything. `abi-decode` never guesses — a selector that
  matches none of your signatures is `no_match` with the selector shown, so an unknown
  payload fails loud instead of signing blind.
- **Intent and state stay apart.** Nonce, gas price and `eth_estimateGas` are ephemeral —
  you re-read them (move 1) and re-resolve every time; the `(to, sig, args)` triple is the
  fixed thing. Never bake a live fact into the intent, and never trust a calldata blob
  handed to you (e.g. by SwapChan) — decode it yourself and check it against the triple you
  meant before it is signed.

Everything below is how you resolve, verify, sign and broadcast that plan; the decode/encode
tools are the resolver and the verifier, the `tx-*` tools carry and sign the payload.

## Move 1 + verify (read/decode) vs moves 2→3→4 (the signing path) vs host tools

- **Move 1 and verify — read-only, offline, never touch a key** — `sig-hash`,
  `abi-decode`, `abi-encode`, `abi-inspect`, `bytecode-inspect`, `log-decode`,
  `create-address`, `typed-data-verify`. Pure filters: you feed them a signature, a
  JSON-RPC response you fetched yourself (move 1), or bytecode. Decoding `eth_call` /
  `eth_getLogs` / `eth_getCode` into fields is move 1; decoding unsigned or signed tx bytes
  back to signature + args to check against intent is **verify, the glue**. They run sealed
  or on the host; they decode, they never sign or send. (`abi-encode` is dual-use: as a
  decoder it is move-1/verify, and its calldata output is the input to move 2 below.)
- **The signing path — moves 2 → 3 → 4** — `tx-build`, `tx-verify`, `tx-sign`. A
  contract-call or creation tx goes through the sealed boundary exactly like a transfer:
  **build** the unsigned tx (move 2), **verify** it (`--call` decodes the calldata back to
  signature + args; `--create-hash` pins the init code), **sign** sealed (move 3, verify
  again), then **broadcast** (move 4). The private key enters only `tx-sign`, inside the
  sealed run, and comes back `[REDACTED]`.
- **HOST tools, move 1, NOT in the sealed image** — `contract-call`, `contract-trace` and
  `rpc`. These are move-1 reads against **the user's own node** (`rpc --url <their-node>`):
  they need the network by design, so `sealed-run` refuses them. Run them on the host and
  give them public data only (addresses, public keys). They send only through `rpc`'s read
  allowlist and secret checks, so a read is only ever a read.

Rules that carry over from the hub: **verify every transaction** before you sign it (move 2
→ 3) and again before you broadcast it (move 3 → 4), keep keys inside the sealed boundary,
and **never `./blocktools reveal`**. blocktools has no chain list baked in — you fetch the
JSON-RPC response yourself from whatever EVM chain and RPC you choose, and pin the chain
with `--chain-id N`.

## Jobs → tool

The first block is **move 1 / verify** (read-only, offline, no key); the last two rows are
the **moves 2 → 3 → 4** signing path.

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
| signature + args | a signed contract-call tx (moves 2→3→4) | `abi-encode` → `tx-build --data` → `tx-verify --call` → `tx-sign --call` → broadcast |
| init code | a signed contract-creation tx (moves 2→3→4) | `tx-build --create` → `tx-verify --create-hash` → `tx-sign` |

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

A full contract call walks moves 2 → 3 → 4: `abi-encode` the calldata and `tx-build` the
unsigned tx (move 2), then verify (decode back to signature + args and compare to intent).
`--gas` is required and comes from your node's `eth_estimateGas` — a move-1 read against
your own node — never a constant; the chain is whatever you pin with `--chain-id`:

```
tx-build --chain eth --chain-id 8453 --nonce 3 --max-fee-per-gas 2000000000 --gas <estimate> \
  --to 0xCONTRACT --data $(abi-encode 'setValue(uint256)' 42 | jq -r .data) \
  | tx-verify --chain-id 8453 --expect-to 0xCONTRACT --call 'setValue(uint256)'
```

Without a matching `--call` (or `--abi`), `tx-verify` flags the selector and refuses the tx
(`unknown_contract_call` / `unknown_selector`). Then **sign sealed** (move 3) with the same
assertions — the terminal summary shows `Contract call: setValue(uint256)` and each
argument before you type the code:

```
tx-sign --tx unsigned.json --chain-id 8453 --expect-to 0xCONTRACT --call 'setValue(uint256)' < key
```

Contract creation has no `to`: `tx-build --create INITCODE_HEX` (or `@FILE`) prints
`initcode_keccak256`, and `tx-verify` / `tx-sign` approve it only with
`--create-hash $(sig-hash --keccak INITCODE | jq -r .keccak256)`. The sign summary prints
the new contract address (cross-check with `create-address --deployer ADDR --nonce N`).
**Broadcast on the host** (move 4), through the same node you read in move 1:
`tx-broadcast --chain eth --url URL < signed.json` (which wraps `eth_sendRawTransaction`).

## See also

- **smart-wallet** — the hub: the four moves (1 read, 2 build, 3 sign, 4 broadcast) and
  verify as the glue that this skill's read/decode and signing tools slot into.
- **send-and-sign** — the general moves 2 → 3 → 4 (build → verify → sign → broadcast) loop
  and the sealed boundary this skill plugs into.
- **cross-chain-swap** — swaps and routes when the contract call is a DEX interaction (e.g.
  a THORChain `depositWithExpiry` router call on an EVM source chain).
- `recipes/evm-contract-tx.md` and `recipes/evm-contract-data.md` — the authoritative,
  CI-tested worked flows. Prefer them over snippets pasted from chat.
- `man/man1/`: `abi-encode.1`, `abi-decode.1`, `abi-inspect.1`, `sig-hash.1`,
  `create-address.1`, `bytecode-inspect.1`, `log-decode.1`, `typed-data-verify.1`,
  `contract-call.1`, `contract-trace.1`, `tx-build.1`, `tx-verify.1`, `tx-sign.1`.
