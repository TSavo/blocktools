# Cookbook (by wallet type and chain)

This index points at the executable recipes. Every **tested** example in those files
is run verbatim by `scripts/recipe-check.py` in e2e. Prefer the recipe over copying
snippets from chat logs.

## By wallet / input type

| You have | Go to |
|---|---|
| BIP39 seed (typos / missing word) | [recipes/input-seed-phrase.md](../recipes/input-seed-phrase.md), [recipes/offline-recovery-guide.md](../recipes/offline-recovery-guide.md) |
| Electrum seed or wallet | [recipes/input-electrum.md](../recipes/input-electrum.md) |
| Bitcoin Core `wallet.dat` | [recipes/input-wallet-dat.md](../recipes/input-wallet-dat.md) |
| Armory | [recipes/input-armory.md](../recipes/input-armory.md) |
| MultiBit / bitcoinj | [recipes/input-multibit.md](../recipes/input-multibit.md) |
| Raw hex / WIF | [recipes/input-raw-key.md](../recipes/input-raw-key.md) |
| Ethereum keystore | [recipes/input-keystore.md](../recipes/input-keystore.md) |
| xprv / xpub / address | [recipes/input-xprv.md](../recipes/input-xprv.md), [recipes/input-xpub-address.md](../recipes/input-xpub-address.md) |
| BIP38 / Blockchain.com | tools `bip38-open`, `blockchain-read` + classify; see ROADMAP-PARITY |
| Password candidate lists | `pw-candidates` piped into openers |
| Unknown file | [recipes/input-unknown.md](../recipes/input-unknown.md) → `classify` |

## By chain

See the chain table in [recipes/README.md](../recipes/README.md) and [CHAINS.md](CHAINS.md).
Account-model chains (XLM, ALGO, ATOM, ADA, DOT, TON) use `acct-tx`; XRP uses `xrp-tx`; Monero uses `xmr-keys` / `xmr-wallet`.

## By goal

| Goal | Recipe |
|---|---|
| List addresses | `--goal addresses` via [recover.sh](../recipes/recover.sh) |
| Check balance | [recipes/goal-check-balance.md](../recipes/goal-check-balance.md) |
| Sweep | [recipes/goal-sweep.md](../recipes/goal-sweep.md) |
| Decode before sign | [recipes/decode-a-transaction.md](../recipes/decode-a-transaction.md) |
| Offline verify + sign | [recipes/goal-verify-and-offline.md](../recipes/goal-verify-and-offline.md) |

## Contract data (EVM, offline filters)

| Goal | Recipe |
|---|---|
| Unknown selector → signature (from a file you supply) | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (b), `sig-hash` |
| Transaction input → arguments (`jq` + signature) | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (a), `abi-decode` |
| `eth_getLogs` events → decoded fields | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (c), `abi-decode` |
| `eth_call` return data (e.g. `balanceOf`) | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (d), `abi-decode` |
| Revert data: `Error(string)`, `Panic`, custom errors | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (e), `abi-decode` |
| Arguments → calldata (`eth_call`/tx `data`), or a bare tuple (CREATE2 salt preimage) | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (g), `abi-encode` |
| Deployment tx → contract address (CREATE, from + nonce) | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (f), `create-address` |
| Factory + salt + init-code hash → CREATE2 address (e.g. a Uniswap V3 pool) | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (f), `abi-encode`, `sig-hash --keccak`, `create-address` |
| ABI → selectors, collisions, ERC-165/ERC-20 interfaces | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (h), `abi-inspect` |
| `eth_getCode` → proxy / delegation / EOF, compiler version, size limit, selector candidates | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (i), `bytecode-inspect` |
| `eth_signTypedData_v4` request or signed typed data → digest, recovered signer, verdict | [recipes/evm-contract-data.md](../recipes/evm-contract-data.md) (j), `typed-data-verify` |
| Contract call tx: signature + args → calldata → unsigned tx → decoded re-verify → sign → broadcast (any chain id) | [recipes/evm-contract-tx.md](../recipes/evm-contract-tx.md), `abi-encode`, `tx-build --data`, `tx-verify --call`, `tx-sign --call` |
| Contract creation tx: init code → unsigned tx → approve by init-code hash → sign (shows new address) | [recipes/evm-contract-tx.md](../recipes/evm-contract-tx.md), `tx-build --create`, `--create-hash` |
| Solana or Tron transfer: build unsigned from a plan, decode, verify (chain auto-detected, `--chain` overrides) | `sol-tron-tx` |
| Prove control of an address: sign a text message (Bitcoin `signmessage` P2PKH, Ethereum `personal_sign`), or verify one (chain detected from the address) | `msg-sign`, `msg-verify` |
