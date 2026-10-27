#!/bin/sh
# tx-decode --chain eth on committed public Ethereum mainnet raw txs (fixtures/evm-mainnet: one each of legacy
# EIP-155, EIP-2930, EIP-1559, EIP-4844, EIP-7702, fetched from publicnode with eth_getRawTransactionByHash, a JSON-RPC POST outside the rpc tool allowlist)
# must reproduce every field eth_getTransactionByHash returned for the same txid. Offline: no network here.
set -eu
B=${BIN:-target/release}
f() { echo "FAIL $1"; exit 1; }
python3 scripts/evm-decode-check.py "$B" || f "evm-decode-check"
# auto-detect: the same bytes decode with no --chain; --chain eth refuses a UTXO tx
$B/tx-decode < fixtures/evm-mainnet/eip4844.raw.json | grep -q '"type":"evm-4844"' || f autodetect
echo "ok   tx-decode without --chain auto-detects the EVM envelope (evm-4844)"
D=$(mktemp); trap 'rm -f "$D"' EXIT
if echo 0100000000 | $B/tx-decode --chain eth > "$D" 2>&1; then f "--chain eth accepted a non-EVM input"; fi
grep -q not_evm "$D" && echo "ok   tx-decode --chain eth on a non-EVM input -> not_evm (exit 2)" || f not_evm
