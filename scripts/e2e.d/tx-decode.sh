#!/bin/sh
# tx-decode on public vectors, direct and through the agent boundary (no txids may cross).
set -eu
B=${BIN:-target/release}; V=crates/tx/tests/vectors
o=$($B/tx-decode --text < $V/block170.hex)
echo "$o" | grep -q "1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3 10.00000000" && echo "ok   tx-decode text block170" || { echo "FAIL tx-decode text"; exit 1; }
a=$($B/tx-decode < $V/block170.hex | $B/redact)
echo "$a" | grep -q '"address":"12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"' && ! echo "$a" | grep -q txid && echo "ok   tx-decode via redact (no txid)" || { echo "FAIL tx-decode redact"; exit 1; }
# Novacoin explorer JSON -> raw hex (hash-checked), then decoded back to the same txid.
N=crates/tx/tests/data/nvc_c053a3fd.json; T=c053a3fddd508df8cadd90bf8c987c35802c2779a8a19b4efc8c83124d11df20
h=$($B/tx-decode --nvc-json $T < $N)
[ ${#h} = 360 ] && echo "$h" | $B/tx-decode --chain nvc | grep -q "$T" && echo "ok   tx-decode --nvc-json coinstake" || { echo "FAIL tx-decode --nvc-json"; exit 1; }
if $B/tx-decode --nvc-json cdced5fa03d9651443deea305e09290b925794ed3836de21ef30e13f42f83bd7 < $N > /dev/null; then echo "FAIL tx-decode --nvc-json wrong txid accepted"; exit 1; else echo "ok   tx-decode --nvc-json wrong txid refused"; fi
# A non-UTXO chain without a decoder (xmr) is refused, not parsed as UTXO bytes (docs/COVERAGE.md finding).
o=$($B/tx-decode --chain xmr < $V/block170.hex) && { echo "FAIL tx-decode --chain xmr accepted"; exit 1; }
echo "$o" | grep -q '"error":"unsupported_chain' && echo "ok   tx-decode --chain xmr refused (unsupported_chain)" || { echo "FAIL tx-decode --chain xmr: $o"; exit 1; }
