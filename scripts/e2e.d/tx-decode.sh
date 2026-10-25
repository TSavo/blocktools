#!/bin/sh
# tx-decode on public vectors, direct and through the agent boundary (no txids may cross).
set -eu
B=${BIN:-target/release}; V=crates/kr-tx/tests/vectors
o=$($B/tx-decode --text < $V/block170.hex)
echo "$o" | grep -q "1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3 10.00000000" && echo "ok   tx-decode text block170" || { echo "FAIL tx-decode text"; exit 1; }
a=$($B/tx-decode < $V/block170.hex | $B/kr-redact)
echo "$a" | grep -q '"address":"12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"' && ! echo "$a" | grep -q txid && echo "ok   tx-decode via kr-redact (no txid)" || { echo "FAIL tx-decode redact"; exit 1; }
