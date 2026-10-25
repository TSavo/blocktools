#!/bin/sh
# Local (no Docker) check of the agent boundary using only the public BIP39 test vector.
set -eu
B=target/release; T=$(mktemp -d)
echo "abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot" > "$T/seed.txt"
$B/seed-repair < "$T/seed.txt" | $B/derive --count 2 | $B/kr-redact > "$T/agent.jsonl"
grep -q bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu "$T/agent.jsonl"
if grep -Eq 'wif|private_key|mnemonic|abandon|[0-9a-fA-F]{64}' "$T/agent.jsonl"; then echo "LEAK"; exit 1; fi
echo "e2e ok: $(wc -l < "$T/agent.jsonl") public lines, no secrets"; rm -rf "$T"
