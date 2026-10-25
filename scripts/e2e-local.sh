#!/bin/sh
# Local (no Docker) check of the agent boundary using only the public BIP39 test vector.
set -eu
B=target/release; T=$(mktemp -d)
echo "abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot" > "$T/seed.txt"
$B/seed-repair < "$T/seed.txt" | $B/derive --count 2 | $B/kr-redact > "$T/agent.jsonl"
grep -q bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu "$T/agent.jsonl"
if grep -Eq 'wif|private_key|mnemonic|abandon|[0-9a-fA-F]{64}' "$T/agent.jsonl"; then echo "LEAK"; exit 1; fi
echo "e2e ok: $(wc -l < "$T/agent.jsonl") public lines, no secrets"; rm -rf "$T"
# Same check through the real boundary script (container/kr-run agent).
T=$(mktemp -d)
echo "abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot" \
  | PATH="$PWD/$B:$PATH" sh container/kr-run agent 'seed-repair | derive --count 1' > "$T/agent.jsonl"
grep -q bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu "$T/agent.jsonl"
if grep -Eq 'wif|private_key|mnemonic|abandon|[0-9a-fA-F]{64}' "$T/agent.jsonl"; then echo "LEAK via kr-run"; exit 1; fi
echo "kr-run ok: $(wc -l < "$T/agent.jsonl") public lines"; rm -rf "$T"
