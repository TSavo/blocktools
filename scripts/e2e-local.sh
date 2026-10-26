#!/bin/sh
# Local (no Docker) end-to-end checks of the agent boundary.
# Only public test vectors / throwaway self-made fixtures are used.
set -eu
# No pipefail here on purpose: checks are `tool | grep -q EXPECTED && ok || fail`, where the tool's
# nonzero exit IS the refusal under test; the asserted output, not the exit code, decides pass/fail.
. scripts/e2e-only/portable.sh
B="$PWD/target/release"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# Secret VALUES (field names may appear: redact keeps them with a "[REDACTED]" placeholder).
LEAK='"(wif|private_key|xprv|seed|mnemonic|passphrase|password|secret)":"[^[]|xprv[1-9A-Za-z]{20}|abandon|[0-9a-fA-F]{64}|"(5|K|L)[1-9A-HJ-NP-Za-km-z]{50,51}"|[1-9A-HJ-NP-Za-km-z]{60,}'
# boundary <name> <expect-substring> <pipeline>   (stdin = data)
boundary() {
  "$B/sealed-run" agent "$3" > "$T/$1.jsonl"
  grep -q -- "$2" "$T/$1.jsonl" || { echo "FAIL $1: missing $2"; cat "$T/$1.jsonl"; exit 1; }
  if grep -Eq "$LEAK" "$T/$1.jsonl"; then echo "LEAK in $1"; exit 1; fi
  echo "ok  $1: $(wc -l < "$T/$1.jsonl") public lines, no secrets"
}
SEED="abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot"
# 1. raw tools DO print secrets (control)
echo "$SEED" | "$B/seed-repair" | "$B/seed-to-master" | "$B/derive" --count 1 > "$T/raw.jsonl"
grep -Eq '"wif":"[KL5]' "$T/raw.jsonl" || { echo "FAIL raw control"; exit 1; }
echo "ok  raw control: tools print keys ($(grep -c wif "$T/raw.jsonl") wif lines)"
# 2. full pipe through the boundary
echo "$SEED" | boundary seed 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu' 'seed-repair | seed-to-master | derive --count 2'
# 3. half pipe (stops at master key) - boundary must drop the xprv line
echo "$SEED" | boundary half '"tool":"seed-to-master"' 'seed-repair | seed-to-master'
# 3b. public address list (derive --address-list: label<TAB>path<TAB>address) passes the boundary
#     unchanged; the same pipe without --address-list still has its key fields redacted.
echo "$SEED" | "$B/sealed-run" agent 'seed-repair | seed-to-master | derive --count 2 --chain btc --address-list' > "$T/al.txt"
echo "$SEED" | "$B/seed-repair" | "$B/seed-to-master" | "$B/derive" --count 2 --chain btc --address-list 2>/dev/null > "$T/al-raw.txt"
[ -s "$T/al-raw.txt" ] && grep -vF '"tool":"redact"' "$T/al.txt" | cmp -s - "$T/al-raw.txt" && ! grep -Eq "$LEAK" "$T/al.txt" \
  && grep -q "$(printf "\tm/84'/0'/0'/0/0\tbc1q")" "$T/al.txt" \
  && echo "ok  address-list: $(wc -l < "$T/al-raw.txt") lines through sealed-run unchanged, no secrets" || { echo "FAIL address-list boundary"; cat "$T/al.txt"; exit 1; }
echo "$SEED" | "$B/sealed-run" agent 'seed-repair | seed-to-master | derive --count 2 --chain btc' | grep -q '"wif":"\[REDACTED\]"' \
  && echo "ok  address-list: key lines still redacted" || { echo "FAIL key redaction"; exit 1; }
# 4. boundary refuses non-allowlisted programs / shell syntax
"$B/sealed-run" agent 'sh -c id' | grep -q unsupported && echo "ok  sealed-run refuses sh"
"$B/sealed-run" agent 'derive ; id' | grep -q bad_input && echo "ok  sealed-run refuses shell syntax"
# 5. human mode without a terminal refuses
if nosid "$B/sealed-run" human 'seed-repair' </dev/null 2>/dev/null | grep -q bad_input; then echo "ok  human mode refuses without tty"; else echo "FAIL human no-tty"; exit 1; fi
grep -q '"wif":"\[REDACTED\]"' "$T/seed.jsonl" && echo "ok  placeholders: secret fields labelled, values gone"
# extra checks appended by later milestones
# Each script in a subshell, so one script's "skip ...; exit 0" does not end the whole suite.
for f in scripts/e2e.d/*.sh; do [ -f "$f" ] || continue; set +e; ( B=target/release; set -e; . "$f" ); rc=$?; set -e; [ $rc = 0 ] || { echo "FAIL $f (rc=$rc)"; exit 1; }; done
echo "e2e: all ok"
