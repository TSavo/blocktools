#!/bin/sh
# Fails if any crate's normal (non-dev) dependency tree contains a crate not in deps/<crate>.allow.
# Growing the list must be a reviewed change to deps/*.allow.
set -eu
cd "$(dirname "$0")/.."
rc=0
for f in deps/*.allow; do
  p=$(basename "$f" .allow)
  new=$(cargo tree -q --locked -p "$p" -e normal --prefix none | awk '{print $1}' | sort -u | grep -vx "$p" | comm -23 - "$f")
  if [ -n "$new" ]; then echo "FAIL $p: new deps not in $f: $new"; rc=1
  else echo "ok   $p ($(wc -l < "$f") crates)"; fi
done
exit $rc
