#!/bin/sh
# Fails if any workspace crate's normal (non-dev) dependency tree contains a crate
# not listed in deps/<crate>.allow, or if a crate has no allowlist at all.
# Growing a list is a reviewed change:  sh scripts/check-deps.sh --regen <crate>
set -eu
cd "$(dirname "$0")/.."
tree() { cargo tree -q --locked -p "$1" -e normal --prefix none | awk '{print $1}' | sort -u | grep -vx "$1" || true; }
if [ "${1:-}" = "--regen" ]; then tree "$2" > "deps/$2.allow"; echo "wrote deps/$2.allow"; exit 0; fi
members=$(sed -n '/^members/,/]/p' Cargo.toml | grep -o '"[^"]*"' | tr -d '"')
rc=0
for m in $members; do
  [ -n "$m" ] || continue
  p=$(sed -n 's/^name = "\(.*\)"/\1/p' "$m/Cargo.toml" | head -1); f="deps/$p.allow"
  [ -f "$f" ] || { echo "FAIL $p: no $f"; rc=1; continue; }
  new=$(tree "$p" | comm -23 - "$f")
  if [ -n "$new" ]; then echo "FAIL $p: new deps not in $f: $new"; rc=1
  else echo "ok   $p ($(grep -c . "$f" || true) crates)"; fi
done
# network crates may only appear in the host-side tools
for m in $members; do
  p=$(sed -n 's/^name = "\(.*\)"/\1/p' "$m/Cargo.toml" | head -1)
  case "$p" in kr-net|utxo-fetch|tx-broadcast) continue;; esac
  if tree "$p" | grep -qxE 'minreq|rustls|ring|webpki-roots|kr-net'; then echo "FAIL $p: pulls a network crate"; rc=1; fi
done
exit $rc
