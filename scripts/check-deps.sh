#!/bin/sh
# Fails if any workspace crate's normal (non-dev) dependency tree contains a crate
# not listed in deps/<crate>.allow, or if a crate has no allowlist at all.
# Growing a list is a reviewed change:  sh scripts/check-deps.sh --regen <crate>
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
export LC_ALL=C  # sort/comm agree on byte order everywhere
cd "$(dirname "$0")/.."
# cargo's output and exit status are captured separately: a pipe would let awk/grep mask
# cargo's 101 (stale lock, unknown package) under a shell without pipefail. Fail closed.
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
tree() {
  if ! cargo tree -q --locked -p "$1" -e normal --prefix none > "$tmp/raw" 2> "$tmp/err"; then
    echo "FAIL cargo tree -p $1 exited non-zero:" >&2; cat "$tmp/err" >&2; return 1  # rule:C-stale
  fi
  awk '{print $1}' "$tmp/raw" | sort -u | grep -vx "$1" || [ $? -eq 1 ]
}
if [ "${1:-}" = "--regen" ]; then tree "$2" > "$tmp/t"; mv "$tmp/t" "deps/$2.allow"; echo "wrote deps/$2.allow"; exit 0; fi
# Workspace members from cargo itself (--locked: fail if Cargo.lock is stale), not a sed over Cargo.toml.
cargo metadata --locked --no-deps --format-version 1 > "$tmp/meta" || { echo "FAIL cargo metadata exited non-zero"; exit 1; }  # rule:C-stale
members=$(python3 -c 'import json,sys,os; d=json.load(sys.stdin); r=d["workspace_root"]; print("\n".join(os.path.relpath(os.path.dirname(p["manifest_path"]), r) for p in d["packages"] if p["id"] in d["workspace_members"]))' < "$tmp/meta")
[ -n "$members" ] || { echo "FAIL no workspace members"; exit 1; }  # rule:C-meta neg-exempt: cargo metadata never lists zero members for a valid workspace; unplantable without breaking cargo itself (C-stale covers the error path)
rc=0
for m in $members; do
  [ -n "$m" ] || continue
  p=$(sed -n 's/^name = "\(.*\)"/\1/p' "$m/Cargo.toml" | head -1); f="deps/$p.allow"
  [ -f "$f" ] || { echo "FAIL $p: no $f"; rc=1; continue; }  # rule:C-allow
  tree "$p" > "$tmp/t" || { rc=1; continue; }  # rule:C-stale
  new=$(comm -23 "$tmp/t" "$f")
  if [ -n "$new" ]; then echo "FAIL $p: new deps not in $f: $new"; rc=1  # rule:C-allow
  else echo "ok   $p ($(grep -c . "$f" || [ $? -eq 1 ]) crates)"; fi
done
# network crates may only appear in the host-side tools
for m in $members; do
  p=$(sed -n 's/^name = "\(.*\)"/\1/p' "$m/Cargo.toml" | head -1)
  case "$p" in blocktools-net|utxo-fetch|tx-broadcast) continue;; esac
  tree "$p" > "$tmp/t" || { rc=1; continue; }  # rule:C-stale
  if grep -qxE 'minreq|rustls|ring|webpki-roots|blocktools-net' "$tmp/t"; then echo "FAIL $p: pulls a network crate"; rc=1; fi  # rule:C-net
done
# the library facade and the public crates, with default features, carry no secret-handling
# or network crates (DESIGN.md §11)
for p in blocktools blocktools-core blocktools-tx; do
  tree "$p" > "$tmp/t" || { rc=1; continue; }  # rule:C-stale
  if grep -qxE 'blocktools-secrets|blocktools-net|bip39|scrypt|pbkdf2|aes|cbc|ctr|minreq|rustls|ring' "$tmp/t"; then echo "FAIL $p: default features pull secret/network crates"; rc=1  # rule:C-facade
  else echo "ok   $p default features: no secrets/net crates"; fi
done
exit $rc
