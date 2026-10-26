#!/bin/sh
# Regression for check-deps.sh: it must FAIL (never pass) on
#   (a) a planted network crate in a no-network crate, and
#   (b) a stale Cargo.lock (cargo exits 101; a pipe must not mask that),
# under both sh and bash. Works on a throwaway git worktree; the real tree is untouched.
set -eu
cd "$(dirname "$0")/.."
root=$(pwd); wt=$(mktemp -d)/wt
cleanup() { git -C "$root" worktree remove --force "$wt" 2>/dev/null || rm -rf "$wt"; }
trap cleanup EXIT
git worktree add -q --detach "$wt" HEAD
cp scripts/check-deps.sh "$wt/scripts/check-deps.sh"  # test the working copy, not only HEAD
export CARGO_TARGET_DIR="$root/target"
rc=0
expect_fail() {  # $1 label; runs check-deps under sh and bash, both must exit non-zero
  for shl in sh bash; do
    if (cd "$wt" && "$shl" scripts/check-deps.sh > "$wt/../out" 2>&1); then
      echo "FAIL check-deps passed under $shl with $1"; tail -5 "$wt/../out"; rc=1
    else echo "ok   check-deps fails under $shl with $1"; fi
  done
}
# (a) network crate planted in blocktools-core; minreq is already in the lock, so the lock stays valid offline
cp "$wt/crates/core/Cargo.toml" "$wt/../core.toml"
awk '{print} /^\[dependencies\]$/{print "minreq.workspace = true"}' "$wt/../core.toml" > "$wt/crates/core/Cargo.toml"
(cd "$wt" && cargo update -q --offline -w) || { echo "FAIL could not refresh lock offline for (a)"; exit 1; }
expect_fail "a planted network crate"
# (b) stale lock: restore the toml but keep the lock that lists minreq under core -> --locked refuses
cp "$wt/../core.toml" "$wt/crates/core/Cargo.toml"
expect_fail "a stale Cargo.lock"
grep -q "exited non-zero" "$wt/../out" || { echo "FAIL stale-lock run did not report the cargo error"; rc=1; }
[ $rc = 0 ] && echo "check-deps regression ok"
exit $rc
