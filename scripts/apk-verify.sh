#!/bin/sh
# apk verify each APK in a clean Alpine container that trusts ONLY the given public key.
#   scripts/apk-verify.sh key.rsa.pub file.apk...    exit 0 iff every file verifies
set -eu
pub=$1; shift
d=$(mktemp -d); cid=""
cleanup() {
  rm -rf "$d"
  [ -z "$cid" ] || ${DOCKER:-docker} rm -f "$cid" >/dev/null 2>&1 || true  # allow-true: the verify container may already be gone
  return 0
}
trap cleanup EXIT
cp "$pub" "$d/"; for a in "$@"; do cp "$a" "$d/"; done
# No host bind mounts (the engine may be Docker Desktop, which cannot mount WSL2 paths): docker cp the
# public key + APKs into a created container, then start it. --network none (offline) is kept.
cid=$(${DOCKER:-docker} create --network none alpine:3.20 sh -euc "
  rm -f /etc/apk/keys/*; cp /v/*.pub /etc/apk/keys/
  for f in /v/*.apk; do apk verify \"\$f\" >/dev/null 2>&1 || { echo \"UNTRUSTED: \${f##*/}\"; exit 1; }; echo \"verified: \${f##*/}\"; done")
${DOCKER:-docker} cp "$d" "$cid:/v" >/dev/null
${DOCKER:-docker} start -a "$cid"
