#!/bin/sh
# apk verify each APK in a clean Alpine container that trusts ONLY the given public key.
#   scripts/apk-verify.sh key.rsa.pub file.apk...    exit 0 iff every file verifies
set -eu
pub=$1; shift
d=$(mktemp -d); trap "rm -rf \"$d\"" EXIT
cp "$pub" "$d/"; for a in "$@"; do cp "$a" "$d/"; done
${DOCKER:-docker} run --rm --network none -v "$d:/v:ro" alpine:3.20 sh -euc "
  rm -f /etc/apk/keys/*; cp /v/*.pub /etc/apk/keys/
  for f in /v/*.apk; do apk verify \"\$f\" >/dev/null 2>&1 || { echo \"UNTRUSTED: \${f##*/}\"; exit 1; }; echo \"verified: \${f##*/}\"; done"
