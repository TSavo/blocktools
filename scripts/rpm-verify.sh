#!/bin/sh
# Verify a blocktools RPM repo dir against ONE public key in a clean container (no other keys imported):
# rpm -K on every RPM must report a good signature, and gpgv must accept repodata/repomd.xml.asc.
#   scripts/rpm-verify.sh RPM-GPG-KEY-file REPO_DIR
set -eu
pub=$(CDPATH= cd -- "$(dirname "$1")" && pwd)/$(basename "$1"); dir=$(CDPATH= cd -- "$2" && pwd)
${DOCKER:-docker} run --rm --network none -v "$pub:/pub.asc:ro" -v "$dir:/r:ro" ${RPM_VERIFY_IMAGE:-fedora:40} sh -euc '
  rpm --import /pub.asc
  for f in /r/*.rpm; do
    out=$(rpm -K "$f" 2>&1) || { echo "rpm-verify: FAIL $out"; exit 1; }
    case "$out" in *": digests signatures OK") echo "rpm-verify: ok $out";; *) echo "rpm-verify: FAIL $out"; exit 1;; esac
  done
  if [ -f /r/repodata/repomd.xml ]; then
    gpg --batch --dearmor < /pub.asc > /tmp/k.gpg
    gpgv --keyring /tmp/k.gpg /r/repodata/repomd.xml.asc /r/repodata/repomd.xml 2>/dev/null || { echo "rpm-verify: FAIL repomd.xml signature"; exit 1; }
    echo "rpm-verify: ok repodata/repomd.xml.asc"
  fi'
