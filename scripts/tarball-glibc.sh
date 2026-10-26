#!/bin/sh
# Re-measure the glibc floor of a release tarball from its binaries (claim tarball-glibc-floor).
# Downloads the public asset, checks SHA256SUMS, then per binary: newest GLIBC_ symbol version
# (objdump -T | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1). Prints one summary line.
set -eu
TAG=${1:-v0.1.0}
B=https://github.com/TSavo/blocktools/releases/download/$TAG
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cd "$T"
curl -fsSLO "$B/blocktools-$TAG-linux-x86_64.tar.gz" && curl -fsSLO "$B/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS >/dev/null
tar xzf "blocktools-$TAG-linux-x86_64.tar.gz"
n=0; for b in */bin/*; do n=$((n + 1)); echo "$(objdump -T "$b" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1) $(basename "$b")"; done > floors
c34=$(grep -c '^GLIBC_2.34 ' floors || true)  # allow-true: grep -c exits 1 on zero matches, count is still printed
hi=$(awk '$1 != "GLIBC_2.34" {print $2 "=" $1}' floors | sort | tr '\n' ' ')
echo "tarball-glibc $TAG: sha256 ok; $n binaries; $c34 need GLIBC_2.34; others: ${hi% }"
