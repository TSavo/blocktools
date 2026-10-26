#!/bin/sh
# Print the sealed runtime image size in decimal MB (one decimal), matching `docker images`.
# Prefers an existing blocktools docker image; else sums musl sealed bins (same as Dockerfile scratch).
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
cd "$(dirname "$0")/.."
bytes=""
if command -v docker >/dev/null 2>&1; then
  for tag in blocktools:local blocktools:size-measure; do
    b=$(docker image inspect "$tag" --format '{{.Size}}' 2>/dev/null || true)  # allow-true: image may be absent
    if [ -n "$b" ]; then bytes=$b; break; fi
  done
fi
if [ -z "$bytes" ]; then
  root=target/x86_64-unknown-linux-musl/release
  [ -d "$root" ] || { echo "image-size: no docker image and no $root" >&2; exit 2; }
  bytes=0
  for t in tools/*/; do
    n=$(basename "$t")
    case "$n" in utxo-fetch|tx-broadcast|xmr-wallet) continue;; esac
    b="$root/$n"
    [ -x "$b" ] || continue
    s=$(wc -c < "$b")
    bytes=$((bytes + s))
  done
fi
# docker images prints decimal MB with one fraction digit for this magnitude
awk -v b="$bytes" 'BEGIN{ printf "%.1f\n", b/1000000 }'
