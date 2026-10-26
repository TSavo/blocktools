#!/bin/sh
# Print the sealed runtime image size in decimal MB (one decimal, matching `docker images`),
# ONLY from a real built image (docker save layer bytes; see below). Exit 2 if no image can be inspected:
# there is no silent fallback, so a size claim can't be "measured" from something that isn't an image.
#   sh scripts/image-size.sh               -> "instrument: ...; N bytes" and MB (stdout); environment + inspect size (stderr)
#   sh scripts/image-size.sh --build       -> ./blocktools build first (labels the image with HEAD), then measure
#   sh scripts/image-size.sh --binary-sum  -> estimate from musl bins; prints "FALLBACK: binary sum, not an image"
#                                             (claims-check K-fallback refuses any measured claim whose output says FALLBACK)
# Set BLOCKTOOLS_DOCKER="sudo docker" where the daemon needs root.
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
cd "$(dirname "$0")/.."
mb() { awk -v b="$1" 'BEGIN{ printf "%.1f\n", b/1000000 }'; }
if [ "${1:-}" = --binary-sum ]; then
  root=target/x86_64-unknown-linux-musl/release
  [ -d "$root" ] || { echo "image-size: no $root" >&2; exit 2; }
  bytes=0
  for t in tools/*/; do
    n=$(basename "$t")
    case "$n" in utxo-fetch|tx-broadcast|rpc|xmr-wallet) continue;; esac
    [ -x "$root/$n" ] || continue
    bytes=$((bytes + $(wc -c < "$root/$n")))
  done
  echo "FALLBACK: binary sum, not an image"; mb "$bytes"; exit 0
fi
D=${BLOCKTOOLS_DOCKER:-docker}
if [ "${1:-}" = --build ]; then BLOCKTOOLS_DOCKER=$D sh ./blocktools build >&2 || { echo "image-size: build failed" >&2; exit 2; }; fi
# The image must come from this exact tree: its revision label (./blocktools build) must equal HEAD and
# the tracked tree must be clean, else a size measured from an older image would be claimed for HEAD.
head=$(git rev-parse HEAD)
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "FAIL image-size: tracked files modified; commit first, a dirty tree has no commit to claim" >&2; exit 2; }
# Instrument (default): sum of uncompressed layer bytes from `docker save` (scripts/image-layer-bytes.py).
# `docker image inspect .Size` depends on the image store (overlay2 reports layer bytes, the containerd
# store reports content size: reviewer saw 56.2 MB vs our 33.2 MB for the same build), so it is printed
# for reference only. The environment line names docker version and store so a re-run elsewhere is comparable.
for tag in ${BLOCKTOOLS_IMAGE:-blocktools:local}; do  # only the image ./blocktools runs
  ib=$($D image inspect "$tag" --format '{{.Size}}' 2>/dev/null) || continue
  [ -n "$ib" ] || continue
  rev=$($D image inspect "$tag" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || echo none)
  [ "$rev" = "$head" ] || { echo "FAIL image-size: image $tag was built from '${rev:-no label}', HEAD is $head; rebuild (sh scripts/image-size.sh --build)" >&2; exit 2; }  # rule:I-commit
  env=$($D info --format 'docker {{.ServerVersion}} driver {{.Driver}} {{range .DriverStatus}}{{index . 0}}={{index . 1}};{{end}}' 2>/dev/null || echo unknown)
  lb=$($D save "$tag" | python3 scripts/image-layer-bytes.py) || { echo "image-size: docker save / layer sum failed" >&2; exit 2; }
  echo "image-size: environment: $env" >&2
  echo "image-size: reference only (store-dependent): docker image inspect .Size = $ib bytes" >&2
  echo "instrument: docker-save uncompressed layer bytes; image $tag; commit $head; $lb bytes"
  mb "$lb"; exit 0
done
echo "image-size: no blocktools image could be inspected with '$D' (build one; no fallback)" >&2
exit 2
