#!/bin/sh
# Print the sealed runtime image size in decimal MB (one decimal, matching `docker images`),
# ONLY from `docker image inspect` of a real built image. Exit 2 if no image can be inspected:
# there is no silent fallback, so a size claim can't be "measured" from something that isn't an image.
#   sh scripts/image-size.sh               -> "33.3" (stdout) and "image-size: inspected <tag>" (stderr)
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
    case "$n" in utxo-fetch|tx-broadcast|xmr-wallet) continue;; esac
    [ -x "$root/$n" ] || continue
    bytes=$((bytes + $(wc -c < "$root/$n")))
  done
  echo "FALLBACK: binary sum, not an image"; mb "$bytes"; exit 0
fi
D=${BLOCKTOOLS_DOCKER:-docker}
for tag in ${BLOCKTOOLS_IMAGE:-blocktools:local}; do  # only the image ./blocktools runs; ad-hoc tags (size-measure) are not the sealed build
  b=$($D image inspect "$tag" --format '{{.Size}}' 2>/dev/null) || continue
  [ -n "$b" ] || continue
  echo "image-size: inspected $tag ($b bytes)" >&2; mb "$b"; exit 0
done
echo "image-size: no blocktools image could be inspected with '$D' (build one; no fallback)" >&2
exit 2
