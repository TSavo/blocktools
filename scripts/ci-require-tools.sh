#!/bin/sh
# CI preflight: the self-hosted runner image must provide these; we never apt-get/sudo in CI.
set -eu
m=""
for t in clang ld.lld python3 cc git; do command -v "$t" >/dev/null 2>&1 || m="$m $t"; done
if [ -n "$m" ]; then
  echo "::error::runner is missing required tools:$m (install them in the runner image; CI does not apt-get)"
  echo "FAIL ci-require-tools: missing:$m"; exit 1
fi
echo "ok   ci-require-tools: clang ld.lld python3 cc git present"
