#!/bin/sh
# Run scripts/gate.sh inside the pinned gate image (Dockerfile.gate) on the Docker host the CLI points at.
#   sh scripts/gate-docker.sh            all stages        sh scripts/gate-docker.sh test   one stage
# The checkout must be visible to the Docker HOST: bind mounts resolve there, not where this script runs
# (a Mac whose docker context is Battleaxe mounts a Battleaxe path). Set GATE_SRC to that host path
# (default: this checkout's absolute path, right when the host is local). Cargo registry and target
# live in named volumes (blocktools-gate-cargo, blocktools-gate-target), so a rerun is incremental.
# The container runs as root: files it writes into the checkout (bindings/wasm/pkg, man/ on regen) are root-owned.
set -eu
cd "$(dirname "$0")/.."
IMG=${GATE_IMAGE:-blocktools-gate}
SRC=${GATE_SRC:-$PWD}
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "== building $IMG from Dockerfile.gate"
  docker build -q -t "$IMG" - < Dockerfile.gate
fi
exec docker run --rm -v "$SRC:/src" -v blocktools-gate-cargo:/cargo-home -v blocktools-gate-target:/src/target \
  -e CARGO_HOME=/cargo-home "$IMG" sh scripts/gate.sh "$@"
