#!/bin/sh
# "Sealed on macOS", measured on the Mac itself (docs/MACOS.md). Needs a Docker engine running LOCALLY on the
# Mac (Docker Desktop, colima, OrbStack: a unix:// endpoint), the blocktools:local image built with that
# engine, and this checkout. Prints the host and engine it measured, then runs scripts/sealed-check.sh, which
# creates the container exactly as `./blocktools run` does and checks network none, read-only rootfs,
# cap-drop ALL, uid 10001, no-new-privileges, read-only /in, that the file in /in reached the tools
# (addresses printed) and that the output carries no secret material.
# A remote engine (ssh:// or tcp://, e.g. Battleaxe) is refused: there the container, its isolation and the
# /in bind mount are all on the Linux host, which the Linux gate measures; nothing about the Mac is.
# Exit: 0 all properties hold; 1 a property failed; 2 not a Mac, no local engine, or no image.
set -eu
cd "$(dirname "$0")/.."
D=${BLOCKTOOLS_DOCKER:-docker}
[ "$(uname -s)" = Darwin ] || { echo "macos-sealed-check: not macOS ($(uname -s))" >&2; exit 2; }
ep=${DOCKER_HOST:-$($D context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || echo none)}
case "$ep" in unix://*) ;; *) echo "macos-sealed-check: engine endpoint '$ep' is not a local unix socket (refused: see docs/MACOS.md)" >&2; exit 2;; esac
srv=$($D version --format '{{.Server.Os}}/{{.Server.Arch}} {{.Server.Version}}' 2>/dev/null) || { echo "macos-sealed-check: docker engine not running at $ep" >&2; exit 2; }
echo "host: macOS $(sw_vers -productVersion) $(uname -m); engine: $ep, server $srv; commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
out=$(sh scripts/sealed-check.sh 2>&1) && rc=0 || rc=$?
printf '%s\n' "$out"
[ $rc = 0 ] && echo "macos-sealed-check ok"
exit $rc
