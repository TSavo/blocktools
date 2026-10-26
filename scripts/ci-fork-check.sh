#!/bin/sh
# rule:H-fork wrapper (gate-negatives runs scripts/<name>.sh)
set -eu
exec python3 scripts/ci-fork-check.py "$@"
