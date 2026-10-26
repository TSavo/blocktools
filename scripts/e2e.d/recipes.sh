# shellcheck shell=sh
# Every tested example in recipes/*.md, run as written (scripts/recipe-check.py). Sourced by e2e-local.sh.
set -eu
. scripts/e2e-only/portable.sh
have_pymod cryptography || { echo "skip recipes (python3 module cryptography not installed: pip install cryptography)"; exit 0; }
python3 scripts/recipe-check.py "$B" "$T" || exit 1
