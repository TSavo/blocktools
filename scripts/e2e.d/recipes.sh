# shellcheck shell=sh
# Every tested example in recipes/*.md, run as written (scripts/recipe-check.py). Sourced by e2e-local.sh.
python3 scripts/recipe-check.py "$B" "$T" || exit 1
