#!/bin/sh
# docs/REFUSALS.md: run every <!-- run --> example (exit code + expected codes) and check that every
# status and failure code the source can emit has a section. Local fixtures only, no network.
set -eu
python3 scripts/e2e-only/doc-run.py docs/REFUSALS.md
