#!/bin/sh
# Every gate must pass, in order, or nothing is pushed. Usage: scripts/verify-and-push.sh "commit message"
# Stage changes by explicit path first (`git add path...`); this script never stages anything.
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
# Expects cargo and node on PATH.
[ $# = 1 ] || { echo "usage: $0 MESSAGE" >&2; exit 2; }
# Must be on main: a detached HEAD would commit locally while `git push origin main` pushes nothing new.
[ "$(git symbolic-ref -q HEAD)" = refs/heads/main ] || { echo "verify-and-push: not on branch main (detached HEAD?)" >&2; exit 2; }
sh scripts/gate.sh
git commit -qm "$1"
git push -q origin HEAD:refs/heads/main
[ "$(git rev-parse HEAD)" = "$(git ls-remote origin refs/heads/main | cut -f1)" ] || { echo "verify-and-push: remote main is not HEAD after push" >&2; exit 1; }
git log --oneline -1
