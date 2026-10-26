#!/bin/sh
# Job-started hook for the host-side "blocktools-signer" runner (ACTIONS_RUNNER_HOOK_JOB_STARTED).
# The runner user can read the apk/apt/rpm signer AppRole files, so it may run ONLY release.yml from this
# repo, and only for a v* tag push or a workflow_dispatch on main (the dry run, which signs nothing).
# Any other job fails before its first step. See docs/RELEASE-REPOS.md.
set -eu
want=${SIGNER_REPO:-TSavo/blocktools}
wf="$want/.github/workflows/release.yml@"
r=${GITHUB_WORKFLOW_REF:-}
case "${GITHUB_REPOSITORY:-}|${GITHUB_EVENT_NAME:-}|$r" in
  "$want|push|${wf}refs/tags/v"*) ;;
  "$want|workflow_dispatch|${wf}refs/heads/main") ;;
  *) echo "FAIL signer-hook: refusing job: repo=${GITHUB_REPOSITORY:-?} event=${GITHUB_EVENT_NAME:-?} workflow_ref=${r:-?}"; exit 1;;  # rule:R-signer neg-exempt: runner hook; planted in scripts/e2e.d/signer-hook.sh
esac
echo "ok   signer-hook: $GITHUB_EVENT_NAME $r"
