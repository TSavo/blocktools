# signer-runner-hook.sh: only release.yml on a v* tag push or a main workflow_dispatch may run on the signer.
h=scripts/signer-runner-hook.sh
set -eu
ok()  { env -i PATH="$PATH" "$@" sh $h >/dev/null 2>&1 || { echo "FAIL signer-hook should allow: $*"; exit 1; }; }
bad() { env -i PATH="$PATH" "$@" sh $h >/dev/null 2>&1 && { echo "FAIL signer-hook should refuse: $*"; exit 1; }; true; }
W=TSavo/blocktools/.github/workflows/release.yml
ok  GITHUB_REPOSITORY=TSavo/blocktools GITHUB_EVENT_NAME=push GITHUB_WORKFLOW_REF=$W@refs/tags/v0.1.2
ok  GITHUB_REPOSITORY=TSavo/blocktools GITHUB_EVENT_NAME=workflow_dispatch GITHUB_WORKFLOW_REF=$W@refs/heads/main
bad GITHUB_REPOSITORY=TSavo/blocktools GITHUB_EVENT_NAME=push GITHUB_WORKFLOW_REF=$W@refs/heads/main
bad GITHUB_REPOSITORY=TSavo/blocktools GITHUB_EVENT_NAME=workflow_dispatch GITHUB_WORKFLOW_REF=$W@refs/heads/evil
bad GITHUB_REPOSITORY=TSavo/blocktools GITHUB_EVENT_NAME=push GITHUB_WORKFLOW_REF=TSavo/blocktools/.github/workflows/ci.yml@refs/tags/v0.1.2
bad GITHUB_REPOSITORY=TSavo/blocktools GITHUB_EVENT_NAME=push GITHUB_WORKFLOW_REF=$W@refs/tags/x0.1.2
bad GITHUB_REPOSITORY=evil/blocktools GITHUB_EVENT_NAME=push GITHUB_WORKFLOW_REF=evil/blocktools/.github/workflows/release.yml@refs/tags/v1
bad GITHUB_REPOSITORY=TSavo/blocktools GITHUB_EVENT_NAME=pull_request GITHUB_WORKFLOW_REF=$W@refs/tags/v1
bad
echo "ok   signer-hook: allows tag/dispatch release.yml only"
