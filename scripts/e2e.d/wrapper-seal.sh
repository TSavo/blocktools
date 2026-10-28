# ./blocktools puts ./in and ./secrets into the sealed container without host bind mounts (Docker Desktop on
# Windows does not see WSL2 paths: a bind mount arrives empty), read-only, with --network none, and removes
# what it created, also when the pipeline fails.
# Part 1 (everywhere, fake docker): the exact docker calls. Part 2 (real engine): a throwaway busybox image
# stands in for the scratch sealed image (it has a shell to look around); the wrapper's container flags are
# unchanged. Part 2 is required on the Linux self-hosted CI runners (Battleaxe), skipped elsewhere without docker.
set -eu
T=${T:-$(mktemp -d)}; W="$PWD/blocktools"
f() { echo "FAIL wrapper-seal $1"; exit 1; }
SECRET="e2e-not-a-real-secret-$$-7f3a"
mkdir -p "$T/ws/in/sub" "$T/ws/secrets" "$T/ws/bin"
printf 'hello-in\n' > "$T/ws/in/m.txt"; printf 'nested\n' > "$T/ws/in/sub/n.txt"
printf '%s\n' "$SECRET" > "$T/ws/secrets/pw"; chmod 600 "$T/ws/secrets/pw"
# ---- part 1: fake docker logs argv (one call per line) and the tar member names it receives on cp
cat > "$T/ws/bin/docker" <<'EOS'
#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$1" in
  context) echo unix:///var/run/docker.sock;;
  create) echo stagerid;;
  cp) tar -tvf - >> "$FAKE_LOG";;
  run) [ -z "${FAKE_RUN_RC:-}" ] || exit "$FAKE_RUN_RC"; echo RAN;;
esac
EOS
chmod +x "$T/ws/bin/docker"
fake() { (cd "$T/ws" && env -u DOCKER_HOST FAKE_LOG="$T/ws/log" BLOCKTOOLS_DOCKER="$T/ws/bin/docker" "$@" sh "$W" run 'pipeline' 2>&1); }
: > "$T/ws/log"; o=$(fake env) || f "fake run failed: $o"
[ "$o" = RAN ] || f "fake run output: $o"
L="$T/ws/log"
grep -q 'type=bind' "$L" && f "a bind mount is still used"
grep -Eq '(^| )-v ' "$L" && f "a -v mount is still used"
grep '^run ' "$L" | grep -q -- '--network none' || f "run without --network none"
grep '^run ' "$L" | grep -q 'dst=/in,readonly' || f "/in not mounted readonly"
grep '^run ' "$L" | grep -q 'dst=/secrets,readonly' || f "/secrets not mounted readonly"
grep '^create ' "$L" | grep -q -- '--network none' || f "staging container without --network none"
grep -q '^start' "$L" && f "staging container was started"
grep -q 'm.txt' "$L" && grep -q 'sub/n.txt' "$L" || f "inputs not in the cp stream"
grep -Eq '10001[/ ]+10001 .*pw' "$L" || f "secret not owned by the container user in the stream"
grep -q "$SECRET" "$L" && f "secret content reached docker argv"
grep -q '^rm -f stagerid' "$L" || f "staging container not removed"
[ "$(grep -c '^volume create' "$L")" = 2 ] || f "want 2 volumes"
grep '^volume rm' "$L" | grep -q -- '-in' || f "volumes not removed"
: > "$L"; o=$(fake env FAKE_RUN_RC=7) && f "pipeline failure not propagated"
grep '^volume rm' "$L" | grep -q -- '-secrets' || f "volumes not removed after a failed run"
echo "$o" | grep -q "$SECRET" && f "secret printed"
echo "ok   wrapper-seal fake: no bind mounts; /in and /secrets copied as tar streams (secret owned 10001) into volumes mounted readonly; --network none; staging never started; cleanup on success and failure"
# ---- part 2: real engine
D=${BLOCKTOOLS_DOCKER:-docker}
need=0; [ "$(uname -s)" = Linux ] && [ "${GITHUB_ACTIONS:-}" = true ] && [ "${RUNNER_ENVIRONMENT:-}" = self-hosted ] && need=1
if ! $D info >/dev/null 2>&1; then
  [ $need = 0 ] || f "no docker engine on the self-hosted Linux runner ($D info failed)"
  echo "skip wrapper-seal real-engine part: no docker engine ($D)"; exit 0
fi
IMG="blocktools-e2e-seal:$$"
printf 'FROM busybox:1.36.1\nENTRYPOINT ["/bin/sh","-c","eval \\"$2\\"","sealed-run"]\n' | $D build -q -t "$IMG" - >/dev/null || f "test image build failed"
trap '$D image rm -f "$IMG" >/dev/null 2>&1 || :' EXIT
before=$($D volume ls -q --filter label=blocktools.sealed | sort); cb=$($D ps -aq --filter label=blocktools.sealed | sort)
P='cat /in/m.txt /in/sub/n.txt; ls -A /in | wc -l | sed "s/^ */in_entries=/"
  touch /in/x 2>/dev/null && echo IN_WRITABLE || echo IN_RO
  touch /secrets/x 2>/dev/null && echo SECRETS_WRITABLE || echo SECRETS_RO
  [ -s /secrets/pw ] && grep -q e2e-not-a-real /secrets/pw && echo SECRET_READABLE
  touch /etc/x 2>/dev/null && echo ROOT_WRITABLE || echo ROOT_RO
  echo "netifs=$(ls /sys/class/net | tr "\n" " ")"
  wget -q -T 3 -O /dev/null http://1.1.1.1/ 2>/dev/null && echo NET_ON || echo NET_OFF; echo "uid=$(id -u)"'
o=$(cd "$T/ws" && env -u DOCKER_HOST BLOCKTOOLS_IMAGE="$IMG" sh "$W" run "$P" 2>&1) || f "real run failed: $o"
for w in hello-in nested in_entries=2 IN_RO SECRETS_RO SECRET_READABLE ROOT_RO NET_OFF uid=10001; do
  echo "$o" | grep -qx "$w" || f "real run: want '$w', got: $(echo "$o" | tr '\n' '|')"; done
echo "$o" | grep -qx 'netifs=lo ' || f "real run: network interfaces: $(echo "$o" | grep netifs)"
echo "$o" | grep -q "$SECRET" && f "secret printed"
o=$(cd "$T/ws" && env -u DOCKER_HOST BLOCKTOOLS_IMAGE="$IMG" sh "$W" run 'exit 7' 2>&1) && f "failing pipeline returned 0"
[ "$($D volume ls -q --filter label=blocktools.sealed | sort)" = "$before" ] || f "volumes left behind"
[ "$($D ps -aq --filter label=blocktools.sealed | sort)" = "$cb" ] || f "containers left behind"
[ "$(ls -A "$T/ws/secrets")" = pw ] || f "host secrets dir changed"
echo "ok   wrapper-seal real engine ($($D version --format '{{.Server.Os}} {{.Server.Version}}' 2>/dev/null)): /in arrived (2 entries, nested file), /in, /secrets and rootfs read-only, secret readable inside and never printed, only lo, outbound fetch fails, uid 10001; no volumes or containers left after a success and a failure"
