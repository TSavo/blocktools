# ./blocktools puts ./in and ./secrets into the sealed container with no host bind mounts and no volumes
# (Docker Desktop on Windows does not see WSL2 paths: a bind mount arrives empty; and secrets must not touch
# the engine's disk): tar streams on stdin into tmpfs mounts, read-only to uid 10001, --network none, and
# the container (with its tmpfs) is removed, also when the pipeline fails.
# Part 1 (everywhere, fake docker): the exact docker calls. Part 2 (everywhere, real sealed-run binary):
# `sealed-run unpack` on the tar the wrapper sends. Part 3 (real engine): a throwaway busybox image stands in
# for the scratch sealed image (it has a shell to look around; its /blocktools/sealed-run is a shell stand-in
# for unpack/staged); the wrapper's container flags are unchanged. Part 3 is required on the Linux
# self-hosted CI runners (Battleaxe), skipped elsewhere without docker.
set -eu
T=${T:-$(mktemp -d)}; W="$PWD/blocktools"; B=${B:-target/release}
f() { echo "FAIL wrapper-seal $1"; exit 1; }
SECRET="e2e-not-a-real-secret-$$-7f3a"
mkdir -p "$T/ws/in/sub" "$T/ws/secrets" "$T/ws/bin"
printf 'hello-in\n' > "$T/ws/in/m.txt"; printf 'nested\n' > "$T/ws/in/sub/n.txt"
printf '%s\n' "$SECRET" > "$T/ws/secrets/pw"; chmod 600 "$T/ws/secrets/pw"
# ---- part 1: fake docker logs argv (one call per line) and the tar member names it receives on exec
cat > "$T/ws/bin/docker" <<'EOF'
#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$1" in
  context) echo unix:///var/run/docker.sock;;
  create) echo sealedid;;
  inspect) echo true;;
  exec) tar -tvf - >> "$FAKE_LOG";;
  start) [ -z "${FAKE_RUN_RC:-}" ] || exit "$FAKE_RUN_RC"; echo RAN;;
esac
EOF
chmod +x "$T/ws/bin/docker"
fake() { (cd "$T/ws" && env -u DOCKER_HOST FAKE_LOG="$T/ws/log" BLOCKTOOLS_DOCKER="$T/ws/bin/docker" "$@" sh "$W" run 'pipeline' 2>&1); }
: > "$T/ws/log"; o=$(fake env) || f "fake run failed: $o"
[ "$o" = RAN ] || f "fake run output: $o"
L="$T/ws/log"
grep -q 'type=bind' "$L" && f "a bind mount is used"
grep -Eq '(^| )(-v|--volume|--mount) ' "$L" && f "a -v/--mount is used"
grep -q '^volume' "$L" && f "a volume is created"
grep -q '^cp' "$L" && f "docker cp is used"
C=$(grep '^create ' "$L")
for w in '--network none' '--read-only' '--cap-drop ALL' '--user 10001:10001' '--log-driver none' \
  '--tmpfs /in:rw,noexec,nosuid,nodev,size=512m,mode=0700,uid=0,gid=0' '--tmpfs /secrets:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=0,gid=0'; do
  echo "$C" | grep -q -- "$w" || f "create without $w"; done
echo "$C" | grep -q ' staged agent pipeline$' || f "entrypoint args: $C"
[ "$(grep -c '^exec -i -u 0 sealedid /blocktools/sealed-run unpack' "$L")" = 2 ] || f "want 2 unpack execs"
grep '^exec ' "$L" | head -1 | grep -q 'unpack /in$' || f "/in must be staged first"
grep '^exec ' "$L" | tail -1 | grep -q 'unpack /secrets$' || f "/secrets must be staged last"
grep -q 'm.txt' "$L" && grep -q 'sub/n.txt' "$L" && grep -q 'pw' "$L" || f "inputs not in the exec streams"
grep -q "$SECRET" "$L" && f "secret content reached docker argv"
grep -q '^rm -f sealedid' "$L" || f "container not removed"
: > "$L"; o=$(fake env FAKE_RUN_RC=7) && f "pipeline failure not propagated"
grep -q '^rm -f sealedid' "$L" || f "container not removed after a failed run"
echo "$o" | grep -q "$SECRET" && f "secret printed"
echo "ok   wrapper-seal fake: no bind mounts, no volumes, no docker cp; /in then /secrets streamed on stdin (docker exec -u 0 sealed-run unpack) into tmpfs /in, /secrets (mode 0700 root until unpacked); --network none --read-only --cap-drop ALL --user 10001:10001; cleanup on success and failure"
# ---- part 2: the real unpacker on the wrapper's own tar
if [ -x "$B/sealed-run" ]; then
  U="$T/unpack"; mkdir "$U"
  eval "$(sed -n '/^tar_as_user()/,/^}/p' "$W")"
  tar_as_user "$T/ws/in" | BLOCKTOOLS_UNPACK_ANYWHERE=1 "$B/sealed-run" unpack "$U" | grep -q '"status":"unpacked","count":3' || f "sealed-run unpack count"
  [ "$(cat "$U/m.txt" "$U/sub/n.txt")" = "hello-in
nested" ] || f "sealed-run unpack content"
  [ "$(find "$U" "$U/sub" -prune -perm 555 | wc -l)" -eq 2 ] && [ -n "$(find "$U/m.txt" -perm 444)" ] || f "sealed-run unpack modes: $(ls -ld "$U" "$U/sub" "$U/m.txt")"
  "$B/sealed-run" unpack /etc </dev/null | grep -q bad_input || f "unpack outside /in,/secrets accepted"
  chmod -R u+w "$U"
  echo "ok   wrapper-seal unpack: sealed-run unpack took the wrapper's tar (3 entries, nested file), files 0444, dirs 0555; other targets refused"
else
  echo "skip wrapper-seal unpack: no $B/sealed-run"
fi
# ---- part 3: real engine
D=${BLOCKTOOLS_DOCKER:-docker}
need=0; [ "$(uname -s)" = Linux ] && [ "${GITHUB_ACTIONS:-}" = true ] && [ "${RUNNER_ENVIRONMENT:-}" = self-hosted ] && need=1
if ! $D info >/dev/null 2>&1; then
  [ $need = 0 ] || f "no docker engine on the self-hosted Linux runner ($D info failed)"
  echo "skip wrapper-seal real-engine part: no docker engine ($D)"; exit 0
fi
IMG="blocktools-e2e-seal:$$"; X="$T/img"; mkdir "$X"
cat > "$X/sealed-run" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  unpack) [ "$2" = /in ] || [ "$2" = /secrets ]; cd "$2"; tar -xof -
          find . -mindepth 1 -type f -exec chmod 0444 {} +; find . -mindepth 1 -type d -exec chmod 0555 {} +; chmod 0555 .;;
  staged) i=0; until ls /secrets >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 1200 ]; sleep 0.1; done; eval "$3";;
  *) exit 2;;
esac
EOF
chmod 755 "$X/sealed-run"
printf 'FROM busybox:1.36.1\nCOPY sealed-run /blocktools/sealed-run\nENTRYPOINT ["/blocktools/sealed-run"]\n' > "$X/Dockerfile"
$D build -q -t "$IMG" "$X" >/dev/null || f "test image build failed"
PID_F="$T/probe-id"
trap '[ ! -s "$PID_F" ] || $D rm -f "$(cat "$PID_F")" >/dev/null 2>&1; $D image rm -f "$IMG" >/dev/null 2>&1 || :' EXIT
vb=$($D volume ls -q | sort); cb=$($D ps -aq --filter label=blocktools.sealed | sort)
P='cat /in/m.txt /in/sub/n.txt; ls -A /in | wc -l | sed "s/^ */in_entries=/"
  touch /in/x 2>/dev/null && echo IN_WRITABLE || echo IN_RO
  chmod 666 /in/m.txt 2>/dev/null && echo IN_CHMOD || echo IN_NOCHMOD
  touch /secrets/x 2>/dev/null && echo SECRETS_WRITABLE || echo SECRETS_RO
  chmod 666 /secrets/pw 2>/dev/null && echo SECRETS_CHMOD || echo SECRETS_NOCHMOD
  [ -s /secrets/pw ] && grep -q e2e-not-a-real /secrets/pw && echo SECRET_READABLE
  touch /etc/x 2>/dev/null && echo ROOT_WRITABLE || echo ROOT_RO
  echo "mounts=$(awk "\$2==\"/in\"||\$2==\"/secrets\"{print \$2\":\"\$3}" /proc/mounts | sort | tr "\n" " ")"
  echo "netifs=$(ls /sys/class/net | tr "\n" " ")"
  wget -q -T 3 -O /dev/null http://1.1.1.1/ 2>/dev/null && echo NET_ON || echo NET_OFF; echo "uid=$(id -u)"'
run() { (cd "$T/ws" && env -u DOCKER_HOST BLOCKTOOLS_IMAGE="$IMG" "$@" sh "$W" run "$P" 2>&1); }
o=$(run env) || f "real run failed: $o"
for w in hello-in nested in_entries=2 IN_RO IN_NOCHMOD SECRETS_RO SECRETS_NOCHMOD SECRET_READABLE ROOT_RO NET_OFF uid=10001 \
  'mounts=/in:tmpfs /secrets:tmpfs ' 'netifs=lo '; do
  echo "$o" | grep -qx -- "$w" || f "real run: want '$w', got: $(echo "$o" | tr '\n' '|')"; done
echo "$o" | grep -q "$SECRET" && f "secret printed"
[ "$($D ps -aq --filter label=blocktools.sealed | sort)" = "$cb" ] || f "container left behind after a success (its tmpfs with it)"
o=$(cd "$T/ws" && env -u DOCKER_HOST BLOCKTOOLS_IMAGE="$IMG" sh "$W" run 'exit 7' 2>&1) && f "failing pipeline returned 0"
[ "$($D ps -aq --filter label=blocktools.sealed | sort)" = "$cb" ] || f "container left behind after a failure"
# probe: keep the container to inspect what it had: no mounts but the tmpfs, and its disk layer has no secret
o=$(run env BLOCKTOOLS_SEAL_PROBE="$PID_F") || f "probe run failed: $o"
id=$(cat "$PID_F")
[ "$($D inspect -f '{{len .Mounts}} {{len .HostConfig.Binds}} {{len .HostConfig.Mounts}}' "$id")" = "0 0 0" ] || f "container has mounts/binds: $($D inspect -f '{{json .Mounts}}' "$id")"
$D inspect -f '{{index .HostConfig.Tmpfs "/secrets"}}' "$id" | grep -q '^rw,noexec,nosuid,nodev,size=16m' || f "/secrets not a tmpfs"
# the engine may create the mount points themselves in the container layer; anything else is a write to disk
dd=$($D diff "$id" | grep -Ev '^[AC] /(in|secrets|tmp|run|run/blocktools)$' || true)  # allow-true: asserted next
[ -z "$dd" ] || f "container wrote to its disk layer: $(echo "$dd" | head -5 | tr '\n' ' ')"
n=$($D export "$id" | tar -xOf - 2>/dev/null | grep -c "$SECRET" || true)  # allow-true: count asserted next
[ "$n" = 0 ] || f "secret found in the container's exported filesystem"
$D export "$id" | tar -tf - | grep -Eq '^(\./)?secrets/.' && f "/secrets has files in the container's disk filesystem"
$D rm -f "$id" >/dev/null; : > "$PID_F"
[ "$($D volume ls -q | sort)" = "$vb" ] || f "a volume was created"
[ "$(ls -A "$T/ws/secrets")" = pw ] || f "host secrets dir changed"
echo "ok   wrapper-seal real engine ($($D version --format '{{.Server.Os}} {{.Server.Version}}' 2>/dev/null)): /in arrived (2 entries, nested file) and secret readable inside, never printed; /in and /secrets are tmpfs (from /proc/mounts), not writable and not chmod-able by uid 10001; rootfs read-only; only lo, outbound fetch fails, uid 10001; no mounts/binds/volumes, docker diff shows at most the mount points, secret absent from docker export; no container (so no tmpfs) left after a success and a failure"
