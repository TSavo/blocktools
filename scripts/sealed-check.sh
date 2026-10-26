#!/bin/sh
# Sealed run, measured: creates the container exactly as `./blocktools run` does (BLOCKTOOLS_SEAL_PROBE=1),
# checks the properties on the real container with docker inspect, then runs it on a public test mnemonic
# and checks the agent output carries addresses and no secret material.
#   BLOCKTOOLS_DOCKER="sudo docker" sh scripts/sealed-check.sh     (needs the blocktools:local image)
# Prints "sealed-check ok" only if every property holds; exits 2 if there is no image or docker.
set -eu
cd "$(dirname "$0")/.."
D=${BLOCKTOOLS_DOCKER:-docker}; IMG=${BLOCKTOOLS_IMAGE:-blocktools:local}
$D image inspect "$IMG" >/dev/null 2>&1 || { echo "sealed-check: no image $IMG (docker: $D)" >&2; exit 2; }
id=""; W=$(mktemp -d)
trap 'rm -rf "$W"; [ -z "$id" ] || $D rm -f "$id" >/dev/null 2>&1' EXIT
mkdir "$W/in" "$W/secrets"; chmod 755 "$W" "$W/in"
echo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" > "$W/in/m.txt"; chmod 644 "$W/in/m.txt"
id=$(BLOCKTOOLS_SEAL_PROBE=1 BLOCKTOOLS_IN="$W/in" BLOCKTOOLS_SECRETS="$W/secrets" sh ./blocktools run 'seed-to-master < /in/m.txt | derive --chain btc --count 2' | tail -1)
rc=0
chk() { v=$($D inspect -f "$2" "$id"); if [ "$v" = "$3" ]; then echo "ok   sealed $1 = $v"; else echo "FAIL sealed $1: $v (want $3)"; rc=1; fi; }
chk NetworkMode '{{.HostConfig.NetworkMode}}' none
chk ReadonlyRootfs '{{.HostConfig.ReadonlyRootfs}}' true
chk CapDrop '{{.HostConfig.CapDrop}}' '[ALL]'
chk User '{{.Config.User}}' 10001:10001
chk SecurityOpt '{{.HostConfig.SecurityOpt}}' '[no-new-privileges:true]'
chk InMountRW '{{range .Mounts}}{{if eq .Destination "/in"}}{{.RW}}{{end}}{{end}}' false
out=$($D start -a "$id" 2>&1 < /dev/null) || { echo "FAIL sealed run exited non-zero: $(printf '%s' "$out" | head -3)"; rc=1; }
n=$(printf '%s\n' "$out" | grep -c '"address":"bc1q' || true)  # allow-true: count asserted next
if [ "$n" -ge 1 ]; then echo "ok   sealed run printed $n bc1q addresses"; else echo "FAIL sealed run printed no addresses"; rc=1; fi
LEAK='"(wif|private_key|xprv|seed|mnemonic|passphrase|password|secret)":"[^[]|xprv[1-9A-Za-z]{20}|abandon|[0-9a-fA-F]{64}|"(5|K|L)[1-9A-HJ-NP-Za-km-z]{50,51}"'
if printf '%s\n' "$out" | grep -Eq "$LEAK"; then echo "FAIL sealed run output leaks secret material"; rc=1; else echo "ok   sealed run output: no secret material"; fi
[ $rc = 0 ] && echo "sealed-check ok"
exit $rc
