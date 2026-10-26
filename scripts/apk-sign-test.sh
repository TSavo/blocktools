#!/bin/sh
# Property test for scripts/apk-sign-host.sh against a THROWAWAY dev-mode Vault (never the real one).
# Checks: (1) an APK signed via Vault verifies against its public key, (2) it does NOT verify against a
# different key, (3) the script refuses when the AppRole's policy does not cover the path, (4) no PEM
# private-key block appears in any output, (5) no key dir is left on tmpfs. Needs docker.
# Usage: scripts/apk-sign-test.sh [file.apk]
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd); cd "$root"
D=${DOCKER:-docker}; port=${TEST_VAULT_PORT:-18298}; name=bt-apksign-testvault-$$
t=$(mktemp -d); log=$t/log
fin() { $D rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$t"; }; trap fin EXIT INT TERM  # allow-true: container may already be gone
tok=throwaway-dev-root   # throwaway: dev-mode vault root token, container lives only for this test
$D run -d --rm --name "$name" -p 127.0.0.1:$port:8200 -e VAULT_DEV_ROOT_TOKEN_ID=$tok hashicorp/vault:1.18 >/dev/null
V=http://127.0.0.1:$port; i=0
until curl -sf $V/v1/sys/health >/dev/null; do i=$((i+1)); [ $i -lt 30 ] || { echo "dev vault did not start"; exit 1; }; sleep 1; done
vx() { $D exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=$tok "$name" vault "$@"; }
mk() { $D run --rm -v "$t:/o" alpine:3.20 sh -c "apk add -q openssl >/dev/null 2>&1; openssl genrsa -out /o/$1 2048 2>/dev/null; openssl rsa -in /o/$1 -pubout -out /o/$1.pub 2>/dev/null; chmod 644 /o/$1 /o/$1.pub"; }
mk test@throwaway.rsa; mk other@throwaway.rsa
$D cp "$t/test@throwaway.rsa" "$name:/tmp/k" >/dev/null
vx kv put secret/blocktools/apk-signing private_key=@/tmp/k key_name=test@throwaway.rsa >/dev/null
vx auth enable approle >/dev/null
printf 'path "secret/data/blocktools/apk-signing" { capabilities = ["read"] }\n' | vx policy write signer - >/dev/null
vx write auth/approle/role/good token_policies=signer token_no_default_policy=true token_ttl=5m >/dev/null
vx write auth/approle/role/nopolicy token_policies=nothing token_no_default_policy=true token_ttl=5m >/dev/null
for r in good nopolicy; do
  mkdir -p "$t/$r"
  vx read -field=role_id auth/approle/role/$r/role-id < /dev/null > "$t/$r/role-id"
  vx write -f -field=secret_id auth/approle/role/$r/secret-id < /dev/null > "$t/$r/secret-id"
done
apk=${1:-}
if [ -z "$apk" ]; then mkdir -p "$t/empty"; MUSL_BINDIR=$t/empty scripts/package-native.sh apk >/dev/null 2>&1; apk=$(ls -t /tmp/blocktools-*-r0.apk | head -1); fi
cp "$apk" "$t/a.apk"; cp "$apk" "$t/b.apk"
fail=0
run() { VAULT_ADDR=$V APK_SIGN_CRED_DIR=$t/$1 APK_SIGN_KEY_NAME=test@throwaway.rsa APK_SIGN_PUB=$t/test@throwaway.rsa.pub scripts/apk-sign-host.sh "$2" >>"$log" 2>&1; }
if run good "$t/a.apk"; then echo "ok   signed APK verifies against its public key"; else echo "FAIL sign+verify (rc $?)"; fail=1; fi
if scripts/apk-verify.sh "$t/other@throwaway.rsa.pub" "$t/a.apk" >>"$log" 2>&1; then echo "FAIL verified against a different key"; fail=1; else echo "ok   does not verify against a different key"; fi
if run nopolicy "$t/b.apk"; then echo "FAIL signed without policy"; fail=1; else echo "ok   refuses when the role has no policy for the path"; fi
if cmp -s "$apk" "$t/b.apk"; then echo "ok   refused run left the APK untouched"; else echo "FAIL refused run modified the APK"; fail=1; fi
if grep -q "BEGIN.*PRIVATE KEY" "$log"; then echo "FAIL PEM private key block in output"; fail=1; else echo "ok   no PEM private key block in output"; fi
if ls /dev/shm | grep -q "^bt-apksign"; then echo "FAIL key dir left on /dev/shm"; fail=1; else echo "ok   no key left on /dev/shm"; fi
[ $fail = 0 ] || { echo "--- log (PEM lines redacted) ---"; sed "s/.*PRIVATE KEY.*/<redacted>/" "$log"; }
exit $fail
