#!/bin/sh
# Property test for scripts/rpm-sign-host.sh against a THROWAWAY dev-mode Vault (never the real one) and
# throwaway GPG keys. Checks: (1) RPMs + repomd.xml signed via Vault verify against its public key, (2) they
# do NOT verify against a different key, (3) the script refuses, leaving the RPM untouched, when the
# AppRole's policy does not cover the path, (4) it refuses when the Vault key is not the given public key,
# (5) no PGP/PEM private-key block appears in any output, (6) no key dir is left on tmpfs. Needs docker.
# Usage: scripts/rpm-sign-test.sh [file.rpm]
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd); cd "$root"
D=${DOCKER:-docker}; port=${TEST_VAULT_PORT:-18299}; name=bt-rpmsign-testvault-$$
t=$(mktemp -d); log=$t/log
fin() { $D rm -f "$name" >/dev/null 2>&1 || true; $D run --rm -v "$t:/t" alpine:3.20 rm -rf /t/a /t/b /t/c >/dev/null 2>&1 || true; rm -rf "$t"; }; trap fin EXIT INT TERM  # allow-true: cleanup
tok=throwaway-dev-root   # throwaway: dev-mode vault root token, container lives only for this test
$D run -d --rm --name "$name" -p 127.0.0.1:$port:8200 -e VAULT_DEV_ROOT_TOKEN_ID=$tok hashicorp/vault:1.18 >/dev/null
V=http://127.0.0.1:$port; i=0
until curl -sf $V/v1/sys/health >/dev/null; do i=$((i+1)); [ $i -lt 30 ] || { echo "dev vault did not start"; exit 1; }; sleep 1; done
vx() { $D exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=$tok "$name" vault "$@"; }
# Two throwaway keys: test (armored secret + public + fingerprint) and other (public only).
$D run --rm -v "$t:/o" alpine:3.20 sh -c 'apk add -q gnupg >/dev/null 2>&1
  for k in test other; do export GNUPGHOME=$(mktemp -d)
    gpg --batch --pinentry-mode loopback --passphrase "" --quick-gen-key "throwaway $k <$k@throwaway>" rsa2048 sign never >/dev/null 2>&1
    gpg --batch --armor --export > /o/$k.pub
    gpg --batch --with-colons --list-keys | awk -F: "/^fpr/{print \$10; exit}" > /o/$k.fpr
    [ $k = other ] || gpg --batch --pinentry-mode loopback --passphrase "" --armor --export-secret-keys > /o/$k.sec
  done 2>/dev/null; chmod 644 /o/*'
$D cp "$t/test.sec" "$name:/tmp/k" >/dev/null; rm -f "$t/test.sec"
vx kv put secret/blocktools/rpm-signing private_key=@/tmp/k key_id=x fingerprint="$(cat "$t/test.fpr")" >/dev/null
vx auth enable approle >/dev/null
printf 'path "secret/data/blocktools/rpm-signing" { capabilities = ["read"] }\n' | vx policy write signer - >/dev/null
vx write auth/approle/role/good token_policies=signer token_no_default_policy=true token_ttl=5m >/dev/null
vx write auth/approle/role/nopolicy token_policies=nothing token_no_default_policy=true token_ttl=5m >/dev/null
for r in good nopolicy; do
  mkdir -p "$t/$r"
  vx read -field=role_id auth/approle/role/$r/role-id < /dev/null > "$t/$r/role-id"
  vx write -f -field=secret_id auth/approle/role/$r/secret-id < /dev/null > "$t/$r/secret-id"
done
rpm=${1:-}
if [ -z "$rpm" ]; then mkdir -p "$t/empty"; BINDIR=$t/empty scripts/package-native.sh rpm >/dev/null 2>&1; rpm=$(ls -t /tmp/blocktools-*-1.x86_64.rpm | head -1); fi
for d in a b c; do mkdir -p "$t/$d"; cp "$rpm" "$t/$d/"; done
fail=0
run() { VAULT_ADDR=$V RPM_SIGN_CRED_DIR=$t/$1 RPM_SIGN_PUB=$t/$2 scripts/rpm-sign-host.sh "$t/$3" >>"$log" 2>&1; }
if run good test.pub a; then echo "ok   signed RPM and repomd.xml verify against the public key"; else echo "FAIL sign+verify (rc $?)"; fail=1; fi
if scripts/rpm-verify.sh "$t/other.pub" "$t/a" >>"$log" 2>&1; then echo "FAIL verified against a different key"; fail=1; else echo "ok   does not verify against a different key"; fi
if run nopolicy test.pub b; then echo "FAIL signed without policy"; fail=1; else echo "ok   refuses when the role has no policy for the path"; fi
if cmp -s "$rpm" "$t/b/$(basename "$rpm")" && [ ! -e "$t/b/repodata" ]; then echo "ok   refused run left the RPM untouched"; else echo "FAIL refused run modified the repo dir"; fail=1; fi
if run good other.pub c; then echo "FAIL signed although the Vault key is not the given public key"; fail=1; else echo "ok   refuses when the Vault key does not match the public key"; fi
if grep -qE "BEGIN.*PRIVATE KEY" "$log"; then echo "FAIL private key block in output"; fail=1; else echo "ok   no private key block in output"; fi
if ls /dev/shm | grep -q "^bt-rpmsign"; then echo "FAIL key dir left on /dev/shm"; fail=1; else echo "ok   no key left on /dev/shm"; fi
[ $fail = 0 ] || { echo "--- log (key lines redacted) ---"; sed "/PRIVATE KEY/,/END/d" "$log"; }
exit $fail
