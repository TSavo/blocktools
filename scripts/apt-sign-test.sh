#!/bin/sh
# Property test for scripts/apt-sign-host.sh against a THROWAWAY dev-mode Vault (never the real one) and
# throwaway GPG keys. Checks: (1) the signed repo verifies against its keyring, (2) not against another
# key, (3) refuses when the AppRole policy does not cover the path, (4) refuses when the Vault key is not
# the committed one, (5) no PGP private-key block in output, (6) nothing left on /dev/shm, and in a real
# Debian container (APT_TEST_IMAGE, default debian:12): (7) apt update + install succeed with signed-by,
# (8) apt update fails with a different key, (9) fails with a tampered Packages file.
# Needs docker, gpg, jq, curl, apt-ftparchive, python3. Usage: scripts/apt-sign-test.sh [file.deb]
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd); cd "$root"
D=${DOCKER:-docker}; port=${TEST_VAULT_PORT:-18299}; name=bt-aptsign-testvault-$$
img=${APT_TEST_IMAGE:-debian:12}
t=$(mktemp -d); log=$t/log
fin() { $D rm -f "$name" >/dev/null 2>&1 || true; GNUPGHOME=$t/g gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$t"; }  # allow-true: cleanup
trap fin EXIT INT TERM
tok=throwaway-dev-root   # throwaway: dev-mode vault root token, container lives only for this test
$D run -d --rm --name "$name" -p 127.0.0.1:$port:8200 -e VAULT_DEV_ROOT_TOKEN_ID=$tok hashicorp/vault:1.18 >/dev/null
V=http://127.0.0.1:$port; i=0
until curl -sf $V/v1/sys/health >/dev/null; do i=$((i+1)); [ $i -lt 30 ] || { echo "dev vault did not start"; exit 1; }; sleep 1; done
vx() { $D exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=$tok "$name" vault "$@"; }
mkdir -m 700 "$t/g"
mk() { GNUPGHOME=$t/g gpg --batch --quiet --passphrase '' --quick-gen-key "$1" ed25519 sign never >/dev/null 2>&1
  GNUPGHOME=$t/g gpg --batch --with-colons --list-keys "$1" | awk -F: '/^fpr/{print $10; exit}'; }
fp=$(mk "throwaway apt test <test@throwaway>"); ofp=$(mk "other apt test <other@throwaway>")
GNUPGHOME=$t/g gpg --batch --export "$fp" > "$t/test.gpg"; GNUPGHOME=$t/g gpg --batch --export "$ofp" > "$t/other.gpg"
GNUPGHOME=$t/g gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys "$fp" > "$t/k" 2>/dev/null
GNUPGHOME=$t/g gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys "$ofp" > "$t/ko" 2>/dev/null
$D cp "$t/k" "$name:/tmp/k" >/dev/null; $D cp "$t/ko" "$name:/tmp/ko" >/dev/null; rm -f "$t/k" "$t/ko"
vx kv put secret/blocktools/apt-signing private_key=@/tmp/k fingerprint="$fp" key_id=x >/dev/null
vx kv put secret/blocktools/apt-wrong private_key=@/tmp/ko fingerprint="$ofp" key_id=x >/dev/null
vx auth enable approle >/dev/null
printf 'path "secret/data/blocktools/apt-signing" { capabilities = ["read"] }\npath "secret/data/blocktools/apt-wrong" { capabilities = ["read"] }\n' | vx policy write signer - >/dev/null
vx write auth/approle/role/good token_policies=signer token_no_default_policy=true token_ttl=5m >/dev/null
vx write auth/approle/role/nopolicy token_policies=nothing token_no_default_policy=true token_ttl=5m >/dev/null
for r in good nopolicy; do
  mkdir -p "$t/$r"
  vx read -field=role_id auth/approle/role/$r/role-id < /dev/null > "$t/$r/role-id"
  vx write -f -field=secret_id auth/approle/role/$r/secret-id < /dev/null > "$t/$r/secret-id"
done
deb=${1:-}
if [ -z "$deb" ]; then mkdir -p "$t/empty"; BINDIR=$t/empty scripts/package-native.sh deb >/dev/null 2>&1; deb=$(ls -t /tmp/blocktools_*_amd64.deb | head -1); fi
fail=0
run() { VAULT_ADDR=$V APT_SIGN_CRED_DIR=$t/$1 APT_SIGN_KEYRING=$t/test.gpg APT_SIGN_SECRET_PATH=${3:-secret/data/blocktools/apt-signing} scripts/apt-sign-host.sh "$2" "$deb" >>"$log" 2>&1; }
ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
if run good "$t/repo"; then ok "signed repo verifies against its keyring"; else bad "sign+verify"; fi
r=$t/repo/dists/stable
if gpgv --keyring "$t/other.gpg" "$r/InRelease" >>"$log" 2>&1; then bad "verified against a different key"; else ok "does not verify against a different key"; fi
if run nopolicy "$t/repo2"; then bad "signed without policy"; else ok "refuses when the role has no policy for the path"; fi
[ ! -e "$t/repo2/dists" ] && ok "refused run wrote no repo" || bad "refused run wrote a repo"
if run good "$t/repo3" secret/data/blocktools/apt-wrong; then bad "signed with a key that is not the committed one"; else ok "refuses when the vault key is not the committed key"; fi
if grep -q "PGP PRIVATE KEY" "$log"; then bad "PGP private key block in output"; else ok "no PGP private key block in output"; fi
if ls /dev/shm | grep -q "^bt-aptsign"; then bad "key dir left on /dev/shm"; else ok "no key left on /dev/shm"; fi
# Real apt client. Tampered copy: one byte changed in Packages (Release hashes then mismatch).
cp -r "$t/repo" "$t/tamper"; printf 'X-Tampered: 1\n' >> "$t/tamper/dists/stable/main/binary-amd64/Packages"
gzip -9nkf "$t/tamper/dists/stable/main/binary-amd64/Packages"
cp "$t/test.gpg" "$t/repo/k.gpg"; cp "$t/other.gpg" "$t/repo/o.gpg"; cp "$t/test.gpg" "$t/tamper/k.gpg"
chmod -R a+rX "$t"
apt_try() { # $1 repo dir, $2 keyring name, $3 install?
  $D run --rm -v "$1:/repo:ro" "$img" sh -c "
    rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list; install -d /etc/apt/keyrings; cp /repo/$2 /etc/apt/keyrings/bt.gpg
    echo 'deb [signed-by=/etc/apt/keyrings/bt.gpg] file:/repo stable main' > /etc/apt/sources.list.d/bt.list
    apt-get -o Acquire::Languages=none update 2>&1 | tee /tmp/u; ! grep -qE '^(W|E):' /tmp/u || exit 1
    [ -z '$3' ] || { apt-get install -y blocktools >/dev/null 2>&1 && dpkg -s blocktools | grep -q 'Status: install ok installed'; }"
}
if apt_try "$t/repo" k.gpg 1 >>"$log" 2>&1; then ok "apt update + install with signed-by ($img)"; else bad "apt update/install with the right key ($img)"; fi
if apt_try "$t/repo" o.gpg "" >>"$log" 2>&1; then bad "apt accepted a different key"; else ok "apt update fails with a different key"; fi
if apt_try "$t/tamper" k.gpg "" >>"$log" 2>&1; then bad "apt accepted a tampered Packages"; else ok "apt update fails with a tampered Packages"; fi
[ $fail = 0 ] || { echo "--- log (key lines redacted) ---"; sed "/BEGIN PGP PRIVATE/,/END PGP PRIVATE/d" "$log"; }
exit $fail
