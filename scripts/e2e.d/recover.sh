# shellcheck shell=bash
# docs/recipes/recover.sh end to end, one dummy input per type, against scripts/mock-chain.py on
# 127.0.0.1 only. A pty (tty-drive.py) types BOTH confirmation codes (sign, then broadcast).
# Sourced by e2e-local.sh ($B, $T set). Every key here is a public test vector.
R=$T/rec; mkdir -p "$R"; D=bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
python3 scripts/make-fixtures.py "$R" >/dev/null
: > "$R/funded"; MOCK_FUNDED="$R/funded" python3 scripts/mock-chain.py "$R/port" "$R/log" "$R/noexp" >/dev/null 2>&1 & RM=$!
while [ ! -s "$R/port" ]; do sleep 0.1; done; RU=http://127.0.0.1:$(cat "$R/port")
# rec NAME FILE FUNDED_ADDR [PASSWORD] : fund one address, recover FILE, expect one broadcast
rec() {
  if [ ! -f "$2" ]; then echo "skip recover $1: $2 absent (scripts/fetch-fixtures.sh)"; return 0; fi
  echo "$3" > "$R/funded"; : > "$R/log"; printf '%s\n' "${4:-}" > "$R/pw"
  dst=$D; case $3 in 0x*) dst=0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF ;; esac
  BIN=$B python3 scripts/tty-drive.py right /dev/null "$R/$1.out" "$PWD/docs/recipes/recover.sh" "$2" "$dst" \
    --url "$RU" --count 2 --password-file "$R/pw" > "$R/$1.tty" 2>&1 || { echo "FAIL recover $1"; cat "$R/$1.tty" "$R/$1.out"; exit 1; }
  if ! grep -q '"status":"ok"' "$R/$1.out" || [ "$(grep -Ec '^/tx |eth_sendRawTransaction' "$R/log")" != 1 ]; then echo "FAIL recover $1: not broadcast once"; cat "$R/$1.out"; exit 1; fi
  # txids are public 64-hex: strip them; then nothing key-shaped may remain in stdout or on the terminal
  if sed -E 's/(txid[": ]*|id )[0-9a-f]{64}//g' "$R/$1.out" "$R/$1.tty" | grep -Eq "$LEAK"; then echo "LEAK recover $1"; exit 1; fi
  echo "ok  recover $1: $(sed -n 's/^recover: classified as //p' "$R/$1.tty") -> signed sweep, confirmed twice, broadcast once"
}
echo "abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot" > "$R/seed.txt"
rec seed-typo "$R/seed.txt" bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
echo "cycle rocket west magnet parrot shuffle foot correct salt library feed song" > "$R/electrum-seed.txt"
rec electrum-seed "$R/electrum-seed.txt" 1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf
echo 0000000000000000000000000000000000000000000000000000000000000001 > "$R/key.hex"
rec hex-key "$R/key.hex" bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
echo KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn > "$R/key.wif"
rec wif "$R/key.wif" 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
rec wallet-dat "$R/descriptor-encrypted.sqlite" bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu blocktools-test-password
rec electrum-wallet fixtures/external/electrum4_4_3_unencrypted bc1qsz0dhew357cj6eznmcawgyf44jzpgcax2lvfvm btcr-test-password
[ -f fixtures/external/multibit-wallet.key.privkeys.txt ] && MB=$("$B/key-to-addresses" --chain btc < fixtures/external/multibit-wallet.key.privkeys.txt | "$B/redact" | sed -n 's/.*"address":"\(1[^"]*\)".*/\1/p' | head -1)
rec multibit fixtures/external/multibit-wallet.key "${MB:-}" btcr-test-password
python3 -c 'import re;print(re.search(r"const V: &str = r#\"(.*?)\"#;", open("crates/secrets/src/keystore.rs").read()).group(1))' > "$R/keystore.json"
rec keystore "$R/keystore.json" 0x008AeEda4D805471dF9b2A5B0f38A0C3BCBA786b testpassword
# watch-only and wrong-code cases: nothing may be signed or sent
echo bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu > "$R/addr.txt"; : > "$R/log"
if BIN=$B docs/recipes/recover.sh "$R/addr.txt" $D --url "$RU" 2>/dev/null; then echo "FAIL recover address"; exit 1; fi
[ ! -s "$R/log" ] && echo "ok  recover address: watch-only, refused (exit 3), nothing sent"
echo bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu > "$R/funded"
BIN=$B python3 scripts/tty-drive.py wrong /dev/null "$R/w.out" "$PWD/docs/recipes/recover.sh" "$R/seed.txt" $D --url "$RU" > "$R/w.tty" 2>&1 || true
if [ ! -s "$R/log" ] && grep -q aborted "$R/w.tty"; then echo "ok  recover wrong code: aborted at tx-sign, nothing sent"; else echo "FAIL recover wrong"; exit 1; fi
kill $RM 2>/dev/null; wait $RM 2>/dev/null || true
# Monero (public monero-python test seed): classify -> xmr-keys prints the public address, then stops (exit 3)
echo "adjust mugged vaults atlas nasty mews damp toenail suddenly toxic possible framed succeed fuzzy return demonstrate nucleus album noises peculiar virtual rowboat inorganic jester fuzzy" > "$R/xmr-seed.txt"
set +e; BIN=$B bash docs/recipes/recover.sh "$R/xmr-seed.txt" "$D" > "$R/xmr.out" 2> "$R/xmr.err"; rc=$?; set -e
if [ $rc = 3 ] && grep -q '"address":"44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH"' "$R/xmr.out" && grep -q "classified as monero_seed" "$R/xmr.err"; then echo "ok  recover xmr-seed: monero_seed -> address (KAT), stops before scan"; else echo "FAIL recover xmr-seed"; cat "$R/xmr.out" "$R/xmr.err"; exit 1; fi
