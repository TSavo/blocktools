#!/bin/sh
# BIP38 non-EC (public BIP vectors) and Blockchain.com wallet.aes.json (self-made v3 wrapper).
# Never print WIFs; verify via known addresses only.
set -eu
B=${BIN:-target/release}
T=${T:-$(mktemp -d)}
f() { echo "FAIL $1"; exit 1; }

# --- BIP38 Test 1 uncompressed (bitcoin/bips bip-0038) ---
# Address of decrypted key is 1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB (BIP hex CBF4...; older drafts listed 1JwSSub...).
printf 'TestingOneTwoThree\n6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg\n' | $B/bip38-open > $T/b38.json || f bip38-open
grep -q '"status":"ok"' $T/b38.json || f bip38-status
grep -q '"compressed":false' $T/b38.json || f bip38-comp
$B/key-to-addresses --chain btc < $T/b38.json > $T/b38.addr || f bip38-k2a
grep -q '1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB' $T/b38.addr || f bip38-addr
printf 'wrong\n6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg\n' | $B/bip38-open > $T/b38.bad 2>/dev/null && f bip38-wrong-exit
grep -q wrong_passphrase $T/b38.bad || f bip38-wrong-status
echo '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg' > $T/b38.raw
$B/classify $T/b38.raw | grep -q '"class":"bip38"' || f bip38-classify
echo "ok   bip38-open: BIP38 TestingOneTwoThree -> 1Jq6Mks...; wrong passphrase refused; classify=bip38"

# --- Blockchain.com v3 wrapper (openssl + stdlib; password is a test token) ---
python3 - "$T" <<'PY' || f bc-fixture
import base64, hashlib, json, os, subprocess, sys, tempfile
T = sys.argv[1]
password = b"blocktools-bc-test"
iv = bytes([7] * 16)
key = hashlib.pbkdf2_hmac("sha1", password, iv, 10, dklen=32)
inner = b'{"guid":"test","keys":[{"priv":"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"}]}'
pad = 16 - (len(inner) % 16)
plain = inner + bytes([0xAA] * (pad - 1)) + bytes([pad])
with tempfile.NamedTemporaryFile() as f:
    f.write(plain); f.flush()
    ct = subprocess.check_output(["openssl", "enc", "-aes-256-cbc", "-nopad", "-K", key.hex(), "-iv", iv.hex(), "-in", f.name])
w = {"version": 3, "pbkdf2_iterations": 10, "payload": base64.b64encode(iv + ct).decode()}
open(T + "/bc.json", "w").write(json.dumps(w, separators=(",", ":")) + "\n")
open(T + "/bc.in", "wb").write(password + b"\n" + json.dumps(w, separators=(",", ":")).encode())
PY
$B/classify $T/bc.json | grep -q '"class":"blockchain_wallet"' || f bc-classify
$B/blockchain-read < $T/bc.in > $T/bc.out || f bc-read
grep -q '"status":"ok"' $T/bc.out || f bc-status
$B/key-to-addresses --chain btc < $T/bc.out > $T/bc.addr || f bc-k2a
grep -q '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm' $T/bc.addr || f bc-addr
printf 'wrong\n' | cat - $T/bc.json | $B/blockchain-read > $T/bc.bad 2>/dev/null && f bc-wrong-exit
grep -qE 'wrong_password|bad_padding|decrypt' $T/bc.bad || f bc-wrong-status
echo "ok   blockchain-read: v3 wrapper decrypts; classify=blockchain_wallet; key1 -> 1EHNa6Q4...; wrong password refused"
