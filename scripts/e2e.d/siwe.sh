#!/bin/sh
# siwe (EIP-4361) through the real CLI against spruceid/siwe 911f6f2c test vectors (tools/siwe/tests/data,
# docs/PROVENANCE-siwe.md): every parsing_positive message parses and rebuilds byte-exact, every parsing_negative
# and invalid_uris message is refused, and each verification_positive message built from its fields verifies with
# msg-verify --chain eth against spruce's published signature, with spruce's time/domain/nonce as siwe parse checks
# (each verification_negative case fails at build, msg-verify or a check).
# Opt-in checks: domain, nonce, expiry, not-before.
set -eu
B=${BIN:-target/release}; D=tools/siwe/tests/data; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
python3 - "$B" "$D" "$T" <<'P' || f vectors
import json, subprocess, sys
B, D, T = sys.argv[1:]
def run(args, inp):
    p = subprocess.run([f"{B}/siwe"] + args, input=inp.encode(), capture_output=True)
    return p.returncode, p.stdout.decode()
n = 0
for name, t in json.load(open(f"{D}/parsing_positive.json")).items():
    rc, o = run(["parse"], t["message"]); assert rc == 0, (name, o)
    fields = json.loads(o)["fields"]
    assert fields == {k: v for k, v in t["fields"].items() if v is not None}, name
    rc, o = run(["build", "--raw"], json.dumps(fields)); assert rc == 0 and o == t["message"], name
    n += 1
for f in ["parsing_negative.json", "invalid_uris.json"]:
    for name, m in json.load(open(f"{D}/{f}")).items():
        rc, o = run(["parse"], m); assert rc == 1 and json.loads(o)["status"] == "refused", (name, o); n += 1
for pos, f in [(True, "verification_positive.json"), (False, "verification_negative.json")]:
    for name, t in json.load(open(f"{D}/{f}")).items():
        sig = t.pop("signature")
        chk = ["--now", t.pop("time")] if "time" in t else ["--check-time"]
        if "domainBinding" in t: chk += ["--domain", t.pop("domainBinding")]
        if "matchNonce" in t: chk += ["--nonce", t.pop("matchNonce")]
        rc, msg = run(["build", "--raw"], json.dumps(t))
        ok = rc == 0
        if ok:
            open(f"{T}/m", "w").write(msg)
            v = subprocess.run([f"{B}/msg-verify", "--chain", "eth", "--address", t["address"], "--message-file", f"{T}/m", "--sig", sig], capture_output=True, text=True)
            ok = v.returncode == 0 and '"status":"ok"' in v.stdout and run(["parse"] + chk, msg)[0] == 0
        assert ok == pos, (f, name)
        n += 1
print(f"ok   siwe spruceid vectors: {n} messages")
P
cat > $T/f.json <<'J'
{"domain":"service.org","address":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","statement":"I accept the ServiceOrg Terms of Service: https://service.org/tos","uri":"https://service.org/login","version":"1","chainId":1,"nonce":"32891757","issuedAt":"2021-09-30T16:25:24.000Z","expirationTime":"2021-10-30T16:25:24.000Z","notBefore":"2021-10-01T16:25:24.000Z"}
J
$B/siwe build --raw < $T/f.json > $T/m || f build
p() { $B/siwe parse "$@" < $T/m; }
NONCE=$(p | python3 -c "import json,sys;print(json.load(sys.stdin)['fields']['nonce'])")
DOM=$(p | python3 -c "import json,sys;print(json.load(sys.stdin)['fields']['domain'])")
EXP=$(p | python3 -c "import json,sys;print(json.load(sys.stdin)['fields']['expirationTime'])")
NB=$(p | python3 -c "import json,sys;print(json.load(sys.stdin)['fields']['notBefore'])")
p | grep -q '"unchecked":\["signature","domain","nonce","time"\]' || f "default unchecked"
p --domain "$DOM" --nonce "$NONCE" --now "$NB" | grep -q '"checked":\["domain","nonce","time"\]' || f "checks pass"
o=$(p --domain evil.example 2>&1) && f "domain"; echo "$o" | grep -q domain_mismatch || f "domain code"
o=$(p --nonce 00000000 2>&1) && f "nonce"; echo "$o" | grep -q nonce_mismatch || f "nonce code"
o=$(p --now "$EXP" 2>&1) && f "expired"; echo "$o" | grep -q '"expired"' || f "expired code"
o=$(p --now 1970-01-01T00:00:00Z 2>&1) && f "nbf"; echo "$o" | grep -q not_yet_valid || f "nbf code"
printf '%s\n' "$(cat $T/m)" | $B/siwe parse | grep -q non_canonical || f "trailing newline"
set +e; $B/siwe parse --now yesterday < $T/m >/dev/null; [ $? = 2 ] || f "bad --now rc"; set -e
echo "ok   siwe checks: domain, nonce, expired, not_yet_valid, non_canonical"
