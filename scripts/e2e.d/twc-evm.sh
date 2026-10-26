#!/bin/sh
# Trust Wallet Core EVM vectors through the real tx-sign CLI (pty types the code): the unsigned
# form of TWC's signed legacy EIP-155 native tx and EIP-1559 ERC-20 transfer is signed with TWC's
# public test key and must come out byte for byte equal to TWC's signed tx. The chain id comes
# from the tx itself (--chain-id pins it). ERC-1155 safeTransferFrom calldata and ERC-721
# transferFrom are refused by policy (unknown_contract_call / token_call_not_transfer). No network.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
V=crates/tx/tests/vectors/twc-evm.json
# vector name -> $T/NAME.{key,unsigned,signed}; unsigned = signed with the signature dropped
python3 - "$V" "$T" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))["vectors"]
def rlp_dec(b, i=0):
    p = b[i]
    if p < 0x80: return b[i:i+1], i+1
    if p < 0xb8: return b[i+1:i+1+p-0x80], i+1+p-0x80
    if p < 0xc0: n = p-0xb7; l = int.from_bytes(b[i+1:i+1+n], "big"); return b[i+1+n:i+1+n+l], i+1+n+l
    if p < 0xf8: l, s = p-0xc0, i+1
    else: n = p-0xf7; l = int.from_bytes(b[i+1:i+1+n], "big"); s = i+1+n
    out, j = [], s
    while j < s+l: x, j = rlp_dec(b, j); out.append(x)
    return out, s+l
def rlp_enc(x):
    if isinstance(x, list):
        p = b"".join(rlp_enc(y) for y in x); return hdr(len(p), 0xc0) + p
    if len(x) == 1 and x[0] < 0x80: return x
    return hdr(len(x), 0x80) + x
def hdr(l, o):
    if l < 56: return bytes([o+l])
    n = l.to_bytes((l.bit_length()+7)//8, "big"); return bytes([o+55+len(n)]) + n
for x in v:
    s = bytes.fromhex(x["signed"])
    if s[0] == 2: f, _ = rlp_dec(s, 1); u = b"\x02" + rlp_enc(f[:9])
    else:
        f, _ = rlp_dec(s); vv = int.from_bytes(f[6], "big"); cid = (vv-35)//2
        u = rlp_enc(f[:6] + [cid.to_bytes((cid.bit_length()+7)//8, "big"), b"", b""])
    n = x["test"].replace("test_sign_transaction_", "")
    open(f"{sys.argv[2]}/{n}.key", "w").write(x["key"] + "\n")
    open(f"{sys.argv[2]}/{n}.unsigned", "w").write(u.hex() + "\n")
    open(f"{sys.argv[2]}/{n}.signed", "w").write(x["signed"] + "\n")
PY
sign() { # name chain_id expect_to [extra]
  n=$1; c=$2; to=$3; shift 3
  python3 scripts/e2e-only/tty-drive.py right $T/$n.key $T/$n.out $PWD/$B/tx-sign --tx $T/$n.unsigned --chain-id $c --expect-to $to "$@" >/dev/null 2>&1 || return 1
}
sign non_typed_native 1 0x3535353535353535353535353535353535353535 || f "tx-sign native"
python3 -c "import json,sys; o=[json.loads(l) for l in open('$T/non_typed_native.out') if l.strip().startswith('{')]; s=[x['signed_tx'] for x in o if 'signed_tx' in x][0]; sys.exit(s.removeprefix('0x')!=open('$T/non_typed_native.signed').read().strip())" || f "native bytes"
echo "ok   twc-evm legacy EIP-155 native: tx-sign output == Trust Wallet Core signed tx"
sign eip1559_erc20_transfer 1 0x5322b34c88ed0691971bf52a7047448f0f4efc84 || f "tx-sign erc20"
python3 -c "import json,sys; o=[json.loads(l) for l in open('$T/eip1559_erc20_transfer.out') if l.strip().startswith('{')]; s=[x['signed_tx'] for x in o if 'signed_tx' in x][0]; sys.exit(s.removeprefix('0x')!=open('$T/eip1559_erc20_transfer.signed').read().strip())" || f "erc20 bytes"
echo "ok   twc-evm EIP-1559 ERC-20 transfer: tx-sign output == Trust Wallet Core signed tx"
for c in "eip1559_erc1155_transfer unknown_contract_call" "eip1559_erc721_transfer token_call_not_transfer"; do
  set -- $c
  if $B/tx-sign --tx $T/$1.unsigned --chain-id 1 --expect-to 0x5322b34c88ed0691971bf52a7047448f0f4efc84 < $T/$1.key > $T/$1.ref 2>&1; then f "$1 signed"; fi
  grep -q "\"$2\"" $T/$1.ref && grep -q '"status":"refused"' $T/$1.ref && ! grep -q signed_tx $T/$1.ref || f "$1 refusal: $(cat $T/$1.ref)"
done
echo "ok   twc-evm ERC-1155 (unknown_contract_call) / ERC-721 transferFrom (token_call_not_transfer) refused, nothing signed"
