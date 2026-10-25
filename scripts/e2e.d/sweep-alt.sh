#!/bin/sh
# Sweep e2e for GRS (single-SHA-256 txid/sighash, Groestl base58 checksum), LTC, DOGE, BLK and the
# PoS-nTime chains PPC/NVC/CLAM/RDD (raw tx + pos_prevouts instead of a PSBT):
# build -> verify -> sign (pty types the code via tty-drive.py) -> decode -> re-verify.
# Throwaway key 1 only; nothing touches a network. For GRS the decoded txid must equal the
# single-SHA-256 txid computed here in Python (and differ from the sha256d one).
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
# Legacy inputs carry a synthetic prev_tx (amount proof); zec's ZIP-244 sighash commits to amounts.
MU="cargo run -q --offline --release -p blocktools-tx --example mock-utxo --"
TID=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
sweep() { # chain from-addr-segwit-or-empty from-p2pkh to
  c=$1; w=$2; p=$3; d=$4
  { [ -n "$w" ] && printf '{"txid":"%s","vout":0,"amount":50000,"address":"%s"}\n' $TID $w; if [ $c = zec ]; then printf '{"txid":"%s","vout":1,"amount":%s,"address":"%s"}\n' $TID ${AMT:-30000} $p; else $MU $c 1 ${AMT:-30000} $p; fi; } > $T/u.$c
  $B/tx-build --chain $c --utxos $T/u.$c --to $d --sweep --fee-rate 5 ${TIME:+--time $TIME} > $T/p.$c || { cat $T/p.$c; f "$c build"; }
  $B/tx-verify --chain $c --expect-to $d < $T/p.$c >/dev/null || f "$c verify"
  python3 scripts/e2e-only/tty-drive.py right $T/k $T/o.$c $PWD/$B/tx-sign --tx $T/p.$c --expect-to $d > $T/tty.$c || f "$c sign"
  grep -q "Checks passed" $T/tty.$c || f "$c summary"
  $B/tx-decode --chain $c < $T/o.$c > $T/d.$c && grep -q '"signed":true' $T/d.$c || f "$c decode"
  $B/tx-verify --chain $c --expect-to $d < $T/o.$c >/dev/null || f "$c reverify"
  echo "ok   $c sweep: build -> verify -> tty sign -> decode signed -> re-verify"
}
sweep grs grs1qw508d6qejxtdg4y5r3zarvary0c5xw7k3k4sj5 Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR Fob4maNwBGVRPmMcRLS6qtTJfKeySAMsWq
python3 -c 'import json,sys;print([json.loads(l) for l in open(sys.argv[1]) if "signed_tx" in l][0]["signed_tx"])' $T/o.grs > $T/raw.grs
$B/tx-decode --chain grs < $T/raw.grs > $T/dr.grs || f "grs decode raw"
python3 - "$T/o.grs" "$T/dr.grs" <<'PY' || f "grs txid"
import hashlib, importlib.util, json, sys
s = importlib.util.spec_from_file_location("m", "scripts/mock-chain.py"); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
raw = [json.loads(l) for l in open(sys.argv[1]) if "signed_tx" in l][0]["signed_tx"]
dec = [json.loads(l) for l in open(sys.argv[2]) if '"txid"' in l][0]["txid"]
assert dec == m.txid(raw, single=True) and dec != m.txid(raw), (dec,)
PY
echo "ok   grs signed txid = single-SHA-256 (not sha256d)"
sweep ltc ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9 LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ MR8UQSBr5ULwWheBHznrHk2jxyxkHQu8vB
sweep doge "" DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE DJRU7MLhcPwCTNRZ4e8gJzDebtG1H5M7pc
sweep blk "" BF8MAsLp7aSfb9g9qGSHwzDerit8nAZAJX BHjTBorG4VcpNCj7wYU5tMriTMyHkKTWwV
TIME=1792800000
sweep ppc "" PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9 PMsYj4nuMuX6uCuig8TeS82KLVhb6hBZqt
sweep nvc "" 4QP6S2Gv3WZmgnJgR8mshrbHA9W6hQiTxR 4SzCSxnMzRjvTqMeXQofeEELknbFfka5SC
sweep clam "" xJyuT2j5dnLoBhHraFjzG2hmMDjnS3fefx xMb1TyEXahWwxkLpgXmnCQLpwrpwLRRhrb
sweep rdd "" RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa RmuAdiadczJMookEpeTZLsf37XFFKpkCxW
# PoS: the signed tx carries the requested nTime, the fee is known from pos_prevouts, and the
# txid is sha256d of the raw bytes.
for c in ppc nvc clam rdd; do
  python3 - "$T/o.$c" "$T/d.$c" $c <<'PY' || f "$c pos fields"
import hashlib, json, sys
o = [json.loads(l) for l in open(sys.argv[1]) if "signed_tx" in l][0]
d = [json.loads(l) for l in open(sys.argv[2]) if '"txid"' in l][0]
raw = bytes.fromhex(o["signed_tx"])
assert o["time"] == 1792800000 and o["chain"] == sys.argv[3]
t = raw[-4:] if sys.argv[3] == "rdd" else raw[4:8]
assert int.from_bytes(t, "little") == 1792800000
assert d["txid"] == hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
assert d.get("fee") not in (None, "")
PY
done
echo "ok   ppc/nvc/clam/rdd signed tx: nTime placed, sha256d txid, fee from pos_prevouts"
# Zcash transparent v5 (ZIP-244): raw tx + zec_prevouts + branch_id. The txid of the signed tx
# is recomputed here with Python's hashlib BLAKE2b, independently of the Rust code.
TIME= AMT=1000000
sweep zec "" t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs t1X9yaRpCHJpWX1HrGUxEu39xyQinmo3Ana
python3 - "$T/o.zec" "$T/d.zec" <<'PY' || f "zec txid"
import hashlib, json, sys
o = [json.loads(l) for l in open(sys.argv[1]) if "signed_tx" in l][0]
d = [json.loads(l) for l in open(sys.argv[2]) if '"txid"' in l][0]
b = bytes.fromhex(o["signed_tx"]); p = 20
H = lambda pers, x: hashlib.blake2b(x, digest_size=32, person=pers).digest()
def cs():
    global p
    v = b[p]; p += 1
    if v < 0xfd: return v
    n = {0xfd: 2, 0xfe: 4}[v]; r = int.from_bytes(b[p:p+n], "little"); p += n; return r
assert int.from_bytes(b[:4], "little") == 0x80000005 and b[8:12] == int(o["branch_id"], 16).to_bytes(4, "little")
ins = []
for _ in range(cs()):
    op = b[p:p+36]; p += 36; n = cs(); p += n; sq = b[p:p+4]; p += 4; ins.append((op, sq))
outs = b""
for _ in range(cs()):
    v = b[p:p+8]; p += 8; n = cs(); outs += v + bytes([n]) + b[p:p+n]; p += n
assert b[p:] == b"\0\0\0", "unexpected shielded bytes"
hdr = H(b"ZTxIdHeadersHash", b[:20])
tr = H(b"ZTxIdTranspaHash", H(b"ZTxIdPrevoutHash", b"".join(i[0] for i in ins)) + H(b"ZTxIdSequencHash", b"".join(i[1] for i in ins)) + H(b"ZTxIdOutputsHash", outs))
txid = H(b"ZcashTxHash_" + b[8:12], hdr + tr + H(b"ZTxIdSaplingHash", b"") + H(b"ZTxIdOrchardHash", b""))[::-1].hex()
assert d["txid"] == txid, (d["txid"], txid)
assert o["chain"] == "zec" and o["tx_format"] == "zcash-v5" and d.get("fee") not in (None, "")
PY
echo "ok   zec signed v5 txid = ZIP-244 recomputed with hashlib BLAKE2b; fee from zec_prevouts"
