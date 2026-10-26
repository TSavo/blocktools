#!/bin/sh
# Trust Wallet Core message-signer vectors through the real msg-sign / msg-verify CLIs (pty types
# the code). Bitcoin signmessage (compressed + uncompressed P2PKH) and Ethereum personal_sign
# (legacy v, Immutable X raw v, EIP-155 v) must come out byte for byte equal to TWC's signatures;
# wrong-code, blind-hash, segwit, key-mismatch and mismatch paths are refused. No network.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
sig() { python3 -c "import json,sys; o=[json.loads(l) for l in open('$1') if l.strip().startswith('{')]; print([x['signature'] for x in o if 'signature' in x][0])"; }
echo afeefca74d9a325cf1d6b6911d61a65c32afa8e02bd5e78e2e4ac2910bab45f5 > $T/btc.key
echo 03a9ca895dca1623c7dfd69693f7b4111f5d819d2e145536e0b03c136025a25d > $T/eth.key
# btc: compressed and uncompressed address of the same key
for c in "19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X ILH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo=" \
         "1E4T9JZ3mq6cdgiRJEWzHqDXb9t322fE6d HLH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo="; do
  set -- $c
  python3 scripts/e2e-only/tty-drive.py right $T/btc.key $T/o $PWD/$B/msg-sign --address $1 --message "test signature" >/dev/null 2>&1 || f "msg-sign btc $1: $(cat $T/o)"
  [ "$(sig $T/o)" = "$2" ] || f "btc sig $1"
  $B/msg-verify --address $1 --message "test signature" --sig "$2" | grep -q '"status":"ok"' || f "msg-verify btc $1"
done
echo "ok   twc-message btc signmessage compressed+uncompressed: msg-sign == Trust Wallet Core, msg-verify ok"
# eth: derive the address with msg-verify from TWC's legacy vector, then sign three v conventions
S1=0x21a779d499957e7fd39392d49a079679009e60e492d9654a148829be43d2490736ec72bc4a5644047d979c3cf4ebe2c1c514044cf436b063cb89fc6676be71101b
EA=$($B/msg-verify --address 0x0000000000000000000000000000000000000001 --message Foo --sig $S1 | python3 -c "import json,sys; print(json.load(sys.stdin)['recovered'])") || true # allow-true: signer_mismatch exits 1 by design; only the recovered address is read
[ -n "$EA" ] || f "eth recover"
for c in "legacy $S1" "eip155:0 ${S1%1b}23"; do
  set -- $c
  python3 scripts/e2e-only/tty-drive.py right $T/eth.key $T/o $PWD/$B/msg-sign --address $EA --message Foo --v $1 >/dev/null 2>&1 || f "msg-sign eth $1: $(cat $T/o)"
  [ "$(sig $T/o)" = "$2" ] || f "eth sig $1: $(sig $T/o)"
  $B/msg-verify --address $EA --message Foo --sig $2 | grep -q '"status":"ok"' || f "msg-verify eth $1"
done
echo 3b0a61f46fdae924007146eacb6db6642de7a5603ad843ec58e10331d89d4b84 > $T/imx.key
printf 'Only sign this request if you\342\200\231ve initiated an action with Immutable X.\n\nFor internal use:\nbd717ba31dca6e0f3f136f7c4197babce5f09a9f25176044c0b3112b1b6017a3' > $T/imx.msg
SI=0x32cd5a58f3419fc5db672e3d57f76199b853eda0856d491b38f557b629b0a0814ace689412bf354a1af81126d2749207dffae8ae8845160f33948a6b787e17ee01
IA=$($B/msg-verify --address 0x0000000000000000000000000000000000000001 --message-file $T/imx.msg --sig $SI | python3 -c "import json,sys; print(json.load(sys.stdin)['recovered'])") || true # allow-true: signer_mismatch exits 1 by design; only the recovered address is read
python3 scripts/e2e-only/tty-drive.py right $T/imx.key $T/o $PWD/$B/msg-sign --address $IA --message-file $T/imx.msg --v raw >/dev/null 2>&1 || f "msg-sign imx"
[ "$(sig $T/o)" = "$SI" ] || f "imx sig"
echo "ok   twc-message eth personal_sign legacy / eip155:0 / Immutable X raw v: msg-sign == Trust Wallet Core, msg-verify ok"
# TWC legacy_hex vector verifies as bytes (--hex), but msg-sign refuses the blind 32-byte hash
H=0xc0a96273d5c3fbe4d4000491f08daef9c17f88df846c1d6f57eb5f33c1fbd035
SH=0xb18a666ad08bf9bfcd39920b26b5a5d1486b67b45119810b3c7bda22e41e5c4c1bfbe0c932f6c14df4947a18ba310831a37b7307d724a3ac2a4935b99d7075141b
HA=$($B/msg-verify --address 0x0000000000000000000000000000000000000001 --message $H --hex --sig $SH | python3 -c "import json,sys; print(json.load(sys.stdin)['recovered'])") || true # allow-true: signer_mismatch exits 1 by design; only the recovered address is read
$B/msg-verify --address $HA --message $H --hex --sig $SH | grep -q '"status":"ok"' || f "legacy_hex verify"
echo 9066aa168c379a403becb235c15e7129c133c244e56a757ab07bc369288bcab0 > $T/hx.key
ref() { # expected-failure args...
  e=$1; shift
  if $B/msg-sign "$@" < $T/btc.key > $T/r 2>&1; then f "signed: $*"; fi
  grep -q "\"$e\"" $T/r && grep -q '"status":"refused"' $T/r && ! grep -q signature $T/r || f "refusal $e: $(cat $T/r)"
}
ref blind_hash_message --address $HA --message $H
ref only_text_messages_signed --address $HA --message $H --hex
ref address_not_p2pkh --address bc1qpjult34k9spjfym8hss2jrwjgf0xjf40ze0pp8 --message "test signature"
ref address_does_not_match_key --address 1B8Qea79tsxmn4dTiKKRVvsJpHwL2fMQnr --message "test signature"
ref message_prefix_unproven_for_chain --address 19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X --chain ltc --message "test signature"
ref message_looks_like_transaction --address 19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X --message "$(python3 -c "import json; print(json.load(open('crates/tx/tests/vectors/twc-evm.json'))['vectors'][0]['signed'])")"
python3 scripts/e2e-only/tty-drive.py wrong $T/btc.key $T/o $PWD/$B/msg-sign --address 19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X --message "test signature" >/dev/null 2>&1 && f "wrong code signed"
grep -q '"aborted"' $T/o && ! grep -q signature $T/o || f "wrong code output"
$B/msg-verify --address 1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN --message "test signature" --sig ILH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo= > $T/r && f "mismatch exit 0"
grep -q '"signer_mismatch"' $T/r || f "mismatch status"
echo "ok   twc-message refusals: blind hash, hex, segwit, key mismatch, ltc prefix, tx-as-message, wrong code; msg-verify mismatch exits 1"
