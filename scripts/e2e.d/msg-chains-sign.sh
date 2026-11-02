#!/bin/sh
# msg-sign for Tron / Solana / Cosmos ADR-036 through the real CLI (pty types the code), checked with msg-verify.
# Tron signMessageV2 and Solana raw must equal Trust Wallet Core 2a8aa020's published signatures byte for byte
# (tests/chains/Tron/TronMessageSignerTests.cpp, tests/chains/Solana/SolanaMessageSigner.cpp; public test keys).
# Solana offchain-v0 and Cosmos ADR-036 have no published signature vector: round-trip through msg-verify only
# (UNTESTED for interop). Refusals: blind hash, missing --format, wrong-chain options, key mismatch, wrong code.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
j() { python3 -c "import json,sys; o=[json.loads(l) for l in open('$1') if l.strip().startswith('{')]; print([x.get('$2','') for x in o if 'status' in x][0])"; }
echo 75065f100e38d3f3b4c5c4235834ba8216de62272a4f03532c44b31a5734360a > $T/tron.key
echo 44f480ca27711895586074a14c552e58cc52e66a58edb6c58cf9b9b7295d4a2d > $T/sol.key
echo 4646464646464646464646464646464646464646464646464646464646464646 > $T/cosmos.key
TA=TWWb9EjUWai17YEVB7FR8hreupYJKG9sMR; SA=H3imdwa5VQMB5V6yBNyrWwPdSKs4k9Pcpsu4diogoAcg; CA=cosmos1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0emlrvp
drive() { k=$1; shift; python3 scripts/e2e-only/tty-drive.py right $T/$k.key $T/o $PWD/$B/msg-sign "$@" >/dev/null 2>&1 || f "msg-sign $*: $(cat $T/o)"; }
for c in "Hello World|bc0753c070cc55693097df11bc11e1a7c4bd5e1a40b9dc94c75568e59bcc9d6b50a7873ef25b469e494490a54de37327b4bc7fc825c81a377b555e34fb7261ba1c" \
         "A much longer message to test the signing and verification process|93aee5f753cf889e0749c74dd0c5996cce889883ae079e09ede462e16d65d06a4f43d1ed2745e9f3c1690695628269bd58f057a4a93953cc50e66b4a05bc0f451b"; do
  m=${c%%|*}; s=${c#*|}
  drive tron --address $TA --message "$m"; [ "$(j $T/o signature)" = "$s" ] || f "tron sig: $(j $T/o signature)"
  $B/msg-verify --address $TA --message "$m" --sig "$s" | grep -q '"status":"ok"' || f "msg-verify tron"
done
echo "ok   msg-chains-sign tron signMessageV2: msg-sign == Trust Wallet Core (2 vectors), msg-verify ok"
drive sol --address $SA --message "Hello world" --format raw
[ "$(j $T/o signature)" = 2iBZ6zrQRKHcbD8NWmm552gU5vGvh1dk3XV4jxnyEdRKm8up8AeQk1GFr9pJokSmchw7i9gMtNyFBdDt8tBxM1cG ] || f "sol raw sig"
drive sol --address $SA --message "Hello world" --format offchain-v0; S=$(j $T/o signature)
$B/msg-verify --address $SA --message "Hello world" --sig "$S" --format offchain-v0 | grep -q '"status":"ok"' || f "msg-verify sol offchain-v0"
$B/msg-verify --address $SA --message "Hello world" --sig "$S" --format raw | grep -q '"signer_mismatch"' || f "offchain-v0 sig verified as raw"
python3 -c "import json; print(json.dumps(list(bytes.fromhex(open('$T/sol.key').read().strip()))+[0]*32))" > $T/bad.json
echo "ok   msg-chains-sign solana raw == Trust Wallet Core; offchain-v0 round-trips through msg-verify (untested: no published vector)"
drive cosmos --address $CA --message "random"
[ "$(j $T/o hrp)" = cosmos ] || f "cosmos hrp"
$B/msg-verify --address $CA --message random --sig "$(j $T/o signature)" --pubkey "$(j $T/o pub_key)" | grep -q '"status":"ok"' || f "msg-verify cosmos"
echo "ok   msg-chains-sign cosmos ADR-036 round-trips through msg-verify (untested: no published vector)"
ref() { k=$1; e=$2; shift 2
  if $B/msg-sign "$@" < $T/$k > $T/r 2>&1; then f "signed: $*"; fi
  grep -qF -- "$e" $T/r && ! grep -q signature $T/r || f "refusal $e: $(cat $T/r)"
}
ref sol.key solana_format_required --address $SA --message "Hello world"
ref sol.key blind_hash_message --address $SA --format raw --message 0xc0a96273d5c3fbe4d4000491f08daef9c17f88df846c1d6f57eb5f33c1fbd035
ref tron.key blind_hash_message --address $TA --message c0a96273d5c3fbe4d4000491f08daef9c17f88df846c1d6f57eb5f33c1fbd035
ref cosmos.key blind_hash_message --address $CA --message c0a96273d5c3fbe4d4000491f08daef9c17f88df846c1d6f57eb5f33c1fbd035
ref tron.key only_text_messages_signed --address $TA --message 00 --hex
ref cosmos.key address_does_not_match_key --address $TA --message hi
ref tron.key address_does_not_match_key --address $CA --message hi
ref bad.json "unreadable key line" --address $SA --format raw --message hi
ref tron.key "--format is for Solana only" --address $TA --format raw --message hi
ref tron.key chain_does_not_match_address --address $TA --chain sol --message hi
python3 scripts/e2e-only/tty-drive.py wrong $T/tron.key $T/o $PWD/$B/msg-sign --address $TA --message "Hello World" >/dev/null 2>&1 && f "wrong code signed"
grep -q '"aborted"' $T/o && ! grep -q signature $T/o || f "wrong code output"
echo "ok   msg-chains-sign refusals: no --format, blind hash x3, hex, key mismatch, bad keypair, wrong-chain option, wrong code"
