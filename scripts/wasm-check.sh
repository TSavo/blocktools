#!/bin/sh
# Build the blocktools facade (default features) to WebAssembly, generate the npm package,
# and prove the .wasm carries no secret-handling code (DESIGN.md §11, ROADMAP L4b):
#   1. the binding crate's dependency tree has no secrets / net / seed / wallet crates;
#   2. the name section (function names, kept for this check) has none of the secret APIs;
#   3. exports are exactly the public JS API + wasm-bindgen glue + secp256k1-sys context hooks;
#   4. the Node smoke test (bindings/wasm/test.mjs) passes against public vectors.
# Needs: rustup target wasm32-unknown-unknown, clang (secp256k1-sys C), wasm-bindgen-cli =0.2.100, node.
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
cd "$(dirname "$0")/../bindings/wasm"
rc=0
# Reproducible build: scripts/wasm-build.sh builds from a copy in a build dir (see its header).
W=$(sh ../../scripts/wasm-build.sh)
mkdir -p target
# rule:W-repro: the same sources checked out at another path, built clean in a DIFFERENT build dir
# (BLOCKTOOLS_WASM_BUILD_DIR, other name and length), give the same bytes.
alt=$(mktemp -d "${TMPDIR:-/tmp}/blocktools-alt-checkout.XXXXXX")
(cd ../.. && git ls-files -z --cached --others --exclude-standard | xargs -0 cp --parents -t "$alt") && (cd "$alt" && git init -q && git add -A)
h1=$(sha256sum "$W" | cut -d' ' -f1)
cp "$W" target/blocktools_wasm.wasm; W=$PWD/target/blocktools_wasm.wasm
# The clean rebuild below runs in a fresh build dir ($b2), so the default build dir is kept: its next build is incremental.
b2=$(mktemp -d "${TMPDIR:-/tmp}/blocktools-wasm-alt-build-dir.XXXXXXXX")
W2=$(BLOCKTOOLS_WASM_BUILD_DIR="$b2" sh "$alt/scripts/wasm-build.sh"); h2=$(sha256sum "$W2" | cut -d' ' -f1); rm -rf "$alt" "$b2" "$b2.lock"
[ "${BLOCKTOOLS_WASM_BUILD_DIR:-/tmp/blocktools-wasm-build}" != "$b2" ] || { echo "FAIL repro builds share a build dir"; rc=1; }
[ "$h1" = "$h2" ] || { echo "FAIL wasm not reproducible: $h1 (repo) vs $h2 (clean build from another checkout path and build dir)"; rc=1; }
echo "wasm sha256 $h1 (clean rebuild from another checkout path and build dir matches: $([ "$h1" = "$h2" ] && echo yes || echo no))"
bad=$(cargo tree -q --locked --target wasm32-unknown-unknown -e normal --prefix none | awk '{print $1}' | sort -u \
  | grep -xE 'blocktools-secrets|blocktools-net|blocktools-tty|blocktools-io|bip39|scrypt|pbkdf2|aes|cbc|ctr|ed25519-dalek|minreq|rustls|ring|tokio|getrandom|rand' || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL wasm dep tree has: $bad"; rc=1; }
rm -rf pkg && wasm-bindgen "$W" --out-dir pkg/node --target nodejs && wasm-bindgen "$W" --out-dir pkg/web --target web && echo '{"type":"module"}' > pkg/web/package.json
# finding 10: wasm-bindgen's passStringToWasm0 trusts arg.length, so a non-string argument (a number, an
# Error object) corrupts wasm memory ("memory access out of bounds"). Guard it; fail if the hook moved.
for g in pkg/node/blocktools_wasm.js pkg/web/blocktools_wasm.js; do
  grep -q '^function passStringToWasm0(arg, malloc, realloc) {$' "$g" || { echo "FAIL $g: passStringToWasm0 not found (string guard)"; exit 1; }
  sed -i 's/^function passStringToWasm0(arg, malloc, realloc) {$/&\n    if (typeof arg !== "string") throw new TypeError("expected_string");/' "$g"
done
M=pkg/web/blocktools_wasm_bg.wasm
python3 ../../scripts/wasm-names.py "$M" funcs > target/funcs.txt
[ -s target/funcs.txt ] || { echo "FAIL no name section to check"; rc=1; }
hits=$(grep -E 'blocktools_secrets|blocktools_tx::sign|evm::Tx::sign|chains::(secp_rows|wif|derive_chain|slip10_ed25519|sol_row|derive_sol)|blocktools_core::(derive_from_master|derive_account|key_rows|row_for|eth_address::)|bip39::|scrypt::|pbkdf2::|aes::|ed25519_dalek|Xpriv|PrivateKey|to_wif|from_wif|secp256k1_v0_10_0_(ecdsa_sign|ecdsa_sign_recoverable|schnorrsig_sign(32|_custom)?|keypair_create|ec_pubkey_create|ec_seckey_tweak_(add|mul)|ellswift_create)$' target/funcs.txt || [ $? -eq 1 ])
[ -z "$hits" ] || { echo "FAIL secret code in wasm:"; echo "$hits"; rc=1; }
exp=$(python3 ../../scripts/wasm-names.py "$M" exports | awk '{print $2}' | sort | tr '\n' ' ')
want="__externref_table_alloc __externref_table_dealloc __wbindgen_export_0 __wbindgen_free __wbindgen_malloc __wbindgen_realloc __wbindgen_start addressToScript addressValidate addressesFromXpub base58Decode base58Encode blake2b buildEvmTransfer buildPsbtWithMemo buildUnsignedSweep buildUnsignedSweepAt cashAddrDecode cashAddrEncode cashAddrToLegacy chainParams chainTable checkTx checkTxPolicy convertAddress convertAddressFrom decodeAccountInfo decodeTx deriveFromXpub describeTx detectAddress detectAddressInfo evmAbiDecode evmAbiEncode evmAbiEncodePacked evmAbiInspect evmApproveCall evmBytecodeInspect evmCreateAddress evmKeccak256 evmSigHash evmSigLookup evmTypedDataVerify explainPlan legacyToCashAddr listChains memory polkadotAccountStorageKey recoveryTables rustsecp256k1_v0_10_0_context_create rustsecp256k1_v0_10_0_context_destroy rustsecp256k1_v0_10_0_default_error_callback_fn rustsecp256k1_v0_10_0_default_illegal_callback_fn scriptToAddress selectUtxos serializeNvcTxFromJson solAnchorDiscriminator solAssociatedTokenAddress solBuildTransfer solDecodeTx solFindProgramAddress solIsOnCurve solVerifyTx ss58Decode ss58Encode supportedChains tronBuildTransfer tronDecodeTx tronTxId twox128 unverifiedChains validateAddress verifyRecovery verifyRecoveryRaw verifySweepRaw verifySweepTx verifyTx version "
[ "$exp" = "$want" ] || { echo "FAIL exports differ:"; echo " got  $exp"; echo " want $want"; rc=1; }
node test.mjs || rc=1
node test-web.mjs || rc=1
node gen-reference.mjs --check || rc=1  # docs/EXPORTS-reference.md is generated from the test.mjs calls
raw=$(wc -c < "$M"); gz=$(gzip -9c "$M" | wc -c)
wasm-bindgen "$W" --out-dir target/stripped --target web --remove-name-section --remove-producers-section
st=$(wc -c < target/stripped/blocktools_wasm_bg.wasm); stgz=$(gzip -9c target/stripped/blocktools_wasm_bg.wasm | wc -c)
deps=$(cargo tree -q --locked --target wasm32-unknown-unknown -e normal --prefix none | awk '{print $1}' | sort -u | wc -l)
echo "wasm: $(wc -l < target/funcs.txt) functions; $raw bytes ($gz gz) with names, $st bytes ($stgz gz) stripped; $deps crates in tree"
[ $rc = 0 ] && echo "wasm-check ok"
exit $rc
