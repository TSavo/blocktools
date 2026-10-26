#!/bin/sh
# seed-repair breadth: pairwise swap + Electrum 2.x scheme (public vectors). Never print mnemonics in ok lines.
set -eu
B=${BIN:-target/release}
T=${T:-$(mktemp -d)}
f() { echo "FAIL $1"; exit 1; }

# BIP39 Trezor vector with non-adjacent swap legal<->year
printf 'year winner thank legal wave sausage worth useful legal winner thank yellow\n' | $B/seed-repair --max 50 > $T/sw.out || f swap
grep -q 'legal winner thank year wave sausage worth useful legal winner thank yellow' $T/sw.out || f swap-phrase
echo "ok   seed-repair: non-adjacent pairwise swap restored BIP39 Trezor vector"

# Electrum segwit public vector (seed.rs / electrum tests)
EL='wild father tree among universe such mobile favorite target dynamic credit identify'
printf '%s\n' "$EL" | $B/seed-repair --scheme bip39 --max 5 > $T/el.bip || f el-bip
# Must not emit the Electrum phrase as a BIP39 candidate (may emit unrelated BIP39 hits).
if grep -q "\"mnemonic\":\"$EL\"" $T/el.bip; then f el-bip39-should-not-passthrough; fi
printf '%s\n' "$EL" | $B/seed-repair --scheme electrum --max 5 > $T/el.out || f el
grep -q "\"mnemonic\":\"$EL\"" $T/el.out || f el-phrase
# swapped neighbours under electrum scheme
printf 'wild father tree universe among such mobile favorite target dynamic credit identify\n' | $B/seed-repair --scheme electrum --max 50 > $T/el.sw || f el-sw
grep -q "\"mnemonic\":\"$EL\"" $T/el.sw || f el-sw-phrase
echo "ok   seed-repair --scheme electrum: Electrum vector passthrough + adjacent swap; bip39 scheme refuses it"

# finding:R1-2: an unknown --scheme is refused (bad_input, exit 2), not silently run as bip39.
rc=0; printf '%s\n' "$EL" | $B/seed-repair --scheme elektrum > $T/sch.out 2>&1 || rc=$?
[ $rc = 2 ] && grep -q '"error":"unknown_scheme"' $T/sch.out && echo "ok   seed-repair: unknown --scheme refused (exit 2)" || f "unknown-scheme rc=$rc"
