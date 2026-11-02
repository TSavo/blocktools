#!/bin/sh
# msg-verify on strings that are BOTH a valid Cosmos bech32 address and a canonical on-curve Solana
# base58 key (public osmo1/juno1 addresses): refused as ambiguous_address unless --chain names the
# chain; with --chain cosmos a bogus pubkey/signature is refused, never accepted. No keys, no network.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
for a in osmo148yundzwcr97np3s8c8yrx2p6p33ck6sd4stfm juno1av6j5wgy64cwknm75pwyvegpwduf753uytqkwk; do
  $B/msg-verify --address $a --message x --sig AA== --pubkey AA== > $T/r && f "ambiguous exit 0 $a"
  grep -q '"ambiguous_address"' $T/r || f "ambiguous $a: $(cat $T/r)"
  $B/msg-verify --address $a --chain cosmos --message x --sig AA== --pubkey AA== > $T/r && f "bogus cosmos accepted $a"
  ! grep -q '"ambiguous_address"\|"pubkey_only_for_cosmos"\|"status":"ok"' $T/r || f "cosmos hint $a: $(cat $T/r)"
  $B/msg-verify --address $a --chain eth --message x --sig AA== > $T/r && f "eth hint exit 0 $a"
  grep -q '"chain_does_not_match_address"' $T/r || f "eth hint $a: $(cat $T/r)"
done
echo "ok   msg-ambiguous osmo1/juno1 cosmos-or-solana: ambiguous_address without --chain, --chain cosmos refuses bogus pubkey, --chain eth mismatch"
