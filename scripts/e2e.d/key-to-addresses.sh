# raw 32-byte key (private key 1, textbook value) -> multi-chain addresses through the boundary
set -eu
echo 0000000000000000000000000000000000000000000000000000000000000001 | boundary k2a '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm' 'key-to-addresses'
grep -q TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC "$T/k2a.jsonl" && grep -q 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf "$T/k2a.jsonl" || { echo "FAIL k2a chains"; exit 1; }
echo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" | boundary allchains 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk' 'seed-repair | seed-to-master | derive --chain all --count 1'
# broken pipe: outln! exits 0 quietly (no panic) when the reader goes away.
# head -c1 closes after one byte so EPIPE hits mid-write on a JSON line.
epipe_check() {
  name=$1; shift
  err=$(mktemp)
  set +e
  "$@" 2>"$err" | head -c1 >/dev/null
  set -e
  if grep -qiE 'panic|BrokenPipe|broken pipe' "$err"; then
    echo "FAIL EPIPE panic in $name: $(tr '\n' ' ' < "$err")"
    rm -f "$err"; exit 1
  fi
  rm -f "$err"
}
MN='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
epipe_check key-to-addresses sh -c 'echo 0000000000000000000000000000000000000000000000000000000000000001 | "$1"' _ "$B/key-to-addresses"
epipe_check chain-table "$B/chain-table"
epipe_check tx-envelope sh -c '"$1" --json "{\"op\":\"chain_table\"}"' _ "$B/tx-envelope"
epipe_check seed-to-master sh -c 'printf "%s\n" "$2" | "$1"' _ "$B/seed-to-master" "$MN"
epipe_check zec-sapling sh -c 'printf "%s\n" "$2" | "$1" --count 1' _ "$B/zec-sapling" "$MN"
epipe_check xmr-keys sh -c 'printf "%s\n" "$2" | "$1"' _ "$B/xmr-keys" "$MN"
epipe_check acct-tx sh -c 'printf "%s\n" "$2" | "$1" keys --chain xlm' _ "$B/acct-tx" "$MN"
epipe_check xrp-tx sh -c 'printf "%s\n" "$2" | "$1" keys' _ "$B/xrp-tx" "$MN"
echo "ok  EPIPE: quiet (head -c1, no panic) for key-to-addresses chain-table tx-envelope seed-to-master zec-sapling xmr-keys acct-tx xrp-tx"
# chain registry as data
n=$(( $("$B/chain-table" | wc -l) )); [ "$n" -ge 40 ] || { echo "FAIL chain-table rows $n"; exit 1; }
"$B/chain-table" ltc | grep -q '"p2pkh":48,"p2sh":50,"wif":176,"hrp":"ltc"' || { echo "FAIL chain-table ltc"; exit 1; }
"$B/chain-table" nope 2>/dev/null && { echo "FAIL chain-table unknown accepted"; exit 1; }
echo "ok  chain-table: $n rows, ltc row matches chainparams"
