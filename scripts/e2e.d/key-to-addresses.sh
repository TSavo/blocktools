# raw 32-byte key (private key 1, textbook value) -> multi-chain addresses through the boundary
set -eu
echo 0000000000000000000000000000000000000000000000000000000000000001 | boundary k2a '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm' 'key-to-addresses'
grep -q TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC "$T/k2a.jsonl" && grep -q 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf "$T/k2a.jsonl" || { echo "FAIL k2a chains"; exit 1; }
echo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" | boundary allchains 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk' 'seed-repair | seed-to-master | derive --chain all --count 1'
# broken pipe: no panic message, quiet exit
r=$(echo 0000000000000000000000000000000000000000000000000000000000000001 | "$B/key-to-addresses" 2>&1 | head -1 >/dev/null; echo ok)
[ "$r" = ok ] && echo "ok  EPIPE: quiet"
# chain registry as data
n=$(( $("$B/chain-table" | wc -l) )); [ "$n" -ge 40 ] || { echo "FAIL chain-table rows $n"; exit 1; }
"$B/chain-table" ltc | grep -q '"p2pkh":48,"p2sh":50,"wif":176,"hrp":"ltc"' || { echo "FAIL chain-table ltc"; exit 1; }
"$B/chain-table" nope 2>/dev/null && { echo "FAIL chain-table unknown accepted"; exit 1; }
echo "ok  chain-table: $n rows, ltc row matches chainparams"
