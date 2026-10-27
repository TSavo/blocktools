# utxo-set --chainstate throughput and peak RSS on a real Dogecoin 1.14.9 regtest chainstate ('c' per-tx
# layout) holding ~1M coins: 500 txs of 2000 outputs each, built at test time by
# scripts/e2e.d/chainstate-real.sh (CHAINSTATE_BULK_TXS). Prints the pass-1 (logs only) and pass-2 (after restart: tables + log) ok lines (coins, read seconds,
# peak_rss) and the host. Needs network on first run (pinned tarball, sha256-checked).
set -eu
echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), $(nproc) threads, $(uname -s) $(uname -m)"
CHAINSTATE_CHAINS=doge CHAINSTATE_BULK_TXS=${CHAINSTATE_BULK_TXS:-500} BLOCKTOOLS_REQUIRE_FIXTURES=1 sh scripts/e2e.d/chainstate-real.sh | grep -E 'pass [12]:'
