# Chain: Qtum

Qtum uses Bitcoin's key format with its own version bytes (`Q...`, `M...`, `qc1...`) and coin type 2301.
Its P2PKH transactions are Bitcoin-legacy: 5 mainnet txs from qtum.info (crates/tx/tests/qtum.rs) re-hash
to their txids, every input signature verifies under the legacy sighash, and the input addresses re-derive.

<!-- e2e: expect=QXykR884CoPkbYHCFZ68bNVTMRvicWAFq2 ; expect=qc1qyqpjac4mtrr2elzmfknt28nau0hqq29ctk08ez -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain qtum --count 1'

The front door lists the addresses and stops (exit 3), pointing at tx-build:

<!-- e2e: rc=3 ; expect=QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59 ; expect=recipes/chain-qtum.md -->
    recipes/recover.sh /in/key.hex - --chain qtum

## Sweep (offline)

Fetch the UTXOs for your addresses from qtum.info (`https://qtum.info/api/address/ADDR/utxo`) into a JSON
list (`{"txid","vout","amount","address"}` per line), then build, read, and verify the unsigned sweep:

<!-- e2e: expect=QMDLoKJqTv5YNaDbHuuEQPwmTFaiaKHJVp -->
    ./blocktools run 'tx-build --chain qtum --utxos /in/u-qtum.json --to QMDLoKJqTv5YNaDbHuuEQPwmTFaiaKHJVp --sweep --fee-rate 700 | tx-decode --chain qtum'

<!-- e2e: expect="tool":"tx-verify" ; expect="failures":[] -->
    ./blocktools run 'tx-build --chain qtum --utxos /in/u-qtum.json --to QMDLoKJqTv5YNaDbHuuEQPwmTFaiaKHJVp --sweep --fee-rate 700 | tx-verify --chain qtum --expect-to QMDLoKJqTv5YNaDbHuuEQPwmTFaiaKHJVp'

Sign with `tx-sign --chain qtum` (TTY confirmation, as in goal-sweep.md) and broadcast the hex yourself
(qtum.info, or `sendrawtransaction` in Qtum Core). Qtum's fee floor is high: the fee warning uses a measured
median of 700 sat/vB. Not covered: contract (OP_CALL/OP_CREATE) outputs, P2PK inputs. No Qtum tx built here
has been broadcast.

Qtum wallet.dat (Qtum Core is a Bitcoin Core fork): input-wallet-dat.md, then `key-to-addresses --chain qtum`.
