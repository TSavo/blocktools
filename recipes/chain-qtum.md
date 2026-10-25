# Chain: Qtum

Addresses only. Qtum uses Bitcoin's key format with its own version bytes (`Q...`, `M...`, `qc1...`)
and coin type 2301.

<!-- e2e: expect=QXykR884CoPkbYHCFZ68bNVTMRvicWAFq2 ; expect=qc1qyqpjac4mtrr2elzmfknt28nau0hqq29ctk08ez -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain qtum --count 1'

The front door lists the addresses and stops (exit 3):

<!-- e2e: rc=3 ; expect=QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59 ; expect=sweep is not built -->
    recipes/recover.sh /in/key.hex - --chain qtum

Qtum wallet.dat (Qtum Core is a Bitcoin Core fork): input-wallet-dat.md, then `key-to-addresses --chain qtum`.
NOT BUILT: Qtum sweep. Qtum is UTXO, but its transactions and its Esplora-style API are untested here. To move the funds,
import the key into Qtum Core (`importprivkey`, via `./blocktools reveal`, run by a human).
