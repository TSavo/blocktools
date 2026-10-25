# Chain: Litecoin and Dogecoin

Same pipeline as Bitcoin with `--chain ltc` / `--chain doge`. Sweep is built (UTXO PSBT). Dogecoin
has no segwit, so its inputs carry the full previous transaction.

<!-- e2e: expect=LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez ; expect=ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh ; expect=DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain ltc,doge --count 1'

<!-- e2e: expect=ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh ; fund=ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh -->
    recipes/recover.sh /in/seed.txt - --chain ltc --goal balance

Sweep: `recipes/recover.sh in/seed.txt ltc1q... --chain ltc` (the address and balance steps are e2e-tested on the mock chain;
the ltc/doge sign+broadcast leg through recover.sh is UNTESTED). Defaults: litecoinspace.org. Dogecoin has no
default Esplora, so pass `--url`.
UNTESTED against a live LTC or DOGE network.
