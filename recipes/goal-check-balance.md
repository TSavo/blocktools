# Goal: check whether anything is left (balance only, nothing signed)

`recipes/recover.sh FILE - --goal balance` runs the right reader, keeps public addresses only, and asks the chain:
Esplora for btc/ltc/doge, JSON-RPC for eth. Only addresses leave the sealed step. Exit 0 = funds found
(UTXO lines or the account object), 4 = nothing found, 3 = this chain has no balance lookup here.

<!-- e2e: expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu ; expect="txid" ; fund=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu -->
    recipes/recover.sh /in/seed.txt - --goal balance

<!-- e2e: rc=4 ; expect=no funds found ; fund=1BoatSLRHtKNngkdXEeobR76b53LETtpyT -->
    recipes/recover.sh /in/seed.txt - --goal balance

Wider search: `--count 50`, or derive.md with `--gap-limit`. Using a public server shows it your addresses;
for privacy, point `--url` at your own node. Balance lookups for Tron, Solana, XRP, Qtum, old coins and
Monero are not built (each chain's recipe says what to do instead).
