# Goal: verify before signing, and sign on an offline machine

The online machine has addresses only. The offline machine has the keys.

1. Online: `recipes/recover.sh FILE - --goal balance > utxos.jsonl`, then
   `tx-build --chain btc --utxos utxos.jsonl --to DEST --sweep --fee-rate 5 > unsigned.json`.
2. Copy `unsigned.json` to the offline machine (USB). Check it there:

<!-- e2e: expect="status":"failed" ; expect=input_amounts_unknown -->
    ./blocktools run 'tx-verify --expect-to 1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3 --max-fee 10000 < /in/block170.hex'

   (Here the check correctly fails: a raw transaction has no input amounts, so the fee is unknown. A PSBT from
   `tx-build` carries them, so the check can pass.)
3. Offline, a human signs: `./blocktools reveal 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc | tx-sign --tx /in/unsigned.json --expect-to DEST'`
   with a typed code. Then copy the signed tx back.
4. Online: `tx-decode --text < signed.json`, then `tx-broadcast --chain btc < signed.json` (a second code).
