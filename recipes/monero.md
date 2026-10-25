# Chain: Monero

Built: 25-word English seed → spend/view keys → standard address (checked against the monero-python vector);
a view-only scan request for your own wallet-rpc. NOT BUILT: scan, sweep (design: docs/monero-sweep-design.md).

<!-- e2e: expect="class":"monero_seed" -->
    ./blocktools run 'classify /in/xmr-seed.txt'

<!-- e2e: expect=44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH -->
    ./blocktools run 'xmr-keys < /in/xmr-seed.txt'

<!-- e2e: rc=3 ; expect=44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH -->
    recipes/recover.sh /in/xmr-seed.txt -

## Check the balance (view-only, on the host, your own node)

    xmr-keys --scan-out viewonly.json --restore-height 2000000 < in/xmr-seed.txt
    curl -s http://127.0.0.1:18083/json_rpc -d @viewonly.json   # your monero-wallet-rpc
    shred -u viewonly.json

`viewonly.json` holds the private view key (mode 0600, never printed). It lets the holder see incoming funds
but not spend them. The e2e test checks the file's mode and contents. Sending it to a real wallet-rpc is UNTESTED.
Not supported: Polyseed, 13-word MyMonero, non-English seeds, subaddresses.
