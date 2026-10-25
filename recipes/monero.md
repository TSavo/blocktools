# Chain: Monero

Built: 25-word English seed → spend/view keys → standard address (checked against the monero-python vector);
a view-only scan request; host tool `xmr-wallet` (scan + sweep through YOUR loopback monero-wallet-rpc; sweep relays only after a human types a code at the TTY).

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
but not spend them. The e2e test checks the file's mode and contents. 

## Scan and sweep with xmr-wallet (host, loopback wallet-rpc)

    xmr-wallet scan  --rpc http://127.0.0.1:18083 --scan-req viewonly.json
    xmr-wallet sweep --rpc http://127.0.0.1:18083 --to DEST --restore-height N < in/xmr-seed.txt          # plan only
    xmr-wallet sweep --rpc http://127.0.0.1:18083 --to DEST --restore-height N --relay < in/xmr-seed.txt  # asks at /dev/tty

2026-10-25 stagenet run (Mac, official monero v0.18.5.4 binaries, SHA-256 checked against the published hashes.txt): faucet 0.5 XMR seen by `xmr-wallet scan` (unlocked 500000000000 at height 2236134); `xmr-wallet sweep --relay` planned amount 499969620000 + fee 30380000 = unlocked, relayed tx bb300227e8e6c418fe7d825ac432d79abc2d4b943d99e053eabfba3c8197a96d (mined in stagenet block 2236135, checked on a public stagenet node); a view-only `scan` of the destination wallet shows that amount incoming (pool). The TTY confirm was answered by an `expect` script standing in for a human. Untested: mainnet, Polyseed/13-word/non-English seeds, subaddresses.

Not supported: Polyseed, 13-word MyMonero, non-English seeds, subaddresses.
