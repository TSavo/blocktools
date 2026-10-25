# Goal: move everything to a new address (sweep)

    recipes/recover.sh in/WALLET DEST [--chain btc|ltc|doge] [--password-file secrets/pw] [--fee-rate N]

The steps:
1. classify picks the reader.
2. Public addresses go to the chain, and the funded outputs come back.
3. `tx-build --sweep` makes an UNSIGNED PSBT, and `tx-decode --text` shows it.
4. `tx-sign --expect-to DEST` re-checks the destination, prints the decoded transaction on the terminal, and waits for a typed code.
5. `tx-broadcast` shows it again and waits for a second code.

Keys are never written to disk. They are re-derived and piped straight into `tx-sign`.

The e2e test runs this end to end against a 127.0.0.1 mock chain for seed (with typos), Electrum seed and
wallet, wallet.dat, raw hex key, WIF, MultiBit, Ethereum keystore, Litecoin and Dogecoin, with both codes typed
by a pty driver. A wrong code aborts with nothing sent. That flow needs a terminal, so it isn't one of the
one-line examples here. The watch-only refusal is:

<!-- e2e: rc=3 ; expect=watch-only -->
    recipes/recover.sh /in/xpub.txt bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

Chains without a sweep stop after the addresses (exit 3): Qtum, old coins, Tron, Solana. XRP has its
own builder (xrp.md). Monero is design-only (monero.md).
Before you broadcast: goal-verify-and-offline.md. UNTESTED: a sweep on a live network by this script.
