# Chain: Algorand

Addresses and keys only, from Algorand's own 25-word mnemonic (Pera / algosdk format; the last
word is a checksum). It is not a BIP39 seed, so `derive` does not cover it.

<!-- e2e: expect="class":"algo_mnemonic" -->
    ./blocktools run 'classify /in/algo-mnemonic.txt'

<!-- e2e: expect=47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU -->
    ./blocktools run 'key-to-addresses --chain algo < /in/algo-mnemonic.txt'

The key is printed as `private_key` = base64(seed || public key), the algosdk format, and is
always redacted by `redact`.
## Payments and sweep (acct-tx)

    utxo-fetch --chain algo A...  # host-side: algonode: amount, min-balance, opted-in assets, last_round, min_fee
    acct-tx build --chain algo --from A... --to A... --amount MICROALGO --fee 1000 --first-round LAST_ROUND > u.json
    acct-tx build --chain algo --from A... --to A... --sweep --fee 1000 --first-round LAST_ROUND > u.json   # close-to
    acct-tx decode --chain algo < u.json
    acct-tx sign --chain algo --tx u.json --expect-to A... < key.txt > signed.json   # 25 words or base64 key; typed code on /dev/tty

Canonical msgpack `pay` only. The sweep is amount 0 with close-remainder-to = destination: everything moves and the
account closes. Algorand refuses this while ASAs are opted in. Decode refuses rekey, lease, group, msig and lsig fields.
`--last-round` defaults to first + 1000. KAT: unsigned and signed bytes and txids byte-equal to py-algorand-sdk
(crates/acct/tests/kat.rs, scripts/e2e.d/acct.sh).

NOT BUILT: Ledger-style BIP32-Ed25519 paths (m/44'/283'/...), broadcast, ASA transfers, rekeyed accounts.
UNTESTED: a real network submit; `utxo-fetch` was run once against mainnet-api.algonode.cloud (2026-10-25) and is not in CI.
