# Chain: Algorand

Addresses and keys only, from Algorand's own 25-word mnemonic (Pera / algosdk format; the last
word is a checksum). It is not a BIP39 seed, so `derive` does not cover it.

<!-- e2e: expect="class":"algo_mnemonic" -->
    ./blocktools run 'classify /in/algo-mnemonic.txt'

<!-- e2e: expect=47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU -->
    ./blocktools run 'key-to-addresses --chain algo < /in/algo-mnemonic.txt'

The key is printed as `private_key` = base64(seed || public key), the algosdk format, and is
always redacted by `redact`.
NOT BUILT: Ledger-style BIP32-Ed25519 paths (m/44'/283'/...), payments, balance, rekeyed accounts.
