# Zcash shielded (Sapling) from a BIP39 mnemonic

Status: address + viewing key only. Verified against ZIP-32 Sapling vectors (hard derivation, key components).
Not cross-checked against a wallet app's mnemonic -> zs1 output; check that the first address matches what
your wallet showed before you rely on it.

<!-- e2e: expect=zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta -->

    ./blocktools run 'zec-sapling --count 5 < /in/ada-mnemonic.txt'

With an output directory for the view-only key:

```sh
./blocktools run zec-sapling --count 1 --viewkey-out /out/zec.view < /in/mnemonic.txt
```

The viewing-key file (zxviews…, mode 0600, never overwritten) can be imported into a wallet such as
Zingo or Ywallet as view-only to scan for notes. It reveals all incoming and outgoing history, so treat it
as sensitive. The spending key is never written. To move funds, restore the mnemonic in a Zcash wallet
(Orchard, scanning and spending are not built here).
