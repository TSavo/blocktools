# XRP Ledger: family seed / key -> address -> sweep Payment

Input types:
- A family seed: `s...` (secp256k1) or `sEd...` (ed25519). classify calls it `xrp_seed`.
- A BIP39 mnemonic. `derive --chain xrp` uses m/44'/144'/0'/0/i, secp256k1.
- A classic `r...` address or an `X...` address. These are watch-only.

```sh
./blocktools classify wallet.txt                 # -> xrp_seed
./blocktools run xrp-tx keys < seed.txt          # public only: address, X-address, public key
# Look up Balance and Sequence for the account on any rippled/Clio server (account_info).
# This is not automated yet.
./blocktools run xrp-tx build --account rYOUR... --to X7Acg...or r... [--destination-tag N] \
    --sweep --balance DROPS [--reserve 1000000] --fee 12 --sequence N --last-ledger N > unsigned.json
./blocktools run xrp-tx decode < unsigned.json   # read it
./blocktools run xrp-tx sign --tx unsigned.json --expect-to X7Acg... < seed.txt > signed.json   # typed code on the terminal
# Submit signed.json's tx_blob with rippled `submit`. This is not automated yet.
```

Rules:
- **Destination tag.** Exchanges credit deposits by tag. When the payment has no tag, `build` and `sign` both print `WARNING destination_tag_missing`. An X-address carries the tag, and `build` refuses a `--destination-tag` that conflicts with it.
- **Reserve.** The base reserve (default 1 XRP, `--reserve`) stays locked in the account. Only `AccountDelete` frees it, and that is not built here. Check the server's current `reserve_base` before you sweep.
- **Scope.** Only Payments of XRP (drops) are encoded and decoded. Issued currencies, paths and every other field are refused, never dropped.
- **Tests.**
  - Covered: keys, X-address and the signed blob, using xrpl.js vectors (crates/xrp/tests/kat.rs), plus scripts/e2e.d/xrp.sh.
  - **Not covered:** a real submission to the network.
