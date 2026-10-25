# Chain: Zcash transparent (t1…)

`--chain zec`. Transparent only (shielded: see zcash-shielded.md). Builds v5 (NU5, ZIP-244) transactions. Sighashes are checked
against the ZIP-243/244 vectors and real mainnet txs (crates/tx/tests). Addresses use a 2-byte prefix, so zec is NOT in the
`derive` / `key-to-addresses` chain table.

The t1 address of a BIP39 phrase (m/44'/133'/0'/0/0) comes with the unified address:

<!-- e2e: expect=t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F -->
    ./blocktools run 'zec-sapling --count 1 --unified < /in/ada-mnemonic.txt'

Offline sweep of one 0.01 ZEC output at key 1's t1 address (t1UYsZ…) to key 2's (t1X9ya…):

<!-- e2e: expect=t1X9yaRpCHJpWX1HrGUxEu39xyQinmo3Ana -->
    ./blocktools run 'tx-build --chain zec --utxos /in/u-zec.json --to t1X9yaRpCHJpWX1HrGUxEu39xyQinmo3Ana --sweep --fee-rate 5 | tx-decode --chain zec'

<!-- e2e: expect="tool":"tx-verify" ; expect="failures":[] -->
    ./blocktools run 'tx-build --chain zec --utxos /in/u-zec.json --to t1X9yaRpCHJpWX1HrGUxEu39xyQinmo3Ana --sweep --fee-rate 5 | tx-verify --chain zec --expect-to t1X9yaRpCHJpWX1HrGUxEu39xyQinmo3Ana'

Signing is the TTY step (`tx-sign --chain zec`, human-typed code). scripts/e2e.d/sweep-alt.sh covers it.
NOT BUILT: a t1 address from a raw key or WIF (key-to-addresses has no zec row; use the phrase route above), zec in `derive`,
xpub, broadcast. UNTESTED: derivation m/44'/133' against a wallet app (only the ZIP-316 vectors), network acceptance.
