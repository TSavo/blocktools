# SCAN_JS parity fixture

`abandon-about-TREZOR.txt` is the output of SwapChan's SCAN_JS script (keyrecovery.ts logic as
scan.mjs, run with node), for the public BIP-39 test phrase "abandon x11 about", `GAP=20` and a
passphrase file holding the single line `TREZOR`. Each line is `wallet path[ [passphrase #N]] address`.
`scripts/e2e.d/scan-js.sh` checks that `seed-to-master --passphrase-file | derive --preset scan-js
--address-list` prints the same lines in the same order (tabs read as spaces). Public addresses only.
