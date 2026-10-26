# Trust Wallet Core UTXO forks (public TWC test keys, tests/chains/{Syscoin,Firo}): key-to-addresses
# must give TWC's published addresses, and redact must keep the rows. Address/WIF only; these chains have no signing claim.
set -eu
k2a() { echo "$1" | "$B/key-to-addresses" --chain "$2"; }
k2a a22ddec5c567b4488bb00f69b6146c50da2ee883e2c096db098726394d585730 sys | grep -q '"address":"SXBPFk2PFDAP13qyKSdC4yptsJ8kJRAT3T"' \
 && k2a 55f9cbb0376c422946fa28397c1219933ac60b312ede41bfacaf701ecd546625 sys | grep -q '"address":"sys1qytnqzjknvv03jwfgrsmzt0ycmwqgl0as7lkcf7"' \
 && k2a a22ddec5c567b4488bb00f69b6146c50da2ee883e2c096db098726394d585730 firo | grep -q '"address":"aAbqxogrjdy2YHVcnQxFHMzqpt2fhjCTVT"' \
 && k2a a22ddec5c567b4488bb00f69b6146c50da2ee883e2c096db098726394d585730 firo | "$B/redact" | grep -q '"address":"aAbqxogrjdy2YHVcnQxFHMzqpt2fhjCTVT"' \
 && k2a a22ddec5c567b4488bb00f69b6146c50da2ee883e2c096db098726394d585730 pivx | "$B/redact" | grep -q '"chain":"pivx"' \
 && echo "ok  twc-utxo: syscoin p2pkh+p2wpkh, firo p2pkh match TWC" || { echo "FAIL twc-utxo"; exit 1; }
