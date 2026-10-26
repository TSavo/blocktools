# Chain spec files (`blocktools-chain-spec/1`)

A chain spec is a small JSON file that describes one UTXO chain blocktools does not have in its
table. Pass it with `--chain-spec FILE`, or set `BLOCKTOOLS_CHAIN_SPEC=FILE`. The row exists only
in that process. Nothing is written or cached, and the file is re-read and re-hashed on every run.

The row is always **unverified**. Every plain summary and the tx-sign confirmation screen print
`!! unverified chain spec: NAME (sha256 …)`. JSON output from tx-build, tx-verify and tx-decode
carries `"chain_spec":"unverified chain spec"`, and tx-build/tx-verify also carry the file's sha256.

These tools read it: tx-build, tx-verify, tx-sign, tx-decode, key-to-addresses, derive,
classify (address detection), chain-table and xpub-addresses. chain-learn writes the same format.

```json
{"format":"blocktools-chain-spec/1","name":"bcs","ticker":"BCC","p2pkh":18,"p2sh":85,"wif":146,
 "checksum":"sha256d","sign":"postime","decimals":8,"allow_collision":true,
 "evidence":{"p2pkh":"bitconnectcoin@3ab3d19 src/base58.h:279"}}
```

| field | required | meaning |
|---|---|---|
| format | yes | `blocktools-chain-spec/1` |
| name | yes | lowercase `[a-z0-9]{2,8}`; must not equal a built-in chain name (always refused) |
| checksum | yes | `sha256d` only in v1 |
| ticker, title | no | display only |
| p2pkh, p2sh, wif | no | version bytes 0-255 |
| hrp | no | bech32 prefix; `null` means the chain has no segwit |
| slip44 | no | BIP44 coin type for derive paths |
| sign | no | `standard` (Bitcoin sighash) is the only kind tx-build/tx-sign accept in v1 |
| decimals | no | must be 8 to build or sign |
| allow_collision | no | `true` lets p2pkh/p2sh/hrp equal a built-in chain's bytes |
| evidence | no | free-text map, field -> where the value came from |

A field you leave out stays **unknown**. blocktools never guesses it. Each tool refuses only the
step that needs that field, with a stable code:

| missing | refused step | code |
|---|---|---|
| p2pkh | addresses (key-to-addresses, derive), tx-build, tx-sign | `spec_missing_p2pkh` |
| p2sh | p2sh rows are not printed; p2sh scripts are not encoded | `spec_missing_p2sh` |
| wif | key-to-addresses prints `"missing":"spec_missing_wif"` in place of the WIF; tx-sign refuses | `spec_missing_wif` |
| decimals | tx-build, tx-sign | `spec_missing_decimals` |
| sign other than standard | tx-build, tx-sign (addresses still work) | `spec_unsupported_sign` |

The file is refused as a whole (`bad_input`, exit 2, before any input is read) for these reasons:
- `spec_malformed`: not strict JSON
- `spec_bad_format`
- `spec_unknown_field`
- `spec_duplicate_field`
- `spec_bad_name`
- `spec_bad_value`
- `spec_missing_name`
- `spec_missing_checksum`
- `spec_unsupported_checksum`
- `spec_name_collision`
- `spec_byte_collision`: lists `collides_with`
- `spec_contains_secret`: any value that looks like a WIF or 64-hex key. A spec holds no secrets.
- `spec_too_large`
- `spec_unreadable`

A spec cannot weaken any check. It gets the default UTXO fee cap (100,000 base units floor, with
no per-chain rate) and the same verifier rules as a built-in row. A spec cannot shadow a built-in
name.

Measured (Linux only, `scripts/e2e.d/chain-spec.sh`, offline, throwaway keys):
- ftc and ltc described as spec chains `ftx`/`ltx` give byte-identical key-to-addresses and derive
  output, PSBT and signed transaction to the built-in rows. Only the chain name and the spec
  markers differ.
- The bcc spec gives the same addresses as the built-in unverified bcc row, and classify detects
  them. tx-build refuses with `spec_unsupported_sign`.
- The missing-field refusals and the negatives above each run once per tool.
