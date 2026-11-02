# siwe test vectors: provenance

All vectors are public test data from spruceid/siwe (MIT / Apache-2.0), commit
911f6f2c73ef24deac73fec2f6b84930721d2fb4, directory `test/`, copied unchanged to `tools/siwe/tests/data/`:

| file | count | used for |
|---|---|---|
| parsing_positive.json | 19 | parse gives the published fields; build from the fields gives the published text byte for byte |
| parsing_negative.json | 29 | every message refused by parse |
| parsing_negative_objects.json | 18 | every field set refused by build |
| message_objects.json | 13 | build accepts exactly the cases spruce marks `error: none` |
| valid_specification.json | 9 | statement, request ID and resources parsed as published |
| valid_uris.json / invalid_uris.json | 36 / 17 | URI grammar (RFC 3986) accepted / refused (`bad_uri`) |
| verification_positive.json / verification_negative.json | 4 / 10 | text built from the fields verifies (or not) with `msg-verify --chain eth` against spruce's published `personal_sign` signature, with spruce's `time` / `domainBinding` / `matchNonce` as `--now` / `--domain` / `--nonce` |

`recipes/fixtures/siwe/example-message.json` is the "example message" entry of verification_positive.json
without its signature. Run: `cargo test -p siwe` and `sh scripts/e2e.d/siwe.sh` (claim siwe-e2e (untested), not yet stamped).

UNTESTED: messages from real wallets and dapps other than these vectors; spruce's `valid_chars` /
`invalid_chars` files are not wired in. No wasm export.
