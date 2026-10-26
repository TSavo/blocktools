# Test fixtures

The repo holds **no wallet files**. `scripts/secret-scan.sh` rejects wallet-like files.

* **Self-made** wallets are generated at test time into a temp dir by
  `scripts/make-fixtures.py <dir>` (Python sqlite3 + hashlib + `cryptography`, independent of
  the Rust code). They contain only the BIP84 account key of the public BIP39 phrase
  `abandon ×11 about` (expects `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`) and a throwaway key
  `sha256("blocktools throwaway fixture key 1")` (expects `1McH57cuCXCq5hKooyJvQFG5XGL9fsbqHd`).
  Encrypted variant password: `blocktools-test-password`. If python3 + cryptography are missing,
  those tests print `skip` (set `BLOCKTOOLS_REQUIRE_FIXTURES=1` to make that a failure).
* **Third-party** public test wallets (btcrecover, GPL, password `btcr-test-password`) are
  downloaded and sha256-checked by `scripts/fetch-fixtures.sh` into the git-ignored
  `fixtures/external/`; tests skip them when absent. Blockchain.com e2e builds its own v3 wrapper in-process (openssl); BIP38 uses public BIP ciphertext strings.

## Git history note
Commit 360a78e (and its parent state) still contains the earlier committed
self-made wallet fixtures. They are throwaway files generated from public test
phrases and passwords and never held value. By decision we do **not** rewrite
history or force-push; they were removed from the tree in 5061f16 and are now
generated at test time.

## Parity corpora

The JSON corpora under `crates/blocktools/tests/data/` that come from Node reference scripts in
`tools/*-parity` and `tools/sol-v1` are described in [PARITY-GENERATORS.md](PARITY-GENERATORS.md).
