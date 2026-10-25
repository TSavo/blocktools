# Test fixtures

The repo holds **no wallet files**. `scripts/secret-scan.sh` rejects wallet-like files.

* **Self-made** wallets are generated at test time into a temp dir by
  `scripts/make-fixtures.py <dir>` (Python sqlite3 + hashlib + `cryptography`, independent of
  the Rust code). They contain only the BIP84 account key of the public BIP39 phrase
  `abandon ×11 about` (expects `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`) and a throwaway key
  `sha256("keyrescue throwaway fixture key 1")` (expects `13M3vwLduvWviNdwLqrsLYBf6KLNq1cyYM`).
  Encrypted variant password: `keyrescue-test-password`. If python3 + cryptography are missing,
  those tests print `skip` (set `KR_REQUIRE_FIXTURES=1` to make that a failure).
* **Third-party** public test wallets (btcrecover, GPL, password `btcr-test-password`) are
  downloaded and sha256-checked by `scripts/fetch-fixtures.sh` into the git-ignored
  `fixtures/external/`; tests skip them when absent.
