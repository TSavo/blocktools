# blocktools

> **⚠️ DANGEROUS: use at your own risk.** Code that handles keys and signs transactions
> should always be read and audited by you before you trust it with real funds.
> **Used incorrectly, it can destroy your money**: signing to a wrong address, paying a
> huge fee, losing keys, or sending on the wrong chain. You are responsible for verifying
> every transaction. It opens hostile wallet files and extracts secrets, so run it only
> sealed and offline (`./blocktools run`, `--network none`). The unit tests are evidence,
> not a substitute for your own review. See [docs/SECURITY.md](docs/SECURITY.md).


Sealed, offline key recovery and safe signing for old wallet files.

Small Unix tools (Rust, static musl) run in a `--network none` container.
Tools print keys. The agent-facing wrapper returns only addresses,
derivation paths and statuses. See [DESIGN.md](DESIGN.md).

```sh
./blocktools build                 # on a Docker host
echo "your phrase" > in/seed.txt  # or copy wallet files into in/
make recover                      # agent-safe: addresses + paths only
make reveal                       # human at a terminal: shows keys after typed code
```

Status: image built and sealed run verified on Battleaxe (18.2 MB; network off, read-only rootfs, no leaks in agent output). Phase-2 tools (tx-build, tx-verify, tx-sign, tx-broadcast, account and XRP signers) are covered by unit/KAT tests and `scripts/e2e-local.sh`; `sealed-run human` (what `reveal` runs inside the container) is driven through a pty in e2e. Not yet tested: `./blocktools reveal` itself under Docker on a real terminal. See DESIGN.md "Verified status".

Tools: `seed-repair`, `seed-to-master`, `derive`, `keystore-open`, `redact`, `sealed-run`, `read-file`, `dat-read`.

Manual pages for every tool, `recover.sh` and the wrapper are in `man/` (`man -l man/man7/blocktools.7`).
They are generated from `--help` and the doc headers by `scripts/gen-man.py`, and CI fails if they are stale.
Offline policy files for tx-verify and tx-sign are described in [docs/POLICY.md](docs/POLICY.md).

Docs: [getting started](docs/getting-started.md) · [cookbook](docs/cookbook.md) · [troubleshooting](docs/troubleshooting.md) · [library API](docs/library-api.md) · [wasm/TS](bindings/wasm/README.md) · [docs readiness](docs/DOCS-READINESS.md).

### Bitcoin Core wallet.dat

`dat-read` reads legacy (Berkeley DB) and descriptor (SQLite) `wallet.dat` with its own
bounded parsers (no libdb, no libsqlite). stdin = password line (empty if unencrypted),
then the wallet bytes. Every decrypted key is checked against its stored public key.

```sh
# human, at a terminal, in the sealed container:
{ cat pw.txt; cat wallet.dat; } | sealed-run agent 'dat-read | derive --count 20'
```

Tested: 3 public Core test wallets (BDB 0.x, 0.20.1 HD, 0.21.1 SQLite) when fetched with
`scripts/fetch-fixtures.sh`, and self-made (generated at test time) wallets that must reproduce a known
BIP84 address. Statuses: `ok`, `wrong_password`, `unsupported`, `bad_input`.
Tools read stdin and write stdout only (see DESIGN.md "Pipe principles").
Dev: `cargo test --release && sh scripts/e2e-local.sh`.

Test vectors are public (BIP39 "abandon … about", Web3 Secret Storage spec).
Never commit real wallet data. `in/` and `secrets/` are git-ignored.
