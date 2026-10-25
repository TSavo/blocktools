# keyrescue

Sealed, offline key recovery and safe signing for old wallet files.

Small Unix tools (Rust, static musl) run in a `--network none` container.
Tools print keys. The agent-facing wrapper returns only addresses,
derivation paths and statuses. See [DESIGN.md](DESIGN.md).

```sh
./keyrescue build                 # on a Docker host
echo "your phrase" > in/seed.txt  # or copy wallet files into in/
make recover                      # agent-safe: addresses + paths only
make reveal                       # human at a terminal: shows keys after typed code
```

Status: image built and sealed run verified on Battleaxe (18.2 MB; network off, read-only rootfs, no leaks in agent output). `./keyrescue reveal` and phase-2 tools are not yet tested. See DESIGN.md "Verified status".

Tools: `seed-repair`, `seed-to-master`, `derive`, `keystore-open`, `kr-redact`, `kr-run`, `kr-cat`, `dat-read`.

### Bitcoin Core wallet.dat

`dat-read` reads legacy (Berkeley DB) and descriptor (SQLite) `wallet.dat` with its own
bounded parsers (no libdb, no libsqlite). stdin = password line (empty if unencrypted),
then the wallet bytes. Every decrypted key is checked against its stored public key.

```sh
# human, at a terminal, in the sealed container:
{ cat pw.txt; cat wallet.dat; } | kr-run agent 'dat-read | derive --count 20'
```

Tested: 3 public Core test wallets (BDB 0.x, 0.20.1 HD, 0.21.1 SQLite) when fetched with
`scripts/fetch-fixtures.sh`, and committed self-made wallets that must reproduce a known
BIP84 address. Statuses: `ok`, `wrong_password`, `unsupported`, `bad_input`.
Tools read stdin and write stdout only (see DESIGN.md "Pipe principles").
Dev: `cargo test --release && sh scripts/e2e-local.sh`.

Test vectors are public (BIP39 "abandon … about", Web3 Secret Storage spec).
Never commit real wallet data. `in/` and `secrets/` are git-ignored.
