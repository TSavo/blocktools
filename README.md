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

Tools: `seed-repair`, `derive`, `keystore-open`, `kr-redact` (phase 1).
Dev: `cargo test --release && sh scripts/e2e-local.sh`.

Test vectors are public (BIP39 "abandon … about", Web3 Secret Storage spec).
Never commit real wallet data. `in/` and `secrets/` are git-ignored.
