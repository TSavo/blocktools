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

Tools: `seed-repair`, `derive`, `keystore-open`, `kr-redact` (phase 1).
Tools read stdin and write stdout only (see DESIGN.md "Pipe principles").
Dev: `cargo test --release && sh scripts/e2e-local.sh`.

Test vectors are public (BIP39 "abandon … about", Web3 Secret Storage spec).
Never commit real wallet data. `in/` and `secrets/` are git-ignored.
