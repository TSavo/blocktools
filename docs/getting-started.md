# Getting started

**DANGEROUS with real funds.** Read [SECURITY.md](SECURITY.md). Practice on public
fixtures and mock chains before any mainnet key.

## Install

Pick one:

1. **From source (dev):** `cargo build --locked --release --workspace`. Binaries land in `target/release/`. Use the wrapper `./blocktools` (Docker sealed image) for secret-touching pipelines.
2. **Release tarball:** GitHub Actions `release` workflow (tag `v*` publishes; `workflow_dispatch` uploads artifacts only). Unpack; bins under `bin/`, man pages under `share/man/`.
3. **DEB / RPM / APK (dry-run packaging):** see `scripts/package-dist.sh` and `scripts/package-native.sh`. Install-tested in debian/fedora/alpine containers; man pages under `/usr/share/man`.

Man pages: `man derive`, `man blocktools` (section 7 overview), `man recover.sh`.

## Security model in plain words

- **Secrets stay offline.** Anything that reads a seed, keystore, or wallet file runs inside `./blocktools run` (sealed container, no network, redacted stdout).
- **Flags are public.** Passwords and mnemonics never go on argv; use stdin JSON or `read-file` with files under `./secrets`.
- **Humans confirm spend.** `tx-sign` and broadcast ask for a one-time code on a real terminal. Wrong code → nothing signed.
- **Policy can refuse.** Optional policy files ([POLICY.md](POLICY.md)) cap fees and destinations before signing.
- **Unverified chains stay unlabeled as supported.** [CHAINS.md](CHAINS.md) lists verified vs unverified rows.

## First recovery (end to end, sample data)

Public fixtures live under the repo's test vectors / `scripts/fetch-fixtures.sh` outputs. Example shape (BIP39 → addresses), sealed:

```sh
# Put a public test mnemonic in ./in/seed.txt (never a real phrase on a networked machine).
mkdir -p in
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' > in/seed.txt

./blocktools run 'classify < /in/seed.txt'
./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc --count 1'
```

Front door for an unknown file:

```sh
recipes/recover.sh ./in/seed.txt - --goal addresses
```

Sweep against a **mock** chain is covered by e2e (`scripts/e2e-local.sh`); do not point `--url` at mainnet until you have read SECURITY.md and verified the destination on screen.

## Next

- Cookbook by wallet / chain: [cookbook.md](cookbook.md) → [recipes/README.md](../recipes/README.md)
- Stuck? [troubleshooting.md](troubleshooting.md)
- Library / wasm: [library-api.md](library-api.md), [../bindings/wasm/README.md](../bindings/wasm/README.md)
