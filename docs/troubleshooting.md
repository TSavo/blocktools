# Troubleshooting / FAQ

Every status and failure code, with its cause, what to do and a run example: [REFUSALS.md](REFUSALS.md).

## `bad_input` / exit 2

The tool could not parse stdin or flags. Check: JSONL shape from the previous stage,
chain id spelling (`btc` not `BTC`), and that secrets are on stdin not argv.
`--help` shows the public flag surface; man pages list INPUT/OUTPUT.

## Exit 3 (refused)

Watch-only input, policy deny, wrong TTY confirmation code, or a deliberate stop
(e.g. recover.sh on an address-only file). Nothing was signed. Read the last JSON
`status` line.

## `sealed-run` / `./blocktools run` refuses a tool

Host-only network tools (`utxo-fetch`, `tx-broadcast`, `xmr-wallet`) are not in the
sealed image. Run them on the host after redacted public data leaves the container.
Shell metacharacters are rejected; use the sealed pipeline grammar only.

## Man page missing after DEB install in Docker

Debian slim images often `path-exclude` `/usr/share/man`. Remove that dpkg config
(or use a full image) before `dpkg -i`. Packages themselves include the pages.

## Alpine: binary "not found"

The v0.1.0 tarball binaries are glibc-linked (GLIBC_2.39 or newer) and do not run on musl
(Alpine) or on older glibc. There is no musl release asset; build from source
(`cargo build --locked --release --target x86_64-unknown-linux-musl`) or use the APK dry-run
packaging (scripts/package-native.sh).

## Wasm: "cannot sign" / missing export

The wasm package is **secrets-off** by design. No seed→master, no WIF, no PSBT sign.
Use validate / xpub / decode / verify / builders that take public data only ([EXPORTS.md](../EXPORTS.md)).

## Chain not in `supportedChains`

Unverified rows (e.g. wdc, anc) never appear as supported. Transparent ZEC is supported
for validate/sweep; shielded Sapling is address/viewkey only. See [CHAINS.md](CHAINS.md).

## Still stuck

Re-run `scripts/docs-check.sh` and `cargo test -p blocktools --test coins table_params_no_drift`.
Open an issue with the JSON `status` line (never paste seeds or keys).
