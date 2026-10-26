# Library API guide (Rust)

Crate: `blocktools` (facade). Default features are **public-data only** — no private
keys, no filesystem wallet openers, no sockets.

```toml
blocktools = { version = "0.1.0", path = "..." }  # or crates.io when published
# Optional: features = ["secrets", "ed25519", "schema", "net"]
```

## Build docs locally

```sh
RUSTDOCFLAGS='-D warnings' cargo doc -p blocktools --no-deps --open
```

CI denies rustdoc warnings on this crate. Prefer rustdoc on each public item over
duplicating signatures here.

## Surface (default features)

| Area | Module / re-export | Notes |
|---|---|---|
| Version | `VERSION` | Same as package version |
| Chains | `chains`, `address::{validate,detect,convert,params}` | Unverified chains error closed |
| Watch-only | `xpub`, `plan` | No xprv in default build |
| Transactions | `tx::{build,policy,...}` | Sign behind `secrets` |
| Wasm parity helpers | `cashaddr`, `sol`, `substrate`, `verifier`, `psbtmemo`, `tron`, `build` | See EXPORTS.md |

Enable `secrets` only in sealed/offline binaries. Dependents like SwapChan should stay
on default features (DESIGN §11).

## CLIs vs library

`tools/*/src/main.rs` is argv + stdin + one library call + JSONL out. Prefer calling
the library from Rust tests; use CLIs for human/agent pipelines.
