# blocktools documentation

Start with **[getting started](getting-started.md)**. Everything below is checked by `scripts/gate.sh`
(docs-check, claims-check, findings-check, the man check and the e2e runners) unless a page says otherwise.
Measured results are Linux-only unless labelled.

## Use it
- [Getting started](getting-started.md): install, first sealed run.
- [Parity generators](PARITY-GENERATORS.md): the Node oracles behind the parity test corpora.
- [Cookbook](cookbook.md): by wallet type and chain. Also see [recipes/README.md](../recipes/README.md), which covers inputs, goals and chains.
- [Paths](PATHS.md): eight end-to-end routes (RPC in, tools piped, RPC out). Each one is run in the gate against
  saved RPC responses and a local mock chain.
- [Refusals and status codes](REFUSALS.md): every status and failure code, what causes it and what to do.
  Every example on that page is run.
- [Troubleshooting / FAQ](troubleshooting.md)
- Man pages: `man -l man/man1/<tool>.1`, overview `man -l man/man7/blocktools.7`. Every man page
  example is run by `scripts/gen-man.py --check`.
- [Offline policy file](POLICY.md) for tx-verify / tx-sign.
- [Supported chains](CHAINS.md), [chain spec files](CHAIN-SPEC.md), [adding a chain](ADDING-A-CHAIN.md).

## Trust it
- [Security](SECURITY.md): threat model, sealed runs, what is and is not protected.
- [Claims](CLAIMS.md): every number and security claim, the command that measured it, and where it was measured
  (generated from [claims.toml](claims.toml)).
- [Findings](FINDINGS.md): review findings, open and fixed, with guards.
- [Fixtures](FIXTURES.md): where the test data comes from.
- [CI](CI.md): runners.

## Build on it
- [Library API (Rust)](library-api.md), [wasm export reference](EXPORTS-reference.md) (generated),
  [wasm/TS bindings](../bindings/wasm/README.md).

## Plans (not implemented unless marked)
- [Roadmap](ROADMAP.md), [parity roadmap](ROADMAP-PARITY.md), [Monero sweep design](monero-sweep-design.md),
  [prior art](prior-art-crypto-plugins.md), [docs readiness audit](DOCS-READINESS.md).
