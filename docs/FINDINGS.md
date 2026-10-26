# Review findings ledger

Every finding from T's reviews has a permanent id. A finding marked `fixed` must name the commit that
fixed it and a guard: a test file containing the token `finding:<id>`, which runs in scripts/gate.sh.
`scripts/findings-check.sh` (run by docs-check) parses the table below. It fails if a fixed finding has no
guard, if the guard file is missing or does not carry the token, if the commit is not an ancestor of HEAD,
or if a row has an unknown status. `open` rows are still unfixed and have no guard yet. They are listed so
they can't be forgotten, and the check prints them on every run.

| id | finding | status | fixed in | guard |
|----|---------|--------|----------|-------|
| R1-1 | Envelope/C ABI/wasm paths had no default fee cap (could sign a 9.99 ETH fee) | fixed | 4949027 | crates/blocktools/tests/fee_cap_paths.rs |
| R1-2 | seed-repair accepts an unknown --scheme silently | open | - | - |
| R1-3 | classify CLASSES list misses bip38 and blockchain_wallet; no test ties it to emitted kinds | open | - | - |
| R1-4 | sha-1 crate (deprecated name) instead of sha1 | open | - | - |
| R1-5 | println! in tool bins (10 tools); no hygiene rule against it | open | - | - |
| R1-6 | recipes.sh errors instead of skipping when python `cryptography` is missing | open | - | - |
| R1-7 | Image size in docs not tied to a revision label | open | - | - |
| R1-8 | Mac e2e tx-sign pin-tty step fails (rc=2 near tx-sign.sh:35) | open | - | - |
| R2-1 | Sealed image build broken (check-deps needs python3 in builder); README size unmeasured | fixed | 26b3373 | scripts/check-deps-regress.sh |
| R2-2 | CI red: non-ASCII emoji in man pages under groff LC_ALL=C | fixed | a22023f | scripts/gate-negatives.sh |
| R2-3 | hygiene BSD-skew rules used \s, inert on macOS git grep | fixed | 8160aeb | scripts/hygiene-check.sh |
| R2-5 | check-deps: pipe masked cargo exit 101 (stale lock) | fixed | bb1ceff | scripts/check-deps-regress.sh |
| R2-6 | release.yml can publish without required reviewers on the release environment | open | - | - |
| R2-7 | Readers (bip38-open, blockchain-read, pw-candidates, tx-envelope, chain-table) "unsupported" under sealed-run | open | - | - |
| R2-8 | Doc numbers not tied to a measuring command (claims registry) | fixed | 997c606 | scripts/gate-negatives.sh |
| R2-9 | Gates grep for words instead of testing the property | fixed | 76c9850 | scripts/gate-negatives.sh |
| R2-10 | CI and local verify-and-push ran different step lists | fixed | 94449bd | scripts/ci-gate-check.sh |
| R2-11 | No macOS CI coverage, so Mac failures surface only in manual reruns | open | - | - |
| R2-12 | CI checkout was shallow (fetch-depth 1), so findings-check misreported real commits as missing | fixed | 14700aa | scripts/gate-negatives.sh |
