# Exit codes (D1-14)

Each tool prints one JSON status line. Its exit code comes from that status
through `blocktools_io::exit_code`:

| exit | status |
|---|---|
| 0 | `ok`, `done`, `checksum_ok` |
| 2 | `bad_input`, `unsupported` |
| 1 | anything else, including `error` and every refusal |

A tool that exits nonzero without printing a status counts as a bug.

Exception: shell recipes (`*.sh`, such as `recover.sh`) are not tools. `recover.sh`
exits 3 when the search finishes with no match. The rule does not check recipes.

Enforced by `scripts/gen-man.py --check` (`# rule:X-exit`): it runs every example in
`scripts/man-examples.txt` and fails if a tool's exit code differs from the rule for
its printed status. The negative test `X-exit` in gate-negatives plants a
mismatching example. Measured on Linux only.
