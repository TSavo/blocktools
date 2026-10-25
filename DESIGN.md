# keyrescue: design

keyrescue is a set of small Unix command-line tools that recover keys from old
wallet files and sign transactions. The tools run inside a sealed, offline
container. It ships tools only: it is not an agent and not an MCP server.
It is a companion to [SwapChan](https://swapchan.com), which never holds keys.

## 1. Model: the tools print keys, the boundary filters them

Every tool is an ordinary Unix filter. It reads files or stdin, does one job,
and writes **JSON lines** to stdout. Tools print secrets (mnemonics, WIF,
private keys), because printing them is the job, for a human or the next tool in
the pipe. Tools do not police their own output.

The rule that **the agent never sees secrets** is enforced at one boundary:

```
host (agent)                         sealed container (--network none)
-----------                          ---------------------------------
./keyrescue run '<pipeline>'  --->   kr-run agent '<pipeline>'
                                       sh -c pipeline 2>/run/kr/stderr.log
                                         | tee /run/kr/raw.jsonl   (tmpfs, dies with container)
                                         | kr-redact               ---> stdout to the agent
./keyrescue reveal '<pipeline>' -->  kr-run human: needs a TTY + typed one-time code,
   (T at a terminal)                   writes raw output to /dev/tty only
```

* `kr-redact` is the only process whose stdout reaches the agent. It keeps only
  allowlisted fields, each with a strict validator (§3). A line that fails any
  check is dropped completely. It ends with a summary line (kept/dropped counts).
* Tool stderr goes to tmpfs, never to the agent.
* Leak tests target `kr-redact` and the end-to-end agent view
  (`crates/kr-schema` tests, `scripts/e2e-local.sh`), not the individual tools.

## 2. Threat model

| Threat | Mitigation |
|---|---|
| Agent (LLM) context leaks keys (logs, prompt injection, transcripts) | Agent only gets `kr-redact` output; allowlist + validators + leak scan |
| Hostile wallet files / filenames carrying instructions | Treated as data only; bounded reads; no eval/pickle/shell-outs in tools; filenames never interpreted |
| Hostile KDF params (CPU/memory DoS) | Bounded scrypt/PBKDF2 parameters; container memory/pids/CPU limits |
| Exfiltration over the network | `--network none`; no network tools in the image; no network code in tools |
| Container escape / privilege | non-root uid 10001, `--cap-drop ALL`, `no-new-privileges`, read-only rootfs, noexec tmpfs |
| Persistence of secrets on disk | Only tmpfs is writable; inputs mounted read-only; `--log-driver none` |
| Blind signing / tampered unsigned tx | `tx-verify` decodes inside the container; human confirms on the TTY (§6) |
| Password in agent context, argv or env | Passwords come only from a read-only file in `/secrets` or a `/dev/tty` prompt |
| Agent runs `reveal` | `reveal` needs a real TTY and a random code typed by the human; agent shells have no TTY |

Out of reach: a compromised Docker host (Battleaxe) or kernel, or a human who
pastes keys into chat.

## 3. Agent-facing schema (enforced by `kr-redact`)

One JSON object per line, at most 512 bytes. Allowlisted fields:

| field | validator |
|---|---|
| `tool` | enum of keyrescue tool names |
| `status` | enum: ok, checksum_ok, checksum_fail, no_candidates, too_many_candidates, bad_input, wrong_password, unsupported, error, done (**required**) |
| `kind` | enum: p2pkh, p2sh-p2wpkh, p2wpkh, p2tr, eth |
| `address` | base58 `1…`/`3…`, bech32/bech32m `bc1…`, or `0x` + 40 hex |
| `path` | `m(/N'?){0,8}` |
| `candidate`, `count`, `index`, `changed_words`, `line` | integer ≤ 1e9 |

Unknown fields are dropped. A listed field that fails its validator drops the
whole line. Then the serialized line is scanned and dropped if it contains a
64-hex run, `xprv/yprv/zprv/tprv…`, a WIF-shaped string, or 3+ consecutive
BIP39 words. Txids (64 hex) are blocked on purpose until phase 2 adds a typed
`txid` field.

## 4. Tools (one job each)

| tool | in | out (raw, may contain secrets) | phase |
|---|---|---|---|
| `seed-repair` | phrase file/stdin | `{status:checksum_ok, candidate, changed_words, mnemonic}` | 1 ✅ |
| `derive` | seed-repair lines or `--phrase-file`, `--passphrase-file` | `{kind, path, address, wif / private_key}` | 1 ✅ |
| `keystore-open` | Web3 v3 keystore JSON + `--password-file`/`--password-tty` | `{kind:eth, address, private_key}` | 1 ✅ |
| `kr-redact` | raw lines | public lines only | 1 ✅ |
| `walletdat-read` | Bitcoin Core `wallet.dat` (BDB/SQLite, bounded own parser, no libdb) | keys, addresses | 2 |
| `electrum-open`, `multibit-open`, `armory-open` | respective formats | keys, addresses | 2 |
| `utxo-match` | addresses + UTXO JSON file (from host) | matched address/amount | 2 |
| `tx-verify` | unsigned PSBT/tx file | plain summary: inputs, outputs, fee, change | 2 |
| `tx-sign` | PSBT + key stream + confirmation | signed raw tx hex | 2 |

Composition example (in the container): `seed-repair --in /in/seed.txt | derive --count 5`.

**seed-repair algorithm (phase 1):** lengths 12/15/18/21/24. Unknown words → words
within edit distance 2 or sharing the 4-letter prefix (BIP39 words are unique by
4 letters). Searches combinations, capped at 200k, and keeps the ones whose
BIP39 checksum is valid. If every word is known but the checksum fails, it tries
adjacent swaps, then each single-word substitution. Phase 2: missing word
positions and wordlists in other languages.

**derive paths:** m/44'/0'/0'/0/i, m/49'…, m/84'…, m/86'… (BIP86 taproot), and
m/44'/60'/0'/0/i (ETH, EIP-55). Phase 2: change chain, more accounts,
Electrum-seed derivation, custom paths.

## 5. Passwords and passphrases

Only two sources: a file in `$KR_SECRETS` (mounted read-only at `/secrets`, host
dir chmod 700, git-ignored), or a prompt to the human on `/dev/tty`. Never from
argv, env or stdin from the agent. Values are zeroized after use (`zeroize`).

## 6. Signing flow (phase 2, designed only)

1. Host: the agent uses SwapChan `find_money` to locate funds for the public
   addresses and `signing_guide` to build an **unsigned** PSBT. The agent writes
   the PSBT and UTXO JSON into `in/`.
2. Container: `tx-verify` decodes the PSBT itself, checks that the inputs match the
   UTXO file, and sums inputs, outputs, fee and change. Change must go back to an
   address we derived. It returns the public summary to the agent.
3. `keyrescue sign` (human mode, TTY required) prints a plain-language summary on
   the TTY ("Send 0.0123 BTC to bc1q…, fee 0.00002 BTC (5 sat/vB), change 0 → …"),
   plus a random code. The human types the code. The agent never sees or relays it.
4. `tx-sign` signs only the exact PSBT hash that was confirmed and writes the
   signed raw hex to stdout. The redactor passes it through as a typed
   `signed_tx` field (raw tx only, shape-checked).
5. Host: the agent runs SwapChan `verify_tx` on the hex, then `broadcast_tx`.

## 7. SwapChan integration (host side only)

The container never talks to SwapChan. Public data (addresses, unsigned
txs, signed hex) moves between the agent's SwapChan MCP tools and the container
as files in `in/` and lines from `kr-redact`.

## 8. Build and run

* `Dockerfile`: two stages pinned by digest (rust:1.85-alpine → alpine:3.20),
  static musl binaries, tests run during build, non-root user, network tools removed.
* `./keyrescue build | run '<pipeline>' | reveal '<pipeline>'`, plus `make recover`
  and `make reveal` for one-command use.

## 9. Out of scope

Brute-forcing unknown passwords at scale (GPU cracking), any network access in
the container, holding funds, custody, broadcasting from the container, hardware
wallets, and any key escrow or backup service.

## 10. Roadmap

* **Phase 1 (this commit):** seed-repair, derive (BIP44/49/84/86, ETH), keystore-open, kr-redact, sealed wrapper.
* **Phase 2:** wallet.dat reader, Electrum, MultiBit, Armory; utxo-match; tx-verify, tx-sign + TTY confirmation; typed `txid`/`signed_tx` fields.
* **Phase 3:** password-candidate lists from a human-provided file (bounded), missing-word repair, more chains.
