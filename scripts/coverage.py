#!/usr/bin/env python3
"""Verb x chain coverage matrix, measured from the release binaries (issue #11: one verb per tool, chain as a parameter).

Each ROW names a tool, a verb and how its chains are measured:
  probe  - run the tool with `--chain C` on a dummy input for every chain in CHAINS; the chain counts as covered unless
           the tool rejects it as an unknown/unsupported chain (REJECT). The probe must also reject --chain bogus, or the
           row is a FAIL (a probe that cannot tell "unsupported" from "bad input" measures nothing).
  help   - the chains are the `a|b|c` list after --chain in the tool's --help.
  fixed  - a single-chain tool; the verb word must appear in its --help.
Every row's verb word must appear in the tool's --help, and every built tool binary must be in ROWS or NO_TX_VERB.
Gate (rule:D-coverage): a (verb, chain) cell served by more than one tool must be listed in docs/COVERAGE.md's
"Listed overlaps" section, with a reason; and the matrix between the coverage markers must equal this script's output.
  python3 scripts/coverage.py           rewrite the matrix in docs/COVERAGE.md
  python3 scripts/coverage.py --check   fail on a stale matrix, an unlisted overlap, a stale listing or a broken probe
"""
import os, re, subprocess, sys
B = os.environ.get("BIN", "target/release")
DOC = "docs/COVERAGE.md"
CHAINS = "btc ltc doge bch zec eth sol tron xrp xlm algo atom ton ada dot xmr".split()
REJECT = re.compile(r"unknown_chain|unknown chain|unsupported --chain|unsupported_family|usage: ")
ENV = lambda op: ["tx-envelope", "--json", '{"op":"%s","chain":"{c}","tx":"00"}' % op]
ROWS = [  # (tool, verb, mode, argv-template-or-chains)
    ("tx-decode", "decode", "probe", ["tx-decode", "--chain", "{c}"]),
    ("acct-tx", "decode", "probe", ["acct-tx", "decode", "--chain", "{c}"]),
    ("sol-tron-tx", "decode", "probe", ["sol-tron-tx", "decode", "--chain", "{c}"]),
    ("xrp-tx", "decode", "fixed", ["xrp"]),
    ("tx-envelope", "decode", "probe", ENV("decode")),
    ("tx-verify", "verify", "fixed", ["btc", "ltc", "doge", "bch", "zec", "eth"]),
    ("sol-tron-tx", "verify", "probe", ["sol-tron-tx", "verify", "--chain", "{c}"]),
    ("tx-envelope", "verify", "probe", ENV("verify")),
    ("tx-build", "build", "probe", ["tx-build", "--chain", "{c}"]),
    ("acct-tx", "build", "probe", ["acct-tx", "build", "--chain", "{c}"]),
    ("sol-tron-tx", "build", "probe", ["sol-tron-tx", "build", "--chain", "{c}"]),
    ("xrp-tx", "build", "fixed", ["xrp"]),
    ("tx-sign", "sign", "fixed", ["btc", "ltc", "doge", "bch", "zec", "eth"]),
    ("acct-tx", "sign", "fixed", ["xlm", "algo", "atom", "ton", "ada", "dot"]),
    ("xrp-tx", "sign", "fixed", ["xrp"]),
    ("tx-broadcast", "broadcast", "help", None),
    ("xmr-wallet", "sweep", "fixed", ["xmr"]),
    ("acct-tx", "keys", "probe", ["acct-tx", "keys", "--chain", "{c}"]),
    ("xrp-tx", "keys", "fixed", ["xrp"]),
    ("xmr-keys", "keys", "fixed", ["xmr"]),
    ("zec-sapling", "keys", "fixed", ["zec"]),
]
NO_TX_VERB = set("""abi-decode abi-encode abi-inspect armory-read bip38-open blockchain-read build-parity bytecode-inspect chain-table
chainstate-dump classify contract-call contract-trace create-address dat-read derive electrum-read key-to-addresses keystore-open
log-decode msg-sign msg-verify multibit-read new-seed phrase-to-key psbt-parity pw-candidates read-file redact rpc sealed-run seed-repair
seed-to-master sig-hash signum-account tx-plan twc-vectors typed-data-verify utxo-fetch utxo-set verifier-parity wallet-finder xpub-addresses""".split())
# tx-plan is a declarative skin over blocktools-plan: every chain it resolves/checks is already a cell served by
# the family's own tool (tx-build/tx-verify/acct-tx/...); it encodes no chain of its own, so it adds no matrix cell.
# A probe on dummy bytes cannot tell these apart: the UTXO decoder takes any name in the chains table (which has xmr,
# for addresses) and fails on the bytes, not the chain. Measured: `tx-decode --chain xmr` parses UTXO bytes; it is
# not a Monero decoder. Listed in docs/COVERAGE.md "Findings".
NOT_PROBED = {"tx-decode": ("xmr",)}
errs = []
def run(argv):
    try:
        p = subprocess.run([os.path.join(B, argv[0])] + argv[1:], input=b"00\n", capture_output=True, timeout=10, stdin=None)
    except subprocess.TimeoutExpired:
        return "timeout"
    return (p.stdout + p.stderr).decode("utf-8", "replace")
helps = {}
def help_of(t):
    if t not in helps: helps[t] = run([t, "--help"])
    return helps[t]
for inj in os.environ.get("COVERAGE_INJECT", "").split():  # test hook: TOOL:VERB:CHAIN adds a fixed row
    t, v, c = inj.split(":"); ROWS.append((t, v, "fixed", [c]))
cells = {}
for tool, verb, mode, arg in ROWS:
    if not re.search(r"\b%s\b" % re.escape(verb), help_of(tool)): errs.append(f"{tool} --help does not mention verb '{verb}'")
    if mode == "fixed": got = list(arg)
    elif mode == "help":
        m = re.search(r"--chain ([a-z]+(?:\|[a-z]+)+)", help_of(tool)); got = m.group(1).split("|") if m else []
        if not got: errs.append(f"{tool}: no --chain a|b list in --help")
    else:
        if not REJECT.search(run([x.replace("{c}", "bogus") for x in arg])): errs.append(f"{tool} {verb}: probe does not reject --chain bogus")
        got = [c for c in CHAINS if c not in NOT_PROBED.get(tool, ()) and not REJECT.search(run([x.replace("{c}", c) for x in arg]))]
    for c in got:
        if c not in CHAINS: errs.append(f"{tool} {verb}: chain {c} is not a matrix column"); continue
        cells.setdefault((verb, c), []).append(tool)
built = {f for f in os.listdir(B) if os.path.isfile(os.path.join(B, f)) and os.access(os.path.join(B, f), os.X_OK) and os.path.isdir(f"tools/{f}")}
for t in sorted(built - NO_TX_VERB - {r[0] for r in ROWS}): errs.append(f"tool {t} is in neither ROWS nor NO_TX_VERB (scripts/coverage.py)")
verbs = list(dict.fromkeys(r[1] for r in ROWS))
lines = ["| verb | " + " | ".join(CHAINS) + " |", "|---|" + "---|" * len(CHAINS)]
for v in verbs:
    row = []
    for c in CHAINS:
        ts = cells.get((v, c), [])
        row.append("<br>".join(ts) + (" **(2+)**" if len(ts) > 1 else "") if ts else "-")
    lines.append(f"| {v} | " + " | ".join(row) + " |")
table = "\n".join(lines)
doc = open(DOC).read()
m = re.search(r"(<!-- coverage:begin -->\n)(.*?)(\n<!-- coverage:end -->)", doc, re.S)
if not m: sys.exit(f"FAIL coverage: markers missing in {DOC}")
listed = {}
sec = doc.split("## Listed overlaps", 1)[1] if "## Listed overlaps" in doc else ""
for v, cs, ts, why in re.findall(r"^- `([a-z]+)/([a-z,]+)`: ([a-z0-9, -]+?) - (.+)$", sec, re.M):
    for c in cs.split(","): listed[(v, c)] = (sorted(x.strip() for x in ts.split(",")), why)
for k, ts in sorted(cells.items()):
    if len(ts) > 1:
        if k not in listed: errs.append(f"unlisted overlap: {k[0]}/{k[1]} is served by {', '.join(ts)}; list it under 'Listed overlaps' in {DOC} with a reason, or remove one")
        elif listed[k][0] != sorted(ts): errs.append(f"stale listing: {k[0]}/{k[1]} lists {', '.join(listed[k][0])} but measured {', '.join(sorted(ts))}")
for k in listed:
    if len(cells.get(k, [])) < 2: errs.append(f"stale listing: {k[0]}/{k[1]} is listed as an overlap but is served by {len(cells.get(k, []))} tool(s)")
if "--check" in sys.argv:
    if m.group(2) != table: errs.append(f"{DOC} matrix is stale: run python3 scripts/coverage.py")
    for e in errs: print("FAIL coverage:", e)
    if errs: sys.exit(1)
    print(f"coverage ok: {len(ROWS)} tool verbs, {len(cells)} cells, {sum(len(t) > 1 for t in cells.values())} listed overlaps")
else:
    open(DOC, "w").write(doc[:m.start(2)] + table + doc[m.end(2):])
    for e in errs: print("FAIL coverage:", e)
    print(table)
