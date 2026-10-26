#!/usr/bin/env python3
"""doc-run.py DOC: execute every block in DOC preceded by `<!-- run rc=N expect=a,b -->` and check
exit code and that each expected code appears in the output. Then check coverage: every refusal
code the tools can emit (schema TX_FAILURES + STATUSES + every f.push("...") in crates/) has a
"### `code`" heading in DOC. Fixtures are built here from public test values; nothing touches a network
except 127.0.0.1:9 (closed port)."""
import os, re, subprocess, sys, tempfile, pathlib
root = pathlib.Path(__file__).resolve().parents[2]; doc = root / sys.argv[1]; text = doc.read_text()
fx = tempfile.mkdtemp(prefix="refusals."); B = pathlib.Path(os.environ.get("BIN", root / "target/release")).resolve()
env = dict(os.environ, PATH=f"{B}:{os.environ['PATH']}", FX=fx,
           BTC_TO="bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
           EVM_TO="0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF")
def sh(c, **k): return subprocess.run(["sh", "-eu", "-c", c], env=env, cwd=fx, capture_output=True, text=True, start_new_session=True, **k)
gen = root / "scripts/e2e-only/evm-fixture.py"
setup = f"""
txid=$(printf 'c%.0s' $(seq 64))
printf '{{"address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","amount":50000,"txid":"%s","vout":0}}\\n' $txid > utxos.jsonl
tx-build --chain btc --utxos utxos.jsonl --to "$BTC_TO" --sweep --fee-rate 5 > btc.psbt
python3 {root}/scripts/e2e-only/psbt-unsigned.py < btc.psbt > btc-raw.hex
for k in transfer legacy-no-chain-id approve unknown-call value-and-token; do python3 {gen} $k > evm-$k.hex; done
printf '%064x\\n' 2 > key2
"""
r = sh(setup)
if r.returncode: sys.exit(f"FAIL fixture setup: {r.stderr}")
bad = n = 0
for m in re.finditer(r"<!-- run rc=(\d+) expect=([\w,]*) -->\s*```sh\n(.*?)```", text, re.S):
    rc, exp, cmd = int(m[1]), [e for e in m[2].split(",") if e], m[3]; n += 1
    r = sh(cmd, timeout=60); out = r.stdout + r.stderr
    miss = [e for e in exp if f'"{e}"' not in out]
    if r.returncode != rc or miss:
        bad += 1; print(f"FAIL refusals: `{cmd.strip()}` rc={r.returncode} (want {rc}) missing={miss}\n{out}")
src = (root / "crates/schema/src/lib.rs").read_text()
codes = set()
for name in ("STATUSES", "TX_FAILURES"):
    blk = re.search(name + r"[^=]*=\s*&?\[(.*?)\]", src, re.S); codes |= set(re.findall(r'"(\w+)"', blk[1]))
for p in (root / "crates").rglob("*.rs"):
    codes |= set(re.findall(r'f\.push\("(\w+)"\)', p.read_text()))
heads = set(re.findall(r"^### `(\w+)`", text, re.M))
for c in sorted(codes - heads): bad += 1; print(f"FAIL refusals: code `{c}` has no section in {sys.argv[1]}")
print(f"refusals: {n} blocks run, {len(codes)} codes covered, {bad} failures")
import shutil; shutil.rmtree(fx, ignore_errors=True)
sys.exit(1 if bad or n == 0 else 0)
