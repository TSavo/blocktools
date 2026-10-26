#!/usr/bin/env python3
"""Claims registry check (docs/claims.toml). See docs/CLAIMS.md.

Exit status 1 when:
  * a doc contains a quantitative claim (number with units, a count of tools/tests/chains/crates/...,
    "verified/tested on X") that no registered claim covers;                         [K-unreg]
  * a registered claim's doc text is no longer in that doc;                          [K-gone]
  * a measured claim lacks command/expect/commit/date, or its commit isn't in HEAD;  [K-fields]
  * a measured claim is stale: a file in `depends` changed since `commit`;           [K-stale]
  * a measured claim marked cheap=true: its command fails or prints no `expect`;     [K-run]
  * a measured macos claim has no `ci_run`, or that run's macos job did not succeed
    at the claim's commit (checked with gh; fails closed if gh is unavailable);      [K-macos]
  * a number claim that is not measured is not labelled "(unmeasured)" on its doc line,
    or an unmeasurable claim has no reason;
  * a re-run measured claim's command reports FALLBACK (measured something else);   [K-fallback]                                          [K-label]
  * a claim the registry does not mark measured is stated as fact: each doc line carrying its text
    must also carry "(untested)", "(unmeasured)" or "(unmeasurable)"                  [K-assert]
  * docs/CLAIMS.md's generated Measured/Untested sections are out of date.            [K-render]
Usage: claims-check.py [--render] [--run-all]
"""
import os, re, subprocess, sys, tomllib, json, shutil
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
REG = os.environ.get("CLAIMS_TOML", "docs/claims.toml")
DOCS = ["README.md", "DESIGN.md", "EXPORTS.md", "bindings/wasm/README.md"] + \
    sorted("docs/" + f for f in os.listdir("docs") if f.endswith(".md") and f not in ("CLAIMS.md", "FINDINGS.md")) + \
    sorted("recipes/" + f for f in os.listdir("recipes") if f.endswith(".md"))
UNITS = r"(?:[KMG]i?B|bytes?|ms|seconds?|sats?|sat/vB|gwei|ETH|tools|tests|chains|CLIs|crates|man pages|checks|wallet formats)"
PAT = re.compile(r"(?<![-\w])\d+(?:[.,]\d+)*(?:\.\.\d+)?\s?" + UNITS + r"\b|\b(?:verified|tested|works|runs) on (?:Linux|macOS|Mac|Windows|Docker|Battleaxe|[A-Z][a-z]+)\b")
VALID_STATUS = {"measured", "untested", "unmeasurable"}
VALID_KIND = {"number", "security", "platform"}
VALID_PLAT = {"linux", "macos", "docker", "any"}

def git(*a):
    return subprocess.run(["git", *a], capture_output=True, text=True)

SHALLOW = git("rev-parse", "--is-shallow-repository").stdout.strip() == "true"


def main():
    render = "--render" in sys.argv; run_all = "--run-all" in sys.argv
    reg = tomllib.load(open(REG, "rb"))["claim"]
    bad = []
    ids = [c.get("id") for c in reg]
    for d in sorted({i for i in ids if ids.count(i) > 1}): bad.append(f"duplicate claim id {d}")
    texts = {}
    for c in reg:
        cid = c.get("id", "?")
        for k in ("id", "statement", "kind", "platform", "status"):
            if k not in c: bad.append(f"[K-fields] {cid}: missing {k}")  # rule:K-fields
        if c.get("status") not in VALID_STATUS: bad.append(f"[K-fields] {cid}: bad status {c.get('status')}")  # rule:K-fields
        if c.get("kind") not in VALID_KIND: bad.append(f"[K-fields] {cid}: bad kind {c.get('kind')}")  # rule:K-fields
        if c.get("platform") not in VALID_PLAT: bad.append(f"[K-fields] {cid}: bad platform {c.get('platform')}")  # rule:K-fields
        for loc in c.get("doc", []):
            f, t = loc["file"], loc["text"]
            lines = [l for l in open(f, encoding="utf-8").read().split("\n") if t in l] if os.path.exists(f) else []
            if c.get("status") == "unmeasurable" and not c.get("reason", "").strip():
                bad.append(f"[K-label] {cid}: unmeasurable claim needs a reason")  # rule:K-label
            if not lines: bad.append(f"[K-gone] {cid}: text {t!r} not found in {f}"); continue  # rule:K-gone
            texts.setdefault(f, []).append((t, c))
            if c.get("status") != "measured" and c.get("kind") != "number":
                for l in lines:
                    if not any(m in l for m in ("(untested)", "(unmeasured)", "(unmeasurable)")):
                        bad.append(f"[K-assert] {cid}: {f} states {t!r} as fact but the registry marks it {c.get('status')}")  # rule:K-assert
            if c.get("kind") == "number" and c.get("status") == "untested" and not all("(unmeasured)" in l for l in lines):
                bad.append(f"[K-label] {cid}: unmeasured number {t!r} in {f} is not labelled (unmeasured)")  # rule:K-label
        if c.get("status") == "measured":
            for k in ("command", "expect", "commit", "date"):
                if not c.get(k): bad.append(f"[K-fields] {cid}: measured but no {k}")  # rule:K-fields
            com = c.get("commit", "")
            if com and SHALLOW:
                bad.append(f"[K-fields] {cid}: shallow clone, cannot check commit {com} (use fetch-depth: 0)")  # rule:K-fields
            elif com and git("merge-base", "--is-ancestor", com, "HEAD").returncode:
                bad.append(f"[K-fields] {cid}: commit {com} is not in HEAD's history")  # rule:K-fields
            elif com and c.get("depends"):
                if git("diff", "--quiet", com, "HEAD", "--", *c["depends"]).returncode:
                    bad.append(f"[K-stale] {cid}: {', '.join(c['depends'])} changed since {com}; re-measure")  # rule:K-stale
            if c.get("platform") == "macos":
                run = c.get("ci_run")
                if not run: bad.append(f"[K-macos] {cid}: macos claim measured without a ci_run of the macos job")  # rule:K-macos
                elif not shutil.which("gh"): bad.append(f"[K-macos] {cid}: gh unavailable, cannot verify ci_run {run} (fail closed)")  # rule:K-macos
                else:
                    r = subprocess.run(["gh", "run", "view", str(run), "--json", "headSha,jobs"], capture_output=True, text=True)
                    ok = False
                    if r.returncode == 0:
                        j = json.loads(r.stdout)
                        ok = j["headSha"].startswith(com) and any(x["name"] == "macos" and x["conclusion"] == "success" for x in j["jobs"])
                    if not ok: bad.append(f"[K-macos] {cid}: ci_run {run} has no successful macos job at {com}")  # rule:K-macos
            if c.get("command") and (c.get("cheap") or run_all):
                r = subprocess.run(c["command"], shell=True, capture_output=True, text=True)
                if "FALLBACK" in r.stdout + r.stderr:
                    bad.append(f"[K-fallback] {cid}: `{c['command']}` measured via a fallback path, not the property")  # rule:K-fallback
                elif r.returncode or c.get("expect", "\0") not in r.stdout:
                    bad.append(f"[K-run] {cid}: `{c['command']}` rc={r.returncode}, expected {c.get('expect')!r} in output: {(r.stdout + r.stderr)[-300:]!r}")  # rule:K-run
    for f in DOCS:
        if not os.path.exists(f): continue
        for n, line in enumerate(open(f, encoding="utf-8").read().split("\n"), 1):
            for m in PAT.finditer(line):
                h = m.group(0)
                if not any((h in t or t in h) and t in line for t, _ in texts.get(f, [])):
                    bad.append(f"[K-unreg] {f}:{n}: unregistered claim {h!r} (add it to {REG} or remove it)")  # rule:K-unreg
    out = gen(reg)
    if render: open("docs/CLAIMS.md", "w").write(out); print("wrote docs/CLAIMS.md")
    elif not os.path.exists("docs/CLAIMS.md") or open("docs/CLAIMS.md").read() != out:
        bad.append("[K-render] docs/CLAIMS.md is out of date: run python3 scripts/claims-check.py --render")  # rule:K-render
    for b in bad: print("FAIL claims " + b)
    if bad: sys.exit(1)
    st = {s: sum(1 for c in reg if c["status"] == s) for s in sorted(VALID_STATUS)}
    print(f"claims ok ({len(reg)} registered: " + ", ".join(f"{v} {k}" for k, v in st.items()) + ")")

def gen(reg):
    o = ["# Claims", "", "Generated from docs/claims.toml by `python3 scripts/claims-check.py --render`; do not edit by hand.",
         "docs-check fails on any quantitative doc claim not registered there, on a stale or failing measurement,",
         "and on a macOS claim marked measured without a successful macOS CI job.", ""]
    for title, sts in (("Measured", ("measured",)), ("Untested", ("untested", "unmeasurable"))):
        o += [f"## {title}", "", "| id | kind | platform | status | statement | command | commit | date |", "|---|---|---|---|---|---|---|---|"]
        for c in reg:
            if c["status"] in sts:
                cmd = c.get("command", "-").replace("|", "\\|")
                o.append(f"| {c['id']} | {c['kind']} | {c['platform']} | {c['status']} | {c['statement']} | `{cmd}` | {c.get('commit', '-')} | {c.get('date', '-')} |")
        o.append("")
    return "\n".join(o)

if __name__ == "__main__": main()
