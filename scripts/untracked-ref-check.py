#!/usr/bin/env python3
"""Fail if a tracked script, recipe, man page or man example names a fixtures/ path that a clean
checkout does not have. Each one must be tracked, or be a file scripts/fetch-fixtures.sh downloads
and sha256-pins (gate.sh runs fetch-fixtures before every stage that reads them). A local-only
file makes the local gate pass where CI fails (run 40281683311). Paths resolve from the repo root
or from the referencing file's directory."""
import os, re, subprocess, sys
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
tracked = set(subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split("\n"))
dirs = {os.path.dirname(t) for t in tracked}
while True:
    more = {os.path.dirname(d) for d in dirs} - dirs
    if not more: break
    dirs |= more
ff = open("scripts/fetch-fixtures.sh").read()
fetched = {"fixtures/external/" + n for n in re.findall(r"^[0-9a-f]{64} (\S+)$", ff, re.M) + re.findall(r'\$D/([A-Za-z0-9_.-]+)', ff)}
ok = lambda p: p in tracked or p.rstrip("/") in dirs or p in fetched or p.rstrip("/") == "fixtures/external"
bad = n = 0
for f in sorted(t for t in tracked if re.match(r"(scripts|recipes|man)/", t)):
    try: s = open(f, encoding="utf-8").read().replace("\\-", "-")
    except (UnicodeDecodeError, FileNotFoundError): continue
    # a leading $VAR/ (the man examples' $R, gate-negatives' $root) stands for the repo root
    for p in set(m[1] for m in re.findall(r"(\$\{?\w+\}?/)?((?<![$\w{}])[A-Za-z0-9_./-]*fixtures/[A-Za-z0-9_./-]*[A-Za-z0-9_/])", s)):
        n += 1
        if p.startswith("/"): continue
        cands = [os.path.normpath(p), os.path.normpath(os.path.join(os.path.dirname(f), p))]
        if p.startswith("."): cands = cands[1:]
        if not any(ok(c) or ok(c + "/") for c in cands):
            print(f"FAIL untracked reference: {f} names {p}, which is neither tracked nor pinned in scripts/fetch-fixtures.sh"); bad = 1  # rule:U-untracked
if not bad: print(f"untracked-ref ok ({n} fixtures/ references)")
sys.exit(bad)
