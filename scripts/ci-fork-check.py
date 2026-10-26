#!/usr/bin/env python3
"""Fork-PR runner check (rule H-fork). Parses every workflow in .github/workflows and, for each job that a
pull_request event can start, EVALUATES its runs-on expression (a small GitHub-expression evaluator, not a grep)
for a fork PR and a same-repo PR / push, with vars.RUNNER_LABELS unset and set. Fails if:
  - a fork PR can select a self-hosted label (or any label but ubuntu-latest / macos-latest / windows-latest),
  - a workflow uses pull_request_target (runs fork code with secrets),
  - a job reachable from pull_request may get a write token (workflow or job permissions not read-only / absent),
  - push / same-repo PR jobs that use the Battleaxe expression stop selecting self-hosted by default.
Usage: python3 scripts/ci-fork-check.py [workflow-dir]"""
import glob, json, os, re, sys
import yaml

HOSTED = {"ubuntu-latest", "macos-latest", "windows-latest"}

def tokens(s):
    pat = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<op>==|!=|&&|\|\||!|\(|\)|,)|(?P<num>\d+)|(?P<id>[A-Za-z_][\w.-]*))")
    i, out = 0, []
    s = s.strip()
    while i < len(s):
        m = pat.match(s, i)
        if not m or m.end() == i: raise SyntaxError(f"cannot parse expression at: {s[i:]!r}")
        i = m.end()
        k = m.lastgroup; v = m.group(k)
        out.append((k, v[1:-1].replace("''", "'") if k == "str" else v))
    return out

class Ev:
    def __init__(self, toks, ctx): self.t, self.i, self.ctx = toks, 0, ctx
    def peek(self): return self.t[self.i] if self.i < len(self.t) else (None, None)
    def take(self, v=None):
        k, x = self.peek()
        if v is not None and x != v: raise SyntaxError(f"expected {v}, got {x}")
        self.i += 1; return k, x
    def expr(self):
        v = self.and_()
        while self.peek()[1] == "||":
            self.take(); r = self.and_(); v = v or r
        return v
    def and_(self):
        v = self.cmp()
        while self.peek()[1] == "&&":
            self.take(); r = self.cmp(); v = v and r
        return v
    def cmp(self):
        v = self.unary()
        while self.peek()[1] in ("==", "!="):
            op = self.take()[1]; r = self.unary()
            a, b = (v.lower(), r.lower()) if isinstance(v, str) and isinstance(r, str) else (v, r)
            v = (a == b) if op == "==" else (a != b)
        return v
    def unary(self):
        if self.peek()[1] == "!": self.take(); return not self.unary()
        return self.atom()
    def atom(self):
        k, x = self.take()
        if x == "(":
            v = self.expr(); self.take(")"); return v
        if k == "str": return x
        if k == "num": return int(x)
        if k == "id":
            if x in ("true", "false"): return x == "true"
            if x == "null": return None
            if self.peek()[1] == "(":
                self.take("("); args = [self.expr()]
                while self.peek()[1] == ",": self.take(); args.append(self.expr())
                self.take(")")
                if x.lower() == "fromjson": return json.loads(args[0])
                raise SyntaxError(f"unsupported function {x}")
            cur = self.ctx
            for part in x.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            return cur if cur is not None else ""
        raise SyntaxError(f"unexpected {x}")

def evaluate(val, ctx):
    if isinstance(val, list): return val
    if not isinstance(val, str): raise SyntaxError(f"runs-on {val!r} not understood")
    m = re.fullmatch(r"\s*\$\{\{(.*)\}\}\s*", val, re.S)
    if not m: return [val]
    e = Ev(tokens(m.group(1)), ctx); v = e.expr()
    if e.i != len(e.t): raise SyntaxError("trailing tokens in expression")
    return v if isinstance(v, list) else [v]

def ctx(fork, labels):
    repo = "TSavo/blocktools"
    ev = {"pull_request": {"head": {"repo": {"full_name": "mallory/blocktools" if fork else repo}}}}
    return {"github": {"event_name": "pull_request", "repository": repo, "event": ev},
            "vars": ({"RUNNER_LABELS": labels} if labels else {})}

def push_ctx(labels):
    return {"github": {"event_name": "push", "repository": "TSavo/blocktools", "event": {}},
            "vars": ({"RUNNER_LABELS": labels} if labels else {})}

def read_only(perm):
    if perm is None: return False
    if isinstance(perm, str): return perm in ("read-all", "{}")
    return all(v in ("read", "none") for v in perm.values())

def main(d):
    bad = []; n = 0
    for f in sorted(glob.glob(os.path.join(d, "*.yml")) + glob.glob(os.path.join(d, "*.yaml"))):
        w = yaml.safe_load(open(f)); name = os.path.basename(f)
        on = w.get("on", w.get(True))  # PyYAML reads the bare key `on` as True
        evs = set(on) if isinstance(on, (list, dict)) else {on}
        if "pull_request_target" in evs: bad.append(f"{name}: uses pull_request_target")
        if "pull_request" not in evs: continue
        wperm = w.get("permissions")
        for jid, job in (w.get("jobs") or {}).items():
            n += 1
            perm = job.get("permissions", wperm)
            if not read_only(perm): bad.append(f"{name}:{jid}: permissions {perm!r} are not read-only on pull_request")
            ro = job.get("runs-on")
            for labels in (None, '["self-hosted","Linux","X64","blocktools"]', '"ubuntu-latest"'):
                try: got = evaluate(ro, ctx(True, labels))
                except SyntaxError as e: bad.append(f"{name}:{jid}: {e}"); break
                if not got or any(l not in HOSTED for l in got):
                    bad.append(f"{name}:{jid}: fork pull_request selects {got} (RUNNER_LABELS={labels})")
            if isinstance(ro, str) and "RUNNER_LABELS" in ro:
                for c in (ctx(False, None), push_ctx(None)):
                    got = evaluate(ro, c)
                    if "self-hosted" not in got:
                        bad.append(f"{name}:{jid}: {c['github']['event_name']} from this repo no longer selects self-hosted ({got})")
    for b in bad: print("FAIL ci-fork-check:", b)
    if bad: return 1
    print(f"ci-fork-check ok ({n} pull_request jobs: fork PRs evaluate to GitHub-hosted labels only, read-only token)")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ".github/workflows"))
