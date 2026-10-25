#!/usr/bin/env python3
"""Generate man pages from each tool's --help and its main.rs header (docs readiness).

  python3 scripts/gen-man.py            write man/man1/*.1 and man/man7/blocktools.7
  python3 scripts/gen-man.py --check    fail if man/ is stale; lint with groff/mandoc when present
Needs the release binaries (BIN, default target/release). Public text only: the help banner,
the usage line and the doc comments. Output is deterministic (no dates).
"""
import os, re, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Manual date: bump with the version at release (keeps output deterministic).
DATE = "2026-10-25"
BIN = os.environ.get("BIN", os.path.join(ROOT, "target/release"))

def version():
    m = re.search(r'^version\s*=\s*"([^"]+)"', open(os.path.join(ROOT, "Cargo.toml")).read(), re.M)
    return m.group(1) if m else "0"

def tools():
    s = open(os.path.join(ROOT, "Cargo.toml")).read()
    return sorted(m for m in re.findall(r'"tools/([a-z0-9-]+)"', s))

def esc(t):
    t = t.replace("\\", "\\e").replace("-", "\\-")
    return ("\\&" + t) if t[:1] in ".'" else t

def header(path, prefix):
    out = []
    for l in open(path):
        if l.startswith("#!"): continue
        if not l.startswith(prefix): break
        out.append(l[len(prefix):].rstrip("\n").removeprefix(" "))
    return out

def para(lines):
    """Doc lines -> roff: "- " starts a bullet (indented lines continue it), other indented
    lines are literal blocks, the rest flows."""
    r, lit, bullet = [], False, False
    for l in lines:
        if l.startswith("- "):
            if lit: r += [".RE", ".fi"]; lit = False
            r += [".IP \\(bu 2", esc(l[2:].strip())]; bullet = True; continue
        code = l.startswith(("  ", "\t"))
        if bullet and code and l.strip(): r.append(esc(l.strip())); continue
        if not l.strip(): bullet = False
        elif not code and bullet: r.append(".PP"); bullet = False
        if code and not lit: r += [".nf", ".RS 2"]; lit = True
        if not code and lit: r += [".RE", ".fi"]; lit = False
        r.append(".PP" if not l.strip() and not lit else esc(l.strip() if not code else l.rstrip()))
    if lit: r += [".RE", ".fi"]
    while r and r[0] == ".PP": r.pop(0)
    while r and r[-1] == ".PP": r.pop()
    return [x for i, x in enumerate(r) if not (x == ".PP" and ((i and r[i - 1] in (".PP", ".fi")) or (i + 1 < len(r) and r[i + 1].startswith(".IP"))))]

def page(name, sec, short, synopsis, desc, warn):
    r = [f'.TH {esc(name.upper())} {sec} {DATE} "blocktools {version()}" "blocktools manual"',
         ".SH NAME", esc(f"{name} - {short}"), ".SH SYNOPSIS", ".nf"] + [esc(s) for s in synopsis] + [".fi"]
    if desc: r += [".SH DESCRIPTION"] + para(desc)
    if warn: r += [".SH WARNING"] + [x for w in warn for x in (esc(w), ".br")][:-1]
    r += [".SH SEE ALSO", esc("blocktools(7), docs/SECURITY.md, recipes/README.md")]
    return "\n".join(r) + "\n"

def help_of(t):
    p = subprocess.run([os.path.join(BIN, t), "--help"], capture_output=True, text=True, timeout=20)
    txt = (p.stdout + p.stderr).strip("\n").split("\n")
    if "" in txt:
        i = txt.index(""); return [l for l in txt[:i] if l], [l for l in txt[i + 1:] if l]
    return [], [l for l in txt if l]

def generate(out):
    os.makedirs(os.path.join(out, "man1"), exist_ok=True); os.makedirs(os.path.join(out, "man7"), exist_ok=True)
    idx = []
    for t in tools():
        warn, use = help_of(t)
        if not use: sys.exit(f"FAIL {t} --help printed no usage")
        doc = header(os.path.join(ROOT, "tools", t, "src/main.rs"), "//!")
        first = doc[0] if doc else t
        short = first.split(":", 1)[1].strip() if first.startswith(t + ":") else first
        short = short.rstrip(".") or t
        idx.append((t, short))
        open(os.path.join(out, "man1", t + ".1"), "w").write(page(t, 1, short, use, doc[1:] if doc else [], warn))
    for path, name, short in [("recipes/recover.sh", "recover.sh", "unknown wallet file to sweep, with human confirmation at each step"),
                              ("blocktools", "blocktools", "host wrapper that runs a pipeline in the sealed container")]:
        doc = header(os.path.join(ROOT, path), "#")
        use = [l.strip() for l in doc if l.strip().startswith(("recover.sh ", "./blocktools "))]
        idx.append((name, short))
        open(os.path.join(out, "man1", name + ".1"), "w").write(page(name, 1, short, use, [l for l in doc if l.strip() not in use], []))
    ov = [f'.TH BLOCKTOOLS 7 {DATE} "blocktools {version()}" "blocktools manual"', ".SH NAME",
          esc("blocktools - offline wallet recovery, inspection and signing tools"), ".SH DESCRIPTION",
          esc("Small tools joined by JSON lines on stdin and stdout. Readers turn wallet files into keys, derive and key-to-addresses turn keys into addresses, tx-build/tx-verify/tx-sign/tx-broadcast move funds. Every signature and broadcast waits for a code typed on the terminal."),
          ".PP", esc("Run anything that touches secrets inside ./blocktools run (sealed, offline). Policy files: docs/POLICY.md. Supported chains: docs/CHAINS.md."),
          ".SH TOOLS"]
    for n, s in idx: ov += [".TP", f"\\fB{esc(n)}\\fR(1)", esc(s)]
    ov += [".SH SEE ALSO", esc("README.md, DESIGN.md, EXPORTS.md, docs/SECURITY.md, docs/ROADMAP-PARITY.md")]
    open(os.path.join(out, "man7", "blocktools.7"), "w").write("\n".join(ov) + "\n")

def lint(d):
    pages = [os.path.join(d, s, f) for s in ("man1", "man7") for f in sorted(os.listdir(os.path.join(d, s)))]
    for tool, args in [("mandoc", ["-T", "lint", "-W", "warning"]), ("groff", ["-man", "-ww", "-z"])]:
        if shutil.which(tool):
            bad = 0
            for p in pages:
                r = subprocess.run([tool] + args + [p], capture_output=True, text=True)
                msg = "\n".join(l for l in (r.stdout + r.stderr).splitlines() if "no blank" not in l)
                if (tool == "groff" and r.returncode) or msg.strip(): print(f"FAIL {tool} {p}: {msg[:300]}"); bad = 1
            if shutil.which("man") and subprocess.run(["man", "-l", "-Tutf8", pages[0]], capture_output=True).returncode: print("FAIL man -l"); bad = 1
            return bad
    print("man lint skipped (no mandoc/groff)"); return 0

if __name__ == "__main__":
    dest = os.path.join(ROOT, "man")
    if "--check" in sys.argv:
        tmp = tempfile.mkdtemp(); generate(tmp)
        r = subprocess.run(["diff", "-r", dest, tmp], capture_output=True, text=True)
        if r.returncode: print("FAIL man/ is stale: run python3 scripts/gen-man.py"); print(r.stdout[:2000]); sys.exit(1)
        rc = lint(tmp); shutil.rmtree(tmp)
        if rc: sys.exit(1)
        print("man-check ok"); sys.exit(0)
    generate(dest)
