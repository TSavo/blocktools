#!/usr/bin/env python3
"""Generate man pages from each tool's --help and its main.rs header (docs readiness).

  python3 scripts/gen-man.py            write man/man1/*.1 and man/man7/blocktools.7
  python3 scripts/gen-man.py --check    fail if man/ is stale; lint with groff/mandoc when present

Needs the release binaries (BIN, default target/release). Public text only: the help banner,
the usage line and the doc comments. Output is deterministic (no dates).

Each page has: NAME, SYNOPSIS, DESCRIPTION, OPTIONS, INPUT/OUTPUT, EXIT STATUS,
EXAMPLES, SECURITY NOTES, SEE ALSO (WARNING banner folded into SECURITY NOTES).
"""
import os, re, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATE = "2026-10-25"
BIN = os.environ.get("BIN", os.path.join(ROOT, "target/release"))

def version():
    m = re.search(r'^version\s*=\s*"([^"]+)"', open(os.path.join(ROOT, "Cargo.toml")).read(), re.M)
    return m.group(1) if m else "0"

def tools():
    s = open(os.path.join(ROOT, "Cargo.toml")).read()
    return sorted(m for m in re.findall(r'"tools/([a-z0-9-]+)"', s))

ASCII = {"\u2705": "yes", "\u274c": "no", "\u2192": "->", "\u2014": "--", "\u2013": "-", "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00d7": "x", "\u2264": "<=", "\u2265": ">="}

def ascii_only(t):
    # groff under LC_ALL=C rejects non-ASCII input; man pages are ASCII by construction.
    t = "".join(ASCII.get(c, c) for c in t)
    return t.encode("ascii", "replace").decode().replace("?\ufe0f", "")

def esc(t):
    t = ascii_only(t)
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

def split_help(use):
    """Split --help usage into synopsis lead-in vs option lines."""
    syn, opts = [], []
    for l in use:
        s = l.strip()
        if s.startswith("--") or s.startswith("- ") or (s.startswith("-") and len(s) > 1 and s[1] != "-"):
            opts.append(l)
        elif opts and (l.startswith("  ") or l.startswith("\t")):
            opts.append(l)  # continuation
        else:
            syn.append(l)
    return syn or use[:1], opts

def io_blurb(name, doc):
    lines = [l for l in doc if any(k in l.lower() for k in ("stdin", "stdout", "json", "output", "input", "secre"))]
    if not lines:
        lines = [
            "One JSON object per line on stdin and/or stdout (JSONL).",
            "Secrets travel only on stdin/stdout pipes inside ./blocktools run; flags are public parameters.",
            "Public status lines include tool and status fields; secret-bearing fields are redacted at the sealed boundary.",
        ]
    return lines[:12]

CASES = os.path.join(ROOT, "scripts/man-examples.txt")

def load_cases():
    cases = {}
    for l in open(CASES):
        if not l.strip() or l.startswith("#"): continue
        t, rc, cmd = (x.strip() for x in l.split("|", 2))
        cases.setdefault(t, []).append((rc, cmd))
    return cases

# D1-14: one exit-code rule for every tool (docs/EXIT-CODES.md).
EXIT_RULE = {**{k: 0 for k in ("ok", "done", "checksum_ok")},
             **{k: 1 for k in ("failed", "refused", "aborted", "wrong_password", "checksum_fail", "no_candidates", "too_many_candidates", "error")},
             **{k: 2 for k in ("bad_input", "unsupported")}}

def run_cases(cases):
    """Run every example (cwd = temp dir, PATH has BIN, no controlling terminal, stdin /dev/null).
    Returns {tool: [(cmd, rc, last_status)]}; any exit code that differs from the file is fatal."""
    env = dict(os.environ, PATH=os.path.abspath(BIN) + os.pathsep + os.environ["PATH"], R=ROOT, BIN=os.path.abspath(BIN), LC_ALL="C")
    out, bad = {}, []
    for t, cs in cases.items():
        for want, cmd in cs:
            if want == "-": out.setdefault(t, []).append((cmd, None, None)); continue
            d = tempfile.mkdtemp()
            p = subprocess.run(["sh", "-c", cmd], cwd=d, env=env, capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, start_new_session=True, timeout=60)
            shutil.rmtree(d)
            st = re.findall(r'"status":"([a-z_]+)"', p.stdout + p.stderr)
            if str(p.returncode) != want: bad.append(f"FAIL man example ({t}) exit {p.returncode}, file says {want}: {cmd}")
            # rule:X-exit (D1-14, docs/EXIT-CODES.md): the exit code follows the last status field.
            last = st[-1] if st else None
            need = EXIT_RULE.get(last) if last else (0 if p.returncode == 0 else None)
            if not t.endswith(".sh") and (need is None or p.returncode != need):  # recipes have their own codes (EXIT-CODES.md)
                bad.append(f"FAIL exit rule ({t}): status {last or 'missing'} exited {p.returncode}, rule says {need if need is not None else 'a status field'}: {cmd}")
            out.setdefault(t, []).append((cmd, p.returncode, st[-1] if st else None))
    if bad: print("\n".join(bad)); sys.exit(1)
    return out

def examples_for(name, ran):
    r = []
    for cmd, rc, st in ran.get(name, []):
        r.append("$ " + cmd)
        r.append("# not run by the man check (needs the sealed container or a real wallet)" if rc is None else
                 f"# exit {rc}" + (f", last status: {st}" if st else ", no status field"))
    return r

def exit_lines(name, ran):
    seen = sorted({(rc, st or "-") for _, rc, st in ran.get(name, []) if rc is not None})
    r = [esc("Measured on Linux by the EXAMPLES below (scripts/gen-man.py runs them):")]
    for rc, st in seen: r += [".TP", str(rc), esc("last status " + st if st != "-" else "no status field")]
    r += [".PP", esc("Not every tool uses the same code for bad input: some exit 1, others exit 2 (docs/FINDINGS.md D1-14). Always read the last JSON status line. Status and failure codes: docs/REFUSALS.md.")]
    return r

def page(name, sec, short, synopsis, options, desc, warn, io_lines, examples, exits):
    r = [f'.TH {esc(name.upper())} {sec} {DATE} "blocktools {version()}" "blocktools manual"',
         ".SH NAME", esc(f"{name} - {short}"),
         ".SH SYNOPSIS", ".nf"] + [esc(s) for s in synopsis] + [".fi"]
    if desc: r += [".SH DESCRIPTION"] + para(desc)
    if options:
        r += [".SH OPTIONS", ".nf"] + [esc(o) for o in options] + [".fi"]
    else:
        flags = sorted(set(re.findall(r"(?<![\w-])(--?[a-z][a-z0-9-]*)", " ".join(synopsis))))
        r += [".SH OPTIONS"] + ([".nf"] + [esc(f) for f in flags] + [".fi", esc("Each flag's meaning is in the SYNOPSIS usage line(s) above (taken from --help).")]
                                if flags else [esc("No flags. Input is read from stdin or the arguments shown in SYNOPSIS.")])
    r += [".SH INPUT/OUTPUT"] + para(io_lines)
    r += [".SH EXIT STATUS"] + exits
    r += [".SH EXAMPLES", ".nf"] + [esc(e) for e in examples] + [".fi"]
    sec_notes = warn[:] if warn else [
        "DANGEROUS: audit before use with real funds. See docs/SECURITY.md.",
        "Run secret-touching tools only inside ./blocktools run (sealed, offline).",
    ]
    r += [".SH SECURITY NOTES"] + para(sec_notes)
    r += [".SH SEE ALSO", esc("blocktools(7), docs/SECURITY.md, docs/getting-started.md, recipes/README.md")]
    return "\n".join(r) + "\n"

def help_of(t):
    p = subprocess.run([os.path.join(BIN, t), "--help"], capture_output=True, text=True, timeout=20)
    txt = (p.stdout + p.stderr).strip("\n").split("\n")
    if "" in txt:
        i = txt.index(""); return [l for l in txt[:i] if l], [l for l in txt[i + 1:] if l]
    return [], [l for l in txt if l]

def generate(out):
    ran = run_cases(load_cases())
    missing = [t for t in tools() + ["recover.sh", "blocktools"] if t not in ran]
    if missing: sys.exit(f"FAIL scripts/man-examples.txt has no example for: {' '.join(missing)}")
    os.makedirs(os.path.join(out, "man1"), exist_ok=True); os.makedirs(os.path.join(out, "man7"), exist_ok=True)
    idx = []
    for t in tools():
        warn, use = help_of(t)
        if not use: sys.exit(f"FAIL {t} --help printed no usage")
        syn, opts = split_help(use)
        doc = header(os.path.join(ROOT, "tools", t, "src/main.rs"), "//!")
        first = doc[0] if doc else t
        short = first.split(":", 1)[1].strip() if first.startswith(t + ":") else first
        short = short.rstrip(".") or t
        idx.append((t, short))
        open(os.path.join(out, "man1", t + ".1"), "w").write(
            page(t, 1, short, syn, opts, doc[1:] if doc else [], warn, io_blurb(t, doc), examples_for(t, ran), exit_lines(t, ran)))
    for path, name, short in [("recipes/recover.sh", "recover.sh", "unknown wallet file to sweep, with human confirmation at each step"),
                              ("blocktools", "blocktools", "host wrapper that runs a pipeline in the sealed container")]:
        doc = header(os.path.join(ROOT, path), "#")
        use = [l.strip() for l in doc if l.strip().startswith(("recover.sh ", "./blocktools "))]
        idx.append((name, short))
        open(os.path.join(out, "man1", name + ".1"), "w").write(
            page(name, 1, short, use or [name], [], [l for l in doc if l.strip() not in use], [], io_blurb(name, doc), examples_for(name, ran), exit_lines(name, ran)))
    ov = [f'.TH BLOCKTOOLS 7 {DATE} "blocktools {version()}" "blocktools manual"',
          ".SH NAME", esc("blocktools - offline wallet recovery, inspection and signing tools"),
          ".SH SYNOPSIS", ".nf",
          esc("./blocktools run '<pipeline>'"),
          esc("./blocktools reveal '<pipeline>'"),
          esc("recipes/recover.sh FILE DEST [options]"),
          ".fi",
          ".SH DESCRIPTION",
          esc("Small tools joined by JSON lines on stdin and stdout. Readers turn wallet files into keys, derive and key-to-addresses turn keys into addresses, tx-build/tx-verify/tx-sign/tx-broadcast move funds. Every signature and broadcast waits for a code typed on the terminal."),
          ".PP", esc("Run anything that touches secrets inside ./blocktools run (sealed, offline). Policy files: docs/POLICY.md. Supported chains: docs/CHAINS.md. Start here: docs/getting-started.md."),
          ".SH OPTIONS", esc("See blocktools(1) and each tool's man page. The wrapper passes the pipeline to sealed-run; tools parse their own flags."),
          ".SH INPUT/OUTPUT",
          esc("Pipelines speak JSONL. The sealed boundary redacts secret fields before host-visible stdout. Host-side network tools (utxo-fetch, tx-broadcast, rpc, xmr-wallet) see addresses and signed transactions only."),
          ".SH EXIT STATUS",
          ".TP", "0", esc("Success."),
          ".TP", "1", esc("Refused, failed verification, aborted, or (some tools) bad input."),
          ".TP", "2", esc("Bad input or unsupported (most tools)."),
          ".PP", esc("Measured on Linux; per-tool codes are in each page. See docs/REFUSALS.md."),
          ".SH EXAMPLES", ".nf",
          esc("./blocktools run 'classify < /in/seed.txt'"),
          esc("recipes/recover.sh /in/seed.txt bc1q... --goal addresses"),
          ".fi",
          ".SH SECURITY NOTES",
          esc("DANGEROUS with real funds. Audit the code. Prefer sealed offline runs. See docs/SECURITY.md."),
          ".SH TOOLS"]
    for n, s in idx: ov += [".TP", f"\\fB{esc(n)}\\fR(1)", esc(s)]
    ov += [".SH SEE ALSO", esc("README.md, DESIGN.md, EXPORTS.md, docs/SECURITY.md, docs/getting-started.md, docs/troubleshooting.md, recipes/README.md")]
    open(os.path.join(out, "man7", "blocktools.7"), "w").write("\n".join(ov) + "\n")

def lint(d):
    """Render every page with groff under LC_ALL=C (-wall, any diagnostic fatal), as CI does; also mandoc
    if present. Fails closed when groff is missing: the gate must test the property, not skip it."""
    pages = [os.path.join(d, s, f) for s in ("man1", "man7") for f in sorted(os.listdir(os.path.join(d, s)))]
    bad = 0
    for p in pages:
        try: open(p, encoding="ascii").read()
        except UnicodeDecodeError: print(f"FAIL non-ASCII in {p}"); bad = 1
    if not shutil.which("groff"): print("FAIL groff not installed (needed for the man render check)"); return 1
    env = dict(os.environ, LC_ALL="C", LANG="C")
    for p in pages:
        r = subprocess.run(["groff", "-man", "-wall", "-z", p], capture_output=True, text=True, env=env)
        msg = "\n".join(l for l in (r.stdout + r.stderr).splitlines() if "no blank" not in l)
        if r.returncode or msg.strip(): print(f"FAIL groff LC_ALL=C {p}: {msg[:300]}"); bad = 1
    if shutil.which("mandoc"):
        for p in pages:
            r = subprocess.run(["mandoc", "-T", "lint", "-W", "warning", p], capture_output=True, text=True)
            msg = "\n".join(l for l in (r.stdout + r.stderr).splitlines() if "no blank" not in l)
            if msg.strip(): print(f"FAIL mandoc {p}: {msg[:300]}"); bad = 1
    return bad

BOILER = [r"See SYNOPSIS; this tool has no separate long-option list", r"See recipes/ for end-to-end flows",
          r"Other nonzero codes are tool-specific", r"One JSON object per line on stdin and/or stdout \(JSONL\)\."]
REQUIRED = ["NAME", "SYNOPSIS", "DESCRIPTION", "OPTIONS", "INPUT/OUTPUT", "EXIT STATUS", "EXAMPLES", "SECURITY NOTES", "SEE ALSO"]

def strict(d):
    """Every man1 page has every required section, and none is only generator boilerplate."""
    bad = 0
    for f in sorted(os.listdir(os.path.join(d, "man1"))):
        secs, cur = {}, None
        for l in open(os.path.join(d, "man1", f)):
            if l.startswith(".SH "): cur = l[4:].strip().strip('"'); secs[cur] = []; continue
            t = (re.sub(r"^\.\S+ ?", "", l) if l.startswith(".") else l).replace("\\-", "-").replace("\\&", "").strip()
            if cur and t and not re.fullmatch(r"\d", t) and not any(re.search(b, t) for b in BOILER): secs[cur].append(t)
        for s in REQUIRED:
            if len(" ".join(secs.get(s, []))) < 15: print(f"FAIL man stub: {f} section {s} is missing or boilerplate"); bad = 1
    return bad

if __name__ == "__main__":
    dest = os.path.join(ROOT, "man")
    if "--check" in sys.argv:
        tmp = tempfile.mkdtemp(); generate(tmp)
        # lint the committed pages (what ships) as well as fresh output, before the stale diff
        rc = lint(dest) | lint(tmp) | strict(dest)
        r = subprocess.run(["diff", "-r", dest, tmp], capture_output=True, text=True)
        if r.returncode: print("FAIL man/ is stale: run python3 scripts/gen-man.py"); print(r.stdout[:2000]); sys.exit(1)
        shutil.rmtree(tmp)
        if rc: sys.exit(1)
        n = len(os.listdir(os.path.join(dest, "man1")))
        print(f"man-check ok: {n} man1 pages, every section filled, every example run"); sys.exit(0)
    generate(dest)
    print(f"wrote man pages for {len(tools())} tools + recover.sh + blocktools + blocktools(7)")
