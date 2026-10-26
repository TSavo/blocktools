#!/usr/bin/env python3
"""rule:B-bash-sh: fail when a tracked file runs a bash-shebang script with `sh` (dash < 0.5.11 has no
pipefail: CI 40293548186 recover.sh man examples exited 2). Scans tracked md/txt/sh/yml/py/man files."""
import re,subprocess,os,sys
root=subprocess.check_output(["git","rev-parse","--show-toplevel"],text=True).strip(); os.chdir(root)
files=[f for f in subprocess.check_output(["git","ls-files"],text=True).split() if f.endswith((".md",".txt",".sh",".yml",".1",".7",".py")) or f=="blocktools"]
bash={f for f in subprocess.check_output(["git","ls-files"],text=True).split() if os.path.isfile(f) and open(f,'rb').read(40).startswith((b"#!/usr/bin/env bash",b"#!/bin/bash"))}
pat=re.compile(r'(?<![\w-])sh\s+(?:-\w+\s+)*"?(?:\$\{?\w+\}?/|\./)?([\w./-]+\.sh)')
bad=[]
for f in files:
    if f=="scripts/bash-via-sh-check.py": continue
    for n,l in enumerate(open(f,errors="replace"),1):
        for m in pat.finditer(l.replace("\\-","-")):
            p=m.group(1)
            for c in (p, os.path.normpath(os.path.join(os.path.dirname(f),p)), "recipes/"+os.path.basename(p)):
                if c in bash: bad.append(f"{f}:{n}: sh {p}"); break
for b in bad: print("FAIL bash script run via sh: "+b)
if bad: sys.exit(1)
print(f"bash-via-sh ok ({len(bash)} bash scripts)")
