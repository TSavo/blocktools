#!/usr/bin/env python3
"""Lock file for the wasm build copy (scripts/wasm-build.sh): the root Cargo.lock's packages, then
bindings/wasm/Cargo.lock's packages not already present (same name and version), in that order.
Every package the copy's workspace can need is pinned by one of the two committed, vetted locks;
wasm-build.sh then checks that the wasm crate's resolved tree (versions and features) is identical
to the one bindings/wasm/Cargo.lock gives. Usage: wasm-lock-merge.py ROOT_LOCK WASM_LOCK > OUT"""
import re, sys
SEP = "\n[[package]]\n"
main, wasm = (open(p).read() for p in sys.argv[1:3])
head = main.split(SEP)[0]
seen, out = set(), []
for b in main.split(SEP)[1:] + wasm.split(SEP)[1:]:
    k = tuple(re.findall(r'^(?:name|version) = "(.*)"', b, re.M))
    if k not in seen:
        seen.add(k); out.append(b.rstrip("\n"))
sys.stdout.write(head + SEP + "\n\n[[package]]\n".join(out) + "\n")
