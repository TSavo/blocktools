#!/usr/bin/env python3
"""List a .wasm module's sections, exports, imports and (if present) name-section function
names. Stdlib only; used by scripts/wasm-check.sh. Usage: wasm-names.py FILE [sections|exports|imports|funcs]"""
import sys

def leb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if x < 0x80: return r, i

def name(b, i):
    n, i = leb(b, i); return b[i:i + n].decode('utf-8', 'replace'), i + n

def sections(b):
    assert b[:4] == b'\0asm', 'not wasm'
    i = 8
    while i < len(b):
        sid = b[i]; n, j = leb(b, i + 1); yield sid, b[j:j + n]; i = j + n

def main():
    b = open(sys.argv[1], 'rb').read(); what = sys.argv[2] if len(sys.argv) > 2 else 'sections'
    for sid, body in sections(b):
        if what == 'sections':
            label = name(body, 0)[0] if sid == 0 else str(sid)
            print(f'{sid:2} {label:24} {len(body)}')
        elif what == 'exports' and sid == 7:
            n, i = leb(body, 0)
            for _ in range(n):
                nm, i = name(body, i); kind = body[i]; _, i = leb(body, i + 1); print(kind, nm)
        elif what == 'imports' and sid == 2:
            n, i = leb(body, 0)
            for _ in range(n):
                m, i = name(body, i); f, i = name(body, i); kind = body[i]; i += 1
                if kind == 0: _, i = leb(body, i)
                elif kind == 1: i += 1; fl = body[i]; i += 1; _, i = leb(body, i); i = leb(body, i)[1] if fl & 1 else i
                elif kind == 2: fl = body[i]; i += 1; _, i = leb(body, i); i = leb(body, i)[1] if fl & 1 else i
                elif kind == 3: i += 2
                print(m, f)
        elif what == 'funcs' and sid == 0:
            nm, i = name(body, 0)
            if nm != 'name': continue
            while i < len(body):
                sub = body[i]; sz, i = leb(body, i + 1); end = i + sz
                if sub == 1:
                    n, k = leb(body, i)
                    for _ in range(n):
                        _, k = leb(body, k); fn, k = name(body, k); print(fn)
                i = end

main()
