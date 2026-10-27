# Realistic damage to a seed phrase. argv: kind wordlist(bip39|electrum) ; stdin: phrase. stdout: damaged phrase.
# typo = one word loses a letter (first word from the end whose result is not a list word); swap = first adjacent pair from
# words 7/8 whose swap fails the checksum; missing = word 11 dropped; unknown = word 5 replaced by '?'.
import sys
from mnemonic import Mnemonic
kind = sys.argv[1]; w = sys.stdin.read().split(); words = set(Mnemonic('english').wordlist)
if kind == 'typo':
    for i in range(len(w) - 2, -1, -1):
        t = w[i][:1] + w[i][2:]
        if t not in words and len(t) >= 3: w[i] = t; break
elif kind == 'swap':
    # Adjacent swap from words 7/8 on whose result FAILS the BIP39 checksum. A swap that still passes the
    # checksum (~1 in 16) is undetectable: seed-repair reports checksum_ok and searches nothing (see README).
    m = Mnemonic('english')
    for i in range(6, len(w) - 1):
        v = w[:]; v[i], v[i + 1] = v[i + 1], v[i]
        if v[i] != v[i + 1] and not m.check(' '.join(v)): w = v; break
elif kind == 'missing': del w[10]
elif kind == 'unknown': w[4] = '?'
print(' '.join(w))
