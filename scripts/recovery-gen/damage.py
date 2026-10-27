# Realistic damage to a seed phrase. argv: kind wordlist(bip39|electrum) ; stdin: phrase. stdout: damaged phrase.
# typo = one word loses a letter (first word from the end whose result is not a list word); swap = words 7,8
# exchanged; missing = word 11 dropped; unknown = word 5 replaced by '?'.
import sys
from mnemonic import Mnemonic
kind = sys.argv[1]; w = sys.stdin.read().split(); words = set(Mnemonic('english').wordlist)
if kind == 'typo':
    for i in range(len(w) - 2, -1, -1):
        t = w[i][:1] + w[i][2:]
        if t not in words and len(t) >= 3: w[i] = t; break
elif kind == 'swap': w[6], w[7] = w[7], w[6]
elif kind == 'missing': del w[10]
elif kind == 'unknown': w[4] = '?'
print(' '.join(w))
