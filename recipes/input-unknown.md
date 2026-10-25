# Input: "I don't know what this is"

Start with `classify`. It names the type and prints a fingerprint (first/last 4 hex of a SHA-256) for
secrets, and echoes only public items (addresses, xpubs). `recipes/recover.sh` runs it first and
switches on the class. Supported classes are listed in recipes/README.md, under "By input".

<!-- e2e: expect="class":"xrp_seed" -->
    ./blocktools run 'classify /in/xrp-seed.txt'

<!-- e2e: expect="class":"monero_seed" -->
    ./blocktools run 'classify /in/xmr-seed.txt'

<!-- e2e: expect="class":"address" -->
    ./blocktools run 'classify /in/address.txt'
