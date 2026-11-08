#!/usr/bin/env python3
"""Fail if docs/VERB-CHAIN.md drops a required name, or a new split *-tx tool is unlisted (issue #11)."""
import os, sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
doc_path = root / "docs/VERB-CHAIN.md"
if not doc_path.is_file() or not doc_path.stat().st_size:
    print("FAIL verb-chain: docs/VERB-CHAIN.md is missing or empty")
    sys.exit(1)
doc = doc_path.read_text()
required = [
    "sol-tron-tx", "xrp-tx", "acct-tx", "xmr-wallet", "xmr-keys", "zec-sapling",
    "tx-build", "tx-sign", "tx-verify", "tx-decode", "tx-broadcast",
    "signing_not_available", "xmr_requires_wallet_rpc", "verify_not_available",
    "broadcast_not_available", "contract-call", "log-decode", "contract-trace",
]
missing = [n for n in required if n not in doc]
if missing:
    print("FAIL verb-chain: docs/VERB-CHAIN.md missing " + ", ".join(missing))
    sys.exit(1)
for name in sorted(os.listdir(root / "tools")):
    if not name.endswith("-tx") or name.startswith("tx-"):
        continue
    if name not in doc:
        print(f"FAIL verb-chain: split tool {name} is not listed in docs/VERB-CHAIN.md")
        sys.exit(1)
print("ok verb-chain")
