#!/usr/bin/env python3
"""Run every recipe example in recipes/*.md against public dummy vectors (no network but a
127.0.0.1 mock chain). A tested example is an HTML comment followed by a 4-space-indented command:

    <!-- e2e: expect=bc1q... ; expect=... ; rc=0 ; fund=ADDR ; needs=wallet.dat -->
        ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc'

`./blocktools run '<pipeline>'` runs through the real agent boundary (target/release/sealed-run
agent). `recipes/recover.sh ...` runs the front door (fund= funds one address on the mock chain and
appends --url). A command starting with jq/sig-hash/abi-decode/abi-encode/create-address/log-decode/tx-build/tx-verify is an
offline EVM pipeline on recipes/fixtures/ run by bash with BIN first on PATH; contract-call $ETH/<prefix> ...
talks to a 127.0.0.1 mock node that answers with the recorded fixture <prefix>-*.json.
/in/ and /secrets/ map to a temp dir of vectors made here. Checks: exit code,
every expect substring in stdout+stderr, and no secret value in stdout (public fields stripped).
Every recipe file except README.md must carry at least one tested example.
usage: recipe-check.py BIN_DIR TMP_DIR"""
import os, re, shlex, shutil, subprocess, sys, time
# Offline filters a recipe pipeline may run (also the only commands allowed after `curl ... |`).
TOOLS = ("jq", "sig-hash", "abi-decode", "abi-encode", "create-address", "abi-inspect", "bytecode-inspect", "typed-data-verify", "log-decode",
         "contract-call", "contract-trace", "tx-build", "tx-verify", "utxo-set", "wallet-finder", "multisig", "bolt11")
CURL_OPTS_ARG = {"-X", "-H", "--data", "--data-raw", "-d"}; CURL_OPTS = {"-s", "-sS", "-S", "--silent", "--fail", "-f"}
def curl_shape(cmd, eth):
    """None when `cmd` is exactly `curl [opts] $ETH/<prefix>... | FILTER ... [| FILTER ...]`, else the reason.
    Only the 127.0.0.1 fixture mock ($ETH) may be fetched; no command lists, substitutions or redirects."""
    if re.search(r"`|\$\(|\$\{", cmd): return "command substitution"
    if any(m.group(0) != "$ETH/" for m in re.finditer(r"\$\w*/?", cmd)): return "only $ETH/ may be expanded"
    lx = shlex.shlex(cmd, posix=True, punctuation_chars=";&|<>()"); lx.whitespace_split = True
    try: toks = list(lx)
    except ValueError as e: return f"unparsable: {e}"
    segs = [[]]
    for t in toks:
        if t == "|": segs.append([])
        elif t and set(t) <= set("|&;<>()"): return f"shell operator {t!r}"
        else: segs[-1].append(t)
    first, rest = segs[0], segs[1:]
    if not first or first[0] != "curl" or not rest: return "must be: curl ... $ETH/PREFIX | FILTER"
    urls, i = [], 1
    while i < len(first):
        t = first[i]
        if t in CURL_OPTS_ARG and i + 1 < len(first): i += 2; continue
        if t in CURL_OPTS: i += 1; continue
        if t.startswith("-"): return f"curl option {t!r} not allowed"
        urls.append(t); i += 1
    if not urls or any(not u.startswith("$ETH/") or not (u.replace("$ETH", eth, 1)).startswith(eth + "/") for u in urls): return "every curl URL must start with $ETH/"
    if re.search(r"https?://", cmd): return "literal http(s) URL"
    for sg in rest:
        if not sg or sg[0] not in TOOLS: return f"pipe target {sg[:1]} not an offline filter"
    return None
if sys.argv[1:] == ["--self-test"]:
    E = "http://127.0.0.1:1"; good = "curl -s -X POST -H 'Content-Type: application/json' --data '{\"id\":1}' $ETH/01a | jq -r .result | abi-decode"
    assert curl_shape(good, E) is None, curl_shape(good, E)
    for b in ["curl https://example.com/x ; curl $ETH/01a | jq .", "curl $ETH/01a | jq . ; curl https://e.com", "curl $ETH/01a && rm -rf x | jq .",
              "curl $ETH/01a || true | jq .", "curl $ETH/$(id) | jq .", "curl `id` $ETH/01a | jq .", "curl https://evil/ $ETH/01a | jq .", "curl evil.example $ETH/01a | jq .",
              "curl $ETH/01a -o /tmp/x | jq .", "curl $ETH/01a | sh", "curl $ETH/01a > /tmp/x", "curl $HOME/x $ETH/01a | jq .",
              "curl $ETH/01a | jq . & curl https://e.com", "curl -K cfg $ETH/01a | jq .", "curl $ETH/01a"]:
        assert curl_shape(b, E) is not None, f"accepted: {b}"
    print("recipe-check self-test ok"); sys.exit(0)
B, T = sys.argv[1], sys.argv[2]
VD = os.path.join(T, "recipes"); IN = os.path.join(VD, "in"); SEC = os.path.join(VD, "secrets")
os.makedirs(IN, exist_ok=True); os.makedirs(SEC, mode=0o700, exist_ok=True)
MOCK = ["cargo", "run", "-q", "--offline", "--release", "-p", "blocktools-tx", "--example", "mock-utxo", "--"]
def w(d, n, s): open(os.path.join(d, n), "w").write(s + "\n")
# Public test vectors only (BIP39/84 spec mnemonic, Electrum's test seed, key 1, xrpl.js and
# monero-python fixtures, Ethereum's keystore test vector).
w(IN, "seed.txt", "abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot")
w(IN, "electrum-seed.txt", "cycle rocket west magnet parrot shuffle foot correct salt library feed song")
# Electrum 1.x old seed (Electrum tests test_electrum_seed_old), the xkcd brainwallet, keybase/warpwallet spec.json #1
w(IN, "electrum-old-seed.txt", "powerful random nobody notice nothing important anyway look away hidden message over")
w(IN, "brainwallet.txt", "correct horse battery staple")
# utxo-set / wallet-finder: the committed Core-format dump of the five public test-vector scripts, and text hiding the phrase
open(os.path.join(IN, "utxo.dat"), "wb").write(bytes.fromhex("".join(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "utxo", "brainwallet-5.utxo-hex.txt")).read().split())))  # tracked as hex: no binary files in git
w(IN, "notes.txt", "Shopping: eggs, milk.\nMy old note: correct horse battery staple. Do not lose it")
w(IN, "addresses.txt", "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T\n1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
w(IN, "warpwallet.json", '{"phrase":"ER8FT+HFjk0","salt":"7DpniYifN6c"}')
w(IN, "key.hex", "0" * 63 + "1")
w(IN, "key.wif", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
# Mock UTXO lists for offline tx-build examples: one 0.01-coin output (qtum: 1 QTUM, since its 700 sat/vB fee is 13% of 0.01) at key 1's address (txid all 'c').
for _c, _a in [("ppc", "PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9"), ("nvc", "4QP6S2Gv3WZmgnJgR8mshrbHA9W6hQiTxR"),
               ("clam", "xJyuT2j5dnLoBhHraFjzG2hmMDjnS3fefx"), ("rdd", "RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa"),
               ("blk", "BF8MAsLp7aSfb9g9qGSHwzDerit8nAZAJX"), ("zec", "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs"),
               ("qrk", "QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59"), ("xpm", "AST9CekEhDWuxHPynRmeyjg5biNFSijvb3"),
               ("qtum", "QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59"),
               ("doge", "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE"),  # key 1 (thorchain-swap-utxo.md inbound)
               ("grs", "grs1qw508d6qejxtdg4y5r3zarvary0c5xw7k3k4sj5"),
               ("bcc", "8XFa9Ce4Pf6d3Rvpr3jnp6sm8279Ec1V92")]:  # legacy-bcc.dat key 1 (make-fixtures.py)
    # Each line carries a synthetic prev_tx (legacy inputs must prove their amount; see SECURITY.md).
    if _c == "zec":  # ZIP-243/244 sighash commits to the amount: a lying amount only yields an invalid signature
        w(IN, "u-zec.json", '{"txid":"' + "c" * 64 + '","vout":1,"amount":1000000,"address":"' + _a + '"}'); continue
    w(IN, f"u-{_c}.json", subprocess.run(MOCK + [_c, "1", "500000000" if _c == "doge" else "100000000" if _c == "qtum" else "1000000", _a],
                                         check=True, capture_output=True, text=True).stdout.strip())
# BIP84 spec mnemonic (abandon x11 about) root key in xprv form (same key as BIP84's zprvAWgYBBk7...).
w(IN, "xprv.txt", "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
# Public BIE1 vector (scripts/electrum-bie1-gen.py, pw blocktools-bie1-test): decrypts, holds no keystore.
w(IN, "electrum-bie1-nokeys", "QklFMQP5c6C4cGLDidEl2BmegDuDK2rGv3hnpPbNh1BgYPxMWK0baBcm30a4MYvrXX0n8QXwd98GGE3NTj0ntXbfB5FfKdhKhYV7otO7SQiFvUrSzMzAeC9MQG+4FdNhjn9Ohxmuk9m1ZjliG6izoUXpBl2U9E7iSbSKl7oy7tiYBdCERiVq/YlWwbsqlyW7cLcfZRp5NhbVfpwiHEA/qfv+aPNJ")
w(IN, "grs-tpub.txt", "tpubDMBn7xW1g1Gsok5eThkJAKJnB3ZFqZQnvsdWv8VvM3RjZkqVPZZpjPDAAmbyDHnZPdAZY8EnFBh1ibTBtiuDqb8t9wRcAZiFihma41vfyVK")
w(IN, "xrp-seed.txt", "sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r")
w(IN, "xmr-seed.txt", "adjust mugged vaults atlas nasty mews damp toenail suddenly toxic possible framed succeed fuzzy return demonstrate nucleus album noises peculiar virtual rowboat inorganic jester fuzzy")
# Stellar SEP-0005 vector 1 mnemonic; its m/44'/148'/0' StrKey seed is derived here in Python
# (PBKDF2 + SLIP-0010 + CRC16-XModem), independently of the Rust code.
XM = "illness spike retreat truth genius clock brain pass fit cave bargain toe"; w(IN, "xlm-mnemonic.txt", XM)
def _xlm_seed(m):
    import hashlib, hmac, base64
    k = hmac.new(b"ed25519 seed", hashlib.pbkdf2_hmac("sha512", m.encode(), b"mnemonic", 2048), "sha512").digest()
    for i in (44, 148, 0):
        k = hmac.new(k[32:], b"\0" + k[:32] + (i | 0x80000000).to_bytes(4, "big"), "sha512").digest()
    d = bytes([18 << 3]) + k[:32]; c = 0
    for b in d:
        c ^= b << 8
        for _ in range(8): c = ((c << 1) ^ 0x1021) & 0xffff if c & 0x8000 else (c << 1) & 0xffff
    return base64.b32encode(d + c.to_bytes(2, "little")).decode().rstrip("=")
w(IN, "xlm-seed.txt", _xlm_seed(XM))
w(IN, "atom-mnemonic.txt", "special sign fit simple patrol salute grocery chicken wheat radar tonight ceiling")
w(IN, "algo-mnemonic.txt", "advice pudding treat near rule blouse same whisper inner electric quit surface sunny dismiss leader blood seat clown cost exist hospital century reform able sponsor")
w(IN, "dot-mnemonic.txt", "caution juice atom organ advance problem want pledge someone senior holiday very")
w(IN, "ton-mnemonic.txt", "elbow ramp code slogan cigar note auto solution leaf bunker process essence armed burger item blossom achieve normal vault whip switch artefact parrot coffee")
w(IN, "ada-mnemonic.txt", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
w(IN, "address.txt", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
w(IN, "xpub.txt", "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
w(IN, "keystore.json", re.search(r'const V: &str = r#"(.*?)"#;', open("crates/secrets/src/keystore.rs").read()).group(1))
subprocess.run([sys.executable, "scripts/make-fixtures.py", IN], check=True, stdout=subprocess.DEVNULL)
shutil.copy(os.path.join(IN, "descriptor-encrypted.sqlite"), os.path.join(IN, "wallet.dat"))
shutil.copy("crates/tx/tests/vectors/block170.hex", os.path.join(IN, "block170.hex"))
w(IN, "passphrases.txt", "TREZOR")  # public BIP39 test-vector passphrase
w(IN, "targets.txt", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf")
# Public BIP39 test vector with one word dropped (position 5) and with the last word unknown ("?").
w(IN, "seed-missing.txt", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
w(IN, "seed-unknown.txt", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?")
w(IN, "targets-eth.txt", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
for src, dst in [("fixtures/external/electrum4_4_3_unencrypted", "electrum-wallet"), ("fixtures/external/multibit-wallet.key", "multibit.key"), ("fixtures/external/electrum-wallet", "electrum1-wallet"), ("fixtures/external/electrum28-wallet", "electrum-bie1-wallet"),
                 ("fixtures/external/multibit.wallet.bitcoinj.encrypted", "bitcoinj.wallet"), ("fixtures/external/multibit.wallet.bitcoinj.clear", "bitcoinj-clear.wallet"),
                 ("fixtures/external/bitcoincore-wallet.dat", "old-client-wallet.dat"), ("fixtures/external/armory-wallet.wallet", "armory.wallet")]:
    if os.path.exists(src): shutil.copy(src, os.path.join(IN, dst))
for n, p in [("wallet.pw", "blocktools-test-password"), ("keystore.pw", "testpassword"), ("electrum.pw", "btcr-test-password"), ("bie1.pw", "blocktools-bie1-test"),
             ("multibit.pw", "btcr-test-password"), ("armory.pw", "btcr-test-password"), ("empty.pw", "")]:
    w(SEC, n, p)
secret_values = [open(os.path.join(IN, f)).read().strip() for f in ("seed.txt", "electrum-seed.txt", "key.hex", "key.wif", "xrp-seed.txt", "xmr-seed.txt", "xlm-mnemonic.txt", "xlm-seed.txt", "atom-mnemonic.txt", "algo-mnemonic.txt", "dot-mnemonic.txt", "ton-mnemonic.txt", "ada-mnemonic.txt")]
LEAK = re.compile(r'"(wif|private_key|xprv|seed|mnemonic|passphrase|password|secret|view_secret|spend_secret)":"[^\[]|xprv[1-9A-Za-z]{20}|abandon|illness spike|special sign fit|advice pudding|caution juice|elbow ramp|"S[A-Z2-7]{55}"')
PUBLIC = re.compile(r'"(address|x_address|spend_public|view_public|public|psbt|unsigned|txid|xpub|fp)":"[^"]*"')
# mock chain for --goal balance
pf, lf, ff = (os.path.join(T, n) for n in ("rc-port", "rc-log", "rc-funded")); open(ff, "w").close()
mock = subprocess.Popen([sys.executable, "scripts/mock-chain.py", pf, lf, os.path.join(T, "rc-noexp")], env={**os.environ, "MOCK_FUNDED": ff},
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
while not (os.path.exists(pf) and os.path.getsize(pf)): time.sleep(0.05)
RU = "http://127.0.0.1:" + open(pf).read().strip()
# mock EVM node for contract-call examples: $ETH/<fixture-prefix> answers eth_chainId with 0x1 (mainnet, where the
# fixtures were recorded) and any other method with that recorded fixture (recipes/fixtures/evm-mainnet/<prefix>*.json)
import http.server, json, threading
class _Eth(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        fx = [f for f in os.listdir("recipes/fixtures/evm-mainnet") if f.startswith(self.path.strip("/") + "-")]
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x1"}) if req.get("method") == "eth_chainId" else \
            open("recipes/fixtures/evm-mainnet/" + fx[0]).read() if len(fx) == 1 else '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no fixture"}}'
        b = body.encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
_eth = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Eth); threading.Thread(target=_eth.serve_forever, daemon=True).start()
ETH = f"http://127.0.0.1:{_eth.server_address[1]}"
def sub(s): return s.replace("/in/", IN + "/").replace("/secrets/", SEC + "/").replace("$ETH", ETH)
ok = skipped = 0; bad = []
try:
    # recipes/*.md plus the two front-door pages, so their worked examples cannot rot either
    docs = [os.path.join("recipes", f) for f in sorted(os.listdir("recipes")) if f.endswith(".md") and f != "README.md"]
    for f in docs + ["README.md", "docs/getting-started.md"]:
        lines = open(f).read().split("\n"); n_here = 0
        for i, l in enumerate(lines):
            m = re.match(r"\s*<!-- e2e:(.*)-->\s*$", l)
            if not m: continue
            opts = [o.strip() for o in m.group(1).split(" ; ") if o.strip()]
            want = [o[7:] for o in opts if o.startswith("expect=")]
            rc = int(next((o[3:] for o in opts if o.startswith("rc=")), "0"))
            fund = next((o[5:] for o in opts if o.startswith("fund=")), None)
            needs = [o[6:] for o in opts if o.startswith("needs=")]
            cmd = next(x for x in lines[i + 1:] if x.strip()).strip(); where = f"{f}:{i + 2}"
            n_here += 1
            if any(not os.path.exists(os.path.join(IN, x)) for x in needs):
                print(f"skip recipe {where}: needs {needs} (scripts/fetch-fixtures.sh)"); skipped += 1; continue
            if cmd.startswith("./blocktools run '") and cmd.endswith("'"):
                argv = [os.path.join(B, "sealed-run"), "agent", sub(cmd[len("./blocktools run '"):-1])]
            elif cmd.startswith("recipes/recover.sh "):
                argv = ["bash", "recipes/recover.sh"] + [sub(a) for a in shlex.split(cmd)[1:]]
                if fund: open(ff, "w").write(fund + "\n"); argv += ["--url", RU]
            elif re.match(r"(" + "|".join(TOOLS) + ") ", cmd):
                # offline, secret-free filters on recorded fixtures (contract-call: against the $ETH fixture mock; utxo-set/wallet-finder: public UTXO dump, no keys out): bash with BIN on PATH
                argv = ["bash", "-o", "pipefail", "-c", sub(cmd)]
            elif cmd.startswith("curl "):
                # fetch-then-decode examples: one curl, only to the 127.0.0.1 $ETH fixture mock, piped into offline filters
                why = curl_shape(cmd, ETH)
                if why: bad.append(f"{where}: curl example refused ({why}): {cmd}"); continue
                argv = ["bash", "-o", "pipefail", "-c", sub(cmd)]
            else:
                bad.append(f"{where}: untestable command form: {cmd}"); continue
            env_path = {"PATH": os.path.abspath(B) + os.pathsep + os.environ.get("PATH", "")} if argv[0] == "bash" and argv[1] == "-o" else {}
            p = subprocess.run(argv, capture_output=True, text=True, env={**os.environ, "BIN": B, **env_path}, stdin=subprocess.DEVNULL, timeout=120)
            both = p.stdout + p.stderr; stripped = PUBLIC.sub("", p.stdout)
            errs = [f"exit {p.returncode} != {rc}"] if p.returncode != rc else []
            errs += [f"missing {x!r}" for x in want if x not in both]
            if LEAK.search(stripped) or any(v in p.stdout for v in secret_values): errs.append("SECRET IN STDOUT")
            if errs: bad.append(f"{where}: {'; '.join(errs)}\n{both[-1500:]}")
            else: ok += 1; print(f"ok  recipe {where}: {cmd[:90]}")
        if n_here == 0: bad.append(f"{f}: no tested example (<!-- e2e: ... -->)")
finally:
    mock.kill()
for b in bad: print("FAIL recipe " + b)
print(f"recipes: {ok} examples ok, {skipped} skipped, {len(bad)} failed")
sys.exit(1 if bad else 0)
