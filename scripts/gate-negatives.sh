#!/bin/sh
# finding:R2-9 (docs/FINDINGS.md): gates must test the property; this file proves each rule fires.
# Negative tests for every gate rule: each `neg` plants one violation in a throwaway worktree
# of HEAD, runs the gate script, and requires (a) a non-zero exit and (b) the rule's own FAIL
# message, so a rule that greps for a word instead of testing the property, or that went inert,
# is caught. hygiene-check.sh requires every `# rule:ID` in a gate script to have a `neg ID` here.
# Usage: sh scripts/gate-negatives.sh [ID...]   (needs release binaries in target/release)
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
export LC_ALL=C
cd "$(dirname "$0")/.."
root=$(pwd); base=$(mktemp -d); wt=$base/wt
export CLAIMS_GREEN_CACHE="$base/green.json"  # K-ci: one GitHub API fetch for all the docs-check runs below
export BIN="$root/target/release" CARGO_TARGET_DIR="$root/target"
head0=$(git rev-parse HEAD)
git worktree add -q --detach "$wt" "$head0"
cleanup() { git -C "$root" worktree remove --force "$wt" 2>/dev/null || rm -rf "$wt"; rm -rf "$base"; }  # allow-true: cleanup must not mask the result
trap cleanup EXIT
# fixtures/external is untracked downloaded test data (man examples run against it); copy it into the worktree (1.1 MB).
ext() { if [ -d "$root/fixtures/external" ]; then mkdir -p "$wt/fixtures" && cp -R "$root/fixtures/external" "$wt/fixtures/"; fi; }
ext
reset() { git -C "$wt" reset -q --hard "$head0" && git -C "$wt" clean -fdqx && ext; }  # --hard to the start commit: undoes plants that commit (K-stale)
rc=0; n=0; want=" ${*:-} "
# baseline: each gate script passes on the unplanted tree, else every negative would be vacuous
for s in hygiene-check docs-check prepush-check secret-scan check-deps; do
  (cd "$wt" && sh "scripts/$s.sh") > "$base/out" 2>&1 || { echo "FAIL gate-negatives: baseline $s fails on clean HEAD (full output follows)"; cat "$base/out"; exit 1; }
done
neg() {  # neg ID SCRIPT EXPECTED-SUBSTRING PLANT-SHELL
  id=$1 s=$2 exp=$3 plant=$4
  case "$want" in "  ") ;; *" $id "*) ;; *) return 0;; esac
  n=$((n+1)); reset
  (cd "$wt" && eval "$plant") || { echo "FAIL neg $id: plant step errored"; rc=1; return 0; }
  if (cd "$wt" && sh "scripts/$s.sh") > "$base/out" 2>&1; then echo "FAIL neg $id: $s passed with the violation planted"; rc=1
  elif ! grep -qF -- "$exp" "$base/out"; then echo "FAIL neg $id: $s failed but not with '$exp':"; tail -5 "$base/out"; rc=1
  else echo "ok   neg $id"; fi
}
ADD='git add -f'
# ---- hygiene-check.sh
neg H-fork hygiene-check "fork pull_request selects" 'sed -i "s/github.event.pull_request.head.repo.full_name != github.repository/false/" .github/workflows/ci.yml'
neg H-forkperm hygiene-check "not read-only on pull_request" 'sed -i "s/^  contents: read$/  contents: write/" .github/workflows/ci.yml'
neg H-pin hygiene-check "unpinned actions" 'printf "      - uses: actions/checkout@v4\n" >> .github/workflows/ci.yml'
neg U-untracked hygiene-check "untracked reference" 'x=local-only; echo "dat-read | 2 | dat-read < \"\$R/fixtures/external/$x.dat\"" >> scripts/man-examples.txt'
neg B-bash-sh hygiene-check "bash script run via sh" 'echo "recover.sh | 0 | sh \"\$R/recipes/recover.sh\" s - --goal addresses" >> scripts/man-examples.txt'
neg H-art hygiene-check "tracked build artifacts" 'echo x > junk.zip && $ADD junk.zip'
neg H-relenv hygiene-check "release publish has no environment" 'grep -v "environment: release" .github/workflows/release.yml > t && mv t .github/workflows/release.yml'
neg H-true hygiene-check "unjustified || true" 'printf "#!/bin/sh\nset -eu\nfalse || true\n" > scripts/zz.sh && $ADD scripts/zz.sh'
neg H-seteu hygiene-check "zz.sh: no " 'printf "#!/bin/sh\necho hi\n" > scripts/zz.sh && $ADD scripts/zz.sh'
neg H-wc hygiene-check "BSD-unsafe wc" 'printf "#!/bin/sh\nset -eu\n[ \"\$(wc -l < f)\" = 3 ]\n" > scripts/zz.sh && $ADD scripts/zz.sh'
neg H-sed hygiene-check "GNU-only in-place sed" 'printf "#!/bin/sh\nset -eu\nsed -i s/a/b/ f\n" > scripts/zz.sh && $ADD scripts/zz.sh'
neg H-readlink hygiene-check "GNU-only readlink" 'printf "#!/bin/sh\nset -eu\nreadlink -f x\n" > scripts/zz.sh && $ADD scripts/zz.sh'
neg H-stat hygiene-check "GNU-only stat -c" 'printf "#!/bin/sh\nset -eu\nstat -c %%a x\n" > scripts/zz.sh && $ADD scripts/zz.sh'
neg H-cigate hygiene-check "ci-gate:" 'printf "      - run: cargo test\n" >> .github/workflows/ci.yml'
neg G-yaml hygiene-check "not valid workflow YAML" 'printf "on: push\nconcurrency: { group: ci-\${{ github.ref }}, cancel-in-progress: false }\njobs: {}\n" > .github/workflows/broken.yml'
neg G-stages hygiene-check "stage matrix" 'sed "s/stage: \[lint, test, negatives, e2e, package\]/stage: [lint, test, e2e, package]/" .github/workflows/ci.yml > t && mv t .github/workflows/ci.yml'
neg H-selftest hygiene-check "hygiene self-test" 'sed "s/^WC_PAT=.*/WC_PAT=nevermatches_zz/" scripts/hygiene-check.sh > t && mv t scripts/hygiene-check.sh'
neg H-neg hygiene-check "has no negative test" 'printf "false # rule:Z-none\n" >> scripts/prepush-check.sh'
# ---- docs-check.sh
neg D-tooldoc docs-check "tool zzfake not documented" 'mkdir -p tools/zzfake && echo x > tools/zzfake/f'
neg D-counts docs-check "hard-coded test counts" 'echo "123 tests pass" >> README.md'
neg D-planned docs-check "exists but is called planned" 'echo "**tx-sign** (planned)" >> README.md'
neg X-exit docs-check "FAIL exit rule" 'echo "classify | 0 | echo _status_:_error_ | tr _ \\\"" >> scripts/man-examples.txt'
neg D-sealed docs-check "sealed-run allows utxo-fetch" 'echo utxo-fetch >> crates/io/sealed-tools.txt'
# finding:R2-2 (non-ASCII man page must fail docs-check)
neg D-ascii docs-check "non-ASCII in" 'printf "\342\234\205\n" >> man/man1/tx-sign.1'
neg D-stale docs-check "man/ is stale" 'echo ".\\\" zz" >> man/man1/tx-sign.1'
neg D-guides docs-check "missing or empty docs/cookbook.md" ': > docs/cookbook.md'
neg D-sections docs-check "missing .SH EXAMPLES" 'grep -v "^\.SH EXAMPLES$" man/man1/tx-sign.1 > t && mv t man/man1/tx-sign.1'
neg D-man7 docs-check "man7 missing NAME" 'grep -v "^\.SH NAME$" man/man7/blocktools.7 > t && mv t man/man7/blocktools.7'
neg D-share docs-check "package-dist missing share/man" 'sed "s|share/man|share/zz|g" scripts/package-dist.sh > t && mv t scripts/package-dist.sh'
neg D-share2 docs-check "package-native missing share/man" 'sed "s|share/man|share/zz|g" scripts/package-native.sh > t && mv t scripts/package-native.sh'
neg D-caps docs-check "differs from what the CLIs do" 'sed "s/^| fet | yes | yes | no |/| fet | yes | yes | acct-tx |/" docs/CHAINS.md > t && mv t docs/CHAINS.md'  # fet has no TWC vector: acct-tx refuses it
neg D-caps docs-check "differs from what the CLIs do" 'sed "s/^\(| btc | .*\) | mock only |$/\\1 | regtest bitcoin-25.2 |/" docs/CHAINS.md > t && mv t docs/CHAINS.md'  # btc has no real-node broadcast test: the doc may not claim one
neg D-caps docs-check "pinned in scripts/fork-pins but sign is" 'sed "s/^doge https/eth https/" scripts/fork-pins/doge > scripts/fork-pins/eth'  # a real-node pin on a row tx-build cannot build fails closed
# ---- findings-check.sh (via docs-check)
neg F-guard docs-check "has no guard file" 'sed "s/| R2-5 \\(.*\\) | scripts\\/check-deps-regress.sh |/| R2-5 \\1 | - |/" docs/FINDINGS.md > t && mv t docs/FINDINGS.md'
neg F-token docs-check "does not carry finding:R2-5" 'grep -v "finding:R2-5" scripts/check-deps-regress.sh > t && mv t scripts/check-deps-regress.sh'
neg F-commit docs-check "is not a commit" 'sed "s/| bb1ceff |/| 0000000 |/" docs/FINDINGS.md > t && mv t docs/FINDINGS.md'
# finding:R2-8 claims registry: an unregistered doc number must fail docs-check.
neg K-unreg docs-check "unregistered claim" 'echo "The cache holds 77 MB." >> docs/ROADMAP.md'
# K-agree: README number disagrees with the registry value.
neg K-agree docs-check "does not carry" 'sed -i "s/^value = \"[0-9.]*\"/value = \"31.0\"/" docs/claims.toml'  # any measured number: the pinned 45.3 went inert when the image was re-measured (46.1)
# K-assert: a registry-untested claim stated as fact (marker removed from its doc line) must fail.
neg K-assert docs-check "as fact" 'sed -i "s/(reviewer report, not reproduced by us) (untested)/(reviewer report, not reproduced by us) verified/" README.md'
neg K-gone docs-check "not found in" 'sed "s/0\.01 ETH/one hundredth ETH/g" docs/SECURITY.md > t && mv t docs/SECURITY.md'
neg K-fields docs-check "bad status" 'sed "0,/status = \"measured\"/s//status = \"verified\"/" docs/claims.toml > t && mv t docs/claims.toml'
neg K-stale docs-check "re-measure" 'echo "// x" >> crates/tx/src/policy.rs && git -c user.name=n -c user.email=n@n commit -qam plant'
neg K-stale docs-check "image-size-readme" 'python3 -c "import re;p=\"docs/claims.toml\";s=open(p).read();i=s.index(\"id = \\\"image-size-readme\\\"\");j=s.index(\"[[claim]]\",i);open(p,\"w\").write(s[:i]+s[i:j].replace(\"status = \\\"untested\\\"\",\"status = \\\"measured\\\"\\ncommit = \\\"f2e066a\\\"\\ndate = \\\"2026-10-26\\\"\")+s[j:])" && echo "# x" >> crates/io/sealed-tools.txt && git -c user.name=n -c user.email=n@n commit -qam plant'  # sealed image contents change: image claims go stale
neg K-run docs-check "expected" 'printf "[[claim]]\nid = \"z\"\nstatement = \"z\"\nkind = \"security\"\nplatform = \"linux\"\nstatus = \"measured\"\ncommand = \"false\"\nexpect = \"ok\"\ncommit = \"%s\"\ndate = \"d\"\ncheap = true\ndoc = []\n" $(git rev-parse --short HEAD) >> docs/claims.toml'
neg K-fallback docs-check "measured via a fallback path" 'mkdir -p target/x86_64-unknown-linux-musl/release && printf "[[claim]]\nid = \"z\"\nstatement = \"z\"\nkind = \"number\"\nplatform = \"docker\"\nstatus = \"measured\"\ncommand = \"sh scripts/image-size.sh --binary-sum\"\nexpect = \"\"\ncommit = \"%s\"\ndate = \"d\"\ncheap = true\ndoc = []\n" $(git rev-parse --short HEAD) >> docs/claims.toml'
neg K-macos docs-check "without a ci_run" 'printf "[[claim]]\nid = \"z\"\nstatement = \"z\"\nkind = \"platform\"\nplatform = \"macos\"\nstatus = \"measured\"\ncommand = \"true\"\nexpect = \"\"\ncommit = \"%s\"\ndate = \"d\"\ndoc = []\n" $(git rev-parse --short HEAD) >> docs/claims.toml'
neg K-label docs-check "is not labelled" 'sed "/image is 18\.2 MB\./s/ (unmeasured)//" DESIGN.md > t && mv t DESIGN.md'
# K-ci: a claim stamped at a commit with no completed successful ci run on main (here a fresh commit) must fail.
neg K-ci docs-check "no successful ci run on main" 'git -c user.name=n -c user.email=n@n commit -q --allow-empty -m plant && sed "0,/^commit = \"1f1fa71\"/s//commit = \"$(git rev-parse --short HEAD)\"/" docs/claims.toml > t && mv t docs/claims.toml'
# K-agree (expect vs statement): the measured output in expect names a byte count the statement does not carry.
neg K-agree docs-check "but the statement does not" 'sed "/^id = \"redact-512\"/,/^expect/s/^expect = \"\(.*\)\"/expect = \"\1; 99999 bytes\"/" docs/claims.toml > t && mv t docs/claims.toml'  # a measured number claim; was image-size-readme (pending re-stamp)
neg K-render docs-check "out of date" 'echo stale >> docs/CLAIMS.md'
neg F-status docs-check "unknown status" 'sed "s/| R1-5 \\(.*\\) | open |/| R1-5 \\1 | wontfix |/" docs/FINDINGS.md > t && mv t docs/FINDINGS.md'
neg F-dup docs-check "duplicate ids" 'grep "^| R1-2 " docs/FINDINGS.md > t && cat t >> docs/FINDINGS.md && rm t'
neg F-rows docs-check "no rows in" 'grep -Ev "^\| [A-Z][0-9]+-[0-9]+ \|" docs/FINDINGS.md > t && mv t docs/FINDINGS.md'
neg F-file docs-check "findings: no docs/FINDINGS.md" 'rm docs/FINDINGS.md'
# ---- prepush-check.sh
neg P-untracked prepush-check "untracked files" 'echo x > zz-untracked.txt'
neg P-unstaged prepush-check "unstaged changes" 'echo x >> README.md'
neg P-large prepush-check "large file" 'head -c 2200000 /dev/zero | tr "\0" a > big.txt && $ADD big.txt'
neg P-binary prepush-check "binary file tracked" 'printf "a\0b" > bin.txt && $ADD bin.txt'
# ---- secret-scan.sh (planted values are random-looking but are NOT keys: built at runtime)
neg S-key secret-scan "UNLISTED secret-shaped" 'printf "%064d\n" 0 | tr 0 a > zz.txt && $ADD zz.txt'
neg S-path secret-scan "personal path/email" 'echo "/Us""ers/zz/x" > zz.txt && $ADD zz.txt'
neg S-walletname secret-scan "wallet-like file name" 'echo x > wallet1.txt && $ADD wallet1.txt'
neg S-sqlite secret-scan "SQLite file" 'printf "SQLite format 3\0padpadpad" > zz.txt && $ADD zz.txt'
neg S-bdb secret-scan "Berkeley DB file" 'printf "\0\0\0\0\0\0\0\0\0\0\0\0\142\61\5\0pad" > zz.txt && $ADD zz.txt'
neg S-pem secret-scan "PEM private key block" 'printf -- "-----BEGIN"" PRIVATE KEY-----\nzz\n" > zz.txt && $ADD zz.txt'
neg S-pgp secret-scan "PGP private key block" 'printf -- "-----BEGIN PGP"" PRIVATE KEY BLOCK-----\nzz\n" > zz.txt && $ADD zz.txt'
neg C-allow check-deps "new deps not in" 'tail -n +2 deps/blocktools-core.allow > t && mv t deps/blocktools-core.allow'
neg C-renamed check-deps "deprecated crate name in Cargo.lock" 'printf "\n[[package]]\nname = \"sha-1\"\nversion = \"0.10.1\"\n" >> Cargo.lock'
neg C-facade check-deps "default features pull secret/network crates" 'sed "s/^default = \[\]/default = [\"secrets\"]/" crates/blocktools/Cargo.toml > t && mv t crates/blocktools/Cargo.toml'
# W-repro plants the original drift mechanism: the build dir hashed into every crate's -C metadata.
neg W-repro wasm-check "FAIL wasm not reproducible" 'sed -i "s|=/cargo\"|=/cargo\$S-Cmetadata=\$B\"|" scripts/wasm-build.sh'
# ---- check-deps.sh: planted network crate + stale lock live in check-deps-regress.sh (C-net, C-stale)
case "$want" in "  "|*" C-net "*|*" C-stale "*) n=$((n+1)); sh scripts/check-deps-regress.sh > "$base/out" 2>&1 && echo "ok   neg C-net C-stale (check-deps-regress.sh)" || { echo "FAIL neg C-net/C-stale"; tail -5 "$base/out"; rc=1; };; esac
# finding:R2-12 shallow clone (CI checkout default): history-based checks must refuse, not misreport.
case "$want" in "  "|*" F-shallow "*)
  n=$((n+1)); sc="$base/shallow"; rm -rf "$sc"
  git clone -q --depth 1 "file://$PWD" "$sc"
  if (cd "$sc" && sh scripts/findings-check.sh) > "$base/out" 2>&1; then echo "FAIL neg F-shallow: findings-check passed in a shallow clone"; rc=1
  elif ! grep -qF "shallow clone" "$base/out"; then echo "FAIL neg F-shallow: failed but not with 'shallow clone':"; tail -3 "$base/out"; rc=1
  else echo "ok   neg F-shallow"; fi
  rm -rf "$sc";;
esac
[ $rc = 0 ] && echo "gate-negatives ok ($n planted violations caught)"
exit $rc
