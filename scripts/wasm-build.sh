#!/bin/sh
# Reproducible wasm build (same bytes from any checkout path and any build dir; Linux-measured).
# Cause of the old drift (measured): bindings/wasm is its own cargo workspace, so cargo hashes the
# ABSOLUTE path of the ../../crates path dependencies into -C metadata; symbol hashes then differ by
# checkout path, LLVM inlines differently, and the .wasm bytes change. Panic locations also embed the
# checkout path and $CARGO_HOME. Fix: copy the tracked + untracked-not-ignored sources to a build
# path, and in that copy make the copy's ROOT a one-member workspace holding bindings/wasm (manifest
# rewritten below), so every path dependency sits inside the workspace and cargo hashes it by its
# RELATIVE path. Build with --remap-path-prefix for the build path and $CARGO_HOME. The build path
# then no longer reaches the bytes: scripts/wasm-check.sh builds twice in two DIFFERENT build dirs.
# Prints the path of the built .wasm on stdout.
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
B=${BLOCKTOOLS_WASM_BUILD_DIR:-/tmp/blocktools-wasm-build}
CH=${CARGO_HOME:-$HOME/.cargo}
mkdir -p "$B"
if command -v flock >/dev/null; then exec 9>"$B.lock"; flock 9; fi
mkdir -p "$B/src"
# Sync sources (keep $B/src/target for incremental builds). The three manifests generated below are
# not synced.
(cd "$src" && git ls-files -z --cached --others --exclude-standard) > "$B/files"
find "$B/src" -path "$B/src/target" -prune -o -type f -print | while read -r f; do
  rel=${f#"$B/src/"}; [ -e "$src/$rel" ] || rm -f "$f"; done
# Copy only files whose bytes differ, so cargo's mtime fingerprints see every real change and no
# unchanged file looks new.
(cd "$src" && tr '\0' '\n' < "$B/files" | while IFS= read -r f; do
  [ -f "$f" ] || continue
  case $f in Cargo.toml|Cargo.lock|bindings/wasm/Cargo.toml) continue ;; esac
  cmp -s "$f" "$B/src/$f" 2>/dev/null || { mkdir -p "$B/src/$(dirname "$f")"; cp "$f" "$B/src/$f"; }; done)
# Generated manifests: root = workspace with the wasm crate as its only member, the wasm crate's own
# lock file and release profile moved up to it. Written only when the bytes change (mtime fingerprints).
put() { if ! cmp -s "$1" "$2" 2>/dev/null; then cp "$1" "$2"; fi; rm -f "$1"; }
# The crates inherit [workspace.package] / [workspace.dependencies] from the main root manifest, so
# those sections are kept; its members list and release profile are not (the wasm crate's profile is).
{ printf '[workspace]\nresolver = "2"\nmembers = ["bindings/wasm"]\n\n'
  sed -n '/^\[workspace\.package\]/,/^\[profile/p' "$src/Cargo.toml" | sed '/^\[profile/d'
  sed -n '/^\[profile\.release\]/,/^$/p' "$src/bindings/wasm/Cargo.toml"; } > "$B/root.toml"
sed -e '/^\[workspace\]$/d' -e '/^\[profile\.release\]/,/^$/d' "$src/bindings/wasm/Cargo.toml" > "$B/wasm.toml"
# Path crates under the copy's root become implicit members, so the lock covers their dev and optional
# deps too: merge the two committed locks (scripts/wasm-lock-merge.py), never resolve anew.
python3 "$src/scripts/wasm-lock-merge.py" "$src/Cargo.lock" "$src/bindings/wasm/Cargo.lock" > "$B/lock"
put "$B/root.toml" "$B/src/Cargo.toml"; put "$B/wasm.toml" "$B/src/bindings/wasm/Cargo.toml"; put "$B/lock" "$B/src/Cargo.lock"
cd "$B/src"
unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR CARGO_PROFILE_RELEASE_LTO  # LTO comes from bindings/wasm/Cargo.toml, never the gate (scripts/gate.sh)
cargo metadata -q --format-version 1 >/dev/null  # prunes the merged lock to what is used
# The wasm crate's resolved tree (versions + features) must equal what its own committed lock gives.
tree() { p=$1; shift; cargo tree -q --locked --target wasm32-unknown-unknown -e normal,build,features --prefix none "$@" \
  | sed -e "s| ($p/| (|" -e 's| (\*)||' | sort -u; }
t1=$(cd "$src/bindings/wasm" && tree "$src"); t2=$(tree "$B/src" -p blocktools-wasm)
[ "$t1" = "$t2" ] || { echo "wasm-build: build-copy dependency tree differs from bindings/wasm/Cargo.lock" >&2; exit 1; }
# The output must land under the build dir, and a caller's target dir (gate-negatives exports
# CARGO_TARGET_DIR) would both move it and share build state between the two repro builds (unset above).
S=$(printf '\037')
CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$B/src=/blocktools$S--remap-path-prefix=$CH=/cargo" \
CFLAGS_wasm32_unknown_unknown="-ffile-prefix-map=$B/src=/blocktools -ffile-prefix-map=$CH=/cargo" \
  cargo build -q --locked --release --target wasm32-unknown-unknown -p blocktools-wasm >&2
echo "$B/src/target/wasm32-unknown-unknown/release/blocktools_wasm.wasm"
