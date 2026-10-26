#!/bin/sh
# Reproducible wasm build (ROADMAP: same bytes from any checkout path).
# Cause of the old drift (measured): bindings/wasm is its own cargo workspace, so cargo hashes the
# ABSOLUTE path of the ../../crates path dependencies into -C metadata; symbol hashes then differ by
# checkout path, LLVM inlines differently, and the .wasm bytes change. Panic locations also embed the
# checkout path and $CARGO_HOME. Fix: copy the tracked + untracked-not-ignored sources to one fixed
# path and build there, with --remap-path-prefix for that path and $CARGO_HOME.
# Prints the path of the built .wasm on stdout.
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
B=${BLOCKTOOLS_WASM_BUILD_DIR:-/tmp/blocktools-wasm-build}
CH=${CARGO_HOME:-$HOME/.cargo}
mkdir -p "$B"
if command -v flock >/dev/null; then exec 9>"$B.lock"; flock 9; fi
mkdir -p "$B/src"
# Sync sources (keep $B/src/bindings/wasm/target for incremental builds).
(cd "$src" && git ls-files -z --cached --others --exclude-standard) > "$B/files"
find "$B/src" -path "$B/src/bindings/wasm/target" -prune -o -type f -print | while read -r f; do
  rel=${f#"$B/src/"}; [ -e "$src/$rel" ] || rm -f "$f"; done
# Copy only files whose bytes differ, so cargo's mtime fingerprints see every real change and no
# unchanged file looks new.
(cd "$src" && tr '\0' '\n' < "$B/files" | while IFS= read -r f; do
  [ -f "$f" ] || continue
  cmp -s "$f" "$B/src/$f" 2>/dev/null || { mkdir -p "$B/src/$(dirname "$f")"; cp "$f" "$B/src/$f"; }; done)
cd "$B/src/bindings/wasm"
# The output must land under the fixed path, and a caller's target dir (gate-negatives exports
# CARGO_TARGET_DIR) would both move it and share build state between the two repro builds.
unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR
S=$(printf '\037')
CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$B/src=/blocktools$S--remap-path-prefix=$CH=/cargo" \
CFLAGS_wasm32_unknown_unknown="-ffile-prefix-map=$B/src=/blocktools -ffile-prefix-map=$CH=/cargo" \
  cargo build -q --locked --release --target wasm32-unknown-unknown >&2
echo "$B/src/bindings/wasm/target/wasm32-unknown-unknown/release/blocktools_wasm.wasm"
