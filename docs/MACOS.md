# macOS and arm64

## What CI measures

| Job | Runner | What runs | Status |
|---|---|---|---|
| `macos` (blocking) | macos-latest (arm64) | `gate.sh e2e`, native tools, not sealed | measured (claim e2e-macos) |
| `package-macos` | macos-latest (arm64) | `gate.sh test`, `gate.sh package` | measured (claim package-macos-arm64) |
| `package-linux-arm` | ubuntu-24.04-arm | `gate.sh test`, `gate.sh package` | measured (claim package-linux-aarch64) |

The tarballs are CI artifacts only. release.yml builds and publishes linux-x86_64 only. Not built anywhere:
macOS x86_64, Linux musl. GitHub's macOS runners have no Docker, so CI cannot run the sealed path on a Mac.

## "Sealed on macOS": the definition

On the Mac, `./blocktools run` and `reveal` start the container on a Docker engine that runs **on that Mac**
(Docker Desktop, colima or OrbStack, a `unix://` endpoint; the engine is a Linux VM). The files in `/in` are
the Mac's files. That container has network none, a read-only rootfs, all capabilities dropped, uid 10001,
no-new-privileges, a read-only `/in` whose files reach the tools, and agent output without secret material.
`scripts/macos-sealed-check.sh` checks exactly that (it wraps `scripts/sealed-check.sh`) and prints the
macOS version, the engine endpoint and the server OS/arch it measured.

A remote engine is not "sealed on macOS". With an `ssh://` context (for example Battleaxe), the container
and its `/in` bind mount are on the Linux host, so the tools see that host's directory, not the Mac's (seen
once by hand: empty `/in`). `./blocktools run`/`reveal` refuse such an engine unless
`BLOCKTOOLS_ALLOW_REMOTE=1` (the wrapper now streams `./in` and `./secrets` over `docker exec` stdin into tmpfs instead of bind-mounting,
so with the override they would be copied to that host), and `macos-sealed-check.sh` refuses it outright. That refusal runs in the
macos job with a fake docker (`scripts/e2e.d/wrapper-remote.sh`, `scripts/e2e.d/macos-sealed-refuse.sh`).
With the override, sealing is the Linux host's, which the Linux gate measures (claim sealed-run-linux).

## What is needed from a Mac

Not yet run on any Mac (untested); claim macos-sealed. On the Mac:

1. A local engine, for example `brew install colima docker && colima start` or Docker Desktop running.
   Then `docker context use default` (or `colima`), so `docker context inspect` shows `unix://`.
2. One command, in a checkout at a green main commit (builds the image with that engine, then checks):
   `git pull --ff-only && sh scripts/macos-sealed-check.sh --build >macos-sealed.txt 2>&1; echo rc=$? >>macos-sealed.txt; cat macos-sealed.txt`
3. Keep the whole output. `rc=0` with
   `macos-sealed-check ok` is the measurement. It needs no secrets: it uses the public test mnemonic.
4. Optional: `sh scripts/image-size.sh` for the image size on that engine.

The output (host, engine, commit, every `ok`/`FAIL` line) is what gets stamped into claim macos-sealed.
