# Language wrappers (secrets-off C ABI)

Thin wrappers over `crates/cabi` (`libblocktools_c` + `include/blocktools.h`).
Public data only: `bt_version`, `bt_chain_table`, `bt_envelope`, `bt_free`.

Build the library first:

```sh
cargo build -p blocktools-c --release
```

| Lang | Path | Smoke test |
|------|------|------------|
| Python | `bindings/python/blocktools.py` | `python3 bindings/python/test_blocktools.py` |
| Go | `bindings/go/blocktools` | `cd bindings/go && go test ./blocktools` |
| C++ | `bindings/cpp/blocktools.hpp` | see below |
| Zig | `bindings/zig/blocktools.zig` | see below |

C++:

```sh
c++ -std=c++17 -I bindings/include -I crates/cabi/include \
  bindings/cpp/test_blocktools.cpp -L target/release -lblocktools_c \
  -Wl,-rpath,$PWD/target/release -o /tmp/bt-cpp-test && /tmp/bt-cpp-test
```

Zig (link the shared object; static `.a` alone segfaults under `zig test`):

```sh
zig test bindings/zig/blocktools.zig -lc -dynamic \
  -L target/release -lblocktools_c -rpath "$PWD/target/release"
```

Not published. Measured: Python/Go/C++/Zig smoke tests pass against `libblocktools_c.so`.
Untested: language-registry packaging (PyPI/crates/npm packages for wrappers).
