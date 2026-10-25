"""Thin ctypes wrapper over libblocktools_c (secrets-off C ABI)."""
from __future__ import annotations
import ctypes, json, os
from ctypes import c_char_p, c_void_p

def _load():
    env = os.environ.get("BLOCKTOOLS_C_LIB")
    cands = [env] if env else []
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "../.."))
    cands += [
        os.path.join(root, "target/release/libblocktools_c.so"),
        os.path.join(root, "target/debug/libblocktools_c.so"),
        "libblocktools_c.so",
    ]
    for p in cands:
        if p and (os.path.isfile(p) or p == "libblocktools_c.so"):
            try:
                return ctypes.CDLL(p)
            except OSError:
                continue
    raise FileNotFoundError("libblocktools_c.so not found; build with `cargo build -p blocktools-c --release` or set BLOCKTOOLS_C_LIB")

_lib = _load()
_lib.bt_version.restype = c_char_p
_lib.bt_chain_table.restype = c_void_p
_lib.bt_envelope.argtypes = [c_char_p]
_lib.bt_envelope.restype = c_void_p
_lib.bt_free.argtypes = [c_void_p]

def _take(p) -> str:
    if not p:
        raise RuntimeError("null C string from blocktools-c")
    try:
        s = ctypes.cast(p, c_char_p).value
        return (s or b"").decode("utf-8")
    finally:
        _lib.bt_free(p)

def version() -> str:
    v = _lib.bt_version()
    return v.decode("utf-8") if isinstance(v, bytes) else str(v)

def chain_table() -> list:
    return json.loads(_take(_lib.bt_chain_table()))

def envelope(req) -> dict:
    if isinstance(req, dict):
        req = json.dumps(req)
    raw = req if isinstance(req, bytes) else req.encode("utf-8")
    return json.loads(_take(_lib.bt_envelope(raw)))
