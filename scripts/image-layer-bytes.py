#!/usr/bin/env python3
"""Store-independent image size: read a `docker save` tar on stdin and sum the UNCOMPRESSED
bytes of every layer listed in manifest.json (gzip/zstd-less layers are counted as-is, gzip
layers are decompressed). overlay2 and the containerd image store export the same layer diffs,
so this number should not depend on the daemon's image store (verified on overlay2 only)."""
import gzip, json, sys, tarfile, zlib
t = tarfile.open(fileobj=sys.stdin.buffer, mode="r|")
blobs, manifest = {}, None
for m in t:
    if not m.isfile(): continue
    data = t.extractfile(m).read()
    if m.name == "manifest.json": manifest = json.loads(data)
    else: blobs[m.name] = data
if not manifest: sys.exit("image-layer-bytes: no manifest.json in docker save output")
total = 0
for layer in manifest[0]["Layers"]:
    d = blobs.get(layer)
    if d is None: sys.exit(f"image-layer-bytes: layer {layer} missing")
    if d[:2] == b"\x1f\x8b": d = gzip.decompress(d)
    elif d[:4] == b"\x28\xb5\x2f\xfd": sys.exit("image-layer-bytes: zstd layer, unsupported (fail closed)")
    total += len(d)
print(total)
