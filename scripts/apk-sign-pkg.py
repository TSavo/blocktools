#!/usr/bin/env python3
"""Re-sign an APK v2 package with an RSA key, the way abuild signs packages.

    apk-sign-pkg.py PRIVKEY PUBNAME file.apk...

An APK v2 is concatenated gzip members: [signature], control, data. The package signature is an
RSA/SHA1 signature over the compressed control member (abuild-sign signs whole files, which is the
index format, so it cannot be used here). Any existing leading .SIGN.* member (the build-time
throwaway signature) is dropped, since apk consults only the first signature block. The key is
read by openssl from PRIVKEY; nothing about it is printed.
"""
import io, subprocess, sys, tarfile, time, zlib, gzip

def members(b):
    out = []
    while b:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = d.decompress(b)
        n = len(b) - len(d.unused_data)
        out.append((b[:n], raw)); b = d.unused_data
    return out

def names(raw):
    try: return tarfile.open(fileobj=io.BytesIO(raw + b"\0" * 1024)).getnames()
    except tarfile.TarError: return []

key, pubname = sys.argv[1], sys.argv[2]
for p in sys.argv[3:]:
    ms = members(open(p, "rb").read())
    if ms and names(ms[0][1]) and all(n.startswith(".SIGN.") for n in names(ms[0][1])):
        ms = ms[1:]
    if len(ms) != 2 or ".PKGINFO" not in names(ms[0][1]):
        sys.exit(f"apk-sign-pkg: {p} is not an APK v2 package (control+data)")
    control = ms[0][0]
    sig = subprocess.run(["openssl", "dgst", "-sha1", "-sign", key], input=control,
                         capture_output=True, check=True).stdout
    ti = tarfile.TarInfo(".SIGN.RSA." + pubname); ti.size = len(sig); ti.mtime = int(time.time())
    ti.uname = ti.gname = "root"; ti.mode = 0o644
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        t.addfile(ti, io.BytesIO(sig))
    cut = 512 + (len(sig) + 511) // 512 * 512          # drop end-of-archive blocks (abuild-tar --cut)
    sigmember = gzip.compress(buf.getvalue()[:cut], compresslevel=9)
    open(p, "wb").write(sigmember + ms[0][0] + ms[1][0])
