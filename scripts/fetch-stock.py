#!/usr/bin/env python3
"""从 OTA zip 里只取 recovery 分区，拼成完整分区镜像（含 AVB footer）。

用法: fetch-stock.py <ota_url> <out.img> [expected_sha256]
"""
import hashlib
import os
import struct
import shutil
import subprocess
import sys

BLOCK = 4096
PART_SIZE = 100 * 1024 * 1024


def rng(url, start, end, out):
    want = end - start + 1
    for _ in range(5):
        r = subprocess.run(
            ["curl", "-sSL", "-r", f"{start}-{end}", "--max-time", "600", url, "-o", out],
            capture_output=True,
        )
        if r.returncode == 0 and os.path.exists(out) and os.path.getsize(out) == want:
            return
    raise SystemExit(f"range {start}-{end} failed")


def _varint(b, i):
    v = 0
    s = 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << s
        if not c & 0x80:
            return v, i
        s += 7


def _fields(b, start, end):
    i = start
    while i < end:
        key, i = _varint(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(b, i)
            yield fn, wt, v, 0, 0
        elif wt == 2:
            ln, i = _varint(b, i)
            yield fn, wt, b[i:i + ln], i, i + ln
            i += ln
        elif wt == 5:
            yield fn, wt, 0, 0, 0
            i += 4
        elif wt == 1:
            yield fn, wt, 0, 0, 0
            i += 8
        else:
            raise ValueError(f"wire type {wt}")


def parse_manifest(b):
    parts = []
    for fn, wt, _, s, e in _fields(b, 0, len(b)):
        if fn != 13 or wt != 2:
            continue
        name, ops = "?", []
        for f2, w2, v2, s2, e2 in _fields(b, s, e):
            if f2 == 1 and w2 == 2:
                name = v2.decode()
            elif f2 == 8 and w2 == 2:
                op = [0, 0, 0, []]
                for f3, w3, v3, s3, e3 in _fields(b, s2, e2):
                    if f3 == 1 and w3 == 0:
                        op[0] = v3
                    elif f3 == 2 and w3 == 0:
                        op[1] = v3
                    elif f3 == 3 and w3 == 0:
                        op[2] = v3
                    elif f3 == 6 and w3 == 2:
                        sb = nb = 0
                        for f4, w4, v4, _, _ in _fields(b, s3, e3):
                            if f4 == 1 and w4 == 0:
                                sb = v4
                            elif f4 == 2 and w4 == 0:
                                nb = v4
                        op[3].append((sb, nb))
                ops.append(tuple(op))
        parts.append((name, ops))
    return parts


def main():
    url, out_path = sys.argv[1], sys.argv[2]
    want_sha = sys.argv[3].lower() if len(sys.argv) > 3 else None
    work = "/tmp/stock"
    os.makedirs(work, exist_ok=True)

    head = os.path.join(work, "head4m.bin")
    rng(url, 0, 4 * 1024 * 1024 - 1, head)
    d = open(head, "rb").read()

    i = 0
    payload_off = payload_size = None
    while i < len(d) - 30:
        if d[i:i + 4] != b"PK\x03\x04":
            i += 1
            continue
        method = struct.unpack("<H", d[i + 8:i + 10])[0]
        nlen, elen = struct.unpack("<HH", d[i + 26:i + 30])
        name = d[i + 30:i + 30 + nlen].decode("utf-8", "replace")
        data_start = i + 30 + nlen + elen
        if name == "payload.bin":
            extra = d[i + 30 + nlen:data_start]
            size = None
            j = 0
            while j < len(extra):
                hid, hsz = struct.unpack("<HH", extra[j:j + 4])
                if hid == 1 and hsz >= 8:
                    size = int.from_bytes(extra[j + 4:j + 12], "little")
                j += 4 + hsz
            payload_off = data_start
            payload_size = size
            break
        if method == 0:
            csize = struct.unpack("<I", d[i + 18:i + 22])[0]
            if csize not in (0, 0xFFFFFFFF):
                i = data_start + csize
                continue
        i += 1

    if payload_off is None:
        raise SystemExit("no payload.bin in zip")
    print(f"payload.bin @ {payload_off}, size {payload_size}")

    hdr = os.path.join(work, "ph.bin")
    rng(url, payload_off, payload_off + 63, hdr)
    h = open(hdr, "rb").read()
    if h[:4] != b"CrAU":
        raise SystemExit(f"payload magic wrong: {h[:4]}")
    mlen = struct.unpack(">Q", h[12:20])[0]
    siglen = struct.unpack(">I", h[20:24])[0]
    print(f"manifest {mlen}, sig {siglen}")

    mf = os.path.join(work, "m.bin")
    rng(url, payload_off + 24, payload_off + 24 + mlen - 1, mf)
    parts = parse_manifest(open(mf, "rb").read())

    rec = next((p for p in parts if p[0] == "recovery"), None)
    if not rec:
        raise SystemExit("no recovery partition")

    ops = [o for o in rec[1] if o[0] != 6 and o[2] > 0]
    lo = min(o[1] for o in ops)
    hi = max(o[1] + o[2] for o in ops)
    data_off = payload_off + 24 + mlen + siglen
    print(f"recovery {len(rec[1])} ops, data {hi - lo} @ {lo}")

    contiguous = all(b[1] == a[1] + a[2] for a, b in zip(ops, ops[1:]))
    if contiguous:
        blob = os.path.join(work, "rec.xz")
        rng(url, data_off + lo, data_off + hi - 1, blob)
        raw = open(blob, "rb").read()
    else:
        chunks = []
        for i, o in enumerate(ops):
            p = os.path.join(work, f"c{i}")
            rng(url, data_off + o[1], data_off + o[1] + o[2] - 1, p)
            chunks.append(open(p, "rb").read())
        raw = b"".join(chunks)
    print(f"took {len(raw)} bytes")

    xz = shutil.which("xz") or shutil.which("busybox")
    cmd = [xz, "-dc"] if xz and xz.endswith("xz") else [xz, "xz", "-dc"]
    img = subprocess.run(cmd, input=raw, capture_output=True).stdout
    if not img:
        raise SystemExit("xz failed")
    print(f"unxz {len(img)} bytes, head {img[:8]}")

    salt = bytes(32)
    digest = hashlib.sha256(salt + img).digest()
    alg = bytearray(32)
    alg[:6] = b"sha256"
    desc = bytearray()
    desc += struct.pack(">Q", 2)
    desc += struct.pack(">Q", 0)
    desc += struct.pack(">Q", len(img))
    desc += bytes(alg)
    for n in (8, 32, 32, 0):
        desc += struct.pack(">I", n)
    desc += bytes(60)
    desc += b"recovery"
    desc += salt
    desc += digest
    while len(desc) % 8:
        desc += b"\x00"
    desc[8:16] = struct.pack(">Q", len(desc) - 16)
    desc = bytes(desc)

    aux = (len(desc) + 63) // 64 * 64
    vb = bytearray(b"AVB0")
    vb += struct.pack(">I", 1)
    vb += struct.pack(">I", 0)
    vb += struct.pack(">Q", 0)
    vb += struct.pack(">Q", aux)
    vb += struct.pack(">I", 0)
    for v in (0, 0, 0, 0, len(desc), 0, len(desc), 0, 0, len(desc), 0):
        vb += struct.pack(">Q", v)
    vb += struct.pack(">I", 0)
    vb += struct.pack(">I", 0)
    vb += b"skyward-pack"
    vb += bytes(256 - len(vb))
    vb += desc
    vb += bytes(aux - len(desc))

    offset = (len(img) + BLOCK - 1) // BLOCK * BLOCK
    out = bytearray(img)
    out += bytes(offset - len(out))
    out += vb
    out += bytes(PART_SIZE - 64 - len(out))
    out += b"AVBf"
    out += struct.pack(">II", 1, 0)
    out += struct.pack(">QQQ", len(img), offset, len(vb))
    out += bytes(PART_SIZE - len(out))

    sha = hashlib.sha256(bytes(out)).hexdigest()
    if want_sha and sha != want_sha:
        raise SystemExit(f"sha256 mismatch: got {sha}, want {want_sha}")
    open(out_path, "wb").write(bytes(out))
    print(f"wrote {out_path} ({len(out)} bytes), sha256 {sha}")


if __name__ == "__main__":
    main()
