# find_class.py — STATIC+runtime: find IL2CPP classes by their namespace string.
#
# Every Il2CppClass holds two pointers into the static string blob:
#     klass + 0x188 -> name       (short class name, e.g. "Player")
#     klass + 0x190 -> namespace  (e.g. "Axlebolt.Standoff.Gameplay.Player")
# The namespace string address is known STATICALLY (it lives in .rodata, VA == file
# offset). So one 8-byte needle search over the writable heap finds EVERY class of
# that assembly at once — far cheaper than the full method-record dump.
#
# usage:
#   python find_class.py <namespace-string> [expected-short-name]
#   python find_class.py Axlebolt.Standoff.Gameplay.Player
import base64
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import device as R

LIB = os.path.join(device.ROOT, 'extract', 'libunity.so')
DUMP = device.DUMP
NAME_OFF = 0x188
NS_OFF = 0x190


def find_string_va(s):
    d = open(LIB, "rb").read()
    b = s.encode()
    m = re.search(re.escape(b) + rb"\x00", d)
    return m.start() if m else None


def writable_regions(pid):
    maps = device.su(f"cat /proc/{pid}/maps")
    regs = []
    for line in maps.splitlines():
        p = line.split()
        if len(p) < 5 or "w" not in p[1]:
            continue
        path = p[5] if len(p) > 5 else ""
        if any(k in path for k in (".so", ".apk", ".oat", ".vdex", ".art", "/dev/")):
            continue
        a, b = int(p[0].split("-")[0], 16), int(p[0].split("-")[1], 16)
        if b - a < 0x200000:
            continue
        regs.append((a, b))
    return regs


def scan(needle, regs, chunk=8 << 20):
    hits = []
    for lo, hi in regs:
        off = lo
        while off < hi:
            n = min(chunk, hi - off)
            d = device.pull(off, n)
            if len(d) != n:
                break
            i = d.find(needle)
            while i >= 0:
                hits.append(off + i)
                i = d.find(needle, i + 1)
                if len(hits) > 128:
                    return hits
            off += n
    return hits


def read_cstr(ptr, maxlen=160):
    d = device.pull(ptr, maxlen)
    e = d.find(b"\x00")
    if e < 0:
        return None
    try:
        t = d[:e].decode("ascii")
    except Exception:
        return None
    return t if t and all(32 <= ord(c) < 127 for c in t) else None


def main():
    if len(sys.argv) < 2:
        print("usage: find_class.py <namespace> [short-name]")
        return 1
    ns = sys.argv[1]
    want = sys.argv[2] if len(sys.argv) > 2 else None
    va = find_string_va(ns)
    if va is None:
        print(f"namespace string {ns!r} not found in libunity.so")
        return 1
    print(f"namespace string {ns!r} @ {va:#x}")

    pid = device.game_pid()
    if not pid:
        print("game not running"); return 1
    regs = writable_regions(pid)
    print(f"pid {pid}: {len(regs)} writable regions "
          f"({sum(b-a for a,b in regs)/2**20:.0f} MB)")

    needle = struct.pack("<Q", va)
    print("scanning for the namespace pointer ...")
    hits = scan(needle, regs)
    print(f"  {len(hits)} pointer hits")

    found = []
    for h in hits:
        klass = h - NS_OFF
        if klass < 0x1000:
            continue
        name = read_cstr(klass + NAME_OFF, 120)
        if not name:
            continue
        if want and name != want:
            continue
        found.append((klass, name))
        print(f"  klass {klass:#x}  name={name!r}")

    out = os.path.join(DUMP, "classes.json")
    json.dump({"namespace": ns, "namespace_va": va,
               "classes": [{"klass": k, "name": n} for k, n in found]},
              open(out, "w", encoding="utf-8"), indent=2)
    print(f"saved {out} ({len(found)} classes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
