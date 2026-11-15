# class_layout.py — STATIC+runtime: locate a gameplay class in the live process and
# dump its field layout (names + offsets) and its instances.
#
# How it works
#   The dump (methods_all.csv) gives us a method NAME -> .text VA for every class.
#   In the live process each method has an Il2CppMethodInfo record:
#       [+0x00] Il2CppMethod* pointer
#       [+0x04] uint32 token            (MethodDef 0x06xxxxxx)
#       [+0x10] Il2CppMethodPointer methodPtr   <-- the .text VA we know
#       [+0x18] const char* name
#       [+0x30] Il2CppClass* klass
#   So: search the heap for the 8-byte methodPtr, the record is 0x10 before it,
#   and klass is at record+0x30.
#
#   From klass we dump 0x200 bytes and resolve every pointer that looks like a
#   string, which exposes the FieldInfo array; each FieldInfo gives name+offset.
#
# usage:
#   python class_layout.py <ClassName> [<MethodName>]     # e.g. Axlebolt.Standoff.Gameplay.Player
import base64
import csv
import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import device as R

DUMP = device.DUMP
REGIONS_CACHE = os.path.join(DUMP, "regions.json")


def read_regions(pid):
    """Writable anon regions of the game process (the GC heap lives here)."""
    maps = device.su(f"cat /proc/{pid}/maps")
    regs = []
    for line in maps.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        perms = p[1]
        path = p[5] if len(p) > 5 else ""
        if "w" not in perms:
            continue
        if any(k in path for k in (".so", ".apk", ".oat", ".vdex", ".art", "/dev/")):
            continue
        a, b = int(p[0].split("-")[0], 16), int(p[0].split("-")[1], 16)
        if b - a < 0x100000:
            continue
        regs.append((a, b))
    return regs


def pull(addr, size):
    return device.pull(addr, size)


def find_pattern(pid, needle, regions, chunk=8 << 20):
    """Scan the writable regions for an 8-byte needle. Returns a list of addresses."""
    hits = []
    for lo, hi in regions:
        off = lo
        while off < hi:
            n = min(chunk, hi - off)
            d = pull(off, n)
            if len(d) != n:
                break
            i = d.find(needle)
            while i >= 0:
                hits.append(off + i)
                i = d.find(needle, i + 1)
                if len(hits) > 64:
                    return hits
            off += n
    return hits


def read_cstr(ptr, maxlen=120):
    d = pull(ptr, maxlen)
    e = d.find(b"\x00")
    if e < 0:
        return None
    s = d[:e]
    try:
        t = s.decode("ascii")
    except Exception:
        return None
    return t if t and all(32 <= ord(c) < 127 for c in t) else None


def main():
    if len(sys.argv) < 2:
        print("usage: class_layout.py <ClassName> [MethodName]")
        return 1
    cls_name = sys.argv[1]
    meth_hint = sys.argv[2] if len(sys.argv) > 2 else None

    # ---- 1) find the class in the dump tables
    rows = []
    for f in ("methods_all.csv", "methods_notoken.csv"):
        p = os.path.join(DUMP, f)
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8", errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                if r.get("class") == cls_name or r.get("class", "").endswith(cls_name):
                    rows.append((r.get("method", ""), int(r["methodPtr"], 16)))
    if not rows:
        print(f"class {cls_name!r} not in the dump tables (dump made in the lobby?)")
        return 1
    print(f"class {cls_name}: {len(rows)} methods in the dump")

    if meth_hint:
        pick = [r for r in rows if r[0] == meth_hint]
    else:
        pick = rows
    if not pick:
        print("method hint not found")
        return 1

    pid = device.game_pid()
    if not pid:
        print("game not running")
        return 1
    base = device.module_base(pid, timeout=60)
    regions = read_regions(pid)
    print(f"pid {pid} base {base:#x}  {len(regions)} writable regions "
          f"({sum(b-a for a,b in regions)/2**20:.0f} MB)")

    # ---- 2) find a method record -> klass
    klass = None
    used_meth = None
    for name, mva in pick:
        needle = struct.pack("<Q", mva)
        hits = find_pattern(pid, needle, regions, chunk=4 << 20)
        for h in hits:
            rec = h - 0x10
            cp = struct.unpack("<Q", pull(rec + 0x30, 8))[0]
            if not cp:
                continue
            nm = read_cstr(cp + 0x188, 160)
            if nm and (cls_name.split(".")[-1] in nm or nm == cls_name):
                klass = cp
                used_meth = (name, mva)
                print(f"  method {name!r} @ {mva:#x} -> record {rec:#x} -> klass {cp:#x} ({nm})")
                break
        if klass:
            break
    if not klass:
        print("class pointer not found (method record layout changed?)")
        return 1

    # ---- 3) dump the Il2CppClass and resolve string pointers
    print(f"\n== Il2CppClass {klass:#x} ==")
    blob = pull(klass, 0x200)
    for i in range(0, 0x200, 8):
        v = struct.unpack_from("<Q", blob, i)[0]
        if 0x7000000000 < v < 0x8000000000:
            s = read_cstr(v, 80)
            if s and len(s) > 2:
                print(f"   +{i:#04x}  -> {v:#x}  {s!r}")

    with open(os.path.join(DUMP, "class_info.json"), "w", encoding="utf-8") as f:
        json.dump({"class": cls_name, "klass": klass, "pid": pid, "base": base,
                   "method": used_meth[0], "methodPtr": used_meth[1]}, f, indent=2)
    print(f"\nsaved {os.path.join(DUMP, 'class_info.json')}")
    return 0


if __name__ == "__main__":
    import json
    raise SystemExit(main())
