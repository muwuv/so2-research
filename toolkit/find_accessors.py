# find_accessors.py — STATIC: enumerate the trivial property accessors of the recoil class.
#
# IL2CPP AOT emits property accessors as tiny leaf functions:
#     ldr s0, [x0, #N] ; ret      -> float GETTER at field offset N
#     str s0, [x0, #N] ; ret      -> float SETTER at field offset N
#     ldr x0, [x0, #N] ; ret      -> object GETTER at field offset N
#     str x1, [x0, #N] ; ret      -> object SETTER at field offset N
#
# Accessors of one class are emitted in contiguous runs, so the known recoil setters
# (from dump/recoil_setter_map.csv) anchor the run boundaries; everything inside is
# that class's accessor set.
#
# Output: dump/accessors.csv {va, off, kind, field, orig_bytes}
import csv
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf_sections import va_to_off, text_range
from static_disas import lib

OUT = os.path.join(device.ROOT, 'dump', 'accessors.csv')
RET = 0xD65F03C0

# known recoil-class setters: name -> (va, field_off)
KNOWN = {
    "set_RecoilMultOnCrouch":     (0x9ca4a40, 0x10),
    "set_AccuracyAimMult":         (0x9caa3dc, 0x10),
    "set_RecoilAimMult":           (0x9cb2e04, 0x14),
    "set_AccuracyMultOnCrouch":    (0x9ca5530, 0x14),
    "set_RecoilAimMultOnCrouch":   (0x9caf6c8, 0x18),
    "set_AccuracyAimMultOnCrouch": (0x9ca5f34, 0x18),
    "set_AccuracyMultOnJump":      (0x9ca0c38, 0x1c),
    "set_RecoilControl":           (0x7ddcc9c, 0x2c),
    "set_AimingSpeed":             (0x7df6230, 0x30),
    "set_AimingTolerance":         (0x7de6894, 0x34),
    "set_RecoilAccelDuration":     (0x9cac26c, 0x64),
    "set_RecoilAccelStep":         (0x9ca5f14, 0x68),
}


def scan_accessors():
    """Yield (va, kind, field_off, word) for every leaf accessor in .text."""
    data = lib()
    tlo, thi = text_range()
    for off in range(tlo - 0x4000, thi - 0x4000 - 8, 4):
        w = struct.unpack_from("<I", data, off)[0]
        nxt = struct.unpack_from("<I", data, off + 4)[0]
        if nxt != RET:
            continue
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        top = w & 0xFFC00000
        if rn != 0:
            continue
        if top == 0xBD400000:          # LDR S
            yield off + 0x4000, "fget", ((w >> 10) & 0xFFF) * 4, w
        elif top == 0xBD000000:        # STR S
            yield off + 0x4000, "fset", ((w >> 10) & 0xFFF) * 4, w
        elif top == 0xF9400000:        # LDR X
            yield off + 0x4000, "oget", ((w >> 10) & 0xFFF) * 8, w
        elif top == 0xF9000000:        # STR X
            yield off + 0x4000, "oset", ((w >> 10) & 0xFFF) * 8, w


def main():
    acc = list(scan_accessors())
    print(f"leaf accessors found in .text: {len(acc)}")

    # Group into contiguous runs (accessors of one class are emitted together).
    acc.sort(key=lambda r: r[0])
    runs = []
    cur = [acc[0]]
    for r in acc[1:]:
        if r[0] - cur[-1][0] <= 0x40:
            cur.append(r)
        else:
            runs.append(cur)
            cur = [r]
    runs.append(cur)
    print(f"accessor runs: {len(runs)}")

    known_vas = {v for v, _ in KNOWN.values()}
    rows = []
    for run in runs:
        vas = {r[0] for r in run}
        hits = sorted(vas & known_vas)
        if not hits:
            continue
        print(f"\n=== run {run[0][0]:#x} .. {run[-1][0]:#x}  ({len(run)} accessors, "
              f"{len(hits)} known setters) ===")
        for va, kind, field, w in run:
            known = ""
            for n, (kv, kf) in KNOWN.items():
                if kv == va:
                    known = f"  <= {n} (field {kf:#x})"
            mark = "*" if va in known_vas else " "
            print(f" {mark}{va:#x}  {kind:<5} field {field:#04x}  {struct.pack('<I', w).hex()}{known}")
            rows.append({"va": hex(va), "off": hex(va_to_off(va)), "kind": kind,
                         "field": hex(field), "orig_bytes": struct.pack("<I", w).hex(),
                         "known": known.strip()})

    with open(OUT, "w", newline="", encoding="utf-8") as f:
        wcsv = csv.DictWriter(f, fieldnames=["va", "off", "kind", "field", "orig_bytes", "known"])
        wcsv.writeheader()
        for r in rows:
            wcsv.writerow(r)
    print(f"\nwrote {OUT}: {len(rows)} accessors in recoil-class runs")


if __name__ == "__main__":
    main()
