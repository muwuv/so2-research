# analyze_class.py — STATIC: disassemble every method of a class and profile it.
#
# For each method: size, #reads/#writes of the class's own float fields, whether it
# touches the object-pointer fields, and a short signature. The recoil application
# shows up as the method that READS the recoil magnitudes and writes a result.
#
# Usage:  python analyze_class.py <method_va> [max_methods]
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from class_table import class_range
from static_disas import lib, disas_at
from elf_sections import va_to_off

# float field offsets of the recoil/accuracy params class
FIELDS = {0x10, 0x14, 0x18, 0x1C, 0x2C, 0x30, 0x34, 0x58, 0x5C, 0x60, 0x64, 0x68,
          0x78, 0xA4, 0x6C, 0x20, 0x28, 0x38, 0x40, 0x80}


def method_extent(method_va, known):
    """Real end of a method = next known method VA in .text."""
    import bisect
    i = bisect.bisect_right(known, method_va) - 1
    if i < 0:
        return method_va + 0x400
    nxt = known[i + 1] if i + 1 < len(known) else method_va + 0x400
    return nxt


def classify(method_va, max_ins=400, end_va=None):
    size = (end_va - method_va) if end_va else 0x600
    ins = disas_at(method_va, size=max(size, 8), count=max_ins)
    reads, writes, ptr_reads = {}, {}, {}
    calls = []
    for a, m, o in ins:
        if m in ("bl", "b"):
            try:
                calls.append((a, m, int(o.strip().lstrip("#"), 16)))
            except ValueError:
                pass
        if m in ("ldr", "str", "stur", "ldur"):
            mm = re.search(r"\[x\d+(?:, #(\w+))?\]", o)
            if not mm:
                continue
            off = int(mm.group(1), 0) if mm.group(1) else 0
            if off not in FIELDS:
                continue
            reg = o.split(",")[0].strip()
            if reg.startswith("s") or reg.startswith("d"):
                if m == "ldr":
                    reads[off] = reads.get(off, 0) + 1
                else:
                    writes[off] = writes.get(off, 0) + 1
            elif reg.startswith("x"):
                if m == "ldr":
                    ptr_reads[off] = ptr_reads.get(off, 0) + 1
    return ins, reads, writes, ptr_reads, calls


def main():
    target = int(sys.argv[1], 16)
    r = class_range(target)
    if not r:
        print("class not found"); return
    lo, hi, methods = r
    from class_table import all_slots
    from elf_sections import text_range
    tlo, thi = text_range()
    known = sorted({m for m in all_slots().values() if tlo <= m < thi})
    print(f"class of {target:#x}: slots {lo:#x}..{hi:#x} ({len(methods)} methods)\n")
    for m in sorted(methods):
        end = method_extent(m, known)
        ins, reads, writes, ptrs, calls = classify(m, end_va=end)
        size = end - m
        mark = " <== TARGET" if m == target else ""
        print(f"--- {m:#x}  size={size:#x}  ins={len(ins)}{mark}")
        print(f"    float READ : " + " ".join(f"{k:#x}x{v}" for k, v in sorted(reads.items())))
        print(f"    float WRITE: " + " ".join(f"{k:#x}x{v}" for k, v in sorted(writes.items())))
        print(f"    ptr  READ : " + " ".join(f"{k:#x}x{v}" for k, v in sorted(ptrs.items())))
        if calls:
            print(f"    calls      : " + " ".join(f"{d:#x}" for _, _, d in calls[:14]))


if __name__ == "__main__":
    main()
