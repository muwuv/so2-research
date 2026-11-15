# class_table.py — STATIC: reconstruct IL2CPP class method tables from the .data pointer arrays.
#
# The protector stores every method pointer as an R_AARCH64_RELATIVE relocation in .data.
# Methods of one class occupy a contiguous run of slots. In IL2CPP the .ctor is emitted
# LAST in a class's method list, so a .ctor marks the END of its class.
#
# .ctor detection: the generated constructor tail-branches to the shared base
# Object/ValueType constructor. For this binary that target is 0x68af774.
#
# API:
#   all_slots()          -> {slot_va: method_va}
#   ctors_in(method_vas) -> {method_va: ctor_va}
#   class_range(m_va)    -> (first_slot, last_slot, [method_vas])
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from static_disas import lib, disas_at

REL_OFF = 0x3660
REL_SZ = 0x1A199A8

_slots = None


def all_slots():
    """slot VA -> method VA, for every R_AARCH64_RELATIVE in the file."""
    global _slots
    if _slots is None:
        d = lib()
        out = {}
        for i in range(REL_SZ // 24):
            o = REL_OFF + i * 24
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, o)
            if (r_info & 0xFFFFFFFF) != 0x403:
                continue
            out[r_offset] = r_addend & 0xFFFFFFFFFFFFFFFF
        _slots = out
    return _slots


_ctor_cache = {}


def is_ctor(method_va, base_ctor=0x68AF774):
    """A .ctor tail-branches to the shared base constructor."""
    if method_va in _ctor_cache:
        return _ctor_cache[method_va]
    ins = disas_at(method_va, size=0x60, count=24)
    res = False
    for a, m, o in ins:
        if m == "b":
            try:
                dest = int(o.strip().lstrip("#"), 16)
            except ValueError:
                continue
            if dest == base_ctor:
                res = True
                break
    _ctor_cache[method_va] = res
    return res


def class_range(method_va, base_ctor=0x68AF774):
    """Return (first_slot, last_slot, [method_vas]) for the class owning method_va."""
    slots = all_slots()
    # walk left/right over contiguous slots; a .ctor ends a class
    # .data lives at 0x0C997E00 .. 0x0CFB2A80 (7 hex digits)
    ordered = sorted(s for s in slots if 0x0C000000 <= s < 0x0D000000)
    idx = {s: i for i, s in enumerate(ordered)}

    # a method can own several slots (thunks); take the one inside the table range
    cand = [s for s, m in slots.items() if m == method_va and s in idx]
    if not cand:
        return None
    home = min(cand, key=lambda s: abs(s - 0xCE14000))

    # nearest .ctor at or after the method's slot
    end = None
    i = idx[home]
    while i < len(ordered):
        s = ordered[i]
        if s != home and is_ctor(slots[s], base_ctor):
            end = i
            break
        i += 1
    if end is None:
        end = len(ordered) - 1
    # nearest .ctor strictly before -> class start is right after it
    start = 0
    j = idx[home] - 1
    while j >= 0:
        s = ordered[j]
        if is_ctor(slots[s], base_ctor):
            start = j + 1
            break
        j -= 1
    span = ordered[start:end + 1]
    return span[0], span[-1], [slots[s] for s in span]


if __name__ == "__main__":
    target = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x9CAA890
    r = class_range(target)
    if not r:
        print("no slot for that method")
    else:
        lo, hi, methods = r
        print(f"class of {target:#x}: slots {lo:#x}..{hi:#x}  ({len(methods)} methods)")
        for m in sorted(methods):
            mark = " <== TARGET" if m == target else ""
            print(f"   {m:#x}{mark}")
