# find_usage_slots.py — STATIC: resolve a method token -> its metadataUsages slot, then find
# every call site that loads that slot.
#
# The protector replaced global-metadata with native tables. One of them (PROJECT_LOG §2.3)
# is a flat table of 8-byte records at the tail of .rodata:
#
#     { u32 slot_off, u32 token }
#
# where token is the vanilla il2cpp encoding
#     token = (usage << 29) | (image << 25) | index
# and slot_off is the BYTE offset of the method's slot inside the runtime
# metadataUsages pointer array (built by il2cpp_init).
#
# A generated call site looks like:
#     ldr  x8, [xUsagesBase, #slot_off]   ; the slot immediate is the fingerprint
#     ...
#     blr  x8
#
# So: find slot_off for a token, then grep .text for the LDR that carries that exact
# immediate offset off a 64-bit base register.
#
# Usage:  python find_usage_slots.py 0x0600023e [...]
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf_sections import LIB, section_of, va_to_off, text_range
from static_disas import lib

# pair-table window (from PROJECT_LOG §2.3): .rodata ~0x3196100 .. 0x31fb7e0
TABLE_LO = 0x3196100
TABLE_HI = 0x31FB7E0

USAGE_NAMES = {0: "usage0", 1: "TypeInfo", 2: "Il2CppType", 3: "MethodDef", 4: "FieldInfo"}


def encode_token(token, image=None):
    """0x0600023e -> (usage<<29)|(image<<25)|idx"""
    usage = (token >> 29) & 0x7
    idx = token & 0x01FFFFFF
    if image is None:
        image = (token >> 25) & 0xF
    return (usage << 29) | (image << 25) | idx


def find_slot(token, image=None):
    """Return (slot_off, encoded_token) for a method token, or None."""
    enc = encode_token(token, image)
    data = lib()
    lo = va_to_off(TABLE_LO)
    hi = va_to_off(TABLE_HI)
    needle = struct.pack("<I", enc)
    pos = lo
    while True:
        pos = data.find(needle, pos, hi)
        if pos < 0:
            return None
        # the token must sit at record offset +4 (u32 slot_off, u32 token)
        if (pos - lo) % 8 == 4:
            slot = struct.unpack_from("<I", data, pos - 4)[0]
            return slot, enc
        pos += 4


def find_slot_by_lowidx(idx, usage=3):
    """Search the table for any token whose low index == idx (image-independent)."""
    data = lib()
    lo = va_to_off(TABLE_LO)
    hi = va_to_off(TABLE_HI)
    out = []
    for off in range(lo, hi - 8, 8):
        tok = struct.unpack_from("<I", data, off + 4)[0]
        if (tok & 0x01FFFFFF) == idx and (tok >> 29) == usage:
            slot = struct.unpack_from("<I", data, off)[0]
            out.append((slot, tok))
    return out


def ldr_imm_sites(slot_off, lo=None, hi=None):
    """Find LDR Xt, [Xn, #slot_off] in .text (imm12 scaled by 8)."""
    if slot_off % 8 != 0:
        return []
    imm12 = slot_off // 8
    if imm12 > 0xFFF:
        return []
    data = lib()
    tlo, thi = text_range()
    lo = tlo if lo is None else lo
    hi = thi if hi is None else hi
    hits = []
    for off in range(lo - 0x4000, hi - 0x4000 - 4, 4):
        w = struct.unpack_from("<I", data, off)[0]
        # LDR (immediate, unsigned offset, 64-bit): 11111001 00 imm12 Rn Rt
        if (w & 0xFFC00000) != 0xF9400000:
            continue
        if ((w >> 10) & 0xFFF) != imm12:
            continue
        hits.append(off + 0x4000)
    return hits


def main():
    args = sys.argv[1:]
    if not args:
        args = ["0x0600023e", "0x0600023f", "0x060023e"]
    for a in args:
        tok = int(a, 16)
        print(f"\n===== token {tok:#x} =====")
        r = find_slot(tok)
        if r:
            slot, enc = r
            print(f"  slot_off = {slot:#x} ({slot})  encoded token {enc:#010x} "
                  f"usage={USAGE_NAMES.get(enc >> 29, enc >> 29)} image={(enc >> 25) & 0xF}")
            sites = ldr_imm_sites(slot)
            print(f"  call sites (ldr x?, [xn, #{slot:#x}]): {len(sites)}")
            for s in sites[:30]:
                print(f"    {s:#x}")
        else:
            print("  not found by exact token — trying low-index search")
            for slot, enc in find_slot_by_lowidx(tok & 0x01FFFFFF)[:8]:
                print(f"  slot_off={slot:#x} enc={enc:#010x} image={(enc >> 25) & 0xF}")
                sites = ldr_imm_sites(slot)
                print(f"    call sites: {len(sites)}")
                for s in sites[:20]:
                    print(f"      {s:#x}")


if __name__ == "__main__":
    main()
