# static_disas.py — static ARM64 disassembly + BL xref engine for libunity.so.
#
# Pure static: reads extract/libunity.so, no emulator, no runtime.
#
#   from static_disas import disas_at, bl_xrefs_to, decode_class_tag
#
# VA space: methodPtr values in the dump tables are MODULE VAs.
# File offset = VA - 0x4000 for .text (verify_facts.py section table).
import re
import struct
import os

import capstone

LIB = os.path.join(device.ROOT, 'extract', 'libunity.so')
TEXT_OFF = 0x4000
TEXT_VA_LO = 0x57b9480
TEXT_VA_HI = 0xC25D7C0

_md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
_md.detail = False

_lib = None


def lib():
    global _lib
    if _lib is None:
        _lib = open(LIB, "rb").read()
    return _lib


def va_to_off(va):
    return va - TEXT_OFF


def off_to_va(off):
    return off + TEXT_OFF


def read_at_va(va, size):
    off = va_to_off(va)
    return lib()[off:off + size]


def disas_at(va, size=0x200, count=60):
    """Disassemble `size` bytes at module VA `va`. Returns list of (addr, mnemonic, op_str)."""
    off = va_to_off(va)
    data = lib()[off:off + size]
    out = []
    for ins in _md.disasm(data, va):
        out.append((ins.address, ins.mnemonic, ins.op_str))
        if len(out) >= count:
            break
    return out


def disas_until_ret(va, max_bytes=0x400, max_ins=200):
    """Disassemble from va until a RET is hit (or limits reached)."""
    off = va_to_off(va)
    data = lib()[off:off + max_bytes]
    out = []
    for ins in _md.disasm(data, va):
        out.append((ins.address, ins.mnemonic, ins.op_str))
        if ins.mnemonic in ("ret", "br") and len(out) > 3:
            break
        if len(out) >= max_ins:
            break
    return out


# --------------------------------------------------------------------------
# BL xref: find direct branch-with-link instructions targeting a given VA.
# --------------------------------------------------------------------------
_BL_RE = None  # resolved lazily below


def _bl_re():
    global _BL_RE
    if _BL_RE is None:
        # BL imm26: 0b100101 ... ; top 6 bits == 0b100101
        _BL_RE = re.compile(rb"[\x00-\xff]")
    return _BL_RE


def bl_xrefs_to(target_va, lo=TEXT_VA_LO, hi=TEXT_VA_HI):
    """Scan .text for BL instructions whose destination == target_va.

    BL encoding: bits[31:26] = 100101, imm26 = signed word offset in words.
    dest = pc + sign_extend(imm26 << 2)
    """
    data = lib()
    start_off = lo - TEXT_OFF
    end_off = hi - TEXT_OFF
    hits = []
    # process 4-byte aligned
    for off in range(start_off, end_off - 4, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if (w >> 26) != 0b100101:
            continue
        imm26 = w & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        pc = off + TEXT_OFF
        dest = pc + (imm26 << 2)
        if dest == target_va:
            hits.append(pc)
    return hits


def adrp_refs_to(target_page_va, lo=TEXT_VA_LO, hi=TEXT_VA_HI):
    """Scan .text for ADRP instructions whose computed page == target page."""
    data = lib()
    hits = []
    for off in range(lo - TEXT_OFF, hi - TEXT_OFF - 4, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        pc = off + TEXT_OFF
        dest_page = (pc & ~0xFFF) + (imm << 12)
        if dest_page == (target_page_va & ~0xFFF):
            hits.append(pc)
    return hits


def fmt_ins_list(items):
    lines = []
    for a, m, o in items:
        lines.append(f"  {a:#x}  {m:<8} {o}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:]:
        va = int(arg, 16)
        print(f"===== disasm @ {va:#x} =====")
        print(fmt_ins_list(disas_until_ret(va)))
        print()
