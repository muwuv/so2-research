# elf_sections.py — authoritative ELF section map for libunity.so.
#
# Everything downstream (static patcher, usage-table walker) needs exact VA->file-offset.
# The PROJECT_LOG hand-written offsets are unreliable; this reads the real section headers.
#
#   from elf_sections import SECTIONS, va_to_off, off_to_va, section_of, dump_map
from elftools.elf.elffile import ELFFile

LIB = os.path.join(device.ROOT, 'extract', 'libunity.so')

_f = None
SECTIONS = []   # list of dict(name, addr, off, size, type, flags)


def _load():
    global _f, SECTIONS
    if _f is None:
        _f = open(LIB, "rb")
        elf = ELFFile(_f)
        for s in elf.iter_sections():
            SECTIONS.append({
                "name": s.name,
                "addr": s["sh_addr"],
                "off": s["sh_offset"],
                "size": s["sh_size"],
                "type": s["sh_type"],
                "flags": s["sh_flags"],
            })
    return _f


def dump_map():
    _load()
    print(f"{'section':<24} {'VA':<14} {'off':<12} {'size':<12} {'flags':<6}")
    for s in SECTIONS:
        if s["addr"] or s["size"]:
            print(f"{s['name']:<24} {s['addr']:#012x} {s['off']:#010x} {s['size']:#012x} {s['flags']:#06x}")


def section_of(va):
    _load()
    for s in SECTIONS:
        if s["addr"] <= va < s["addr"] + s["size"]:
            return s
    return None


def va_to_off(va):
    """VA -> file offset. Falls back to the section's own delta mapping."""
    s = section_of(va)
    if not s:
        raise ValueError(f"VA {va:#x} not in any section")
    return s["off"] + (va - s["addr"])


def off_to_va(off):
    _load()
    for s in SECTIONS:
        if s["off"] <= off < s["off"] + s["size"]:
            return s["addr"] + (off - s["off"])
    raise ValueError(f"offset {off:#x} not in any section")


def text_range():
    _load()
    for s in SECTIONS:
        if s["name"] == ".text":
            return s["addr"], s["addr"] + s["size"]
    raise ValueError("no .text")


if __name__ == "__main__":
    dump_map()
    print()
    lo, hi = text_range()
    print(f".text  {lo:#x} .. {hi:#x}  (size {hi-lo:#x})")
    for probe in (0x9caa890, 0x9cacda4, 0x1b45368, 0x3196100, 0x31fb7e0, 0xce14ae0):
        s = section_of(probe)
        print(f"  {probe:#x} -> off {va_to_off(probe):#x}  in {s['name'] if s else '??'}")
