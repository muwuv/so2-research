from elftools.elf.elffile import ELFFile
import struct

path = os.path.join(device.ROOT, 'extract', 'libunity.so')
RODATA = (0x1a1ea40, 0x1a1ea40 + 0x2162b0c)   # (va, end)
STRTAB = 0x2c83c9a

f = open(path, "rb")
elf = ELFFile(f)

def sect(name):
    s = elf.get_section_by_name(name)
    return (s.header.sh_addr, s.header.sh_addr + s.header.sh_size)

data_ranges = [sect(".data"), sect(".data.rel.ro")]

ptrs = []
for section in elf.iter_sections():
    if section.header["sh_type"] not in ("SHT_REL", "SHT_RELA"):
        continue
    for r in section.iter_relocations():
        off = r["r_offset"]
        in_data = any(a <= off < b for a, b in data_ranges)
        if not in_data:
            continue
        add = r["r_addend"] if section.header["sh_type"] == "SHT_RELA" else 0
        if add and RODATA[0] <= add < RODATA[1]:
            ptrs.append((off, add))

print("candidate metadata pointers into .rodata:", len(ptrs))
# keep those whose blob (add .. end) contains the string table
cands = [(off, add) for off, add in ptrs if add <= STRTAB]
cands.sort(key=lambda x: x[1])
print("pointing before string table:", len(cands))
for off, add in cands[:60]:
    print(f"  reloc_site=0x{off:x}  target=0x{add:x}  (strtab off within = 0x{STRTAB-add:x})")
