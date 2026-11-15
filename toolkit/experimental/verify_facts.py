# Verify PROJECT_LOG claims against the actual libunity.so (offline, no emulator).
import struct

PATH = os.path.join(device.ROOT, 'extract', 'libunity.so')
data = open(PATH, "rb").read()
print(f"file size: {len(data):#x} ({len(data)/2**20:.1f} MB)")

# ---- ELF header / sections ----
e_shoff, = struct.unpack_from("<Q", data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
shstr_off, = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x18)

sections = []
for i in range(e_shnum):
    b = e_shoff + i * e_shentsize
    name_off, sh_type, flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, b)
    end = data.index(b"\0", shstr_off + name_off)
    name = data[shstr_off + name_off:end].decode()
    sections.append((name, sh_type, addr, off, size))

print("\nsections:")
for name, typ, addr, off, size in sections:
    if size:
        print(f"  {name:20s} addr={addr:#12x} off={off:#12x} size={size:#10x}  VA-off={addr-off:+#x}")

# index for "which section contains file offset X"
def sect_of_off(o):
    for name, typ, addr, off, size in sections:
        if typ != 8 and off <= o < off + size:  # not NOBITS
            return name
    return None

# ---- claim checks ----
print("\n--- claim checks ---")

# 1. 0x2120000 u64/u32 sites
for val in (0x2120000,):
    pat8 = val.to_bytes(8, "little"); pat4 = val.to_bytes(4, "little")
    u64s = []
    i = 0
    while True:
        i = data.find(pat8, i)
        if i < 0: break
        u64s.append(i); i += 1
    print(f"u64 {val:#x}: {len(u64s)} sites")
    for o in u64s:
        print(f"   file {o:#12x}  in section: {sect_of_off(o)}")

# u32 only (exclude u64 overlaps)
u32s = []
i = 0
while True:
    i = data.find(pat4, i)
    if i < 0: break
    u32s.append(i); i += 1
u32_only = [o for o in u32s if o not in u64s and (o - 4) not in u64s]
print(f"u32 {val:#x} standalone: {len(u32_only)} (first 10: {[hex(o) for o in u32_only[:10]]})")

# 2. metadata sanity magic
magic = bytes.fromhex("AF1BB1FA")
print(f"\nmagic AF 1B B1 FA: {data.count(magic)} hits")

# 3. dynsym il2cpp exports
dynsym = next((s for s in sections if s[0] == ".dynsym"), None)
dynstr = next((s for s in sections if s[0] == ".dynstr"), None)
if dynsym and dynstr:
    _, _, _, symoff, symsz = dynsym[:1] + dynsym[1:2] + dynsym[2:3] + dynsym[3:4] + dynsym[4:5]
    name, typ, addr, off, size = dynsym
    stcoff, _, _, _, _ = dynstr[0], dynstr[1], dynstr[2], dynstr[3], dynstr[4]
    stroff = dynstr[3]
    n = size // 24
    defined = 0; il2cpp_syms = []
    for i in range(n):
        b = off + i * 24
        nm, info, other, shndx, value, sz = struct.unpack_from("<IBBHQQ", data, b)
        if shndx != 0:
            defined += 1
            end = data.index(b"\0", stroff + nm)
            sname = data[stroff + nm:end].decode(errors="replace")
            if "il2cpp" in sname.lower():
                il2cpp_syms.append(sname)
    print(f"dynsym entries: {n}, defined (shndx!=0): {defined}, il2cpp_* exports: {len(il2cpp_syms)}")
    for s in il2cpp_syms[:10]:
        print("   ", s)

# 4. key anchors: what's at the claimed sites
print("\n--- anchor neighborhoods ---")
sites = [0x1e71120, 0x2931468, 0x3274956, 0x3278ace, 0x3b65a6a,
         0xc9bd696, 0xc9bd6ae, 0xc9dc1ce, 0xca3f486,
         0x212c1b0, 0x2c7c4fe, 0x2c83c9a, 0x1a1ea40]
for s in sites:
    if s + 32 <= len(data):
        hexs = data[s:s+32].hex(" ")
        sec = sect_of_off(s)
        print(f"  {s:#12x} [{sec:10s}] {hexs}")

# 5. relocs targeting the 0x2120000 u64 sites (are they runtime-patched?)
print("\n--- relocations targeting u64 0x2120000 sites ---")
import collections
r_hits = collections.Counter()
rela_sections = [s for s in sections if s[0] in (".rela.dyn", ".rela.plt")]
target_set = set(u64s)
for name, typ, addr, off, size in rela_sections:
    for i in range(size // 24):
        b = off + i * 24
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, b)
        # .rodata: VA == file offset (to be confirmed by section table above)
        if r_offset in target_set:
            rtype = r_info & 0xFFFFFFFF
            print(f"  {name}: target VA {r_offset:#x} type={rtype} addend={r_addend:#x}")
            r_hits[r_offset] += 1
if not r_hits:
    print("  none -> sites are plain constants, not runtime-relocated pointers")

# 6. count R_AARCH64_RELATIVE total (sanity that we read relocs correctly)
for name, typ, addr, off, size in rela_sections:
    cnt = 0
    for i in range(size // 24):
        b = off + i * 24
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, b)
        if (r_info & 0xFFFFFFFF) == 0x403:
            cnt += 1
    print(f"  {name}: R_AARCH64_RELATIVE count = {cnt}")
