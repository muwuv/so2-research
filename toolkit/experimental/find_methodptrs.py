# find_methodptrs.py — offline: find the CodeRegistration methodPointers array.
# R_AARCH64_RELATIVE runs with 8-stride sources whose addends land in .text.
import struct
from collections import Counter

PATH = os.path.join(device.ROOT, 'extract', 'libunity.so')
data = open(PATH, "rb").read()
RELA_OFF, RELA_SZ = 0x3660, 0x1a199a8
TEXT_LO, TEXT_HI = 0x57b9480, 0xc25d7c0
PLT_LO, PLT_HI = 0xc25d7c0, 0xc25d7c0 + 0x1190

pairs = []
for i in range(RELA_SZ // 24):
    b = RELA_OFF + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, b)
    if (r_info & 0xFFFFFFFF) != 0x403:
        continue
    if TEXT_LO <= r_addend < PLT_HI:
        pairs.append((r_offset, r_addend))
print(f"RELATIVE relocs into .text/.plt: {len(pairs)}")

pairs.sort()
runs = []
cur = [pairs[0]]
for p in pairs[1:]:
    if p[0] - cur[-1][0] == 8:
        cur.append(p)
    else:
        if len(cur) >= 64: runs.append(cur)
        cur = [p]
if len(cur) >= 64: runs.append(cur)
runs.sort(key=len, reverse=True)
print(f"contiguous 8-stride runs >=64 into .text: {len(runs)}")
for r in runs[:15]:
    srcs = [x[0] for x in r]; tgts = [x[1] for x in r]
    gaps = Counter(srcs[i+1] == srcs[i] for i in range(len(srcs)-1))
    # monotone targets?
    mono_up = all(tgts[i] <= tgts[i+1] for i in range(len(tgts)-1))
    print(f"  src {srcs[0]:#x}..{srcs[-1]:#x} n={len(r)} tgt {tgts[0]:#x}..{tgts[-1]:#x} sorted={mono_up}")

# The methodPointers array: usually sorted-ish ascending per assembly (not guaranteed).
# Report the biggest run's neighborhood stats.
if runs:
    r = runs[0]
    tgts = [x[1] for x in r]
    d = [tgts[i+1]-tgts[i] for i in range(len(tgts)-1)]
    pos = sum(1 for x in d if x > 0); neg = sum(1 for x in d if x < 0)
    print(f"\nbiggest run: deltas pos={pos} neg={neg} (method tables are usually near-sorted)")
