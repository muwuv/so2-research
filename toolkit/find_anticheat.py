# find_anticheat.py — STATIC: find the client's integrity / anti-tamper / anti-debug checks.
#
# Scans a native library for:
#   - strings that betray an integrity checker (package name, "libunity.so", /proc paths,
#     "TracerPid", "frida", "su", "magisk", hash-related words)
#   - cryptographic constants (SHA-256/512, MD5, CRC32) so we can spot a hashing routine
#   - code that references those strings (ADRP+ADD materialising a string address)
#
# Usage:  python find_anticheat.py [lib.so ...]
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf_sections import SECTIONS, _load, section_of

KEYWORDS = [
    b"/proc/self/maps", b"/proc/self/mem", b"/proc/self/status", b"TracerPid",
    b"/proc/", b"maps", b"TracerPid", b"ptrace",
    b"libunity.so", b"libil2cpp", b"libsigner", b"libmain.so",
    b"com.axlebolt.standoff2", b"axlebolt",
    b"frida", b"gadget", b"xposed", b"substrate", b"magisk", b"supersu",
    b"/system/xbin/su", b"/system/bin/su", b"which su", b"busybox",
    b"integrity", b"tamper", b"checksum", b"signature", b"verify",
    b"sha256", b"sha1", b"md5", b"crc32", b"hash",
    b"/system/app", b"package.xml", b"classes.dex", b"AndroidManifest",
    b"debugger", b"emulator", b"genymotion", b"nox", b"bluestacks", b"andy",
]

# well-known hash init constants
HASH_CONSTS = {
    0x6A09E667: "SHA-256 H0", 0xBB67AE85: "SHA-256 H1", 0x3C6EF372: "SHA-256 H2",
    0xA54FF53A: "SHA-256 H3", 0x510E527F: "SHA-256 H4", 0x9B05688C: "SHA-256 H5",
    0x1F83D9AB: "SHA-256 H0'", 0x5BE0CD19: "SHA-256 H1'",
    0x6A09E667F3BCC908: "SHA-512",
    0x67452301: "MD5/SHA-1 A", 0xEFCDAB89: "MD5/SHA-1 B", 0x98BADCFE: "MD5/SHA-1 C",
    0x10325476: "MD5/SHA-1 D", 0xC3D2E1F0: "SHA-1 E",
    0xEDB88320: "CRC32 (reflected)", 0x04C11DB7: "CRC32 (normal)",
    0xEDB88320: "CRC32",
}


def strings(data, minlen=5):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append((m.start(), m.group()))
    return out


def scan(path):
    data = open(path, "rb").read()
    name = os.path.basename(path)
    print(f"\n===== {name}  ({len(data)/2**20:.1f} MB) =====")

    # --- keyword strings ---
    hits = []
    for off, s in strings(data, 4):
        for kw in KEYWORDS:
            if kw in s:
                hits.append((off, s[:120]))
                break
    print(f"keyword strings: {len(hits)}")
    seen = set()
    for off, s in hits:
        key = s[:60]
        if key in seen:
            continue
        seen.add(key)
        print(f"   {off:#010x}  {s.decode('ascii', 'replace')}")

    # --- hash constants in code ---
    print("\nhash constants found in the file:")
    for i in range(0, len(data) - 4, 4):
        w = struct.unpack_from("<I", data, i)[0]
        if w in HASH_CONSTS:
            print(f"   {i:#010x}  {HASH_CONSTS[w]:<20} {w:#010x}")
    return hits


def main():
    files = sys.argv[1:] or [os.path.join(device.ROOT, 'extract', 'libsigner.so')]
    for f in files:
        scan(f)


if __name__ == "__main__":
    main()
