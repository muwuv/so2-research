# scan_big.py — fast keyword scan over a large binary (207 MB libunity.so).
#
# Finds every occurrence of each keyword and prints the FULL null-terminated string
# that contains it, so we see the real context (paths, messages, format strings).
#
# Usage:  python scan_big.py <file> [keyword-group]
import os
import re
import sys

GROUPS = {
    "anticheat": [
        b"/proc/self/maps", b"/proc/self/mem", b"/proc/self/status", b"/proc/self/cmdline",
        b"/proc/self/auxv", b"TracerPid", b"ptrace", b"PTRACE",
        b"/proc/", b"maps", b"smaps", b"status",
    ],
    "root": [
        b"/system/xbin/su", b"/system/bin/su", b"/sbin/su", b"/su",
        b"which su", b"magisk", b"Magisk", b"supersu", b"SuperSU", b"busybox",
        b"root access", b"rooted", b"isRooted", b"RootTools",
        b"com.topjohnwu.magisk", b"eu.chainfire.supersu",
    ],
    "cheat": [
        b"frida", b"Frida", b"gum-js-loop", b"linjector", b"gadget",
        b"xposed", b"Xposed", b"substrate", b"Substrate",
        b"gameguardian", b"GameGuardian", b"libGG",
        b"debmodulator", b"blackmart", b"Lucky Patcher",
    ],
    "emulator": [
        b"emulator", b"Emulator", b"goldfish", b"ranchu", b"genymotion",
        b"bluestacks", b"BlueStacks", b"nox", b"Nox", b"vbox", b"qemu",
        b"andy", b"ttVM", b"leidian", b"ldplayer",
    ],
    "integrity": [
        b"checksum", b"Checksum", b"crc32", b"CRC32", b"tamper", b"Tamper",
        b"integrity", b"Integrity", b"signature", b"Signature",
        b"hash", b"Hash", b"SHA", b"MD5", b"md5",
        b"libunity.so", b"libmain.so", b"libil2cpp.so",
        b"com.axlebolt.standoff2", b"axlebolt", b"Axlebolt",
        b"classes.dex", b"AndroidManifest.xml", b"base.apk",
    ],
    "net": [
        b"api.", b"http", b"signature", b"token=", b"hmac", b"HMAC",
    ],
}


def find_all(data, kw):
    out = []
    start = 0
    while True:
        i = data.find(kw, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def string_at(data, off, maxlen=160):
    s = data.rfind(b"\x00", max(0, off - 400), off) + 1
    e = data.find(b"\x00", off)
    if e < 0:
        e = off + maxlen
    raw = data[s:e]
    if len(raw) > maxlen:
        raw = raw[:maxlen]
    return raw


def main():
    path = sys.argv[1]
    groups = sys.argv[2:] or list(GROUPS)
    data = open(path, "rb").read()
    print(f"== {os.path.basename(path)} ({len(data)/2**20:.1f} MB) ==")
    for g in groups:
        kws = GROUPS.get(g, [])
        print(f"\n--- group {g} ---")
        total = 0
        for kw in kws:
            offs = find_all(data, kw)
            if not offs:
                continue
            total += len(offs)
            shown = offs[:12]
            print(f"  {kw.decode('latin1')}: {len(offs)} hit(s)")
            for o in shown:
                ctx = string_at(data, o)
                try:
                    txt = ctx.decode("ascii", "replace")
                except Exception:
                    txt = repr(ctx)
                print(f"      {o:#010x}  {txt}")
            if len(offs) > len(shown):
                print(f"      ... +{len(offs)-len(shown)} more")
        print(f"  [{g}] total hits: {total}")


if __name__ == "__main__":
    main()
