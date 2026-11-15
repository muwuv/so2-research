# device.py — shared device helpers: ADB, root, process introspection, memory access.
#
# The only two things that matter for this toolkit:
#   1. talking to the device (adb + root shell)
#   2. reading / writing the live process memory of the target
#
# Everything else in toolkit/ builds on top of these.
import base64
import os
import subprocess
import sys

ADB = os.environ.get("SO2_ADB", r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe")
SERIAL = os.environ.get("SO2_SERIAL", "emulator-5554")
PKG = os.environ.get("SO2_PKG", "com.axlebolt.standoff2")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP = os.path.join(ROOT, "dump")
MEM_SH = "/data/local/tmp/mem.sh"
MEMW_SH = "/data/local/tmp/memw.sh"

_SU = None


def adb(args, timeout=180):
    r = subprocess.run([ADB, "-s", SERIAL] + args, capture_output=True, timeout=timeout)
    return r.stdout.decode(errors="replace")


def find_su():
    """The guest `su` may be hidden by the app's own anti-root check. Try the usual
    locations, including a private copy outside /system/xbin."""
    global _SU
    if _SU:
        return _SU
    for cand in ("su", "/system/xbin/bstk/su", "/system/xbin/.su.bak",
                 "/data/local/tmp/.r/su"):
        if "uid=0" in adb(["shell", f"{cand} -c id"], timeout=45):
            _SU = cand
            return _SU
    return "su"


def su(cmd, timeout=180):
    return adb(["shell", f"{find_su()} -c '{cmd}'"], timeout=timeout)


def game_pid():
    out = adb(["shell", f"pidof {PKG}"], timeout=45)
    p = sorted(int(x) for x in out.split())
    return p[0] if p else None


def module_base(pid, timeout=60):
    """Image base of the game's main library, from /proc/<pid>/maps."""
    maps = su(f"cat /proc/{pid}/maps")
    for line in maps.splitlines():
        if "libunity.so" in line:
            p = line.split()
            if len(p) >= 4 and p[2] == "057b5000":
                return int(p[0].split("-")[0], 16) - 0x57B9000
    return None


def pull(addr, size):
    r = su(f"sh {MEM_SH} {addr} {size} | base64", timeout=120)
    try:
        return base64.b64decode("".join(r.split()), validate=False)
    except Exception:
        return b""


def push(addr, data):
    b64 = base64.b64encode(data).decode()
    su(f"echo {b64} | base64 -d | sh {MEMW_SH} {addr}", timeout=120)


def load_manifest(path):
    import csv
    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            rows.append({"va": int(r["va"], 16), "orig": bytes.fromhex(r["orig"]),
                         "new": bytes.fromhex(r["new"]), "name": r.get("name", ""),
                         "kind": r.get("kind", ""), "check": r.get("check", "")})
    return rows
