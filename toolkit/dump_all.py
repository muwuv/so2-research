# dump_all.py — ONE COMMAND full pipeline for a game-version dump.
# Run AFTER entering a match (training is fine). ~20-30 min.
# Usage: python dump_all.py
#
# Steps: reveal su (direct or bstime trick) -> detect pid/base -> scan ALL memory regions
# with 3 record patterns -> resolve class names -> write CSVs + diff -> re-hide su.
import subprocess, base64, struct, re, os, collections, time, sys

ADB = r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe"
DEV = "emulator-5554"
PKG = "com.axlebolt.standoff2"
D = os.path.join(device.ROOT, 'dump')
os.makedirs(D, exist_ok=True)
lib = open(os.path.join(device.ROOT, 'extract', 'libunity.so'), "rb").read()

def adb(cmd, timeout=600):
    r = subprocess.run([ADB, "-s", DEV, "shell", cmd], capture_output=True, timeout=timeout)
    return r.stdout.decode(errors="replace")

SU_BIN = None

def _find_su():
    """The guest `su` is hidden (anti-root). Our own root channel survives hardening:
    /data/local/tmp/.r/su. Fall back to the frida/bstime trick only if that fails."""
    global SU_BIN
    if SU_BIN:
        return SU_BIN
    for cand in ("su", "/system/xbin/bstk/su", "/system/xbin/.su.bak",
                 "/data/local/tmp/.r/su"):
        if "uid=0" in adb(f"{cand} -c id"):
            SU_BIN = cand
            return SU_BIN
    return "su"

def su(cmd):
    return adb(f"{_find_su()} -c '{cmd}'")

def frida_system(pid, cmdline):
    import frida
    dev = frida.get_usb_device(timeout=10)
    s = dev.attach(pid)
    sc = s.create_script(
        "var system = new NativeFunction(Module.getExportByName('libc.so','system'),'int',['pointer']);"
        "system(Memory.allocUtf8String(" + repr(cmdline) + ")); send('ok');")
    out = []
    sc.on("message", lambda m, d: out.append(m.get("payload") or m))
    sc.load(); time.sleep(2)
    try: s.detach()
    except Exception: pass
    return out

def reveal_su():
    # 1) direct (incl. our private root channel /data/local/tmp/.r/su)?
    if "uid=0" in su("id"):
        print(f"[su] available via {_find_su()}"); return True
    # 2) hidden -> bstime trick (needs frida-server running)
    out = adb("pidof bstime").split()
    if not out:
        print("[su] hidden AND frida/bstime unavailable. Fix: restart BlueStacks (su returns),"
              " start frida-server, re-hide su, then run this again."); return False
    bpid = int(out[0])
    print(f"[su] hidden -> bstime injection (pid {bpid})")
    frida_system(bpid, "mv /system/xbin/.su.bak /system/xbin/su; mv /system/xbin/bstk/.su.bak /system/xbin/bstk/su")
    if "uid=0" in su("id"):
        print("[su] revealed"); return True
    print("[su] reveal FAILED"); return False

def hide_su():
    su("mv /system/xbin/su /system/xbin/.su.bak; mv /system/xbin/bstk/su /system/xbin/bstk/.su.bak")
    print("[su] hidden again")

def str_at(ptr, base):
    o = ptr - base
    if not (0 <= o < len(lib)): return None
    e = lib.find(b"\x00", o, o + 160)
    if e < 0: return None
    try:
        s = lib[o:e].decode("ascii")
        return s if s and all(32 <= ord(c) < 127 for c in s) else None
    except Exception:
        return None

def pull(addr, size):
    r = subprocess.run([ADB, "-s", DEV, "shell",
                        f"{_find_su()} -c 'sh /data/local/tmp/mem.sh {addr} {size} | base64'"],
                        capture_output=True, timeout=600)
    return base64.b64decode(b"".join(r.stdout.split()))

# ---------- 1. su ----------
if not reveal_su():
    sys.exit(1)

# ---------- 2. mem.sh present? ----------
if "dd" not in adb("cat /data/local/tmp/mem.sh"):
    print("[mem.sh] missing — installing")
    open(os.path.join(device.ROOT, 'agent', 'mem.sh'), "rb").read()  # local copy exists
    subprocess.run([ADB, "-s", DEV, "push", os.path.join(device.ROOT, 'agent', 'mem.sh'),
                    "/data/local/tmp/mem.sh"], capture_output=True)
    su("chmod 755 /data/local/tmp/mem.sh")

# ---------- 3. game pid + base ----------
pids = sorted(int(p) for p in adb(f"pidof {PKG}").split())
if not pids:
    print("[!] game is not running. Enter a match first, then re-run."); hide_su(); sys.exit(1)
pid = pids[0]
maps = su(f"cat /proc/{pid}/maps")
base = None
for line in maps.splitlines():
    if "libunity.so" in line:
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "057b5000":
            base = int(parts[0].split("-")[0], 16) - 0x57b9000
            break
if not base:
    print("[!] libunity executed-mapping not found"); hide_su(); sys.exit(1)
print(f"[game] pid {pid}, base {base:#x}")

# ---------- 4. regions ----------
regions = []
for line in maps.splitlines():
    m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (rw-p)", line)
    if not m: continue
    lo, hi = int(m.group(1), 16), int(m.group(2), 16)
    tail = line.split()[-1] if len(line.split()) > 5 else ""
    if any(k in tail for k in (".so", ".apk", ".oat", ".vdex", ".art", "/dev/")): continue
    if hi - lo >= 0x200000:
        regions.append((lo, hi))
total = sum(h - l for l, h in regions)
print(f"[scan] {len(regions)} regions, {total/2**20:.0f} MB")

# ---------- 5. scan ----------
TEXT_LO, TEXT_HI = 0x57b9480, 0xc25d7c0
tok_methods = {}     # token -> (name, mp_rel, classPtr)
nt_methods = {}      # (name, mp_rel) -> rodata
CH = 0x800000
t0 = time.time()
done = 0
for lo, hi in regions:
    for addr in range(lo, hi, CH):
        sz = min(CH, hi - addr)
        try:
            d = pull(addr, sz)
        except Exception:
            continue
        n = len(d)
        for i in range(8, n - 0x78, 8):
            # token patterns (strict+relaxed)
            v = struct.unpack_from("<Q", d, i)[0]
            tok = v >> 32
            if (tok >> 24) == 0x06 and (tok & 0xFFFFFF) > 0:
                mp = struct.unpack_from("<Q", d, i + 0x10)[0]
                np = struct.unpack_from("<Q", d, i + 0x18)[0]
                mp_rel = mp - base
                if TEXT_LO <= mp_rel < TEXT_HI:
                    nm = str_at(np, base)
                    if nm:
                        t = tok & 0xFFFFFF
                        if t not in tok_methods:
                            cp = struct.unpack_from("<Q", d, i + 0x30)[0]
                            tok_methods[t] = (nm, mp_rel, cp)
            # no-token pattern: [mp @ -8, name @ 0, 1 @ +8, rodata @ +16]
            np2 = struct.unpack_from("<Q", d, i)[0]
            nm2 = str_at(np2, base)
            if nm2:
                pv = struct.unpack_from("<Q", d, i - 8)[0]
                pv_rel = pv - base
                nx = struct.unpack_from("<Q", d, i + 8)[0]
                if TEXT_LO <= pv_rel < TEXT_HI and nx == 1:
                    key = (nm2, pv_rel)
                    if key not in nt_methods:
                        nt_methods[key] = struct.unpack_from("<Q", d, i + 0x10)[0]
        done += sz
        print(f"  [{done/2**20:5.0f}/{total/2**20:.0f}MB {time.time()-t0:4.0f}s] tok={len(tok_methods)} nt={len(nt_methods)}", flush=True)

print(f"[scan] DONE in {time.time()-t0:.0f}s: token-methods={len(tok_methods)} no-token={len(nt_methods)}")

# ---------- 6. class names ----------
cps = sorted(set(m[2] for m in tok_methods.values()))
wins = []
i = 0
while i < len(cps):
    j = i
    while j + 1 < len(cps) and cps[j + 1] - cps[j] < 0x1000:
        j += 1
    lo = cps[i] & ~0xFFF
    hi = (cps[j] + 0x200 + 0xFFF) & ~0xFFF
    wins.append((lo, hi - lo))
    i = j + 1
names = {}
for lo, sz in wins:
    try:
        d = pull(lo, sz)
    except Exception:
        continue
    for cp in cps:
        if lo <= cp < lo + sz:
            o = cp - lo + 0x188
            if o + 8 <= len(d):
                v = struct.unpack_from("<Q", d, o)[0]
                s = str_at(v, base)
                if s: names[cp] = s
print(f"[classes] {len(names)}/{len(cps)} resolved")

# ---------- 7. write (MERGE with previous dump — never lose old rows) ----------
import csv as _csv
_csv.field_size_limit(1 << 30)

prev_tok = {}     # token -> (class, method, mp)  from previous methods_all.csv
if os.path.exists(D + r"\methods_all.csv"):
    for r in _csv.DictReader(open(D + r"\methods_all.csv", encoding="utf-8")):
        try:
            prev_tok[int(r["token"], 16)] = (r["class"], r["method"], r["methodPtr"])
        except Exception:
            continue

merged = dict(prev_tok)
for t, (nm, mp, cp) in tok_methods.items():
    merged[t] = (names.get(cp, ""), nm, f"{mp:#x}")
added = len(merged) - len(prev_tok)
print(f"[merge] previous={len(prev_tok)} new={len(tok_methods)} merged={len(merged)} (+{added})")

with open(D + r"\methods_all.csv", "w", encoding="utf-8", newline="") as f:
    w = _csv.writer(f)
    w.writerow(["token", "class", "method", "methodPtr"])
    for t, (cn, nm, mp) in sorted(merged.items()):
        w.writerow([f"{t:#x}", cn, nm, mp])

# merge no-token as well
prev_nt = {}
if os.path.exists(D + r"\methods_notoken.csv"):
    for r in _csv.DictReader(open(D + r"\methods_notoken.csv", encoding="utf-8")):
        try:
            prev_nt[(r["method"], r["methodPtr"])] = r["rodata"]
        except Exception:
            continue
for (nm, mp), rod in nt_methods.items():
    prev_nt[(nm, f"{mp:#x}")] = f"{rod:#x}"
with open(D + r"\methods_notoken.csv", "w", encoding="utf-8", newline="") as f:
    w = _csv.writer(f)
    w.writerow(["method", "methodPtr", "rodata"])
    for (nm, mp), rod in sorted(prev_nt.items()):
        w.writerow([nm, mp, rod])

new_names = {names.get(m[2], "?") for m in tok_methods.values()} - \
            {v[0] for v in prev_tok.values()}
print(f"[diff] classes not in previous dump: {sorted(new_names)[:20]}")

# ---------- 8. hide su ----------
hide_su()
print("[done] outputs: dump/methods_all.csv (merged), dump/methods_notoken.csv (merged)")
print("[NOTE] the game must stay OPEN and IN A MATCH during the whole scan —")
print("       minimizing unloads gameplay classes (OnApplicationPause)")
