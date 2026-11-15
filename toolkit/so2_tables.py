# so2_tables.py — robust loaders for the SO2 dump tables.
#
# The no-token CSVs (gameplay_methods.csv, methods_notoken.csv) were written with broken
# quoting: the method name is wrapped in `"` and the row itself is not quoted, e.g.
#     """",0x67a1f0c,0x703ba86bc688
# so csv.DictReader mis-parses them. These loaders normalise both flavours.
#
# API:
#   load_token_methods()  -> list[dict]  {token, cls, name, va}
#   load_notoken_methods() -> list[dict]  {name, va, rodata}
#   dedup_by_name(rows)    -> list[dict]  unique name -> row
#
# VA space note: methodPtr values are MODULE VAs (libunity.so image base + offset).
# File offset = VA - 0x4000 for .text (see PROJECT_LOG.md §2.5 / verify_facts.py).
import csv
import os
import re

DUMP = os.path.join(device.ROOT, 'dump')
LIB = os.path.join(device.ROOT, 'extract', 'libunity.so')

TEXT_VA_LO = 0x57b9480
TEXT_VA_HI = 0xC25D7C0
TEXT_OFF = 0x4000

_NAME_RE = re.compile(r'^[A-Za-z_<>][\w<>$`.\-+]*$')


def _norm_name(raw):
    """Strip the stray quoting the no-token writers left behind."""
    s = raw.strip()
    while len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s.strip()


def _norm_class(raw):
    s = _norm_name(raw)
    # token CSV class column may be like 'Axlebolt.Standoff.Gameplay.Player'
    return s


def load_token_methods(path=None):
    """methods_all.csv / methods_final.csv — {token, cls, name, va}."""
    path = path or os.path.join(DUMP, "methods_all.csv")
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("token,"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            tok, cls, name, va = parts[0], parts[1], parts[2], parts[3]
            name = _norm_name(name)
            if not name:
                continue
            try:
                va_i = int(va, 16)
            except ValueError:
                continue
            rows.append({"token": tok, "cls": _norm_class(cls), "name": name, "va": va_i})
    return rows


def load_notoken_methods(path=None):
    """methods_notoken.csv / gameplay_methods.csv — {name, va, rodata}.

    Row shape after normalisation: name,va,extra   (extra = rodata ptr or class tag)
    """
    out = []
    for p in ([path] if path else
              [os.path.join(DUMP, "methods_notoken.csv"),
               os.path.join(DUMP, "gameplay_methods.csv")]):
        if not p or not os.path.exists(p):
            continue
        with open(p, encoding="utf-8", errors="replace", newline="") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                # split on commas but keep the quoted name intact
                if line.startswith('"'):
                    end = line.find('"', 1)
                    if end < 0:
                        continue
                    name = line[1:end]
                    rest = line[end + 1:].lstrip(",")
                else:
                    parts = line.split(",")
                    name, rest = parts[0], ",".join(parts[1:])
                name = name.strip()
                if not name:
                    continue
                rparts = rest.split(",")
                try:
                    va = int(rparts[0], 16)
                except (ValueError, IndexError):
                    continue
                extra = rparts[1].strip() if len(rparts) > 1 else ""
                out.append({"name": name, "va": va, "extra": extra, "src": os.path.basename(p)})
        if out:
            break   # methods_notoken.csv supersedes gameplay_methods.csv
    return out


def dedup_by_name(rows):
    """name -> row, first occurrence wins, ordered by VA."""
    best = {}
    for r in rows:
        n = r["name"]
        if n not in best:
            best[n] = r
    return sorted(best.values(), key=lambda r: r["va"])


def in_text(va):
    return TEXT_VA_LO <= va < TEXT_VA_HI


def va_to_off(va):
    """Module VA -> file offset in libunity.so (for .text)."""
    return va - TEXT_OFF


if __name__ == "__main__":
    tok = load_token_methods()
    notk = load_notoken_methods()
    print(f"token methods:  {len(tok)}")
    print(f"no-token rows:  {len(notk)}")
    uniq = dedup_by_name(notk)
    print(f"unique names:   {len(uniq)}")
    intext = sum(1 for r in uniq if in_text(r["va"]))
    print(f"  with .text VA: {intext}")
