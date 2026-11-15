# unity-il2cpp-structure-recovery

**Recovering class, method and field structure from an obfuscated Unity IL2CPP Android client —
statically, with no debugger attached.**

Research toolkit and findings produced while analysing the native client of **Standoff 2**
(Axlebolt, `com.axlebolt.standoff2`, version 1.1.0) on Android. The tooling is target-agnostic;
the findings are specific to that build.

* **Methodology** — [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md)
* **Findings report** — [`docs/FINDINGS.md`](docs/FINDINGS.md)

> **Scope.** This repository contains **analysis tooling and research findings**. It ships no
> game binaries and no game assets. Its purpose is to make a previously undocumented class of
> client-side weakness reproducible and auditable.

---

## 1. The problem

Unity ships IL2CPP games as a native library plus a C# metadata file, `global-metadata.dat`.
Recovering the game's structure — its classes, methods, fields and offsets — normally means
dumping that metadata and running Il2CppDumper.

This target does not ship one. A commercial obfuscator **replaces** the metadata with native
tables baked into the binary:

* no `global-metadata.dat` anywhere in the APK, the OBB or the app data
* the metadata magic `AF 1B B1 FA` occurs **zero** times in the APK, in the OBB, and in process
  memory both in the lobby and during a live match
* the replacement tables sit in a ~30 MB region of `.rodata` that no instruction references, and
  are wired in through relocation clusters in `.data` / `.data.rel.ro`

Every standard entry point is closed: Il2CppDumper needs a file that does not exist, the public
dumper for this title targets version 0.39.4, and the metadata decryptor looks for markers that
1.1.0 no longer contains.

**What this repository solves:** how to recover the same structure from such a build using only
the ELF file, plus read-only introspection of the running process.

---

## 2. The approach in one paragraph

The obfuscator stores every method pointer as a relocated pointer in `.data`. Methods of one
class occupy a contiguous run of those slots, so **the run boundaries are the class boundaries**.
IL2CPP emits every property as a two-instruction leaf function (`ldr/str s0,[x0,#N]; ret`), so
scanning for that shape yields each class's **field offsets and access modes**. At runtime, each
method owns a record whose `+0x30` is the owning class pointer, and each class holds a pointer
to its namespace string — whose address is known statically — so a single 8-byte needle finds
every class of an assembly at once. No metadata file, no debugger, no hooking.

Full derivation, including the corrections and the traps, is in
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

---

## 3. Findings

Written up in report form in [`docs/FINDINGS.md`](docs/FINDINGS.md). In brief:

| # | Finding |
|---|---|
| 1 | The client transmits its own root/device verdict to the backend, and the backend acts on it — the verdict is a client-controlled `bool` |
| 2 | The backend correlates and sanctions **devices** rather than accounts (`OnDeviceBanned { DeviceId }`), so a new account does not reset the sanction |
| 3 | The complete internal class/method/field map is recoverable from the shipped binary, and gameplay class names are plaintext in the metadata blob |
| 4 | Configuration deserialisation writes fields directly, bypassing property setters — so setter-side validation cannot be relied on |
| 5 | A malformed environment report raises a server-side `NullReferenceException` on the authentication path and presents to the player as a backend outage |

Findings 1 and 2 together are the substantive result: **the client-side anti-abuse design
cannot work as intended**, because the decision input is authored by the client and the sanction
is attached to an identifier that re-registration does not reset.

---

## 4. Tooling

| tool | what it does |
|---|---|
| `toolkit/device.py` | device layer: ADB, root-shell discovery, process selection, `/proc/<pid>/mem` access |
| `toolkit/elf_sections.py` | authoritative VA ↔ file-offset map from the ELF section headers |
| `toolkit/static_disas.py` | ARM64 disassembly, BL / ADRP cross-references |
| `toolkit/so2_tables.py` | robust loaders for the dump tables (their CSV quoting is broken) |
| `toolkit/class_table.py` | reconstructs class method tables from the relocated pointer arrays |
| `toolkit/find_accessors.py` | finds property accessors and maps them onto their class |
| `toolkit/find_class.py` | finds IL2CPP classes by namespace-string address |
| `toolkit/class_layout.py` | dumps a class's field names and offsets from the live process |
| `toolkit/dump_all.py` | full-memory method-record dumper |
| `toolkit/scan_big.py` | fast keyword scanner over a 200 MB binary |
| `toolkit/axml.py` | minimal Android binary-XML (manifest) reader |
| `toolkit/find_anticheat.py` | anti-tamper / root / emulator / debugger string scanner |

`toolkit/experimental/` holds approaches that did **not** work, kept because the negative results
are part of the method (see §9 of the methodology).

Every generated patch is round-tripped through Capstone and asserted to decode to the intended
instruction — the methodology documents the three encoding bugs that check caught.

---

## 5. Requirements

```bash
pip install -r requirements.txt
```

* **Static tools** (`elf_sections`, `static_disas`, `axml`, `find_accessors`, `scan_big`) need
  only the ELF file.
* **Runtime tools** (`find_class`, `class_layout`, `dump_all`) need the target running on a
  device or emulator with read access to `/proc/<pid>/mem`.

---

## 6. Responsible use

* Analyse only software you are authorised to analyse. For finding and fixing issues in
  software you do not own, the correct channel is the publisher's bug-bounty programme or a
  private disclosure — not a public exploit.
* The findings in `docs/FINDINGS.md` are written to be submitted to a publisher. The offsets
  they refer to are deliberately **not** included in this repository.
* `toolkit/` is intended for auditing a client's own defences: to check what a client detects,
  what it reports, and whether the backend trusts it.

---

## 7. License

MIT — see [`LICENSE`](LICENSE).

Standoff 2 is a trademark of Axlebolt Ltd. This project is not affiliated with, endorsed by, or
sponsored by Axlebolt Ltd, and contains no game binaries or proprietary game data.
