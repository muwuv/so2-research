# Methodology — recovering structure from an obfuscated Unity IL2CPP client

How the findings in [`FINDINGS.md`](FINDINGS.md) were obtained, in enough detail to reproduce
them on another target.

Target of the study: `com.axlebolt.standoff2` (Standoff 2), Android arm64-v8a, Unity IL2CPP,
version 1.1.0.

---

## 0. The obstacle

IL2CPP compiles C# to native ARM64 and normally ships the C# metadata alongside as
`global-metadata.dat`. Standard tooling (Il2CppDumper and friends) reads that file.

This build does not ship one:

| check | result |
|---|---|
| `global-metadata.dat` in APK / OBB / app data | absent |
| metadata magic `AF 1B B1 FA` in APK | 0 hits |
| metadata magic in the OBB | 0 hits |
| metadata magic in process memory (lobby **and** live match) | 0 hits |

Instead, a commercial obfuscator replaces the metadata with native tables compiled into the
binary. Those tables are not referenced by any instruction; they are wired in through
relocation clusters. Consequences:

* Il2CppDumper cannot run — the file it needs does not exist.
* A public dumper for this title targets 0.39.4, not 1.1.0.
* A metadata decryptor for this title looks for markers that 1.1.0 no longer contains.

The standard entry points are all closed. The work below reopens them.

---

## 1. Address translation, from the file rather than from notes

Every later step depends on converting a module virtual address to a file offset. Hand-written
section tables get this wrong, and the error is silent — the code still produces plausible
looking data.

`toolkit/elf_sections.py` reads the real ELF section headers with `pyelftools` and maps
VA → offset exactly.

Two corrections against commonly repeated values for this binary:

| section | VA → file-offset delta |
|---|---|
| `.text` | `0x4000` |
| `.rodata` | `0x0` |
| `.data`, `.got`, `.data.rel.ro` | `0x8000` |

---

## 2. The relocated pointer arrays are a class table

The obfuscator stores every method pointer as an `R_AARCH64_RELATIVE` relocation in `.data`.
Parsing `.rela.dyn` (1 140 032 entries in this build) yields a flat map:

```
slot address  ->  method VA
```

Methods belonging to one class occupy a **contiguous run of slots**. So the run boundaries
*are* the class boundaries, and a class's entire method list can be reconstructed without any
runtime involvement.

`toolkit/class_table.py` implements this. It uses the constructor as the terminator of a
class's method list, because IL2CPP emits the constructor last.

> **Caveat found the hard way.** The `.ctor` heuristic is a *heuristic*. On one large class
> boundary it produced a 1 447-method run that plainly spanned several classes. When a class
> boundary matters, confirm it against the method table rather than trusting the run.

---

## 3. Property accessors map fields to classes

IL2CPP emits every property as a tiny leaf function:

```asm
ldr  s0, [x0, #0x14]     ; float getter, field at +0x14
ret
str  s0, [x0, #0x14]     ; float setter
ret
ldr  x0, [x0, #0x40]     ; object getter
ret
```

`toolkit/find_accessors.py` scans `.text` for exactly that shape. The **class each accessor
belongs to** comes from the slot table of §2, because a method's slot position inside a
contiguous run identifies its class.

Result: for any class, the set of fields it has, their offsets, and which of them are read or
written — statically, from the file.

---

## 4. Reaching the runtime object graph

In the live process each method owns an `Il2CppMethodInfo` record:

| offset | field |
|---|---|
| `+0x04` | `uint32` MethodDef token |
| `+0x10` | `Il2CppMethodPointer` → the `.text` VA |
| `+0x18` | `const char*` name |
| `+0x30` | `Il2CppClass*` klass |

Two consequences:

1. **Method → class.** The class pointer of any method is reachable from a method VA that §2
   already produced: search the heap for the 8-byte method pointer, the record starts 0x10
   earlier, and `klass` is at `+0x30`.
2. **Namespace → all classes of an assembly.** `Il2CppClass` holds pointers to the class name
   and to the namespace, both pointing into the static string blob. The namespace string's
   address is known statically from `.rodata`, so a **single 8-byte needle** finds every class
   of that assembly at once — no method table needed.

`toolkit/find_class.py` implements (2); `toolkit/class_layout.py` reads a class's field table
out of the `Il2CppClass` and prints every field name with its offset.

---

## 5. Reading the client's own environment report

`AppVerification` is a protobuf message the client sends during sign-in. Locating it:

1. `toolkit/scan_big.py` sweeps the binary for keywords (`/proc/self/maps`, `TracerPid`,
   `magisk`, `ptrace`, `libunity.so`, the package name, …) and prints the surrounding strings.
2. The protobuf message set is recovered by name from the metadata blob, and the accessors
   (`get_IsRooted`, `set_IsRooted`, …) give the field offsets directly.
3. `toolkit/axml.py` parses the APK's binary `AndroidManifest.xml` (a minimal AXML reader —
   the manifest is binary XML, and the permissions are what decide whether the client *can*
   inspect other processes).

This is where the two findings that matter most came from: the environment verdict is a
client-side `bool` with a one-byte setter, and the sanction is attached to a device id.

---

## 6. Verifying every generated patch

Any instruction encoding computed by hand is a guess. Every patch this project emits is
round-tripped through Capstone and asserted to decode to the instruction intended.

That check caught three real errors that would otherwise have shipped:

| mistake | consequence |
|---|---|
| `str wzr` built as `0xB9000000 \| (imm<<10)` | register field must be **31**; without it the instruction is `str w0` and stores the *argument* instead of zero |
| `strb` offset scaled by 4 | `strb` uses an **unscaled** immediate: `strb w1, [x0, #0x6c]` is `0x3901B001`, not `0x39006001` |
| `fmov s0, wzr` as `0x1E2E13E0` | does not decode at all; the correct word is `0x1E2703E0` |

---

## 7. A methodological trap worth recording

A patch derived from a **linear disassembly window** — a few instructions printed starting at an
arbitrary address — crashed the target with `SIGSEGV`. The instruction was executed, but the
value it produced was not the one assumed, and forcing it to zero produced an invalid pointer.

**Linear disassembly windows are not function bodies.** Use the `.eh_frame` FDEs
(`dwarf.EH_CFI_entries()`) to obtain real function boundaries before reasoning about what a
piece of code does.

---

## 8. Reproducing

```bash
pip install -r requirements.txt

# static only, no device needed
python toolkit/elf_sections.py <path-to-libunity.so>
python toolkit/scan_big.py <path-to-libunity.so> anticheat
python toolkit/find_accessors.py <path-to-libunity.so>

# with the target running on a rooted device
python toolkit/find_class.py "Axlebolt.Standoff.Gameplay.Player"
python toolkit/class_layout.py Axlebolt.Standoff.Gameplay.Player
```

`toolkit/device.py` holds the device layer: ADB, root-shell discovery (the target's own
anti-root check hides `su`, so several locations are tried), process selection, and
`/proc/<pid>/mem` read/write helpers.

---

## 9. What was tried and did not work

Kept in `toolkit/experimental/` where it is still instructive.

* **Metadata magic scan** — no standard metadata image exists at all, in the file or in memory.
* **Static `ADRP`/literal scan for the metadata base** — the base is not built from any
  address-materialising instruction; the published "anchor" values for this title do not hold.
* **The `(slot_off, token)` table read as a vanilla IL2CPP usages table** — the offset field
  increments irregularly, so it is not "8 × slot index". Public notes on this title should be
  treated as hypotheses to re-verify.
* **Heuristic metadata-base search** (section contiguity, count magnitudes, header layout) —
  produces only false positives on data tables that happen to look like bitfields.
* **Runtime class-name resolution by scanning the whole heap** — works, but it is the slowest
  possible way to do it; the namespace-pointer search of §4 reaches the same classes in one
  narrow needle search.
