Below, “formats” are ELF, Mach-O, and PE. PIE / ASLR / RELRO / NX etc. are security *features* that each format represents differently. The goal is to normalize them into a single reporting model.

First outline what’s structurally different per format, then how to reconcile them into one report, then provide canonical references.

---

## 1. ELF

### 1.1 Characteristics

- Typical platforms: Linux, BSDs, most Unix-like OSes.
- Basic structure:
  - ELF header (`Elf32_Ehdr` / `Elf64_Ehdr`).
  - Program header table: segments (`PT_LOAD`, `PT_DYNAMIC`, etc.) used by the loader.
  - Section header table: sections (`.text`, `.data`, `.bss`, `.symtab`, `.dynsym`, `.rela.*`, DWARF sections, etc.) used mostly by the linker and tools.
- File types:
  - `ET_EXEC` (non-PIE executable).
  - `ET_DYN` (shared object / PIE).
  - `ET_REL` (relocatable object).
- Dynamic linking:
  - `PT_DYNAMIC` segment + `.dynamic` section.
  - `DT_NEEDED` entries list shared libs.
- PIE / ASLR:
  - Typically: **PIE if** `ET_DYN` executable with suitable relocations & compiled as PIE.
- RELRO:
  - Derived from `PT_GNU_RELRO` segment + `DF_BIND_NOW` (in dynamic flags).
- NX:
  - Often implied by presence/absence of executable permission on `PT_LOAD` segments (`PF_X`).

### 1.2 Library-Level Normalization

From ELF, you can fill unified fields such as:

- Format: `ELF`.
- Arch: from `e_machine` + `EI_CLASS` (32/64).
- OS/ABI: from `EI_OSABI` (Linux, FreeBSD, etc.).
- File type: exe/shared/object/core from `e_type`.
- PIE: `true` if `ET_DYN` main binary and expected to be loaded at randomized base.
- RELRO: derived from `PT_GNU_RELRO` + bind-now.
- NX: `true` if no writable+executable segments (derive from program headers).
- Stripped: `true` if `.symtab` missing / empty.
- Imports/exports: from `.dynamic`, `.dynsym`, `.symtab`.
- Sections/segments: direct from headers.

---

## 2. Mach-O

### 2.1 Characteristics

- Typical platforms: macOS, iOS, related Apple OSes.
- Basic structure:
  - Mach-O header (`mach_header` / `mach_header_64`).
  - Sequence of **load commands**:
    - Segment commands (`LC_SEGMENT[_64]`) each with one or more sections.
    - Dynamic linker info (`LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_ID_DYLIB`, `LC_LOAD_DYLINKER`).
    - Symbol table info (`LC_SYMTAB`, `LC_DYSYMTAB`).
    - UUID (`LC_UUID`), code signature (`LC_CODE_SIGNATURE`), etc.
- File types:
  - `MH_EXECUTE` (executable).
  - `MH_DYLIB` (dynamic library).
  - `MH_BUNDLE`, `MH_OBJECT`, `MH_CORE`, etc.
  - **Fat binaries** (multi-arch) via a separate `fat_header` + per-arch Mach-O slices.
- Dynamic linking:
  - `LC_LOAD_DYLIB`, `LC_REEXPORT_DYLIB`, `LC_RPATH`, etc.
- PIE / ASLR:
  - Flags in header, e.g. `MH_PIE`, `MH_TWOLEVEL`, etc.
  - Slide-at-load used for ASLR.
- RELRO-like behavior:
  - Not expressed as “RELRO” in spec; protection is more policy/OS-driven.
- NX:
  - Derived from segment protections in `LC_SEGMENT[_64]` (vm protection bits).

### 2.2 Library-Level Normalization

From Mach-O, you can fill unified fields:

- Format: `Mach-O`.
- Arch: from `cputype` / `cpusubtype` (normalized to `x86_64`, `arm64`, etc.).
- OS/ABI: `macOS`, `iOS`, etc. inferred from target/platform fields and common conventions.
- File type: exe/shared/object/core from `filetype`.
- PIE: `true` if `MH_PIE` flag set for an executable.
- ASLR: `true` if `MH_PIE` plus modern OS version assumed (you may mark “yes (inferred)”).
- RELRO: report as `unknown` or `n/a` (Mach-O has no native RELRO concept; document that).
- NX: `true` if code segments are RX not RWX; detect any RWX segments.
- Stripped:
  - If `LC_SYMTAB` is present but only minimal symbols, consider “partially stripped”.
  - If symbol table is missing or only a tiny subset, consider “stripped”.
- Imports/exports:
  - Imported dylibs from `LC_LOAD_*_DYLIB`.
  - Symbols from `LC_SYMTAB` / `LC_DYSYMTAB`.
- Multi-arch:
  - For fat binaries, present one entry per architecture under the same file path.

---

## 3. PE (Portable Executable)

### 3.1 Characteristics

- Typical platforms: Windows (32/64-bit), UEFI.
- Basic structure:
  - DOS header (`IMAGE_DOS_HEADER`) with `MZ` + stub.
  - PE signature (`PE\0\0`).
  - COFF file header (`IMAGE_FILE_HEADER`).
  - Optional header (`IMAGE_OPTIONAL_HEADER32/64`).
  - Section headers + sections.
- File types:
  - Executable images (`.exe`).
  - DLLs (`.dll`, `.ocx`, etc.).
  - Drivers (`.sys`), UEFI binaries, others.
- Dynamic linking:
  - Import directory (usually `.idata`) listing DLLs and imported symbols.
  - Export directory (usually `.edata`) listing exported symbols.
- PIE / ASLR:
  - ASLR indicated primarily by `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` in “DLL characteristics” (Optional header).
  - PE files are not PIC; relocation info in `.reloc` allows rebasing.
- RELRO:
  - Not a direct concept in PE; some roughly analogous mitigations exist but are OS/loader policy.
- NX (DEP):
  - `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` indicates DEP compatibility.
- Other Windows-specifics:
  - Code signing / certificates (attribute certificate table).
  - Debug info via debug directory and external PDB.

### 3.2 Library-Level Normalization

From PE, you can fill unified fields:

- Format: `PE`.
- Arch: from `Machine` in COFF header (normalize to `x86`, `x86_64`, `arm`, `arm64`, etc.).
- OS/ABI: `Windows` / `UEFI` inferred from subsystem, characteristics.
- File type: exe/shared/object/driver from characteristics + subsystem.
- PIE:
  - Represent as: “ASLR capable” if `DYNAMIC_BASE` set and reloc section present.
  - For the unified model, you can have:
    - `pie_capable` (bool) and
    - `pie_effective` (bool or unknown), since Windows semantics differ.
- ASLR:
  - `true` if `DYNAMIC_BASE` and relocations available.
- RELRO:
  - `unknown`/`n/a` (no direct mapping).
- NX:
  - `true` if `NX_COMPAT` is set.
- Stripped:
  - If COFF symbol table is absent and debug directory either missing or external-only, mark as stripped.
- Imports/exports:
  - DLL dependencies and imported symbols from import directory.
  - Exported symbols from export directory.
- Sections/segments:
  - Sections from section headers with characteristics (RX, RW, etc.).

---

## 4. Reconciling Differences in Reporting

Design a **format-neutral report model** where each field is either:

- **Directly mappable** for all three formats.
- **Derived/inferred** differently per format.
- **Intentionally “unknown/not applicable”** on some formats.

### 4.1 Core Identity Fields

Normalize:

- `format`: `ELF` | `Mach-O` | `PE`.
- `os_abi`: `Linux`, `FreeBSD`, `macOS`, `iOS`, `Windows`, `UEFI`, `Unknown`.
- `arch`: `x86`, `x86_64`, `armv7`, `arm64`, etc.
- `bitness`: `32` | `64`.
- `file_kind` (unified):
  - `executable`
  - `shared_library`
  - `object`
  - `core_dump`
  - `driver`
  - `other`.

Each parser fills these from its native headers; the CLI never shows raw native enum values.

### 4.2 Security-Feature Fields

Define a canonical set:

- `pie` (bool | unknown):
  - ELF: true if `ET_DYN` main binary with expected PIE semantics.
  - Mach-O: true if `MH_PIE`.
  - PE: true if ASLR/relocs imply relocatable image; document semantics difference.
- `aslr` (bool | unknown):
  - ELF: derived from OS + PIE; typically same as `pie` in modern setups.
  - Mach-O: true if `MH_PIE`.
  - PE: true if `DYNAMIC_BASE` + reloc info present.
- `nx` (bool | unknown):
  - ELF: if no RWX segments.
  - Mach-O: if segments follow RX/RW separation and OS supports NX.
  - PE: if `NX_COMPAT` flag set.
- `relro` (`none` | `partial` | `full` | `unknown` | `not_applicable`):
  - ELF: derived from `PT_GNU_RELRO` + bind-now.
  - Mach-O / PE: `unknown` or `not_applicable`.
- `stripped` (`yes` | `no` | `partial` | `unknown`):
  - ELF: presence/absence of `.symtab`, debug sections.
  - Mach-O: symbol table size vs. expected; debug info presence.
  - PE: COFF symbol table, debug directory, PDB references.

The CLI always presents *the same small set of fields* for any file, with per-format notes when something is not meaningful (e.g. `RELRO: not applicable (Mach-O)`).

### 4.3 Structural Fields

Unified:

- `sections[]`:
  - `name`, `kind` (`code` / `data` / `bss` / `debug` / `other`), `size`, `file_offset`, `flags` (R/W/X).
  - ELF sections map directly.
  - Mach-O sections are from segment+section pairs, but exposed simply as sections.
  - PE sections from section headers.
- `segments[]` (if available):
  - For PE, segments == sections for most use-cases; you can either:
    - treat PE sections as segments; or
    - mark `segments` as `not_applicable` and rely on `sections` only.
  - For ELF and Mach-O, segments are real loader units and should be represented.
- `imports[]`:
  - ELF: from `DT_NEEDED` and `dynsym`.
  - Mach-O: from `LC_LOAD_*_DYLIB` and symbol tables.
  - PE: from import descriptors.
- `exports[]`:
  - ELF: from `dynsym`/`symtab`.
  - Mach-O: from symbol tables / export trie.
  - PE: from `.edata`.

Even when some formats don’t have an exact 1:1 concept, you still expose the arrays but may leave them empty.

### 4.4 Reporting Strategy in CLI

For each file, present:

1. **Summary block** (format-independent):
   - Format, OS/ABI, arch, bitness, file kind.
   - Entry point (if applicable).
   - Security flags: PIE, ASLR, NX, RELRO, Stripped.
2. **Details blocks** (same headings, contents per format):
   - Sections (same columns regardless of ELF/Mach-O/PE).
   - Segments (if applicable).
   - Dependencies (imports).
   - Symbols (exports/imports, when requested).

If a field is not meaningful on a given format, clearly display a neutral value:

- e.g. `RELRO: not applicable for PE` rather than leaving it out.

---

## 5. Canonical References

Use these as spec / documentation anchors in comments and docs:

- **ELF**
  - System V Application Binary Interface, AMD64 Supplement (includes ELF spec):
    - https://refspecs.linuxfoundation.org/elf/elf.pdf
  - OSDev ELF overview (informal but practical):
    - https://wiki.osdev.org/ELF

- **Mach-O**
  - Apple “Mach-O Executable Format” overview:
    - https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html
  - OS X ABI Mach-O File Format Reference (Apple doc mirror):
    - https://github.com/aidansteele/osx-abi-macho-file-format-reference

- **PE (Portable Executable)**
  - Microsoft PE and COFF specification:
    - https://learn.microsoft.com/windows/win32/debug/pe-format
  - Background summary:
    - https://en.wikipedia.org/wiki/Portable_Executable

In your code module, you can link to these in docstrings next to the format-specific parsers and the feature-mapping logic so future contributors see exactly where each mapping came from.


```python
# Top-level entry: analyze a binary from a byte stream / buffer
#
# Input:
#   reader:  random-access byte source with:
#              read_at(offset, length) -> byte[]
#              len() -> integer (total size)
# Output:
#   Result<BinaryDescription, ParseError>

function analyze_binary(reader):
    # 1. Sanity check
    if reader.len() < MIN_HEADER_SIZE:
        return Err(ParseError.TooSmall)

    # 2. Detect format
    detection = detect_format(reader)
    match detection.kind:
        case FormatKind.ELF:
            return decode_elf(reader, detection.elf_hint)
        case FormatKind.MACHO:
            return decode_macho(reader, detection.macho_hint)
        case FormatKind.PE:
            return decode_pe(reader, detection.pe_hint)
        case FormatKind.UNKNOWN:
            return Err(ParseError.UnknownFormat(detection.reason))


# Detect the format by examining magic bytes and minimal header fields.
#
# Output:
#   DetectionResult with:
#     kind: ELF | MACHO | PE | UNKNOWN
#     elf_hint / macho_hint / pe_hint: optional small info (bitness, endian, etc.)
#     reason: string (for UNKNOWN)

function detect_format(reader):
    # Read enough bytes to decide among ELF / Mach-O / PE.
    # Use a fixed-size prefix; 64 bytes is more than enough.
    prefix_len = min(64, reader.len())
    prefix = reader.read_at(0, prefix_len)

    # 1. ELF: starts with 0x7F 'E' 'L' 'F'
    if prefix.len() >= 4 and
       prefix[0] == 0x7F and prefix[1] == 'E' and prefix[2] == 'L' and prefix[3] == 'F':
        # ELF header fields:
        #   EI_CLASS (32/64) at offset 4
        #   EI_DATA (endian) at offset 5
        ei_class = prefix[4]     # 1 = 32-bit, 2 = 64-bit
        ei_data  = prefix[5]     # 1 = little, 2 = big endian
        elf_hint = ElfHint(
            bitness = if ei_class == 1 then 32 else 64,
            endian  = if ei_data == 1 then LITTLE else BIG
        )
        return DetectionResult(kind = ELF, elf_hint = elf_hint)

    # 2. Mach-O:
    #    Several magic constants possible (32/64, BE/LE, MH vs MH_CIGAM, plus FAT)
    #    Check first 4 bytes for known Mach-O or FAT magic values.
    if prefix.len() >= 4:
        magic = read_u32_be(prefix[0..4])  # interpret as big-endian for comparison
        if magic in MACHO_MAGIC_SET:
            # Distinguish 32/64, endian, fat vs thin
            macho_hint = parse_macho_magic(magic)
            return DetectionResult(kind = MACHO, macho_hint = macho_hint)

    # 3. PE:
    #    DOS header 'MZ' at offset 0, then PE signature at e_lfanew.
    if prefix.len() >= 2 and prefix[0] == 'M' and prefix[1] == 'Z':
        # Need the PE header offset from DOS header (e_lfanew at offset 0x3C, 4 bytes LE).
        if reader.len() >= 0x3C + 4:
            dos_header = reader.read_at(0, 0x40)  # small DOS header region
            e_lfanew = read_u32_le(dos_header[0x3C..0x40])
            # Basic sanity: e_lfanew must be within file bounds and allow "PE\0\0"
            if e_lfanew + 4 <= reader.len():
                pe_sig = reader.read_at(e_lfanew, 4)
                if pe_sig == ['P', 'E', 0x00, 0x00]:
                    # Optionally, peek Machine / OptionalHeader.Magic
                    coff_header = reader.read_at(e_lfanew + 4, 4 + 20)  # sig + COFF header
                    machine = read_u16_le(coff_header[4..6])
                    pe_hint = PeHint(machine = machine)
                    return DetectionResult(kind = PE, pe_hint = pe_hint)

    # 4. None matched
    return DetectionResult(
        kind   = UNKNOWN,
        reason = "Unrecognized magic or invalid header"
    )


# Format-specific decoders: take the same reader and any hints extracted during detection,
# return a unified BinaryDescription or a ParseError.

function decode_elf(reader, elf_hint):
    # Validate full ELF header, parse program headers, sections, etc.
    # On success, map to BinaryDescription.
    # On failure, return ParseError.
    ...

function decode_macho(reader, macho_hint):
    # Validate Mach-O / FAT header, iterate load commands, etc.
    # On success, map to BinaryDescription.
    ...

function decode_pe(reader, pe_hint):
    # Validate PE headers, section table, data directories, etc.
    # On success, map to BinaryDescription.
    ...
```
