---
type: standard
date: 2026-02-24
session_goal: "Continue Phase 2 Mach-O decoding: support common Mach-O variants (thin 64-bit little-endian), add FAT/universal support, adopt a single owning BinaryBundle + zero-copy backing buffer, add invariant-focused tests, and extract repeated parsing patterns into module-level helpers."
files_touched:
  - src/root.zig
  - chronicles/session-2026-02-24-215948.txt
  - chronicles/quicklog-2026-02-24-220000.md
  - chronicles/session-2026-02-23-233014.txt
  - chronicles/session-2026-02-24-002100.txt
modules_changed:
  - root (src/root.zig)
  - decoders (ELF/Mach-O behavior in root)
dependencies:
  added: []
  removed: []
  updated: []
duration: "~3h"
status: in-progress
---

# Session Chronicle: Mach-O Phase 2 (standard chronicle)

## Quick Summary
Implemented a substantial Phase 2 iteration of the Mach-O decoder in src/root.zig: 64-bit little-endian Mach-O decoding (thin), FAT/universal container handling (iterate slices), and a BinaryBundle ownership model that provides a single allocator-owned backing buffer for zero-copy slices. Added invariant-focused tests for ELF and Mach-O, fixed several alignment/comptime/runtime issues encountered during development, and refactored repeated parsing patterns into module-level helper functions to reduce duplication and clarify intent. Big-endian and 32-bit Mach-O full support, export-trie / dyld-info parsing, and dysymtab/indirect-symbol handling remain planned.

---

## What We Built/Changed
- Mach-O phase 2 implementation in src/root.zig:
  - decodeMachoSlice(...) — parses single Mach-O slice, supports little-endian 64-bit path using std.macho helpers and a conservative big-endian header path.
  - decodeMacho(...) — reads full file into one allocator-owned backing buffer, detects FAT containers, iterates fat_arch entries, and produces a BinaryBundle with one BinaryDescription per decoded slice.
- BinaryBundle introduced as the single owning container (items: []BinaryDescription + backing_file: []u8) and BinaryBundle.free(allocator, bundle) to free everything.
- Updated decodeElf/analyzeBinary to return BinaryBundle (single-item bundle for ELF).
- SYMTAB-first strategy implemented for baseline imports/exports (nlist/nlist_64 + strtab). parseSymtab(...) helper added.
- FAT container handling: iterate fat_arch, create slices into backing buffer, attempt decoding only for supported variants (conservative: skip unsupported/big-endian slices).
- Added invariant-focused tests in src/root.zig:
  - "decoders.invariants: ELF (...)"
  - "decoders.invariants: Mach-O (...)"
  Tests assert backing buffer invariants, section/segment bounds, basic structural sanity, and that writePretty() runs.
- Refactor: extracted repeated patterns into module-scope helper functions (see "Helpers Extracted" below).
- Created and linked chronicles (quicklog + detailed session chronicle).

## Helpers Extracted (module scope)
These helpers reduce duplication and centralize endian/struct handling decisions:

- zslice(bytes: []const u8) []const u8 — find NUL terminator and return zero-terminated slice.
- machoProtToPermission(p: macho.vm_prot_t) Permission — translate Mach-O initprot/maxprot flags to our Permission enum.
- elfSectionFlagsToPermission(sh_flags: u64) Permission — map ELF sh_flags -> Permission.
- elfProgFlagsToPermission(p_flags: u32) Permission — map ELF program header flags -> Permission.
- appendSegmentAndMap(allocator, segments_list, segmaps, fileoff, filesize, vmaddr, perm) — append a segment entry and maintain the segment->vmaddr map used for entrypoint translation.
- appendSectionFromBlock(allocator, sections_list, block, is64, m_endian) — parse a raw section block (either 32/64 and either endian) and append a Section (zero-copy names pointing into the backing buffer).
- appendDylibNameFromLcData(allocator, imports_list, lc_data, m_endian) — extract dylib/name string from a load-command data block (endianness-aware).
- appendRpathMessageFromLcData(allocator, messages_list, lc_data, m_endian) — extract rpath string for messages.
- parseSymtab(allocator, macho_buf, symoff, nsyms, stroff, strsize, is64, m_endian, imports, exports) — unified SYMTAB parsing for little- and big-endian variants (SYMTAB-first symbol discovery).

These were added because the main decode path was repeating the same logic in multiple places (little-endian std.macho path vs manual big-endian parsing), and pulling helpers reduces future surface area to keep consistent when adding more variants.

## Key Decisions & Rationale
- BinaryBundle single owner: one backing buffer per analyzed file (BinaryBundle.backing_file) and lightweight BinaryDescription views that point into it. Rationale: efficient zero-copy slices across multiple architecture slices (fat binaries) and consistent lifetime management.
- Zero-copy model preserved: read the entire file into allocator-owned buffer and return slices pointing into it (no duplicated file contents unless caller explicitly makes owned copies).
- Conservative variant support: only fully decode variants we support (currently 64-bit little-endian). For unsupported slices (big-endian, unknown arch) we either return error.UnsupportedVariant or skip the slice inside a FAT container. Rationale: avoid unsafe parsing.
- SYMTAB-first symbol strategy: pragmatic baseline for imports/exports (nlist/nlist_64 + strtab). Export trie / dyld-info parsing to follow.
- Use stdlib helpers where possible (std.macho, std.elf) but avoid assuming native endianness for big-endian files: implemented a manual parsing path for headers/load commands and added helpers to keep logic localized.
- Avoid copying embedded .interface values: use returned file.reader(file_buf) and call reader.interface methods directly rather than copying the entire interface value.

## Next Steps
- Implement full big-endian and 32-bit Mach-O parsing (safe, endianness-aware field extraction for load commands, sections, and symbols).
- Parse LC_DYLD_INFO and LC_DYLD_EXPORTS_TRIE (export trie) and LC_DYSYMTAB + indirect symbol table to improve import/export accuracy.
- Improve Mach-O security feature detection (NX, RELRO, ASLR) by inspecting segment protections and flags.
- Add unit tests for fat Mach-O fixtures, malformed/truncated inputs, and explicit big-endian/32-bit fixtures once support is implemented.
- Consider moving Mach-O parsing out of src/root.zig into a dedicated module/file for readability and testing.
- Push commits and open a PR; add CI guards for platform/fixture-specific tests if needed.

## Unresolved Issues / Caveats
- Current big-endian path: header fields are now extracted for big-endian slices, but some later parsing still relies on std.macho helpers or pointer casts that assume native/little endianness. This is an intentional, staged approach but means big-endian slices are not fully parsed yet.
- Symbol resolution is SYMTAB-first; export-trie and dyld-info processing are not implemented, so imports/exports may be incomplete for some Mach-O binaries.
- Indirect symbol table (LC_DYSYMTAB) parsing is missing; lazy/non-lazy imports and stub resolution are not yet correct.
- There are lots of alignment/pointer-cast pitfalls in Zig — we used align(1) casts and read slices carefully, but further review/CI is needed.

---

## Technical Deep Dive (optional)

Implementation notes useful for follow-up work and reviews:
- Ownership/lifetimes: BinaryBundle owns the backing_file []u8. All BinaryDescription slices point into bundle.backing_file. Callers must call BinaryBundle.free(allocator, bundle) to free the owned slices and the backing buffer.
- To avoid comptime/runtime @sizeOf pitfalls we compute sizes in runtime variables when the value depends on runtime control flow (e.g., nlist entry size selection) instead of embedding @sizeOf(...) in a comptime-only context.
- Load command iteration: for little-endian slices we reuse std.macho.LoadCommandIterator. For big-endian slices we implemented a manual lc loop that reads cmd/cmdsize via mem.readInt(..., m_endian) and slices lc_data for safe indexed reads.
- Symbol parsing: parseSymtab() implements both little-endian (ptr-cast into macho.nlist[_64] with align(1)) and big-endian manual read paths to avoid undefined behaviour on unaligned/native-endian differences.

### Tests added
- src/root.zig tests: two new invariant-based tests for ELF and Mach-O decoders. They check:
  - analyzeBinary returns BinaryBundle with >=1 item,
  - format/bitness/arch/file_kind are sane,
  - sections/segments > 0,
  - file_offset + size <= backing_file.len for non-zero offsets,
  - imports/exports names non-empty if present,
  - writePretty() runs and produces output.

## Learning & Insights
- Zig pointer-cast/alignment and comptime/@sizeOf interaction are delicate; prefer explicit runtime size variables and align(1) casts when parsing raw bytes.
- Copying interface-typed structs (Reader/Writer) can panic; use .interface pointer and call methods on the interface value returned by file.reader(file_buf).

## References & Resources
- Zig stdlib: std.macho.zig, std.elf.zig, std.mem.readInt
- Mach-O format references (Apple/UNIX docs) and export-trie/dyld-info descriptions.

---

## Context for Next Session
Start by finishing big-endian/32-bit parsing: implement endianness-aware load-command parsing and section/symbol extraction (move away from ptrCast when necessary). Then implement LC_DYLD_EXPORTS_TRIE and LC_DYLD_INFO parsing, followed by LC_DYSYMTAB/indirect symbol table handling. After that, add fat-Mach-O fixtures and negative tests. Finally, consider splitting Mach-O-specific parsing into its own module for clarity and to simplify unit testing.

Related chronicles:
- chronicles/quicklog-2026-02-24-220000.md
- chronicles/session-2026-02-24-215948.txt
