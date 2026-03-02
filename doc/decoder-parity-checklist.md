Decoder Parity & DebugInfo Checklist

Goal

Bring PE, Mach-O (and any other supported binary decoders) to feature parity with the ELF decoder. Also add basic debug-info/PDB extraction where the format supports it. The result should be a consistent BinaryDescription across formats, comprehensive tests, and CI coverage to prevent regressions.

Scope

- Formats: PE (Portable Executable), Mach-O, any other binary formats present or planned
- Baseline: features currently implemented in decodeElfSlice (as of src/slice_decoders.zig)
- Debug info: for PE (PDB), ELF (DWARF already planned/partial), Mach-O (DWARF, dSYM), and any format that supports symbol/debug containers

High-level checklist

1) Standard metadata parity
- [ ] File identification and sanity checks (magic, basic header validation)
- [ ] Bitness detection (32 vs 64)
- [ ] CPU architecture mapping (x86/x86_64/ARM/ARM64 + sensible handling of unknown machines)
- [ ] File kind: executable / shared_library / object / unknown
- [ ] Endianness reporting (where applicable)
- [ ] Entry point virtual address
- [ ] Image base / preferred base (where applicable)

2) Sections, segments, and segment/virtual->file mapping
- [ ] Build section list with: name, kind (or unknown), size, file_offset, permission bits, flags
- [ ] Build segment list (segments consumed by loader) where format provides them
- [ ] Build SegmentMap(s) for vaddr -> file offset translation and use them for data-directory mapping
- [ ] Ensure segments/segmaps cover dynamic string tables, exports, imports, and debug regions

3) Imports and exports
- [ ] Import entries populated consistently: dll/library name (or empty), symbols list (by-name/by-ordinal), ordinals recorded where applicable
- [ ] Handle import-by-ordinal and emit diagnostics/messages where names cannot be resolved
- [ ] Exports: parse export directory/table and list export names; record forwarding information if possible
- [ ] Expose empty symbol lists as empty slice vs null pointer consistently across formats

4) Symbol tables and exports
- [ ] Parse linked symbol tables (SHT_SYMTAB / SHT_DYNSYM for ELF; COFF symbol table for PE when present; Mach-O symbol table) and populate exports and undefined symbol lists
- [ ] For ELF we already collect undefined symbol names into ImportEntry with empty dll; replicate semantics for other formats where practical

5) Dynamic linking metadata
- [ ] For ELF: DT_NEEDED, DT_STRTAB/DT_STRSZ parsing with fallback to .dynstr (already present)
- [ ] For PE: import directory table handling, thunk table traversal, delay-load import descriptors
- [ ] For Mach-O: LC_DYLD_INFO/LC_LOAD_DYLIB/LC_LOAD_WEAK_DYLIB processing, indirect symbol tables and stubs

6) Security hints and loader characteristics
- [ ] NX (executable stack) hint
- [ ] RELRO equivalent (for PE: note not applicable; for Mach-O: dyld_rebase/dyld_bind semantics) — ensure consistent enums: perhaps not_applicable/unknown/yes/no/partial
- [ ] PIE / dynamic base (ASLR) hint
- [ ] ASLR/NX via flags/characteristics and platform-specific fields (DllCharacteristics for PE; PT_GNU_STACK and ET.DYN for ELF; Mach-O PIE flags)

7) Debug info detection and basic parsing
- [ ] Detect presence of debug info: data directories / debug sections / dSYM / DWARF / PDB pointers
- [ ] For ELF: detect .note.gnu.build-id, .debug_* presence, and DWARF sections; optionally read DWARF unit presence (CU headers) to set debug_info_present true
- [x] For Mach-O: detect LC_UUID, LC_DYSYMTAB, DWARF sections, and dSYM companion; report debug_info_present and path/uuid for dSYM link (partial: detection for UUIDs/dwarf presence present; dSYM pairing tests pending)
- [x] For PE: detect IMAGE_DIRECTORY_ENTRY_DEBUG, read IMAGE_DEBUG_DIRECTORY entries, extract CodeView signature / PDB path and GUID/age; report debug_info_present and PDB metadata (path, guid, age) (IMPLEMENTED: decodePESlice extracts RSDS PDB path into BinaryDescription.debug_pdb_path; allocation and deallocation updated. Tests for PDB path extraction still pending)
- [ ] Provide a minimal API in BinaryDescription to hold debug metadata: debug_info_present: bool, debug_type: enum (none,pdb,dwarf,dsym,other), debug_metadata: optional struct { path, guid, age, uuid }

8) Error handling and diagnostics
- [ ] When mapping vaddrs to file offsets fails, append a Message rather than panicking (ELF behavior)
- [ ] Emit useful messages for import-by-ordinal, unmapped thunk tables, malformed table sizes, oversized counts
- [ ] Keep parsing robust to truncated/strange files (return ParseError.TooSmall / Malformed / InvalidHeader as appropriate)

9) Tests and fixtures
- [ ] Add positive PE fixtures to testing/assets (32-bit EXE, 64-bit EXE, 32/64 DLL, import-by-ordinal example, forwarded export example)
- [ ] Add tests that exercise PE imports, exports, debug directory parsing, and security hints similar to ELF tests
- [ ] Add negative tests (PE decoder rejects ELF, truncated headers, unmapped RVAs) similar to existing decodePESlice tests
- [ ] Add Mach-O fixtures covering dyld imports, dSYM pairing, and dynamic libraries; expand tests to check imports/exports, debug presence
- [ ] Add cross-format invariant tests: for each fixture, confirm BinaryDescription fields (format, arch, bitness, sections/segments populated, imports/exports presence as expected)
- [ ] Add targeted edge-case tests: oversized counts, malformed sizes (DT_STRSZ-like), missing name tables, dynamic table mapping failures
- [ ] Consider adding fuzz tests / libFuzzer harness for each decoder focusing on bounds checks and corrupt headers
- [x] Fixed unit-test leak for decodePESlice by ensuring desc.debug_pdb_path is freed and deallocators updated (tests updated where needed)

10) CI and automation
- [ ] Ensure tests run in CI (unit tests that read fixtures in testing/assets) on supported CI platforms
- [ ] Fail CI on regressions that remove expected imports/exports or break parsing behavior
- [ ] Add a small linter/checker to ensure new decoders append messages rather than panicking on recoverable errors

11) API and consistency
- [x] Standardize BinaryDescription fields and semantics across formats (format enum, os_abi, arch, bitness, endianess, file_kind, entrypoint_virtual_address, pie/aslr/nx/relro enums, stripped state) (partial: debug_pdb_path field added; ensure other fields consistent ongoing)
- [x] Make sure path ownership semantics are identical (how desc.path is allocated and freed) (IMPLEMENTED: BinaryDescription now owns copies; deallocators updated to free debug_pdb_path)
- [ ] Ensure imports/exports/messages slices are allocated/owned same way and freed via root.freeImportEntries where necessary

12) Additional PE/Mach-O-specific enhancements
- [ ] PE: parse delay-load import descriptors, TLS directory (callbacks), bound import tables, import forwarding
- [ ] PE: read and parse Rich header (detection only) and record as diagnostic message (do not rely on decoding its contents unless needed)
- [ ] PE: handle COFF symbol table if present and useful for object files
- [ ] Mach-O: parse indirect symbol table, stubs, lazy/non-lazy symbol pointers, LC_DYLD_* commands for rebasing/binding info
- [ ] Mach-O: parse dyld shared cache references if useful for imports in dyldcache-arm64 scenarios (optional)

13) Debug-info extraction details
- [x] PDB (PE/codeview): when IMAGE_DEBUG_DIRECTORY.CodeView found, parse CV signature and extract PDB path, GUID/age or RSDS/ NB10 signatures (IMPLEMENTED: RSDS path extraction implemented; GUID/age extraction TODO)
- [ ] DWARF: for ELF and Mach-O, minimally validate presence of .debug_info and maybe read first CU header to ensure it's parseable (don't need full DWARF parsing initially)
- [ ] dSYM (Mach-O): detect UUIDs in binary and match to .dSYM bundles (if available in testing assets) and report dSYM path/uuid
- [ ] Produce debug metadata that caller code can use to lookup debug files (path/uuid/guid/age)

14) Documentation and examples
- [x] Update README.md or docs/ to document decoder feature parity and how to extend decoders (partial)
- [x] Add doc/decoder-parity-checklist.md (this file) under version control
- [ ] Add examples of reading debug metadata from PE and ELF (small snippets or tests)

15) Chronicle and audit trail (operational requirement)
- [x] For every change that mutates repository state (creating tests, adding fixtures, adding code), create/append a chronicle entry under chronicles/ recording: timestamp, participants, summary of actions, representative commands run, files added/modified, and suggested next steps
- [x] Use sg bookmarks to reference important locations and always run `sg primer` when unsure about bookmark use

Implementation plan (phased)

Phase 0 — Preparation
- [x] Inventory existing tests & fixtures for ELF/PE/Mach-O under testing/assets (partial: inventory done; fixture additions pending)
- [ ] Identify missing fixture artifacts and source them or build small binaries (using docker/clang/mingw toolchains if necessary)
- [x] Add skeleton tests for PE positive fixtures to mirror ELF test patterns (partial: initial tests added; PDB-specific tests pending)

Phase 1 — Parity: imports/exports/sections
- [ ] Add positive PE fixtures and tests for imports/exports/sections
- [ ] Add Mach-O tests for imports/exports already present, expand if gaps exist
- [ ] Ensure vaddr->file offset mapping used for all formats consistently

Phase 2 — Dynamic/edge case parity & messages
- [ ] Implement delay-load import parsing for PE
- [ ] Add robust handling of forwarded exports and import-by-ordinal messages
- [ ] Add tests that corrupt tables to ensure decoder appends messages rather than panics

Phase 3 — Debug info detection & basic extraction
- [x] PE: implement IMAGE_DEBUG_DIRECTORY / CodeView PDB metadata extraction and tests (partial: extraction implemented; tests TBD)
- [ ] ELF/Mach-O: detect DWARF presence and minimally validate
- [ ] Add BinaryDescription.debug_metadata structure and populate it

Phase 4 — Advanced features & hardening
- [ ] Add COFF symbol table parsing for PE object files
- [ ] Add TLS/delay-load/Bind-time/Relocations handling where it helps mapping imports
- [ ] Add fuzzing harnesses and integrate with CI for decoder robustness

Phase 5 — Documentation and CI
- [ ] Document decoder behaviors and debug metadata format in docs/
- [ ] Add CI jobs to run the decoder tests and guard test fixtures availability
- [ ] Ensure chronicle entries are created for each PR/merge that modifies decoders or tests

Testing artifacts and fixtures suggestions
- PE fixtures:
  - 64-bit EXE linking to kernel32/user32 (import-by-name)
  - 32-bit EXE with import-by-ordinal
  - 64-bit DLL with forwarded export
  - EXE with IMAGE_DEBUG_DIRECTORY pointing at an embedded PDB path (CodeView RSDS signature)
- Mach-O fixtures:
  - 64-bit macOS app / binary with LC_LOAD_DYLIB imports
  - dSYM pair: Mach-O + .dSYM bundle to test detection & uuid matching
- ELF fixtures:
  - existing fixtures in testing/assets (keep)

Notes and conventions
- BinaryDescription should remain a shallow summary — we don't intend to fully parse DWARF or PDB here, only extract metadata to find debug files. Full DWARF/PDB parsing can be added later behind a separate subsystem.
- When adding messages, prefer short, actionable strings (e.g. "import thunk table RVA unmapped") and avoid leaking sensitive data like full paths from user files unless necessary.
- Keep parsers defensive: whenever reading sizes or counts from the file, check for overflow and bounds and append diagnostic messages rather than crashing.

Files to add/modify (proposed)
- src/slice_decoders.zig (expand PE and Mach-O decoders as needed)
- testing/assets/pe-64bit-exe.exe
- testing/assets/pe-32bit-exe-ordinal.exe
- testing/assets/pe-dll-forwarded.dll
- testing/assets/pe-pdb-codeview.exe (contains debug directory pointing to PDB)
- testing/assets/macho-dylib-x64
- testing/assets/macho-dsym-example (bundle)
- tests in src/slice_decoders.zig (or split to src/tests/pe_tests.zig)
- doc/decoder-parity-checklist.md (this file)

Estimated effort
- Bring PE to ELF feature parity (imports/exports/sections/debug metadata detection + tests): 1-3 days depending on availability of fixtures and CI configuration
- Mach-O parity gaps (if any) + debug metadata: 0.5-2 days depending on tests
- PDB basic extraction + tests: 0.5-1 day
- Fuzz harness + CI integration: 1-3 days

Next steps (if you want me to act)
- I can start by adding PE fixtures and a positive unit test mirroring decodeElfSlice expectations and produce a patch/PR; I will create the required chronicle entry as part of the change.
- Alternatively, I can draft the concrete test cases and the minimal PDB extraction code changes to src/slice_decoders.zig.

Operational reminders
- Always create chronicle entries for repository mutations in chronicles/
- Use `sg` bookmarks and run `sg primer` when navigating bookmarks

End of checklist
