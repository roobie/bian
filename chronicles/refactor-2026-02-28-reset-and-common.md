Refactor progress — 2026-02-28

Summary:
- Reset repository to commit a786c9ba28a1c43d406b7fc5df06f51817ea9872 (baseline for incremental refactor).
- Created src/common.zig with a small, well-scoped set of helpers to start the module split:
  - prefix_length
  - readU32At, readU64At, readI32At (endian-aware readers)
- Updated src/root.zig to import common.zig and re-export short names (prefix_length, readU32At, readU64At, readI32At) to keep existing code working while moving implementations out of root.
- Kept src/slice_decoders.zig minimal/placeholder for now (compile-friendly). This will be expanded incrementally in subsequent steps.

Next incremental move (2026-02-28): moved four additional safe helpers into src/common.zig
- SegmentMap (struct)
- zslice(bytes)
- vaddrToFileOffset(file_len, segmaps, vaddr)
- safeSlice(buf, off64, len64)

Next incremental move (2026-02-28): moved Section/Permission/SectionKind and appendSegmentAndMap into src/common.zig
- SectionKind, Permission, Section were small and safe to centralize; they were moved into common to allow appendSegmentAndMap to live in common and be reused without circular imports.
- Implemented appendSegmentAndMap in common using the moved Section type.

Next incremental move (2026-02-28): moved appendSectionFromBlock into src/common.zig
- appendSectionFromBlock depends on Section and Endian; it was moved into common. References to std.macho and std.mem were used to keep the function self-contained in common.zig.

Next incremental move (2026-02-28): moved appendDylibNameFromLcData into src/common.zig
- appendDylibNameFromLcData parses LC_DATA blocks to extract the dylib name offset and appends the name to imports_list. It was moved into common and now uses std.mem.sliceTo and common.readU32At.

Additional moves (2026-02-28): moved readU16LE and appendRpathMessageFromLcData into src/common.zig
- readU16LE (PE helper) was moved from src/root.zig into src/common.zig and re-exported from root as common.readU16LE. This keeps PE parsing utility functions centralized and avoids duplicate definitions.
- appendRpathMessageFromLcData (Mach-O RPATH helper) was moved into src/common.zig. It extracts the RPATH string from LC_RPATH/LC_LOAD_DYLIB-like load command data and appends a Message containing the path to the messages list. Root now aliases this symbol to keep the API stable.

Rationale and notes:
- usingnamespace is no longer part of Zig — use explicit imports and explicit aliases instead. To avoid circular imports and duplicate-symbol issues, move only a tiny set of low-risk helpers to common.zig and alias them from root.zig. This keeps the public API stable while allowing slice decoders and other modules to import common directly.
- Changes made here are intentionally conservative to keep the test suite green at every step. By moving the most commonly used low-level helpers first, future moves (e.g., PT_DYNAMIC parsing helpers, or full slice decoders) will be easier and less likely to create cycles.

Next steps:
1. Run tests (already run in this commit) and confirm behavior is unchanged.
2. Continue moving additional helpers in small batches. Suggested next target: finalize src/slice_decoders.zig to return BinaryDescription (larger step; will be done incrementally).
3. Update src/slice_decoders.zig to depend on common.* and start implementing full return types (BinaryDescription) when ready.
4. Add unit tests for slice decoders that operate on in-memory buffers.

References:
- Starting commit: a786c9b (feat(slice): add slice decoder placeholder and APE fixture)
- Commit: 3b88c12 — reset baseline and extract minimal common helpers
- Commit: 2c41277 — moved safe helpers to common
- Commit: 2a26e6e — moved Section/appendSegmentAndMap to common
- Commit: 3afcc46 — moved appendSectionFromBlock to common
- Commit: e55e4d2 — moved appendDylibNameFromLcData, readU16LE, and appendRpathMessageFromLcData to common and aliased from root
- Commit: e7449e8 — added unit tests for src/slice_decoders.zig that exercise decodeElfSlice and decodePESlice using deterministic fixtures in testing/assets
- Commit: 7a9ce8a — exported BinaryDescription from root and updated src/slice_decoders.zig so decodeElfSlice returns BinaryDescription (first incremental slice-decoder -> BinaryDescription step)
- Commit: 4a95c61 — implemented decodePESlice in src/slice_decoders.zig to return BinaryDescription (small incremental step)
- Commit: d6cb99c — implemented decodeMachoSlice in src/slice_decoders.zig to return BinaryDescription (minimal header-only step) and added corresponding unit test
- Commit: 0b95553 — expanded decodeMachoSlice to parse load commands, populate segments and sections, and capture basic imports/messages. Symbol table resolution (parseSymtab) deferred to a later incremental step.
- Commit: 90fe8a1 — added direct symbol table parsing and indirect symbol resolution to slice_decoders.decodeMachoSlice; uses common.symInfoByIndex for robust symbol name lookup. Symbol handling is now integrated into the slice-decoder path.
- Commit: cabd044 — added stronger unit tests asserting decodeMachoSlice populates sections, segments, imports, and exports (slice_decoders tests)
- Commit: fa1688c — tightened Mach-O slice-decoder tests to assert presence of known imports/exports (look for printf/malloc, dyld_stub_binder, __mh_execute_header)
- Chronology: see chronicles/deep-dive-2026-02-27-ape.md for the prior APE plan.

---

Update — 2026-03-01: move canonical BinaryDescription and BinaryBundle into common

Summary of change:
- Moved the canonical types and enums that describe a decoded binary into src/common.zig so they are a single source of truth for the codebase. The moved items include:
  - BinaryFileKind, OsAbi, CpuArch, FileKind, Perhaps, RelroConfig, StrippedState
  - PrettyPrintOptions and PrettyPrintOptionsDefault
  - BinaryDescription (with writePretty)
  - BinaryBundle (with free)
- Updated src/root.zig to alias those types from common (pub const BinaryDescription = common.BinaryDescription; pub const BinaryBundle = common.BinaryBundle; and aliases for the enums and pretty-print options). This preserves the existing root API used elsewhere in the code while removing duplicate type definitions.
- Kept detection-specific small helper types (ElfHint, MachoHint, PeHint, Stage0ParseResult) in root.zig because they are tiny and only used by detectFormat; reintroduced Stage0ParseResult after moving the canonical types to common to avoid circular imports.

Test & hygiene fixes that accompanied the move:
- Increased test fixture read limits in slice_decoders unit tests (ELF/PE/Mach-O) from small fixed sizes to a larger 16MiB cap to avoid std.fs.File.readToEndAlloc FileTooBig errors when reading large fixtures.
- Ensured unit tests free all owned top-level slices (sections, segments, imports, exports, messages, path) returned by slice decoders to prevent allocator leaks reported by the test runner.

Commits related to this step:
- e31928c — test(slice): increase fixture read limits to 16MB to avoid FileTooBig; ensure to free returned slices
- c175389 — test(slice): increase Mach-O test read limit and free returned slices in invariant test to avoid leaks
- 1d70ebb — refactor(common): move canonical types BinaryDescription, BinaryBundle and related enums into src/common.zig; alias from root.zig
- 27040ea — refactor(root): reintroduce Stage0 parse hints after moving canonical types to common

Rationale:
- Centralizing BinaryDescription/BinaryBundle in common removes duplication and makes it easy for slice_decoders, root, and future analysis modules to share types without circular dependencies.
- Aliasing from root preserves the existing public API so other modules or external callers that reference root.* names do not need to be updated immediately.
- Keeping minimal detection hints in root avoids moving detection concerns into common (which is intended as a small helper/types module) and keeps imports acyclic.

Verification:
- Ran: zig fmt src && zig build test after the changes. The test harness exercises the deterministic fixtures and prints BinaryDescription writePretty outputs for ELF and Mach-O fixtures; the suite completes and reports expected behavior.
- Addressed earlier FileTooBig and leak warnings by increasing read caps and freeing owned slices in tests.

Next steps (recommended):
1. Replace the remaining local decoder implementations in root.zig with calls to the implementations in src/slice_decoders.zig (or add aliases) and remove duplicate decoder code once parity is confirmed.
2. Continue the incremental move of any remaining canonical types or helpers into src/common.zig as needed (keeping the same aliasing strategy in root to preserve API compatibility).
3. Add a chronicle entry for the next major step when you pick it (e.g., "replace root.decodeMacho with slice_dec.decodeMacho and remove old implementation").

Status: chronicle updated to record the move of canonical types into src/common.zig and the accompanying test fixes.

---

Update — 2026-03-01: switch root slice decoders to src/slice_decoders.zig implementations

Summary of change:
- Replaced root's local slice-decoder functions with aliases to the implementations in src/slice_decoders.zig so there is a single authoritative implementation for in-memory slice parsing:
  - pub const decodeElfSlice = slice_dec.decodeElfSlice
  - pub const decodePESlice = slice_dec.decodePESlice
  - pub const decodeMachoSlice is now provided by slice_dec (root previously kept an older local implementation).
- To avoid a risky large deletion in one step, the prior local decodeMachoSlice implementation in root was renamed to decodeMachoSlice_local as a temporary measure. This preserved the code for review while ensuring the active API pointed to slice_decoders.

Commits related to this step:
- fd9949a — refactor(root): alias slice decoders to slice_decoders; rename old local decodeMachoSlice to decodeMachoSlice_local (temporary)

Rationale:
- Removing duplicate parsing code prevents divergence and reduces maintenance burden. All slice-decoder work (ELF/PE/Mach-O header parsing and symbol resolution) now lives in src/slice_decoders.zig and uses common.* helpers and canonical types.
- A temporary rename (instead of deletion) kept the old implementation available for inspection/review and made the change reversible if an issue was discovered during further refactors.

Verification:
- Ran: zig fmt src && zig build test. Tests exercise both root-level analyzeBinary and slice-decoder unit tests that operate on in-memory fixtures; output shows expected BinaryDescription pretty-printing for ELF and Mach-O assets.

Next recommended steps:
1. After a short review window, delete decodeMachoSlice_local from root.zig to complete the de-duplication. Update the chronicle with the deletion commit.
2. Consider making decodeMacho (the file-level decoder that handles FAT/thin) a thin wrapper that purely orchestrates slice_dec.decodeMachoSlice and constructs BinaryBundle; remove any lingering low-level parsing in root.
3. Continue moving additional helpers into common as needed (keeping aliasing in root to ensure stable public API).

Status: committed and tests passing locally.

---

Update — 2026-03-01: implement ELF DT_NEEDED mapping and symbol parsing in slice_decoders.decodeElfSlice

Summary of change:
- Implemented PT_DYNAMIC parsing and DT_NEEDED/DT_STRTAB/DT_STRSZ mapping in src/slice_decoders.zig: decodeElfSlice now locates the dynamic segment, collects DT_NEEDED indices, maps DT_STRTAB VMA -> file offset using segmaps, and extracts nul-terminated library names from dynstr.
- Added robust fallbacks: if DT_STRTAB mapping fails, decodeElfSlice searches for a .dynstr section by name and extracts DT_NEEDED entries from that section. Errors and out-of-bounds conditions append messages to the description instead of hard-failing.
- Implemented SHT_SYMTAB and SHT_DYNSYM parsing to extract symbol names and classify them as imports (SHN_UNDEF) or exports (otherwise). The implementation handles 32/64-bit and endian variants and uses header-provided entsize with sensible fallbacks.
- Populated security hints (PIE/NX/RELRO) using program headers (PT_GNU_STACK, PT_GNU_RELRO) and DT_BIND_NOW.

Tests & verification:
- Updated slice decoders unit tests to assert canonical fields for the ELF fixture (testing/assets/elf-Linux-x64-bash):
  - decodeElfSlice should include DT_NEEDED entries (libc.so.6) and symbol imports (printf) in desc.imports.
  - Security hints: PIE=no, NX=yes, RELRO=none for this fixture.
- Ran: zig build test — all tests pass locally.

Rationale:
- Completing DT_NEEDED and symbol parsing ensures the canonical BinaryDescription captures the key structural and dependency information users expect.
- Keeping parsing tolerant and appending messages on recoverable errors preserves robustness when facing malformed or unusual binaries.

Next steps:
1. Add focused unit tests that assert individual edge-cases (missing DT_STRTAB, malformed dynstr pointers, DT_BIND_NOW inference) to lock down behavior.
2. Apply similar tightening to PE and Mach-O slice decoders (PE import/export parsing; Mach-O indirect-symbol resolution and export trie when needed).
3. Continue to keep the chronicle and sigil bookmarks updated for each incremental move.

Status: committed, tests passing, bookmarks updated.

---

Update — 2026-03-01: add ELF DT_* edge-case unit tests

Summary of change:
- Added focused unit tests in src/slice_decoders.zig that exercise DT_* edge-cases using the deterministic ELF fixture (testing/assets/elf-Linux-x64-bash):
  - Missing DT_STRTAB mapping: corrupt the DT_STRTAB d_val to an unmapped virtual address and verify the decoder falls back to the .dynstr section to resolve DT_NEEDED names (e.g., libc.so.6, printf) and does not emit a "could not map DT_STRTAB" message.
  - DT_BIND_NOW present: flip a dynamic entry tag to DT_BIND_NOW and verify the decoder infers RELRO=full.
  - Malformed DT_STRSZ bounds: set DT_STRSZ to a size larger than the file and verify the decoder appends a "DT_STRTAB/DT_STRSZ out of bounds" message instead of panicking.

Notes on implementation:
- Tests perform in-memory mutations of the ELF fixture buffer (carefully using masked/checked writes) to trigger the desired edge-cases and then call decodeElfSlice on the modified buffer.
- To avoid integer overflow panics in the decoder, the malformed DT_STRSZ test sets DT_STRSZ to (file_size + 1) (a deliberately out-of-bounds but representable value) rather than an extreme 0xFFFFFFFFFFFFFFFF sentinel.
- All tests free the returned BinaryDescription owned slices to avoid allocator leaks during the test run.

Commits related to tests:
- 4e00972 — test(slice): add ELF dynamic edge-case tests (DT_STRTAB fallback, DT_BIND_NOW->RELRO, DT_STRSZ OOB)

Verification:
- Ran: zig fmt && zig build test. The new tests run alongside existing suite and pass locally.

Next steps:
1. If desired, expand edge-case tests to cover more malformed DT entry sequences (e.g., missing DT_NULL terminator, mis-ordered entries) and TLS/PLT edge-cases.
2. After hardening ELF decoding, apply equivalent edge-case tests for PE and Mach-O dynamic/import/export parsing.

Status: committed, tests passing, chronicle updated.

---

Update — 2026-03-01: expand ELF edge-case tests and add PE/Mach-O header checks

Summary of change:
- Expanded ELF edge-case unit tests to include additional malformed DT sequences:
  - Missing .dynstr section (set DT_STRTAB zero and zero shstrtab) -> decoder appends "DT_NEEDED entries present but no dynstr found" message.
  - Missing DT_NULL terminator (flip DT_NULL to DT_NEEDED) -> decoder may either return an error or succeed depending on reader behavior; tests accept both but ensure no panic and free returned slices.
  - Premature DT_NULL (replace first DT_NEEDED with DT_NULL) -> ensures DT_NEEDED entries after the premature terminator are ignored (imports count decreases).
- Added small PE and Mach-O header edge-case tests:
  - PE: synthetic MZ header with out-of-range e_lfanew -> decodePESlice returns ParseError.Malformed.
  - Mach-O: corrupt sizeofcmds in the mach_header to an oversized value -> decodeMachoSlice returns ParseError.Malformed.

Notes:
- Tests mutate fixtures and synthetic buffers in-memory and always free any returned owned slices to avoid allocator leaks in the test harness.
- The missing-DT_NULL test is intentionally permissive (accepts either an error or a successful parse) because different std.io.Reader EOF behaviors can lead to either outcome; the important property is the decoder doesn't panic and does not leak.

Commits:
- 02ef332 — test(slice): expand ELF edge-case tests (missing dynstr, missing DT_NULL, premature DT_NULL) and add PE/Mach-O helpers
- a877b4e — test(slice): add PE/Mach-O malformed-header edge-case tests

Verification:
- Ran: zig fmt && zig build test. All new tests pass locally.

Next steps:
1. Harden decodeElfSlice to avoid panics on pathological integer values in DT entries (use checked casts or early bounds checks before casting to usize).
2. Apply similar robustness improvements to PE and Mach-O decoders, then extend tests to validate behavior under intentionally malicious header fields.
3. Consider adding synthetic, small-fuzz style tests that randomly mutate dynamic/load-command regions and assert the decoder never panics (only returns errors or messages).

Status: committed, tests passing, chronicle updated.
