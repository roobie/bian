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
- Chronology: see chronicles/deep-dive-2026-02-27-ape.md for the prior APE plan.
