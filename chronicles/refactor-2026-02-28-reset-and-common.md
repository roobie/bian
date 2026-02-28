Refactor progress — 2026-02-28

Summary:
- Reset repository to commit a786c9ba28a1c43d406b7fc5df06f51817ea9872 (baseline for incremental refactor).
- Created src/common.zig with a small, well-scoped set of helpers to start the module split:
  - prefix_length
  - readU32At, readU64At, readI32At (endian-aware readers)
- Updated src/root.zig to import common.zig and re-export short names (prefix_length, readU32At, readU64At, readI32At) to keep existing code working while moving implementations out of root.
- Kept src/slice_decoders.zig minimal/placeholder for now (compile-friendly). This will be expanded incrementally in subsequent steps.

Rationale and notes:
- usingnamespace is no longer part of Zig — use explicit imports and explicit aliases instead. To avoid circular imports and duplicate-symbol issues, move only a tiny set of low-risk helpers to common.zig and alias them from root.zig. This keeps the public API stable while allowing slice decoders and other modules to import common directly.
- Changes made here are intentionally conservative to keep the test suite green at every step.

Next steps:
1. Add a small set of further helpers to src/common.zig that are safe to centralize (safeSlice, vaddrToFileOffset, SegmentMap) and replace their definitions in root.zig with aliases. Run tests after each move.
2. Update src/slice_decoders.zig to call into common.* types/helpers and implement the real return type (common.BinaryDescription) once BinaryDescription is moved/shared or re-exported.
3. Add unit tests for slice decoders that operate on in-memory buffers.
4. Implement decodeApe using the slice decoders.

References:
- Starting commit: a786c9b (feat(slice): add slice decoder placeholder and APE fixture)
- Chronology: see chronicles/deep-dive-2026-02-27-ape.md for the prior APE plan.
