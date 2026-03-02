> This document is for tracking work, and is a living document to be kept updated.

PE decoding implementation checklist

- [x] Task 1 — Populate segments[]
    - Status: DONE — BinaryDescription.segments is now populated for PE images.
    - Where changed: src/slice_decoders.zig (decodePESlice section header loop). Replaced manual segmaps.append(...) with try root.appendSegmentAndMap(...).
    - Acceptance: unit test added: "slice_decoders: decodePESlice parses PE fixture and populates segments" (testing/assets/pe-Windows-x64-cmd).
    - Bookmarks: src/slice_decoders.zig:402 (decodePESlice), src/slice_decoders.zig:532 (section loop), src/common.zig:104 (appendSegmentAndMap).
    - Branch/PR: feat/pe-segments
    - Estimate: 1–2h (actual)

- [x] Task 2 — Import-by-ordinal handling (structured)
    - Status: PARTIALLY DONE — import-by-ordinal detection implemented and API changed to use a structured ImportSymbol type. Remaining: add more unit tests and PE fixtures for pure-ordinal imports.
    - What changed:
        - Introduced ImportSymbolKind and ImportSymbol in src/common.zig:
            pub const ImportSymbolKind = enum { by_name, by_ordinal, by_name_and_ordinal };
            pub const ImportSymbol = struct { kind: ImportSymbolKind, name: []const u8, ordinal: u32 };
        - ImportEntry.symbols now uses []ImportSymbol.
        - PE thunk parsing updated to append ImportSymbol entries for by-name and by-ordinal imports (ordinals stored as u32 low 16 bits).
        - ELF/Mach-O undefined symbols are converted to ImportEntry with empty dll and symbols as ImportSymbol{.by_name, name, 0}.
        - Tests and decoders updated to inspect ImportSymbol.kind and .name instead of treating symbols as []const u8.
        - Root re-exports added so decoders can use root.ImportSymbol and root.ImportSymbolKind.
    - JSON/schema: compact JSON schema bumped to version 2 to reflect structured symbol objects (src/json_output.zig, src/common.zig jsonStringify).
    - Acceptance: tests updated; basic tests pass locally. Need an explicit test fixture that contains ordinal-only imports and asserts .ordinal value.
    - Branch/PR: feat/pe-import-ordinals
    - Estimate: original 2–4h; actual: larger due to API change and test updates

- [x] Task 3 — Surface pe_undef_syms or remove
    - Status: DONE (converted into ImportEntry)
    - What changed: pe_undef_syms handling converted so undefined symbols are emitted as ImportEntry with empty dll and symbol entries using ImportSymbol.by_name.
    - Where: src/slice_decoders.zig
    - Acceptance: verified by updated tests and JSON output inclusion for undefined symbols.

- [ ] Task 4 — Export table improvements (ordinals & forwarded exports)
    - Status: TODO
    - Plan: parse AddressOfFunctions, AddressOfNameOrdinals, and detect forwarders where the function RVA points into the export directory (forwarder string). Add export ordinal fields to exported symbols and string forwarder targets.
    - Where: src/slice_decoders.zig, export parsing block.
    - Acceptance: tests that assert export ordinals and forwarders are present.
    - Branch/PR: feat/pe-exports
    - Estimate: 4–8h

- [ ] Task 5 — Base relocations + PDB debug extraction
    - Status: TODO
    - Plan: parse IMAGE_DIRECTORY_ENTRY_BASERELOC entries and DebugDirectory CodeView records for PDB path extraction.
    - Where: src/slice_decoders.zig, data directory parsing.
    - Acceptance: messages/fields show relocations presence and PDB path if present.
    - Branch/PR: feat/pe-reloc-pdb
    - Estimate: 6–12h

- [ ] Task 6 — Resource, certificates, TLS, exception directory (selective)
    - Status: TODO
    - Plan: parse resources (VERSIONINFO), WIN_CERTIFICATE table, consider TLS callback table and exception directory as needed.
    - Where: src/slice_decoders.zig or helper files if complexity grows.
    - Acceptance: resource/version info and certificate presence extracted for fixtures.
    - Branch/PR: feat/pe-resources
    - Estimate: 8–24h

- [ ] Task 7 — Map section names -> SectionKind and refine permissions
    - Status: TODO
    - Plan: map known PE section names (.text, .rdata, .data, .rsrc, .reloc) to SectionKind and compute permissions by combining section characteristics bits.
    - Where: src/slice_decoders.zig, section header loop.
    - Acceptance: tests assert SectionKind and permissions for fixtures.
    - Branch/PR: feat/pe-section-kinds
    - Estimate: 1–3h

- [ ] Task 8 — Add PE fixtures and tests
    - Status: TODO (some tests added already)
    - Plan: add more PE test assets to testing/assets and unit tests validating imports (name & ordinal), exports (ordinals & forwarders), segments, relocations, PDB path, and resource/cert parsing.
    - Where: testing/assets, tests in src/slice_decoders.zig or new test file.
    - Acceptance: new tests added and run in CI; local zig test passes.
    - Branch/PR: test/pe-fixtures
    - Estimate: 3–8h

Cross-cutting (apply to each PR)
- [x] Add a chronicle markdown entry under chronicles/ for each significant session/PR. Recent entries:
    - chronicles/20260302-000835-pe-decoding-plan.md
    - chronicles/20260302-001245-pe-task1-populate-segments.md
    - chronicles/20260302-001350-pe-task1-test.md
    - chronicles/20260302-002100-pe-task2-ordinal.md
- [x] Use sg/bookmarks for important locations. Recent bookmark targets: decodePESlice, section loop, appendSegmentAndMap, PE thunk handling.
- [x] Maintain defensive bounds checks (safeSlice, vaddrToFileOffset) — decoders continue to prefer bounds-checked access and return errors rather than panic on malformed data.
- [x] API decision updated: introduced structured ImportSymbol (typed) and bumped compact JSON schema_version to 2. This is an intentional API/schema change (library unreleased) and removes the prior preference for string-encoded ordinals.

Recent commits / state
- All changes committed. Key files modified:
    - src/slice_decoders.zig (PE import & section parsing, tests updated)
    - src/common.zig (ImportSymbol type, pretty-printer, jsonStringify)
    - src/json_output.zig (schema_version = 2 output)
    - src/root.zig (re-export ImportSymbol / ImportSymbolKind)
    - src/tests/json_output_test.zig (updated expected schema_version)
- Local test run: zig build test completed (no failing tests locally at time of update).

Next action (recommended)
1. Add unit tests that explicitly cover PE import-by-ordinal cases (fixture with ordinal-only imports) and assert .ordinal values recorded in ImportSymbol.
2. Implement Task 4 (exports ordinals & forwarders) and add tests.
3. Add more PE fixtures covering relocations, PDB, resources, and signed certificates.
4. Tidy up decoder code: remove redundant nested-kind checks, balance blocks and add comments clarifying ImportSymbol ownership model (non-owning name slices). Consider owning allocation later and update freeBinaryDescription/freeImportEntries accordingly.
5. Open PRs for each feature branch and include a chronicle entry and sg bookmarks with each PR.

If you'd like, I can update this further to include exact sg commands used for recent edits and a single consolidated chronicle entry summarizing the compilation fixes and test run results.
