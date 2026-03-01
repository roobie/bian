# Chronicle: PE import symbol parsing and thunk handling

- timestamp: 2026-03-02T21:XX:00Z
- participants: assistant

Summary

Today I extended the PE slice decoder to better populate imported symbol names from the IMAGE_IMPORT_DESCRIPTOR thunk table. Previously the PE decoder only collected DLL names; now it also collects imported function names (when present) by parsing the OriginalFirstThunk / FirstThunk arrays and resolving IMAGE_IMPORT_BY_NAME entries.

Actions taken

- Implemented parsing of Optional Header to extract AddressOfEntryPoint and ImageBase and compute entrypoints for PE32 and PE32+.
- Added ASLR and NX detection from DllCharacteristics.
- Parsed section headers and built segment maps to support RVA -> file offset mapping.
- Implemented export name parsing (exported names list) and import DLL name collection (existing behavior preserved).
- Implemented parsing of import thunk arrays to collect imported symbol names (skips imports by ordinal for now).
- Added messages[] entries when RVAs cannot be mapped ("import thunk table RVA unmapped", "import name RVA unmapped") so we can surface decoder gaps in the JSON and human output.
- Kept memory ownership consistent: imported symbol names are slices into the backing file buffer (no heap-allocated strings), so BinaryBundle.free behavior remains correct.

Commands run (representative)

- zig fmt src/slice_decoders.zig
- zig build test --verbose

Files changed

- src/slice_decoders.zig — extended PE parser: optional header, section parsing, export/import parsing, thunk table parsing, messages populating.
- (previous commits) src/json_output.zig, src/test_utils.zig, src/root.zig, src/main.zig, src/common.zig — existing changes supporting JSON and test behavior.

Notes on limitations & next steps

- Current import parsing collects DLL names and function names as separate entries in desc.imports (flat list). The decoder does not yet record which symbol belongs to which DLL; resolving that would require changing the BinaryDescription schema (e.g., a structured import table) and updating JSON and pretty-printer code.
- Imports by ordinal are currently skipped. We should decide how to represent ordinal imports (e.g., include a marker or "DLL!#ordinal") and whether to allocate formatted strings or change schema.
- COFF symbol table parsing (for object files) is not implemented.
- Exports record names only. Export ordinals and RVA information are not yet emitted.
- Consider adding more messages describing mapping problems (with offsets and RVAs) to help triage.
- Add PE fixtures and unit/integration tests (EXE/DLL PE32 and PE32+ with imports by name, ordinal, delay-load, debug/pdb directories). The lack of tests for real-world PE files is the current top-priority gap.

Suggested immediate next work (I can take these on)

1. Add imported symbol <-> DLL association in the schema: consider adding an ImportEntry struct with dll and symbols fields. Update JSON writer and pretty-printer accordingly.
2. Implement parsing of imports-by-ordinal and represent them clearly in the description.
3. Add PE test fixtures (32/64-bit, EXE/DLL) and unit tests that assert imported symbols and exports are discovered, and integration tests running the CLI with --json and parsing the JSON.
4. Expand export parsing to include ordinals and RVAs, and record forwarders.

If you'd like, I'll continue by (pick one):
- (A) Implement an ImportEntry schema and wire JSON/pretty-printer to emit per-DLL symbol lists (preferred, more accurate representation).
- (B) Add PE fixtures and unit/integration tests to validate current behavior and detect regressions across real-world files.
- (C) Implement ordinal import parsing and include ordinal markers in imports (less invasive than schema change).

Please tell me which next step you'd like prioritized (A/B/C), or I can proceed with recommendation A.
