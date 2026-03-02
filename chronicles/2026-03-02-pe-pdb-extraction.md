Timestamp: 2026-03-02T21:XX:00Z
Participants: AI assistant

Summary:
- Added minimal CodeView/PDB extraction support for PE decoders.
- Extended BinaryDescription to include debug_pdb_path field (holds PDB path if embedded via CodeView RSDS).
- Parse IMAGE_DEBUG_DIRECTORY entries in decodePESlice and extract RSDS PDB path if present.
- Allocated owned copies of discovered PDB path into BinaryDescription so returned descriptions don't alias the input buffer.
- Updated pretty-print and JSON serialization to include debug_pdb_path.

Representative commands run:
- sg list
- Edited src/common.zig to add debug_pdb_path field and JSON/pretty-print changes
- Edited src/slice_decoders.zig to parse IMAGE_DEBUG_DIRECTORY and populate debug_pdb_path
- Wrote this chronicle entry

Files added/modified:
- modified: src/common.zig (added debug_pdb_path to BinaryDescription, print & JSON changes)
- modified: src/slice_decoders.zig (PE decode: parse IMAGE_DEBUG_DIRECTORY, extract CodeView RSDS PDB path, populate BinaryDescription.debug_pdb_path)
- added: doc/decoder-parity-checklist.md (previous step)
- added: chronicles/2026-03-02-pe-pdb-extraction.md (this file)

Suggested next steps:
1) Add a PE fixture that includes a CodeView RSDS debug directory pointing to a PDB path, and a unit test that asserts debug_pdb_path is populated as expected.
2) Extend BinaryDescription to include structured debug metadata (GUID, age) if needed.
3) Add similar basic DWARF/dSYM detection for ELF and Mach-O decoders.
4) Run full test suite and fix any compile or test failures.

Notes:
- This change is conservative: it only extracts the PDB path string and sets debug_info_present. It does not parse PDB contents.
- Per project policy, this session's repository mutations are recorded in this chronicle file.
