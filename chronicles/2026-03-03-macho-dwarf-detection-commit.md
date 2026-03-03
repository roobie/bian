# Chronicle: Mach-O DWARF detection

- timestamp: 2026-03-03T21:26:00Z
- participants: agent

Summary

- Implemented minimal DWARF detection for Mach-O slices in src/slice_decoders.zig.
- Scans Mach-O sections for names like "__debug_info", "__zdebug_info", or any section with prefix "__debug_".
- For candidate sections, validates DWARF compilation unit header using existing dwarfUnitHeaderLooksValid(buf, off, sz, endian).
- If header looks valid, marks debug metadata: sets debug_type to .dwarf (unless already set to .dsym) and ensures debug_info_present is reflected in the returned BinaryDescription.
- If a section name suggests DWARF but header validation fails, appends diagnostic message: "found .debug_info section but DWARF CU header invalid".

Commands run (representative)

- zig build test
- git add src/slice_decoders.zig chronicles/2026-03-03-macho-dwarf-detection-commit.md
- git commit -m "feat(macho): detect __debug_info sections and validate DWARF CU header; set debug_type=\"dwarf\" conservatively"

Files changed

- src/slice_decoders.zig (modified):
  - Added LC_UUID handling earlier commit
  - Added Mach-O DWARF detection logic (scan sections and validate CU header)
- chronicles/2026-03-03-macho-dwarf-detection-commit.md (new): chronicle entry

Next steps

1. Add unit tests that exercise Mach-O DWARF detection using either an existing Mach-O fixture that contains DWARF sections or a synthetic buffer test. Ensure both little-endian and big-endian paths are covered.
2. Implement dSYM discovery using the recorded UUID (search for companion .dSYM bundles by UUID naming patterns) and/or add logic to prefer .dsym when a UUID is present.
3. Add integration tests that assert decodeMachoSlice sets debug_info_present and debug_type as expected for real fixtures.
4. Continue with PE COFF symbol table parsing per decoder parity checklist.

