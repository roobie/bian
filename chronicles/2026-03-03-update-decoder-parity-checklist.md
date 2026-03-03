timestamp: 2026-03-03T01:10:00+01:00
participants: [assistant]

summary:
- Reviewed doc/decoder-parity-checklist.md and updated implementation status markers to reflect current repository state.
- Made conservative edits to mark items implemented where code/tests are present (ELF/PE/Mach-O basic parity, segment/section mapping, imports/exports, security hints, many tests), and left TODOs where functionality or tests are missing (PDB GUID/age, COFF symbol table, dSYM pairing, CI integration, additional fixtures).
- Created this chronicle entry recording the change.

representative commands run:
- sg list
- rg "debug_pdb_path|BinaryDescription|decodePESlice|decodeMachoSlice|decodeElfSlice" -n
- sed -n '1,200p' doc/decoder-parity-checklist.md

files added/modified:
- modified: doc/decoder-parity-checklist.md (updated status checkboxes & notes)
- added: chronicles/2026-03-03-update-decoder-parity-checklist.md (this entry)

notes about repository state and provenance:
- Inspected src/slice_decoders.zig, src/common.zig, src/root.zig and unit tests under src/ to determine implemented features.
- Confirmed BinaryDescription contains debug_info_present and debug_pdb_path fields, and that decodePESlice and Mach-O/ELF decoders populate many BinaryDescription fields.
- Confirmed unit tests exist for many ELF/PE/Mach-O behaviors; PDB extraction tests and some PE/Mach-O edge-case fixtures are still outstanding.

tools referenced:
- tools/agh_search_replace.py — available for scripted text replacements across repo; useful when applying bulk checkbox/state updates or renaming markers consistently. I reviewed the tool but did not run it for this small change.

suggested next steps:
1) Add a focused PE fixture containing an IMAGE_DEBUG_DIRECTORY with CodeView RSDS record and a unit test asserting BinaryDescription.debug_pdb_path and debug_info_present are populated. I can prepare the test + fixture and a patch/PR.
2) Implement GUID/age extraction from RSDS and populate a small debug_metadata struct on BinaryDescription (or extend existing debug_pdb_path into a structured field). Update freeBinaryDescription to free any new allocations.
3) Add cross-format invariant tests and expand PE fixtures: import-by-ordinal, forwarded exports, delay-load descriptors.
4) Consider using tools/agh_search_replace.py to update any other documentation checklists or mass-edit status markers across docs.

end
