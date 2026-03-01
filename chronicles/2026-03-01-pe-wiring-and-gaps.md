# Chronicle: 2026-03-01 — PE wiring and decoder gaps

- timestamp: 2026-03-01T22:13:23+01:00
- participants: jani (developer agent)

Summary
--------
Recorded the current decoder coverage for binary formats (ELF, Mach-O, PE, APE) and implemented wiring to enable PE decoding end-to-end through analyzeBinary(), producing BinaryBundle results consumable by the CLI and JSON writer.

Actions taken
-------------
1. Audited repository for decoder coverage and tests (ELF, Mach-O, PE, APE).
2. Created a chronicle entry listing known gaps and recommended next steps.
3. Implemented decodePe(allocator, file, path) in `src/root.zig` which:
   - Reads the whole file into an allocator-owned backing buffer.
   - Calls `slice_dec.decodePESlice(...)` to produce a BinaryDescription.
   - Attaches path (if provided) by copying bytes into an owned slice.
   - Wraps the description into a BinaryBundle that owns the backing buffer.
4. Wired analyzeBinary(...) to call decodePe for Stage0ParseResult.pe instead of returning UnsupportedVariant.

Representative commands run
---------------------------
- Run full test-suite:
  - zig build test --verbose
- Quick manual run of the CLI with pretty JSON (verified functionality):
  - zig build run -- --json-pretty testing/assets/elf-Haiku-GCC2-ls
- Quick manual run to ensure include-symbols is independent of JSON:
  - zig build run -- --include-symbols testing/assets/elf-Haiku-GCC2-ls

Files added/modified
--------------------
- modified: src/root.zig
  - Added: fn decodePe(allocator: std.mem.Allocator, file: std.fs.File, path: ?[]const u8) !BinaryBundle
  - Updated: analyzeBinary(...) to call decodePe for .pe stage0
- added chronicle: chronicles/2026-03-01-pe-wiring-and-gaps.md

Current gaps (detailed)
-----------------------
1. PE integration completeness
   - Status: slice decoder present (src/slice_decoders.zig:decodePESlice) and unit-tested at slice level, but until now the high-level analyzeBinary did not call a PE wrapper. This is now fixed by decodePe().
   - Remaining risk: slice_dec.decodePESlice must be robust to all real-world PE variants; more integration tests across multiple PE fixtures are recommended.

2. APE format
   - Status: Not implemented. Stage0 detection refers to APE in the enum, but analyzeBinary still returns UnsupportedVariant for APE.
   - Recommendation: implement decodeApe if APE is in scope; otherwise leave as UnsupportedVariant with clear runtime messaging.

3. Mach-O edge commands
   - Status: decodeMachoSlice whitelists known LC commands and skips unknown ones (safe-by-default). This is good for safety but may miss additional metadata for some binaries.
   - Recommendation: extend whitelist as needed when encountering binaries requiring extra LC handling.

4. PE symbol parsing and edge cases
   - Status: decodePESlice exists but needs more real-world coverage (COFF symbol tables, import tables, delayed imports, CLR/managed PE constructs, etc.).
   - Recommendation: add fixtures for Windows PE variants and exercise decodePESlice with integration tests.

5. A consistent ABI/os_abi mapping
   - Status: Many assets currently map os_abi -> "unknown". More precise OS/ABI mapping logic can improve JSON output usefulness.
   - Recommendation: add mappings from format headers to `OsAbi` enum for ELF e_ident[EI_OSABI] and Mach-O platform fields.

6. Streaming very-large symbol lists
   - Status: JSON writer has two paths: compact (omits symbols) and full (std.json.Stringify via jsonStringify). The full path streams via std.json.Stringify and should be safe, but the compact path previously used ad-hoc escaping. Recent changes made both paths use std.json.Stringify to honor pretty parameter.
   - Recommendation: add tests for very large symbol sets and confirm memory and time behavior. Optionally add flags to limit symbol emission (top-N) to avoid huge JSON.

7. Tests and integrations missing
   - Status: Unit tests for slice decoders exist. Integration tests that run the built CLI (`zig build run`) and parse JSON output are missing.
   - Recommendation: add an integration test that invokes the CLI with --json / --json-pretty / --include-symbols against fixtures and validates the output via std.json.parseFromSlice.

Suggested next steps
--------------------
1. Expand PE integration tests: add several PE fixtures (x86/x64, DLL/exe, object files) and assert expected fields.
2. Add CLI integration tests that run the installed executable with JSON flags and parse output into std.json.Value to verify validity.
3. Decide on APE support: implement or deprecate/ignore with a clear message.
4. Add additional Mach-O LC support as required by fixtures.
5. Consider adding --include-symbols limitations (top-N) for very large binaries.

Notes
-----
- Memory ownership: wrappers (decodeElf/decodeMacho/decodePe) return BinaryBundle owning both the items and backing buffer. Callers must call BinaryBundle.free(allocator, bundle) to release resources — tests demonstrate this pattern.
- JSON behavior: jsonStringify provides a canonical, deterministic schema. The compact writer omits symbol arrays unless include-symbols is true.

Next actions performed immediately
--------------------------------
- Wired PE at the analyzeBinary entrypoint by adding decodePe and updating the switch. Ran the test-suite and executed manual CLI runs to validate expected behavior.


