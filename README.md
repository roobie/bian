## Cross-Platform Binary Inspector

Main goals:
- Implement using `zig`
- Be cross-platform
- Be performant
- Be idiomatic
- Be useful

1. A reusable code (library) module.
2. A CLI/program module that uses the library.

---

## 1. Core Code Module (Library)

### 1.1 Purpose

Provide a single, cross-platform API to inspect binary executables and libraries, independent of CLI concerns. The module should:

- Detect file format (ELF, Mach-O, PE, APE, possibly “unknown”).
- Extract structural info (architecture, endianness, bitness, sections, segments).
- Extract metadata (build ID, entry point, PIE/ASLR flags, RELRO, NX, stripping status).
- Extract dynamic info (imported libraries, exported symbols, dynamic relocations).
- Offer a stable, format-agnostic data model so callers don’t deal with ELF/Mach-O/PE oddities directly.

### 1.2 Module Structure

Organize the module into the following logical submodules:

1. File Abstraction
   - Responsibilities:
     - Open file by path or existing handle.
     - Memory-map or buffered read with safe bounds checking.
     - Provide unified interfaces to read ranges, translate offsets, and get file size.
   - Goals:
     - Hide OS-specific file IO details.
     - Facilitate unit testing with in-memory buffers.

2. Format Detection
   - Responsibilities:
     - Inspect magic bytes and minimal header fields to determine:
       - Binary format (ELF, Mach-O, PE).
       - Word size (32/64-bit).
       - Endianness (little/big).
     - Return a clear result type:
       - Recognized(format, hint-arch, hint-os) or
       - Unknown(reason).
   - Goals:
     - Fast, minimal reads (only what’s necessary).
     - Avoid fully parsing until required, to keep overhead low.

3. Format-Specific Parsers
   - Submodules: ELF Parser, Mach-O Parser, PE Parser.
   - Responsibilities (each):
     - Validate headers (sanity checks on offsets, counts, sizes).
     - Parse:
       - File/optional headers.
       - Section headers.
       - Segment/program headers (or equivalents).
       - Symbol tables (static/dynamic).
       - Dynamic linking info (imports/exports, relocation tables).
       - Flags related to PIE/ASLR/NX/RELRO, etc. (translated into format-agnostic fields).
     - Record warnings for non-fatal irregularities.
   - Goals:
     - Robustness against malformed/broken files (never crash, always fail gracefully).
     - Clear mapping from native flags to generic capability fields.

4. Unified Binary Model
   - A central “binary description” data structure produced by parsers.
   - Contains:
     - General Info:
       - Format (ELF/Mach-O/PE/Unknown).
       - OS/ABI (Linux, BSD, macOS, Windows, Unknown).
       - Architecture (x86, x86_64, armv7, aarch64, etc.).
       - Bitness (32/64).
       - Endianness.
       - File type (executable, shared library, object, core, etc.).
       - Entry point address (if applicable).
     - Security/Runtime Features:
       - PIE enabled (yes/no/unknown).
       - ASLR support (derived from PIE + platform knowledge).
       - NX/DEP (yes/no/unknown).
       - RELRO type (none/partial/full/unknown).
       - Stripped status (yes/no/partially/unknown).
     - Sections:
       - List with name, type (code/data/debug/other), size, file offset, permissions.
     - Segments (or equivalent):
       - List with type (load, dynamic, etc.), virtual address, permissions, alignment.
     - Dynamic Linking:
       - Imported libraries (names, possibly version info).
       - Exported symbols (names, types, visibility, binding).
       - Imported symbols (names, libraries).
     - Debug Info Indicators:
       - Presence of debug sections / symbols (e.g., DWARF, PDB hints).
     - Anomalies/Warnings:
       - Non-critical issues (odd alignment, overlapping ranges, truncated sections).
   - Goals:
     - Single, format-neutral object that higher layers can render however they like.
     - Extensible without breaking existing consumers.

5. Feature Detection Layer
   - Responsibilities:
     - Infer higher-level properties from low-level fields:
       - Derive effective ASLR support from PIE and OS-ABI.
       - Determine “stripped” by checking for symbol/debug presence.
       - Summarize “security posture” into a small set of flags or scores.
   - Goals:
     - Centralize the logic so the CLI and any other consumers don’t re-implement it.

6. Error and Warning Model
   - Clear types for:
     - Fatal errors (cannot parse, truncated file, unsupported variant).
     - Non-fatal warnings (suspicious field values but still interpretable).
   - All public APIs should:
     - Never panic.
     - Return either:
       - A result with parsed binary plus warnings, or
       - A descriptive error with type and message.

7. Public API Surface
   - Core operations (expressed in words, no code):
     - “Inspect file at path and return a full binary description.”
     - “Inspect from an in-memory buffer and return a binary description.”
     - “Detect format only without full parsing.”
   - Configuration options:
     - Parsing depth (minimal headers only vs. full parse).
     - Symbol loading options (skip symbols for speed, or full symbol parse).
     - Security-analysis toggle (enable/disable additional inference work).

---

## 2. CLI / Program Module

### 2.1 Purpose

Provide a single, static, user-facing command-line tool that leverages the library to inspect binaries uniformly across platforms.

The CLI should:

- Accept multiple input files.
- Offer different levels of detail (summary vs. verbose).
- Present a consistent, human-friendly output for all formats.
- Provide machine-readable output modes for scripting.

### 2.2 Overall CLI Structure

1. Argument Parsing Layer
   - Responsibilities:
     - Parse:
       - File paths (one or more).
       - Output mode (human summary, verbose, machine-readable).
       - Filters (only show sections, only show imports, only show security flags).
       - Global options (color on/off, quiet, help, version).
     - Validate arguments and produce a clean configuration object.
   - Goals:
     - Provide predictable, POSIX-like flags (short and long).
     - Avoid surprises in exit codes and error messages.

2. Command Dispatch / Modes

   Use a single binary with subcommands or flags that alter behavior.

   Core modes:

   - Default (no explicit subcommand):
     - Per-file concise summary:
       - Format, arch, OS/ABI, bitness.
       - File type (exe/shared/object).
       - PIE/RELRO/NX/ASLR summary.
       - Stripped / debug info status.
       - Count of sections, imports, exports.
     - Minimal but useful for quick “what is this file?” checks.

   - “Details” / “Verbose” Mode:
     - Everything in summary plus:
       - Full section table.
       - Segment layout.
       - Full list of imported libraries.
       - High-level security posture (e.g., describing protections).
       - Any warnings or anomalies.

   - “Sections” Mode:
     - Only section list with:
       - Name, type, size, permissions, offset.
     - Optional filters: only code, only writable, name patterns.

   - “Deps” / “Imports” Mode:
     - Dynamic dependencies (libraries).
     - Imported symbols (optionally).
     - Basic resolution hints (where they might load from on typical OS defaults, if known).

   - “Symbols” Mode:
     - Exported symbols (by default).
     - Optional switch to show imported, or all.
     - Ability to filter (e.g., by name substring or type).

   - “Security” Mode:
     - Focused output on protections only:
       - PIE, ASLR, RELRO, NX/DEP, canary hints if derivable, stripped/debug status.
     - Possibly present a summarized “score” or rating.

   - “Format” Mode:
     - Just quickly output format + architecture + file type for scripting.

3. Output Formatting Layer

   - Human-readable output:
     - Clean, consistent headings and ordering across formats.
     - Align columns where possible.
     - Highlight important security flags.
     - Color support (enabled by default on TTY, disabled otherwise, with overrides).
   - Machine-readable output:
     - Optional JSON or another structured format:
       - Direct serialization of the unified binary model.
       - Stable field names for scripting and integration.
   - Error reporting:
     - Clear messages including file path and reason.
     - Non-zero exit code if any file fails, with summary of failures.

4. Integration with Library

   - For each input file:
     - Open using the library’s “inspect file” function.
     - Handle errors:
       - Print per-file error and continue with remaining files (unless configured to stop).
     - Map library’s unified model to:
       - The selected CLI output mode.
   - Respect user config:
     - Use parsing-depth settings depending on mode:
       - Summary/security modes may use medium depth.
       - Verbose/symbols modes request full parsing.

5. Performance and UX Considerations

   - Handle many files efficiently:
     - Optionally process in parallel (if feasible with file IO).
     - Ensure deterministic output ordering (e.g., sorted by input order).
   - Sensible defaults:
     - Default to summary mode with colorized, human-friendly output.
   - Stable behavior:
     - Once options are established, avoid changing semantics between versions in breaking ways, especially for machine-readable mode.

6. Extensibility

   - Designed so that adding support for:
     - New binary formats (e.g., WebAssembly, COFF variants) requires:
       - New parser submodule.
       - Extended detection logic.
       - Minimal to no changes in CLI logic.
   - Adding new CLI modes:
     - Build them atop the existing unified model, not format-specific logic.

7. Testing Strategy (Conceptual)

   - Library:
     - Unit tests with artificial/minimal binaries for each format.
     - Fuzz tests against parsers to ensure robustness.
   - CLI:
     - Snapshot tests of text output for known binaries.
     - Tests of machine-readable JSON output for stability.

---

This design separates a robust, reusable inspection library from a flexible, user-friendly CLI, while ensuring that all binary formats are presented through a single, coherent abstraction.
