---
type: deep-dive
date: 2026-03-01
session_goal: "Design and record a complete implementation plan to add machine-readable JSON output to the CLI while preserving existing human-readable output and satisfying repo documentation/chronicle conventions."
files_touched:
  - src/root.zig
  - src/common.zig
  - src/json_output.zig (new)
  - src/tests/json_output_test.zig (new)
  - build.zig
  - README.md
  - HANDOFF.md
  - chronicles/2026-03-01-enable-json-output-deepdive.md
modules_changed:
  - cli
  - decoder_serialization
  - tests
dependencies:
  added: []
  removed: []
  updated: []
duration: "≈45m"
status: in-progress
participants:
  - "assistant (planning)"
  - "repo maintainer (review/implementation)"
---

# Session Chronicle: Deep-dive — Add JSON output mode to CLI

## Quick Summary
This deep-dive documents a complete plan to add a JSON output mode to the CLI. The goal is to add a stable, versioned JSON schema and a CLI flag (and alias) to emit JSON instead of the existing human-readable text. The JSON writer should be streaming to avoid large allocations and must respect the existing ownership conventions (free BinaryDescription slices after serialization). The plan includes exact files to change/add, a schema proposal, CLI UX, implementation notes (including Zig-specific guidance), representative commands for validation, tests to add, and follow-up work.

---

## What We Plan to Build / Change
- Add CLI parsing for output format:
  - Flag: --format <text|json[:pretty]> (short alias: --json).
  - Environment override optional: BIAN_OUTPUT (deferred).
- Implement JSON serialization for BinaryDescription:
  - New module src/json_output.zig with streaming helpers and writeJson function(s).
  - Use schema_version field for future evolution.
  - Default JSON is compact; pretty mode supported.
- Wire JSON output into CLI (src/root.zig):
  - Branch after decode*Slice to call JSON writer or existing pretty print.
  - Free BinaryDescription slices after serialization as currently done for text output.
- Add tests:
  - Unit test to parse JSON output (zig test src/tests/json_output_test.zig) that runs decode on testing assets and validates JSON structure.
  - Integration test: run binary with --format json and verify stdout is parseable JSON and contains expected keys.
- Docs & examples:
  - Update README.md/HANDOFF.md to show CLI usage examples for JSON mode and to document the schema.
  - Add a small example JSON fixture for reference in testing/fixtures (optional).
- Chronicle & bookkeeping:
  - Add this deep-dive chronicle under chronicles/ (this file).
  - Add sg bookmarks where appropriate (follow project policy).

## Representative commands (to run during implementation & verification)
- Build & run full test suite:
  - zig build test
- Run only the new JSON tests:
  - zig test src/tests/json_output_test.zig
- Run CLI manually:
  - ./bian --format json testing/assets/elf-Linux-x64-bash
  - ./bian --json testing/assets/elf-Linux-x64-bash
  - ./bian --format json:pretty testing/assets/MachO-OSX-x64-ls
- Existing property tests unaffected:
  - zig test src/minish_property.zig
- Formatting & lint:
  - zig fmt src

---

## Key Decisions & Rationale

Decision: Keep human-readable output as default and add explicit JSON mode via flags.
Rationale: Preserve existing UX for humans; JSON is opt-in for machine consumers.

Decision: Use a small, versioned JSON schema (schema_version: 1).
Rationale: Allows forward/backward compatibility and schema evolution for consumers.

Decision: Stream JSON tokens to stdout rather than building a giant in-memory string.
Rationale: Files can be large (many sections/symbols); streaming minimizes peak memory and is consistent with repository's care around allocator usage.

Decision: Default JSON omits raw section bytes and full symbol lists (emit counts, and optionally top-N symbols).
Rationale: Keeps default output compact and usable. Provide flags later to include base64 payloads or full symbol lists.

Decision: Implement writer in a new module src/json_output.zig, using Zig's std.io.Writer and either std.json.Writer (if available) or a minimal, deterministic manual writer for stability and control over ordering.
Rationale: Keeps serialization logic isolated and testable.

Decision: When editing Zig files, consult the repo skill /skill:zig-best-practices for recommended patterns (tagged unions, explicit error sets, comptime validation, and memory management), and use /home/jani/temp/zigst/zig-reference.md as a quick local Zig reference while authoring the code.
Rationale: The project follows strong Zig idioms; the zig-best-practices skill captures repository-specific recommendations and must be followed to maintain consistency and safety. The local zig-reference.md provides handy reminders for std APIs and writer patterns.

Alternatives considered:
- Full in-memory JSON via std.json.stringify: simpler but risky for large payloads (memory blow-ups).
- Emit both text and JSON always: noisy; prefer opt-in to maintain clean UX.
- Use top-level 'error' JSON only on failures: kept flexible — plan to include a diagnostics/messages array in JSON output.

---

## Next Steps (implementation checklist)
- [ ] Add CLI flags parsing to src/root.zig (support --format and --json alias).
- [ ] Add new module src/json_output.zig with streaming writer functions:
    - writeBinaryDescriptionJson(writer, binaryDesc, options)
- [ ] Wire the JSON writer callpath in CLI after decode*Slice and free slices after write completes.
- [ ] Add tests: src/tests/json_output_test.zig (unit + integration).
- [ ] Update README.md and HANDOFF.md with JSON CLI examples and schema.
- [ ] Run zig fmt and zig build test; fix any issues.
- [ ] Create a commit and tag with changelog; add sg bookmarks if appropriate.
- [ ] (Optional) Add optional flags for including symbol lists or base64 section data (follow-up).

Note: When implementing the Zig code changes, consult the /skill:zig-best-practices guidance and the local reference at /home/jani/temp/zigst/zig-reference.md to apply best practices for error handling, ownership, and comptime checks.

---

## Unresolved Issues / Open Questions
- Do we want to include both numeric and hex address fields (e.g., entrypoint as number and hex string) or just hex? (Current plan: emit hex string for addresses; include numeric values only if requested).
- How large should default symbol lists be if we include them? (Suggest default to counts only; top-N configurable.)
- Should parse diagnostics (parser messages appended by decoders) be included in JSON in a "messages" array? (Plan: include messages array.)
- Should the environment variable override (BIAN_OUTPUT) be included in v1 or deferred? (Deferred unless requested.)

---

## Technical Deep Dive

### JSON Schema (proposal) — schema_version: 1
Top-level JSON object (compact representation):
{
  "schema_version": 1,
  "file": "testing/assets/elf-Linux-x64-bash",
  "format": "elf",
  "os_abi": "unknown",
  "arch": { "isa": "x86_64", "bits": 64, "endianness": "little" },
  "file_kind": "executable",
  "entrypoint": "0x41f010",            // hex string or null
  "security": { "pie": false, "nx": true, "relro": "none", "aslr": null, "stripped": null },
  "sections": [ { "idx": 1, "name": ".interp", "size": 28, "offset": 512, "perm": "r" }, ... ],
  "segments": [ { "idx": 0, "offset": 64, "size": 448, "perm": "x" }, ... ],
  "imports": { "count": 195 /*, "symbols": [ "printf", ... ] optional */ },
  "exports": { "count": 1925 },
  "messages": [ "code signature present" ],
  "debug_info_present": false,
  "metadata": { "parsed_at": "2026-03-01T20:13:23Z", "duration_ms": 201.4 }
}

Notes:
- Numeric offsets and sizes are integers (usize).
- Addresses emitted as hex strings by default (consistent and readable). If numeric needed, provide an option later.
- "messages" collects parser diagnostics appended during decoding.

### Implementation patterns and snippets (Zig pseudocode)

1) CLI flag handling (src/root.zig):
```zig
const OutputFormat = enum { Text, Json };
var out_format: OutputFormat = OutputFormat.Text;
var json_pretty: bool = false;

while (it.nextArg()) |arg| {
  if (std.mem.eql(u8, arg, "--json")) {
    out_format = OutputFormat.Json;
  } else if (std.mem.startsWith(u8, arg, "--format")) {
    // parse --format json or --format json:pretty
  }
  // ... existing flags
}
```

2) JSON writer interface (src/json_output.zig):
```zig
pub const JsonWriterOptions = struct {
    pretty: bool,
    include_symbols: bool,
};

pub fn writeBinaryDescriptionJson(writer: anytype, bd: *BinaryDescription, opts: JsonWriterOptions) !void {
    // Use streaming writes with deterministic ordering.
    try writer.print("{");
    try writeFieldString(writer, "schema_version", "1");
    try writeFieldString(writer, "file", bd.path);
    // sections array:
    try writer.print(",\"sections\":[");
    var first = true;
    for (bd.sections) |s| {
        if (!first) try writer.print(",");
        try writer.print("{...}");
        first = false;
    }
    try writer.print("]");
    try writer.print("}");
}
```

3) Wiring and cleanup (in CLI after decode):
```zig
const stdout = std.io.getStdOut().writer();
if (out_format == OutputFormat.Json) {
    try writeBinaryDescriptionJson(stdout, &bd, .{ .pretty = json_pretty, .include_symbols = false });
} else {
    prettyPrintBinaryDescription(stdout, &bd);
}
freeBinaryDescription(&bd); // free slices, sections, etc.
```

### Patterns & Conventions Established
- Streaming first: use std.io.Writer to emit JSON tokens sequentially.
- Deterministic field ordering for stable tests and diffs.
- Schema versioning: include "schema_version" top-level integer.
- Keep default output minimal (counts not full symbol dumps) to avoid huge JSON by default.

### Alternatives Explored (and why not chosen)
- Use std.json.Writer to build AST then stringify: rejected due to potential memory overhead.
- Emit addresses as numbers only: rejected for readability and JSON consumers that might expect hex; hex string chosen as default.

### Performance Considerations
- Streaming avoids large allocations when listing many sections or symbols.
- When include_symbols is enabled, consider limiting to top-N or streaming in chunks to keep memory usage low.
- Avoid base64-encoding section contents by default; add opt-in flag for that.

### Technical Debt Introduced
- If we implement include_symbols later, it risks causing large JSON outputs and potential slowdowns. Add tests guarding size or providing upper bounds.
- For expediency, the first implementation may not include an environment variable override — add later.

### Testing Strategy
- Unit tests:
  - Programmatically call the JSON writer on a small constructed BinaryDescription and assert keys/values using Zig's std.json.parse.
  - Use testing assets (elf / macho) to test end-to-end JSON output is parseable and contains expected keys.
- Integration tests:
  - Shell-run the CLI with --format json and parse stdout with zig test harness (or small parser) to ensure valid JSON.
- Property tests: no changes to existing Minish property tests required; ensure freeing behavior is preserved (to avoid allocator leak reports).

### Learning & Insights
- Existing code already properly frees BinaryDescription-owned slices in tests — reuse that pattern after JSON serialization to avoid leak reports.
- The repo emphasizes deterministic, safe parsing (many u64-to-usize checks). JSON serialization must not temporarily create inconsistent representations of sizes/offsets.

### References & Resources
- HANDOFF.md (session handoff & decoder hardening notes) — documents existing constraints about ownership and freeing.
- chronicles/META.md and TEMPLATE.md — for chronicle structure and required content.
- Zig docs: std.io.Writer, std.json (for possible utilities).
- Existing code locations:
  - src/common.zig (BinaryDescription and pretty-print helpers)
  - src/root.zig (CLI entrypoint and decode flow)
  - src/slice_decoders.zig (decoder logic and ownership notes)
- Zig best-practices skill: /skill:zig-best-practices — consult this skill when authoring or changing Zig files (it enforces Zig-specific idioms and patterns used in this repository).
- Local Zig reference: /home/jani/temp/zigst/zig-reference.md — a local quick-reference file for Zig std APIs and common patterns; keep it open during implementation.

---

## Context for Next Session
- Start by invoking sg list (project policy) to locate relevant bookmarks; the previous session's bookmarks include src/root.zig and src/common.zig which are the likely change points.
- Implement changes in small commits:
  - commit 1: CLI flag parsing + config struct
  - commit 2: new JSON writer module + basic schema
  - commit 3: wiring + tests + docs
- Verify with:
  - zig fmt
  - zig build test
  - zig test src/tests/json_output_test.zig
- If Minish property tests report leaks after adding JSON, ensure the JSON writer does not retain ownership of any slices and that freeBinaryDescription is called after writing completes.

Suggested immediate command to pick this up:
- sg list
- git checkout -b feat/json-output
- edit src/root.zig to add flags
- create src/json_output.zig and iterate with zig test

---

If you'd like, I can:
- produce the exact minimal patch (diff) for src/root.zig and the new src/json_output.zig (pseudocode or ready-to-apply Zig),
- or implement the feature directly in this environment and run zig build test, then append a "work performed" chronicle entry recording commands run and files changed. Which would you prefer?
