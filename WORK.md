# This file tracks TODO, DOING and DONE tasks

Make sure to reference [README.md](./README.md) and [NOTES.md](./NOTES.md) for an overview.
This document is for tracking work, and is a living document to be kept updated.

1. [DONE] Define the BinaryDescription Struct in src/root.zig:
- Create a top-level struct that encapsulates all normalized data from a parsed binary.
- Base it directly on the "Unified Binary Model" section in README.md and NOTES.md.
- Key fields (prioritize core identity and security first, as they're simpler and central):
- Identity Fields (always populated):
- format: Enum (e.g., .elf, .macho, .pe, .unknown).
- os_abi: Enum or string (e.g., .linux, .macos, .windows, .unknown).
- arch: Enum (e.g., .x86, .x86_64, .armv7, .aarch64, .unknown).
- bitness: u8 (32 or 64).
- endianness: std.builtin.Endian (.little or .big).
- file_kind: Enum (e.g., .executable, .shared_library, .object, .unknown).
- entry_point: Optional u64 (virtual address, if applicable).
- Security Features (normalized booleans/enums, with derivation logic in parsers):
- pie: Enum (.yes, .no, .unknown).
- aslr: Enum (.yes, .no, .unknown).
- nx: Enum (.yes, .no, .unknown).
- relro: Enum (.none, .partial, .full, .unknown, .not_applicable).
- stripped: Enum (.yes, .no, .partial, .unknown).
- Structural Fields (arrays of structs, start with basics):
- sections: Array of structs with name: []const u8, kind: enum (.code, .data, etc.), size: u64, file_offset: u64, permissions: enum (.r, .w, .x).
- segments: Similar array (for ELF/Mach-O; PE can map sections here or leave empty).
- imports: Array of []const u8 (library names).
- exports: Array of structs with name: []const u8, kind: enum (e.g., .function, .variable).
- Additional Fields:
- warnings: Array of strings for non-fatal issues (e.g., "overlapping sections").
- debug_info_present: Bool (derived from sections/symbols).
- Use Zig's standard types (e.g., std.ArrayList for dynamic arrays, allocators passed in).
- Include doc comments linking to specs (e.g., ELF references).

2. [TODO] Define Error Types:
- Add a ParseError union/enum for failures (e.g., .too_small, .invalid_header, .unsupported_variant, .malformed).
- Ensure all parsing functions return Result<BinaryDescription, ParseError> to enforce graceful handling.

3. [TODO] Update the Public API in src/root.zig:
- Replace or extend detectFormat with a top-level analyzeBinary function (as sketched in NOTES.md).
- Signature: pub fn analyzeBinary(allocator: std.mem.Allocator, reader: FileReader) !BinaryDescription.
- Internally, call detection, then dispatch to format-specific decoders (e.g., decodeElf, decodeMacho).
- For now, decoders can be stubs returning partial data or errors, focusing on structure.

4. [TODO] Integration and Testing Considerations:
- Add unit tests for the struct (e.g., creating mock BinaryDescription instances).
- Ensure compatibility with existing tests (e.g., detection still works).
- Plan for memory management: Use an allocator for strings/arrays to avoid leaks.
- Future-proof: Leave hooks for features like symbol loading options or partial parsing.

5. [TODO] Next
- Implement decodeElf first (most common), populating basic fields.
- Add Mach-O and PE decoders iteratively.
- Integrate into CLI (src/main.zig) for output modes.
- Handle edge cases (fat binaries, multi-arch) per design.

