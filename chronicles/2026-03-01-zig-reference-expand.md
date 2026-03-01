# Chronicle: Expand Zig reference and bookmarks

- Timestamp: 2026-03-01T22:58:00+01:00
- Participants: assistant (automated)

Summary
-------
Continued analysis of the vendor/zig std library to expand the zig-reference.md document and add representative sg bookmarks for additional idioms found in the std library (allocator helpers, allocWithOptions, allocBytesWithAlignment, reallocAdvanced, array_list deinit patterns, failing allocator tests, etc.).

Actions taken (representative commands run)
-----------------------------------------
- rg searches across vendor/zig for allocator and memory idioms
- sg add <file>:<line> -t <tags> -d "..." (multiple bookmarks added)
- Updated doc/zig-reference.md with an "Expanded examples and direct references" section listing created bookmarks and guidance

Files/bookmarks added
--------------------
New bookmarks (id → file:line)
- 165_aa76 → vendor/zig/lib/std/mem/Allocator.zig:184 (allocWithOptions)
- 165_0e4c → vendor/zig/lib/std/mem/Allocator.zig:248 (allocAdvancedWithRetAddr)
- 165_798c → vendor/zig/lib/std/mem/Allocator.zig:257 (allocWithSizeAndAlignment)
- 165_1a21 → vendor/zig/lib/std/mem/Allocator.zig:272 (allocBytesWithAlignment)
- 165_301c → vendor/zig/lib/std/mem/Allocator.zig:382 (reallocAdvanced)
- 165_1517 → vendor/zig/lib/std/mem.zig:174 (testing.failing_allocator usage)
- 165_c9c6 → vendor/zig/lib/std/array_list.zig:62 (array_list.deinit)
- 165_3e91 → vendor/zig/lib/std/array_list.zig:654 (Managed deinit with gpa)
- 165_cf75 → vendor/zig/lib/std/json/static.zig:61 (Parsed deinit)
- 166_f894 → vendor/zig/lib/std/testing/FailingAllocator.zig:153 (FailingAllocator impl)
- 166_16fe → vendor/zig/lib/std/heap/arena_allocator.zig:51 (ArenaAllocator.deinit)
- 166_eb59 → vendor/zig/lib/std/mem.zig:3325 (concat implementation)

Changes to repository
---------------------
- doc/zig-reference.md — updated (appended "Expanded examples and direct references" and listed created bookmarks and usage guidance)
- chronicles/2026-03-01-zig-sg-bookmarks.md — earlier chronicle created
- chronicles/2026-03-01-zig-reference-expand.md — this chronicle entry

Suggested next steps
--------------------
- Review and tweak bookmark descriptions/tags to align with team conventions.
- Optionally mark additional std hotspots for bookmarks (hash_map, static_string_map, crypto secureZero, mem.eql fast paths, indexOfSentinel optimizations).
- Generate a JSON checklist or extract minimal snippet examples for each idiom to embed in prompts (I can do this next).

Command log excerpt
-------------------
- sg add vendor/zig/lib/std/mem/Allocator.zig:184 -t allocator,allocWithOptions -d 'allocWithOptions wrapper...'
- sg add vendor/zig/lib/std/array_list.zig:62 -t containers,deinit -d 'array_list deinit pattern...'
- sg list --json | jq '.[] | {id: .id, file: .file, line: .line, tags: .tags, desc: .desc}'

