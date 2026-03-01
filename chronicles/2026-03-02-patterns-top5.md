# Chronicle: Patterns sweep (top-5)

- Timestamp: 2026-03-02T02:05:00+01:00
- Participants: assistant (automated)

Summary
-------
Performed a representative sweep of five high-value pattern areas in the vendored Zig stdlib, adding Sigil bookmarks and updating doc/zig-reference.md with an "Explored pattern areas" subsection.

Areas swept
-----------
1. Allocator implementations & wrapper patterns
2. Comptime-driven APIs & reflection patterns
3. Error handling & testing patterns
4. Crypto & secure-zero / constant-time idioms
5. Parsing / binary loaders (safe slice handling)

Commands run (representative)
-----------------------------
- sg list --json | jq ...
- rg to locate target function signatures and test blocks
- sg add <file>:<line> -t <tags> -d "..." for representative bookmarks
- Updated doc/zig-reference.md with a new subsection (Explored pattern areas)
- Wrote this chronicle

Bookmarks added
---------------
- Allocator.VTable — 754_7b95
- rawAlloc wrapper — 754_075b
- allocAdvancedWithRetAddr — 754_312c
- alloc @memset undefined example — 754_b2eb
- mem wrapper rawAlloc usage — 754_8667
- inline-for float types parse_float — 762_1bf0
- timing_safe.eql — 762_cd42
- blake2 inline-for rounds — 762_e99c
- Zir.ExtraData (comptime fields) — 762_6150
- FailingAllocator test — 772_be76
- zon.parse expectError examples — 772_85a2
- crypto.secureZero helper — 779_7e62
- timing_safe module header — 779_2519
- bcrypt secureZero usage — 779_b281
- decodeElfSlice — 788_1d06
- decodePESlice — 788_2bd7
- decodeMachoSlice — 788_685c
- elf module entry — 788_83ee

Files changed
-------------
- doc/zig-reference.md — appended "Explored pattern areas" and the representative bookmark list
- chronicles/2026-03-02-patterns-top5.md — this chronicle

Next steps
----------
- Expand any area (e.g., exhaustive secureZero sites, all `inline for` reflection points, full testing.expectError map).
- Produce JSON mapping for tooling.

