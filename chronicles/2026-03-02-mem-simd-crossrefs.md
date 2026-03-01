# Chronicle: SIMD cross-references + mem.zig sweep

- Timestamp: 2026-03-02T00:38:00+01:00
- Participants: assistant (automated)

Summary
-------
Added cross-references in doc/zig-reference.md relating std.simd helpers (suggestVectorLength, firstTrue) to std.mem fast-paths (indexOfSentinel, indexOfScalarPos, eqlBytes). Continued the mem.zig sweep to bookmark eqlBytes and indexOfScalarPos vectorized implementations.

Actions taken
-------------
- Bookmarked SIMD helpers and mem fast-paths (indexOfSentinel was previously bookmarked).
- Appended a "SIMD cross-references" section to doc/zig-reference.md describing how the pieces fit together and listing bookmark IDs.

Representative commands run
---------------------------
- rg -n "indexOfSentinel|eqlBytes|suggestVectorLength|firstTrue|indexOfScalarPos" vendor/zig
- sg add vendor/zig/lib/std/mem.zig:<line> -t mem,eqlBytes -d '...'
- sg add vendor/zig/lib/std/simd.zig:<line> -t simd,firstTrue -d '...'
- edit doc/zig-reference.md (appended new section)

Bookmarks added in this step (id → file:line)
---------------------------------------------
- 484_6d6e → vendor/zig/lib/std/mem.zig:729 — eqlBytes: optimized byte-slice equality
- 484_92c6 → vendor/zig/lib/std/mem.zig:748 — eqlBytes Scan struct (vector/word chunk)
- 484_ea23 → vendor/zig/lib/std/mem.zig:786 — eqlBytes chunk loop
- 484_fa06 → vendor/zig/lib/std/mem.zig:820 — eqlBytes last-chunk compare
- 484_64fb → vendor/zig/lib/std/mem.zig:1258 — indexOfScalarPos vectorized search
- 330_2c12 → vendor/zig/lib/std/simd.zig:11 — suggestVectorLengthForCpu
- 330_48ae → vendor/zig/lib/std/simd.zig:81 — suggestVectorLength
- 330_93bc → vendor/zig/lib/std/simd.zig:305 — firstTrue
- 330_f34d → vendor/zig/lib/std/simd.zig:341 — firstIndexOfValue

Files changed
-------------
- doc/zig-reference.md — appended SIMD cross-references section
- chronicles/2026-03-02-mem-simd-crossrefs.md — this chronicle

Suggested next steps
--------------------
- Extract a short explanatory snippet (1-2 paragraphs) for the indexOfSentinel page-crossing prologue to include in doc/zig-reference.md.
- Sweep mem.zig for further simd usage in functions like mem.eql callers (already partially covered) and index/search helpers; add additional bookmarks where warranted.
- Optionally produce a JSON mapping (idiom -> bookmark ids) for programmatic consumption.

