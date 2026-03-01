# Chronicle: indexOfSentinel deep-dive

- Timestamp: 2026-03-02T00:12:00+01:00
- Participants: assistant (automated)

Summary
-------
Performed a focused analysis of std.mem.indexOfSentinel in vendor/zig/lib/std/mem.zig. Added Sigil bookmarks for the function signature, vectorized fast-path entry, page-alignment prologue, alignment advancement, page-crossing slow path, aligned vector loop using @alignCast/@ptrCast, scalar fallback, and the corresponding test validating vector paths.

Commands run (representative)
-----------------------------
- sg list --json > /tmp/sg_list.json
- rg -n "indexOfSentinel" vendor/zig
- nl -ba vendor/zig/lib/std/mem.zig | sed -n '1085,1160p'
- sg add vendor/zig/lib/std/mem.zig:<line> -t <tags> -d "..." (multiple bookmarks)

Bookmarks added (id → file:line)
--------------------------------
- 168_f1d7 → vendor/zig/lib/std/mem.zig:1092 — indexOfSentinel signature
- 168_7391 → vendor/zig/lib/std/mem.zig:1104 — vector path entry (arch + std.simd.suggestVectorLength)
- 168_a15e → vendor/zig/lib/std/mem.zig:1113 — page alignment prologue (start_addr & offset_in_page)
- 168_ac0f → vendor/zig/lib/std/mem.zig:1124 — alignForward advance before vector loop
- 168_e286 → vendor/zig/lib/std/mem.zig:1126 — page-crossing slow path (per-byte loop, @branchHint(.unlikely))
- 168_e6e5 → vendor/zig/lib/std/mem.zig:1137 — aligned vector loop using @ptrCast/@alignCast + std.simd.firstTrue
- 168_075b → vendor/zig/lib/std/mem.zig:1151 — scalar fallback
- 168_3363 → vendor/zig/lib/std/mem.zig:1157 — test: "indexOfSentinel vector paths"

Notes & observations
--------------------
- indexOfSentinel implements a careful vectorized fast-path that:
  - only enables when vector comparisons are allowed and the type is integer/float with power-of-two bitwidth
  - queries std.simd.suggestVectorLength(T) to pick a block_len
  - computes page-alignment to avoid reading past a page boundary (reads past buffer end are allowed if not crossing pages)
  - handles the rare page-crossing case with a per-byte loop until block alignment
  - uses @ptrCast(@alignCast(...)) to get an aligned vector pointer, compares vector==mask and finds the first match with std.simd.firstTrue
- The test exercise ensures correct behavior across sub-block offsets and page boundary crossings.

Suggested follow-ups
--------------------
- Bookmark and document related SIMD helpers: std.simd.firstTrue, suggestVectorLength, and vector comparison ops in std/simd.zig.
- Extract a small explanatory snippet for the reference showing: "How indexOfSentinel avoids page faults when vectorizing" for educational use.
- Sweep for other functions that use the same page-crossing prologue idiom (indexOfScalarPos has similar vector logic) and add bookmarks for comparison.

