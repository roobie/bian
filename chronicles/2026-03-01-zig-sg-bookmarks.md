# Chronicle: Add sg bookmarks for Zig std idioms

- Timestamp: 2026-03-01T22:33:52+01:00
- Participants: assistant (automated)

Summary
-------
Created Sigil (sg) bookmarks inside the vendor/zig submodule to index representative locations that demonstrate the idioms and patterns documented in doc/zig-reference.md (allocator patterns, comptime idioms, zero-sized handling, errdefer/deinit patterns, alignment/ptr casts, SIMD hints, @compileError guards, testing idioms, etc.).

Actions taken (representative commands run)
-----------------------------------------
- sg list
- sg primer
- sg add vendor/zig/lib/std/mem/Allocator.zig:11 -t allocator,error -d 'Allocator Error declaration (OutOfMemory) — std allocation error idiom'
- sg add vendor/zig/lib/std/mem/Allocator.zig:153 -t allocator,zero-sized -d 'Special-case for zero-sized types (@sizeOf(T) == 0) in alloc helpers'
- sg add vendor/zig/lib/std/mem/Allocator.zig:180 -t allocator,alloc,comptime -d 'High-level alloc wrapper: alloc(self, comptime T: type, n) — converts counts to bytes and handles alignment'
- sg add vendor/zig/lib/std/mem/Allocator.zig:284 -t allocator,memset,undef -d 'Set returned memory to undefined with @memset before returning; std treats alloced memory as undefined'
- sg add vendor/zig/lib/std/mem/Allocator.zig:312 -t allocator,resize -d 'rawResize wrapper: resize semantics and boolean in-place success hint'
- sg add vendor/zig/lib/std/mem/Allocator.zig:356 -t allocator,remap -d 'rawRemap usage: may return moved pointer or null, caller fallback alloc/copy/free semantics'
- sg add vendor/zig/lib/std/mem/Allocator.zig:430 -t allocator,free,undef -d 'Free path sets memory to undefined then calls rawFree — std practice to aid diagnostics'
- sg add vendor/zig/lib/std/mem.zig:41 -t mem,alignment -d 'Alignment utilities (Alignment.of) — std alignment helpers and Alignment enum usage'
- sg add vendor/zig/lib/std/mem.zig:1092 -t mem,sentinel,slices -d 'indexOfSentinel implementation — sentinel-terminated slice handling idiom'
- sg add vendor/zig/lib/std/mem.zig:4246 -t mem,bytes,conversion -d 'bytesAsSlice / bytesAsValue helpers — converting between element slices and byte slices'
- sg add vendor/zig/lib/std/mem.zig:3325 -t mem,alloc,concat -d 'concat(allocator, comptime T: type, slices) — allocator passed explicitly for owned concatenation'
- sg add vendor/zig/lib/std/mem.zig:263 -t mem,zeroes,init -d 'zeroes(comptime T: type) helper — std zero-initialization helper (used sparingly)'
- sg add vendor/zig/lib/std/mem.zig:453 -t mem,zeroInit,init -d 'zeroInit(comptime T: type) helper — zero-init helper used by std when needed'
- sg add vendor/zig/lib/std/simd.zig:81 -t simd,performance -d 'std.simd.suggestVectorLength usage — choose vector length for SIMD fast paths'
- sg add vendor/zig/lib/std/heap/debug_allocator.zig:481 -t allocator,retaddr,diagnostics -d '@returnAddress() passed to raw allocator hooks for diagnostics'
- sg add vendor/zig/lib/std/heap/debug_allocator.zig:722 -t performance,branchHint -d '@branchHint(.unlikely)/.likely usage to mark rare/common branches'
- sg add vendor/zig/lib/std/http/Client.zig:85 -t ptr,alignCast -d 'Example use of @alignCast and @ptrCast when recovering parent struct from pointer field'
- sg add vendor/zig/lib/std/mem.zig:81 -t validation,allocator -d 'ValidationAllocator wrapper type — paranoid validation pattern'
- sg add vendor/zig/lib/std/Thread.zig:439 -t validation,compileError -d '@compileError guards to enforce unsupported configurations at compile time'
- sg add vendor/zig/lib/std/http/Client.zig:250 -t errdefer,allocator -d 'errdefer used to free resources on early-return; demonstrates LIFO deallocation ordering'
- sg add vendor/zig/lib/std/json/hashmap.zig:23 -t deinit,destroy,allocator -d 'errdefer map.deinit(allocator) — pattern for ensuring container deinit on error paths'
- sg add vendor/zig/lib/std/zig/LibCInstallation.zig:61 -t dupeZ,allocator -d 'dupeZ usage: duplicate NUL-terminated strings with allocator (dup helpers)'

Files/bookmarks added
--------------------
(The sg run output includes the new bookmark IDs and contexts.)

Contents of the run output (excerpt)
------------------------------------

<see /tmp/sg_add_outputs.txt — appended outputs include Added bookmark <id> → file:line and context lines>

Representative created bookmarks (id → file:line)
- 993_54a3 → vendor/zig/lib/std/mem/Allocator.zig:11
- 993_5c52 → vendor/zig/lib/std/mem/Allocator.zig:153
- 993_5eb7 → vendor/zig/lib/std/mem/Allocator.zig:180
- 993_6d57 → vendor/zig/lib/std/mem/Allocator.zig:284
- 993_1c6f → vendor/zig/lib/std/mem/Allocator.zig:312
- 993_8d43 → vendor/zig/lib/std/mem/Allocator.zig:356
- 993_7c1e → vendor/zig/lib/std/mem/Allocator.zig:430
- 993_536a → vendor/zig/lib/std/mem.zig:41
- 993_626d → vendor/zig/lib/std/mem.zig:1092
- 993_24ba → vendor/zig/lib/std/mem.zig:4246
- 993_94ab → vendor/zig/lib/std/mem.zig:3325
- 993_942b → vendor/zig/lib/std/mem.zig:263
- 993_afc5 → vendor/zig/lib/std/mem.zig:453
- 993_db99 → vendor/zig/lib/std/simd.zig:81
- 993_c21d → vendor/zig/lib/std/heap/debug_allocator.zig:481
- 993_f4e2 → vendor/zig/lib/std/heap/debug_allocator.zig:722
- 993_e8ea → vendor/zig/lib/std/http/Client.zig:85
- 993_2cdc → vendor/zig/lib/std/mem.zig:81
- 993_2998 → vendor/zig/lib/std/Thread.zig:439
- 993_fbff → vendor/zig/lib/std/http/Client.zig:250
- 993_b0b1 → vendor/zig/lib/std/json/hashmap.zig:23
- 994_37f4 → vendor/zig/lib/std/zig/LibCInstallation.zig:61

Suggested next steps
--------------------
- Review the created bookmarks and adjust descriptions/tags to match team conventions (if desired).
- Run `sg validate` to ensure bookmark contexts remain valid after any repo changes.
- Optionally expand bookmarks to cover additional std patterns mentioned in doc/zig-reference.md (e.g., more SIMD hotspots, other container implementations like array_list.zig/hash_map.zig, tests that exercise failing_allocator, etc.).

Commands run (representative)
----------------------------
- sg list
- sg primer
- sg add <file>:<line> -t <tags> -d "..."  (many invocations)
- sg list --json | jq ...

