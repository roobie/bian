# Chronicle: Zig std sweep — continued

- Timestamp: 2026-03-01T23:10:00+01:00
- Participants: assistant (automated)

Summary
-------
Performed another sweep of vendor/zig to find representative idioms/patterns and add Sigil bookmarks covering: container deinit patterns, secure-zeroing of secrets in crypto code, dupe/dupeZ allocation+copy examples, mem.eql usage, @alignCast parent-pointer casting, @compileError guards, and errdefer ordering concerns.

Commands run (representative)
-----------------------------
- sg list --json > /tmp/sg_list.json
- rg --hidden -n "dupeZ(|dupe(|errdefer .*free|deinit(self|secureZero|mem.eql|eqlBytes|indexOfSentinel|@compileError(|@returnAddress(|@alignCast(|@memset([^)]*undefined|ValidationAllocator|allocSentinel(|allocWithOptions()" vendor/zig
- sg add <file>:<line> -t <tags> -d "<description>" (multiple)

Bookmarks added (id → file:line; short desc)
--------------------------------------------
- 394_b0b5 → vendor/zig/lib/std/static_string_map.zig:134 — static_string_map.deinit(self, allocator) pattern
- 394_628c → vendor/zig/lib/std/hash_map.zig:211 — hash_map.deinit(self) pattern
- 394_12f3 → vendor/zig/lib/std/hash_map.zig:728 — hash_map.deinit(self, allocator) variant
- 394_2683 → vendor/zig/lib/std/crypto/bcrypt.zig:446 — crypto.secureZero wiping password buffer
- 394_a770 → vendor/zig/lib/std/crypto/salsa20.zig:423 — secureZero then @memset(undefined) ephemeral buffer wipe
- 394_a78f → vendor/zig/lib/std/crypto/keccak_p.zig:135 — secureZero method on keccak state
- 394_9f50 → vendor/zig/lib/compiler/aro/aro/CodeGen.zig:981 — dupeZ used with arena allocator
- 394_155e → vendor/zig/lib/compiler/resinator/cli.zig:212 — dupe + errdefer free ordering example
- 394_24c8 → vendor/zig/lib/compiler/resinator/compile.zig:1044 — Data.deinit(self, allocator) deinit example
- 394_f008 → vendor/zig/lib/compiler/aro/backend/Interner.zig:136 — std.mem.eql(u8, a_bytes, b_bytes) example
- 394_fb1e → vendor/zig/lib/compiler/resinator/parse.zig:1280 — @compileError("unreachable") example
- 394_3de1 → vendor/zig/lib/compiler/resinator/ast.zig:606 — @alignCast(@fieldParentPtr(...)) parent-pointer cast pattern
- 395_4812 → vendor/zig/lib/compiler/aro/aro/Compilation.zig:1263 — @compileError guarding errdefer ordering / realloc semantics

Files changed
-------------
- chronicles/2026-03-01-zig-sweep-continued.md (this file)
- doc/zig-reference.md (was last updated in earlier step)
- chronicles/2026-03-01-zig-reference-expand.md (previous chronicle)

Notes & observations
--------------------
- Crypto code consistently uses std.crypto.secureZero for secret wiping and often follows with `@memset(..., undefined)` to clearly mark memory as unused/undefined.
- The compiler codebase is a rich source of parent-pointer casting examples using `@alignCast(@fieldParentPtr(...))` and of careful errdefer/dupe usage patterns — good canonical examples for the reference.
- `std.mem.eql(u8, a, b)` is used pervasively for byte-slice equality and appears in many hot codepaths (interner, net, fs). When documenting `mem.eql` use, also reference SIMD/vectorized paths in std/mem.zig and std/simd.zig (bookmarked earlier).

Suggested next sweep targets
---------------------------
- indexOfSentinel implementation internals (std/mem.zig) and page/block alignment optimizations.
- mem.eql / eqlBytes fast-paths and SIMD-backed implementations in std/mem.zig and std/simd.zig.
- More container clone/cloneWithAllocator examples (hash_map clone, static_string_map clone).
- Places using @returnAddress() in allocator callsites beyond debug_allocator (fuzzer, build step uses).
- All uses of testing.failing_allocator and tests that assert OutOfMemory to document test patterns.

Next steps
----------
I can continue sweeping the tree for the suggested targets and add more bookmarks. Do you want me to prioritize any of the suggested targets above, or continue broadly and add another representative batch covering indexOfSentinel, mem.eql SIMD paths, and failing_allocator tests?

