Zig std (0.15.2) — idioms, style, and memory-management patterns
================================================================

Purpose
-------
This document condenses recurring patterns, naming conventions, memory-management idioms, and style signals used throughout Zig's std library (v0.15.2). Its goal is to be an authoritative reference an LLM can consult when producing new Zig code that matches std style and behaviour — especially around memory allocation and safety.

High-level principles
---------------------
- Prefer explicitness: pass allocators to APIs that allocate, avoid globals.
- Paranoid validation: std often encodes checks via asserts, @compileError, and wrapper types (e.g., ValidationAllocator).
- Comptime-driven APIs: many functions are generic over element type and alignment using comptime parameters.
- Zero-sized types are special-cased: code must handle @sizeOf(T) == 0 explicitly.
- Resource ownership is explicit: allocations must be freed by the owner; patterns favor creating deinit/destroy functions or using `defer/errdefer`.
- Performance-aware code: use @alignCast, @ptrCast, SIMD paths, loop unrolling, and specialized implementations for slices of bytes.

Naming and file structure
-------------------------
- Files are generally named lower_snake_case.zig for modules. Types or exported constants may be CamelCase or UpperCamel (e.g., Allocator, Alignment).
- Public functions are usually lower_snake_case. Types/struct names are UpperCamel or capitalize as appropriate (Allocator, Error, VTable).
- Constants and helper types often appear at the top of the file (e.g., Alignment enum in std/mem.zig).
- `test` blocks are used heavily within std files for unit test coverage and examples.

Common language patterns
------------------------
- Generic functions use `comptime T: type` and return typed slices (e.g., `pub fn alloc(self: Allocator, comptime T: type, n: usize) Error![]T`).
- `inline for (...) |item| { ... }` is used for compile-time loops or to unroll operations.
- `@typeInfo`, `@typeName`, `@sizeOf`, `@alignOf`, `@inComptime`, and other builtin reflectors are used extensively.
- Explicit `@compileError` guards to enforce correct compile-time usage.
- Use of `@returnAddress()` when calling allocator raw APIs (for diagnostics / debugging).
- `@ptrCast`, `@alignCast`, `@constCast`, `@memcpy`, `@memset`, `@bitCast` are used for low-level memory manipulations.
- Branch hints: `@branchHint(.unlikely)` used where appropriate.

Allocator-centric patterns
--------------------------

1. The Allocator interface
   - Located at std/mem/Allocator.zig and exported as std.mem.Allocator:
     - Struct with:
       - ptr: *anyopaque
       - vtable: *const VTable
     - VTable with functions:
       - alloc(*anyopaque, len, alignment, ret_addr) ?[*]u8
       - resize(*anyopaque, memory, alignment, new_len, ret_addr) bool
       - remap(*anyopaque, memory, alignment, new_len, ret_addr) ?[*]u8
       - free(*anyopaque, memory, alignment, ret_addr) void
   - High-level convenience functions (alloc, allocSentinel, alignedAlloc, allocWithOptions, free, dupe, dupeZ, realloc, remap, resize, create/destroy) are thin wrappers that:
     - convert element counts to byte counts (careful with overflow),
     - handle zero-sized type behavior,
     - call the raw vtable via `self.rawAlloc`, `self.rawResize`, `self.rawRemap`, `self.rawFree`.
   - Error type for allocation operations: `pub const Error = error{OutOfMemory};` — std functions return `Error!T` on allocation failure.

2. Memory semantics expected from allocators
   - Allocators return memory with contents set to "undefined" (std often explicitly @memset to undefined for returned memory).
   - Freeing logic sets memory to `undefined` before passing it to rawFree.
   - rawResize returns bool indicating whether resizing in-place succeeded (true) or not (false). rawRemap can return a moved pointer (or null if caller should do alloc/copy/free).
   - Many higher-level functions (realloc, remap) provide semantics suitable for callers (e.g., realloc guarantees not to return null — returns Error.OutOfMemory on failure).

3. Patterns for callers (how std code uses allocators)
   - Accept an allocator parameter where memory may be allocated: `allocator: std.mem.Allocator` or `Allocator` type alias.
   - Typical allocation + cleanup:
     - Allocate: `var buf = try allocator.alloc(u8, n);`
     - Ensure cleanup: `defer allocator.free(buf);` or `errdefer allocator.free(buf);` when inside fallible init paths.
     - For struct-like objects, provide `deinit`/`destroy` that accepts allocator and frees internals.
   - Use `errdefer` to free allocated resources on early-return errors while preserving deallocation order:
     - allocate resource A
     - errdefer allocator.free(A);
     - allocate B
     - errdefer allocator.free(B);
     - now finalize; errdefer unwinds in reverse order on early error.
   - For null-terminated / sentinel arrays, use `allocSentinel` or `allocWithOptions` with sentinel and return the sentinel-typed slice.

4. Zero-sized types
   - Standard library special-cases zero-sized types:
     - `if (@sizeOf(T) == 0) { return some canonical pointer or set len }`
     - Use sentinel pointer patterns (`@ptrFromInt` / alignBackward) to represent “allocated” zero-sized memory without calling vtable.
   - When implementing generic allocation helpers, explicitly handle @sizeOf(T) == 0 to avoid calling into allocator for zero bytes.

5. Alignment
   - std.mem.Alignment exists and is used to specify alignment constraints.
   - There are utility methods to compute alignment sizes, forward/backward address, check: `Alignment.of(T)`, `Alignment.toByteUnits()`.
   - Use `@alignCast` to interpret raw byte pointers as aligned slice types before returning to caller.

6. Return address / diagnostics
   - When calling raw allocator hooks, std passes `@returnAddress()`; allocator implementations may use that for diagnostics or debugging.

7. Duplication helpers
   - `dupe(allocator, T, slice)` to allocate and copy.
   - `dupeZ` for NUL-terminated copying.

8. Resizing & remapping
   - `resize` is a hint that may succeed in-place (returns bool).
   - `remap` attempts to relocate or extend and returns a new pointer if successful or `null` if the allocator can't handle the request and the caller should allocate/copy/free.

Memory initialization and deinitialization patterns
--------------------------------------------------
- Allocators return memory in `undefined` state. Caller must initialize fields before use.
- std provides `zeroes(comptime T: type)` and `zeroInit(T, init)` helper functions to produce zero-initialized objects where appropriate, but their use is discouraged for regular struct initialization (explicit initialization is preferred).
- Before freeing, std usually sets user memory to undefined: `@memset(non_const_ptr[0..bytes_len], undefined);` then calls rawFree. This makes it explicit that memory is no longer in a defined state (also helps catch use-after-free in some analyzers).
- For externally defined C structs (extern struct/union), std may use `@memset(asBytes(&item), 0);` to zero padding as required by some C APIs.

Pointer/slice handling idioms
-----------------------------
- Many utility functions handle many pointer shapes: slices (`[]T`), sentinel slices (`[:0]T`), C pointers (`[*c]T`), arrays (`[N]T`), optional pointers, etc.
- `@typeInfo` switches and helper types like `Span()` and `SliceTo()` are used for generic pointer handling while preserving pointer attributes (const, sentinel, alignment).
- `mem.sliceAsBytes(...)` and `mem.bytesAsSlice(T, bytes)` are used to convert between element slices and byte slices.
- For sentinel terminated memory, the code expects either an explicit sentinel property in the pointer type or uses helper functions such as `len`, `indexOfSentinel`, `span`, `sliceTo`.
- Always preserve pointer attributes (constness, sentinel) when returning new pointer/slice views.

Error handling idioms
--------------------
- Allocation failure is modelled with `Error.OutOfMemory` in std; APIs that allocate usually return `Error!T`.
- `try` is used to propagate errors upward; `try` + `errdefer` is a common combo to ensure allocated resources are freed on error.
- Code often uses `try testing.expectError(error.OutOfMemory, ...)` in tests to check allocator error conditions.
- `@compileError` is used for impossible/invalid compile-time use cases.

Testing idioms
--------------
- `test "description" { ... }` blocks in std files both test and document usage.
- `std.testing.allocator` and `testing.failing_allocator` are used for runtime testing of allocation success/failure.
- Tests commonly exercise both common and edge behaviours (zero-sized types, sentinel behavior, resizing, SIMD paths).

Performance and architecture-aware patterns
-------------------------------------------
- SIMD: std uses `std.simd.suggestVectorLength(T)` to choose vectorized implementations where appropriate (e.g., eqlBytes, indexOfSentinel, indexOfScalarPos). When using SIMD it defers to compile-time suggestions or back-end capability checks.
- Fast paths for bytes/slices: special-casing u8 slices is common; use of memcmp-like vector/word comparisons appears.
- Page- and block-aware logic: indexOfSentinel has page-crossing considerations and aligns reads to blocks when safe.
- Branch hints (`@branchHint(.unlikely)`) used for rare paths.

Common micro-patterns and idioms you should reproduce
----------------------------------------------------
- Passing Allocator explicitly to functions that allocate.
- Using `try allocator.alloc(T, n)` then `defer allocator.free(some_slice)` or `errdefer allocator.free(some_slice)` in fallible constructors.
- For types that own allocated buffers, include an explicit `deinit(self: *Type, allocator: Allocator)` or `destroy`.
- Use `if (@sizeOf(T) == 0)` special-case code paths that do not call into the allocator.
- Use `@alignCast` and `@ptrCast` when interpreting low-level pointer results.
- Use `@returnAddress()` when calling low-level allocator vtable functions so allocator implementations can report where allocations originated (std does this).
- Use `@memset(..., undefined)` or `@memset(..., 0)` as std does to intentionally reset memory before free if you mimic std behaviour.
- Use `@compileError` to make invalid API usages fail at compile time.
- Prefer `allocSentinel`/`allocWithOptions` for sentinel/NUL-terminated buffers rather than manual allocation + append semantics.

Explored pattern areas (top-5 sweep)
------------------------------------
I swept five high-value pattern areas and added representative Sigil bookmarks for quick reference. Below are the areas, why they matter, and bookmark pointers (use `sg show <id>` to view context).

1) Allocator implementations & wrapper patterns
- Why: allocators are central to std's memory model; many APIs follow the same allocation/free/errdefer patterns and use raw hooks for diagnostics.
- Representative bookmarks:
  - Allocator.VTable declaration — 754_7b95
  - rawAlloc wrapper (calls through vtable) — 754_075b
  - allocAdvancedWithRetAddr core allocation — 754_312c
  - alloc + @memset undefined example — 754_b2eb
  - mem wrapper underlying.rawAlloc usage — 754_8667

2) Comptime-driven APIs & reflection patterns
- Why: comptime generics, `inline for`, and `@typeInfo` are used to implement type-generic algorithms and code generation.
- Representative bookmarks:
  - inline-for over float types in parse_float — 762_1bf0
  - timing_safe.eql (comptime T: type + @typeInfo usage) — 762_cd42
  - blake2 rounds unrolling (inline for) — 762_e99c
  - Zir.ExtraData (comptime T and inline for over fields) — 762_6150

3) Error handling & testing patterns
- Why: std uses error unions and a testing harness (`testing.expectError`, `testing.failing_allocator`) extensively to document and validate failure modes.
- Representative bookmarks:
  - FailingAllocator test / failing_allocator usage — 772_be76
  - zon.parse tests: many expectError usages — 772_85a2

4) Crypto & secure-zero / constant-time idioms
- Why: security-critical code uses secureZero and timing-safe comparisons; these patterns must be followed for secrets handling.
- Representative bookmarks:
  - crypto.secureZero helper and test — 779_7e62
  - timing_safe module header & helpers — 779_2519
  - bcrypt secureZero usage on password buffers — 779_b281

5) Parsing / binary loaders (safe slice handling)
- Why: parsers demonstrate careful bounds checks, zero-copy slice handling, and fallbacks for malformed data — great examples for robust code.
- Representative bookmarks:
  - decodeElfSlice (src/slice_decoders.zig) — 788_1d06
  - decodePESlice (src/slice_decoders.zig) — 788_2bd7
  - decodeMachoSlice (src/slice_decoders.zig) — 788_685c
  - elf module entry (vendor/zig/lib/std/elf.zig) — 788_83ee

How I picked locations
- Used ripgrep to find canonical helper functions and test blocks (e.g., rawAlloc/vtable in Allocator.zig, `inline for` uses in crypto and fmt, testing.expectError occurrences, secureZero in crypto, and decode*Slice functions in src/).
- Added Sigil bookmarks (sg add) at representative signatures/definitions and test blocks so you can jump to these patterns with `sg show`.

Next steps
----------
- I can expand any of these areas with deeper sweeps (e.g., collect every secureZero usage, every `inline for` reflection pattern, or all testing.expectError sites) and produce a JSON mapping for tooling.
- I can sweep tests in the parsing modules and bookmark failure-case examples.

