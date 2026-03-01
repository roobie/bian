# Chronicle: Collections sweep

- Timestamp: 2026-03-02T00:48:00+01:00
- Participants: assistant (automated)

Summary
-------
Performed a sweep of std collection modules and added Sigil bookmarks for canonical container idioms: constructors, deinit variants, grow/ensureCapacity helpers, insert/getOrPut/put semantics, clone/cloneWithAllocator patterns, pop/remove behaviors, and iterator/peek usage.

Commands run (representative)
-----------------------------
- rg across vendor/zig/lib/std to locate collection modules and key symbols (init, deinit, append, put, getOrPut, ensureTotalCapacity, cloneWithAllocator, pop, remove)
- sg add <file>:<line> -t <tags> -d "..." (many bookmarks added)
- Updated doc/zig-reference.md with a "Collections" section linking representative bookmarks

Bookmarks added (representative)
---------------------------------
- array_list.init — 701_f3b6
- array_list.append — 701_5348
- array_list.appendSlice — 701_01f9
- array_list.ensureTotalCapacity — 701_9898
- array_list.clone / clone(gpa) — 701_341d / 701_d28a
- array_hash_map.init — 701_c72d
- array_hash_map.getOrPut — 701_6cfe
- array_hash_map.put — 701_db2f
- array_hash_map.cloneWithAllocator — 701_5d11
- array_hash_map.ensureTotalCapacity(gpa) — 701_7377
- hash_map.init — 702_66be
- hash_map.getOrPut — 702_a4f4
- hash_map.put — 702_810f
- hash_map.remove — 702_90f1
- hash_map.cloneWithAllocator — 702_be59
- hash_map.ensureTotalCapacity(allocator) — 702_6f6c
- static_string_map.init — 702_8309
- priority_queue.init/remove/ensureTotalCapacity — 702_4e34 / 702_3dfe / 702_c8b1
- multi_array_list.append/ensureTotalCapacity/clone — 702_90cc / 702_fcfd / 702_ac5f
- buf_set.init/insert/clone — 702_3c24 / 702_499b / 702_520e
- bit_set.deinit/clone — 702_f1d4 / 702_3438

Files changed
-------------
- doc/zig-reference.md — appended Collections section and representative bookmarks
- chronicles/2026-03-02-collections-sweep.md — this chronicle

Next steps
----------
- Option A: Extract a JSON checklist mapping the container idioms to bookmark IDs for programmatic use.
- Option B: Continue sweeping other container modules (segmented_list, DoublyLinkedList, SinglyLinkedList, treap, priority_dequeue) and add representative bookmarks.
- Option C: Extract small code snippets showing typical `init`/`deinit`/`cloneWithAllocator` patterns for the doc and LLM prompts.

