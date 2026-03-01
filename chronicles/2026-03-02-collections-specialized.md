# Chronicle: Collections — specialized sweep

- Timestamp: 2026-03-02T01:12:00+01:00
- Participants: assistant (automated)

Summary
-------
Swept the specialized collection modules in the vendored Zig stdlib and added Sigil bookmarks for representative APIs and idioms in:
- DoublyLinkedList.zig
- SinglyLinkedList.zig
- segmented_list.zig
- treap.zig
- priority_dequeue.zig

Commands run (representative)
-----------------------------
- sg list --json (session start)
- rg "pub fn" vendor/zig/lib/std/{DoublyLinkedList.zig,SinglyLinkedList.zig,segmented_list.zig,treap.zig,priority_dequeue.zig} -n
- sg add <file>:<line> -t <tags> -d "..." (added many bookmarks)

Bookmarks added (representative)
---------------------------------
- DoublyLinkedList.insertAfter — 982_6bca
- DoublyLinkedList.insertBefore — 982_e8eb
- DoublyLinkedList.concatByMoving — 982_c1a0
- DoublyLinkedList.append/prepend — 982_87f8 / 982_a129
- DoublyLinkedList.pop/popFirst/len — 982_33b6 / 982_4516 / 982_c1b2
- SinglyLinkedList.insertAfter/removeNext/prepend/popFirst/len — 990_8eb2 / 990_e74e / 990_0e0d / 990_8996 / 990_aa96
- SegmentedList type/deinit/append/addOne/pop/iterator — 998_729d / 998_b25d / 998_fd5a / 998_8ee1 / 998_ce98 / 999_fa00
- Treap type/getEntryFor/inorderIterator/init — 004_f912 / 004_9fd4 / 004_78bd / 004_66e6
- PriorityDequeue type/init/add/peek/remove/ensureTotalCapacity/iterator — 012_73bd / 012_40d3 / 012_9031 / 012_045f / 012_988f / 012_7407 / 012_c0e7

Files changed
-------------
- doc/zig-reference.md — added "Specialized collections" subsection and bookmark references
- chronicles/2026-03-02-collections-specialized.md — this chronicle

Next steps
----------
- Sweep tests inside these files to bookmark iterator edge-cases and failing_allocator behavior.
- Optionally produce JSON mapping (idiom -> bookmark ids) and/or a short snippet per specialized collection to include in doc/zig-reference.md.

