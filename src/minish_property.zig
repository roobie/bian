const std = @import("std");
const minish = @import("minish");
const gen = minish.gen;

// A minimal property-based test demonstrating Minish integration.
// Property: reversing a string twice yields the original string.

fn reverse(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, s.len);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        result[s.len - 1 - i] = s[i];
    }
    return result;
}

fn reverse_twice_is_identity(allocator: std.mem.Allocator, s: []const u8) !void {
    const once = try reverse(allocator, s);
    defer allocator.free(once);
    const twice = try reverse(allocator, once);
    defer allocator.free(twice);
    try std.testing.expectEqualStrings(s, twice);
}

test "minish: reverse twice identity property" {
    const string_gen = gen.string(.{
        .min_len = 0,
        .max_len = 256,
        .charset = .alphanumeric,
    });

    // Run property checks using minish; if failures occur Minish will attempt
    // to shrink inputs and will print a minimal counterexample.
    try minish.check(std.testing.allocator, string_gen, prop_fn, .{ .num_runs = 200 });
}

fn prop_fn(s: []const u8) !void {
    return reverse_twice_is_identity(std.testing.allocator, s);
}

// ---------------------------------------------------------------------------
// Property test: ELF dynamic-region mutation fuzzing
// ---------------------------------------------------------------------------

const root = @import("root.zig");

const MutKind = enum {
    NoOp,
    ModifyDynTag,
    ModifyDynVal,
    ZeroShstrtab,
    SetDTSTRSZLarge,
    FlipDTNull,
    PrematureDTNull,
};

const Mutation = struct {
    kind: MutKind,
    idx: u32,
    val: u64,
};

fn write_u64_le_local(buf: []u8, off: usize, v: u64) void {
    var tmp: u64 = v;
    var j: usize = 0;
    while (j < 8) : (j += 1) {
        buf[off + j] = @as(u8, tmp & @as(u64, 0xFF));
        tmp = tmp >> 8;
    }
}

fn elf_prop(m: Mutation) !void {
    const allocator = std.testing.allocator;
    // Read fixture
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const orig = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(orig);

    // Make a mutable copy to mutate
    var buf = try allocator.alloc(u8, orig.len);
    defer allocator.free(buf);
    std.mem.copy(u8, buf, orig);

    // Decode baseline to locate dynamic section
    const desc0 = try root.decodeElfSlice(allocator, orig, null);
    defer if (desc0.sections.len != 0) allocator.free(desc0.sections);
    defer if (desc0.segments.len != 0) allocator.free(desc0.segments);
    defer if (desc0.imports.len != 0) allocator.free(desc0.imports);
    defer if (desc0.exports.len != 0) allocator.free(desc0.exports);
    defer if (desc0.messages.len != 0) allocator.free(desc0.messages);
    defer if (desc0.path.len != 0) allocator.free(desc0.path);

    var dyn_index: ?usize = null;
    var i: usize = 0;
    while (i < desc0.sections.len) : (i += 1) {
        if (std.mem.eql(u8, desc0.sections[i].name, ".dynamic")) {
            dyn_index = i;
            break;
        }
    }
    if (dyn_index == null) return;
    const dyn_off = @as(usize, desc0.sections[dyn_index.?].file_offset);
    const dyn_sz = @as(usize, desc0.sections[dyn_index.?].size);
    const entry_size = @sizeOf(elf.Elf64_Dyn);
    if (entry_size == 0) return;
    const n_entries = dyn_sz / entry_size;
    if (n_entries == 0) return;

    const chosen = @as(usize, (m.idx % @as(u32, n_entries)));
    const off = dyn_off + chosen * entry_size;

    switch (m.kind) {
        .NoOp => {},
        .ModifyDynTag => {
            write_u64_le_local(buf, off, m.val);
        },
        .ModifyDynVal => {
            write_u64_le_local(buf, off + 8, m.val);
        },
        .ZeroShstrtab => {
            // find .shstrtab and zero it
            var si: ?usize = null;
            var k: usize = 0;
            while (k < desc0.sections.len) : (k += 1) {
                if (std.mem.eql(u8, desc0.sections[k].name, ".shstrtab")) {
                    si = k;
                    break;
                }
            }
            if (si) |sidx| {
                const so = @as(usize, desc0.sections[sidx].file_offset);
                const ss = @as(usize, desc0.sections[sidx].size);
                var t: usize = 0;
                while (t < ss) : (t += 1) buf[so + t] = 0;
            }
        },
        .SetDTSTRSZLarge => {
            // locate DT_STRSZ entry and set to buf.len + 1
            var off2: usize = dyn_off;
            while (off2 + entry_size <= dyn_off + dyn_sz) : (off2 += entry_size) {
                const tag = root.readU64At(orig, off2, desc0.endianess);
                if (tag == @as(u64, elf.DT_STRSZ)) {
                    write_u64_le_local(buf, off2 + 8, @as(u64, buf.len) + 1);
                    break;
                }
            }
        },
        .FlipDTNull => {
            var off2: usize = dyn_off;
            while (off2 + entry_size <= dyn_off + dyn_sz) : (off2 += entry_size) {
                const tag = root.readU64At(orig, off2, desc0.endianess);
                if (tag == @as(u64, elf.DT_NULL)) {
                    write_u64_le_local(buf, off2, @as(u64, elf.DT_NEEDED));
                    write_u64_le_local(buf, off2 + 8, 0);
                    break;
                }
            }
        },
        .PrematureDTNull => {
            var off2: usize = dyn_off;
            while (off2 + entry_size <= dyn_off + dyn_sz) : (off2 += entry_size) {
                const tag = root.readU64At(orig, off2, desc0.endianess);
                if (tag == @as(u64, elf.DT_NEEDED)) {
                    write_u64_le_local(buf, off2, @as(u64, elf.DT_NULL));
                    break;
                }
            }
        },
    }

    // Now run decoder on mutated buffer; accept either error or success, but ensure no panic/leak
    const res = root.decodeElfSlice(allocator, buf, null) catch |_| {
        return; // acceptable error
    };
    // If successful, free returned slices and return
    defer if (res.sections.len != 0) allocator.free(res.sections);
    defer if (res.segments.len != 0) allocator.free(res.segments);
    defer if (res.imports.len != 0) allocator.free(res.imports);
    defer if (res.exports.len != 0) allocator.free(res.exports);
    defer if (res.messages.len != 0) allocator.free(res.messages);
    defer if (res.path.len != 0) allocator.free(res.path);
    return;
}

test "minish: elf dynamic mutations do not panic or leak" {
    const allocator = std.testing.allocator;
    const mut_gen = gen.structure(Mutation, .{
        .kind = gen.enumValue(MutKind),
        .idx = gen.intRange(u32, 0, 64),
        .val = gen.int(u64),
    });

    try minish.check(allocator, mut_gen, elf_prop, .{ .num_runs = 200, .verbose = false });
}
