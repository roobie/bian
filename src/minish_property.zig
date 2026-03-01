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
    defer if (desc0.imports.len != 0) root.freeImportEntries(allocator, desc0.imports);
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
    defer if (res.imports.len != 0) root.freeImportEntries(allocator, res.imports);
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

// ---------------------------------------------------------------------------
// Property test: PE header mutation fuzzing (minimal synthetic buffer)
// ---------------------------------------------------------------------------

const PEMutKind = enum {
    NoOp,
    Set_e_lfanew,
    Write_PE_at_val,
    Zero_from_val,
    Corrupt_COFF_fields,
};

const PEMutation = struct {
    kind: PEMutKind,
    val: u32,
};

fn pe_prop(m: PEMutation) !void {
    const allocator = std.testing.allocator;
    const len: usize = 256;
    var buf = try allocator.alloc(u8, len);
    defer allocator.free(buf);
    var k: usize = 0;
    while (k < len) : (k += 1) buf[k] = 0;
    buf[0] = 'M';
    buf[1] = 'Z';

    // Apply mutation
    switch (m.kind) {
        .NoOp => {},
        .Set_e_lfanew => {
            // write little-endian u32 at 0x3c
            write_u32_le(buf, 0x3c, m.val);
        },
        .Write_PE_at_val => {
            const off64 = @as(u64, m.val);
            if (off64 + 4 <= @as(u64, buf.len)) {
                const off = @as(usize, m.val);
                buf[off] = 'P';
                buf[off + 1] = 'E';
                buf[off + 2] = 0;
                buf[off + 3] = 0;
            }
        },
        .Zero_from_val => {
            const start64 = @as(u64, m.val);
            if (start64 < @as(u64, buf.len)) {
                const start = @as(usize, m.val);
                var i: usize = start;
                while (i < buf.len) : (i += 1) buf[i] = 0;
            }
        },
        .Corrupt_COFF_fields => {
            // try to compute e_lfanew and corrupt COFF fields if header present
            const e_lfanew_u32 = root.readU32At(buf, 0x3c, .little);
            const e_lfanew_64 = @as(u64, e_lfanew_u32);
            if (e_lfanew_64 + 4 <= @as(u64, buf.len)) {
                const e_lfanew = @as(usize, e_lfanew_u32);
                const coff_off = e_lfanew + 4;
                if (coff_off + 20 <= buf.len) {
                    // write machine (u16) and characteristics (u16) derived from val
                    const machine = @as(u16, (m.val & 0xFFFF));
                    const characteristics = @as(u16, ((m.val >> 16) & 0xFFFF));
                    buf[coff_off + 0] = @as(u8, machine & 0xFF);
                    buf[coff_off + 1] = @as(u8, (machine >> 8) & 0xFF);
                    buf[coff_off + 18] = @as(u8, characteristics & 0xFF);
                    buf[coff_off + 19] = @as(u8, (characteristics >> 8) & 0xFF);
                }
            }
        },
    }

    // Run decoder; accept either error or ok but ensure no panic/leak
    const res = decodePESlice(allocator, buf, null) catch |_| return;
    defer if (res.sections.len != 0) allocator.free(res.sections);
    defer if (res.segments.len != 0) allocator.free(res.segments);
    defer if (res.imports.len != 0) root.freeImportEntries(allocator, res.imports);
    defer if (res.exports.len != 0) allocator.free(res.exports);
    defer if (res.messages.len != 0) allocator.free(res.messages);
    defer if (res.path.len != 0) allocator.free(res.path);
}

test "minish: pe header mutations do not panic or leak" {
    const allocator = std.testing.allocator;
    const gen_pe = gen.structure(PEMutation, .{
        .kind = gen.enumValue(PEMutKind),
        .val = gen.int(u32),
    });
    try minish.check(allocator, gen_pe, pe_prop, .{ .num_runs = 200, .verbose = false });
}

// ---------------------------------------------------------------------------
// Property test: Mach-O load-command and header mutation fuzzing
// ---------------------------------------------------------------------------

const MachMutKind = enum {
    NoOp,
    SetSizeOfCmds,
    SetNcmds,
    CorruptFirstLC_Cmdsize,
    FlipMagic,
    CorruptSymtabOffsets,
};

const MachMutation = struct {
    kind: MachMutKind,
    val: u32,
    idx: u32,
};

fn macho_prop(m: MachMutation) !void {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-x64-ls", .{});
    defer file.close();
    const orig = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(orig);

    var buf = try allocator.alloc(u8, orig.len);
    defer allocator.free(buf);
    std.mem.copy(u8, buf, orig);

    // Determine magic and endianness similar to decodeMachoSlice
    const mm = root.readU32At(buf, 0, .big);
    var is_64: bool = false;
    var m_endian: Endian = Endian.little;
    if (mm == macho.MH_MAGIC_64) {
        is_64 = true;
        m_endian = Endian.big;
    } else if (mm == macho.MH_CIGAM_64) {
        is_64 = true;
        m_endian = Endian.little;
    } else if (mm == macho.MH_MAGIC) {
        is_64 = false;
        m_endian = Endian.big;
    } else if (mm == macho.MH_CIGAM) {
        is_64 = false;
        m_endian = Endian.little;
    } else return; // not a macho file

    const hdr_size: usize = if (is_64) @sizeOf(macho.mach_header_64) else @sizeOf(macho.mach_header);

    switch (m.kind) {
        .NoOp => {},
        .SetSizeOfCmds => {
            if (m_endian == .little) write_u32_le(buf, 20, m.val) else write_u32_be(buf, 20, m.val);
        },
        .SetNcmds => {
            if (m_endian == .little) write_u32_le(buf, 16, m.val) else write_u32_be(buf, 16, m.val);
        },
        .CorruptFirstLC_Cmdsize => {
            const off64 = @as(u64, hdr_size);
            if (off64 + 8 <= @as(u64, buf.len)) {
                const off = hdr_size;
                // write cmdsize at off+4
                if (m_endian == .little) write_u32_le(buf, off + 4, m.val) else write_u32_be(buf, off + 4, m.val);
            }
        },
        .FlipMagic => {
            // write new magic as big-endian to offset 0
            write_u32_be(buf, 0, m.val);
        },
        .CorruptSymtabOffsets => {
            // iterate load commands to find LC_SYMTAB and corrupt symoff/stroff
            var off: usize = hdr_size;
            var lc_index: usize = 0;
            // read ncmds safely
            const ncmds_u32 = root.readU32At(buf, if (is_64) 16 else 16, m_endian);
            var ncmds: usize = @as(usize, ncmds_u32);
            while (lc_index < ncmds) : (lc_index += 1) {
                if (off + 8 > buf.len) break;
                const cmd_val = root.readU32At(buf, off, m_endian);
                const cmdsize_u32 = root.readU32At(buf, off + 4, m_endian);
                const cmdsize_64 = @as(u64, cmdsize_u32);
                if (cmdsize_64 < 8 or off + @as(usize, cmdsize_u32) > buf.len) break;
                const opt_cmd = root.machoLCFromU32(cmd_val);
                if (opt_cmd) |cmd| {
                    if (cmd == macho.LC.SYMTAB) {
                        // symoff at off+8, stroff at off+16
                        if (off + 24 <= buf.len) {
                            if (m_endian == .little) {
                                write_u32_le(buf, off + 8, m.val);
                                write_u32_le(buf, off + 16, m.val);
                            } else {
                                write_u32_be(buf, off + 8, m.val);
                                write_u32_be(buf, off + 16, m.val);
                            }
                        }
                        break;
                    }
                }
                off += @as(usize, cmdsize_u32);
            }
        },
    }

    // Run decoder; accept either error or ok but ensure no panic/leak
    const res = decodeMachoSlice(allocator, buf, null) catch |_| return;
    defer if (res.sections.len != 0) allocator.free(res.sections);
    defer if (res.segments.len != 0) allocator.free(res.segments);
    defer if (res.imports.len != 0) root.freeImportEntries(allocator, res.imports);
    defer if (res.exports.len != 0) allocator.free(res.exports);
    defer if (res.messages.len != 0) allocator.free(res.messages);
    defer if (res.path.len != 0) allocator.free(res.path);
}

test "minish: macho header mutations do not panic or leak" {
    const allocator = std.testing.allocator;
    const gen_macho = gen.structure(MachMutation, .{
        .kind = gen.enumValue(MachMutKind),
        .val = gen.int(u32),
        .idx = gen.intRange(u32, 0, 128),
    });
    try minish.check(allocator, gen_macho, macho_prop, .{ .num_runs = 200, .verbose = false });
}
