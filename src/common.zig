const std = @import("std");
const Endian = std.builtin.Endian;

// Minimal common helpers moved out of root to avoid circular imports during
// incremental refactor. Keep this small: prefix_length and endian-aware
// integer readers which are widely useful.

pub const prefix_length: usize = 512;

pub fn readU32At(buf: []const u8, off: usize, endian: Endian) u32 {
    const b0 = @as(u32, buf[off]);
    const b1 = @as(u32, buf[off + 1]);
    const b2 = @as(u32, buf[off + 2]);
    const b3 = @as(u32, buf[off + 3]);
    return if (endian == .big) (b0 << 24) | (b1 << 16) | (b2 << 8) | b3 else (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

pub fn readU64At(buf: []const u8, off: usize, endian: Endian) u64 {
    const b0 = @as(u64, buf[off]);
    const b1 = @as(u64, buf[off + 1]);
    const b2 = @as(u64, buf[off + 2]);
    const b3 = @as(u64, buf[off + 3]);
    const b4 = @as(u64, buf[off + 4]);
    const b5 = @as(u64, buf[off + 5]);
    const b6 = @as(u64, buf[off + 6]);
    const b7 = @as(u64, buf[off + 7]);
    return if (endian == .big)
        (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) | (b4 << 24) | (b5 << 16) | (b6 << 8) | b7
    else
        (b7 << 56) | (b6 << 48) | (b5 << 40) | (b4 << 32) | (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

pub fn readI32At(buf: []const u8, off: usize, endian: Endian) i32 {
    return @bitCast(readU32At(buf, off, endian));
}

pub const SegmentMap = struct { fileoff: u64, filesize: u64, vmaddr: u64 };

pub fn zslice(bytes: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    return bytes[0..end];
}

pub fn vaddrToFileOffset(file_len: usize, segmaps: []const SegmentMap, vaddr: u64) ?usize {
    var i: usize = 0;
    while (i < segmaps.len) : (i += 1) {
        const m = segmaps[i];
        if (vaddr >= m.vmaddr and vaddr < m.vmaddr + m.filesize) {
            const off64 = m.fileoff + (vaddr - m.vmaddr);
            if (off64 <= @as(u64, file_len)) return @as(usize, off64);
            return null;
        }
    }
    return null;
}

pub fn safeSlice(buf: []const u8, off64: u64, len64: u64) ?[]const u8 {
    if (off64 > @as(u64, buf.len)) return null;
    const off = @as(usize, off64);
    if (len64 > @as(u64, buf.len)) return null;
    const len = @as(usize, len64);
    if (len > buf.len - off) return null;
    return buf[off .. off + len];
}

pub const SectionKind = enum { unknown, code, data };
pub const Permission = enum { read, write, execute, none };

pub const Section = struct {
    name: []const u8,
    kind: SectionKind,
    size: u64,
    file_offset: u64,
    permission: Permission,
    // Mach-O specific metadata (0 for other formats)
    flags: u32,
    reserved1: u32,
    reserved2: u32,
};

pub fn appendSegmentAndMap(allocator: std.mem.Allocator, segments_list: *std.ArrayList(Section), segmaps: *std.ArrayList(SegmentMap), fileoff: u64, filesize: u64, vmaddr: u64, perm: Permission) !void {
    try segments_list.append(allocator, Section{ .name = "", .kind = SectionKind.unknown, .size = filesize, .file_offset = fileoff, .permission = perm, .flags = 0, .reserved1 = 0, .reserved2 = 0 });
    try segmaps.append(allocator, SegmentMap{ .fileoff = fileoff, .filesize = filesize, .vmaddr = vmaddr });
}

pub fn appendSectionFromBlock(allocator: std.mem.Allocator, sections_list: *std.ArrayList(Section), block: []const u8, is64: bool, m_endian: Endian) !void {
    const name_bytes: []const u8 = block[0..16];
    const end = std.mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
    const name = name_bytes[0..end];

    if (m_endian == .little) {
        if (is64) {
            const sect_struct = @as(*align(1) const std.macho.section_64, @ptrCast(block.ptr)).*;
            const off = @as(u64, sect_struct.offset);
            const size = sect_struct.size;
            const flags = sect_struct.flags;
            const reserved1 = sect_struct.reserved1;
            const reserved2 = sect_struct.reserved2;
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = size, .file_offset = off, .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        } else {
            const sect_struct = @as(*align(1) const std.macho.section, @ptrCast(block.ptr)).*;
            const off = @as(u64, sect_struct.offset);
            const size = @as(u64, sect_struct.size);
            const flags = sect_struct.flags;
            const reserved1 = sect_struct.reserved1;
            const reserved2 = sect_struct.reserved2;
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = size, .file_offset = off, .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        }
    } else {
        if (is64) {
            const off32 = readU32At(block, 48, m_endian);
            const size = readU64At(block, 40, m_endian);
            const off64 = @as(u64, off32);
            const flags = readU32At(block, 64, m_endian);
            const reserved1 = readU32At(block, 68, m_endian);
            const reserved2 = readU32At(block, 72, m_endian);
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = size, .file_offset = off64, .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        } else {
            const off32 = readU32At(block, 40, m_endian);
            const size32 = readU32At(block, 36, m_endian);
            const flags = readU32At(block, 56, m_endian);
            const reserved1 = readU32At(block, 60, m_endian);
            const reserved2 = readU32At(block, 64, m_endian);
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = @as(u64, size32), .file_offset = @as(u64, off32), .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        }
    }
}

pub fn appendDylibNameFromLcData(allocator: std.mem.Allocator, imports_list: *std.ArrayList([]const u8), lc_data: []const u8, m_endian: Endian) !void {
    if (lc_data.len < 12) return;
    const name_off = @as(usize, readU32At(lc_data, 8, m_endian));
    if (name_off < lc_data.len) {
        const name = std.mem.sliceTo(lc_data[name_off..], 0);
        if (name.len != 0) try imports_list.append(allocator, name);
    }
}
