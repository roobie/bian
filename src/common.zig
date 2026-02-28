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
