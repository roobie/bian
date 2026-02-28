const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const Endian = std.builtin.Endian;

// Minimal, compile-friendly placeholders for slice decoders.
// These are intentionally small in the base commit; later refactors will
// replace return types with the project's BinaryDescription and move helpers
// into src/common.zig.

pub const ParseError = error{ TooSmall, InvalidHeader, Malformed };

pub fn decodeElfSlice(allocator: std.mem.Allocator, file_buf: []const u8) !std.elf.Header {
    if (file_buf.len < 16) return ParseError.TooSmall;
    var fixed_reader = std.io.Reader.fixed(file_buf);
    const header = try elf.Header.read(&fixed_reader);
    return header; // placeholder behavior
}

pub fn decodePESlice(allocator: std.mem.Allocator, buf: []const u8) ![]const u8 {
    if (buf.len < 64) return ParseError.TooSmall;
    if (buf[0] != 'M' or buf[1] != 'Z') return ParseError.InvalidHeader;
    const e_lfanew = @as(usize, buf[0x3c]) | (@as(usize, buf[0x3d]) << 8) | (@as(usize, buf[0x3e]) << 16) | (@as(usize, buf[0x3f]) << 24);
    if (e_lfanew + 4 > buf.len) return ParseError.Malformed;
    if (buf[e_lfanew] != 'P' or buf[e_lfanew + 1] != 'E') return ParseError.InvalidHeader;
    return buf; // placeholder
}

// Unit tests for the minimal slice decoder placeholders. These tests exercise
// the in-memory slice API (no filesystem side-effects beyond reading test
// fixtures) and assert deterministic behavior for the supplied test assets.

test "slice_decoders: decodeElfSlice parses ELF header from fixture" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 1024);
    defer allocator.free(buf);

    const header = try decodeElfSlice(allocator, buf);
    try expect(header.is_64);
    try expect(header.machine == elf.EM.X86_64);
}

test "slice_decoders: decodePESlice rejects non-PE file with InvalidHeader" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 512);
    defer allocator.free(buf);

    // decodePESlice should error with InvalidHeader for an ELF file
    _ = decodePESlice(allocator, buf) catch |err| {
        try expect(err == ParseError.InvalidHeader);
        return;
    };
    // If we get here, decodePESlice didn't error as expected
    try expect(false);
}
