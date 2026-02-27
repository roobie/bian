const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const Endian = std.builtin.Endian;

// Reuse types from root.zig by importing the root module in tests. We'll assume
// the root module will import this file and use its functions. To keep this
// file minimal, duplicate only small helpers and the public functions.

pub fn decodeElfSlice(allocator: std.mem.Allocator, file_buf: []const u8) !anytype {
    // Return type is "anytype" so root.zig can cast/forward as needed.
    if (file_buf.len < 16) return error.TooSmall;
    var fixed_reader = std.io.Reader.fixed(file_buf);
    const header = try elf.Header.read(&fixed_reader);
    return header; // caller will perform real decoding; placeholder
}

pub fn decodePESlice(allocator: std.mem.Allocator, buf: []const u8) !anytype {
    if (buf.len < 64) return error.TooSmall;
    if (buf[0] != 'M' or buf[1] != 'Z') return error.InvalidHeader;
    const e_lfanew = @as(usize, buf[0x3c]) | (@as(usize, buf[0x3d]) << 8) | (@as(usize, buf[0x3e]) << 16) | (@as(usize, buf[0x3f]) << 24);
    if (e_lfanew + 4 > buf.len) return error.Malformed;
    if (buf[e_lfanew] != 'P' or buf[e_lfanew + 1] != 'E') return error.InvalidHeader;
    return buf; // placeholder
}
