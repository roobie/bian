const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const Endian = std.builtin.Endian;

// Minimal, compile-friendly placeholders for slice decoders.
// These are intentionally small in the base commit; later refactors will
// replace return types with the project's BinaryDescription and move helpers
// into src/common.zig.

pub const ParseError = error{ TooSmall, InvalidHeader, Malformed };

const root = @import("root.zig");

pub fn decodeElfSlice(allocator: std.mem.Allocator, file_buf: []const u8, path: ?[]const u8) !root.BinaryDescription {
    if (file_buf.len < 16) return ParseError.TooSmall;
    var fixed_reader = std.io.Reader.fixed(file_buf);
    const header = try elf.Header.read(&fixed_reader);
    const bitness: u8 = if (header.is_64) 64 else 32;
    const arch = switch (header.machine) {
        elf.EM.X86_64 => root.CpuArch.x86_64,
        elf.EM.AARCH64 => root.CpuArch.aarch64,
        elf.EM.@"386" => root.CpuArch.x86,
        else => root.CpuArch.unknown,
    };
    const file_kind = switch (header.type) {
        elf.ET.EXEC => root.FileKind.executable,
        elf.ET.DYN => root.FileKind.shared_library,
        elf.ET.REL => root.FileKind.object,
        else => root.FileKind.unknown,
    };

    var sections = try std.ArrayList(root.Section).initCapacity(allocator, 0);
    defer sections.deinit(allocator);
    var segments = try std.ArrayList(root.Section).initCapacity(allocator, 0);
    defer segments.deinit(allocator);
    var imports = try std.ArrayList([]const u8).initCapacity(allocator, 0);
    defer imports.deinit(allocator);
    var exports = try std.ArrayList(root.Export).initCapacity(allocator, 0);
    defer exports.deinit(allocator);
    var messages = try std.ArrayList(root.Message).initCapacity(allocator, 0);
    defer messages.deinit(allocator);

    var desc_path: []const u8 = &[_]u8{};
    if (path) |p| {
        var pbuf = try allocator.alloc(u8, p.len);
        var j: usize = 0;
        while (j < p.len) : (j += 1) pbuf[j] = p[j];
        desc_path = pbuf[0..p.len];
    }

    const desc = root.BinaryDescription{
        .format = root.BinaryFileKind.elf,
        .os_abi = root.OsAbi.unknown,
        .arch = arch,
        .bitness = bitness,
        .endianess = header.endian,
        .file_kind = file_kind,
        .entrypoint_virtual_address = header.entry,
        .pie = if (header.type == elf.ET.DYN) root.Perhaps.yes else root.Perhaps.no,
        .aslr = root.Perhaps.unknown,
        .nx = root.Perhaps.unknown,
        .relro = root.RelroConfig.unknown,
        .stripped = root.StrippedState.unknown,
        .sections = try sections.toOwnedSlice(allocator),
        .segments = try segments.toOwnedSlice(allocator),
        .imports = try imports.toOwnedSlice(allocator),
        .exports = try exports.toOwnedSlice(allocator),
        .messages = try messages.toOwnedSlice(allocator),
        .path = desc_path,
        .debug_info_present = false,
    };

    return desc;
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

    const desc = try decodeElfSlice(allocator, buf, null);
    try expect(desc.format == root.BinaryFileKind.elf);
    try expect(desc.arch == root.CpuArch.x86_64);
    try expect(desc.bitness == 64);
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
