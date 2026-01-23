//! By convention, root.zig is the root source file when making a library.
const std = @import("std");
const fs = std.fs;
const mem = std.mem;

const expect = std.testing.expect;

const prefix_length = 64;

pub fn bufferedPrint() !void {
    // Stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try stdout.flush(); // Don't forget to flush!
}

pub const BinaryFileKind = enum {
    unknown,
    elf,
    macho,
    pe,
};
pub const Endianess = enum {
    little,
    big,
};

const ElfHint = struct {
    bitness: u8,
    endianess: Endianess,
};

const Stage0ParseResult = union(BinaryFileKind) {
    unknown,
    elf: ElfHint,
    macho: u8, // TBD MachoHint
    pe: u8, // TBD PeHint
};

pub fn bufferedRead(path: []const u8, buffer: []u8, max_length: usize) !void {
    var file = try fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();
    const file_size = (try file.stat()).size;
    var file_reader: fs.File.Reader = file.reader(buffer[0..]);
    const length = @min(max_length, file_size);
    try file_reader.interface.fill(length);
}

test "sanity checks: what's CWD?" {
    var buf: [1024]u8 = @splat(0);
    const p = try fs.cwd().realpath(".", buf[0..]);
    std.debug.print("CWD: {s}\n", .{p});
}

test "bufferedRead: base case 1 - read ascii text file, which is shorter than default read length" {
    var buf: [prefix_length]u8 = @splat(0);
    try bufferedRead("testing/assets/ascii.txt", buf[0..], prefix_length);
    try expect(mem.eql(u8, "one", buf[0..3]));
}

test "bufferedRead: base case 2 - read ELF file" {
    var buf: [prefix_length]u8 = @splat(0);
    try bufferedRead("testing/assets/bian", buf[0..], prefix_length);
    try expect(0x7F == buf[0]);
    try expect(mem.eql(u8, "ELF", buf[1..4]));
}
