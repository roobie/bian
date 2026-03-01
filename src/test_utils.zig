const std = @import("std");

pub fn dumpAllocatingToStderr(alloc_w: *std.io.Writer.Allocating) !void {
    // Use a small stack buffer for the stderr writer. This is only used when
    // emitting captured diagnostics during test failure, so stack allocation
    // is acceptable.
    var buf: [4096]u8 = undefined;
    var sw = std.fs.File.stderr().writer(&buf);
    // Write the captured bytes to stderr and flush.
    try sw.interface.writeAll(alloc_w.written());
    try sw.interface.flush();
}
