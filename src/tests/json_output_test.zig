const std = @import("std");
const root = @import("root.zig");
const json_out = @import("json_output.zig");

test "json_output: ELF asset produces compact JSON with expected keys" {
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try root.analyzeBinary(allocator, file, "testing/assets/elf-Linux-x64-bash");
    defer root.BinaryBundle.free(allocator, bundle);
    try expect(bundle.items.len >= 1);
    const desc = bundle.items[0];

    var alloc_w = std.io.Writer.Allocating.init(allocator);
    defer alloc_w.deinit();
    try json_out.writeBinaryDescriptionJson(&alloc_w.writer, &desc, json_out.JsonOptions{ .pretty = false, .include_symbols = false });
    const out = alloc_w.written();
    // Basic sanity checks: must start with '{' and contain schema_version and format
    try expect(out.len > 0);
    try expect(out[0] == '{');
    const out_str = std.mem.trimRight(u8, out, &[_]u8{ '\n', ' ', '\r', '\t' });
    const got = std.mem.indexOfSlice(u8, out_str, "\"schema_version\":1") orelse unreachable;
    _ = got;
    const got2 = std.mem.indexOfSlice(u8, out_str, "\"format\":\"elf\"") orelse unreachable;
    _ = got2;

    // Also ensure we wrote sections array
    const got3 = std.mem.indexOfSlice(u8, out_str, "\"sections\":[") orelse unreachable;
    _ = got3;

    // Also exercise include_symbols = true which should include a symbols array
    alloc_w = std.io.Writer.Allocating.init(allocator);
    defer alloc_w.deinit();
    try json_out.writeBinaryDescriptionJson(&alloc_w.writer, &desc, json_out.JsonOptions{ .pretty = false, .include_symbols = true });
    const out2 = alloc_w.written();
    try expect(out2.len > 0);
    const out2_str = std.mem.trimRight(u8, out2, &[_]u8{ '\n', ' ', '\r', '\t' });
    // When symbols are included, the JSON should contain an imports.symbols array
    const got4 = std.mem.indexOfSlice(u8, out2_str, "\"imports\":") orelse unreachable;
    _ = got4;
    const got5 = std.mem.indexOfSlice(u8, out2_str, "\"symbols\"") orelse unreachable;
    _ = got5;

    // cleanup: free per-description owned slices
    root.freeBinaryDescription(allocator, desc);
}
