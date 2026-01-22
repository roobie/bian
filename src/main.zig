const std = @import("std");
const bian = @import("bian");
const argsParser = @import("args");

pub fn main() !u8 {
    // Prints to stderr, ignoring potential errors.
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
    try bian.bufferedPrint();

    // var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // defer arena.deinit();

    // const allocator = &arena.allocator;

    var buf: [1024]u8 = @splat(0);
    var fb = std.heap.FixedBufferAllocator{
        .buffer = buf[0..],
        .end_index = 0,
    };
    const argsAllocator = fb.allocator();

    const options = argsParser.parseForCurrentProcess(struct {
        // This declares long options for double hyphen
        output: ?[]const u8 = null,
        @"with-offset": bool = false,
        @"with-hexdump": bool = false,
        @"intermix-source": bool = false,
        numberOfBytes: ?i32 = null,
        signed_number: ?i64 = null,
        unsigned_number: ?u64 = null,
        mode: enum { default, special, slow, fast } = .default,

        // This declares short-hand options for single hyphen
        pub const shorthands = .{
            .S = "intermix-source",
            .b = "with-hexdump",
            .O = "with-offset",
            .o = "output",
        };
    }, argsAllocator, .print) catch return 1;
    defer options.deinit();

    std.debug.print("executable name: {?s}\n", .{options.executable_name});

    std.debug.print("parsed options:\n", .{});
    inline for (std.meta.fields(@TypeOf(options.options))) |fld| {
        std.debug.print("\t{s} = {any}\n", .{
            fld.name,
            @field(options.options, fld.name),
        });
    }

    std.debug.print("parsed positionals:\n", .{});
    for (options.positionals) |arg| {
        std.debug.print("\t'{s}'\n", .{arg});
    }

    return 0;
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
