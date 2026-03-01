const std = @import("std");
const bian = @import("bian");
const argsParser = @import("args");

pub fn main() !u8 {
    // CLI startup: no noisy banner; keep output focused on requested work.

    var buf: [2048]u8 = @splat(0);
    var fb = std.heap.FixedBufferAllocator{
        .buffer = buf[0..],
        .end_index = 0,
    };
    const argsAllocator = fb.allocator();

    const options = argsParser.parseForCurrentProcess(struct {
        // Existing options (unused for now in CLI)
        output: ?[]const u8 = null,
        @"with-offset": bool = false,
        @"with-hexdump": bool = false,
        @"intermix-source": bool = false,
        numberOfBytes: ?i32 = null,
        signed_number: ?i64 = null,
        unsigned_number: ?u64 = null,
        mode: enum { default, special, slow, fast } = .default,

        // JSON/output flags
        json: bool = false,
        @"json-pretty": bool = false,
        @"include-symbols": bool = false,

        // Shorthands
        pub const shorthands = .{
            .S = "intermix-source",
            .b = "with-hexdump",
            .O = "with-offset",
            .o = "output",
            .j = "json",
        };
    }, argsAllocator, .print) catch return 1;
    defer options.deinit();

    // Collect positionals as file paths to analyze
    if (options.positionals.len == 0) {
        std.debug.print("Usage: bian [--json] [--json-pretty] [--include-symbols] <file>...\n", .{});
        return 0;
    }

    const allocator = std.heap.page_allocator;

    // Prepare stdout writer
    var out_buf: [8192]u8 = undefined;
    var out_file_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_file_writer.interface;

    // JSON writer options
    const json_opts = bian.json_output.JsonOptions{ .pretty = options.options.@"json-pretty", .include_symbols = options.options.@"include-symbols" };

    // Iterate input files
    for (options.positionals) |path| {
        var file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
        defer file.close();

        const bundle = try bian.analyzeBinary(allocator, file, path);
        defer bian.BinaryBundle.free(allocator, bundle);

        // For each description in bundle, emit either pretty text or JSON
        var i: usize = 0;
        while (i < bundle.items.len) : (i += 1) {
            const desc = bundle.items[i];
            const want_json = options.options.json or options.options.@"json-pretty";
            if (want_json) {
                try bian.json_output.writeBinaryDescriptionJson(out, &desc, json_opts);
                try out.flush();
            } else {
                try desc.writePretty(out, bian.PrettyPrintOptionsDefault);
                try out.flush();
            }
        }
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
