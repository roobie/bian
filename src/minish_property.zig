const std = @import("std");
const minish = @import("minish");
const gen = minish.gen;

// A minimal property-based test demonstrating Minish integration.
// Property: reversing a string twice yields the original string.

fn reverse(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, s.len);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        result[s.len - 1 - i] = s[i];
    }
    return result;
}

fn reverse_twice_is_identity(allocator: std.mem.Allocator, s: []const u8) !void {
    const once = try reverse(allocator, s);
    defer allocator.free(once);
    const twice = try reverse(allocator, once);
    defer allocator.free(twice);
    try std.testing.expectEqualStrings(s, twice);
}

test "minish: reverse twice identity property" {
    const string_gen = gen.string(.{
        .min_len = 0,
        .max_len = 256,
        .charset = .alphanumeric,
    });

    // Run property checks using minish; if failures occur Minish will attempt
    // to shrink inputs and will print a minimal counterexample.
    try minish.check(std.testing.allocator, string_gen, prop_fn, .{ .num_runs = 200 });
}

fn prop_fn(s: []const u8) !void {
    return reverse_twice_is_identity(std.testing.allocator, s);
}
