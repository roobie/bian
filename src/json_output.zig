const std = @import("std");
const common = @import("common.zig");

pub const JsonOptions = struct {
    pretty: bool,
    include_symbols: bool,
};

fn writeEscapedString(w: *std.io.Writer, s: []const u8) !void {
    // Minimal JSON string escaper: escape backslash, double-quote, and control chars
    try w.print("\"");
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '"') {
            try w.print("\\\"");
        } else if (c == '\\') {
            try w.print("\\\\");
        } else if (c < 0x20) {
            // control char -> \u00XX
            try w.print("\\u00{02x}", .{c});
        } else {
            try w.writeAll(s[i .. i + 1]);
        }
    }
    try w.print("\"");
}

fn perm_str_map(p: common.Permission) []const u8 {
    if (p == common.Permission.read) return "r";
    if (p == common.Permission.write) return "w";
    if (p == common.Permission.execute) return "x";
    return "-";
}

pub fn writeBinaryDescriptionJson(w: *std.io.Writer, bd: *const common.BinaryDescription, opts: JsonOptions) !void {
    // If caller requests symbols, use std.json which will call
    // bd.jsonStringify (implemented in src/common.zig) for full control.
    if (opts.include_symbols) {
        const js_opts = std.json.Stringify.Options{ .whitespace = if (opts.pretty) .indent_2 else .minified };
        try std.json.Stringify.value(bd.*, js_opts, w);
        return;
    }

    // Use std.json.Stringify to produce compact or pretty output deterministically
    const js_opts = std.json.Stringify.Options{ .whitespace = if (opts.pretty) .indent_2 else .minified };
    var s: std.json.Stringify = .{ .writer = w, .options = js_opts };

    // Prepare some helper string mappings
    const fmt_str = switch (bd.format) {
        common.BinaryFileKind.elf => "elf",
        common.BinaryFileKind.macho => "macho",
        common.BinaryFileKind.pe => "pe",
        common.BinaryFileKind.ape => "ape",
        else => "unknown",
    };
    const os_str = switch (bd.os_abi) {
        common.OsAbi.linux => "linux",
        common.OsAbi.macos => "macos",
        common.OsAbi.windows => "windows",
        else => "unknown",
    };
    const arch_str = switch (bd.arch) {
        common.CpuArch.x86 => "x86",
        common.CpuArch.x86_64 => "x86_64",
        common.CpuArch.armv7 => "armv7",
        common.CpuArch.aarch64 => "aarch64",
        else => "unknown",
    };
    const endian_str = switch (bd.endianess) {
        std.builtin.Endian.little => "little",
        else => "big",
    };
    const fk = switch (bd.file_kind) {
        common.FileKind.executable => "executable",
        common.FileKind.shared_library => "shared_library",
        common.FileKind.object => "object",
        else => "unknown",
    };
    const relro_str = switch (bd.relro) {
        common.RelroConfig.unknown => "unknown",
        common.RelroConfig.none => "none",
        common.RelroConfig.partial => "partial",
        common.RelroConfig.full => "full",
        common.RelroConfig.not_applicable => "n/a",
    };

    try s.beginObject();

    try s.objectField("schema_version");
    try s.write(2);

    try s.objectField("file");
    if (bd.path.len == 0) try s.write(null) else try s.write(bd.path);

    try s.objectField("format");
    try s.write(fmt_str);

    try s.objectField("os_abi");
    try s.write(os_str);

    try s.objectField("arch");
    try s.beginObject();
    try s.objectField("isa");
    try s.write(arch_str);
    try s.objectField("bits");
    const bits32: u32 = @intCast(bd.bitness);
    try s.write(bits32);
    try s.objectField("endianness");
    try s.write(endian_str);
    try s.endObject();

    try s.objectField("file_kind");
    try s.write(fk);

    try s.objectField("entrypoint");
    if (bd.entrypoint_virtual_address == 0) {
        try s.write(null);
    } else {
        // emit hex string
        try s.beginWriteRaw();
        try s.writer.print("\"0x{x}\"", .{bd.entrypoint_virtual_address});
        s.endWriteRaw();
    }

    try s.objectField("security");
    try s.beginObject();
    try s.objectField("pie");
    switch (bd.pie) {
        common.Perhaps.yes => try s.write(true),
        common.Perhaps.no => try s.write(false),
        else => try s.write(null),
    }
    try s.objectField("nx");
    switch (bd.nx) {
        common.Perhaps.yes => try s.write(true),
        common.Perhaps.no => try s.write(false),
        else => try s.write(null),
    }
    try s.objectField("relro");
    try s.write(relro_str);
    try s.endObject();

    // sections
    try s.objectField("sections");
    try s.beginArray();
    var i: usize = 0;
    while (i < bd.sections.len) : (i += 1) {
        const sec = bd.sections[i];
        try s.beginObject();
        try s.objectField("idx");
        const idx32: u32 = @intCast(i);
        try s.write(idx32);
        try s.objectField("name");
        if (sec.name.len == 0) try s.write("(unnamed)") else try s.write(sec.name);
        try s.objectField("size");
        try s.write(sec.size);
        try s.objectField("offset");
        try s.write(sec.file_offset);
        try s.objectField("perm");
        try s.write(perm_str_map(sec.permission));
        try s.endObject();
    }
    try s.endArray();

    // segments
    try s.objectField("segments");
    try s.beginArray();
    i = 0;
    while (i < bd.segments.len) : (i += 1) {
        const seg = bd.segments[i];
        try s.beginObject();
        try s.objectField("idx");
        const idx32: u32 = @intCast(i);
        try s.write(idx32);
        try s.objectField("offset");
        try s.write(seg.file_offset);
        try s.objectField("size");
        try s.write(seg.size);
        try s.objectField("perm");
        try s.write(perm_str_map(seg.permission));
        try s.endObject();
    }
    try s.endArray();

    // imports
    try s.objectField("imports");
    try s.beginObject();
    try s.objectField("count");
    const ic: u32 = @intCast(bd.imports.len);
    try s.write(ic);
    try s.endObject();

    // exports
    try s.objectField("exports");
    try s.beginObject();
    try s.objectField("count");
    const ec: u32 = @intCast(bd.exports.len);
    try s.write(ec);
    try s.endObject();

    // messages
    try s.objectField("messages");
    try s.beginArray();
    i = 0;
    while (i < bd.messages.len) : (i += 1) {
        try s.write(bd.messages[i].body);
    }
    try s.endArray();

    try s.objectField("debug_info_present");
    try s.write(bd.debug_info_present);

    try s.objectField("metadata");
    try s.beginObject();
    try s.objectField("duration_ms");
    try s.write(0);
    try s.endObject();

    try s.endObject();
}
