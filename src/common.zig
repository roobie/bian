const std = @import("std");
const Endian = std.builtin.Endian;

// Minimal common helpers moved out of root to avoid circular imports during
// incremental refactor. Keep this small: prefix_length and endian-aware
// integer readers which are widely useful.

pub const prefix_length: usize = 512;

pub fn readU32At(buf: []const u8, off: usize, endian: Endian) u32 {
    const b0 = @as(u32, buf[off]);
    const b1 = @as(u32, buf[off + 1]);
    const b2 = @as(u32, buf[off + 2]);
    const b3 = @as(u32, buf[off + 3]);
    return if (endian == .big) (b0 << 24) | (b1 << 16) | (b2 << 8) | b3 else (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

pub fn readU64At(buf: []const u8, off: usize, endian: Endian) u64 {
    const b0 = @as(u64, buf[off]);
    const b1 = @as(u64, buf[off + 1]);
    const b2 = @as(u64, buf[off + 2]);
    const b3 = @as(u64, buf[off + 3]);
    const b4 = @as(u64, buf[off + 4]);
    const b5 = @as(u64, buf[off + 5]);
    const b6 = @as(u64, buf[off + 6]);
    const b7 = @as(u64, buf[off + 7]);
    return if (endian == .big)
        (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) | (b4 << 24) | (b5 << 16) | (b6 << 8) | b7
    else
        (b7 << 56) | (b6 << 48) | (b5 << 40) | (b4 << 32) | (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

pub fn readI32At(buf: []const u8, off: usize, endian: Endian) i32 {
    return @bitCast(readU32At(buf, off, endian));
}

pub const SegmentMap = struct { fileoff: u64, filesize: u64, vmaddr: u64 };

pub fn zslice(bytes: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    return bytes[0..end];
}

pub fn vaddrToFileOffset(file_len: usize, segmaps: []const SegmentMap, vaddr: u64) ?usize {
    var i: usize = 0;
    while (i < segmaps.len) : (i += 1) {
        const m = segmaps[i];
        if (vaddr >= m.vmaddr and vaddr < m.vmaddr + m.filesize) {
            const off64 = m.fileoff + (vaddr - m.vmaddr);
            if (off64 <= @as(u64, file_len)) return @as(usize, off64);
            return null;
        }
    }
    return null;
}

pub fn safeSlice(buf: []const u8, off64: u64, len64: u64) ?[]const u8 {
    if (off64 > @as(u64, buf.len)) return null;
    const off = @as(usize, off64);
    if (len64 > @as(u64, buf.len)) return null;
    const len = @as(usize, len64);
    if (len > buf.len - off) return null;
    return buf[off .. off + len];
}

pub const SectionKind = enum { unknown, code, data };
pub const Permission = enum { read, write, execute, none };

pub const Section = struct {
    name: []const u8,
    kind: SectionKind,
    size: u64,
    file_offset: u64,
    permission: Permission,
    // Mach-O specific metadata (0 for other formats)
    flags: u32,
    reserved1: u32,
    reserved2: u32,
};

pub fn freeImportEntries(allocator: std.mem.Allocator, imports: []ImportEntry) void {
    for (imports) |ie| {
        if (ie.symbols.len != 0) allocator.free(ie.symbols);
    }
    allocator.free(imports);
}

pub const ExportKind = enum { unknown, function, variable };

pub const Export = struct {
    name: []const u8,
    kind: ExportKind,
};

pub const Message = struct {
    body: []const u8,
};

pub const ImportSymbolKind = enum {
    by_name,
    by_ordinal,
    by_name_and_ordinal,
};

pub const ImportSymbol = struct {
    kind: ImportSymbolKind,
    name: []const u8,
    ordinal: u32,
};

pub const ImportEntry = struct {
    dll: []const u8,
    symbols: []ImportSymbol,
};

pub fn appendSegmentAndMap(allocator: std.mem.Allocator, segments_list: *std.ArrayList(Section), segmaps: *std.ArrayList(SegmentMap), fileoff: u64, filesize: u64, vmaddr: u64, perm: Permission) !void {
    try segments_list.append(allocator, Section{ .name = "", .kind = SectionKind.unknown, .size = filesize, .file_offset = fileoff, .permission = perm, .flags = 0, .reserved1 = 0, .reserved2 = 0 });
    try segmaps.append(allocator, SegmentMap{ .fileoff = fileoff, .filesize = filesize, .vmaddr = vmaddr });
}

pub fn appendSectionFromBlock(allocator: std.mem.Allocator, sections_list: *std.ArrayList(Section), block: []const u8, is64: bool, m_endian: Endian) !void {
    const name_bytes: []const u8 = block[0..16];
    const end = std.mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
    const name = name_bytes[0..end];

    if (m_endian == .little) {
        if (is64) {
            const sect_struct = @as(*align(1) const std.macho.section_64, @ptrCast(block.ptr)).*;
            const off = @as(u64, sect_struct.offset);
            const size = sect_struct.size;
            const flags = sect_struct.flags;
            const reserved1 = sect_struct.reserved1;
            const reserved2 = sect_struct.reserved2;
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = size, .file_offset = off, .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        } else {
            const sect_struct = @as(*align(1) const std.macho.section, @ptrCast(block.ptr)).*;
            const off = @as(u64, sect_struct.offset);
            const size = @as(u64, sect_struct.size);
            const flags = sect_struct.flags;
            const reserved1 = sect_struct.reserved1;
            const reserved2 = sect_struct.reserved2;
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = size, .file_offset = off, .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        }
    } else {
        if (is64) {
            const off32 = readU32At(block, 48, m_endian);
            const size = readU64At(block, 40, m_endian);
            const off64 = @as(u64, off32);
            const flags = readU32At(block, 64, m_endian);
            const reserved1 = readU32At(block, 68, m_endian);
            const reserved2 = readU32At(block, 72, m_endian);
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = size, .file_offset = off64, .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        } else {
            const off32 = readU32At(block, 40, m_endian);
            const size32 = readU32At(block, 36, m_endian);
            const flags = readU32At(block, 56, m_endian);
            const reserved1 = readU32At(block, 60, m_endian);
            const reserved2 = readU32At(block, 64, m_endian);
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = @as(u64, size32), .file_offset = @as(u64, off32), .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        }
    }
}

pub fn appendDylibNameFromLcData(allocator: std.mem.Allocator, imports_list: *std.ArrayList(ImportEntry), lc_data: []const u8, m_endian: Endian) !void {
    if (lc_data.len < 12) return;
    const name_off = @as(usize, readU32At(lc_data, 8, m_endian));
    if (name_off < lc_data.len) {
        const name = std.mem.sliceTo(lc_data[name_off..], 0);
        if (name.len != 0) try imports_list.append(allocator, ImportEntry{ .dll = name, .symbols = &[_]ImportSymbol{} });
    }
}

pub fn readU16LE(buf: []const u8, off: usize) u16 {
    return @as(u16, buf[off]) | (@as(u16, buf[off + 1]) << 8);
}

pub fn appendRpathMessageFromLcData(allocator: std.mem.Allocator, messages_list: *std.ArrayList(Message), lc_data: []const u8, m_endian: Endian) !void {
    if (lc_data.len < 12) return;
    const path_off = @as(usize, readU32At(lc_data, 8, m_endian));
    if (path_off < lc_data.len) {
        const rp = std.mem.sliceTo(lc_data[path_off..], 0);
        if (rp.len != 0) try messages_list.append(allocator, Message{ .body = rp });
    }
}

// --- New moves: macho helpers ---
pub fn machoLCFromU32(val: u32) ?std.macho.LC {
    if (val == 0x19) return std.macho.LC.SEGMENT_64; // SEGMENT_64
    if (val == 0x1) return std.macho.LC.SEGMENT; // SEGMENT
    if (val == 0x2) return std.macho.LC.SYMTAB; // SYMTAB
    if (val == (0x28 | std.macho.LC_REQ_DYLD)) return std.macho.LC.MAIN; // MAIN with REQ_DYLD
    if (val == 0x0c) return std.macho.LC.LOAD_DYLIB; // LOAD_DYLIB
    if (val == (0x18 | std.macho.LC_REQ_DYLD)) return std.macho.LC.LOAD_WEAK_DYLIB; // LOAD_WEAK_DYLIB
    if (val == (0x1f | std.macho.LC_REQ_DYLD)) return std.macho.LC.REEXPORT_DYLIB; // REEXPORT_DYLIB
    if (val == (0x23 | std.macho.LC_REQ_DYLD)) return std.macho.LC.LOAD_UPWARD_DYLIB; // LOAD_UPWARD_DYLIB
    if (val == (0x1c | std.macho.LC_REQ_DYLD)) return std.macho.LC.RPATH; // RPATH
    if (val == 0x1d) return std.macho.LC.CODE_SIGNATURE; // CODE_SIGNATURE
    if (val == (0x33 | std.macho.LC_REQ_DYLD)) return std.macho.LC.DYLD_EXPORTS_TRIE; // DYLD_EXPORTS_TRIE
    if (val == 0x22) return std.macho.LC.DYLD_INFO; // DYLD_INFO
    return null;
}

pub fn machoProtToPermission(p: std.macho.vm_prot_t) Permission {
    return if ((p & std.macho.PROT.EXEC) != 0) Permission.execute else if ((p & std.macho.PROT.WRITE) != 0) Permission.write else if ((p & std.macho.PROT.READ) != 0) Permission.read else Permission.none;
}

// --- New moves: ELF helpers ---
pub fn elfSectionFlagsToPermission(sh_flags: u64) Permission {
    return if ((sh_flags & std.elf.SHF_EXECINSTR) != 0) Permission.execute else if ((sh_flags & std.elf.SHF_WRITE) != 0) Permission.write else if ((sh_flags & std.elf.SHF_ALLOC) != 0) Permission.read else Permission.none;
}

pub fn elfProgFlagsToPermission(p_flags: u32) Permission {
    return if ((p_flags & std.elf.PF_X) != 0) Permission.execute else if ((p_flags & std.elf.PF_W) != 0) Permission.write else if ((p_flags & std.elf.PF_R) != 0) Permission.read else Permission.none;
}

// --- New moves: SymInfo and symbol helper ---
pub const SymInfo = struct {
    name: []const u8,
    n_type: u8,
};

pub fn symInfoByIndex(macho_buf: []const u8, symoff: usize, nsyms: usize, stroff: usize, strsize: usize, is64: bool, m_endian: Endian, idx: usize) ?SymInfo {
    if (idx >= nsyms) return null;
    if (m_endian == .little) {
        if (is64) {
            const syms = @as([*]align(1) const std.macho.nlist_64, @ptrCast(macho_buf[symoff..].ptr))[0..nsyms];
            const sym = syms[idx];
            const sidx = @as(usize, sym.n_strx);
            if (sidx >= strsize) return null;
            const name = std.mem.sliceTo(macho_buf[stroff + sidx ..], 0);
            return SymInfo{ .name = name, .n_type = sym.n_type };
        } else {
            const syms = @as([*]align(1) const std.macho.nlist, @ptrCast(macho_buf[symoff..].ptr))[0..nsyms];
            const sym = syms[idx];
            const sidx = @as(usize, sym.n_strx);
            if (sidx >= strsize) return null;
            const name = std.mem.sliceTo(macho_buf[stroff + sidx ..], 0);
            return SymInfo{ .name = name, .n_type = sym.n_type };
        }
    } else {
        const entry_size: usize = if (is64) 16 else 12;
        const entry_off = symoff + idx * entry_size;
        if (entry_off + entry_size > macho_buf.len) return null;
        const n_strx = readU32At(macho_buf, entry_off, m_endian);
        const n_type = macho_buf[entry_off + 4];
        const sidx = @as(usize, n_strx);
        if (sidx >= strsize) return null;
        const name = std.mem.sliceTo(macho_buf[stroff + sidx ..], 0);
        return SymInfo{ .name = name, .n_type = n_type };
    }
}

// === Canonical types (moved from root.zig) ===

pub const BinaryFileKind = enum {
    unknown,
    elf,
    macho,
    pe,
    ape,
};

pub const OsAbi = enum {
    unknown,
    linux,
    macos,
    windows,
};

pub const CpuArch = enum {
    unknown,
    x86,
    x86_64,
    armv7,
    aarch64,
};

pub const FileKind = enum {
    unknown,
    executable,
    shared_library,
    object,
};

pub const Perhaps = enum {
    unknown,
    yes,
    no,
};

pub const RelroConfig = enum {
    unknown,
    none,
    partial,
    full,
    not_applicable,
};

pub const StrippedState = enum {
    unknown,
    yes,
    no,
    partial,
};

pub const PrettyPrintOptions = struct {
    print_symbols: bool,
};

pub const PrettyPrintOptionsDefault = PrettyPrintOptions{ .print_symbols = false };

/// Unified description structure (canonical type used across the codebase)
pub const BinaryDescription = struct {
    // === BASICS ===
    format: BinaryFileKind,
    os_abi: OsAbi,
    arch: CpuArch,
    bitness: u8,
    endianess: Endian,
    file_kind: FileKind,
    entrypoint_virtual_address: u64,

    // === SECURITY FEATURES ===
    pie: Perhaps,
    aslr: Perhaps,
    nx: Perhaps,
    relro: RelroConfig,
    stripped: StrippedState,

    // === STRUCTURAL ===
    sections: []Section,
    segments: []Section,
    imports: []ImportEntry,
    exports: []Export,

    messages: []Message,

    // optional path provided by the caller to analyzeBinary (canonicalization
    // left to caller). If empty, path is unknown.
    path: []const u8,

    debug_info_present: bool,

    pub fn writePretty(self: *const BinaryDescription, w: *std.io.Writer, opts: PrettyPrintOptions) !void {
        // If path supplied, print it first
        if (self.path.len != 0) {
            try w.print("file: {s}\n", .{self.path});
        }

        // Short helpers and mappings
        const fmt_str = switch (self.format) {
            BinaryFileKind.elf => "elf",
            BinaryFileKind.macho => "macho",
            BinaryFileKind.pe => "pe",
            BinaryFileKind.ape => "ape",
            else => "unknown",
        };
        try w.print("format: {s}\n", .{fmt_str});

        const os_str = switch (self.os_abi) {
            OsAbi.linux => "linux",
            OsAbi.macos => "macos",
            OsAbi.windows => "windows",
            else => "unknown",
        };
        try w.print("os_abi: {s}\n", .{os_str});

        const arch_str = switch (self.arch) {
            CpuArch.x86 => "x86",
            CpuArch.x86_64 => "x86_64",
            CpuArch.armv7 => "armv7",
            CpuArch.aarch64 => "aarch64",
            else => "unknown",
        };
        const endian_str = switch (self.endianess) {
            Endian.little => "little",
            Endian.big => "big",
        };
        try w.print("arch: {s} / {d}-bit / {s}\n", .{ arch_str, self.bitness, endian_str });

        const file_kind_str = switch (self.file_kind) {
            FileKind.executable => "executable",
            FileKind.shared_library => "shared_library",
            FileKind.object => "object",
            else => "unknown",
        };
        try w.print("file_kind: {s}\n", .{file_kind_str});
        try w.print("entrypoint: 0x{x}\n", .{self.entrypoint_virtual_address});

        const pie_str = switch (self.pie) {
            Perhaps.yes => "yes",
            Perhaps.no => "no",
            else => "unknown",
        };
        const aslr_str = switch (self.aslr) {
            Perhaps.yes => "yes",
            Perhaps.no => "no",
            else => "unknown",
        };
        const nx_str = switch (self.nx) {
            Perhaps.yes => "yes",
            Perhaps.no => "no",
            else => "unknown",
        };
        const relro_str = switch (self.relro) {
            RelroConfig.unknown => "unknown",
            RelroConfig.none => "none",
            RelroConfig.partial => "partial",
            RelroConfig.full => "full",
            RelroConfig.not_applicable => "n/a",
        };
        const stripped_str = switch (self.stripped) {
            StrippedState.unknown => "unknown",
            StrippedState.yes => "yes",
            StrippedState.no => "no",
            StrippedState.partial => "partial",
        };
        try w.print("security: PIE={s}, ASLR={s}, NX={s}, RELRO={s}, stripped={s}\n", .{ pie_str, aslr_str, nx_str, relro_str, stripped_str });

        try w.print("sections: {d}\n", .{self.sections.len});
        var i: usize = 0;
        for (self.sections) |sec| {
            const name = if (sec.name.len != 0) sec.name else "(unnamed)";
            const perm_str = switch (sec.permission) {
                Permission.read => "r",
                Permission.write => "w",
                Permission.execute => "x",
                else => "-",
            };
            try w.print("  [{d}] {s} size={d} offset=0x{x} perm={s}\n", .{ i, name, sec.size, sec.file_offset, perm_str });
            i += 1;
        }

        try w.print("segments: {d}\n", .{self.segments.len});
        i = 0;
        for (self.segments) |seg| {
            const perm_str = switch (seg.permission) {
                Permission.read => "r",
                Permission.write => "w",
                Permission.execute => "x",
                else => "-",
            };
            try w.print("  [{d}] offset=0x{x} size={d} perm={s}\n", .{ i, seg.file_offset, seg.size, perm_str });
            i += 1;
        }

        try w.print("imports: {d}\n", .{self.imports.len});
        if (opts.print_symbols) {
            for (self.imports) |imp| {
                if (imp.dll.len != 0) try w.print("  - DLL: {s}\n", .{imp.dll});
                for (imp.symbols) |sym| {
                    switch (sym.kind) {
                        .by_name => try w.print("    - {s}\n", .{sym.name}),
                        .by_ordinal => try w.print("    - ordinal:{d}\n", .{sym.ordinal}),
                        .by_name_and_ordinal => try w.print("    - {s} (ordinal:{d})\n", .{ sym.name, sym.ordinal }),
                    }
                }
            }
        }

        try w.print("exports: {d}\n", .{self.exports.len});
        if (opts.print_symbols) {
            for (self.exports) |ex| {
                const kind_str = switch (ex.kind) {
                    ExportKind.function => "function",
                    ExportKind.variable => "variable",
                    else => "unknown",
                };
                try w.print("  - {s} ({s})\n", .{ ex.name, kind_str });
            }
        }

        try w.print("messages: {d}\n", .{self.messages.len});
        for (self.messages) |m| {
            try w.print("  - {s}\n", .{m.body});
        }

        try w.print("debug_info_present: {s}\n", .{if (self.debug_info_present) "yes" else "no"});
    }
};

// JSON stringifier hook used by std.json.Stringify when serializing the
// BinaryDescription. This gives us complete control over the emitted JSON
// structure (field names, ordering, hex formatting, which fields to include
// and how). Consumers that need to include or omit large symbol lists can
// either call std.json.value on the BinaryDescription (this will invoke this
// method and include symbols) or implement their own writer that omits the
// symbols.
pub fn jsonStringify(self: *@This(), jw: anytype) !void {
    // Note: `jw` is expected to be a std.json.Stringify instance. We use the
    // Stringify API (objectField, write, beginArray, beginObject, beginWriteRaw)
    // which allows streaming and correct escaping without allocating.
    try jw.beginObject();

    try jw.objectField("schema_version");
    try jw.write(2);

    try jw.objectField("file");
    if (self.path.len == 0) {
        try jw.write(null);
    } else {
        try jw.write(self.path);
    }

    try jw.objectField("format");
    const fmt_str = switch (self.format) {
        BinaryFileKind.elf => "elf",
        BinaryFileKind.macho => "macho",
        BinaryFileKind.pe => "pe",
        BinaryFileKind.ape => "ape",
        else => "unknown",
    };
    try jw.write(fmt_str);

    try jw.objectField("os_abi");
    const os_str = switch (self.os_abi) {
        OsAbi.linux => "linux",
        OsAbi.macos => "macos",
        OsAbi.windows => "windows",
        else => "unknown",
    };
    try jw.write(os_str);

    // arch
    try jw.objectField("arch");
    try jw.beginObject();
    const arch_str = switch (self.arch) {
        CpuArch.x86 => "x86",
        CpuArch.x86_64 => "x86_64",
        CpuArch.armv7 => "armv7",
        CpuArch.aarch64 => "aarch64",
        else => "unknown",
    };
    try jw.objectField("isa");
    try jw.write(arch_str);
    try jw.objectField("bits");
    try jw.write(@as(u32, self.bitness));
    const endian_str = switch (self.endianess) {
        Endian.little => "little",
        else => "big",
    };
    try jw.objectField("endianness");
    try jw.write(endian_str);
    try jw.endObject();

    try jw.objectField("file_kind");
    const fk_str = switch (self.file_kind) {
        FileKind.executable => "executable",
        FileKind.shared_library => "shared_library",
        FileKind.object => "object",
        else => "unknown",
    };
    try jw.write(fk_str);

    // entrypoint as hex string or null
    try jw.objectField("entrypoint");
    if (self.entrypoint_virtual_address == 0) {
        try jw.write(null);
    } else {
        // Emit as hex string without allocating by writing raw content to the
        // underlying writer. We must include the surrounding quotes.
        try jw.beginWriteRaw();
        try jw.writer.print("\"0x{x}\"", .{self.entrypoint_virtual_address});
        jw.endWriteRaw();
    }

    // security object
    try jw.objectField("security");
    try jw.beginObject();
    try jw.objectField("pie");
    switch (self.pie) {
        Perhaps.yes => try jw.write(true),
        Perhaps.no => try jw.write(false),
        else => try jw.write(null),
    }
    try jw.objectField("nx");
    switch (self.nx) {
        Perhaps.yes => try jw.write(true),
        Perhaps.no => try jw.write(false),
        else => try jw.write(null),
    }
    try jw.objectField("relro");
    const relro_str = switch (self.relro) {
        RelroConfig.unknown => "unknown",
        RelroConfig.none => "none",
        RelroConfig.partial => "partial",
        RelroConfig.full => "full",
        RelroConfig.not_applicable => "n/a",
    };
    try jw.write(relro_str);
    try jw.endObject();

    // sections
    try jw.objectField("sections");
    try jw.beginArray();
    var idx: usize = 0;
    while (idx < self.sections.len) : (idx += 1) {
        const s = self.sections[idx];
        try jw.beginObject();
        try jw.objectField("idx");
        try jw.write(@as(u32, idx));
        try jw.objectField("name");
        if (s.name.len == 0) try jw.write("(unnamed)") else try jw.write(s.name);
        try jw.objectField("size");
        try jw.write(s.size);
        try jw.objectField("offset");
        try jw.write(s.file_offset);
        try jw.objectField("perm");
        const perm_str = switch (s.permission) {
            Permission.read => "r",
            Permission.write => "w",
            Permission.execute => "x",
            else => "-",
        };
        try jw.write(perm_str);
        try jw.endObject();
    }
    try jw.endArray();

    // segments
    try jw.objectField("segments");
    try jw.beginArray();
    idx = 0;
    while (idx < self.segments.len) : (idx += 1) {
        const seg = self.segments[idx];
        try jw.beginObject();
        try jw.objectField("idx");
        try jw.write(@as(u32, idx));
        try jw.objectField("offset");
        try jw.write(seg.file_offset);
        try jw.objectField("size");
        try jw.write(seg.size);
        try jw.objectField("perm");
        const perm_s = switch (seg.permission) {
            Permission.read => "r",
            Permission.write => "w",
            Permission.execute => "x",
            else => "-",
        };
        try jw.write(perm_s);
        try jw.endObject();
    }
    try jw.endArray();

    // imports (structured: per-dll entries)
    try jw.objectField("imports");
    try jw.beginObject();
    try jw.objectField("count");
    try jw.write(@as(u32, self.imports.len));
    try jw.objectField("entries");
    try jw.beginArray();
    idx = 0;
    while (idx < self.imports.len) : (idx += 1) {
        const ie = self.imports[idx];
        try jw.beginObject();
        try jw.objectField("dll");
        if (ie.dll.len == 0) try jw.write(null) else try jw.write(ie.dll);
        try jw.objectField("count");
        try jw.write(@as(u32, ie.symbols.len));
        try jw.objectField("symbols");
        try jw.beginArray();
        var sidx: usize = 0;
        while (sidx < ie.symbols.len) : (sidx += 1) {
            const sym = ie.symbols[sidx];
            try jw.beginObject();
            try jw.objectField("name");
            if (sym.kind == ImportSymbolKind.by_name or sym.kind == ImportSymbolKind.by_name_and_ordinal) {
                if (sym.name.len == 0) try jw.write(null) else try jw.write(sym.name);
            } else {
                try jw.write(null);
            }
            try jw.objectField("ordinal");
            if (sym.kind == ImportSymbolKind.by_ordinal or sym.kind == ImportSymbolKind.by_name_and_ordinal) {
                try jw.write(sym.ordinal);
            } else {
                try jw.write(null);
            }
            try jw.endObject();
        }
        try jw.endArray();
        try jw.endObject();
    }
    try jw.endArray();
    try jw.endObject();

    // exports
    try jw.objectField("exports");
    try jw.beginObject();
    try jw.objectField("count");
    try jw.write(@as(u32, self.exports.len));
    try jw.objectField("symbols");
    try jw.beginArray();
    idx = 0;
    while (idx < self.exports.len) : (idx += 1) {
        try jw.write(self.exports[idx].name);
    }
    try jw.endArray();
    try jw.endObject();

    // messages
    try jw.objectField("messages");
    try jw.beginArray();
    idx = 0;
    while (idx < self.messages.len) : (idx += 1) {
        try jw.write(self.messages[idx].body);
    }
    try jw.endArray();

    try jw.objectField("debug_info_present");
    try jw.write(self.debug_info_present);

    try jw.objectField("metadata");
    try jw.beginObject();
    try jw.objectField("duration_ms");
    try jw.write(0);
    try jw.endObject();

    try jw.endObject();
}

/// An owning container for one-or-more BinaryDescription items and the
/// backing file buffer that all item slices point into (zero-copy).
pub const BinaryBundle = struct {
    items: []BinaryDescription,
    backing_file: []u8,

    pub fn free(allocator: std.mem.Allocator, self: BinaryBundle) void {
        // Free per-description owned slices
        for (self.items) |d| {
            // Free top-level slices allocated with toOwnedSlice()
            if (d.sections.len != 0) allocator.free(d.sections);
            if (d.segments.len != 0) allocator.free(d.segments);
            if (d.imports.len != 0) {
                // Free nested symbol arrays inside each ImportEntry
                for (d.imports) |ie| {
                    if (ie.symbols.len != 0) allocator.free(ie.symbols);
                }
                allocator.free(d.imports);
            }
            if (d.exports.len != 0) allocator.free(d.exports);
            if (d.messages.len != 0) allocator.free(d.messages);
            // Free per-description path if present
            if (d.path.len != 0) allocator.free(d.path);
        }
        // Free the items slice itself
        if (self.items.len != 0) allocator.free(self.items);
        // Finally free the backing file buffer
        if (self.backing_file.len != 0) allocator.free(self.backing_file);
    }
};
