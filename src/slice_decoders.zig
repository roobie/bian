const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const macho = std.macho;
const Endian = std.builtin.Endian;

// Minimal, compile-friendly placeholders for slice decoders.
// These are intentionally small in the base commit; later refactors will
// replace return types with the project's BinaryDescription and move helpers
// into src/common.zig.

pub const ParseError = error{ TooSmall, InvalidHeader, Malformed };

const root = @import("root.zig");
const expect = std.testing.expect;

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

pub fn decodePESlice(allocator: std.mem.Allocator, buf: []const u8, path: ?[]const u8) !root.BinaryDescription {
    if (buf.len < 64) return ParseError.TooSmall;
    if (buf[0] != 'M' or buf[1] != 'Z') return ParseError.InvalidHeader;
    const e_lfanew = @as(usize, buf[0x3c]) | (@as(usize, buf[0x3d]) << 8) | (@as(usize, buf[0x3e]) << 16) | (@as(usize, buf[0x3f]) << 24);
    if (e_lfanew + 4 > buf.len) return ParseError.Malformed;
    if (e_lfanew + 4 > buf.len) return ParseError.Malformed;
    if (buf[e_lfanew] != 'P' or buf[e_lfanew + 1] != 'E' or buf[e_lfanew + 2] != 0 or buf[e_lfanew + 3] != 0) return ParseError.InvalidHeader;

    const coff_off = e_lfanew + 4;
    if (coff_off + 20 > buf.len) return ParseError.Malformed;
    const machine = root.readU16LE(buf, coff_off + 0);
    const characteristics = root.readU16LE(buf, coff_off + 18);

    const arch = switch (machine) {
        0x8664 => root.CpuArch.x86_64,
        0x014c => root.CpuArch.x86,
        else => root.CpuArch.unknown,
    };
    const bitness: u8 = if (arch == root.CpuArch.x86_64) 64 else if (arch == root.CpuArch.x86) 32 else 0;

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

    var file_kind = root.FileKind.unknown;
    const IMAGE_FILE_DLL: u16 = 0x2000;
    const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    if ((characteristics & IMAGE_FILE_DLL) != 0) {
        file_kind = root.FileKind.shared_library;
    } else if ((characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0) {
        file_kind = root.FileKind.executable;
    }

    const desc = root.BinaryDescription{
        .format = root.BinaryFileKind.pe,
        .os_abi = root.OsAbi.windows,
        .arch = arch,
        .bitness = bitness,
        .endianess = Endian.little,
        .file_kind = file_kind,
        .entrypoint_virtual_address = 0,
        .pie = root.Perhaps.unknown,
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
    _ = decodePESlice(allocator, buf, null) catch |err| {
        try expect(err == ParseError.InvalidHeader);
        return;
    };
    // If we get here, decodePESlice didn't error as expected
    try expect(false);
}

test "slice_decoders: decodeMachoSlice parses Mach-O header from fixture" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-x64-ls", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 4096);
    defer allocator.free(buf);

    const desc = try decodeMachoSlice(allocator, buf, null);
    try expect(desc.format == root.BinaryFileKind.macho);
    try expect(desc.arch == root.CpuArch.x86_64);
    try expect(desc.bitness == 64);
}

test "slice_decoders.invariants: Mach-O decode populates sections, segments, imports, and exports" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-x64-ls", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 65536);
    defer allocator.free(buf);

    const desc = try decodeMachoSlice(allocator, buf, null);
    try expect(desc.format == root.BinaryFileKind.macho);
    try expect(desc.sections.len > 0);
    try expect(desc.segments.len > 0);
    try expect(desc.imports.len > 0);
    try expect(desc.exports.len >= 0); // exports may be 0 or more depending on asset

    // Ensure imports contain non-empty names
    var found_printf_or_malloc: bool = false;
    var found_dyld_stub: bool = false;
    for (desc.imports) |imp| {
        try expect(imp.len > 0);
        if (std.mem.indexOf(u8, imp, "printf")) |*| { found_printf_or_malloc = true; };
        if (std.mem.indexOf(u8, imp, "malloc")) |*| { found_printf_or_malloc = true; };
        if (std.mem.indexOf(u8, imp, "dyld_stub_binder")) |*| { found_dyld_stub = true; };
    }
    try expect(found_printf_or_malloc == true);
    try expect(found_dyld_stub == true);

    // If exports present, ensure export names are non-empty and contain known header symbol
    if (desc.exports.len > 0) {
        var found_mh_header: bool = false;
        for (desc.exports) |ex| {
            try expect(ex.name.len > 0);
            if (std.mem.indexOf(u8, ex.name, "__mh_execute_header")) |*| { found_mh_header = true; };
        }
        try expect(found_mh_header == true);
    }
}

pub fn decodeMachoSlice(allocator: std.mem.Allocator, buf: []const u8, path: ?[]const u8) !root.BinaryDescription {
    if (buf.len < 4) return ParseError.TooSmall;
    const mm = root.readU32At(buf, 0, .big);
    var is_64: bool = false;
    var m_endian: Endian = Endian.little;
    if (mm == macho.MH_MAGIC_64) {
        is_64 = true;
        m_endian = Endian.big;
    } else if (mm == macho.MH_CIGAM_64) {
        is_64 = true;
        m_endian = Endian.little;
    } else if (mm == macho.MH_MAGIC) {
        is_64 = false;
        m_endian = Endian.big;
    } else if (mm == macho.MH_CIGAM) {
        is_64 = false;
        m_endian = Endian.little;
    } else return ParseError.InvalidHeader;

    // Header parsing (handle both little and big endian)
    var hdr_size: usize = 0;
    var ncmds: usize = 0;
    var sizeofcmds: usize = 0;
    var hdr_cputype: macho.cpu_type_t = 0;
    var hdr_filetype: u32 = 0;
    var hdr_flags: u32 = 0;

    if (m_endian == .little) {
        if (is_64) {
            if (buf.len < @sizeOf(macho.mach_header_64)) return ParseError.TooSmall;
            const hdr_ptr = @as(*align(1) const macho.mach_header_64, @ptrCast(buf.ptr));
            const hdr = hdr_ptr.*;
            hdr_size = @sizeOf(macho.mach_header_64);
            ncmds = @as(usize, hdr.ncmds);
            sizeofcmds = @as(usize, hdr.sizeofcmds);
            hdr_cputype = hdr.cputype;
            hdr_filetype = hdr.filetype;
            hdr_flags = hdr.flags;
        } else {
            if (buf.len < @sizeOf(macho.mach_header)) return ParseError.TooSmall;
            const hdr_ptr = @as(*align(1) const macho.mach_header, @ptrCast(buf.ptr));
            const hdr = hdr_ptr.*;
            hdr_size = @sizeOf(macho.mach_header);
            ncmds = @as(usize, hdr.ncmds);
            sizeofcmds = @as(usize, hdr.sizeofcmds);
            hdr_cputype = hdr.cputype;
            hdr_filetype = hdr.filetype;
            hdr_flags = hdr.flags;
        }
    } else {
        // Big-endian parsing: read header fields explicitly with endian-aware readers
        if (is_64) {
            if (buf.len < @sizeOf(macho.mach_header_64)) return ParseError.TooSmall;
            hdr_size = @sizeOf(macho.mach_header_64);
            hdr_cputype = @as(macho.cpu_type_t, root.readI32At(buf, 4, m_endian));
            hdr_filetype = root.readU32At(buf, 12, m_endian);
            ncmds = @as(usize, root.readU32At(buf, 16, m_endian));
            sizeofcmds = @as(usize, root.readU32At(buf, 20, m_endian));
            hdr_flags = root.readU32At(buf, 24, m_endian);
        } else {
            if (buf.len < @sizeOf(macho.mach_header)) return ParseError.TooSmall;
            hdr_size = @sizeOf(macho.mach_header);
            hdr_cputype = @as(macho.cpu_type_t, root.readI32At(buf, 4, m_endian));
            hdr_filetype = root.readU32At(buf, 12, m_endian);
            ncmds = @as(usize, root.readU32At(buf, 16, m_endian));
            sizeofcmds = @as(usize, root.readU32At(buf, 20, m_endian));
            hdr_flags = root.readU32At(buf, 24, m_endian);
        }
    }

    if (hdr_size + sizeofcmds > buf.len) return ParseError.Malformed;
    const lc_buffer = buf[hdr_size .. hdr_size + sizeofcmds];

    var sections_list = try std.ArrayList(root.Section).initCapacity(allocator, 0);
    defer sections_list.deinit(allocator);
    var segments_list = try std.ArrayList(root.Section).initCapacity(allocator, 0);
    defer segments_list.deinit(allocator);
    var imports = try std.ArrayList([]const u8).initCapacity(allocator, 0);
    defer imports.deinit(allocator);
    var exports = try std.ArrayList(root.Export).initCapacity(allocator, 0);
    defer exports.deinit(allocator);
    var messages = try std.ArrayList(root.Message).initCapacity(allocator, 0);
    defer messages.deinit(allocator);

    var segmaps = try std.ArrayList(root.SegmentMap).initCapacity(allocator, 0);
    defer segmaps.deinit(allocator);

    var symoff: usize = 0;
    var nsyms: usize = 0;
    var stroff: usize = 0;
    var strsize: usize = 0;
    var entry_fileoff: u64 = 0;
    var have_entry: bool = false;

    // LC_DYSYMTAB fields (indirect symbol table, ranges)
    var indirectsymoff: usize = 0;
    var nindirectsyms: usize = 0;
    var ilocalsym: usize = 0;
    var nlocalsym: usize = 0;
    var iextdefsym: usize = 0;
    var nextdefsym: usize = 0;
    var iundefsym: usize = 0;
    var nundefsym: usize = 0;

    // Little-endian parsing using std.macho helpers where possible
    if (m_endian == .little) {
        var lc_it: macho.LoadCommandIterator = .{ .ncmds = ncmds, .buffer = lc_buffer, .index = 0 };
        while (true) {
            const lc = lc_it.next() orelse break;
            const cmd = lc.hdr.cmd;

            if (cmd == macho.LC.SEGMENT_64 and is_64) {
                const seg = lc.cast(macho.segment_command_64) orelse continue;
                const seg_fileoff = @as(u64, seg.fileoff);
                const seg_filesize = seg.filesize;
                const perm = root.machoProtToPermission(seg.initprot);
                try root.appendSegmentAndMap(allocator, &segments_list, &segmaps, seg_fileoff, seg_filesize, seg.vmaddr, perm);

                const section_size = @sizeOf(macho.section_64);
                const sections_data = lc.data[@sizeOf(macho.segment_command_64)..];
                var i: usize = 0;
                while (i < seg.nsects) : (i += 1) {
                    const start = i * section_size;
                    if (start + section_size > sections_data.len) break;
                    const block = sections_data[start .. start + section_size];
                    try root.appendSectionFromBlock(allocator, &sections_list, block, true, m_endian);
                }
            } else if (cmd == macho.LC.SEGMENT and !is_64) {
                const seg = lc.cast(macho.segment_command) orelse continue;
                const seg_fileoff = @as(u64, seg.fileoff);
                const seg_filesize = @as(u64, seg.filesize);
                const perm = root.machoProtToPermission(seg.initprot);
                try root.appendSegmentAndMap(allocator, &segments_list, &segmaps, seg_fileoff, seg_filesize, @as(u64, seg.vmaddr), perm);

                const section_size = @sizeOf(macho.section);
                const sections_data = lc.data[@sizeOf(macho.segment_command)..];
                var i: usize = 0;
                while (i < seg.nsects) : (i += 1) {
                    const start = i * section_size;
                    if (start + section_size > sections_data.len) break;
                    const block = sections_data[start .. start + section_size];
                    try root.appendSectionFromBlock(allocator, &sections_list, block, false, m_endian);
                }
            } else if (cmd == macho.LC.SYMTAB) {
                const st = lc.cast(macho.symtab_command) orelse continue;
                symoff = @as(usize, st.symoff);
                nsyms = @as(usize, st.nsyms);
                stroff = @as(usize, st.stroff);
                strsize = @as(usize, st.strsize);
            } else if (cmd == macho.LC.DYSYMTAB) {
                const dt = lc.cast(macho.dysymtab_command) orelse continue;
                ilocalsym = @as(usize, dt.ilocalsym);
                nlocalsym = @as(usize, dt.nlocalsym);
                iextdefsym = @as(usize, dt.iextdefsym);
                nextdefsym = @as(usize, dt.nextdefsym);
                iundefsym = @as(usize, dt.iundefsym);
                nundefsym = @as(usize, dt.nundefsym);
                indirectsymoff = @as(usize, dt.indirectsymoff);
                nindirectsyms = @as(usize, dt.nindirectsyms);
            } else if (cmd == macho.LC.MAIN) {
                const ep = lc.cast(macho.entry_point_command) orelse continue;
                entry_fileoff = ep.entryoff;
                have_entry = true;
            } else {
                if (cmd == macho.LC.LOAD_DYLIB or cmd == macho.LC.LOAD_WEAK_DYLIB or cmd == macho.LC.REEXPORT_DYLIB or cmd == macho.LC.LOAD_UPWARD_DYLIB) {
                    const name = lc.getDylibPathName();
                    if (name.len != 0) try imports.append(allocator, name);
                } else if (cmd == macho.LC.RPATH) {
                    const rp = lc.getRpathPathName();
                    if (rp.len != 0) try messages.append(allocator, root.Message{ .body = rp });
                } else if (cmd == macho.LC.CODE_SIGNATURE) {
                    try messages.append(allocator, root.Message{ .body = "code signature present" });
                } else if (cmd == macho.LC.DYLD_EXPORTS_TRIE or cmd == macho.LC.DYLD_INFO) {
                    try messages.append(allocator, root.Message{ .body = "dyld export/bind info present (not parsed)" });
                }
            }
        }
    } else {
        // Big-endian load command parsing (use readU32At/machoLCFromU32 helpers)
        var off: usize = hdr_size;
        var lc_index: usize = 0;
        while (lc_index < ncmds) : (lc_index += 1) {
            if (off + 8 > buf.len) return ParseError.Malformed;
            const cmd_val = root.readU32At(buf, off, m_endian);
            const opt_cmd = root.machoLCFromU32(cmd_val);
            const cmdsize = @as(usize, root.readU32At(buf, off + 4, m_endian));
            if (cmdsize < 8) return ParseError.Malformed;
            if (off + cmdsize > buf.len) return ParseError.Malformed;

            const lc_data = buf[off .. off + cmdsize];

            if (opt_cmd) |cmd| {
                if (cmd == macho.LC.SEGMENT_64 and is_64) {
                    const seg_fileoff = root.readU64At(lc_data, 40, m_endian);
                    const seg_filesize = root.readU64At(lc_data, 48, m_endian);
                    const vmaddr = root.readU64At(lc_data, 24, m_endian);
                    const initprot = @as(macho.vm_prot_t, root.readI32At(lc_data, 60, m_endian));
                    const perm = root.machoProtToPermission(initprot);
                    try root.appendSegmentAndMap(allocator, &segments_list, &segmaps, seg_fileoff, seg_filesize, vmaddr, perm);

                    const section_size = @sizeOf(macho.section_64);
                    const sections_data = lc_data[@sizeOf(macho.segment_command_64)..];
                    var i: usize = 0;
                    const nsects = @as(usize, root.readU32At(lc_data, 64, m_endian));
                    while (i < nsects) : (i += 1) {
                        const start = i * section_size;
                        if (start + section_size > sections_data.len) break;
                        const block = sections_data[start .. start + section_size];
                        try root.appendSectionFromBlock(allocator, &sections_list, block, true, m_endian);
                    }
                } else if (cmd == macho.LC.SEGMENT and !is_64) {
                    const seg_fileoff = @as(u64, root.readU32At(lc_data, 32, m_endian));
                    const seg_filesize = @as(u64, root.readU32At(lc_data, 36, m_endian));
                    const vmaddr = @as(u64, root.readU32At(lc_data, 24, m_endian));
                    const initprot = @as(macho.vm_prot_t, root.readI32At(lc_data, 44, m_endian));
                    const perm = root.machoProtToPermission(initprot);
                    try root.appendSegmentAndMap(allocator, &segments_list, &segmaps, seg_fileoff, seg_filesize, vmaddr, perm);

                    const section_size = @sizeOf(macho.section);
                    const sections_data = lc_data[@sizeOf(macho.segment_command)..];
                    var i: usize = 0;
                    const nsects = @as(usize, root.readU32At(lc_data, 48, m_endian));
                    while (i < nsects) : (i += 1) {
                        const start = i * section_size;
                        if (start + section_size > sections_data.len) break;
                        const block = sections_data[start .. start + section_size];
                        try root.appendSectionFromBlock(allocator, &sections_list, block, false, m_endian);
                    }
                } else if (cmd == macho.LC.SYMTAB) {
                    symoff = @as(usize, root.readU32At(lc_data, 8, m_endian));
                    nsyms = @as(usize, root.readU32At(lc_data, 12, m_endian));
                    stroff = @as(usize, root.readU32At(lc_data, 16, m_endian));
                    strsize = @as(usize, root.readU32At(lc_data, 20, m_endian));
                } else if (cmd == macho.LC.MAIN) {
                    entry_fileoff = root.readU64At(lc_data, 8, m_endian);
                    have_entry = true;
                } else {
                    if (cmd == macho.LC.LOAD_DYLIB or cmd == macho.LC.LOAD_WEAK_DYLIB or cmd == macho.LC.REEXPORT_DYLIB or cmd == macho.LC.LOAD_UPWARD_DYLIB) {
                        try root.appendDylibNameFromLcData(allocator, &imports, lc_data, m_endian);
                    } else if (cmd == macho.LC.RPATH) {
                        try root.appendRpathMessageFromLcData(allocator, &messages, lc_data, m_endian);
                    } else if (cmd == macho.LC.CODE_SIGNATURE) {
                        try messages.append(allocator, root.Message{ .body = "code signature present" });
                    } else if (cmd == macho.LC.DYLD_EXPORTS_TRIE or cmd == macho.LC.DYLD_INFO) {
                        try messages.append(allocator, root.Message{ .body = "dyld export/bind info present (not parsed)" });
                    }
                }
            } else {
                // Unknown/unsupported load command: skip
            }

            off += cmdsize;
        }
    }

    // Parse direct symbol table entries (simple, tolerant pass).
    if (nsyms != 0) {
        var si_idx: usize = 0;
        while (si_idx < nsyms) : (si_idx += 1) {
            const si = root.symInfoByIndex(buf, symoff, nsyms, stroff, strsize, is_64, m_endian, si_idx) orelse continue;
            const name = si.name;
            const n_type = si.n_type;
            const type_ = @as(u32, n_type) & macho.N_TYPE;
            if (type_ == macho.N_UNDF) {
                try imports.append(allocator, name);
            } else if ((@as(u32, n_type) & macho.N_EXT) != 0) {
                try exports.append(allocator, root.Export{ .name = name, .kind = root.ExportKind.unknown });
            }
        }
    }

    // Indirect symbol table resolution (via LC_DYSYMTAB)
    if (indirectsymoff != 0 and nindirectsyms != 0) {
        if (indirectsymoff + nindirectsyms * 4 > buf.len) return ParseError.Malformed;
        const INDIRECT_INDEX_MASK: u32 = 0x3FFFFFFF;
        var sidx: usize = 0;
        while (sidx < sections_list.items.len) : (sidx += 1) {
            const sec = sections_list.items[sidx];
            const stype = sec.flags & macho.SECTION_TYPE;
            var entry_size: usize = 4;
            var entry_count: usize = 0;
            if (stype == macho.S_SYMBOL_STUBS) {
                if (sec.reserved2 == 0) {
                    sidx += 1;
                    continue;
                }
                entry_size = @as(usize, sec.reserved2);
                entry_count = @as(usize, sec.size) / entry_size;
            } else if (stype == macho.S_NON_LAZY_SYMBOL_POINTERS or stype == macho.S_LAZY_SYMBOL_POINTERS or stype == macho.S_LAZY_DYLIB_SYMBOL_POINTERS) {
                entry_size = 4;
                entry_count = @as(usize, sec.size) / 4;
            } else {
                sidx += 1;
                continue;
            }

            const base_index = @as(usize, sec.reserved1);
            var ii: usize = 0;
            while (ii < entry_count) : (ii += 1) {
                const indirect_idx = base_index + ii;
                if (indirect_idx >= nindirectsyms) break;
                const entry_off = indirectsymoff + indirect_idx * 4;
                if (entry_off + 4 > buf.len) break;
                const entry = root.readU32At(buf, entry_off, m_endian);
                if ((entry & macho.INDIRECT_SYMBOL_LOCAL) != 0) continue;
                if ((entry & macho.INDIRECT_SYMBOL_ABS) != 0) continue;
                const sym_index = @as(usize, entry & INDIRECT_INDEX_MASK);
                if (sym_index >= nsyms) continue;
                const si = root.symInfoByIndex(buf, symoff, nsyms, stroff, strsize, is_64, m_endian, sym_index) orelse continue;
                const name = si.name;
                const n_type = si.n_type;
                const type_ = @as(u32, n_type) & macho.N_TYPE;
                if (type_ == macho.N_UNDF) {
                    try imports.append(allocator, name);
                } else if ((@as(u32, n_type) & macho.N_EXT) != 0) {
                    try exports.append(allocator, root.Export{ .name = name, .kind = root.ExportKind.unknown });
                }
            }
            sidx += 1;
        }
    }

    // Translate entry offset to virtual address using segmaps
    var entry_va: u64 = 0;
    if (have_entry) {
        var i: usize = 0;
        while (i < segmaps.items.len) : (i += 1) {
            const sm = segmaps.items[i];
            if (entry_fileoff >= sm.fileoff and entry_fileoff < sm.fileoff + sm.filesize) {
                entry_va = sm.vmaddr + (entry_fileoff - sm.fileoff);
                break;
            }
        }
        if (entry_va == 0) entry_va = entry_fileoff;
    }

    const arch2 = switch (hdr_cputype) {
        macho.CPU_TYPE_X86_64 => root.CpuArch.x86_64,
        macho.CPU_TYPE_ARM64 => root.CpuArch.aarch64,
        7 => root.CpuArch.x86,
        else => root.CpuArch.unknown,
    };

    const file_kind = switch (hdr_filetype) {
        macho.MH_EXECUTE => root.FileKind.executable,
        macho.MH_DYLIB => root.FileKind.shared_library,
        macho.MH_OBJECT => root.FileKind.object,
        else => root.FileKind.unknown,
    };

    var desc_path: []const u8 = &[_]u8{};
    if (path) |p| {
        var pbuf = try allocator.alloc(u8, p.len);
        var j: usize = 0;
        while (j < p.len) : (j += 1) pbuf[j] = p[j];
        desc_path = pbuf[0..p.len];
    }

    const desc = root.BinaryDescription{
        .format = root.BinaryFileKind.macho,
        .os_abi = root.OsAbi.macos,
        .arch = arch2,
        .bitness = if (is_64) 64 else 32,
        .endianess = m_endian,
        .file_kind = file_kind,
        .entrypoint_virtual_address = entry_va,
        .pie = if ((hdr_flags & macho.MH_PIE) != 0) root.Perhaps.yes else root.Perhaps.no,
        .aslr = root.Perhaps.unknown,
        .nx = root.Perhaps.unknown,
        .relro = root.RelroConfig.unknown,
        .stripped = if (nsyms == 0) root.StrippedState.yes else root.StrippedState.no,
        .sections = try sections_list.toOwnedSlice(allocator),
        .segments = try segments_list.toOwnedSlice(allocator),
        .imports = try imports.toOwnedSlice(allocator),
        .exports = try exports.toOwnedSlice(allocator),
        .messages = try messages.toOwnedSlice(allocator),
        .path = desc_path,
        .debug_info_present = false,
    };

    return desc;
}
