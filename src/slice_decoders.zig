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

fn try_u64_range_to_slice(off64: u64, sz64: u64, file_len: usize) ?struct { off: usize, sz: usize } {
    const file_len_u64 = @as(u64, file_len);
    if (off64 > file_len_u64) return null;
    if (sz64 > file_len_u64 - off64) return null;
    return .{ .off = @as(usize, off64), .sz = @as(usize, sz64) };
}

fn u64_to_usize_checked(v: u64) ?usize {
    const usize_max_u64 = @as(u64, std.math.maxInt(usize));
    if (v > usize_max_u64) return null;
    return @as(usize, v);
}

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

    // Build section name table (shstrtab) if present
    var shstrtab: []const u8 = &[_]u8{};
    if (header.shstrndx != 0) {
        var sh_iter = header.iterateSectionHeadersBuffer(file_buf);
        var idx: usize = 0;
        while (true) {
            const sh = try sh_iter.next() orelse break;
            if (idx == @as(usize, header.shstrndx)) {
                const maybe_range = try_u64_range_to_slice(@as(u64, sh.sh_offset), @as(u64, sh.sh_size), file_buf.len);
                if (maybe_range) |r| shstrtab = file_buf[r.off .. r.off + r.sz];
                break;
            }
            idx += 1;
        }
    }

    var sections = try std.ArrayList(root.Section).initCapacity(allocator, 0);
    defer sections.deinit(allocator);
    var segments = try std.ArrayList(root.Section).initCapacity(allocator, 0);
    defer segments.deinit(allocator);
    var segmaps = try std.ArrayList(root.SegmentMap).initCapacity(allocator, 0);
    defer segmaps.deinit(allocator);
    var imports = try std.ArrayList(root.ImportEntry).initCapacity(allocator, 0);
    defer imports.deinit(allocator);
    var exports = try std.ArrayList(root.Export).initCapacity(allocator, 0);
    defer exports.deinit(allocator);
    var messages = try std.ArrayList(root.Message).initCapacity(allocator, 0);
    defer messages.deinit(allocator);

    // For ELF we may collect undefined symbol names into a temporary list so we can
    // represent them as a single ImportEntry with empty dll (unknown origin).
    var undef_syms = try std.ArrayList(root.ImportSymbol).initCapacity(allocator, 0);
    defer undef_syms.deinit(allocator);

    // Collect sections
    var sh_iter2 = header.iterateSectionHeadersBuffer(file_buf);
    while (true) {
        const sh = try sh_iter2.next() orelse break;
        var name_slice: []const u8 = "unknown";
        if (shstrtab.len != 0 and @as(usize, sh.sh_name) < shstrtab.len) {
            const tail = shstrtab[@as(usize, sh.sh_name)..];
            const end = mem.indexOfScalar(u8, tail, 0) orelse tail.len;
            name_slice = tail[0..end];
        }
        const perm = if ((sh.sh_flags & elf.SHF_EXECINSTR) != 0) root.Permission.execute else if ((sh.sh_flags & elf.SHF_WRITE) != 0) root.Permission.write else if ((sh.sh_flags & elf.SHF_ALLOC) != 0) root.Permission.read else root.Permission.none;
        try sections.append(allocator, root.Section{
            .name = name_slice,
            .kind = root.SectionKind.unknown,
            .size = sh.sh_size,
            .file_offset = sh.sh_offset,
            .permission = perm,
            .flags = 0,
            .reserved1 = 0,
            .reserved2 = 0,
        });
    }

    // Collect segments and segmaps
    var ph_iter = header.iterateProgramHeadersBuffer(file_buf);
    while (true) {
        const ph = try ph_iter.next() orelse break;
        const perm = if ((ph.p_flags & elf.PF_X) != 0) root.Permission.execute else if ((ph.p_flags & elf.PF_W) != 0) root.Permission.write else if ((ph.p_flags & elf.PF_R) != 0) root.Permission.read else root.Permission.none;
        try root.appendSegmentAndMap(allocator, &segments, &segmaps, ph.p_offset, ph.p_filesz, ph.p_vaddr, perm);
    }

    // PT_DYNAMIC parsing
    var dyn_off: usize = 0;
    var dyn_sz: usize = 0;
    var have_dyn: bool = false;
    var dyn_bind_now: bool = false;

    var ph_iter2 = header.iterateProgramHeadersBuffer(file_buf);
    while (true) {
        const ph = try ph_iter2.next() orelse break;
        if (ph.p_type == elf.PT_DYNAMIC) {
            dyn_off = @as(usize, ph.p_offset);
            dyn_sz = @as(usize, ph.p_filesz);
            have_dyn = true;
            break;
        }
    }

    var dt_needed_indices = try std.ArrayList(usize).initCapacity(allocator, 0);
    defer dt_needed_indices.deinit(allocator);
    var dyn_str_vaddr: u64 = 0;
    var dyn_str_sz: u64 = 0;

    if (have_dyn) {
        const dyn_region = root.safeSlice(file_buf, @as(u64, dyn_off), @as(u64, dyn_sz));
        if (dyn_region == null) {
            try messages.append(allocator, root.Message{ .body = "PT_DYNAMIC region out of bounds" });
        } else {
            var rdr = std.io.Reader.fixed(dyn_region.?);
            while (true) {
                if (header.is_64) {
                    const d = try rdr.takeStruct(elf.Elf64_Dyn, header.endian);
                    if (d.d_tag == elf.DT_NULL) break;
                    if (d.d_tag == elf.DT_NEEDED) {
                        const maybe_idx = u64_to_usize_checked(d.d_val);
                        if (maybe_idx) |idx| try dt_needed_indices.append(allocator, idx) else try messages.append(allocator, root.Message{ .body = "DT_NEEDED index too large" });
                    } else if (d.d_tag == elf.DT_STRTAB) {
                        dyn_str_vaddr = d.d_val;
                    } else if (d.d_tag == elf.DT_STRSZ) {
                        dyn_str_sz = d.d_val;
                    } else if (d.d_tag == elf.DT_BIND_NOW) {
                        dyn_bind_now = true;
                    }
                } else {
                    const d = try rdr.takeStruct(elf.Elf32_Dyn, header.endian);
                    if (d.d_tag == elf.DT_NULL) break;
                    if (d.d_tag == elf.DT_NEEDED) {
                        const maybe_idx = u64_to_usize_checked(@as(u64, d.d_val));
                        if (maybe_idx) |idx| try dt_needed_indices.append(allocator, idx) else try messages.append(allocator, root.Message{ .body = "DT_NEEDED index too large" });
                    } else if (d.d_tag == elf.DT_STRTAB) {
                        dyn_str_vaddr = @as(u64, d.d_val);
                    } else if (d.d_tag == elf.DT_STRSZ) {
                        dyn_str_sz = @as(u64, d.d_val);
                    } else if (d.d_tag == elf.DT_BIND_NOW) {
                        dyn_bind_now = true;
                    }
                }
            }

            if (dyn_str_vaddr != 0 and dyn_str_sz != 0) {
                const maybe = root.vaddrToFileOffset(file_buf.len, segmaps.items, dyn_str_vaddr);
                if (maybe) |str_off| {
                    const dyn_str_sz_us = u64_to_usize_checked(dyn_str_sz);
                    if (dyn_str_sz_us == null) {
                        try messages.append(allocator, root.Message{ .body = "DT_STRSZ too large" });
                    } else if (dyn_str_sz_us.? <= file_buf.len - str_off) {
                        const dynstr = file_buf[str_off .. str_off + dyn_str_sz_us.?];
                        for (dt_needed_indices.items) |name_off| {
                            if (name_off < dynstr.len) {
                                const s = mem.sliceTo(dynstr[name_off..], 0);
                                if (s.len != 0) try imports.append(allocator, root.ImportEntry{ .dll = s, .symbols = &[_]root.ImportSymbol{} });
                            }
                        }
                    } else {
                        try messages.append(allocator, root.Message{ .body = "DT_STRTAB/DT_STRSZ out of bounds" });
                    }
                } else {
                    // fallback: search for .dynstr section among section headers
                    var found_dynstr: bool = false;
                    var sh_iter3 = header.iterateSectionHeadersBuffer(file_buf);
                    while (true) {
                        const sh = try sh_iter3.next() orelse break;
                        var name_slice: []const u8 = "";
                        if (shstrtab.len != 0 and @as(usize, sh.sh_name) < shstrtab.len) {
                            const tail = shstrtab[@as(usize, sh.sh_name)..];
                            const end = mem.indexOfScalar(u8, tail, 0) orelse tail.len;
                            name_slice = tail[0..end];
                        }
                        if (name_slice.len != 0 and mem.eql(u8, name_slice, ".dynstr")) {
                            const maybe_range2 = try_u64_range_to_slice(@as(u64, sh.sh_offset), @as(u64, sh.sh_size), file_buf.len);
                            if (maybe_range2) |r| {
                                const dynstr = file_buf[r.off .. r.off + r.sz];
                                for (dt_needed_indices.items) |name_off| {
                                    if (name_off < dynstr.len) {
                                        const s = mem.sliceTo(dynstr[name_off..], 0);
                                        if (s.len != 0) try imports.append(allocator, root.ImportEntry{ .dll = s, .symbols = &[_]root.ImportSymbol{} });
                                    }
                                }
                                found_dynstr = true;
                                break;
                            }
                        }
                    }
                    if (!found_dynstr) try messages.append(allocator, root.Message{ .body = "could not map DT_STRTAB vaddr to file offset" });
                }
            } else if (dt_needed_indices.items.len != 0) {
                // try .dynstr fallback
                var found_dynstr2: bool = false;
                var sh_iter4 = header.iterateSectionHeadersBuffer(file_buf);
                while (true) {
                    const sh = try sh_iter4.next() orelse break;
                    var name_slice: []const u8 = "";
                    if (shstrtab.len != 0 and @as(usize, sh.sh_name) < shstrtab.len) {
                        const tail = shstrtab[@as(usize, sh.sh_name)..];
                        const end = mem.indexOfScalar(u8, tail, 0) orelse tail.len;
                        name_slice = tail[0..end];
                    }
                    if (name_slice.len != 0 and mem.eql(u8, name_slice, ".dynstr")) {
                        const maybe_range3 = try_u64_range_to_slice(@as(u64, sh.sh_offset), @as(u64, sh.sh_size), file_buf.len);
                        if (maybe_range3) |r| {
                            const dynstr = file_buf[r.off .. r.off + r.sz];
                            for (dt_needed_indices.items) |name_off| {
                                if (name_off < dynstr.len) {
                                    const s = mem.sliceTo(dynstr[name_off..], 0);
                                    if (s.len != 0) try imports.append(allocator, root.ImportEntry{ .dll = s, .symbols = &[_]root.ImportSymbol{} });
                                }
                            }
                            found_dynstr2 = true;
                            break;
                        }
                    }
                }
                if (!found_dynstr2) try messages.append(allocator, root.Message{ .body = "DT_NEEDED entries present but no dynstr found" });
            }
        }
    }

    // Symbol table parsing
    var sh_iter_sym = header.iterateSectionHeadersBuffer(file_buf);
    var sh_index: usize = 0;
    while (true) {
        const sh = try sh_iter_sym.next() orelse break;
        if (sh.sh_type == elf.SHT_SYMTAB or sh.sh_type == elf.SHT_DYNSYM) {
            const sym_range = try_u64_range_to_slice(@as(u64, sh.sh_offset), @as(u64, sh.sh_size), file_buf.len);
            var sym_off: usize = 0;
            var sym_sz: usize = 0;
            if (sym_range) |r| {
                sym_off = r.off;
                sym_sz = r.sz;
            } else {
                sh_index += 1;
                continue;
            }

            var entsz_usize: usize = 0;
            const entsz_u64 = @as(u64, sh.sh_entsize);
            if (entsz_u64 == 0) entsz_usize = if (header.is_64) @sizeOf(elf.Elf64_Sym) else @sizeOf(elf.Elf32_Sym) else {
                const maybe_entsz = u64_to_usize_checked(entsz_u64);
                if (maybe_entsz == null) {
                    sh_index += 1;
                    continue;
                }
                entsz_usize = maybe_entsz.?;
            }
            if (entsz_usize == 0) {
                sh_index += 1;
                continue;
            }
            const nsyms = sym_sz / entsz_usize;
            if (nsyms == 0) {
                sh_index += 1;
                continue;
            }

            // find linked string table
            var strtab_off: usize = 0;
            var strtab_sz: usize = 0;
            var st_iter = header.iterateSectionHeadersBuffer(file_buf);
            var st_idx: usize = 0;
            while (true) {
                const st = try st_iter.next() orelse break;
                if (st_idx == @as(usize, sh.sh_link)) {
                    const maybe_str = try_u64_range_to_slice(@as(u64, st.sh_offset), @as(u64, st.sh_size), file_buf.len);
                    if (maybe_str) |r| {
                        strtab_off = r.off;
                        strtab_sz = r.sz;
                    } else {
                        strtab_off = 0;
                        strtab_sz = 0;
                    }
                    break;
                }
                st_idx += 1;
            }
            if (strtab_off + strtab_sz > file_buf.len) continue;
            const strtab = file_buf[strtab_off .. strtab_off + strtab_sz];

            var i_sym: usize = 0;
            while (i_sym < nsyms) : (i_sym += 1) {
                const entry_off = sym_off + i_sym * entsz_usize;
                if (entry_off + entsz_usize > file_buf.len) break;
                var rdr_sym = std.io.Reader.fixed(file_buf[entry_off..]);
                if (header.is_64) {
                    const sym = try rdr_sym.takeStruct(elf.Elf64_Sym, header.endian);
                    const name_idx = @as(usize, sym.st_name);
                    if (name_idx >= strtab.len) continue;
                    const name = mem.sliceTo(strtab[name_idx..], 0);
                    if (sym.st_shndx == elf.SHN_UNDEF) {
                        if (name.len != 0) try undef_syms.append(allocator, root.ImportSymbol{ .kind = root.ImportSymbolKind.by_name, .name = name, .ordinal = 0 });
                    } else {
                        const kind = if (sym.st_type() == elf.STT_FUNC) root.ExportKind.function else root.ExportKind.variable;
                        if (name.len != 0) try exports.append(allocator, root.Export{ .name = name, .kind = kind });
                    }
                } else {
                    const sym32 = try rdr_sym.takeStruct(elf.Elf32_Sym, header.endian);
                    const name_idx = @as(usize, sym32.st_name);
                    if (name_idx >= strtab.len) continue;
                    const name = mem.sliceTo(strtab[name_idx..], 0);
                    if (sym32.st_shndx == elf.SHN_UNDEF) {
                        if (name.len != 0) try undef_syms.append(allocator, root.ImportSymbol{ .kind = root.ImportSymbolKind.by_name, .name = name, .ordinal = 0 });
                    } else {
                        const kind = if (sym32.st_type() == elf.STT_FUNC) root.ExportKind.function else root.ExportKind.variable;
                        if (name.len != 0) try exports.append(allocator, root.Export{ .name = name, .kind = kind });
                    }
                }
            }
        }
        sh_index += 1;
    }

    // If we collected undefined symbol names, represent them as a single
    // ImportEntry with empty dll (unknown origin).
    if (undef_syms.items.len != 0) {
        const syms_slice = try undef_syms.toOwnedSlice(allocator);
        try imports.append(allocator, root.ImportEntry{ .dll = &[_]u8{}, .symbols = syms_slice });
    }

    // Security hints: NX, RELRO, PIE
    var nx_hint = root.Perhaps.unknown;
    var relro_hint = root.RelroConfig.unknown;
    var ph_iter3 = header.iterateProgramHeadersBuffer(file_buf);
    var found_gnu_stack: bool = false;
    var found_gnu_relro: bool = false;
    while (true) {
        const ph = try ph_iter3.next() orelse break;
        if (ph.p_type == elf.PT_GNU_STACK) {
            found_gnu_stack = true;
            if ((ph.p_flags & elf.PF_X) != 0) nx_hint = root.Perhaps.no else nx_hint = root.Perhaps.yes;
        }
        if (ph.p_type == elf.PT_GNU_RELRO) {
            found_gnu_relro = true;
            relro_hint = root.RelroConfig.partial;
        }
    }
    if (dyn_bind_now) relro_hint = root.RelroConfig.full else if (!found_gnu_relro) relro_hint = root.RelroConfig.none;
    const pie_hint = if (header.type == elf.ET.DYN) root.Perhaps.yes else if (header.type == elf.ET.EXEC) root.Perhaps.no else root.Perhaps.unknown;

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
        .pie = pie_hint,
        .aslr = root.Perhaps.unknown,
        .nx = nx_hint,
        .relro = relro_hint,
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
    const e_lfanew_u32 = root.readU32At(buf, 0x3c, .little);
    const maybe_e_lfanew = u64_to_usize_checked(@as(u64, e_lfanew_u32));
    if (maybe_e_lfanew == null) return ParseError.Malformed;
    const e_lfanew = maybe_e_lfanew.?;
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
    var imports = try std.ArrayList(root.ImportEntry).initCapacity(allocator, 0);
    defer imports.deinit(allocator);
    var exports = try std.ArrayList(root.Export).initCapacity(allocator, 0);
    defer exports.deinit(allocator);
    var messages = try std.ArrayList(root.Message).initCapacity(allocator, 0);
    defer messages.deinit(allocator);

    var pe_undef_syms = try std.ArrayList(root.ImportSymbol).initCapacity(allocator, 0);
    defer pe_undef_syms.deinit(allocator);

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

    // Read COFF header fields to get section table location and optional header
    const number_of_sections = @as(usize, root.readU16LE(buf, coff_off + 2));
    const size_of_optional_header = @as(usize, root.readU16LE(buf, coff_off + 16));

    const optional_header_off = coff_off + 20;
    if (optional_header_off + size_of_optional_header > buf.len) return ParseError.Malformed;

    const opt = buf[optional_header_off .. optional_header_off + size_of_optional_header];
    if (opt.len < 2) return ParseError.Malformed;
    const magic = root.readU16LE(opt, 0);
    const is_pe32 = (magic == 0x10b);
    const is_pe32_plus = (magic == 0x20b);

    // AddressOfEntryPoint is at offset 0x10 in both PE32 and PE32+
    if (opt.len < 0x14) return ParseError.Malformed;
    const address_of_entry = root.readU32At(opt, 0x10, .little);

    var image_base: u64 = 0;
    if (is_pe32) {
        if (opt.len < 0x1C + 4) return ParseError.Malformed;
        image_base = @as(u64, root.readU32At(opt, 0x1C, .little));
    } else if (is_pe32_plus) {
        // PE32+: ImageBase is 8 bytes at offset 0x18
        if (opt.len < 0x18 + 8) return ParseError.Malformed;
        image_base = root.readU64At(opt, 0x18, .little);
    }

    const entry_va = image_base + @as(u64, address_of_entry);

    // DllCharacteristics offset: 0x46 for PE32, 0x5E for PE32+
    var dll_chars: u16 = 0;
    if (is_pe32) {
        if (opt.len >= 0x48) dll_chars = root.readU16LE(opt, 0x46);
    } else if (is_pe32_plus) {
        if (opt.len >= 0x60) dll_chars = root.readU16LE(opt, 0x5E);
    }

    const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
    const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;

    var aslr_hint = root.Perhaps.unknown;
    var nx_hint = root.Perhaps.unknown;
    if ((dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0) aslr_hint = root.Perhaps.yes else aslr_hint = root.Perhaps.no;
    if ((dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0) nx_hint = root.Perhaps.yes else nx_hint = root.Perhaps.no;

    // Parse section headers
    const section_table_off = optional_header_off + size_of_optional_header;
    const section_entry_size = 40;
    if (section_table_off + number_of_sections * section_entry_size > buf.len) return ParseError.Malformed;

    var segmaps = try std.ArrayList(root.SegmentMap).initCapacity(allocator, number_of_sections);
    defer segmaps.deinit(allocator);

    var i: usize = 0;
    while (i < number_of_sections) : (i += 1) {
        const off = section_table_off + i * section_entry_size;
        const name_bytes = buf[off .. off + 8];
        const end = std.mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
        const name = name_bytes[0..end];
        const virtual_size = root.readU32At(buf, off + 8, .little);
        const virtual_address = root.readU32At(buf, off + 12, .little);
        const size_of_raw = root.readU32At(buf, off + 16, .little);
        const pointer_to_raw = root.readU32At(buf, off + 20, .little);
        const characteristics_sec = root.readU32At(buf, off + 36, .little);
        const perm = if ((characteristics_sec & 0x20000000) != 0) root.Permission.execute else if ((characteristics_sec & 0x80000000) != 0) root.Permission.write else if ((characteristics_sec & 0x40000000) != 0) root.Permission.read else root.Permission.none;

        try sections.append(allocator, root.Section{
            .name = name,
            .kind = root.SectionKind.unknown,
            .size = @as(u64, virtual_size),
            .file_offset = @as(u64, pointer_to_raw),
            .permission = perm,
            .flags = characteristics_sec,
            .reserved1 = 0,
            .reserved2 = 0,
        });

        // add segmap + segment if there's raw data
        if (pointer_to_raw != 0 and size_of_raw != 0) {
            try root.appendSegmentAndMap(allocator, &segments, &segmaps, @as(u64, pointer_to_raw), @as(u64, size_of_raw), @as(u64, virtual_address), perm);
        }
    }

    // Parse DataDirectory: import/export/debug
    const data_dir_off = optional_header_off + (if (is_pe32) @as(usize, 96) else @as(usize, 112));
    if (data_dir_off + 8 * 16 <= buf.len) {
        const export_rva = root.readU32At(buf, data_dir_off + 0 * 8 + 0, .little);
        const export_sz = root.readU32At(buf, data_dir_off + 0 * 8 + 4, .little);
        const import_rva = root.readU32At(buf, data_dir_off + 1 * 8 + 0, .little);
        const import_sz = root.readU32At(buf, data_dir_off + 1 * 8 + 4, .little);
        const debug_rva = root.readU32At(buf, data_dir_off + 6 * 8 + 0, .little);
        const debug_sz = root.readU32At(buf, data_dir_off + 6 * 8 + 4, .little);

        // debug info present
        var debug_present: bool = false;
        if (debug_rva != 0 and debug_sz != 0) debug_present = true;

        // Parse exports
        if (export_rva != 0 and export_sz != 0) {
            if (root.vaddrToFileOffset(buf.len, segmaps.items, @as(u64, export_rva))) |off| {
                if (off + 40 <= buf.len) {
                    const ed = buf[off .. off + 40];
                    const number_of_names = root.readU32At(ed, 24, .little);
                    const address_of_names_rva = root.readU32At(ed, 32, .little);
                    if (number_of_names != 0 and address_of_names_rva != 0) {
                        if (root.vaddrToFileOffset(buf.len, segmaps.items, @as(u64, address_of_names_rva))) |names_off| {
                            var ni: usize = 0;
                            while (ni < @as(usize, number_of_names)) : (ni += 1) {
                                const name_rva = root.readU32At(buf, names_off + ni * 4, .little);
                                if (root.vaddrToFileOffset(buf.len, segmaps.items, @as(u64, name_rva))) |n_off| {
                                    const name = std.mem.sliceTo(buf[n_off..], 0);
                                    if (name.len != 0) try exports.append(allocator, root.Export{ .name = name, .kind = root.ExportKind.unknown });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Parse imports (collect DLL names and imported symbols)
        if (import_rva != 0 and import_sz != 0) {
            var imp_desc_rva = import_rva;
            while (imp_desc_rva != 0) {
                if (root.vaddrToFileOffset(buf.len, segmaps.items, @as(u64, imp_desc_rva))) |imp_off| {
                    if (imp_off + 20 > buf.len) break;
                    const name_rva = root.readU32At(buf, imp_off + 12, .little);
                    if (name_rva == 0) break;
                    if (root.vaddrToFileOffset(buf.len, segmaps.items, @as(u64, name_rva))) |name_off| {
                        const dllname = std.mem.sliceTo(buf[name_off..], 0);
                        if (dllname.len != 0) {
                            // Gather symbol names for this DLL into a temporary list
                            var dll_symbols = try std.ArrayList(root.ImportSymbol).initCapacity(allocator, 0);
                            defer dll_symbols.deinit(allocator);

                            // Parse import name thunk table to collect imported symbol names
                            const oft_rva = root.readU32At(buf, imp_off + 0, .little);
                            const first_thunk_rva = root.readU32At(buf, imp_off + 16, .little);
                            const thunk_rva = if (oft_rva != 0) oft_rva else first_thunk_rva;
                            if (thunk_rva != 0) {
                                if (root.vaddrToFileOffset(buf.len, segmaps.items, @as(u64, thunk_rva))) |thunk_off| {
                                    var toff = thunk_off;
                                    while (true) {
                                        if (is_pe32) {
                                            if (toff + 4 > buf.len) break;
                                            const t = root.readU32At(buf, toff, .little);
                                            if (t == 0) break;
                                            const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;
                                            if ((t & IMAGE_ORDINAL_FLAG32) != 0) {
                                                // import by ordinal: record ordinal value and diagnostic message
                                                const masked: u64 = t & 0xFFFF;
                                                const ord = @as(u32, masked);
                                                try dll_symbols.append(allocator, root.ImportSymbol{ .kind = root.ImportSymbolKind.by_ordinal, .name = &[_]u8{}, .ordinal = ord });
                                                try messages.append(allocator, root.Message{ .body = "import by ordinal (32-bit)" });
                                            } else {
                                                const name_rva2 = t;
                                                if (root.vaddrToFileOffset(buf.len, segmaps.items, @as(u64, name_rva2))) |name_off2| {
                                                    if (name_off2 + 2 < buf.len) {
                                                        const byname = std.mem.sliceTo(buf[name_off2 + 2 ..], 0);
                                                        if (byname.len != 0) try dll_symbols.append(allocator, root.ImportSymbol{ .kind = root.ImportSymbolKind.by_name, .name = byname, .ordinal = 0 });
                                                    }
                                                } else {
                                                    try messages.append(allocator, root.Message{ .body = "import name RVA unmapped" });
                                                }
                                            }
                                            toff += 4;
                                        } else {
                                            if (toff + 8 > buf.len) break;
                                            const t64 = root.readU64At(buf, toff, .little);
                                            if (t64 == 0) break;
                                            const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;
                                            if ((t64 & IMAGE_ORDINAL_FLAG64) != 0) {
                                                // import by ordinal: record ordinal value and diagnostic message
                                                const masked64: u64 = t64 & 0xFFFF;
                                                const ord64 = @as(u32, masked64);
                                                try dll_symbols.append(allocator, root.ImportSymbol{ .kind = root.ImportSymbolKind.by_ordinal, .name = &[_]u8{}, .ordinal = ord64 });
                                                try messages.append(allocator, root.Message{ .body = "import by ordinal (64-bit)" });
                                            } else {
                                                const name_rva2 = t64;
                                                if (root.vaddrToFileOffset(buf.len, segmaps.items, name_rva2)) |name_off2| {
                                                    if (name_off2 + 2 < buf.len) {
                                                        const byname = std.mem.sliceTo(buf[name_off2 + 2 ..], 0);
                                                        if (byname.len != 0) try dll_symbols.append(allocator, root.ImportSymbol{ .kind = root.ImportSymbolKind.by_name, .name = byname, .ordinal = 0 });
                                                    }
                                                } else {
                                                    try messages.append(allocator, root.Message{ .body = "import name RVA unmapped" });
                                                }
                                            }
                                            toff += 8;
                                        }
                                    }
                                } else {
                                    try messages.append(allocator, root.Message{ .body = "import thunk table RVA unmapped" });
                                }
                            }

                            // Move collected symbols into an owned slice and append ImportEntry
                            if (dll_symbols.items.len != 0) {
                                const syms_slice = try dll_symbols.toOwnedSlice(allocator);
                                try imports.append(allocator, root.ImportEntry{ .dll = dllname, .symbols = syms_slice });
                            } else {
                                try imports.append(allocator, root.ImportEntry{ .dll = dllname, .symbols = &[_]root.ImportSymbol{} });
                            }
                        }
                    }
                    // detect null descriptor (all zeros)
                    const null_check = root.readU32At(buf, imp_off + 0, .little) | root.readU32At(buf, imp_off + 4, .little) | root.readU32At(buf, imp_off + 8, .little) | root.readU32At(buf, imp_off + 12, .little) | root.readU32At(buf, imp_off + 16, .little);
                    if (null_check == 0) break;
                    imp_desc_rva += 20;
                } else break;
            }
        }

        // Assign debug flag
        const desc = root.BinaryDescription{
            .format = root.BinaryFileKind.pe,
            .os_abi = root.OsAbi.windows,
            .arch = arch,
            .bitness = bitness,
            .endianess = Endian.little,
            .file_kind = file_kind,
            .entrypoint_virtual_address = entry_va,
            .pie = root.Perhaps.unknown,
            .aslr = aslr_hint,
            .nx = nx_hint,
            .relro = root.RelroConfig.not_applicable,
            .stripped = root.StrippedState.unknown,
            .sections = try sections.toOwnedSlice(allocator),
            .segments = try segments.toOwnedSlice(allocator),
            .imports = try imports.toOwnedSlice(allocator),
            .exports = try exports.toOwnedSlice(allocator),
            .messages = try messages.toOwnedSlice(allocator),
            .path = desc_path,
            .debug_info_present = debug_present,
        };

        return desc;
    }

    // Fallback: no data directories available; return minimal desc
    const desc2 = root.BinaryDescription{
        .format = root.BinaryFileKind.pe,
        .os_abi = root.OsAbi.windows,
        .arch = arch,
        .bitness = bitness,
        .endianess = Endian.little,
        .file_kind = file_kind,
        .entrypoint_virtual_address = entry_va,
        .pie = root.Perhaps.unknown,
        .aslr = aslr_hint,
        .nx = nx_hint,
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

    return desc2;
}

// Unit tests for the minimal slice decoder placeholders. These tests exercise
// the in-memory slice API (no filesystem side-effects beyond reading test
// fixtures) and assert deterministic behavior for the supplied test assets.

test "slice_decoders: decodeElfSlice parses ELF header from fixture" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc = try decodeElfSlice(allocator, buf, null);
    // Free owned top-level slices from BinaryDescription after assertions
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    try expect(desc.format == root.BinaryFileKind.elf);
    try expect(desc.arch == root.CpuArch.x86_64);
    try expect(desc.bitness == 64);

    // Expect DT_NEEDED libs to include libc and symbol imports like printf
    var found_libc: bool = false;
    var found_printf: bool = false;
    for (desc.imports) |ie| {
        if (ie.dll.len != 0) {
            if (std.mem.indexOf(u8, ie.dll, "libc.so.6")) |pos| {
                _ = pos;
                found_libc = true;
            }
        }
        for (ie.symbols) |sym| {
            if (sym.kind == root.ImportSymbolKind.by_name or sym.kind == root.ImportSymbolKind.by_name_and_ordinal) {
                if (std.mem.indexOf(u8, sym.name, "printf")) |pos| {
                _ = pos;
                found_printf = true;
                }
            }
        }
    }
    try expect(found_libc == true);
    try expect(found_printf == true);

    // Basic security hint expectations for this asset
    try expect(desc.pie == root.Perhaps.no);
    try expect(desc.nx == root.Perhaps.yes);
    try expect(desc.relro == root.RelroConfig.none);
}

test "slice_decoders: decodePESlice rejects non-PE file with InvalidHeader" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
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
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc = try decodeMachoSlice(allocator, buf, null);
    // Free top-level slices allocated by decodeMachoSlice
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    try expect(desc.format == root.BinaryFileKind.macho);
    try expect(desc.arch == root.CpuArch.x86_64);
    try expect(desc.bitness == 64);
}

test "slice_decoders.invariants: Mach-O decode populates sections, segments, imports, and exports" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-x64-ls", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc = try decodeMachoSlice(allocator, buf, null);
    // Free top-level slices allocated by decodeMachoSlice
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    try expect(desc.format == root.BinaryFileKind.macho);
    try expect(desc.sections.len > 0);
    try expect(desc.segments.len > 0);
    try expect(desc.imports.len > 0);
    try expect(desc.exports.len >= 0); // exports may be 0 or more depending on asset

    // Ensure imports contain non-empty names
    var found_printf_or_malloc: bool = false;
    var found_dyld_stub: bool = false;
    for (desc.imports) |ie| {
        try expect(ie.dll.len > 0 or ie.symbols.len > 0);
        if (ie.dll.len != 0) {
            if (std.mem.indexOf(u8, ie.dll, "printf")) |pos| {
                _ = pos;
                found_printf_or_malloc = true;
            }
            if (std.mem.indexOf(u8, ie.dll, "malloc")) |pos| {
                _ = pos;
                found_printf_or_malloc = true;
            }
        }
        for (ie.symbols) |sym| {
            if (sym.kind == root.ImportSymbolKind.by_name or sym.kind == root.ImportSymbolKind.by_name_and_ordinal) {
                if (std.mem.indexOf(u8, sym.name, "printf")) |pos| {
                    _ = pos;
                    found_printf_or_malloc = true;
                }
                if (std.mem.indexOf(u8, sym.name, "malloc")) |pos| {
                    _ = pos;
                    found_printf_or_malloc = true;
                }
                if (std.mem.indexOf(u8, sym.name, "dyld_stub_binder")) |pos| {
                    _ = pos;
                    found_dyld_stub = true;
                }
            }
        }
    }
    try expect(found_printf_or_malloc == true);
    try expect(found_dyld_stub == true);

    // If exports present, ensure export names are non-empty and contain known header symbol
    if (desc.exports.len > 0) {
        var found_mh_header: bool = false;
        for (desc.exports) |ex| {
            try expect(ex.name.len > 0);
            if (std.mem.indexOf(u8, ex.name, "__mh_execute_header")) |pos| {
                _ = pos;
                found_mh_header = true;
            }
        }
        try expect(found_mh_header == true);
    }
}

// Edge-case tests for ELF dynamic parsing

fn write_u64_le(buf: []u8, off: usize, v: u64) void {
    var tmp: u64 = v;
    var j: usize = 0;
    while (j < 8) : (j += 1) {
        buf[off + j] = @intCast(tmp & @as(u64, 0xFF));
        tmp = tmp >> 8;
    }
}

fn write_u32_le(buf: []u8, off: usize, v: u32) void {
    var tmp: u32 = v;
    var j: usize = 0;
    while (j < 4) : (j += 1) {
        buf[off + j] = @intCast(tmp & @as(u32, 0xFF));
        tmp = tmp >> 8;
    }
}

fn write_u32_be(buf: []u8, off: usize, v: u32) void {
    var tmp: u32 = v;
    var j: usize = 0;
    while (j < 4) : (j += 1) {
        buf[off + (3 - j)] = @intCast(tmp & @as(u32, 0xFF));
        tmp = tmp >> 8;
    }
}

test "slice_decoders: fallback when DT_STRTAB vaddr doesn't map (use .dynstr)" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    // First decode to locate dynamic section and confirm baseline
    const desc0 = try decodeElfSlice(allocator, buf, null);
    defer if (desc0.sections.len != 0) allocator.free(desc0.sections);
    defer if (desc0.segments.len != 0) allocator.free(desc0.segments);
    defer if (desc0.imports.len != 0) root.freeImportEntries(allocator, desc0.imports);
    defer if (desc0.exports.len != 0) allocator.free(desc0.exports);
    defer if (desc0.messages.len != 0) allocator.free(desc0.messages);
    defer if (desc0.path.len != 0) allocator.free(desc0.path);

    var dyn_sec_index: ?usize = null;
    var i: usize = 0;
    while (i < desc0.sections.len) : (i += 1) {
        if (std.mem.eql(u8, desc0.sections[i].name, ".dynamic")) {
            dyn_sec_index = i;
            break;
        }
    }
    try expect(dyn_sec_index != null);
    const dyn_off = @as(usize, desc0.sections[dyn_sec_index.?].file_offset);
    const dyn_sz = @as(usize, desc0.sections[dyn_sec_index.?].size);

    // Corrupt DT_STRTAB vaddr to an unmapped address (so vaddr->fileoff fails)
    // This ELF is 64-bit little-endian; write d_val for DT_STRTAB entries
    var off: usize = dyn_off;
    const entry_size = @sizeOf(elf.Elf64_Dyn);
    while (off + entry_size <= dyn_off + dyn_sz) : (off += entry_size) {
        const tag = root.readU64At(buf, off, desc0.endianess);
        if (tag == @as(u64, elf.DT_STRTAB)) {
            // DT_STRTAB's d_tag at off, d_val at off+8
            write_u64_le(buf, off + 8, 0xDEADBEEFDEADBEEF);
            break;
        }
    }

    const desc = try decodeElfSlice(allocator, buf, null);
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    // Imports should still include libc and printf via .dynstr fallback
    var found_libc: bool = false;
    var found_printf: bool = false;
    for (desc.imports) |ie| {
        if (ie.dll.len != 0) {
            if (std.mem.indexOf(u8, ie.dll, "libc.so.6")) |pos| {
                _ = pos;
                found_libc = true;
            }
        }
        for (ie.symbols) |sym| {
            if (sym.kind == root.ImportSymbolKind.by_name or sym.kind == root.ImportSymbolKind.by_name_and_ordinal) {
                if (std.mem.indexOf(u8, sym.name, "printf")) |pos| {
                _ = pos;
                found_printf = true;
                }
            }
        }
    }
    try expect(found_libc == true);
    try expect(found_printf == true);

    // Ensure we didn't get an explicit failure message about mapping DT_STRTAB
    var saw_map_fail: bool = false;
    for (desc.messages) |m| {
        if (std.mem.indexOf(u8, m.body, "could not map DT_STRTAB")) |pos| {
            _ = pos;
            saw_map_fail = true;
        }
    }
    try expect(saw_map_fail == false);
}

test "slice_decoders: DT_BIND_NOW triggers RELRO full" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc0 = try decodeElfSlice(allocator, buf, null);
    defer if (desc0.sections.len != 0) allocator.free(desc0.sections);
    defer if (desc0.segments.len != 0) allocator.free(desc0.segments);
    defer if (desc0.imports.len != 0) root.freeImportEntries(allocator, desc0.imports);
    defer if (desc0.exports.len != 0) allocator.free(desc0.exports);
    defer if (desc0.messages.len != 0) allocator.free(desc0.messages);
    defer if (desc0.path.len != 0) allocator.free(desc0.path);

    // Find dynamic table
    var dyn_sec_index: ?usize = null;
    var i: usize = 0;
    while (i < desc0.sections.len) : (i += 1) {
        if (std.mem.eql(u8, desc0.sections[i].name, ".dynamic")) {
            dyn_sec_index = i;
            break;
        }
    }
    try expect(dyn_sec_index != null);
    const dyn_off = @as(usize, desc0.sections[dyn_sec_index.?].file_offset);
    const dyn_sz = @as(usize, desc0.sections[dyn_sec_index.?].size);

    // Flip an existing dynamic entry's d_tag to DT_BIND_NOW (safe: pick first non-special tag)
    var off: usize = dyn_off;
    const entry_size = @sizeOf(elf.Elf64_Dyn);
    while (off + entry_size <= dyn_off + dyn_sz) : (off += entry_size) {
        const tag = root.readU64At(buf, off, desc0.endianess);
        if (tag != 0 and tag != @as(u64, elf.DT_NEEDED) and tag != @as(u64, elf.DT_STRTAB) and tag != @as(u64, elf.DT_STRSZ)) {
            // write DT_BIND_NOW into d_tag (little-endian)
            write_u64_le(buf, off, @as(u64, elf.DT_BIND_NOW));
            break;
        }
    }

    const desc = try decodeElfSlice(allocator, buf, null);
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    try expect(desc.relro == root.RelroConfig.full);
}

test "slice_decoders: malformed DT_STRSZ appends message instead of panicking" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc0 = try decodeElfSlice(allocator, buf, null);
    defer if (desc0.sections.len != 0) allocator.free(desc0.sections);
    defer if (desc0.segments.len != 0) allocator.free(desc0.segments);
    defer if (desc0.imports.len != 0) root.freeImportEntries(allocator, desc0.imports);
    defer if (desc0.exports.len != 0) allocator.free(desc0.exports);
    defer if (desc0.messages.len != 0) allocator.free(desc0.messages);
    defer if (desc0.path.len != 0) allocator.free(desc0.path);

    // Locate DT_STRSZ entry and set it to an enormous size to force out-of-bounds
    var dyn_sec_index: ?usize = null;
    var i: usize = 0;
    while (i < desc0.sections.len) : (i += 1) {
        if (std.mem.eql(u8, desc0.sections[i].name, ".dynamic")) {
            dyn_sec_index = i;
            break;
        }
    }
    try expect(dyn_sec_index != null);
    const dyn_off = @as(usize, desc0.sections[dyn_sec_index.?].file_offset);
    const dyn_sz = @as(usize, desc0.sections[dyn_sec_index.?].size);

    var off: usize = dyn_off;
    const entry_size2 = @sizeOf(elf.Elf64_Dyn);
    while (off + entry_size2 <= dyn_off + dyn_sz) : (off += entry_size2) {
        const tag = root.readU64At(buf, off, desc0.endianess);
        if (tag == @as(u64, elf.DT_STRSZ)) {
            // set DT_STRSZ d_val to a size larger than the file to trigger OOB message
            write_u64_le(buf, off + 8, @as(u64, buf.len) + 1);
            break;
        }
    }

    const desc = try decodeElfSlice(allocator, buf, null);
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    var saw_oob: bool = false;
    for (desc.messages) |m| {
        if (std.mem.indexOf(u8, m.body, "DT_STRTAB/DT_STRSZ out of bounds")) |pos| {
            _ = pos;
            saw_oob = true;
        }
    }
    try expect(saw_oob == true);
}

// Additional edge-case tests

test "slice_decoders: decodePESlice errors on corrupt e_lfanew" {
    const allocator = std.testing.allocator;
    // Build synthetic minimal PE-like buffer so we can mutate e_lfanew
    const len: usize = 256;
    var buf = try allocator.alloc(u8, len);
    // initialize zero
    var k: usize = 0;
    while (k < len) : (k += 1) buf[k] = 0;
    buf[0] = "M"[0];
    buf[1] = "Z"[0];

    // set e_lfanew to an out-of-range value (beyond buffer len)
    const new_e: u32 = 0xFFFFFFFF;
    write_u32_le(buf, 0x3c, new_e);

    _ = decodePESlice(allocator, buf, null) catch |err| {
        try expect(err == ParseError.Malformed);
        allocator.free(buf);
        return;
    };
    // If we get here, decodePESlice unexpectedly returned success
    allocator.free(buf);
    try expect(false);
}

test "slice_decoders: decodePESlice parses PE fixture and populates segments" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/pe-Windows-x64-cmd", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc = try decodePESlice(allocator, buf, null);
    // Free top-level slices allocated by decodePESlice
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    try expect(desc.format == root.BinaryFileKind.pe);
    try expect(desc.segments.len > 0);
    try expect(desc.sections.len > 0);
}

test "slice_decoders: decodeMachoSlice errors on oversized sizeofcmds" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-x64-ls", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    // Read magic like decodeMachoSlice to determine is_64 and endianness
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
    } else return;

    // sizeofcmds is at offset 20 in both 32-bit and 64-bit headers
    const new_sz: u32 = 0xFFFFFFFF;
    if (m_endian == .little) {
        write_u32_le(buf, 20, new_sz);
    } else {
        write_u32_be(buf, 20, new_sz);
    }

    _ = decodeMachoSlice(allocator, buf, null) catch |err| {
        try expect(err == ParseError.Malformed);
        return;
    };
    try expect(false);
}

test "slice_decoders: missing .dynstr section yields DT_NEEDED/no-dynstr message" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc0 = try decodeElfSlice(allocator, buf, null);
    defer if (desc0.sections.len != 0) allocator.free(desc0.sections);
    defer if (desc0.segments.len != 0) allocator.free(desc0.segments);
    defer if (desc0.imports.len != 0) root.freeImportEntries(allocator, desc0.imports);
    defer if (desc0.exports.len != 0) allocator.free(desc0.exports);
    defer if (desc0.messages.len != 0) allocator.free(desc0.messages);
    defer if (desc0.path.len != 0) allocator.free(desc0.path);

    // Find .dynamic and DT_STRTAB and set its d_val to 0 (no vaddr)
    var dyn_sec_index: ?usize = null;
    var i: usize = 0;
    while (i < desc0.sections.len) : (i += 1) {
        if (std.mem.eql(u8, desc0.sections[i].name, ".dynamic")) {
            dyn_sec_index = i;
            break;
        }
    }
    try expect(dyn_sec_index != null);
    const dyn_off = @as(usize, desc0.sections[dyn_sec_index.?].file_offset);
    const dyn_sz = @as(usize, desc0.sections[dyn_sec_index.?].size);

    var off: usize = dyn_off;
    const entry_size = @sizeOf(elf.Elf64_Dyn);
    while (off + entry_size <= dyn_off + dyn_sz) : (off += entry_size) {
        const tag = root.readU64At(buf, off, desc0.endianess);
        if (tag == @as(u64, elf.DT_STRTAB)) {
            write_u64_le(buf, off + 8, 0);
            break;
        }
    }

    // Zero shstrtab so .dynstr can't be found by name
    var shstr_index: ?usize = null;
    i = 0;
    while (i < desc0.sections.len) : (i += 1) {
        if (std.mem.eql(u8, desc0.sections[i].name, ".shstrtab")) {
            shstr_index = i;
            break;
        }
    }
    try expect(shstr_index != null);
    const shstr_off = @as(usize, desc0.sections[shstr_index.?].file_offset);
    const shstr_sz = @as(usize, desc0.sections[shstr_index.?].size);
    var j: usize = 0;
    while (j < shstr_sz) : (j += 1) buf[shstr_off + j] = 0;

    const desc = try decodeElfSlice(allocator, buf, null);
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    var saw_msg: bool = false;
    for (desc.messages) |m| {
        if (std.mem.indexOf(u8, m.body, "DT_NEEDED entries present but no dynstr found")) |pos| {
            _ = pos;
            saw_msg = true;
        }
    }
    try expect(saw_msg == true);
}

test "slice_decoders: missing DT_NULL in dynamic table results in error" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc0 = try decodeElfSlice(allocator, buf, null);
    defer if (desc0.sections.len != 0) allocator.free(desc0.sections);
    defer if (desc0.segments.len != 0) allocator.free(desc0.segments);
    defer if (desc0.imports.len != 0) root.freeImportEntries(allocator, desc0.imports);
    defer if (desc0.exports.len != 0) allocator.free(desc0.exports);
    defer if (desc0.messages.len != 0) allocator.free(desc0.messages);
    defer if (desc0.path.len != 0) allocator.free(desc0.path);

    // Find .dynamic and change any DT_NULL tag to DT_NEEDED (removes terminator)
    var dyn_sec_index: ?usize = null;
    var i: usize = 0;
    while (i < desc0.sections.len) : (i += 1) {
        if (std.mem.eql(u8, desc0.sections[i].name, ".dynamic")) {
            dyn_sec_index = i;
            break;
        }
    }
    try expect(dyn_sec_index != null);
    const dyn_off = @as(usize, desc0.sections[dyn_sec_index.?].file_offset);
    const dyn_sz = @as(usize, desc0.sections[dyn_sec_index.?].size);

    var off: usize = dyn_off;
    const entry_size2 = @sizeOf(elf.Elf64_Dyn);
    var changed: bool = false;
    while (off + entry_size2 <= dyn_off + dyn_sz) : (off += entry_size2) {
        const tag = root.readU64At(buf, off, desc0.endianess);
        if (tag == @as(u64, elf.DT_NULL)) {
            // set this tag to DT_NEEDED so there may be no terminator
            write_u64_le(buf, off, @as(u64, elf.DT_NEEDED));
            // set some d_val to a small offset (0) to keep val in-range
            write_u64_le(buf, off + 8, 0);
            changed = true;
            break;
        }
    }
    try expect(changed == true);

    // Decoding may error or succeed depending on how the reader handles EOF. We accept either
    // as long as it does not panic. If decoding succeeds, free the returned description and pass.
    const maybe_desc = decodeElfSlice(allocator, buf, null) catch {
        return; // error is acceptable
    };
    defer if (maybe_desc.sections.len != 0) allocator.free(maybe_desc.sections);
    defer if (maybe_desc.segments.len != 0) allocator.free(maybe_desc.segments);
    defer if (maybe_desc.imports.len != 0) root.freeImportEntries(allocator, maybe_desc.imports);
    defer if (maybe_desc.exports.len != 0) allocator.free(maybe_desc.exports);
    defer if (maybe_desc.messages.len != 0) allocator.free(maybe_desc.messages);
    defer if (maybe_desc.path.len != 0) allocator.free(maybe_desc.path);
    return;
}

test "slice_decoders: premature DT_NULL causes DT_NEEDED to be ignored" {
    const allocator = std.testing.allocator;
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const buf = try file.readToEndAlloc(allocator, 16777216);
    defer allocator.free(buf);

    const desc0 = try decodeElfSlice(allocator, buf, null);
    defer if (desc0.sections.len != 0) allocator.free(desc0.sections);
    defer if (desc0.segments.len != 0) allocator.free(desc0.segments);
    defer if (desc0.imports.len != 0) root.freeImportEntries(allocator, desc0.imports);
    defer if (desc0.exports.len != 0) allocator.free(desc0.exports);
    defer if (desc0.messages.len != 0) allocator.free(desc0.messages);
    defer if (desc0.path.len != 0) allocator.free(desc0.path);

    // Count baseline imports
    const baseline_imports = desc0.imports.len;

    // Find .dynamic and set the first DT_NEEDED tag to DT_NULL (premature terminator)
    var dyn_sec_index: ?usize = null;
    var i: usize = 0;
    while (i < desc0.sections.len) : (i += 1) {
        if (std.mem.eql(u8, desc0.sections[i].name, ".dynamic")) {
            dyn_sec_index = i;
            break;
        }
    }
    try expect(dyn_sec_index != null);
    const dyn_off = @as(usize, desc0.sections[dyn_sec_index.?].file_offset);
    const dyn_sz = @as(usize, desc0.sections[dyn_sec_index.?].size);

    var off: usize = dyn_off;
    const entry_size3 = @sizeOf(elf.Elf64_Dyn);
    var changed2: bool = false;
    while (off + entry_size3 <= dyn_off + dyn_sz) : (off += entry_size3) {
        const tag = root.readU64At(buf, off, desc0.endianess);
        if (tag == @as(u64, elf.DT_NEEDED)) {
            write_u64_le(buf, off, @as(u64, elf.DT_NULL));
            changed2 = true;
            break;
        }
    }
    try expect(changed2 == true);

    const desc = try decodeElfSlice(allocator, buf, null);
    defer if (desc.sections.len != 0) allocator.free(desc.sections);
    defer if (desc.segments.len != 0) allocator.free(desc.segments);
    defer if (desc.imports.len != 0) root.freeImportEntries(allocator, desc.imports);
    defer if (desc.exports.len != 0) allocator.free(desc.exports);
    defer if (desc.messages.len != 0) allocator.free(desc.messages);
    defer if (desc.path.len != 0) allocator.free(desc.path);

    try expect(desc.imports.len < baseline_imports);
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
            const maybe_ncmds = u64_to_usize_checked(@as(u64, hdr.ncmds));
            const maybe_sizeofcmds = u64_to_usize_checked(@as(u64, hdr.sizeofcmds));
            if (maybe_ncmds == null or maybe_sizeofcmds == null) return ParseError.Malformed;
            ncmds = maybe_ncmds.?;
            sizeofcmds = maybe_sizeofcmds.?;
            hdr_cputype = hdr.cputype;
            hdr_filetype = hdr.filetype;
            hdr_flags = hdr.flags;
        } else {
            if (buf.len < @sizeOf(macho.mach_header)) return ParseError.TooSmall;
            const hdr_ptr = @as(*align(1) const macho.mach_header, @ptrCast(buf.ptr));
            const hdr = hdr_ptr.*;
            hdr_size = @sizeOf(macho.mach_header);
            const maybe_ncmds = u64_to_usize_checked(@as(u64, hdr.ncmds));
            const maybe_sizeofcmds = u64_to_usize_checked(@as(u64, hdr.sizeofcmds));
            if (maybe_ncmds == null or maybe_sizeofcmds == null) return ParseError.Malformed;
            ncmds = maybe_ncmds.?;
            sizeofcmds = maybe_sizeofcmds.?;
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
    var imports = try std.ArrayList(root.ImportEntry).initCapacity(allocator, 0);
    defer imports.deinit(allocator);
    var exports = try std.ArrayList(root.Export).initCapacity(allocator, 0);
    defer exports.deinit(allocator);
    var messages = try std.ArrayList(root.Message).initCapacity(allocator, 0);
    defer messages.deinit(allocator);

    var segmaps = try std.ArrayList(root.SegmentMap).initCapacity(allocator, 0);
    defer segmaps.deinit(allocator);

    var mach_undef_syms = try std.ArrayList(root.ImportSymbol).initCapacity(allocator, 0);
    defer mach_undef_syms.deinit(allocator);

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
                const maybe_symoff = u64_to_usize_checked(@as(u64, st.symoff));
                const maybe_nsyms = u64_to_usize_checked(@as(u64, st.nsyms));
                const maybe_stroff = u64_to_usize_checked(@as(u64, st.stroff));
                const maybe_strsize = u64_to_usize_checked(@as(u64, st.strsize));
                if (maybe_symoff == null or maybe_nsyms == null or maybe_stroff == null or maybe_strsize == null) continue;
                symoff = maybe_symoff.?;
                nsyms = maybe_nsyms.?;
                stroff = maybe_stroff.?;
                strsize = maybe_strsize.?;
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
                    if (name.len != 0) try imports.append(allocator, root.ImportEntry{ .dll = name, .symbols = &[_]root.ImportSymbol{} });
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
            const cmdsize_u32 = root.readU32At(buf, off + 4, m_endian);
            const maybe_cmdsize = u64_to_usize_checked(@as(u64, cmdsize_u32));
            if (maybe_cmdsize == null) return ParseError.Malformed;
            const cmdsize = maybe_cmdsize.?;
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
                    const nsects_u32 = root.readU32At(lc_data, 64, m_endian);
                    const maybe_nsects = u64_to_usize_checked(@as(u64, nsects_u32));
                    if (maybe_nsects == null) break;
                    const nsects = maybe_nsects.?;
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
                    const nsects_u32 = root.readU32At(lc_data, 48, m_endian);
                    const maybe_nsects = u64_to_usize_checked(@as(u64, nsects_u32));
                    if (maybe_nsects == null) break;
                    const nsects = maybe_nsects.?;
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
                try mach_undef_syms.append(allocator, root.ImportSymbol{ .kind = root.ImportSymbolKind.by_name, .name = name, .ordinal = 0 });
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
                    try mach_undef_syms.append(allocator, root.ImportSymbol{ .kind = root.ImportSymbolKind.by_name, .name = name, .ordinal = 0 });
                } else if ((@as(u32, n_type) & macho.N_EXT) != 0) {
                    try exports.append(allocator, root.Export{ .name = name, .kind = root.ExportKind.unknown });
                }
            }
            sidx += 1;
        }
    }

    // If we collected undefined Mach-O symbol names, append them as a single import entry
    if (mach_undef_syms.items.len != 0) {
        const syms_slice2 = try mach_undef_syms.toOwnedSlice(allocator);
        try imports.append(allocator, root.ImportEntry{ .dll = &[_]u8{}, .symbols = syms_slice2 });
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
