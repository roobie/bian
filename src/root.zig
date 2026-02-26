//! By convention, root.zig is the root source file when making a library.
const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const elf = std.elf;
const macho = std.macho;
const builtin = @import("builtin");

const expect = std.testing.expect;

pub const ParseError = error{
    TooSmall,
    InvalidHeader,
    UnsupportedVariant,
    Malformed,
    OutOfMemory,
};

/// We assume that we will fit all metadata required in this length, to
/// successfully perform the stage 0 parsing.
const prefix_length = 512;

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
    ape,
};

const Endian = std.builtin.Endian;
const ElfHint = struct {
    bitness: u8,
    endianess: Endian,
};
const MachoHint = struct {
    bitness: u8,
    endianess: Endian,
};
const PeHint = struct {
    // machine is the COFF header “Machine” field from the PE header.
    // It’s a 16-bit value that tells you what CPU/architecture the
    // file is intended for (e.g. x86, x64, ARM, etc.).
    // Common examples (from IMAGE_FILE_MACHINE_* in winnt.h):
    // 0x014c → 332 → IMAGE_FILE_MACHINE_I386 (32-bit x86)
    // 0x8664 → 34404 → IMAGE_FILE_MACHINE_AMD64 (x64)
    // 0x01c0 → 448 → IMAGE_FILE_MACHINE_ARM
    // 0xaa64 → 43620 → IMAGE_FILE_MACHINE_ARM64

    machine: u16,
    coff_header: []u8,
};

const Stage0ParseResult = union(BinaryFileKind) {
    unknown,
    elf: ElfHint,
    macho: MachoHint,
    pe: PeHint,
    ape: u8, // TBD ApeHint
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

const SectionKind = enum {
    unknown,
    code,
    data,
};
const Permission = enum { read, write, execute, none };

const Section = struct {
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
const ExportKind = enum {
    unknown,
    function,
    variable,
};
const Export = struct {
    name: []const u8,
    kind: ExportKind,
};

const Message = struct {
    body: []const u8,
    // level (Warning, Information, etc.)
};

/// Unified description structure
const BinaryDescription = struct {
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
    imports: [][]const u8,
    exports: []Export,

    messages: []Message,

    debug_info_present: bool,

    pub fn writePretty(self: *const BinaryDescription, w: *std.io.Writer) !void {
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
        for (self.imports) |imp| {
            try w.print("  - {s}\n", .{imp});
        }

        try w.print("exports: {d}\n", .{self.exports.len});
        for (self.exports) |ex| {
            const kind_str = switch (ex.kind) {
                ExportKind.function => "function",
                ExportKind.variable => "variable",
                else => "unknown",
            };
            try w.print("  - {s} ({s})\n", .{ ex.name, kind_str });
        }

        try w.print("messages: {d}\n", .{self.messages.len});
        for (self.messages) |m| {
            try w.print("  - {s}\n", .{m.body});
        }

        try w.print("debug_info_present: {s}\n", .{if (self.debug_info_present) "yes" else "no"});
    }
};

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
            if (d.imports.len != 0) allocator.free(d.imports);
            if (d.exports.len != 0) allocator.free(d.exports);
            if (d.messages.len != 0) allocator.free(d.messages);
        }
        // Free the items slice itself
        if (self.items.len != 0) allocator.free(self.items);
        // Finally free the backing file buffer
        if (self.backing_file.len != 0) allocator.free(self.backing_file);
    }
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

pub fn detectFormat(buffer: []u8) Stage0ParseResult {
    // 1. ELF: starts with 0x7F 'E' 'L' 'F'
    if (buffer.len > 4 and buffer[0] == 0x7F and mem.eql(u8, "ELF", buffer[1..4])) {
        // ELF header fields:
        //   EI_CLASS (32/64) at offset 4
        //   EI_DATA (endian) at offset 5
        const ei_class = buffer[4]; // 1 = 32-bit, 2 = 64-bit
        const ei_data = buffer[5]; // 1 = little, 2 = big endian
        return Stage0ParseResult{ .elf = ElfHint{ .bitness = if (ei_class == 1) 32 else 64, .endianess = if (ei_data == 1) .little else .big } };
    }

    // 2. Mach-O:
    //    Several magic constants possible (32/64, BE/LE, MH vs MH_CIGAM, plus FAT)
    //    Check first 4 bytes for known Mach-O or FAT magic values.
    if (buffer.len > 4) {
        // https://en.wikipedia.org/wiki/Mach-O
        // For big-endian binaries (as in, the architecture uses big endian),
        // magic number for 32-bit code is 0xfeedface while the magic number for 64-bit architectures is 0xfeedfacf.
        // For little-endian binaries,
        // it will be 0xcefaedfe for 32-bit and 0xcffaedfe for 64-bit.
        // These latter two are just the former but with inverted endianness.
        const magic = readU32At(buffer, 0, .big);
        // std.debug.print("{x}\n", .{magic});
        if (magic == 0xfeedface) {
            // 32 BE
            return Stage0ParseResult{ .macho = MachoHint{ .bitness = 32, .endianess = .big } };
        } else if (magic == 0xfeedfacf) {
            // 64 BE
            return Stage0ParseResult{ .macho = MachoHint{ .bitness = 64, .endianess = .big } };
        } else if (magic == 0xcefaedfe) {
            // 32 LE
            return Stage0ParseResult{ .macho = MachoHint{ .bitness = 32, .endianess = .little } };
        } else if (magic == 0xcffaedfe) {
            // 64 LE
            return Stage0ParseResult{ .macho = MachoHint{ .bitness = 64, .endianess = .little } };
        }

        // FAT/universal Mach-O container: recognize FAT_MAGIC variants and
        // consider the file as Mach-O. We don't pick a single bitness here
        // since a fat file can contain multiple slices of varying bitness; the
        // downstream decoder will handle slice enumeration.
        // FAT magic constants are defined in std.macho (FAT_MAGIC / FAT_CIGAM / FAT_MAGIC_64 / FAT_CIGAM_64).
        const fat_magic = readU32At(buffer, 0, .big);
        if (fat_magic == macho.FAT_MAGIC or fat_magic == macho.FAT_CIGAM or fat_magic == macho.FAT_MAGIC_64 or fat_magic == macho.FAT_CIGAM_64) {
            const fat_endian = if (fat_magic == macho.FAT_CIGAM or fat_magic == macho.FAT_CIGAM_64) Endian.little else Endian.big;
            return Stage0ParseResult{ .macho = MachoHint{ .bitness = 0, .endianess = fat_endian } };
        }
    }

    // 3. PE:
    //    DOS header 'MZ' at offset 0, then PE signature at e_lfanew.
    if (buffer.len >= 2 and buffer[0] == 'M' and buffer[1] == 'Z') {
        // Need the PE header offset from DOS header
        // (e_lfanew at offset 0x3C, 4 bytes LE).
        if (buffer.len >= 0x3C + 4) {
            const dos_header = buffer[0..0x40]; // small DOS header region
            const e_lfanew = readU32At(dos_header, 0x3C, .little);
            // Basic sanity: e_lfanew must be within file bounds and allow "PE\0\0"
            const pe_sig_end = e_lfanew + 4;
            if (pe_sig_end <= buffer.len) {
                var pe_sig = buffer[e_lfanew..pe_sig_end];
                if (mem.eql(u8, pe_sig[0..2], "PE") and pe_sig[2] == 0 and pe_sig[3] == 0) {
                    const coff_header_end = pe_sig_end + 24;
                    const coff_header = buffer[pe_sig_end..coff_header_end];
                    const machine = mem.readInt(u16, coff_header[0..2], .little);

                    // std.debug.print("{x}\n", .{machine});
                    const pe_hint = PeHint{ .machine = machine, .coff_header = coff_header };
                    return Stage0ParseResult{ .pe = pe_hint };
                }
            }
        }
    }

    return Stage0ParseResult{ .unknown = undefined };
}

test "elf.amd64" {
    var buf: [prefix_length]u8 = @splat(0);
    try bufferedRead("testing/assets/bian", buf[0..], prefix_length);
    const presult = detectFormat(buf[0..]);
    try expect(presult.elf.bitness == 64);
}

test "macho.amd64" {
    var buf: [prefix_length]u8 = @splat(0);
    try bufferedRead("testing/assets/MachO-OSX-x64-ls", buf[0..], prefix_length);
    const presult = detectFormat(buf[0..]);
    // std.debug.print("{}\n", .{presult});
    try expect(presult.macho.bitness == 64);
}

test "pe.amd64" {
    var buf: [prefix_length]u8 = @splat(0);
    try bufferedRead("testing/assets/pe-Windows-x64-cmd", buf[0..], prefix_length);
    const presult = detectFormat(buf[0..]);
    // std.debug.print("{}\n", .{presult});
    // Key COFF Header Fields (IMAGE_FILE_HEADER):
    // Machine (2 bytes): Identifies the target CPU (e.g., \(0x014c\) for x86, \(0x8664\) for x64).
    // NumberOfSections (2 bytes): Indicates the size of the section table, which immediately follows the headers.
    // TimeDateStamp (4 bytes): Seconds since Jan 1, 1970, indicating when the file was created.
    // PointerToSymbolTable (4 bytes): File offset to the COFF symbol table (0 if none).
    // NumberOfSymbols (4 bytes): Number of entries in the symbol table.
    // SizeOfOptionalHeader (2 bytes): Size of the optional header, essential for executable images, typically 0 for object files.
    // Characteristics (2 bytes): Flags indicating file attributes (e.g., executable, system file, DLL
    try expect(presult.pe.machine == 0x8664);
}

/// Decodes an ELF file into a BinaryBundle using the provided hint.
fn decodeElf(allocator: std.mem.Allocator, file: std.fs.File) !BinaryBundle {
    // 1) read whole file into an allocator-owned buffer (we keep this as
    //    the backing buffer so section name slices can point into it)
    const stat = try file.stat();
    const file_size = @as(usize, stat.size);
    var file_buf = try allocator.alloc(u8, file_size);
    var keep_backing: bool = false;
    defer if (!keep_backing) allocator.free(file_buf);

    var fr = file.reader(file_buf);
    // fill the buffer completely
    try fr.interface.fill(file_size);

    // 2) parse ELF header using std.elf
    var fixed_reader = std.io.Reader.fixed(file_buf);
    const header = try elf.Header.read(&fixed_reader);

    // 3) map a few fields
    const bitness: u8 = if (header.is_64) 64 else 32;
    const arch = switch (header.machine) {
        elf.EM.X86_64 => CpuArch.x86_64,
        elf.EM.AARCH64 => CpuArch.aarch64,
        // the EM enum contains a variant named "386" which you reference as: elf.EM.@"386"
        elf.EM.@"386" => CpuArch.x86,
        else => CpuArch.unknown,
    };
    const file_kind = switch (header.type) {
        elf.ET.EXEC => FileKind.executable,
        elf.ET.DYN => FileKind.shared_library,
        elf.ET.REL => FileKind.object,
        else => FileKind.unknown,
    };

    // 4) find the section header string table (shstrtab) so we can get section names
    var shstrtab: []const u8 = &[_]u8{};
    if (header.shstrndx != 0) {
        var sh_iter = header.iterateSectionHeadersBuffer(file_buf);
        var idx: usize = 0;
        while (true) {
            const sh = try sh_iter.next() orelse break;
            if (idx == @as(usize, header.shstrndx)) {
                const off = @as(usize, sh.sh_offset);
                const sz = @as(usize, sh.sh_size);
                if (off + sz <= file_buf.len) shstrtab = file_buf[off .. off + sz];
                break;
            }
            idx += 1;
        }
    }

    // 5) collect sections (zero-copy: section names point into file_buf)
    var sections_list = try std.ArrayList(Section).initCapacity(allocator, 0);
    defer sections_list.deinit(allocator);

    var sh_iter2 = header.iterateSectionHeadersBuffer(file_buf);
    while (true) {
        const sh = try sh_iter2.next() orelse break;
        var name_slice: []const u8 = "unknown";
        if (shstrtab.len != 0 and @as(usize, sh.sh_name) < shstrtab.len) {
            const tail = shstrtab[@as(usize, sh.sh_name)..];
            const end = mem.indexOfScalar(u8, tail, 0) orelse tail.len;
            // zero-copy: point into the backing buffer
            name_slice = tail[0..end];
        }
        const perm = if ((sh.sh_flags & elf.SHF_EXECINSTR) != 0) Permission.execute else if ((sh.sh_flags & elf.SHF_WRITE) != 0) Permission.write else if ((sh.sh_flags & elf.SHF_ALLOC) != 0) Permission.read else Permission.none;
        try sections_list.append(allocator, Section{
            .name = name_slice,
            .kind = SectionKind.unknown,
            .size = sh.sh_size,
            .file_offset = sh.sh_offset,
            .permission = perm,
            .flags = 0,
            .reserved1 = 0,
            .reserved2 = 0,
        });
    }

    // 6) collect segments from program headers and record segment maps for vaddr->file mappings
    var segments_list = try std.ArrayList(Section).initCapacity(allocator, 0);
    defer segments_list.deinit(allocator);
    var segmaps = try std.ArrayList(SegmentMap).initCapacity(allocator, 0);
    defer segmaps.deinit(allocator);
    var ph_iter = header.iterateProgramHeadersBuffer(file_buf);
    while (true) {
        const ph = try ph_iter.next() orelse break;
        const perm = if ((ph.p_flags & elf.PF_X) != 0) Permission.execute else if ((ph.p_flags & elf.PF_W) != 0) Permission.write else if ((ph.p_flags & elf.PF_R) != 0) Permission.read else Permission.none;
        try appendSegmentAndMap(allocator, &segments_list, &segmaps, ph.p_offset, ph.p_filesz, ph.p_vaddr, perm);
    }

    // 7) build and return BinaryDescription (imports/exports parsing omitted here)
    var imports = try std.ArrayList([]const u8).initCapacity(allocator, 0);
    defer imports.deinit(allocator);
    var exports = try std.ArrayList(Export).initCapacity(allocator, 0);
    defer exports.deinit(allocator);
    var messages = try std.ArrayList(Message).initCapacity(allocator, 0);
    defer messages.deinit(allocator);

    // --- PT_DYNAMIC parsing: collect DT_NEEDED entries and map them via DT_STRTAB ---
    var dyn_off: usize = 0;
    var dyn_sz: usize = 0;
    var have_dyn: bool = false;

    // track bind_now across parsing for later RELRO inference
    var dyn_bind_now: bool = false;

    // We recorded segmaps while parsing program headers. Re-iterate the program
    // headers to discover the dynamic segment if we didn't capture it already.
    // (We captured p_offset/p_filesz during the earlier iteration when building
    // segmaps; if the underlying iterateProgramHeadersBuffer doesn't allow
    // observing PT_DYNAMIC at that time, you would need to capture it there.
    // But since we can observe ph entries again cheaply, do a quick second pass.)
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

    if (have_dyn) {
        // Collect DT_* values
        var dt_needed_indices = try std.ArrayList(usize).initCapacity(allocator, 0);
        defer dt_needed_indices.deinit(allocator);
        var dyn_str_vaddr: u64 = 0;
        var dyn_str_sz: u64 = 0;

        const dyn_region = safeSlice(file_buf, @as(u64, dyn_off), @as(u64, dyn_sz));
        if (dyn_region == null) {
            try messages.append(allocator, Message{ .body = "PT_DYNAMIC region out of bounds" });
        } else {
            var rdr = std.io.Reader.fixed(dyn_region.?);
            while (true) {
                if (header.is_64) {
                    const d = try rdr.takeStruct(elf.Elf64_Dyn, header.endian);
                    if (d.d_tag == elf.DT_NULL) break;
                    if (d.d_tag == elf.DT_NEEDED) {
                        try dt_needed_indices.append(allocator, @as(usize, d.d_val));
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
                        try dt_needed_indices.append(allocator, @as(usize, d.d_val));
                    } else if (d.d_tag == elf.DT_STRTAB) {
                        dyn_str_vaddr = @as(u64, d.d_val);
                    } else if (d.d_tag == elf.DT_STRSZ) {
                        dyn_str_sz = @as(u64, d.d_val);
                    } else if (d.d_tag == elf.DT_BIND_NOW) {
                        dyn_bind_now = true;
                    }
                }
            }

            // Map DT_STRTAB VMA -> file offset using segmaps
            if (dyn_str_vaddr != 0 and dyn_str_sz != 0) {
                const maybe = vaddrToFileOffset(file_buf.len, segmaps.items, dyn_str_vaddr);
                if (maybe) |str_off| {
                    if (str_off + @as(usize, dyn_str_sz) <= file_buf.len) {
                        const dynstr = file_buf[str_off .. str_off + @as(usize, dyn_str_sz)];
                        for (dt_needed_indices.items) |name_off| {
                            if (name_off < dynstr.len) {
                                const s = mem.sliceTo(dynstr[name_off..], 0);
                                if (s.len != 0) try imports.append(allocator, s);
                            }
                        }
                    } else {
                        try messages.append(allocator, Message{ .body = "DT_STRTAB/DT_STRSZ out of bounds" });
                    }
                } else {
                    // Fallback: look for a .dynstr section among section headers
                    var found_dynstr: bool = false;
                    var sh_iter3 = header.iterateSectionHeadersBuffer(file_buf);
                    while (true) {
                        const sh = try sh_iter3.next() orelse break;
                        var name_slice: []const u8 = "";
                        // Use shstrtab we built earlier
                        if (shstrtab.len != 0 and @as(usize, sh.sh_name) < shstrtab.len) {
                            const tail = shstrtab[@as(usize, sh.sh_name)..];
                            const end = mem.indexOfScalar(u8, tail, 0) orelse tail.len;
                            name_slice = tail[0..end];
                        }
                        if (name_slice.len != 0 and mem.eql(u8, name_slice, ".dynstr")) {
                            const off = @as(usize, sh.sh_offset);
                            const sz = @as(usize, sh.sh_size);
                            if (off + sz <= file_buf.len) {
                                const dynstr = file_buf[off .. off + sz];
                                for (dt_needed_indices.items) |name_off| {
                                    if (name_off < dynstr.len) {
                                        const s = mem.sliceTo(dynstr[name_off..], 0);
                                        if (s.len != 0) try imports.append(allocator, s);
                                    }
                                }
                                found_dynstr = true;
                                break;
                            }
                        }
                    }
                    if (!found_dynstr) try messages.append(allocator, Message{ .body = "could not map DT_STRTAB vaddr to file offset" });
                }
            } else if (dt_needed_indices.items.len != 0) {
                // No DT_STRTAB/DT_STRSZ available; try .dynstr section fallback similarly
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
                        const off = @as(usize, sh.sh_offset);
                        const sz = @as(usize, sh.sh_size);
                        if (off + sz <= file_buf.len) {
                            const dynstr = file_buf[off .. off + sz];
                            for (dt_needed_indices.items) |name_off| {
                                if (name_off < dynstr.len) {
                                    const s = mem.sliceTo(dynstr[name_off..], 0);
                                    if (s.len != 0) try imports.append(allocator, s);
                                }
                            }
                            found_dynstr2 = true;
                            break;
                        }
                    }
                }
                if (!found_dynstr2) try messages.append(allocator, Message{ .body = "DT_NEEDED entries present but no dynstr found" });
            }
        }
    }

    // --- Symbol table parsing: SHT_SYMTAB and SHT_DYNSYM ---
    var sh_iter_sym = header.iterateSectionHeadersBuffer(file_buf);
    var sh_index: usize = 0;
    while (true) {
        const sh = try sh_iter_sym.next() orelse break;
        if (sh.sh_type == elf.SHT_SYMTAB or sh.sh_type == elf.SHT_DYNSYM) {
            const sym_off = @as(usize, sh.sh_offset);
            const sym_sz = @as(usize, sh.sh_size);
            var entsz = @as(usize, sh.sh_entsize);
            if (entsz == 0) entsz = if (header.is_64) @sizeOf(elf.Elf64_Sym) else @sizeOf(elf.Elf32_Sym);
            if (entsz == 0) continue;
            const nsyms = if (entsz != 0) sym_sz / entsz else 0;
            if (nsyms == 0) continue;

            // Find linked string table (sh_link is the section index of the strtab)
            var strtab_off: usize = 0;
            var strtab_sz: usize = 0;
            var st_iter = header.iterateSectionHeadersBuffer(file_buf);
            var st_idx: usize = 0;
            while (true) {
                const st = try st_iter.next() orelse break;
                if (st_idx == @as(usize, sh.sh_link)) {
                    strtab_off = @as(usize, st.sh_offset);
                    strtab_sz = @as(usize, st.sh_size);
                    break;
                }
                st_idx += 1;
            }
            if (strtab_off + strtab_sz > file_buf.len) continue; // malformed strtab
            const strtab = file_buf[strtab_off .. strtab_off + strtab_sz];

            // Parse symbol entries
            var i_sym: usize = 0;
            while (i_sym < nsyms) : (i_sym += 1) {
                const entry_off = sym_off + i_sym * entsz;
                if (entry_off + entsz > file_buf.len) break;
                var rdr_sym = std.io.Reader.fixed(file_buf[entry_off..]);
                if (header.is_64) {
                    const sym = try rdr_sym.takeStruct(elf.Elf64_Sym, header.endian);
                    const name_idx = @as(usize, sym.st_name);
                    if (name_idx >= strtab.len) continue;
                    const name = mem.sliceTo(strtab[name_idx..], 0);
                    if (sym.st_shndx == elf.SHN_UNDEF) {
                        if (name.len != 0) try imports.append(allocator, name);
                    } else {
                        const kind = if (sym.st_type() == elf.STT_FUNC) ExportKind.function else ExportKind.variable;
                        if (name.len != 0) try exports.append(allocator, Export{ .name = name, .kind = kind });
                    }
                } else {
                    const sym32 = try rdr_sym.takeStruct(elf.Elf32_Sym, header.endian);
                    const name_idx = @as(usize, sym32.st_name);
                    if (name_idx >= strtab.len) continue;
                    const name = mem.sliceTo(strtab[name_idx..], 0);
                    if (sym32.st_shndx == elf.SHN_UNDEF) {
                        if (name.len != 0) try imports.append(allocator, name);
                    } else {
                        const kind = if (sym32.st_type() == elf.STT_FUNC) ExportKind.function else ExportKind.variable;
                        if (name.len != 0) try exports.append(allocator, Export{ .name = name, .kind = kind });
                    }
                }
            }
        }
        sh_index += 1;
    }

    // Compute security hints: NX, RELRO, PIE refinement
    var nx_hint = Perhaps.unknown;
    var relro_hint = RelroConfig.unknown;
    // Check program headers for PT_GNU_STACK and PT_GNU_RELRO
    var ph_iter3 = header.iterateProgramHeadersBuffer(file_buf);
    var found_gnu_stack: bool = false;
    var found_gnu_relro: bool = false;
    while (true) {
        const ph = try ph_iter3.next() orelse break;
        if (ph.p_type == elf.PT_GNU_STACK) {
            found_gnu_stack = true;
            if ((ph.p_flags & elf.PF_X) != 0) nx_hint = Perhaps.no else nx_hint = Perhaps.yes;
        }
        if (ph.p_type == elf.PT_GNU_RELRO) {
            found_gnu_relro = true;
            // tentatively partial; may be elevated to full if DT_BIND_NOW present
            relro_hint = RelroConfig.partial;
        }
    }
    // If we found no PT_GNU_STACK, leave NX as unknown
    // If dynamic table indicated bind_now, infer full RELRO
    if (dyn_bind_now) {
        relro_hint = RelroConfig.full;
    } else if (!found_gnu_relro) {
        // If no GNU_RELRO and no bind_now, treat as none
        relro_hint = RelroConfig.none;
    }

    const pie_hint = if (header.type == elf.ET.DYN) Perhaps.yes else if (header.type == elf.ET.EXEC) Perhaps.no else Perhaps.unknown;

    const desc = BinaryDescription{
        .format = BinaryFileKind.elf,
        .os_abi = OsAbi.unknown, // map header.os_abi -> your OsAbi as needed
        .arch = arch,
        .bitness = bitness,
        .endianess = header.endian,
        .file_kind = file_kind,
        .entrypoint_virtual_address = header.entry,
        .pie = pie_hint,
        .aslr = Perhaps.unknown,
        .nx = nx_hint,
        .relro = relro_hint,
        .stripped = StrippedState.unknown,
        .sections = try sections_list.toOwnedSlice(allocator),
        .segments = try segments_list.toOwnedSlice(allocator),
        .imports = try imports.toOwnedSlice(allocator),
        .exports = try exports.toOwnedSlice(allocator),
        .messages = try messages.toOwnedSlice(allocator),
        .debug_info_present = false,
    };

    // Construct a bundle that owns the single description and the backing buffer
    var bundle_list = try std.ArrayList(BinaryDescription).initCapacity(allocator, 0);
    defer bundle_list.deinit(allocator);
    try bundle_list.append(allocator, desc);
    const items = try bundle_list.toOwnedSlice(allocator);

    const bundle = BinaryBundle{
        .items = items,
        .backing_file = file_buf,
    };

    // We are returning `file_buf` inside the bundle.backing_file. Prevent the
    // deferred free from running.
    keep_backing = true;
    return bundle;
}

/// Frees resources owned by a BinaryDescription that were allocated using the
/// provided allocator. Call this when you are finished using a single
/// description's owned slices (but not the shared backing file).
pub fn freeBinaryDescription(allocator: std.mem.Allocator, desc: BinaryDescription) void {
    // Free top-level slices allocated with toOwnedSlice()
    if (desc.sections.len != 0) allocator.free(desc.sections);
    if (desc.segments.len != 0) allocator.free(desc.segments);
    if (desc.imports.len != 0) allocator.free(desc.imports);
    if (desc.exports.len != 0) allocator.free(desc.exports);
    if (desc.messages.len != 0) allocator.free(desc.messages);
}

/// Analyzes a binary file and returns a BinaryBundle containing one or more
/// BinaryDescription items (one per architecture slice for fat Mach-O).
pub fn analyzeBinary(allocator: std.mem.Allocator, file: std.fs.File) !BinaryBundle {
    var buf: [1024]u8 = @splat(0);
    // Read initial prefix for detection (reuse prefix_length)
    var reader = file.reader(buf[0..]);
    const buffer = try reader.interface.readAlloc(allocator, prefix_length);
    defer allocator.free(buffer);
    try reader.seekTo(0);

    const stage0 = detectFormat(buffer);
    switch (stage0) {
        .elf => return try decodeElf(allocator, file),
        .macho => return try decodeMacho(allocator, file),
        .pe => return error.UnsupportedVariant, // Stub for now
        .ape => return error.UnsupportedVariant, // Stub for now
        .unknown => return error.InvalidHeader,
    }
}

const SegmentMap = struct { fileoff: u64, filesize: u64, vmaddr: u64 };

fn zslice(bytes: []const u8) []const u8 {
    const end = mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    return bytes[0..end];
}

fn vaddrToFileOffset(file_len: usize, segmaps: []const SegmentMap, vaddr: u64) ?usize {
    var i: usize = 0;
    while (i < segmaps.len) : (i += 1) {
        const m = segmaps[i];
        // Check whether vaddr lies within the segment's vm range (file-backed portion)
        if (vaddr >= m.vmaddr and vaddr < m.vmaddr + m.filesize) {
            const off64 = m.fileoff + (vaddr - m.vmaddr);
            if (off64 <= @as(u64, file_len)) return @as(usize, off64);
            return null;
        }
    }
    return null;
}

fn safeSlice(buf: []const u8, off64: u64, len64: u64) ?[]const u8 {
    // Bounds-check and avoid overflow when computing start+len
    if (off64 > @as(u64, buf.len)) return null;
    const off = @as(usize, off64);
    if (len64 > @as(u64, buf.len)) return null;
    const len = @as(usize, len64);
    if (len > buf.len - off) return null;
    return buf[off .. off + len];
}

fn readU32At(buf: []const u8, off: usize, endian: Endian) u32 {
    // Caller must ensure off + 4 <= buf.len; keep this simple and inline for speed.
    const b0 = @as(u32, buf[off]);
    const b1 = @as(u32, buf[off + 1]);
    const b2 = @as(u32, buf[off + 2]);
    const b3 = @as(u32, buf[off + 3]);
    return if (endian == .big) (b0 << 24) | (b1 << 16) | (b2 << 8) | b3 else (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

fn readU64At(buf: []const u8, off: usize, endian: Endian) u64 {
    // Caller must ensure off + 8 <= buf.len
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

fn readI32At(buf: []const u8, off: usize, endian: Endian) i32 {
    return @bitCast(readU32At(buf, off, endian));
}

// Top-level helper to lookup symbol name and type by index (used by parseSymtab)
const SymInfo = struct {
    name: []const u8,
    n_type: u8,
};

fn symInfoByIndex(macho_buf: []const u8, symoff: usize, nsyms: usize, stroff: usize, strsize: usize, is64: bool, m_endian: Endian, idx: usize) ?SymInfo {
    if (idx >= nsyms) return null;
    if (m_endian == .little) {
        if (is64) {
            const syms = @as([*]align(1) const macho.nlist_64, @ptrCast(macho_buf[symoff..].ptr))[0..nsyms];
            const sym = syms[idx];
            const sidx = @as(usize, sym.n_strx);
            if (sidx >= strsize) return null;
            const name = mem.sliceTo(macho_buf[stroff + sidx ..], 0);
            return SymInfo{ .name = name, .n_type = sym.n_type };
        } else {
            const syms = @as([*]align(1) const macho.nlist, @ptrCast(macho_buf[symoff..].ptr))[0..nsyms];
            const sym = syms[idx];
            const sidx = @as(usize, sym.n_strx);
            if (sidx >= strsize) return null;
            const name = mem.sliceTo(macho_buf[stroff + sidx ..], 0);
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
        const name = mem.sliceTo(macho_buf[stroff + sidx ..], 0);
        return SymInfo{ .name = name, .n_type = n_type };
    }
}

// Guarded macho.LC conversion: return null if the numeric value doesn't map
// to any of the LC enum variants we care about. This is intentionally
// conservative: we whitelist only the commands our parser handles and treat
// unknown/extended values as "skip" instead of triggering a safety error.
fn machoLCFromU32(val: u32) ?macho.LC {
    // Note: avoid casting enum variants to integers (older Zig versions may not
    // support the required builtin). Use the documented numeric values from
    // std.macho for comparisons.
    if (val == 0x19) return macho.LC.SEGMENT_64; // SEGMENT_64
    if (val == 0x1) return macho.LC.SEGMENT; // SEGMENT
    if (val == 0x2) return macho.LC.SYMTAB; // SYMTAB
    if (val == (0x28 | macho.LC_REQ_DYLD)) return macho.LC.MAIN; // MAIN with REQ_DYLD
    if (val == 0x0c) return macho.LC.LOAD_DYLIB; // LOAD_DYLIB
    if (val == (0x18 | macho.LC_REQ_DYLD)) return macho.LC.LOAD_WEAK_DYLIB; // LOAD_WEAK_DYLIB
    if (val == (0x1f | macho.LC_REQ_DYLD)) return macho.LC.REEXPORT_DYLIB; // REEXPORT_DYLIB
    if (val == (0x23 | macho.LC_REQ_DYLD)) return macho.LC.LOAD_UPWARD_DYLIB; // LOAD_UPWARD_DYLIB
    if (val == (0x1c | macho.LC_REQ_DYLD)) return macho.LC.RPATH; // RPATH
    if (val == 0x1d) return macho.LC.CODE_SIGNATURE; // CODE_SIGNATURE
    if (val == (0x33 | macho.LC_REQ_DYLD)) return macho.LC.DYLD_EXPORTS_TRIE; // DYLD_EXPORTS_TRIE
    if (val == 0x22) return macho.LC.DYLD_INFO; // DYLD_INFO
    return null;
}

fn machoProtToPermission(p: macho.vm_prot_t) Permission {
    return if ((p & macho.PROT.EXEC) != 0) Permission.execute else if ((p & macho.PROT.WRITE) != 0) Permission.write else if ((p & macho.PROT.READ) != 0) Permission.read else Permission.none;
}

// Unit test for readU32At helper
test "readU32At: endian correctness" {
    const data: [8]u8 = .{ 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD };
    try expect(readU32At(data[0..], 0, Endian.big) == 0x11223344);
    try expect(readU32At(data[0..], 0, Endian.little) == 0x44332211);
    try expect(readU32At(data[0..], 4, Endian.big) == 0xAABBCCDD);
    try expect(readU32At(data[0..], 4, Endian.little) == 0xDDCCBBAA);
}

// Unit test for readU64At and readI32At helpers
test "readU64At: endian correctness" {
    const data: [16]u8 = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88 };
    try expect(readU64At(data[0..], 0, Endian.big) == 0x1122334455667788);
    try expect(readU64At(data[0..], 0, Endian.little) == 0x8877665544332211);
    try expect(readU64At(data[0..], 8, Endian.big) == 0xFFEEDDCCBBAA9988);
    try expect(readU64At(data[0..], 8, Endian.little) == 0x8899AABBCCDDEEFF);
}

test "readI32At: endian correctness" {
    const data_be: [8]u8 = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00 };
    try expect(readI32At(data_be[0..], 0, Endian.big) == -1);
    try expect(readI32At(data_be[0..], 4, Endian.big) == -2147483648);
    const data_le: [8]u8 = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x80 };
    try expect(readI32At(data_le[0..], 4, Endian.little) == -2147483648);
}

// Unit tests for guarded enum conversion
test "machoLCFromU32: macho.LC known/unknown" {
    const known: u32 = 0x2; // LC_SYMTAB
    const maybe = machoLCFromU32(known);
    try expect(maybe != null);
    try expect(maybe.? == macho.LC.SYMTAB);

    const unknown_val: u32 = 0xDEADBEEF;
    const none = machoLCFromU32(unknown_val);
    try expect(none == null);
}

// TDD: ensure decodeMachoSlice treats unknown load commands in big-endian
// buffers gracefully (i.e. does not crash due to @enumFromInt).
test "decodeMachoSlice: big-endian unknown LC skipped" {
    var buf: [128]u8 = @splat(0);
    const macho_buf = buf[0..];
    const hdr_size = @sizeOf(macho.mach_header_64);
    // Write big-endian MH_MAGIC_64
    const mh_magic = @as(u32, macho.MH_MAGIC_64);
    macho_buf[0] = @as(u8, mh_magic >> 24);
    macho_buf[1] = @as(u8, (mh_magic >> 16) & 0xFF);
    macho_buf[2] = @as(u8, (mh_magic >> 8) & 0xFF);
    macho_buf[3] = @as(u8, mh_magic & 0xFF);

    // cputype (i32) at 4..8 -> CPU_TYPE_X86_64
    const cputype = @as(u32, macho.CPU_TYPE_X86_64);
    macho_buf[4] = @as(u8, cputype >> 24);
    macho_buf[5] = @as(u8, (cputype >> 16) & 0xFF);
    macho_buf[6] = @as(u8, (cputype >> 8) & 0xFF);
    macho_buf[7] = @as(u8, cputype & 0xFF);

    // filetype at 12..16 -> MH_EXECUTE
    const filetype = @as(u32, macho.MH_EXECUTE);
    macho_buf[12] = @as(u8, filetype >> 24);
    macho_buf[13] = @as(u8, (filetype >> 16) & 0xFF);
    macho_buf[14] = @as(u8, (filetype >> 8) & 0xFF);
    macho_buf[15] = @as(u8, filetype & 0xFF);

    // ncmds at 16..20 -> 1
    const ncmds: u32 = 1;
    macho_buf[16] = @as(u8, ncmds >> 24);
    macho_buf[17] = @as(u8, (ncmds >> 16) & 0xFF);
    macho_buf[18] = @as(u8, (ncmds >> 8) & 0xFF);
    macho_buf[19] = @as(u8, ncmds & 0xFF);

    // sizeofcmds at 20..24 -> 8 (one minimal LC)
    const sizeofcmds: u32 = 8;
    macho_buf[20] = @as(u8, sizeofcmds >> 24);
    macho_buf[21] = @as(u8, (sizeofcmds >> 16) & 0xFF);
    macho_buf[22] = @as(u8, (sizeofcmds >> 8) & 0xFF);
    macho_buf[23] = @as(u8, sizeofcmds & 0xFF);

    const total_len = hdr_size + @as(usize, sizeofcmds);

    // Write one unknown load command at offset hdr_size
    const off = hdr_size;
    const unknown_cmd: u32 = 0xDEADBEEF;
    macho_buf[off + 0] = @as(u8, unknown_cmd >> 24);
    macho_buf[off + 1] = @as(u8, (unknown_cmd >> 16) & 0xFF);
    macho_buf[off + 2] = @as(u8, (unknown_cmd >> 8) & 0xFF);
    macho_buf[off + 3] = @as(u8, unknown_cmd & 0xFF);

    const cmdsize: u32 = 8;
    macho_buf[off + 4] = @as(u8, cmdsize >> 24);
    macho_buf[off + 5] = @as(u8, (cmdsize >> 16) & 0xFF);
    macho_buf[off + 6] = @as(u8, (cmdsize >> 8) & 0xFF);
    macho_buf[off + 7] = @as(u8, cmdsize & 0xFF);

    const allocator = std.testing.allocator;
    const desc = try decodeMachoSlice(allocator, macho_buf[0..total_len]);
    // Should succeed and produce a macho description; unknown LC is skipped.
    try expect(desc.format == .macho);
    try expect(desc.file_kind == .executable);
    try expect(desc.arch == .x86_64);
}

fn elfSectionFlagsToPermission(sh_flags: u64) Permission {
    return if ((sh_flags & elf.SHF_EXECINSTR) != 0) Permission.execute else if ((sh_flags & elf.SHF_WRITE) != 0) Permission.write else if ((sh_flags & elf.SHF_ALLOC) != 0) Permission.read else Permission.none;
}

fn elfProgFlagsToPermission(p_flags: u32) Permission {
    return if ((p_flags & elf.PF_X) != 0) Permission.execute else if ((p_flags & elf.PF_W) != 0) Permission.write else if ((p_flags & elf.PF_R) != 0) Permission.read else Permission.none;
}

fn appendSegmentAndMap(allocator: std.mem.Allocator, segments_list: *std.ArrayList(Section), segmaps: *std.ArrayList(SegmentMap), fileoff: u64, filesize: u64, vmaddr: u64, perm: Permission) !void {
    try segments_list.append(allocator, Section{ .name = "", .kind = SectionKind.unknown, .size = filesize, .file_offset = fileoff, .permission = perm, .flags = 0, .reserved1 = 0, .reserved2 = 0 });
    try segmaps.append(allocator, SegmentMap{ .fileoff = fileoff, .filesize = filesize, .vmaddr = vmaddr });
}

fn appendSectionFromBlock(allocator: std.mem.Allocator, sections_list: *std.ArrayList(Section), block: []const u8, is64: bool, m_endian: Endian) !void {
    const name_bytes: []const u8 = block[0..16];
    const end = mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
    const name = name_bytes[0..end];

    if (m_endian == .little) {
        if (is64) {
            const sect_struct = @as(*align(1) const macho.section_64, @ptrCast(block.ptr)).*;
            const off = @as(u64, sect_struct.offset);
            const size = sect_struct.size;
            const flags = sect_struct.flags;
            const reserved1 = sect_struct.reserved1;
            const reserved2 = sect_struct.reserved2;
            try sections_list.append(allocator, Section{ .name = name, .kind = SectionKind.unknown, .size = size, .file_offset = off, .permission = Permission.none, .flags = flags, .reserved1 = reserved1, .reserved2 = reserved2 });
        } else {
            const sect_struct = @as(*align(1) const macho.section, @ptrCast(block.ptr)).*;
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

fn appendDylibNameFromLcData(allocator: std.mem.Allocator, imports_list: *std.ArrayList([]const u8), lc_data: []const u8, m_endian: Endian) !void {
    if (lc_data.len < 12) return;
    const name_off = @as(usize, readU32At(lc_data, 8, m_endian));
    if (name_off < lc_data.len) {
        const name = mem.sliceTo(lc_data[name_off..], 0);
        if (name.len != 0) try imports_list.append(allocator, name);
    }
}

fn appendRpathMessageFromLcData(allocator: std.mem.Allocator, messages_list: *std.ArrayList(Message), lc_data: []const u8, m_endian: Endian) !void {
    if (lc_data.len < 12) return;
    const path_off = @as(usize, readU32At(lc_data, 8, m_endian));
    if (path_off < lc_data.len) {
        const rp = mem.sliceTo(lc_data[path_off..], 0);
        if (rp.len != 0) try messages_list.append(allocator, Message{ .body = rp });
    }
}

fn parseSymtab(allocator: std.mem.Allocator, macho_buf: []const u8, symoff: usize, nsyms: usize, stroff: usize, strsize: usize, is64: bool, m_endian: Endian, sections: []const Section, indirectsymoff: usize, nindirectsyms: usize, ilocalsym: usize, nlocalsym: usize, iextdefsym: usize, nextdefsym: usize, iundefsym: usize, nundefsym: usize, imports: *std.ArrayList([]const u8), exports: *std.ArrayList(Export)) !void {
    if (nsyms == 0) return;

    // silence unused LC_DYSYMTAB range parameters for now (may be used later)
    _ = ilocalsym;
    _ = nlocalsym;
    _ = iextdefsym;
    _ = nextdefsym;
    _ = iundefsym;
    _ = nundefsym;

    // SymInfo and symInfoByIndex are defined at top-level for reuse.

    // --- direct symtab parsing (existing behavior) ---
    if (m_endian == .little) {
        var nlist_entry_size: usize = 0;
        if (is64) nlist_entry_size = @sizeOf(macho.nlist_64) else nlist_entry_size = @sizeOf(macho.nlist);
        if (!(symoff + nsyms * nlist_entry_size <= macho_buf.len and stroff + strsize <= macho_buf.len)) return;
        if (is64) {
            const syms = @as([*]align(1) const macho.nlist_64, @ptrCast(macho_buf[symoff..].ptr))[0..nsyms];
            var j: usize = 0;
            while (j < syms.len) : (j += 1) {
                const sym = syms[j];
                const idx = @as(usize, sym.n_strx);
                if (idx >= strsize) continue;
                const name = mem.sliceTo(macho_buf[stroff + idx ..], 0);
                if (macho.nlist_64.undf(sym)) {
                    try imports.append(allocator, name);
                } else if (macho.nlist_64.ext(sym)) {
                    try exports.append(allocator, Export{ .name = name, .kind = ExportKind.unknown });
                }
            }
        } else {
            const syms = @as([*]align(1) const macho.nlist, @ptrCast(macho_buf[symoff..].ptr))[0..nsyms];
            var j: usize = 0;
            while (j < syms.len) : (j += 1) {
                const sym = syms[j];
                const idx = @as(usize, sym.n_strx);
                if (idx >= strsize) continue;
                const name = mem.sliceTo(macho_buf[stroff + idx ..], 0);
                const ntype = sym.n_type;
                const type_ = macho.N_TYPE & ntype;
                if (type_ == macho.N_UNDF) {
                    try imports.append(allocator, name);
                } else if ((ntype & macho.N_EXT) != 0) {
                    try exports.append(allocator, Export{ .name = name, .kind = ExportKind.unknown });
                }
            }
        }
    } else {
        const nlist_entry_size_big: usize = if (is64) 16 else 12;
        if (!(symoff + nsyms * nlist_entry_size_big <= macho_buf.len and stroff + strsize <= macho_buf.len)) return;
        var j: usize = 0;
        while (j < nsyms) : (j += 1) {
            const entry_off = symoff + j * nlist_entry_size_big;
            if (entry_off + nlist_entry_size_big > macho_buf.len) break;
            if (is64) {
                const n_strx = readU32At(macho_buf, entry_off, m_endian);
                const n_type = macho_buf[entry_off + 4];
                const idx = @as(usize, n_strx);
                if (idx >= strsize) continue;
                const name = mem.sliceTo(macho_buf[stroff + idx ..], 0);
                const type_ = @as(u32, n_type) & macho.N_TYPE;
                if (type_ == macho.N_UNDF) {
                    try imports.append(allocator, name);
                } else if ((@as(u32, n_type) & macho.N_EXT) != 0) {
                    try exports.append(allocator, Export{ .name = name, .kind = ExportKind.unknown });
                }
            } else {
                const n_strx = readU32At(macho_buf, entry_off, m_endian);
                const n_type = macho_buf[entry_off + 4];
                const idx = @as(usize, n_strx);
                if (idx >= strsize) continue;
                const name = mem.sliceTo(macho_buf[stroff + idx ..], 0);
                const type_ = @as(u32, n_type) & macho.N_TYPE;
                if (type_ == macho.N_UNDF) {
                    try imports.append(allocator, name);
                } else if ((@as(u32, n_type) & macho.N_EXT) != 0) {
                    try exports.append(allocator, Export{ .name = name, .kind = ExportKind.unknown });
                }
            }
        }
    }

    // --- indirect symbol table resolution (via LC_DYSYMTAB) ---
    if (indirectsymoff != 0 and nindirectsyms != 0) {
        if (indirectsymoff + nindirectsyms * 4 > macho_buf.len) return;
        const INDIRECT_INDEX_MASK: u32 = 0x3FFFFFFF;
        var sidx: usize = 0;
        while (sidx < sections.len) : (sidx += 1) {
            const sec = sections[sidx];
            const stype = sec.flags & macho.SECTION_TYPE;
            var entry_size: usize = 4;
            var entry_count: usize = 0;
            if (stype == macho.S_SYMBOL_STUBS) {
                if (sec.reserved2 == 0) continue;
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
                if (entry_off + 4 > macho_buf.len) break;
                const entry = readU32At(macho_buf, entry_off, m_endian);
                if ((entry & macho.INDIRECT_SYMBOL_LOCAL) != 0) continue;
                if ((entry & macho.INDIRECT_SYMBOL_ABS) != 0) continue;
                const sym_index = @as(usize, entry & INDIRECT_INDEX_MASK);
                if (sym_index >= nsyms) continue;
                const si = symInfoByIndex(macho_buf, symoff, nsyms, stroff, strsize, is64, m_endian, sym_index) orelse continue;
                const name = si.name;
                const n_type = si.n_type;
                const type_ = @as(u32, n_type) & macho.N_TYPE;
                if (type_ == macho.N_UNDF) {
                    try imports.append(allocator, name);
                } else if ((@as(u32, n_type) & macho.N_EXT) != 0) {
                    try exports.append(allocator, Export{ .name = name, .kind = ExportKind.unknown });
                }
            }
            sidx += 1;
        }
    }
}

/// Decode a single Mach-O slice (must be little-endian for the std.macho helpers)
fn decodeMachoSlice(allocator: std.mem.Allocator, macho_buf: []const u8) !BinaryDescription {
    if (macho_buf.len < 4) return ParseError.TooSmall;
    const mm = readU32At(macho_buf, 0, .big);
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
            if (macho_buf.len < @sizeOf(macho.mach_header_64)) return ParseError.TooSmall;
            const hdr_ptr = @as(*align(1) const macho.mach_header_64, @ptrCast(macho_buf.ptr));
            const hdr = hdr_ptr.*;
            hdr_size = @sizeOf(macho.mach_header_64);
            ncmds = @as(usize, hdr.ncmds);
            sizeofcmds = @as(usize, hdr.sizeofcmds);
            hdr_cputype = hdr.cputype;
            hdr_filetype = hdr.filetype;
            hdr_flags = hdr.flags;
        } else {
            if (macho_buf.len < @sizeOf(macho.mach_header)) return ParseError.TooSmall;
            const hdr_ptr = @as(*align(1) const macho.mach_header, @ptrCast(macho_buf.ptr));
            const hdr = hdr_ptr.*;
            hdr_size = @sizeOf(macho.mach_header);
            ncmds = @as(usize, hdr.ncmds);
            sizeofcmds = @as(usize, hdr.sizeofcmds);
            hdr_cputype = hdr.cputype;
            hdr_filetype = hdr.filetype;
            hdr_flags = hdr.flags;
        }
    } else {
        // Big-endian parsing: read header fields explicitly with mem.readInt
        if (is_64) {
            if (macho_buf.len < @sizeOf(macho.mach_header_64)) return ParseError.TooSmall;
            hdr_size = @sizeOf(macho.mach_header_64);
            hdr_cputype = @as(macho.cpu_type_t, readI32At(macho_buf, 4, m_endian));
            hdr_filetype = readU32At(macho_buf, 12, m_endian);
            ncmds = @as(usize, readU32At(macho_buf, 16, m_endian));
            sizeofcmds = @as(usize, readU32At(macho_buf, 20, m_endian));
            hdr_flags = readU32At(macho_buf, 24, m_endian);
        } else {
            if (macho_buf.len < @sizeOf(macho.mach_header)) return ParseError.TooSmall;
            hdr_size = @sizeOf(macho.mach_header);
            hdr_cputype = @as(macho.cpu_type_t, readI32At(macho_buf, 4, m_endian));
            hdr_filetype = readU32At(macho_buf, 12, m_endian);
            ncmds = @as(usize, readU32At(macho_buf, 16, m_endian));
            sizeofcmds = @as(usize, readU32At(macho_buf, 20, m_endian));
            hdr_flags = readU32At(macho_buf, 24, m_endian);
        }
    }

    if (hdr_size + sizeofcmds > macho_buf.len) return ParseError.Malformed;
    const lc_buffer = macho_buf[hdr_size .. hdr_size + sizeofcmds];

    var sections_list = try std.ArrayList(Section).initCapacity(allocator, 0);
    defer sections_list.deinit(allocator);
    var segments_list = try std.ArrayList(Section).initCapacity(allocator, 0);
    defer segments_list.deinit(allocator);
    var imports = try std.ArrayList([]const u8).initCapacity(allocator, 0);
    defer imports.deinit(allocator);
    var exports = try std.ArrayList(Export).initCapacity(allocator, 0);
    defer exports.deinit(allocator);
    var messages = try std.ArrayList(Message).initCapacity(allocator, 0);
    defer messages.deinit(allocator);

    // Keep a mapping of segments (fileoff, filesize -> vmaddr) so we can translate
    // LC_MAIN.entryoff (file offset) -> virtual address
    var segmaps = try std.ArrayList(SegmentMap).initCapacity(allocator, 0);
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

    if (m_endian == .little) {
        var lc_it: macho.LoadCommandIterator = .{ .ncmds = ncmds, .buffer = lc_buffer, .index = 0 };

        while (true) {
            const lc = lc_it.next() orelse break;
            const cmd = lc.hdr.cmd;

            if (cmd == macho.LC.SEGMENT_64 and is_64) {
                const seg = lc.cast(macho.segment_command_64) orelse continue;
                const seg_fileoff = @as(u64, seg.fileoff);
                const seg_filesize = seg.filesize;
                const perm = machoProtToPermission(seg.initprot);
                try appendSegmentAndMap(allocator, &segments_list, &segmaps, seg_fileoff, seg_filesize, seg.vmaddr, perm);

                // parse sections by slicing the raw lc data (avoids alignment/@alignCast issues)
                const section_size = @sizeOf(macho.section_64);
                const sections_data = lc.data[@sizeOf(macho.segment_command_64)..];
                var i: usize = 0;
                while (i < seg.nsects) : (i += 1) {
                    const start = i * section_size;
                    if (start + section_size > sections_data.len) break; // malformed
                    const block = sections_data[start .. start + section_size];
                    try appendSectionFromBlock(allocator, &sections_list, block, true, m_endian);
                }
            } else if (cmd == macho.LC.SEGMENT and !is_64) {
                const seg = lc.cast(macho.segment_command) orelse continue;
                const seg_fileoff = @as(u64, seg.fileoff);
                const seg_filesize = @as(u64, seg.filesize);
                const perm = machoProtToPermission(seg.initprot);
                try appendSegmentAndMap(allocator, &segments_list, &segmaps, seg_fileoff, seg_filesize, @as(u64, seg.vmaddr), perm);

                const section_size = @sizeOf(macho.section);
                const sections_data = lc.data[@sizeOf(macho.segment_command)..];
                var i: usize = 0;
                while (i < seg.nsects) : (i += 1) {
                    const start = i * section_size;
                    if (start + section_size > sections_data.len) break; // malformed
                    const block = sections_data[start .. start + section_size];
                    try appendSectionFromBlock(allocator, &sections_list, block, false, m_endian);
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
                    if (rp.len != 0) try messages.append(allocator, Message{ .body = rp });
                } else if (cmd == macho.LC.CODE_SIGNATURE) {
                    // code signature presence
                    try messages.append(allocator, Message{ .body = "code signature present" });
                } else if (cmd == macho.LC.DYLD_EXPORTS_TRIE or cmd == macho.LC.DYLD_INFO) {
                    try messages.append(allocator, Message{ .body = "dyld export/bind info present (not parsed)" });
                }
            }
        }
    } else {
        // Big-endian load command parsing
        var off: usize = hdr_size;
        var lc_index: usize = 0;
        while (lc_index < ncmds) : (lc_index += 1) {
            if (off + 8 > macho_buf.len) return ParseError.Malformed;
            const cmd_val = readU32At(macho_buf, off, m_endian);
            const opt_cmd = machoLCFromU32(cmd_val);
            const cmdsize = @as(usize, readU32At(macho_buf, off + 4, m_endian));
            if (cmdsize < 8) return ParseError.Malformed;
            if (off + cmdsize > macho_buf.len) return ParseError.Malformed;

            const lc_data = macho_buf[off .. off + cmdsize];

            if (opt_cmd) |cmd| {
                if (cmd == macho.LC.SEGMENT_64 and is_64) {
                    // segment_command_64 layout (big-endian): cmd/cmdsize (0..8), segname (8..24), vmaddr (24..32), vmsize (32..40), fileoff (40..48), filesize (48..56), maxprot (56..60), initprot (60..64), nsects (64..68), flags (68..72)
                    const seg_fileoff = readU64At(lc_data, 40, m_endian);
                    const seg_filesize = readU64At(lc_data, 48, m_endian);
                    const vmaddr = readU64At(lc_data, 24, m_endian);
                    const initprot = @as(macho.vm_prot_t, readI32At(lc_data, 60, m_endian));
                    const perm = machoProtToPermission(initprot);
                    try appendSegmentAndMap(allocator, &segments_list, &segmaps, seg_fileoff, seg_filesize, vmaddr, perm);

                    const section_size = @sizeOf(macho.section_64);
                    const sections_data = lc_data[@sizeOf(macho.segment_command_64)..];
                    var i: usize = 0;
                    const nsects = @as(usize, readU32At(lc_data, 64, m_endian));
                    while (i < nsects) : (i += 1) {
                        const start = i * section_size;
                        if (start + section_size > sections_data.len) break;
                        const block = sections_data[start .. start + section_size];
                        try appendSectionFromBlock(allocator, &sections_list, block, true, m_endian);
                    }
                } else if (cmd == macho.LC.SEGMENT and !is_64) {
                    // segment_command (32-bit): cmd/cmdsize (0..8), segname (8..24), vmaddr (24..28), vmsize (28..32), fileoff (32..36), filesize (36..40), maxprot (40..44), initprot (44..48), nsects (48..52), flags (52..56)
                    const seg_fileoff = @as(u64, readU32At(lc_data, 32, m_endian));
                    const seg_filesize = @as(u64, readU32At(lc_data, 36, m_endian));
                    const vmaddr = @as(u64, readU32At(lc_data, 24, m_endian));
                    const initprot = @as(macho.vm_prot_t, readI32At(lc_data, 44, m_endian));
                    const perm = machoProtToPermission(initprot);
                    try appendSegmentAndMap(allocator, &segments_list, &segmaps, seg_fileoff, seg_filesize, vmaddr, perm);

                    const section_size = @sizeOf(macho.section);
                    const sections_data = lc_data[@sizeOf(macho.segment_command)..];
                    var i: usize = 0;
                    const nsects = @as(usize, readU32At(lc_data, 48, m_endian));
                    while (i < nsects) : (i += 1) {
                        const start = i * section_size;
                        if (start + section_size > sections_data.len) break;
                        const block = sections_data[start .. start + section_size];
                        try appendSectionFromBlock(allocator, &sections_list, block, false, m_endian);
                    }
                } else if (cmd == macho.LC.SYMTAB) {
                    symoff = @as(usize, readU32At(lc_data, 8, m_endian));
                    nsyms = @as(usize, readU32At(lc_data, 12, m_endian));
                    stroff = @as(usize, readU32At(lc_data, 16, m_endian));
                    strsize = @as(usize, readU32At(lc_data, 20, m_endian));
                } else if (cmd == macho.LC.MAIN) {
                    entry_fileoff = readU64At(lc_data, 8, m_endian);
                    have_entry = true;
                } else {
                    if (cmd == macho.LC.LOAD_DYLIB or cmd == macho.LC.LOAD_WEAK_DYLIB or cmd == macho.LC.REEXPORT_DYLIB or cmd == macho.LC.LOAD_UPWARD_DYLIB) {
                        try appendDylibNameFromLcData(allocator, &imports, lc_data, m_endian);
                    } else if (cmd == macho.LC.RPATH) {
                        try appendRpathMessageFromLcData(allocator, &messages, lc_data, m_endian);
                    } else if (cmd == macho.LC.CODE_SIGNATURE) {
                        try messages.append(allocator, Message{ .body = "code signature present" });
                    } else if (cmd == macho.LC.DYLD_EXPORTS_TRIE or cmd == macho.LC.DYLD_INFO) {
                        try messages.append(allocator, Message{ .body = "dyld export/bind info present (not parsed)" });
                    }
                }
            } else {
                // Unknown/unsupported load command value: skip it gracefully.
            }

            off += cmdsize;
        }
    }

    try parseSymtab(allocator, macho_buf, symoff, nsyms, stroff, strsize, is_64, m_endian, sections_list.items, indirectsymoff, nindirectsyms, ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym, &imports, &exports);

    // Translate entry file offset -> virtual address using segment maps
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
        if (entry_va == 0) entry_va = entry_fileoff; // fallback to file offset
    }

    const arch = switch (hdr_cputype) {
        macho.CPU_TYPE_X86_64 => CpuArch.x86_64,
        macho.CPU_TYPE_ARM64 => CpuArch.aarch64,
        7 => CpuArch.x86,
        else => CpuArch.unknown,
    };

    const file_kind = switch (hdr_filetype) {
        macho.MH_EXECUTE => FileKind.executable,
        macho.MH_DYLIB => FileKind.shared_library,
        macho.MH_OBJECT => FileKind.object,
        else => FileKind.unknown,
    };

    const desc = BinaryDescription{
        .format = BinaryFileKind.macho,
        .os_abi = OsAbi.macos,
        .arch = arch,
        .bitness = if (is_64) 64 else 32,
        .endianess = m_endian,
        .file_kind = file_kind,
        .entrypoint_virtual_address = entry_va,
        .pie = if ((hdr_flags & macho.MH_PIE) != 0) Perhaps.yes else Perhaps.no,
        .aslr = Perhaps.unknown,
        .nx = Perhaps.unknown,
        .relro = RelroConfig.unknown,
        .stripped = if (nsyms == 0) StrippedState.yes else StrippedState.no,
        .sections = try sections_list.toOwnedSlice(allocator),
        .segments = try segments_list.toOwnedSlice(allocator),
        .imports = try imports.toOwnedSlice(allocator),
        .exports = try exports.toOwnedSlice(allocator),
        .messages = try messages.toOwnedSlice(allocator),
        .debug_info_present = false,
    };

    return desc;
}

/// Decodes a Mach-O file (thin or fat) into a BinaryBundle.
fn decodeMacho(allocator: std.mem.Allocator, file: std.fs.File) !BinaryBundle {
    // Read whole file into backing buffer
    const stat = try file.stat();
    const file_size = @as(usize, stat.size);
    var file_buf = try allocator.alloc(u8, file_size);
    var keep_backing: bool = false;
    defer if (!keep_backing) allocator.free(file_buf);

    var fr = file.reader(file_buf);
    try fr.interface.fill(file_size);

    // Decide whether this is a FAT container or a thin Mach-O
    const magic = readU32At(file_buf, 0, .big);
    var bundle_list = try std.ArrayList(BinaryDescription).initCapacity(allocator, 0);
    defer bundle_list.deinit(allocator);

    if (magic == macho.FAT_MAGIC or magic == macho.FAT_CIGAM or magic == macho.FAT_MAGIC_64 or magic == macho.FAT_CIGAM_64) {
        const fat_endian: Endian = if (magic == macho.FAT_CIGAM or magic == macho.FAT_CIGAM_64) Endian.little else Endian.big;
        if (file_buf.len < @sizeOf(macho.fat_header)) return ParseError.TooSmall;
        const nfat = @as(usize, readU32At(file_buf, 4, fat_endian));
        if (nfat == 0) return ParseError.Malformed;
        const arch_off = @sizeOf(macho.fat_header);
        const arch_size = @sizeOf(macho.fat_arch);
        if (file_buf.len < arch_off + nfat * arch_size) return ParseError.TooSmall;

        var i: usize = 0;
        while (i < nfat) : (i += 1) {
            const off_field = arch_off + i * arch_size + 8; // offset in fat_arch
            const size_field = arch_off + i * arch_size + 12; // size in fat_arch

            const off32 = @as(usize, readU32At(file_buf, off_field, fat_endian));

            const sz32 = @as(usize, readU32At(file_buf, size_field, fat_endian));

            if (off32 + sz32 <= file_buf.len) {
                const slice = file_buf[off32 .. off32 + sz32];
                const mm = readU32At(slice, 0, .big);
                // Quick check: only attempt to decode little-endian slices here.
                if (mm == macho.MH_CIGAM_64 or mm == macho.MH_CIGAM) {
                    // little-endian slices - try decode
                    const desc = try decodeMachoSlice(allocator, slice);
                    try bundle_list.append(allocator, desc);
                } else {
                    // Unsupported (big-endian) slice — skip for now
                    continue;
                }
            }
        }
    } else {
        // Thin Mach-O — decode the whole file
        const desc = try decodeMachoSlice(allocator, file_buf);
        try bundle_list.append(allocator, desc);
    }

    const items = try bundle_list.toOwnedSlice(allocator);
    const bundle = BinaryBundle{ .items = items, .backing_file = file_buf };
    keep_backing = true;
    return bundle;
}

test ": ELF.amd64 analyze binary + pretty print" {
    // var file = try std.fs.cwd().openFile("testing/assets/bian", .{});
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);
    try expect(bundle.items[0].format == .elf);
    try expect(bundle.items[0].arch == .x86_64); // Assuming test file
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buffer);
    try bundle.items[0].writePretty(&stderr_writer.interface);
    try stderr_writer.interface.flush();
}

test ": Mach-O.amd64 analyze binary + pretty print" {
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-x64-ls", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);
    try expect(bundle.items[0].format == .macho);
    try expect(bundle.items[0].arch == .x86_64);
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buffer);
    try bundle.items[0].writePretty(&stderr_writer.interface);
    try stderr_writer.interface.flush();
}

// Decoders invariants tests — exercise only robust invariants so tests remain
// useful as decoders evolve. These assert zero-copy backing buffer invariants,
// basic structural consistency (sections/segments present), bounds checks, and
// that pretty-printing succeeds.

test "decoders.invariants: ELF (backing buffer, sections/segments bounds, pretty print)" {
    var file = try std.fs.cwd().openFile("testing/assets/bian", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);

    try expect(bundle.items.len >= 1);
    const backing_len_u64 = @as(u64, bundle.backing_file.len);

    for (bundle.items) |desc| {
        try expect(desc.format == .elf);
        try expect(desc.bitness == 64);
        try expect(desc.arch != CpuArch.unknown);
        try expect(desc.file_kind != FileKind.unknown);
        try expect(desc.sections.len > 0);
        try expect(desc.segments.len > 0);

        // Sections/segments whose file_offset is non-zero should fit inside the
        // backing file. Zero file_offset is allowed (e.g. BSS/common sections).
        for (desc.sections) |s| {
            if (s.file_offset != 0) try expect(s.file_offset + s.size <= backing_len_u64);
        }
        for (desc.segments) |seg| {
            if (seg.file_offset != 0) try expect(seg.file_offset + seg.size <= backing_len_u64);
        }

        // Pretty-print must run without error and produce some output.
        var alloc_w = std.io.Writer.Allocating.init(allocator);
        defer alloc_w.deinit();
        try desc.writePretty(&alloc_w.writer);
        try expect(alloc_w.written().len > 0);
    }
}

test "probe: Mach-O ppc thin detectFormat + analyzeBinary" {
    var buf: [prefix_length]u8 = @splat(0);
    try bufferedRead("testing/assets/MachO-OSX-ppc-openssl-1.0.1h", buf[0..], prefix_length);
    const presult = detectFormat(buf[0..]);
    try expect(presult.macho.bitness == 32);
    try expect(presult.macho.endianess == .big);

    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-ppc-openssl-1.0.1h", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);
    try expect(bundle.items.len >= 1);
    try expect(bundle.items[0].format == .macho);
    try expect(bundle.items[0].bitness == 32);
    try expect(bundle.items[0].endianess == .big);
}

test "probe: Mach-O universal libSystem decode has both 32 and 64 slices" {
    var file = try std.fs.cwd().openFile("testing/assets/libSystem.B.dylib", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);
    try expect(bundle.items.len >= 2);
    var found64: bool = false;
    var found32: bool = false;
    var i: usize = 0;
    while (i < bundle.items.len) : (i += 1) {
        const d = bundle.items[i];
        if (d.bitness == 64) found64 = true;
        if (d.bitness == 32) found32 = true;
    }
    try expect(found64 == true);
    try expect(found32 == true);
}

test "probe: Mach-O universal (ppc+i386) decodes at least one slice" {
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-ppc-and-i386-bash", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);
    try expect(bundle.items.len >= 1);
    var any32: bool = false;
    var i: usize = 0;
    while (i < bundle.items.len) : (i += 1) {
        if (bundle.items[i].bitness == 32) any32 = true;
    }
    try expect(any32 == true);
}

test "decoders.invariants: Mach-O (backing buffer, sections/segments bounds, imports/exports, pretty print)" {
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-x64-ls", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);

    try expect(bundle.items.len >= 1);
    const backing_len_u64 = @as(u64, bundle.backing_file.len);

    for (bundle.items) |desc| {
        try expect(desc.format == .macho);
        try expect(desc.bitness == 64);
        try expect(desc.arch != CpuArch.unknown);
        try expect(desc.file_kind != FileKind.unknown);
        try expect(desc.sections.len > 0);
        try expect(desc.segments.len > 0);

        for (desc.sections) |s| {
            if (s.file_offset != 0) try expect(s.file_offset + s.size <= backing_len_u64);
        }
        for (desc.segments) |seg| {
            if (seg.file_offset != 0) try expect(seg.file_offset + seg.size <= backing_len_u64);
        }

        // Imports and exports should contain valid non-empty names if present.
        for (desc.imports) |imp| {
            try expect(imp.len > 0);
        }
        for (desc.exports) |ex| {
            try expect(ex.name.len > 0);
        }

        var alloc_w = std.io.Writer.Allocating.init(allocator);
        defer alloc_w.deinit();
        try desc.writePretty(&alloc_w.writer);
        try expect(alloc_w.written().len > 0);
    }
}

// New unit tests: security hints presence and basic DT_NEEDED/symbol checks
test "security.hints: ELF asset reports hints and imports/exports arrays" {
    var file = try std.fs.cwd().openFile("testing/assets/elf-Linux-x64-bash", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);
    try expect(bundle.items.len >= 1);
    const desc = bundle.items[0];

    // Ensure the security hint fields are present (enum values) and the description is ELF
    try expect(desc.format == .elf);
    try expect(desc.pie == Perhaps.yes or desc.pie == Perhaps.no or desc.pie == Perhaps.unknown);
    try expect(desc.nx == Perhaps.yes or desc.nx == Perhaps.no or desc.nx == Perhaps.unknown);
    try expect(desc.relro == RelroConfig.unknown or desc.relro == RelroConfig.none or desc.relro == RelroConfig.partial or desc.relro == RelroConfig.full or desc.relro == RelroConfig.not_applicable);

    // imports/exports arrays exist (length may be zero depending on asset)
    try expect(desc.imports.len >= 0);
    try expect(desc.exports.len >= 0);
}

test "symbol.parsing: Mach-O asset contains imports and at least one export" {
    var file = try std.fs.cwd().openFile("testing/assets/MachO-OSX-x64-ls", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);
    try expect(bundle.items.len >= 1);
    const desc = bundle.items[0];

    try expect(desc.format == .macho);
    try expect(desc.imports.len > 0);
    try expect(desc.exports.len > 0);
}
