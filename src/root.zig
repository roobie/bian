//! By convention, root.zig is the root source file when making a library.
const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const elf = std.elf;
const macho = std.macho;

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
        const magic = mem.readInt(u32, buffer[0..4], .big);
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
    }

    // 3. PE:
    //    DOS header 'MZ' at offset 0, then PE signature at e_lfanew.
    if (buffer.len >= 2 and buffer[0] == 'M' and buffer[1] == 'Z') {
        // Need the PE header offset from DOS header
        // (e_lfanew at offset 0x3C, 4 bytes LE).
        if (buffer.len >= 0x3C + 4) {
            var dos_header = buffer[0..0x40]; // small DOS header region
            const e_lfanew = mem.readInt(u32, dos_header[0x3C..0x40], .little);
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
        });
    }

    // 6) collect segments from program headers
    var segments_list = try std.ArrayList(Section).initCapacity(allocator, 0);
    defer segments_list.deinit(allocator);
    var ph_iter = header.iterateProgramHeadersBuffer(file_buf);
    while (true) {
        const ph = try ph_iter.next() orelse break;
        const perm = if ((ph.p_flags & elf.PF_X) != 0) Permission.execute else if ((ph.p_flags & elf.PF_W) != 0) Permission.write else if ((ph.p_flags & elf.PF_R) != 0) Permission.read else Permission.none;
        try segments_list.append(allocator, Section{
            .name = "", // segments typically don't have human names
            .kind = SectionKind.unknown,
            .size = ph.p_filesz,
            .file_offset = ph.p_offset,
            .permission = perm,
        });
    }

    // 7) build and return BinaryDescription (imports/exports parsing omitted here)
    var imports = try std.ArrayList([]const u8).initCapacity(allocator, 0);
    defer imports.deinit(allocator);
    var exports = try std.ArrayList(Export).initCapacity(allocator, 0);
    defer exports.deinit(allocator);
    var messages = try std.ArrayList(Message).initCapacity(allocator, 0);
    defer messages.deinit(allocator);

    const desc = BinaryDescription{
        .format = BinaryFileKind.elf,
        .os_abi = OsAbi.unknown, // map header.os_abi -> your OsAbi as needed
        .arch = arch,
        .bitness = bitness,
        .endianess = header.endian,
        .file_kind = file_kind,
        .entrypoint_virtual_address = header.entry,
        .pie = if (header.type == elf.ET.DYN) Perhaps.yes else Perhaps.no,
        .aslr = Perhaps.unknown,
        .nx = Perhaps.unknown,
        .relro = RelroConfig.unknown,
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
        .macho => return error.UnsupportedVariant, // Stub for now
        .pe => return error.UnsupportedVariant, // Stub for now
        .ape => return error.UnsupportedVariant, // Stub for now
        .unknown => return error.InvalidHeader,
    }
}

test ": ELF basic parsing" {
    var file = try std.fs.cwd().openFile("testing/assets/bian", .{});
    defer file.close();
    const allocator = std.testing.allocator;
    const bundle = try analyzeBinary(allocator, file);
    defer BinaryBundle.free(allocator, bundle);
    try expect(bundle.items[0].format == .elf);
    try expect(bundle.items[0].arch == .x86_64); // Assuming test file
    //std.debug.print("{}\n", .{desc});
    //
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buffer);
    try bundle.items[0].writePretty(&stderr_writer.interface);
    try stderr_writer.interface.flush();
}
