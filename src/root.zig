//! By convention, root.zig is the root source file when making a library.
const std = @import("std");
const fs = std.fs;
const mem = std.mem;

const expect = std.testing.expect;

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
const Section = struct {
    name: []const u8,
    kind: SectionKind,
    size: u64,
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
    // stage0: Stage0ParseResult,

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
