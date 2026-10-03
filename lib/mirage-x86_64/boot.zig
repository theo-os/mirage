//! Parse the setup header a 64-bit Linux bzImage carries at file offset 0x1f1.
//!
//! The header is the contract between the boot loader and the kernel; reading it
//! before mapping anything avoids surprises at entry.

const std = @import("std");
const testing = std.testing;

pub const Error = error{ TooSmall, NotABzImage, UnsupportedProtocol, No64BitEntry };

/// The fields the boot path needs, laid out exactly as the spec places them
/// starting at file offset 0x1f1.  Offsets in comments are relative to 0x1f1.
pub const SetupHeader = extern struct {
    setup_sects: u8, // rel 0x00  abs 0x1f1
    _pad0: [0x0c]u8,
    boot_flag: u16 align(1), // rel 0x0d  abs 0x1fe
    jump: u16 align(1), // rel 0x0f  abs 0x200
    header: u32 align(1), // rel 0x11  abs 0x202
    version: u16 align(1), // rel 0x15  abs 0x206
    _pad1: [0x08]u8,
    type_of_loader: u8, // rel 0x1f  abs 0x210
    loadflags: u8, // rel 0x20  abs 0x211
    _pad2: [0x02]u8,
    code32_start: u32 align(1), // rel 0x23  abs 0x214
    ramdisk_image: u32 align(1), // rel 0x27  abs 0x218
    ramdisk_size: u32 align(1), // rel 0x2b  abs 0x21c
    _pad3: [0x04]u8,
    heap_end_ptr: u16 align(1), // rel 0x33  abs 0x224
    _pad4: [0x02]u8,
    cmd_line_ptr: u32 align(1), // rel 0x37  abs 0x228
    _pad5: [0x04]u8,
    kernel_alignment: u32 align(1), // rel 0x3f  abs 0x230
    relocatable_kernel: u8, // rel 0x43  abs 0x234
    _pad6: [0x01]u8,
    xloadflags: u16 align(1), // rel 0x45  abs 0x236
    cmdline_size: u32 align(1), // rel 0x47  abs 0x238
    _pad7: [0x1c]u8,
    pref_address: u64 align(1), // rel 0x67  abs 0x258
    init_size: u32 align(1), // rel 0x6f  abs 0x260
};

// Each field offset is checked at compile time so a layout mistake surfaces
// before any image is ever parsed.
comptime {
    const base = 0x1f1;
    std.debug.assert(@offsetOf(SetupHeader, "setup_sects") == 0x1f1 - base);
    std.debug.assert(@offsetOf(SetupHeader, "boot_flag") == 0x1fe - base);
    std.debug.assert(@offsetOf(SetupHeader, "header") == 0x202 - base);
    std.debug.assert(@offsetOf(SetupHeader, "version") == 0x206 - base);
    std.debug.assert(@offsetOf(SetupHeader, "type_of_loader") == 0x210 - base);
    std.debug.assert(@offsetOf(SetupHeader, "loadflags") == 0x211 - base);
    std.debug.assert(@offsetOf(SetupHeader, "code32_start") == 0x214 - base);
    std.debug.assert(@offsetOf(SetupHeader, "ramdisk_image") == 0x218 - base);
    std.debug.assert(@offsetOf(SetupHeader, "ramdisk_size") == 0x21c - base);
    std.debug.assert(@offsetOf(SetupHeader, "heap_end_ptr") == 0x224 - base);
    std.debug.assert(@offsetOf(SetupHeader, "cmd_line_ptr") == 0x228 - base);
    std.debug.assert(@offsetOf(SetupHeader, "kernel_alignment") == 0x230 - base);
    std.debug.assert(@offsetOf(SetupHeader, "relocatable_kernel") == 0x234 - base);
    std.debug.assert(@offsetOf(SetupHeader, "xloadflags") == 0x236 - base);
    std.debug.assert(@offsetOf(SetupHeader, "cmdline_size") == 0x238 - base);
    std.debug.assert(@offsetOf(SetupHeader, "pref_address") == 0x258 - base);
    std.debug.assert(@offsetOf(SetupHeader, "init_size") == 0x260 - base);
}

pub const Parsed = struct {
    header: SetupHeader,
    protected_mode_offset: usize,
    entry_offset: u64 = 0x200,
};

/// Parse the setup header from raw image bytes.
///
/// Returns an error rather than panicking when any field fails a protocol
/// check, so callers can surface a clean diagnostic to the user.
pub fn parse(image: []const u8) Error!Parsed {
    const hdr_start = 0x1f1;
    const hdr_end = 0x1f1 + @sizeOf(SetupHeader);

    if (image.len < hdr_end) return error.TooSmall;

    // Read the magic values directly from the byte slice so there is no
    // aliasing via a pointer cast on unaligned, untrusted memory.
    const magic = std.mem.readInt(u32, image[0x202..][0..4], .little);

    // "HdrS" at 0x202 is the definitive sign that a setup header is present.
    if (magic != 0x53726448) return error.NotABzImage;

    const version = std.mem.readInt(u16, image[0x206..][0..2], .little);
    if (version < 0x020c) return error.UnsupportedProtocol;

    const xloadflags = std.mem.readInt(u16, image[0x236..][0..2], .little);
    // Bit 0 signals that a 64-bit entry point exists; without it the kernel
    // cannot be started in long mode.
    if (xloadflags & 0x1 == 0) return error.No64BitEntry;

    // Copy the header bytes into a value so callers get a clean typed struct.
    var hdr: SetupHeader = undefined;
    @memcpy(
        @as([*]u8, @ptrCast(&hdr))[0..@sizeOf(SetupHeader)],
        image[hdr_start..hdr_end],
    );

    const setup_sects: usize = if (hdr.setup_sects == 0) 4 else hdr.setup_sects;
    const protected_mode_offset = (setup_sects + 1) * 512;

    return Parsed{
        .header = hdr,
        .protected_mode_offset = protected_mode_offset,
    };
}

test "a valid 64-bit bzImage header parses" {
    var img = [_]u8{0} ** 2048;
    img[0x1f1] = 4; // setup_sects
    std.mem.writeInt(u16, img[0x1fe..][0..2], 0xaa55, .little); // boot_flag
    std.mem.writeInt(u32, img[0x202..][0..4], 0x53726448, .little); // "HdrS"
    std.mem.writeInt(u16, img[0x206..][0..2], 0x020c, .little); // protocol 2.12
    std.mem.writeInt(u16, img[0x236..][0..2], 0x1, .little); // xloadflags: XLF_KERNEL_64
    const p = try parse(&img);
    try testing.expectEqual(@as(usize, (4 + 1) * 512), p.protected_mode_offset);
    try testing.expectEqual(@as(u16, 0x020c), p.header.version);
}

test "a header without HdrS is refused" {
    var img = [_]u8{0} ** 2048;
    try testing.expectError(error.NotABzImage, parse(&img));
}

test "an old protocol or no 64-bit entry is refused" {
    var img = [_]u8{0} ** 2048;
    std.mem.writeInt(u32, img[0x202..][0..4], 0x53726448, .little);
    std.mem.writeInt(u16, img[0x206..][0..2], 0x020a, .little); // 2.10, too old
    try testing.expectError(error.UnsupportedProtocol, parse(&img));
    std.mem.writeInt(u16, img[0x206..][0..2], 0x020c, .little);
    // xloadflags left 0 -> no XLF_KERNEL_64
    try testing.expectError(error.No64BitEntry, parse(&img));
}
