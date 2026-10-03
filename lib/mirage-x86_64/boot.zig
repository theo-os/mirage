//! Parse the setup header a 64-bit Linux bzImage carries at file offset 0x1f1.
//!
//! The header is the contract between the boot loader and the kernel; reading it
//! before mapping anything avoids surprises at entry.

const std = @import("std");
// A portable module's tests use `mirage-testing`, not `std.testing`, because the standard
// allocator reaches the page allocator and its failure reports reach `std.Io.Threaded`, and the
// freestanding build that proves this module names no operating system has neither.
const testing = @import("mirage-testing");
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;

pub const Error = error{ TooSmall, NotABzImage, UnsupportedProtocol, No64BitEntry, CmdlineTooLong, TooManyRegions, InitrdTooLarge } || GuestMemory.Error;

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
    // Pin the size too, so a later field cannot grow the struct unnoticed.
    std.debug.assert(@sizeOf(SetupHeader) == 0x264 - base);
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

/// Fixed low-memory GPAs for the boot params and support structures.
/// All values sit below the kernel at 0x100000.
pub const LowLayout = struct {
    boot_params: u64,
    cmdline: u64,
    pml4: u64,
    pdpt: u64,
    pd: u64,
    gdt: u64,
};

pub const default_low: LowLayout = .{
    .boot_params = 0x10000,
    .cmdline = 0x20000,
    .pml4 = 0x30000,
    .pdpt = 0x31000,
    .pd = 0x32000,
    .gdt = 0x33000,
};

/// Fixed GPA where the initrd is placed. 64 MiB clears the kernel at 0x100000 and
/// the decompression working set the kernel needs above it before it mounts a filesystem.
pub const initrd_base: u64 = 0x4000000;

// The e820 entry stride on disk is always 20 bytes: 8+8+4, no tail padding.
// A Zig extern struct with those fields pads to 24, so entries are written
// field by field rather than as a struct copy.
comptime {
    std.debug.assert(8 + 8 + 4 == 20);
}

/// The maximum e820 entries the zero page can hold.
const max_e820_entries = 128;

/// Write the Linux zero page (boot_params) into guest RAM at low.boot_params.
///
/// When initrd is non-null the bytes are copied to initrd_base and the ramdisk
/// fields in the header are set to record where the kernel will find them. The
/// caller must supply enough guest RAM to hold the initrd above initrd_base.
///
/// The caller provides the memory map through memory.regions; each region
/// becomes one usable e820 entry.
pub fn buildBootParams(
    memory: *GuestMemory,
    header: SetupHeader,
    cmdline: []const u8,
    initrd: ?[]const u8,
    low: LowLayout,
) Error!void {
    // Reject a cmdline that would not fit in its reserved region.
    const cmdline_room = low.pml4 - low.cmdline;
    if (cmdline.len + 1 > cmdline_room) return error.CmdlineTooLong;

    const n_regions = memory.regions.len;
    if (n_regions > max_e820_entries) return error.TooManyRegions;

    // Write the cmdline bytes NUL-terminated at the cmdline GPA.
    try memory.write(low.cmdline, cmdline);
    const nul = [1]u8{0};
    try memory.write(low.cmdline + cmdline.len, &nul);

    // Copy the setup header into the zero page at offset 0x1f1.
    var hdr_copy = header;
    hdr_copy.type_of_loader = 0xff;
    hdr_copy.loadflags |= 0x01; // LOADED_HIGH
    hdr_copy.cmd_line_ptr = @intCast(low.cmdline);

    if (initrd) |bytes| {
        // Sum all region lengths to know the total guest RAM available. The room above
        // initrd_base is found by subtraction so the check cannot wrap on a huge length.
        var total: u64 = 0;
        for (memory.regions) |r| total += r.len;
        const room = if (total > initrd_base) total - initrd_base else 0;
        if (bytes.len > room) return error.InitrdTooLarge;

        try memory.write(initrd_base, bytes);
        hdr_copy.ramdisk_image = @intCast(initrd_base);
        hdr_copy.ramdisk_size = @intCast(bytes.len);
    }

    const hdr_bytes = @as([*]const u8, @ptrCast(&hdr_copy))[0..@sizeOf(SetupHeader)];
    try memory.write(low.boot_params + 0x1f1, hdr_bytes);

    // Write e820_entries count at offset 0x1e8.
    const e820_count: u8 = @intCast(n_regions);
    try memory.write(low.boot_params + 0x1e8, &[1]u8{e820_count});

    // Serialize each e820 entry as 20 packed bytes: addr(8) + size(8) + type(4).
    for (memory.regions, 0..) |region, i| {
        const entry_base = low.boot_params + 0x2d0 + i * 20;
        var buf: [20]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], region.gpa, .little);
        std.mem.writeInt(u64, buf[8..16], region.len, .little);
        std.mem.writeInt(u32, buf[16..20], 1, .little); // type 1: usable RAM
        try memory.write(entry_base, &buf);
    }
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

test "boot_params carries the e820 map, cmdline pointer, and header" {
    const backing = try testing.allocator().alloc(u8, 0x200000);
    defer testing.allocator().free(backing);
    @memset(backing, 0);
    var regions = [_]GuestMemory.Region{.{ .gpa = 0, .len = 0x200000, .backing = .{ .shared = backing } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var header: SetupHeader = std.mem.zeroes(SetupHeader);
    header.version = 0x020c;
    // boot_flag at rel offset 0x0d (abs 0x1fe): set it so the copy preserves it
    header.boot_flag = 0xaa55;
    try buildBootParams(&memory, header, "console=ttyS0", null, default_low);

    // The copied header carries boot_flag 0xaa55 at zero-page offset 0x1fe.
    var flag_buf: [2]u8 = undefined;
    try memory.read(default_low.boot_params + 0x1fe, &flag_buf);
    try testing.expectEqual(@as(u16, 0xaa55), std.mem.readInt(u16, &flag_buf, .little));

    // e820_entries at 0x1e8 must be at least 1.
    var n: [1]u8 = undefined;
    try memory.read(default_low.boot_params + 0x1e8, &n);
    try std.testing.expect(n[0] >= 1);

    // First entry type field is at 0x2d0 + 16 (after the 8-byte addr and 8-byte size).
    var ty: [4]u8 = undefined;
    try memory.read(default_low.boot_params + 0x2d0 + 16, &ty);
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, &ty, .little));

    // cmd_line_ptr at zero-page offset 0x228 must point at the cmdline GPA.
    var ptr_buf: [4]u8 = undefined;
    try memory.read(default_low.boot_params + 0x228, &ptr_buf);
    try testing.expectEqual(@as(u32, @intCast(default_low.cmdline)), std.mem.readInt(u32, &ptr_buf, .little));
}

test "a cmdline longer than its region is refused" {
    const backing = try testing.allocator().alloc(u8, 0x200000);
    defer testing.allocator().free(backing);
    @memset(backing, 0);
    var regions = [_]GuestMemory.Region{.{ .gpa = 0, .len = 0x200000, .backing = .{ .shared = backing } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var header: SetupHeader = std.mem.zeroes(SetupHeader);
    header.version = 0x020c;

    // The cmdline room is pml4 - cmdline = 0x30000 - 0x20000 = 0x10000 bytes.
    // A string one byte longer than that room (after NUL) must be refused.
    const too_long = try testing.allocator().alloc(u8, 0x10000);
    defer testing.allocator().free(too_long);
    @memset(too_long, 'x');
    try testing.expectError(error.CmdlineTooLong, buildBootParams(&memory, header, too_long, null, default_low));
}

test "more than 128 regions is refused" {
    const backing = try testing.allocator().alloc(u8, 0x200000);
    defer testing.allocator().free(backing);
    @memset(backing, 0);

    // Build a region array with 129 entries, all pointing into the same backing.
    var regions: [129]GuestMemory.Region = undefined;
    for (&regions) |*r| r.* = .{ .gpa = 0, .len = 0x200000, .backing = .{ .shared = backing } };
    var memory: GuestMemory = .{ .regions = &regions };
    var header: SetupHeader = std.mem.zeroes(SetupHeader);
    header.version = 0x020c;

    try testing.expectError(error.TooManyRegions, buildBootParams(&memory, header, "x", null, default_low));
}

test "an initramfs is placed in guest ram and recorded in boot_params" {
    const backing = try testing.allocator().alloc(u8, 0x8000000); // 128 MiB
    defer testing.allocator().free(backing);
    @memset(backing, 0);
    var memory: GuestMemory = .{ .regions = &.{.{ .gpa = 0, .len = backing.len, .backing = .{ .shared = backing } }} };
    var header: SetupHeader = std.mem.zeroes(SetupHeader);
    header.version = 0x020c;
    const initrd = "INITRAMFSBYTES";
    try buildBootParams(&memory, header, "console=ttyS0", initrd, default_low);
    // ramdisk_image/ramdisk_size recorded
    var img: [4]u8 = undefined;
    try memory.read(default_low.boot_params + 0x218, &img);
    var sz: [4]u8 = undefined;
    try memory.read(default_low.boot_params + 0x21c, &sz);
    try testing.expectEqual(@as(u32, initrd_base), std.mem.readInt(u32, &img, .little));
    try testing.expectEqual(@as(u32, initrd.len), std.mem.readInt(u32, &sz, .little));
    // bytes actually landed
    var out: [14]u8 = undefined;
    try memory.read(initrd_base, &out);
    try testing.expectEqualSlices(u8, initrd, &out);
}

test "an initramfs past guest ram is refused" {
    // The region covers the low structures but stops just below initrd_base, so
    // the initrd cannot fit and the bounds check must fire before the write.
    const backing = try testing.allocator().alloc(u8, initrd_base); // exactly initrd_base bytes, initrd would go past it
    defer testing.allocator().free(backing);
    @memset(backing, 0);
    var memory: GuestMemory = .{ .regions = &.{.{ .gpa = 0, .len = backing.len, .backing = .{ .shared = backing } }} };
    var header: SetupHeader = std.mem.zeroes(SetupHeader);
    header.version = 0x020c;
    const initrd = "INITRAMFSBYTES";
    try testing.expectError(error.InitrdTooLarge, buildBootParams(&memory, header, "console=ttyS0", initrd, default_low));
}

/// GDT selectors matching the descriptors written by buildLongMode.
pub const code_selector: u16 = 0x08;
pub const data_selector: u16 = 0x10;

/// Put an x86 guest into long mode at its entry.
///
/// x86 needs full control and segment register state to start, not the few general
/// registers the arm boot entry sets, so the boot entry is its own seam here. The vCPU is
/// passed in rather than imported, so this stays below the backend; it establishes the
/// state `buildLongMode` left the tables and the GDT ready for.
pub fn enter(vcpu: anytype, layout: Layout) !void {
    try vcpu.enterLongMode(default_low.pml4, layout.entry, layout.device_tree, default_low.gdt);
}

/// Build a 4-level identity-map paging hierarchy (PML4 → PDPT → PD) using
/// 2MB pages covering the first gigabyte, then write a minimal GDT.
///
/// For B1 the identity map is capped at 1 GB; a single PD (512 entries × 2 MB)
/// covers that range, which is enough to start the kernel.
pub fn buildLongMode(
    memory: *GuestMemory,
    low: LowLayout,
    map_bytes: u64,
) Error!void {
    // Cap the map at 1 GB so it fits within one PD (512 × 2 MB entries).
    const cap: u64 = 0x40000000;
    const covered = @min(map_bytes, cap);

    // PML4[0] → PDPT, present | rw.
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, low.pdpt | 0x3, .little);
    try memory.write(low.pml4, &buf);

    // PDPT[0] → PD, present | rw.
    std.mem.writeInt(u64, &buf, low.pd | 0x3, .little);
    try memory.write(low.pdpt, &buf);

    // PD entries: each covers 2 MB with present | rw | ps (0x83).
    const n_pages = (covered + 0x1fffff) / 0x200000; // ceil(covered / 2MB)
    const max_pd_entries: u64 = 512;
    const n = @min(n_pages, max_pd_entries);
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const pde = (i * 0x200000) | 0x83;
        std.mem.writeInt(u64, &buf, pde, .little);
        try memory.write(low.pd + i * 8, &buf);
    }

    // GDT: null descriptor, 64-bit code, 32-bit data.
    const gdt = [3]u64{
        0x0000000000000000, // null
        0x00AF9A000000FFFF, // 64-bit code: L=1, present, exec/read
        0x00CF92000000FFFF, // data: present, read/write
    };
    for (gdt, 0..) |entry, idx| {
        std.mem.writeInt(u64, &buf, entry, .little);
        try memory.write(low.gdt + idx * 8, &buf);
    }
}

// Read a u64 little-endian from guest memory; panics on I/O error in tests.
fn readU64(memory: *const GuestMemory, gpa: u64) u64 {
    var buf: [8]u8 = undefined;
    memory.read(gpa, &buf) catch unreachable;
    return std.mem.readInt(u64, &buf, .little);
}

test "the page tables identity-map low memory with 2mb pages" {
    // One region covers the full first gigabyte so all table GPAs are reachable.
    const backing = try testing.allocator().alloc(u8, 0x40000000);
    defer testing.allocator().free(backing);
    @memset(backing, 0);
    var regions = [_]GuestMemory.Region{.{ .gpa = 0, .len = 0x40000000, .backing = .{ .shared = backing } }};
    var memory: GuestMemory = .{ .regions = &regions };
    const low = default_low;

    try buildLongMode(&memory, low, 0x40000000);

    // PML4[0] must be present, writable, and point at the PDPT.
    const pml4e = readU64(&memory, low.pml4 + 0);
    try std.testing.expect((pml4e & 0x3) == 0x3);
    try testing.expectEqual(low.pdpt, pml4e & ~@as(u64, 0xfff));

    // PDPT[0] must be present, writable, and point at the PD.
    const pdpte = readU64(&memory, low.pdpt + 0);
    try std.testing.expect((pdpte & 0x3) == 0x3);
    try testing.expectEqual(low.pd, pdpte & ~@as(u64, 0xfff));

    // PD[0]: present, writable, page-size (maps physical 0).
    const pde0 = readU64(&memory, low.pd + 0);
    try std.testing.expect((pde0 & 0x83) == 0x83);
    try testing.expectEqual(@as(u64, 0), pde0 & 0xffffffffffe00000);

    // PD[1]: present, writable, page-size, mapping 0x200000.
    const pde1 = readU64(&memory, low.pd + 8);
    try std.testing.expect((pde1 & 0x83) == 0x83);
    try testing.expectEqual(@as(u64, 0x200000), pde1 & 0xffffffffffe00000);
}

test "the gdt has a 64-bit code and a data descriptor" {
    const backing = try testing.allocator().alloc(u8, 0x40000000);
    defer testing.allocator().free(backing);
    @memset(backing, 0);
    var regions = [_]GuestMemory.Region{.{ .gpa = 0, .len = 0x40000000, .backing = .{ .shared = backing } }};
    var memory: GuestMemory = .{ .regions = &regions };
    const low = default_low;

    try buildLongMode(&memory, low, 0x200000);

    // Code descriptor at GDT[1] (offset +8): L bit is bit 53, must be set.
    const code = readU64(&memory, low.gdt + 8);
    try std.testing.expect((code >> 53) & 1 == 1);

    // Data descriptor at GDT[2] (offset +16): present bit (bit 47) must be set.
    const data = readU64(&memory, low.gdt + 16);
    try std.testing.expect((data >> 47) & 1 == 1);
}

/// Where the protected mode kernel is placed. A relocatable bzImage is happy at the one megabyte
/// mark, below which the zero page and the page tables sit.
pub const kernel_base = 0x10_0000;

/// What is being started. x86 boots a bzImage only in this sub-project; firmware is named so a
/// caller shared with the other architecture can hand across the same kind without a special case.
pub const Kind = union(enum) {
    linux,
    firmware: struct {
        at: u64,
        len: u64,
    },
};

/// A span of guest memory the loader produced. x86 names nothing in a device tree, so this is only
/// here to meet the shape the caller expects.
pub const Range = struct {
    start: u64,
    end: u64,
};

/// The arch neutral launch request, with the same field names the other architecture takes. The
/// fields x86 does not use are accepted and ignored, because the caller is one source for both.
pub const Config = struct {
    kind: Kind = .linux,
    kernel: []const u8,
    initrd: ?[]const u8 = null,
    cmdline: []const u8,
    rng_seed: ?[]const u8 = null,
    rootfs_verity: ?[]const u8 = null,
    block_device: bool = true,
    vsock: bool = false,
    balloon: bool = false,
    net: bool = false,
    share: bool = false,
    tpm: bool = false,
    ram_base: u64,
    ram_size: u64,
    cpus: u32,
    uart_base: u64,
};

pub const Layout = struct {
    /// Where the guest starts. The sixty four bit entry is the protected mode base plus the jump the
    /// header names.
    entry: u64,
    /// Where the zero page sits. The long mode entry is handed this in `rsi`, which is where the other
    /// architecture puts the device tree.
    device_tree: u64,
    initrd: ?Range = null,
    log: ?Range = null,
};

pub const PrepareError = error{
    NoRoom,
} || std.mem.Allocator.Error || Error || Manifest.Error;

/// Place a bzImage and the structures it needs to reach long mode, measuring the kernel and the
/// command line on the way in, and say where the guest starts.
///
/// This produces the layout and the boot state. Entering long mode is a later step; here the guest's
/// memory is left with everything the entry needs.
pub fn prepare(
    gpa: std.mem.Allocator,
    memory: *GuestMemory,
    manifest: *Manifest,
    config: Config,
) PrepareError!Layout {
    const parsed = try parse(config.kernel);

    // The protected mode half of the image is everything past the setup sectors. It goes at the one
    // megabyte mark, where a relocatable kernel is content to run.
    if (parsed.protected_mode_offset > config.kernel.len) return PrepareError.NoRoom;
    const protected = config.kernel[parsed.protected_mode_offset..];
    const end = config.ram_base + config.ram_size;
    if (kernel_base + protected.len > end) return PrepareError.NoRoom;

    const low = default_low;

    var initrd_range: ?Range = null;
    if (config.initrd) |bytes| {
        // The room above initrd_base is found by subtraction, the same accounting
        // buildBootParams uses, so neither check wraps on a huge length.
        const room = if (end > initrd_base) end - initrd_base else 0;
        if (bytes.len > room) return error.InitrdTooLarge;
        initrd_range = .{ .start = initrd_base, .end = initrd_base + bytes.len };
    }

    try buildBootParams(memory, parsed.header, config.cmdline, config.initrd, low);
    try buildLongMode(memory, low, config.ram_size);
    try memory.write(kernel_base, protected);

    // The kernel and the command line are measured. x86 has no device tree to measure, and the rest
    // of the launch inputs reach the guest through the zero page the command line names.
    try manifest.add(gpa, .kernel, config.kernel);
    if (config.initrd) |bytes| try manifest.add(gpa, .initrd, bytes);
    if (config.rng_seed) |bytes| try manifest.add(gpa, .device_config, bytes);
    if (config.rootfs_verity) |bytes| try manifest.add(gpa, .rootfs_verity, bytes);
    try manifest.add(gpa, .cmdline, config.cmdline);
    manifest.seal();

    return .{
        .entry = kernel_base + parsed.entry_offset,
        .device_tree = low.boot_params,
        .initrd = initrd_range,
    };
}

test "a launch places the protected mode kernel and names the zero page" {
    const gpa = testing.allocator();
    const ram_base = 0;
    const backing = try gpa.alloc(u8, 0x40_0000);
    defer gpa.free(backing);
    @memset(backing, 0);
    var regions = [_]GuestMemory.Region{.{ .gpa = ram_base, .len = backing.len, .backing = .{ .shared = backing } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    var img = [_]u8{0} ** 4096;
    img[0x1f1] = 4; // setup_sects, so the protected mode half starts at (4 + 1) * 512
    std.mem.writeInt(u16, img[0x1fe..][0..2], 0xaa55, .little);
    std.mem.writeInt(u32, img[0x202..][0..4], 0x53726448, .little); // "HdrS"
    std.mem.writeInt(u16, img[0x206..][0..2], 0x020c, .little);
    std.mem.writeInt(u16, img[0x236..][0..2], 0x1, .little); // XLF_KERNEL_64
    // A byte the loader can find once the image is placed.
    img[(4 + 1) * 512] = 0x5a;

    const layout = try prepare(gpa, &memory, &manifest, .{
        .kernel = &img,
        .cmdline = "console=ttyS0",
        .ram_base = ram_base,
        .ram_size = backing.len,
        .cpus = 1,
        .uart_base = 0x3f8,
    });

    // Entered at the protected mode base plus the header's jump.
    try testing.expectEqual(@as(u64, kernel_base + 0x200), layout.entry);
    // The zero page is named where the entry will look for it.
    try testing.expectEqual(default_low.boot_params, layout.device_tree);
    // The first byte of the protected mode half landed at the one megabyte mark.
    try testing.expectEqual(@as(u8, 0x5a), backing[kernel_base]);

    // The kernel and the command line were measured, and the manifest is sealed.
    try std.testing.expect(manifest.sealed);
    try testing.expectEqual(Manifest.Tag.kernel, manifest.entries.items[0].tag);
    try testing.expectEqual(Manifest.Tag.cmdline, manifest.entries.items[1].tag);
}
