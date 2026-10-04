//! Builds the ACPI tables the guest firmware reads at boot.
//!
//! The module is buffer-based and freestanding-clean. No allocator, no std.Io,
//! no std.heap. It composes over almanac, which holds the same property.

const std = @import("std");
const testing = @import("mirage-testing");

pub const almanac = @import("almanac");

/// The I/O port the FADT sleep-control and sleep-status registers name.
pub const sleep_port: u16 = 0x600;

/// Options for building the ACPI table set. Carries optional table addresses
/// for tables added in later tasks.
pub const Options = struct {
    /// Physical address of the DSDT; zero until Task 4 supplies one.
    dsdt_phys: u64 = 0,
};

// The FADT is 276 bytes (ACPI 6.x). Layout is fixed by the spec; fields are
// written by offset using std.mem.writeInt. Asserts below pin every field used.
const fadt_size: usize = 276;

// The Generic Address Structure is 12 bytes. The assert below confirms it.
comptime {
    std.debug.assert(@sizeOf(almanac.Gas) == 12);
    // sleep-control GAS lives at FADT offset 244; sleep-status at 256.
    // The assertions are on the constants, not on a struct field, because the
    // FADT body is a raw [276]u8 built field-by-field.
    std.debug.assert(sleep_control_off == 244);
    std.debug.assert(sleep_status_off == 256);
    std.debug.assert(sleep_status_off + @sizeOf(almanac.Gas) <= fadt_size);
}

// Byte offsets within the 276-byte FADT for the two sleep GAS fields.
const sleep_control_off: usize = 244;
const sleep_status_off: usize = 256;

// Bit 20 of the FADT flags field: hardware-reduced ACPI platform.
const flag_hw_reduced: u32 = 1 << 20;

/// Write a 12-byte GAS into `dst` at `off`. address_space=1 (SystemIO),
/// bit_width=8, bit_offset=0, access_size=1 (byte), address=port.
fn writeGas(dst: []u8, off: usize, port: u16) void {
    dst[off + 0] = 1; // address_space: SystemIO
    dst[off + 1] = 8; // bit_width
    dst[off + 2] = 0; // bit_offset
    dst[off + 3] = 1; // access_size: byte
    std.mem.writeInt(u64, dst[off + 4 ..][0..8], port, .little);
}

/// Build an RSDP, XSDT, and hardware-reduced FADT into `buf` at guest
/// physical address `base_phys`. Returns the bytes written (Builder.finish()).
pub fn build(buf: []u8, base_phys: u64, opts: Options) ![]u8 {
    var b = almanac.Builder.init(buf, base_phys);

    // Build the FADT body by hand because almanac's fadt() helper does not set
    // the sleep-control/status registers.
    var fadt_bytes = [_]u8{0} ** fadt_size;

    // SDT header (36 bytes): signature, length, revision, checksum (0 for now),
    // OEM id, OEM table id, OEM revision, creator id, creator revision.
    @memcpy(fadt_bytes[0..4], "FACP");
    std.mem.writeInt(u32, fadt_bytes[4..8], fadt_size, .little);
    fadt_bytes[8] = 6; // ACPI revision 6
    fadt_bytes[9] = 0; // checksum placeholder

    // OEM / creator fields use almanac's defaults so read-back agrees.
    @memcpy(fadt_bytes[10..16], "MIDSTL");
    @memcpy(fadt_bytes[16..24], "ALMANAC ");
    std.mem.writeInt(u32, fadt_bytes[24..28], 1, .little);
    @memcpy(fadt_bytes[28..32], "ALMA");
    std.mem.writeInt(u32, fadt_bytes[32..36], 1, .little);

    // DSDT (32-bit, offset 40) and X_DSDT (64-bit, offset 140).
    std.mem.writeInt(u32, fadt_bytes[40..44], @truncate(opts.dsdt_phys), .little);
    std.mem.writeInt(u64, fadt_bytes[140..148], opts.dsdt_phys, .little);

    // Flags at offset 112: set HW_REDUCED_ACPI.
    std.mem.writeInt(u32, fadt_bytes[112..116], flag_hw_reduced, .little);

    // Minor version at offset 131 = 1 (ACPI 6.1+).
    fadt_bytes[131] = 1;

    // Sleep-control GAS at offset 244, sleep-status GAS at offset 256.
    writeGas(&fadt_bytes, sleep_control_off, sleep_port);
    writeGas(&fadt_bytes, sleep_status_off, sleep_port);

    // Stamp the checksum into byte 9 (the SDT header checksum slot).
    fadt_bytes[9] = almanac.checksum.compute(&fadt_bytes);

    const fadt_phys = try b.addRaw(&fadt_bytes);
    const xsdt_phys = try b.xsdt(&.{fadt_phys});
    _ = try b.rsdp(xsdt_phys);

    return b.finish();
}

/// The physical address the RSDP will occupy when the table set is built at
/// `base_phys`. The Builder places the RSDP last, after a 276-byte FADT
/// (aligned to 8), a variable-size XSDT (aligned to 8), and a 36-byte RSDP
/// (aligned to 16). Matches the offset the Builder produces.
///
/// Layout (all offsets relative to base_phys; `off` tracks Builder.alloc state):
///   off=0   -> FADT start (align 8, already aligned)
///   off=276 -> FADT end
///   off=280 -> XSDT start (alignForward(276, 8) = 280 = 0x118)
///   off=324 -> XSDT end   (280 + 44 bytes = 324 = 0x144)
///   off=336 -> RSDP start (alignForward(324, 16) = 336 = 0x150)
pub fn rsdp_phys(base_phys: u64) u64 {
    // FADT: starts at 0, length 276. off after = 276.
    const after_fadt: u64 = 276;
    // XSDT: starts at alignForward(276, 8) = 280, length = 36 + 1*8 = 44. off after = 324.
    const xsdt_start: u64 = std.mem.alignForward(u64, after_fadt, 8);
    const after_xsdt: u64 = xsdt_start + (36 + 1 * 8);
    // RSDP: starts at alignForward(324, 16) = 336 = 0x150.
    const rsdp_start: u64 = std.mem.alignForward(u64, after_xsdt, 16);
    return base_phys + rsdp_start;
}

test "the acpi set has a hw-reduced fadt discoverable from the rsdp" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const bytes = try build(&buf, base, .{});
    _ = bytes;
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    // The OffsetMapper maps phys -> virt by adding the offset. We want:
    //   virt = @intFromPtr(&buf) + (phys - base)
    //        = phys + (@intFromPtr(&buf) - base)
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, rsdp_phys(base));
    try std.testing.expect(tabs.usesXsdt());
    const fadt = (try tabs.findAs(almanac.Fadt)).?;
    try std.testing.expect(fadt.isHwReduced());
}

test "the fadt names the sleep port" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const bytes = try build(&buf, base, .{});
    _ = bytes;

    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, rsdp_phys(base));
    const fadt = (try tabs.findAs(almanac.Fadt)).?;

    // SLEEP_CONTROL_REG is at FADT byte offset 244.
    const gas_bytes = fadt.bytes[sleep_control_off .. sleep_control_off + @sizeOf(almanac.Gas)];
    const g = almanac.Gas.fromBytes(gas_bytes);
    try testing.expectEqual(@as(u8, 1), g.address_space); // SystemIO
    try testing.expectEqual(sleep_port, @as(u16, @intCast(g.address)));
}

test {
    _ = almanac;
}
