//! Builds the ACPI tables the guest firmware reads at boot.
//!
//! The module is buffer-based and freestanding-clean. No allocator, no std.Io,
//! no std.heap. It composes over almanac, which holds the same property.

const std = @import("std");
const testing = @import("mirage-testing");

pub const almanac = @import("almanac");

/// The I/O port the FADT sleep-control and sleep-status registers name.
pub const sleep_port: u16 = 0x600;

/// The S5 sleep type value written to the hw-reduced sleep-control register
/// to trigger poweroff. Task 5's shutdown-port device decodes
/// (s5_slp_typ << 2) | (1 << 5) on that register.
pub const s5_slp_typ: u8 = 5;

/// Options for building the ACPI table set.
pub const Options = struct {
    /// How many Processor Local APIC entries the MADT carries.
    cpus: u32 = 1,
};

/// The result of building the table set: the bytes to copy into guest RAM and
/// the physical address of the RSDP, reported by the Builder rather than
/// recomputed, so adding tables cannot desync where the RSDP lands.
pub const Built = struct {
    bytes: []u8,
    rsdp: u64,
};

// The FADT is 276 bytes (ACPI 6.x). Layout is fixed by the spec; fields are
// written by offset using std.mem.writeInt. Asserts below pin every field used.
const fadt_size: usize = 276;

// AML encoding for: Name (_S5, Package (2) { 5, 5 })
//
// ACPI spec §20.2.3: NameOp NameString; §20.2.5.4: PackageOp PkgLength
// NumElements PackageElementList.
//
// PkgLength counts itself plus the body that follows it:
//   body = NumElements(1 byte) + ByteData(2 bytes) + ByteData(2 bytes) = 5 bytes
//   PkgLength = 1 (self) + 5 (body) = 6
//
// The two Byte() elements encode s5_slp_typ for SLP_TYPa and SLP_TYPb.
const s5_aml = [_]u8{
    0x08, // NameOp
    0x5F, 0x53, 0x35, 0x5F, // "_S5_" NameSeg
    0x12, // PackageOp
    0x06, // PkgLength = 6 (self + 5 body bytes)
    0x02, // NumElements = 2
    almanac.aml.encoding.byte_prefix, s5_slp_typ, // SLP_TYPa = 5
    almanac.aml.encoding.byte_prefix, s5_slp_typ, // SLP_TYPb = 5
};

comptime {
    // PkgLength body: NumElements(1) + 2*ByteData(2 each) = 5; PkgLength = 1+5 = 6.
    std.debug.assert(s5_aml[6] == 6);
    std.debug.assert(s5_aml.len == 12);
}

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

// These three structs pin sizes via @sizeOf for the raw-offset writer, they are never memcpy'd, so do not fold the offset writes into struct stores and pick up padding.
// MADT fixed header that follows the 36-byte SDT header: local APIC address
// and the multiple-APIC flags word. Eight bytes total.
const MadtHeader = extern struct {
    local_apic_address: u32,
    flags: u32,
};

// Type 0x00 interrupt-controller entry: Processor Local APIC. Eight bytes.
const LocalApicEntry = extern struct {
    type: u8,
    length: u8,
    acpi_processor_id: u8,
    apic_id: u8,
    flags: u32 align(1),
};

// Type 0x01 interrupt-controller entry: I/O APIC. Twelve bytes.
const IoApicEntry = extern struct {
    type: u8,
    length: u8,
    ioapic_id: u8,
    reserved: u8,
    address: u32 align(1),
    global_system_interrupt_base: u32 align(1),
};

comptime {
    std.debug.assert(@sizeOf(MadtHeader) == 8);
    std.debug.assert(@sizeOf(LocalApicEntry) == 8);
    std.debug.assert(@sizeOf(IoApicEntry) == 12);
}

/// Build the MADT body (everything after the 36-byte SDT header) into `dst`.
/// `dst` must be exactly `madtBodyLen(cpus)` bytes.
fn writeMadtBody(dst: []u8, cpus: u32) void {
    // Fixed header: local APIC address and flags (bit 0 = PCAT_COMPAT).
    std.mem.writeInt(u32, dst[0..4], 0xfee00000, .little);
    std.mem.writeInt(u32, dst[4..8], 1, .little); // PCAT_COMPAT

    var off: usize = @sizeOf(MadtHeader);

    // One Processor Local APIC entry per cpu.
    var i: u32 = 0;
    while (i < cpus) : (i += 1) {
        const id: u8 = @intCast(i);
        dst[off + 0] = 0; // type: Processor Local APIC
        dst[off + 1] = @sizeOf(LocalApicEntry);
        dst[off + 2] = id; // acpi_processor_id
        dst[off + 3] = id; // apic_id
        std.mem.writeInt(u32, dst[off + 4 ..][0..4], 1, .little); // enabled
        off += @sizeOf(LocalApicEntry);
    }

    // One I/O APIC entry.
    dst[off + 0] = 1; // type: I/O APIC
    dst[off + 1] = @sizeOf(IoApicEntry);
    dst[off + 2] = 0; // ioapic_id
    dst[off + 3] = 0; // reserved
    std.mem.writeInt(u32, dst[off + 4 ..][0..4], 0xfec00000, .little);
    std.mem.writeInt(u32, dst[off + 8 ..][0..4], 0, .little); // gsi_base
}

/// Number of bytes in the MADT body for the given cpu count.
fn madtBodyLen(cpus: u32) usize {
    return @sizeOf(MadtHeader) + cpus * @sizeOf(LocalApicEntry) + @sizeOf(IoApicEntry);
}

/// Write a 12-byte GAS into `dst` at `off`. address_space=1 (SystemIO),
/// bit_width=8, bit_offset=0, access_size=1 (byte), address=port.
fn writeGas(dst: []u8, off: usize, port: u16) void {
    dst[off + 0] = 1; // address_space: SystemIO
    dst[off + 1] = 8; // bit_width
    dst[off + 2] = 0; // bit_offset
    dst[off + 3] = 1; // access_size: byte
    std.mem.writeInt(u64, dst[off + 4 ..][0..8], port, .little);
}

/// Build an RSDP, XSDT, hardware-reduced FADT, and DSDT carrying _S5 into
/// `buf` at guest physical address `base_phys`. Returns the bytes written and
/// the RSDP's physical address as the Builder placed it.
pub fn build(buf: []u8, base_phys: u64, opts: Options) !Built {
    var b = almanac.Builder.init(buf, base_phys);

    // The DSDT is placed before the FADT so its physical address is known when
    // the FADT's DSDT and X_DSDT fields are written. The DSDT is referenced
    // only by the FADT and is never listed in the XSDT (ACPI rule).
    const dsdt_phys = try b.addTable("DSDT", &s5_aml, 2);

    // Build the FADT body by hand because almanac's fadt() helper does not set
    // the sleep-control/status registers.
    var fadt_bytes = [_]u8{0} ** fadt_size;

    // SDT header (36 bytes): signature, length, revision, checksum (0 for now),
    // OEM id, OEM table id, OEM revision, creator id, creator revision.
    @memcpy(fadt_bytes[0..4], "FACP");
    std.mem.writeInt(u32, fadt_bytes[4..8], fadt_size, .little);
    fadt_bytes[8] = 6; // ACPI revision 6
    fadt_bytes[9] = 0; // checksum placeholder

    // These OEM / creator values mirror almanac.Builder's defaults so read-back agrees, a coupling.
    @memcpy(fadt_bytes[10..16], "MIDSTL");
    @memcpy(fadt_bytes[16..24], "ALMANAC ");
    std.mem.writeInt(u32, fadt_bytes[24..28], 1, .little);
    @memcpy(fadt_bytes[28..32], "ALMA");
    std.mem.writeInt(u32, fadt_bytes[32..36], 1, .little);

    // DSDT (32-bit, offset 40) and X_DSDT (64-bit, offset 140) point at the
    // DSDT placed above.
    std.mem.writeInt(u32, fadt_bytes[40..44], @truncate(dsdt_phys), .little);
    std.mem.writeInt(u64, fadt_bytes[140..148], dsdt_phys, .little);

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

    // Build the MADT body into a stack buffer sized for the cpu count. The
    // xAPIC id is one byte, so 256 is the ceiling; cpus is VMM config, so a
    // caller past it is a programmer error, caught here before the body is
    // sized and before the per-cpu loop narrows each id to a u8.
    const madt_max_cpus: u32 = 256;
    std.debug.assert(opts.cpus <= madt_max_cpus);
    const madt_max_body = @sizeOf(MadtHeader) + madt_max_cpus * @sizeOf(LocalApicEntry) + @sizeOf(IoApicEntry);
    var madt_body_buf = [_]u8{0} ** madt_max_body;
    const madt_body = madt_body_buf[0..madtBodyLen(opts.cpus)];
    writeMadtBody(madt_body, opts.cpus);
    const madt_phys = try b.addTable("APIC", madt_body, 4);

    const xsdt_phys = try b.xsdt(&.{ fadt_phys, madt_phys });
    const rsdp = try b.rsdp(xsdt_phys);

    return .{ .bytes = b.finish(), .rsdp = rsdp };
}

test "the madt describes the cpu and the ioapic" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const built = try build(&buf, base, .{ .cpus = 1 });
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
    const madt = (try tabs.findAs(almanac.Madt)).?;

    try testing.expectEqual(@as(u32, 0xfee00000), madt.localApicAddress());

    var local_apic_count: u32 = 0;
    var io_apic_count: u32 = 0;
    var io_apic_address: u32 = 0;
    var it = madt.iterator();
    while (try it.next()) |entry| {
        switch (entry) {
            .local_apic => local_apic_count += 1,
            .io_apic => |ia| {
                io_apic_count += 1;
                io_apic_address = ia.address;
            },
            else => {},
        }
    }
    try testing.expectEqual(true, local_apic_count >= 1);
    try testing.expectEqual(@as(u32, 1), io_apic_count);
    try testing.expectEqual(@as(u32, 0xfec00000), io_apic_address);
}

test "the acpi set has a hw-reduced fadt discoverable from the rsdp" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const built = try build(&buf, base, .{});
    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    // The OffsetMapper maps phys -> virt by adding the offset. We want:
    //   virt = @intFromPtr(&buf) + (phys - base)
    //        = phys + (@intFromPtr(&buf) - base)
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
    try std.testing.expect(tabs.usesXsdt());
    const fadt = (try tabs.findAs(almanac.Fadt)).?;
    try std.testing.expect(fadt.isHwReduced());
}

test "the fadt names the sleep port" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const built = try build(&buf, base, .{});

    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);
    const fadt = (try tabs.findAs(almanac.Fadt)).?;

    // SLEEP_CONTROL_REG is at FADT byte offset 244.
    const gas_bytes = fadt.bytes[sleep_control_off .. sleep_control_off + @sizeOf(almanac.Gas)];
    const g = almanac.Gas.fromBytes(gas_bytes);
    try testing.expectEqual(@as(u8, 1), g.address_space); // SystemIO
    try testing.expectEqual(sleep_port, @as(u16, @intCast(g.address)));
}

test "the dsdt carries an s5 package the fadt points at" {
    var buf: [4096]u8 align(16) = undefined;
    const base: u64 = 0x80000;
    const built = try build(&buf, base, .{});

    const Tables = almanac.TablesGeneric(almanac.OffsetMapper);
    const offset: u64 = @intFromPtr(&buf) -% base;
    const tabs = try Tables.init(.{ .offset = offset }, built.rsdp);

    // The FADT must point at a non-zero DSDT address.
    const fadt = (try tabs.findAs(almanac.Fadt)).?;
    const dsdt_addr = fadt.preferredDsdt();
    try std.testing.expect(dsdt_addr != 0);

    // Read the DSDT bytes via the offset mapper and spot-check the _S5 AML.
    // The DSDT begins with a 36-byte SDT header; the AML body follows.
    const dsdt_total = 36 + s5_aml.len;
    const dsdt_bytes = (almanac.OffsetMapper{ .offset = offset }).slice(dsdt_addr, dsdt_total);
    // Verify signature "DSDT" in the header.
    try std.testing.expect(std.mem.eql(u8, dsdt_bytes[0..4], "DSDT"));
    // The AML body starts at byte 36. Spot-check: NameOp, "_S5_", PackageOp,
    // PkgLength, and the two SLP_TYP bytes.
    const aml_body = dsdt_bytes[36..];
    try std.testing.expect(aml_body[0] == 0x08); // NameOp
    try std.testing.expect(std.mem.eql(u8, aml_body[1..5], "_S5_")); // NameSeg
    try std.testing.expect(aml_body[5] == 0x12); // PackageOp
    try std.testing.expect(aml_body[6] == 0x06); // PkgLength = 6
    try std.testing.expect(aml_body[8] == almanac.aml.encoding.byte_prefix); // SLP_TYPa prefix
    try std.testing.expect(aml_body[9] == s5_slp_typ); // SLP_TYPa = 5
    try std.testing.expect(aml_body[10] == almanac.aml.encoding.byte_prefix); // SLP_TYPb prefix
    try std.testing.expect(aml_body[11] == s5_slp_typ); // SLP_TYPb = 5
}

test {
    _ = almanac;
}
