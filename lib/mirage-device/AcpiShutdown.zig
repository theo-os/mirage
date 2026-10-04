//! An ACPI shutdown port.
//!
//! The hw-reduced FADT names an I/O port as its sleep-control register.
//! When the guest kernel powers the machine off it writes
//! (SLP_TYP << 2) | SLP_EN to that port, where SLP_EN is bit 5.
//! This device recognises the S5 value and records the request.
//! The run loop reads `requested` and returns `Reason.shutdown`.

const std = @import("std");
const Bus = @import("Bus.zig");

const AcpiShutdown = @This();

/// The S5 sleep type this port was built to recognise.
slp_typ: u8,
/// Set when the guest has asked the machine to power off.
requested: bool = false,

/// Return a `Bus.Device` anchored at `port`. The port is one byte wide:
/// only the sleep-control register address is claimed.
pub fn device(self: *AcpiShutdown, port: u64) Bus.Device {
    return .{
        .base = port,
        .len = 1,
        .ctx = self,
        .vtable = &.{ .read = AcpiShutdown.read, .write = AcpiShutdown.write },
    };
}

fn read(_: *anyopaque, _: u64, _: Bus.Size) u64 {
    return 0;
}

fn write(ctx: *anyopaque, _: u64, _: Bus.Size, value: u64) void {
    const self: *AcpiShutdown = @ptrCast(@alignCast(ctx));
    // hw-reduced sleep-control: bits 2-4 = SLP_TYP, bit 5 = SLP_EN.
    const slp_en: u8 = 1 << 5;
    const expected: u8 = (@as(u8, self.slp_typ) << 2) | slp_en;
    self.requested = (@as(u8, @truncate(value)) == expected);
}

test "a write of the s5 sleep value to the acpi port requests shutdown" {
    const acpi_sleep_port: u64 = 0x600;
    var dev: AcpiShutdown = .{ .slp_typ = 5 };
    var devices = [_]Bus.Device{dev.device(acpi_sleep_port)};
    var ports: Bus = .{ .devices = &devices };
    try std.testing.expect(!dev.requested);
    ports.write(acpi_sleep_port, .byte, (5 << 2) | (1 << 5)); // SLP_TYP=5, SLP_EN
    try std.testing.expect(dev.requested);
    // a non-matching write does not request shutdown
    dev.requested = false;
    ports.write(acpi_sleep_port, .byte, 0x00);
    try std.testing.expect(!dev.requested);
}
