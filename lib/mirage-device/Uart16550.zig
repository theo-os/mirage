//! A 16550 UART, enough of one for an x86 guest to print through a polled console.
//!
//! Two registers carry all the work: the transmit holding register the guest writes a
//! byte to, and the line status register it reads to know the transmitter is free. No
//! divisor-latch emulation or interrupt routing is needed for polled early console output.

const std = @import("std");
const testing = @import("mirage-testing");
const Bus = @import("Bus.zig");

const Uart16550 = @This();

pub const len = 8;

/// The registers this port exposes, by offset from the base port address.
const reg = struct {
    /// Transmit holding register (write) / receive buffer register (read).
    const thr = 0;
    /// Interrupt enable register. Accepted and ignored for polled output.
    const ier = 1;
    /// Interrupt identification / FIFO control. Accepted and ignored.
    const iir_fcr = 2;
    /// Line control register. Accepted and ignored.
    const lcr = 3;
    /// Modem control register. Accepted and ignored.
    const mcr = 4;
    /// Line status register. Reports the transmitter always ready.
    const lsr = 5;
    /// Modem status register. Accepted and ignored.
    const msr = 6;
    /// Scratch register. Accepted and ignored.
    const scr = 7;
};

/// THRE (bit 5) and TEMT (bit 6): the transmitter holds nothing and has nothing in
/// flight. A guest polls the line status before writing, so a port that never reports
/// itself ready leaves the guest spinning forever.
const lsr_ready: u64 = 0x60;

sink: *std.Io.Writer,
/// Bytes the sink would not take. A byte lost in silence is a bug that hides itself.
dropped: u64 = 0,

pub fn device(self: *Uart16550, port: u64) Bus.Device {
    return .{
        .base = port,
        .len = len,
        .ctx = self,
        .vtable = &.{ .read = Uart16550.read, .write = Uart16550.write },
    };
}

fn read(ctx: *anyopaque, offset: u64, size: Bus.Size) u64 {
    _ = size;
    const self: *Uart16550 = @ptrCast(@alignCast(ctx));
    _ = self;
    return switch (offset) {
        reg.lsr => lsr_ready,
        // RBR (offset 0) returns 0: no input in B1.
        reg.thr, reg.ier, reg.iir_fcr, reg.lcr, reg.mcr, reg.msr, reg.scr => 0,
        else => 0,
    };
}

fn write(ctx: *anyopaque, offset: u64, size: Bus.Size, value: u64) void {
    _ = size;
    const self: *Uart16550 = @ptrCast(@alignCast(ctx));
    switch (offset) {
        reg.thr => self.sink.writeByte(@truncate(value)) catch {
            self.dropped += 1;
        },
        // IER, IIR/FCR, LCR, MCR, MSR, SCR: accepted and ignored.
        reg.ier, reg.iir_fcr, reg.lcr, reg.mcr, reg.msr, reg.scr => {},
        else => {},
    }
}

test "a byte written to the 16550 transmit register reaches the sink" {
    var buf: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buf);
    var uart: Uart16550 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x3f8)};
    var bus: Bus = .{ .devices = &devices };
    bus.write(0x3f8, .byte, 'M');
    try testing.expectEqualSlices(u8, "M", sink.buffered());
}

test "the line status register reports the transmitter ready" {
    // read 0x3f8+5 -> 0x60 (THRE|TEMT) so the guest never spins
    var buf: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buf);
    var uart: Uart16550 = .{ .sink = &sink };
    var devices = [_]Bus.Device{uart.device(0x3f8)};
    var bus: Bus = .{ .devices = &devices };
    try testing.expectEqual(@as(u64, 0x60), bus.read(0x3f8 + 5, .byte));
}
