//! The interrupt controller the guest is given, chosen by the architecture this is built for.
//!
//! On aarch64 the controller is a GIC the kernel emulates, and the runner creates it, saves it,
//! and gives it back. On x86 the irqchip is built into the machine from creation, so this process
//! keeps only a pointer to it and drives interrupts through setIrq. On all other targets a stub
//! stands in with the same shape and does nothing.

const std = @import("std");
const builtin = @import("builtin");
const device = @import("mirage-device");

/// Whether this build holds a GIC. Only a Linux aarch64 guest gets one from this process.
const own_controller = builtin.os.tag == .linux and builtin.cpu.arch == .aarch64;

/// Whether this build uses the in-kernel x86 irqchip line.
const x86_controller = builtin.os.tag == .linux and builtin.cpu.arch == .x86_64;

const Vm = if (builtin.os.tag == .linux) @import("linux/kvm/Vm.zig") else void;
const Gic = if (own_controller) @import("linux/kvm/Gic.zig") else void;
const X86Irq = if (x86_controller) @import("linux/kvm/X86Irq.zig") else void;

/// The controller the runner holds. On aarch64 it is the GIC; on x86 it is the irqchip line;
/// on all other targets it is a stub.
pub const Controller = if (own_controller) Gic else if (x86_controller) X86Irq else Stub;

/// Create the controller the guest is given, after every CPU exists.
pub fn createController(vm: *Vm, cpus: u32) !Controller {
    if (comptime own_controller) {
        const arm64 = @import("mirage-arm64");
        return Gic.create(vm, cpus, arm64.fdt.gicd_base, arm64.fdt.gicr_base);
    }
    if (comptime x86_controller) return X86Irq.create(vm, cpus);
    _ = .{ vm, cpus };
    return .{};
}

/// The line into the guest, for a run loop that sets it from a controller this process holds.
pub fn controllerLine(ctrl: *Controller) ?device.Controller {
    if (comptime own_controller) {
        return ctrl.controller();
    }
    if (comptime x86_controller) return ctrl.controller();
    _ = .{ctrl};
    return null;
}

/// What stands in for a controller on a target with no supported interrupt controller. It meets the
/// shape the runner expects and does nothing.
const Stub = struct {
    dropped: u64 = 0,

    pub fn deinit(self: *Stub) void {
        _ = self;
    }

    pub const State = struct {
        pub fn size(cpus: usize) usize {
            _ = cpus;
            return 0;
        }
    };

    pub fn save(self: *Stub, cpus: usize, into: []u8) error{}!usize {
        _ = self;
        _ = cpus;
        _ = into;
        return 0;
    }

    pub fn load(self: *Stub, from: []const u8) error{}!usize {
        _ = self;
        _ = from;
        return 0;
    }
};

test "the x86 controller line is real and quiet on the cpu line" {
    if (comptime builtin.cpu.arch != .x86_64) return error.SkipZigTest;

    // On x86 the Controller must be X86Irq, not Stub. The raise/lower -> setIrq path is
    // proven functionally by the x86 vsock gate (Task 6), the same way the arm GIC is proven
    // by its own gates rather than a fake-Vm unit test.
    comptime std.debug.assert(@hasField(Controller, "vm"));

    // signalled never touches vm, so a stack instance with an undefined pointer is safe here.
    var irq: Controller = .{ .vm = undefined };
    const line = irq.controller();
    try std.testing.expect(!line.signalled(line.ctx, 0));
}
