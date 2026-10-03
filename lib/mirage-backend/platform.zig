//! The interrupt controller the guest is given, chosen by the architecture this is built for.
//!
//! On aarch64 the controller is a GIC the kernel emulates, and the runner creates it, saves it,
//! and gives it back. On x86 the controller is built with the machine and lives in the kernel from
//! the start, so there is nothing here to create: the type below is a stub that meets the same shape
//! and does nothing, which lets one runner serve both architectures without naming either.

const builtin = @import("builtin");
const device = @import("mirage-device");

/// Whether this build holds its own controller. Only a Linux aarch64 guest gets a GIC from this
/// process; every other build answers its interrupts in the kernel.
const own_controller = builtin.os.tag == .linux and builtin.cpu.arch == .aarch64;

const Vm = if (builtin.os.tag == .linux) @import("linux/kvm/Vm.zig") else void;
const Gic = if (own_controller) @import("linux/kvm/Gic.zig") else void;

/// The controller the runner holds. On aarch64 it is the real GIC; on x86 it is a stub.
pub const Controller = if (own_controller) Gic else Stub;

/// Create the controller the guest is given, after every CPU exists.
///
/// aarch64 makes a GIC at the addresses the device tree names. x86 makes nothing: the in kernel
/// controller already exists, and the stub it returns holds no state.
pub fn createController(vm: *Vm, cpus: u32) !Controller {
    if (comptime own_controller) {
        const arm64 = @import("mirage-arm64");
        return Gic.create(vm, cpus, arm64.fdt.gicd_base, arm64.fdt.gicr_base);
    }
    _ = .{ vm, cpus };
    return .{};
}

/// The line into the guest, for a run loop that sets it from a controller this process holds. x86
/// answers its own interrupts in the kernel, so there is no line here and the run loop is given none.
pub fn controllerLine(ctrl: *Controller) ?device.Controller {
    if (comptime own_controller) {
        return ctrl.controller();
    }
    _ = .{ctrl};
    return null;
}

/// What stands in for a controller on an architecture whose own is in the kernel. It meets the shape
/// the runner expects and does nothing: there is no state to save, nothing is ever dropped, and there
/// is no line to set.
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
