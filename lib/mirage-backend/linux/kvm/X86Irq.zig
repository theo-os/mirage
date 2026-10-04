//! The x86 interrupt controller line, backed by the in-kernel irqchip.
//!
//! KVM creates the APIC and IOAPIC when the VM is created (KVM_CREATE_IRQCHIP).
//! This type keeps a pointer to the VM so it can call setIrq when a device
//! raises or lowers a line. The kernel drives the actual CPU interrupt pin, so
//! signalled always returns false.

const device = @import("mirage-device");
const Vm = @import("Vm.zig");

const X86Irq = @This();

vm: *Vm,
/// Interrupts the kernel refused. A failed injection is a runtime fault, not a
/// programmer error, so it is counted and the guest carries on.
dropped: u64 = 0,

pub fn create(vm: *Vm, cpus: u32) X86Irq {
    _ = cpus;
    return .{ .vm = vm };
}

pub fn deinit(self: *X86Irq) void {
    _ = self;
}

fn cast(ctx: *anyopaque) *X86Irq {
    return @ptrCast(@alignCast(ctx));
}

fn askSignalled(_: *anyopaque, _: u32) bool {
    return false;
}

fn askRaise(ctx: *anyopaque, intid: u32) void {
    const self = cast(ctx);
    self.vm.setIrq(intid, true) catch {
        self.dropped +%= 1;
    };
}

fn askRaiseOn(ctx: *anyopaque, cpu: u32, intid: u32) void {
    _ = cpu;
    askRaise(ctx, intid);
}

fn askLower(ctx: *anyopaque, intid: u32) void {
    const self = cast(ctx);
    self.vm.setIrq(intid, false) catch {
        self.dropped +%= 1;
    };
}

fn askActing(_: *anyopaque, _: u32) void {}

pub fn controller(self: *X86Irq) device.Controller {
    return .{
        .ctx = self,
        .signalled = X86Irq.askSignalled,
        .raise = X86Irq.askRaise,
        .raiseOn = X86Irq.askRaiseOn,
        .lower = X86Irq.askLower,
        .acting = X86Irq.askActing,
    };
}

pub const State = struct {
    pub fn size(cpus: usize) usize {
        _ = cpus;
        return 0;
    }
};

pub fn save(self: *X86Irq, cpus: usize, into: []u8) error{}!usize {
    _ = self;
    _ = cpus;
    _ = into;
    return 0;
}

pub fn load(self: *X86Irq, from: []const u8) error{}!usize {
    _ = self;
    _ = from;
    return 0;
}
