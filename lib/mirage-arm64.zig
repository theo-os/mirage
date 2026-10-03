//! The parts of aarch64 a guest needs before it can run.
//!
//! Nothing here knows which hypervisor is underneath. The Linux boot protocol, the
//! interrupt controller and the timer are properties of the architecture, so KVM and
//! Hypervisor.framework both meet them in the same shape.

pub const boot = @import("mirage-arm64/boot.zig");
pub const esr = @import("mirage-arm64/esr.zig");
pub const fdt = @import("mirage-arm64/fdt.zig");
pub const psci = @import("mirage-arm64/psci.zig");
pub const timer = @import("mirage-arm64/timer.zig");
pub const registers = @import("mirage-arm64/registers.zig");
pub const Register = registers.Register;
pub const enter = @import("mirage-arm64/enter.zig").enter;

/// Whether this architecture has a power interface the VMM answers. arm does; the run
/// loop routes the power and timer exits through here.
pub const has_power = true;

test {
    _ = boot;
    _ = esr;
    _ = psci;
    _ = timer;
    _ = fdt;
    _ = registers;
    _ = Register;
    _ = &enter;
}
