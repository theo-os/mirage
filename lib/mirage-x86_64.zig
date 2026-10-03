//! The parts of x86-64 a guest needs before it can run.
//!
//! Nothing here knows which hypervisor is underneath. The register set and the boot
//! entry are properties of the architecture. This is the seam's x86 side; the bodies
//! that boot a real guest come later.

pub const registers = @import("mirage-x86_64/registers.zig");
pub const Register = registers.Register;
pub const enter = @import("mirage-x86_64/enter.zig").enter;
pub const boot = @import("mirage-x86_64/boot.zig");

/// Whether this architecture has a power interface the VMM answers. x86 has none: the
/// hypervisor never emits a power, idle, or timer exit, so the run loop's arms for them
/// are never reached here.
pub const has_power = false;

test {
    _ = registers;
    _ = Register;
    _ = &enter;
    _ = boot;
}
