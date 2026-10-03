//! Put a guest at its entry point the way the arm64 Linux boot protocol asks.
//!
//! The protocol wants the device tree address in `x0` and the other three argument
//! registers zeroed. The hypervisor and the layout are passed in rather than imported,
//! so this stays below the backend that names this architecture. Only the layout's entry
//! and device tree addresses are read.

const boot = @import("boot.zig");

pub fn enter(hv: anytype, vcpu: anytype, layout: anytype) !void {
    const Shim = struct {
        hv: @TypeOf(hv),
        vcpu: @TypeOf(vcpu),

        fn setRegister(self: @This(), reg: anytype, val: u64) !void {
            try self.hv.setRegister(self.vcpu, reg, val);
        }
    };
    try boot.enter(Shim{ .hv = hv, .vcpu = vcpu }, layout);
}
