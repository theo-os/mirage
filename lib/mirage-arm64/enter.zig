//! Put a guest at its entry point the way the arm64 Linux boot protocol asks.
//!
//! The protocol wants the device tree address in `x0` and the other three argument
//! registers zeroed. The hypervisor and the layout are passed in rather than imported,
//! so this stays below the backend that names this architecture. Only the layout's entry
//! and device tree addresses are read.

pub fn enter(hv: anytype, vcpu: anytype, layout: anytype) !void {
    try hv.setRegister(vcpu, .pc, layout.entry);
    try hv.setRegister(vcpu, .x0, layout.device_tree);
    try hv.setRegister(vcpu, .x1, 0);
    try hv.setRegister(vcpu, .x2, 0);
    try hv.setRegister(vcpu, .x3, 0);
}
