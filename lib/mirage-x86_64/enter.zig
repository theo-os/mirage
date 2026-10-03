//! Put an x86-64 guest at its entry point the way the Linux boot entry asks.
//!
//! The 64-bit entry takes its boot-params pointer in `rsi`; the shared layout names
//! that address `device_tree`, which on this architecture is where boot params go. Bit
//! one of the flags register is always set. The hypervisor and the layout are passed in
//! rather than imported, so this stays below the backend. The real layout and the full
//! register set come later.

pub fn enter(hv: anytype, vcpu: anytype, layout: anytype) !void {
    try hv.setRegister(vcpu, .rip, layout.entry);
    try hv.setRegister(vcpu, .rsi, layout.device_tree);
    try hv.setRegister(vcpu, .rflags, 0x2);
}
