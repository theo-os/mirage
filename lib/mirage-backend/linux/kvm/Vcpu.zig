//! The KVM virtual CPU, chosen by the architecture this build runs on.
//!
//! A vCPU is where KVM stops being arch-neutral: the registers and the exits differ by
//! architecture. This file picks the one for the host, so nothing above it names an
//! architecture.

const builtin = @import("builtin");

pub const Vcpu = switch (builtin.cpu.arch) {
    .aarch64 => @import("vcpu/arm64.zig"),
    .x86_64 => @import("vcpu/x86_64.zig"),
    else => @compileError("mirage's kvm backend runs on aarch64 and x86_64"),
};
