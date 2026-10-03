//! The shared `kvm_run` structure, and the exit and event numbers at the top of it.
//!
//! The head of `struct kvm_run` is the same on every architecture: the exit reason
//! sits at a fixed offset, and the union that follows holds the decoded access. Both
//! arch vCPUs read it in the same shape, so the struct and its offset asserts live in
//! one place rather than once per architecture.

/// `KVM_EXIT_*` in `linux/kvm.h`.
pub const exit = struct {
    pub const io = 2;
    pub const mmio = 6;
    pub const shutdown = 8;
    pub const system_event = 24;
};

/// `KVM_SYSTEM_EVENT_*`.
pub const event = struct {
    pub const shutdown = 1;
    pub const reset = 2;
};

pub const Run = extern struct {
    request_interrupt_window: u8,
    immediate_exit: u8,
    padding1: [6]u8,
    exit_reason: u32,
    ready_for_interrupt_injection: u8,
    if_flag: u8,
    flags: u16,
    cr8: u64,
    apic_base: u64,
    data: Data,

    pub const Mmio = extern struct {
        phys_addr: u64,
        data: [8]u8,
        len: u32,
        is_write: u8,
    };

    /// `struct kvm_run`'s `io`. A port access reports its direction, width, port, and
    /// how many values sit in the data page at `data_offset`.
    pub const Io = extern struct {
        direction: u8,
        size: u8,
        port: u16,
        count: u32,
        data_offset: u64,
    };

    pub const SystemEvent = extern struct {
        type: u32,
        ndata: u32,
        data: [16]u64,
    };

    pub const Data = extern union {
        mmio: Mmio,
        io: Io,
        system_event: SystemEvent,
    };

    comptime {
        // The kernel fixes these two offsets. If this struct ever drifts from
        // `struct kvm_run`, the code reads some other field as the exit reason and
        // behaves at random. Fail the build instead.
        if (@offsetOf(Run, "exit_reason") != 8) @compileError("kvm_run.exit_reason is not at offset 8");
        if (@offsetOf(Run, "data") != 32) @compileError("the kvm_run union is not at offset 32");
    }
};
