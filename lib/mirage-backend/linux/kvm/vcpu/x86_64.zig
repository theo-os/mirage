//! A KVM virtual CPU on x86-64: CPUID, flat protected mode, and the general registers.
//!
//! `create` puts the vCPU in flat 32-bit protected mode with paging off, so a
//! guest's RIP is a physical address. CPUID is loaded from the host so a guest
//! that executes `cpuid` does not fault.

const std = @import("std");
const testing = @import("mirage-testing");
const Backend = @import("../../../Backend.zig");
const Vm = @import("../Vm.zig");
const ioctl = @import("../ioctl.zig");
const shared = @import("run.zig");
const linux = std.os.linux;

const Vcpu = @This();

const nr = struct {
    const get_vcpu_mmap_size = 0x04;
    const create_vcpu = 0x41;
    const run = 0x80;
    const get_regs = 0x81;
    const set_regs = 0x82;
    const get_sregs = 0x83;
    const set_sregs = 0x84;
    const set_cpuid2 = 0x90;
    const get_supported_cpuid = 0x05;
};

/// `struct kvm_regs` — the general-purpose registers the kernel reads and writes as one block.
const Regs = extern struct {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
    comptime {
        if (@sizeOf(@This()) != 144) @compileError("kvm_regs is 18 u64 = 144 bytes");
    }
};

/// `struct kvm_segment` — one protected-mode segment descriptor in the form KVM accepts.
const Segment = extern struct {
    base: u64,
    limit: u32,
    selector: u16,
    kind: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
    comptime {
        if (@sizeOf(@This()) != 24) @compileError("kvm_segment is 24 bytes");
    }
};

/// `struct kvm_dtable` — a descriptor table register (GDTR/IDTR).
const Dtable = extern struct {
    base: u64,
    limit: u16,
    padding: [3]u16,
    comptime {
        if (@sizeOf(@This()) != 16) @compileError("kvm_dtable is 16 bytes");
    }
};

/// `struct kvm_sregs` — the segment and control registers.
const Sregs = extern struct {
    cs: Segment,
    ds: Segment,
    es: Segment,
    fs: Segment,
    gs: Segment,
    ss: Segment,
    tr: Segment,
    ldt: Segment,
    gdt: Dtable,
    idt: Dtable,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [4]u64,
    comptime {
        if (@sizeOf(@This()) != 312) @compileError("kvm_sregs is 312 bytes");
    }
};

/// `struct kvm_cpuid_entry2` — one leaf the kernel will answer for the guest.
const CpuidEntry2 = extern struct {
    function: u32,
    index: u32,
    flags: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    padding: [3]u32,
    comptime {
        if (@sizeOf(@This()) != 40) @compileError("kvm_cpuid_entry2 is 40 bytes");
    }
};

/// `struct kvm_cpuid2` header — the kernel sees just this size in the ioctl number because
/// `entries` is a flexible array in C. Entries follow immediately in memory.
const Cpuid2Header = extern struct {
    nent: u32,
    padding: u32,
    comptime {
        if (@sizeOf(@This()) != 8) @compileError("kvm_cpuid2 header is 8 bytes");
    }
};

/// Maximum CPUID leaves the host is likely to report. 128 is well above any current CPU.
const max_cpuid_entries = 128;

/// On-stack buffer: the header followed by space for entries.
const Cpuid2Buffer = extern struct {
    header: Cpuid2Header,
    entries: [max_cpuid_entries]CpuidEntry2,
};

pub const Run = shared.Run;

pub const Error = error{HypervisorFault} || ioctl.Error || std.posix.MMapError;

/// Which exit the last run came back with, kept for the completion routing a port read
/// needs. Filled in later with the real decode.
pub const LastExit = enum { none, mmio, port_in };

fd: std.posix.fd_t,
mapping: []align(std.heap.page_size_min) u8,
state: *Run,
last_exit: LastExit = .none,

pub fn create(vm: *Vm, index: u32) Error!Vcpu {
    const raw = try ioctl.call(vm.fd, comptime ioctl.request(.none, void, nr.create_vcpu), index);
    const fd: std.posix.fd_t = @intCast(raw);
    errdefer _ = linux.close(fd);

    const size = try ioctl.call(vm.kvm, comptime ioctl.request(.none, void, nr.get_vcpu_mmap_size), 0);
    const mapping = try std.posix.mmap(
        null,
        size,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .SHARED },
        fd,
        0,
    );
    errdefer std.posix.munmap(mapping);

    try loadCpuid(vm.kvm, fd);
    try enterFlatMode(fd);

    return .{ .fd = fd, .mapping = mapping, .state = @ptrCast(@alignCast(mapping.ptr)) };
}

/// Copy the host's supported CPUID leaves to the vCPU so a guest `cpuid` does not fault.
///
/// The ioctl number encodes the header size only, because `entries` is a C flexible array.
/// The kernel reads and writes past the header on purpose.
fn loadCpuid(kvm_fd: std.posix.fd_t, vcpu_fd: std.posix.fd_t) Error!void {
    var buf: Cpuid2Buffer = .{
        .header = .{ .nent = max_cpuid_entries, .padding = 0 },
        .entries = undefined,
    };
    _ = try ioctl.call(
        kvm_fd,
        comptime ioctl.request(.read_write, Cpuid2Header, nr.get_supported_cpuid),
        @intFromPtr(&buf),
    );
    _ = try ioctl.call(
        vcpu_fd,
        comptime ioctl.request(.write, Cpuid2Header, nr.set_cpuid2),
        @intFromPtr(&buf),
    );
}

/// A flat code segment: base 0, 4G limit, 32-bit, present, executable/readable.
const cs_flat: Segment = .{
    .base = 0,
    .limit = 0xffff_ffff,
    .selector = 0x8,
    .kind = 0xb, // executable, readable, accessed
    .present = 1,
    .dpl = 0,
    .db = 1,
    .s = 1,
    .l = 0,
    .g = 1,
    .avl = 0,
    .unusable = 0,
    .padding = 0,
};

/// A flat data segment: same span as code, read/write.
const ds_flat: Segment = .{
    .base = 0,
    .limit = 0xffff_ffff,
    .selector = 0x10,
    .kind = 0x3, // read/write, accessed
    .present = 1,
    .dpl = 0,
    .db = 1,
    .s = 1,
    .l = 0,
    .g = 1,
    .avl = 0,
    .unusable = 0,
    .padding = 0,
};

/// Put the vCPU in flat 32-bit protected mode with paging off.
///
/// Linear addresses equal physical addresses, so a test can point RIP at a GPA directly
/// without building page tables.
fn enterFlatMode(vcpu_fd: std.posix.fd_t) Error!void {
    var sregs: Sregs = undefined;
    _ = try ioctl.call(
        vcpu_fd,
        comptime ioctl.request(.read, Sregs, nr.get_sregs),
        @intFromPtr(&sregs),
    );

    sregs.cs = cs_flat;
    sregs.ds = ds_flat;
    sregs.es = ds_flat;
    sregs.ss = ds_flat;

    // PE=1 enables protected mode; PG (bit 31) stays 0 so paging is off.
    sregs.cr0 = (sregs.cr0 | 1) & ~@as(u64, 1 << 31);
    sregs.cr4 = 0;

    _ = try ioctl.call(
        vcpu_fd,
        comptime ioctl.request(.write, Sregs, nr.set_sregs),
        @intFromPtr(&sregs),
    );
}

pub fn deinit(self: *Vcpu) void {
    std.posix.munmap(self.mapping);
    _ = linux.close(self.fd);
    self.* = undefined;
}

pub fn setRegister(self: *Vcpu, reg: Backend.Register, value: u64) Error!void {
    var regs: Regs = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Regs, nr.get_regs), @intFromPtr(&regs));
    switch (reg) {
        .rip => regs.rip = value,
        .rsi => regs.rsi = value,
        .rdi => regs.rdi = value,
        .rdx => regs.rdx = value,
        .rcx => regs.rcx = value,
        .rflags => regs.rflags = value,
    }
    _ = try ioctl.call(self.fd, comptime ioctl.request(.write, Regs, nr.set_regs), @intFromPtr(&regs));
}

pub fn getRegister(self: *Vcpu, reg: Backend.Register) Error!u64 {
    var regs: Regs = undefined;
    _ = try ioctl.call(self.fd, comptime ioctl.request(.read, Regs, nr.get_regs), @intFromPtr(&regs));
    return switch (reg) {
        .rip => regs.rip,
        .rsi => regs.rsi,
        .rdi => regs.rdi,
        .rdx => regs.rdx,
        .rcx => regs.rcx,
        .rflags => regs.rflags,
    };
}

pub fn run(self: *Vcpu) Error!Backend.Exit {
    _ = self;
    return Error.NotSupported;
}

pub fn completeMmioRead(self: *Vcpu, value: u64) Error!void {
    _ = self;
    _ = value;
    return Error.NotSupported;
}

pub fn runState(self: *Vcpu) Error!u32 {
    _ = self;
    return Error.NotSupported;
}

pub fn setRunState(self: *Vcpu, value: u32) Error!void {
    _ = self;
    _ = value;
    return Error.NotSupported;
}

pub fn save(self: *Vcpu, ids: []const u64, into: []u8) Error!usize {
    _ = self;
    _ = ids;
    _ = into;
    return Error.NotSupported;
}

pub const Restored = struct {
    written: usize,
    refused: usize,
};

pub fn load(self: *Vcpu, from: []const u8) Error!Restored {
    _ = self;
    _ = from;
    return Error.NotSupported;
}

const ram = 0x4000_0000;

fn openVm() !Vm {
    return Vm.create() catch |err| switch (err) {
        error.NoKvm => error.SkipZigTest,
        else => err,
    };
}

test "a vcpu is created and its run structure is mapped" {
    var vm = try openVm();
    defer vm.deinit();

    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();

    try std.testing.expect(cpu.fd > 0);
}

test "an x86 register written is the register read back" {
    var vm = try openVm();
    defer vm.deinit();
    var cpu = try Vcpu.create(&vm, 0);
    defer cpu.deinit();
    try cpu.setRegister(.rip, 0x1000);
    try cpu.setRegister(.rsi, 0xdead_beef);
    try testing.expectEqual(@as(u64, 0x1000), try cpu.getRegister(.rip));
    try testing.expectEqual(@as(u64, 0xdead_beef), try cpu.getRegister(.rsi));
}
