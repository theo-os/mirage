//! A KVM virtual machine and the memory slots it owns.
//!
//! A shared slot is ordinary anonymous memory the VMM maps and the guest sees at a
//! guest physical address. A private slot is a `guest_memfd` created without
//! `GUEST_MEMFD_FLAG_MMAP`, so the VMM has nothing to map and `GuestMemory.slice`
//! refuses it.
//!
//! On aarch64 the two are separate slots decided before launch, because this kernel
//! has no `KVM_CAP_MEMORY_ATTRIBUTES` and a guest cannot move a page between private
//! and shared while it runs. See the probe in `probe.zig` for what was asked.

const std = @import("std");
const builtin = @import("builtin");
const testing = @import("mirage-testing");
const GuestMemory = @import("mirage-memory").GuestMemory;
const ioctl = @import("ioctl.zig");
const probe = @import("probe.zig");
const linux = std.os.linux;

const Vm = @This();

pub const max_slots = 16;

const nr = struct {
    const check_extension = 0x03;
    const create_vm = 0x01;
    const create_irqchip = 0x60;
    const irq_line = 0x61;
    const create_pit2 = 0x77;
    const create_guest_memfd = 0xd4;
    const set_user_memory_region2 = 0x49;
    const memory_encrypt_op = 0xba;
};

const sev_cmd_id = struct {
    const init2: u32 = 22;
    const launch_start: u32 = 2;
    const launch_update_data: u32 = 3;
    const launch_update_vmsa: u32 = 4;
    const launch_secret: u32 = 5;
    const launch_measure: u32 = 6;
    const launch_finish: u32 = 7;
};

/// `struct kvm_pit_config`: one word of flags and fifteen reserved, sixty four bytes in all.
const PitConfig = extern struct {
    flags: u32,
    pad: [15]u32,

    comptime {
        std.debug.assert(@sizeOf(PitConfig) == 64);
    }
};

/// `KVM_MEM_GUEST_MEMFD` in `linux/kvm.h`.
const mem_guest_memfd: u32 = 1 << 2;

pub const Kind = enum { shared, private };

pub const IrqLevel = extern struct {
    irq: u32,
    level: u32,
};

/// An SPI is a shared interrupt, the kind a device raises. The interrupt number a
/// device tree calls `n` is `32 + n` to the controller, because the first 32 are
/// reserved for interrupts private to a CPU.
const spi_base = 32;

/// `irq_type` 1 selects a shared interrupt on the in kernel controller.
const irq_type_spi = 1;

/// Raise or lower a device interrupt. On x86 the argument is a bare GSI; the
/// in-kernel PIC and IOAPIC route it. On arm the argument is an SPI number and
/// the GIC routes it. The controller must exist before this is called.
pub fn setIrq(self: *Vm, irq: u32, level: bool) Error!void {
    const encoded: u32 = switch (comptime builtin.cpu.arch) {
        .x86_64 => irq,
        .aarch64 => (irq_type_spi << 24) | (spi_base + irq),
        else => @compileError("setIrq is only defined for x86_64 and aarch64"),
    };
    const request: IrqLevel = .{
        .irq = encoded,
        .level = @intFromBool(level),
    };
    _ = try ioctl.call(
        self.fd,
        comptime ioctl.request(.write, IrqLevel, nr.irq_line),
        @intFromPtr(&request),
    );
}

pub const Error = error{
    NoKvm,
    TooManySlots,
    Misaligned,
    PrivateMemoryUnsupported,
    SevFirmwareError,
} || ioctl.Error || std.posix.MMapError;

const Slot = struct {
    mapping: ?[]align(std.heap.page_size_min) u8 = null,
    memfd: ?std.posix.fd_t = null,

    fn release(self: Slot) void {
        if (self.mapping) |m| std.posix.munmap(m);
        if (self.memfd) |fd| _ = linux.close(fd);
    }
};

kvm: std.posix.fd_t,
fd: std.posix.fd_t,
slots: u32 = 0,
owned: [max_slots]Slot = @splat(.{}),
/// True for a SEV-ES VM (type 3). The guest cannot manage the CET supervisor xstate under
/// encrypted state, so its CPUID must not advertise it. See the leaf 0xD filter in the vcpu.
sev_es: bool = false,

pub fn create() Error!Vm {
    return createWithType(0);
}

pub fn createWithType(vm_type: u64) Error!Vm {
    const opened = linux.open("/dev/kvm", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return Error.NoKvm;
    const kvm: std.posix.fd_t = @intCast(opened);
    errdefer _ = linux.close(kvm);

    // Machine type zero asks for this host's default intermediate physical address
    // size. aarch64 encodes a wider address space in the low bits of this argument.
    const raw = try ioctl.call(kvm, comptime ioctl.request(.none, void, nr.create_vm), vm_type);
    const vm_fd: std.posix.fd_t = @intCast(raw);
    errdefer _ = linux.close(vm_fd);

    // On x86 the in-kernel PIC, IOAPIC, and per-vcpu LAPIC are built here, before
    // any vcpu exists. The kernel requires that order. On arm the GIC fills this
    // role and is created separately via Gic.zig; nothing changes on that path.
    // A SEV VM (type 2) builds the same irqchip, but after sevInit2, so the SEV
    // path calls installIrqchip itself once init is done.
    if (comptime builtin.cpu.arch == .x86_64) {
        if (vm_type == 0) try installIrqchip(vm_fd);
    }

    return .{ .kvm = kvm, .fd = vm_fd, .sev_es = vm_type == 3 };
}

/// Build the in-kernel PIC, IOAPIC, and PIT. x86 only, and before any vcpu exists.
fn installIrqchip(vm_fd: std.posix.fd_t) Error!void {
    _ = try ioctl.call(vm_fd, comptime ioctl.request(.none, void, nr.create_irqchip), 0);

    // The in-kernel timer the guest's clock needs. Without it the kernel reaches userspace but
    // its timekeeping never advances, so the first process makes no progress. The LAPIC timer is
    // not enough here: the kernel calibrates against this one first.
    const pit: PitConfig = .{ .flags = 0, .pad = @splat(0) };
    _ = try ioctl.call(vm_fd, comptime ioctl.request(.write, PitConfig, nr.create_pit2), @intFromPtr(&pit));
}

/// Build the x86 in-kernel irqchip and PIT for a SEV VM, after sevInit2 and before any vcpu.
pub fn createIrqchip(self: *Vm) Error!void {
    if (comptime builtin.cpu.arch != .x86_64) return;
    try installIrqchip(self.fd);
}

fn sevCmd(self: *Vm, id: u32, data: u64, sev_fd: u32) Error!void {
    var cmd: ioctl.KvmSevCmd = .{ .id = id, .data = data, .sev_fd = sev_fd };
    const req = comptime ioctl.request(.read_write, u64, nr.memory_encrypt_op);
    const rc = std.os.linux.ioctl(self.fd, req, @intFromPtr(&cmd));

    // The kernel reports a PSP firmware error by setting cmd.error and failing the ioctl, as a rule
    // with EIO. The firmware code takes priority over the generic errno, and the kernel still writes
    // any output the command produced, such as a measurement length, back into the argument struct.
    if (cmd.@"error" != 0) return Error.SevFirmwareError;
    return switch (std.posix.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => Error.PermissionDenied,
        .BADF => Error.InvalidFileDescriptor,
        .FAULT => Error.BadAddress,
        .INVAL => Error.InvalidArgument,
        .IO => Error.SevFirmwareError,
        else => |e| std.posix.unexpectedErrno(e),
    };
}

/// Open /dev/sev for the LAUNCH commands. It is root only, so this returns null when the caller
/// cannot open it, which lets an unprivileged run skip the launch rather than fault.
pub fn openSev() ?std.posix.fd_t {
    const opened = linux.open("/dev/sev", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return null;
    return @intCast(opened);
}

pub fn sevInit2(self: *Vm) Error!void {
    var args: ioctl.KvmSevInit = .{
        .vmsa_features = 0,
        .flags = 0,
        .ghcb_version = 0,
        .pad1 = 0,
        .pad2 = @splat(0),
    };
    try self.sevCmd(sev_cmd_id.init2, @intFromPtr(&args), 0);
}

fn launchStartInner(
    self: *Vm,
    policy: u32,
    sev_fd: std.posix.fd_t,
    dh_uaddr: u64,
    dh_len: u32,
    session_uaddr: u64,
    session_len: u32,
) Error!void {
    var args: ioctl.KvmSevLaunchStart = .{
        .handle = 0,
        .policy = policy,
        .dh_uaddr = dh_uaddr,
        .dh_len = dh_len,
        .session_uaddr = session_uaddr,
        .session_len = session_len,
    };
    try self.sevCmd(sev_cmd_id.launch_start, @intFromPtr(&args), @intCast(sev_fd));
}

/// Start the launch. The kernel remembers this sev_fd on the guest, so the update, measure, and
/// finish commands reuse it and take no fd of their own.
pub fn launchStart(self: *Vm, policy: u32, sev_fd: std.posix.fd_t) Error!void {
    try self.launchStartInner(policy, sev_fd, 0, 0, 0, 0);
}

/// Start the launch with a guest-owner DH certificate and session blob.
pub fn launchStartAttested(
    self: *Vm,
    policy: u32,
    sev_fd: std.posix.fd_t,
    dh_cert: []const u8,
    session: []const u8,
) Error!void {
    try self.launchStartInner(
        policy,
        sev_fd,
        @intFromPtr(dh_cert.ptr),
        @intCast(dh_cert.len),
        @intFromPtr(session.ptr),
        @intCast(session.len),
    );
}

/// Inject an encrypted secret into guest memory after the launch measurement is accepted.
pub fn launchSecret(
    self: *Vm,
    sev_fd: std.posix.fd_t,
    hdr: []const u8,
    guest_uaddr: u64,
    trans: []const u8,
) Error!void {
    var args: ioctl.KvmSevLaunchSecret = .{
        .hdr_uaddr = @intFromPtr(hdr.ptr),
        .hdr_len = @intCast(hdr.len),
        .guest_uaddr = guest_uaddr,
        .guest_len = @intCast(trans.len),
        .trans_uaddr = @intFromPtr(trans.ptr),
        .trans_len = @intCast(trans.len),
    };
    try self.sevCmd(sev_cmd_id.launch_secret, @intFromPtr(&args), @intCast(sev_fd));
}

pub fn launchUpdateData(self: *Vm, uaddr: u64, len: u64) Error!void {
    var args: ioctl.KvmSevLaunchUpdateData = .{
        .uaddr = uaddr,
        .len = @intCast(len),
    };
    try self.sevCmd(sev_cmd_id.launch_update_data, @intFromPtr(&args), 0);
}

pub fn launchMeasure(self: *Vm, buf: []u8) Error![]u8 {
    // A zero length queries the blob size. The firmware flags the empty buffer as an error but the
    // kernel writes the needed length back first, so tolerate that one error and read the length.
    var args: ioctl.KvmSevLaunchMeasure = .{ .uaddr = 0, .len = 0 };
    self.sevCmd(sev_cmd_id.launch_measure, @intFromPtr(&args), 0) catch |err| switch (err) {
        error.SevFirmwareError => {},
        else => return err,
    };
    const needed = args.len;
    if (needed == 0 or needed > buf.len) return buf[0..0];
    args = .{ .uaddr = @intFromPtr(buf.ptr), .len = needed };
    try self.sevCmd(sev_cmd_id.launch_measure, @intFromPtr(&args), 0);
    return buf[0..needed];
}

pub fn launchFinish(self: *Vm) Error!void {
    try self.sevCmd(sev_cmd_id.launch_finish, 0, 0);
}

/// Seal every vCPU VMSA for a SEV-ES guest. The kernel reuses the /dev/sev fd
/// remembered from launchStart, so no fd is passed here.
pub fn launchUpdateVmsa(self: *Vm) Error!void {
    try self.sevCmd(sev_cmd_id.launch_update_vmsa, 0, 0);
}

pub fn deinit(self: *Vm) void {
    for (self.owned[0..self.slots]) |slot| slot.release();
    _ = linux.close(self.fd);
    _ = linux.close(self.kvm);
    self.* = undefined;
}

pub fn addMemory(self: *Vm, gpa: u64, len: u64, kind: Kind) Error!GuestMemory.Region {
    if (self.slots >= max_slots) return Error.TooManySlots;

    // KVM measures a memory slot in host pages. This host uses 64K pages, so a size
    // that looks reasonable for a 4K host is refused with EINVAL several calls later.
    // Refusing it here names the real problem.
    const page = std.heap.pageSize();
    if (gpa % page != 0 or len % page != 0 or len == 0) return Error.Misaligned;

    var request: ioctl.UserspaceMemoryRegion2 = .{
        .slot = self.slots,
        .flags = 0,
        .guest_phys_addr = gpa,
        .memory_size = len,
        .userspace_addr = 0,
        .guest_memfd_offset = 0,
        .guest_memfd = 0,
        .pad1 = 0,
        .pad2 = @splat(0),
    };

    var slot: Slot = .{};
    var backing: GuestMemory.Backing = .private;
    errdefer slot.release();

    switch (kind) {
        .shared => {
            const mapping = try std.posix.mmap(
                null,
                @intCast(len),
                .{ .READ = true, .WRITE = true },
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            );
            slot.mapping = mapping;
            request.userspace_addr = @intFromPtr(mapping.ptr);
            backing = .{ .shared = mapping };
        },
        .private => {
            var args: ioctl.CreateGuestMemfd = .{ .size = len, .flags = 0, .reserved = @splat(0) };
            const raw = try ioctl.call(
                self.fd,
                comptime ioctl.request(.read_write, ioctl.CreateGuestMemfd, nr.create_guest_memfd),
                @intFromPtr(&args),
            );
            slot.memfd = @intCast(raw);
            request.flags = mem_guest_memfd;
            request.guest_memfd = @intCast(raw);
        },
    }

    _ = ioctl.call(
        self.fd,
        comptime ioctl.request(.write, ioctl.UserspaceMemoryRegion2, nr.set_user_memory_region2),
        @intFromPtr(&request),
    ) catch |err| switch (err) {
        // aarch64 refuses a slot backed by memory the VMM cannot map, because with
        // no memory attributes it has no way to fault a private page. Say that,
        // rather than let a caller read EINVAL and guess. A caller that wants a
        // guest anyway asks for `.shared` and records the tier it actually got.
        error.InvalidArgument => if (kind == .private) return Error.PrivateMemoryUnsupported else return err,
        else => return err,
    };

    self.owned[self.slots] = slot;
    self.slots += 1;
    return .{ .gpa = gpa, .len = len, .backing = backing };
}

const base = 0x4000_0000;

fn pages(n: u64) u64 {
    return n * std.heap.pageSize();
}

fn open() !Vm {
    return Vm.create() catch |err| switch (err) {
        error.NoKvm => error.SkipZigTest,
        else => err,
    };
}

test "a shared region can be written and read back through guest memory" {
    var vm = try open();
    defer vm.deinit();

    const region = try vm.addMemory(base, pages(4), .shared);
    var memory: GuestMemory = .{ .regions = &.{region} };

    try memory.write(base + 8, "mirage");
    var out: [6]u8 = undefined;
    try memory.read(base + 8, &out);
    try testing.expectEqualSlices(u8, "mirage", &out);
}

test "a private region is refused only where the kernel cannot back private pages" {
    var vm = try open();
    defer vm.deinit();

    const report = probe.host() catch |err| switch (err) {
        error.NoKvm => return error.SkipZigTest,
        else => return err,
    };
    if (report.private_backs_memory) {
        // This kernel accepts a guest_memfd slot; the private path succeeds.
        const region = try vm.addMemory(base, pages(4), .private);
        try testing.expectEqual(base, region.gpa);
    } else {
        // No memory attributes: the kernel refuses a slot the VMM cannot fault.
        try testing.expectError(error.PrivateMemoryUnsupported, vm.addMemory(base, pages(4), .private));
    }
}

test "each added region takes the next slot number" {
    var vm = try open();
    defer vm.deinit();

    _ = try vm.addMemory(base, pages(1), .shared);
    _ = try vm.addMemory(base + 0x1000_0000, pages(1), .shared);
    try testing.expectEqual(@as(u32, 2), vm.slots);
}

test "a region that is not a whole number of host pages is refused" {
    var vm = try open();
    defer vm.deinit();

    // One byte past a full page is never a whole number of pages on any host.
    try testing.expectError(error.Misaligned, vm.addMemory(base, std.heap.pageSize() + 1, .shared));
    try testing.expectError(error.Misaligned, vm.addMemory(base + 1, pages(1), .shared));
}

/// `KVM_CAP_MAX_VCPUS` and `KVM_CAP_NR_VCPUS`, which are what the kernel will say about how many CPUs
/// a guest may have. The first is the hard limit and the second is what it recommends.
const cap_nr_vcpus = 9;
const cap_max_vcpus = 66;

/// The most CPUs this host will give a guest.
///
/// Asked rather than decided. How many CPUs a guest may have belongs to the kernel and the machine it
/// runs on, and a number written here would be wrong on the first host that disagreed. A kernel too
/// old to answer still allows four, which is what the interface promised before the question existed.
pub fn maxVcpus(self: *const Vm) u32 {
    const request = comptime ioctl.request(.none, void, nr.check_extension);
    if (ioctl.call(self.kvm, request, cap_max_vcpus)) |most| {
        if (most > 0) return @intCast(most);
    } else |_| {}
    if (ioctl.call(self.kvm, request, cap_nr_vcpus)) |advised| {
        if (advised > 0) return @intCast(advised);
    } else |_| {}
    return 4;
}

test "an x86 vm accepts an injected irq line" {
    if (comptime builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    var vm = try open();
    defer vm.deinit();
    // Raising and lowering a GSI must not error; the in-kernel irqchip routes it.
    try vm.setIrq(5, true);
    try vm.setIrq(5, false);
}

test "a sev vm initialises as the normal user" {
    if (comptime builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    var vm = Vm.createWithType(2) catch |err| switch (err) {
        error.NoKvm, error.NotSupported, error.PermissionDenied, error.InvalidArgument => return error.SkipZigTest,
        else => return err,
    };
    defer vm.deinit();
    vm.sevInit2() catch |err| switch (err) {
        error.NotSupported, error.PermissionDenied, error.InvalidArgument, error.SevFirmwareError => return error.SkipZigTest,
        else => return err,
    };
}
