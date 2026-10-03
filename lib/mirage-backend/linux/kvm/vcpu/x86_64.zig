//! A KVM virtual CPU on x86-64: the shared run structure and the exits.
//!
//! This is the seam's x86 side. `create` does the real `KVM_CREATE_VCPU` and maps the
//! run structure, so a machine with no KVM still fails the same way and a test on a
//! host that has KVM can make a vCPU. The register and run bodies that boot a real
//! guest come later; for now they report that the work is not done.

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

    return .{ .fd = fd, .mapping = mapping, .state = @ptrCast(@alignCast(mapping.ptr)) };
}

pub fn deinit(self: *Vcpu) void {
    std.posix.munmap(self.mapping);
    _ = linux.close(self.fd);
    self.* = undefined;
}

pub fn setRegister(self: *Vcpu, reg: Backend.Register, value: u64) Error!void {
    _ = self;
    _ = reg;
    _ = value;
    return Error.NotSupported;
}

pub fn getRegister(self: *Vcpu, reg: Backend.Register) Error!u64 {
    _ = self;
    _ = reg;
    return Error.NotSupported;
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
