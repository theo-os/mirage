//! Boots a real x86-64 Linux bzImage under KVM and reads its banner off the serial port.
//!
//! This gate is Linux and x86 only. It lives outside `lib/` because it opens a file, which a
//! portable module may not. It maps the kernel this machine booted, places it with the x86 boot
//! path, enters long mode, and pumps the run loop until the kernel's first serial line arrives.

const std = @import("std");
const core = @import("mirage-core");
const backend = @import("mirage-backend");
const device = @import("mirage-device");
const arch = @import("mirage-arch");
const GuestMemory = @import("mirage-memory").GuestMemory;
const attest = @import("mirage-attest");
const Manifest = attest.Manifest;
const linux = std.os.linux;

const options = @import("boot-options");

/// Guest RAM starts at zero on x86: the bzImage sits at the one megabyte mark, the structures it
/// reaches long mode through sit below that, and the identity map covers physical memory from zero.
const ram_base = 0;
const ram_size = 512 << 20;

/// The serial port of a PC, reached through an I/O port rather than memory.
const serial_port = 0x3f8;

/// A booting kernel prints far more than this. The cap is here so a kernel that spins does not hang
/// the suite; the deadline below stops it sooner on a machine that is merely slow.
const max_exits = 5_000_000;

/// The line the kernel prints before anything else. Seeing it is proof the guest reached its own code
/// in long mode, read the boot params, and found the serial port where it was told.
const banner = "Linux version";

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

/// A vCPU waiting for an interrupt blocks inside `KVM_RUN`, and no loop in this process runs while it
/// does. A signal with no `SA_RESTART` takes the CPU back: the blocked ioctl returns `EINTR`.
fn onAlarm(_: linux.SIG) callconv(.c) void {}

fn armTicks(interval_ms: isize) void {
    const act: linux.Sigaction = .{
        .handler = .{ .handler = onAlarm },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.ALRM, &act, null);

    // This syscall takes microseconds in its second field, which the standard library names `nsec`.
    const every: linux.timespec = .{
        .sec = @divTrunc(interval_ms, 1000),
        .nsec = @rem(interval_ms, 1000) * std.time.us_per_ms,
    };
    const spec: linux.itimerspec = .{ .it_interval = every, .it_value = every };
    _ = linux.setitimer(@intFromEnum(linux.ITIMER.REAL), &spec, null);
}

/// Map the kernel this machine booted, or nothing when the path is unset or cannot be read.
fn mapKernel() !?[]align(std.heap.page_size_min) u8 {
    var path: [256:0]u8 = @splat(0);
    if (options.kernel_path.len >= path.len) return null;
    @memcpy(path[0..options.kernel_path.len], options.kernel_path);

    const opened = linux.open(&path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (std.posix.errno(opened) != .SUCCESS) return null;
    const fd: std.posix.fd_t = @intCast(opened);
    defer _ = linux.close(fd);

    const end = linux.lseek(fd, 0, 2);
    if (std.posix.errno(end) != .SUCCESS) return null;

    return try std.posix.mmap(null, @intCast(end), .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, 0);
}

test "a real x86 kernel boots to its serial banner" {
    // Only an x86 host can build the page tables this gate relies on and run the bzImage it maps.
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;

    const gpa = std.testing.allocator;

    const kernel = (try mapKernel()) orelse return error.SkipZigTest;
    defer std.posix.munmap(kernel);

    var machine = backend.kvm.Machine.create(gpa, 1) catch |err| switch (err) {
        error.NoKvm => return error.SkipZigTest,
        else => return err,
    };
    defer machine.deinit();

    const region = try machine.vm.addMemory(ram_base, ram_size, .shared);
    var regions = [_]GuestMemory.Region{region};
    var memory: GuestMemory = .{ .regions = &regions };

    const hv = machine.backend();
    const id = try hv.addVcpu();

    // The controller is the in-kernel one the machine was built with, so this makes nothing on x86.
    var gic = try backend.platform.createController(&machine.vm, 1);
    defer gic.deinit();

    var manifest: Manifest = .{};
    defer manifest.deinit(gpa);

    const layout = try core.Launch.prepare(gpa, &memory, &manifest, .{
        .kernel = kernel,
        // The kernel talks to our UART from its first line and gives up rather than waiting forever.
        .cmdline = "console=ttyS0 earlyprintk=serial,ttyS0 panic=-1",
        .ram_base = ram_base,
        .ram_size = ram_size,
        .cpus = 1,
        .uart_base = serial_port,
    });

    // The serial sink. Large enough to hold the banner and a good deal past it, so a kernel that keeps
    // printing does not stop the gate reading what it came for.
    const output = try gpa.alloc(u8, 256 << 10);
    defer gpa.free(output);
    var sink = std.Io.Writer.fixed(output);
    var serial: device.Uart16550 = .{ .sink = &sink };

    // The serial sits on an I/O port on x86, so it goes on a port bus of its own rather than the memory
    // bus. The memory bus holds nothing: this gate drives no virtio device.
    var port_devices = [_]device.Bus.Device{serial.device(serial_port)};
    var ports: device.Bus = .{ .devices = &port_devices };
    var devices: [0]device.Bus.Device = undefined;
    var bus: device.Bus = .{ .devices = &devices };

    // Long mode and the full segment state the kernel starts in need the concrete vCPU, not the
    // abstract backend, so the boot entry takes it.
    try arch.boot.enter(&machine.vcpus[id], layout);

    // A guest that is waiting on something that never comes sits in `KVM_RUN` forever, so the run is
    // bounded by the clock as well as by the exit count.
    const deadline = nowMs() + 10_000;
    armTicks(10);

    var exits: usize = 0;
    var stopped: ?backend.Backend.Exit = null;
    while (exits < max_exits) : (exits += 1) {
        // The banner is what this gate came for. Stop reading the moment it arrives rather than running
        // the kernel on past it.
        if (exits % 1024 == 0) {
            if (std.mem.indexOf(u8, sink.buffered(), banner) != null) break;
            if (nowMs() > deadline) {
                std.debug.print("\n=== deadline after {d} exits ===\n", .{exits});
                break;
            }
        }

        const exit = hv.run(id) catch |err| {
            std.debug.print("\nrun failed after {d} exits: {t}, kvm said {?}\n", .{ exits, err, machine.fault });
            break;
        };

        switch (exit) {
            .port_out => |w| ports.write(w.port, w.size, w.value),
            .port_in => |r| try hv.completeMmioRead(id, ports.read(r.port, r.size)),
            .mmio_write => |w| bus.write(w.gpa, w.size, w.value),
            .mmio_read => |r| try hv.completeMmioRead(id, bus.read(r.gpa, r.size)),
            .interrupted => {},
            else => {
                stopped = exit;
                break;
            },
        }

        if (sink.buffered().len + 512 > output.len) break;
    }

    const log = sink.buffered();

    if (std.mem.indexOf(u8, log, banner) == null) {
        // The guest rip says where it got to, which a log that is only a prompt does not. Reading it
        // needs the concrete vCPU, the same one the boot entry took.
        const rip = machine.vcpus[id].getRegister(.rip) catch 0;
        std.debug.print(
            "\n=== no banner after {d} exits, stopped {?}, rip {x}, unmapped {d} ===\n{s}\n=== end ===\n",
            .{ exits, stopped, rip, bus.unmapped, log },
        );
    }

    try std.testing.expect(std.mem.indexOf(u8, log, banner) != null);
}
