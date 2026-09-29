//! Linux AArch64 user execution on the shared Vulcan translator.
const std = @import("std");
const arm = @import("aarch64.zig");
pub const Space = @import("user/Memory.zig").Space;
pub const Loader = @import("user/Loader.zig");
pub const Syscalls = @import("user/Syscalls.zig");

const UserGuest = struct {
    pub const Cpu = arm.Cpu;
    pub const Block = arm.Block;
    pub const Error = anyerror;
    pub const Tlb = Space;
    pub const max_instruction_bytes = 4;
    pub const pc = arm.pc;
    pub const compile = arm.compile;
    pub const terminates = arm.terminates;
    pub fn fetch(_: *@import("mirage-memory").GuestMemory, _: *const Cpu, space: *Space, at: u64, into: []u8) !usize {
        try space.check(at, 4, 4);
        @memcpy(into[0..4], try space.slice(at, 4));
        const instruction = try arm.Decode.decode(std.mem.readInt(u32, into[0..4], .little));
        switch (instruction) {
            .system => |operand| switch (operand.register) {
                .nzcv, .tpidr_el0, .fpcr, .fpsr => {},
                .tpidrro_el0, .ctr_el0, .dczid_el0, .cntvct_el0, .cntfrq_el0 => if (!operand.read) return error.InvalidUserInstruction,
                else => return error.InvalidUserInstruction,
            },
            .eret, .psci, .tlbi, .wfi => return error.InvalidUserInstruction,
            else => {},
        }
        return 4;
    }
};

pub fn run(allocator: std.mem.Allocator, io: std.Io, path: []const u8, args: []const []const u8, env: []const []const u8) !u8 {
    var space = Space.init(allocator);
    defer space.deinit();
    const entry = try Loader.load(&space, io, path, args, env);
    var syscalls = try Syscalls.State.init(allocator, &space, entry.brk);
    defer syscalls.deinit();
    var cpu: arm.Cpu = .{ .pc = entry.pc, .sp = entry.sp, .system = .{ .el = 0, .spsel = false, .daif = 0 } };
    var cache = @import("Cache.zig").Cache(UserGuest).init(allocator);
    defer cache.deinit();
    while (true) {
        var memory = space.memory();
        _ = cache.runBlock(&memory, &cpu, &space) catch |err| {
            std.debug.print("mirage-aarch64: pc=0x{x}: {s}\n", .{ cpu.pc, @errorName(err) });
            return err;
        };
        switch (cpu.trap) {
            .none => {},
            .load, .store => try service(&space, &cpu),
            .svc => {
                cpu.trap = .none;
                cpu.monitor_valid = false;
                if (try syscalls.dispatch(&cpu)) |status| return status;
            },
            .sync => cpu.trap = .none,
            .dc_zva => {
                try space.check(cpu.address & ~@as(u64, 63), 64, 2);
                @memset(try space.slice(cpu.address & ~@as(u64, 63), 64), 0);
                cpu.monitor_valid = false;
                cpu.trap = .none;
            },
            else => {
                std.debug.print("mirage-aarch64: pc=0x{x}: unexpected {s}\n", .{ cpu.pc, @tagName(cpu.trap) });
                return error.InvalidUserInstruction;
            },
        }
    }
}

fn service(space: *Space, cpu: *arm.Cpu) !void {
    const loading = cpu.trap == .load;
    if (cpu.exclusive == .store) {
        const held = cpu.monitor_valid and cpu.monitor_address == cpu.address and cpu.monitor_width == cpu.width;
        cpu.monitor_valid = false;
        if (!held) {
            if (cpu.status_dest != 31) cpu.x[cpu.status_dest] = 1;
            cpu.exclusive = .none;
            cpu.trap = .none;
            return;
        }
    }
    try access(space, cpu, loading, cpu.address, cpu.width, cpu.dest, cpu.value, cpu.load_signed);
    if (cpu.second_pending) {
        try access(space, cpu, loading, cpu.second_address, cpu.second_width, cpu.second_dest, cpu.second_value, cpu.second_signed);
        cpu.second_pending = false;
        cpu.second_signed = .none;
    }
    if (cpu.writeback) {
        if (cpu.writeback_dest == 31) cpu.sp = cpu.writeback_value else cpu.x[cpu.writeback_dest] = cpu.writeback_value;
        cpu.writeback = false;
    }
    if (cpu.exclusive == .load) {
        cpu.monitor_valid = true;
        cpu.monitor_address = cpu.address;
        cpu.monitor_width = cpu.width;
    } else if (!loading) {
        cpu.monitor_valid = false;
        if (cpu.exclusive == .store and cpu.status_dest != 31) cpu.x[cpu.status_dest] = 0;
    }
    cpu.exclusive = .none;
    cpu.load_signed = .none;
    cpu.trap = .none;
}

fn access(space: *Space, cpu: *arm.Cpu, loading: bool, address: u64, width: u8, dest: u8, value: u64, signed: arm.Cpu.SignExtend) !void {
    if (width != 1 and width != 2 and width != 4 and width != 8) return error.InvalidAccessWidth;
    try space.check(address, width, if (loading) @as(u8, 1) else @as(u8, 2));
    var encoded: [8]u8 = undefined;
    const direct = space.slice(address, width) catch null;
    if (!loading) {
        std.mem.writeInt(u64, &encoded, value, .little);
        if (direct) |bytes| {
            @memcpy(bytes, encoded[0..width]);
        } else {
            for (0..width) |i| (try space.slice(address + i, 1))[0] = encoded[i];
        }
        return;
    }
    if (dest == 31) return;
    const kept = if (direct) |bytes| std.mem.readVarInt(u64, bytes, .little) else blk: {
        for (0..width) |i| encoded[i] = (try space.slice(address + i, 1))[0];
        break :blk std.mem.readVarInt(u64, encoded[0..width], .little);
    };
    const drop: u6 = @intCast(64 - @as(u7, @intCast(width)) * 8);
    cpu.x[dest] = switch (signed) {
        .none => kept,
        .to32, .to64 => blk: {
            const wide: u64 = @bitCast(@as(i64, @bitCast(kept << drop)) >> drop);
            break :blk if (signed == .to32) wide & 0xffff_ffff else wide;
        },
    };
}
