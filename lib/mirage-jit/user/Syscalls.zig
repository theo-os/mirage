//! Linux AArch64 syscall ABI, with owned host descriptors and translated memory.
//! Only Linux x86_64 hosts are supported. Signal delivery, clone/futex/thread
//! setup, file-backed/fixed mappings and all unimplemented calls return ENOSYS.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Cpu = @import("../aarch64/Cpu.zig");
const Space = @import("Memory.zig").Space;

const page_size: u64 = 4096;
const user_limit: u64 = 0x0001_0000_0000_0000;
const max_rw_count: u64 = 0x7fff_f000;
const HostIovec = extern struct { base: [*]const u8, len: usize };

pub const State = struct {
    allocator: std.mem.Allocator,
    space: *Space,
    fds: std.ArrayList(?i32) = .empty,
    brk: u64,
    brk_min: u64,
    mapped_brk: u64,
    mmap_next: u64 = 0x0000_2000_0000_0000,
    clear_child_tid: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, space: *Space, brk: u64) !State {
        if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedHost;
        var self: State = .{
            .allocator = allocator,
            .space = space,
            .brk = brk,
            .brk_min = brk,
            .mapped_brk = try roundPage(brk),
        };
        errdefer self.deinit();
        try self.fds.appendNTimes(allocator, null, 3);
        for (0..3) |fd| {
            const result = linux.fcntl(@intCast(fd), linux.F.DUPFD_CLOEXEC, 3);
            switch (linux.errno(result)) {
                .SUCCESS => self.fds.items[fd] = @intCast(result),
                .BADF => {}, // A closed host standard stream stays closed in the guest.
                else => return error.DuplicateDescriptorFailed,
            }
        }
        return self;
    }

    pub fn deinit(self: *State) void {
        for (self.fds.items) |fd| if (fd) |owned| {
            _ = linux.close(owned);
        };
        self.fds.deinit(self.allocator);
    }

    /// x8 holds the syscall number, x0..x5 the arguments. Linux errors are
    /// negative errno values in x0; only exit/exit_group return an exit status.
    pub fn dispatch(self: *State, cpu: *Cpu) !?u8 {
        if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedHost;
        const a = cpu.x[0..6].*;
        if (cpu.x[8] == 93 or cpu.x[8] == 94) {
            if (self.clear_child_tid != 0) {
                self.copyOut(self.clear_child_tid, &.{ 0, 0, 0, 0 }) catch {};
            }
            cpu.x[0] = 0;
            return @truncate(a[0]);
        }
        cpu.x[0] = switch (cpu.x[8]) {
            56 => self.openat(a),
            57 => self.close(a[0]),
            62 => self.lseek(a),
            63 => self.readWrite(a, false),
            64 => self.readWrite(a, true),
            66 => self.writev(a),
            96 => blk: {
                // Never pass a guest address to the host kernel. There is one
                // guest thread; its registered word is cleared on guest exit.
                self.clear_child_tid = a[0];
                break :blk hostResult(linux.syscall0(.gettid));
            },
            113 => self.clockGettime(a),
            160 => self.uname(a[0]),
            172 => hostResult(linux.syscall0(.getpid)),
            174 => hostResult(linux.syscall0(.getuid)),
            175 => hostResult(linux.syscall0(.geteuid)),
            176 => hostResult(linux.syscall0(.getgid)),
            177 => hostResult(linux.syscall0(.getegid)),
            178 => hostResult(linux.syscall0(.gettid)),
            214 => self.changeBrk(a[0]),
            215 => self.unmap(a),
            222 => self.mmap(a),
            226 => self.mprotect(a),
            278 => self.getrandom(a),
            else => failure(.NOSYS),
        };
        return null;
    }

    fn hostFd(self: *State, guest: u64) ?i32 {
        const fd: i32 = @bitCast(@as(u32, @truncate(guest)));
        if (fd < 0 or @as(usize, @intCast(fd)) >= self.fds.items.len) return null;
        return self.fds.items[@intCast(fd)];
    }

    fn buffer(self: *State, address: u64, len: usize, permission: u8) ?[]u8 {
        // Zero-length transfers do not dereference the guest pointer.
        if (len == 0) return @constCast(&[_]u8{});
        self.space.check(address, len, permission) catch return null;
        return self.space.slice(address, len) catch null;
    }

    fn chunk(self: *State, address: u64, len: usize) ![]u8 {
        for (self.space.regions.items) |region| {
            if (address >= region.gpa and address - region.gpa < region.len) {
                const size: usize = @intCast(@min(len, region.len - (address - region.gpa)));
                return self.space.slice(address, size);
            }
        }
        return error.OutOfBounds;
    }

    fn copyIn(self: *State, address: u64, bytes: []u8) !void {
        try self.space.check(address, bytes.len, 1);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const part = try self.chunk(address + offset, bytes.len - offset);
            @memcpy(bytes[offset..][0..part.len], part);
            offset += part.len;
        }
    }

    fn copyOut(self: *State, address: u64, bytes: []const u8) !void {
        try self.space.check(address, bytes.len, 2);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const part = try self.chunk(address + offset, bytes.len - offset);
            @memcpy(part, bytes[offset..][0..part.len]);
            offset += part.len;
        }
    }

    // Flatten guest spans into native pointers, stopping at the host IOV_MAX.
    // A short transfer is legal for read/write/writev, including regular files.
    fn vectorsFor(self: *State, address: u64, len: usize, vectors: []HostIovec) !usize {
        var offset: usize = 0;
        var count: usize = 0;
        while (offset < len and count < vectors.len) {
            const part = try self.chunk(address + offset, len - offset);
            vectors[count] = .{ .base = part.ptr, .len = part.len };
            count += 1;
            offset += part.len;
        }
        return count;
    }

    fn readWrite(self: *State, a: [6]u64, writing: bool) u64 {
        const fd = self.hostFd(a[0]) orelse return failure(.BADF);
        const count: usize = @intCast(@min(a[2], max_rw_count));
        const permission: u8 = if (writing) 1 else 2;
        if (self.buffer(a[1], count, permission)) |bytes| {
            return hostResult(if (writing) linux.write(fd, bytes.ptr, bytes.len) else linux.read(fd, bytes.ptr, bytes.len));
        }
        self.space.check(a[1], count, permission) catch return failure(.FAULT);
        var vectors: [1024]HostIovec = undefined;
        const n = self.vectorsFor(a[1], count, &vectors) catch return failure(.FAULT);
        return hostResult(linux.syscall3(if (writing) .writev else .readv, fdBits(fd), @intFromPtr(&vectors), n));
    }

    fn writev(self: *State, a: [6]u64) u64 {
        const fd = self.hostFd(a[0]) orelse return failure(.BADF);
        // Linux caps the vector count at UIO_MAXIOV and treats it as an int.
        const count: i32 = @bitCast(@as(u32, @truncate(a[2])));
        if (count < 0 or count > 1024) return failure(.INVAL);
        const n: usize = @intCast(count);
        var guest: [1024 * 16]u8 = undefined;
        self.copyIn(a[1], guest[0 .. n * 16]) catch return failure(.FAULT);
        var vectors: [1024]HostIovec = undefined;
        var used: usize = 0;
        var total: u64 = 0;
        var remaining: usize = @intCast(max_rw_count);
        for (0..n) |i| {
            const address = std.mem.readInt(u64, guest[i * 16 ..][0..8], .little);
            const len = std.mem.readInt(u64, guest[i * 16 + 8 ..][0..8], .little);
            total = std.math.add(u64, total, len) catch return failure(.INVAL);
            if (total > std.math.maxInt(i64)) return failure(.INVAL);
            const size: usize = @intCast(@min(len, remaining));
            if (size == 0 or used == vectors.len) continue;
            self.space.check(address, size, 1) catch return failure(.FAULT);
            used += self.vectorsFor(address, size, vectors[used..]) catch return failure(.FAULT);
            remaining -= size;
        }
        return hostResult(linux.syscall3(.writev, fdBits(fd), @intFromPtr(&vectors), used));
    }

    fn openat(self: *State, a: [6]u64) u64 {
        var path: [4096:0]u8 = undefined;
        var len: usize = 0;
        while (len < path.len) : (len += 1) {
            const address = std.math.add(u64, a[1], len) catch return failure(.FAULT);
            const byte = self.buffer(address, 1, 1) orelse return failure(.FAULT);
            path[len] = byte[0];
            if (byte[0] == 0) break;
        }
        if (len == path.len) return failure(.NAMETOOLONG);
        if (len == 0) return failure(.NOENT);
        path[path.len] = 0;
        const guest_dir: i32 = @bitCast(@as(u32, @truncate(a[0])));
        // An absolute pathname ignores dirfd, including an invalid descriptor.
        const dir: i32 = if (path[0] == '/' or guest_dir == -100) -100 else self.hostFd(a[0]) orelse return failure(.BADF);
        const guest_flags: u32 = @truncate(a[2]);
        // asm-generic AArch64 differs from x86_64 for these four flag bits.
        const known: u32 = 3 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x2000 |
            0x4000 | 0x8000 | 0x10000 | 0x20000 | 0x40000 | 0x80000 | 0x100000 | 0x200000 | 0x400000;
        if (guest_flags & ~known != 0) return failure(.INVAL);
        var flags = guest_flags & ~@as(u32, 0x3c000);
        if (guest_flags & 0x4000 != 0) flags |= 0x10000; // O_DIRECTORY
        if (guest_flags & 0x8000 != 0) flags |= 0x20000; // O_NOFOLLOW
        if (guest_flags & 0x10000 != 0) flags |= 0x4000; // O_DIRECT
        // O_LARGEFILE is implicit on the 64-bit host. Host descriptors never
        // leak through an exec in the emulator process.
        flags |= 0x80000;
        const result = linux.openat(dir, &path, @bitCast(flags), @truncate(a[3]));
        if (linux.errno(result) != .SUCCESS) return hostResult(result);
        const owned: i32 = @intCast(result);
        for (self.fds.items, 0..) |*slot, index| {
            if (slot.* == null) {
                slot.* = owned;
                return @intCast(index);
            }
        }
        if (self.fds.items.len > std.math.maxInt(i32)) {
            _ = linux.close(owned);
            return failure(.MFILE);
        }
        self.fds.append(self.allocator, owned) catch {
            _ = linux.close(owned);
            return failure(.NOMEM);
        };
        return @intCast(self.fds.items.len - 1);
    }

    fn close(self: *State, guest: u64) u64 {
        const fd = self.hostFd(guest) orelse return failure(.BADF);
        // Linux releases the descriptor even when close reports an error.
        self.fds.items[@as(u32, @truncate(guest))] = null;
        return hostResult(linux.close(fd));
    }

    fn lseek(self: *State, a: [6]u64) u64 {
        const fd = self.hostFd(a[0]) orelse return failure(.BADF);
        return hostResult(linux.lseek(fd, @bitCast(a[1]), @as(u32, @truncate(a[2]))));
    }

    fn clockGettime(self: *State, a: [6]u64) u64 {
        self.space.check(a[1], 16, 2) catch return failure(.FAULT);
        var bytes: [16]u8 = undefined;
        var time: linux.timespec = undefined;
        var id: u32 = @truncate(a[0]);
        if (@as(i32, @bitCast(id)) < 0 and id & 7 == 3) {
            // FD_TO_CLOCKID embeds a descriptor, which must be translated too.
            const fd = self.hostFd((~id) >> 3) orelse return failure(.BADF);
            id = (~@as(u32, @intCast(fd)) << 3) | 3;
        }
        const result = linux.syscall2(.clock_gettime, id, @intFromPtr(&time));
        if (linux.errno(result) != .SUCCESS) return hostResult(result);
        std.mem.writeInt(i64, bytes[0..8], @intCast(time.sec), .little);
        std.mem.writeInt(i64, bytes[8..16], @intCast(time.nsec), .little);
        self.copyOut(a[1], &bytes) catch return failure(.FAULT);
        return 0;
    }

    fn uname(self: *State, address: u64) u64 {
        self.space.check(address, 6 * 65, 2) catch return failure(.FAULT);
        var bytes: [6 * 65]u8 = undefined;
        var host: linux.utsname = undefined;
        const result = linux.uname(&host);
        if (linux.errno(result) != .SUCCESS) return hostResult(result);
        // Copy fields, not the native struct layout. The machine names the
        // architecture whose ABI the guest is running, not the emulator host.
        @memcpy(bytes[0..65], @as(*const [65]u8, @ptrCast(&host.sysname)));
        @memcpy(bytes[65..130], @as(*const [65]u8, @ptrCast(&host.nodename)));
        @memcpy(bytes[130..195], @as(*const [65]u8, @ptrCast(&host.release)));
        @memcpy(bytes[195..260], @as(*const [65]u8, @ptrCast(&host.version)));
        @memset(bytes[260..325], 0);
        @memcpy(bytes[260..267], "aarch64");
        @memcpy(bytes[325..390], @as(*const [65]u8, @ptrCast(&host.domainname)));
        self.copyOut(address, &bytes) catch return failure(.FAULT);
        return 0;
    }

    fn getrandom(self: *State, a: [6]u64) u64 {
        const count: usize = @intCast(@min(a[1], max_rw_count));
        const bytes = self.buffer(a[0], count, 2) orelse blk: {
            self.space.check(a[0], count, 2) catch return failure(.FAULT);
            break :blk self.chunk(a[0], count) catch return failure(.FAULT);
        };
        return hostResult(linux.getrandom(bytes.ptr, bytes.len, @truncate(a[2])));
    }

    fn changeBrk(self: *State, requested: u64) u64 {
        // Unlike other calls, Linux brk returns the previous break on failure.
        if (requested == 0 or requested < self.brk_min or requested >= user_limit) return self.brk;
        const end = roundPage(requested) catch return self.brk;
        if (end > self.mapped_brk) {
            const start = self.mapped_brk;
            _ = self.space.map(start, @intCast(end - start)) catch return self.brk;
            self.space.protect(start, @intCast(end - start), 3) catch {
                self.space.unmap(start, @intCast(end - start)) catch {};
                return self.brk;
            };
        } else if (end < self.mapped_brk) {
            self.space.unmap(end, @intCast(self.mapped_brk - end)) catch return self.brk;
        }
        self.brk = requested;
        self.mapped_brk = end;
        return requested;
    }

    fn mmap(self: *State, a: [6]u64) u64 {
        if (a[1] == 0) return failure(.INVAL);
        const prot: u32 = @truncate(a[2]);
        if (prot & ~@as(u32, 7) != 0) return failure(.INVAL);
        const flags: u32 = @truncate(a[3]);
        if (flags & 0x20 == 0) return failure(.NOSYS); // No file-backed mappings.
        if (flags & 3 != 1 and flags & 3 != 2) return failure(.INVAL);
        if (flags & ~@as(u32, 0x23) != 0) return failure(.NOSYS); // No fixed/huge/shared-thread semantics.
        if (a[5] % page_size != 0) return failure(.INVAL);
        const len = roundPage(a[1]) catch return failure(.NOMEM);
        if (len >= user_limit) return failure(.NOMEM);
        // A non-fixed hint may be ignored. Never reuse addresses, and skip all
        // existing regions (including loader mappings and growing brk regions).
        var address = self.mmap_next;
        while (true) {
            const end = std.math.add(u64, address, len) catch return failure(.NOMEM);
            if (end > user_limit) return failure(.NOMEM);
            var collided = false;
            for (self.space.regions.items) |region| {
                const region_end = std.math.add(u64, region.gpa, region.len) catch return failure(.NOMEM);
                if (address < region_end and end > region.gpa) {
                    address = roundPage(region_end) catch return failure(.NOMEM);
                    collided = true;
                    break;
                }
            }
            if (!collided) break;
        }
        _ = self.space.map(address, @intCast(len)) catch return failure(.NOMEM);
        self.space.protect(address, @intCast(len), @intCast(prot)) catch {
            self.space.unmap(address, @intCast(len)) catch {};
            return failure(.NOMEM);
        };
        self.mmap_next = address + len;
        return address;
    }

    fn unmap(self: *State, a: [6]u64) u64 {
        if (a[0] % page_size != 0 or a[1] == 0) return failure(.INVAL);
        const len = roundPage(a[1]) catch return failure(.INVAL);
        _ = std.math.add(u64, a[0], len) catch return failure(.INVAL);
        self.space.unmap(a[0], @intCast(len)) catch return failure(.NOMEM);
        return 0;
    }

    fn mprotect(self: *State, a: [6]u64) u64 {
        if (a[0] % page_size != 0) return failure(.INVAL);
        const prot: u32 = @truncate(a[2]);
        if (prot & ~@as(u32, 7) != 0) return failure(.INVAL);
        const len = roundPage(a[1]) catch return failure(.INVAL);
        _ = std.math.add(u64, a[0], len) catch return failure(.INVAL);
        if (len == 0) return 0;
        self.space.protect(a[0], @intCast(len), @intCast(prot)) catch return failure(.NOMEM);
        return 0;
    }
};

fn roundPage(value: u64) !u64 {
    const added = try std.math.add(u64, value, page_size - 1);
    return added & ~(page_size - 1);
}

fn fdBits(fd: i32) usize {
    return @bitCast(@as(isize, fd));
}

fn failure(err: linux.E) u64 {
    return @bitCast(-@as(i64, @intFromEnum(err)));
}

fn hostResult(result: usize) u64 {
    const err = linux.errno(result);
    return if (err == .SUCCESS) @intCast(result) else failure(err);
}
