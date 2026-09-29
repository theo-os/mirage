//! Owned sparse user address space. Guest addresses are never host pointers.
const std = @import("std");
const GuestMemory = @import("mirage-memory").GuestMemory;

pub const Space = struct {
    allocator: std.mem.Allocator,
    regions: std.ArrayList(GuestMemory.Region) = .empty,
    permissions: std.ArrayList(u8) = .empty,
    allocations: std.ArrayList(Allocation) = .empty,

    const Allocation = struct { bytes: []u8 };

    pub fn init(allocator: std.mem.Allocator) Space {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Space) void {
        for (self.allocations.items) |allocation| self.allocator.free(allocation.bytes);
        self.allocations.deinit(self.allocator);
        self.permissions.deinit(self.allocator);
        self.regions.deinit(self.allocator);
    }

    pub fn map(self: *Space, address: u64, size: usize) ![]u8 {
        if (size == 0) return error.InvalidSize;
        const end = std.math.add(u64, address, size) catch return error.AddressOverflow;
        for (self.regions.items) |region| {
            if (address < region.gpa + region.len and region.gpa < end) return error.OverlappingMapping;
        }
        try self.regions.ensureUnusedCapacity(self.allocator, 1);
        try self.permissions.ensureUnusedCapacity(self.allocator, 1);
        try self.allocations.ensureUnusedCapacity(self.allocator, 1);
        const bytes = try self.allocator.alloc(u8, size);
        @memset(bytes, 0);
        self.allocations.appendAssumeCapacity(.{ .bytes = bytes });
        self.regions.appendAssumeCapacity(.{ .gpa = address, .len = size, .backing = .{ .shared = bytes } });
        self.permissions.appendAssumeCapacity(3);
        return bytes;
    }

    /// Checks every byte, including spans crossing region/protection boundaries.
    pub fn check(self: *Space, address: u64, len: usize, permission: u8) !void {
        const end = std.math.add(u64, address, len) catch return error.OutOfBounds;
        var at = address;
        while (at < end) {
            var found = false;
            for (self.regions.items, self.permissions.items) |region, allowed| {
                const region_end = region.gpa + region.len;
                if (at < region.gpa or at >= region_end) continue;
                if (allowed & permission != permission) return error.AccessDenied;
                at = @min(end, region_end);
                found = true;
                break;
            }
            if (!found) return error.OutOfBounds;
        }
    }

    /// A borrowed span must be both mapped in full and contiguous in host storage.
    pub fn slice(self: *Space, address: u64, len: usize) ![]u8 {
        try self.check(address, len, 0);
        const end = std.math.add(u64, address, len) catch return error.OutOfBounds;
        for (self.regions.items) |first| {
            if (address < first.gpa or address >= first.gpa + first.len) continue;
            const first_offset: usize = @intCast(address - first.gpa);
            const pointer = @intFromPtr(first.backing.shared.ptr) + first_offset;
            for (self.allocations.items) |allocation| {
                const base = @intFromPtr(allocation.bytes.ptr);
                if (pointer < base or pointer - base > allocation.bytes.len) continue;
                const offset = pointer - base;
                if (len > allocation.bytes.len - offset) continue;
                var at = address;
                while (at < end) {
                    for (self.regions.items) |region| {
                        if (at < region.gpa or at >= region.gpa + region.len) continue;
                        const region_offset: usize = @intCast(at - region.gpa);
                        const displacement: usize = @intCast(at - address);
                        if (@intFromPtr(region.backing.shared.ptr) + region_offset != pointer + displacement) return error.OutOfBounds;
                        at = @min(end, region.gpa + region.len);
                        break;
                    }
                }
                return allocation.bytes[offset..][0..len];
            }
        }
        return error.OutOfBounds;
    }

    pub fn memory(self: *Space) GuestMemory {
        return .{ .regions = self.regions.items };
    }

    fn split(self: *Space, at: u64) void {
        for (self.regions.items, 0..) |region, i| {
            if (at <= region.gpa or at >= region.gpa + region.len) continue;
            const offset: usize = @intCast(at - region.gpa);
            const bytes = region.backing.shared;
            self.regions.items[i].len = offset;
            self.regions.items[i].backing = .{ .shared = bytes[0..offset] };
            self.regions.insertAssumeCapacity(i + 1, .{
                .gpa = at,
                .len = region.len - offset,
                .backing = .{ .shared = bytes[offset..] },
            });
            self.permissions.insertAssumeCapacity(i + 1, self.permissions.items[i]);
            return;
        }
    }

    pub fn protect(self: *Space, address: u64, len: usize, permission: u8) !void {
        if (len == 0 or permission & ~@as(u8, 7) != 0) return error.InvalidSize;
        try self.check(address, len, 0);
        const end = std.math.add(u64, address, len) catch return error.AddressOverflow;
        try self.regions.ensureUnusedCapacity(self.allocator, 2);
        try self.permissions.ensureUnusedCapacity(self.allocator, 2);
        self.split(address);
        self.split(end);
        for (self.regions.items, self.permissions.items) |region, *allowed| {
            if (region.gpa >= address and region.gpa < end) allowed.* = permission;
        }
    }

    /// Like Linux munmap, holes in the requested range are harmless.
    pub fn unmap(self: *Space, address: u64, len: usize) !void {
        if (len == 0) return error.InvalidSize;
        const end = std.math.add(u64, address, len) catch return error.AddressOverflow;
        try self.regions.ensureUnusedCapacity(self.allocator, 2);
        try self.permissions.ensureUnusedCapacity(self.allocator, 2);
        self.split(address);
        self.split(end);
        var i: usize = 0;
        while (i < self.regions.items.len) {
            const region = self.regions.items[i];
            if (region.gpa >= address and region.gpa < end) {
                _ = self.regions.orderedRemove(i);
                _ = self.permissions.orderedRemove(i);
            } else i += 1;
        }
        self.freeUnused();
    }

    /// Roll back mappings appended by a failed loader transaction.
    pub fn truncate(self: *Space, region_count: usize) void {
        self.regions.shrinkRetainingCapacity(region_count);
        self.permissions.shrinkRetainingCapacity(region_count);
        self.freeUnused();
    }

    fn freeUnused(self: *Space) void {
        var i: usize = 0;
        while (i < self.allocations.items.len) {
            const allocation = self.allocations.items[i];
            var used = false;
            for (self.regions.items) |region| {
                const pointer = @intFromPtr(region.backing.shared.ptr);
                const base = @intFromPtr(allocation.bytes.ptr);
                if (pointer >= base and pointer - base < allocation.bytes.len) {
                    used = true;
                    break;
                }
            }
            if (used) {
                i += 1;
            } else {
                self.allocator.free(allocation.bytes);
                _ = self.allocations.orderedRemove(i);
            }
        }
    }
};
