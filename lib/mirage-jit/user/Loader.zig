//! Linux ELF64/AArch64 process images and initial userspace stack.
//! PT_INTERP is opened at its absolute host path; no interpreter prefix is applied.
const std = @import("std");
const Space = @import("Memory.zig").Space;

const page_size: u64 = 4096;
const image_limit: usize = 1 << 30;
const stack_size: usize = 8 << 20;
const stack_top: u64 = 0x7fff_fff0_0000;
const stack_base: u64 = stack_top - stack_size;
const user_limit: u64 = stack_base - 0x10000;

pub const Result = struct { pc: u64, sp: u64, brk: u64 };
const Image = struct {
    entry: u64,
    end: u64,
    bias: u64,
    phdr: u64,
    phnum: u16,
    interpreter: ?[]const u8,
};
const Segment = struct {
    address: u64,
    end: u64,
    offset: u64,
    filesz: u64,
    flags: u32,
};
const Aux = struct { tag: u64, value: u64 };

pub fn load(space: *Space, io: std.Io, path: []const u8, args: []const []const u8, env: []const []const u8) !Result {
    const previous_regions = space.regions.items.len;
    errdefer space.truncate(previous_regions);
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, space.allocator, .limited(image_limit));
    defer space.allocator.free(bytes);
    const executable = try loadImage(space, bytes, 0x4000_0000, true);
    var pc = executable.entry;
    var interpreter_bias: u64 = 0;
    if (executable.interpreter) |interpreter_path| {
        const interpreter_bytes = try std.Io.Dir.cwd().readFileAlloc(io, interpreter_path, space.allocator, .limited(image_limit));
        defer space.allocator.free(interpreter_bytes);
        const interpreter = try loadImage(space, interpreter_bytes, 0x10_0000_0000, false);
        pc = interpreter.entry;
        interpreter_bias = interpreter.bias;
    }
    _ = try space.map(stack_base, stack_size);
    const sp = try makeStack(space, io, path, args, env, executable, interpreter_bias);
    return .{ .pc = pc, .sp = sp, .brk = try alignPage(executable.end) };
}

fn integer(comptime T: type, bytes: []const u8, offset: usize) T {
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

fn fileSpan(bytes: []const u8, offset: u64, length: u64) ![]const u8 {
    const end = std.math.add(u64, offset, length) catch return error.InvalidElf;
    if (end > bytes.len) return error.InvalidElf;
    const start = std.math.cast(usize, offset) orelse return error.InvalidElf;
    const finish = std.math.cast(usize, end) orelse return error.InvalidElf;
    return bytes[start..finish];
}

fn alignPage(value: u64) !u64 {
    const rounded = std.math.add(u64, value, page_size - 1) catch return error.AddressOverflow;
    return rounded & ~(page_size - 1);
}

fn lessThan(_: void, a: Segment, b: Segment) bool {
    return a.address < b.address;
}

fn loadImage(space: *Space, bytes: []const u8, dynamic_bias: u64, allow_interpreter: bool) !Image {
    if (bytes.len < 64 or !std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.InvalidElf;
    if (bytes[4] != 2) return error.UnsupportedElfClass;
    if (bytes[5] != 1) return error.UnsupportedElfByteOrder;
    if (bytes[6] != 1 or integer(u32, bytes, 20) != 1) return error.InvalidElf;
    if (integer(u16, bytes, 18) != 183) return error.UnsupportedElfMachine;
    const kind = integer(u16, bytes, 16);
    if (kind != 2 and kind != 3) return error.UnsupportedElfType;
    if (integer(u16, bytes, 52) != 64 or integer(u16, bytes, 54) != 56) return error.InvalidElf;
    const phnum = integer(u16, bytes, 56);
    if (phnum == 0 or phnum > 1024) return error.InvalidElf;
    const phoff = integer(u64, bytes, 32);
    const table_size: u64 = @as(u64, phnum) * 56;
    const headers = try fileSpan(bytes, phoff, table_size);
    const bias: u64 = if (kind == 3) dynamic_bias else 0;
    const entry = std.math.add(u64, bias, integer(u64, bytes, 24)) catch return error.InvalidElf;
    var segments: std.ArrayList(Segment) = .empty;
    defer segments.deinit(space.allocator);
    var interpreter: ?[]const u8 = null;
    var phdr: ?u64 = null;
    var image_end: u64 = 0;
    var entry_loaded = false;
    for (0..phnum) |i| {
        const header = headers[i * 56 ..][0..56];
        const tag = integer(u32, header, 0);
        const offset = integer(u64, header, 8);
        const vaddr = integer(u64, header, 16);
        const filesz = integer(u64, header, 32);
        const memsz = integer(u64, header, 40);
        if (tag == 3) {
            if (!allow_interpreter) return error.InterpreterHasInterpreter;
            if (interpreter != null or filesz < 2 or filesz > 4096) return error.InvalidElf;
            const name = try fileSpan(bytes, offset, filesz);
            if (name[0] != '/' or name[name.len - 1] != 0 or std.mem.indexOfScalar(u8, name[0 .. name.len - 1], 0) != null) return error.InvalidInterpreterPath;
            interpreter = name[0 .. name.len - 1];
            continue;
        }
        if (tag != 1) continue;
        const flags = integer(u32, header, 4);
        const alignment = integer(u64, header, 48);
        if (filesz > memsz or memsz > image_limit or flags & ~@as(u32, 7) != 0) return error.InvalidElf;
        if (filesz != 0) _ = try fileSpan(bytes, offset, filesz);
        if (alignment > 1 and ((alignment & (alignment - 1)) != 0 or (vaddr & (alignment - 1)) != (offset & (alignment - 1)))) return error.InvalidElf;
        if ((vaddr & (page_size - 1)) != (offset & (page_size - 1))) return error.InvalidElf;
        const address = std.math.add(u64, bias, vaddr) catch return error.InvalidElf;
        const end = std.math.add(u64, address, memsz) catch return error.InvalidElf;
        if (end > user_limit) return error.InvalidElf;
        if (memsz == 0) continue;
        if (entry >= address and entry < end and flags & 1 != 0) entry_loaded = true;
        image_end = @max(image_end, end);
        const file_end = std.math.add(u64, offset, filesz) catch return error.InvalidElf;
        const table_end = std.math.add(u64, phoff, table_size) catch return error.InvalidElf;
        if (phoff >= offset and table_end <= file_end) {
            phdr = std.math.add(u64, address, phoff - offset) catch return error.InvalidElf;
        }
        try segments.append(space.allocator, .{ .address = address, .end = end, .offset = offset, .filesz = filesz, .flags = flags });
    }
    if (!entry_loaded or entry & 3 != 0 or segments.items.len == 0) return error.InvalidElfEntry;
    std.mem.sort(Segment, segments.items, {}, lessThan);
    var mapping_start: u64 = 0;
    var mapping_end: u64 = 0;
    var total: u64 = 0;
    for (segments.items, 0..) |segment, i| {
        if (i != 0 and segments.items[i - 1].end > segment.address) return error.OverlappingElfSegments;
        const start = segment.address & ~(page_size - 1);
        const end = try alignPage(segment.end);
        if (i == 0) {
            mapping_start = start;
            mapping_end = end;
        } else if (start <= mapping_end) {
            mapping_end = @max(mapping_end, end);
        } else {
            total = try mapImageSpan(space, mapping_start, mapping_end, total);
            mapping_start = start;
            mapping_end = end;
        }
    }
    _ = try mapImageSpan(space, mapping_start, mapping_end, total);
    for (segments.items) |segment| {
        const contents = if (segment.filesz == 0) "" else try fileSpan(bytes, segment.offset, segment.filesz);
        if (contents.len != 0) @memcpy(try space.slice(segment.address, contents.len), contents);
    }
    for (segments.items) |segment| {
        const start = segment.address & ~(page_size - 1);
        const end = try alignPage(segment.end);
        const permission: u8 = @intCast(((segment.flags & 4) >> 2) | (segment.flags & 2) | ((segment.flags & 1) << 2));
        try space.protect(start, @intCast(end - start), permission);
    }
    const phdr_address = phdr orelse try mapHeaders(space, headers);
    return .{ .entry = entry, .end = image_end, .bias = bias, .phdr = phdr_address, .phnum = phnum, .interpreter = interpreter };
}

fn mapImageSpan(space: *Space, start: u64, end: u64, previous: u64) !u64 {
    const total = std.math.add(u64, previous, end - start) catch return error.ImageTooLarge;
    if (total > image_limit) return error.ImageTooLarge;
    _ = try space.map(start, std.math.cast(usize, end - start) orelse return error.ImageTooLarge);
    return total;
}

/// An ELF need not include its program-header table in a PT_LOAD. Preserve the
/// actual table in a separate read-only mapping so AT_PHDR is always addressable.
fn mapHeaders(space: *Space, headers: []const u8) !u64 {
    const size = try alignPage(headers.len);
    var address: u64 = 0x6000_0000_0000;
    while (true) {
        var overlap = false;
        for (space.regions.items) |region| {
            if (address >= region.gpa + region.len or address + size <= region.gpa) continue;
            const below = region.gpa & ~(page_size - 1);
            address = std.math.sub(u64, below, size) catch return error.AddressSpaceExhausted;
            overlap = true;
            break;
        }
        if (!overlap) break;
    }
    const destination = try space.map(address, @intCast(size));
    @memcpy(destination[0..headers.len], headers);
    try space.protect(address, @intCast(size), 1);
    return address;
}

const Stack = struct {
    space: *Space,
    at: u64 = stack_top,

    fn reserve(self: *Stack, length: usize) !u64 {
        if (length > self.at - stack_base) return error.ArgumentsTooLarge;
        self.at -= length;
        return self.at;
    }

    fn string(self: *Stack, value: []const u8) !u64 {
        if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidArgument;
        const size = std.math.add(usize, value.len, 1) catch return error.ArgumentsTooLarge;
        const address = try self.reserve(size);
        const destination = try self.space.slice(address, size);
        @memcpy(destination[0..value.len], value);
        destination[value.len] = 0;
        return address;
    }
};

fn makeStack(space: *Space, io: std.Io, path: []const u8, args: []const []const u8, env: []const []const u8, executable: Image, interpreter_bias: u64) !u64 {
    // The pointers alone must fit before allocating their temporary arrays.
    const count = std.math.add(usize, args.len, env.len) catch return error.ArgumentsTooLarge;
    if (count > stack_size / 8) return error.ArgumentsTooLarge;
    const argv = try space.allocator.alloc(u64, args.len);
    defer space.allocator.free(argv);
    const envp = try space.allocator.alloc(u64, env.len);
    defer space.allocator.free(envp);
    var stack: Stack = .{ .space = space };
    const execfn = try stack.string(path);
    for (env, envp) |value, *pointer| pointer.* = try stack.string(value);
    for (args, argv) |value, *pointer| pointer.* = try stack.string(value);
    var random: [16]u8 = undefined;
    try io.randomSecure(&random);
    const random_address = try stack.reserve(random.len);
    @memcpy(try space.slice(random_address, random.len), &random);
    const aux = [_]Aux{
        .{ .tag = 3, .value = executable.phdr }, // AT_PHDR
        .{ .tag = 4, .value = 56 }, // AT_PHENT
        .{ .tag = 5, .value = executable.phnum }, // AT_PHNUM
        .{ .tag = 6, .value = page_size }, // AT_PAGESZ
        .{ .tag = 7, .value = interpreter_bias }, // AT_BASE
        .{ .tag = 9, .value = executable.entry }, // AT_ENTRY
        .{ .tag = 11, .value = std.os.linux.getuid() },
        .{ .tag = 12, .value = std.os.linux.geteuid() },
        .{ .tag = 13, .value = std.os.linux.getgid() },
        .{ .tag = 14, .value = std.os.linux.getegid() },
        .{ .tag = 16, .value = 0 }, // AT_HWCAP: FP/ASIMD are not implemented.
        .{ .tag = 23, .value = 0 }, // AT_SECURE: no set-id credential transition.
        .{ .tag = 25, .value = random_address }, // AT_RANDOM
        .{ .tag = 26, .value = 0 }, // AT_HWCAP2
        .{ .tag = 31, .value = execfn }, // AT_EXECFN
        .{ .tag = 0, .value = 0 },
    };
    const words = std.math.add(usize, count, 3 + aux.len * 2) catch return error.ArgumentsTooLarge;
    const table_size = std.math.mul(usize, words, 8) catch return error.ArgumentsTooLarge;
    _ = try stack.reserve(table_size);
    stack.at &= ~@as(u64, 15);
    if (stack.at < stack_base) return error.ArgumentsTooLarge;
    const table = try space.slice(stack.at, table_size);
    var offset: usize = 0;
    putWord(table, &offset, args.len);
    for (argv) |pointer| putWord(table, &offset, pointer);
    putWord(table, &offset, 0);
    for (envp) |pointer| putWord(table, &offset, pointer);
    putWord(table, &offset, 0);
    for (aux) |pair| {
        putWord(table, &offset, pair.tag);
        putWord(table, &offset, pair.value);
    }
    return stack.at;
}

fn putWord(bytes: []u8, offset: *usize, value: u64) void {
    std.mem.writeInt(u64, bytes[offset.*..][0..8], value, .little);
    offset.* += 8;
}
