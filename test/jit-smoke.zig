const std = @import("std");
const jit = @import("mirage-jit");
const GuestMemory = @import("mirage-memory").GuestMemory;

/// Run a guest ELF image under the translator. Real compiled code reaches its
/// data through addresses the linker chose, so the loadable segments are placed
/// where the image says they go rather than at an address of our choosing.
/// Returns the low byte of x0 when the guest asks to exit, which is the status
/// QEMU reports, so that the two can be compared exactly.
pub fn run(init: std.process.Init, path: []const u8, tracing: bool) !u8 {
    trace = tracing;
    const image = try std.Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(1 << 26));
    var reader: std.Io.Reader = .fixed(image);
    const header = try std.elf.Header.read(&reader);

    // One region per loadable segment, plus a stack below the image. The count
    // is small and fixed in practice, so a generous array avoids an allocator.
    var storage: [8]GuestMemory.Region = undefined;
    var backing: [8][]u8 = undefined;
    var count: usize = 0;

    var lowest: u64 = std.math.maxInt(u64);
    var it = header.iterateProgramHeadersBuffer(image);
    while (try it.next()) |ph| {
        if (ph.p_type != @as(u32, 1)) continue;
        if (count == storage.len) return error.TooManySegments;
        const size = ph.p_filesz;
        if (size == 0) continue;
        // The file holds the initialised part; a segment is often larger than
        // its contents, and the rest is zero until the guest writes it.
        const memory = try init.gpa.alloc(u8, ph.p_memsz);
        errdefer init.gpa.free(memory);
        backing[count] = memory;
        @memset(memory, 0);
        const file_start: usize = @intCast(ph.p_offset);
        const file_len: usize = @intCast(size);
        @memcpy(memory[0..file_len], image[file_start..][0..file_len]);
        storage[count] = .{ .gpa = ph.p_vaddr, .len = ph.p_memsz, .backing = .{ .shared = memory } };
        count += 1;
        lowest = @min(lowest, ph.p_vaddr);
    }
    if (count == 0) return error.NoLoadableSegments;

    const stack_size: u64 = 1 << 22;
    // Below the image if there is room for it there, which is the usual layout
    // and keeps the stack out of the way of anything the guest reaches. An image
    // linked low has no room below it, so the stack goes above instead rather
    // than wrapping round to the top of the address space.
    var highest: u64 = 0;
    {
        var scan = header.iterateProgramHeadersBuffer(image);
        while (try scan.next()) |ph| {
            if (ph.p_type != @as(u32, 1)) continue;
            highest = @max(highest, ph.p_vaddr + ph.p_memsz);
        }
    }
    const stack: u64 = if (lowest >= stack_size) lowest - stack_size else highest;
    const stack_bytes = try init.gpa.alloc(u8, @intCast(stack_size));
    backing[count] = stack_bytes;
    @memset(stack_bytes, 0);
    storage[count] = .{ .gpa = stack, .len = stack_size, .backing = .{ .shared = stack_bytes } };
    count += 1;

    // Every buffer above is now in use, and the guest is finished with all of
    // them however this function returns.
    defer for (backing[0..count]) |bytes| init.gpa.free(bytes);

    var memory: GuestMemory = .{ .regions = storage[0..count] };
    if (header.machine != .AARCH64) return error.NotAnAArch64Image;
    const entry: u64 = header.entry;
    var cpu: jit.aarch64.Cpu = .{ .pc = entry, .sp = lowest };
    var cache = jit.aarch64.Cache.init(init.gpa);
    defer cache.deinit();
    // The one the fetch and the data side share, because a page that is
    // executable for one and not the other is not a state the architecture has.
    var tlb: jit.aarch64.Tlb = .{};

    // Every load or store ends a block, so a function call runs for as many
    // blocks as it has accesses. The budget only exists to turn a hang into an
    // error rather than a wrong answer.
    for (0..100_000_000) |_| {
        // A fault on the fetch is an instruction abort, taken to a vector, and
        // the vector is fetched through the walk like anything else.
        _ = cache.runBlock(&memory, &cpu, &tlb) catch |err| switch (err) {
            error.TranslationFault, error.PermissionFault, error.MalformedTables => {
                const status: u6 = switch (err) {
                    error.PermissionFault => jit.aarch64.Exception.status.permission_fetch,
                    else => jit.aarch64.Exception.status.translation,
                };
                cpu.trap = .none;
                // The class for an instruction abort taken at the current level,
                // with the instruction bit set because this is a fetch.
                const reason: jit.aarch64.Exception.Reason = .{
                    .kind = .sync,
                    .ec = 0b001001,
                    .instruction = true,
                    .status = status,
                };
                _ = jit.aarch64.Exception.take(&cpu, reason, cpu.pc);
            },
            else => return err,
        };
        if (trace) std.debug.print("block pc={x} trap={s} sp={x}\n", .{ cpu.pc, @tagName(cpu.trap), cpu.sp });
        switch (cpu.trap) {
            .none => {},
            .load, .store => try service(&memory, &cpu, &tlb),
            // An `ISB` orders nothing here, but it is where the guest says the
            // translation regime may have changed, so the cache is dropped.
            .sync => {
                tlb.flush();
                cpu.trap = .none;
            },
            .dc_zva => {
                cpu.trap = .none;
                try zeroLine(&memory, &cpu, &tlb, cpu.address);
            },
            .eret => {
                cpu.trap = .none;
                _ = jit.aarch64.Exception.eret(&cpu);
            },
            // A synchronous call is an exception now, so a guest that wants to
            // exit has to have a handler that turns it into one. The
            // convention QEMU cannot be checked against here is the same one
            // Linux uses: the exit syscall is the one every userland program
            // ends with, and nothing above it is going to run again.
            .svc => {
                if (cpu.x[8] == 93) return @truncate(cpu.x[0]);
                const pc = cpu.pc;
                cpu.trap = .none;
                _ = jit.aarch64.Exception.take(&cpu, .{ .kind = .sync, .ec = 0b010101 }, pc);
            },
            .brk => {
                const pc = cpu.pc;
                cpu.trap = .none;
                _ = jit.aarch64.Exception.take(&cpu, .{ .kind = .sync, .ec = 0b000000 }, pc);
            },
            else => return error.UnexpectedGuestExit,
        }
    }
    return error.GuestDidNotExit;
}

/// Zero the cache line holding `virtual`, which is sixty-four bytes. The line
/// boundary is the address with its low six bits clear, and a machine whose
/// memory is coherent with its cache has nothing to do beyond the zeroing.
fn zeroLine(memory: *GuestMemory, cpu: *jit.aarch64.Cpu, tlb: *jit.aarch64.Tlb, virtual: u64) !void {
    const base = virtual & ~@as(u64, 0x3f);
    const physical = jit.aarch64.Translate.translate(tlb, cpu, memory, base, .write) catch |fault_kind| {
        cpu.trap = .none;
        const status: u6 = if (fault_kind == error.PermissionFault)
            jit.aarch64.Exception.status.permission
        else
            jit.aarch64.Exception.status.translation;
        _ = jit.aarch64.Exception.take(cpu, .{
            .kind = .sync,
            .ec = if (cpu.system.el == 1) 0b100001 else 0b100000,
            .status = status,
        }, virtual);
        return;
    };
    var line: [64]u8 = @splat(0);
    memory.write(physical, &line) catch return error.GuestMemoryFault;
}

/// Perform the access a block asked for, and then the second half of a pair if
/// this was one. Register 31 is the stack pointer for an access, as it is for
/// the base a translated block reads.
fn service(memory: *GuestMemory, cpu: *jit.aarch64.Cpu, tlb: *jit.aarch64.Tlb) !void {
    try access(memory, cpu, tlb, cpu.address, cpu.width, cpu.dest, cpu.value);
    if (cpu.writeback) {
        if (cpu.writeback_dest == 31) {
            cpu.sp = cpu.writeback_value;
        } else {
            cpu.x[cpu.writeback_dest] = cpu.writeback_value;
        }
        cpu.writeback = false;
    }
    if (cpu.second_pending) {
        cpu.second_pending = false;
        try access(memory, cpu, tlb, cpu.second_address, cpu.second_width, cpu.second_dest, cpu.second_value);
    }
}

fn access(memory: *GuestMemory, cpu: *jit.aarch64.Cpu, tlb: *jit.aarch64.Tlb, address: u64, width: u8, dest: u8, value: u64) !void {
    // The address a block formed is virtual, and becomes physical here.
    const kind: jit.aarch64.Translate.Access = if (cpu.trap == .load) .read else .write;
    const physical = jit.aarch64.Translate.translate(tlb, cpu, memory, address, kind) catch |fault_kind| {
        const fetched = kind == jit.aarch64.Translate.Access.execute;
        const ec: u6 = if (cpu.system.el == 1) 0b100001 else 0b100000;
        const status: u6 = switch (fault_kind) {
            error.PermissionFault => if (fetched) jit.aarch64.Exception.status.permission_fetch else jit.aarch64.Exception.status.permission,
            else => jit.aarch64.Exception.status.translation,
        };
        cpu.trap = .none;
        const reason: jit.aarch64.Exception.Reason = .{
            .kind = .sync,
            .ec = ec,
            .instruction = fetched,
            .status = status,
        };
        _ = jit.aarch64.Exception.take(cpu, reason, address);
        return;
    };
    if (trace) std.debug.print("access va={x} pa={x} width={d} dest={d} value={x}\n", .{ address, physical, width, dest, value });
    var bytes: [8]u8 = @splat(0);
    if (cpu.trap == .load) {
        // A physical address in no region is a translation fault, not a host
        // error: the guest asked for memory that does not exist, and its own
        // handler is what should hear about it.
        memory.read(physical, bytes[0..width]) catch {
            cpu.trap = .none;
            _ = jit.aarch64.Exception.take(cpu, .{ .kind = .sync, .ec = if (cpu.system.el == 1) 0b100001 else 0b100000, .status = jit.aarch64.Exception.status.translation }, address);
            return;
        };
        if (dest != 31) {
            const bits: u7 = @intCast(width * 8);
            cpu.x[dest] = if (bits == 64) std.mem.readInt(u64, &bytes, .little) else std.mem.readInt(u64, &bytes, .little) & ((@as(u64, 1) << @as(u6, @intCast(bits))) - 1);
        }
    } else {
        std.mem.writeInt(u64, &bytes, value, .little);
        memory.write(physical, bytes[0..width]) catch {
            cpu.trap = .none;
            _ = jit.aarch64.Exception.take(cpu, .{ .kind = .sync, .ec = if (cpu.system.el == 1) 0b100001 else 0b100000, .status = jit.aarch64.Exception.status.translation }, address);
            return;
        };
    }
}

var trace = false;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.ExpectedGuestCodePath;
    const status = try run(init, args[1], args.len > 2);
    // The guest's own exit status, so that this and QEMU can be compared
    // directly without parsing anything.
    std.process.exit(status);
}
