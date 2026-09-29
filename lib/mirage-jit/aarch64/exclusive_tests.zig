//! Exclusive and ordered loads and stores. The monitor lives in the run loop, so
//! these run real instructions through a `Machine` with memory behind it and read
//! the result out of both the registers and the memory.
const std = @import("std");
const testing = @import("mirage-testing");
const GuestMemory = @import("mirage-memory").GuestMemory;
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const Decode = guest.Decode;
const Exception = guest.Exception;

const base: u64 = 0x1000;
/// Where the two words of data are: `x0` points at the first and `x1` at the second.
const first_at = base + 0x100;
const second_at = base + 0x108;

const wfi: u32 = 0xd503207f;

const Outcome = struct { cpu: Cpu, first: u64, second: u64 };

/// Run `words` from the start of memory until the guest waits for an interrupt.
fn execute(words: []const u32, first: u64, second: u64) !Outcome {
    var bytes: [0x200]u8 = @splat(0);
    for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    std.mem.writeInt(u64, bytes[0x100..][0..8], first, .little);
    std.mem.writeInt(u64, bytes[0x108..][0..8], second, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = guest.Machine.init(testing.allocator(), &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    try hv.setRegister(id, .x0, first_at);
    try hv.setRegister(id, .x1, second_at);
    machine.cpu.sp = 0x7777;
    while (true) switch (try hv.run(id)) {
        .wfi => break,
        .interrupted => {},
        else => return error.UnexpectedExit,
    };
    return .{
        .cpu = machine.cpu,
        .first = std.mem.readInt(u64, bytes[0x100..][0..8], .little),
        .second = std.mem.readInt(u64, bytes[0x108..][0..8], .little),
    };
}

// The instructions, by their assembly.
const ldxr_x2_x0: u32 = 0xc85f7c02;
const ldxrb_w2_x0: u32 = 0x085f7c02;
const stxr_w3_x2_x0: u32 = 0xc8037c02;
const stxr_w3_x2_x1: u32 = 0xc8037c22;
const stxr_w4_x2_x0: u32 = 0xc8047c02;
const stxr_wzr_x2_x0: u32 = 0xc81f7c02;
const add_x2_x2_1: u32 = 0x91000442;
const movz_x2_7: u32 = 0xd28000e2;
const clrex: u32 = 0xd503305f;

test "a load-exclusive followed by a store-exclusive to the same place stores" {
    // ldxr x2, [x0]; add x2, x2, #1; stxr w3, x2, [x0]: an atomic increment.
    const out = try execute(&.{ ldxr_x2_x0, add_x2_x2_1, stxr_w3_x2_x0, wfi }, 41, 0);
    try testing.expectEqual(@as(u64, 42), out.first);
    try testing.expectEqual(@as(u64, 0), out.cpu.x[3]); // it stored
}

test "a store-exclusive with no claim does not store and says so" {
    const out = try execute(&.{ movz_x2_7, stxr_w3_x2_x0, wfi }, 0, 0);
    try testing.expectEqual(@as(u64, 0), out.first);
    try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
}

test "CLREX drops the claim" {
    const out = try execute(&.{ ldxr_x2_x0, clrex, stxr_w3_x2_x0, wfi }, 5, 0);
    try testing.expectEqual(@as(u64, 5), out.first);
    try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
}

test "a store-exclusive to a different address than the claim fails" {
    const out = try execute(&.{ ldxr_x2_x0, stxr_w3_x2_x1, wfi }, 5, 9);
    try testing.expectEqual(@as(u64, 9), out.second);
    try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
}

test "the claim is spent by the store-exclusive that used it" {
    // The first stores, and the second has nothing left to succeed with.
    const out = try execute(&.{ ldxr_x2_x0, add_x2_x2_1, stxr_w3_x2_x0, stxr_w4_x2_x0, wfi }, 10, 0);
    try testing.expectEqual(@as(u64, 11), out.first);
    try testing.expectEqual(@as(u64, 0), out.cpu.x[3]);
    try testing.expectEqual(@as(u64, 1), out.cpu.x[4]);
}

test "a claim of one size does not license a store of another" {
    // A byte claim, and a doubleword store to the same address.
    const out = try execute(&.{ ldxrb_w2_x0, stxr_w3_x2_x0, wfi }, 0x55, 0);
    try testing.expectEqual(@as(u64, 0x55), out.first);
    try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
}

test "a failed store-exclusive also spends the claim" {
    // The failed store is to the wrong place; the one after it, to the right place, has no claim.
    const out = try execute(&.{ ldxr_x2_x0, stxr_w3_x2_x1, stxr_w4_x2_x0, wfi }, 5, 9);
    try testing.expectEqual(@as(u64, 1), out.cpu.x[3]);
    try testing.expectEqual(@as(u64, 1), out.cpu.x[4]);
    try testing.expectEqual(@as(u64, 5), out.first);
}

test "a store-exclusive that reports to register 31 discards the report, not the stack" {
    const out = try execute(&.{ ldxr_x2_x0, add_x2_x2_1, stxr_wzr_x2_x0, wfi }, 1, 0);
    try testing.expectEqual(@as(u64, 2), out.first);
    try testing.expectEqual(@as(u64, 0x7777), out.cpu.sp);
}

test "the ordered loads and stores are plain accesses" {
    // ldar x2, [x0]; stlr x2, [x1]: the value moves across.
    const ldar_x2_x0: u32 = 0xc8dffc02;
    const stlr_x2_x1: u32 = 0xc89ffc22;
    const out = try execute(&.{ ldar_x2_x0, stlr_x2_x1, wfi }, 0xdead_beef, 0);
    try testing.expectEqual(@as(u64, 0xdead_beef), out.second);
    // And they decode as the plain accesses they are, with no offset.
    switch (try Decode.decode(ldar_x2_x0)) {
        .memory => |access| {
            try testing.expectEqual(Decode.Size.double, access.size);
            try testing.expectEqual(@as(i64, 0), access.addressing.offset);
        },
        else => return error.NotAPlainLoad,
    }
    // The acquire forms without bit 15 are the same accesses: the kernel's own
    // `ldaprb w9, [x0]` and `ldarb w8, [x0]` move a byte each.
    const out_acquire = try execute(&.{ 0x085f7c09, 0x08dffc08, wfi }, 0x5a, 0);
    try testing.expectEqual(@as(u64, 0x5a), out_acquire.cpu.x[9]);
    try testing.expectEqual(@as(u64, 0x5a), out_acquire.cpu.x[8]);
}

test "taking or returning from an exception ends the claim" {
    var cpu: Cpu = .{ .monitor_valid = true };
    _ = Exception.take(&cpu, .{ .kind = .sync, .ec = 0 }, 0);
    try testing.expectEqual(false, cpu.monitor_valid);

    cpu.monitor_valid = true;
    _ = Exception.eret(&cpu);
    try testing.expectEqual(false, cpu.monitor_valid);
}

test "the forms of this class that are not modelled are refused" {
    // A pair (LDXP) and compare-and-swap. `LDLAR` (bit 15 clear with bit 23 set
    // and a load) stays refused: only the acquire `LDAPR` form without bit 15
    // is accepted, which is what the kernel's spin loop uses.
    for ([_]u32{ 0xc87f0440, 0x88a07c00 }) |word| {
        try testing.expectError(error.UnsupportedInstruction, Decode.decode(word));
    }
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xc8df7c00)); // ldlar w0, [x0]
    // A load-exclusive names no status register, so anything but 31 there is not one.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xc85f7c02 & ~@as(u32, 0x000f_0000)));
}
