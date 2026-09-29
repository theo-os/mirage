//! `EXTR` and the rotate by an immediate it is the general case of.
const std = @import("std");
const testing = @import("mirage-testing");
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const Decode = guest.Decode;

const Case = struct { name: []const u8, word: u32, x1: u64, x2: u64, expected: u64 };

fn check(cases: []const Case) !void {
    for (cases) |case| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, case.word, .little);
        var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
        defer block.deinit();
        var cpu: Cpu = .{ .sp = 0x1234 };
        cpu.x[0] = 0xdead_beef_dead_beef;
        cpu.x[1] = case.x1;
        cpu.x[2] = case.x2;
        _ = block.run(&cpu);
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
        try testing.expectEqual(case.expected, cpu.x[0]);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

test "extract takes a register's worth of bits from a pair" {
    try check(&.{
        // (x2 >> 8) with the low byte of x1 coming in at the top.
        .{ .name = "extr x0, x1, x2, #8", .word = 0x93c22020, .x1 = 0x1111_2222_3333_4444, .x2 = 0x5555_6666_7777_8888, .expected = 0x4455_5566_6677_7788 },
        // A distance of zero is the second register as it is.
        .{ .name = "extr x0, x1, x2, #0", .word = 0x93c20020, .x1 = 0x1111, .x2 = 0x5555_6666_7777_8888, .expected = 0x5555_6666_7777_8888 },
        // The distance can be all but one bit.
        .{ .name = "extr x0, x1, x2, #63", .word = 0x93c2fc20, .x1 = 1, .x2 = 0x8000_0000_0000_0000, .expected = 3 },
    });
}

test "a rotate by an immediate is extract of a register with itself" {
    try check(&.{
        .{ .name = "ror x0, x1, #4", .word = 0x93c11020, .x1 = 0x0123_4567_89ab_cdef, .x2 = 0, .expected = 0xf012_3456_789a_bcde },
        // A 32-bit rotate is within 32 bits, and clears the top of the register.
        .{ .name = "ror w0, w1, #1", .word = 0x13810420, .x1 = 1, .x2 = 0, .expected = 0x8000_0000 },
        .{ .name = "ror w0, w1, #16", .word = 0x13814020, .x1 = 0xdead_beef_1234_5678, .x2 = 0, .expected = 0x5678_1234 },
        // The kernel's own, on registers 9 and 14: `ror w14, w9, #16`.
    });
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 0x1389412e, .little);
    var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
    defer block.deinit();
    var cpu: Cpu = .{};
    cpu.x[9] = 0x1234_5678;
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 0x5678_1234), cpu.x[14]);
}

test "an extract written to register 31 is discarded and the stack is untouched" {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 0x93c2201f, .little); // extr xzr, x0, x2, #8
    var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
    defer block.deinit();
    var cpu: Cpu = .{ .sp = 0x1234 };
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
}

test "the reserved extract encodings are refused, and the bitfield class next door is not claimed" {
    // A 32-bit form with a position of 32 or more, and N disagreeing with the width.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x13828020));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x13c22020));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x93822020));
    switch (try Decode.decode(0xd3504c20)) { // ubfx x0, x1, #16, #4
        .bitfield => {},
        else => return error.NotABitfield,
    }
    switch (try Decode.decode(0x93c22020)) {
        .extract => |pair| try testing.expectEqual(@as(u6, 8), pair.lsb),
        else => return error.NotAnExtract,
    }
}
