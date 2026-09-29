//! Conditional compares and the conditions that select between values. Every
//! expected flag word is derived by hand from the architecture's own rule: the
//! sum of the first operand, the second (inverted for a compare) and a carry in.
const std = @import("std");
const testing = @import("mirage-testing");
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const Decode = guest.Decode;

fn run(word: u32, cpu: *Cpu) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
    defer block.deinit();
    _ = block.run(cpu);
}

const Z: u32 = 1 << 30;
const C: u32 = 1 << 29;
const N: u32 = 1 << 31;
const V: u32 = 1 << 28;

const Case = struct { name: []const u8, word: u32, flags: u32 = 0, x1: u64 = 0, x2: u64 = 0, expected: u32 };

fn check(cases: []const Case) !void {
    for (cases) |case| {
        var cpu: Cpu = .{ .flags = case.flags, .sp = 0x1234 };
        cpu.x[1] = case.x1;
        cpu.x[2] = case.x2;
        try run(case.word, &cpu);
        errdefer std.debug.print("{s}: flags {x}, wanted {x}\n", .{ case.name, cpu.flags, case.expected });
        try testing.expectEqual(case.expected, cpu.flags);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

test "a conditional compare whose condition holds sets the flags of the comparison" {
    // ccmp x1, #15, #4, ne, with Z clear so that `ne` holds.
    try check(&.{
        .{ .name = "equal", .word = 0xfa4f1824, .x1 = 15, .expected = Z | C },
        // 3 - 15 is negative and borrows.
        .{ .name = "less", .word = 0xfa4f1824, .x1 = 3, .expected = N },
        // 20 - 15 is positive with no borrow.
        .{ .name = "greater", .word = 0xfa4f1824, .x1 = 20, .expected = C },
        // The most negative value less 15 overflows to a positive result.
        .{ .name = "overflow", .word = 0xfa4f1824, .x1 = 0x8000_0000_0000_0000, .expected = C | V },
    });
}

test "a conditional compare whose condition fails loads the flags the encoding carries" {
    // The same ccmp with Z set, so `ne` fails: the four bits are N Z C V from the
    // top, and the operands are not looked at.
    try check(&.{
        .{ .name = "nzcv 4", .word = 0xfa4f1824, .flags = Z, .x1 = 15, .expected = Z },
        .{ .name = "nzcv 4, other value", .word = 0xfa4f1824, .flags = Z, .x1 = 3, .expected = Z },
        // ccmp x1, #15, #10, ne: N and C.
        .{ .name = "nzcv 10", .word = 0xfa4f182a, .flags = Z, .x1 = 15, .expected = N | C },
        // ccmp x1, #15, #0, ne clears everything, including what was set going in.
        .{ .name = "nzcv 0", .word = 0xfa4f1820, .flags = Z | C | V, .x1 = 15, .expected = 0 },
    });
}

test "a conditional compare negative adds instead of subtracting" {
    // ccmn x1, #1, #0, eq, with Z set so that `eq` holds.
    try check(&.{
        // All ones plus one wraps to zero: Z, and a carry out, and no overflow.
        .{ .name = "wrap", .word = 0xba410820, .flags = Z, .x1 = std.math.maxInt(u64), .expected = Z | C },
        // The largest signed value plus one overflows into the sign bit.
        .{ .name = "overflow", .word = 0xba410820, .flags = Z, .x1 = 0x7fff_ffff_ffff_ffff, .expected = N | V },
        .{ .name = "plain", .word = 0xba410820, .flags = Z, .x1 = 5, .expected = 0 },
        // With `eq` failing, the encoding's own flags: ccmn x1, #1, #8, eq is N.
        .{ .name = "fails", .word = 0xba410828, .flags = 0, .x1 = 5, .expected = N },
    });
}

test "a conditional compare with a register second operand, and the always condition" {
    // ccmp x1, x2, #0, al: `al` is a condition that always holds.
    try check(&.{
        .{ .name = "equal", .word = 0xfa42e020, .x1 = 7, .x2 = 7, .expected = Z | C },
        .{ .name = "less", .word = 0xfa42e020, .x1 = 1, .x2 = 7, .expected = N },
        // `nv` means the same as `al`, not "never".
        .{ .name = "nv holds", .word = 0xfa42f020, .x1 = 7, .x2 = 7, .expected = Z | C },
    });
}

test "a 32-bit conditional compare compares 32 bits" {
    // ccmp w1, #5, #0, eq, with Z set so that `eq` holds.
    try check(&.{
        // The upper half of the register is not part of the comparison.
        .{ .name = "equal", .word = 0x7a450820, .flags = Z, .x1 = 0x1_0000_0005, .expected = Z | C },
        // At 32 bits the most negative value less 5 overflows, though it would not at 64.
        .{ .name = "overflow", .word = 0x7a450820, .flags = Z, .x1 = 0x8000_0000, .expected = C | V },
    });
}

test "a select on the always conditions takes its first operand" {
    // csel x0, x1, x2, al and csel x0, x1, x2, nv.
    for ([_]u32{ 0x9a82e020, 0x9a82f020 }) |word| {
        var cpu: Cpu = .{ .flags = 0 };
        cpu.x[1] = 0x11;
        cpu.x[2] = 0x22;
        try run(word, &cpu);
        try testing.expectEqual(@as(u64, 0x11), cpu.x[0]);
    }
}

test "the neighbouring classes are not read as conditional compares" {
    // A select, which differs in bit 23, and a compare with bit 4 set.
    switch (try Decode.decode(0x9a82e020)) {
        .csel => {},
        else => return error.NotASelect,
    }
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xfa4f1834));
    switch (try Decode.decode(0xfa4f1824)) {
        .cond_compare => |compare| {
            try testing.expectEqual(Decode.Condition.ne, compare.cond);
            try testing.expectEqual(@as(u4, 4), compare.nzcv);
            try testing.expectEqual(@as(u5, 15), compare.operand.immediate);
        },
        else => return error.NotACompare,
    }
}
