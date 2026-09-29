//! The widening and high-half multiplies. Expected values are worked out by
//! hand from the definitions, and the wrapped ones from the two's complement of
//! the true result.
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

const Case = struct { name: []const u8, word: u32, x1: u64, x2: u64, x3: u64 = 100, expected: u64 };

fn check(cases: []const Case) !void {
    for (cases) |case| {
        var cpu: Cpu = .{ .sp = 0x1234 };
        cpu.x[0] = 0xdead_beef_dead_beef; // what a write to the wrong place would leave
        cpu.x[1] = case.x1;
        cpu.x[2] = case.x2;
        cpu.x[3] = case.x3;
        try run(case.word, &cpu);
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
        try testing.expectEqual(case.expected, cpu.x[0]);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

// The 32-bit operands are minus one and five, with junk above them that a 32-bit
// operand must not see. The accumulator is one hundred.
const minus_one_word: u64 = 0xdead_beef_ffff_ffff;
const five_word: u64 = 0xcafe_0000_0005;

test "the signed long multiplies extend each word and use a 64-bit accumulator" {
    try check(&.{
        // -1 * 5 = -5.
        .{ .name = "smaddl", .word = 0x9b220c20, .x1 = minus_one_word, .x2 = five_word, .expected = 95 },
        .{ .name = "smsubl", .word = 0x9b228c20, .x1 = minus_one_word, .x2 = five_word, .expected = 105 },
        .{ .name = "smull", .word = 0x9b227c20, .x1 = minus_one_word, .x2 = five_word, .expected = 0xffff_ffff_ffff_fffb },
        .{ .name = "smnegl", .word = 0x9b22fc20, .x1 = minus_one_word, .x2 = five_word, .expected = 5 },
        // Two of the most negative words multiply to 2^62.
        .{ .name = "smull min * min", .word = 0x9b227c20, .x1 = 0x8000_0000, .x2 = 0x8000_0000, .expected = 0x4000_0000_0000_0000 },
        .{ .name = "smull max * max", .word = 0x9b227c20, .x1 = 0x7fff_ffff, .x2 = 0x7fff_ffff, .expected = 0x3fff_ffff_0000_0001 },
    });
}

test "the unsigned long multiplies zero-extend each word" {
    // 0xffffffff * 5 = 0x4ffffffb.
    try check(&.{
        .{ .name = "umaddl", .word = 0x9ba20c20, .x1 = minus_one_word, .x2 = five_word, .expected = 0x5_0000_005f },
        .{ .name = "umsubl", .word = 0x9ba28c20, .x1 = minus_one_word, .x2 = five_word, .expected = 0xffff_fffb_0000_0069 },
        .{ .name = "umull", .word = 0x9ba27c20, .x1 = minus_one_word, .x2 = five_word, .expected = 0x4_ffff_fffb },
        .{ .name = "umnegl", .word = 0x9ba2fc20, .x1 = minus_one_word, .x2 = five_word, .expected = 0xffff_fffb_0000_0005 },
    });
}

test "the high-half multiplies give the top 64 bits of the 128-bit product" {
    const all: u64 = std.math.maxInt(u64);
    try check(&.{
        // -2^63 * 2 = -2^64, whose top half is minus one; unsigned it is 2^64, whose is one.
        .{ .name = "smulh", .word = 0x9b427c20, .x1 = 0x8000_0000_0000_0000, .x2 = 2, .expected = all },
        .{ .name = "umulh", .word = 0x9bc27c20, .x1 = 0x8000_0000_0000_0000, .x2 = 2, .expected = 1 },
        // 2^62 * 2^62 = 2^124, so the top half is 2^60, either way.
        .{ .name = "smulh 2^62", .word = 0x9b427c20, .x1 = 0x4000_0000_0000_0000, .x2 = 0x4000_0000_0000_0000, .expected = 0x1000_0000_0000_0000 },
        .{ .name = "umulh 2^62", .word = 0x9bc27c20, .x1 = 0x4000_0000_0000_0000, .x2 = 0x4000_0000_0000_0000, .expected = 0x1000_0000_0000_0000 },
        // (-1) * (-1) = 1, top half zero; (2^64 - 1)^2 has 2^64 - 2 as its top half.
        .{ .name = "smulh -1 * -1", .word = 0x9b427c20, .x1 = all, .x2 = all, .expected = 0 },
        .{ .name = "umulh max * max", .word = 0x9bc27c20, .x1 = all, .x2 = all, .expected = all - 1 },
        // 3 * -1 = -3 is negative, so its top half is all ones; unsigned, 3 * (2^64 - 1) has top half 2.
        .{ .name = "smulh 3 * -1", .word = 0x9b427c20, .x1 = 3, .x2 = all, .expected = all },
        .{ .name = "umulh 3 * max", .word = 0x9bc27c20, .x1 = 3, .x2 = all, .expected = 2 },
    });
}

test "a widening multiply written to register 31 is discarded and the stack is untouched" {
    for ([_]u32{ 0x9b227c3f, 0x9ba27c3f, 0x9b427c3f, 0x9bc27c3f }) |word| {
        var cpu: Cpu = .{ .sp = 0x1234 };
        cpu.x[1] = 3;
        cpu.x[2] = 4;
        try run(word, &cpu);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

test "the multiply class is told apart, and its reserved forms are refused" {
    // The plain forms are still the plain forms.
    try testing.expectEqual(true, (try Decode.decode(0x9b027c20)) == .mul);
    try testing.expectEqual(true, (try Decode.decode(0x1b020c20)) == .mul);
    try testing.expectEqual(true, (try Decode.decode(0x9b220c20)) == .mul_long);
    try testing.expectEqual(true, (try Decode.decode(0x9b427c20)) == .mul_high);
    // The high halves have no accumulator and no subtract.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x9b420c20));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x9bc2fc20));
    // The long forms exist only at 64 bits.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x1b220c20));
    // Bits 30:29 are zero in every multiply, so a word that sets one is not one.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x3b020c20));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x5b020c20));
}
