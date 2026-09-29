//! The instructions that rearrange or count the bits of one register: the byte
//! and bit reversals and counting leading zeros. Every expected value is worked
//! out on paper from the definition, byte by byte and bit by bit.
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

const pattern: u64 = 0x0123_4567_89ab_cdef;

const Case = struct { name: []const u8, word: u32, x1: u64 = pattern, expected: u64 };

fn check(cases: []const Case) !void {
    for (cases) |case| {
        var cpu: Cpu = .{ .sp = 0x1234 };
        cpu.x[0] = 0xdead_beef_dead_beef; // what a partial write would leave showing
        cpu.x[1] = case.x1;
        try run(case.word, &cpu);
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
        try testing.expectEqual(case.expected, cpu.x[0]);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

test "the byte reversals reverse within the unit they name" {
    try check(&.{
        // The whole register: the eight bytes in the opposite order.
        .{ .name = "rev x0, x1", .word = 0xdac00c20, .expected = 0xefcd_ab89_6745_2301 },
        // A 32-bit register: four bytes of the low word, and the top half of the
        // result is clear.
        .{ .name = "rev w0, w1", .word = 0x5ac00820, .expected = 0xefcd_ab89 },
        // Each halfword's two bytes swapped, the halfwords staying where they are.
        .{ .name = "rev16 x0, x1", .word = 0xdac00420, .expected = 0x2301_6745_ab89_efcd },
        .{ .name = "rev16 w0, w1", .word = 0x5ac00420, .expected = 0xab89_efcd },
        // Each 32-bit word reversed on its own: the words do not change places.
        .{ .name = "rev32 x0, x1", .word = 0xdac00820, .expected = 0x6745_2301_efcd_ab89 },
    });
}

test "a bit reversal reverses every bit, not the bytes" {
    // Each byte's bits reversed (0x01 to 0x80, 0x23 to 0xc4, 0x45 to 0xa2, 0x67 to
    // 0xe6, 0x89 to 0x91, 0xab to 0xd5, 0xcd to 0xb3, 0xef to 0xf7), and then the
    // bytes in the opposite order.
    try check(&.{
        .{ .name = "rbit x0, x1", .word = 0xdac00020, .expected = 0xf7b3_d591_e6a2_c480 },
        .{ .name = "rbit w0, w1", .word = 0x5ac00020, .expected = 0xf7b3_d591 },
        // One bit at each end swaps ends.
        .{ .name = "rbit x0, x1, lowest bit", .word = 0xdac00020, .x1 = 1, .expected = 0x8000_0000_0000_0000 },
        .{ .name = "rbit w0, w1, highest bit", .word = 0x5ac00020, .x1 = 0x8000_0000, .expected = 1 },
    });
}

test "counting leading zeros counts from the top of the register at its width" {
    try check(&.{
        .{ .name = "clz x, zero", .word = 0xdac01020, .x1 = 0, .expected = 64 },
        .{ .name = "clz x, one", .word = 0xdac01020, .x1 = 1, .expected = 63 },
        .{ .name = "clz x, top bit", .word = 0xdac01020, .x1 = 0x8000_0000_0000_0000, .expected = 0 },
        .{ .name = "clz x, bit 32", .word = 0xdac01020, .x1 = 0x0000_0001_0000_0000, .expected = 31 },
        // The top byte is 0000 0001: seven zeros before the first one.
        .{ .name = "clz x, pattern", .word = 0xdac01020, .expected = 7 },
        .{ .name = "clz w, zero", .word = 0x5ac01020, .x1 = 0, .expected = 32 },
        .{ .name = "clz w, one", .word = 0x5ac01020, .x1 = 1, .expected = 31 },
        .{ .name = "clz w, top bit", .word = 0x5ac01020, .x1 = 0x8000_0000, .expected = 0 },
        // The upper half of the register is not part of a 32-bit operand.
        .{ .name = "clz w ignores the top half", .word = 0x5ac01020, .x1 = 0xffff_ffff_0000_0001, .expected = 31 },
        .{ .name = "clz w, 0x00ff0000", .word = 0x5ac01020, .x1 = 0x00ff_0000, .expected = 8 },
    });
    // Every position of a single set bit, at both widths.
    var bit: u7 = 0;
    while (bit < 64) : (bit += 1) {
        var cpu: Cpu = .{};
        cpu.x[1] = @as(u64, 1) << @intCast(bit);
        try run(0xdac01020, &cpu);
        try testing.expectEqual(@as(u64, 63 - bit), cpu.x[0]);
        if (bit < 32) {
            var narrow: Cpu = .{};
            narrow.x[1] = @as(u64, 1) << @intCast(bit);
            try run(0x5ac01020, &narrow);
            try testing.expectEqual(@as(u64, 31 - bit), narrow.x[0]);
        }
    }
}

test "a one-source result written to register 31 is discarded and the stack is untouched" {
    var cpu: Cpu = .{ .sp = 0x1234 };
    cpu.x[1] = pattern;
    try run(0xdac00c3f, &cpu); // rev xzr, x1
    try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
}

test "the neighbours of the one-source class are refused, not read as members" {
    // The 32-bit form of the 64-bit byte reversal does not exist.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x5ac00c20));
    // CLS and a pointer-authentication instruction share the class.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xdac01420));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xdac123e0));
    // With the flag-setting bit set this is not the class at all.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xfac00c20));
    // And the two-source class next door is still the two-source class.
    switch (try Decode.decode(0x9ac22020)) {
        .variable => {},
        else => return error.NotTwoSource,
    }
}

test "the decoder reads the width-dependent opcodes the right way round" {
    // Opcode 2 is the 32-bit byte reversal and the 64-bit reversal within words.
    try testing.expectEqual(Decode.UnaryOp.rev, (try Decode.decode(0x5ac00820)).unary.op);
    try testing.expectEqual(Decode.UnaryOp.rev32, (try Decode.decode(0xdac00820)).unary.op);
    // Opcode 3 is the 64-bit byte reversal.
    try testing.expectEqual(Decode.UnaryOp.rev, (try Decode.decode(0xdac00c20)).unary.op);
}
