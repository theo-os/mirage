//! Add and subtract with carry. Each expected value is the architecture's own
//! rule: the first operand, plus the second (inverted for a subtract), plus the
//! carry flag, with the flags read off that three-term sum.
const std = @import("std");
const testing = @import("mirage-testing");
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const Decode = guest.Decode;

const N: u32 = 1 << 31;
const Z: u32 = 1 << 30;
const C: u32 = 1 << 29;
const V: u32 = 1 << 28;
const all: u64 = std.math.maxInt(u64);

const Case = struct {
    name: []const u8,
    word: u32,
    x1: u64 = 0,
    x2: u64 = 0,
    flags: u32 = 0,
    result: u64,
    /// The flags after, when the instruction sets them.
    after: ?u32 = null,
};

fn check(cases: []const Case) !void {
    for (cases) |case| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, case.word, .little);
        var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
        defer block.deinit();
        var cpu: Cpu = .{ .flags = case.flags, .sp = 0x1234 };
        cpu.x[0] = 0xdead_beef_dead_beef;
        cpu.x[1] = case.x1;
        cpu.x[2] = case.x2;
        _ = block.run(&cpu);
        errdefer std.debug.print("{s}: got {x} flags {x}\n", .{ case.name, cpu.x[0], cpu.flags });
        try testing.expectEqual(case.result, cpu.x[0]);
        try testing.expectEqual(case.after orelse case.flags, cpu.flags);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

// adc x0, x1, x2 and its relatives, on registers 0, 1 and 2.
const adc_x: u32 = 0x9a020020;
const adcs_x: u32 = 0xba020020;
const sbc_x: u32 = 0xda020020;
const sbcs_x: u32 = 0xfa020020;
const ngc_x: u32 = 0xda0203e0; // sbc x0, xzr, x2
const sbc_w: u32 = 0x5a020020;
const sbcs_w: u32 = 0x7a020020;

test "add with carry adds the carry flag as one" {
    try check(&.{
        .{ .name = "no carry", .word = adc_x, .x1 = 5, .x2 = 7, .result = 12 },
        .{ .name = "carry", .word = adc_x, .x1 = 5, .x2 = 7, .flags = C, .result = 13, .after = C },
        // The other flags are not read, and adc does not change any of them.
        .{ .name = "other flags left", .word = adc_x, .x1 = 1, .x2 = 1, .flags = N | Z | V, .result = 2, .after = N | Z | V },
    });
}

test "subtract with carry treats the carry flag as no borrow" {
    // a - b - 1 + C: with the carry set there is no borrow and it is a plain subtract.
    try check(&.{
        .{ .name = "no borrow", .word = sbc_x, .x1 = 10, .x2 = 3, .flags = C, .result = 7, .after = C },
        .{ .name = "borrow", .word = sbc_x, .x1 = 10, .x2 = 3, .result = 6 },
        // ngc x0, x2 is sbc x0, xzr, x2: zero, less the operand, less the borrow.
        .{ .name = "ngc, no borrow", .word = ngc_x, .x2 = 5, .flags = C, .result = @as(u64, 0) -% 5, .after = C },
        .{ .name = "ngc, borrow", .word = ngc_x, .x2 = 5, .result = @as(u64, 0) -% 6 },
    });
}

test "the flag-setting add reports the carry out of all three terms" {
    try check(&.{
        // max + 0 + 1 wraps to zero and carries.
        .{ .name = "wrap to zero", .word = adcs_x, .x1 = all, .x2 = 0, .flags = C, .result = 0, .after = Z | C },
        // max + max + 1 is 2^65 - 1: the result is all ones, and it carried.
        .{ .name = "max + max + carry", .word = adcs_x, .x1 = all, .x2 = all, .flags = C, .result = all, .after = N | C },
        // 3 + max + 1 is 2^64 + 3: the result is 3, which is not below 3, and it
        // still carried. A carry read only from "result below operand" misses this.
        .{ .name = "the wrap that leaves the sum equal", .word = adcs_x, .x1 = 3, .x2 = all, .flags = C, .result = 3, .after = C },
        // The same operands with no carry in: 3 + max is 2^64 + 2, a carry with result 2.
        .{ .name = "and without the carry in", .word = adcs_x, .x1 = 3, .x2 = all, .result = 2, .after = C },
        // No carry anywhere.
        .{ .name = "plain", .word = adcs_x, .x1 = 1, .x2 = 2, .flags = C, .result = 4, .after = 0 },
        // The largest signed value plus one, with a carry in, overflows into the sign bit.
        .{ .name = "signed overflow", .word = adcs_x, .x1 = 0x7fff_ffff_ffff_ffff, .x2 = 0, .flags = C, .result = 0x8000_0000_0000_0000, .after = N | V },
    });
}

test "the flag-setting subtract reports borrow and overflow" {
    try check(&.{
        // 0 - 0 - 1: everything borrows, and the result is all ones.
        .{ .name = "borrow out", .word = sbcs_x, .flags = 0, .result = all, .after = N },
        // 5 - 5 with no borrow is zero with the carry set.
        .{ .name = "equal", .word = sbcs_x, .x1 = 5, .x2 = 5, .flags = C, .result = 0, .after = Z | C },
        // The most negative value less one overflows, and nothing was borrowed.
        .{ .name = "signed overflow", .word = sbcs_x, .x1 = 0x8000_0000_0000_0000, .x2 = 1, .flags = C, .result = 0x7fff_ffff_ffff_ffff, .after = C | V },
        // The borrow in can be what pushes a subtraction across zero.
        .{ .name = "borrow in crosses zero", .word = sbcs_x, .x1 = 5, .x2 = 5, .flags = 0, .result = all, .after = N },
    });
}

test "the 32-bit forms work in 32 bits and clear the top of the register" {
    try check(&.{
        // The upper half of each operand is not part of a 32-bit operand.
        .{ .name = "sbc w", .word = sbc_w, .x1 = 0x1_0000_0005, .x2 = 0x7_0000_0003, .flags = C, .result = 2, .after = C },
        .{ .name = "sbc w borrow wraps in 32 bits", .word = sbc_w, .x1 = 0, .x2 = 0, .result = 0xffff_ffff },
        // 0x80000000 - 1 overflows at 32 bits though not at 64.
        .{ .name = "sbcs w overflow", .word = sbcs_w, .x1 = 0x8000_0000, .x2 = 1, .flags = C, .result = 0x7fff_ffff, .after = C | V },
    });
}

test "a carry result written to register 31 is discarded and the stack is untouched" {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 0x9a02001f, .little); // adc xzr, x0, x2
    var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
    defer block.deinit();
    var cpu: Cpu = .{ .sp = 0x1234 };
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
}

test "the carry class is told apart from the selects and compares beside it" {
    switch (try Decode.decode(0x5a1f02a9)) { // sbc w9, w21, wzr, the kernel's own
        .arith_carry => |arith| {
            try testing.expectEqual(Decode.ArithOp.sub, arith.op);
            try testing.expectEqual(false, arith.flags);
            try testing.expectEqual(@as(u5, 31), arith.rm);
        },
        else => return error.NotACarryInstruction,
    }
    switch (try Decode.decode(0x9a820020)) { // csel x0, x1, x2, eq
        .csel => {},
        else => return error.NotASelect,
    }
    switch (try Decode.decode(0xfa4f1824)) { // ccmp x1, #15, #4, ne
        .cond_compare => {},
        else => return error.NotACompare,
    }
    // The second opcode is zero in all four; anything else there is not one of them.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x9a020420));
}
