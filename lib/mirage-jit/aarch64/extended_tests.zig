//! ADD and SUB with an extended second operand, and the stack pointer they alone
//! can name as an operand of a register-form add.
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

const Case = struct { name: []const u8, word: u32, x1: u64, x2: u64, expected: u64 };

test "the extension picks the low bits of the operand and fills the rest" {
    // add x0, x1, w2, <extend> with x1 = 0x1000 in each.
    try run2(&.{
        // Zero extensions keep only the field.
        .{ .name = "uxtb", .word = 0x8b220020, .x1 = 0x1000, .x2 = 0xdead_beef_1234_56f0, .expected = 0x10f0 },
        .{ .name = "uxth", .word = 0x8b222020, .x1 = 0x1000, .x2 = 0xdead_beef_1234_fff0, .expected = 0x1000 + 0xfff0 },
        .{ .name = "uxtw", .word = 0x8b224020, .x1 = 0x1000, .x2 = 0xdead_beef_8000_0001, .expected = 0x1000 + 0x8000_0001 },
        // `uxtx` is the operand as it is, which is also what `lsl` means here.
        .{ .name = "uxtx", .word = 0x8b226020, .x1 = 0x1000, .x2 = 0x0000_0001_0000_0000, .expected = 0x1_0000_1000 },
        // Sign extensions fill from the top bit of the field.
        .{ .name = "sxtb negative", .word = 0x8b228020, .x1 = 0x1000, .x2 = 0x1f0, .expected = 0x1000 - 0x10 },
        .{ .name = "sxtb positive", .word = 0x8b228020, .x1 = 0x1000, .x2 = 0x17f, .expected = 0x1000 + 0x7f },
        .{ .name = "sxth negative", .word = 0x8b22a020, .x1 = 0x1000, .x2 = 0x1_fff0, .expected = 0x1000 - 0x10 },
        .{ .name = "sxtw negative", .word = 0x8b22c020, .x1 = 0x1000, .x2 = 0xffff_ffff_8000_0001, .expected = 0xffff_ffff_8000_1001 },
        .{ .name = "sxtw positive", .word = 0x8b22c020, .x1 = 0x1000, .x2 = 0xffff_ffff_7fff_ffff, .expected = 0x1000 + 0x7fff_ffff },
        .{ .name = "sxtx", .word = 0x8b22e020, .x1 = 0x1000, .x2 = 0xffff_ffff_ffff_fff0, .expected = 0x1000 - 0x10 },
    });
}

test "the extended operand is shifted left by up to four after it is extended" {
    try run2(&.{
        // add x0, x1, w2, uxtw #2: the word times four, whatever sits above it.
        .{ .name = "uxtw #2", .word = 0x8b224820, .x1 = 0x1000, .x2 = 0xdead_beef_0000_0010, .expected = 0x1040 },
        // add x0, x1, w2, sxtw #4 with a low word of minus two: minus thirty-two.
        .{ .name = "sxtw #4", .word = 0x8b22d020, .x1 = 0x1000, .x2 = 0xffff_fffe, .expected = 0x1000 - 32 },
        .{ .name = "uxtb #3", .word = 0x8b220c20, .x1 = 0, .x2 = 0x1ff, .expected = 0xff << 3 },
    });
}

test "subtract, and the kernel's own form" {
    try run2(&.{
        .{ .name = "sub x0, x1, w2, sxtw", .word = 0xcb22c020, .x1 = 0x1000, .x2 = 0xffff_ffff, .expected = 0x1001 },
        // `add x23, x20, w22, sxtw` is a word in Linux's early code, on registers 20,
        // 22 and 23: a base plus a 32-bit signed offset, here minus sixteen.
        .{ .name = "kernel", .word = 0x8b36c297, .x1 = 0x4000_0000, .x2 = 0xffff_fff0, .expected = 0x3fff_fff0 },
    });
}

test "a 32-bit operation extends within 32 bits and clears the top of the result" {
    try run2(&.{
        // add w0, w1, w2, sxtb: 0x10 plus minus 128 wraps at 32 bits.
        .{ .name = "sxtb", .word = 0x0b228020, .x1 = 0x10, .x2 = 0x80, .expected = 0xffff_ff90 },
        .{ .name = "uxth", .word = 0x0b222020, .x1 = 0xffff_0000, .x2 = 0x1_0001, .expected = 0xffff_0001 },
        // The upper half of the first operand is not part of a 32-bit sum.
        .{ .name = "upper half", .word = 0x0b224020, .x1 = 0xffff_ffff_0000_0005, .x2 = 3, .expected = 8 },
    });
}

/// Run each case with `x0` holding a value that a write to the wrong place would leave.
fn run2(cases: []const Case) !void {
    for (cases) |case| {
        var cpu: Cpu = .{ .sp = 0x9000 };
        cpu.x[0] = 0xdead_beef_dead_beef;
        cpu.x[1] = case.x1;
        cpu.x[2] = case.x2;
        cpu.x[20] = case.x1;
        cpu.x[22] = case.x2;
        try run(case.word, &cpu);
        const got = if (case.word == 0x8b36c297) cpu.x[23] else cpu.x[0];
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, got, case.expected });
        try testing.expectEqual(case.expected, got);
        try testing.expectEqual(@as(u64, 0x9000), cpu.sp);
    }
}

test "the stack pointer as an operand and as a destination" {
    // add sp, sp, x1 is `add sp, sp, x1, uxtx`: the destination is the stack pointer.
    var cpu: Cpu = .{ .sp = 0x1000 };
    cpu.x[1] = 0x10;
    try run(0x8b2163ff, &cpu);
    try testing.expectEqual(@as(u64, 0x1010), cpu.sp);

    // sub x0, sp, x1: the stack pointer is read as the first operand.
    var read: Cpu = .{ .sp = 0x1000 };
    read.x[1] = 0x10;
    try run(0xcb2163e0, &read);
    try testing.expectEqual(@as(u64, 0xff0), read.x[0]);
    try testing.expectEqual(@as(u64, 0x1000), read.sp);
}

test "with the flags set, register 31 as the destination is the zero register" {
    // cmp sp, x2 is `subs xzr, sp, x2`: the difference is thrown away, and the
    // stack pointer is not written with it.
    var equal: Cpu = .{ .sp = 0x1000 };
    equal.x[2] = 0x1000;
    try run(0xeb2263ff, &equal);
    try testing.expectEqual(@as(u32, (1 << 30) | (1 << 29)), equal.flags);
    try testing.expectEqual(@as(u64, 0x1000), equal.sp);

    // cmp x1, w2, sxtw with 5 against minus one: 5 - (-1) borrows, so C is clear.
    var below: Cpu = .{ .sp = 0x1000 };
    below.x[1] = 5;
    below.x[2] = 0xffff_ffff;
    try run(0xeb22c03f, &below);
    try testing.expectEqual(@as(u32, 0), below.flags);
    try testing.expectEqual(@as(u64, 0x1000), below.sp);

    // adds with a real destination writes it, and sets the flags from the sum.
    var sum: Cpu = .{ .sp = 0x1000 };
    sum.x[1] = std.math.maxInt(u64);
    sum.x[2] = 1;
    try run(0xab226020, &sum); // adds x0, x1, x2, uxtx
    try testing.expectEqual(@as(u64, 0), sum.x[0]);
    try testing.expectEqual(@as(u32, (1 << 30) | (1 << 29)), sum.flags);
}

test "the extended form is told apart from the shifted register form and its reserved amounts" {
    // add x0, x1, x2 (shifted register) has bit 21 clear.
    switch (try Decode.decode(0x8b020020)) {
        .arith_reg => {},
        else => return error.NotShiftedRegister,
    }
    switch (try Decode.decode(0x8b22c020)) {
        .arith_ext => |ext| {
            try testing.expectEqual(Decode.Extend.sxtw, ext.extend);
            try testing.expectEqual(@as(u3, 0), ext.amount);
        },
        else => return error.NotExtended,
    }
    // An amount past four is not allocated.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x8b22d420));
    // Bits 23:22 are not a shift type in this form.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x8b62c020));
}
