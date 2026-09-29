//! Register-source data processing: variable shifts, divides, and the encodings
//! whose register 31 is the zero register rather than the stack pointer.
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

fn check(cases: []const Case) !void {
    for (cases) |case| {
        var cpu: Cpu = .{ .sp = 0x1234 };
        cpu.x[1] = case.x1;
        cpu.x[2] = case.x2;
        try run(case.word, &cpu);
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
        try testing.expectEqual(case.expected, cpu.x[0]);
    }
}

test "a shift by a register takes its distance modulo the register width" {
    try check(&.{
        .{ .name = "lsl x", .word = 0x9ac22020, .x1 = 1, .x2 = 65, .expected = 2 },
        .{ .name = "lsl w", .word = 0x1ac22020, .x1 = 1, .x2 = 33, .expected = 2 },
        // A 32-bit result clears the top half of the register.
        .{ .name = "lsl w drops the top", .word = 0x1ac22020, .x1 = 0x8000_0001, .x2 = 1, .expected = 2 },
        .{ .name = "lsr x", .word = 0x9ac22420, .x1 = 0x8000_0000_0000_0000, .x2 = 63, .expected = 1 },
        .{ .name = "lsr w", .word = 0x1ac22420, .x1 = 0xffff_ffff_8000_0000, .x2 = 31, .expected = 1 },
        .{ .name = "asr x", .word = 0x9ac22820, .x1 = 0x8000_0000_0000_0000, .x2 = 63, .expected = std.math.maxInt(u64) },
        .{ .name = "asr x positive", .word = 0x9ac22820, .x1 = 0x4000_0000_0000_0000, .x2 = 62, .expected = 1 },
        .{ .name = "asr w", .word = 0x1ac22820, .x1 = 0x8000_0000, .x2 = 31, .expected = 0xffff_ffff },
        .{ .name = "ror x", .word = 0x9ac22c20, .x1 = 1, .x2 = 1, .expected = 0x8000_0000_0000_0000 },
        .{ .name = "ror x by zero", .word = 0x9ac22c20, .x1 = 0x1234_5678_9abc_def0, .x2 = 0, .expected = 0x1234_5678_9abc_def0 },
        .{ .name = "ror x by the width", .word = 0x9ac22c20, .x1 = 0x1234_5678_9abc_def0, .x2 = 64, .expected = 0x1234_5678_9abc_def0 },
        .{ .name = "ror w", .word = 0x1ac22c20, .x1 = 1, .x2 = 1, .expected = 0x8000_0000 },
        .{ .name = "ror w by zero", .word = 0x1ac22c20, .x1 = 0xdead_beef, .x2 = 0, .expected = 0xdead_beef },
    });
}

test "unsigned divide, including the divide by zero that traps on the host" {
    try check(&.{
        .{ .name = "udiv x", .word = 0x9ac20820, .x1 = 100, .x2 = 7, .expected = 14 },
        .{ .name = "udiv x large", .word = 0x9ac20820, .x1 = std.math.maxInt(u64), .x2 = 2, .expected = std.math.maxInt(u64) / 2 },
        .{ .name = "udiv x by zero", .word = 0x9ac20820, .x1 = 100, .x2 = 0, .expected = 0 },
        .{ .name = "udiv w", .word = 0x1ac20820, .x1 = 0x1_0000_0064, .x2 = 7, .expected = 14 },
        // The divisor's top half is not part of a 32-bit divisor.
        .{ .name = "udiv w by zero low half", .word = 0x1ac20820, .x1 = 100, .x2 = 0x1_0000_0000, .expected = 0 },
    });
}

test "signed divide, including the two quotients that trap on the host" {
    const min64: u64 = 0x8000_0000_0000_0000;
    try check(&.{
        .{ .name = "sdiv x", .word = 0x9ac20c20, .x1 = 100, .x2 = 7, .expected = 14 },
        .{ .name = "sdiv x negative", .word = 0x9ac20c20, .x1 = @bitCast(@as(i64, -100)), .x2 = 7, .expected = @bitCast(@as(i64, -14)) },
        // Toward zero, not toward minus infinity.
        .{ .name = "sdiv x truncates", .word = 0x9ac20c20, .x1 = @bitCast(@as(i64, -7)), .x2 = 2, .expected = @bitCast(@as(i64, -3)) },
        .{ .name = "sdiv x by zero", .word = 0x9ac20c20, .x1 = 100, .x2 = 0, .expected = 0 },
        .{ .name = "sdiv x by minus one", .word = 0x9ac20c20, .x1 = 100, .x2 = std.math.maxInt(u64), .expected = @bitCast(@as(i64, -100)) },
        .{ .name = "sdiv x min by minus one", .word = 0x9ac20c20, .x1 = min64, .x2 = std.math.maxInt(u64), .expected = min64 },
        .{ .name = "sdiv w", .word = 0x1ac20c20, .x1 = 0xffff_ff9c, .x2 = 7, .expected = 0xffff_fff2 },
        .{ .name = "sdiv w min by minus one", .word = 0x1ac20c20, .x1 = 0x8000_0000, .x2 = 0xffff_ffff, .expected = 0x8000_0000 },
        // Minus one in the low half is minus one, whatever sits above it.
        .{ .name = "sdiv w minus one low half", .word = 0x1ac20c20, .x1 = 100, .x2 = 0x1_ffff_ffff, .expected = 0xffff_ff9c },
    });
}

test "a two-source result written to register 31 is discarded, not stored in the stack pointer" {
    var cpu: Cpu = .{ .sp = 0x1234 };
    cpu.x[1] = 100;
    cpu.x[2] = 7;
    try run(0x9ac2083f, &cpu); // udiv xzr, x1, x2
    try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
}

test "the two-source class refuses the instructions it shares its space with" {
    // CRC32B, and a pointer-authentication instruction, share the class.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x1ac04020));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x9ac03020));
    // The flag-setting bit selects a different instruction (SUBPS), not this class.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xbac20020));
}

test "the zero register is read as zero and written nowhere by a conditional select" {
    // With SP holding a value that would be visible if it were read instead.
    const cases = [_]struct { name: []const u8, word: u32, flags: u32, expected: u64 }{
        // cset w0, eq is csinc w0, wzr, wzr, ne: one when Z is set.
        .{ .name = "cset w true", .word = 0x1a9f17e0, .flags = 1 << 30, .expected = 1 },
        .{ .name = "cset w false", .word = 0x1a9f17e0, .flags = 0, .expected = 0 },
        .{ .name = "cset x true", .word = 0x9a9f17e0, .flags = 1 << 30, .expected = 1 },
        // csetm x0, eq is csinv x0, xzr, xzr, ne: all ones when Z is set.
        .{ .name = "csetm x true", .word = 0xda9f13e0, .flags = 1 << 30, .expected = std.math.maxInt(u64) },
        .{ .name = "csetm x false", .word = 0xda9f13e0, .flags = 0, .expected = 0 },
        // csel x0, xzr, x1, eq and csel x0, x1, xzr, eq.
        .{ .name = "csel xzr first", .word = 0x9a8103e0, .flags = 1 << 30, .expected = 0 },
        .{ .name = "csel xzr second", .word = 0x9a9f0020, .flags = 0, .expected = 0 },
    };
    for (cases) |case| {
        var cpu: Cpu = .{ .sp = 0x1234, .flags = case.flags };
        cpu.x[1] = 0x77;
        try run(case.word, &cpu);
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
        try testing.expectEqual(case.expected, cpu.x[0]);
    }

    // csel xzr, x1, x2, eq writes nowhere: the stack pointer is not the destination.
    var cpu: Cpu = .{ .sp = 0x1234, .flags = 1 << 30 };
    cpu.x[1] = 0x77;
    try run(0x9a82003f, &cpu);
    try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
}

test "multiply reads the zero register as zero and negates for the subtracting forms" {
    try check(&.{
        .{ .name = "mul", .word = 0x9b027c20, .x1 = 6, .x2 = 7, .expected = 42 },
        // mneg x0, x1, x2 is msub x0, x1, x2, xzr: zero minus the product.
        .{ .name = "mneg", .word = 0x9b02fc20, .x1 = 6, .x2 = 7, .expected = @bitCast(@as(i64, -42)) },
        .{ .name = "mneg w", .word = 0x1b02fc20, .x1 = 6, .x2 = 7, .expected = 0xffff_ffd6 },
        // mul x0, xzr, x2: a zero factor, not the stack pointer.
        .{ .name = "mul by xzr", .word = 0x9b027fe0, .x1 = 6, .x2 = 7, .expected = 0 },
    });
    var cpu: Cpu = .{ .sp = 0x1234 };
    cpu.x[1] = 6;
    cpu.x[2] = 7;
    try run(0x9b027c3f, &cpu); // mul xzr, x1, x2
    try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
}
