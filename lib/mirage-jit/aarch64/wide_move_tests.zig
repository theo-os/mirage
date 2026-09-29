//! Move wide: MOVN, MOVZ and MOVK, which build a constant a halfword at a time.
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

test "MOVN writes the complement of the shifted constant at the register's width" {
    const cases = [_]struct { name: []const u8, word: u32, expected: u64 }{
        .{ .name = "movn x0, #0", .word = 0x92800000, .expected = 0xffff_ffff_ffff_ffff },
        .{ .name = "movn x0, #0x1234, lsl #16", .word = 0x92a24680, .expected = 0xffff_ffff_edcb_ffff },
        .{ .name = "movn x0, #1, lsl #48", .word = 0x92e00020, .expected = 0xfffe_ffff_ffff_ffff },
        // At 32 bits nothing is above bit 31: `mov w0, #-1` is 0xffffffff, not all ones.
        .{ .name = "movn w0, #0", .word = 0x12800000, .expected = 0xffff_ffff },
        .{ .name = "movn w0, #0x8000, lsl #16", .word = 0x12b00000, .expected = 0x7fff_ffff },
    };
    for (cases) |case| {
        var cpu: Cpu = .{ .sp = 0x1234 };
        // What a write that did not replace the whole register would leave showing.
        cpu.x[0] = 0xdead_beef_dead_beef;
        try run(case.word, &cpu);
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
        try testing.expectEqual(case.expected, cpu.x[0]);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

test "the kernel's own MOVN reads back as the value it names" {
    // `movn w9, #0x8000, lsl #16` is how Linux writes 0x7fffffff into w9.
    var cpu: Cpu = .{};
    cpu.x[9] = 0xffff_ffff_ffff_ffff;
    try run(0x12b00009, &cpu);
    try testing.expectEqual(@as(u64, 0x7fff_ffff), cpu.x[9]);
}

test "a wide move to register 31 is discarded and the stack pointer is untouched" {
    for ([_]u32{ 0x9280001f, 0xd280001f, 0xf280001f }) |word| { // movn, movz, movk to xzr
        var cpu: Cpu = .{ .sp = 0x1234 };
        try run(word, &cpu);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

test "MOVN, MOVZ and MOVK are told apart, and the unallocated encoding is refused" {
    try testing.expectEqual(true, (try Decode.decode(0x92800000)) == .movn);
    try testing.expectEqual(true, (try Decode.decode(0xd2800000)) == .movz);
    try testing.expectEqual(true, (try Decode.decode(0xf2800000)) == .movk);
    // The opcode between MOVN and MOVZ is not allocated.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xb2800000));
    // A 32-bit form cannot shift by 32 or 48.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x12c00000));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x12e00000));
}
