//! How a load or store with a register offset forms its address: the index may be
//! a 32-bit register that is extended first, and the scale is the size of the
//! access. The address, width and direction are read off the state a translated
//! block leaves for the run loop, so this needs no memory behind it.
const std = @import("std");
const testing = @import("mirage-testing");
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const Decode = guest.Decode;

const Case = struct {
    name: []const u8,
    word: u32,
    base: u64 = 0x1000,
    index: u64,
    address: u64,
    width: u8,
    trap: Cpu.Trap,
};

fn check(cases: []const Case) !void {
    for (cases) |case| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, case.word, .little);
        var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
        defer block.deinit();
        var cpu: Cpu = .{ .sp = 0x9000 };
        cpu.x[1] = case.base;
        cpu.x[2] = case.index;
        _ = block.run(&cpu);
        errdefer std.debug.print("{s}: address {x} width {d} trap {t}\n", .{ case.name, cpu.address, cpu.width, cpu.trap });
        try testing.expectEqual(case.address, cpu.address);
        try testing.expectEqual(case.width, cpu.width);
        try testing.expectEqual(case.trap, cpu.trap);
    }
}

test "an unscaled register offset is added as it is, whatever the size of the access" {
    try check(&.{
        .{ .name = "ldrb w0, [x1, x2]", .word = 0x38626820, .index = 5, .address = 0x1005, .width = 1, .trap = .load },
        // The `S` bit is clear, so a doubleword access is not shifted by three.
        .{ .name = "ldr x0, [x1, x2]", .word = 0xf8626820, .index = 8, .address = 0x1008, .width = 8, .trap = .load },
        .{ .name = "ldr w0, [x1, x2]", .word = 0xb8626820, .index = 8, .address = 0x1008, .width = 4, .trap = .load },
    });
}

test "a scaled register offset is shifted by the log2 of the size of the access" {
    try check(&.{
        // A word is four bytes, so the shift is two, and not the three that
        // only a doubleword would use.
        .{ .name = "ldr w0, [x1, x2, lsl #2]", .word = 0xb8627820, .index = 5, .address = 0x1014, .width = 4, .trap = .load },
        .{ .name = "str w0, [x1, x2, lsl #2]", .word = 0xb8227820, .index = 5, .address = 0x1014, .width = 4, .trap = .store },
        .{ .name = "ldr x0, [x1, x2, lsl #3]", .word = 0xf8627820, .index = 5, .address = 0x1028, .width = 8, .trap = .load },
        .{ .name = "ldrh w0, [x1, x2, lsl #1]", .word = 0x78627820, .index = 5, .address = 0x100a, .width = 2, .trap = .load },
        // A byte access cannot be scaled: the shift is log2 of one.
        .{ .name = "ldrb w0, [x1, x2, lsl #0]", .word = 0x38627820, .index = 5, .address = 0x1005, .width = 1, .trap = .load },
    });
}

test "a 32-bit index is extended before it is scaled and added" {
    try check(&.{
        // Zero-extended: the upper half of the register is not part of a word index.
        .{ .name = "ldrh w0, [x1, w2, uxtw #1]", .word = 0x78625820, .index = 0xffff_ffff_0000_0004, .address = 0x1008, .width = 2, .trap = .load },
        .{ .name = "ldrb w0, [x1, w2, uxtw]", .word = 0x38624820, .index = 0xffff_ffff_0000_0004, .address = 0x1004, .width = 1, .trap = .load },
        // Sign-extended: a word of minus two is minus two, and minus sixteen once scaled.
        .{ .name = "ldr x0, [x1, w2, sxtw #3]", .word = 0xf862d820, .index = 0xffff_fffe, .address = 0x1000 - 16, .width = 8, .trap = .load },
        .{ .name = "ldr x0, [x1, w2, sxtw]", .word = 0xf862c820, .index = 0xffff_fffe, .address = 0x1000 - 2, .width = 8, .trap = .load },
        // A positive word index stays positive.
        .{ .name = "ldr x0, [x1, w2, sxtw #3]", .word = 0xf862d820, .index = 0x7fff_ffff, .address = 0x1000 + (0x7fff_ffff << 3), .width = 8, .trap = .load },
        // The 64-bit sign extension is the operand as it is.
        .{ .name = "ldr x0, [x1, x2, sxtx]", .word = 0xf862e820, .index = 0xffff_ffff_ffff_fff0, .address = 0x1000 - 16, .width = 8, .trap = .load },
    });
}

test "the kernel's own register-offset store" {
    // `strb w9, [x8, w21, sxtw]`, from Linux's early code: a byte store at a base
    // plus a sign-extended 32-bit index of minus one.
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 0x3835c909, .little);
    var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
    defer block.deinit();
    var cpu: Cpu = .{};
    cpu.x[8] = 0x2000;
    cpu.x[21] = 0xffff_ffff;
    cpu.x[9] = 0xab;
    _ = block.run(&cpu);
    try testing.expectEqual(@as(u64, 0x1fff), cpu.address);
    try testing.expectEqual(Cpu.Trap.store, cpu.trap);
    try testing.expectEqual(@as(u8, 1), cpu.width);
    try testing.expectEqual(@as(u64, 0xab), cpu.value);
}

test "the reserved index options are refused" {
    // The options for a byte, halfword and their signed forms are not allocated for an index.
    for ([_]u32{ 0xf8620820, 0xf8622820, 0xf8628820, 0xf862a820 }) |word| {
        try testing.expectError(error.UnsupportedInstruction, Decode.decode(word));
    }
}

test "a literal load reads from an address relative to the instruction itself" {
    const Literal = struct { word: u32, address: u64, width: u8, dest: u8 };
    for ([_]Literal{
        // `ldr x8, <pc+20>`, as the kernel has it: five instructions on.
        .{ .word = 0x580000a8, .address = 0x4014, .width = 8, .dest = 8 },
        // `ldr w0, <pc-8>`: a negative displacement, and a word.
        .{ .word = 0x18ffffc0, .address = 0x3ff8, .width = 4, .dest = 0 },
        // The largest reach forward is a little under a megabyte: 2^18 - 1 words.
        .{ .word = 0x587fffe1, .address = 0x4000 + ((1 << 18) - 1) * 4, .width = 8, .dest = 1 },
    }) |case| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, case.word, .little);
        var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
        defer block.deinit();
        var cpu: Cpu = .{};
        cpu.x[1] = 0x1111; // a base register must have no say in a PC-relative address
        _ = block.run(&cpu);
        errdefer std.debug.print("{x}: address {x}\n", .{ case.word, cpu.address });
        try testing.expectEqual(case.address, cpu.address);
        try testing.expectEqual(case.width, cpu.width);
        try testing.expectEqual(case.dest, cpu.dest);
        try testing.expectEqual(Cpu.Trap.load, cpu.trap);
    }
}

test "the literal forms this does not perform are refused, not read as plain loads" {
    // The sign-extending word load and the SIMD load.
    for ([_]u32{ 0x98000000, 0x1c000000 }) |word| {
        try testing.expectError(error.UnsupportedInstruction, Decode.decode(word));
    }
}

test "a prefetch decodes as nothing and touches nothing" {
    // prfm with an immediate (the kernel's own), a register, an unscaled offset, and a literal.
    for ([_]u32{ 0xf9800131, 0xf8a16800, 0xf8800000, 0xd8000000 }) |word| {
        try testing.expectEqual(true, (try Decode.decode(word)) == .nop);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
        defer block.deinit();
        var cpu: Cpu = .{ .sp = 0x1234 };
        cpu.x[1] = 0x77;
        _ = block.run(&cpu);
        try testing.expectEqual(Cpu.Trap.none, cpu.trap); // no access was asked for
        try testing.expectEqual(@as(u64, 0x77), cpu.x[1]);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}
