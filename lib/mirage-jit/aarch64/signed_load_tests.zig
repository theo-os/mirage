//! Loads that sign-extend what they read: LDRSB, LDRSH and LDRSW. They run through
//! a `Machine`, because the extension happens when the load completes, and a load
//! answered by a device completes on a different path from one answered by memory.
const std = @import("std");
const testing = @import("mirage-testing");
const GuestMemory = @import("mirage-memory").GuestMemory;
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const Decode = guest.Decode;

const base: u64 = 0x1000;
const wfi: u32 = 0xd503207f;
const device: u64 = 0x9000_0000;

/// Run `words` with `x0` at a word of RAM holding `data` and `x3` at a device that
/// answers every read with `answer`.
fn execute(words: []const u32, data: u64, answer: u64) !Cpu {
    var bytes: [0x200]u8 = @splat(0);
    for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    std.mem.writeInt(u64, bytes[0x100..][0..8], data, .little);
    const regions = [_]GuestMemory.Region{.{ .gpa = base, .len = bytes.len, .backing = .{ .shared = &bytes } }};
    var memory: GuestMemory = .{ .regions = &regions };
    var machine = guest.Machine.init(testing.allocator(), &memory);
    defer machine.deinit();
    const hv = machine.backend();
    const id = try hv.addVcpu();
    try hv.setRegister(id, .pc, base);
    try hv.setRegister(id, .x0, base + 0x100);
    try hv.setRegister(id, .x3, device);
    while (true) switch (try hv.run(id)) {
        .wfi => break,
        .interrupted => {},
        .mmio_read => try hv.completeMmioRead(id, answer),
        else => return error.UnexpectedExit,
    };
    return machine.cpu;
}

const ldrsw_x2: u32 = 0xb9800002; // ldrsw x2, [x0]
const ldrsb_x2: u32 = 0x39800002;
const ldrsb_w2: u32 = 0x39c00002;
const ldrsh_x2: u32 = 0x79800002;
const ldrsh_w2: u32 = 0x79c00002;
const ldrb_w4: u32 = 0x39400004; // ldrb w4, [x0]

test "a sign-extending load fills from the top bit of what it read" {
    const cases = [_]struct { name: []const u8, word: u32, data: u64, expected: u64 }{
        .{ .name = "ldrsw negative", .word = ldrsw_x2, .data = 0x8000_0001, .expected = 0xffff_ffff_8000_0001 },
        .{ .name = "ldrsw positive", .word = ldrsw_x2, .data = 0x7fff_ffff, .expected = 0x7fff_ffff },
        // Only the four bytes it names are looked at, whatever sits above them.
        .{ .name = "ldrsw ignores what follows", .word = ldrsw_x2, .data = 0xdead_beef_0000_0001, .expected = 1 },
        .{ .name = "ldrsb to x", .word = ldrsb_x2, .data = 0x80, .expected = 0xffff_ffff_ffff_ff80 },
        .{ .name = "ldrsb to x positive", .word = ldrsb_x2, .data = 0x7f, .expected = 0x7f },
        // To a W register the extension stops at bit 31 and the rest is clear.
        .{ .name = "ldrsb to w", .word = ldrsb_w2, .data = 0x80, .expected = 0xffff_ff80 },
        .{ .name = "ldrsh to x", .word = ldrsh_x2, .data = 0x8000, .expected = 0xffff_ffff_ffff_8000 },
        .{ .name = "ldrsh to w", .word = ldrsh_w2, .data = 0x8000, .expected = 0xffff_8000 },
        .{ .name = "ldrsh to w positive", .word = ldrsh_w2, .data = 0x7fff, .expected = 0x7fff },
    };
    for (cases) |case| {
        const cpu = try execute(&.{ case.word, wfi }, case.data, 0);
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[2], case.expected });
        try testing.expectEqual(case.expected, cpu.x[2]);
    }
}

test "the extension belongs to one load and does not leak into the next" {
    // A sign-extending byte load, and then a plain one of the same byte.
    const cpu = try execute(&.{ ldrsb_x2, ldrb_w4, wfi }, 0x80, 0);
    try testing.expectEqual(@as(u64, 0xffff_ffff_ffff_ff80), cpu.x[2]);
    try testing.expectEqual(@as(u64, 0x80), cpu.x[4]);
}

test "a load answered by a device is extended when the answer arrives" {
    // ldrsb x2, [x3], ldrsh w5, [x3], and a plain ldrb after them.
    const ldrsb_x2_x3: u32 = 0x39800062;
    const ldrsh_w5_x3: u32 = 0x79c00065;
    const ldrb_w6_x3: u32 = 0x39400066;
    const cpu = try execute(&.{ ldrsb_x2_x3, ldrsh_w5_x3, ldrb_w6_x3, wfi }, 0, 0x8080);
    try testing.expectEqual(@as(u64, 0xffff_ffff_ffff_ff80), cpu.x[2]);
    try testing.expectEqual(@as(u64, 0xffff_8080), cpu.x[5]);
    try testing.expectEqual(@as(u64, 0x80), cpu.x[6]);
}

test "the other addressing forms extend too" {
    // ldursw x2, [x0] (unscaled), and ldrsw x2, [x0], #0 (post-index).
    for ([_]u32{ 0xb8800002, 0xb8800402 }) |word| {
        const cpu = try execute(&.{ word, wfi }, 0x8000_0000, 0);
        try testing.expectEqual(@as(u64, 0xffff_ffff_8000_0000), cpu.x[2]);
    }
}

test "the sign-extending forms that do not exist are refused" {
    // A word cannot be extended to 32 bits, and a doubleword has nothing to extend:
    // opcode 2 there is the prefetch.
    for ([_]u32{ 0xb9c00002, 0xf9c00002 }) |word| {
        try testing.expectError(error.UnsupportedInstruction, Decode.decode(word));
    }
    // A plain load and store are not extending.
    try testing.expectEqual(Cpu.SignExtend.none, (try Decode.decode(0xb9400002)).memory.signed);
    try testing.expectEqual(Cpu.SignExtend.to64, (try Decode.decode(ldrsw_x2)).memory.signed);
    try testing.expectEqual(Cpu.SignExtend.to32, (try Decode.decode(ldrsb_w2)).memory.signed);
}
