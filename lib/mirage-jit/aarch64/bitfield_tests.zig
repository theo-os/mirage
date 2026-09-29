//! The bitfield moves: extract, insert, and the extensions and shifts spelled
//! with them. Every expected value is worked out from the definition of the
//! instruction, not read back from the translator.
const std = @import("std");
const testing = @import("mirage-testing");
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const Decode = guest.Decode;

const source: u64 = 0x0123_4567_89ab_cdef;
const previous: u64 = 0x1111_1111_1111_1111;

fn run(word: u32, cpu: *Cpu) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
    defer block.deinit();
    _ = block.run(cpu);
}

const Case = struct { name: []const u8, word: u32, x1: u64 = source, x0: u64 = previous, expected: u64 };

fn check(cases: []const Case) !void {
    for (cases) |case| {
        var cpu: Cpu = .{ .sp = 0x1234 };
        cpu.x[0] = case.x0;
        cpu.x[1] = case.x1;
        try run(case.word, &cpu);
        errdefer std.debug.print("{s}: got {x}, wanted {x}\n", .{ case.name, cpu.x[0], case.expected });
        try testing.expectEqual(case.expected, cpu.x[0]);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}

test "extracting a field zero- or sign-extends the bits at its position" {
    // Bits 19:16 of the source are 0xb, which is 0b1011: its top bit is set.
    try check(&.{
        .{ .name = "ubfx x0, x1, #16, #4", .word = 0xd3504c20, .expected = 0xb },
        .{ .name = "sbfx x0, x1, #16, #4", .word = 0x93504c20, .expected = 0xffff_ffff_ffff_fffb },
        // Bits 11:4 of the low word are 0xde, whose top bit is set.
        .{ .name = "ubfx w0, w1, #4, #8", .word = 0x53042c20, .expected = 0xde },
        // A 32-bit result is sign-extended in 32 bits and then zero-extended into
        // the register, so the upper half is clear.
        .{ .name = "sbfx w0, w1, #4, #8", .word = 0x13042c20, .expected = 0xffff_ffde },
        // A field that reaches the top of the register.
        .{ .name = "ubfx x0, x1, #60, #4", .word = 0xd37cfc20, .expected = 0x0 },
        .{ .name = "sbfx x0, x1, #56, #8", .word = 0x9378fc20, .x1 = 0x8000_0000_0000_0000, .expected = 0xffff_ffff_ffff_ff80 },
    });
}

test "inserting a field places the bottom of the source at a position" {
    // The bottom four bits of the source are 0xf.
    try check(&.{
        .{ .name = "ubfiz x0, x1, #8, #4", .word = 0xd3780c20, .expected = 0xf00 },
        .{ .name = "sbfiz x0, x1, #8, #4", .word = 0x93780c20, .expected = 0xffff_ffff_ffff_ff00 },
        // Positive when the field's top bit is clear: the bottom four bits are 0x7.
        .{ .name = "sbfiz x0, x1, #8, #4 positive", .word = 0x93780c20, .x1 = 0x7, .expected = 0x700 },
        .{ .name = "ubfiz w0, w1, #4, #8", .word = 0x531c1c20, .x1 = 0xffff_ffff_ffff_ffab, .expected = 0xab0 },
    });
}

test "the bitfield insert forms leave the rest of the destination alone" {
    try check(&.{
        // bfxil x0, x1, #16, #4 takes the field to the bottom and keeps the rest.
        .{ .name = "bfxil x0, x1, #16, #4", .word = 0xb3504c20, .expected = 0x1111_1111_1111_111b },
        // bfi x0, x1, #8, #4 replaces bits 11:8 with the source's bottom four.
        .{ .name = "bfi x0, x1, #8, #4", .word = 0xb3780c20, .expected = 0x1111_1111_1111_1f11 },
        // bfc is bfi from the zero register.
        .{ .name = "bfc x0, #8, #4", .word = 0xb3780fe0, .expected = 0x1111_1111_1111_1011 },
        // The 32-bit form keeps the destination's low word and clears the top half.
        .{ .name = "bfi w0, w1, #8, #4", .word = 0x33180c20, .x0 = 0xffff_ffff_ffff_ffff, .expected = 0x0000_0000_ffff_ffff },
        .{ .name = "bfi w0, w1, #8, #4 changes bits", .word = 0x33180c20, .x0 = 0x1111_1111, .x1 = 0x5, .expected = 0x1111_1511 },
    });
}

test "the extensions and shifts that are spelled as bitfields still mean what they say" {
    try check(&.{
        .{ .name = "sxtb x0, w1", .word = 0x93401c20, .x1 = 0x80, .expected = 0xffff_ffff_ffff_ff80 },
        .{ .name = "sxth x0, w1", .word = 0x93403c20, .x1 = 0x8000, .expected = 0xffff_ffff_ffff_8000 },
        .{ .name = "sxtw x0, w1", .word = 0x93407c20, .x1 = 0x8000_0000, .expected = 0xffff_ffff_8000_0000 },
        .{ .name = "sxtw x0, w1 positive", .word = 0x93407c20, .x1 = 0x1_7fff_ffff, .expected = 0x7fff_ffff },
        .{ .name = "uxtb w0, w1", .word = 0x53001c20, .x1 = 0x1ff, .expected = 0xff },
        .{ .name = "uxth w0, w1", .word = 0x53003c20, .x1 = 0x1_ffff, .expected = 0xffff },
        .{ .name = "ubfx x0, x1, #0, #64", .word = 0xd340fc20, .expected = source },
        .{ .name = "ubfx w0, w1, #0, #32", .word = 0x53007c20, .expected = 0x89ab_cdef },
    });
}

test "a bitfield written to register 31 is discarded and the stack pointer is untouched" {
    var cpu: Cpu = .{ .sp = 0x1234 };
    cpu.x[1] = source;
    try run(0xd3504c3f, &cpu); // ubfx xzr, x1, #16, #4
    try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
}

test "the reserved bitfield encodings are refused rather than read as something else" {
    // The N bit disagrees with the register width, in both directions.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x53400c20));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xd3000c20));
    // A 32-bit form naming a bit past 31 in either field.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x53200020));
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0x53008020));
    // The fourth opcode is not a bitfield move.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xf3504c20));
    // And the class next door is not claimed: MOVN shares its top bits with it, and
    // is its own instruction, not a bitmask and not a bitfield.
    try testing.expectEqual(true, (try Decode.decode(0x92800000)) == .movn);
}

test "the decoder unpacks a position and a length, not the encoding's own fields" {
    // ubfx x0, x1, #16, #4: taken from bit 16, four bits.
    const extract = (try Decode.decode(0xd3504c20)).bitfield;
    try testing.expectEqual(true, extract.extract);
    try testing.expectEqual(@as(u6, 16), extract.lsb);
    try testing.expectEqual(@as(u7, 4), extract.len);
    // ubfiz x0, x1, #8, #4: placed at bit 8, four bits. The encoding says rotate by 56.
    const insert = (try Decode.decode(0xd3780c20)).bitfield;
    try testing.expectEqual(false, insert.extract);
    try testing.expectEqual(@as(u6, 8), insert.lsb);
    try testing.expectEqual(@as(u7, 4), insert.len);
    // lsl x0, x1, #3 is ubfm with a rotation of 61 and a run ending at 60.
    const shift = (try Decode.decode(0xd37df020)).bitfield;
    try testing.expectEqual(false, shift.extract);
    try testing.expectEqual(@as(u6, 3), shift.lsb);
    try testing.expectEqual(@as(u7, 61), shift.len);
}
