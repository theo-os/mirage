const std = @import("std");
const Decode = @import("mirage-jit").aarch64.Decode;

// Statically reachable census of a raw AArch64 binary loaded at `base`.
// Entry is raw offset 0; every direct branch target is followed. Indirect
// branches stop a path: their targets are not knowable without running.
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.ExpectedImagePath;
    const image = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], init.gpa, .limited(64 << 20));
    defer init.gpa.free(image);
    if (image.len % 4 != 0) return error.NotAnImage;

    var seen = try init.gpa.alloc(bool, image.len / 4);
    defer init.gpa.free(seen);
    @memset(seen, false);
    var stack = std.ArrayList(u64).empty;
    defer stack.deinit(init.gpa);
    try stack.append(init.gpa, 0);

    var classes = std.StringHashMap(u64).init(init.gpa);
    defer classes.deinit();
    var unsupported: u64 = 0;
    var unsupported_examples = std.ArrayList(u32).empty;
    defer unsupported_examples.deinit(init.gpa);

    while (stack.pop()) |pc| {
        if (pc + 4 > image.len) continue;
        const index = pc / 4;
        if (seen[index]) continue;
        seen[index] = true;
        const word = std.mem.readInt(u32, image[pc..][0..4], .little);
        const class_name: []const u8 = nameOf(word);
        const entry = try classes.getOrPut(class_name);
        if (!entry.found_existing) entry.value_ptr.* = 0;
        entry.value_ptr.* += 1;
        if (Decode.decode(word)) |instruction| {
            switch (instruction) {
                .b => |offset| {
                    const target = @as(i64, @intCast(pc)) + offset;
                    if (target >= 0) try stack.append(init.gpa, @intCast(target));
                },
                .b_cond => |branch| {
                    const target = @as(i64, @intCast(pc)) + branch.offset;
                    if (target >= 0) try stack.append(init.gpa, @intCast(target));
                    try stack.append(init.gpa, pc + 4);
                },
                .test_branch => |branch| {
                    const target = @as(i64, @intCast(pc)) + branch.offset;
                    if (target >= 0) try stack.append(init.gpa, @intCast(target));
                    try stack.append(init.gpa, pc + 4);
                },
                .call => |call| {
                    if (!call.link) {
                        const target = @as(i64, @intCast(pc)) + call.target;
                        if (target >= 0) try stack.append(init.gpa, @intCast(target));
                    } else {
                        const target = @as(i64, @intCast(pc)) + call.target;
                        if (target >= 0) try stack.append(init.gpa, @intCast(target));
                        try stack.append(init.gpa, pc + 4);
                    }
                },
                .indirect, .eret, .svc, .psci, .wfi, .trap => {},
                else => try stack.append(init.gpa, pc + 4),
            }
        } else |_| {
            unsupported += 1;
            if (unsupported_examples.items.len < 20) try unsupported_examples.append(init.gpa, word);
        }
    }

    var reached: u64 = 0;
    for (seen) |each| {
        if (each) reached += 1;
    }
    std.debug.print("reached {d} of {d} words\n", .{ reached, image.len / 4 });
    std.debug.print("unsupported {d}\n", .{unsupported});
    var it = classes.iterator();
    while (it.next()) |kv| std.debug.print("{d:>8} {s}\n", .{ kv.value_ptr.*, kv.key_ptr.* });
    std.debug.print("first unsupported words:\n", .{});
    for (unsupported_examples.items) |word| std.debug.print("  {x:0>8}\n", .{word});
}

// Bit 31:21 class, good enough to triage rather than to decode.
fn nameOf(word: u32) []const u8 {
    return switch (word >> 21) {
        0b00000000000 => "zero-or-literal",
        0b00000000001 => "adrp-family?",
        0b10101010000 => "orr-shifted?",
        0b11111001010 => "ldr-imm?",
        0b10010001000 => "add-imm",
        0b11111111111 => "literal-pool?",
        0b01010100000 => "cbz-cbnz",
        0b10010100000 => "adr",
        0b10101001000 => "eor-shifted?",
        0b00101010000 => "movk?",
        0b11111001000 => "str-imm?",
        0b01010010100 => "exception?",
        0b10101001010 => "and-shifted?",
        0b10010111111 => "bl?",
        0b00010100000 => "b",
        0b11010110010 => "sysop?",
        0b10110100000 => "cbz?",
        0b11101011000 => "subs-shifted?",
        0b10111001010 => "ldr-reg?",
        0b00000100000 => "bl2?",
        0b00010111111 => "svc?",
        0b11010101001 => "mrs?",
        0b10111001000 => "str-reg?",
        0b11010101000 => "msr?",
        0b10101001101 => "eon?",
        0b10101000110 => "lsr-shifted?",
        0b10001011000 => "add-shifted",
        0b01110001000 => "tbnz?",
        0b11001000110 => "lsr-imm?",
        0b11111000101 => "ldp?",
        0b11010001000 => "ubfm?",
        0b00111001010 => "fcmp?",
        0b10010001001 => "sub-imm?",
        0b00010010100 => "sys?",
        0b01010100111 => "tbz?",
        0b11110001000 => "cmp-shifted?",
        0b10000000000 => "ldp-stp?",
        0b00110100000 => "br?",
        0b11111000010 => "stp?",
        0b00010001000 => "nop?",
        0b10010000000 => "movn?",
        else => "other",
    };
}
