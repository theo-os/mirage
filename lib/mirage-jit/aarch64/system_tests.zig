//! The system registers, the identification values a guest boots on, and the
//! system instructions that are not register moves.
const std = @import("std");
const testing = @import("mirage-testing");
const guest = @import("mirage-jit").aarch64;
const Cpu = guest.Cpu;
const Decode = guest.Decode;
const Identification = guest.Identification;

fn run(word: u32, cpu: *Cpu) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
    defer block.deinit();
    _ = block.run(cpu);
}

test "the registers that describe the machine read back what Identification says" {
    const rows = [_]struct { word: u32, register: Decode.SystemRegister }{
        .{ .word = 0xd5380000, .register = .midr_el1 }, // mrs x0, midr_el1
        .{ .word = 0xd53800a0, .register = .mpidr_el1 },
        .{ .word = 0xd53b0020, .register = .ctr_el0 },
        .{ .word = 0xd53b00e0, .register = .dczid_el0 },
        .{ .word = 0xd53be000, .register = .cntfrq_el0 },
        .{ .word = 0xd5380400, .register = .id_aa64pfr0_el1 },
        .{ .word = 0xd5380500, .register = .id_aa64dfr0_el1 },
        .{ .word = 0xd5380700, .register = .id_aa64mmfr0_el1 },
    };
    for (rows) |row| {
        const decoded = try Decode.decode(row.word);
        try testing.expectEqual(row.register, decoded.system.register);
        var cpu: Cpu = .{ .sp = 0x1234 };
        try run(row.word, &cpu);
        errdefer std.debug.print("{t}: got {x}\n", .{ row.register, cpu.x[0] });
        try testing.expectEqual(Identification.value(row.register).?, cpu.x[0]);
    }
}

test "SP_ELn accesses select the bank named by PSTATE.SP" {
    var cpu: Cpu = .{ .sp = 0x1111, .system = .{ .spsel = false } };
    cpu.system.sp_el[1] = 0x2222;
    try run(0xd5384100, &cpu); // mrs x0, sp_el0: live in EL1t
    try testing.expectEqual(@as(u64, 0x1111), cpu.x[0]);
    try run(0xd53c4100, &cpu); // mrs x0, sp_el1: banked in EL1t
    try testing.expectEqual(@as(u64, 0x2222), cpu.x[0]);

    cpu.system.spsel = true;
    cpu.sp = 0x3333;
    try run(0xd53c4100, &cpu); // mrs x0, sp_el1: live in EL1h
    try testing.expectEqual(@as(u64, 0x3333), cpu.x[0]);
}

test "every identification register the kernel reads is answered, and none can be written" {
    // The kernel reads these before anything else, and one that is refused stops
    // the boot at an address no bug report will explain.
    const reads = [_]u32{
        0xd5380000, 0xd53800a0, 0xd53b0020, 0xd53b00e0, 0xd5390020, // midr, mpidr, ctr, dczid, clidr
        0xd5380400, 0xd5380420, 0xd5380440, 0xd5380480, 0xd53804a0, // pfr0, pfr1, pfr2, zfr0, smfr0
        0xd5380500, 0xd5380520, // dfr0, dfr1
        0xd53800c0, // revidr
        0xd53804e0, 0xd5380660, 0xd53900e0, // id_aa64fpfr0 (0,0,4,7), id_aa64isar3 (0,0,6,3), aidr (1,0,0,7)
        0xd5380600, 0xd5380620, 0xd5380640, // isar0, isar1, isar2
        0xd5380700, 0xd5380720, 0xd5380740, 0xd5380760, 0xd5380780, // mmfr0 .. mmfr4
    };
    for (reads) |word| {
        const decoded = try Decode.decode(word);
        try testing.expectEqual(true, Identification.value(decoded.system.register) != null);
        // The same word with the direction bit cleared is an MSR to the same register.
        try testing.expectError(error.UnsupportedInstruction, Decode.decode(word & ~@as(u32, 0x0020_0000)));
    }
}

test "the guest is told nothing it cannot do" {
    // No system register interface to the interrupt controller: it is memory mapped.
    try testing.expectEqual(@as(u64, 0), Identification.value(.id_aa64pfr0_el1).? >> 24 & 0xf);
    // AArch64 at EL0 and EL1, and nothing above or below.
    try testing.expectEqual(@as(u64, 0x11), Identification.value(.id_aa64pfr0_el1).? & 0xff);
    // FP and ASIMD are not implemented, so advertise the architectural
    // "not implemented" value rather than the implemented-zero encoding.
    const pfr0 = Identification.value(.id_aa64pfr0_el1).?;
    try testing.expectEqual(@as(u64, 0xf), pfr0 >> 16 & 0xf);
    try testing.expectEqual(@as(u64, 0xf), pfr0 >> 20 & 0xf);
    // No atomic instructions, so the guest builds its own from exclusives.
    try testing.expectEqual(@as(u64, 0), Identification.value(.id_aa64isar0_el1).?);
    // 4 KiB pages only: the 64 KiB field says "no" with 0xf and the 16 KiB one with 0.
    const mmfr0 = Identification.value(.id_aa64mmfr0_el1).?;
    try testing.expectEqual(@as(u64, 0), mmfr0 >> 28 & 0xf);
    try testing.expectEqual(@as(u64, 0xf), mmfr0 >> 24 & 0xf);
    try testing.expectEqual(@as(u64, 0), mmfr0 >> 20 & 0xf);
    // The zeroing block is the sixty-four bytes the run loop clears for `DC ZVA`.
    try testing.expectEqual(@as(u64, 64), @as(u64, 4) << @intCast(Identification.value(.dczid_el0).? & 0xf));
    // Register 31 is reserved as one in `CTR_EL0`, and both line sizes are 64 bytes.
    const ctr = Identification.value(.ctr_el0).?;
    try testing.expectEqual(@as(u64, 1), ctr >> 31);
    try testing.expectEqual(@as(u64, 4), ctr >> 16 & 0xf);
    try testing.expectEqual(@as(u64, 4), ctr & 0xf);
}

test "a register the kernel keeps its own state in stores what is written" {
    const rows = [_]struct { write: u32, read: u32, name: []const u8 }{
        .{ .write = 0xd518d080, .read = 0xd538d080, .name = "tpidr_el1" },
        .{ .write = 0xd5100240, .read = 0xd5300240, .name = "mdscr_el1" },
        .{ .write = 0xd518e100, .read = 0xd538e100, .name = "cntkctl_el1" },
        .{ .write = 0xd51b4400, .read = 0xd53b4400, .name = "fpcr" },
        .{ .write = 0xd51b4420, .read = 0xd53b4420, .name = "fpsr" },
    };
    for (rows) |row| {
        var cpu: Cpu = .{};
        cpu.x[0] = 0xfeed_face_cafe_beef;
        try run(row.write, &cpu);
        cpu.x[0] = 0;
        try run(row.read, &cpu);
        errdefer std.debug.print("{s}: read back {x}\n", .{ row.name, cpu.x[0] });
        try testing.expectEqual(@as(u64, 0xfeed_face_cafe_beef), cpu.x[0]);
    }
}

test "writing the zero register to a system register writes zero, not the stack pointer" {
    var cpu: Cpu = .{ .sp = 0x1234 };
    cpu.system.tpidr_el1 = 0xffff;
    try run(0xd518d09f, &cpu); // msr tpidr_el1, xzr
    try testing.expectEqual(@as(u64, 0), cpu.system.tpidr_el1);
}

test "the register form of DAIF puts the masks at bits 9:6 and reads them back from there" {
    // Interrupts masked means bit 7 of what `mrs` returns, which is what a kernel tests.
    var cpu: Cpu = .{ .system = .{ .daif = 0b0010 } }; // only I
    try run(0xd53b4220, &cpu); // mrs x0, daif
    try testing.expectEqual(@as(u64, 1 << 7), cpu.x[0]);
    cpu.system.daif = 0xf;
    try run(0xd53b4220, &cpu);
    try testing.expectEqual(@as(u64, 0xf << 6), cpu.x[0]);

    // Writing the register form stores the four masks in the layout the immediate
    // forms and an exception use, and ignores every other bit of the value.
    cpu.x[0] = (0b0100 << 6) | 0xffff_0000_0000_003f;
    try run(0xd51b4220, &cpu); // msr daif, x0
    try testing.expectEqual(@as(u64, 0b0100), cpu.system.daif);
}
test "the counter advances per executed instruction and drives timer status" {
    // Single-instruction blocks advance it by one guest tick each.
    var cpu: Cpu = .{};
    try run(0xd503201f, &cpu); // nop
    try run(0xd503201f, &cpu); // nop
    try testing.expectEqual(@as(u64, 2), cpu.system.cntvct_el0);
    // Reading the counter itself executes and advances one instruction.
    cpu.x[0] = 0;
    try run(0xd53be040, &cpu); // mrs x0, cntvct_el0
    try testing.expectEqual(@as(u64, 3), cpu.x[0]);

    // The kernel's own words: program a compare, enable the timer, read control.
    cpu.x[9] = 0x1000;
    try run(0xd51be349, &cpu); // msr cntv_cval_el0, x9
    try testing.expectEqual(@as(u64, 0x1000), cpu.system.cntv_cval_el0);
    cpu.system.cntvct_el0 = 0x2000;
    cpu.x[8] = 0b1;
    try run(0xd51be328, &cpu); // msr cntv_ctl_el0, x8
    try run(0xd53be328, &cpu); // mrs x8, cntv_ctl_el0
    try testing.expectEqual(@as(u64, 0b101), cpu.x[8]);
    // A write cannot set or clear the condition: only enable and mask are stored.
    cpu.x[8] = 0xffff_ffff_ffff_ffff;
    try run(0xd51be328, &cpu); // msr cntv_ctl_el0, x8
    try testing.expectEqual(@as(u64, 0b11), cpu.system.cntv_ctl_el0);
    // Before compare: read control advances once, but remains below the compare.
    cpu.system.cntvct_el0 = 0;
    cpu.system.cntv_cval_el0 = 2;
    try run(0xd53be328, &cpu); // mrs x8, cntv_ctl_el0
    try testing.expectEqual(@as(u64, 0b11), cpu.x[8]);
}
test "the debug locks clear and the status follows them" {
    // Reset state reads locked; the kernel's own sequence unlocks both.
    var cpu: Cpu = .{};
    try run(0xd530118a, &cpu); // mrs x10, oslsr_el1
    try testing.expectEqual(@as(u64, 0b10), cpu.x[10]);
    cpu.x[8] = 0;
    try run(0xd5101388, &cpu); // msr osdlr_el1, x8
    try run(0xd5101088, &cpu); // msr oslar_el1, x8
    try testing.expectEqual(@as(u64, 0), cpu.system.osdlr_el1);
    try testing.expectEqual(@as(u64, 0), cpu.system.oslar_el1);
    try run(0xd530118a, &cpu); // mrs x10, oslsr_el1
    try testing.expectEqual(@as(u64, 0), cpu.x[10]);
    // Holding either lock reads locked again.
    cpu.x[8] = 1;
    try run(0xd5101088, &cpu); // msr oslar_el1, x8
    try run(0xd530118a, &cpu); // mrs x10, oslsr_el1
    try testing.expectEqual(@as(u64, 0b10), cpu.x[10]);
}

test "cache maintenance does nothing and address translation is refused" {
    // dc civac, dc cvau, dc ivac, dc cvac, ic ivau, ic iallu, ic ialluis.
    for ([_]u32{ 0xd50b7e20, 0xd50b7b20, 0xd5087620, 0xd50b7a20, 0xd50b7520, 0xd508751f, 0xd508711f }) |word| {
        switch (try Decode.decode(word)) {
            .cache_op => {},
            else => return error.NotCacheMaintenance,
        }
        var cpu: Cpu = .{ .sp = 0x1234 };
        cpu.x[0] = 0x9999;
        try run(word, &cpu);
        // Nothing observable changes: not a register, not the stack, not the flags.
        try testing.expectEqual(@as(u64, 0x9999), cpu.x[0]);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
    // `dc zva` is still its own instruction, and not one of these.
    switch (try Decode.decode(0xd50b7420)) {
        .dc_zva => {},
        else => return error.NotDcZva,
    }
    // `at s1e1r, x0` asks for a translation this does not perform.
    try testing.expectError(error.UnsupportedInstruction, Decode.decode(0xd5087800));
}

test "a TLB invalidation ends the block so the run loop can flush what it remembers" {
    // tlbi vmalle1, tlbi vae1 x0, tlbi vaae1 x0, tlbi aside1 x0.
    for ([_]u32{ 0xd508871f, 0xd5088720, 0xd5088760, 0xd5088740 }) |word| {
        const decoded = try Decode.decode(word);
        try testing.expectEqual(true, decoded.terminates());
        var cpu: Cpu = .{};
        try run(word, &cpu);
        // The same trap an ISB raises: the run loop flushes on it.
        try testing.expectEqual(Cpu.Trap.sync, cpu.trap);
    }
}

test "the first block a kernel runs reads its level and leaves the stack pointer alone" {
    // `record_mmu_state`, as Linux's head.S runs it before it has a stack:
    //   mrs x19, CurrentEL; cmp x19, #8; mrs x19, SCTLR_EL1; b.ne +8
    const words = [_]u32{ 0xd5384253, 0xf100227f, 0xd5381013, 0x54000041 };
    var bytes: [16]u8 = undefined;
    for (words, 0..) |word, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    var block = try guest.compile(testing.allocator(), 0x4000, &bytes);
    defer block.deinit();

    var cpu: Cpu = .{ .sp = 0 };
    cpu.system.sctlr_el1 = 0;
    const next = block.run(&cpu);

    // EL1 is the level in bits 3:2, so CurrentEL reads 4. Comparing that to 8
    // borrows, which is negative, not zero, no carry, and no overflow.
    try testing.expectEqual(@as(u32, 0x8000_0000), cpu.flags);
    // SCTLR_EL1 was zero, so x19 ended as zero.
    try testing.expectEqual(@as(u64, 0), cpu.x[19]);
    // The stack is not touched by any of it, and the branch is taken: not equal to 8.
    try testing.expectEqual(@as(u64, 0), cpu.sp);
    try testing.expectEqual(@as(u64, 0x4000 + 12 + 8), next);
}

test "CurrentEL names the level in bits 3:2 and nothing else" {
    for ([_]struct { el: u8, expected: u64 }{
        .{ .el = 0, .expected = 0 },
        .{ .el = 1, .expected = 4 },
        .{ .el = 2, .expected = 8 },
    }) |row| {
        var cpu: Cpu = .{ .sp = 0x1234, .system = .{ .el = row.el } };
        try run(0xd5384253, &cpu); // mrs x19, CurrentEL
        errdefer std.debug.print("el {d}: read {x}\n", .{ row.el, cpu.x[19] });
        try testing.expectEqual(row.expected, cpu.x[19]);
        try testing.expectEqual(@as(u64, 0x1234), cpu.sp);
    }
}
