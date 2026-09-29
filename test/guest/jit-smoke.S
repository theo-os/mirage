// Exercises the arithmetic, flag, and conditional-branch slice the JIT
// implements. Every check that fails jumps to `fail`, so the exit status is one
// byte that says whether the whole program agreed with the architecture. Run it
// under QEMU and under mirage-jit-smoke: the two must agree.
    .text
    .global _start
_start:
    // A counted loop: a conditional branch and a backward target.
    mov x0, #0                  // accumulator
    mov x1, #9                  // counter, counting down to zero
loop:
    add x0, x0, x1
    subs x1, x1, #1
    cmp x1, #0
    b.ne loop
    // 9 + 8 + ... + 0 = 45
    mov x3, #45
    cmp x0, x3
    b.eq sum_ok
    b fail
sum_ok:

    // csel picks between two registers on the condition. Z is set, so x5 is 7.
    mov x4, #7
    csel x5, x4, x0, eq
    cmp x5, #7
    b.eq csel_ok
    b fail
csel_ok:
    add x0, x0, x5              // 45 + 7 = 52

    // A 32-bit borrow: 0 - 1 sets N and V, and leaves Z and C clear.
    mov x6, #0
    subs w6, w6, #1
    b.mi borrow_ok
    b fail
borrow_ok:

    // A 32-bit carry: 0xffffffff + 1 wraps to zero, setting Z and C.
    adds w6, w6, #1
    b.cs carry_ok
    b fail
carry_ok:
    cmp w6, #0
    b.eq zero_ok
    b fail
zero_ok:

    // A signed overflow. The largest signed value plus one is negative, so N and
    // V set, and the carry out is clear. x7 is built with movk because the value
    // does not fit in a 16-bit immediate.
    mov x7, #0xffff
    movk x7, #0xffff, lsl #16
    movk x7, #0x7fff, lsl #32
    mov x9, #0
    movk x9, #0x8000, lsl #48    // 2^63
    adds x7, x7, x9
    cmp x7, #0
    b.lt overflow_ok
    b fail
overflow_ok:

    mov x8, #93
    svc #0

fail:
    mov x0, #0xee
    mov x8, #93
    svc #0
