// Uses `dc zva` to clear memory the way a compiler does, and checks both that
// the whole line went and that the bytes either side of it did not.
//
// There is no QEMU counterpart. qemu-aarch64 in user mode treats `dc zva` as
// nothing at all, so it fails this guest by leaving the line dirty, which is
// not a disagreement about the architecture but a missing instruction on one
// side.
    .text
    .global _start
_start:
    adrp x0, page
    add x0, x0, :lo12:page
    // Fill the line and its neighbours with a pattern.
    mov x1, #0
str_loop:
    strb w1, [x0, x1]
    add x1, x1, #1
    cmp x1, #192
    b.lo str_loop
    // Zero one line, from the middle of it so the boundary matters.
    add x2, x0, #80
    dc zva, x2
    // The line from 64 to 128 must now be zero.
    mov x1, #64
check_loop:
    ldrb w3, [x0, x1]
    cbnz w3, fail
    add x1, x1, #1
    cmp x1, #128
    b.lo check_loop
    // And the bytes before and after it must not have moved.
    ldrb w3, [x0, #63]
    cbz w3, fail
    ldrb w3, [x0, #128]
    cbz w3, fail
    mov x0, #52
    mov x8, #93
    svc #0
fail:
    mov x0, #1
    mov x8, #93
    svc #0
    .data
    .balign 64
page:
    .space 192
