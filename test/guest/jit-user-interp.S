// Minimal real PT_INTERP target: inspect auxv, then transfer to AT_ENTRY.
.text
.global _start
_start:
    ldr x0, [sp]
    add x1, sp, #16
    add x1, x1, x0, lsl #3
1:
    ldr x2, [x1], #8
    cbnz x2, 1b
    mov x3, #0
    mov x4, #0
2:
    ldp x5, x6, [x1], #16
    cbz x5, 3f
    cmp x5, #7
    csel x3, x6, x3, eq
    cmp x5, #9
    csel x4, x6, x4, eq
    b 2b
3:
    cbz x3, fail
    cbz x4, fail
    br x4
fail:
    mov x0, #31
    mov x8, #94
    svc #0
