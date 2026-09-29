// Takes a data abort on purpose, handles it, and returns. The handler checks
// ESR_EL1 says what happened and steps the return address past the faulting
// load, so reaching the exit at all means the whole round trip worked: the
// fault, the vector, the handler, and the resume.
//
// There is no QEMU counterpart, unlike the other guests. qemu-aarch64 in user
// mode runs at EL0, where a load from an unmapped address kills the process
// rather than taking an exception, so there is no oracle to compare against.
// Takes a data abort on purpose, handles it, and returns. The handler is told
// what happened by ESR_EL1 and steps the return address past the faulting load.
// QEMU in user mode cannot run this at all, so the JIT is the only check.
    .text
    .global _start
_start:
    adrp x2, _vectors          // the vector table, built just after this code
    add x2, x2, :lo12:_vectors
    msr vbar_el1, x2
    mov x0, #0                 // what the handler will report
    ldr x1, [x19]              // x19 is unmapped: this faults
    mov x0, #1                 // reached only if the fault did not happen
    mov x8, #93
    svc #0

handler:
    // The class says it was a data abort and the status says translation.
    mrs x2, esr_el1
    lsr x2, x2, #26
    cmp x2, #0b100001
    b.ne fail
    // Step past the faulting load, so returning resumes after it.
    mrs x2, elr_el1
    add x2, x2, #4
    msr elr_el1, x2
    mov x0, #52                // the success status
    mov x8, #93
    svc #0

fail:
    mov x0, #1
    mov x8, #93
    svc #0

    .global _start
    mov x19, #0xdead0000       // deliberately not mapped, so the load faults

    .balign 2048
_vectors:
    .space 0x200
    b handler                 // EL1h sync vector (VBAR + 0x200)
