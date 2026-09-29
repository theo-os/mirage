// Reads and writes the system registers a kernel touches in its first
// instructions, and checks each one came back. The exit status is the low byte
// of x0, so that a failure is a nonzero status.
//
// This guest has no QEMU counterpart, unlike the other two. qemu-aarch64 in user
// mode runs at EL0 and traps on every system register access, so there is no
// oracle to compare against; the encodings are checked against the assembler in
// the unit tests instead, and this checks that the whole thing runs.
typedef unsigned long ulong;

static inline ulong rd(void) { ulong v; __asm__ volatile("mrs %0, CurrentEL" : "=r"(v)); return v; }
static inline void tpidr_set(ulong v) { __asm__ volatile("msr tpidr_el0, %0" :: "r"(v)); }
static inline ulong tpidr_get(void) { ulong v; __asm__ volatile("mrs %0, tpidr_el0" : "=r"(v)); return v; }
static inline void sp1_set(ulong v) { __asm__ volatile("msr sp_el1, %0" :: "r"(v)); }
static inline ulong sp1_get(void) { ulong v; __asm__ volatile("mrs %0, sp_el1" : "=r"(v)); return v; }
static inline void vbar_set(ulong v) { __asm__ volatile("msr vbar_el1, %0" :: "r"(v)); }
static inline ulong vbar_get(void) { ulong v; __asm__ volatile("mrs %0, vbar_el1" : "=r"(v)); return v; }
static inline void sctlr_set(ulong v) { __asm__ volatile("msr sctlr_el1, %0\n\tdsb sy\n\tisb" :: "r"(v) : "memory"); }
static inline ulong sctlr_get(void) { ulong v; __asm__ volatile("mrs %0, sctlr_el1" : "=r"(v)); return v; }
static inline ulong daif_get(void) { ulong v; __asm__ volatile("mrs %0, daif" : "=r"(v)); return v; }
static inline void daifclr(void) { __asm__ volatile("msr daifclr, #0xf"); }

void _start(void) {
    if (rd() == 0 || rd() == 0xffffffffffffffffUL) __builtin_trap();

    tpidr_set(0xdeadbeefUL);
    if (tpidr_get() != 0xdeadbeefUL) __builtin_trap();

    vbar_set(0xffff0000UL);
    if (vbar_get() != 0xffff0000UL) __builtin_trap();

    sctlr_set(0x30d00800UL);
    if (sctlr_get() != 0x30d00800UL) __builtin_trap();

    // SP_EL1 at EL1 must be the live stack pointer.
    ulong live;
    __asm__ volatile("mov %0, sp" : "=r"(live));
    sp1_set(live);
    if (sp1_get() != live) __builtin_trap();

    // Interrupts start masked; clearing them must be observable.
    if (((daif_get() >> 6) & 0xf) != 0xf) __builtin_trap();
    daifclr();
    if (((daif_get() >> 6) & 0xf) != 0) __builtin_trap();

    __asm__ volatile("mov x8, #93\n\tmov x0, #0\n\tsvc #0");
}
