// A compiled C program rather than hand-written assembly: real code with real
// stack frames, so it exercises the call sequence (STP/LDP with pre- and
// post-index, BL, RET) and the addressing modes a compiler emits. Every check
// that fails calls __builtin_trap, and the exit status is the low byte of x0,
// so that QEMU and the JIT must agree exactly.
typedef unsigned long ulong;

__attribute__((noinline)) static ulong sum(const ulong *v, ulong n) {
    ulong total = 0;
    for (ulong i = 0; i < n; i++) total += v[i];
    return total;
}

__attribute__((noinline)) static ulong fact(ulong n) { return n <= 1 ? 1 : n * fact(n - 1); }

struct pair {
    ulong a;
    ulong b;
};

__attribute__((noinline)) static ulong swap_sum(struct pair p) { return p.b - p.a; }

__attribute__((noinline)) static ulong walk(const ulong *v, ulong n) {
    // A register-offset load and a loop the compiler cannot fully unroll.
    ulong acc = 0;
    const ulong *p = v;
    while (n--) acc += *p++;
    return acc;
}

void _start(void) {
    static const ulong data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    if (sum(data, 8) != 36) __builtin_trap();
    if (sum(data, 0) != 0) __builtin_trap();
    if (sum(data, 1) != 1) __builtin_trap();
    if (fact(6) != 720) __builtin_trap();
    if (fact(0) != 1) __builtin_trap();
    struct pair s = {111, 222};
    if (swap_sum(s) != 111) __builtin_trap();
    if (walk(data, 8) != 36) __builtin_trap();

    __asm__ volatile("mov x8, #93\n\tmov x0, #0\n\tsvc #0");
}
