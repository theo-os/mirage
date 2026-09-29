// Real Linux ABI boundary checks; runs identically under qemu-aarch64.
typedef unsigned long u64;
// Volatile keeps ELF magic checks scalar; this translator has no FP/ASIMD.
static volatile char bss[4096];
static long call(u64 n, u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) {
    register u64 x0 __asm__("x0") = a;
    register u64 x1 __asm__("x1") = b;
    register u64 x2 __asm__("x2") = c;
    register u64 x3 __asm__("x3") = d;
    register u64 x4 __asm__("x4") = e;
    register u64 x5 __asm__("x5") = f;
    register u64 x8 __asm__("x8") = n;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
    return (long)x0;
}
#define SC(n,a,b,c,d,e,f) call(n,(u64)(a),(u64)(b),(u64)(c),(u64)(d),(u64)(e),(u64)(f))
static int equal(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
int guest(u64 *stack) {
    if (stack[0] != 2 || !equal((char *)stack[2], "argument")) return 10;
    u64 *env = stack + stack[0] + 2;
    int found = 0;
    while (*env) { if (equal((char *)*env, "MIRAGE_USER_TEST=present")) found = 1; ++env; }
    if (!found) return 11;
    u64 *aux = env + 1;
    int pages = 0;
    while (aux[0]) { if (aux[0] == 6 && aux[1] == 4096) pages = 1; aux += 2; }
    if (!pages || bss[0] || bss[4095]) return 12;
    if (SC(64,1,1,8,0,0,0) != -14) return 13;
    if (SC(64,99999,bss,1,0,0,0) != -9) return 14;
    if (SC(65535,0,0,0,0,0,0) != -38) return 15;
    long address = SC(222,0,8192,3,0x22,-1,0);
    if (address < 0) return 16;
    char *p = (char *)address;
    if (p[0] || p[8191]) return 17;
    p[4096] = 'x';
    if (SC(226,p,4096,1,0,0,0) != 0) return 18;
    if (SC(63,0,p,1,0,0,0) != -14) return 19;
    if (SC(215,p,4096,0,0,0,0) != 0) return 20;
    if (SC(64,1,p,1,0,0,0) != -14) return 21;
    if (p[4096] != 'x') return 22;
    if (SC(215,p+4096,4096,0,0,0,0) != 0) return 23;
    long fd = SC(56,-100,stack[1],0,0,0,0);
    if (fd < 0) return 25;
    if (SC(63,fd,bss,4,0,0,0) != 4 || bss[0] != 127 || bss[1] != 'E' || bss[2] != 'L' || bss[3] != 'F') return 26;
    if (SC(62,fd,1,0,0,0,0) != 1) return 27;
    if (SC(63,fd,bss,1,0,0,0) != 1 || bss[0] != 'E') return 28;
    if (SC(57,fd,0,0,0,0,0) || SC(63,fd,bss,1,0,0,0) != -9) return 29;
    long oldbrk = SC(214,0,0,0,0,0,0);
    if (SC(214,oldbrk+4096,0,0,0,0,0) != oldbrk+4096) return 34;
    if (SC(214,oldbrk+8192,0,0,0,0,0) != oldbrk+8192) return 30;
    char *heap = (char *)oldbrk;
    if (heap[0] || heap[8191]) return 32;
    heap[8191] = 42;
    struct __attribute__((packed)) word { u64 value; };
    volatile struct word *cross = (volatile struct word *)(heap + 4093);
    cross->value = 0x123456789abcdef0UL;
    if (cross->value != 0x123456789abcdef0UL) return 35;
    if (SC(214,oldbrk,0,0,0,0,0) != oldbrk) return 33;
    const char text[] = "linux-user ok\n";
    if (SC(64,1,text,sizeof(text)-1,0,0,0) != sizeof(text)-1) return 24;
    return 0;
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl guest\nmov x8, #94\nsvc #0\n");
