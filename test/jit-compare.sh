#!/bin/sh
# Run each guest under QEMU TCG and under the translator, and require that they
# agree. The guests are hand-written assembly and compiled C, so between them
# they cover the instruction set the translator implements.
set -eu
cd "$(dirname "$0")/.."
for tool in zig qemu-aarch64; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
zig build jit-smoke

fail=0
check() {
    name=$1
    elf=$2
    qemu_result=0
    qemu-aarch64 "$elf" || qemu_result=$?
    jit_result=0
    ./zig-out/bin/mirage-jit-smoke "$elf" 2>/dev/null || jit_result=$?
    if [ "$qemu_result" != "$jit_result" ]; then
        echo "MISMATCH $name: QEMU TCG=$qemu_result JIT=$jit_result" >&2
        fail=1
    else
        echo "ok $name: QEMU TCG and mirage-jit both exited with $jit_result"
    fi
}

# Hand-written assembly, exercising the arithmetic, flag, and branch slice.
zig cc --target=aarch64-linux-gnu -nostdlib -static -Wl,--build-id=none -Wl,-e,_start \
    test/guest/jit-smoke.S -o "$tmp/smoke.elf"
check jit-smoke.S "$tmp/smoke.elf"

# Compiled C, so the call sequence and the compiler's addressing modes are what
# is under test. -fno-inline keeps the calls real, so there are stack frames.
zig cc --target=aarch64-linux-gnu -nostdlib -static -O1 -fno-inline \
    -Wl,--build-id=none -Wl,-e,_start test/guest/jit-calls.c -o "$tmp/calls.elf"
check jit-calls.c "$tmp/calls.elf"

# The system register guest has no QEMU counterpart: qemu-aarch64 in user mode
# runs at EL0 and traps on these, so it is run here alone. This is a weaker check
# than the two above and is not pretending to be otherwise.
zig cc --target=aarch64-linux-gnu -nostdlib -static -O1 \
    -Wl,--build-id=none -Wl,-e,_start test/guest/jit-sysreg.c -o "$tmp/sysreg.elf"
sysreg_result=0
./zig-out/bin/mirage-jit-smoke "$tmp/sysreg.elf" 2>/dev/null || sysreg_result=$?
if [ "$sysreg_result" != "0" ]; then
    echo "MISMATCH jit-sysreg.c: mirage-jit exited with $sysreg_result" >&2
    fail=1
else
    echo "ok jit-sysreg.c: mirage-jit exited with 0 (no QEMU oracle at EL0)"
fi

# The exception guest has no QEMU counterpart either, for the same reason: a
# user-mode process cannot take the exception. It is run alone, and it is a
# weaker check than the two QEMU agrees with.
tmp2=$(mktemp -d)
# Assembled and linked here rather than through zig cc, because the vector table
# has to land at an address the guest can name with a page-relative pair.
zig cc --target=aarch64-linux-gnu -c test/guest/jit-exception.S -o "$tmp2/exception.o"
zig ld.lld -Ttext=0x400000 -e _start --build-id=none "$tmp2/exception.o" -o "$tmp2/exception.elf"
exception_result=0
./zig-out/bin/mirage-jit-smoke "$tmp2/exception.elf" 2>/dev/null || exception_result=$?
rm -rf "$tmp2"
if [ "$exception_result" != "52" ]; then
    echo "MISMATCH jit-exception.S: mirage-jit exited with $exception_result, expected 52" >&2
    fail=1
else
    echo "ok jit-exception.S: data abort taken, handled and returned from (52)"
fi

# The `dc zva` guest also has no QEMU counterpart: user mode leaves the line
# dirty because it does not implement the instruction.
zig cc --target=aarch64-linux-gnu -nostdlib -static -Wl,--build-id=none -Wl,-e,_start \
    test/guest/jit-zva.S -o "$tmp/zva.elf"
zva_result=0
./zig-out/bin/mirage-jit-smoke "$tmp/zva.elf" 2>/dev/null || zva_result=$?
if [ "$zva_result" != "52" ]; then
    echo "MISMATCH jit-zva.S: mirage-jit exited with $zva_result" >&2
    fail=1
else
    echo "ok jit-zva.S: the whole line was zeroed and its neighbours were not (52)"
fi

exit $fail
