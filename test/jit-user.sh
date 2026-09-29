#!/bin/sh
# Exercise actual ELF execution, initial stack, errno, and mapping transitions.
set -eu
cd "$(dirname "$0")/.."
for tool in zig qemu-aarch64; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
zig build jit-user
for layout in static pie; do
    if [ "$layout" = static ]; then flags="-static -no-pie"; else flags="-fPIE -pie -Wl,--no-dynamic-linker"; fi
    zig cc --target=aarch64-linux-gnu -nostdlib $flags -O1 -mgeneral-regs-only -fno-stack-protector \
        -Wl,--build-id=none -Wl,-e,_start test/guest/jit-user.c -o "$tmp/$layout.elf"
    MIRAGE_USER_TEST=present qemu-aarch64 "$tmp/$layout.elf" argument >"$tmp/qemu.out"
    MIRAGE_USER_TEST=present ./zig-out/bin/mirage-aarch64 "$tmp/$layout.elf" argument >"$tmp/mirage.out"
    printf 'linux-user ok\n' >"$tmp/expected.out"
    cmp "$tmp/expected.out" "$tmp/mirage.out"
    cmp "$tmp/qemu.out" "$tmp/mirage.out"
    echo "ok $layout: stack, BSS, errno, mmap/mprotect/munmap, stdout"
done

# A distinct ELF interpreter must see AT_BASE and hand control to AT_ENTRY.
zig cc --target=aarch64-linux-gnu -nostdlib -shared -Wl,-e,_start \
    test/guest/jit-user-interp.S -o "$tmp/interpreter.elf"
zig cc --target=aarch64-linux-gnu -nostdlib -no-pie -O1 -mgeneral-regs-only -fno-stack-protector \
    -Wl,--dynamic-linker="$tmp/interpreter.elf" -Wl,-e,_start \
    test/guest/jit-user.c -o "$tmp/dynamic.elf"
MIRAGE_USER_TEST=present qemu-aarch64 "$tmp/dynamic.elf" argument >"$tmp/qemu.out"
MIRAGE_USER_TEST=present ./zig-out/bin/mirage-aarch64 "$tmp/dynamic.elf" argument >"$tmp/mirage.out"
cmp "$tmp/expected.out" "$tmp/mirage.out"
cmp "$tmp/qemu.out" "$tmp/mirage.out"
echo "ok PT_INTERP: interpreter load and executable handoff"
