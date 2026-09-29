# mirage

VMM/hypervisor in pure Zig

## Experimental JIT

`mirage-jit.Cache(Guest)` is guest-ISA-independent: it fetches instruction
bytes through `Guest.fetch`, asks `Guest.terminates` where a block ends, and
caches `Guest.compile` results by PC and exact bytes. The guest provides `Cpu`,
`Block`, `Error`, `max_instruction_bytes`, `pc`, `fetch`, `terminates`, and
`compile`. Fetch returns the actual instruction length, so the cache also
supports variable-length encodings. Only `mirage-jit.aarch64` implements this
contract today; ARMv6 and RISC-V decoders, CPU states, and backends do not exist.

The AArch64 translator decodes a growing instruction subset and lowers it to
x86-64 native code through
[Vulcan](https://github.com/LilithSemi/vulcan). `aarch64.Machine` implements a
one-vCPU `Backend`: RAM accesses use `GuestMemory`, unmapped accesses exit for
MMIO service, and PSCI, WFI, and timer events return to Mirage's launch loop.
Translated blocks are cached by guest PC and fetched instruction bytes; lookup
uses a hash index, while bytes are still compared on a hit so guest code writes
cannot reuse stale translations.

The current AArch64 model includes integer arithmetic, branches, memory and
exclusive accesses, system registers, exceptions, address translation, and
timer/interrupt delivery. FP and ASIMD are not implemented and are advertised
as absent in `ID_AA64PFR0_EL1`, keeping Linux on scalar paths. The virtual
counter advances by one tick for each executed guest instruction; it is
deterministic, not wall-clock calibrated. Unsupported instructions fail closed:
there is no interpreter fallback.

On an x86-64 Linux host, build and run the experimental raw-kernel boot runner:

```sh
zig build jit-boot -Doptimize=ReleaseFast
zig-out/bin/mirage-jit-boot path/to/arch/arm64/boot/Image [seconds] [cmdline]
```

The runner provides 128 MiB RAM, a PL011 console, and a GICv2. Its default
command line enables the serial console and verbose kernel logging. It has no
root filesystem or block device, so a successful kernel boot currently reaches
the expected VFS panic when it cannot mount a root. The deadline bounds the run
and the report includes the guest state and recent block trace.

Run native JIT tests with `zig build test-jit` and launch-loop integration tests
with `zig build test-jit-launch`. On x86-64 Linux with `zig` and `qemu-aarch64`,
`sh test/jit-compare.sh` compares exit statuses for the assembly and C smoke
guests against QEMU TCG. It also runs the system-register, exception, and
`DC ZVA` guests without a QEMU oracle; those checks do not claim to compare
system-level behavior.

### Linux user-mode emulator

On x86-64 Linux, `mirage-aarch64` runs AArch64 Linux ELF programs without a
guest kernel, using the same Vulcan translator as the full-system backend:

```sh
zig build jit-user -Doptimize=ReleaseFast
zig-out/bin/mirage-aarch64 ./aarch64-program argument
sh test/jit-user.sh
```

`mirage-jit.user.run` provides the library entry point. The loader supports
ELF64 little-endian `ET_EXEC` and `ET_DYN`, zero-initialized BSS, and `PT_INTERP`.
Interpreter paths resolve directly on the host; there is no QEMU-style `-L`
sysroot prefix. The initial stack contains arguments, inherited environment,
and Linux auxiliary vectors. Guest exit status becomes the command's exit status.
Mappings enforce read/write/execute permissions, including instruction fetch
on cached translations.

Implemented Linux calls: `read`, `write`, `writev`, `openat`, `close`, `lseek`,
`brk`, anonymous `mmap`, `munmap`, `mprotect`, identity calls, `uname`,
`clock_gettime`, `getrandom`, `set_tid_address`, `exit`, and `exit_group`.
Descriptors and guest addresses are translated rather than passed through.
Unimplemented calls return `-ENOSYS`. Signals, threads, `clone`, `futex`,
file-backed/fixed mappings, and FP/ASIMD remain unsupported, so this is not
a general replacement for `qemu-aarch64` or a guarantee that a normal libc
dynamic linker will run. Unsupported instructions stop with a PC diagnostic.
Image allocations are limited to 1 GiB per image; the initial stack is 8 MiB.
This is not a sandbox: guest file I/O uses the host process's filesystem access
and credentials. Set-id guest executables do not change credentials.

The command accepts the ordinary `binfmt_misc` interpreter calling convention.
To register it manually, with an absolute installed interpreter path:

```sh
sudo sh -c 'echo ":mirage-aarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00:\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xff\xff\xff:/absolute/path/to/mirage-aarch64:" > /proc/sys/fs/binfmt_misc/register'
```

The mask matches little-endian AArch64 ELF executables and PIE images. This
requires `binfmt_misc` to be mounted and root access; the build does not alter
host registrations. No `P`, `O`, or `C` flags are used. Remove the registration
by writing `-1` to `/proc/sys/fs/binfmt_misc/mirage-aarch64`.
The comparison script checks static, PIE, and interpreter-handoff guests against
`qemu-aarch64`, including initial stack, BSS, errno, file I/O, heap growth,
mapping protection/unmapping, and stdout.