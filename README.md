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