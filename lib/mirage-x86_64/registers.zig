//! The registers an x86-64 guest is set up with before the first instruction.
//!
//! The 64-bit Linux boot entry takes its boot-params pointer in `rsi`. The flags
//! register has a bit that is always one, so it is named here to be set rather than
//! left at whatever the reset state was.

pub const Register = enum { rip, rsi, rdi, rdx, rcx, rflags };
