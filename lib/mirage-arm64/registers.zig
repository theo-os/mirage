//! The registers the arm64 Linux boot protocol names before the first instruction.
//!
//! The protocol wants the device tree address in `x0` and the other three argument
//! registers zeroed, so they are named here to be set rather than assumed.

pub const Register = enum { pc, x0, x1, x2, x3 };
