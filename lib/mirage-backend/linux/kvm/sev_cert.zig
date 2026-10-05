//! SEV certificate (sev_cert) parse and build.
//!
//! Parse extracts a P-384 public key from a platform PDH cert blob.
//! Build writes an unsigned guest-owner DH cert wrapping a P-384 point.
//! Layout matches sevapi.h from AMDESE/sev-tool.

const std = @import("std");
const P384 = std.crypto.ecc.P384;

// sev_cert field offsets and sizes (sevapi.h, __packed, 1568 bytes total).
const cert_version_off: usize = 0;
const cert_api_major_off: usize = 4;
const cert_api_minor_off: usize = 5;
const cert_pub_key_usage_off: usize = 8;
const cert_pub_key_algo_off: usize = 12;
const cert_pub_key_off: usize = 16;
const cert_sig1_usage_off: usize = 528;
const cert_sig1_algo_off: usize = 532;
const cert_sig2_usage_off: usize = 1048;
const cert_sig2_algo_off: usize = 1052;
const cert_total: usize = 1568;

// sev_ecdh_pub_key offsets within the 512-byte pub_key field.
const ecdh_curve_off: usize = 0;
const ecdh_qx_off: usize = 4;
const ecdh_qy_off: usize = 76;
const ecdh_coord_field: usize = 72; // bytes per coordinate field
const ecdh_coord_used: usize = 48; // P-384 uses the low 48 bytes of each field

comptime {
    // Offsets must be consistent: sig_1 starts at pub_key end (16 + 512 = 528).
    std.debug.assert(cert_pub_key_off + 512 == cert_sig1_usage_off);
    // sig_2 starts at sig_1 end (528 + 4 + 4 + 512 = 1048).
    std.debug.assert(cert_sig1_usage_off + 4 + 4 + 512 == cert_sig2_usage_off);
    // cert total: sig_2 end (1048 + 4 + 4 + 512 = 1568).
    std.debug.assert(cert_sig2_usage_off + 4 + 4 + 512 == cert_total);
    // qy follows qx: 4 + 72 = 76.
    std.debug.assert(ecdh_qx_off + ecdh_coord_field == ecdh_qy_off);
}

// SEV usage and algorithm enum values.
const usage_pdh: u32 = 0x1003;
const usage_invalid: u32 = 0x1000;
const algo_ecdh_sha384: u32 = 0x103;
const curve_p384: u32 = 2;

pub const Error = error{
    CertTooShort,
    NotPdhUsage,
    NotP384Curve,
    InvalidPoint,
};

/// Parse the P-384 public key from a PDH cert blob.
///
/// The blob is untrusted input: every field is bounds-checked and validated.
/// Returns the platform PDH public key as a P-384 point.
///
/// Coordinate endianness: the SEV cert convention is little-endian. The gate
/// settles this empirically if LAUNCH_START rejects the session.
pub fn parsePdh(blob: []const u8) Error!P384 {
    if (blob.len < cert_total) return error.CertTooShort;

    const usage = std.mem.readInt(u32, blob[cert_pub_key_usage_off..][0..4], .little);
    if (usage != usage_pdh) return error.NotPdhUsage;

    const pk = blob[cert_pub_key_off..][0..512];
    const curve = std.mem.readInt(u32, pk[ecdh_curve_off..][0..4], .little);
    if (curve != curve_p384) return error.NotP384Curve;

    // qx and qy: 72-byte LE fields; P-384 uses the low 48 bytes.
    const qx_le = pk[ecdh_qx_off..][0..ecdh_coord_used].*;
    const qy_le = pk[ecdh_qy_off..][0..ecdh_coord_used].*;

    // Reverse to big-endian for fromSec1 (which expects SEC1 big-endian coords).
    var x_be: [48]u8 = qx_le;
    std.mem.reverse(u8, &x_be);
    var y_be: [48]u8 = qy_le;
    std.mem.reverse(u8, &y_be);

    var sec1: [97]u8 = undefined;
    sec1[0] = 0x04;
    sec1[1..49].* = x_be;
    sec1[49..97].* = y_be;

    return P384.fromSec1(&sec1) catch return error.InvalidPoint;
}

/// Write an unsigned guest-owner DH cert into `into`.
///
/// The cert carries the guest-owner's ephemeral P-384 public key with usage PDH.
/// Signature fields are zeroed (usage INVALID). The caller signs it in a later step.
///
/// Coordinate endianness: the SEV cert convention is little-endian; coords are
/// written with the low 48 bytes of each 72-byte field set and the high 24 zero.
pub fn buildGuestOwner(point: P384, api_major: u8, api_minor: u8, into: *[cert_total]u8) void {
    @memset(into, 0);

    const ac = point.affineCoordinates();
    const x_le = ac.x.toBytes(.little);
    const y_le = ac.y.toBytes(.little);

    std.mem.writeInt(u32, into[cert_version_off..][0..4], 1, .little);
    into[cert_api_major_off] = api_major;
    into[cert_api_minor_off] = api_minor;
    std.mem.writeInt(u32, into[cert_pub_key_usage_off..][0..4], usage_pdh, .little);
    std.mem.writeInt(u32, into[cert_pub_key_algo_off..][0..4], algo_ecdh_sha384, .little);

    const pk = into[cert_pub_key_off..][0..512];
    std.mem.writeInt(u32, pk[ecdh_curve_off..][0..4], curve_p384, .little);
    pk[ecdh_qx_off..][0..ecdh_coord_used].* = x_le;
    pk[ecdh_qy_off..][0..ecdh_coord_used].* = y_le;

    std.mem.writeInt(u32, into[cert_sig1_usage_off..][0..4], usage_invalid, .little);
    std.mem.writeInt(u32, into[cert_sig2_usage_off..][0..4], usage_invalid, .little);
}

test "comptime layout constants are consistent with the 1568-byte cert" {
    comptime {
        std.debug.assert(cert_total == 1568);
        std.debug.assert(cert_pub_key_off == 16);
        std.debug.assert(cert_sig1_usage_off == 528);
        std.debug.assert(cert_sig2_usage_off == 1048);
    }
}

test "round trips a p384 point through the guest-owner cert" {
    const point = P384.basePoint;

    var buf: [cert_total]u8 = undefined;
    buildGuestOwner(point, 1, 0, &buf);

    const recovered = try parsePdh(&buf);
    const orig_ac = point.affineCoordinates();
    const recv_ac = recovered.affineCoordinates();
    try std.testing.expectEqualSlices(u8, &orig_ac.x.toBytes(.big), &recv_ac.x.toBytes(.big));
    try std.testing.expectEqualSlices(u8, &orig_ac.y.toBytes(.big), &recv_ac.y.toBytes(.big));
}

test "parsePdh rejects a truncated cert" {
    const blob: [100]u8 = @splat(0);
    const result = parsePdh(&blob);
    try std.testing.expectError(error.CertTooShort, result);
}

test "parsePdh rejects a non-PDH usage" {
    const point = P384.basePoint;
    var buf: [cert_total]u8 = undefined;
    buildGuestOwner(point, 1, 0, &buf);

    // Corrupt the usage field.
    std.mem.writeInt(u32, buf[cert_pub_key_usage_off..][0..4], 0x1002, .little);
    const result = parsePdh(&buf);
    try std.testing.expectError(error.NotPdhUsage, result);
}
