//! SEV key derivation: P-384 ECDH and SP800-108 KDF.
//!
//! Derives the master secret, KEK, and KIK from a guest-owner private scalar
//! and the platform PDH public point. The caller supplies all key material;
//! this module has no I/O and no randomness.

const std = @import("std");
const P384 = std.crypto.ecc.P384;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Error = error{IdentityElement};

/// Compute the shared secret X coordinate: big-endian X of (priv_scalar * peer).
///
/// priv_scalar is a 48-byte big-endian scalar. The result is the 48-byte big-endian
/// X coordinate, which is the KDF key for the master secret.
pub fn ecdhSharedX(priv_scalar: [48]u8, peer: P384) Error![48]u8 {
    const shared = peer.mul(priv_scalar, .big) catch return error.IdentityElement;
    return shared.affineCoordinates().x.toBytes(.big);
}

/// Compute the guest-owner DH public key: basePoint * priv_scalar.
pub fn publicPoint(priv_scalar: [48]u8) Error!P384 {
    return P384.basePoint.mul(priv_scalar, .big) catch return error.IdentityElement;
}

/// One-block SP800-108 counter-mode KDF, PRF = HMAC-SHA256.
///
/// Produces 16 bytes (the first 16 of the 32-byte HMAC output).
/// context may be empty; pass an empty slice for KEK and KIK.
pub fn kdf16(key: []const u8, label: []const u8, context: []const u8) [16]u8 {
    // HMAC message: i(u32 LE) || label || 0x00 || context || L(u32 LE)
    // i = 1, L = 128 (bits).
    var hmac = HmacSha256.init(key);

    var i_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &i_buf, 1, .little);
    hmac.update(&i_buf);
    hmac.update(label);
    hmac.update(&[_]u8{0x00});
    hmac.update(context);
    var l_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &l_buf, 128, .little);
    hmac.update(&l_buf);

    var out: [HmacSha256.mac_length]u8 = undefined;
    hmac.final(&out);

    return out[0..16].*;
}

/// Derive master secret, KEK, and KIK from a shared X coordinate and nonce.
pub fn deriveKeys(shared_x: [48]u8, nonce: [16]u8) struct { master: [16]u8, kek: [16]u8, kik: [16]u8 } {
    const master = kdf16(&shared_x, "sev-master-secret", &nonce);
    const kek = kdf16(&master, "sev-kek", &.{});
    const kik = kdf16(&master, "sev-kik", &.{});
    return .{ .master = master, .kek = kek, .kik = kik };
}

test "ecdh agrees both ways" {
    // Two small nonzero scalars. Both sides must agree on the same shared X.
    var scalar_a: [48]u8 = @splat(0);
    scalar_a[47] = 0x07;
    var scalar_b: [48]u8 = @splat(0);
    scalar_b[47] = 0x0b;

    const pub_a = try publicPoint(scalar_a);
    const pub_b = try publicPoint(scalar_b);

    const x_ab = try ecdhSharedX(scalar_a, pub_b);
    const x_ba = try ecdhSharedX(scalar_b, pub_a);

    try std.testing.expectEqualSlices(u8, &x_ab, &x_ba);
}

test "kdf is deterministic and shaped" {
    // No external test vector is available; the real end-to-end check is the gate in Task 6.
    const key = "some-key-material";
    const label_a = "sev-kek";
    const label_b = "sev-kik";
    const ctx: []const u8 = &.{};

    const out1 = kdf16(key, label_a, ctx);
    const out2 = kdf16(key, label_a, ctx);
    try std.testing.expectEqualSlices(u8, &out1, &out2);

    const out3 = kdf16(key, label_b, ctx);
    try std.testing.expect(!std.mem.eql(u8, &out1, &out3));

    var fixed_x: [48]u8 = @splat(0xab);
    const fixed_nonce: [16]u8 = @splat(0x5c);
    const m1 = kdf16(&fixed_x, "sev-master-secret", &fixed_nonce);
    const m2 = kdf16(&fixed_x, "sev-master-secret", &fixed_nonce);
    try std.testing.expectEqualSlices(u8, &m1, &m2);
}

test "derived keys are distinct" {
    var shared_x: [48]u8 = @splat(0);
    shared_x[0] = 0x01;
    shared_x[47] = 0x02;
    const nonce: [16]u8 = @splat(0x33);

    const keys = deriveKeys(shared_x, nonce);
    try std.testing.expect(!std.mem.eql(u8, &keys.master, &keys.kek));
    try std.testing.expect(!std.mem.eql(u8, &keys.master, &keys.kik));
    try std.testing.expect(!std.mem.eql(u8, &keys.kek, &keys.kik));
}
