//! SEV key derivation: P-384 ECDH, SP800-108 KDF, session blob, and measurement.
//!
//! Derives the master secret, KEK, and KIK from a guest-owner private scalar
//! and the platform PDH public point. Builds the 128-byte session blob and
//! verifies the launch measurement HMAC. The caller supplies all key material;
//! this module has no I/O and no randomness.

const std = @import("std");
const P384 = std.crypto.ecc.P384;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes128 = std.crypto.core.aes.Aes128;
const AesEncryptCtx = std.crypto.core.aes.AesEncryptCtx;
const ctr = std.crypto.core.modes.ctr;
const Sha256 = std.crypto.hash.sha2.Sha256;

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

// Session blob offsets (sev_session_buf, 128 bytes, __packed).
const off_nonce: usize = 0;
const off_wrap_tk: usize = 16;
const off_wrap_iv: usize = 48;
const off_wrap_mac: usize = 64;
const off_policy_mac: usize = 96;
const session_len: usize = 128;

comptime {
    std.debug.assert(off_nonce == 0);
    std.debug.assert(off_wrap_tk == 16);
    std.debug.assert(off_wrap_iv == 48);
    std.debug.assert(off_wrap_mac == 64);
    std.debug.assert(off_policy_mac == 96);
    std.debug.assert(off_policy_mac + 32 == session_len);
}

/// Build the 128-byte SEV session blob.
///
/// Produces: nonce | wrap_tk | wrap_iv | wrap_mac | policy_mac.
/// wrap_tk = AES-128-CTR(kek, iv) over tek||tik.
/// wrap_mac = HMAC-SHA256(kik, wrap_tk).
/// policy_mac = HMAC-SHA256(tik, policy as 4-byte LE).
pub fn buildSession(args: struct {
    kek: [16]u8,
    kik: [16]u8,
    tek: [16]u8,
    tik: [16]u8,
    nonce: [16]u8,
    iv: [16]u8,
    policy: u32,
}) [128]u8 {
    var blob: [session_len]u8 = undefined;

    // nonce at offset 0
    @memcpy(blob[off_nonce..][0..16], &args.nonce);

    // wrap tek||tik with AES-128-CTR(kek, iv)
    var plain: [32]u8 = undefined;
    @memcpy(plain[0..16], &args.tek);
    @memcpy(plain[16..32], &args.tik);
    const aes_ctx = Aes128.initEnc(args.kek);
    ctr(AesEncryptCtx(Aes128), aes_ctx, blob[off_wrap_tk..][0..32], plain[0..32], args.iv, .big);

    // wrap_iv at offset 48
    @memcpy(blob[off_wrap_iv..][0..16], &args.iv);

    // wrap_mac = HMAC-SHA256(kik, wrap_tk)
    var wrap_mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&wrap_mac, blob[off_wrap_tk..][0..32], &args.kik);
    @memcpy(blob[off_wrap_mac..][0..32], &wrap_mac);

    // policy_mac = HMAC-SHA256(tik, policy as 4-byte LE)
    var policy_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &policy_buf, args.policy, .little);
    var policy_mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&policy_mac, &policy_buf, &args.tik);
    @memcpy(blob[off_policy_mac..][0..32], &policy_mac);

    return blob;
}

/// Verify the launch measurement HMAC from sev_measure_buf.
///
/// Recomputes HMAC-SHA256(tik, 0x04 || api_major || api_minor || build_id ||
/// policy(4 LE) || digest(32) || m_nonce(16)) and compares with got using
/// a constant-time comparison.
pub fn verifyMeasurement(args: struct {
    tik: [16]u8,
    api_major: u8,
    api_minor: u8,
    build_id: u8,
    policy: u32,
    digest: [32]u8,
    m_nonce: [16]u8,
}, got: [32]u8) bool {
    var policy_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &policy_buf, args.policy, .little);

    var h = HmacSha256.init(&args.tik);
    h.update(&[_]u8{0x04});
    h.update(&[_]u8{args.api_major});
    h.update(&[_]u8{args.api_minor});
    h.update(&[_]u8{args.build_id});
    h.update(&policy_buf);
    h.update(&args.digest);
    h.update(&args.m_nonce);
    var expected: [HmacSha256.mac_length]u8 = undefined;
    h.final(&expected);

    return std.crypto.timing_safe.eql([32]u8, expected, got);
}

/// Compute SHA-256 over data (the launch digest for LAUNCH_UPDATE_DATA content).
pub fn launchDigest(data: []const u8) [32]u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
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

test "session layout is 128 bytes" {
    comptime {
        std.debug.assert(off_nonce == 0);
        std.debug.assert(off_wrap_tk == 16);
        std.debug.assert(off_wrap_iv == 48);
        std.debug.assert(off_wrap_mac == 64);
        std.debug.assert(off_policy_mac == 96);
        std.debug.assert(session_len == 128);
    }
}

test "session wrap round-trips" {
    const kek: [16]u8 = .{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const kik: [16]u8 = .{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };
    const tek: [16]u8 = .{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };
    const tik: [16]u8 = .{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
    const nonce: [16]u8 = .{ 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
    const iv: [16]u8 = .{ 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f };
    const policy: u32 = 0x00000001;

    const blob = buildSession(.{
        .kek = kek,
        .kik = kik,
        .tek = tek,
        .tik = tik,
        .nonce = nonce,
        .iv = iv,
        .policy = policy,
    });

    // nonce and iv pass through verbatim
    try std.testing.expectEqualSlices(u8, &nonce, blob[off_nonce..][0..16]);
    try std.testing.expectEqualSlices(u8, &iv, blob[off_wrap_iv..][0..16]);

    // decrypt wrap_tk with AES-128-CTR(kek, iv) and check we get tek||tik back
    const aes_ctx = Aes128.initEnc(kek);
    var recovered: [32]u8 = undefined;
    ctr(AesEncryptCtx(Aes128), aes_ctx, &recovered, blob[off_wrap_tk..][0..32], iv, .big);
    try std.testing.expectEqualSlices(u8, &tek, recovered[0..16]);
    try std.testing.expectEqualSlices(u8, &tik, recovered[16..32]);

    // recompute wrap_mac = HMAC-SHA256(kik, wrap_tk) and compare
    var expected_wrap_mac: [32]u8 = undefined;
    HmacSha256.create(&expected_wrap_mac, blob[off_wrap_tk..][0..32], &kik);
    try std.testing.expectEqualSlices(u8, &expected_wrap_mac, blob[off_wrap_mac..][0..32]);

    // recompute policy_mac = HMAC-SHA256(tik, policy LE) and compare
    var policy_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &policy_buf, policy, .little);
    var expected_policy_mac: [32]u8 = undefined;
    HmacSha256.create(&expected_policy_mac, &policy_buf, &tik);
    try std.testing.expectEqualSlices(u8, &expected_policy_mac, blob[off_policy_mac..][0..32]);
}

test "measurement verifies and rejects" {
    const tik: [16]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const api_major: u8 = 0;
    const api_minor: u8 = 24;
    const build_id: u8 = 5;
    const policy: u32 = 0;
    var digest: [32]u8 = @splat(0xaa);
    const m_nonce: [16]u8 = @splat(0xbb);

    var policy_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &policy_buf, policy, .little);
    var h = HmacSha256.init(&tik);
    h.update(&[_]u8{0x04});
    h.update(&[_]u8{api_major});
    h.update(&[_]u8{api_minor});
    h.update(&[_]u8{build_id});
    h.update(&policy_buf);
    h.update(&digest);
    h.update(&m_nonce);
    var expected: [32]u8 = undefined;
    h.final(&expected);

    try std.testing.expect(verifyMeasurement(.{
        .tik = tik,
        .api_major = api_major,
        .api_minor = api_minor,
        .build_id = build_id,
        .policy = policy,
        .digest = digest,
        .m_nonce = m_nonce,
    }, expected));

    // flip one byte of digest
    digest[0] ^= 0xff;
    try std.testing.expect(!verifyMeasurement(.{
        .tik = tik,
        .api_major = api_major,
        .api_minor = api_minor,
        .build_id = build_id,
        .policy = policy,
        .digest = digest,
        .m_nonce = m_nonce,
    }, expected));
}

test "launch digest matches sha-256" {
    const got = launchDigest("abc");
    const known = [32]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &known, &got);
}
