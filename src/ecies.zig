//! ECIES as used by the RLPx transport (devp2p) auth/ack handshake.
//!
//! Scheme "ECIES_AES128_SHA256": ephemeral ECDH on secp256k1, a NIST SP 800-56
//! concatenation KDF (SHA-256) to derive a 16-byte AES key and a 32-byte MAC
//! key, AES-128-CTR encryption, and an HMAC-SHA256 tag over `IV ‖ ciphertext ‖
//! shared_mac_data`. The encrypted blob is laid out as:
//!
//!   ephemeral_pubkey(65, uncompressed SEC1) ‖ IV(16) ‖ ciphertext ‖ tag(32)
//!
//! `shared_mac_data` is authenticated but not transmitted here; RLPx passes the
//! 2-byte auth-body length prefix so a man-in-the-middle can't truncate.

const std = @import("std");
const Io = std.Io;
const Secp = std.crypto.ecc.Secp256k1;
const Aes128 = std.crypto.core.aes.Aes128;
const ctr = std.crypto.core.modes.ctr;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const PUBKEY_LEN = 64; // x ‖ y, no SEC1 prefix (devp2p convention)
const OVERHEAD = 65 + 16 + 32; // ephemeral pubkey + IV + MAC tag

pub const Error = error{ InvalidPublicKey, InvalidCiphertext, AuthFailed, OutOfMemory };

/// secp256k1 public key (x‖y) for a private scalar: `priv · G`.
pub fn pubFromPriv(priv: [32]u8) Error![PUBKEY_LEN]u8 {
    const p = Secp.basePoint.mul(priv, .big) catch return error.InvalidPublicKey;
    return xy(p);
}

/// Generate a valid (canonical, non-zero) private scalar.
pub fn randomPriv(io: Io) [32]u8 {
    while (true) {
        var b: [32]u8 = undefined;
        io.random(&b);
        const s = Secp.scalar.Scalar.fromBytes(b, .big) catch continue;
        if (s.isZero()) continue;
        return s.toBytes(.big);
    }
}

/// The ECDH shared secret: the X coordinate of `priv · pub`.
pub fn ecdhX(priv: [32]u8, pub_key: [PUBKEY_LEN]u8) Error![32]u8 {
    const point = pointFromXY(pub_key) catch return error.InvalidPublicKey;
    const shared = point.mul(priv, .big) catch return error.InvalidPublicKey;
    return shared.affineCoordinates().x.toBytes(.big);
}

/// Encrypt `msg` to `remote_pub`, authenticating `shared_mac` alongside it.
/// Caller owns the returned blob.
pub fn encrypt(
    allocator: std.mem.Allocator,
    io: Io,
    remote_pub: [PUBKEY_LEN]u8,
    msg: []const u8,
    shared_mac: []const u8,
) Error![]u8 {
    const eph_priv = randomPriv(io);
    const eph_pub_point = Secp.basePoint.mul(eph_priv, .big) catch return error.InvalidPublicKey;
    const secret = try ecdhX(eph_priv, remote_pub);
    const keys = deriveKeys(secret);

    var iv: [16]u8 = undefined;
    io.random(&iv);

    const out = allocator.alloc(u8, OVERHEAD + msg.len) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    out[0..65].* = eph_pub_point.toUncompressedSec1();
    out[65..81].* = iv;
    const ct = out[81 .. 81 + msg.len];
    ctr(@TypeOf(Aes128.initEnc(keys.ke)), Aes128.initEnc(keys.ke), ct, msg, iv, .big);

    // tag = HMAC-SHA256(Km, IV ‖ ciphertext ‖ shared_mac)
    var mac = HmacSha256.init(&keys.km);
    mac.update(&iv);
    mac.update(ct);
    mac.update(shared_mac);
    mac.final(out[81 + msg.len ..][0..32]);
    return out;
}

/// Decrypt a blob produced by `encrypt`, verifying the HMAC over `shared_mac`.
/// Caller owns the returned plaintext.
pub fn decrypt(
    allocator: std.mem.Allocator,
    priv: [32]u8,
    blob: []const u8,
    shared_mac: []const u8,
) Error![]u8 {
    if (blob.len < OVERHEAD) return error.InvalidCiphertext;
    var eph_pub: [PUBKEY_LEN]u8 = undefined;
    @memcpy(&eph_pub, blob[1..65]); // strip the 0x04 SEC1 prefix
    const iv = blob[65..81];
    const ct = blob[81 .. blob.len - 32];
    const tag = blob[blob.len - 32 ..][0..32];

    const secret = try ecdhX(priv, eph_pub);
    const keys = deriveKeys(secret);

    var expect: [32]u8 = undefined;
    var mac = HmacSha256.init(&keys.km);
    mac.update(iv);
    mac.update(ct);
    mac.update(shared_mac);
    mac.final(&expect);
    if (!std.crypto.timing_safe.eql([32]u8, expect, tag.*)) return error.AuthFailed;

    const out = allocator.alloc(u8, ct.len) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    ctr(@TypeOf(Aes128.initEnc(keys.ke)), Aes128.initEnc(keys.ke), out, ct, iv[0..16].*, .big);
    return out;
}

const Keys = struct { ke: [16]u8, km: [32]u8 };

/// NIST SP 800-56 concatenation KDF (SHA-256, one block) → 32 bytes, split into
/// the AES key Ke = K[0..16] and the MAC key Km = SHA-256(K[16..32]).
fn deriveKeys(secret: [32]u8) Keys {
    var k: [32]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(&[_]u8{ 0, 0, 0, 1 }); // counter = 1, big-endian
    h.update(&secret);
    h.final(&k);
    var keys: Keys = undefined;
    @memcpy(&keys.ke, k[0..16]);
    Sha256.hash(k[16..32], &keys.km, .{});
    return keys;
}

fn xy(p: Secp) [PUBKEY_LEN]u8 {
    const u = p.toUncompressedSec1();
    var out: [PUBKEY_LEN]u8 = undefined;
    @memcpy(&out, u[1..65]);
    return out;
}

fn pointFromXY(pub_key: [PUBKEY_LEN]u8) !Secp {
    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    @memcpy(sec1[1..65], &pub_key);
    return Secp.fromSec1(&sec1);
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

fn testIo(threaded: *Io.Threaded) Io {
    threaded.* = Io.Threaded.init(testing.allocator, .{});
    return threaded.io();
}

test "ecies round-trip" {
    var threaded: Io.Threaded = undefined;
    const io = testIo(&threaded);
    defer threaded.deinit();

    const priv = randomPriv(io);
    const pub_key = try pubFromPriv(priv);
    const msg = "the quick brown fox jumps over the lazy dog";
    const smac = "shared-mac-data";

    const blob = try encrypt(testing.allocator, io, pub_key, msg, smac);
    defer testing.allocator.free(blob);
    const out = try decrypt(testing.allocator, priv, blob, smac);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(msg, out);
}

test "ecies rejects tampered ciphertext and wrong shared-mac" {
    var threaded: Io.Threaded = undefined;
    const io = testIo(&threaded);
    defer threaded.deinit();

    const priv = randomPriv(io);
    const pub_key = try pubFromPriv(priv);
    const blob = try encrypt(testing.allocator, io, pub_key, "secret", "mac");
    defer testing.allocator.free(blob);

    blob[90] ^= 0xff; // flip a ciphertext byte
    try testing.expectError(error.AuthFailed, decrypt(testing.allocator, priv, blob, "mac"));
    blob[90] ^= 0xff; // restore
    try testing.expectError(error.AuthFailed, decrypt(testing.allocator, priv, blob, "wrong-mac"));
}

test "ecdh is symmetric" {
    var threaded: Io.Threaded = undefined;
    const io = testIo(&threaded);
    defer threaded.deinit();

    const a_priv = randomPriv(io);
    const b_priv = randomPriv(io);
    const a_pub = try pubFromPriv(a_priv);
    const b_pub = try pubFromPriv(b_priv);
    const s1 = try ecdhX(a_priv, b_pub);
    const s2 = try ecdhX(b_priv, a_pub);
    try testing.expectEqualSlices(u8, &s1, &s2);
}
