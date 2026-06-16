//! secp256k1 ECDSA with public-key recovery — the signing side Ethereum needs
//! for the RLPx handshake (and, generally, recoverable signatures). The verify
//! side lives in `precompiles.zig` (ecrecover → address); this adds `sign` and
//! a full-pubkey `recoverPubkey`.

const std = @import("std");
const Io = std.Io;
const ecies = @import("ecies.zig");
const Secp = std.crypto.ecc.Secp256k1;
const Scalar = Secp.scalar.Scalar;
const Fe = Secp.Fe;

/// secp256k1 group order n.
const N: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
const HALF_N: u256 = N / 2;

/// A recoverable signature: r, s (big-endian), and recovery id v ∈ {0,1}.
pub const Signature = struct { r: [32]u8, s: [32]u8, v: u8 };

/// Sign `hash` with `priv`, producing a low-s recoverable signature. Uses a
/// random nonce drawn from `io` (sufficient for the handshake; a deterministic
/// RFC-6979 nonce is not required here).
pub fn sign(io: Io, hash: [32]u8, priv: [32]u8) Signature {
    const z = Scalar.fromBytes(hash, .big) catch Scalar.zero;
    const d = Scalar.fromBytes(priv, .big) catch Scalar.zero;
    while (true) {
        const k_bytes = ecies.randomPriv(io); // canonical, non-zero
        const k = Scalar.fromBytes(k_bytes, .big) catch continue;
        const point = Secp.basePoint.mul(k_bytes, .big) catch continue;
        const aff = point.affineCoordinates();
        // r = R.x mod n (retry on the ~2^-128 chance R.x ≥ n).
        const r = Scalar.fromBytes(aff.x.toBytes(.big), .big) catch continue;
        if (r.isZero()) continue;
        // s = k⁻¹ · (z + r·d)
        var s = k.invert().mul(z.add(r.mul(d)));
        if (s.isZero()) continue;
        var v: u8 = aff.y.toBytes(.big)[31] & 1;
        // Enforce low-s (EIP-2); flipping s flips the recovery parity.
        if (beU256(s.toBytes(.big)) > HALF_N) {
            s = s.neg();
            v ^= 1;
        }
        return .{ .r = r.toBytes(.big), .s = s.toBytes(.big), .v = v };
    }
}

/// Recover the 64-byte (x‖y) public key that produced `(r, s, v)` over `hash`.
pub fn recoverPubkey(hash: [32]u8, v: u8, r_be: [32]u8, s_be: [32]u8) ?[64]u8 {
    if (v > 1) return null;
    const r = Scalar.fromBytes(r_be, .big) catch return null;
    const s = Scalar.fromBytes(s_be, .big) catch return null;
    if (r.isZero() or s.isZero()) return null;

    const rx = Fe.fromBytes(r_be, .big) catch return null;
    const R = Secp.fromAffineCoordinates(.{ .x = rx, .y = recoverY(rx, v) orelse return null }) catch return null;

    // Q = r⁻¹ · (s·R − z·G)
    const z = Scalar.fromBytes(hash, .big) catch Scalar.zero;
    const r_inv = r.invert();
    const c1 = z.mul(r_inv).neg();
    const c2 = s.mul(r_inv);
    const q = Secp.mulDoubleBasePublic(Secp.basePoint, c1.toBytes(.little), R, c2.toBytes(.little), .little) catch return null;
    const a = q.affineCoordinates();
    var out: [64]u8 = undefined;
    @memcpy(out[0..32], &a.x.toBytes(.big));
    @memcpy(out[32..64], &a.y.toBytes(.big));
    return out;
}

fn recoverY(x: Fe, parity: u8) ?Fe {
    const x3 = x.mul(x).mul(x);
    const y2 = x3.add(Fe.fromInt(7) catch return null);
    const y = y2.sqrt() catch return null;
    return if ((y.toBytes(.big)[31] & 1) == parity) y else y.neg();
}

fn beU256(b: [32]u8) u256 {
    return std.mem.readInt(u256, &b, .big);
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "sign then recover yields the signer's pubkey" {
    var threaded: Io.Threaded = undefined;
    threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const priv = ecies.randomPriv(io);
    const pub_key = try ecies.pubFromPriv(priv);
    var hash: [32]u8 = undefined;
    io.random(&hash);

    const sig = sign(io, hash, priv);
    // low-s invariant
    try testing.expect(beU256(sig.s) <= HALF_N);
    const recovered = recoverPubkey(hash, sig.v, sig.r, sig.s) orelse return error.RecoverFailed;
    try testing.expectEqualSlices(u8, &pub_key, &recovered);
}

test "recover rejects a tampered signature" {
    var threaded: Io.Threaded = undefined;
    threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const priv = ecies.randomPriv(io);
    const pub_key = try ecies.pubFromPriv(priv);
    var hash: [32]u8 = undefined;
    io.random(&hash);
    var sig = sign(io, hash, priv);
    sig.r[0] ^= 0x01; // corrupt r
    const recovered = recoverPubkey(hash, sig.v, sig.r, sig.s);
    if (recovered) |rk| try testing.expect(!std.mem.eql(u8, &rk, &pub_key));
}
