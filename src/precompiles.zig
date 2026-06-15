//! Precompiled contracts at addresses 0x01–0x0a. Implemented: ecrecover (0x01),
//! sha256 (0x02), ripemd160 (0x03), identity (0x04), modexp (0x05), bn254
//! ecadd/ecmul/ecpairing (0x06–0x08), blake2f (0x09). Not yet: KZG point-eval
//! (0x0a) and the BLS12-381 set (0x0b–0x12), which report failure.

const std = @import("std");
const crypto = @import("crypto.zig");
const state_mod = @import("state.zig");
const bn254 = @import("bn254.zig");
const bls = @import("bls12_381.zig");
const Address = state_mod.Address;

pub const Output = struct { data: []u8, gas: u64 };

/// Return the precompile id if `addr` is an implemented precompile, else null.
/// 0x01–0x09 (classic), 0x0b (BLS12-381 G1ADD). 0x0a (KZG) and the rest of the
/// BLS set are not yet implemented, so they are not treated as precompiles.
pub fn idOf(addr: Address) ?u8 {
    for (addr[0..19]) |b| if (b != 0) return null;
    const id = addr[19];
    if (id >= 1 and id <= 0x09) return id;
    // BLS12-381: G1ADD, G1MSM, G2ADD, G2MSM.
    if (id == 0x0b or id == 0x0c or id == 0x0d or id == 0x0e) return id;
    return null;
}

fn words(len: usize) u64 {
    return @intCast((len + 31) / 32);
}

/// Run precompile `id` on `input` with `gas_available`. Returns the output and
/// gas consumed, or null on out-of-gas / failure (which the caller turns into a
/// reverted sub-call with empty output, per spec).
pub fn run(allocator: std.mem.Allocator, id: u8, input: []const u8, gas_available: u64) ?Output {
    return switch (id) {
        0x01 => ecrecover(allocator, input, gas_available),
        0x02 => sha256(allocator, input, gas_available),
        0x04 => identity(allocator, input, gas_available),
        0x03 => ripemd160(allocator, input, gas_available),
        0x05 => modexp(allocator, input, gas_available),
        0x06 => bnAdd(allocator, input, gas_available),
        0x07 => bnMul(allocator, input, gas_available),
        0x08 => bnPairing(allocator, input, gas_available),
        0x09 => blake2f(allocator, input, gas_available),
        0x0b => blsG1Add(allocator, input, gas_available),
        0x0c => blsG1Msm(allocator, input, gas_available),
        0x0d => blsG2Add(allocator, input, gas_available),
        0x0e => blsG2Msm(allocator, input, gas_available),
        else => null, // unimplemented precompile (kzg / map / pairing)
    };
}

fn identity(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    const cost = 15 + 3 * words(input.len);
    if (cost > gas) return null;
    return .{ .data = allocator.dupe(u8, input) catch @panic("oom"), .gas = cost };
}

fn sha256(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    const cost = 60 + 12 * words(input.len);
    if (cost > gas) return null;
    const out = allocator.alloc(u8, 32) catch @panic("oom");
    std.crypto.hash.sha2.Sha256.hash(input, out[0..32], .{});
    return .{ .data = out, .gas = cost };
}

/// ECDSA public-key recovery over secp256k1 (EIP-2). Input is
/// hash(32) ‖ v(32) ‖ r(32) ‖ s(32); output is the 32-byte left-padded address.
fn ecrecover(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    const cost: u64 = 3000;
    if (cost > gas) return null;
    // Always succeeds gas-wise; an invalid signature yields empty output.
    const empty = Output{ .data = allocator.alloc(u8, 0) catch @panic("oom"), .gas = cost };

    var buf: [128]u8 = std.mem.zeroes([128]u8);
    const n = @min(input.len, 128);
    @memcpy(buf[0..n], input[0..n]);

    const v = std.mem.readInt(u256, buf[32..64], .big);
    if (v != 27 and v != 28) return empty;
    const r = buf[64..96].*;
    const s = buf[96..128].*;

    const addr = recoverAddress(buf[0..32].*, @intCast(v - 27), r, s) orelse return empty;
    const out = allocator.alloc(u8, 32) catch @panic("oom");
    @memset(out[0..12], 0);
    @memcpy(out[12..32], &addr);
    return .{ .data = out, .gas = cost };
}

const Managed = std.math.big.int.Managed;

fn read32(b: []const u8) u256 {
    return std.mem.readInt(u256, b[0..32], .big);
}

fn bigFromBe(allocator: std.mem.Allocator, bytes: []const u8) Managed {
    var m = Managed.init(allocator) catch @panic("oom");
    m.set(0) catch @panic("oom");
    var b256 = Managed.initSet(allocator, 256) catch @panic("oom");
    defer b256.deinit();
    var tmp = Managed.init(allocator) catch @panic("oom");
    defer tmp.deinit();
    for (bytes) |byte| {
        tmp.mul(&m, &b256) catch @panic("oom"); // m = m*256 + byte
        m.set(byte) catch @panic("oom");
        m.add(&tmp, &m) catch @panic("oom");
    }
    return m;
}

/// r = (a * b) mod m   (a/b/m are Managed; r may alias a or b).
fn mulmod(allocator: std.mem.Allocator, r: *Managed, a: *const Managed, b: *const Managed, m: *const Managed) void {
    var prod = Managed.init(allocator) catch @panic("oom");
    defer prod.deinit();
    var q = Managed.init(allocator) catch @panic("oom");
    defer q.deinit();
    prod.mul(a, b) catch @panic("oom");
    q.divFloor(r, &prod, m) catch @panic("oom");
}

/// First min(32, exp_len) bytes of the exponent, as a big-endian integer (the
/// "exponent head" the EIP-2565 iteration count is based on). Zero-padded.
fn modexpExpHead(input: []const u8, base_len: u256, exp_len: u256) u256 {
    if (exp_len == 0) return 0;
    const off_u: u256 = 96 + base_len;
    if (off_u >= input.len) return 0; // exponent lies entirely past the input
    const off: usize = @intCast(off_u);
    const n: usize = @intCast(@min(exp_len, 32));
    var head: u256 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const b: u8 = if (off + i < input.len) input[off + i] else 0;
        head = (head << 8) | b;
    }
    return head;
}

/// EIP-2565 modexp. Input: base_len(32) ‖ exp_len(32) ‖ mod_len(32) ‖ base ‖ exp ‖ mod.
fn modexp(allocator: std.mem.Allocator, input: []const u8, gas_available: u64) ?Output {
    var hdr: [96]u8 = std.mem.zeroes([96]u8);
    @memcpy(hdr[0..@min(input.len, 96)], input[0..@min(input.len, 96)]);
    const base_len = read32(hdr[0..32]);
    const exp_len = read32(hdr[32..64]);
    const mod_len = read32(hdr[64..96]);

    // Gas (EIP-2565), computed without materializing huge operands. Work in u512
    // so adversarial multi-thousand-bit lengths cannot overflow the arithmetic.
    const max_len: u512 = @max(base_len, mod_len);
    const w: u512 = (max_len + 7) / 8;
    const mult_complexity: u512 = w * w;
    // If the multiplication term alone can't be afforded, reject before the
    // (potentially enormous) iteration-count multiply.
    if (mult_complexity > @as(u512, gas_available) * 3) return null;
    const iters: u512 = blk: {
        const head = modexpExpHead(input, base_len, exp_len);
        const head_bits: u512 = if (head == 0) 0 else 256 - @clz(head);
        const adj: u512 = if (head_bits == 0) 0 else head_bits - 1;
        break :blk if (exp_len <= 32) adj else 8 * (@as(u512, exp_len) - 32) + adj;
    };
    const dyn: u512 = mult_complexity * @max(iters, 1) / 3;
    const cost_u: u512 = @max(@as(u512, 200), dyn);
    if (cost_u > gas_available) return null;
    const cost: u64 = @intCast(cost_u);

    // A zero-length modulus yields an empty result regardless of base/exponent.
    if (mod_len == 0) return .{ .data = allocator.alloc(u8, 0) catch @panic("oom"), .gas = cost };

    // The lengths are now bounded by affordability, so materialization is safe.
    const bl: usize = @intCast(base_len);
    const el: usize = @intCast(exp_len);
    const ml: usize = @intCast(mod_len);
    const padded = allocator.alloc(u8, @max(96 + bl + el + ml, input.len)) catch @panic("oom");
    defer allocator.free(padded);
    @memset(padded, 0);
    @memcpy(padded[0..input.len], input);
    const base_b = padded[96 .. 96 + bl];
    const exp_b = padded[96 + bl .. 96 + bl + el];
    const mod_b = padded[96 + bl + el .. 96 + bl + el + ml];

    const out = allocator.alloc(u8, ml) catch @panic("oom");
    @memset(out, 0);

    var mod = bigFromBe(allocator, mod_b);
    defer mod.deinit();
    if (mod.eqlZero()) return .{ .data = out, .gas = cost }; // mod 0 -> zeros

    var result = Managed.initSet(allocator, 1) catch @panic("oom");
    defer result.deinit();
    var base = bigFromBe(allocator, base_b);
    defer base.deinit();
    {
        var q = Managed.init(allocator) catch @panic("oom");
        defer q.deinit();
        q.divFloor(&base, &base, &mod) catch @panic("oom"); // base %= mod
    }
    for (exp_b) |byte| {
        var bit: u8 = 0x80;
        while (bit != 0) : (bit >>= 1) {
            mulmod(allocator, &result, &result, &result, &mod);
            if (byte & bit != 0) mulmod(allocator, &result, &result, &base, &mod);
        }
    }
    writeBigBe(result, out);
    return .{ .data = out, .gas = cost };
}

// --- RIPEMD-160 (0x03) ---  std.crypto has no ripemd, so implement it here.

const RIPEMD_R = [80]u5{
    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,
};
const RIPEMD_RR = [80]u5{
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
};
const RIPEMD_S = [80]u5{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
};
const RIPEMD_SS = [80]u5{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
};
const RIPEMD_K = [5]u32{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
const RIPEMD_KK = [5]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

inline fn ripemdF(j: usize, x: u32, y: u32, z: u32) u32 {
    return switch (j / 16) {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        else => x ^ (y | ~z),
    };
}

fn ripemd160Hash(msg: []const u8, out: *[20]u8) void {
    var h = [5]u32{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    // Build padded message (append 0x80, pad to 56 mod 64, 64-bit LE length).
    const bitlen = @as(u64, msg.len) * 8;
    var pad_len: usize = msg.len + 1;
    while (pad_len % 64 != 56) pad_len += 1;
    var total = pad_len + 8;
    // Process block by block over a small scratch (one block at a time).
    var processed: usize = 0;
    while (processed < total) : (processed += 64) {
        var block: [64]u8 = undefined;
        for (0..64) |i| {
            const idx = processed + i;
            block[i] = if (idx < msg.len)
                msg[idx]
            else if (idx == msg.len)
                0x80
            else if (idx >= total - 8)
                @truncate(bitlen >> @intCast(8 * (idx - (total - 8))))
            else
                0;
        }
        var x: [16]u32 = undefined;
        for (0..16) |i| x[i] = std.mem.readInt(u32, block[4 * i ..][0..4], .little);

        var al = h[0];
        var bl = h[1];
        var cl = h[2];
        var dl = h[3];
        var el = h[4];
        var ar = h[0];
        var br = h[1];
        var cr = h[2];
        var dr = h[3];
        var er = h[4];
        for (0..80) |j| {
            var t = al +% ripemdF(j, bl, cl, dl) +% x[RIPEMD_R[j]] +% RIPEMD_K[j / 16];
            t = std.math.rotl(u32, t, RIPEMD_S[j]) +% el;
            al = el;
            el = dl;
            dl = std.math.rotl(u32, cl, @as(u5, 10));
            cl = bl;
            bl = t;
            var tr = ar +% ripemdF(79 - j, br, cr, dr) +% x[RIPEMD_RR[j]] +% RIPEMD_KK[j / 16];
            tr = std.math.rotl(u32, tr, RIPEMD_SS[j]) +% er;
            ar = er;
            er = dr;
            dr = std.math.rotl(u32, cr, @as(u5, 10));
            cr = br;
            br = tr;
        }
        const t = h[1] +% cl +% dr;
        h[1] = h[2] +% dl +% er;
        h[2] = h[3] +% el +% ar;
        h[3] = h[4] +% al +% br;
        h[4] = h[0] +% bl +% cr;
        h[0] = t;
    }
    for (0..5) |i| std.mem.writeInt(u32, out[4 * i ..][0..4], h[i], .little);
    _ = &total;
}

fn ripemd160(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    const cost = 600 + 120 * words(input.len);
    if (cost > gas) return null;
    var digest: [20]u8 = undefined;
    ripemd160Hash(input, &digest);
    const out = allocator.alloc(u8, 32) catch @panic("oom");
    @memset(out, 0);
    @memcpy(out[12..32], &digest); // left-pad to 32 bytes
    return .{ .data = out, .gas = cost };
}

// --- bn254 (alt_bn128) precompiles ---

/// Read a 32-byte big-endian word at `off` from `input`, zero-padding past end.
fn word32(input: []const u8, off: usize) u256 {
    var buf: [32]u8 = std.mem.zeroes([32]u8);
    if (off < input.len) {
        const n = @min(32, input.len - off);
        @memcpy(buf[0..n], input[off .. off + n]);
    }
    return std.mem.readInt(u256, &buf, .big);
}

/// Decode a 64-byte (x, y) window into a G1 point, validating the field and the
/// curve. Returns null on InvalidParameter (which the caller turns into OOG).
fn decodeG1(input: []const u8, off: usize) ?bn254.G1 {
    const x = word32(input, off);
    const y = word32(input, off + 32);
    if (x >= bn254.P or y >= bn254.P) return null;
    const z: bn254.Fp = if (x == 0 and y == 0) bn254.Fp.zero() else bn254.Fp.one();
    const p = bn254.G1{ .x = bn254.Fp.init(x), .y = bn254.Fp.init(y), .z = z };
    if (!p.isOnCurve(bn254.Fp.scalar(3))) return null;
    return p;
}

fn encodeG1(allocator: std.mem.Allocator, p: bn254.G1) []u8 {
    const aff = bn254.normalizeG1(p);
    const out = allocator.alloc(u8, 64) catch @panic("oom");
    std.mem.writeInt(u256, out[0..32], aff.x.v, .big);
    std.mem.writeInt(u256, out[32..64], aff.y.v, .big);
    return out;
}

fn bnAdd(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    const cost: u64 = 150;
    if (cost > gas) return null;
    const p0 = decodeG1(input, 0) orelse return null;
    const p1 = decodeG1(input, 64) orelse return null;
    return .{ .data = encodeG1(allocator, p0.add(p1)), .gas = cost };
}

fn bnMul(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    const cost: u64 = 6000;
    if (cost > gas) return null;
    const p0 = decodeG1(input, 0) orelse return null;
    const n = word32(input, 64);
    return .{ .data = encodeG1(allocator, p0.mul(n)), .gas = cost };
}

/// Decode a 128-byte G2 window (py_ecc byte order: x0,x1,y0,y1 with the FQ2
/// coefficients swapped) into a G2 point, validating field and curve.
fn decodeG2(input: []const u8, off: usize) ?bn254.G2 {
    const x0 = word32(input, off);
    const x1 = word32(input, off + 32);
    const y0 = word32(input, off + 64);
    const y1 = word32(input, off + 96);
    if (x0 >= bn254.P or x1 >= bn254.P or y0 >= bn254.P or y1 >= bn254.P) return null;
    const x = bn254.Fp2{ .c0 = bn254.Fp.init(x1), .c1 = bn254.Fp.init(x0) };
    const y = bn254.Fp2{ .c0 = bn254.Fp.init(y1), .c1 = bn254.Fp.init(y0) };
    const z: bn254.Fp2 = if (x.isZero() and y.isZero()) bn254.Fp2.zero() else bn254.Fp2.one();
    const q = bn254.G2{ .x = x, .y = y, .z = z };
    if (!q.isOnCurve(bn254.b2())) return null;
    return q;
}

fn bnPairing(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    if (input.len % 192 != 0) return null;
    const n_points: u64 = @intCast(input.len / 192);
    const cost: u64 = 45000 + 34000 * n_points;
    if (cost > gas) return null;

    const pts = allocator.alloc(bn254.PairPoint, @intCast(n_points)) catch @panic("oom");
    defer allocator.free(pts);
    var i: usize = 0;
    while (i < n_points) : (i += 1) {
        const p = decodeG1(input, 192 * i) orelse return null;
        const q = decodeG2(input, 192 * i + 64) orelse return null;
        // Subgroup membership: [R]·point must be the identity.
        if (!p.mul(bn254.R).isInf()) return null;
        if (!q.mul(bn254.R).isInf()) return null;
        pts[i] = .{ .q = q, .p = p };
    }
    const out = allocator.alloc(u8, 32) catch @panic("oom");
    @memset(out, 0);
    out[31] = if (bn254.pairingProductIsOne(pts)) 1 else 0;
    return .{ .data = out, .gas = cost };
}

// --- BLS12-381 (EIP-2537) precompiles ---

/// Decode a 64-byte big-endian field element, validating it is < P (which also
/// rejects non-zero high padding, since P < 2^384 < 2^512).
fn blsFp(input: []const u8, off: usize) ?bls.Fp {
    var buf: [64]u8 = std.mem.zeroes([64]u8);
    @memcpy(&buf, input[off .. off + 64]);
    const v = std.mem.readInt(u512, &buf, .big);
    if (v >= bls.P) return null;
    return bls.Fp{ .v = @intCast(v) };
}

/// Decode a 128-byte G1 point (x ‖ y, 64 bytes each), validating the field and
/// the curve. (0, 0) is the point at infinity.
fn decodeBlsG1(input: []const u8, off: usize) ?bls.G1 {
    const x = blsFp(input, off) orelse return null;
    const y = blsFp(input, off + 64) orelse return null;
    const z: bls.Fp = if (x.isZero() and y.isZero()) bls.Fp.zero() else bls.Fp.one();
    const p = bls.G1{ .x = x, .y = y, .z = z };
    if (!p.isOnCurve(bls.Fp.scalar(4))) return null;
    return p;
}

fn encodeBlsG1(allocator: std.mem.Allocator, p: bls.G1) []u8 {
    const aff = bls.normalizeG1(p);
    const out = allocator.alloc(u8, 128) catch @panic("oom");
    @memset(out, 0);
    std.mem.writeInt(u512, out[0..64], @as(u512, aff.x.v), .big);
    std.mem.writeInt(u512, out[64..128], @as(u512, aff.y.v), .big);
    return out;
}

fn blsG1Add(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    if (input.len != 256) return null; // EIP-2537: fixed 256-byte input
    const cost: u64 = 375;
    if (cost > gas) return null;
    const p1 = decodeBlsG1(input, 0) orelse return null;
    const p2 = decodeBlsG1(input, 128) orelse return null;
    return .{ .data = encodeBlsG1(allocator, p1.add(p2)), .gas = cost };
}

/// Decode a 128-byte Fp2 element (c0 ‖ c1, 64 bytes each).
fn blsFp2(input: []const u8, off: usize) ?bls.Fp2 {
    const c0 = blsFp(input, off) orelse return null;
    const c1 = blsFp(input, off + 64) orelse return null;
    return bls.Fp2{ .c0 = c0, .c1 = c1 };
}

/// Decode a 256-byte G2 point (x ‖ y, 128-byte Fp2 each). (0, 0) is infinity.
fn decodeBlsG2(input: []const u8, off: usize) ?bls.G2 {
    const x = blsFp2(input, off) orelse return null;
    const y = blsFp2(input, off + 128) orelse return null;
    const z: bls.Fp2 = if (x.isZero() and y.isZero()) bls.Fp2.zero() else bls.Fp2.one();
    const p = bls.G2{ .x = x, .y = y, .z = z };
    if (!p.isOnCurve(bls.b2())) return null;
    return p;
}

fn encodeBlsG2(allocator: std.mem.Allocator, p: bls.G2) []u8 {
    const aff = bls.normalizeG2(p);
    const out = allocator.alloc(u8, 256) catch @panic("oom");
    @memset(out, 0);
    std.mem.writeInt(u512, out[0..64], @as(u512, aff.x.c0.v), .big);
    std.mem.writeInt(u512, out[64..128], @as(u512, aff.x.c1.v), .big);
    std.mem.writeInt(u512, out[128..192], @as(u512, aff.y.c0.v), .big);
    std.mem.writeInt(u512, out[192..256], @as(u512, aff.y.c1.v), .big);
    return out;
}

fn blsG2Add(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    if (input.len != 512) return null; // EIP-2537: fixed 512-byte input
    const cost: u64 = 600;
    if (cost > gas) return null;
    const p1 = decodeBlsG2(input, 0) orelse return null;
    const p2 = decodeBlsG2(input, 256) orelse return null;
    return .{ .data = encodeBlsG2(allocator, p1.add(p2)), .gas = cost };
}

// EIP-2537 multi-scalar-multiplication per-k gas discounts (×1/1000).
const BLS_G1_DISCOUNT = [128]u16{ 1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677, 673, 669, 665, 661, 658, 654, 651, 648, 645, 642, 640, 637, 635, 632, 630, 627, 625, 623, 621, 619, 617, 615, 613, 611, 609, 608, 606, 604, 603, 601, 599, 598, 596, 595, 593, 592, 591, 589, 588, 586, 585, 584, 582, 581, 580, 579, 577, 576, 575, 574, 573, 572, 570, 569, 568, 567, 566, 565, 564, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 551, 550, 549, 548, 547, 547, 546, 545, 544, 543, 542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534, 533, 532, 532, 531, 530, 529, 528, 528, 527, 526, 525, 525, 524, 523, 522, 522, 521, 520, 520, 519 };
const BLS_G2_DISCOUNT = [128]u16{ 1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717, 711, 704, 699, 693, 688, 683, 679, 674, 670, 666, 663, 659, 655, 652, 649, 646, 643, 640, 637, 634, 632, 629, 627, 624, 622, 620, 618, 615, 613, 611, 609, 607, 606, 604, 602, 600, 598, 597, 595, 593, 592, 590, 589, 587, 586, 584, 583, 582, 580, 579, 578, 576, 575, 574, 573, 571, 570, 569, 568, 567, 566, 565, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 552, 551, 550, 549, 548, 547, 546, 545, 545, 544, 543, 542, 541, 541, 540, 539, 538, 537, 537, 536, 535, 535, 534, 533, 532, 532, 531, 530, 530, 529, 528, 528, 527, 526, 526, 525, 524, 524 };

/// Subgroup membership: a decoded curve point must also lie in the prime-order
/// subgroup, i.e. [R]·P is the identity. Required by the MSM precompiles.
fn msmGas(k: usize, mul_gas: u64, discounts: *const [128]u16, max_discount: u64) ?u64 {
    const discount: u64 = if (k == 0) return null else if (k <= 128) discounts[k - 1] else max_discount;
    const total: u128 = @as(u128, k) * mul_gas * discount / 1000;
    return if (total > std.math.maxInt(u64)) null else @intCast(total);
}

fn blsG1Msm(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    if (input.len == 0 or input.len % 160 != 0) return null;
    const k = input.len / 160;
    const cost = msmGas(k, 12000, &BLS_G1_DISCOUNT, 519) orelse return null;
    if (cost > gas) return null;
    var acc = bls.G1.infinity();
    var i: usize = 0;
    while (i < k) : (i += 1) {
        const p = decodeBlsG1(input, i * 160) orelse return null;
        if (!p.mul(bls.R).isInf()) return null; // subgroup check
        const m = std.mem.readInt(u256, input[i * 160 + 128 ..][0..32], .big);
        acc = acc.add(p.mul(m));
    }
    return .{ .data = encodeBlsG1(allocator, acc), .gas = cost };
}

fn blsG2Msm(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    if (input.len == 0 or input.len % 288 != 0) return null;
    const k = input.len / 288;
    const cost = msmGas(k, 22500, &BLS_G2_DISCOUNT, 524) orelse return null;
    if (cost > gas) return null;
    var acc = bls.G2.infinity();
    var i: usize = 0;
    while (i < k) : (i += 1) {
        const p = decodeBlsG2(input, i * 288) orelse return null;
        if (!p.mul(bls.R).isInf()) return null; // subgroup check
        const m = std.mem.readInt(u256, input[i * 288 + 256 ..][0..32], .big);
        acc = acc.add(p.mul(m));
    }
    return .{ .data = encodeBlsG2(allocator, acc), .gas = cost };
}

/// Write `m` as big-endian into `out` (left-zero-padded; high bytes dropped).
fn writeBigBe(m: Managed, out: []u8) void {
    const c = m.toConst();
    @memset(out, 0);
    const limbs = c.limbs[0..c.limbs.len];
    const limb_bytes = @sizeOf(std.math.big.Limb);
    var bi: usize = 0; // byte index from the LSB end
    for (limbs) |limb| {
        var l = limb;
        var k: usize = 0;
        while (k < limb_bytes) : (k += 1) {
            if (bi < out.len) out[out.len - 1 - bi] = @truncate(l);
            l >>= 8;
            bi += 1;
        }
    }
}

// --- blake2f (EIP-152): the BLAKE2b compression function F ---

const BLAKE2B_IV = [8]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};
const SIGMA = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

fn g(v: *[16]u64, a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 32);
    v[c] = v[c] +% v[d];
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 24);
    v[a] = v[a] +% v[b] +% y;
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 63);
}

fn blake2f(allocator: std.mem.Allocator, input: []const u8, gas: u64) ?Output {
    if (input.len != 213) return null;
    const final = input[212];
    if (final != 0 and final != 1) return null;
    const rounds = std.mem.readInt(u32, input[0..4], .big);
    if (rounds > gas) return null;

    var h: [8]u64 = undefined;
    for (0..8) |i| h[i] = std.mem.readInt(u64, input[4 + i * 8 ..][0..8], .little);
    var m: [16]u64 = undefined;
    for (0..16) |i| m[i] = std.mem.readInt(u64, input[68 + i * 8 ..][0..8], .little);
    const t0 = std.mem.readInt(u64, input[196..204], .little);
    const t1 = std.mem.readInt(u64, input[204..212], .little);

    var v: [16]u64 = undefined;
    @memcpy(v[0..8], &h);
    @memcpy(v[8..16], &BLAKE2B_IV);
    v[12] ^= t0;
    v[13] ^= t1;
    if (final == 1) v[14] ^= 0xFFFFFFFFFFFFFFFF;

    var r: u32 = 0;
    while (r < rounds) : (r += 1) {
        const s = SIGMA[r % 10];
        g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (0..8) |i| h[i] ^= v[i] ^ v[i + 8];

    const out = allocator.alloc(u8, 64) catch @panic("oom");
    for (0..8) |i| std.mem.writeInt(u64, out[i * 8 ..][0..8], h[i], .little);
    return .{ .data = out, .gas = rounds };
}

const Secp = std.crypto.ecc.Secp256k1;

pub fn recoverAddress(msg: [32]u8, recid: u8, r_be: [32]u8, s_be: [32]u8) ?[20]u8 {
    const Scalar = Secp.scalar.Scalar;
    // r, s must be in [1, n).
    const r = Scalar.fromBytes(r_be, .big) catch return null;
    const s = Scalar.fromBytes(s_be, .big) catch return null;
    if (r.isZero() or s.isZero()) return null;

    // R = point with x = r and y parity = recid.
    const Fe = Secp.Fe;
    const rx = Fe.fromBytes(r_be, .big) catch return null;
    const R = Secp.fromAffineCoordinates(.{ .x = rx, .y = recoverY(rx, recid) orelse return null }) catch return null;

    // Q = r^-1 * (s*R - z*G)
    const z = Scalar.fromBytes(msg, .big) catch Scalar.zero;
    const r_inv = r.invert();
    const c1 = z.mul(r_inv).neg();
    const c2 = s.mul(r_inv);
    const point = Secp.mulDoubleBasePublic(Secp.basePoint, c1.toBytes(.little), R, c2.toBytes(.little), .little) catch return null;

    const a = point.affineCoordinates();
    var pub_bytes: [64]u8 = undefined;
    @memcpy(pub_bytes[0..32], &a.x.toBytes(.big));
    @memcpy(pub_bytes[32..64], &a.y.toBytes(.big));
    const h = crypto.keccak256(&pub_bytes);
    var out: [20]u8 = undefined;
    @memcpy(&out, h[12..32]);
    return out;
}

fn recoverY(x: Secp.Fe, parity: u8) ?Secp.Fe {
    // y^2 = x^3 + 7
    const x3 = x.mul(x).mul(x);
    const y2 = x3.add(Secp.Fe.fromInt(7) catch return null);
    const y = y2.sqrt() catch return null;
    const y_bytes = y.toBytes(.big);
    const y_parity: u8 = y_bytes[31] & 1;
    return if (y_parity == parity) y else y.neg();
}

const testing = std.testing;

test "idOf detects precompile range" {
    var a = state_mod.zero_address;
    try testing.expectEqual(@as(?u8, null), idOf(a));
    a[19] = 4;
    try testing.expectEqual(@as(?u8, 4), idOf(a));
    a[19] = 0x0b;
    try testing.expectEqual(@as(?u8, null), idOf(a));
}

test "identity returns input" {
    const out = run(testing.allocator, 4, "hello", 1000).?;
    defer testing.allocator.free(out.data);
    try testing.expectEqualStrings("hello", out.data);
    try testing.expectEqual(@as(u64, 18), out.gas);
}

test "blake2f EIP-152 vector (12 rounds)" {
    var input: [213]u8 = std.mem.zeroes([213]u8);
    std.mem.writeInt(u32, input[0..4], 12, .big); // rounds
    _ = try std.fmt.hexToBytes(input[4..68], "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b");
    input[68] = 0x61; // "abc" message
    input[69] = 0x62;
    input[70] = 0x63;
    input[196] = 3; // t0 = 3
    input[212] = 1; // final block
    const out = run(testing.allocator, 9, &input, 100).?;
    defer testing.allocator.free(out.data);
    var got: [128]u8 = undefined;
    _ = std.fmt.bufPrint(&got, "{x}", .{out.data}) catch unreachable;
    try testing.expectEqualStrings("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923", &got);
}

test "modexp 3^2 mod 5 = 4" {
    var input: [99]u8 = std.mem.zeroes([99]u8);
    input[31] = 1; // base_len
    input[63] = 1; // exp_len
    input[95] = 1; // mod_len
    input[96] = 3; // base
    input[97] = 2; // exp
    input[98] = 5; // mod
    const out = run(testing.allocator, 5, &input, 100000).?;
    defer testing.allocator.free(out.data);
    try testing.expectEqual(@as(usize, 1), out.data.len);
    try testing.expectEqual(@as(u8, 4), out.data[0]);
}

test "sha256 of empty" {
    const out = run(testing.allocator, 2, "", 1000).?;
    defer testing.allocator.free(out.data);
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{out.data}) catch unreachable;
    try testing.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &hex);
}

test "ripemd160 known vectors" {
    var d: [20]u8 = undefined;
    ripemd160Hash("", &d);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31 }, &d);
    ripemd160Hash("abc", &d);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc }, &d);
}
