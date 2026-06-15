//! Precompiled contracts at addresses 0x01–0x0a. Implemented: ecrecover (0x01),
//! sha256 (0x02), identity (0x04). Not yet: ripemd160 (no std impl), modexp,
//! bn254 (ecadd/ecmul/ecpairing), blake2f, KZG point-eval — these need bigint
//! modexp and pairing crypto (the long pole), so calls to them report failure.

const std = @import("std");
const crypto = @import("crypto.zig");
const state_mod = @import("state.zig");
const bn254 = @import("bn254.zig");
const Address = state_mod.Address;

pub const Output = struct { data: []u8, gas: u64 };

/// Return the precompile id (1..0x0a) if `addr` is a precompile, else null.
pub fn idOf(addr: Address) ?u8 {
    for (addr[0..19]) |b| if (b != 0) return null;
    const id = addr[19];
    return if (id >= 1 and id <= 0x0a) id else null;
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
        0x05 => modexp(allocator, input, gas_available),
        0x06 => bnAdd(allocator, input, gas_available),
        0x07 => bnMul(allocator, input, gas_available),
        0x08 => bnPairing(allocator, input, gas_available),
        0x09 => blake2f(allocator, input, gas_available),
        else => null, // unimplemented precompile (kzg/bls)
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

/// EIP-2565 modexp. Input: base_len(32) ‖ exp_len(32) ‖ mod_len(32) ‖ base ‖ exp ‖ mod.
fn modexp(allocator: std.mem.Allocator, input: []const u8, gas_available: u64) ?Output {
    var hdr: [96]u8 = std.mem.zeroes([96]u8);
    @memcpy(hdr[0..@min(input.len, 96)], input[0..@min(input.len, 96)]);
    const base_len = read32(hdr[0..32]);
    const exp_len = read32(hdr[32..64]);
    const mod_len = read32(hdr[64..96]);
    if (base_len > 4096 or exp_len > 4096 or mod_len > 4096) return null; // DoS guard
    const bl: usize = @intCast(base_len);
    const el: usize = @intCast(exp_len);
    const ml: usize = @intCast(mod_len);

    // Zero-padded reads of the three operands.
    const padded = allocator.alloc(u8, @max(96 + bl + el + ml, input.len)) catch @panic("oom");
    defer allocator.free(padded);
    @memset(padded, 0);
    @memcpy(padded[0..input.len], input);
    const base_b = padded[96 .. 96 + bl];
    const exp_b = padded[96 + bl .. 96 + bl + el];
    const mod_b = padded[96 + bl + el .. 96 + bl + el + ml];

    // Gas (EIP-2565).
    const max_len = @max(bl, ml);
    const w: u64 = @intCast((max_len + 7) / 8);
    const mult_complexity: u128 = @as(u128, w) * w;
    const iters = iterCount(exp_b);
    const dyn: u128 = mult_complexity * @max(iters, 1) / 3;
    const cost: u64 = @intCast(@max(@as(u128, 200), dyn));
    if (cost > gas_available) return null;

    const out = allocator.alloc(u8, ml) catch @panic("oom");
    @memset(out, 0);
    if (ml == 0) return .{ .data = out, .gas = cost };

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

fn iterCount(exp_b: []const u8) u64 {
    const head_len = @min(exp_b.len, 32);
    var head: u256 = 0;
    for (exp_b[0..head_len]) |b| head = (head << 8) | b;
    const head_bits: u64 = if (head == 0) 0 else 256 - @clz(head);
    if (exp_b.len <= 32) {
        return if (head_bits == 0) 0 else head_bits - 1;
    }
    return 8 * @as(u64, @intCast(exp_b.len - 32)) + (if (head_bits == 0) 0 else head_bits - 1);
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

fn recoverAddress(msg: [32]u8, recid: u8, r_be: [32]u8, s_be: [32]u8) ?[20]u8 {
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
