//! BLS12-381 (EIP-2537) curve arithmetic for the precompiles at 0x0b–0x11.
//! The point group operations are identical in shape to bn254's (projective
//! coordinates, py_ecc's `optimized_curve`), so we reuse `bn254.Point(F)` with a
//! BLS base field. This file implements the base field Fp and the G1 group
//! (y² = x³ + 4); Fp2/G2 and the pairing build on top.

const std = @import("std");
const Point = @import("bn254.zig").Point;

/// Base field modulus (381 bits).
pub const P: u384 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
/// Subgroup order (255 bits).
pub const R: u256 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

// --- Fp: integers mod P ---------------------------------------------------

pub const Fp = struct {
    v: u384,

    pub inline fn init(x: u384) Fp {
        return .{ .v = x % P };
    }
    pub inline fn scalar(x: u256) Fp {
        return .{ .v = @as(u384, x) % P };
    }
    pub inline fn zero() Fp {
        return .{ .v = 0 };
    }
    pub inline fn one() Fp {
        return .{ .v = 1 };
    }
    pub inline fn eql(a: Fp, b: Fp) bool {
        return a.v == b.v;
    }
    pub inline fn isZero(a: Fp) bool {
        return a.v == 0;
    }
    pub inline fn add(a: Fp, b: Fp) Fp {
        return .{ .v = @intCast((@as(u768, a.v) + b.v) % P) };
    }
    pub inline fn sub(a: Fp, b: Fp) Fp {
        return .{ .v = if (a.v >= b.v) a.v - b.v else P - (b.v - a.v) };
    }
    pub inline fn neg(a: Fp) Fp {
        return .{ .v = if (a.v == 0) 0 else P - a.v };
    }
    pub inline fn mul(a: Fp, b: Fp) Fp {
        return .{ .v = @intCast((@as(u768, a.v) * b.v) % P) };
    }
    pub fn pow(a: Fp, e: u384) Fp {
        var result = Fp.one();
        var base = a;
        var exp = e;
        while (exp != 0) : (exp >>= 1) {
            if (exp & 1 == 1) result = result.mul(base);
            base = base.mul(base);
        }
        return result;
    }
    pub fn inv(a: Fp) Fp {
        return a.pow(P - 2);
    }
};

pub const G1 = Point(Fp);

/// G1 affine (x, y); infinity maps to (0, 0) as the precompile encodes it.
pub fn normalizeG1(p: G1) struct { x: Fp, y: Fp } {
    if (p.isInf()) return .{ .x = Fp.zero(), .y = Fp.zero() };
    const zi = p.z.inv();
    return .{ .x = p.x.mul(zi), .y = p.y.mul(zi) };
}

// --- Fp2 = Fp[u]/(u² + 1):  c0 + c1·u -------------------------------------

pub const Fp2 = struct {
    c0: Fp,
    c1: Fp,

    pub inline fn scalar(x: u256) Fp2 {
        return .{ .c0 = Fp.scalar(x), .c1 = Fp.zero() };
    }
    pub inline fn zero() Fp2 {
        return .{ .c0 = Fp.zero(), .c1 = Fp.zero() };
    }
    pub inline fn one() Fp2 {
        return .{ .c0 = Fp.one(), .c1 = Fp.zero() };
    }
    pub inline fn eql(a: Fp2, b: Fp2) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }
    pub inline fn isZero(a: Fp2) bool {
        return a.c0.isZero() and a.c1.isZero();
    }
    pub inline fn add(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }
    pub inline fn sub(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }
    pub inline fn neg(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg() };
    }
    pub fn mul(a: Fp2, b: Fp2) Fp2 {
        return .{
            .c0 = a.c0.mul(b.c0).sub(a.c1.mul(b.c1)),
            .c1 = a.c0.mul(b.c1).add(a.c1.mul(b.c0)),
        };
    }
    pub fn inv(a: Fp2) Fp2 {
        const d = a.c0.mul(a.c0).add(a.c1.mul(a.c1)).inv();
        return .{ .c0 = a.c0.mul(d), .c1 = a.c1.neg().mul(d) };
    }
};

pub const G2 = Point(Fp2);

/// G2 curve constant b₂ = 4·(1 + u).
pub fn b2() Fp2 {
    return .{ .c0 = Fp.scalar(4), .c1 = Fp.scalar(4) };
}

pub fn normalizeG2(p: G2) struct { x: Fp2, y: Fp2 } {
    if (p.isInf()) return .{ .x = Fp2.zero(), .y = Fp2.zero() };
    const zi = p.z.inv();
    return .{ .x = p.x.mul(zi), .y = p.y.mul(zi) };
}

// --- Fp12: degree-12 over Fp, modulus x¹² − 2x⁶ + 2 (py_ecc bls12_381) -----

pub const Fp12 = struct {
    c: [12]Fp,

    pub fn zero() Fp12 {
        return std.mem.zeroes(Fp12);
    }
    pub fn one() Fp12 {
        var r = Fp12.zero();
        r.c[0] = Fp.one();
        return r;
    }
    pub fn fromFp(a: Fp) Fp12 {
        var r = Fp12.zero();
        r.c[0] = a;
        return r;
    }
    pub fn scalar(x: u256) Fp12 {
        return fromFp(Fp.scalar(x));
    }
    pub fn eql(a: Fp12, b: Fp12) bool {
        for (0..12) |i| if (!a.c[i].eql(b.c[i])) return false;
        return true;
    }
    pub fn isZero(a: Fp12) bool {
        for (0..12) |i| if (!a.c[i].isZero()) return false;
        return true;
    }
    pub fn add(a: Fp12, b: Fp12) Fp12 {
        var r: Fp12 = undefined;
        for (0..12) |i| r.c[i] = a.c[i].add(b.c[i]);
        return r;
    }
    pub fn sub(a: Fp12, b: Fp12) Fp12 {
        var r: Fp12 = undefined;
        for (0..12) |i| r.c[i] = a.c[i].sub(b.c[i]);
        return r;
    }
    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        var buf = std.mem.zeroes([23]Fp);
        for (0..12) |i| {
            for (0..12) |j| buf[i + j] = buf[i + j].add(a.c[i].mul(b.c[j]));
        }
        // Reduce: x¹² ≡ 2x⁶ − 2 (mc = [2,0,0,0,0,0,−2,…]; bᵢ −= top·mcᵢ).
        var len: usize = 23;
        while (len > 12) : (len -= 1) {
            const top = buf[len - 1];
            const exp = len - 13;
            buf[exp] = buf[exp].sub(top.mul(Fp.scalar(2)));
            buf[exp + 6] = buf[exp + 6].add(top.mul(Fp.scalar(2)));
        }
        var r: Fp12 = undefined;
        for (0..12) |i| r.c[i] = buf[i];
        return r;
    }
    pub fn pow(a: Fp12, comptime W: type, e: W) Fp12 {
        var result = Fp12.one();
        var base = a;
        var exp = e;
        while (exp != 0) : (exp >>= 1) {
            if (exp & 1 == 1) result = result.mul(base);
            base = base.mul(base);
        }
        return result;
    }
    pub fn inv(a: Fp12) Fp12 {
        return a.pow(u4736, INV_EXP);
    }
    pub fn div(a: Fp12, b: Fp12) Fp12 {
        return a.mul(b.inv());
    }
};

// Big exponents (comptime). P¹² ~ 2⁴⁵⁷² fits in u4736.
const P12: comptime_int = blk: {
    const p2 = @as(comptime_int, P) * @as(comptime_int, P);
    const p4 = p2 * p2;
    const p8 = p4 * p4;
    break :blk p8 * p4;
};
const INV_EXP: u4736 = P12 - 2;
const FINAL_EXP: u4736 = (P12 - 1) / @as(comptime_int, R);

pub const G12 = Point(Fp12);

fn castG1(p: G1) G12 {
    return .{ .x = Fp12.fromFp(p.x), .y = Fp12.fromFp(p.y), .z = Fp12.fromFp(p.z) };
}

/// py_ecc bls12_381 sextic twist: G2(Fp2) → G12, with the w-power offsets folded
/// into the Fp12 coefficient indices (x→1,7; y→0,6; z→3,9) and the (1+u) twist
/// giving coeffs [c0−c1, c1].
fn twist(q: G2) G12 {
    var nx = Fp12.zero();
    var ny = Fp12.zero();
    var nz = Fp12.zero();
    nx.c[1] = q.x.c0.sub(q.x.c1);
    nx.c[7] = q.x.c1;
    ny.c[0] = q.y.c0.sub(q.y.c1);
    ny.c[6] = q.y.c1;
    nz.c[3] = q.z.c0.sub(q.z.c1);
    nz.c[9] = q.z.c1;
    return .{ .x = nx, .y = ny, .z = nz };
}

const Line = struct { n: Fp12, d: Fp12 };

fn linefunc(p1: G12, p2: G12, t: G12) Line {
    var mn = p2.y.mul(p1.z).sub(p1.y.mul(p2.z));
    var md = p2.x.mul(p1.z).sub(p1.x.mul(p2.z));
    if (!md.isZero()) {
        return .{
            .n = mn.mul(t.x.mul(p1.z).sub(p1.x.mul(t.z))).sub(md.mul(t.y.mul(p1.z).sub(p1.y.mul(t.z)))),
            .d = md.mul(t.z).mul(p1.z),
        };
    } else if (mn.isZero()) {
        mn = Fp12.scalar(3).mul(p1.x.mul(p1.x));
        md = Fp12.scalar(2).mul(p1.y.mul(p1.z));
        return .{
            .n = mn.mul(t.x.mul(p1.z).sub(p1.x.mul(t.z))).sub(md.mul(t.y.mul(p1.z).sub(p1.y.mul(t.z)))),
            .d = md.mul(t.z).mul(p1.z),
        };
    } else {
        return .{ .n = t.x.mul(p1.z).sub(p1.x.mul(t.z)), .d = p1.z.mul(t.z) };
    }
}

// BLS12-381 ate loop = |seed| = 0xd201000000010000; iterate bits 62..0.
const ATE_LOOP: u64 = 15132376222941642752;

/// Miller loop: point doublings/additions stay in G2 and are re-twisted into
/// G12 each step, exactly as py_ecc's optimized_bls12_381 does. Returns
/// num/den before final exponentiation.
fn millerLoopRaw(q: G2, p: G1) Line {
    const cast_p = castG1(p);
    const twist_q = twist(q);
    var r = q;
    var twist_r = twist_q;
    var f_num = Fp12.one();
    var f_den = Fp12.one();
    var i: usize = 63;
    while (i > 0) {
        i -= 1;
        const lf = linefunc(twist_r, twist_r, cast_p);
        f_num = f_num.mul(f_num).mul(lf.n);
        f_den = f_den.mul(f_den).mul(lf.d);
        r = r.double();
        twist_r = twist(r);
        if ((ATE_LOOP >> @intCast(i)) & 1 == 1) {
            const la = linefunc(twist_r, twist_q, cast_p);
            f_num = f_num.mul(la.n);
            f_den = f_den.mul(la.d);
            r = r.add(q);
            twist_r = twist(r);
        }
    }
    return .{ .n = f_num, .d = f_den };
}

pub fn finalExp(f: Fp12) Fp12 {
    return f.pow(u4736, FINAL_EXP);
}

pub const PairPoint = struct { q: G2, p: G1 };

/// Multi-point pairing product check e(Q₁,P₁)·…·e(Qₖ,Pₖ) == 1.
pub fn pairingProductIsOne(pts: []const PairPoint) bool {
    var num = Fp12.one();
    var den = Fp12.one();
    for (pts) |pt| {
        if (pt.p.isInf() or pt.q.isInf()) continue;
        const m = millerLoopRaw(pt.q, pt.p);
        num = num.mul(m.n);
        den = den.mul(m.d);
    }
    return finalExp(num.div(den)).eql(Fp12.one());
}

// --- tests ----------------------------------------------------------------

const testing = std.testing;

test "Fp inverse" {
    const a = Fp.init(123456789);
    try testing.expect(a.mul(a.inv()).eql(Fp.one()));
}

test "G1 generator on curve, order R" {
    // BLS12-381 G1 generator.
    const gx: u384 = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    const gy: u384 = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;
    const g = G1{ .x = Fp.init(gx), .y = Fp.init(gy), .z = Fp.one() };
    try testing.expect(g.isOnCurve(Fp.scalar(4)));
    try testing.expect(g.mul(R).isInf());
    // 2G via add equals 2G via mul.
    const a = normalizeG1(g.add(g));
    const b = normalizeG1(g.mul(2));
    try testing.expect(a.x.eql(b.x) and a.y.eql(b.y));
}

test "G2 generator on curve, order R" {
    const g2 = G2{
        .x = .{
            .c0 = Fp.init(0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8),
            .c1 = Fp.init(0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e),
        },
        .y = .{
            .c0 = Fp.init(0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801),
            .c1 = Fp.init(0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be),
        },
        .z = Fp2.one(),
    };
    try testing.expect(g2.isOnCurve(b2()));
    try testing.expect(g2.mul(R).isInf());
}

test "pairing: bilinear + non-degenerate" {
    const g1 = G1{
        .x = Fp.init(0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb),
        .y = Fp.init(0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1),
        .z = Fp.one(),
    };
    const g2 = G2{
        .x = .{
            .c0 = Fp.init(0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8),
            .c1 = Fp.init(0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e),
        },
        .y = .{
            .c0 = Fp.init(0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801),
            .c1 = Fp.init(0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be),
        },
        .z = Fp2.one(),
    };
    const neg_g1 = G1{ .x = g1.x, .y = g1.y.neg(), .z = g1.z };
    const neg_g2 = G2{ .x = g2.x, .y = g2.y.neg(), .z = g2.z };
    // Non-degenerate: e(P,Q) ≠ 1.
    try testing.expect(!pairingProductIsOne(&.{.{ .q = g2, .p = g1 }}));
    // Bilinear in G1: e(P,Q)·e(-P,Q) == 1.
    try testing.expect(pairingProductIsOne(&.{ .{ .q = g2, .p = g1 }, .{ .q = g2, .p = neg_g1 } }));
    // Bilinear in G2: e(2Q,P)·e(-Q,P)·e(-Q,P) == 1.
    try testing.expect(pairingProductIsOne(&.{
        .{ .q = g2.mul(2), .p = g1 },
        .{ .q = neg_g2, .p = g1 },
        .{ .q = neg_g2, .p = g1 },
    }));
}
