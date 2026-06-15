//! alt_bn128 (BN254) curve arithmetic for the ecAdd (0x06), ecMul (0x07) and
//! ecPairing (0x08) precompiles. Ported to match py_ecc's `optimized_bn128`,
//! which the execution-specs use as the source of truth.
//!
//! Field tower (py_ecc representation): Fp, then Fp2 = Fp[u]/(u²+1), and Fp12 as
//! a *degree-12* extension of Fp with modulus x¹² = 18x⁶ − 82. Points use
//! projective coordinates (x = X/Z, y = Y/Z); the curve is y² = x³ + 3.

const std = @import("std");

/// Base field modulus.
pub const P: u256 = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
/// Subgroup (curve) order.
pub const R: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

// --- Fp: integers mod P ---------------------------------------------------

pub const Fp = struct {
    v: u256,

    pub inline fn init(x: u256) Fp {
        return .{ .v = x % P };
    }
    pub inline fn scalar(x: u256) Fp {
        return init(x);
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
        return .{ .v = @intCast((@as(u512, a.v) + b.v) % P) };
    }
    pub inline fn sub(a: Fp, b: Fp) Fp {
        return .{ .v = if (a.v >= b.v) a.v - b.v else P - (b.v - a.v) };
    }
    pub inline fn neg(a: Fp) Fp {
        return .{ .v = if (a.v == 0) 0 else P - a.v };
    }
    pub inline fn mul(a: Fp, b: Fp) Fp {
        return .{ .v = @intCast((@as(u512, a.v) * b.v) % P) };
    }
    pub fn pow(a: Fp, e: u256) Fp {
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

// --- Fp2 = Fp[u]/(u² + 1):  c0 + c1·u -------------------------------------

pub const Fp2 = struct {
    c0: Fp,
    c1: Fp,

    pub inline fn scalar(x: u256) Fp2 {
        return .{ .c0 = Fp.init(x), .c1 = Fp.zero() };
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
        // (a0+a1u)(b0+b1u) = (a0b0 - a1b1) + (a0b1 + a1b0)u   (u² = -1)
        return .{
            .c0 = a.c0.mul(b.c0).sub(a.c1.mul(b.c1)),
            .c1 = a.c0.mul(b.c1).add(a.c1.mul(b.c0)),
        };
    }
    pub fn inv(a: Fp2) Fp2 {
        // 1/(c0+c1u) = (c0 - c1u)/(c0² + c1²)
        const d = a.c0.mul(a.c0).add(a.c1.mul(a.c1)).inv();
        return .{ .c0 = a.c0.mul(d), .c1 = a.c1.neg().mul(d) };
    }
};

// --- Fp12: degree-12 over Fp, modulus x¹² = 18x⁶ − 82 ---------------------

pub const Fp12 = struct {
    c: [12]Fp,

    pub fn zero() Fp12 {
        return std.mem.zeroes(Fp12); // all coeffs .v = 0
    }
    pub fn one() Fp12 {
        var r = Fp12.zero();
        r.c[0] = Fp.one();
        return r;
    }
    pub fn scalar(x: u256) Fp12 {
        var r = Fp12.zero();
        r.c[0] = Fp.init(x);
        return r;
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
    pub fn neg(a: Fp12) Fp12 {
        var r: Fp12 = undefined;
        for (0..12) |i| r.c[i] = a.c[i].neg();
        return r;
    }
    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        var buf = std.mem.zeroes([23]Fp);
        for (0..12) |i| {
            for (0..12) |j| buf[i + j] = buf[i + j].add(a.c[i].mul(b.c[j]));
        }
        // Reduce: x¹² ≡ 18x⁶ − 82  (py_ecc modulus_coeffs [82,0,0,0,0,0,-18,…]).
        var len: usize = 23;
        while (len > 12) : (len -= 1) {
            const top = buf[len - 1];
            const exp = len - 13;
            buf[exp] = buf[exp].sub(top.mul(Fp.init(82))); // -= top·mc[0]
            buf[exp + 6] = buf[exp + 6].sub(top.mul(Fp.init(P - 18))); // -= top·mc[6]
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
    /// Fermat inverse over the field of pⁱ² elements: a^(p¹² − 2).
    pub fn inv(a: Fp12) Fp12 {
        return a.pow(u4096, INV_EXP);
    }
    pub fn div(a: Fp12, b: Fp12) Fp12 {
        return a.mul(b.inv());
    }
    /// Frobenius: a^p.
    pub fn frobenius(a: Fp12) Fp12 {
        return a.pow(u4096, @as(u4096, P));
    }
};

// Big exponents (comptime). P¹² ~ 2³⁰⁴⁴ fits in u4096.
const P12: comptime_int = blk: {
    const p2 = @as(comptime_int, P) * @as(comptime_int, P);
    const p4 = p2 * p2;
    const p8 = p4 * p4;
    break :blk p8 * p4;
};
const INV_EXP: u4096 = P12 - 2;
const FINAL_EXP: u4096 = (P12 - 1) / @as(comptime_int, R);

// --- Generic projective point over a field F ------------------------------

pub fn Point(comptime F: type) type {
    return struct {
        x: F,
        y: F,
        z: F,
        const Self = @This();

        pub fn infinity() Self {
            return .{ .x = F.one(), .y = F.one(), .z = F.zero() };
        }
        pub fn isInf(p: Self) bool {
            return p.z.isZero();
        }
        /// On-curve check y²z = x³ + b·z³ for the given curve constant b.
        pub fn isOnCurve(p: Self, b: F) bool {
            if (p.isInf()) return true;
            const y2z = p.y.mul(p.y).mul(p.z);
            const x3 = p.x.mul(p.x).mul(p.x);
            const bz3 = b.mul(p.z.mul(p.z).mul(p.z));
            return y2z.sub(x3).eql(bz3);
        }
        pub fn double(p: Self) Self {
            const W = F.scalar(3).mul(p.x.mul(p.x));
            const S = p.y.mul(p.z);
            const B = p.x.mul(p.y).mul(S);
            const H = W.mul(W).sub(F.scalar(8).mul(B));
            const S2 = S.mul(S);
            return .{
                .x = F.scalar(2).mul(H).mul(S),
                .y = W.mul(F.scalar(4).mul(B).sub(H)).sub(F.scalar(8).mul(p.y.mul(p.y)).mul(S2)),
                .z = F.scalar(8).mul(S).mul(S2),
            };
        }
        pub fn add(p1: Self, p2: Self) Self {
            if (p1.z.isZero()) return p2;
            if (p2.z.isZero()) return p1;
            const U1 = p2.y.mul(p1.z);
            const U2 = p1.y.mul(p2.z);
            const V1 = p2.x.mul(p1.z);
            const V2 = p1.x.mul(p2.z);
            if (V1.eql(V2) and U1.eql(U2)) return p1.double();
            if (V1.eql(V2)) return infinity();
            const U = U1.sub(U2);
            const V = V1.sub(V2);
            const V2_ = V.mul(V);
            const V2V2 = V2_.mul(V2);
            const V3 = V.mul(V2_);
            const W = p1.z.mul(p2.z);
            const A = U.mul(U).mul(W).sub(V3).sub(F.scalar(2).mul(V2V2));
            return .{
                .x = V.mul(A),
                .y = U.mul(V2V2.sub(A)).sub(V3.mul(U2)),
                .z = V3.mul(W),
            };
        }
        pub fn mul(p: Self, n: u256) Self {
            var result = infinity();
            var base = p;
            var k = n;
            while (k != 0) : (k >>= 1) {
                if (k & 1 == 1) result = result.add(base);
                base = base.double();
            }
            return result;
        }
    };
}

pub const G1 = Point(Fp);
pub const G2 = Point(Fp2);
pub const G12 = Point(Fp12);

/// G1 affine (x, y); infinity maps to (0, 0) as the precompile encodes it.
pub fn normalizeG1(p: G1) struct { x: Fp, y: Fp } {
    if (p.isInf()) return .{ .x = Fp.zero(), .y = Fp.zero() };
    const zi = p.z.inv();
    return .{ .x = p.x.mul(zi), .y = p.y.mul(zi) };
}

/// G2 curve constant b₂ = 3/(9 + u) = (27 − 3u)/82.
pub fn b2() Fp2 {
    const inv82 = Fp.init(82).inv();
    return .{ .c0 = Fp.init(27).mul(inv82), .c1 = Fp.init(3).neg().mul(inv82) };
}

// --- Pairing --------------------------------------------------------------

const ATE_LOOP_COUNT: u256 = 29793968203157093288;
const LOG_ATE: usize = 63;

/// Embed a G1 point's coordinates into Fp12 (each as a constant term).
fn castG1(p: G1) G12 {
    return .{
        .x = Fp12.scalar(p.x.v),
        .y = Fp12.scalar(p.y.v),
        .z = Fp12.scalar(p.z.v),
    };
}

fn fp2ToFp12(a: Fp2) struct { lo: Fp12, hi: Fp12 } {
    // py_ecc twist: split (c0 + c1·u) as [c0 - 9·c1] at deg 0 and [c1] at deg 6.
    var lo = Fp12.zero();
    var hi = Fp12.zero();
    lo.c[0] = a.c0.sub(Fp.init(9).mul(a.c1));
    hi.c[6] = a.c1;
    return .{ .lo = lo, .hi = hi };
}

/// Twist a G2 point into a G12 point (py_ecc `twist`).
fn twist(q: G2) G12 {
    const xs = fp2ToFp12(q.x);
    const ys = fp2ToFp12(q.y);
    const zs = fp2ToFp12(q.z);
    const nx = xs.lo.add(xs.hi);
    const ny = ys.lo.add(ys.hi);
    const nz = zs.lo.add(zs.hi);
    var w2 = Fp12.zero();
    w2.c[2] = Fp.one(); // w² (w = x)
    var w3 = Fp12.zero();
    w3.c[3] = Fp.one(); // w³
    return .{ .x = nx.mul(w2), .y = ny.mul(w3), .z = nz };
}

const Line = struct { n: Fp12, d: Fp12 };

fn linefunc(p1: G12, p2: G12, t: G12) Line {
    const x1 = p1.x;
    const y1 = p1.y;
    const z1 = p1.z;
    const x2 = p2.x;
    const y2 = p2.y;
    const z2 = p2.z;
    const xt = t.x;
    const yt = t.y;
    const zt = t.z;
    var mn = y2.mul(z1).sub(y1.mul(z2));
    var md = x2.mul(z1).sub(x1.mul(z2));
    if (!md.isZero()) {
        return .{
            .n = mn.mul(xt.mul(z1).sub(x1.mul(zt))).sub(md.mul(yt.mul(z1).sub(y1.mul(zt)))),
            .d = md.mul(zt).mul(z1),
        };
    } else if (mn.isZero()) {
        mn = Fp12.scalar(3).mul(x1.mul(x1));
        md = Fp12.scalar(2).mul(y1.mul(z1));
        return .{
            .n = mn.mul(xt.mul(z1).sub(x1.mul(zt))).sub(md.mul(yt.mul(z1).sub(y1.mul(zt)))),
            .d = md.mul(zt).mul(z1),
        };
    } else {
        return .{ .n = xt.mul(z1).sub(x1.mul(zt)), .d = z1.mul(zt) };
    }
}

/// Miller loop returning the (numerator, denominator) before final
/// exponentiation, so a multi-point pairing can fold all points into a single
/// inverse + final exponentiation.
pub fn millerLoopRaw(q: G12, p: G12) Line {
    var r = q;
    var f_num = Fp12.one();
    var f_den = Fp12.one();
    var i: usize = LOG_ATE + 1;
    while (i > 0) {
        i -= 1;
        const lf = linefunc(r, r, p);
        f_num = f_num.mul(f_num).mul(lf.n);
        f_den = f_den.mul(f_den).mul(lf.d);
        r = r.double();
        if ((ATE_LOOP_COUNT >> @intCast(i)) & 1 == 1) {
            const la = linefunc(r, q, p);
            f_num = f_num.mul(la.n);
            f_den = f_den.mul(la.d);
            r = r.add(q);
        }
    }
    // Frobenius end steps.
    const q1 = G12{ .x = q.x.frobenius(), .y = q.y.frobenius(), .z = q.z.frobenius() };
    const nq2 = G12{ .x = q1.x.frobenius(), .y = q1.y.frobenius().neg(), .z = q1.z.frobenius() };
    const l1 = linefunc(r, q1, p);
    f_num = f_num.mul(l1.n);
    f_den = f_den.mul(l1.d);
    r = r.add(q1);
    const l2 = linefunc(r, nq2, p);
    f_num = f_num.mul(l2.n);
    f_den = f_den.mul(l2.d);
    return .{ .n = f_num, .d = f_den };
}

/// Final exponentiation f^((p¹² − 1)/r).
pub fn finalExp(f: Fp12) Fp12 {
    return f.pow(u4096, FINAL_EXP);
}

/// Optimal-ate pairing e(Q, P) with Q in G2, P in G1 (single point).
pub fn pairing(q: G2, p: G1) Fp12 {
    if (p.isInf() or q.isInf()) return Fp12.one();
    const m = millerLoopRaw(twist(q), castG1(p));
    return finalExp(m.n.div(m.d));
}

pub const PairPoint = struct { q: G2, p: G1 };

/// Multi-point pairing product check e(Q₁,P₁)·…·e(Qₖ,Pₖ) == 1, with a single
/// inverse and final exponentiation. `pts` is the list of (Q, P) pairs.
pub fn pairingProductIsOne(pts: []const PairPoint) bool {
    var num = Fp12.one();
    var den = Fp12.one();
    for (pts) |pt| {
        if (pt.p.isInf() or pt.q.isInf()) continue; // e = 1, no contribution
        const m = millerLoopRaw(twist(pt.q), castG1(pt.p));
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

test "G1 generator: on curve, order R" {
    const g = G1{ .x = Fp.one(), .y = Fp.init(2), .z = Fp.one() };
    try testing.expect(g.isOnCurve(Fp.scalar(3)));
    try testing.expect(g.mul(R).isInf());
}

test "G1 add matches mul" {
    const g = G1{ .x = Fp.one(), .y = Fp.init(2), .z = Fp.one() };
    const a = normalizeG1(g.add(g));
    const b = normalizeG1(g.mul(2));
    try testing.expect(a.x.eql(b.x) and a.y.eql(b.y));
}

test "G2 generator on curve" {
    // BN254 G2 generator.
    const g2 = G2{
        .x = .{
            .c0 = Fp.init(10857046999023057135944570762232829481370756359578518086990519993285655852781),
            .c1 = Fp.init(11559732032986387107991004021392285783925812861821192530917403151452391805634),
        },
        .y = .{
            .c0 = Fp.init(8495653923123431417604973247489272438418190587263600148770280649306958101930),
            .c1 = Fp.init(4082367875863433681332203403145435568316851327593401208105741076214120093531),
        },
        .z = Fp2.one(),
    };
    try testing.expect(g2.isOnCurve(b2()));
    try testing.expect(g2.mul(R).isInf());
}

test "pairing bilinearity: e(2*G2, G1) == e(G2, 2*G1)" {
    const g1 = G1{ .x = Fp.one(), .y = Fp.init(2), .z = Fp.one() };
    const g2 = G2{
        .x = .{
            .c0 = Fp.init(10857046999023057135944570762232829481370756359578518086990519993285655852781),
            .c1 = Fp.init(11559732032986387107991004021392285783925812861821192530917403151452391805634),
        },
        .y = .{
            .c0 = Fp.init(8495653923123431417604973247489272438418190587263600148770280649306958101930),
            .c1 = Fp.init(4082367875863433681332203403145435568316851327593401208105741076214120093531),
        },
        .z = Fp2.one(),
    };
    const lhs = pairing(g2.mul(2), g1);
    const rhs = pairing(g2, g1.mul(2));
    try testing.expect(lhs.eql(rhs));
}
