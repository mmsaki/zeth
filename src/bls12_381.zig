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
