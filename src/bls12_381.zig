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

/// Fp square root (P ≡ 3 mod 4, so √a = a^((P+1)/4)); null if `a` is a non-residue.
pub fn fpSqrt(a: Fp) ?Fp {
    const r = a.pow((P + 1) / 4);
    return if (r.mul(r).eql(a)) r else null;
}

/// Curve generators (EIP-2537 / BLS12-381 standard).
pub fn g1Generator() G1 {
    return .{
        .x = Fp.init(0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb),
        .y = Fp.init(0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1),
        .z = Fp.one(),
    };
}

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

pub fn g2Generator() G2 {
    return .{
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
}

/// EIP-4844 trusted-setup point [τ]₂ = KZG_SETUP_G2_MONOMIAL[1], decompressed.
pub fn kzgSetupG2() G2 {
    return .{
        .x = .{
            .c0 = Fp.init(0x185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2),
            .c1 = Fp.init(0x15bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72),
        },
        .y = .{
            .c0 = Fp.init(0x014353bdb96b626dd7d5ee8599d1fca2131569490e28de18e82451a496a9c9794ce26d105941f383ee689bfbbb832a99),
            .c1 = Fp.init(0x1666c54b0a32529503432fcae0181b4bef79de09fc63671fda5ed1ba9bfa07899495346f3d7ac9cd23048ef30d0a154f),
        },
        .z = Fp2.one(),
    };
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

// EIP-2537 MAP_FP_TO_G1 constants (BLS12-381 SSWU + 11-isogeny), from py_ecc.
const ISO_11_A = Fp{ .v = 0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d };
const ISO_11_B = Fp{ .v = 0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0 };
const ISO_11_Z = Fp{ .v = 0xb };
const SQRT_MINUS_11_CUBED = Fp{ .v = 0x3d689d1e0e762cef9f2bec6130316806b4c80eda6fc10ce77ae83eab1ea8b8b8a407c9c6db195e06f2dbeabc2baeff5 };
const P_MINUS_3_DIV_4: u384 = 0x680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaaa;
const H_EFF_G1: u256 = 0xd201000000010001;
const ISO_11_X_NUM = [_]Fp{ .{ .v = 0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7 }, .{ .v = 0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb }, .{ .v = 0xd54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0 }, .{ .v = 0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861 }, .{ .v = 0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9 }, .{ .v = 0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983 }, .{ .v = 0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84 }, .{ .v = 0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e }, .{ .v = 0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317 }, .{ .v = 0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e }, .{ .v = 0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b }, .{ .v = 0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229 } };
const ISO_11_X_DEN = [_]Fp{ .{ .v = 0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c }, .{ .v = 0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff }, .{ .v = 0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19 }, .{ .v = 0x3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8 }, .{ .v = 0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e }, .{ .v = 0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5 }, .{ .v = 0x772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a }, .{ .v = 0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e }, .{ .v = 0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641 }, .{ .v = 0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a }, .{ .v = 0x1 } };
const ISO_11_Y_NUM = [_]Fp{ .{ .v = 0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33 }, .{ .v = 0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696 }, .{ .v = 0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6 }, .{ .v = 0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb }, .{ .v = 0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb }, .{ .v = 0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0 }, .{ .v = 0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2 }, .{ .v = 0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29 }, .{ .v = 0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587 }, .{ .v = 0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30 }, .{ .v = 0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132 }, .{ .v = 0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e }, .{ .v = 0xb182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8 }, .{ .v = 0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133 }, .{ .v = 0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b }, .{ .v = 0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604 } };
const ISO_11_Y_DEN = [_]Fp{ .{ .v = 0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1 }, .{ .v = 0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d }, .{ .v = 0x58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2 }, .{ .v = 0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416 }, .{ .v = 0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d }, .{ .v = 0x8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac }, .{ .v = 0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c }, .{ .v = 0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9 }, .{ .v = 0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a }, .{ .v = 0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55 }, .{ .v = 0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8 }, .{ .v = 0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092 }, .{ .v = 0xad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc }, .{ .v = 0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7 }, .{ .v = 0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f }, .{ .v = 0x1 } };

fn sgn0(a: Fp) u1 {
    return @intCast(a.v & 1);
}

const SqrtDiv = struct { ok: bool, result: Fp };
fn sqrtDivision(u: Fp, v: Fp) SqrtDiv {
    const temp = u.mul(v);
    const result = temp.mul(temp.mul(v.mul(v)).pow(P_MINUS_3_DIV_4));
    return .{ .ok = result.mul(result).mul(v).eql(u), .result = result };
}

fn optimizedSwuG1(t: Fp) G1 {
    const t2 = t.mul(t);
    const zt2 = ISO_11_Z.mul(t2);
    const temp = zt2.add(zt2.mul(zt2));
    var den = ISO_11_A.mul(temp).neg();
    var num = ISO_11_B.mul(temp.add(Fp.one()));
    if (den.isZero()) den = ISO_11_Z.mul(ISO_11_A);
    const v = den.mul(den).mul(den);
    const u = num.mul(num).mul(num)
        .add(ISO_11_A.mul(num).mul(den.mul(den)))
        .add(ISO_11_B.mul(v));
    const sd = sqrtDivision(u, v);
    var y = sd.result;
    if (!sd.ok) {
        y = y.mul(t.mul(t).mul(t)).mul(SQRT_MINUS_11_CUBED);
        num = num.mul(zt2);
    }
    if (sgn0(t) != sgn0(y)) y = y.neg();
    y = y.mul(den);
    return .{ .x = num, .y = y, .z = den };
}

fn horner(k: []const Fp, x: Fp, zpow: []const Fp) Fp {
    var acc = k[k.len - 1];
    var j: usize = 0;
    while (j < k.len - 1) : (j += 1) {
        acc = acc.mul(x).add(zpow[j].mul(k[k.len - 2 - j]));
    }
    return acc;
}

/// Apply the 11-isogeny from the SSWU curve back to G1.
fn isoMapG1(p: G1) G1 {
    var zpow: [15]Fp = undefined;
    zpow[0] = p.z;
    for (1..15) |i| zpow[i] = zpow[i - 1].mul(p.z);
    var x_num = horner(&ISO_11_X_NUM, p.x, &zpow);
    var x_den = horner(&ISO_11_X_DEN, p.x, &zpow);
    var y_num = horner(&ISO_11_Y_NUM, p.x, &zpow);
    var y_den = horner(&ISO_11_Y_DEN, p.x, &zpow);
    x_den = x_den.mul(p.z);
    y_num = y_num.mul(p.y);
    y_den = y_den.mul(p.z);
    _ = &x_num;
    return .{ .x = x_num.mul(y_den), .y = x_den.mul(y_num), .z = x_den.mul(y_den) };
}

/// EIP-2537 map_fp_to_G1: SSWU + 11-isogeny + cofactor clearing.
pub fn mapToG1(t: Fp) G1 {
    return isoMapG1(optimizedSwuG1(t)).mul(H_EFF_G1);
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

test "mapToG1 matches py_ecc vector" {
    const r = normalizeG1(mapToG1(Fp.init(12345)));
    try testing.expect(r.x.v == 0x122fe5e9fb6cf588ceacaeabf401519fd29d494b336ca9d7a10361705bbee88ba1993c83f728a32e3b2ad4907230c71a);
    try testing.expect(r.y.v == 0x0e63a1ea3d4680e2c4a31e9217aa1a513458a96cf68a3dc956f3dd8ee56385435e535fb83d567a998b7656dad037f75d);
}
