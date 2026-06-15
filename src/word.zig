//! 256-bit EVM word arithmetic.
//!
//! The EVM operates on 256-bit big-endian unsigned integers. Zig has native
//! arbitrary-width integers, so we use `u256` directly and lean on the
//! compiler for the wrapping arithmetic the EVM mandates. Each helper mirrors
//! the corresponding operation in the Python execution-specs (Frontier fork).

const std = @import("std");

/// Reinterpret a word as a two's-complement signed integer.
pub inline fn toSigned(x: u256) i256 {
    return @bitCast(x);
}

/// Reinterpret a signed integer as an EVM word.
pub inline fn fromSigned(x: i256) u256 {
    return @bitCast(x);
}

/// `2**255`, the most-negative signed value (used by SDIV's overflow case).
pub const SIGN_MIN: i256 = std.math.minInt(i256);

/// EVM `ADD`: wrapping 256-bit addition.
pub inline fn add(x: u256, y: u256) u256 {
    return x +% y;
}

/// EVM `SUB`: wrapping 256-bit subtraction.
pub inline fn sub(x: u256, y: u256) u256 {
    return x -% y;
}

/// EVM `MUL`: wrapping 256-bit multiplication.
pub inline fn mul(x: u256, y: u256) u256 {
    return x *% y;
}

/// EVM `DIV`: unsigned integer division, with division-by-zero yielding 0.
pub inline fn div(dividend: u256, divisor: u256) u256 {
    if (divisor == 0) return 0;
    return dividend / divisor;
}

/// EVM `SDIV`: signed integer division. Division by zero yields 0, and the
/// single overflow case (`-2**255 / -1`) wraps back to `-2**255`.
pub fn sdiv(dividend: u256, divisor: u256) u256 {
    const a = toSigned(dividend);
    const b = toSigned(divisor);
    if (b == 0) return 0;
    if (a == SIGN_MIN and b == -1) return fromSigned(SIGN_MIN);
    return fromSigned(@divTrunc(a, b));
}

/// EVM `MOD`: unsigned remainder, with a zero modulus yielding 0.
pub inline fn mod(x: u256, y: u256) u256 {
    if (y == 0) return 0;
    return x % y;
}

/// EVM `SMOD`: signed remainder (sign follows the dividend), zero modulus -> 0.
pub fn smod(x: u256, y: u256) u256 {
    const a = toSigned(x);
    const b = toSigned(y);
    if (b == 0) return 0;
    return fromSigned(@rem(a, b));
}

/// EVM `ADDMOD`: `(x + y) mod n` computed at full 257-bit precision.
pub fn addmod(x: u256, y: u256, n: u256) u256 {
    if (n == 0) return 0;
    const wide = @as(u512, x) + @as(u512, y);
    return @intCast(wide % @as(u512, n));
}

/// EVM `MULMOD`: `(x * y) mod n` computed at full 512-bit precision.
pub fn mulmod(x: u256, y: u256, n: u256) u256 {
    if (n == 0) return 0;
    const wide = @as(u512, x) * @as(u512, y);
    return @intCast(wide % @as(u512, n));
}

/// EVM `EXP`: `base ** exponent mod 2**256` via square-and-multiply. Reducing
/// modulo `2**256` is exactly the wrapping arithmetic Zig gives us for free.
pub fn exp(base: u256, exponent: u256) u256 {
    var result: u256 = 1;
    var b = base;
    var e = exponent;
    while (e != 0) {
        if (e & 1 == 1) result *%= b;
        b *%= b;
        e >>= 1;
    }
    return result;
}

/// EVM `SIGNEXTEND`: sign-extend `value` from `(byte_num + 1)` bytes to 32.
pub fn signextend(byte_num: u256, value: u256) u256 {
    if (byte_num > 31) return value;
    // Bit index of the sign bit within the chosen byte (counted from the LSB).
    const sign_bit: u8 = @as(u8, @intCast(byte_num)) * 8 + 7;
    // Low `sign_bit + 1` bits are kept; the rest copy the sign bit. When the
    // chosen byte is the most significant one, every bit is kept.
    const bits: u9 = @as(u9, sign_bit) + 1;
    const mask: u256 = if (bits >= 256)
        std.math.maxInt(u256)
    else
        (@as(u256, 1) << @intCast(bits)) - 1;
    if (value & (@as(u256, 1) << @intCast(sign_bit)) != 0) {
        return value | ~mask;
    }
    return value & mask;
}

/// EVM `SHL`: `value << shift` (logical), zero when `shift >= 256`.
/// Stack order: `shift` is on top, so binOp passes `(shift, value)`.
pub fn shl(shift: u256, value: u256) u256 {
    if (shift >= 256) return 0;
    return value << @intCast(shift);
}

/// EVM `SHR`: `value >> shift` (logical), zero when `shift >= 256`.
pub fn shr(shift: u256, value: u256) u256 {
    if (shift >= 256) return 0;
    return value >> @intCast(shift);
}

/// EVM `SAR`: arithmetic (sign-extending) right shift.
pub fn sar(shift: u256, value: u256) u256 {
    const s = toSigned(value);
    if (shift >= 256) return if (s < 0) std.math.maxInt(u256) else 0;
    return fromSigned(s >> @intCast(shift));
}

/// EVM `CLZ` (EIP-7939): count leading zero bits; 256 when the value is zero.
pub fn clz(value: u256) u256 {
    return @clz(value);
}

/// EVM `BYTE`: extract the `i`-th byte counting from the most-significant end.
pub fn byte(i: u256, word: u256) u256 {
    if (i >= 32) return 0;
    const shift: u8 = @intCast((31 - i) * 8);
    return (word >> @intCast(shift)) & 0xFF;
}

/// Encode a word as 32 big-endian bytes (EVM `to_be_bytes32`).
pub fn toBeBytes32(x: u256) [32]u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, x, .big);
    return buf;
}

/// Decode up to 32 big-endian bytes into a word, as PUSH-N and MLOAD do.
pub fn fromBeBytes(bytes: []const u8) u256 {
    std.debug.assert(bytes.len <= 32);
    var x: u256 = 0;
    for (bytes) |b| x = (x << 8) | b;
    return x;
}

test "wrapping arithmetic matches the spec" {
    const max = std.math.maxInt(u256);
    try std.testing.expectEqual(@as(u256, 0), add(max, 1));
    try std.testing.expectEqual(max, sub(0, 1));
    try std.testing.expectEqual(@as(u256, 1), mul(max, max));
}

test "signed division overflow case" {
    const min = fromSigned(SIGN_MIN);
    const neg1 = fromSigned(-1);
    try std.testing.expectEqual(min, sdiv(min, neg1));
    try std.testing.expectEqual(@as(u256, 0), div(5, 0));
    try std.testing.expectEqual(@as(u256, 0), sdiv(5, 0));
}

test "addmod and mulmod use full precision" {
    const max = std.math.maxInt(u256);
    // (max + max) mod 7 — would overflow a naive 256-bit add.
    try std.testing.expectEqual(addmod(max, max, 7), @as(u256, @intCast((@as(u512, max) * 2) % 7)));
    try std.testing.expectEqual(mulmod(max, max, 13), @as(u256, @intCast((@as(u512, max) * max) % 13)));
}

test "exp by squaring" {
    try std.testing.expectEqual(@as(u256, 1024), exp(2, 10));
    try std.testing.expectEqual(@as(u256, 1), exp(123456, 0));
}

test "signextend extends the sign bit" {
    // 0xFF as a 1-byte signed value sign-extends to all-ones (-1).
    try std.testing.expectEqual(std.math.maxInt(u256), signextend(0, 0xFF));
    // 0x7F stays positive.
    try std.testing.expectEqual(@as(u256, 0x7F), signextend(0, 0x7F));
}

test "byte extraction is big-endian" {
    const w: u256 = 0x1122334455667788;
    try std.testing.expectEqual(@as(u256, 0x11), byte(24, w));
    try std.testing.expectEqual(@as(u256, 0x88), byte(31, w));
    try std.testing.expectEqual(@as(u256, 0), byte(32, w));
}

test "big-endian round trip" {
    const w: u256 = 0xdeadbeef;
    const bytes = toBeBytes32(w);
    try std.testing.expectEqual(w, fromBeBytes(&bytes));
}
