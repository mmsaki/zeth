//! Minimal RLP (Recursive Length Prefix) encoder.
//!
//! Currently covers exactly what the EVM core needs — encoding a byte string,
//! a non-negative integer, and a flat list of pre-encoded items — which is
//! enough to derive `CREATE` contract addresses. It is structured so that
//! decoding and richer item types can be layered on later.

const std = @import("std");

/// Encode a byte string per RLP rules.
pub fn encodeBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len == 1 and bytes[0] < 0x80) {
        return allocator.dupe(u8, bytes);
    }
    return encodeWithPrefix(allocator, 0x80, bytes);
}

/// Encode a non-negative integer as its minimal big-endian byte string
/// (zero encodes as the empty string, i.e. `0x80`).
pub fn encodeUint(allocator: std.mem.Allocator, value: u64) ![]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    var start: usize = 0;
    while (start < buf.len and buf[start] == 0) start += 1;
    return encodeBytes(allocator, buf[start..]);
}

/// Encode a list whose items are already RLP-encoded.
pub fn encodeList(allocator: std.mem.Allocator, items: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (items) |it| total += it.len;
    const payload = try allocator.alloc(u8, total);
    defer allocator.free(payload);
    var off: usize = 0;
    for (items) |it| {
        @memcpy(payload[off .. off + it.len], it);
        off += it.len;
    }
    return encodeWithPrefix(allocator, 0xC0, payload);
}

/// Apply an RLP length prefix (`base` = 0x80 for strings, 0xC0 for lists).
fn encodeWithPrefix(allocator: std.mem.Allocator, base: u8, payload: []const u8) ![]u8 {
    if (payload.len < 56) {
        const out = try allocator.alloc(u8, payload.len + 1);
        out[0] = base + @as(u8, @intCast(payload.len));
        @memcpy(out[1..], payload);
        return out;
    }
    // Long form: prefix byte, big-endian length, then payload.
    var len_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_buf, payload.len, .big);
    var start: usize = 0;
    while (start < len_buf.len and len_buf[start] == 0) start += 1;
    const len_bytes = len_buf[start..];
    const out = try allocator.alloc(u8, 1 + len_bytes.len + payload.len);
    out[0] = base + 55 + @as(u8, @intCast(len_bytes.len));
    @memcpy(out[1 .. 1 + len_bytes.len], len_bytes);
    @memcpy(out[1 + len_bytes.len ..], payload);
    return out;
}

const testing = std.testing;

test "encode short string" {
    const out = try encodeBytes(testing.allocator, "dog");
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(u8, &.{ 0x83, 'd', 'o', 'g' }, out);
}

test "encode single low byte is itself" {
    const out = try encodeBytes(testing.allocator, &.{0x0f});
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(u8, &.{0x0f}, out);
}

test "encode integers minimally" {
    const zero = try encodeUint(testing.allocator, 0);
    defer testing.allocator.free(zero);
    try testing.expectEqualSlices(u8, &.{0x80}, zero);

    const n = try encodeUint(testing.allocator, 1024);
    defer testing.allocator.free(n);
    try testing.expectEqualSlices(u8, &.{ 0x82, 0x04, 0x00 }, n);
}

test "encode list of two items" {
    const a = try encodeBytes(testing.allocator, "cat");
    defer testing.allocator.free(a);
    const b = try encodeBytes(testing.allocator, "dog");
    defer testing.allocator.free(b);
    const list = try encodeList(testing.allocator, &.{ a, b });
    defer testing.allocator.free(list);
    try testing.expectEqualSlices(u8, &.{ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' }, list);
}
