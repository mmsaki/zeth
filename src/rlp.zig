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

// ── Decoding ──────────────────────────────────────────────────────────────

/// A decoded RLP item: either a byte string (a slice into the input) or a list
/// of sub-items. Lists are heap-allocated from the decode allocator.
pub const Item = union(enum) {
    str: []const u8,
    list: []Item,

    /// The byte string, or an error if this item is a list.
    pub fn bytes(self: Item) error{NotAString}![]const u8 {
        return switch (self) {
            .str => |s| s,
            .list => error.NotAString,
        };
    }

    /// The sub-items, or an error if this item is a string.
    pub fn items(self: Item) error{NotAList}![]Item {
        return switch (self) {
            .list => |l| l,
            .str => error.NotAList,
        };
    }

    /// Interpret a byte-string item as a big-endian unsigned integer.
    pub fn uint(self: Item, comptime T: type) error{ NotAString, Overflow }!T {
        const s = try self.bytes();
        if (s.len > @sizeOf(T)) return error.Overflow;
        var v: T = 0;
        for (s) |b| v = (v << 8) | b;
        return v;
    }
};

pub const DecodeError = error{ ShortInput, InvalidLength, OutOfMemory };

/// An item plus how many input bytes it consumed.
pub const Decoded = struct { item: Item, consumed: usize };

/// Decode a single RLP item from the front of `input`, returning the item and
/// the number of bytes it consumed. Recursive; list children are allocated from
/// `a` (use an arena).
pub fn decodeItem(a: std.mem.Allocator, input: []const u8) DecodeError!Decoded {
    if (input.len == 0) return error.ShortInput;
    const b0 = input[0];
    if (b0 < 0x80) {
        return .{ .item = .{ .str = input[0..1] }, .consumed = 1 };
    } else if (b0 < 0xb8) { // short string
        const len = b0 - 0x80;
        if (input.len < 1 + len) return error.ShortInput;
        return .{ .item = .{ .str = input[1 .. 1 + len] }, .consumed = 1 + len };
    } else if (b0 < 0xc0) { // long string
        const ll = b0 - 0xb7;
        if (input.len < 1 + ll) return error.ShortInput;
        const len = try readLen(input[1 .. 1 + ll]);
        const start = 1 + ll;
        if (input.len < start + len) return error.ShortInput;
        return .{ .item = .{ .str = input[start .. start + len] }, .consumed = start + len };
    } else if (b0 < 0xf8) { // short list
        const len = b0 - 0xc0;
        if (input.len < 1 + len) return error.ShortInput;
        return decodeList(a, input[1 .. 1 + len], 1 + len);
    } else { // long list
        const ll = b0 - 0xf7;
        if (input.len < 1 + ll) return error.ShortInput;
        const len = try readLen(input[1 .. 1 + ll]);
        const start = 1 + ll;
        if (input.len < start + len) return error.ShortInput;
        return decodeList(a, input[start .. start + len], start + len);
    }
}

/// Decode the top-level item and require it to consume the entire input.
pub fn decode(a: std.mem.Allocator, input: []const u8) DecodeError!Item {
    const r = try decodeItem(a, input);
    if (r.consumed != input.len) return error.InvalidLength;
    return r.item;
}

/// Return each top-level element of an RLP list as its raw encoded span (a
/// slice into `input`). Errors if `input` is not a single list. Useful when the
/// element's *original bytes* matter (e.g. the transactions trie, where a typed
/// transaction's value is its byte-string content, not a re-encoding).
pub fn listSpans(a: std.mem.Allocator, input: []const u8) DecodeError![][]const u8 {
    if (input.len == 0) return error.ShortInput;
    const b0 = input[0];
    var start: usize = undefined;
    var len: usize = undefined;
    if (b0 >= 0xc0 and b0 < 0xf8) {
        len = b0 - 0xc0;
        start = 1;
    } else if (b0 >= 0xf8) {
        const ll = b0 - 0xf7;
        if (input.len < 1 + ll) return error.ShortInput;
        len = try readLen(input[1 .. 1 + ll]);
        start = 1 + ll;
    } else return error.InvalidLength; // not a list
    if (input.len < start + len) return error.ShortInput;
    const payload = input[start .. start + len];
    var spans: std.ArrayList([]const u8) = .empty;
    var off: usize = 0;
    while (off < payload.len) {
        const r = try decodeItem(a, payload[off..]);
        try spans.append(a, payload[off .. off + r.consumed]);
        off += r.consumed;
    }
    return spans.items;
}

fn decodeList(a: std.mem.Allocator, payload: []const u8, consumed: usize) DecodeError!Decoded {
    var children: std.ArrayList(Item) = .empty;
    var off: usize = 0;
    while (off < payload.len) {
        const r = try decodeItem(a, payload[off..]);
        try children.append(a, r.item);
        off += r.consumed;
    }
    return .{ .item = .{ .list = children.items }, .consumed = consumed };
}

fn readLen(bytes: []const u8) DecodeError!usize {
    if (bytes.len == 0 or bytes.len > @sizeOf(usize)) return error.InvalidLength;
    if (bytes[0] == 0) return error.InvalidLength; // non-minimal length
    var v: usize = 0;
    for (bytes) |b| v = (v << 8) | b;
    return v;
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

test "decode string and list" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // "dog"
    const dog = try decode(a, &.{ 0x83, 'd', 'o', 'g' });
    try testing.expectEqualSlices(u8, "dog", try dog.bytes());

    // ["cat", "dog"]
    const list = try decode(a, &.{ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' });
    const xs = try list.items();
    try testing.expectEqual(@as(usize, 2), xs.len);
    try testing.expectEqualSlices(u8, "cat", try xs[0].bytes());
    try testing.expectEqualSlices(u8, "dog", try xs[1].bytes());

    // integer 1024 (long-ish string) round-trips through uint()
    const n = try decode(a, &.{ 0x82, 0x04, 0x00 });
    try testing.expectEqual(@as(u64, 1024), try n.uint(u64));
}

test "decode long string (>55 bytes)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var big: [60]u8 = undefined;
    @memset(&big, 'a');
    const enc = try encodeBytes(a, &big);
    const dec = try decode(a, enc);
    try testing.expectEqualSlices(u8, &big, try dec.bytes());
}
