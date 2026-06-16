//! devp2p message codecs: the base p2p `Hello` and the eth/68 messages a block
//! sync needs (`Status`, `GetBlockHeaders`/`BlockHeaders`,
//! `GetBlockBodies`/`BlockBodies`).
//!
//! A capability message rides an RLPx frame as `rlp(msg_id) ‖ rlp(payload)`.
//! With a single negotiated `eth` capability, the eth message ids start at
//! BASE = 0x10 (after the 16 reserved p2p ids). eth/66+ tags request/response
//! pairs with a request-id.

const std = @import("std");
const rlp = @import("rlp.zig");
const block = @import("block.zig");

/// p2p base-protocol message ids.
pub const p2p = struct {
    pub const hello = 0x00;
    pub const disconnect = 0x01;
    pub const ping = 0x02;
    pub const pong = 0x03;
};

/// eth/68 message ids (offset by the 0x10 capability base).
pub const eth = struct {
    pub const base = 0x10;
    pub const status = base + 0x00;
    pub const new_block_hashes = base + 0x01;
    pub const transactions = base + 0x02;
    pub const get_block_headers = base + 0x03;
    pub const block_headers = base + 0x04;
    pub const get_block_bodies = base + 0x05;
    pub const block_bodies = base + 0x06;
};

pub const ETH_VERSION: u64 = 68;

/// Split a frame body into its message id and the remaining payload RLP.
pub fn splitMessage(frame: []const u8) !struct { id: u64, payload: []const u8 } {
    if (frame.len == 0) return error.EmptyMessage;
    // The id is a single RLP integer: 0 encodes as the empty string 0x80;
    // 0x01..0x7f encode as themselves; a byte ≥ 0x80 is wrapped as 0x81 ‖ byte.
    if (frame[0] == 0x80) return .{ .id = 0, .payload = frame[1..] };
    if (frame[0] < 0x80) return .{ .id = frame[0], .payload = frame[1..] };
    if (frame[0] == 0x81 and frame.len >= 2) return .{ .id = frame[1], .payload = frame[2..] };
    return error.BadMessageId;
}

/// Prepend the RLP-encoded message id to an already-encoded payload, yielding a
/// frame body (caller owns it).
pub fn frameBody(a: std.mem.Allocator, id: u64, payload: []const u8) ![]u8 {
    const id_rlp = try rlp.encodeUint(a, id);
    defer a.free(id_rlp);
    const out = try a.alloc(u8, id_rlp.len + payload.len);
    @memcpy(out[0..id_rlp.len], id_rlp);
    @memcpy(out[id_rlp.len..], payload);
    return out;
}

// ── Status (eth/68) ──────────────────────────────────────────────────────────
pub const Status = struct {
    version: u64,
    network_id: u64,
    total_difficulty: u256,
    best_hash: [32]u8,
    genesis_hash: [32]u8,
    fork_hash: [4]u8,
    fork_next: u64,

    /// rlp[version, networkId, td, bestHash, genesis, [forkHash, forkNext]]
    pub fn encode(self: Status, a: std.mem.Allocator) ![]u8 {
        const forkid = blk: {
            const items = [_][]const u8{
                try rlp.encodeBytes(a, &self.fork_hash),
                try rlp.encodeUint(a, self.fork_next),
            };
            defer for (items) |it| a.free(it);
            break :blk try rlp.encodeList(a, &items);
        };
        defer a.free(forkid);
        const fields = [_][]const u8{
            try rlp.encodeUint(a, self.version),
            try rlp.encodeUint(a, self.network_id),
            try encodeU256(a, self.total_difficulty),
            try rlp.encodeBytes(a, &self.best_hash),
            try rlp.encodeBytes(a, &self.genesis_hash),
            forkid,
        };
        // forkid is borrowed (freed above); free only the five we just made.
        defer for (fields[0..5]) |it| a.free(it);
        return rlp.encodeList(a, &fields);
    }

    pub fn decode(a: std.mem.Allocator, payload: []const u8) !Status {
        const item = try rlp.decode(a, payload);
        const f = try item.items();
        if (f.len < 6) return error.BadStatus;
        const fork = try f[5].items();
        if (fork.len < 2) return error.BadStatus;
        return .{
            .version = try f[0].uint(u64),
            .network_id = try f[1].uint(u64),
            .total_difficulty = try decodeU256(f[2]),
            .best_hash = try fixed(32, f[3]),
            .genesis_hash = try fixed(32, f[4]),
            .fork_hash = try fixed(4, fork[0]),
            .fork_next = try fork[1].uint(u64),
        };
    }
};

// ── GetBlockHeaders / BlockHeaders ───────────────────────────────────────────
/// A header request: by block number or by hash, then amount/skip/reverse.
pub const GetBlockHeaders = struct {
    request_id: u64,
    origin_hash: ?[32]u8 = null,
    origin_number: u64 = 0,
    amount: u64,
    skip: u64 = 0,
    reverse: bool = false,

    /// rlp[reqId, [origin, amount, skip, reverse]]
    pub fn encode(self: GetBlockHeaders, a: std.mem.Allocator) ![]u8 {
        const origin = if (self.origin_hash) |h| try rlp.encodeBytes(a, &h) else try rlp.encodeUint(a, self.origin_number);
        const inner_items = [_][]const u8{
            origin,
            try rlp.encodeUint(a, self.amount),
            try rlp.encodeUint(a, self.skip),
            try rlp.encodeUint(a, @intFromBool(self.reverse)),
        };
        defer for (inner_items) |it| a.free(it);
        const inner = try rlp.encodeList(a, &inner_items);
        defer a.free(inner);
        const fields = [_][]const u8{ try rlp.encodeUint(a, self.request_id), inner };
        defer a.free(fields[0]);
        return rlp.encodeList(a, &fields);
    }

    pub fn decode(a: std.mem.Allocator, payload: []const u8) !GetBlockHeaders {
        const item = try rlp.decode(a, payload);
        const f = try item.items();
        if (f.len < 2) return error.BadRequest;
        const q = try f[1].items();
        if (q.len < 4) return error.BadRequest;
        var g = GetBlockHeaders{ .request_id = try f[0].uint(u64), .amount = try q[1].uint(u64) };
        // origin is a 32-byte hash or a block number.
        const ob = try q[0].bytes();
        if (ob.len == 32) {
            g.origin_hash = try fixed(32, q[0]);
        } else {
            g.origin_number = try q[0].uint(u64);
        }
        g.skip = try q[2].uint(u64);
        g.reverse = (try q[3].uint(u64)) != 0;
        return g;
    }
};

/// rlp[reqId, [headerRLP, ...]] — headers carried as decoded block.Header.
pub fn encodeBlockHeaders(a: std.mem.Allocator, request_id: u64, headers: []const block.Header) ![]u8 {
    var encoded: std.ArrayList([]const u8) = .empty;
    defer {
        for (encoded.items) |e| a.free(e);
        encoded.deinit(a);
    }
    for (headers) |*h| try encoded.append(a, try h.encode(a));
    const list = try rlp.encodeList(a, encoded.items);
    defer a.free(list);
    const fields = [_][]const u8{ try rlp.encodeUint(a, request_id), list };
    defer a.free(fields[0]);
    return rlp.encodeList(a, &fields);
}

/// Returns the request id and the decoded headers (caller owns the slice).
pub fn decodeBlockHeaders(a: std.mem.Allocator, payload: []const u8) !struct { request_id: u64, headers: []block.Header } {
    const item = try rlp.decode(a, payload);
    const f = try item.items();
    if (f.len < 2) return error.BadResponse;
    const hs = try f[1].items();
    const out = try a.alloc(block.Header, hs.len);
    errdefer a.free(out);
    for (hs, 0..) |hi, i| {
        const enc = try reencodeItem(a, hi);
        defer a.free(enc);
        out[i] = try block.headerFromRlp(a, enc);
    }
    return .{ .request_id = try f[0].uint(u64), .headers = out };
}

// ── GetBlockBodies / BlockBodies ─────────────────────────────────────────────
/// rlp[reqId, [hash, ...]]
pub fn encodeGetBlockBodies(a: std.mem.Allocator, request_id: u64, hashes: []const [32]u8) ![]u8 {
    var encoded: std.ArrayList([]const u8) = .empty;
    defer {
        for (encoded.items) |e| a.free(e);
        encoded.deinit(a);
    }
    for (hashes) |*h| try encoded.append(a, try rlp.encodeBytes(a, h));
    const list = try rlp.encodeList(a, encoded.items);
    defer a.free(list);
    const fields = [_][]const u8{ try rlp.encodeUint(a, request_id), list };
    defer a.free(fields[0]);
    return rlp.encodeList(a, &fields);
}

pub fn decodeGetBlockBodies(a: std.mem.Allocator, payload: []const u8) !struct { request_id: u64, hashes: [][32]u8 } {
    const item = try rlp.decode(a, payload);
    const f = try item.items();
    if (f.len < 2) return error.BadRequest;
    const hs = try f[1].items();
    const out = try a.alloc([32]u8, hs.len);
    errdefer a.free(out);
    for (hs, 0..) |hi, i| out[i] = try fixed(32, hi);
    return .{ .request_id = try f[0].uint(u64), .hashes = out };
}

// ── helpers ──────────────────────────────────────────────────────────────────
fn encodeU256(a: std.mem.Allocator, v: u256) ![]u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, v, .big);
    var start: usize = 0;
    while (start < 32 and buf[start] == 0) start += 1;
    return rlp.encodeBytes(a, buf[start..]);
}

fn decodeU256(item: rlp.Item) !u256 {
    const b = try item.bytes();
    if (b.len > 32) return error.Overflow;
    var buf: [32]u8 = std.mem.zeroes([32]u8);
    @memcpy(buf[32 - b.len ..], b);
    return std.mem.readInt(u256, &buf, .big);
}

fn fixed(comptime n: usize, item: rlp.Item) ![n]u8 {
    const b = try item.bytes();
    if (b.len != n) return error.BadField;
    var out: [n]u8 = undefined;
    @memcpy(&out, b);
    return out;
}

/// Re-encode a decoded RLP item back to bytes (to hand a header span to
/// block.headerFromRlp, which wants the full list encoding).
fn reencodeItem(a: std.mem.Allocator, item: rlp.Item) ![]u8 {
    switch (item) {
        .str => |s| return rlp.encodeBytes(a, s),
        .list => |xs| {
            var items: std.ArrayList([]const u8) = .empty;
            defer {
                for (items.items) |e| a.free(e);
                items.deinit(a);
            }
            for (xs) |x| try items.append(a, try reencodeItem(a, x));
            return rlp.encodeList(a, items.items);
        },
    }
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "status round-trips" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var bh: [32]u8 = undefined;
    @memset(&bh, 0xaa);
    var gh: [32]u8 = undefined;
    @memset(&gh, 0xbb);
    const s = Status{
        .version = ETH_VERSION,
        .network_id = 1,
        .total_difficulty = 0x1234_5678_9abc,
        .best_hash = bh,
        .genesis_hash = gh,
        .fork_hash = .{ 0xde, 0xad, 0xbe, 0xef },
        .fork_next = 0,
    };
    const enc = try s.encode(a);
    defer a.free(enc);
    const got = try Status.decode(a, enc);
    try testing.expectEqual(s.version, got.version);
    try testing.expectEqual(s.total_difficulty, got.total_difficulty);
    try testing.expectEqualSlices(u8, &s.best_hash, &got.best_hash);
    try testing.expectEqualSlices(u8, &s.fork_hash, &got.fork_hash);
}

test "get/return block headers round-trip with message framing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const req = GetBlockHeaders{ .request_id = 42, .origin_number = 1000, .amount = 64, .skip = 0, .reverse = false };
    const renc = try req.encode(a);
    defer a.free(renc);
    // frame it with the eth message id, then split back.
    const body = try frameBody(a, eth.get_block_headers, renc);
    defer a.free(body);
    const split = try splitMessage(body);
    try testing.expectEqual(@as(u64, eth.get_block_headers), split.id);
    const dr = try GetBlockHeaders.decode(a, split.payload);
    try testing.expectEqual(@as(u64, 42), dr.request_id);
    try testing.expectEqual(@as(u64, 1000), dr.origin_number);
    try testing.expectEqual(@as(u64, 64), dr.amount);

    // BlockHeaders response with two headers.
    var h0 = block.Header{ .number = 1000 };
    var h1 = block.Header{ .number = 1001 };
    h1.gas_limit = 30_000_000;
    const headers = [_]block.Header{ h0, h1 };
    const benc = try encodeBlockHeaders(a, 42, &headers);
    defer a.free(benc);
    const resp = try decodeBlockHeaders(a, benc);
    defer {
        for (resp.headers) |*h| a.free(h.extra_data);
        a.free(resp.headers);
    }
    try testing.expectEqual(@as(u64, 42), resp.request_id);
    try testing.expectEqual(@as(usize, 2), resp.headers.len);
    try testing.expectEqual(@as(u64, 1000), resp.headers[0].number);
    try testing.expectEqual(@as(u64, 1001), resp.headers[1].number);
    try testing.expectEqual(@as(u64, 30_000_000), resp.headers[1].gas_limit);
    _ = &h0;
    _ = &h1;
}

test "get block bodies round-trips" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var h1: [32]u8 = undefined;
    @memset(&h1, 0x11);
    var h2: [32]u8 = undefined;
    @memset(&h2, 0x22);
    const hashes = [_][32]u8{ h1, h2 };
    const enc = try encodeGetBlockBodies(a, 7, &hashes);
    defer a.free(enc);
    const got = try decodeGetBlockBodies(a, enc);
    defer a.free(got.hashes);
    try testing.expectEqual(@as(u64, 7), got.request_id);
    try testing.expectEqual(@as(usize, 2), got.hashes.len);
    try testing.expectEqualSlices(u8, &h1, &got.hashes[0]);
}
