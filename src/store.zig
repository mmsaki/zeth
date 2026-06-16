//! Typed persistence layer over the append-only KV store (`db.zig`).
//!
//! Maps the node's durable objects onto KV records under single-byte table
//! prefixes:
//!   'h' ‖ hash(32)        → header RLP
//!   'b' ‖ hash(32)        → body RLP (txs ‖ ommers ‖ withdrawals)
//!   'r' ‖ hash(32)        → receipts RLP
//!   'n' ‖ number(8, BE)   → canonical block hash
//!   'a' ‖ address(20)     → account snapshot (see encodeAccount)
//!   'M'                   → chain head: hash(32) ‖ number(8, BE)
//!
//! State is stored as a flat per-account snapshot (account record carries its
//! own storage), which is simple and correct; a node that outgrows RAM would
//! move to a persistent trie node store, but the on-disk format here is a clean
//! starting point.

const std = @import("std");
const Db = @import("db.zig").Db;
const state_mod = @import("state.zig");
const Address = state_mod.Address;
const State = state_mod.State;

pub const Head = struct { hash: [32]u8, number: u64 };

pub const Store = struct {
    db: *Db,

    const HEAD_KEY = "M";

    pub fn init(db: *Db) Store {
        return .{ .db = db };
    }

    // ── blocks ───────────────────────────────────────────────────────────────
    pub fn putHeader(self: *Store, hash: [32]u8, rlp: []const u8) !void {
        var k: [33]u8 = undefined;
        try self.db.put(hashKey(&k, 'h', hash), rlp);
    }
    pub fn getHeader(self: *Store, a: std.mem.Allocator, hash: [32]u8) !?[]u8 {
        var k: [33]u8 = undefined;
        return self.db.get(a, hashKey(&k, 'h', hash));
    }
    pub fn putBody(self: *Store, hash: [32]u8, rlp: []const u8) !void {
        var k: [33]u8 = undefined;
        try self.db.put(hashKey(&k, 'b', hash), rlp);
    }
    pub fn getBody(self: *Store, a: std.mem.Allocator, hash: [32]u8) !?[]u8 {
        var k: [33]u8 = undefined;
        return self.db.get(a, hashKey(&k, 'b', hash));
    }
    pub fn putReceipts(self: *Store, hash: [32]u8, rlp: []const u8) !void {
        var k: [33]u8 = undefined;
        try self.db.put(hashKey(&k, 'r', hash), rlp);
    }
    pub fn getReceipts(self: *Store, a: std.mem.Allocator, hash: [32]u8) !?[]u8 {
        var k: [33]u8 = undefined;
        return self.db.get(a, hashKey(&k, 'r', hash));
    }

    pub fn setCanonical(self: *Store, number: u64, hash: [32]u8) !void {
        var k: [9]u8 = undefined;
        try self.db.put(numKey(&k, 'n', number), &hash);
    }
    pub fn getCanonical(self: *Store, a: std.mem.Allocator, number: u64) !?[32]u8 {
        var k: [9]u8 = undefined;
        const v = (try self.db.get(a, numKey(&k, 'n', number))) orelse return null;
        defer a.free(v);
        if (v.len != 32) return error.Corrupt;
        var out: [32]u8 = undefined;
        @memcpy(&out, v);
        return out;
    }

    // ── chain head ─────────────────────────────────────────────────────────
    pub fn setHead(self: *Store, hash: [32]u8, number: u64) !void {
        var buf: [40]u8 = undefined;
        @memcpy(buf[0..32], &hash);
        std.mem.writeInt(u64, buf[32..40], number, .big);
        try self.db.put(HEAD_KEY, &buf);
    }
    pub fn getHead(self: *Store, a: std.mem.Allocator) !?Head {
        const v = (try self.db.get(a, HEAD_KEY)) orelse return null;
        defer a.free(v);
        if (v.len != 40) return error.Corrupt;
        var h: Head = .{ .hash = undefined, .number = std.mem.readInt(u64, v[32..40], .big) };
        @memcpy(&h.hash, v[0..32]);
        return h;
    }

    // ── world state ──────────────────────────────────────────────────────────
    /// Write every account (with its storage and code) as a snapshot record.
    pub fn snapshotState(self: *Store, a: std.mem.Allocator, st: *const State) !void {
        var it = st.accounts.iterator();
        while (it.next()) |e| {
            const enc = try encodeAccount(a, e.value_ptr);
            defer a.free(enc);
            var k: [21]u8 = undefined;
            try self.db.put(addrKey(&k, 'a', e.key_ptr.*), enc);
        }
    }

    /// Rebuild `st` from the persisted account snapshots.
    pub fn loadState(self: *Store, a: std.mem.Allocator, st: *State) !void {
        var kit = self.db.keys();
        // Collect matching keys first — get() must not run while iterating the
        // index, and decoding mutates nothing in the db.
        var addrs: std.ArrayList(Address) = .empty;
        defer addrs.deinit(a);
        while (kit.next()) |k| {
            if (k.len == 21 and k[0] == 'a') {
                var addr: Address = undefined;
                @memcpy(&addr, k[1..21]);
                try addrs.append(a, addr);
            }
        }
        for (addrs.items) |addr| {
            var k: [21]u8 = undefined;
            const enc = (try self.db.get(a, addrKey(&k, 'a', addr))) orelse continue;
            defer a.free(enc);
            try decodeAccountInto(st, addr, enc);
        }
    }
};

// Key builders write `tag ‖ data` into a caller buffer and return the exact-
// length slice (the db copies the key, so the buffer need only live per-call).
fn hashKey(buf: *[33]u8, tag: u8, hash: [32]u8) []const u8 {
    buf[0] = tag;
    @memcpy(buf[1..33], &hash);
    return buf[0..33];
}
fn addrKey(buf: *[21]u8, tag: u8, addr: Address) []const u8 {
    buf[0] = tag;
    @memcpy(buf[1..21], &addr);
    return buf[0..21];
}
fn numKey(buf: *[9]u8, tag: u8, number: u64) []const u8 {
    buf[0] = tag;
    std.mem.writeInt(u64, buf[1..9], number, .big);
    return buf[0..9];
}

// account record: nonce(8,LE) ‖ balance(32,BE) ‖ codeLen(4,LE) ‖ code ‖
//                 [slot(32,BE) ‖ value(32,BE)]*
fn encodeAccount(a: std.mem.Allocator, acct: *const state_mod.Account) ![]u8 {
    const n_slots = acct.storage.count();
    const total = 8 + 32 + 4 + acct.code.len + n_slots * 64;
    const buf = try a.alloc(u8, total);
    errdefer a.free(buf);
    std.mem.writeInt(u64, buf[0..8], acct.nonce, .little);
    std.mem.writeInt(u256, buf[8..40], acct.balance, .big);
    std.mem.writeInt(u32, buf[40..44], @intCast(acct.code.len), .little);
    @memcpy(buf[44 .. 44 + acct.code.len], acct.code);
    var off: usize = 44 + acct.code.len;
    var it = acct.storage.iterator();
    while (it.next()) |e| {
        std.mem.writeInt(u256, buf[off..][0..32], e.key_ptr.*, .big);
        std.mem.writeInt(u256, buf[off + 32 ..][0..32], e.value_ptr.*, .big);
        off += 64;
    }
    return buf;
}

fn decodeAccountInto(st: *State, addr: Address, enc: []const u8) !void {
    if (enc.len < 44) return error.Corrupt;
    const nonce = std.mem.readInt(u64, enc[0..8], .little);
    const balance = std.mem.readInt(u256, enc[8..40], .big);
    const code_len = std.mem.readInt(u32, enc[40..44], .little);
    if (enc.len < 44 + code_len) return error.Corrupt;
    const code = enc[44 .. 44 + code_len];
    try st.setNonce(addr, nonce);
    try st.setBalance(addr, balance);
    if (code_len > 0) try st.setCode(addr, code);
    var off: usize = 44 + code_len;
    while (off + 64 <= enc.len) : (off += 64) {
        const slot = std.mem.readInt(u256, enc[off..][0..32], .big);
        const value = std.mem.readInt(u256, enc[off + 32 ..][0..32], .big);
        if (value != 0) try st.setStorage(addr, slot, value);
    }
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "store round-trips head, header, and state across reopen" {
    var threaded: std.Io.Threaded = undefined;
    threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const dir = "zeth-store-test";
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};

    var hash: [32]u8 = undefined;
    @memset(&hash, 0xab);
    var addr1: Address = undefined;
    @memset(&addr1, 0x11);
    var addr2: Address = undefined;
    @memset(&addr2, 0x22);

    {
        var db = try Db.open(testing.allocator, io, dir);
        defer db.close();
        var store = Store.init(&db);
        try store.putHeader(hash, "header-rlp-bytes");
        try store.setCanonical(7, hash);
        try store.setHead(hash, 7);

        var st = State.init(testing.allocator);
        defer st.deinit();
        try st.setBalance(addr1, 1000);
        try st.setNonce(addr1, 3);
        try st.setCode(addr1, &[_]u8{ 0x60, 0x00 });
        try st.setStorage(addr1, 1, 42);
        try st.setStorage(addr1, 2, 99);
        try st.setBalance(addr2, 7);
        try store.snapshotState(testing.allocator, &st);
    }
    {
        var db = try Db.open(testing.allocator, io, dir);
        defer db.close();
        var store = Store.init(&db);

        const head = (try store.getHead(testing.allocator)).?;
        try testing.expectEqual(@as(u64, 7), head.number);
        try testing.expectEqualSlices(u8, &hash, &head.hash);

        const hdr = (try store.getHeader(testing.allocator, hash)).?;
        defer testing.allocator.free(hdr);
        try testing.expectEqualStrings("header-rlp-bytes", hdr);

        const canon = (try store.getCanonical(testing.allocator, 7)).?;
        try testing.expectEqualSlices(u8, &hash, &canon);

        var st = State.init(testing.allocator);
        defer st.deinit();
        try store.loadState(testing.allocator, &st);
        try testing.expectEqual(@as(u256, 1000), st.balanceOf(addr1));
        try testing.expectEqual(@as(u64, 3), st.nonceOf(addr1));
        try testing.expectEqualSlices(u8, &[_]u8{ 0x60, 0x00 }, st.codeOf(addr1));
        try testing.expectEqual(@as(u256, 42), st.getStorage(addr1, 1));
        try testing.expectEqual(@as(u256, 99), st.getStorage(addr1, 2));
        try testing.expectEqual(@as(u256, 7), st.balanceOf(addr2));
    }
}
