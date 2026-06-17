//! snap/1 protocol message codec — the state-range sync protocol geth offers
//! alongside eth/69 (see devp2p/caps/snap.md). This implements the wire
//! encoding for the requests a syncing node sends and decoding for the
//! responses it receives, plus the "slim" account body format.
//!
//! Accounts are transferred in a slim RLP form: `[nonce, balance, storageRoot,
//! codeHash]` where `storageRoot` is the empty string when it equals the empty
//! trie root and `codeHash` is the empty string when it equals keccak256("") —
//! saving 64 bytes per plain account.

const std = @import("std");
const rlp = @import("rlp.zig");
const trie = @import("trie.zig");
const crypto = @import("crypto.zig");

/// snap/1 message ids (offset by the negotiated capability base on the wire).
pub const snap = struct {
    pub const get_account_range = 0x00;
    pub const account_range = 0x01;
    pub const get_storage_ranges = 0x02;
    pub const storage_ranges = 0x03;
    pub const get_byte_codes = 0x04;
    pub const byte_codes = 0x05;
    pub const get_trie_nodes = 0x06;
    pub const trie_nodes = 0x07;
};

pub const EMPTY_CODE_HASH: [32]u8 = blk: {
    @setEvalBranchQuota(10000);
    var h: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash("", &h, .{});
    break :blk h;
};

/// Minimal big-endian RLP encoding of a u256 (empty string for zero).
fn rlpU256(a: std.mem.Allocator, v: u256) ![]u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, v, .big);
    var s: usize = 0;
    while (s < 32 and buf[s] == 0) s += 1;
    return rlp.encodeBytes(a, buf[s..]);
}

// ── slim account body ─────────────────────────────────────────────────────────

pub const Account = struct {
    nonce: u64,
    balance: u256,
    /// null ⇒ empty trie (no storage).
    storage_root: ?[32]u8 = null,
    /// null ⇒ empty code.
    code_hash: ?[32]u8 = null,

    /// RLP-encode the slim account body.
    pub fn encodeSlim(self: Account, a: std.mem.Allocator) ![]u8 {
        const sr: []const u8 = if (self.storage_root) |r| &r else &.{};
        const ch: []const u8 = if (self.code_hash) |h| &h else &.{};
        const items = [_][]const u8{
            try rlp.encodeUint(a, self.nonce),
            try rlpU256(a, self.balance),
            try rlp.encodeBytes(a, sr),
            try rlp.encodeBytes(a, ch),
        };
        return rlp.encodeList(a, &items);
    }

    /// Decode a slim account body; empty storageRoot/codeHash become the
    /// canonical empty-trie-root / empty-code-hash.
    pub fn decodeSlim(a: std.mem.Allocator, body: []const u8) !Account {
        const root = try rlp.decode(a, body);
        const f = try root.items();
        if (f.len < 4) return error.BadAccount;
        const sr = try f[2].bytes();
        const ch = try f[3].bytes();
        var acc: Account = .{ .nonce = try f[0].uint(u64), .balance = try f[1].uint(u256) };
        if (sr.len == 32) {
            var r: [32]u8 = undefined;
            @memcpy(&r, sr);
            acc.storage_root = r;
        } else acc.storage_root = trie.EMPTY_TRIE_ROOT;
        if (ch.len == 32) {
            var h: [32]u8 = undefined;
            @memcpy(&h, ch);
            acc.code_hash = h;
        } else acc.code_hash = EMPTY_CODE_HASH;
        return acc;
    }
};

// ── request encoders (what a syncing node sends) ──────────────────────────────

/// GetAccountRange (0x00): `[reqID, root, origin, limit, responseBytes]`.
pub fn encodeGetAccountRange(a: std.mem.Allocator, req_id: u64, root: [32]u8, origin: [32]u8, limit: [32]u8, response_bytes: u64) ![]u8 {
    const items = [_][]const u8{
        try rlp.encodeUint(a, req_id),
        try rlp.encodeBytes(a, &root),
        try rlp.encodeBytes(a, &origin),
        try rlp.encodeBytes(a, &limit),
        try rlp.encodeUint(a, response_bytes),
    };
    return rlp.encodeList(a, &items);
}

/// GetStorageRanges (0x02): `[reqID, root, [accountHashes], origin, limit, bytes]`.
pub fn encodeGetStorageRanges(a: std.mem.Allocator, req_id: u64, root: [32]u8, accounts: []const [32]u8, origin: []const u8, limit: []const u8, response_bytes: u64) ![]u8 {
    var acc_items = try a.alloc([]const u8, accounts.len);
    for (accounts, 0..) |h, i| acc_items[i] = try rlp.encodeBytes(a, &h);
    const items = [_][]const u8{
        try rlp.encodeUint(a, req_id),
        try rlp.encodeBytes(a, &root),
        try rlp.encodeList(a, acc_items),
        try rlp.encodeBytes(a, origin),
        try rlp.encodeBytes(a, limit),
        try rlp.encodeUint(a, response_bytes),
    };
    return rlp.encodeList(a, &items);
}

/// GetByteCodes (0x04): `[reqID, [hashes], bytes]`.
pub fn encodeGetByteCodes(a: std.mem.Allocator, req_id: u64, hashes: []const [32]u8, response_bytes: u64) ![]u8 {
    var hs = try a.alloc([]const u8, hashes.len);
    for (hashes, 0..) |h, i| hs[i] = try rlp.encodeBytes(a, &h);
    const items = [_][]const u8{
        try rlp.encodeUint(a, req_id),
        try rlp.encodeList(a, hs),
        try rlp.encodeUint(a, response_bytes),
    };
    return rlp.encodeList(a, &items);
}

/// snap/1 GetTrieNodes (0x06): request specific trie nodes by path under `root`.
/// Each path set is a list of paths: `[accountPath]` for an account-trie node, or
/// `[accountPath, slotPath, …]` for storage-trie nodes under that account (paths
/// are the raw nibble/compact byte strings). The heal phase uses this to re-fetch
/// nodes that changed as the pivot state root advanced during the range download.
pub fn encodeGetTrieNodes(a: std.mem.Allocator, req_id: u64, root: [32]u8, path_sets: []const []const []const u8, response_bytes: u64) ![]u8 {
    var sets = try a.alloc([]const u8, path_sets.len);
    for (path_sets, 0..) |ps, i| {
        var paths = try a.alloc([]const u8, ps.len);
        for (ps, 0..) |p, j| paths[j] = try rlp.encodeBytes(a, p);
        sets[i] = try rlp.encodeList(a, paths);
    }
    const items = [_][]const u8{
        try rlp.encodeUint(a, req_id),
        try rlp.encodeBytes(a, &root),
        try rlp.encodeList(a, sets),
        try rlp.encodeUint(a, response_bytes),
    };
    return rlp.encodeList(a, &items);
}

// ── response decoders (what a syncing node receives) ──────────────────────────

pub const AccountEntry = struct { hash: [32]u8, account: Account };

pub const AccountRange = struct {
    req_id: u64,
    accounts: []AccountEntry,
    proof: [][]const u8,
};

/// AccountRange (0x01): `[reqID, [[accHash, accBody], …], [proofNodes]]`.
pub fn decodeAccountRange(a: std.mem.Allocator, payload: []const u8) !AccountRange {
    const root = try rlp.decode(a, payload);
    const f = try root.items();
    if (f.len < 3) return error.BadAccountRange;
    const acc_list = try f[1].items();
    var accounts = try a.alloc(AccountEntry, acc_list.len);
    for (acc_list, 0..) |e, i| {
        const ef = try e.items();
        if (ef.len < 2) return error.BadAccountEntry;
        const hb = try ef[0].bytes();
        if (hb.len != 32) return error.BadAccountHash;
        // Re-encode the body item so decodeSlim can parse a standalone list.
        const body = try reencode(a, ef[1]);
        var ae: AccountEntry = .{ .hash = undefined, .account = try Account.decodeSlim(a, body) };
        @memcpy(&ae.hash, hb);
        accounts[i] = ae;
    }
    const proof = try decodeNodeList(a, f[2]);
    return .{ .req_id = try f[0].uint(u64), .accounts = accounts, .proof = proof };
}

pub const StorageSlot = struct { hash: [32]u8, data: []const u8 };

pub const StorageRanges = struct {
    req_id: u64,
    /// One slot list per requested account.
    slots: [][]StorageSlot,
    proof: [][]const u8,
};

/// StorageRanges (0x03): `[reqID, [[[slotHash, slotData], …], …], [proofNodes]]`.
pub fn decodeStorageRanges(a: std.mem.Allocator, payload: []const u8) !StorageRanges {
    const root = try rlp.decode(a, payload);
    const f = try root.items();
    if (f.len < 3) return error.BadStorageRanges;
    const outer = try f[1].items();
    var slots = try a.alloc([]StorageSlot, outer.len);
    for (outer, 0..) |acc_slots, i| {
        const sl = try acc_slots.items();
        var list = try a.alloc(StorageSlot, sl.len);
        for (sl, 0..) |s, j| {
            const sf = try s.items();
            if (sf.len < 2) return error.BadStorageSlot;
            const hb = try sf[0].bytes();
            if (hb.len != 32) return error.BadSlotHash;
            list[j] = .{ .hash = undefined, .data = try a.dupe(u8, try sf[1].bytes()) };
            @memcpy(&list[j].hash, hb);
        }
        slots[i] = list;
    }
    const proof = try decodeNodeList(a, f[2]);
    return .{ .req_id = try f[0].uint(u64), .slots = slots, .proof = proof };
}

/// ByteCodes (0x05): `[reqID, [code1, code2, …]]`.
pub fn decodeByteCodes(a: std.mem.Allocator, payload: []const u8) !struct { req_id: u64, codes: [][]const u8 } {
    const root = try rlp.decode(a, payload);
    const f = try root.items();
    if (f.len < 2) return error.BadByteCodes;
    return .{ .req_id = try f[0].uint(u64), .codes = try decodeNodeList(a, f[1]) };
}

/// snap/1 TrieNodes (0x07): the raw trie-node blobs the peer returned, in the
/// order requested. Verify each by keccak256 against the hash you asked for.
pub fn decodeTrieNodes(a: std.mem.Allocator, payload: []const u8) !struct { req_id: u64, nodes: [][]const u8 } {
    const root = try rlp.decode(a, payload);
    const f = try root.items();
    if (f.len < 2) return error.BadTrieNodes;
    return .{ .req_id = try f[0].uint(u64), .nodes = try decodeNodeList(a, f[1]) };
}

fn decodeNodeList(a: std.mem.Allocator, item: rlp.Item) ![][]const u8 {
    const list = try item.items();
    var out = try a.alloc([]const u8, list.len);
    for (list, 0..) |n, i| out[i] = try a.dupe(u8, try n.bytes());
    return out;
}

/// Re-encode a decoded RLP item back to its canonical bytes (used to feed a
/// nested account body to `decodeSlim`).
fn reencode(a: std.mem.Allocator, item: rlp.Item) ![]u8 {
    switch (item) {
        .str => |s| return rlp.encodeBytes(a, s),
        .list => |l| {
            var parts = try a.alloc([]const u8, l.len);
            for (l, 0..) |child, i| parts[i] = try reencode(a, child);
            return rlp.encodeList(a, parts);
        },
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────
const testing = std.testing;

test "slim account round-trip (plain + contract)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Plain account: empty storage + code → slim omits both.
    const plain: Account = .{ .nonce = 7, .balance = 1234567890123456789 };
    const enc = try plain.encodeSlim(a);
    const dec = try Account.decodeSlim(a, enc);
    try testing.expectEqual(@as(u64, 7), dec.nonce);
    try testing.expectEqual(@as(u256, 1234567890123456789), dec.balance);
    try testing.expectEqualSlices(u8, &trie.EMPTY_TRIE_ROOT, &dec.storage_root.?);
    try testing.expectEqualSlices(u8, &EMPTY_CODE_HASH, &dec.code_hash.?);

    // Contract: explicit storage root + code hash survive.
    var sr: [32]u8 = undefined;
    var ch: [32]u8 = undefined;
    for (&sr, 0..) |*b, i| b.* = @intCast(i);
    for (&ch, 0..) |*b, i| b.* = @intCast(255 - i);
    const contract: Account = .{ .nonce = 1, .balance = 0, .storage_root = sr, .code_hash = ch };
    const dec2 = try Account.decodeSlim(a, try contract.encodeSlim(a));
    try testing.expectEqualSlices(u8, &sr, &dec2.storage_root.?);
    try testing.expectEqualSlices(u8, &ch, &dec2.code_hash.?);
}

test "GetAccountRange encodes and re-decodes its fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var root: [32]u8 = undefined;
    for (&root, 0..) |*b, i| b.* = @intCast(i);
    const origin = std.mem.zeroes([32]u8);
    const limit: [32]u8 = @splat(0xff);
    const enc = try encodeGetAccountRange(a, 42, root, origin, limit, 1024);
    const d = try rlp.decode(a, enc);
    const f = try d.items();
    try testing.expectEqual(@as(u64, 42), try f[0].uint(u64));
    try testing.expectEqualSlices(u8, &root, try f[1].bytes());
    try testing.expectEqual(@as(u64, 1024), try f[4].uint(u64));
}

test "AccountRange decodes accounts + proof" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Build an AccountRange: 2 accounts, 1 proof node.
    var h0: [32]u8 = undefined;
    var h1: [32]u8 = undefined;
    for (&h0, 0..) |*b, i| b.* = @intCast(i);
    for (&h1, 0..) |*b, i| b.* = @intCast(i + 100);
    const body0 = try (Account{ .nonce = 1, .balance = 50 }).encodeSlim(a);
    const body1 = try (Account{ .nonce = 2, .balance = 99 }).encodeSlim(a);
    const e0 = try rlp.encodeList(a, &[_][]const u8{ try rlp.encodeBytes(a, &h0), body0 });
    const e1 = try rlp.encodeList(a, &[_][]const u8{ try rlp.encodeBytes(a, &h1), body1 });
    const accs = try rlp.encodeList(a, &[_][]const u8{ e0, e1 });
    const proof = try rlp.encodeList(a, &[_][]const u8{try rlp.encodeBytes(a, "proofnode")});
    const payload = try rlp.encodeList(a, &[_][]const u8{ try rlp.encodeUint(a, 7), accs, proof });

    const ar = try decodeAccountRange(a, payload);
    try testing.expectEqual(@as(u64, 7), ar.req_id);
    try testing.expectEqual(@as(usize, 2), ar.accounts.len);
    try testing.expectEqualSlices(u8, &h1, &ar.accounts[1].hash);
    try testing.expectEqual(@as(u256, 99), ar.accounts[1].account.balance);
    try testing.expectEqual(@as(usize, 1), ar.proof.len);
    try testing.expectEqualStrings("proofnode", ar.proof[0]);
}

test "GetTrieNodes encodes path sets; TrieNodes decodes blobs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root: [32]u8 = @splat(0xab);
    const acct_path = [_]u8{ 0x01, 0x23 };
    const slot_path = [_]u8{ 0x0a, 0xbc };
    const path_sets = [_][]const []const u8{
        &[_][]const u8{&acct_path}, // an account-trie node
        &[_][]const u8{ &acct_path, &slot_path }, // a storage-trie node under it
    };
    const req = try encodeGetTrieNodes(a, 7, root, &path_sets, 64 * 1024);
    // Re-decode the request envelope and check its shape.
    const it = try rlp.decode(a, req);
    const f = try it.items();
    try testing.expectEqual(@as(u64, 7), try f[0].uint(u64));
    try testing.expectEqualSlices(u8, &root, try f[1].bytes());
    try testing.expectEqual(@as(usize, 2), (try f[2].items()).len);

    // A TrieNodes response: [reqID, [node0, node1]].
    const nodes = [_][]const u8{
        try rlp.encodeBytes(a, "trie-node-blob-0"),
        try rlp.encodeBytes(a, "trie-node-blob-1"),
    };
    const resp_items = [_][]const u8{ try rlp.encodeUint(a, 7), try rlp.encodeList(a, &nodes) };
    const resp = try rlp.encodeList(a, &resp_items);
    const tn = try decodeTrieNodes(a, resp);
    try testing.expectEqual(@as(u64, 7), tn.req_id);
    try testing.expectEqual(@as(usize, 2), tn.nodes.len);
    try testing.expectEqualStrings("trie-node-blob-0", tn.nodes[0]);
}
