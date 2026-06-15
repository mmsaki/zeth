//! Modified Merkle-Patricia Trie — the structure that commits the world state,
//! storage, transactions and receipts to a single 32-byte root. Ported from
//! `ethereum/merkle_patricia_trie.py`.
//!
//! The trie is built only when a root is needed: keys are expanded to nibbles
//! (optionally keccak-hashed first, for "secured" tries), then recursively
//! patricialized into leaf / extension / branch nodes, each RLP-encoded and
//! hashed. Nodes whose encoding is < 32 bytes are inlined into their parent.

const std = @import("std");
const crypto = @import("crypto.zig");
const rlp = @import("rlp.zig");
const state_mod = @import("state.zig");

/// keccak256(rlp("")) — the root of an empty trie.
pub const EMPTY_TRIE_ROOT: [32]u8 = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

/// A key/value pair to commit. `key` is the raw (un-hashed) key; `value` is the
/// already-`encode_node`-ed value bytes (RLP of the account or storage value).
pub const KV = struct { key: []const u8, value: []const u8 };

/// A recursive RLP item: either a byte string or a list of items.
const Item = union(enum) {
    bytes: []const u8,
    list: []const Item,
};

const Entry = struct { key: []const u8, value: []const u8 }; // key is nibbles

/// Compute the trie root for `pairs`. When `secured`, keys are keccak-hashed
/// before being expanded to nibbles (state & storage tries are secured).
pub fn computeRoot(allocator: std.mem.Allocator, pairs: []const KV, secured: bool) [32]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var entries = a.alloc(Entry, pairs.len) catch @panic("oom");
    for (pairs, 0..) |kv, i| {
        const key_bytes: []const u8 = if (secured) blk: {
            const h = a.create([32]u8) catch @panic("oom");
            h.* = crypto.keccak256(kv.key);
            break :blk h;
        } else kv.key;
        entries[i] = .{ .key = bytesToNibbles(a, key_bytes), .value = kv.value };
    }

    const root_item = encodeSubtree(a, entries, 0);
    const encoded = rlpEncode(a, root_item);
    if (encoded.len < 32) return crypto.keccak256(encoded);
    // Otherwise the root node was already hashed down to 32 bytes.
    var out: [32]u8 = undefined;
    @memcpy(&out, root_item.bytes[0..32]);
    return out;
}

/// `encode_internal_node(patricialize(...))` fused into one pass: returns the
/// "Extended" value embedded in the parent — an inline node list, a 32-byte
/// hash, or empty bytes for an absent subtree.
fn encodeSubtree(a: std.mem.Allocator, entries: []const Entry, level: usize) Item {
    if (entries.len == 0) return .{ .bytes = "" };

    var unencoded: Item = undefined;
    if (entries.len == 1) {
        const e = entries[0];
        const items = a.alloc(Item, 2) catch @panic("oom");
        items[0] = .{ .bytes = compact(a, e.key[level..], true) };
        items[1] = .{ .bytes = e.value };
        unencoded = .{ .list = items };
    } else {
        // Longest nibble prefix shared by every key beyond `level`.
        const first = entries[0].key[level..];
        var prefix_len: usize = first.len;
        for (entries) |e| {
            prefix_len = @min(prefix_len, commonPrefix(first, e.key[level..]));
            if (prefix_len == 0) break;
        }

        if (prefix_len > 0) {
            const items = a.alloc(Item, 2) catch @panic("oom");
            items[0] = .{ .bytes = compact(a, entries[0].key[level .. level + prefix_len], false) };
            items[1] = encodeSubtree(a, entries, level + prefix_len);
            unencoded = .{ .list = items };
        } else {
            var buckets: [16]std.ArrayList(Entry) = undefined;
            for (&buckets) |*b| b.* = std.ArrayList(Entry).empty;
            var value: []const u8 = "";
            for (entries) |e| {
                if (e.key.len == level) {
                    value = e.value;
                } else {
                    buckets[e.key[level]].append(a, e) catch @panic("oom");
                }
            }
            const items = a.alloc(Item, 17) catch @panic("oom");
            for (0..16) |k| items[k] = encodeSubtree(a, buckets[k].items, level + 1);
            items[16] = .{ .bytes = value };
            unencoded = .{ .list = items };
        }
    }

    const encoded = rlpEncode(a, unencoded);
    if (encoded.len < 32) return unencoded;
    const h = a.create([32]u8) catch @panic("oom");
    h.* = crypto.keccak256(encoded);
    return .{ .bytes = h };
}

fn rlpEncode(a: std.mem.Allocator, item: Item) []u8 {
    switch (item) {
        .bytes => |b| return rlp.encodeBytes(a, b) catch @panic("oom"),
        .list => |items| {
            var parts = std.ArrayList([]const u8).empty;
            for (items) |child| parts.append(a, rlpEncode(a, child)) catch @panic("oom");
            return rlp.encodeList(a, parts.items) catch @panic("oom");
        },
    }
}

fn bytesToNibbles(a: std.mem.Allocator, bytes: []const u8) []u8 {
    const out = a.alloc(u8, 2 * bytes.len) catch @panic("oom");
    for (bytes, 0..) |b, i| {
        out[2 * i] = b >> 4;
        out[2 * i + 1] = b & 0x0F;
    }
    return out;
}

/// Hex-prefix encoding of a nibble list (with the leaf/extension flag).
fn compact(a: std.mem.Allocator, nibbles: []const u8, is_leaf: bool) []u8 {
    const flag: u8 = if (is_leaf) 2 else 0;
    const odd = nibbles.len % 2 == 1;
    const out = a.alloc(u8, nibbles.len / 2 + 1) catch @panic("oom");
    var idx: usize = 0;
    if (odd) {
        out[0] = 16 * (flag + 1) + nibbles[0];
        idx = 1;
    } else {
        out[0] = 16 * flag;
    }
    var o: usize = 1;
    while (idx < nibbles.len) : (idx += 2) {
        out[o] = 16 * nibbles[idx] + nibbles[idx + 1];
        o += 1;
    }
    return out;
}

fn commonPrefix(a: []const u8, b: []const u8) usize {
    var i: usize = 0;
    while (i < a.len and i < b.len and a[i] == b[i]) i += 1;
    return i;
}

// --- State / storage roots ---------------------------------------------------

/// Minimal big-endian encoding of a 256-bit integer (empty for zero).
fn minimalBytes(a: std.mem.Allocator, value: u256) []const u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, value, .big);
    var start: usize = 0;
    while (start < 32 and buf[start] == 0) start += 1;
    return a.dupe(u8, buf[start..]) catch @panic("oom");
}

/// Root of an account's storage trie (secured; zero values omitted).
pub fn storageRoot(allocator: std.mem.Allocator, storage: anytype) [32]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var pairs = std.ArrayList(KV).empty;
    var it = storage.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* == 0) continue;
        const key = a.alloc(u8, 32) catch @panic("oom");
        std.mem.writeInt(u256, key[0..32], e.key_ptr.*, .big);
        // encode_node(value) = rlp(value) for a U256 storage word.
        const val = rlp.encodeBytes(a, minimalBytes(a, e.value_ptr.*)) catch @panic("oom");
        pairs.append(a, .{ .key = key, .value = val }) catch @panic("oom");
    }
    return computeRoot(a, pairs.items, true);
}

/// World-state root: secured trie of address → RLP([nonce, balance,
/// storageRoot, codeHash]). Fully-empty accounts (EIP-161) are excluded.
pub fn stateRoot(allocator: std.mem.Allocator, st: *const state_mod.State) [32]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var pairs = std.ArrayList(KV).empty;
    var it = st.accounts.iterator();
    while (it.next()) |entry| {
        const acc = entry.value_ptr;
        if (acc.nonce == 0 and acc.balance == 0 and acc.code.len == 0) continue; // empty
        const s_root = storageRoot(a, acc.storage);
        const code_hash = crypto.keccak256(acc.code);

        const fields = a.alloc(Item, 4) catch @panic("oom");
        fields[0] = .{ .bytes = minimalBytes(a, acc.nonce) };
        fields[1] = .{ .bytes = minimalBytes(a, acc.balance) };
        fields[2] = .{ .bytes = a.dupe(u8, &s_root) catch @panic("oom") };
        fields[3] = .{ .bytes = a.dupe(u8, &code_hash) catch @panic("oom") };
        const account_rlp = rlpEncode(a, .{ .list = fields });

        const key = a.dupe(u8, &entry.key_ptr.*) catch @panic("oom");
        pairs.append(a, .{ .key = key, .value = account_rlp }) catch @panic("oom");
    }
    return computeRoot(a, pairs.items, true);
}

const testing = std.testing;

fn hex32(comptime s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "empty trie root" {
    try testing.expectEqual(EMPTY_TRIE_ROOT, computeRoot(testing.allocator, &.{}, false));
}

test "canonical yellow-paper vector" {
    // Non-secured trie of {doe:reindeer, dog:puppy, dogglesworth:cat}.
    const pairs = [_]KV{
        .{ .key = "doe", .value = "reindeer" },
        .{ .key = "dog", .value = "puppy" },
        .{ .key = "dogglesworth", .value = "cat" },
    };
    const expected = hex32("8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3");
    try testing.expectEqual(expected, computeRoot(testing.allocator, &pairs, false));
}

test "single secured entry differs from empty" {
    const pairs = [_]KV{.{ .key = "k", .value = "v" }};
    try testing.expect(!std.mem.eql(u8, &EMPTY_TRIE_ROOT, &computeRoot(testing.allocator, &pairs, true)));
}
