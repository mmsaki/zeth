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

/// Collect a Merkle-Patricia proof for `target` (the raw, pre-hash key) against
/// the trie built from `pairs`: the RLP encodings of every node on the path from
/// the root toward `target`, top-down. Works for both inclusion and exclusion
/// (the path simply ends where it diverges). Caller owns the returned slices
/// (allocated from `allocator`).
pub fn proveKey(allocator: std.mem.Allocator, pairs: []const KV, secured: bool, target: []const u8) [][]const u8 {
    var entries = allocator.alloc(Entry, pairs.len) catch @panic("oom");
    defer allocator.free(entries);
    for (pairs, 0..) |kv, i| {
        const key_bytes: []const u8 = if (secured) blk: {
            const h = allocator.create([32]u8) catch @panic("oom");
            h.* = crypto.keccak256(kv.key);
            break :blk h;
        } else kv.key;
        entries[i] = .{ .key = bytesToNibbles(allocator, key_bytes), .value = kv.value };
    }
    const target_key: []const u8 = if (secured) blk: {
        const h = allocator.create([32]u8) catch @panic("oom");
        h.* = crypto.keccak256(target);
        break :blk h;
    } else target;
    const target_nibbles = bytesToNibbles(allocator, target_key);

    var out = std.ArrayList([]const u8).empty;
    collectProof(allocator, entries, 0, target_nibbles, true, &out);
    return out.toOwnedSlice(allocator) catch @panic("oom");
}

/// Walk the trie toward `target`, appending the RLP of each node on the path
/// (the root is always included; deeper nodes only if their encoding is ≥32
/// bytes, matching how they are referenced — inlined nodes live inside parents).
fn collectProof(a: std.mem.Allocator, entries: []const Entry, level: usize, target: []const u8, is_root: bool, out: *std.ArrayList([]const u8)) void {
    if (entries.len == 0) return;

    // Reconstruct this node exactly as encodeSubtree would, then decide whether
    // it is a proof node (root, or referenced by hash) and which child to follow.
    if (entries.len == 1) {
        const node = nodeItem(a, entries, level);
        emitNode(a, node, is_root, out);
        return; // leaf — path ends
    }

    const first = entries[0].key[level..];
    var prefix_len: usize = first.len;
    for (entries) |e| {
        prefix_len = @min(prefix_len, commonPrefix(first, e.key[level..]));
        if (prefix_len == 0) break;
    }

    if (prefix_len > 0) {
        // Extension node.
        const node = nodeItem(a, entries, level);
        emitNode(a, node, is_root, out);
        // Follow only if the target shares this extension's prefix.
        const ext = entries[0].key[level .. level + prefix_len];
        if (target.len >= level + prefix_len and std.mem.eql(u8, target[level .. level + prefix_len], ext))
            collectProof(a, entries, level + prefix_len, target, false, out);
        return;
    }

    // Branch node.
    const node = nodeItem(a, entries, level);
    emitNode(a, node, is_root, out);
    if (target.len <= level) return; // target ends at this branch's value slot
    const nib = target[level];
    var bucket = std.ArrayList(Entry).empty;
    for (entries) |e| {
        if (e.key.len > level and e.key[level] == nib) bucket.append(a, e) catch @panic("oom");
    }
    if (bucket.items.len > 0) collectProof(a, bucket.items, level + 1, target, false, out);
}

/// The fully-expanded (unencoded) Item for the node covering `entries` at
/// `level`, mirroring encodeSubtree's node shapes but without the hash folding.
fn nodeItem(a: std.mem.Allocator, entries: []const Entry, level: usize) Item {
    if (entries.len == 1) {
        const e = entries[0];
        const items = a.alloc(Item, 2) catch @panic("oom");
        items[0] = .{ .bytes = compact(a, e.key[level..], true) };
        items[1] = .{ .bytes = e.value };
        return .{ .list = items };
    }
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
        return .{ .list = items };
    }
    var buckets: [16]std.ArrayList(Entry) = undefined;
    for (&buckets) |*b| b.* = std.ArrayList(Entry).empty;
    var value: []const u8 = "";
    for (entries) |e| {
        if (e.key.len == level) value = e.value else buckets[e.key[level]].append(a, e) catch @panic("oom");
    }
    const items = a.alloc(Item, 17) catch @panic("oom");
    for (0..16) |k| items[k] = encodeSubtree(a, buckets[k].items, level + 1);
    items[16] = .{ .bytes = value };
    return .{ .list = items };
}

/// Append `node`'s RLP to the proof if it would be referenced by hash (≥32
/// bytes) or it is the root (always included).
fn emitNode(a: std.mem.Allocator, node: Item, is_root: bool, out: *std.ArrayList([]const u8)) void {
    const encoded = rlpEncode(a, node);
    if (is_root or encoded.len >= 32) out.append(a, encoded) catch @panic("oom");
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
/// storageRoot, codeHash]). When `prune_empty` is set (EIP-161, Spurious
/// Dragon+), fully-empty accounts are excluded; before that fork an existing
/// empty account is kept in the trie.
pub fn stateRoot(allocator: std.mem.Allocator, st: *const state_mod.State, prune_empty: bool) [32]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var pairs = std.ArrayList(KV).empty;
    var it = st.accounts.iterator();
    while (it.next()) |entry| {
        const acc = entry.value_ptr;
        if (prune_empty and acc.nonce == 0 and acc.balance == 0 and acc.code.len == 0) continue; // empty
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

/// The RLP-encoded account leaf value: `[nonce, balance, storageRoot, codeHash]`.
/// This is the value `eth_getProof`'s account proof terminates in.
pub fn accountValueRlp(a: std.mem.Allocator, nonce: u64, balance: u256, storage_root: [32]u8, code_hash: [32]u8) []u8 {
    const fields = a.alloc(Item, 4) catch @panic("oom");
    fields[0] = .{ .bytes = minimalBytes(a, nonce) };
    fields[1] = .{ .bytes = minimalBytes(a, balance) };
    fields[2] = .{ .bytes = a.dupe(u8, &storage_root) catch @panic("oom") };
    fields[3] = .{ .bytes = a.dupe(u8, &code_hash) catch @panic("oom") };
    return rlpEncode(a, .{ .list = fields });
}

/// All (address → accountRLP) pairs of the world state, mirroring `stateRoot`.
fn statePairs(a: std.mem.Allocator, st: *const state_mod.State, prune_empty: bool) []KV {
    var pairs = std.ArrayList(KV).empty;
    var it = st.accounts.iterator();
    while (it.next()) |entry| {
        const acc = entry.value_ptr;
        if (prune_empty and acc.nonce == 0 and acc.balance == 0 and acc.code.len == 0) continue;
        const s_root = storageRoot(a, acc.storage);
        const code_hash = crypto.keccak256(acc.code);
        const key = a.dupe(u8, &entry.key_ptr.*) catch @panic("oom");
        pairs.append(a, .{ .key = key, .value = accountValueRlp(a, acc.nonce, acc.balance, s_root, code_hash) }) catch @panic("oom");
    }
    return pairs.items;
}

/// `eth_getProof` account proof: the MPT nodes from the state root to `address`.
pub fn accountProof(a: std.mem.Allocator, st: *const state_mod.State, prune_empty: bool, address: state_mod.Address) [][]const u8 {
    return proveKey(a, statePairs(a, st, prune_empty), true, &address);
}

/// `eth_getProof` storage proof: the MPT nodes from an account's storage root to
/// `key` within `storage` (the same map type `storageRoot` accepts).
pub fn storageProof(a: std.mem.Allocator, storage: anytype, key: u256) [][]const u8 {
    var pairs = std.ArrayList(KV).empty;
    var it = storage.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* == 0) continue;
        const k = a.alloc(u8, 32) catch @panic("oom");
        std.mem.writeInt(u256, k[0..32], e.key_ptr.*, .big);
        pairs.append(a, .{ .key = k, .value = rlp.encodeBytes(a, minimalBytes(a, e.value_ptr.*)) catch @panic("oom") }) catch @panic("oom");
    }
    var target: [32]u8 = undefined;
    std.mem.writeInt(u256, &target, key, .big);
    return proveKey(a, pairs.items, true, &target);
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

// --- proof verification (independent of the prover) -------------------------

/// Decode hex-prefix-compact bytes back to (nibbles, is_leaf).
fn compactDecode(a: std.mem.Allocator, b: []const u8) struct { nibbles: []u8, is_leaf: bool } {
    const flag = b[0] >> 4;
    const is_leaf = flag >= 2;
    const odd = (flag & 1) == 1;
    var nibs = std.ArrayList(u8).empty;
    if (odd) nibs.append(a, b[0] & 0x0F) catch @panic("oom");
    for (b[1..]) |byte| {
        nibs.append(a, byte >> 4) catch @panic("oom");
        nibs.append(a, byte & 0x0F) catch @panic("oom");
    }
    return .{ .nibbles = nibs.items, .is_leaf = is_leaf };
}

/// Verify an MPT proof from scratch: follow `key_nibbles` from the root through
/// the proof nodes (looked up by keccak hash, inline children followed directly)
/// and return the terminal value, or null for a valid exclusion proof.
fn verifyProof(a: std.mem.Allocator, root: [32]u8, proof: []const []const u8, key_nibbles: []const u8) ?[]const u8 {
    // Index proof nodes by hash.
    var by_hash = std.AutoHashMap([32]u8, rlp.Item).init(a);
    for (proof) |node| {
        const item = rlp.decode(a, node) catch return null;
        by_hash.put(crypto.keccak256(node), item) catch @panic("oom");
    }
    const root_item = by_hash.get(root) orelse return null;
    return followNode(a, &by_hash, root_item, key_nibbles, 0);
}

fn followRef(a: std.mem.Allocator, by_hash: *std.AutoHashMap([32]u8, rlp.Item), ref: rlp.Item, key: []const u8, idx: usize) ?[]const u8 {
    switch (ref) {
        .list => return followNode(a, by_hash, ref, key, idx), // inline node
        .str => |h| {
            if (h.len == 0) return null; // empty subtree → exclusion
            if (h.len != 32) return null;
            var hh: [32]u8 = undefined;
            @memcpy(&hh, h);
            const node = by_hash.get(hh) orelse return null;
            return followNode(a, by_hash, node, key, idx);
        },
    }
}

fn followNode(a: std.mem.Allocator, by_hash: *std.AutoHashMap([32]u8, rlp.Item), node: rlp.Item, key: []const u8, idx: usize) ?[]const u8 {
    const items = node.items() catch return null;
    if (items.len == 2) {
        const cd = compactDecode(a, items[0].bytes() catch return null);
        if (cd.is_leaf) {
            if (std.mem.eql(u8, key[idx..], cd.nibbles)) return items[1].bytes() catch null;
            return null;
        }
        if (idx + cd.nibbles.len > key.len) return null;
        if (!std.mem.eql(u8, key[idx .. idx + cd.nibbles.len], cd.nibbles)) return null;
        return followRef(a, by_hash, items[1], key, idx + cd.nibbles.len);
    }
    if (items.len == 17) {
        if (idx == key.len) return items[16].bytes() catch null;
        return followRef(a, by_hash, items[idx_nibble(key, idx)], key, idx + 1);
    }
    return null;
}

fn idx_nibble(key: []const u8, idx: usize) usize {
    return key[idx];
}

// --- snap/1 range-proof verification ----------------------------------------

fn keyLess(x: [32]u8, y: [32]u8) bool {
    return std.mem.order(u8, &x, &y) == .lt;
}

pub const RangeError = error{ RangeInvalid, RangeUnsupported };

/// Verify a snap/1 account/storage range proof against `root` (the analogue of
/// geth's `trie.VerifyRangeProof`). `keys` are the sorted 32-byte, already-hashed
/// leaf keys of the returned range and `values` their encoded bodies; `proof` is
/// the boundary proof nodes the peer sent. Returns true iff the leaves are
/// exactly the trie's slice for that range — i.e. the downloaded data is
/// trustworthy under `root`.
///
/// COVERAGE (increment 1, fully unit-tested below) — the two SOUND cases a real
/// snap sync already hits:
///   • empty proof  → the leaves ARE the whole (sub)trie: rebuild + compare root.
///   • single key   → a degenerate range == an inclusion proof (verifyProof).
/// The general BOUNDED case (reconstruct a sparse trie from the two boundary
/// proofs, prune the interior, re-insert the leaves, recompute the root, and
/// report whether more elements exist to the right) is the next increment; it
/// returns error.RangeUnsupported rather than ever returning a wrong answer.
pub fn verifyRangeProof(
    a: std.mem.Allocator,
    root: [32]u8,
    origin: [32]u8,
    keys: []const [32]u8,
    values: []const []const u8,
    proof: []const []const u8,
) RangeError!bool {
    if (keys.len != values.len) return error.RangeInvalid;
    // Keys must be strictly increasing (sorted, no duplicates).
    var i: usize = 1;
    while (i < keys.len) : (i += 1) {
        if (!keyLess(keys[i - 1], keys[i])) return error.RangeInvalid;
    }

    // Case 1 — no boundary proof: the leaves are the entire (sub)trie.
    if (proof.len == 0) {
        if (keys.len == 0) return std.mem.eql(u8, &root, &EMPTY_TRIE_ROOT);
        const pairs = a.alloc(KV, keys.len) catch @panic("oom");
        for (0..keys.len) |j| pairs[j] = .{ .key = keys[j][0..], .value = values[j] };
        const got = computeRoot(a, pairs, false); // keys already hashed → unsecured
        return std.mem.eql(u8, &got, &root);
    }

    // Case 2 — single key whose left boundary is itself: a degenerate range is
    // just an inclusion proof. (When `origin` is strictly to the left — snap's
    // usual exclusion boundary — fall through to the bounded reconstruction.)
    if (keys.len == 1 and std.mem.eql(u8, &origin, &keys[0])) {
        const got = verifyProof(a, root, proof, bytesToNibbles(a, keys[0][0..]));
        return if (got) |val| std.mem.eql(u8, val, values[0]) else error.RangeInvalid;
    }

    // General bounded case — sparse-trie reconstruction (geth VerifyRangeProof).
    // The LEFT edge is the requested `origin` (usually an exclusion boundary,
    // i.e. lastKey+1 from the prior chunk, not an actual key); the RIGHT edge is
    // the last returned key.
    const first = bytesToNibblesTerm(a, origin[0..], true); // hex path, terminated (geth keybytesToHex)
    const last = bytesToNibblesTerm(a, keys[keys.len - 1][0..], true);

    // Index proof nodes by hash, then reconstruct the two edge paths.
    var by_hash = std.AutoHashMap([32]u8, rlp.Item).init(a);
    for (proof) |node| {
        const item = rlp.decode(a, node) catch return error.RangeInvalid;
        by_hash.put(crypto.keccak256(node), item) catch @panic("oom");
    }
    var rootn = proofToPath(a, &by_hash, root, .nil, first);
    if (rootn == .nil) return error.RangeInvalid;
    rootn = proofToPath(a, &by_hash, root, rootn, last);

    // Remove everything strictly between the two edges, then re-insert the leaves.
    const emptied = unsetInternal(a, &rootn, first, last) catch return error.RangeInvalid;
    if (emptied) rootn = .nil;
    for (0..keys.len) |j| {
        const path = bytesToNibblesTerm(a, keys[j][0..], true); // with leaf terminator
        rootn = insertRN(a, rootn, path, values[j]);
    }
    const got = rootHashOf(a, rootn);
    return std.mem.eql(u8, &got, &root);
}

// --- mutable sparse trie used only by verifyRangeProof -----------------------

const TERM: u8 = 16; // hex-path leaf terminator nibble

const RNode = union(enum) {
    nil,
    hash: [32]u8,
    value: []const u8,
    short: *RShort,
    full: *RFull,
};
const RShort = struct { key: []u8, val: RNode }; // key in nibbles; leaf iff key ends in TERM
const RFull = struct { ch: [17]RNode }; // ch[16] = value slot

fn bytesToNibblesTerm(a: std.mem.Allocator, bytes: []const u8, leaf: bool) []u8 {
    const base = bytesToNibbles(a, bytes);
    if (!leaf) return base;
    const out = a.alloc(u8, base.len + 1) catch @panic("oom");
    @memcpy(out[0..base.len], base);
    out[base.len] = TERM;
    return out;
}

fn isLeafKey(key: []const u8) bool {
    return key.len > 0 and key[key.len - 1] == TERM;
}

/// Decode a child-reference position of an RLP node into an RNode.
fn decodeRef(a: std.mem.Allocator, it: rlp.Item) RNode {
    switch (it) {
        .list => return decodeNodeItem(a, it),
        .str => |s| {
            if (s.len == 0) return .nil;
            if (s.len == 32) {
                var h: [32]u8 = undefined;
                @memcpy(&h, s);
                return .{ .hash = h };
            }
            return .nil;
        },
    }
}

/// Decode a full RLP node (2-item short or 17-item full) into an RNode.
fn decodeNodeItem(a: std.mem.Allocator, it: rlp.Item) RNode {
    const items = it.items() catch return .nil;
    if (items.len == 2) {
        const raw = items[0].bytes() catch return .nil;
        const cd = compactDecode(a, raw);
        const s = a.create(RShort) catch @panic("oom");
        if (cd.is_leaf) {
            const key = a.alloc(u8, cd.nibbles.len + 1) catch @panic("oom");
            @memcpy(key[0..cd.nibbles.len], cd.nibbles);
            key[cd.nibbles.len] = TERM;
            s.* = .{ .key = key, .val = .{ .value = items[1].bytes() catch "" } };
        } else {
            s.* = .{ .key = cd.nibbles, .val = decodeRef(a, items[1]) };
        }
        return .{ .short = s };
    }
    if (items.len == 17) {
        const f = a.create(RFull) catch @panic("oom");
        for (0..16) |k| f.ch[k] = decodeRef(a, items[k]);
        const v = items[16].bytes() catch "";
        f.ch[16] = if (v.len == 0) .nil else .{ .value = v };
        return .{ .full = f };
    }
    return .nil;
}

/// Resolve the trie nodes along `key` from the proof set, returning the root.
fn proofToPath(a: std.mem.Allocator, by_hash: *std.AutoHashMap([32]u8, rlp.Item), root_hash: [32]u8, existing: RNode, key: []const u8) RNode {
    var r = existing;
    if (r == .nil) {
        const it = by_hash.get(root_hash) orelse return .nil;
        r = decodeNodeItem(a, it);
    }
    resolvePath(a, by_hash, &r, key, 0);
    return r;
}

fn resolvePath(a: std.mem.Allocator, by_hash: *std.AutoHashMap([32]u8, rlp.Item), np: *RNode, key: []const u8, pos: usize) void {
    switch (np.*) {
        .short => |s| {
            if (isLeafKey(s.key)) return;
            if (pos + s.key.len > key.len) return;
            if (!std.mem.eql(u8, key[pos .. pos + s.key.len], s.key)) return;
            resolveChild(a, by_hash, &s.val, key, pos + s.key.len);
        },
        .full => |f| {
            if (pos >= key.len) return;
            resolveChild(a, by_hash, &f.ch[key[pos]], key, pos + 1);
        },
        else => {},
    }
}

fn resolveChild(a: std.mem.Allocator, by_hash: *std.AutoHashMap([32]u8, rlp.Item), cp: *RNode, key: []const u8, pos: usize) void {
    switch (cp.*) {
        .hash => |h| {
            if (by_hash.get(h)) |it| {
                cp.* = decodeNodeItem(a, it);
                resolvePath(a, by_hash, cp, key, pos);
            }
        },
        .short, .full => resolvePath(a, by_hash, cp, key, pos),
        else => {},
    }
}

/// Compare edge path `edge[pos..]` against a short node's `key` (bounded to the
/// key length), as geth does: -1 if the edge sorts before the key, 0 equal, +1 after.
fn cmpAt(edge: []const u8, pos: usize, key: []const u8) i8 {
    const slice = if (edge.len - pos < key.len) edge[pos..] else edge[pos .. pos + key.len];
    return switch (std.mem.order(u8, slice, key)) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

/// Nil the child of `parent` reached by nibble `idx` (parent is a full node at a
/// fork; the short-parent case can't arise for canonical tries but is handled).
fn nilChild(parent: *RNode, idx: u8) void {
    switch (parent.*) {
        .full => |f| f.ch[idx] = .nil,
        .short => |s| s.val = .nil,
        else => {},
    }
}

/// Remove every node strictly between the `left` and `right` edge paths (hex,
/// terminated). Faithful port of geth's trie.unsetInternal — walk to the fork
/// point, then handle the short-node (five scenarios) or full-node fork. Returns
/// true if the range spans the whole (sub)trie (caller resets the root to empty).
fn unsetInternal(a: std.mem.Allocator, np: *RNode, left: []const u8, right: []const u8) !bool {
    var pos: usize = 0;
    var parent: ?*RNode = null;
    var cur: *RNode = np;
    var sfl: i8 = 0; // short-fork indicator for the left edge
    var sfr: i8 = 0; // …and the right edge

    findfork: while (true) {
        switch (cur.*) {
            .short => |s| {
                sfl = cmpAt(left, pos, s.key);
                sfr = cmpAt(right, pos, s.key);
                if (sfl != 0 or sfr != 0) break :findfork; // fork is this short node
                parent = cur;
                pos += s.key.len;
                cur = &s.val;
            },
            .full => |f| {
                const ln = left[pos];
                const rn = right[pos];
                // Fork if the edges take different children, or either child is empty.
                if (ln != rn or f.ch[ln] == .nil or f.ch[rn] == .nil) break :findfork;
                parent = cur;
                pos += 1;
                cur = &f.ch[ln];
            },
            else => return error.RangeInvalid,
        }
    }

    switch (cur.*) {
        .short => |s| {
            if (sfl == -1 and sfr == -1) return error.RangeInvalid; // both proofs left of path
            if (sfl == 1 and sfr == 1) return error.RangeInvalid; // both right of path
            if (sfl != 0 and sfr != 0) {
                // Left proof less, right proof greater → unset the whole short node.
                if (parent == null) return true;
                nilChild(parent.?, left[pos - 1]);
                return false;
            }
            if (sfr != 0) {
                // Right proof diverges; left proof points at the short node.
                if (isLeafKey(s.key)) {
                    if (parent == null) return true;
                    nilChild(parent.?, left[pos - 1]);
                    return false;
                }
                unsetSide(a, &s.val, left, pos + s.key.len, false);
                return false;
            }
            if (sfl != 0) {
                // Left proof diverges; right proof points at the short node.
                if (isLeafKey(s.key)) {
                    if (parent == null) return true;
                    nilChild(parent.?, right[pos - 1]);
                    return false;
                }
                unsetSide(a, &s.val, right, pos + s.key.len, true);
                return false;
            }
            return false;
        },
        .full => |f| {
            const ln = left[pos];
            const rn = right[pos];
            var i: usize = @as(usize, ln) + 1;
            while (i < rn) : (i += 1) f.ch[i] = .nil; // clear children strictly between
            unsetSide(a, &f.ch[ln], left, pos + 1, false); // keep left edge, drop its right
            unsetSide(a, &f.ch[rn], right, pos + 1, true); // keep right edge, drop its left
            return false;
        },
        else => return error.RangeInvalid,
    }
}

/// Walk `key` down `np`; drop all branches to one side of the path. `dropLeft`
/// removes children with index < the path nibble (used on the right edge);
/// otherwise removes children with index > the path nibble (the left edge).
fn unsetSide(a: std.mem.Allocator, np: *RNode, key: []const u8, pos: usize, dropLeft: bool) void {
    switch (np.*) {
        .full => |f| {
            const k = key[pos];
            if (dropLeft) {
                var i: usize = 0;
                while (i < k) : (i += 1) f.ch[i] = .nil;
            } else {
                var i: usize = @as(usize, k) + 1;
                while (i < 16) : (i += 1) f.ch[i] = .nil;
                // (geth leaves the value slot untouched; for fixed-length snap keys
                // it's always empty anyway.)
            }
            unsetSide(a, &f.ch[k], key, pos + 1, dropLeft);
        },
        .short => |s| {
            if (isLeafKey(s.key)) {
                np.* = .nil; // the edge leaf itself is part of the range; re-inserted later
                return;
            }
            if (pos + s.key.len <= key.len and std.mem.eql(u8, key[pos .. pos + s.key.len], s.key)) {
                unsetSide(a, &s.val, key, pos + s.key.len, dropLeft);
            } else {
                // Diverging extension (a non-existent branch off the edge). Per geth
                // `unset`: drop it only if it lies *inside* the range, otherwise keep
                // it with its cached hash. Right edge (dropLeft): in range iff its key
                // sorts before the path; left edge: iff it sorts after.
                const ord = std.mem.order(u8, s.key, key[pos..]);
                const in_range = if (dropLeft) ord == .lt else ord == .gt;
                if (in_range) np.* = .nil;
            }
        },
        .hash, .value => np.* = .nil,
        .nil => {},
    }
}

/// Standard MPT insert of (hex `key` with terminator → `value`) into `node`.
fn insertRN(a: std.mem.Allocator, node: RNode, key: []const u8, value: []const u8) RNode {
    switch (node) {
        .nil => {
            const s = a.create(RShort) catch @panic("oom");
            s.* = .{ .key = a.dupe(u8, key) catch @panic("oom"), .val = .{ .value = value } };
            return .{ .short = s };
        },
        .short => |s| {
            const ml = commonPrefix(key, s.key);
            if (ml == s.key.len and isLeafKey(s.key)) {
                s.val = .{ .value = value }; // exact leaf overwrite
                return node;
            }
            if (ml == s.key.len and !isLeafKey(s.key)) {
                s.val = insertRN(a, s.val, key[ml..], value);
                return node;
            }
            // Split the short node at ml.
            const branch = a.create(RFull) catch @panic("oom");
            for (&branch.ch) |*c| c.* = .nil;
            placeRemainder(a, branch, s.key[ml..], s.val);
            placeRemainder(a, branch, key[ml..], .{ .value = value });
            if (ml == 0) return .{ .full = branch };
            const ext = a.create(RShort) catch @panic("oom");
            ext.* = .{ .key = a.dupe(u8, key[0..ml]) catch @panic("oom"), .val = .{ .full = branch } };
            return .{ .short = ext };
        },
        .full => |f| {
            f.ch[key[0]] = insertRN(a, f.ch[key[0]], key[1..], value);
            return node;
        },
        else => {
            // Overwriting a hash/value edge with a concrete leaf (range interior).
            const s = a.create(RShort) catch @panic("oom");
            s.* = .{ .key = a.dupe(u8, key) catch @panic("oom"), .val = .{ .value = value } };
            return .{ .short = s };
        },
    }
}

/// Attach `rest` (a key suffix) → `val` under `branch`, either at the value slot
/// (suffix is just the terminator) or as a short node at the suffix's first nibble.
fn placeRemainder(a: std.mem.Allocator, branch: *RFull, rest: []const u8, val: RNode) void {
    if (rest.len == 1 and rest[0] == TERM) {
        branch.ch[16] = val; // leaf value sits directly in the branch value slot
        return;
    }
    if (rest.len == 1) {
        // A single non-terminator nibble is fully consumed by the branch index:
        // the child attaches directly, not wrapped in an empty-key short node.
        branch.ch[rest[0]] = val;
        return;
    }
    const s = a.create(RShort) catch @panic("oom");
    s.* = .{ .key = a.dupe(u8, rest[1..]) catch @panic("oom"), .val = val };
    branch.ch[rest[0]] = .{ .short = s };
}

// --- hashing the mutable trie (mirrors encodeSubtree) ------------------------

fn rnRef(a: std.mem.Allocator, node: RNode) Item {
    switch (node) {
        .nil => return .{ .bytes = "" },
        .hash => |h| return .{ .bytes = a.dupe(u8, &h) catch @panic("oom") },
        .value => |v| return .{ .bytes = v },
        else => {
            const item = rnItem(a, node);
            const enc = rlpEncode(a, item);
            if (enc.len < 32) return item;
            const h = a.create([32]u8) catch @panic("oom");
            h.* = crypto.keccak256(enc);
            return .{ .bytes = h };
        },
    }
}

fn rnItem(a: std.mem.Allocator, node: RNode) Item {
    switch (node) {
        .short => |s| {
            const items = a.alloc(Item, 2) catch @panic("oom");
            if (isLeafKey(s.key)) {
                items[0] = .{ .bytes = compact(a, s.key[0 .. s.key.len - 1], true) };
                items[1] = rnRef(a, s.val);
            } else {
                items[0] = .{ .bytes = compact(a, s.key, false) };
                items[1] = rnRef(a, s.val);
            }
            return .{ .list = items };
        },
        .full => |f| {
            const items = a.alloc(Item, 17) catch @panic("oom");
            for (0..17) |k| items[k] = rnRef(a, f.ch[k]);
            return .{ .list = items };
        },
        .value => |v| return .{ .bytes = v },
        else => return .{ .bytes = "" },
    }
}

fn rootHashOf(a: std.mem.Allocator, node: RNode) [32]u8 {
    if (node == .nil) return EMPTY_TRIE_ROOT;
    const enc = rlpEncode(a, rnItem(a, node));
    return crypto.keccak256(enc);
}

test "range proof: empty proof rebuilds the whole trie" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    // Sorted, distinct 32-byte keys (snap keys are account/slot hashes).
    var keys: [4][32]u8 = undefined;
    var vals: [4][]const u8 = undefined;
    for (0..4) |j| {
        keys[j] = std.mem.zeroes([32]u8);
        keys[j][0] = @intCast((j + 1) * 16); // 0x10,0x20,0x30,0x40 → distinct root nibble
        vals[j] = "a-reasonably-long-account-body-value-exceeding-the-inline-threshold";
    }
    const pairs = al.alloc(KV, 4) catch unreachable;
    for (0..4) |j| pairs[j] = .{ .key = keys[j][0..], .value = vals[j] };
    const root = computeRoot(al, pairs, false);

    try testing.expect(try verifyRangeProof(al, root, keys[0], keys[0..], vals[0..], &.{}));
    // Tampering any value must be caught.
    vals[1] = "tampered-body";
    try testing.expect(!try verifyRangeProof(al, root, keys[0], keys[0..], vals[0..], &.{}));
    // Unsorted keys are rejected outright.
    const swapped = [_][32]u8{ keys[1], keys[0], keys[2], keys[3] };
    try testing.expectError(error.RangeInvalid, verifyRangeProof(al, root, swapped[0], swapped[0..], vals[0..], &.{}));
}

test "range proof: single key equals an inclusion proof" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var keys: [3][32]u8 = undefined;
    var vals: [3][]const u8 = undefined;
    for (0..3) |j| {
        keys[j] = std.mem.zeroes([32]u8);
        keys[j][0] = @intCast((j + 1) * 32);
        vals[j] = "value-body-long-enough-to-force-hashed-trie-nodes-xxxxxxxxxxxxxx";
    }
    const pairs = al.alloc(KV, 3) catch unreachable;
    for (0..3) |j| pairs[j] = .{ .key = keys[j][0..], .value = vals[j] };
    const root = computeRoot(al, pairs, false);

    const proof = proveKey(al, pairs, false, keys[1][0..]);
    try testing.expect(try verifyRangeProof(al, root, keys[1], keys[1..2], vals[1..2], proof));
    // Wrong value for the proven key → not verified.
    const badv = [_][]const u8{"wrong-value"};
    try testing.expect(!try verifyRangeProof(al, root, keys[1], keys[1..2], badv[0..], proof));
}

test "range proof: bounded range verifies and rejects tampering + gaps" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    // 8 sorted 32-byte keys, distinct root nibbles; values long enough to hash.
    var keys: [8][32]u8 = undefined;
    var vals: [8][]const u8 = undefined;
    for (0..8) |j| {
        keys[j] = std.mem.zeroes([32]u8);
        keys[j][0] = @intCast((j + 1) * 16);
        keys[j][1] = @intCast(j);
        vals[j] = "snap-account-body-value-long-enough-to-be-hashed-not-inlined-xxxx";
    }
    const pairs = al.alloc(KV, 8) catch unreachable;
    for (0..8) |j| pairs[j] = .{ .key = keys[j][0..], .value = vals[j] };
    const root = computeRoot(al, pairs, false);

    // Range covering keys 2..5, with boundary proofs of key 2 (origin) and key 5.
    const lo = 2;
    const hi = 5;
    var proof = std.ArrayList([]const u8).empty;
    for (proveKey(al, pairs, false, keys[lo][0..])) |n| proof.append(al, n) catch unreachable;
    for (proveKey(al, pairs, false, keys[hi][0..])) |n| proof.append(al, n) catch unreachable;

    // Honest range → verifies.
    try testing.expect(try verifyRangeProof(al, root, keys[lo], keys[lo .. hi + 1], vals[lo .. hi + 1], proof.items));
    // Tampered interior value → rejected.
    const tampered = [_][]const u8{ vals[2], "tampered-body", vals[4], vals[5] };
    try testing.expect(!try verifyRangeProof(al, root, keys[lo], keys[lo .. hi + 1], tampered[0..], proof.items));
    // Missing interior leaf (a gap the peer tried to hide) → rejected.
    const gapKeys = [_][32]u8{ keys[2], keys[4], keys[5] };
    const gapVals = [_][]const u8{ vals[2], vals[4], vals[5] };
    try testing.expect(!try verifyRangeProof(al, root, gapKeys[0], gapKeys[0..], gapVals[0..], proof.items));
}

test "proof verifies for included and excluded secured keys" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    // A secured trie of several 32-byte-ish keys → values.
    const pairs = [_]KV{
        .{ .key = "alpha", .value = "0xdeadbeef0000000000000000000000000000000000000000" },
        .{ .key = "beta", .value = "0x1122334455667788990011223344556677889900112233" },
        .{ .key = "gamma", .value = "value-of-gamma-which-is-reasonably-long-to-force-hashed-nodes" },
        .{ .key = "delta", .value = "another-long-enough-value-to-exceed-the-32-byte-inline-threshold" },
    };
    const root = computeRoot(al, &pairs, true);

    // Inclusion: prove "gamma" and recover its value.
    {
        const proof = proveKey(al, &pairs, true, "gamma");
        try testing.expect(proof.len > 0);
        const kh = crypto.keccak256("gamma");
        const recovered = verifyProof(al, root, proof, bytesToNibbles(al, &kh)) orelse return error.ProofFailed;
        try testing.expectEqualStrings("value-of-gamma-which-is-reasonably-long-to-force-hashed-nodes", recovered);
    }
    // Exclusion: a key not in the trie yields a proof that resolves to null.
    {
        const proof = proveKey(al, &pairs, true, "omega");
        const kh = crypto.keccak256("omega");
        try testing.expectEqual(@as(?[]const u8, null), verifyProof(al, root, proof, bytesToNibbles(al, &kh)));
    }
}

// Real geth snap/1 AccountRange fixture (devnet, origin=0x00..0).
// 53 accounts, 6 boundary-proof nodes. Drop into src/trie.zig tests.
test "range proof: real geth AccountRange (origin exclusion boundary)" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a); defer arena.deinit();
    const al = arena.allocator();
    const root = hex32("3b5fc7e6ce716d597716a6327ecfacff00dda2b692bc084d4f1ee3d3ad557559");
    const origin = hex32("0000000000000000000000000000000000000000000000000000000000000000");
    const keyhex = [_][]const u8{
        "005e54f1867fd030f90673b8b625ac8f0656e44a88cfc0b3af3e3f3c3d486960",
        "021fe3360ba8c02e194f8e7facdeb9088b3cf433b6498bd6900d50df0266ffe3",
        "028e62cb4665fce19ae1fc13a604618d7d20be037fc68b63beb3384dfa5ab776",
        "02cb51767354e1fe6bd4a49b64b3721ffddbc95fed1b8ead005c39bbc07bc4d8",
        "03089e01be9eb2af5ff5fa1c5983c6c6fb78dd734658d1f8f11d4f8d27a23fd5",
        "04242954a5cb9748d3f66bcd4583fd3830287aa585bebd9dd06fa6625976be49",
        "06339935111b4a563a28a91c253b638af868b3af7c372cab497cac4f6cb2c0aa",
        "06d9e4b9abc0b8978120d451eb4cca4f72ff1d97321713e0ef379a157b8f2b60",
        "07c57780db2d0b81258ad3be5df2c3a9e89e4c06bfaddc3a1f4e3b9401215947",
        "087fb108e6836a088e06156b1a26210d1f5284296b30b0bb0b3d1c2a7e01ac11",
        "08b3f9a96baba12f47430f2b0e2851f407e8ca355bb8a9a69242bc99aecc2cf3",
        "0999f18de77e9451867cb1935f9acd56f79cbc11d04826c3da6b420a4f4bbe21",
        "09af9e7ea2370ab3e3ee7f0a465a7dacb6c9b7e65196dc496d5570a0d8020bda",
        "0c3a3c99f34afe9d2c8cecc90524ef63afc9fc13384d5d931281f414d5d487c0",
        "0d21eb4f7c202eeccd6d87627f3d512e630d4d05578585847168758fd1aaed22",
        "0d6aea581b220579a2b99819299dd32c7c28a420018ecb0bde93af007ad89a31",
        "0e680db55aa4881318999b2ffdd5911cd03c063230c47468dbcb317ea52868a5",
        "0e8271a44c634b7fedcd00cb09afea2a70ac8380b6bf5f61ff07e793ee3f6d4c",
        "125adc67efe8bf6808c02bd3ae20262953b5e45dab4eb9386441cf6ec7381844",
        "127ec70ea0d8a7b6244ae7d951b2204f75336cf21f49df6370ab920534c95728",
        "1318a4c2bc731718857238ec2c42e4a95c0aeb7290a60c8abb110c2e638341c2",
        "13b8f5750961b5588bc69fbd0b701461854e110fd78c14767515bdd882725975",
        "1468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d",
        "15b381b518c6b754185d6903caf17b4f8dc30babfedf8072b118bbc3eec3013f",
        "15c53c582284ec93075084bae0536b5ab7ae44a44ee2718489b72be3aa78c3c7",
        "15fefe8613a1e673567aac83294fa0da6d048e5c7642227017441c9f899fed1b",
        "162386be0a525c5a9e6110c7244a375038c525fe102df224286161b1289bc716",
        "16a04d8ecc628ed1cba6df897e7502d86e83c941694e6671106159057d599d40",
        "18dcd435bf7d1820085f6c46d587cae669ca7c2d3ad4cea9db320a0b3c8bd21d",
        "1a6d9674aec5c8329252cb634022308bf4c98e70edec613d925ab781483445a4",
        "1d50131be868de2741cb775d0ff800631f96065f40b60845bce72e782718af23",
        "1e22733f173fbc95fa079ed50ec24c498a8aad2515d827e5ff8200c240e9cdc9",
        "1ebfd7dbb6804351804443df01a482e6451912b884cd26b31504bb77bbec9862",
        "1f99af2df2da9c0176bdb3e995bdfa47ffbfe6a3aacf8e54401f4dac2ece9338",
        "1ffff1a455b66d52107a26231feefb0f3565067e9544cf9470d975f01111b1cf",
        "2092b5602121cc484fa55b90cea0be17d931184263925a864e0d5d43a20d67b0",
        "20ebfef43639215aeb35e1e00bc96174f52155afb781659f34628d1f3f7ae018",
        "21120e1be03d384ee32a9bd7268578d8829f271540c848c97a495990bc48f582",
        "2139fa1aaa3d60e53d070d5a1f1ac9c8211f41b2dd5a1813416c8447a7759557",
        "21ea8bdf8a4ea6dc9e204591d88c3b5b19533d33bfbc59c08cca266c3c87a960",
        "2399321a0f2023dcaf15d6d7cd65c1996c7c3bc0b6b7c6e08b37c34386c3c4b7",
        "258487f1d48945c7743c412b0f026d722a4641d5978f11a0b44dbf7c1d274d41",
        "26dbcce1b599ebed46e2569579562031255ea9a1c1c575fdddb0003f4d389165",
        "291b6bbca879d684337ee5e2bca5d18cfb2d3b7a97c8187e703309564280295e",
        "297d3acffb942c7e6f3fb029b735338ac34e39c4ce9e852f64d50fb57cc97ec0",
        "2b7afbb14b4c902f37163b15f70fe8335dec4e26fbae4718c03f19da5aecbe8b",
        "2bd9aebde44794e6db317be6d83c5a266e1a96e18e04bc7073998bb779cfe2fe",
        "2d15e1e82ca50b7334be8990b93a8b043e771340cc9398baa23845763c696d22",
        "2df378e8ecee785e1d65200d738178432cbc9ad55c49ea5af905629d348416c2",
        "2f1b6a8f228675a171126d1781aeb52756d6fe5685af8c7ec23dc8187d783d1f",
        "300d2dbe83a6ba7fd75737c8d7453d984e7938ba7ae113d3da2ad7433061157b",
        "3019c0a91ba30d346a55890b1b07287d8aae35baa8c4068ef8f1de66084aca75",
        "3092dee2834b372effea65d7c74ab9f3ac60ef271e846721aa8759a346a3b554",
    };
    const valhex = [_][]const u8{
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8440180a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a078c6cb5202685228bbcbfb992b1c4e116c7ec5ef11e25b8e92716cfc628ddd60",
        "f850808c033b2e3c9fd0803ce8000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f850808c033b2e3c9fd0803ce8000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f850808c033b2e3c9fd0803ce8000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f850808c033b2e3c9fd0803ce8000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    };
    const proofhex = [_][]const u8{
        "f90211a0fcf8a530a63eb8575eb9a70c95332fc1047b567be3d1da03a21c9917d92b14a6a006d47616df479b46b302f2a8b7ed03cb537f6cf7c551c15421c65db4e00fa97fa038e34f9e0e4830343ba24f5fcf0eba28d79cb86397adfb16a0169ee7f0180036a0cd4de7b1ec974f644c007d6b01bc88e5f25456345d89229369f89cf1ceb7fbc2a08e75c0f5304caaa44a6cd3bf99b4a7ebc42cb98543378fe49a0ebcdbdb6a2ca9a0eea64374052ac460957bbc34a071cb8b25dcdf44d96785a55b34242914c83f9fa065b567b3746e3fbc22cfb8e08ea8197854acbd6e87d428cf02b103806ee59985a083c6979e463c02818ffeadaeeb8abc9f2f51e767fb9151a7fc89989eb40b57aca0cbcdc1d226a540c50cb1e615e7af99f171d4365b45734940e22d47ec4aa23a14a0be88e4724326382a8b56e2328eeef0ad51f18d5bae0e84296afe14c4028c4af9a018e0f191e57d4186717e0f3c9379d2438cec0babd12d3903a4ad560f017331bfa01796617427e67ed10cdf8a72b02689a700ba71eb93186a1b120c9ad0b0e56eaea0ad0bb86b47186c04223e85a9c33dd1c87dd6e5c17f753f4fd0a56772d8a78399a065fb94808e31ca248fb2d9de329b81735b22f75d109f389678c9965418bf1f16a06a2b50671c3f299bfd4b6cf43d6e5d6aafd4d3677c38a8af52a0cd7680de2b94a037ff00fbe2105bce0e6ed9ea80a1d67b8a476b1ff3d177ac9597a53241e47aa780",
        "f90171a046a9f1217c365990825b7d161fc23cae5688cfb6b2307efe4b732c723e03795880a0c0e0b54cb105bad41b4b925883507463ddfae71c619ba2e41d6d57da2a28effea0793c9db0e252f8f5c79a9d872efc5385ab632a9dc31217637b3509fcf6f0b010a077c059a2b360e9c967686a1302a40994cd63a81aa80a841991d8f3d7379b68eb80a0386a1e942dbe86342b17e2e8b28a259d6db65df8e05f944951a089bb9f3d989fa0315b6e4145b520b88ff5fb638b922671ee1ecbcb65b57b9a4be650ab1fce1d39a066e01acc8a9826bc3d5f5286819fc5883dfa30943331f1e7ff2968bfc57ea2d0a00f7041c0b666de2c820d816b27347738f0e8e2d4d7e1e94e2908b88bc3665a338080a012794aea34d39f220863a2977506ebe5555c2b6488a9469fed918b744f67d6d9a0ace6b45485050162428ffe70f5214d2350ed4890b94322bda3ba63a17342983aa0e20d629ffd2bee3848106f86b98c50a9de755283203bb778c19fa269c8ddb2e38080",
        "f869a0205e54f1867fd030f90673b8b625ac8f0656e44a88cfc0b3af3e3f3c3d486960b846f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f901b1a027db720cbe694541a361e08b5450894ddce39b11113fe952080ad5f54ada6f4a80a0d2e57f615a47508c6e60935353428b9fc1cc75677a3eb8f5f73d61dd0aaff5f5a0ca976997ddaf06f18992f6207e4f6a05979d07acead96568058789017cc6d06ba04d78166b48044fdc28ed22d2fd39c8df6f8aaa04cb71d3a17286856f6893ff8380a0fc3b71c33e2e6b77c5e494c1db7fdbb447473f003daf378c7a63ba9bf3f0049da0a8a574c661afe03c682e803d011ab7a421f7daa09b72be5595965d59f2469533a07b8e7a21c1178d28074f157b50fca85ee25c12568ff8e9706dcbcdacb77bf854a0973274526811393ea0bf4811ca9077531db00d06b86237a2ecd683f55ba4bcb0a091d9c76bfbc066e84f0b415c737ab8c477498701d920526db41690050cfade99a06aa67101d011d1c22fe739ef83b04b5214a3e2f8e1a2625d8bfdb116b447e86fa0244e4282dfec33c9bb765162ceee4f2e6390033a94b620d50a2fc6943ebd82fca0f3b039a4f32349e85c782d1164c1890e5bf16badc9ee4cf827db6afd2229dde6a0d9240a9d2d5851d05a97ff3305334dfdb0101e1e321fc279d2bb3cad6afa8fc88080",
        "f871a09e9f7450e306207e301c94b76bab54c21f41220e6dd06de7c944c5d50d91764ea046c75af76032283e7eb7d965e33e06e9aa9c93b7910409b4fd5ef84f3cce105080808080808080a0d6b2eb10ef6726a899495bd907a9ead634c511b2a445a8ee161b8f14fef42e8d80808080808080",
        "f8749f32dee2834b372effea65d7c74ab9f3ac60ef271e846721aa8759a346a3b554b852f850808c033b2e3c9fd0803ce8000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    };
    var keys: [keyhex.len][32]u8 = undefined;
    for (keyhex, 0..) |h, i| _ = std.fmt.hexToBytes(&keys[i], h) catch unreachable;
    var vals: [valhex.len][]const u8 = undefined;
    for (valhex, 0..) |h, i| { const b = al.alloc(u8, h.len/2) catch unreachable; _ = std.fmt.hexToBytes(b, h) catch unreachable; vals[i] = b; }
    var proof: [proofhex.len][]const u8 = undefined;
    for (proofhex, 0..) |h, i| { const b = al.alloc(u8, h.len/2) catch unreachable; _ = std.fmt.hexToBytes(b, h) catch unreachable; proof[i] = b; }
    // GOAL: this must return true once the bounded reconstruction handles
    // geth real proofs + the origin=0x00..0 exclusion boundary.
    try testing.expect(try verifyRangeProof(al, root, origin, keys[0..], vals[0..], proof[0..]));
}
