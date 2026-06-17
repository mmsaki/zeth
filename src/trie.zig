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

    // Case 2 — single key: a degenerate range is just an inclusion proof.
    if (keys.len == 1) {
        const got = verifyProof(a, root, proof, bytesToNibbles(a, keys[0][0..]));
        return if (got) |val| std.mem.eql(u8, val, values[0]) else error.RangeInvalid;
    }

    // General bounded case — sparse-trie reconstruction. Next increment.
    return error.RangeUnsupported;
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

    try testing.expect(try verifyRangeProof(al, root, keys[0..], vals[0..], &.{}));
    // Tampering any value must be caught.
    vals[1] = "tampered-body";
    try testing.expect(!try verifyRangeProof(al, root, keys[0..], vals[0..], &.{}));
    // Unsorted keys are rejected outright.
    const swapped = [_][32]u8{ keys[1], keys[0], keys[2], keys[3] };
    try testing.expectError(error.RangeInvalid, verifyRangeProof(al, root, swapped[0..], vals[0..], &.{}));
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
    try testing.expect(try verifyRangeProof(al, root, keys[1..2], vals[1..2], proof));
    // Wrong value for the proven key → not verified.
    const badv = [_][]const u8{"wrong-value"};
    try testing.expect(!try verifyRangeProof(al, root, keys[1..2], badv[0..], proof));
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
