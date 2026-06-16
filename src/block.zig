//! Block headers: the data structure, its RLP encoding, and the block hash.
//!
//! The header is the backbone of the node layer — `init` (genesis), `import`
//! (block ingestion), and the Engine API all hash and validate headers. Fields
//! are ordered exactly as the consensus encoding requires; the trailing fields
//! are fork-additive (London adds base fee, Shanghai withdrawals, Cancun the
//! blob-gas pair + parent beacon root, Prague the requests hash) and are encoded
//! only when present, so one struct covers every fork we target.

const std = @import("std");
const rlp = @import("rlp.zig");
const crypto = @import("crypto.zig");
const state_mod = @import("state.zig");
const trie = @import("trie.zig");
const vm = @import("vm.zig");
const Address = state_mod.Address;

/// keccak256(rlp([])) — the ommers hash of every post-Merge block (no uncles).
pub const EMPTY_OMMERS_HASH: [32]u8 = .{
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
};

pub const Header = struct {
    parent_hash: [32]u8 = std.mem.zeroes([32]u8),
    ommers_hash: [32]u8 = EMPTY_OMMERS_HASH,
    coinbase: Address = state_mod.zero_address,
    state_root: [32]u8 = std.mem.zeroes([32]u8),
    transactions_root: [32]u8 = trie.EMPTY_TRIE_ROOT,
    receipts_root: [32]u8 = trie.EMPTY_TRIE_ROOT,
    logs_bloom: [256]u8 = std.mem.zeroes([256]u8),
    difficulty: u256 = 0,
    number: u64 = 0,
    gas_limit: u64 = 0,
    gas_used: u64 = 0,
    timestamp: u64 = 0,
    extra_data: []const u8 = &.{},
    prev_randao: [32]u8 = std.mem.zeroes([32]u8), // a.k.a. mixHash
    nonce: [8]u8 = std.mem.zeroes([8]u8),
    // Fork-additive trailing fields (encoded iff non-null).
    base_fee_per_gas: ?u256 = null, // London
    withdrawals_root: ?[32]u8 = null, // Shanghai
    blob_gas_used: ?u64 = null, // Cancun
    excess_blob_gas: ?u64 = null, // Cancun
    parent_beacon_block_root: ?[32]u8 = null, // Cancun
    requests_hash: ?[32]u8 = null, // Prague

    /// RLP-encode the header (the consensus encoding). Caller owns the result.
    /// Intermediate field encodings are arena-scoped, so only the final byte
    /// string is allocated from `gpa`.
    pub fn encode(self: *const Header, gpa: std.mem.Allocator) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var items: std.ArrayList([]const u8) = .empty;
        try items.append(a, try rlp.encodeBytes(a, &self.parent_hash));
        try items.append(a, try rlp.encodeBytes(a, &self.ommers_hash));
        try items.append(a, try rlp.encodeBytes(a, &self.coinbase));
        try items.append(a, try rlp.encodeBytes(a, &self.state_root));
        try items.append(a, try rlp.encodeBytes(a, &self.transactions_root));
        try items.append(a, try rlp.encodeBytes(a, &self.receipts_root));
        try items.append(a, try rlp.encodeBytes(a, &self.logs_bloom));
        try items.append(a, try encodeQuantity(a, self.difficulty));
        try items.append(a, try rlp.encodeUint(a, self.number));
        try items.append(a, try rlp.encodeUint(a, self.gas_limit));
        try items.append(a, try rlp.encodeUint(a, self.gas_used));
        try items.append(a, try rlp.encodeUint(a, self.timestamp));
        try items.append(a, try rlp.encodeBytes(a, self.extra_data));
        try items.append(a, try rlp.encodeBytes(a, &self.prev_randao));
        try items.append(a, try rlp.encodeBytes(a, &self.nonce));
        if (self.base_fee_per_gas) |b| try items.append(a, try encodeQuantity(a, b));
        if (self.withdrawals_root) |w| try items.append(a, try rlp.encodeBytes(a, &w));
        if (self.blob_gas_used) |g| try items.append(a, try rlp.encodeUint(a, g));
        if (self.excess_blob_gas) |g| try items.append(a, try rlp.encodeUint(a, g));
        if (self.parent_beacon_block_root) |r| try items.append(a, try rlp.encodeBytes(a, &r));
        if (self.requests_hash) |r| try items.append(a, try rlp.encodeBytes(a, &r));
        const list = try rlp.encodeList(a, items.items);
        return gpa.dupe(u8, list);
    }

    /// The block hash: keccak256 of the RLP-encoded header.
    pub fn hash(self: *const Header, gpa: std.mem.Allocator) ![32]u8 {
        const enc = try self.encode(gpa);
        defer gpa.free(enc);
        return crypto.keccak256(enc);
    }
};

/// A decoded block body: its header plus the per-item encodings needed to
/// recompute the transactions and withdrawals roots.
pub const Block = struct {
    header: Header,
    /// EIP-2718 transaction encodings (legacy: RLP list; typed: type‖payload) —
    /// exactly the values stored in the transactions trie.
    transactions: []const []const u8,
    /// Raw RLP encodings of each withdrawal — the withdrawals-trie values.
    withdrawals: []const []const u8,
    has_withdrawals: bool,
    /// Ommer (uncle) headers — pre-Merge only; empty post-Merge.
    ommers: []const Header = &.{},
};

/// Decode a full block RLP (`[header, transactions, ommers, withdrawals?]`).
pub fn decodeBlock(a: std.mem.Allocator, raw: []const u8) !Block {
    const parts = try rlp.listSpans(a, raw);
    if (parts.len < 2) return error.InvalidBlock;
    const header = try headerFromRlp(a, parts[0]);

    // Transactions: a legacy tx's trie value is its raw list encoding; a typed
    // tx's is the byte-string *content* (type byte + payload), without the outer
    // RLP string framing.
    const tx_spans = try rlp.listSpans(a, parts[1]);
    var txs = try a.alloc([]const u8, tx_spans.len);
    for (tx_spans, 0..) |span, i| {
        const item = (try rlp.decodeItem(a, span)).item;
        txs[i] = switch (item) {
            .str => |s| s, // typed: inner type‖payload
            .list => span, // legacy: the list encoding itself
        };
    }

    // Ommers (uncle headers) live at index 2; decode each for block rewards.
    var ommers: []Header = &.{};
    if (parts.len >= 3) {
        const ommer_spans = try rlp.listSpans(a, parts[2]);
        ommers = try a.alloc(Header, ommer_spans.len);
        for (ommer_spans, 0..) |span, i| ommers[i] = try headerFromRlp(a, span);
    }

    var withdrawals: []const []const u8 = &.{};
    const has_w = parts.len >= 4;
    if (has_w) withdrawals = try rlp.listSpans(a, parts[3]);

    return .{ .header = header, .transactions = txs, .withdrawals = withdrawals, .has_withdrawals = has_w, .ommers = ommers };
}

/// Reconstruct a Header from its RLP encoding.
pub fn headerFromRlp(a: std.mem.Allocator, raw: []const u8) !Header {
    const item = try rlp.decode(a, raw);
    const f = try item.items();
    if (f.len < 15) return error.InvalidHeader;
    var h = Header{};
    h.parent_hash = try fixedField(32, f[0]);
    h.ommers_hash = try fixedField(32, f[1]);
    h.coinbase = try fixedField(20, f[2]);
    h.state_root = try fixedField(32, f[3]);
    h.transactions_root = try fixedField(32, f[4]);
    h.receipts_root = try fixedField(32, f[5]);
    h.logs_bloom = try fixedField(256, f[6]);
    h.difficulty = try f[7].uint(u256);
    h.number = try f[8].uint(u64);
    h.gas_limit = try f[9].uint(u64);
    h.gas_used = try f[10].uint(u64);
    h.timestamp = try f[11].uint(u64);
    h.extra_data = try f[12].bytes();
    h.prev_randao = try fixedField(32, f[13]);
    h.nonce = try fixedField(8, f[14]);
    if (f.len > 15) h.base_fee_per_gas = try f[15].uint(u256);
    if (f.len > 16) h.withdrawals_root = try fixedField(32, f[16]);
    if (f.len > 17) h.blob_gas_used = try f[17].uint(u64);
    if (f.len > 18) h.excess_blob_gas = try f[18].uint(u64);
    if (f.len > 19) h.parent_beacon_block_root = try fixedField(32, f[19]);
    if (f.len > 20) h.requests_hash = try fixedField(32, f[20]);
    return h;
}

fn fixedField(comptime N: usize, item: rlp.Item) ![N]u8 {
    const s = try item.bytes();
    if (s.len > N) return error.InvalidHeader;
    var out: [N]u8 = std.mem.zeroes([N]u8);
    @memcpy(out[N - s.len ..], s); // right-align (handles minimally-encoded fields)
    return out;
}

/// Root of an index-keyed trie (transactions, receipts, withdrawals): key =
/// rlp(i), value = the item's encoding. Not secured (keys used as-is).
pub fn orderedTrieRoot(gpa: std.mem.Allocator, values: []const []const u8) [32]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var pairs = a.alloc(trie.KV, values.len) catch @panic("oom");
    for (values, 0..) |v, i| {
        pairs[i] = .{ .key = rlp.encodeUint(a, @intCast(i)) catch @panic("oom"), .value = v };
    }
    return trie.computeRoot(a, pairs, false);
}

// ── Receipts ────────────────────────────────────────────────────────────────

/// A transaction receipt. `tx_type` is the EIP-2718 type (0 = legacy); typed
/// receipts are encoded as `type ‖ rlp(body)` and contribute that to the root.
pub const Receipt = struct {
    tx_type: u8,
    success: bool,
    cumulative_gas_used: u64,
    logs: []const vm.Log,
    /// Pre-Byzantium (before EIP-658), the receipt's first field is the
    /// intermediate post-transaction state root, not a status code. When set,
    /// it is encoded in place of `status`.
    post_state: ?[32]u8 = null,

    /// The receipt body RLP: `[status|postStateRoot, cumulativeGas, bloom, logs]`
    /// — a status code (0/1) from Byzantium (EIP-658) on, the post-transaction
    /// state root before that. For a typed receipt the caller prepends the type
    /// byte (see `encode`).
    fn bodyRlp(self: *const Receipt, a: std.mem.Allocator) ![]u8 {
        var log_items: std.ArrayList([]const u8) = .empty;
        for (self.logs) |lg| {
            var topics: std.ArrayList([]const u8) = .empty;
            for (lg.topics) |t| try topics.append(a, try rlp.encodeBytes(a, &t));
            const fields = [_][]const u8{
                try rlp.encodeBytes(a, &lg.address),
                try rlp.encodeList(a, topics.items),
                try rlp.encodeBytes(a, lg.data),
            };
            try log_items.append(a, try rlp.encodeList(a, &fields));
        }
        const bloom = logsBloom(self.logs);
        const status_or_root: []const u8 = if (self.post_state) |ps|
            try rlp.encodeBytes(a, &ps)
        else
            try rlp.encodeUint(a, if (self.success) 1 else 0);
        const body = [_][]const u8{
            status_or_root,
            try rlp.encodeUint(a, self.cumulative_gas_used),
            try rlp.encodeBytes(a, &bloom),
            try rlp.encodeList(a, log_items.items),
        };
        return rlp.encodeList(a, &body);
    }

    /// The receipt's trie value: legacy → body RLP; typed → `type ‖ body RLP`.
    pub fn encode(self: *const Receipt, a: std.mem.Allocator) ![]u8 {
        const body = try self.bodyRlp(a);
        if (self.tx_type == 0) return body;
        const out = try a.alloc(u8, 1 + body.len);
        out[0] = self.tx_type;
        @memcpy(out[1..], body);
        return out;
    }
};

/// The 2048-bit (256-byte) logs bloom over a set of logs: each log's address
/// and topics set three bits derived from its keccak hash (EIP/yellow-paper M3:2048).
pub fn logsBloom(logs: []const vm.Log) [256]u8 {
    var bloom = std.mem.zeroes([256]u8);
    for (logs) |lg| {
        addToBloom(&bloom, &lg.address);
        for (lg.topics) |t| addToBloom(&bloom, &t);
    }
    return bloom;
}

fn addToBloom(bloom: *[256]u8, item: []const u8) void {
    const h = crypto.keccak256(item);
    for ([_]usize{ 0, 2, 4 }) |i| {
        const bit: u16 = ((@as(u16, h[i]) << 8) | h[i + 1]) & 0x07FF;
        bloom[255 - (bit / 8)] |= @as(u8, 1) << @intCast(bit % 8);
    }
}

/// OR two blooms together (per-receipt blooms aggregate into the block bloom).
pub fn orBloom(acc: *[256]u8, other: [256]u8) void {
    for (acc, other) |*a, b| a.* |= b;
}

/// The receipts root: an index-keyed trie of each receipt's encoding.
pub fn receiptsRoot(gpa: std.mem.Allocator, receipts: []const Receipt) [32]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var values = a.alloc([]const u8, receipts.len) catch @panic("oom");
    for (receipts, 0..) |*r, i| values[i] = r.encode(a) catch @panic("oom");
    return orderedTrieRoot(a, values);
}

/// Encode a u256 as an RLP quantity (minimal big-endian, 0 → empty string).
pub fn encodeQuantity(a: std.mem.Allocator, value: u256) ![]u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, value, .big);
    var start: usize = 0;
    while (start < buf.len and buf[start] == 0) start += 1;
    return rlp.encodeBytes(a, buf[start..]);
}

const testing = std.testing;

test "mainnet genesis block hash" {
    // The canonical Ethereum mainnet genesis header — a fork-free correctness pin
    // for the base header encoding + keccak (no London/Shanghai/Cancun fields).
    var h = Header{
        .difficulty = 0x400000000,
        .gas_limit = 0x1388,
        .nonce = .{ 0, 0, 0, 0, 0, 0, 0, 0x42 },
    };
    _ = try std.fmt.hexToBytes(&h.state_root, "d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544");
    h.extra_data = &[_]u8{
        0x11, 0xbb, 0xe8, 0xdb, 0x4e, 0x34, 0x7b, 0x4e, 0x8c, 0x93, 0x7c, 0x1c, 0x83, 0x70, 0xe4, 0xb5,
        0xed, 0x33, 0xad, 0xb3, 0xdb, 0x69, 0xcb, 0xdb, 0x7a, 0x38, 0xe1, 0xe5, 0x0b, 0x1b, 0x82, 0xfa,
    };
    const got = try h.hash(testing.allocator);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
    try testing.expectEqualSlices(u8, &want, &got);
}
