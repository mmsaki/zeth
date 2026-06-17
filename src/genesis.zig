//! Genesis loading: parse a geth-format `genesis.json` (the format hive mounts
//! into the client via mapper.jq) into the initial world state and the genesis
//! block header. This is what `zeth init` runs, and it fixes the genesis block
//! hash the node reports.

const std = @import("std");
const block = @import("block.zig");
const state_mod = @import("state.zig");
const trie = @import("trie.zig");
const fork_mod = @import("fork.zig");
const Fork = fork_mod.Fork;
const State = state_mod.State;
const Address = state_mod.Address;

/// keccak/sha256 of empty — the EIP-7685 requests hash when there are no requests.
pub const EMPTY_REQUESTS_HASH: [32]u8 = .{
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

/// The fork-activation schedule from a genesis `config`: block-number activations
/// for pre-Merge forks, the merge point, and timestamp activations for post-Merge
/// forks.
pub const ForkSchedule = struct {
    chain_id: u64 = 1,
    // Block-activated (pre-Merge).
    homestead_block: ?u64 = null,
    tangerine_block: ?u64 = null, // eip150
    spurious_block: ?u64 = null, // eip158
    byzantium_block: ?u64 = null,
    constantinople_block: ?u64 = null,
    petersburg_block: ?u64 = null,
    istanbul_block: ?u64 = null,
    berlin_block: ?u64 = null,
    london_block: ?u64 = null,
    // The Merge (Paris): a block number (mergeNetsplitBlock) and/or TTD-passed.
    merge_block: ?u64 = null,
    merged_from_genesis: bool = false,
    // Timestamp-activated (post-Merge).
    shanghai_time: ?u64 = null,
    cancun_time: ?u64 = null,
    prague_time: ?u64 = null,
    osaka_time: ?u64 = null,

    /// The fork active at a given block number + timestamp. Timestamp forks
    /// (post-Merge) take precedence; otherwise the Merge gates Paris; otherwise
    /// the block-number activations select the pre-Merge fork (Frontier baseline).
    pub fn forkAt(self: ForkSchedule, number: u64, timestamp: u64) Fork {
        if (self.osaka_time) |t| if (timestamp >= t) return .osaka;
        if (self.prague_time) |t| if (timestamp >= t) return .prague;
        if (self.cancun_time) |t| if (timestamp >= t) return .cancun;
        if (self.shanghai_time) |t| if (timestamp >= t) return .shanghai;
        if (self.merged_from_genesis) return .paris;
        if (self.merge_block) |b| if (number >= b) return .paris;
        if (active(self.london_block, number)) return .london;
        if (active(self.berlin_block, number)) return .berlin;
        if (active(self.istanbul_block, number)) return .istanbul;
        if (active(self.petersburg_block, number)) return .petersburg;
        if (active(self.constantinople_block, number)) return .constantinople;
        if (active(self.byzantium_block, number)) return .byzantium;
        if (active(self.spurious_block, number)) return .spurious_dragon;
        if (active(self.tangerine_block, number)) return .tangerine_whistle;
        if (active(self.homestead_block, number)) return .homestead;
        return .frontier;
    }

    fn active(block_num: ?u64, number: u64) bool {
        return if (block_num) |b| number >= b else false;
    }
};

pub const Genesis = struct {
    schedule: ForkSchedule,
    header: block.Header,
};

// ── hex helpers (geth genesis quantities are 0x-prefixed) ───────────────────
// geth genesis quantity fields are `HexOrDecimal` — `0x`-prefixed values are
// base-16, everything else is base-10 (e.g. `timestamp` and `alloc` balances
// are commonly decimal).
fn hU64(s: ?[]const u8) u64 {
    const v = s orelse return 0;
    if (std.mem.startsWith(u8, v, "0x")) return std.fmt.parseInt(u64, v[2..], 16) catch 0;
    return std.fmt.parseInt(u64, v, 10) catch 0;
}
fn hU256(s: ?[]const u8) u256 {
    const v = s orelse return 0;
    if (std.mem.startsWith(u8, v, "0x")) return std.fmt.parseInt(u256, v[2..], 16) catch 0;
    return std.fmt.parseInt(u256, v, 10) catch 0;
}
/// The 8-byte block nonce: a quantity, right-aligned big-endian (e.g. 0x1234 →
/// 00 00 00 00 00 00 12 34), unlike a fixed hash field.
fn nonceBytes(v: u64) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, v, .big);
    return out;
}
fn hFixed(comptime N: usize, s: ?[]const u8) [N]u8 {
    var out: [N]u8 = std.mem.zeroes([N]u8);
    if (s) |v| {
        const b = if (std.mem.startsWith(u8, v, "0x")) v[2..] else v;
        _ = std.fmt.hexToBytes(&out, b) catch {};
    }
    return out;
}
fn hBytes(a: std.mem.Allocator, s: ?[]const u8) []u8 {
    const v = s orelse return &.{};
    const b = if (std.mem.startsWith(u8, v, "0x")) v[2..] else v;
    const out = a.alloc(u8, b.len / 2) catch @panic("oom");
    _ = std.fmt.hexToBytes(out, b) catch {};
    return out;
}
fn jstr(o: std.json.ObjectMap, k: []const u8) ?[]const u8 {
    const v = o.get(k) orelse return null;
    return if (v == .string) v.string else null;
}
fn jU64(o: std.json.ObjectMap, k: []const u8) ?u64 {
    const v = o.get(k) orelse return null;
    return switch (v) {
        .integer => @intCast(v.integer),
        .string => hU64(v.string),
        else => null,
    };
}

/// Parse genesis JSON, populate `st` with the `alloc`, and return the genesis
/// header + fork schedule. `st` should be freshly initialized.
pub fn load(a: std.mem.Allocator, st: *State, root: std.json.Value) !Genesis {
    if (root != .object) return error.InvalidGenesis;
    const obj = root.object;

    var sched = ForkSchedule{};
    if (obj.get("config")) |c| if (c == .object) {
        const cfg = c.object;
        if (jU64(cfg, "chainId")) |id| sched.chain_id = id;
        // Block-activated pre-Merge forks.
        sched.homestead_block = jU64(cfg, "homesteadBlock");
        sched.tangerine_block = jU64(cfg, "eip150Block");
        sched.spurious_block = jU64(cfg, "eip158Block");
        sched.byzantium_block = jU64(cfg, "byzantiumBlock");
        sched.constantinople_block = jU64(cfg, "constantinopleBlock");
        sched.petersburg_block = jU64(cfg, "petersburgBlock");
        sched.istanbul_block = jU64(cfg, "istanbulBlock");
        sched.berlin_block = jU64(cfg, "berlinBlock");
        sched.london_block = jU64(cfg, "londonBlock");
        // The Merge. "merged from genesis" means the chain is post-Merge at
        // block 0 — i.e. a zero terminal total difficulty (geth's convention for
        // a merged genesis). A *non-zero* TTD means PoW until that difficulty is
        // reached, so it must NOT imply a merged genesis. Read TTD as a number
        // (it is a JSON integer here, which `jstr` would miss).
        sched.merge_block = jU64(cfg, "mergeNetsplitBlock");
        const ttd_is_zero: bool = if (cfg.get("terminalTotalDifficulty")) |v| switch (v) {
            .integer => v.integer == 0,
            .string => hU256(v.string) == 0,
            .number_string => |s| std.mem.eql(u8, s, "0"),
            else => false,
        } else false;
        const ttd_passed: bool = cfg.get("terminalTotalDifficultyPassed") != null and
            cfg.get("terminalTotalDifficultyPassed").? == .bool and cfg.get("terminalTotalDifficultyPassed").?.bool;
        sched.merged_from_genesis = ttd_is_zero or (ttd_passed and sched.merge_block == null);
        // Timestamp-activated post-Merge forks.
        sched.shanghai_time = jU64(cfg, "shanghaiTime");
        sched.cancun_time = jU64(cfg, "cancunTime");
        sched.prague_time = jU64(cfg, "pragueTime");
        sched.osaka_time = jU64(cfg, "osakaTime");
    };

    // World state from `alloc` (addr → balance / nonce / code / storage).
    if (obj.get("alloc")) |al| if (al == .object) {
        var it = al.object.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* != .object) continue;
            const addr = hFixed(20, e.key_ptr.*);
            const acc = e.value_ptr.object;
            try st.setBalance(addr, hU256(jstr(acc, "balance")));
            try st.setNonce(addr, hU64(jstr(acc, "nonce")));
            try st.setCode(addr, hBytes(a, jstr(acc, "code")));
            if (acc.get("storage")) |sto| if (sto == .object) {
                var sit = sto.object.iterator();
                while (sit.next()) |s| if (s.value_ptr.* == .string)
                    try st.setStorage(addr, hU256(s.key_ptr.*), hU256(s.value_ptr.string));
            };
        }
    };

    const timestamp = hU64(jstr(obj, "timestamp"));

    var h = block.Header{
        .coinbase = hFixed(20, jstr(obj, "coinbase")),
        .state_root = trie.stateRoot(a, st, false),
        .difficulty = hU256(jstr(obj, "difficulty")),
        .number = 0,
        .gas_limit = hU64(jstr(obj, "gasLimit")),
        .gas_used = hU64(jstr(obj, "gasUsed")),
        .timestamp = timestamp,
        .extra_data = hBytes(a, jstr(obj, "extraData")),
        .prev_randao = hFixed(32, jstr(obj, "mixHash") orelse jstr(obj, "mixhash")),
        .nonce = nonceBytes(hU64(jstr(obj, "nonce"))),
    };
    // Fork-additive trailing fields. A literal value in the JSON (test fixtures)
    // is authoritative; otherwise a geth-style *config* genesis implies them from
    // the fork active at genesis (block 0), exactly as geth computes the genesis
    // header. (transactions/receipts roots default to empty.)
    const gfork = sched.forkAt(0, timestamp);
    if (jstr(obj, "baseFeePerGas")) |v|
        h.base_fee_per_gas = hU256(v)
    else if (gfork.atLeast(.london))
        h.base_fee_per_gas = 1_000_000_000; // EIP-1559 InitialBaseFee (1 gwei)
    if (jstr(obj, "withdrawalsRoot")) |v|
        h.withdrawals_root = hFixed(32, v)
    else if (gfork.atLeast(.shanghai))
        h.withdrawals_root = trie.EMPTY_TRIE_ROOT;
    if (jstr(obj, "blobGasUsed")) |v|
        h.blob_gas_used = hU64(v)
    else if (gfork.atLeast(.cancun))
        h.blob_gas_used = 0;
    if (jstr(obj, "excessBlobGas")) |v|
        h.excess_blob_gas = hU64(v)
    else if (gfork.atLeast(.cancun))
        h.excess_blob_gas = 0;
    if (jstr(obj, "parentBeaconBlockRoot")) |v|
        h.parent_beacon_block_root = hFixed(32, v)
    else if (gfork.atLeast(.cancun))
        h.parent_beacon_block_root = std.mem.zeroes([32]u8);
    if (jstr(obj, "requestsHash")) |v|
        h.requests_hash = hFixed(32, v)
    else if (gfork.atLeast(.prague)) {
        var r: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("", &r, .{}); // empty requests = sha256("")
        h.requests_hash = r;
    }

    return .{ .schedule = sched, .header = h };
}

const testing = std.testing;

test "load minimal genesis: alloc, schedule, header shape" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{
        \\  "config": { "chainId": 7, "shanghaiTime": 0, "cancunTime": 0, "pragueTime": 0 },
        \\  "coinbase": "0x0000000000000000000000000000000000000000",
        \\  "difficulty": "0x0",
        \\  "gasLimit": "0x1c9c380",
        \\  "timestamp": "0x0",
        \\  "extraData": "0x",
        \\  "baseFeePerGas": "0x7",
        \\  "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        \\  "blobGasUsed": "0x0",
        \\  "excessBlobGas": "0x0",
        \\  "parentBeaconBlockRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
        \\  "requestsHash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        \\  "alloc": {
        \\    "a94f5374fce5edbc8e2a8697c15331677e6ebf0b": { "balance": "0x09184e72a000" }
        \\  }
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
    defer parsed.deinit();
    var st = State.init(testing.allocator);
    defer st.deinit();
    const g = try load(a, &st, parsed.value);

    try testing.expectEqual(@as(u64, 7), g.schedule.chain_id);
    try testing.expectEqual(Fork.prague, g.schedule.forkAt(0, 0));
    try testing.expectEqual(@as(u64, 0), g.header.number);
    try testing.expectEqual(@as(?u256, 7), g.header.base_fee_per_gas);
    try testing.expect(g.header.withdrawals_root != null); // Shanghai+
    try testing.expect(g.header.requests_hash != null); // Prague+
    // The premine balance must be reflected in the genesis state.
    var addr: Address = undefined;
    _ = try std.fmt.hexToBytes(&addr, "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
    try testing.expectEqual(@as(u256, 0x09184e72a000), st.balanceOf(addr));
    // A non-empty state root was computed.
    try testing.expect(!std.mem.eql(u8, &g.header.state_root, &std.mem.zeroes([32]u8)));
}
