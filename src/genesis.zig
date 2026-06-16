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

/// The fork-activation schedule from a genesis `config`. We target the Merge and
/// later, so only timestamp-activated forks are tracked; the chain is PoS.
pub const ForkSchedule = struct {
    chain_id: u64 = 1,
    shanghai_time: ?u64 = null,
    cancun_time: ?u64 = null,
    prague_time: ?u64 = null,
    osaka_time: ?u64 = null,

    /// The fork active at a given block timestamp (number-activated pre-Merge
    /// forks are out of scope; the baseline is Paris).
    pub fn forkAt(self: ForkSchedule, timestamp: u64) Fork {
        if (self.osaka_time) |t| if (timestamp >= t) return .osaka;
        if (self.prague_time) |t| if (timestamp >= t) return .prague;
        if (self.cancun_time) |t| if (timestamp >= t) return .cancun;
        if (self.shanghai_time) |t| if (timestamp >= t) return .shanghai;
        return .paris;
    }
};

pub const Genesis = struct {
    schedule: ForkSchedule,
    header: block.Header,
};

// ── hex helpers (geth genesis quantities are 0x-prefixed) ───────────────────
fn hU64(s: ?[]const u8) u64 {
    const v = s orelse return 0;
    const b = if (std.mem.startsWith(u8, v, "0x")) v[2..] else v;
    return std.fmt.parseInt(u64, b, 16) catch 0;
}
fn hU256(s: ?[]const u8) u256 {
    const v = s orelse return 0;
    const b = if (std.mem.startsWith(u8, v, "0x")) v[2..] else v;
    return std.fmt.parseInt(u256, b, 16) catch 0;
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
    const fork = sched.forkAt(timestamp);

    var h = block.Header{
        .coinbase = hFixed(20, jstr(obj, "coinbase")),
        .state_root = trie.stateRoot(a, st),
        .difficulty = hU256(jstr(obj, "difficulty")),
        .number = 0,
        .gas_limit = hU64(jstr(obj, "gasLimit")),
        .gas_used = 0,
        .timestamp = timestamp,
        .extra_data = hBytes(a, jstr(obj, "extraData")),
        .prev_randao = hFixed(32, jstr(obj, "mixHash")),
        .nonce = hFixed(8, jstr(obj, "nonce")),
    };
    // Fork-additive trailing fields (empty roots at genesis).
    if (fork.atLeast(.london)) h.base_fee_per_gas = hU256(jstr(obj, "baseFeePerGas"));
    if (fork.atLeast(.shanghai)) h.withdrawals_root = trie.EMPTY_TRIE_ROOT;
    if (fork.atLeast(.cancun)) {
        h.blob_gas_used = hU64(jstr(obj, "blobGasUsed"));
        h.excess_blob_gas = hU64(jstr(obj, "excessBlobGas"));
        h.parent_beacon_block_root = hFixed(32, jstr(obj, "parentBeaconBlockRoot"));
    }
    if (fork.atLeast(.prague)) h.requests_hash = EMPTY_REQUESTS_HASH;

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
    try testing.expectEqual(Fork.prague, g.schedule.forkAt(0));
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
