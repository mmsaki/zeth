//! EIP-7928 Block-Level Access Lists (BAL) + the Snap v2 roll-forward that replaces
//! snap/1 trie healing.
//!
//! snap/1 heals by iterative `GetTrieNodes` round-trips that race chain growth and
//! can stall for days (go-ethereum #23191, #25945, #27692). Snap v2 instead pivots
//! at HEAD-64, fetches the BALs for the ~64 post-pivot blocks (EIP-8159 / snap/2
//! `GetBlockAccessLists`), and rolls the flat state forward by applying each block's
//! post-execution diff — purely local, deterministic, bounded. This file is the
//! codec + the diff-extraction; `applyTo` rolls a SnapStore forward one block.
//!
//! BAL layout (EIP-7928, RLP):
//!   BlockAccessList = List[AccountChanges]
//!   AccountChanges  = [address(20), [SlotChanges…], [StorageKey…], [BalanceChange…],
//!                      [NonceChange…], [CodeChange…]]
//!   SlotChanges     = [StorageKey(u256), [StorageChange…]]
//!   StorageChange   = [BlockAccessIndex(u32), StorageValue(u256)]
//!   BalanceChange   = [BlockAccessIndex(u32), Balance(u256)]
//!   NonceChange     = [BlockAccessIndex(u32), Nonce(u64)]
//!   CodeChange      = [BlockAccessIndex(u32), Bytecode]
//! The header commits via `block_access_list_hash = keccak256(rlp(BAL))`.
const std = @import("std");
const rlp = @import("rlp.zig");
const crypto = @import("crypto.zig");

pub const Address = [20]u8;

/// keccak256(rlp(BAL)) of an empty list — the header commitment for an empty block.
pub const EMPTY_BAL_HASH: [32]u8 = blk: {
    @setEvalBranchQuota(10000);
    break :blk hexToBytes32("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
};

pub const StorageChange = struct { index: u32, value: u256 };
pub const SlotChanges = struct { slot: u256, changes: []StorageChange };
pub const BalanceChange = struct { index: u32, balance: u256 };
pub const NonceChange = struct { index: u32, nonce: u64 };
pub const CodeChange = struct { index: u32, code: []const u8 };

pub const AccountChanges = struct {
    address: Address,
    storage_changes: []SlotChanges,
    storage_reads: []u256,
    balance_changes: []BalanceChange,
    nonce_changes: []NonceChange,
    code_changes: []CodeChange,

    /// The post-block balance: the change with the highest BlockAccessIndex (the
    /// list is index-ascending, so the last entry). null if unchanged this block.
    pub fn finalBalance(self: AccountChanges) ?u256 {
        if (self.balance_changes.len == 0) return null;
        return self.balance_changes[self.balance_changes.len - 1].balance;
    }
    pub fn finalNonce(self: AccountChanges) ?u64 {
        if (self.nonce_changes.len == 0) return null;
        return self.nonce_changes[self.nonce_changes.len - 1].nonce;
    }
    pub fn finalCode(self: AccountChanges) ?[]const u8 {
        if (self.code_changes.len == 0) return null;
        return self.code_changes[self.code_changes.len - 1].code;
    }
};

pub const BlockAccessList = struct {
    accounts: []AccountChanges,

    /// The header commitment over the raw RLP body.
    pub fn commitment(body: []const u8) [32]u8 {
        return crypto.keccak256(body);
    }
};

const DecodeError = error{ MalformedBAL, OutOfMemory, NotAString, NotAList };

/// Read a big-endian (minimal, RLP-style) byte slice into an unsigned integer.
fn beInt(comptime T: type, b: []const u8) DecodeError!T {
    if (b.len > @sizeOf(T)) return error.MalformedBAL;
    var v: T = 0;
    for (b) |byte| v = (@as(T, v) << 8) | byte;
    return v;
}

/// Decode an EIP-7928 RLP BlockAccessList. Field ordering is assumed valid (the
/// caller has already checked the body against the header commitment).
pub fn decode(a: std.mem.Allocator, body: []const u8) DecodeError!BlockAccessList {
    const top = rlp.decode(a, body) catch return error.MalformedBAL;
    const accs = top.items() catch return error.MalformedBAL;
    const out = try a.alloc(AccountChanges, accs.len);
    for (accs, 0..) |acc_item, i| {
        const f = acc_item.items() catch return error.MalformedBAL;
        if (f.len != 6) return error.MalformedBAL;

        const addr_b = f[0].bytes() catch return error.MalformedBAL;
        if (addr_b.len != 20) return error.MalformedBAL;
        var address: Address = undefined;
        @memcpy(&address, addr_b);

        // storage_changes: List[ [slot, List[ [index, value] ]] ]
        const sc_items = f[1].items() catch return error.MalformedBAL;
        const storage_changes = try a.alloc(SlotChanges, sc_items.len);
        for (sc_items, 0..) |slot_item, j| {
            const sf = slot_item.items() catch return error.MalformedBAL;
            if (sf.len != 2) return error.MalformedBAL;
            const slot = try beInt(u256, sf[0].bytes() catch return error.MalformedBAL);
            const chg_items = sf[1].items() catch return error.MalformedBAL;
            const changes = try a.alloc(StorageChange, chg_items.len);
            for (chg_items, 0..) |ci, k| {
                const cf = ci.items() catch return error.MalformedBAL;
                if (cf.len != 2) return error.MalformedBAL;
                changes[k] = .{
                    .index = try beInt(u32, cf[0].bytes() catch return error.MalformedBAL),
                    .value = try beInt(u256, cf[1].bytes() catch return error.MalformedBAL),
                };
            }
            storage_changes[j] = .{ .slot = slot, .changes = changes };
        }

        // storage_reads: List[StorageKey]
        const sr_items = f[2].items() catch return error.MalformedBAL;
        const storage_reads = try a.alloc(u256, sr_items.len);
        for (sr_items, 0..) |ri, j| storage_reads[j] = try beInt(u256, ri.bytes() catch return error.MalformedBAL);

        // balance_changes: List[ [index, balance] ]
        const bc_items = f[3].items() catch return error.MalformedBAL;
        const balance_changes = try a.alloc(BalanceChange, bc_items.len);
        for (bc_items, 0..) |bi, j| {
            const bf = bi.items() catch return error.MalformedBAL;
            if (bf.len != 2) return error.MalformedBAL;
            balance_changes[j] = .{
                .index = try beInt(u32, bf[0].bytes() catch return error.MalformedBAL),
                .balance = try beInt(u256, bf[1].bytes() catch return error.MalformedBAL),
            };
        }

        // nonce_changes: List[ [index, nonce] ]
        const nc_items = f[4].items() catch return error.MalformedBAL;
        const nonce_changes = try a.alloc(NonceChange, nc_items.len);
        for (nc_items, 0..) |ni, j| {
            const nf = ni.items() catch return error.MalformedBAL;
            if (nf.len != 2) return error.MalformedBAL;
            nonce_changes[j] = .{
                .index = try beInt(u32, nf[0].bytes() catch return error.MalformedBAL),
                .nonce = try beInt(u64, nf[1].bytes() catch return error.MalformedBAL),
            };
        }

        // code_changes: List[ [index, bytecode] ]
        const cc_items = f[5].items() catch return error.MalformedBAL;
        const code_changes = try a.alloc(CodeChange, cc_items.len);
        for (cc_items, 0..) |ci, j| {
            const cf = ci.items() catch return error.MalformedBAL;
            if (cf.len != 2) return error.MalformedBAL;
            code_changes[j] = .{
                .index = try beInt(u32, cf[0].bytes() catch return error.MalformedBAL),
                .code = cf[1].bytes() catch return error.MalformedBAL,
            };
        }

        out[i] = .{
            .address = address,
            .storage_changes = storage_changes,
            .storage_reads = storage_reads,
            .balance_changes = balance_changes,
            .nonce_changes = nonce_changes,
            .code_changes = code_changes,
        };
    }
    return .{ .accounts = out };
}

fn hexToBytes32(comptime hex: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// --- encode (for fixtures/roundtrip; mirrors decode) -------------------------

fn encUint(a: std.mem.Allocator, comptime T: type, v: T) ![]u8 {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, v, .big);
    var i: usize = 0;
    while (i < buf.len and buf[i] == 0) : (i += 1) {} // strip leading zeros (minimal)
    return rlp.encodeBytes(a, buf[i..]);
}

pub fn encode(a: std.mem.Allocator, bal: BlockAccessList) ![]u8 {
    var accs: std.ArrayList([]const u8) = .empty;
    for (bal.accounts) |ac| {
        var sc: std.ArrayList([]const u8) = .empty;
        for (ac.storage_changes) |slot| {
            var chgs: std.ArrayList([]const u8) = .empty;
            for (slot.changes) |c| {
                const pair = [_][]const u8{ try encUint(a, u32, c.index), try encUint(a, u256, c.value) };
                try chgs.append(a, try rlp.encodeList(a, &pair));
            }
            const slot_list = [_][]const u8{ try encUint(a, u256, slot.slot), try rlp.encodeList(a, chgs.items) };
            try sc.append(a, try rlp.encodeList(a, &slot_list));
        }
        var sr: std.ArrayList([]const u8) = .empty;
        for (ac.storage_reads) |k| try sr.append(a, try encUint(a, u256, k));
        var bc: std.ArrayList([]const u8) = .empty;
        for (ac.balance_changes) |c| {
            const pair = [_][]const u8{ try encUint(a, u32, c.index), try encUint(a, u256, c.balance) };
            try bc.append(a, try rlp.encodeList(a, &pair));
        }
        var nc: std.ArrayList([]const u8) = .empty;
        for (ac.nonce_changes) |c| {
            const pair = [_][]const u8{ try encUint(a, u32, c.index), try encUint(a, u64, c.nonce) };
            try nc.append(a, try rlp.encodeList(a, &pair));
        }
        var cc: std.ArrayList([]const u8) = .empty;
        for (ac.code_changes) |c| {
            const pair = [_][]const u8{ try encUint(a, u32, c.index), try rlp.encodeBytes(a, c.code) };
            try cc.append(a, try rlp.encodeList(a, &pair));
        }
        const fields = [_][]const u8{
            try rlp.encodeBytes(a, &ac.address),
            try rlp.encodeList(a, sc.items),
            try rlp.encodeList(a, sr.items),
            try rlp.encodeList(a, bc.items),
            try rlp.encodeList(a, nc.items),
            try rlp.encodeList(a, cc.items),
        };
        try accs.append(a, try rlp.encodeList(a, &fields));
    }
    return rlp.encodeList(a, accs.items);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "empty BAL commitment matches the spec constant" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = try encode(arena.allocator(), .{ .accounts = &.{} });
    try testing.expectEqualSlices(u8, &EMPTY_BAL_HASH, &BlockAccessList.commitment(body));
}

test "BAL round-trips and exposes post-block final values" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var addr: Address = @splat(0xab);
    const storage = [_]SlotChanges{.{ .slot = 7, .changes = @constCast(&[_]StorageChange{
        .{ .index = 1, .value = 100 }, // tx 1 wrote 100
        .{ .index = 2, .value = 250 }, // tx 2 overwrote with 250 (the post-block value)
    }) }};
    const bal: BlockAccessList = .{ .accounts = @constCast(&[_]AccountChanges{.{
        .address = addr,
        .storage_changes = @constCast(&storage),
        .storage_reads = @constCast(&[_]u256{ 1, 2 }),
        .balance_changes = @constCast(&[_]BalanceChange{ .{ .index = 1, .balance = 5 }, .{ .index = 3, .balance = 9 } }),
        .nonce_changes = @constCast(&[_]NonceChange{.{ .index = 3, .nonce = 4 }}),
        .code_changes = @constCast(&[_]CodeChange{.{ .index = 0, .code = "PUSH1" }}),
    }}) };

    const body = try encode(a, bal);
    const got = try decode(a, body);

    try testing.expectEqual(@as(usize, 1), got.accounts.len);
    const ac = got.accounts[0];
    try testing.expectEqualSlices(u8, &addr, &ac.address);
    try testing.expectEqual(@as(u256, 9), ac.finalBalance().?); // highest-index balance
    try testing.expectEqual(@as(u64, 4), ac.finalNonce().?);
    try testing.expectEqualSlices(u8, "PUSH1", ac.finalCode().?);
    try testing.expectEqual(@as(u256, 7), ac.storage_changes[0].slot);
    // post-block slot value = last storage change (index-ascending)
    const last = ac.storage_changes[0].changes[ac.storage_changes[0].changes.len - 1];
    try testing.expectEqual(@as(u256, 250), last.value);
    try testing.expectEqual(@as(usize, 2), ac.storage_reads.len);
}
