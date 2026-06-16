//! Transaction RLP decoding + sender recovery (EIP-2718 typed envelopes).
//!
//! The node ingests transactions as raw bytes — from `chain.rlp`, the Engine
//! API, or the txpool — so it must decode every type and recover the signer.
//! The state-transition layer (`tx.zig`) consumes the decoded fields. Covers
//! legacy (pre-155 / EIP-155), 0x01 (EIP-2930), 0x02 (EIP-1559), 0x03 (EIP-4844),
//! and 0x04 (EIP-7702).

const std = @import("std");
const rlp = @import("rlp.zig");
const crypto = @import("crypto.zig");
const state_mod = @import("state.zig");
const precompiles = @import("precompiles.zig");
const txmod = @import("tx.zig");
const Address = state_mod.Address;

pub const DecodeError = error{ Malformed, BadSignature, OutOfMemory };

/// A fully decoded, signature-recovered transaction. Fee fields are normalized:
/// legacy / 2930 set `max_fee == max_priority_fee == gas_price`.
pub const Authorization = txmod.Authorization;

pub const Transaction = struct {
    tx_type: u8,
    chain_id: ?u64 = null,
    nonce: u64,
    max_priority_fee: u256,
    max_fee: u256,
    gas_limit: u64,
    to: ?Address,
    value: u256,
    data: []const u8,
    access_list: []const txmod.AccessEntry = &.{},
    max_fee_per_blob_gas: u256 = 0,
    blob_versioned_hashes: []const [32]u8 = &.{},
    authorizations: []const Authorization = &.{},
    y_parity: u8 = 0,
    r: u256 = 0,
    s: u256 = 0,
    sender: Address = state_mod.zero_address,

    /// The effective gas price given a block `base_fee` (EIP-1559): for legacy /
    /// 2930 it's just gas_price; otherwise min(maxFee, baseFee + maxPriorityFee).
    pub fn effectiveGasPrice(self: *const Transaction, base_fee: u256) u256 {
        if (self.tx_type == 0 or self.tx_type == 1) return self.max_fee;
        return @min(self.max_fee, base_fee + self.max_priority_fee);
    }
};

/// Decode one transaction from its network/consensus encoding (legacy RLP list,
/// or `type ‖ rlp(payload)` for typed) and recover the sender.
pub fn decode(a: std.mem.Allocator, bytes: []const u8) DecodeError!Transaction {
    if (bytes.len == 0) return error.Malformed;
    if (bytes[0] >= 0xc0) return decodeLegacy(a, bytes); // RLP list → legacy
    return decodeTyped(a, bytes[0], bytes[1..]);
}

fn uintField(item: rlp.Item, comptime T: type) DecodeError!T {
    return item.uint(T) catch return error.Malformed;
}

fn bytesField(item: rlp.Item) DecodeError![]const u8 {
    return item.bytes() catch return error.Malformed;
}

fn addrField(item: rlp.Item) DecodeError!?Address {
    const s = try bytesField(item);
    if (s.len == 0) return null; // contract creation
    if (s.len != 20) return error.Malformed;
    var out: Address = undefined;
    @memcpy(&out, s);
    return out;
}

fn accessListField(a: std.mem.Allocator, item: rlp.Item) DecodeError![]const txmod.AccessEntry {
    const entries = item.items() catch return error.Malformed;
    var out = try a.alloc(txmod.AccessEntry, entries.len);
    for (entries, 0..) |e, i| {
        const pair = e.items() catch return error.Malformed;
        if (pair.len != 2) return error.Malformed;
        const addr = (try addrField(pair[0])) orelse return error.Malformed;
        const key_items = pair[1].items() catch return error.Malformed;
        var keys = try a.alloc(u256, key_items.len);
        for (key_items, 0..) |k, j| keys[j] = try uintField(k, u256);
        out[i] = .{ .address = addr, .keys = keys };
    }
    return out;
}

fn decodeLegacy(a: std.mem.Allocator, bytes: []const u8) DecodeError!Transaction {
    const item = rlp.decode(a, bytes) catch return error.Malformed;
    const f = item.items() catch return error.Malformed;
    if (f.len != 9) return error.Malformed;
    const gas_price = try uintField(f[1], u256);
    var tx = Transaction{
        .tx_type = 0,
        .nonce = try uintField(f[0], u64),
        .max_priority_fee = gas_price,
        .max_fee = gas_price,
        .gas_limit = try uintField(f[2], u64),
        .to = try addrField(f[3]),
        .value = try uintField(f[4], u256),
        .data = try bytesField(f[5]),
    };
    const v = try uintField(f[6], u64);
    tx.r = try uintField(f[7], u256);
    tx.s = try uintField(f[8], u256);

    // Build the signing hash and recovery id from v (pre-155 vs EIP-155).
    var sig_items: std.ArrayList([]const u8) = .empty;
    for (0..6) |i| try appendRaw(a, &sig_items, f[i]);
    var recid: u8 = undefined;
    if (v == 27 or v == 28) {
        recid = @intCast(v - 27);
    } else {
        const chain_id = (v -% 35) / 2;
        recid = @intCast((v -% 35) % 2);
        tx.chain_id = chain_id;
        try sig_items.append(a, rlp.encodeUint(a, chain_id) catch return error.OutOfMemory);
        try sig_items.append(a, rlp.encodeBytes(a, &.{}) catch return error.OutOfMemory);
        try sig_items.append(a, rlp.encodeBytes(a, &.{}) catch return error.OutOfMemory);
    }
    tx.y_parity = recid;
    const preimage = rlp.encodeList(a, sig_items.items) catch return error.OutOfMemory;
    tx.sender = try recover(crypto.keccak256(preimage), recid, tx.r, tx.s);
    return tx;
}

fn decodeTyped(a: std.mem.Allocator, tx_type: u8, payload: []const u8) DecodeError!Transaction {
    if (tx_type < 1 or tx_type > 4) return error.Malformed;
    const item = rlp.decode(a, payload) catch return error.Malformed;
    const f = item.items() catch return error.Malformed;

    // Field layout per type. All share: chainId, nonce, ...fees..., gasLimit,
    // to, value, data, accessList, [type extras], yParity, r, s.
    var tx = Transaction{ .tx_type = tx_type, .nonce = 0, .max_priority_fee = 0, .max_fee = 0, .gas_limit = 0, .to = null, .value = 0, .data = &.{} };
    tx.chain_id = try uintField(f[0], u64);
    tx.nonce = try uintField(f[1], u64);

    var idx: usize = 2;
    if (tx_type == 1) { // EIP-2930: single gasPrice
        const gp = try uintField(f[idx], u256);
        tx.max_priority_fee = gp;
        tx.max_fee = gp;
        idx += 1;
    } else { // 1559 / 4844 / 7702: priority + max
        tx.max_priority_fee = try uintField(f[idx], u256);
        tx.max_fee = try uintField(f[idx + 1], u256);
        idx += 2;
    }
    tx.gas_limit = try uintField(f[idx], u64);
    tx.to = try addrField(f[idx + 1]);
    tx.value = try uintField(f[idx + 2], u256);
    tx.data = try bytesField(f[idx + 3]);
    tx.access_list = try accessListField(a, f[idx + 4]);
    idx += 5;

    if (tx_type == 3) { // EIP-4844 extras
        tx.max_fee_per_blob_gas = try uintField(f[idx], u256);
        const hashes = f[idx + 1].items() catch return error.Malformed;
        var bvh = try a.alloc([32]u8, hashes.len);
        for (hashes, 0..) |h, i| {
            const s = try bytesField(h);
            if (s.len != 32) return error.Malformed;
            @memcpy(&bvh[i], s);
        }
        tx.blob_versioned_hashes = bvh;
        idx += 2;
    } else if (tx_type == 4) { // EIP-7702 authorization list
        const auths = f[idx].items() catch return error.Malformed;
        var list = try a.alloc(Authorization, auths.len);
        for (auths, 0..) |auth_v, i| {
            const af = auth_v.items() catch return error.Malformed;
            if (af.len != 6) return error.Malformed;
            list[i] = .{
                .chain_id = try uintField(af[0], u256),
                .address = (try addrField(af[1])) orelse return error.Malformed,
                .nonce = try uintField(af[2], u64),
                .y_parity = @intCast(try uintField(af[3], u64)),
                .r = try uintField(af[4], u256),
                .s = try uintField(af[5], u256),
            };
        }
        tx.authorizations = list;
        idx += 1;
    }

    tx.y_parity = @intCast(try uintField(f[idx], u64));
    tx.r = try uintField(f[idx + 1], u256);
    tx.s = try uintField(f[idx + 2], u256);

    // Signing hash = keccak256(type ‖ rlp(all fields except yParity, r, s)).
    var sig_items: std.ArrayList([]const u8) = .empty;
    for (0..idx) |i| try appendRaw(a, &sig_items, f[i]);
    const list = rlp.encodeList(a, sig_items.items) catch return error.OutOfMemory;
    var pre = try a.alloc(u8, 1 + list.len);
    pre[0] = tx_type;
    @memcpy(pre[1..], list);
    tx.sender = try recover(crypto.keccak256(pre), tx.y_parity, tx.r, tx.s);
    return tx;
}

/// Re-encode a decoded item to its RLP bytes (for rebuilding the signing list).
fn appendRaw(a: std.mem.Allocator, list: *std.ArrayList([]const u8), item: rlp.Item) DecodeError!void {
    try list.append(a, reencode(a, item) catch return error.OutOfMemory);
}

fn reencode(a: std.mem.Allocator, item: rlp.Item) error{OutOfMemory}![]u8 {
    switch (item) {
        .str => |s| return rlp.encodeBytes(a, s),
        .list => |xs| {
            var items: std.ArrayList([]const u8) = .empty;
            for (xs) |x| try items.append(a, try reencode(a, x));
            return rlp.encodeList(a, items.items);
        },
    }
}

fn recover(hash: [32]u8, recid: u8, r: u256, s: u256) DecodeError!Address {
    var rb: [32]u8 = undefined;
    var sb: [32]u8 = undefined;
    std.mem.writeInt(u256, &rb, r, .big);
    std.mem.writeInt(u256, &sb, s, .big);
    return precompiles.recoverAddress(hash, recid, rb, sb) orelse error.BadSignature;
}

const testing = std.testing;

test "decode legacy EIP-155 transaction and recover sender" {
    // Canonical EIP-155 example (chainId 1) from the spec, sender
    // 0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var raw: [110]u8 = undefined;
    const hex = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    const bytes = try std.fmt.hexToBytes(&raw, hex);
    const tx = try decode(a, bytes);
    try testing.expectEqual(@as(u8, 0), tx.tx_type);
    try testing.expectEqual(@as(u64, 9), tx.nonce);
    try testing.expectEqual(@as(?u64, 1), tx.chain_id);
    var want: Address = undefined;
    _ = try std.fmt.hexToBytes(&want, "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f");
    try testing.expectEqualSlices(u8, &want, &tx.sender);
}
