//! A hashed-key state store populated by snap sync. Snap data is keyed by
//! keccak256(address) and keccak256(slot) — the secure-trie layout geth uses —
//! so it cannot be inverted back to addresses. This store keeps the verified
//! snap data in that hashed form and answers queries *by address/slot*, hashing
//! the lookup key on the way in (the address is always known at query/execution
//! time, so the hash never needs inverting).
//!
//! This is the read side of "boot a node from snap state": once populated and
//! root-verified, zeth can serve account/storage/code reads by address. The
//! write side (executing blocks and recomputing the state root) additionally
//! needs an incremental hashed-key trie, which is a separate piece.

const std = @import("std");
const crypto = @import("crypto.zig");

pub const Address = [20]u8;

pub const SnapAccount = struct {
    nonce: u64,
    balance: u256,
    storage_root: [32]u8,
    code_hash: [32]u8,
};

const SlotKey = struct { acct: [32]u8, slot: [32]u8 };

pub const SnapStore = struct {
    allocator: std.mem.Allocator,
    accounts: std.AutoHashMapUnmanaged([32]u8, SnapAccount) = .{},
    codes: std.AutoHashMapUnmanaged([32]u8, []const u8) = .{},
    storage: std.AutoHashMapUnmanaged(SlotKey, u256) = .{},

    pub fn init(allocator: std.mem.Allocator) SnapStore {
        return .{ .allocator = allocator };
    }
    pub fn deinit(self: *SnapStore) void {
        self.accounts.deinit(self.allocator);
        self.codes.deinit(self.allocator);
        self.storage.deinit(self.allocator);
    }

    // ── population (keyed by the already-hashed snap keys) ─────────────────────
    pub fn putAccount(self: *SnapStore, acct_hash: [32]u8, acc: SnapAccount) !void {
        try self.accounts.put(self.allocator, acct_hash, acc);
    }
    pub fn putCode(self: *SnapStore, code_hash: [32]u8, code: []const u8) !void {
        try self.codes.put(self.allocator, code_hash, code);
    }
    pub fn putSlot(self: *SnapStore, acct_hash: [32]u8, slot_hash: [32]u8, value: u256) !void {
        try self.storage.put(self.allocator, .{ .acct = acct_hash, .slot = slot_hash }, value);
    }

    pub fn count(self: *const SnapStore) usize {
        return self.accounts.count();
    }

    // ── queries by address/slot (hashed internally) ───────────────────────────
    pub fn account(self: *const SnapStore, addr: Address) ?SnapAccount {
        return self.accounts.get(crypto.keccak256(&addr));
    }
    pub fn balanceOf(self: *const SnapStore, addr: Address) u256 {
        return if (self.account(addr)) |a| a.balance else 0;
    }
    pub fn nonceOf(self: *const SnapStore, addr: Address) u64 {
        return if (self.account(addr)) |a| a.nonce else 0;
    }
    pub fn codeOf(self: *const SnapStore, addr: Address) []const u8 {
        const a = self.account(addr) orelse return &.{};
        return self.codes.get(a.code_hash) orelse &.{};
    }
    pub fn storageOf(self: *const SnapStore, addr: Address, slot: u256) u256 {
        var sb: [32]u8 = undefined;
        std.mem.writeInt(u256, &sb, slot, .big);
        const key: SlotKey = .{ .acct = crypto.keccak256(&addr), .slot = crypto.keccak256(&sb) };
        return self.storage.get(key) orelse 0;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "snap store answers queries by address after hashed insertion" {
    var s = SnapStore.init(testing.allocator);
    defer s.deinit();

    const addr: Address = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04 };
    const code = "some bytecode";
    const code_hash = crypto.keccak256(code);
    var sroot: [32]u8 = undefined;
    for (&sroot, 0..) |*b, i| b.* = @intCast(i);

    // Insert keyed by the hashed (snap) keys.
    try s.putAccount(crypto.keccak256(&addr), .{ .nonce = 5, .balance = 999, .storage_root = sroot, .code_hash = code_hash });
    try s.putCode(code_hash, code);
    var slotb: [32]u8 = undefined;
    std.mem.writeInt(u256, &slotb, 7, .big);
    try s.putSlot(crypto.keccak256(&addr), crypto.keccak256(&slotb), 4242);

    // Query by address/slot — hashing happens inside.
    try testing.expectEqual(@as(u256, 999), s.balanceOf(addr));
    try testing.expectEqual(@as(u64, 5), s.nonceOf(addr));
    try testing.expectEqualStrings(code, s.codeOf(addr));
    try testing.expectEqual(@as(u256, 4242), s.storageOf(addr, 7));
    // Unknown address/slot → zero/empty.
    try testing.expectEqual(@as(u256, 0), s.balanceOf(std.mem.zeroes(Address)));
    try testing.expectEqual(@as(u256, 0), s.storageOf(addr, 8));
}
