//! In-memory world state: accounts, balances, nonces, code, and storage.
//!
//! This is a reference implementation that favors clarity over performance —
//! snapshots are taken by deep-cloning, exactly as the execution-specs do with
//! `copy_tx_state`. A production client would use a persistent/COW trie, but
//! the semantics modeled here (revert-on-error) are identical.

const std = @import("std");
const word = @import("word.zig");
const crypto = @import("crypto.zig");
const rlp = @import("rlp.zig");

/// A 20-byte Ethereum address.
pub const Address = [20]u8;

pub const zero_address: Address = std.mem.zeroes(Address);

/// Take the low 20 bytes of a 256-bit word (the EVM's address masking).
pub fn addressFromWord(w: u256) Address {
    const full = word.toBeBytes32(w);
    var a: Address = undefined;
    @memcpy(&a, full[12..32]);
    return a;
}

/// Widen an address into a left-zero-padded 256-bit word.
pub fn addressToWord(a: Address) u256 {
    var buf: [32]u8 = std.mem.zeroes([32]u8);
    @memcpy(buf[12..32], &a);
    return word.fromBeBytes(&buf);
}

const StorageMap = std.AutoHashMapUnmanaged(u256, u256);

/// A single account. The empty account (absent from the map) behaves as one
/// with zero nonce/balance, empty code, and empty storage.
pub const Account = struct {
    nonce: u64 = 0,
    balance: u256 = 0,
    code: []u8 = &.{},
    storage: StorageMap = .{},

    fn deinit(self: *Account, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        self.storage.deinit(allocator);
    }

    fn clone(self: Account, allocator: std.mem.Allocator) !Account {
        var storage: StorageMap = .{};
        try storage.ensureTotalCapacity(allocator, self.storage.count());
        var it = self.storage.iterator();
        while (it.next()) |entry| {
            storage.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
        }
        return .{
            .nonce = self.nonce,
            .balance = self.balance,
            .code = try allocator.dupe(u8, self.code),
            .storage = storage,
        };
    }
};

const AccountMap = std.AutoHashMapUnmanaged(Address, Account);

/// A (contract, slot) pair — the key for storage access lists and transient
/// storage.
pub const StorageKey = struct { addr: Address, key: u256 };

const AddressSet = std.AutoHashMapUnmanaged(Address, void);
const StorageKeySet = std.AutoHashMapUnmanaged(StorageKey, void);
const StorageKeyMap = std.AutoHashMapUnmanaged(StorageKey, u256);

pub const State = struct {
    allocator: std.mem.Allocator,
    accounts: AccountMap = .{},

    // --- Transaction-scoped bookkeeping (not part of the persistent state) ---
    /// EIP-2929 warm addresses / storage slots.
    accessed_addresses: AddressSet = .{},
    accessed_storage_keys: StorageKeySet = .{},
    /// EIP-1153 transient storage (cleared at end of transaction).
    transient: StorageKeyMap = .{},
    /// Storage values at the start of the transaction, for SSTORE refund math.
    original: StorageKeyMap = .{},
    /// EIP-6780: addresses created during this transaction. SELFDESTRUCT only
    /// deletes an account if it was created in the same transaction. This set is
    /// deliberately NOT rolled back on revert (a reverted CREATE still counts,
    /// per the spec edge case) and is cleared at the start of each transaction.
    created_accounts: AddressSet = .{},
    /// EIP-161 (Spurious Dragon): accounts touched during this transaction.
    /// At the end of the tx, any touched account that is empty is destroyed.
    /// Rolls back with snapshots (a touch inside a reverted frame is discarded).
    touched: AddressSet = .{},

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }

    fn deinitAccounts(self: *State) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.accounts.deinit(self.allocator);
    }

    pub fn deinit(self: *State) void {
        self.deinitAccounts();
        self.accessed_addresses.deinit(self.allocator);
        self.accessed_storage_keys.deinit(self.allocator);
        self.transient.deinit(self.allocator);
        self.original.deinit(self.allocator);
        self.created_accounts.deinit(self.allocator);
        self.touched.deinit(self.allocator);
    }

    /// Reset all transaction-scoped bookkeeping (EIP-2929 access lists, EIP-1153
    /// transient storage, SSTORE originals, EIP-6780 created set). Must run at the
    /// start of every transaction so nothing leaks between txs in a block.
    pub fn beginTx(self: *State) void {
        self.accessed_addresses.clearRetainingCapacity();
        self.accessed_storage_keys.clearRetainingCapacity();
        self.transient.clearRetainingCapacity();
        self.original.clearRetainingCapacity();
        self.created_accounts.clearRetainingCapacity();
        self.touched.clearRetainingCapacity();
    }

    /// Mark `addr` as touched this transaction (EIP-161). Does not create the
    /// account; emptiness is checked at tx end by `destroyTouchedEmpty`.
    pub fn markTouched(self: *State, addr: Address) void {
        self.touched.put(self.allocator, addr, {}) catch @panic("oom");
    }

    /// EIP-161 state clearing: remove every touched account that is now empty
    /// (nonce 0, balance 0, no code). Run at the end of a transaction from
    /// Spurious Dragon onward.
    pub fn destroyTouchedEmpty(self: *State) void {
        var it = self.touched.iterator();
        while (it.next()) |e| {
            const addr = e.key_ptr.*;
            if (self.accounts.get(addr)) |acc| {
                if (acc.nonce == 0 and acc.balance == 0 and acc.code.len == 0) self.removeAccount(addr);
            }
        }
    }

    /// Mark `addr` as created in the current transaction (EIP-6780).
    pub fn markAccountCreated(self: *State, addr: Address) void {
        self.created_accounts.put(self.allocator, addr, {}) catch @panic("oom");
    }

    pub fn wasCreatedThisTx(self: *const State, addr: Address) bool {
        return self.created_accounts.contains(addr);
    }

    /// Mark `addr` warm; return true if it was already warm (EIP-2929).
    pub fn accessAddress(self: *State, addr: Address) bool {
        const gop = self.accessed_addresses.getOrPut(self.allocator, addr) catch @panic("oom");
        return gop.found_existing;
    }

    /// Mark `(addr, key)` warm; return true if it was already warm.
    pub fn accessStorage(self: *State, addr: Address, key: u256) bool {
        const gop = self.accessed_storage_keys.getOrPut(self.allocator, .{ .addr = addr, .key = key }) catch @panic("oom");
        return gop.found_existing;
    }

    pub fn getTransient(self: *const State, addr: Address, key: u256) u256 {
        return self.transient.get(.{ .addr = addr, .key = key }) orelse 0;
    }

    pub fn setTransient(self: *State, addr: Address, key: u256, value: u256) !void {
        try self.transient.put(self.allocator, .{ .addr = addr, .key = key }, value);
    }

    /// Value of `(addr, key)` at the start of the transaction. Recorded lazily
    /// on first touch (when current == original), per the spec's semantics.
    pub fn getStorageOriginal(self: *State, addr: Address, key: u256) u256 {
        const sk = StorageKey{ .addr = addr, .key = key };
        if (self.original.get(sk)) |v| return v;
        const cur = self.getStorage(addr, key);
        self.original.put(self.allocator, sk, cur) catch @panic("oom");
        return cur;
    }

    fn cloneMap(self: *const State, comptime M: type, src: M) M {
        var copy: M = .{};
        copy.ensureTotalCapacity(self.allocator, src.count()) catch @panic("oom");
        var it = src.iterator();
        while (it.next()) |e| copy.putAssumeCapacity(e.key_ptr.*, e.value_ptr.*);
        return copy;
    }

    /// Deep copy, used to snapshot before a message call. Includes the access
    /// lists and transient storage, which also revert on call failure (EIP-2929,
    /// EIP-1153); `original` is transaction-scoped and is not snapshotted.
    pub fn clone(self: *const State) !State {
        var copy = State.init(self.allocator);
        try copy.accounts.ensureTotalCapacity(self.allocator, self.accounts.count());
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            copy.accounts.putAssumeCapacity(entry.key_ptr.*, try entry.value_ptr.clone(self.allocator));
        }
        copy.accessed_addresses = self.cloneMap(AddressSet, self.accessed_addresses);
        copy.accessed_storage_keys = self.cloneMap(StorageKeySet, self.accessed_storage_keys);
        copy.transient = self.cloneMap(StorageKeyMap, self.transient);
        copy.touched = self.cloneMap(AddressSet, self.touched);
        return copy;
    }

    /// Discard the current contents and adopt those of `snapshot` (consumed).
    pub fn restoreFrom(self: *State, snapshot: *State) void {
        self.deinitAccounts();
        self.accounts = snapshot.accounts;
        snapshot.accounts = .{};
        self.accessed_addresses.deinit(self.allocator);
        self.accessed_addresses = snapshot.accessed_addresses;
        snapshot.accessed_addresses = .{};
        self.accessed_storage_keys.deinit(self.allocator);
        self.accessed_storage_keys = snapshot.accessed_storage_keys;
        snapshot.accessed_storage_keys = .{};
        self.transient.deinit(self.allocator);
        self.transient = snapshot.transient;
        snapshot.transient = .{};
        self.touched.deinit(self.allocator);
        self.touched = snapshot.touched;
        snapshot.touched = .{};
    }

    fn getOrCreate(self: *State, addr: Address) !*Account {
        self.touched.put(self.allocator, addr, {}) catch @panic("oom");
        const gop = try self.accounts.getOrPut(self.allocator, addr);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        return gop.value_ptr;
    }

    pub fn exists(self: *const State, addr: Address) bool {
        return self.accounts.contains(addr);
    }

    /// Materialize an (empty) account so it exists, as the EVM's account
    /// "touch" does.
    pub fn touch(self: *State, addr: Address) !void {
        _ = try self.getOrCreate(addr);
    }

    pub fn balanceOf(self: *const State, addr: Address) u256 {
        return if (self.accounts.get(addr)) |a| a.balance else 0;
    }

    pub fn setBalance(self: *State, addr: Address, value: u256) !void {
        const acc = try self.getOrCreate(addr);
        acc.balance = value;
    }

    pub fn nonceOf(self: *const State, addr: Address) u64 {
        return if (self.accounts.get(addr)) |a| a.nonce else 0;
    }

    pub fn incrementNonce(self: *State, addr: Address) !void {
        const acc = try self.getOrCreate(addr);
        acc.nonce += 1;
    }

    pub fn setNonce(self: *State, addr: Address, nonce: u64) !void {
        const acc = try self.getOrCreate(addr);
        acc.nonce = nonce;
    }

    /// Remove an account entirely (used for SELFDESTRUCT).
    pub fn removeAccount(self: *State, addr: Address) void {
        if (self.accounts.fetchRemove(addr)) |kv| {
            var acc = kv.value;
            acc.deinit(self.allocator);
        }
    }

    pub fn codeOf(self: *const State, addr: Address) []const u8 {
        return if (self.accounts.get(addr)) |a| a.code else &.{};
    }

    pub fn setCode(self: *State, addr: Address, code: []const u8) !void {
        const acc = try self.getOrCreate(addr);
        self.allocator.free(acc.code);
        acc.code = try self.allocator.dupe(u8, code);
    }

    /// True if the account is "non-empty enough" to cause a CREATE collision.
    pub fn hasCodeOrNonce(self: *const State, addr: Address) bool {
        const a = self.accounts.get(addr) orelse return false;
        return a.nonce != 0 or a.code.len != 0;
    }

    pub fn hasStorage(self: *const State, addr: Address) bool {
        const a = self.accounts.get(addr) orelse return false;
        return a.storage.count() != 0;
    }

    pub fn getStorage(self: *const State, addr: Address, key: u256) u256 {
        const a = self.accounts.get(addr) orelse return 0;
        return a.storage.get(key) orelse 0;
    }

    pub fn setStorage(self: *State, addr: Address, key: u256, value: u256) !void {
        const acc = try self.getOrCreate(addr);
        if (value == 0) {
            _ = acc.storage.remove(key);
        } else {
            try acc.storage.put(self.allocator, key, value);
        }
    }

    /// Move `amount` wei from `sender` to `recipient` (no balance check here;
    /// callers verify funds first, matching the spec).
    pub fn moveEther(self: *State, sender: Address, recipient: Address, amount: u256) !void {
        const from = try self.getOrCreate(sender);
        from.balance -= amount;
        const to = try self.getOrCreate(recipient);
        to.balance += amount;
    }
};

/// `keccak256(rlp([sender, nonce]))[-20:]` — the Frontier CREATE address.
pub fn computeContractAddress(allocator: std.mem.Allocator, sender: Address, nonce: u64) !Address {
    const enc_addr = try rlp.encodeBytes(allocator, &sender);
    defer allocator.free(enc_addr);
    const enc_nonce = try rlp.encodeUint(allocator, nonce);
    defer allocator.free(enc_nonce);
    const list = try rlp.encodeList(allocator, &.{ enc_addr, enc_nonce });
    defer allocator.free(list);
    const hash = crypto.keccak256(list);
    var addr: Address = undefined;
    @memcpy(&addr, hash[12..32]);
    return addr;
}

const testing = std.testing;

test "address word round trip masks to 20 bytes" {
    const w: u256 = 0xffff_aabb_ccdd_eeff_0011_2233_4455_6677_8899_aabb;
    const a = addressFromWord(w);
    // Re-widening yields the low 20 bytes only.
    try testing.expectEqual(addressFromWord(addressToWord(a)), a);
}

test "storage set/get and zero deletes" {
    var st = State.init(testing.allocator);
    defer st.deinit();
    const a = zero_address;
    try st.setStorage(a, 1, 42);
    try testing.expectEqual(@as(u256, 42), st.getStorage(a, 1));
    try st.setStorage(a, 1, 0);
    try testing.expectEqual(false, st.hasStorage(a));
}

test "snapshot and restore" {
    var st = State.init(testing.allocator);
    defer st.deinit();
    try st.setBalance(zero_address, 100);

    var snap = try st.clone();
    // Mutate after snapshot.
    try st.setBalance(zero_address, 5);
    try st.setStorage(zero_address, 7, 7);
    try testing.expectEqual(@as(u256, 5), st.balanceOf(zero_address));

    st.restoreFrom(&snap);
    try testing.expectEqual(@as(u256, 100), st.balanceOf(zero_address));
    try testing.expectEqual(@as(u256, 0), st.getStorage(zero_address, 7));
}

test "known contract address (nonce 0)" {
    // geth/yellow-paper reference: sender 0x0..0, nonce 0
    // keccak256(rlp([20*0x00, 0x80])) -> bd770416a3345f91e4b34576cb804a576fa48eb1
    const addr = try computeContractAddress(testing.allocator, zero_address, 0);
    var hex: [40]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&addr});
    try testing.expectEqualStrings("bd770416a3345f91e4b34576cb804a576fa48eb1", &hex);
}
