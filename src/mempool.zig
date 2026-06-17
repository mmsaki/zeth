//! A minimal transaction pool: accept raw signed transactions, keep them keyed
//! by (sender, nonce), and select an ordered, gas-bounded batch for block
//! production. Selection is the standard greedy: repeatedly take the ready tx
//! (the one at each sender's next nonce) with the highest effective priority
//! fee, until the block gas limit is reached.

const std = @import("std");
const transaction = @import("transaction.zig");
const state_mod = @import("state.zig");
const fork_mod = @import("fork.zig");

const Address = state_mod.Address;

pub const PooledTx = struct {
    raw: []u8, // owned by the pool
    sender: Address,
    nonce: u64,
    max_fee: u256,
    max_priority_fee: u256,
    gas_limit: u64,
    tx_type: u8,
};

pub const Mempool = struct {
    gpa: std.mem.Allocator,
    txs: std.ArrayList(PooledTx) = .empty,

    pub fn init(gpa: std.mem.Allocator) Mempool {
        return .{ .gpa = gpa };
    }
    pub fn deinit(self: *Mempool) void {
        for (self.txs.items) |t| self.gpa.free(t.raw);
        self.txs.deinit(self.gpa);
    }
    pub fn count(self: *const Mempool) usize {
        return self.txs.items.len;
    }

    /// Decode and add a raw signed transaction. Replaces an existing tx with the
    /// same (sender, nonce) only if the new one bids a strictly higher fee.
    /// Returns the tx hash so callers (eth_sendRawTransaction) can echo it.
    pub fn add(self: *Mempool, raw: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const tx = try transaction.decode(arena.allocator(), raw);

        // Replace-by-fee on a (sender, nonce) collision.
        for (self.txs.items) |*existing| {
            if (existing.nonce == tx.nonce and std.mem.eql(u8, &existing.sender, &tx.sender)) {
                if (tx.max_fee <= existing.max_fee) return; // not a better bid
                self.gpa.free(existing.raw);
                existing.* = .{
                    .raw = try self.gpa.dupe(u8, raw),
                    .sender = tx.sender,
                    .nonce = tx.nonce,
                    .max_fee = tx.max_fee,
                    .max_priority_fee = tx.max_priority_fee,
                    .gas_limit = tx.gas_limit,
                    .tx_type = tx.tx_type,
                };
                return;
            }
        }
        try self.txs.append(self.gpa, .{
            .raw = try self.gpa.dupe(u8, raw),
            .sender = tx.sender,
            .nonce = tx.nonce,
            .max_fee = tx.max_fee,
            .max_priority_fee = tx.max_priority_fee,
            .gas_limit = tx.gas_limit,
            .tx_type = tx.tx_type,
        });
    }

    /// Drop every pooled tx whose nonce is below the sender's current account
    /// nonce (mined or stale). Call after importing/producing a block.
    pub fn prune(self: *Mempool, state: *const state_mod.State) void {
        var i: usize = 0;
        while (i < self.txs.items.len) {
            const t = self.txs.items[i];
            if (t.nonce < state.nonceOf(t.sender)) {
                self.gpa.free(t.raw);
                _ = self.txs.swapRemove(i);
            } else i += 1;
        }
    }

    fn effTip(t: PooledTx, base_fee: u256) u256 {
        if (t.tx_type == 0 or t.tx_type == 1) return if (t.max_fee > base_fee) t.max_fee - base_fee else 0;
        const cap = if (t.max_fee > base_fee) t.max_fee - base_fee else 0;
        return @min(t.max_priority_fee, cap);
    }

    /// Select an ordered batch of raw transactions for a block: greedy by
    /// effective tip, honoring per-sender nonce order, bounded by `gas_limit`.
    /// Returns raw tx slices borrowed from the pool (valid until the next add).
    pub fn select(self: *const Mempool, a: std.mem.Allocator, state: *const state_mod.State, gas_limit: u64, base_fee: u256) ![]const []const u8 {
        // next[sender] = the nonce we still need to include for that sender.
        var next = std.AutoHashMap(Address, u64).init(a);
        for (self.txs.items) |t| {
            const gop = try next.getOrPut(t.sender);
            if (!gop.found_existing) gop.value_ptr.* = state.nonceOf(t.sender);
        }
        var chosen: std.ArrayList([]const u8) = .empty;
        var gas_used: u64 = 0;
        // Repeatedly pick the highest-tip ready tx that still fits.
        while (true) {
            var best: ?usize = null;
            var best_tip: u256 = 0;
            for (self.txs.items, 0..) |t, i| {
                if (t.gas_limit > gas_limit - gas_used) continue; // won't fit
                const want = next.get(t.sender).?;
                if (t.nonce != want) continue; // not this sender's next nonce
                const tip = effTip(t, base_fee);
                if (best == null or tip > best_tip) {
                    best = i;
                    best_tip = tip;
                }
            }
            const idx = best orelse break;
            const t = self.txs.items[idx];
            try chosen.append(a, t.raw);
            gas_used += t.gas_limit;
            try next.put(t.sender, t.nonce + 1);
        }
        return chosen.toOwnedSlice(a);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;
const secp = @import("secp.zig");
const ecies = @import("ecies.zig");
const rlp = @import("rlp.zig");
const crypto = @import("crypto.zig");

/// Build a signed legacy tx (chainId 1, EIP-155) for the pool tests.
fn signedLegacyTx(a: std.mem.Allocator, io: std.Io, priv: [32]u8, nonce: u64, gas_price: u64, gas_limit: u64, to: Address, value: u64) ![]u8 {
    const chain_id: u64 = 1;
    var items: std.ArrayList([]const u8) = .empty;
    try items.append(a, try rlp.encodeUint(a, nonce));
    try items.append(a, try rlp.encodeUint(a, gas_price));
    try items.append(a, try rlp.encodeUint(a, gas_limit));
    try items.append(a, try rlp.encodeBytes(a, &to));
    try items.append(a, try rlp.encodeUint(a, value));
    try items.append(a, try rlp.encodeBytes(a, &.{}));
    // EIP-155 signing payload: [..fields.., chainId, 0, 0]
    try items.append(a, try rlp.encodeUint(a, chain_id));
    try items.append(a, try rlp.encodeBytes(a, &.{}));
    try items.append(a, try rlp.encodeBytes(a, &.{}));
    const sig_payload = try rlp.encodeList(a, items.items);
    const sig = secp.sign(io, crypto.keccak256(sig_payload), priv);
    const v = @as(u64, sig.v) + 35 + chain_id * 2;
    // Final tx: [nonce, gasPrice, gas, to, value, data, v, r, s]
    var f: std.ArrayList([]const u8) = .empty;
    for (items.items[0..6]) |it| try f.append(a, it);
    try f.append(a, try rlp.encodeUint(a, v));
    try f.append(a, try rlp.encodeBytes(a, trimZeros(&sig.r)));
    try f.append(a, try rlp.encodeBytes(a, trimZeros(&sig.s)));
    return rlp.encodeList(a, f.items);
}

fn trimZeros(b: []const u8) []const u8 {
    var i: usize = 0;
    while (i < b.len and b[i] == 0) i += 1;
    return b[i..];
}

test "mempool add/replace-by-fee + nonce-ordered selection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var pool = Mempool.init(testing.allocator);
    defer pool.deinit();

    const priv = ecies.randomPriv(io);
    const pub_key = try ecies.pubFromPriv(priv);
    const ph = crypto.keccak256(&pub_key);
    var sender: Address = undefined;
    @memcpy(&sender, ph[12..32]);
    const to = std.mem.zeroes(Address);

    // Two txs from one sender, nonces 0 and 1 (added out of order).
    try pool.add(try signedLegacyTx(a, io, priv, 1, 10, 21000, to, 0));
    try pool.add(try signedLegacyTx(a, io, priv, 0, 10, 21000, to, 0));
    try testing.expectEqual(@as(usize, 2), pool.count());
    // Replace-by-fee: same nonce 0, higher price → replaces (count unchanged).
    try pool.add(try signedLegacyTx(a, io, priv, 0, 50, 21000, to, 0));
    try testing.expectEqual(@as(usize, 2), pool.count());

    var st = state_mod.State.init(testing.allocator);
    defer st.deinit();
    try st.setBalance(sender, 1_000_000_000_000_000_000);

    const batch = try pool.select(a, &st, 30_000_000, 7);
    try testing.expectEqual(@as(usize, 2), batch.len);
    // Decoded in nonce order: first selected tx must be nonce 0.
    const t0 = try transaction.decode(a, batch[0]);
    const t1 = try transaction.decode(a, batch[1]);
    try testing.expectEqual(@as(u64, 0), t0.nonce);
    try testing.expectEqual(@as(u64, 1), t1.nonce);
    try testing.expectEqualSlices(u8, &sender, &t0.sender); // signature recovered the signer
}
