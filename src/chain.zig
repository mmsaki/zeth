//! The block-import pipeline + a minimal in-memory chain. Given a genesis and a
//! sequence of block RLPs (the `consume-rlp` path), it decodes, executes, and
//! validates each block against its header — the same checks a node performs on
//! `engine_newPayload`. Built entirely on the verified pieces in block.zig,
//! transaction.zig, tx.zig, and trie.zig.

const std = @import("std");
const block = @import("block.zig");
const transaction = @import("transaction.zig");
const txmod = @import("tx.zig");
const state_mod = @import("state.zig");
const trie = @import("trie.zig");
const vm = @import("vm.zig");
const crypto = @import("crypto.zig");
const genesis_mod = @import("genesis.zig");
const Header = block.Header;
const State = state_mod.State;
const Address = state_mod.Address;

const SYSTEM_ADDRESS: Address = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
const BEACON_ROOTS = addr("000F3df6D732807Ef1319fB7B8bB8522d0Beac02"); // EIP-4788
const HISTORY_STORAGE = addr("0000F90827F1C53a10cb7A02335B175320002935"); // EIP-2935

fn addr(comptime hex: []const u8) Address {
    var a: Address = undefined;
    _ = std.fmt.hexToBytes(&a, hex) catch unreachable;
    return a;
}

pub const ImportError = error{
    BadParent,
    StateRootMismatch,
    TransactionsRootMismatch,
    ReceiptsRootMismatch,
    WithdrawalsRootMismatch,
    GasUsedMismatch,
    BloomMismatch,
    DecodeError,
    OutOfMemory,
};

/// A mined transaction plus its receipt, retained for the RPC layer.
pub const TxRecord = struct {
    hash: [32]u8,
    raw: []const u8, // EIP-2718 encoding (gpa-owned)
    sender: Address,
    to: ?Address,
    tx_type: u8,
    nonce: u64,
    gas_used: u64,
    cumulative_gas_used: u64,
    success: bool,
    contract_address: ?Address,
    effective_gas_price: u256,
    logs: []const vm.Log, // gpa-owned (deep)
};
const TxLoc = struct { block_number: u64, index: u32 };

pub const Chain = struct {
    gpa: std.mem.Allocator,
    state: *State,
    schedule: genesis_mod.ForkSchedule,
    chain_id: u64,
    head: Header,
    /// RLP-encoded block size by number (for the `size` RPC field).
    sizes: std.ArrayList(u64) = .empty,
    /// Per-block transaction records, indexed by block number (0 = genesis = empty).
    block_txs: std.ArrayList([]TxRecord) = .empty,
    /// tx hash → (block number, index) for getTransactionByHash/Receipt.
    tx_index: std.AutoHashMapUnmanaged([32]u8, TxLoc) = .{},
    /// Canonical headers by block number (index 0 = genesis). Each header's
    /// `extra_data` is owned by `gpa` (the decoded header otherwise lives in a
    /// per-block arena freed when importBlock returns). RPC serves from here.
    headers: std.ArrayList(Header) = .empty,
    /// Canonical block hashes by number, for the BLOCKHASH opcode + RPC.
    hashes: std.ArrayList([32]u8) = .empty,

    pub fn initGenesis(gpa: std.mem.Allocator, state: *State, g: genesis_mod.Genesis) !Chain {
        var c = Chain{
            .gpa = gpa,
            .state = state,
            .schedule = g.schedule,
            .chain_id = g.schedule.chain_id,
            .head = g.header,
        };
        try c.pushBlock(g.header, try g.header.hash(gpa));
        try c.block_txs.append(gpa, &.{}); // genesis has no transactions
        const genc = try g.header.encode(gpa);
        defer gpa.free(genc);
        try c.sizes.append(gpa, genc.len + 4); // header + empty txs/uncles lists
        return c;
    }

    pub fn deinit(self: *Chain) void {
        for (self.headers.items) |h| self.gpa.free(h.extra_data);
        self.headers.deinit(self.gpa);
        self.hashes.deinit(self.gpa);
        for (self.block_txs.items) |txs| {
            for (txs) |*t| {
                self.gpa.free(t.raw);
                for (t.logs) |lg| {
                    self.gpa.free(lg.topics);
                    self.gpa.free(lg.data);
                }
                self.gpa.free(t.logs);
            }
            if (txs.len > 0) self.gpa.free(txs);
        }
        self.block_txs.deinit(self.gpa);
        self.sizes.deinit(self.gpa);
        self.tx_index.deinit(self.gpa);
    }

    pub fn sizeByNumber(self: *const Chain, number: u64) u64 {
        if (number >= self.sizes.items.len) return 0;
        return self.sizes.items[number];
    }

    /// A transaction record by hash, or null.
    pub fn txByHash(self: *const Chain, hash: [32]u8) ?TxRecord {
        const loc = self.tx_index.get(hash) orelse return null;
        return self.block_txs.items[loc.block_number][loc.index];
    }
    /// A transaction record by block number + index, or null.
    pub fn txByBlockIndex(self: *const Chain, number: u64, index: u32) ?TxRecord {
        if (number >= self.block_txs.items.len) return null;
        const txs = self.block_txs.items[number];
        if (index >= txs.len) return null;
        return txs[index];
    }
    /// All transaction records of a block number.
    pub fn blockTxs(self: *const Chain, number: u64) []const TxRecord {
        if (number >= self.block_txs.items.len) return &.{};
        return self.block_txs.items[number];
    }

    /// Adopt a header as the new head, owning its `extra_data` stably.
    fn pushBlock(self: *Chain, h: Header, hash: [32]u8) !void {
        var owned = h;
        owned.extra_data = try self.gpa.dupe(u8, h.extra_data);
        try self.headers.append(self.gpa, owned);
        try self.hashes.append(self.gpa, hash);
        self.head = owned;
    }

    /// The canonical header at a block number, or null if beyond the head.
    pub fn headerByNumber(self: *const Chain, number: u64) ?Header {
        if (number >= self.headers.items.len) return null;
        return self.headers.items[number];
    }

    pub fn hashByNumber(self: *const Chain, number: u64) ?[32]u8 {
        if (number >= self.hashes.items.len) return null;
        return self.hashes.items[number];
    }

    /// Decode, execute, and validate a block from its RLP. On success the world
    /// state has advanced and the block becomes the new head. Mirrors the
    /// header-vs-execution checks of `engine_newPayload`.
    pub fn importBlock(self: *Chain, raw: []const u8) ImportError!Header {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();

        const blk = block.decodeBlock(a, raw) catch return error.DecodeError;
        const h = blk.header;
        const parent_hash = self.head.hash(self.gpa) catch return error.OutOfMemory;
        if (!std.mem.eql(u8, &h.parent_hash, &parent_hash)) return error.BadParent;

        const fork = self.schedule.forkAt(h.timestamp);
        var env = vm.Environment{
            .fork = fork,
            .chain_id = self.chain_id,
            .coinbase = h.coinbase,
            .number = h.number,
            .time = h.timestamp,
            .gas_limit = h.gas_limit,
            .base_fee = h.base_fee_per_gas orelse 0,
            .prev_randao = bytesToU256(&h.prev_randao),
            .block_hashes = self.hashes.items,
            .blob_base_fee = txmod.blobGasPrice(h.excess_blob_gas orelse 0, fork),
        };

        // Block-start system calls (state writes before transactions).
        if (fork.atLeast(.cancun)) if (h.parent_beacon_block_root) |r|
            self.systemCall(a, &env, BEACON_ROOTS, &r);
        if (fork.atLeast(.prague))
            self.systemCall(a, &env, HISTORY_STORAGE, &h.parent_hash);

        // Execute the transactions, accumulating receipts + retained records.
        var receipts: std.ArrayList(block.Receipt) = .empty;
        var records: std.ArrayList(TxRecord) = .empty;
        var cumulative_gas: u64 = 0;
        for (blk.transactions, 0..) |enc, ti| {
            const dt = transaction.decode(a, enc) catch return error.DecodeError;
            const gas_price = dt.effectiveGasPrice(env.base_fee);
            env.gas_price = gas_price;
            env.origin = dt.sender;
            env.blob_versioned_hashes = dt.blob_versioned_hashes;
            const blob_fee: u256 = @as(u256, txmod.GAS_PER_BLOB) * dt.blob_versioned_hashes.len * env.blob_base_fee;

            var logs: std.ArrayList(vm.Log) = .empty;
            const res = txmod.processWithReceipt(a, self.state, &env, .{
                .sender = dt.sender,
                .to = dt.to,
                .nonce = dt.nonce,
                .gas_limit = dt.gas_limit,
                .gas_price = gas_price,
                .value = dt.value,
                .data = dt.data,
                .access_list = dt.access_list,
                .blob_data_fee = blob_fee,
            }, &logs);
            cumulative_gas += res.gas_used;
            receipts.append(a, .{
                .tx_type = dt.tx_type,
                .success = res.success,
                .cumulative_gas_used = cumulative_gas,
                .logs = logs.items,
            }) catch return error.OutOfMemory;

            // Retain a gpa-owned record for the RPC layer.
            const contract: ?Address = if (dt.to == null)
                (state_mod.computeContractAddress(self.gpa, dt.sender, dt.nonce) catch return error.OutOfMemory)
            else
                null;
            records.append(a, .{
                .hash = crypto.keccak256(enc),
                .raw = self.gpa.dupe(u8, enc) catch return error.OutOfMemory,
                .sender = dt.sender,
                .to = dt.to,
                .tx_type = dt.tx_type,
                .nonce = dt.nonce,
                .gas_used = res.gas_used,
                .cumulative_gas_used = cumulative_gas,
                .success = res.success,
                .contract_address = contract,
                .effective_gas_price = gas_price,
                .logs = ownLogs(self.gpa, logs.items),
            }) catch return error.OutOfMemory;
            _ = ti;
        }

        // Withdrawals (Shanghai+): credit balance, amount is in Gwei.
        for (blk.withdrawals) |w_enc| {
            const wd = decodeWithdrawal(a, w_enc) catch return error.DecodeError;
            self.state.setBalance(wd.address, self.state.balanceOf(wd.address) + @as(u256, wd.amount) * 1_000_000_000) catch return error.OutOfMemory;
        }

        // Validate the execution result against the header (the consensus checks).
        const state_root = trie.stateRoot(a, self.state);
        if (!std.mem.eql(u8, &state_root, &h.state_root)) return error.StateRootMismatch;
        const tx_root = block.orderedTrieRoot(a, blk.transactions);
        if (!std.mem.eql(u8, &tx_root, &h.transactions_root)) return error.TransactionsRootMismatch;
        const rr = block.receiptsRoot(a, receipts.items);
        if (!std.mem.eql(u8, &rr, &h.receipts_root)) return error.ReceiptsRootMismatch;
        if (cumulative_gas != h.gas_used) return error.GasUsedMismatch;
        var bloom = std.mem.zeroes([256]u8);
        for (receipts.items) |*r| block.orBloom(&bloom, block.logsBloom(r.logs));
        if (!std.mem.eql(u8, &bloom, &h.logs_bloom)) return error.BloomMismatch;
        if (h.withdrawals_root) |wr| {
            const got = block.orderedTrieRoot(a, blk.withdrawals);
            if (!std.mem.eql(u8, &got, &wr)) return error.WithdrawalsRootMismatch;
        }

        // Accept: advance head + record the canonical header/hash + retained txs.
        const bh = h.hash(self.gpa) catch return error.OutOfMemory;
        self.pushBlock(h, bh) catch return error.OutOfMemory;
        const owned = self.gpa.dupe(TxRecord, records.items) catch return error.OutOfMemory;
        self.block_txs.append(self.gpa, owned) catch return error.OutOfMemory;
        self.sizes.append(self.gpa, raw.len) catch return error.OutOfMemory;
        for (owned, 0..) |r, i|
            self.tx_index.put(self.gpa, r.hash, .{ .block_number = h.number, .index = @intCast(i) }) catch return error.OutOfMemory;
        return self.head;
    }

    fn systemCall(self: *Chain, a: std.mem.Allocator, env: *const vm.Environment, to: Address, data: []const u8) void {
        if (self.state.codeOf(to).len == 0) return; // not deployed in this fork
        var evm = vm.processMessage(a, self.state, env, .{
            .caller = SYSTEM_ADDRESS,
            .current_target = to,
            .code_address = to,
            .code = self.state.codeOf(to),
            .data = data,
            .gas = 30_000_000,
            .value = 0,
        }, null);
        evm.deinit();
    }
};

fn bytesToU256(b: *const [32]u8) u256 {
    return std.mem.readInt(u256, b, .big);
}

/// Deep-copy a tx's logs into `gpa` so they outlive the per-block arena.
fn ownLogs(gpa: std.mem.Allocator, logs: []const vm.Log) []const vm.Log {
    const out = gpa.alloc(vm.Log, logs.len) catch @panic("oom");
    for (logs, 0..) |lg, i| out[i] = .{
        .address = lg.address,
        .topics = gpa.dupe([32]u8, lg.topics) catch @panic("oom"),
        .data = gpa.dupe(u8, lg.data) catch @panic("oom"),
    };
    return out;
}

const Withdrawal = struct { address: Address, amount: u64 };

/// Decode a withdrawal RLP: `[index, validatorIndex, address, amount]`.
fn decodeWithdrawal(a: std.mem.Allocator, raw: []const u8) !Withdrawal {
    const rlp = @import("rlp.zig");
    const item = try rlp.decode(a, raw);
    const f = try item.items();
    if (f.len != 4) return error.Malformed;
    const addr_bytes = try f[2].bytes();
    if (addr_bytes.len != 20) return error.Malformed;
    var address: Address = undefined;
    @memcpy(&address, addr_bytes);
    return .{ .address = address, .amount = try f[3].uint(u64) };
}
