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

pub const Chain = struct {
    gpa: std.mem.Allocator,
    state: *State,
    schedule: genesis_mod.ForkSchedule,
    chain_id: u64,
    head: Header,
    /// `head.extra_data` storage, owned by `gpa` (the decoded header lives in a
    /// per-block arena that is freed when importBlock returns).
    head_extra: []u8 = &.{},
    /// Canonical block hashes by number (index 0 = genesis) for the BLOCKHASH opcode.
    hashes: std.ArrayList([32]u8) = .empty,

    pub fn initGenesis(gpa: std.mem.Allocator, state: *State, g: genesis_mod.Genesis) !Chain {
        var c = Chain{
            .gpa = gpa,
            .state = state,
            .schedule = g.schedule,
            .chain_id = g.schedule.chain_id,
            .head = g.header,
        };
        c.head_extra = try gpa.dupe(u8, g.header.extra_data);
        c.head.extra_data = c.head_extra;
        try c.hashes.append(gpa, try c.head.hash(gpa));
        return c;
    }

    pub fn deinit(self: *Chain) void {
        self.hashes.deinit(self.gpa);
        self.gpa.free(self.head_extra);
    }

    /// Stably adopt a freshly-decoded header as the new head (its `extra_data`
    /// otherwise dangles once the per-block arena is freed).
    fn setHead(self: *Chain, h: Header) !void {
        const extra = try self.gpa.dupe(u8, h.extra_data);
        self.gpa.free(self.head_extra);
        self.head_extra = extra;
        self.head = h;
        self.head.extra_data = extra;
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

        // Execute the transactions, accumulating receipts.
        var receipts: std.ArrayList(block.Receipt) = .empty;
        var cumulative_gas: u64 = 0;
        for (blk.transactions) |enc| {
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

        // Accept: advance head + record the canonical hash.
        const bh = h.hash(self.gpa) catch return error.OutOfMemory;
        self.hashes.append(self.gpa, bh) catch return error.OutOfMemory;
        self.setHead(h) catch return error.OutOfMemory;
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
