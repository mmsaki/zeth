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
const store_mod = @import("store.zig");
const Header = block.Header;
const State = state_mod.State;
const Address = state_mod.Address;

const SYSTEM_ADDRESS: Address = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
const BEACON_ROOTS = addr("000F3df6D732807Ef1319fB7B8bB8522d0Beac02"); // EIP-4788
const HISTORY_STORAGE = addr("0000F90827F1C53a10cb7A02335B175320002935"); // EIP-2935
// EIP-7685 general-purpose requests (Prague).
const WITHDRAWAL_REQUEST_PREDEPLOY = addr("00000961Ef480Eb55e80D19ad83579A64c007002"); // EIP-7002
const CONSOLIDATION_REQUEST_PREDEPLOY = addr("0000BBdDc7CE488642fb579F8B00f3a590007251"); // EIP-7251
const DEPOSIT_CONTRACT = addr("00000000219ab540356cBB839Cbe05303d7705Fa"); // EIP-6110
const DEPOSIT_EVENT_SIG = [32]u8{ 0x64, 0x9b, 0xbc, 0x62, 0xd0, 0xe3, 0x13, 0x42, 0xaf, 0xea, 0x4e, 0x5c, 0xd8, 0x2d, 0x40, 0x49, 0xe7, 0xe1, 0xee, 0x91, 0x2f, 0xc0, 0x88, 0x9a, 0xa7, 0x90, 0x80, 0x3b, 0xe3, 0x90, 0x38, 0xc5 };

fn addr(comptime hex: []const u8) Address {
    var a: Address = undefined;
    _ = std.fmt.hexToBytes(&a, hex) catch unreachable;
    return a;
}

/// EIP-7685: fold one type-prefixed request into the requests-hash accumulator —
/// `outer` collects sha256(type ‖ data) digests, and its final digest is the
/// header's requests_hash.
fn hashRequest(outer: *std.crypto.hash.sha2.Sha256, type_byte: u8, data: []const u8) void {
    var inner = std.crypto.hash.sha2.Sha256.init(.{});
    inner.update(&[_]u8{type_byte});
    inner.update(data);
    var d: [32]u8 = undefined;
    inner.final(&d);
    outer.update(&d);
}

/// EIP-6110: strip the Solidity ABI framing from a 576-byte DepositEvent payload,
/// returning the 192-byte pubkey‖credentials‖amount‖signature‖index. Offsets and
/// sizes are fixed by the spec, so a wrong length yields null (log ignored).
fn extractDepositData(data: []const u8) ?[192]u8 {
    if (data.len != 576) return null;
    var out: [192]u8 = undefined;
    @memcpy(out[0..48], data[192..240]); // pubkey (48)
    @memcpy(out[48..80], data[288..320]); // withdrawal credentials (32)
    @memcpy(out[80..88], data[352..360]); // amount (8)
    @memcpy(out[88..184], data[416..512]); // signature (96)
    @memcpy(out[184..192], data[544..552]); // index (8)
    return out;
}

pub const ImportError = error{
    InvalidTransaction,
    InvalidExcessBlobGas,
    BadParent,
    StateRootMismatch,
    TransactionsRootMismatch,
    ReceiptsRootMismatch,
    WithdrawalsRootMismatch,
    GasUsedMismatch,
    BloomMismatch,
    RequestsHashMismatch,
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
    /// A clone of the genesis world state, retained so debug_traceTransaction
    /// can replay the chain up to a target transaction.
    genesis_state: ?State = null,
    /// Reason the most recent import failed (for the Engine API validationError).
    last_error: ?[]const u8 = null,
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
        c.genesis_state = try state.clone(); // retained for debug_traceTransaction
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
        if (self.genesis_state) |*gs| gs.deinit();
    }

    pub const TraceResult = struct { gas_used: u64, success: bool, output: []const u8 };

    /// Replay the chain on a fresh genesis-state clone up to `hash`, capturing
    /// the target transaction's opcode trace into `sink` (debug_traceTransaction).
    pub fn traceTransaction(self: *Chain, a: std.mem.Allocator, hash: [32]u8, sink: ?*std.ArrayList(vm.StructLog), call_tr: ?*vm.CallTracer) ?TraceResult {
        const loc = self.tx_index.get(hash) orelse return null;
        var st = (self.genesis_state orelse return null).clone() catch return null;
        defer st.deinit();

        var bn: u64 = 1;
        while (bn <= loc.block_number) : (bn += 1) {
            const h = self.headers.items[bn];
            const fork = self.schedule.forkAt(h.number, h.timestamp);
            var env = vm.Environment{
                .fork = fork,
                .chain_id = self.chain_id,
                .coinbase = h.coinbase,
                .number = h.number,
                .time = h.timestamp,
                .gas_limit = h.gas_limit,
                .base_fee = h.base_fee_per_gas orelse 0,
                .prev_randao = bytesToU256(&h.prev_randao),
                .difficulty = h.difficulty,
                .block_hashes = self.hashes.items[0..bn],
                .blob_base_fee = txmod.blobGasPrice(h.excess_blob_gas orelse 0, fork),
            };
            if (fork.atLeast(.cancun)) if (h.parent_beacon_block_root) |r| {
                _ = self.systemCall(a, &env, BEACON_ROOTS, &r);
            };
            if (fork.atLeast(.prague)) _ = self.systemCall(a, &env, HISTORY_STORAGE, &h.parent_hash);

            for (self.block_txs.items[bn], 0..) |rec, i| {
                const dt = transaction.decode(a, rec.raw) catch return null;
                env.gas_price = rec.effective_gas_price;
                env.origin = dt.sender;
                env.blob_versioned_hashes = dt.blob_versioned_hashes;
                const blob_fee: u256 = @as(u256, txmod.GAS_PER_BLOB) * dt.blob_versioned_hashes.len * env.blob_base_fee;
                const target = bn == loc.block_number and i == loc.index;
                if (target) {
                    vm.trace_sink = sink;
                    vm.call_tracer = call_tr;
                }
                const res = txmod.process(a, &st, &env, .{
                    .sender = dt.sender,
                    .to = dt.to,
                    .nonce = dt.nonce,
                    .gas_limit = dt.gas_limit,
                    .gas_price = rec.effective_gas_price,
                    .value = dt.value,
                    .data = dt.data,
                    .access_list = dt.access_list,
                    .authorizations = dt.authorizations,
                    .blob_data_fee = blob_fee,
                });
                if (target) {
                    vm.trace_sink = null;
                    vm.call_tracer = null;
                    return .{ .gas_used = res.gas_used, .success = res.success, .output = "" };
                }
            }
        }
        return null;
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

    /// Persist the whole canonical chain + world state to `st` (a snapshot, for
    /// `--datadir`). Headers/canonical indices, the head pointer, and a flat
    /// account snapshot are written, then the log is flushed.
    pub fn persistTo(self: *Chain, a: std.mem.Allocator, st: *store_mod.Store) !void {
        for (self.headers.items, 0..) |*h, n| {
            const enc = try h.encode(self.gpa);
            defer self.gpa.free(enc);
            try st.putHeader(self.hashes.items[n], enc);
            try st.setCanonical(n, self.hashes.items[n]);
        }
        try st.setHead(self.hashes.items[self.head.number], self.head.number);
        try st.snapshotState(a, self.state);
        try st.db.flush();
    }

    /// Append a canonical header read back from disk during resume (no
    /// execution; the world state is loaded separately via `store.loadState`).
    /// Per-block transaction history is not reconstructed — a follow-up.
    pub fn appendResumed(self: *Chain, h: Header, hash: [32]u8, size: u64) !void {
        try self.pushBlock(h, hash);
        try self.block_txs.append(self.gpa, &.{});
        try self.sizes.append(self.gpa, size);
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
        return self.importDecoded(a, blk);
    }

    /// Execute + validate a decoded block (header + EIP-2718 tx encodings +
    /// withdrawal encodings) and append it. Shared by RLP import and the Engine
    /// API (engine_newPayload builds the parts from an ExecutionPayload).
    pub fn importDecoded(self: *Chain, a: std.mem.Allocator, blk: block.Block) ImportError!Header {
        self.last_error = null;
        const h = blk.header;
        const parent_hash = self.head.hash(self.gpa) catch return error.OutOfMemory;
        if (!std.mem.eql(u8, &h.parent_hash, &parent_hash)) return error.BadParent;

        const fork = self.schedule.forkAt(h.number, h.timestamp);

        // EIP-4844 (Cancun+): the header's excessBlobGas must equal
        // max(0, parent_excess + parent_blob_used - target).
        if (fork.atLeast(.cancun)) {
            const parent_excess = self.head.excess_blob_gas orelse 0;
            const parent_used = self.head.blob_gas_used orelse 0;
            const target = txmod.targetBlobGasPerBlock(fork);
            const expected: u64 = if (parent_excess + parent_used < target) 0 else parent_excess + parent_used - target;
            if ((h.excess_blob_gas orelse 0) != expected) {
                self.last_error = "invalid excess blob gas";
                return error.InvalidExcessBlobGas;
            }
        }

        var env = vm.Environment{
            .fork = fork,
            .chain_id = self.chain_id,
            .coinbase = h.coinbase,
            .number = h.number,
            .time = h.timestamp,
            .gas_limit = h.gas_limit,
            .base_fee = h.base_fee_per_gas orelse 0,
            .prev_randao = bytesToU256(&h.prev_randao),
            .difficulty = h.difficulty,
            .block_hashes = self.hashes.items,
            .blob_base_fee = txmod.blobGasPrice(h.excess_blob_gas orelse 0, fork),
        };

        // EIP-161 touched-account set is per-block here (cleared per-tx by
        // beginTx); reset it so an empty block can't carry stale touches into
        // the block-level destroy.
        self.state.touched.clearRetainingCapacity();

        // Block-start system calls (state writes before transactions).
        if (fork.atLeast(.cancun)) if (h.parent_beacon_block_root) |r| {
            _ = self.systemCall(a, &env, BEACON_ROOTS, &r);
        };
        if (fork.atLeast(.prague))
            _ = self.systemCall(a, &env, HISTORY_STORAGE, &h.parent_hash);

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

            const tx = txmod.Tx{
                .sender = dt.sender,
                .to = dt.to,
                .nonce = dt.nonce,
                .gas_limit = dt.gas_limit,
                .gas_price = gas_price,
                .value = dt.value,
                .data = dt.data,
                .access_list = dt.access_list,
                .authorizations = dt.authorizations,
                .blob_data_fee = blob_fee,
            };
            // A block is invalid if any transaction is invalid (intrinsic gas,
            // nonce, balance, fee caps, EIP-3607/3860). The state-test runner
            // skips such blocks; the Engine API must reject them.
            if (txmod.validate(self.state, &env, tx, dt.max_fee, dt.max_priority_fee)) |reason| {
                self.last_error = reason.message();
                return error.InvalidTransaction;
            }

            var logs: std.ArrayList(vm.Log) = .empty;
            const res = txmod.processWithReceipt(a, self.state, &env, tx, &logs);
            cumulative_gas += res.gas_used;
            // Pre-Byzantium (before EIP-658) the receipt carries the intermediate
            // post-transaction state root in place of a status code.
            const post_state: ?[32]u8 = if (fork.atLeast(.byzantium))
                null
            else
                trie.stateRoot(a, self.state, false); // EIP-161 empties already destroyed per-tx
            receipts.append(a, .{
                .tx_type = dt.tx_type,
                .success = res.success,
                .cumulative_gas_used = cumulative_gas,
                .logs = logs.items,
                .post_state = post_state,
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

        // PoW block rewards (pre-Merge): pay the miner the static reward plus a
        // 1/32 nephew bonus per ommer, and pay each ommer miner a stale-depth
        // share. Post-Merge `blockReward()` is zero, so this is a no-op.
        const reward = fork.blockReward();
        if (reward > 0) {
            for (blk.ommers) |ommer| {
                // (ommer.number + 8 - block.number) * reward / 8
                const num: u256 = @as(u256, ommer.number) + 8 - @as(u256, h.number);
                const ommer_reward = num * reward / 8;
                self.state.setBalance(ommer.coinbase, self.state.balanceOf(ommer.coinbase) + ommer_reward) catch return error.OutOfMemory;
            }
            const miner_reward = reward + @as(u256, blk.ommers.len) * (reward / 32);
            self.state.setBalance(h.coinbase, self.state.balanceOf(h.coinbase) + miner_reward) catch return error.OutOfMemory;
        }

        // EIP-7685 (Prague): collect general-purpose requests in ascending type
        // order — deposits (0x00) parsed from this block's logs, then the
        // withdrawal (0x01) and consolidation (0x02) predeploy system calls
        // (which dequeue, mutating their storage) — and check the requests hash.
        if (fork.atLeast(.prague)) {
            const Sha256 = std.crypto.hash.sha2.Sha256;
            var outer = Sha256.init(.{}); // sha256 over the per-request sha256s

            var deposits: std.ArrayList(u8) = .empty;
            for (receipts.items) |*r| for (r.logs) |lg| {
                if (std.mem.eql(u8, &lg.address, &DEPOSIT_CONTRACT) and lg.topics.len > 0 and std.mem.eql(u8, &lg.topics[0], &DEPOSIT_EVENT_SIG)) {
                    const dd = extractDepositData(lg.data) orelse continue;
                    deposits.appendSlice(a, &dd) catch return error.OutOfMemory;
                }
            };
            if (deposits.items.len > 0) hashRequest(&outer, 0x00, deposits.items);

            const wd = self.systemCall(a, &env, WITHDRAWAL_REQUEST_PREDEPLOY, &.{});
            if (wd.len > 0) hashRequest(&outer, 0x01, wd);
            const cd = self.systemCall(a, &env, CONSOLIDATION_REQUEST_PREDEPLOY, &.{});
            if (cd.len > 0) hashRequest(&outer, 0x02, cd);

            var got_rh: [32]u8 = undefined;
            outer.final(&got_rh);
            const want_rh = h.requests_hash orelse std.mem.zeroes([32]u8);
            if (!std.mem.eql(u8, &got_rh, &want_rh)) {
                self.last_error = "invalid requests hash";
                return error.RequestsHashMismatch;
            }
        }

        // Validate the execution result against the header (the consensus checks).
        // EIP-161: destroy any empty accounts touched by block-level operations
        // (the coinbase reward, withdrawals, system calls) before the root.
        if (fork.atLeast(.spurious_dragon)) self.state.destroyTouchedEmpty();
        const state_root = trie.stateRoot(a, self.state, false);
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
        var size: u64 = @intCast((h.encode(a) catch return error.OutOfMemory).len);
        for (blk.transactions) |t| size += t.len;
        for (blk.withdrawals) |w| size += w.len;
        self.sizes.append(self.gpa, size + 16) catch return error.OutOfMemory; // ~RLP list overhead
        for (owned, 0..) |r, i|
            self.tx_index.put(self.gpa, r.hash, .{ .block_number = h.number, .index = @intCast(i) }) catch return error.OutOfMemory;
        return self.head;
    }

    /// Run a system call (caller = SYSTEM_ADDRESS, 30M gas, no fees) and return
    /// the call's output, copied into `a`. Empty when the target has no code.
    fn systemCall(self: *Chain, a: std.mem.Allocator, env: *const vm.Environment, to: Address, data: []const u8) []const u8 {
        if (self.state.codeOf(to).len == 0) return &.{}; // not deployed in this fork
        var evm = vm.processMessage(a, self.state, env, .{
            .caller = SYSTEM_ADDRESS,
            .current_target = to,
            .code_address = to,
            .code = self.state.codeOf(to),
            .data = data,
            .gas = 30_000_000,
            .value = 0,
        }, null);
        defer evm.deinit();
        return a.dupe(u8, evm.output) catch &.{};
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
