//! Minimal Ethereum JSON-RPC, enough for the hive `consume-rlp` simulator to
//! verify an imported chain: chain/block identity plus post-state account reads.
//! `handleBody` takes a raw request body (single or batch) and returns the
//! response JSON. State reads resolve against the current (post-import) state.

const std = @import("std");
const chain_mod = @import("chain.zig");
const state_mod = @import("state.zig");
const block = @import("block.zig");
const vm = @import("vm.zig");
const transaction = @import("transaction.zig");
const crypto = @import("crypto.zig");
const rlp = @import("rlp.zig");
const trie = @import("trie.zig");
const Address = state_mod.Address;

const CLIENT_VERSION = "zeth/0.1.0-dev";

/// Append formatted text to an arena-backed buffer.
fn p(a: std.mem.Allocator, buf: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) void {
    const s = std.fmt.allocPrint(a, fmt, args) catch @panic("oom");
    buf.appendSlice(a, s) catch @panic("oom");
}

/// Minimal-hex QUANTITY (no leading zeros; zero → "0x0").
fn qHex(a: std.mem.Allocator, v: u256) []const u8 {
    if (v == 0) return "0x0";
    return std.fmt.allocPrint(a, "0x{x}", .{v}) catch @panic("oom");
}
/// Full-width hex DATA.
fn dataHex(a: std.mem.Allocator, bytes: []const u8) []const u8 {
    var buf: std.ArrayList(u8) = .empty;
    buf.appendSlice(a, "0x") catch @panic("oom");
    for (bytes) |b| p(a, &buf, "{x:0>2}", .{b});
    return buf.items;
}
fn hash32Hex(a: std.mem.Allocator, h: [32]u8) []const u8 {
    return dataHex(a, &h);
}

fn parseAddr(s: []const u8) ?Address {
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (b.len != 40) return null;
    var out: Address = undefined;
    _ = std.fmt.hexToBytes(&out, b) catch return null;
    return out;
}
fn parseU256(s: []const u8) u256 {
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    return std.fmt.parseInt(u256, b, 16) catch 0;
}
fn parseU64(s: []const u8) u64 {
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    return std.fmt.parseInt(u64, b, 16) catch 0;
}
fn jstr(o: std.json.ObjectMap, k: []const u8) ?[]const u8 {
    const v = o.get(k) orelse return null;
    return if (v == .string) v.string else null;
}
fn hexBytes(a: std.mem.Allocator, s: []const u8) []u8 {
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    const out = a.alloc(u8, b.len / 2) catch @panic("oom");
    _ = std.fmt.hexToBytes(out, b) catch {};
    return out;
}

/// Build an EVM environment from the chain head (for eth_call/estimateGas).
fn headEnv(c: *const chain_mod.Chain) vm.Environment {
    const h = c.head;
    return .{
        .fork = c.schedule.forkAt(h.number, h.timestamp),
        .chain_id = c.chain_id,
        .coinbase = h.coinbase,
        .number = h.number,
        .time = h.timestamp,
        .gas_limit = h.gas_limit,
        .base_fee = h.base_fee_per_gas orelse 0,
        .prev_randao = std.mem.readInt(u256, &h.prev_randao, .big),
        .block_hashes = c.hashes.items,
    };
}

/// Execute a call object against a throwaway clone of the current state.
/// Returns the EVM frame (caller owns it / must deinit) and the clone (deinit
/// after reading). Used by eth_call + eth_estimateGas.
const CallResult = struct { output: []const u8, success: bool, gas_used: u64 };
fn execCall(a: std.mem.Allocator, c: *chain_mod.Chain, call: std.json.ObjectMap, gas: u64) CallResult {
    const from = if (jstr(call, "from")) |f| (parseAddr(f) orelse state_mod.zero_address) else state_mod.zero_address;
    const to = if (jstr(call, "to")) |t| (parseAddr(t) orelse state_mod.zero_address) else state_mod.zero_address;
    const data = if (jstr(call, "data") orelse jstr(call, "input")) |d| hexBytes(a, d) else &.{};
    const value = if (jstr(call, "value")) |v| parseU256(v) else 0;

    var st = c.state.clone() catch return .{ .output = "", .success = false, .gas_used = 0 };
    defer st.deinit();
    st.beginTx();
    var env = headEnv(c);
    env.origin = from;
    env.gas_price = if (jstr(call, "gasPrice")) |gp| parseU256(gp) else 0;

    var evm = vm.processMessage(a, &st, &env, .{
        .caller = from,
        .current_target = to,
        .code_address = to,
        .code = st.codeOf(to),
        .data = data,
        .gas = gas,
        .value = value,
    }, null);
    defer evm.deinit();
    const success = evm.halt_error == null and !evm.reverted;
    // Copy output out of the frame before it's freed.
    const out = a.dupe(u8, evm.output) catch "";
    return .{ .output = out, .success = success, .gas_used = gas - evm.gas_left };
}

fn parseHash(s: []const u8) ?[32]u8 {
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (b.len != 64) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, b) catch return null;
    return out;
}

/// Canonical block number for a block hash, or null.
fn numberByHash(c: *const chain_mod.Chain, hs: []const u8) ?u64 {
    const want = parseHash(hs) orelse return null;
    for (c.hashes.items, 0..) |h, n| if (std.mem.eql(u8, &h, &want)) return n;
    return null;
}

/// Block-level log index of the first log of tx `index`.
fn logBase(c: *const chain_mod.Chain, number: u64, index: u32) usize {
    var base: usize = 0;
    const txs = c.blockTxs(number);
    var i: u32 = 0;
    while (i < index and i < txs.len) : (i += 1) base += txs[i].logs.len;
    return base;
}

/// eth_getLogs: scan the block range, emit logs matching the address + topics
/// filter. Supports a single fromBlock/toBlock range or a blockHash.
fn getLogs(a: std.mem.Allocator, c: *const chain_mod.Chain, filter: std.json.ObjectMap) []const u8 {
    var from: u64 = 0;
    var to: u64 = c.head.number;
    if (jstr(filter, "blockHash")) |bh| {
        const n = numberByHash(c, bh) orelse return "[]";
        from = n;
        to = n;
    } else {
        if (jstr(filter, "fromBlock")) |f| from = resolveBlock(c, f) orelse 0;
        if (jstr(filter, "toBlock")) |t| to = resolveBlock(c, t) orelse c.head.number;
    }
    var buf: std.ArrayList(u8) = .empty;
    buf.append(a, '[') catch @panic("oom");
    var first = true;
    var n = from;
    while (n <= to and n < c.headers.items.len) : (n += 1) {
        const bh = c.hashByNumber(n) orelse continue;
        const txs = c.blockTxs(n);
        var lidx: usize = 0;
        for (txs, 0..) |rec, ti| {
            for (rec.logs) |lg| {
                if (logMatches(lg, filter)) {
                    if (!first) buf.append(a, ',') catch @panic("oom");
                    first = false;
                    buf.appendSlice(a, logJson(a, lg, bh, n, rec.hash, @intCast(ti), lidx)) catch @panic("oom");
                }
                lidx += 1;
            }
        }
    }
    buf.append(a, ']') catch @panic("oom");
    return buf.items;
}

fn addrEqStr(addr: Address, s: []const u8) bool {
    const want = parseAddr(s) orelse return false;
    return std.mem.eql(u8, &addr, &want);
}
fn topicEqStr(topic: [32]u8, s: []const u8) bool {
    const want = parseHash(s) orelse return false;
    return std.mem.eql(u8, &topic, &want);
}

/// Match a log against a filter's `address` (string | array | absent) and
/// positional `topics` (string | null | array | absent).
fn logMatches(lg: vm.Log, filter: std.json.ObjectMap) bool {
    if (filter.get("address")) |av| switch (av) {
        .string => |s| if (!addrEqStr(lg.address, s)) return false,
        .array => |arr| {
            var any = false;
            for (arr.items) |e| if (e == .string and addrEqStr(lg.address, e.string)) {
                any = true;
            };
            if (!any) return false;
        },
        else => {},
    };
    if (filter.get("topics")) |tv| if (tv == .array) {
        const want = tv.array.items;
        if (want.len > lg.topics.len) return false;
        for (want, 0..) |w, i| switch (w) {
            .null => {},
            .string => |s| if (!topicEqStr(lg.topics[i], s)) return false,
            .array => |opts| {
                var any = false;
                for (opts.items) |o| if (o == .string and topicEqStr(lg.topics[i], o.string)) {
                    any = true;
                };
                if (!any) return false;
            },
            else => {},
        };
    };
    return true;
}

/// Resolve a block tag/number param to a concrete number against the head.
fn resolveBlock(c: *const chain_mod.Chain, tag: []const u8) ?u64 {
    if (std.mem.eql(u8, tag, "latest") or std.mem.eql(u8, tag, "pending") or std.mem.eql(u8, tag, "safe") or std.mem.eql(u8, tag, "finalized"))
        return c.head.number;
    if (std.mem.eql(u8, tag, "earliest")) return 0;
    const b = if (std.mem.startsWith(u8, tag, "0x")) tag[2..] else tag;
    return std.fmt.parseInt(u64, b, 16) catch null;
}

/// JSON for a block by number. `full` selects transaction objects vs hashes.
fn blockJson(a: std.mem.Allocator, c: *const chain_mod.Chain, number: u64, full: bool) ?[]const u8 {
    const h = c.headerByNumber(number) orelse return null;
    const hash = c.hashByNumber(number) orelse return null;
    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"number\":\"{s}\",\"hash\":\"{s}\",\"parentHash\":\"{s}\"", .{ qHex(a, number), hash32Hex(a, hash), hash32Hex(a, h.parent_hash) });
    p(a, &buf, ",\"nonce\":\"{s}\",\"sha3Uncles\":\"{s}\",\"logsBloom\":\"{s}\"", .{ dataHex(a, &h.nonce), hash32Hex(a, h.ommers_hash), dataHex(a, &h.logs_bloom) });
    p(a, &buf, ",\"transactionsRoot\":\"{s}\",\"stateRoot\":\"{s}\",\"receiptsRoot\":\"{s}\"", .{ hash32Hex(a, h.transactions_root), hash32Hex(a, h.state_root), hash32Hex(a, h.receipts_root) });
    p(a, &buf, ",\"miner\":\"{s}\",\"difficulty\":\"{s}\",\"extraData\":\"{s}\"", .{ dataHex(a, &h.coinbase), qHex(a, h.difficulty), dataHex(a, h.extra_data) });
    p(a, &buf, ",\"gasLimit\":\"{s}\",\"gasUsed\":\"{s}\",\"timestamp\":\"{s}\"", .{ qHex(a, h.gas_limit), qHex(a, h.gas_used), qHex(a, h.timestamp) });
    p(a, &buf, ",\"mixHash\":\"{s}\"", .{hash32Hex(a, h.prev_randao)});
    // Fork-additive fields. EEST's consume-rlp validates the RPC block against a
    // fork-specific header model, so every field the fork mandates must be
    // present (Cancun: blob gas + parentBeaconBlockRoot; Prague: requestsHash).
    if (h.base_fee_per_gas) |bf| p(a, &buf, ",\"baseFeePerGas\":\"{s}\"", .{qHex(a, bf)});
    if (h.withdrawals_root) |wr| p(a, &buf, ",\"withdrawalsRoot\":\"{s}\"", .{hash32Hex(a, wr)});
    if (h.blob_gas_used) |g| p(a, &buf, ",\"blobGasUsed\":\"{s}\"", .{qHex(a, g)});
    if (h.excess_blob_gas) |g| p(a, &buf, ",\"excessBlobGas\":\"{s}\"", .{qHex(a, g)});
    if (h.parent_beacon_block_root) |r| p(a, &buf, ",\"parentBeaconBlockRoot\":\"{s}\"", .{hash32Hex(a, r)});
    if (h.requests_hash) |r| p(a, &buf, ",\"requestsHash\":\"{s}\"", .{hash32Hex(a, r)});
    p(a, &buf, ",\"size\":\"{s}\"", .{qHex(a, c.sizeByNumber(number))});
    // Transactions: hashes (full=false) or TransactionInfo objects (full=true).
    buf.appendSlice(a, ",\"transactions\":[") catch @panic("oom");
    const txs = c.blockTxs(number);
    for (txs, 0..) |rec, i| {
        if (i > 0) buf.append(a, ',') catch @panic("oom");
        if (full)
            buf.appendSlice(a, txInfoJson(a, c, rec, number, @intCast(i))) catch @panic("oom")
        else
            p(a, &buf, "\"{s}\"", .{hash32Hex(a, rec.hash)});
    }
    buf.appendSlice(a, "],\"uncles\":[]}") catch @panic("oom");
    return buf.items;
}

/// A signed-transaction RPC object (TransactionInfo) for a retained record.
fn txInfoJson(a: std.mem.Allocator, c: *const chain_mod.Chain, rec: chain_mod.TxRecord, number: u64, index: u32) []const u8 {
    const dt = transaction.decode(a, rec.raw) catch return "null";
    const bh = c.hashByNumber(number) orelse std.mem.zeroes([32]u8);
    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"type\":\"0x{x}\",\"hash\":\"{s}\",\"nonce\":\"{s}\"", .{ rec.tx_type, hash32Hex(a, rec.hash), qHex(a, dt.nonce) });
    p(a, &buf, ",\"blockHash\":\"{s}\",\"blockNumber\":\"{s}\",\"transactionIndex\":\"{s}\"", .{ hash32Hex(a, bh), qHex(a, number), qHex(a, index) });
    p(a, &buf, ",\"from\":\"{s}\"", .{dataHex(a, &rec.sender)});
    if (dt.to) |t| p(a, &buf, ",\"to\":\"{s}\"", .{dataHex(a, &t)}) else buf.appendSlice(a, ",\"to\":null") catch @panic("oom");
    p(a, &buf, ",\"value\":\"{s}\",\"gas\":\"{s}\",\"input\":\"{s}\"", .{ qHex(a, dt.value), qHex(a, dt.gas_limit), dataHex(a, dt.data) });
    if (dt.chain_id) |cid| p(a, &buf, ",\"chainId\":\"{s}\"", .{qHex(a, cid)});
    // Fee fields: gasPrice is the effective price for all types; 1559+ add the caps.
    p(a, &buf, ",\"gasPrice\":\"{s}\"", .{qHex(a, rec.effective_gas_price)});
    if (rec.tx_type >= 2) {
        p(a, &buf, ",\"maxFeePerGas\":\"{s}\",\"maxPriorityFeePerGas\":\"{s}\"", .{ qHex(a, dt.max_fee), qHex(a, dt.max_priority_fee) });
    }
    if (rec.tx_type >= 1) {
        buf.appendSlice(a, ",\"accessList\":[") catch @panic("oom");
        for (dt.access_list, 0..) |e, i| {
            if (i > 0) buf.append(a, ',') catch @panic("oom");
            p(a, &buf, "{{\"address\":\"{s}\",\"storageKeys\":[", .{dataHex(a, &e.address)});
            for (e.keys, 0..) |k, j| {
                if (j > 0) buf.append(a, ',') catch @panic("oom");
                var w: [32]u8 = undefined;
                std.mem.writeInt(u256, &w, k, .big);
                p(a, &buf, "\"{s}\"", .{hash32Hex(a, w)});
            }
            buf.appendSlice(a, "]}") catch @panic("oom");
        }
        buf.appendSlice(a, "]") catch @panic("oom");
    }
    if (rec.tx_type == 3) {
        p(a, &buf, ",\"maxFeePerBlobGas\":\"{s}\",\"blobVersionedHashes\":[", .{qHex(a, dt.max_fee_per_blob_gas)});
        for (dt.blob_versioned_hashes, 0..) |bvh, i| {
            if (i > 0) buf.append(a, ',') catch @panic("oom");
            p(a, &buf, "\"{s}\"", .{hash32Hex(a, bvh)});
        }
        buf.appendSlice(a, "]") catch @panic("oom");
    }
    var rb: [32]u8 = undefined;
    var sb: [32]u8 = undefined;
    std.mem.writeInt(u256, &rb, dt.r, .big);
    std.mem.writeInt(u256, &sb, dt.s, .big);
    p(a, &buf, ",\"r\":\"{s}\",\"s\":\"{s}\",\"yParity\":\"0x{x}\",\"v\":\"0x{x}\"", .{ hash32Hex(a, rb), hash32Hex(a, sb), dt.y_parity, dt.y_parity });
    buf.append(a, '}') catch @panic("oom");
    return buf.items;
}

/// A ReceiptInfo object for a retained record.
fn receiptJson(a: std.mem.Allocator, c: *const chain_mod.Chain, rec: chain_mod.TxRecord, number: u64, index: u32, log_base: usize) []const u8 {
    const bh = c.hashByNumber(number) orelse std.mem.zeroes([32]u8);
    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"type\":\"0x{x}\",\"transactionHash\":\"{s}\",\"transactionIndex\":\"{s}\"", .{ rec.tx_type, hash32Hex(a, rec.hash), qHex(a, index) });
    p(a, &buf, ",\"blockHash\":\"{s}\",\"blockNumber\":\"{s}\",\"from\":\"{s}\"", .{ hash32Hex(a, bh), qHex(a, number), dataHex(a, &rec.sender) });
    if (rec.to) |t| p(a, &buf, ",\"to\":\"{s}\"", .{dataHex(a, &t)}) else buf.appendSlice(a, ",\"to\":null") catch @panic("oom");
    p(a, &buf, ",\"cumulativeGasUsed\":\"{s}\",\"gasUsed\":\"{s}\"", .{ qHex(a, rec.cumulative_gas_used), qHex(a, rec.gas_used) });
    if (rec.contract_address) |ca| p(a, &buf, ",\"contractAddress\":\"{s}\"", .{dataHex(a, &ca)}) else buf.appendSlice(a, ",\"contractAddress\":null") catch @panic("oom");
    const bloom = block.logsBloom(rec.logs);
    p(a, &buf, ",\"logsBloom\":\"{s}\",\"status\":\"0x{x}\",\"effectiveGasPrice\":\"{s}\"", .{ dataHex(a, &bloom), @as(u8, if (rec.success) 1 else 0), qHex(a, rec.effective_gas_price) });
    buf.appendSlice(a, ",\"logs\":[") catch @panic("oom");
    for (rec.logs, 0..) |lg, li| {
        if (li > 0) buf.append(a, ',') catch @panic("oom");
        buf.appendSlice(a, logJson(a, lg, bh, number, rec.hash, index, log_base + li)) catch @panic("oom");
    }
    buf.appendSlice(a, "]}") catch @panic("oom");
    return buf.items;
}

/// A Log object.
fn logJson(a: std.mem.Allocator, lg: vm.Log, block_hash: [32]u8, number: u64, tx_hash: [32]u8, tx_index: u32, log_index: usize) []const u8 {
    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"address\":\"{s}\",\"topics\":[", .{dataHex(a, &lg.address)});
    for (lg.topics, 0..) |t, i| {
        if (i > 0) buf.append(a, ',') catch @panic("oom");
        p(a, &buf, "\"{s}\"", .{hash32Hex(a, t)});
    }
    p(a, &buf, "],\"data\":\"{s}\"", .{dataHex(a, lg.data)});
    p(a, &buf, ",\"blockHash\":\"{s}\",\"blockNumber\":\"{s}\",\"transactionHash\":\"{s}\"", .{ hash32Hex(a, block_hash), qHex(a, number), hash32Hex(a, tx_hash) });
    p(a, &buf, ",\"transactionIndex\":\"{s}\",\"logIndex\":\"{s}\",\"removed\":false}}", .{ qHex(a, tx_index), qHex(a, log_index) });
    return buf.items;
}

/// Render the `id` field verbatim (number, string, or null).
fn idJson(a: std.mem.Allocator, id: ?std.json.Value) []const u8 {
    const v = id orelse return "null";
    return switch (v) {
        .integer => std.fmt.allocPrint(a, "{d}", .{v.integer}) catch @panic("oom"),
        .string => std.fmt.allocPrint(a, "\"{s}\"", .{v.string}) catch @panic("oom"),
        .null => "null",
        else => "null",
    };
}

fn ok(a: std.mem.Allocator, id: ?std.json.Value, result: []const u8) []const u8 {
    return std.fmt.allocPrint(a, "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}", .{ idJson(a, id), result }) catch @panic("oom");
}
fn okStr(a: std.mem.Allocator, id: ?std.json.Value, result: []const u8) []const u8 {
    return std.fmt.allocPrint(a, "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":\"{s}\"}}", .{ idJson(a, id), result }) catch @panic("oom");
}
fn err(a: std.mem.Allocator, id: ?std.json.Value, code: i32, msg: []const u8) []const u8 {
    return std.fmt.allocPrint(a, "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"error\":{{\"code\":{d},\"message\":\"{s}\"}}}}", .{ idJson(a, id), code, msg }) catch @panic("oom");
}

fn strParam(params: []const std.json.Value, i: usize) ?[]const u8 {
    if (i >= params.len) return null;
    return if (params[i] == .string) params[i].string else null;
}

/// Dispatch a single request object.
/// Render a list of RLP-encoded MPT nodes as a JSON array of 0x-hex strings.
fn proofArray(a: std.mem.Allocator, nodes: []const []const u8) []const u8 {
    var buf: std.ArrayList(u8) = .empty;
    buf.append(a, '[') catch @panic("oom");
    for (nodes, 0..) |n, i| {
        if (i != 0) buf.append(a, ',') catch @panic("oom");
        p(a, &buf, "\"{s}\"", .{dataHex(a, n)});
    }
    buf.append(a, ']') catch @panic("oom");
    return buf.toOwnedSlice(a) catch @panic("oom");
}

/// EIP-1186 `eth_getProof`: account + storage Merkle proofs against the head
/// state. Works for present and absent accounts/slots (exclusion proofs).
fn getProof(a: std.mem.Allocator, c: *chain_mod.Chain, addr: Address, keys: []const std.json.Value) []const u8 {
    const prune = c.schedule.forkAt(c.head.number, c.head.timestamp).atLeast(.spurious_dragon);
    const acct_proof = trie.accountProof(a, c.state, prune, addr);
    const acc = c.state.accounts.getPtr(addr);
    const nonce: u64 = if (acc) |x| x.nonce else 0;
    const balance: u256 = if (acc) |x| x.balance else 0;
    const code: []const u8 = if (acc) |x| x.code else &.{};
    const code_hash = crypto.keccak256(code);
    const storage_root: [32]u8 = if (acc) |x| trie.storageRoot(a, x.storage) else trie.EMPTY_TRIE_ROOT;

    var sp: std.ArrayList(u8) = .empty;
    sp.append(a, '[') catch @panic("oom");
    for (keys, 0..) |kv, i| {
        if (kv != .string) continue;
        const key = parseU256(kv.string);
        const value = c.state.getStorage(addr, key);
        const nodes = if (acc) |x| trie.storageProof(a, x.storage, key) else &[_][]const u8{};
        var kb: [32]u8 = undefined;
        std.mem.writeInt(u256, &kb, key, .big);
        if (i != 0) sp.append(a, ',') catch @panic("oom");
        p(a, &sp, "{{\"key\":\"{s}\",\"value\":\"{s}\",\"proof\":{s}}}", .{ hash32Hex(a, kb), qHex(a, value), proofArray(a, nodes) });
    }
    sp.append(a, ']') catch @panic("oom");

    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"address\":\"{s}\",\"accountProof\":{s},\"balance\":\"{s}\",\"codeHash\":\"{s}\",\"nonce\":\"{s}\",\"storageHash\":\"{s}\",\"storageProof\":{s}}}", .{
        dataHex(a, &addr),
        proofArray(a, acct_proof),
        qHex(a, balance),
        hash32Hex(a, code_hash),
        qHex(a, nonce),
        hash32Hex(a, storage_root),
        sp.toOwnedSlice(a) catch @panic("oom"),
    });
    return buf.toOwnedSlice(a) catch @panic("oom");
}

/// The transaction hash of a raw `eth_sendRawTransaction` payload. For a blob
/// (type-3) transaction submitted in its network sidecar-wrapper form
/// (`0x03 ‖ rlp([txbody, blobs, commitments, proofs])`), the hash is taken over
/// just `0x03 ‖ rlp(txbody)`; everything else hashes the payload directly.
fn rawTxHash(a: std.mem.Allocator, raw: []const u8) [32]u8 {
    if (raw.len >= 2 and raw[0] == 0x03) {
        const body = raw[1..];
        // Skip the outer list header to reach the first element (txbody).
        const b0 = body[0];
        const payload_start: usize = if (b0 >= 0xf8) 1 + (b0 - 0xf7) else if (b0 >= 0xc0) 1 else 0;
        if (payload_start > 0 and payload_start < body.len and body[payload_start] >= 0xc0) {
            // First element is itself a list → this is the sidecar wrapper.
            const dec = rlp.decodeItem(a, body[payload_start..]) catch return crypto.keccak256(raw);
            const txbody = body[payload_start .. payload_start + dec.consumed];
            const buf = a.alloc(u8, 1 + txbody.len) catch return crypto.keccak256(raw);
            buf[0] = 0x03;
            @memcpy(buf[1..], txbody);
            return crypto.keccak256(buf);
        }
    }
    return crypto.keccak256(raw);
}

/// True for a precompile address (0x00…01 … 0x00…14): 19 zero bytes then a
/// small index. These are always warm and never listed in an access list.
fn isPrecompile(addr: Address) bool {
    for (addr[0..19]) |b| if (b != 0) return false;
    return addr[19] >= 1 and addr[19] <= 0x14;
}

/// eth_createAccessList: run the call, collect the EIP-2929 addresses/slots it
/// touched (excluding the sender, precompiles, and the implicitly-warm
/// from/to/coinbase when they carry no storage), and report gasUsed (intrinsic
/// + execution) and any execution error.
fn createAccessList(a: std.mem.Allocator, c: *chain_mod.Chain, call: std.json.ObjectMap) []const u8 {
    const from = if (jstr(call, "from")) |f| (parseAddr(f) orelse state_mod.zero_address) else state_mod.zero_address;
    const to = if (jstr(call, "to")) |t| (parseAddr(t) orelse state_mod.zero_address) else state_mod.zero_address;
    const data = if (jstr(call, "data") orelse jstr(call, "input")) |d| hexBytes(a, d) else &.{};
    const value = if (jstr(call, "value")) |v| parseU256(v) else 0;

    var zero: u64 = 0;
    var nz: u64 = 0;
    for (data) |b| if (b == 0) {
        zero += 1;
    } else {
        nz += 1;
    };
    const is_create = jstr(call, "to") == null;
    const intrinsic: u64 = 21000 + zero * 4 + nz * 16 + (if (is_create) @as(u64, 32000) else 0);
    const msg_gas: u64 = if (c.head.gas_limit > intrinsic) c.head.gas_limit - intrinsic else 0;

    var st = c.state.clone() catch return "{\"accessList\":[],\"gasUsed\":\"0x0\"}";
    defer st.deinit();
    st.beginTx();
    var env = headEnv(c);
    env.origin = from;
    var evm = vm.processMessage(a, &st, &env, .{
        .caller = from,
        .current_target = to,
        .code_address = to,
        .code = st.codeOf(to),
        .data = data,
        .gas = msg_gas,
        .value = value,
    }, null);
    defer evm.deinit();
    const reverted = evm.reverted;
    const failed = evm.halt_error != null;
    const gas_used = intrinsic + (msg_gas - evm.gas_left);

    // Group accessed storage slots by address.
    const Entry = struct { addr: Address, keys: std.ArrayList(u256) };
    var entries: std.ArrayList(Entry) = .empty;
    const find = struct {
        fn f(list: *std.ArrayList(Entry), al: std.mem.Allocator, addr: Address) *Entry {
            for (list.items) |*e| if (std.mem.eql(u8, &e.addr, &addr)) return e;
            list.append(al, .{ .addr = addr, .keys = .empty }) catch @panic("oom");
            return &list.items[list.items.len - 1];
        }
    }.f;

    var sk = st.accessed_storage_keys.iterator();
    while (sk.next()) |e| {
        const addr = e.key_ptr.addr;
        if (std.mem.eql(u8, &addr, &from) or isPrecompile(addr)) continue;
        const ent = find(&entries, a, addr);
        ent.keys.append(a, e.key_ptr.key) catch @panic("oom");
    }
    // Address-only accesses (BALANCE/EXTCODE*/CALL): list them too, unless they
    // are implicitly warm (from/to/coinbase) and carry no storage.
    var ad = st.accessed_addresses.iterator();
    while (ad.next()) |e| {
        const addr = e.key_ptr.*;
        if (std.mem.eql(u8, &addr, &from) or isPrecompile(addr)) continue;
        if (std.mem.eql(u8, &addr, &to) or std.mem.eql(u8, &addr, &c.head.coinbase)) continue;
        _ = find(&entries, a, addr); // ensure present (empty keys ok)
    }

    var buf: std.ArrayList(u8) = .empty;
    buf.appendSlice(a, "{\"accessList\":[") catch @panic("oom");
    var first = true;
    for (entries.items) |*e| {
        // Drop entries with no storage keys that are only implicitly warm.
        if (e.keys.items.len == 0 and (std.mem.eql(u8, &e.addr, &to) or std.mem.eql(u8, &e.addr, &c.head.coinbase))) continue;
        std.mem.sort(u256, e.keys.items, {}, std.sort.asc(u256));
        if (!first) buf.append(a, ',') catch @panic("oom");
        first = false;
        p(a, &buf, "{{\"address\":\"{s}\",\"storageKeys\":[", .{dataHex(a, &e.addr)});
        for (e.keys.items, 0..) |k, i| {
            if (i != 0) buf.append(a, ',') catch @panic("oom");
            var kb: [32]u8 = undefined;
            std.mem.writeInt(u256, &kb, k, .big);
            p(a, &buf, "\"{s}\"", .{hash32Hex(a, kb)});
        }
        buf.appendSlice(a, "]}") catch @panic("oom");
    }
    buf.appendSlice(a, "]") catch @panic("oom");
    if (reverted) {
        p(a, &buf, ",\"error\":\"execution reverted\"", .{});
    } else if (failed) {
        p(a, &buf, ",\"error\":\"{s}\"", .{@errorName(evm.halt_error.?)});
    }
    p(a, &buf, ",\"gasUsed\":\"{s}\"}}", .{qHex(a, gas_used)});
    return buf.toOwnedSlice(a) catch @panic("oom");
}

/// Method names this node routes — returned by `eth_capabilities` (the
/// rpc-compat check is schema-only: a JSON array of strings).
const CAPABILITIES = [_][]const u8{
    "eth_blockNumber",        "eth_chainId",                "eth_call",
    "eth_estimateGas",        "eth_gasPrice",               "eth_baseFee",
    "eth_maxPriorityFeePerGas", "eth_feeHistory",           "eth_blobBaseFee",
    "eth_getBalance",         "eth_getCode",                "eth_getStorageAt",
    "eth_getProof",           "eth_getTransactionCount",    "eth_getBlockByHash",
    "eth_getBlockByNumber",   "eth_getBlockReceipts",       "eth_getTransactionByHash",
    "eth_getTransactionReceipt", "eth_getLogs",             "eth_sendRawTransaction",
    "eth_syncing",            "eth_chainId",
};

/// The EIP-1559 base fee of the block that would follow the head.
fn nextBaseFee(c: *chain_mod.Chain) u256 {
    const parent = c.head.base_fee_per_gas orelse return 0;
    const DENOM: u256 = 8; // BASE_FEE_MAX_CHANGE_DENOMINATOR
    const ELASTICITY: u64 = 2;
    const target: u64 = c.head.gas_limit / ELASTICITY;
    if (target == 0) return parent;
    const used = c.head.gas_used;
    if (used == target) return parent;
    if (used > target) {
        const delta = (parent * (used - target)) / target / DENOM;
        return parent + @max(delta, 1);
    }
    const delta = (parent * (target - used)) / target / DENOM;
    return if (parent > delta) parent - delta else 0;
}

// ── eth_simulateV1 (EIP-7756 / multi-block call simulation) ───────────────────

fn jbool(o: std.json.ObjectMap, k: []const u8) bool {
    const v = o.get(k) orelse return false;
    return v == .bool and v.bool;
}
fn jU64opt(o: std.json.ObjectMap, k: []const u8) ?u64 {
    const v = o.get(k) orelse return null;
    return switch (v) {
        .string => parseU64(v.string),
        .integer => @intCast(v.integer),
        else => null,
    };
}
fn jU256opt(o: std.json.ObjectMap, k: []const u8) ?u256 {
    const v = o.get(k) orelse return null;
    return switch (v) {
        .string => parseU256(v.string),
        .integer => @intCast(v.integer),
        else => null,
    };
}

/// Apply an eth_simulateV1 `stateOverrides` map to `st`: per-account balance,
/// nonce, code, and storage (`state` = full replace, `stateDiff` = merge).
const SimErr = struct { code: i32, msg: []const u8 };

fn applyStateOverrides(a: std.mem.Allocator, st: *state_mod.State, ov: std.json.ObjectMap) ?SimErr {
    var it = ov.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* != .object) continue;
        const addr = parseAddr(e.key_ptr.*) orelse continue;
        const o = e.value_ptr.object;
        // movePrecompileToAddress requires the source to be a precompile.
        if (jstr(o, "movePrecompileToAddress")) |_| {
            if (!isPrecompile(addr))
                return .{ .code = -32000, .msg = std.fmt.allocPrint(a, "account {s} is not a precompile", .{dataHex(a, &addr)}) catch "not a precompile" };
        }
        if (jU256opt(o, "balance")) |b| st.setBalance(addr, b) catch {};
        if (jU64opt(o, "nonce")) |n| st.setNonce(addr, n) catch {};
        if (jstr(o, "code")) |code| st.setCode(addr, hexBytes(a, code)) catch {};
        // `state` clears all existing storage first; `stateDiff` merges.
        if (o.get("state")) |s| if (s == .object) {
            st.clearStorage(addr);
            var sit = s.object.iterator();
            while (sit.next()) |kv| if (kv.value_ptr.* == .string)
                st.setStorage(addr, parseU256(kv.key_ptr.*), parseU256(kv.value_ptr.string)) catch {};
        };
        if (o.get("stateDiff")) |s| if (s == .object) {
            var sit = s.object.iterator();
            while (sit.next()) |kv| if (kv.value_ptr.* == .string)
                st.setStorage(addr, parseU256(kv.key_ptr.*), parseU256(kv.value_ptr.string)) catch {};
        };
    }
    return null;
}

const SimBlock = struct { number: u64, time: u64, ov: ?std.json.ObjectMap, so: ?std.json.ObjectMap, calls: []const std.json.Value };

const SIM_SYSTEM_ADDR: Address = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
const SIM_BEACON_ROOTS: Address = .{ 0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E, 0xf1, 0x31, 0x9f, 0xB7, 0xB8, 0xbB, 0x85, 0x22, 0xd0, 0xBe, 0xac, 0x02 };
const SIM_HISTORY_STORAGE: Address = .{ 0x00, 0x00, 0xF9, 0x08, 0x27, 0xF1, 0xC5, 0x3a, 0x10, 0xcb, 0x7A, 0x02, 0x33, 0x5B, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35 };

fn simSystemCall(a: std.mem.Allocator, st: *state_mod.State, env: *const vm.Environment, to: Address, data: []const u8) void {
    if (st.codeOf(to).len == 0) return;
    var evm = vm.processMessage(a, st, env, .{
        .caller = SIM_SYSTEM_ADDR,
        .current_target = to,
        .code_address = to,
        .code = st.codeOf(to),
        .data = data,
        .gas = 30_000_000,
        .value = 0,
    }, null);
    evm.deinit();
}

fn simulateV1(a: std.mem.Allocator, id: ?std.json.Value, c: *chain_mod.Chain, opts: std.json.ObjectMap, base_tag: []const u8) []const u8 {
    const validation = jbool(opts, "validation");
    const bsc_v = opts.get("blockStateCalls") orelse return err(a, id, -32602, "missing blockStateCalls");
    if (bsc_v != .array) return err(a, id, -32602, "invalid blockStateCalls");

    const base_num = resolveBlock(c, base_tag) orelse return err(a, id, -32000, "header not found");
    if (base_num > c.head.number) return err(a, id, -32000, "header not found");
    const base = c.headerByNumber(base_num) orelse return err(a, id, -32000, "header not found");
    const base_hash = base.hash(a) catch return err(a, id, -32603, "hash");

    // sanitizeChain: assign block numbers (default prev+1) and timestamps
    // (default prev+12), filling numeric gaps with empty blocks.
    var blocks: std.ArrayList(SimBlock) = .empty;
    var prev_num = base.number;
    var prev_time = base.timestamp;
    for (bsc_v.array.items) |b_v| {
        if (b_v != .object) return err(a, id, -32602, "invalid block");
        const bo = b_v.object;
        const ov: ?std.json.ObjectMap = if (bo.get("blockOverrides")) |x| (if (x == .object) x.object else null) else null;
        const num = if (ov != null) (jU64opt(ov.?, "number") orelse prev_num + 1) else prev_num + 1;
        if (num <= prev_num) return err(a, id, -38020, "block numbers must be in order");
        if (num - base.number > 256) return err(a, id, -38026, "too many blocks"); // maxSimulateBlocks
        // Fill gaps with empty blocks.
        var fill = prev_num + 1;
        while (fill < num) : (fill += 1) {
            prev_time += 12;
            blocks.append(a, .{ .number = fill, .time = prev_time, .ov = null, .so = null, .calls = &.{} }) catch return err(a, id, -32603, "oom");
        }
        const t = if (ov != null) (jU64opt(ov.?, "time") orelse prev_time + 12) else prev_time + 12;
        if (t <= prev_time) return err(a, id, -38021, "block timestamps must be in order");
        const calls: []const std.json.Value = if (bo.get("calls")) |cl| (if (cl == .array) cl.array.items else &.{}) else &.{};
        const so: ?std.json.ObjectMap = if (bo.get("stateOverrides")) |x| (if (x == .object) x.object else null) else null;
        blocks.append(a, .{ .number = num, .time = t, .ov = ov, .so = so, .calls = calls }) catch return err(a, id, -32603, "oom");
        prev_num = num;
        prev_time = t;
    }

    // Simulate on a clone of the head state (the only state we retain). Changes
    // persist across the block sequence.
    var st = c.state.clone() catch return err(a, id, -32603, "oom");
    defer st.deinit();

    var out: std.ArrayList(u8) = .empty;
    out.append(a, '[') catch return err(a, id, -32603, "oom");
    var coinbase = base.coinbase;
    var parent_hash = base_hash;
    var prev_base_fee: u256 = base.base_fee_per_gas orelse 0;
    var prev_gas_used: u64 = base.gas_used;
    var prev_gas_limit: u64 = base.gas_limit;

    for (blocks.items, 0..) |blk, bidx| {
        const fork = c.schedule.forkAt(blk.number, blk.time);
        if (blk.ov) |ov| if (jstr(ov, "feeRecipient")) |fr| {
            if (parseAddr(fr)) |addr| coinbase = addr;
        };
        const base_fee: ?u256 = if (fork.atLeast(.london)) blk: {
            if (blk.ov) |ov| if (jU256opt(ov, "baseFeePerGas")) |bf| break :blk bf;
            // Validation mode computes EIP-1559 base fee from the parent;
            // non-validation defaults to 0 (so gasPrice < baseFee is allowed).
            break :blk if (validation) calcBaseFee(prev_base_fee, prev_gas_used, prev_gas_limit) else 0;
        } else null;
        var prev_randao = std.mem.zeroes([32]u8);
        if (blk.ov) |ov| if (jstr(ov, "prevRandao")) |pr| {
            prev_randao = hashFromHex(pr);
        };

        var hdr = block.Header{
            .parent_hash = parent_hash,
            .coinbase = coinbase,
            .number = blk.number,
            .gas_limit = if (blk.ov != null) (jU64opt(blk.ov.?, "gasLimit") orelse base.gas_limit) else base.gas_limit,
            .timestamp = blk.time,
            .prev_randao = prev_randao,
            .difficulty = if (fork.atLeast(.paris)) 0 else base.difficulty,
            .base_fee_per_gas = base_fee,
            .withdrawals_root = if (fork.atLeast(.shanghai)) trie.EMPTY_TRIE_ROOT else null,
            .parent_beacon_block_root = if (fork.atLeast(.cancun)) std.mem.zeroes([32]u8) else null,
            .blob_gas_used = if (fork.atLeast(.cancun)) 0 else null,
            .excess_blob_gas = if (fork.atLeast(.cancun)) 0 else null,
        };

        // State overrides apply before execution.
        if (blk.ov == null) {} // no-op
        if (blk.calls.len == 0 and blk.ov == null) {} // empty block fast-path uses defaults
        if (blk.so) |so| {
            if (applyStateOverrides(a, &st, so)) |se| return err(a, id, se.code, se.msg);
        }

        var env = vm.Environment{
            .fork = fork,
            .chain_id = c.chain_id,
            .coinbase = coinbase,
            .number = blk.number,
            .time = blk.time,
            .gas_limit = hdr.gas_limit,
            .base_fee = base_fee orelse 0,
            .prev_randao = bytesToU256RPC(&prev_randao),
            .block_hashes = c.hashes.items,
        };

        // Block-start system calls mutate predeploy storage (so the empty-block
        // state root differs from the parent's): EIP-4788 beacon root (Cancun+)
        // and EIP-2935 history storage (Prague+).
        if (fork.atLeast(.cancun)) simSystemCall(a, &st, &env, SIM_BEACON_ROOTS, &hdr.parent_beacon_block_root.?);
        if (fork.atLeast(.prague)) simSystemCall(a, &st, &env, SIM_HISTORY_STORAGE, &hdr.parent_hash);

        var receipts: std.ArrayList(block.Receipt) = .empty;
        var tx_encs: std.ArrayList([]const u8) = .empty;
        var calls_json: std.ArrayList(u8) = .empty;
        calls_json.append(a, '[') catch {};
        var cum_gas: u64 = 0;
        var gas_pool: u64 = hdr.gas_limit;

        for (blk.calls, 0..) |call_v, ci| {
            if (call_v != .object) continue;
            const cr = simExecCall(a, &st, &env, call_v.object, gas_pool, validation);
            if (cr.err_code != 0) return err(a, id, cr.err_code, cr.err_msg);
            cum_gas += cr.gas_used;
            if (gas_pool >= cr.gas_used) gas_pool -= cr.gas_used else gas_pool = 0;
            receipts.append(a, .{ .tx_type = 2, .success = cr.success, .cumulative_gas_used = cum_gas, .logs = cr.logs }) catch {};
            tx_encs.append(a, cr.tx_enc) catch {};
            if (ci != 0) calls_json.append(a, ',') catch {};
            calls_json.appendSlice(a, cr.json) catch {};
        }
        calls_json.append(a, ']') catch {};

        if (fork.atLeast(.spurious_dragon)) st.destroyTouchedEmpty();
        hdr.gas_used = cum_gas;
        hdr.state_root = trie.stateRoot(a, &st, false);
        hdr.transactions_root = block.orderedTrieRoot(a, tx_encs.items);
        hdr.receipts_root = block.receiptsRoot(a, receipts.items);
        var bloom = std.mem.zeroes([256]u8);
        for (receipts.items) |*r| block.orBloom(&bloom, block.logsBloom(r.logs));
        hdr.logs_bloom = bloom;
        if (fork.atLeast(.prague)) {
            var rh: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("", &rh, .{});
            hdr.requests_hash = rh;
        }

        const blk_hash = hdr.hash(a) catch return err(a, id, -32603, "hash");
        parent_hash = blk_hash;
        prev_base_fee = base_fee orelse 0;
        prev_gas_used = hdr.gas_used;
        prev_gas_limit = hdr.gas_limit;

        if (bidx != 0) out.append(a, ',') catch {};
        out.appendSlice(a, simBlockJson(a, &hdr, blk_hash, calls_json.items)) catch {};
    }
    out.append(a, ']') catch {};
    return ok(a, id, out.toOwnedSlice(a) catch return err(a, id, -32603, "oom"));
}

fn bytesToU256RPC(b: *const [32]u8) u256 {
    return std.mem.readInt(u256, b, .big);
}

/// EIP-1559 base fee of a block given its parent's base fee, gas used, and gas
/// limit (validation mode; mirrors nextBaseFee but parameterized by the parent).
fn calcBaseFee(parent_base: u256, gas_used: u64, gas_limit: u64) u256 {
    const target: u64 = gas_limit / 2;
    if (target == 0 or gas_used == target) return parent_base;
    if (gas_used > target) {
        const delta = (parent_base * (gas_used - target)) / target / 8;
        return parent_base + @max(delta, 1);
    }
    const delta = (parent_base * (target - gas_used)) / target / 8;
    return if (parent_base > delta) parent_base - delta else 0;
}

const SimCallResult = struct { gas_used: u64, success: bool, logs: []const vm.Log, json: []const u8, tx_enc: []const u8, err_code: i32 = 0, err_msg: []const u8 = "" };

const SIM_GAS_CAP: u64 = 50_000_000; // geth's default RPCGasCap

/// EIP-55 checksummed address string ("0x" + mixed-case hex), as geth prints
/// addresses in error messages.
fn checksumAddr(a: std.mem.Allocator, addr: Address) []const u8 {
    const lower = std.fmt.bytesToHex(&addr, .lower); // 40 chars
    const h = crypto.keccak256(&lower);
    var out = a.alloc(u8, 42) catch @panic("oom");
    out[0] = '0';
    out[1] = 'x';
    for (lower, 0..) |ch, i| {
        const shift: u3 = if (i % 2 == 0) 4 else 0;
        const nibble = (h[i / 2] >> shift) & 0x0f;
        out[2 + i] = if (ch >= 'a' and ch <= 'f' and nibble >= 8) ch - 32 else ch;
    }
    return out;
}

fn rlpMinU256(a: std.mem.Allocator, v: u256) []const u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, v, .big);
    var s: usize = 0;
    while (s < 32 and buf[s] == 0) s += 1;
    return rlp.encodeBytes(a, buf[s..]) catch @panic("oom");
}

/// Encode a simulated call as an unsigned EIP-1559 (type-2) transaction — the
/// form eth_simulateV1 uses to build the synthetic block's transactions root.
fn encodeSimTx(a: std.mem.Allocator, chain_id: u64, nonce: u64, gas: u64, to: ?Address, value: u256, data: []const u8) []const u8 {
    const empty_al = rlp.encodeList(a, &.{}) catch @panic("oom");
    const to_enc = if (to) |t| (rlp.encodeBytes(a, &t) catch @panic("oom")) else (rlp.encodeBytes(a, &.{}) catch @panic("oom"));
    const items = [_][]const u8{
        rlpMinU256(a, chain_id), rlpMinU256(a, nonce), rlpMinU256(a, 0), rlpMinU256(a, 0),
        rlpMinU256(a, gas),      to_enc,               rlpMinU256(a, value),
        rlp.encodeBytes(a, data) catch @panic("oom"), empty_al,
        rlpMinU256(a, 0),        rlpMinU256(a, 0),     rlpMinU256(a, 0),
    };
    const list = rlp.encodeList(a, &items) catch @panic("oom");
    const out = a.alloc(u8, 1 + list.len) catch @panic("oom");
    out[0] = 0x02;
    @memcpy(out[1..], list);
    return out;
}

/// Execute one eth_simulateV1 call against `st` (committing on success,
/// reverting on failure), returning its result + the tx encoding for the root.
fn simExecCall(a: std.mem.Allocator, st: *state_mod.State, env: *vm.Environment, call: std.json.ObjectMap, gas_pool: u64, validation: bool) SimCallResult {
    const from = if (jstr(call, "from")) |f| (parseAddr(f) orelse state_mod.zero_address) else state_mod.zero_address;
    const to: ?Address = if (jstr(call, "to")) |t| parseAddr(t) else null;
    const value = if (jstr(call, "value")) |v| parseU256(v) else 0;
    const data = if (jstr(call, "data") orelse jstr(call, "input")) |d| hexBytes(a, d) else &.{};
    const nonce = jU64opt(call, "nonce") orelse st.nonceOf(from);
    // Default gas is the remaining block gas, clamped to the RPC gas cap.
    const call_gas = jU64opt(call, "gas") orelse @min(gas_pool, SIM_GAS_CAP);
    const gas = @min(@min(call_gas, gas_pool), SIM_GAS_CAP);

    var zero_b: u64 = 0;
    var nz: u64 = 0;
    for (data) |b| if (b == 0) {
        zero_b += 1;
    } else {
        nz += 1;
    };
    const is_create = to == null;
    const intrinsic: u64 = 21000 + zero_b * 4 + nz * 16 + (if (is_create) @as(u64, 32000) else 0);

    const gas_price: u256 = if (validation) (if (jstr(call, "gasPrice") orelse jstr(call, "maxFeePerGas")) |gp| parseU256(gp) else env.base_fee) else 0;
    // Validation-mode pre-checks: nonce overflow and fee cap below base fee.
    if (validation) {
        if (nonce == std.math.maxInt(u64))
            return .{ .gas_used = 0, .success = false, .logs = &.{}, .json = "", .tx_enc = "", .err_code = -32603, .err_msg = std.fmt.allocPrint(a, "err: nonce has max value: address {s}, nonce: {d} (supplied gas {d})", .{ checksumAddr(a, from), nonce, gas }) catch "nonce has max value" };
        const max_fee: u256 = if (jstr(call, "maxFeePerGas") orelse jstr(call, "gasPrice")) |gp| parseU256(gp) else 0;
        if (max_fee < env.base_fee)
            return .{ .gas_used = 0, .success = false, .logs = &.{}, .json = "", .tx_enc = "", .err_code = -38012, .err_msg = std.fmt.allocPrint(a, "err: max fee per gas less than block base fee: address {s}, maxFeePerGas: {d}, baseFee: {d} (supplied gas {d})", .{ checksumAddr(a, from), max_fee, env.base_fee, gas }) catch "max fee too low" };
    }
    // EIP-7756 pre-execution checks (apply even in non-validation mode):
    if (gas < intrinsic) return .{ .gas_used = 0, .success = false, .logs = &.{}, .json = "", .tx_enc = "", .err_code = -38013, .err_msg = std.fmt.allocPrint(a, "err: intrinsic gas too low: have {d}, want {d} (supplied gas {d})", .{ gas, intrinsic, gas }) catch "intrinsic gas too low" };
    const need: u256 = value + @as(u256, gas) * gas_price;
    if (st.balanceOf(from) < need) return .{ .gas_used = 0, .success = false, .logs = &.{}, .json = "", .tx_enc = "", .err_code = -38014, .err_msg = std.fmt.allocPrint(a, "err: insufficient funds for gas * price + value: address {s} have {d} want {d} (supplied gas {d})", .{ checksumAddr(a, from), st.balanceOf(from), need, gas }) catch "insufficient funds" };

    env.origin = from;
    env.gas_price = gas_price;
    st.beginTx();
    st.setNonce(from, nonce +% 1) catch {};

    const msg_gas: u64 = if (gas > intrinsic) gas - intrinsic else 0;
    const target = to orelse (state_mod.computeContractAddress(a, from, nonce) catch state_mod.zero_address);
    var evm = vm.processMessage(a, st, env, .{
        .caller = from,
        .current_target = target,
        .code_address = target,
        .code = st.codeOf(target),
        .data = data,
        .gas = msg_gas,
        .value = value,
    }, null);
    defer evm.deinit();
    const success = evm.halt_error == null and !evm.reverted;
    var gas_used = intrinsic + (msg_gas - evm.gas_left);
    if (success) {
        var refund: i64 = evm.refund_counter;
        if (refund < 0) refund = 0;
        const cap: u64 = if (env.fork.atLeast(.london)) gas_used / 5 else gas_used / 2;
        gas_used -= @min(@as(u64, @intCast(refund)), cap);
    }
    if (env.fork.atLeast(.spurious_dragon)) st.destroyTouchedEmpty();

    const output = a.dupe(u8, evm.output) catch "";
    var logs_buf: std.ArrayList(vm.Log) = .empty;
    if (success) for (evm.logs.items) |lg| {
        logs_buf.append(a, .{ .address = lg.address, .topics = a.dupe([32]u8, lg.topics) catch &.{}, .data = a.dupe(u8, lg.data) catch "" }) catch {};
    };

    // Per-call result JSON.
    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"returnData\":\"{s}\",\"gasUsed\":\"{s}\",\"logs\":[", .{ dataHex(a, output), qHex(a, gas_used) });
    for (logs_buf.items, 0..) |lg, i| {
        if (i != 0) buf.append(a, ',') catch {};
        p(a, &buf, "{{\"address\":\"{s}\",\"topics\":[", .{dataHex(a, &lg.address)});
        for (lg.topics, 0..) |t, j| {
            if (j != 0) buf.append(a, ',') catch {};
            p(a, &buf, "\"{s}\"", .{hash32Hex(a, t)});
        }
        p(a, &buf, "],\"data\":\"{s}\"}}", .{dataHex(a, lg.data)});
    }
    p(a, &buf, "],\"status\":\"{s}\"", .{if (success) "0x1" else "0x0"});
    if (!success) {
        const msg = if (evm.reverted) "execution reverted" else "execution error";
        p(a, &buf, ",\"error\":{{\"code\":{d},\"message\":\"{s}\"}}", .{ @as(i32, if (evm.reverted) 3 else -32000), msg });
    }
    buf.append(a, '}') catch {};

    const tx_enc = encodeSimTx(a, env.chain_id, nonce, gas, to, value, data);
    return .{ .gas_used = gas_used, .success = success, .logs = logs_buf.items, .json = buf.toOwnedSlice(a) catch "", .tx_enc = tx_enc };
}

/// Format a synthetic simulated block: full block fields + `calls` array. The
/// `size` is the byte length of the network-encoded block.
fn simBlockJson(a: std.mem.Allocator, h: *const block.Header, blk_hash: [32]u8, calls_json: []const u8) []const u8 {
    const EMPTY_LIST = [_]u8{0xc0};
    // Assemble block RLP for `size`: rlp([header, txs, ommers, withdrawals?]).
    const hdr_rlp = h.encode(a) catch @panic("oom");
    var parts: std.ArrayList([]const u8) = .empty;
    parts.append(a, hdr_rlp) catch {};
    parts.append(a, &EMPTY_LIST) catch {}; // transactions (empty for size baseline)
    parts.append(a, &EMPTY_LIST) catch {}; // ommers
    if (h.withdrawals_root != null) parts.append(a, &EMPTY_LIST) catch {}; // withdrawals
    const block_rlp = rlp.encodeList(a, parts.items) catch @panic("oom");

    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"number\":\"{s}\",\"hash\":\"{s}\",\"parentHash\":\"{s}\",\"nonce\":\"{s}\",\"mixHash\":\"{s}\",\"sha3Uncles\":\"{s}\",\"logsBloom\":\"{s}\",\"transactionsRoot\":\"{s}\",\"stateRoot\":\"{s}\",\"receiptsRoot\":\"{s}\",\"miner\":\"{s}\",\"difficulty\":\"{s}\",\"extraData\":\"0x\",\"gasLimit\":\"{s}\",\"gasUsed\":\"{s}\",\"timestamp\":\"{s}\",\"size\":\"{s}\"", .{
        qHex(a, h.number),                hash32Hex(a, blk_hash),       hash32Hex(a, h.parent_hash),
        dataHex(a, &h.nonce),             hash32Hex(a, h.prev_randao),  hash32Hex(a, h.ommers_hash),
        dataHex(a, &h.logs_bloom),        hash32Hex(a, h.transactions_root), hash32Hex(a, h.state_root),
        hash32Hex(a, h.receipts_root),    dataHex(a, &h.coinbase),      qHex(a, h.difficulty),
        qHex(a, h.gas_limit),             qHex(a, h.gas_used),          qHex(a, h.timestamp),
        qHex(a, block_rlp.len),
    });
    if (h.base_fee_per_gas) |bf| p(a, &buf, ",\"baseFeePerGas\":\"{s}\"", .{qHex(a, bf)});
    if (h.withdrawals_root) |w| p(a, &buf, ",\"withdrawalsRoot\":\"{s}\"", .{hash32Hex(a, w)});
    if (h.blob_gas_used) |g| p(a, &buf, ",\"blobGasUsed\":\"{s}\"", .{qHex(a, g)});
    if (h.excess_blob_gas) |g| p(a, &buf, ",\"excessBlobGas\":\"{s}\"", .{qHex(a, g)});
    if (h.parent_beacon_block_root) |r| p(a, &buf, ",\"parentBeaconBlockRoot\":\"{s}\"", .{hash32Hex(a, r)});
    if (h.requests_hash) |r| p(a, &buf, ",\"requestsHash\":\"{s}\"", .{hash32Hex(a, r)});
    p(a, &buf, ",\"uncles\":[],\"transactions\":[],\"calls\":{s}}}", .{calls_json});
    return buf.toOwnedSlice(a) catch @panic("oom");
}
fn hashFromHex(s: []const u8) [32]u8 {
    var out: [32]u8 = std.mem.zeroes([32]u8);
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    _ = std.fmt.hexToBytes(&out, b) catch {};
    return out;
}

fn handleOne(a: std.mem.Allocator, c: *chain_mod.Chain, v: std.json.Value) []const u8 {
    if (v != .object) return err(a, null, -32600, "invalid request");
    const obj = v.object;
    const id: ?std.json.Value = obj.get("id");
    const method = if (obj.get("method")) |m| (if (m == .string) m.string else return err(a, id, -32600, "invalid request")) else return err(a, id, -32600, "invalid request");
    const params: []const std.json.Value = if (obj.get("params")) |pp| (if (pp == .array) pp.array.items else &.{}) else &.{};

    if (std.mem.eql(u8, method, "web3_clientVersion")) return okStr(a, id, CLIENT_VERSION);
    if (std.mem.eql(u8, method, "web3_sha3")) {
        const in: []const u8 = if (strParam(params, 0)) |s| hexBytes(a, s) else &.{};
        return okStr(a, id, hash32Hex(a, crypto.keccak256(in)));
    }
    if (std.mem.eql(u8, method, "net_peerCount")) return okStr(a, id, "0x0");
    if (std.mem.eql(u8, method, "eth_protocolVersion")) return okStr(a, id, "0x41");
    if (std.mem.eql(u8, method, "net_version")) return okStr(a, id, std.fmt.allocPrint(a, "{d}", .{c.chain_id}) catch @panic("oom"));
    if (std.mem.eql(u8, method, "net_listening")) return ok(a, id, "true");
    if (std.mem.eql(u8, method, "eth_chainId")) return okStr(a, id, qHex(a, c.chain_id));
    if (std.mem.eql(u8, method, "eth_blockNumber")) return okStr(a, id, qHex(a, c.head.number));
    if (std.mem.eql(u8, method, "eth_syncing")) return ok(a, id, "false");
    if (std.mem.eql(u8, method, "eth_coinbase")) return okStr(a, id, dataHex(a, &c.head.coinbase));
    if (std.mem.eql(u8, method, "eth_accounts")) return ok(a, id, "[]");
    if (std.mem.eql(u8, method, "eth_maxPriorityFeePerGas")) return okStr(a, id, qHex(a, 1_000_000_000));
    if (std.mem.eql(u8, method, "eth_gasPrice")) return okStr(a, id, qHex(a, (c.head.base_fee_per_gas orelse 0) + 1_000_000_000));
    if (std.mem.eql(u8, method, "eth_baseFee")) return okStr(a, id, qHex(a, nextBaseFee(c)));
    if (std.mem.eql(u8, method, "eth_sendRawTransaction")) {
        const raw = hexBytes(a, strParam(params, 0) orelse return err(a, id, -32602, "invalid params"));
        if (raw.len == 0) return err(a, id, -32602, "invalid transaction");
        const hash = rawTxHash(a, raw);
        // Admit to the pending pool (the producer draws on it); reject undecodable txs.
        c.txpool.add(raw) catch return err(a, id, -32000, "invalid transaction");
        return okStr(a, id, hash32Hex(a, hash));
    }
    if (std.mem.eql(u8, method, "eth_createAccessList")) {
        if (params.len < 1 or params[0] != .object) return err(a, id, -32602, "invalid params");
        return ok(a, id, createAccessList(a, c, params[0].object));
    }
    if (std.mem.eql(u8, method, "eth_simulateV1")) {
        if (params.len < 1 or params[0] != .object) return err(a, id, -32602, "invalid params");
        const base_tag = strParam(params, 1) orelse "latest";
        return simulateV1(a, id, c, params[0].object, base_tag);
    }
    if (std.mem.eql(u8, method, "eth_capabilities")) {
        var buf: std.ArrayList(u8) = .empty;
        buf.append(a, '[') catch @panic("oom");
        for (CAPABILITIES, 0..) |m, i| {
            if (i != 0) buf.append(a, ',') catch @panic("oom");
            p(a, &buf, "\"{s}\"", .{m});
        }
        buf.append(a, ']') catch @panic("oom");
        return ok(a, id, buf.toOwnedSlice(a) catch @panic("oom"));
    }
    if (std.mem.eql(u8, method, "eth_blobBaseFee")) {
        const f = c.schedule.forkAt(c.head.number, c.head.timestamp);
        return okStr(a, id, qHex(a, @import("tx.zig").blobGasPrice(c.head.excess_blob_gas orelse 0, f)));
    }

    if (std.mem.eql(u8, method, "eth_getBlockByNumber")) {
        const tag = strParam(params, 0) orelse return err(a, id, -32602, "invalid params");
        const full = params.len > 1 and params[1] == .bool and params[1].bool;
        const num = resolveBlock(c, tag) orelse return ok(a, id, "null");
        return ok(a, id, blockJson(a, c, num, full) orelse "null");
    }
    if (std.mem.eql(u8, method, "eth_getBlockByHash")) {
        const hs = strParam(params, 0) orelse return err(a, id, -32602, "invalid params");
        const full = params.len > 1 and params[1] == .bool and params[1].bool;
        const num = numberByHash(c, hs) orelse return ok(a, id, "null");
        return ok(a, id, blockJson(a, c, num, full) orelse "null");
    }
    if (std.mem.eql(u8, method, "eth_getBalance")) {
        const addr = parseAddr(strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return err(a, id, -32602, "invalid address");
        return okStr(a, id, qHex(a, c.state.balanceOf(addr)));
    }
    if (std.mem.eql(u8, method, "eth_getTransactionCount")) {
        const addr = parseAddr(strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return err(a, id, -32602, "invalid address");
        return okStr(a, id, qHex(a, c.state.nonceOf(addr)));
    }
    if (std.mem.eql(u8, method, "eth_getCode")) {
        const addr = parseAddr(strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return err(a, id, -32602, "invalid address");
        return okStr(a, id, dataHex(a, c.state.codeOf(addr)));
    }
    if (std.mem.eql(u8, method, "eth_getStorageAt")) {
        const addr = parseAddr(strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return err(a, id, -32602, "invalid address");
        const key = parseU256(strParam(params, 1) orelse "0x0");
        var word: [32]u8 = undefined;
        std.mem.writeInt(u256, &word, c.state.getStorage(addr, key), .big);
        return okStr(a, id, hash32Hex(a, word));
    }
    if (std.mem.eql(u8, method, "eth_getProof")) {
        const addr = parseAddr(strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return err(a, id, -32602, "invalid address");
        return ok(a, id, getProof(a, c, addr, if (params.len > 1 and params[1] == .array) params[1].array.items else &.{}));
    }
    if (std.mem.eql(u8, method, "eth_getStorageValues")) {
        if (params.len < 1 or params[0] != .object) return err(a, id, -32602, "invalid params");
        const m = params[0].object;
        if (m.count() == 0) return err(a, id, -32602, "empty request");
        var buf: std.ArrayList(u8) = .empty;
        buf.append(a, '{') catch {};
        var it = m.iterator();
        var first = true;
        while (it.next()) |e| {
            const addr = parseAddr(e.key_ptr.*) orelse continue;
            if (!first) buf.append(a, ',') catch {};
            first = false;
            p(a, &buf, "\"{s}\":[", .{e.key_ptr.*});
            if (e.value_ptr.* == .array) for (e.value_ptr.array.items, 0..) |k, i| {
                if (k != .string) continue;
                if (i != 0) buf.append(a, ',') catch {};
                var word: [32]u8 = undefined;
                std.mem.writeInt(u256, &word, c.state.getStorage(addr, parseU256(k.string)), .big);
                p(a, &buf, "\"{s}\"", .{hash32Hex(a, word)});
            };
            buf.append(a, ']') catch {};
        }
        buf.append(a, '}') catch {};
        return ok(a, id, buf.toOwnedSlice(a) catch return err(a, id, -32603, "oom"));
    }

    if (std.mem.eql(u8, method, "eth_getTransactionByHash")) {
        const h = parseHash(strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return ok(a, id, "null");
        const loc = c.tx_index.get(h) orelse return ok(a, id, "null");
        const rec = c.txByHash(h).?;
        return ok(a, id, txInfoJson(a, c, rec, loc.block_number, loc.index));
    }
    if (std.mem.eql(u8, method, "eth_getTransactionByBlockHashAndIndex") or std.mem.eql(u8, method, "eth_getTransactionByBlockNumberAndIndex")) {
        const num = blk: {
            const p0 = strParam(params, 0) orelse return err(a, id, -32602, "invalid params");
            if (std.mem.eql(u8, method, "eth_getTransactionByBlockHashAndIndex"))
                break :blk (numberByHash(c, p0) orelse return ok(a, id, "null"))
            else
                break :blk (resolveBlock(c, p0) orelse return ok(a, id, "null"));
        };
        const idx: u32 = @intCast(parseU64(strParam(params, 1) orelse "0x0"));
        const rec = c.txByBlockIndex(num, idx) orelse return ok(a, id, "null");
        return ok(a, id, txInfoJson(a, c, rec, num, idx));
    }
    if (std.mem.eql(u8, method, "eth_getTransactionReceipt")) {
        const h = parseHash(strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return ok(a, id, "null");
        const loc = c.tx_index.get(h) orelse return ok(a, id, "null");
        const rec = c.txByHash(h).?;
        return ok(a, id, receiptJson(a, c, rec, loc.block_number, loc.index, logBase(c, loc.block_number, loc.index)));
    }
    if (std.mem.eql(u8, method, "eth_getBlockReceipts")) {
        const num = resolveBlock(c, strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return ok(a, id, "null");
        const txs = c.blockTxs(num);
        var buf: std.ArrayList(u8) = .empty;
        buf.append(a, '[') catch @panic("oom");
        var lbase: usize = 0;
        for (txs, 0..) |rec, i| {
            if (i > 0) buf.append(a, ',') catch @panic("oom");
            buf.appendSlice(a, receiptJson(a, c, rec, num, @intCast(i), lbase)) catch @panic("oom");
            lbase += rec.logs.len;
        }
        buf.append(a, ']') catch @panic("oom");
        return ok(a, id, buf.items);
    }
    if (std.mem.eql(u8, method, "eth_getBlockTransactionCountByHash") or std.mem.eql(u8, method, "eth_getBlockTransactionCountByNumber")) {
        const p0 = strParam(params, 0) orelse return err(a, id, -32602, "invalid params");
        const num = if (std.mem.eql(u8, method, "eth_getBlockTransactionCountByHash"))
            (numberByHash(c, p0) orelse return ok(a, id, "null"))
        else
            (resolveBlock(c, p0) orelse return ok(a, id, "null"));
        if (num >= c.headers.items.len) return ok(a, id, "null");
        return okStr(a, id, qHex(a, c.blockTxs(num).len));
    }
    if (std.mem.eql(u8, method, "eth_getUncleCountByBlockHash") or std.mem.eql(u8, method, "eth_getUncleCountByBlockNumber")) {
        return okStr(a, id, "0x0"); // post-Merge: no uncles
    }
    if (std.mem.eql(u8, method, "eth_getLogs")) {
        if (params.len < 1 or params[0] != .object) return err(a, id, -32602, "invalid params");
        return ok(a, id, getLogs(a, c, params[0].object));
    }

    if (std.mem.eql(u8, method, "eth_call")) {
        if (params.len < 1 or params[0] != .object) return err(a, id, -32602, "invalid params");
        const r = execCall(a, c, params[0].object, 30_000_000);
        return okStr(a, id, dataHex(a, r.output));
    }
    if (std.mem.eql(u8, method, "eth_estimateGas")) {
        if (params.len < 1 or params[0] != .object) return err(a, id, -32602, "invalid params");
        const call = params[0].object;
        // Intrinsic cost (tx base + calldata + create), then binary-search the
        // least *message* gas for which execution succeeds; sum the two.
        const data = if (jstr(call, "data") orelse jstr(call, "input")) |d| hexBytes(a, d) else &.{};
        var zero: u64 = 0;
        var nz: u64 = 0;
        for (data) |b| if (b == 0) {
            zero += 1;
        } else {
            nz += 1;
        };
        const is_create = jstr(call, "to") == null;
        const intrinsic: u64 = 21000 + zero * 4 + nz * 16 + (if (is_create) @as(u64, 32000) else 0);
        if (c.head.gas_limit <= intrinsic) return err(a, id, -32000, "gas limit too low");
        // A call needing no execution gas (e.g. to an EOA) costs just intrinsic.
        if (execCall(a, c, call, 0).success) return okStr(a, id, qHex(a, intrinsic));
        var lo: u64 = 0;
        var hi: u64 = c.head.gas_limit - intrinsic;
        if (!execCall(a, c, call, hi).success) return err(a, id, -32000, "execution reverted");
        while (lo + 1 < hi) {
            const mid = lo + (hi - lo) / 2;
            if (execCall(a, c, call, mid).success) hi = mid else lo = mid;
        }
        return okStr(a, id, qHex(a, intrinsic + hi));
    }

    if (std.mem.eql(u8, method, "debug_traceCall")) {
        if (params.len < 1 or params[0] != .object) return err(a, id, -32602, "invalid params");
        if (wantsCallTracer(params, 2)) {
            var ct = vm.CallTracer{ .alloc = a };
            vm.call_tracer = &ct;
            _ = execCall(a, c, params[0].object, 30_000_000);
            vm.call_tracer = null;
            return ok(a, id, if (ct.root) |r| callFrameJson(a, r) else "{}");
        }
        var sink: std.ArrayList(vm.StructLog) = .empty;
        vm.trace_sink = &sink;
        const r = execCall(a, c, params[0].object, 30_000_000);
        vm.trace_sink = null;
        return ok(a, id, traceResultJson(a, sink.items, r.gas_used, r.success, r.output));
    }
    if (std.mem.eql(u8, method, "debug_traceTransaction")) {
        const h = parseHash(strParam(params, 0) orelse return err(a, id, -32602, "invalid params")) orelse return ok(a, id, "null");
        if (wantsCallTracer(params, 1)) {
            var ct = vm.CallTracer{ .alloc = a };
            _ = c.traceTransaction(a, h, null, &ct) orelse return ok(a, id, "null");
            return ok(a, id, if (ct.root) |r| callFrameJson(a, r) else "{}");
        }
        var sink: std.ArrayList(vm.StructLog) = .empty;
        const tr = c.traceTransaction(a, h, &sink, null) orelse return ok(a, id, "null");
        return ok(a, id, traceResultJson(a, sink.items, tr.gas_used, tr.success, tr.output));
    }

    if (std.mem.eql(u8, method, "debug_traceBlockByNumber") or std.mem.eql(u8, method, "debug_traceBlockByHash")) {
        const p0 = strParam(params, 0) orelse return err(a, id, -32602, "invalid params");
        const num = if (std.mem.eql(u8, method, "debug_traceBlockByHash"))
            (numberByHash(c, p0) orelse return ok(a, id, "null"))
        else
            (resolveBlock(c, p0) orelse return ok(a, id, "null"));
        const call_mode = wantsCallTracer(params, 1);
        var buf: std.ArrayList(u8) = .empty;
        buf.append(a, '[') catch @panic("oom");
        for (c.blockTxs(num), 0..) |rec, i| {
            if (i > 0) buf.append(a, ',') catch @panic("oom");
            if (call_mode) {
                var ct = vm.CallTracer{ .alloc = a };
                _ = c.traceTransaction(a, rec.hash, null, &ct);
                p(a, &buf, "{{\"txHash\":\"{s}\",\"result\":{s}}}", .{ hash32Hex(a, rec.hash), if (ct.root) |r| callFrameJson(a, r) else "{}" });
            } else {
                var sink: std.ArrayList(vm.StructLog) = .empty;
                const tr = c.traceTransaction(a, rec.hash, &sink, null) orelse continue;
                p(a, &buf, "{{\"txHash\":\"{s}\",\"result\":{s}}}", .{ hash32Hex(a, rec.hash), traceResultJson(a, sink.items, tr.gas_used, tr.success, tr.output) });
            }
        }
        buf.append(a, ']') catch @panic("oom");
        return ok(a, id, buf.items);
    }
    if (std.mem.eql(u8, method, "eth_feeHistory")) {
        return ok(a, id, feeHistory(a, c, params));
    }

    // ── Engine API ──
    if (std.mem.startsWith(u8, method, "engine_newPayloadV")) {
        const ver: u8 = std.fmt.parseInt(u8, method["engine_newPayloadV".len..], 10) catch 1;
        return newPayload(a, c, id, params, ver);
    }
    if (std.mem.startsWith(u8, method, "engine_forkchoiceUpdatedV")) {
        // headBlockHash must be a block we know → VALID; else SYNCING.
        const fcs = if (params.len > 0 and params[0] == .object) params[0].object else return err(a, id, -32602, "invalid params");
        const head = fixed(32, jstr(fcs, "headBlockHash"));
        var known = false;
        for (c.hashes.items) |h| if (std.mem.eql(u8, &h, &head)) {
            known = true;
        };
        const body = if (known)
            std.fmt.allocPrint(a, "{{\"payloadStatus\":{{\"status\":\"VALID\",\"latestValidHash\":\"{s}\",\"validationError\":null}},\"payloadId\":null}}", .{hash32Hex(a, head)}) catch @panic("oom")
        else
            "{\"payloadStatus\":{\"status\":\"SYNCING\",\"latestValidHash\":null,\"validationError\":null},\"payloadId\":null}";
        return ok(a, id, body);
    }
    if (std.mem.eql(u8, method, "engine_exchangeCapabilities")) {
        return ok(a, id,
            \\["engine_newPayloadV1","engine_newPayloadV2","engine_newPayloadV3","engine_newPayloadV4","engine_forkchoiceUpdatedV1","engine_forkchoiceUpdatedV2","engine_forkchoiceUpdatedV3","engine_getPayloadV1","engine_getPayloadV2","engine_getPayloadV3","engine_getPayloadV4"]
        );
    }

    return err(a, id, -32601, "method not found");
}

/// eth_feeHistory: baseFeePerGas + gasUsedRatio over a block window (rewards
/// computed per requested percentile from each block's tx priority fees).
fn feeHistory(a: std.mem.Allocator, c: *const chain_mod.Chain, params: []const std.json.Value) []const u8 {
    const count: u64 = if (params.len > 0 and params[0] == .string) parseU64(params[0].string) else 1;
    const newest: u64 = if (params.len > 1 and params[1] == .string) (resolveBlock(c, params[1].string) orelse c.head.number) else c.head.number;
    const oldest: u64 = if (newest + 1 >= count) newest + 1 - count else 0;
    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"oldestBlock\":\"{s}\",\"baseFeePerGas\":[", .{qHex(a, oldest)});
    var n = oldest;
    while (n <= newest) : (n += 1) {
        if (n > oldest) buf.append(a, ',') catch @panic("oom");
        const h = c.headerByNumber(n) orelse continue;
        p(a, &buf, "\"{s}\"", .{qHex(a, h.base_fee_per_gas orelse 0)});
    }
    // baseFeePerGas has count+1 entries (next block's base fee); reuse the head's.
    p(a, &buf, ",\"{s}\"],\"gasUsedRatio\":[", .{qHex(a, c.head.base_fee_per_gas orelse 0)});
    n = oldest;
    while (n <= newest) : (n += 1) {
        if (n > oldest) buf.append(a, ',') catch @panic("oom");
        const h = c.headerByNumber(n) orelse continue;
        const ratio: f64 = if (h.gas_limit > 0) @as(f64, @floatFromInt(h.gas_used)) / @as(f64, @floatFromInt(h.gas_limit)) else 0;
        p(a, &buf, "{d}", .{ratio});
    }
    buf.appendSlice(a, "]}") catch @panic("oom");
    return buf.items;
}

/// True if the options object at `params[idx]` selects {"tracer":"callTracer"}.
fn wantsCallTracer(params: []const std.json.Value, idx: usize) bool {
    if (idx >= params.len or params[idx] != .object) return false;
    const t = params[idx].object.get("tracer") orelse return false;
    return t == .string and std.mem.eql(u8, t.string, "callTracer");
}

/// A geth callTracer frame (the data Foundry renders as its trace tree).
fn callFrameJson(a: std.mem.Allocator, f: *const vm.CallFrame) []const u8 {
    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"type\":\"{s}\",\"from\":\"{s}\",\"to\":\"{s}\"", .{ f.typ, dataHex(a, &f.from), dataHex(a, &f.to) });
    if (f.value != 0) p(a, &buf, ",\"value\":\"{s}\"", .{qHex(a, f.value)});
    p(a, &buf, ",\"gas\":\"{s}\",\"gasUsed\":\"{s}\"", .{ qHex(a, f.gas), qHex(a, f.gas_used) });
    p(a, &buf, ",\"input\":\"{s}\",\"output\":\"{s}\"", .{ dataHex(a, f.input), dataHex(a, f.output) });
    if (f.err) |e| p(a, &buf, ",\"error\":\"{s}\"", .{e});
    if (f.calls.items.len > 0) {
        buf.appendSlice(a, ",\"calls\":[") catch @panic("oom");
        for (f.calls.items, 0..) |child, i| {
            if (i > 0) buf.append(a, ',') catch @panic("oom");
            buf.appendSlice(a, callFrameJson(a, child)) catch @panic("oom");
        }
        buf.append(a, ']') catch @panic("oom");
    }
    buf.append(a, '}') catch @panic("oom");
    return buf.items;
}

/// geth debug trace result: { gas, failed, returnValue, structLogs: [...] }.
fn traceResultJson(a: std.mem.Allocator, logs: []const vm.StructLog, gas_used: u64, success: bool, output: []const u8) []const u8 {
    var buf: std.ArrayList(u8) = .empty;
    const ret = dataHex(a, output); // "0x...."; geth's returnValue is bare hex
    p(a, &buf, "{{\"gas\":{d},\"failed\":{s},\"returnValue\":\"{s}\",\"structLogs\":[", .{ gas_used, if (success) "false" else "true", ret[2..] });
    for (logs, 0..) |lg, i| {
        if (i > 0) buf.append(a, ',') catch @panic("oom");
        // gasCost ≈ gas drop to the next step (flat across frames).
        const next_gas: u64 = if (i + 1 < logs.len) logs[i + 1].gas else lg.gas;
        const gas_cost: u64 = if (lg.gas >= next_gas) lg.gas - next_gas else 0;
        p(a, &buf, "{{\"pc\":{d},\"op\":\"{s}\",\"gas\":{d},\"gasCost\":{d},\"depth\":{d},\"stack\":[", .{ lg.pc, vm.opName(lg.op), lg.gas, gas_cost, lg.depth + 1 });
        for (lg.stack, 0..) |s, j| {
            if (j > 0) buf.append(a, ',') catch @panic("oom");
            p(a, &buf, "\"0x{x}\"", .{s});
        }
        buf.appendSlice(a, "]}") catch @panic("oom");
    }
    buf.appendSlice(a, "]}") catch @panic("oom");
    return buf.items;
}

// ── Engine API ──────────────────────────────────────────────────────────────

fn fixed(comptime N: usize, s: ?[]const u8) [N]u8 {
    var out: [N]u8 = std.mem.zeroes([N]u8);
    if (s) |v| {
        const b = if (std.mem.startsWith(u8, v, "0x")) v[2..] else v;
        _ = std.fmt.hexToBytes(&out, b) catch {};
    }
    return out;
}

/// Build a block from an Engine API ExecutionPayload, computing the tx/
/// withdrawals/requests roots so the assembled header hashes to `blockHash`.
fn buildPayloadBlock(a: std.mem.Allocator, payload: std.json.ObjectMap, pbbr: ?[32]u8, requests: ?[]std.json.Value) struct { blk: block.Block, hash: [32]u8 } {
    var h = block.Header{};
    h.parent_hash = fixed(32, jstr(payload, "parentHash"));
    h.coinbase = fixed(20, jstr(payload, "feeRecipient"));
    h.state_root = fixed(32, jstr(payload, "stateRoot"));
    h.receipts_root = fixed(32, jstr(payload, "receiptsRoot"));
    h.logs_bloom = fixed(256, jstr(payload, "logsBloom"));
    h.number = parseU64(jstr(payload, "blockNumber") orelse "0x0");
    h.gas_limit = parseU64(jstr(payload, "gasLimit") orelse "0x0");
    h.gas_used = parseU64(jstr(payload, "gasUsed") orelse "0x0");
    h.timestamp = parseU64(jstr(payload, "timestamp") orelse "0x0");
    h.extra_data = hexBytes(a, jstr(payload, "extraData") orelse "0x");
    h.prev_randao = fixed(32, jstr(payload, "prevRandao"));
    h.base_fee_per_gas = parseU256(jstr(payload, "baseFeePerGas") orelse "0x0");

    // Transactions (hex EIP-2718 encodings) → transactions root.
    var txs: std.ArrayList([]const u8) = .empty;
    if (payload.get("transactions")) |tv| if (tv == .array)
        for (tv.array.items) |t| if (t == .string) txs.append(a, hexBytes(a, t.string)) catch @panic("oom");
    h.transactions_root = block.orderedTrieRoot(a, txs.items);

    // Withdrawals (V2+): RLP-encode each → withdrawals root.
    var wds: std.ArrayList([]const u8) = .empty;
    var has_w = false;
    if (payload.get("withdrawals")) |wv| if (wv == .array) {
        has_w = true;
        for (wv.array.items) |w| if (w == .object) {
            const o = w.object;
            const items = [_][]const u8{
                rlp.encodeUint(a, parseU64(jstr(o, "index") orelse "0x0")) catch @panic("oom"),
                rlp.encodeUint(a, parseU64(jstr(o, "validatorIndex") orelse "0x0")) catch @panic("oom"),
                rlp.encodeBytes(a, &fixed(20, jstr(o, "address"))) catch @panic("oom"),
                rlp.encodeUint(a, parseU64(jstr(o, "amount") orelse "0x0")) catch @panic("oom"),
            };
            wds.append(a, rlp.encodeList(a, &items) catch @panic("oom")) catch @panic("oom");
        };
        h.withdrawals_root = block.orderedTrieRoot(a, wds.items);
    };

    // Cancun blob gas (V3+) + parent beacon root.
    if (jstr(payload, "blobGasUsed")) |g| h.blob_gas_used = parseU64(g);
    if (jstr(payload, "excessBlobGas")) |g| h.excess_blob_gas = parseU64(g);
    if (pbbr) |r| h.parent_beacon_block_root = r;
    // Prague execution requests (V4) → requests hash (EIP-7685, sha256 commitment).
    if (requests) |reqs| h.requests_hash = computeRequestsHash(a, reqs);

    const hash = h.hash(a) catch std.mem.zeroes([32]u8);
    return .{ .blk = .{ .header = h, .transactions = txs.items, .withdrawals = wds.items, .has_withdrawals = has_w }, .hash = hash };
}

/// EIP-7685 requests hash: sha256(sha256(req_0) ‖ sha256(req_1) ‖ …).
fn computeRequestsHash(a: std.mem.Allocator, reqs: []std.json.Value) [32]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var outer = Sha256.init(.{});
    for (reqs) |r| if (r == .string) {
        const bytes = hexBytes(a, r.string);
        if (bytes.len == 0) continue;
        var inner: [32]u8 = undefined;
        Sha256.hash(bytes, &inner, .{});
        outer.update(&inner);
    };
    var out: [32]u8 = undefined;
    outer.final(&out);
    return out;
}

/// engine_newPayloadV* → import the payload, return the payload status.
fn newPayload(a: std.mem.Allocator, c: *chain_mod.Chain, id: ?std.json.Value, params: []const std.json.Value, version: u8) []const u8 {
    if (params.len < 1 or params[0] != .object) return err(a, id, -32602, "invalid params");
    // V3+ carry parentBeaconBlockRoot at params[2]; V4 executionRequests at params[3].
    const pbbr: ?[32]u8 = if (version >= 3 and params.len >= 3 and params[2] == .string) fixed(32, params[2].string) else null;
    const reqs: ?[]std.json.Value = if (version >= 4 and params.len >= 4 and params[3] == .array) params[3].array.items else null;
    const built = buildPayloadBlock(a, params[0].object, pbbr, reqs);

    const want_hash = fixed(32, jstr(params[0].object, "blockHash"));
    if (!std.mem.eql(u8, &built.hash, &want_hash))
        return payloadStatus(a, id, "INVALID", null, "block hash mismatch");
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    // On INVALID, latestValidHash is the most recent valid ancestor — our head.
    const parent = c.head.hash(a) catch std.mem.zeroes([32]u8);
    _ = c.importDecoded(arena.allocator(), built.blk) catch |e|
        return payloadStatus(a, id, "INVALID", &parent, c.last_error orelse @errorName(e));
    return payloadStatus(a, id, "VALID", &built.hash, null);
}

fn payloadStatus(a: std.mem.Allocator, id: ?std.json.Value, status: []const u8, latest_valid: ?*const [32]u8, validation_err: ?[]const u8) []const u8 {
    var inner: std.ArrayList(u8) = .empty;
    p(a, &inner, "{{\"status\":\"{s}\",\"latestValidHash\":{s}", .{ status, if (latest_valid) |lv| std.fmt.allocPrint(a, "\"{s}\"", .{hash32Hex(a, lv.*)}) catch "null" else "null" });
    if (validation_err) |ve| p(a, &inner, ",\"validationError\":\"{s}\"", .{ve}) else inner.appendSlice(a, ",\"validationError\":null") catch @panic("oom");
    inner.append(a, '}') catch @panic("oom");
    return ok(a, id, inner.items);
}

/// Handle a raw request body (single object or batch array) → response JSON.
pub fn handleBody(a: std.mem.Allocator, c: *chain_mod.Chain, body: []const u8) []const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, a, body, .{}) catch
        return err(a, null, -32700, "parse error");
    const v = parsed.value;
    if (v == .array) {
        var buf: std.ArrayList(u8) = .empty;
        buf.append(a, '[') catch @panic("oom");
        for (v.array.items, 0..) |item, i| {
            if (i > 0) buf.append(a, ',') catch @panic("oom");
            buf.appendSlice(a, handleOne(a, c, item)) catch @panic("oom");
        }
        buf.append(a, ']') catch @panic("oom");
        return buf.items;
    }
    return handleOne(a, c, v);
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;
const genesis_mod = @import("genesis.zig");
const ecies = @import("ecies.zig");
const testsign = @import("testsign.zig");

test "eth_sendRawTransaction admits the tx to the pending pool" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Minimal post-Merge genesis funding a freshly generated sender.
    const priv = ecies.randomPriv(io);
    const pk = try ecies.pubFromPriv(priv);
    const sh = crypto.keccak256(&pk);
    var addr_hex: [40]u8 = undefined;
    for (sh[12..32], 0..) |byte, i| _ = std.fmt.bufPrint(addr_hex[i * 2 ..][0..2], "{x:0>2}", .{byte}) catch unreachable;
    const gjson = try std.fmt.allocPrint(a,
        \\{{"config":{{"chainId":1,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,"byzantiumBlock":0,"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,"londonBlock":0,"mergeNetsplitBlock":0,"terminalTotalDifficulty":0,"shanghaiTime":0}},
        \\"gasLimit":"0x1000000","difficulty":"0x0","timestamp":"0x0",
        \\"alloc":{{"{s}":{{"balance":"0xde0b6b3a7640000"}}}}}}
    , .{addr_hex});
    var parsed = try std.json.parseFromSlice(std.json.Value, a, gjson, .{});
    defer parsed.deinit();
    var st = state_mod.State.init(testing.allocator);
    defer st.deinit();
    const g = try genesis_mod.load(a, &st, parsed.value);
    var ch = try chain_mod.Chain.initGenesis(testing.allocator, &st, g);
    defer ch.deinit();

    var to = std.mem.zeroes(state_mod.Address);
    to[19] = 0x42;
    const raw = try testsign.signLegacy(a, io, priv, 1, 0, 2_000_000_000, 21000, to, 1000);
    var raw_hex = std.ArrayList(u8).empty;
    try raw_hex.appendSlice(a, "0x");
    for (raw) |byte| try raw_hex.print(a, "{x:0>2}", .{byte});
    const body = try std.fmt.allocPrint(a,
        \\{{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["{s}"]}}
    , .{raw_hex.items});

    const resp = handleBody(a, &ch, body);
    try testing.expect(std.mem.indexOf(u8, resp, "\"result\"") != null); // hash returned
    try testing.expectEqual(@as(usize, 1), ch.txpool.count()); // and it's pending
}

test "rawTxHash matches sendRawTransaction fixtures (legacy/2930/1559)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_]struct { raw: []const u8, want: []const u8 }{
        .{ .raw = "0xf86c808405763d658261a894aa000000000000000000000000000000000000000a8255448718e5bb3abd109fa0c8e3b4a0087357bd49d80a0ac24daf0c91191e71086c1e355fc62cfab2218873a074f4636f740fa4d1697b6e736e5982b700be2c8b63031a24fa531ae4814b3af8", .want = "0x66734e85ef096167acb887cf445946a1ed57b90b66ffe38af87e11294febbfa9" },
        .{ .raw = "0x01f8cc870c72dd9d5e883e028405763f5883015f90947dcd17433742f4c0ca53122ab541d0ba67fc27df8083010203f85bf859947dcd17433742f4c0ca53122ab541d0ba67fc27dff842a00000000000000000000000000000000000000000000000000000000000000000a0010000000000000000000000000000000000000000000000000000000000000080a0f9dc42e8bab0a70132fb8399cf03cf38e1c12cc47f736d19e6e7728356d97db3a053daf342acd24da15073f5dac02bec0501a0716165984aab2df9694882b91fac", .want = "0xd07a55a00aeb93c7825d1ca42238abdc3bc225de097ee1b8b2a4a9240ae55f9c" },
        .{ .raw = "0x02f892870c72dd9d5e883e018201f48405763f5882ea60802ab73d602d80600a3d3981f3363d3d373d3d3d363d734d11c446473105a02b5c1ab9ebe9b03f33902a295af43d82803e903d91602b57fd5bf3c001a0fe6d380224a516b802717755d2f640163e81bae64a4ab5adbcf741267f20ad66a015d9ceb9fecb47b342be00782b2485f42ab53715006d208897cc969d7c05ab67", .want = "0xfa245384e9eb7d6a4a40f3bf4bf70f1f44929d8bfcdf75762ce1a015389449e3" },
        .{ .raw = "0x02f8d0870c72dd9d5e883e038201f48405763f5883013880947dcd17433742f4c0ca53122ab541d0ba67fc27df808401020304f85bf859947dcd17433742f4c0ca53122ab541d0ba67fc27dff842a00000000000000000000000000000000000000000000000000000000000000000a0010000000000000000000000000000000000000000000000000000000000000080a0e56d869d8b32f767582fdcb03d1d9d3bcc47f3c7ae08984feafdcd57f2f205f5a074134e4bf0fb11ff606b47259aff0d01bf7cb9ec68cb179b62576b9dd6631cf0", .want = "0x0baf604666cbc4d04263bbc98c048000451b8c188d93ec87ca5a86b044fd956c" },
    };
    for (cases) |cse| {
        const raw = hexBytes(a, cse.raw);
        const got = hash32Hex(a, rawTxHash(a, raw));
        try testing.expectEqualStrings(cse.want, got);
    }
}
