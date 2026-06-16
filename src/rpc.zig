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
        .fork = c.schedule.forkAt(h.timestamp),
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
    if (std.mem.eql(u8, method, "eth_blobBaseFee")) {
        const f = c.schedule.forkAt(c.head.timestamp);
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
