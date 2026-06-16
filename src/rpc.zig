//! Minimal Ethereum JSON-RPC, enough for the hive `consume-rlp` simulator to
//! verify an imported chain: chain/block identity plus post-state account reads.
//! `handleBody` takes a raw request body (single or batch) and returns the
//! response JSON. State reads resolve against the current (post-import) state.

const std = @import("std");
const chain_mod = @import("chain.zig");
const state_mod = @import("state.zig");
const block = @import("block.zig");
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

/// Resolve a block tag/number param to a concrete number against the head.
fn resolveBlock(c: *const chain_mod.Chain, tag: []const u8) ?u64 {
    if (std.mem.eql(u8, tag, "latest") or std.mem.eql(u8, tag, "pending") or std.mem.eql(u8, tag, "safe") or std.mem.eql(u8, tag, "finalized"))
        return c.head.number;
    if (std.mem.eql(u8, tag, "earliest")) return 0;
    const b = if (std.mem.startsWith(u8, tag, "0x")) tag[2..] else tag;
    return std.fmt.parseInt(u64, b, 16) catch null;
}

/// JSON for a block by number (header fields + empty tx/uncle lists).
fn blockJson(a: std.mem.Allocator, c: *const chain_mod.Chain, number: u64) ?[]const u8 {
    const h = c.headerByNumber(number) orelse return null;
    const hash = c.hashByNumber(number) orelse return null;
    var buf: std.ArrayList(u8) = .empty;
    p(a, &buf, "{{\"number\":\"{s}\",\"hash\":\"{s}\",\"parentHash\":\"{s}\"", .{ qHex(a, number), hash32Hex(a, hash), hash32Hex(a, h.parent_hash) });
    p(a, &buf, ",\"nonce\":\"{s}\",\"sha3Uncles\":\"{s}\",\"logsBloom\":\"{s}\"", .{ dataHex(a, &h.nonce), hash32Hex(a, h.ommers_hash), dataHex(a, &h.logs_bloom) });
    p(a, &buf, ",\"transactionsRoot\":\"{s}\",\"stateRoot\":\"{s}\",\"receiptsRoot\":\"{s}\"", .{ hash32Hex(a, h.transactions_root), hash32Hex(a, h.state_root), hash32Hex(a, h.receipts_root) });
    p(a, &buf, ",\"miner\":\"{s}\",\"difficulty\":\"{s}\",\"extraData\":\"{s}\"", .{ dataHex(a, &h.coinbase), qHex(a, h.difficulty), dataHex(a, h.extra_data) });
    p(a, &buf, ",\"gasLimit\":\"{s}\",\"gasUsed\":\"{s}\",\"timestamp\":\"{s}\"", .{ qHex(a, h.gas_limit), qHex(a, h.gas_used), qHex(a, h.timestamp) });
    p(a, &buf, ",\"mixHash\":\"{s}\"", .{hash32Hex(a, h.prev_randao)});
    if (h.base_fee_per_gas) |bf| p(a, &buf, ",\"baseFeePerGas\":\"{s}\"", .{qHex(a, bf)});
    if (h.withdrawals_root) |wr| p(a, &buf, ",\"withdrawalsRoot\":\"{s}\"", .{hash32Hex(a, wr)});
    if (h.blob_gas_used) |g| p(a, &buf, ",\"blobGasUsed\":\"{s}\"", .{qHex(a, g)});
    if (h.excess_blob_gas) |g| p(a, &buf, ",\"excessBlobGas\":\"{s}\"", .{qHex(a, g)});
    buf.appendSlice(a, ",\"transactions\":[],\"uncles\":[]}") catch @panic("oom");
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
    if (std.mem.eql(u8, method, "net_version")) return okStr(a, id, std.fmt.allocPrint(a, "{d}", .{c.chain_id}) catch @panic("oom"));
    if (std.mem.eql(u8, method, "net_listening")) return ok(a, id, "true");
    if (std.mem.eql(u8, method, "eth_chainId")) return okStr(a, id, qHex(a, c.chain_id));
    if (std.mem.eql(u8, method, "eth_blockNumber")) return okStr(a, id, qHex(a, c.head.number));
    if (std.mem.eql(u8, method, "eth_syncing")) return ok(a, id, "false");

    if (std.mem.eql(u8, method, "eth_getBlockByNumber")) {
        const tag = strParam(params, 0) orelse return err(a, id, -32602, "invalid params");
        const num = resolveBlock(c, tag) orelse return ok(a, id, "null");
        return ok(a, id, blockJson(a, c, num) orelse "null");
    }
    if (std.mem.eql(u8, method, "eth_getBlockByHash")) {
        const hs = strParam(params, 0) orelse return err(a, id, -32602, "invalid params");
        var want: [32]u8 = undefined;
        const hb = if (std.mem.startsWith(u8, hs, "0x")) hs[2..] else hs;
        _ = std.fmt.hexToBytes(&want, hb) catch return ok(a, id, "null");
        for (c.hashes.items, 0..) |h, n| if (std.mem.eql(u8, &h, &want))
            return ok(a, id, blockJson(a, c, n) orelse "null");
        return ok(a, id, "null");
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

    return err(a, id, -32601, "method not found");
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
