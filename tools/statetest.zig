//! GeneralStateTests runner: builds the pre-state, applies the transaction, and
//! checks the resulting **post-state root** against the fixture — the real
//! conformance oracle. Currently targets the Prague fork (our EVM's gas rules).
//!
//!   statetest <fixture.json> [more.json ...]

const std = @import("std");
const zeth = @import("zetherum");

const Address = zeth.state.Address;

var g_color = true;
fn clr(comptime code: []const u8) []const u8 {
    return if (g_color) code else "";
}
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";

const FORK = "Prague";
var g_stop = true; // stop at the first failure (like a compiler); ZETH_ALL=1 runs everything
var g_data_filter: ?usize = null; // ZETH_DATA=N runs only data index N (debugging)

/// The path is already printed; show only the variant after "::".
fn shortName(n: []const u8) []const u8 {
    if (std.mem.indexOf(u8, n, "::")) |i| return n[i + 2 ..];
    if (std.mem.lastIndexOfScalar(u8, n, '/')) |i| return n[i + 1 ..];
    return n;
}

const Verdict = enum { pass, fail, skip };
const Tally = struct { pass: usize = 0, fail: usize = 0, skip: usize = 0 };

fn u256FromHex(s: []const u8) u256 {
    const body = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (body.len == 0) return 0;
    return std.fmt.parseInt(u256, body, 16) catch 0;
}

fn u64FromHex(s: []const u8) u64 {
    const body = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (body.len == 0) return 0;
    return std.fmt.parseInt(u64, body, 16) catch 0;
}

fn addrFromHex(s: []const u8) Address {
    var a = zeth.state.zero_address;
    const body = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    _ = std.fmt.hexToBytes(&a, body) catch {};
    return a;
}

fn bytesFromHex(a: std.mem.Allocator, s: []const u8) []u8 {
    const body = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    const out = a.alloc(u8, body.len / 2) catch @panic("oom");
    _ = std.fmt.hexToBytes(out, body) catch {};
    return out;
}

// Safe JSON accessors — a malformed/unexpected fixture skips, never panics.
fn jstr(o: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = o.get(key) orelse return null;
    return if (v == .string) v.string else null;
}
fn jobj(o: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const v = o.get(key) orelse return null;
    return if (v == .object) v.object else null;
}
fn jarr(o: std.json.ObjectMap, key: []const u8) ?[]std.json.Value {
    const v = o.get(key) orelse return null;
    return if (v == .array) v.array.items else null;
}
fn jarrIdx(o: std.json.ObjectMap, key: []const u8, i: usize) ?[]const u8 {
    const v = o.get(key) orelse return null;
    if (v != .array or i >= v.array.items.len) return null;
    const e = v.array.items[i];
    return if (e == .string) e.string else null;
}

fn loadPre(a: std.mem.Allocator, st: *zeth.State, pre: std.json.ObjectMap) void {
    var it = pre.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* != .object) continue;
        const addr = addrFromHex(e.key_ptr.*);
        const acc = e.value_ptr.object;
        st.setBalance(addr, u256FromHex(jstr(acc, "balance") orelse "0x0")) catch @panic("oom");
        st.setNonce(addr, u64FromHex(jstr(acc, "nonce") orelse "0x0")) catch @panic("oom");
        st.setCode(addr, bytesFromHex(a, jstr(acc, "code") orelse "0x")) catch @panic("oom");
        if (acc.get("storage")) |sto| {
            if (sto == .object) {
                var sit = sto.object.iterator();
                while (sit.next()) |s| {
                    if (s.value_ptr.* != .string) continue;
                    st.setStorage(addr, u256FromHex(s.key_ptr.*), u256FromHex(s.value_ptr.string)) catch @panic("oom");
                }
            }
        }
    }
}

/// Print the accounts/slots where our post-state differs from the fixture's
/// expected post-state — localizes which account a failing test got wrong.
fn diffState(st: *zeth.State, post: std.json.ObjectMap) void {
    var it = post.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* != .object) continue;
        const tag = e.key_ptr.*;
        const addr = addrFromHex(tag);
        const exp = e.value_ptr.object;
        const wb = u256FromHex(jstr(exp, "balance") orelse "0x0");
        const gb = st.balanceOf(addr);
        if (gb != wb) std.debug.print("      {s}{s} balance got {d} want {d}{s}\n", .{ clr(DIM), tag, gb, wb, clr(RESET) });
        const wn = u64FromHex(jstr(exp, "nonce") orelse "0x0");
        const gn = st.nonceOf(addr);
        if (gn != wn) std.debug.print("      {s}{s} nonce got {d} want {d}{s}\n", .{ clr(DIM), tag, gn, wn, clr(RESET) });
        if (exp.get("storage")) |sto| if (sto == .object) {
            var sit = sto.object.iterator();
            while (sit.next()) |s| if (s.value_ptr.* == .string) {
                const key = u256FromHex(s.key_ptr.*);
                const wv = u256FromHex(s.value_ptr.string);
                const gv = st.getStorage(addr, key);
                if (gv != wv) std.debug.print("      {s}{s} slot {x} got {x} want {x}{s}\n", .{ clr(DIM), tag, key, gv, wv, clr(RESET) });
            };
        };
    }
}

fn jint(o: std.json.ObjectMap, key: []const u8) ?usize {
    const v = o.get(key) orelse return null;
    return if (v == .integer) @intCast(v.integer) else null;
}

fn runTest(gpa: std.mem.Allocator, name: []const u8, obj: std.json.ObjectMap, idx: usize, count: usize) Verdict {
    const post = jobj(obj, "post") orelse return .skip;
    const entries_v = post.get(FORK) orelse return .skip; // no Prague vector
    if (entries_v != .array) return .skip;
    const env_o = jobj(obj, "env") orelse return .skip;
    const tx_o = jobj(obj, "transaction") orelse return .skip;
    const pre_o = jobj(obj, "pre") orelse return .skip;
    const sender_s = jstr(tx_o, "sender") orelse return .skip;

    var result: Verdict = .pass;
    for (entries_v.array.items) |entry_v| {
        if (entry_v != .object) return .skip;
        const entry = entry_v.object;
        const ix = jobj(entry, "indexes") orelse return .skip;
        const di = jint(ix, "data") orelse return .skip;
        const gi = jint(ix, "gas") orelse return .skip;
        const vi = jint(ix, "value") orelse return .skip;
        if (g_data_filter) |want| {
            if (di != want) continue;
        }

        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();

        var st = zeth.State.init(gpa);
        defer st.deinit();
        loadPre(a, &st, pre_o);

        const base_fee = u256FromHex(jstr(env_o, "currentBaseFee") orelse "0x0");
        var env = zeth.Environment{
            .coinbase = addrFromHex(jstr(env_o, "currentCoinbase") orelse "0x0"),
            .number = u64FromHex(jstr(env_o, "currentNumber") orelse "0x0"),
            .time = u256FromHex(jstr(env_o, "currentTimestamp") orelse "0x0"),
            .gas_limit = u64FromHex(jstr(env_o, "currentGasLimit") orelse "0x0"),
            .base_fee = base_fee,
            .origin = addrFromHex(sender_s),
            .chain_id = 1,
        };
        if (jstr(env_o, "currentRandom")) |r| env.prev_randao = u256FromHex(r);

        // Effective gas price (legacy gasPrice or 1559 fee market), plus the raw
        // fee cap / priority used for pre-execution validation.
        var gas_price: u256 = undefined;
        var max_fee_cap: u256 = undefined;
        var max_prio: u256 = 0;
        if (jstr(tx_o, "gasPrice")) |gp| {
            gas_price = u256FromHex(gp);
            max_fee_cap = gas_price;
        } else {
            const max_fee = u256FromHex(jstr(tx_o, "maxFeePerGas") orelse return .skip);
            max_prio = u256FromHex(jstr(tx_o, "maxPriorityFeePerGas") orelse "0x0");
            gas_price = @min(max_fee, base_fee + max_prio);
            max_fee_cap = max_fee;
        }
        env.gas_price = gas_price;

        // EIP-4844 blob transaction: compute the (burned) blob data fee and
        // expose the versioned hashes + blob base fee to the EVM.
        var blob_data_fee: u256 = 0;
        if (jarr(tx_o, "blobVersionedHashes")) |bh| {
            const excess = u256FromHex(jstr(env_o, "currentExcessBlobGas") orelse "0x0");
            const price = zeth.tx.blobGasPrice(excess);
            env.blob_base_fee = price;
            blob_data_fee = @as(u256, zeth.tx.GAS_PER_BLOB) * bh.len * price;
            var hashes = std.ArrayList([32]u8).empty;
            for (bh) |h| if (h == .string) {
                var hh: [32]u8 = undefined;
                const hs = if (std.mem.startsWith(u8, h.string, "0x")) h.string[2..] else h.string;
                _ = std.fmt.hexToBytes(&hh, hs) catch {};
                hashes.append(a, hh) catch @panic("oom");
            };
            env.blob_versioned_hashes = hashes.items;
        }

        // Optional EIP-2930 access list (indexed by the data index).
        var access_list = std.ArrayList(zeth.tx.AccessEntry).empty;
        if (tx_o.get("accessLists")) |als| {
            if (als == .array and di < als.array.items.len and als.array.items[di] == .array) {
                for (als.array.items[di].array.items) |e_v| {
                    if (e_v != .object) continue;
                    const e = e_v.object;
                    var keys = std.ArrayList(u256).empty;
                    if (e.get("storageKeys")) |sk| {
                        if (sk == .array) for (sk.array.items) |k| {
                            if (k == .string) keys.append(a, u256FromHex(k.string)) catch @panic("oom");
                        };
                    }
                    access_list.append(a, .{ .address = addrFromHex(jstr(e, "address") orelse continue), .keys = keys.items }) catch @panic("oom");
                }
            }
        }

        const to_s = jstr(tx_o, "to") orelse "";
        const tx = zeth.tx.Tx{
            .sender = addrFromHex(sender_s),
            .to = if (to_s.len == 0 or std.mem.eql(u8, to_s, "0x")) null else addrFromHex(to_s),
            .nonce = u64FromHex(jstr(tx_o, "nonce") orelse "0x0"),
            .gas_limit = u64FromHex(jarrIdx(tx_o, "gasLimit", gi) orelse return .skip),
            .gas_price = gas_price,
            .value = u256FromHex(jarrIdx(tx_o, "value", vi) orelse return .skip),
            .data = bytesFromHex(a, jarrIdx(tx_o, "data", di) orelse return .skip),
            .access_list = access_list.items,
            .blob_data_fee = blob_data_fee,
        };

        // Reject invalid transactions outright (state stays at the pre-state).
        if (zeth.tx.validate(&st, &env, tx, max_fee_cap, max_prio)) {
            _ = zeth.tx.process(a, &st, &env, tx);
        }
        const got = zeth.trie.stateRoot(a, &st);

        var want: [32]u8 = undefined;
        const hash = jstr(entry, "hash") orelse return .skip;
        _ = std.fmt.hexToBytes(&want, hash[2..]) catch {};

        if (!std.mem.eql(u8, &got, &want)) {
            result = .fail;
            std.debug.print("  {s}{d}/{d}{s} {s}...{s}FAIL{s} (d{d}g{d}v{d})\n", .{ clr(DIM), idx, count, clr(RESET), shortName(name), clr(RED), clr(RESET), di, gi, vi });
            // Diff against the fixture's expected post accounts to localize the bug.
            if (jobj(entry, "state")) |post_state| diffState(&st, post_state);
            break;
        }
    }
    if (result == .pass)
        std.debug.print("  {s}{d}/{d}{s} {s}...{s}OK{s}\n", .{ clr(DIM), idx, count, clr(RESET), shortName(name), clr(GREEN), clr(RESET) });
    return result;
}

fn runFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) Tally {
    var t = Tally{};
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited) catch return t;
    defer gpa.free(content);
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, content, .{}) catch return t;
    defer parsed.deinit();

    std.debug.print("{s}{s}{s}\n", .{ clr(DIM), path, clr(RESET) });
    var idx: usize = 0;
    const count = parsed.value.object.count();
    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        idx += 1;
        switch (runTest(gpa, entry.key_ptr.*, entry.value_ptr.object, idx, count)) {
            .pass => t.pass += 1,
            .fail => {
                t.fail += 1;
                if (g_stop) break;
            },
            .skip => t.skip += 1,
        }
    }
    return t;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const nc = init.environ_map.get("NO_COLOR");
    g_color = nc == null or nc.?.len == 0;
    if (init.environ_map.get("ZETH_TRACE") != null) zeth.vm.trace_enabled = true;
    if (init.environ_map.get("ZETH_ALL") != null) g_stop = false; // run past failures
    if (init.environ_map.get("ZETH_DATA")) |d| g_data_filter = std.fmt.parseInt(usize, d, 10) catch null;
    if (args.len < 2) {
        std.debug.print("usage: statetest <fixture.json> ...\n", .{});
        return error.MissingArgument;
    }

    var total = Tally{};
    for (args[1..]) |path| {
        const t = runFile(gpa, init.io, path);
        total.pass += t.pass;
        total.fail += t.fail;
        total.skip += t.skip;
        if (g_stop and total.fail > 0) break; // stop at the first failure
    }

    const ok = total.fail == 0;
    std.debug.print("\n{s}{s}{d} passed{s}, {s}{d} failed{s}, {s}{d} skipped{s}\n", .{
        clr(BOLD),                                     if (ok) clr(GREEN) else clr(RED), total.pass, clr(RESET),
        (if (total.fail == 0) clr(DIM) else clr(RED)), total.fail,                       clr(RESET), clr(YELLOW),
        total.skip,                                    clr(RESET),
    });
    if (!ok) return error.ConformanceFailed;
}
