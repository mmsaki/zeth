//! GeneralStateTests runner: builds the pre-state, applies the transaction, and
//! checks the resulting **post-state root** against the fixture — the real
//! conformance oracle. Currently targets the Prague fork (our EVM's gas rules).
//!
//!   statetest <fixture.json> [more.json ...]

const std = @import("std");
const zeth = @import("zeth");
const report = @import("report.zig");

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

/// A fork to evaluate, paired with the fixture `post` key naming it.
const ForkVariant = struct { name: []const u8, fork: zeth.Fork };
/// Forks we run by default — every fixture is checked against each. Override the
/// set with ZETH_FORK=<name> (e.g. for debugging a single fork).
const DEFAULT_FORKS = [_]ForkVariant{
    .{ .name = "Cancun", .fork = .cancun },
    .{ .name = "Prague", .fork = .prague },
};
var g_forks: []const ForkVariant = &DEFAULT_FORKS;
var g_single: [1]ForkVariant = undefined; // backing store when ZETH_FORK is set
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

/// Buffer the accounts/slots where our post-state differs from the fixture's
/// expected post-state — localizes which account a failing test got wrong.
fn diffState(rep: *report.Reporter, st: *zeth.State, post: std.json.ObjectMap) void {
    var it = post.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* != .object) continue;
        const tag = e.key_ptr.*;
        const addr = addrFromHex(tag);
        const exp = e.value_ptr.object;
        const wb = u256FromHex(jstr(exp, "balance") orelse "0x0");
        const gb = st.balanceOf(addr);
        if (gb != wb) rep.failLine("      {s} balance got {d} want {d}\n", .{ tag, gb, wb });
        const wn = u64FromHex(jstr(exp, "nonce") orelse "0x0");
        const gn = st.nonceOf(addr);
        if (gn != wn) rep.failLine("      {s} nonce got {d} want {d}\n", .{ tag, gn, wn });
        if (exp.get("storage")) |sto| if (sto == .object) {
            var sit = sto.object.iterator();
            while (sit.next()) |s| if (s.value_ptr.* == .string) {
                const key = u256FromHex(s.key_ptr.*);
                const wv = u256FromHex(s.value_ptr.string);
                const gv = st.getStorage(addr, key);
                if (gv != wv) rep.failLine("      {s} slot {x} got {x} want {x}\n", .{ tag, key, gv, wv });
            };
        };
    }
}

fn jint(o: std.json.ObjectMap, key: []const u8) ?usize {
    const v = o.get(key) orelse return null;
    return if (v == .integer) @intCast(v.integer) else null;
}

fn runTest(gpa: std.mem.Allocator, rep: *report.Reporter, path: []const u8, name: []const u8, obj: std.json.ObjectMap, variant: ForkVariant) Verdict {
    const g_fork = variant.fork;
    const post = jobj(obj, "post") orelse return .skip;
    const entries_v = post.get(variant.name) orelse return .skip; // no vector for this fork
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
            .fork = g_fork,
            .coinbase = addrFromHex(jstr(env_o, "currentCoinbase") orelse "0x0"),
            .number = u64FromHex(jstr(env_o, "currentNumber") orelse "0x0"),
            .time = u256FromHex(jstr(env_o, "currentTimestamp") orelse "0x0"),
            .gas_limit = u64FromHex(jstr(env_o, "currentGasLimit") orelse "0x0"),
            .base_fee = base_fee,
            .origin = addrFromHex(sender_s),
            .chain_id = 1,
        };
        if (jstr(env_o, "currentRandom")) |r| env.prev_randao = u256FromHex(r);
        if (jstr(env_o, "currentDifficulty")) |d| env.difficulty = u256FromHex(d);
        // BLOBBASEFEE is the blob gas price for the current excess blob gas,
        // regardless of whether this is a blob transaction.
        env.blob_base_fee = zeth.tx.blobGasPrice(u256FromHex(jstr(env_o, "currentExcessBlobGas") orelse "0x0"), g_fork);

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

        // EIP-4844 blob transaction: compute the (burned) blob data fee, expose
        // the versioned hashes + blob base fee, and validate the blob fields.
        var blob_data_fee: u256 = 0;
        var blob_ok = true;
        if (tx_o.get("maxFeePerBlobGas") != null or tx_o.get("blobVersionedHashes") != null) {
            const excess = u256FromHex(jstr(env_o, "currentExcessBlobGas") orelse "0x0");
            const price = zeth.tx.blobGasPrice(excess, g_fork);
            const max_fee_per_blob_gas = u256FromHex(jstr(tx_o, "maxFeePerBlobGas") orelse "0x0");
            env.blob_base_fee = price;
            const bh = jarr(tx_o, "blobVersionedHashes");
            const blob_count: usize = if (bh) |x| x.len else 0;
            blob_data_fee = @as(u256, zeth.tx.GAS_PER_BLOB) * blob_count * price;

            // EIP-4844 validity: non-empty, version 0x01, fee cap, blob-gas limit,
            // and blob txs may not be contract creations.
            if (blob_count == 0) blob_ok = false;
            if (max_fee_per_blob_gas < price) blob_ok = false;
            if (@as(u256, zeth.tx.GAS_PER_BLOB) * blob_count > zeth.tx.maxBlobGasPerBlock(g_fork)) blob_ok = false;
            if (jstr(tx_o, "to")) |t| {
                if (t.len == 0 or std.mem.eql(u8, t, "0x")) blob_ok = false;
            } else blob_ok = false;

            var hashes = std.ArrayList([32]u8).empty;
            if (bh) |hs| for (hs) |h| if (h == .string) {
                var hh: [32]u8 = undefined;
                const s = if (std.mem.startsWith(u8, h.string, "0x")) h.string[2..] else h.string;
                _ = std.fmt.hexToBytes(&hh, s) catch {};
                if (hh[0] != 0x01) blob_ok = false; // VERSIONED_HASH_VERSION_KZG
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
        if (blob_ok and zeth.tx.validate(&st, &env, tx, max_fee_cap, max_prio) == null) {
            _ = zeth.tx.process(a, &st, &env, tx);
        }
        const got = zeth.trie.stateRoot(a, &st);

        var want: [32]u8 = undefined;
        const hash = jstr(entry, "hash") orelse return .skip;
        _ = std.fmt.hexToBytes(&want, hash[2..]) catch {};

        if (!std.mem.eql(u8, &got, &want)) {
            result = .fail;
            rep.failLine("  {s}{s}{s}\n    {s}{s}{s} (d{d}g{d}v{d})\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET), di, gi, vi });
            // Diff against the fixture's expected post accounts to localize the bug.
            if (jobj(entry, "state")) |post_state| diffState(rep, &st, post_state);
            break;
        }
    }
    return result;
}

fn runFile(gpa: std.mem.Allocator, io: std.Io, rep: *report.Reporter, path: []const u8) void {
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited) catch return;
    defer gpa.free(content);
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, content, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;

    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .object) continue;
        for (g_forks) |variant| {
            switch (runTest(gpa, rep, path, entry.key_ptr.*, entry.value_ptr.object, variant)) {
                .pass => rep.passed(),
                .fail => {
                    rep.failed();
                    if (g_stop) return;
                },
                .skip => rep.skipped(),
            }
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const nc = init.environ_map.get("NO_COLOR");
    g_color = nc == null or nc.?.len == 0;
    if (init.environ_map.get("ZETH_TRACE") != null) zeth.vm.trace_enabled = true;
    if (init.environ_map.get("ZETH_ALL") != null) g_stop = false; // run past failures
    if (init.environ_map.get("ZETH_DATA")) |d| g_data_filter = std.fmt.parseInt(usize, d, 10) catch null;
    if (init.environ_map.get("ZETH_FORK")) |f| {
        g_single[0] = .{ .name = f, .fork = zeth.fork.Fork.fromName(f) orelse {
            std.debug.print("unknown fork: {s}\n", .{f});
            return error.MissingArgument;
        } };
        g_forks = &g_single;
    }
    if (args.len < 2) {
        std.debug.print("usage: statetest <fixture.json | dir> ...\n", .{});
        return error.MissingArgument;
    }

    const files = try report.collectJson(gpa, init.io, args[1..]);
    var rep = report.Reporter{ .alloc = gpa, .color = g_color };
    std.debug.print("  ", .{}); // indent the first graph row
    // Run on a thread with a large stack: a fixture can drive the EVM to its
    // 1024-deep call recursion, which overflows the default main-thread stack.
    var ctx = RunCtx{ .gpa = gpa, .io = init.io, .rep = &rep, .files = files };
    const t = try std.Thread.spawn(.{ .stack_size = zeth.vm.NATIVE_STACK_SIZE }, runFilesWorker, .{&ctx});
    t.join();

    const ok = rep.finish("GeneralStateTests");
    if (!ok) return error.ConformanceFailed;
}

const RunCtx = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    rep: *report.Reporter,
    files: []const []const u8,
};

fn runFilesWorker(ctx: *RunCtx) void {
    for (ctx.files) |path| {
        runFile(ctx.gpa, ctx.io, ctx.rep, path);
        if (g_stop and ctx.rep.fail > 0) break; // stop at the first failure
    }
}
