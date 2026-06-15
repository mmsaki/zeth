//! BlockchainTests runner: processes each block's transactions + withdrawals
//! through our tx layer and checks the resulting **state root** against the
//! block header — the same root oracle as the state tests, one level up.
//! Reuses decoded headers/txs from the fixture (no RLP block decoder needed)
//! and targets the Prague fork. This is also the on-ramp to hive `consume-rlp`.
//!
//!   blocktest <fixture.json> [more.json ...]

const std = @import("std");
const zeth = @import("zeth");
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
var g_stop = true; // stop at first failure; ZETH_ALL=1 runs everything
const Verdict = enum { pass, fail, skip };

fn shortName(n: []const u8) []const u8 {
    if (std.mem.indexOf(u8, n, "::")) |i| return n[i + 2 ..];
    if (std.mem.lastIndexOfScalar(u8, n, '/')) |i| return n[i + 1 ..];
    return n;
}

/// Print which accounts/slots differ from the fixture's expected post state.
fn diffState(st: *zeth.State, post: std.json.ObjectMap) void {
    var it = post.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* != .object) continue;
        const tag = e.key_ptr.*;
        const addr = addrH(tag);
        const exp = e.value_ptr.object;
        const wb = u256H(jstr(exp, "balance") orelse "0x0");
        if (st.balanceOf(addr) != wb) std.debug.print("      {s} balance got {d} want {d}\n", .{ tag, st.balanceOf(addr), wb });
        const wn = u64H(jstr(exp, "nonce") orelse "0x0");
        if (st.nonceOf(addr) != wn) std.debug.print("      {s} nonce got {d} want {d}\n", .{ tag, st.nonceOf(addr), wn });
        if (exp.get("storage")) |sto| if (sto == .object) {
            var sit = sto.object.iterator();
            while (sit.next()) |s| if (s.value_ptr.* == .string) {
                const key = u256H(s.key_ptr.*);
                const wv = u256H(s.value_ptr.string);
                if (st.getStorage(addr, key) != wv) std.debug.print("      {s} slot {x} got {x} want {x}\n", .{ tag, key, st.getStorage(addr, key), wv });
            };
        };
    }
}
const Tally = struct { pass: usize = 0, fail: usize = 0, skip: usize = 0 };

fn u256H(s: []const u8) u256 {
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (b.len == 0) return 0;
    return std.fmt.parseInt(u256, b, 16) catch 0;
}
fn u64H(s: []const u8) u64 {
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (b.len == 0) return 0;
    return std.fmt.parseInt(u64, b, 16) catch 0;
}
fn addrH(s: []const u8) Address {
    var a = zeth.state.zero_address;
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    _ = std.fmt.hexToBytes(&a, b) catch {};
    return a;
}
fn bytesH(a: std.mem.Allocator, s: []const u8) []u8 {
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    const out = a.alloc(u8, b.len / 2) catch @panic("oom");
    _ = std.fmt.hexToBytes(out, b) catch {};
    return out;
}
fn jstr(o: std.json.ObjectMap, k: []const u8) ?[]const u8 {
    const v = o.get(k) orelse return null;
    return if (v == .string) v.string else null;
}
fn jobj(o: std.json.ObjectMap, k: []const u8) ?std.json.ObjectMap {
    const v = o.get(k) orelse return null;
    return if (v == .object) v.object else null;
}
fn jarr(o: std.json.ObjectMap, k: []const u8) ?[]std.json.Value {
    const v = o.get(k) orelse return null;
    return if (v == .array) v.array.items else null;
}

fn loadPre(a: std.mem.Allocator, st: *zeth.State, pre: std.json.ObjectMap) void {
    var it = pre.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* != .object) continue;
        const addr = addrH(e.key_ptr.*);
        const acc = e.value_ptr.object;
        st.setBalance(addr, u256H(jstr(acc, "balance") orelse "0x0")) catch @panic("oom");
        st.setNonce(addr, u64H(jstr(acc, "nonce") orelse "0x0")) catch @panic("oom");
        st.setCode(addr, bytesH(a, jstr(acc, "code") orelse "0x")) catch @panic("oom");
        if (acc.get("storage")) |sto| if (sto == .object) {
            var sit = sto.object.iterator();
            while (sit.next()) |s| if (s.value_ptr.* == .string)
                st.setStorage(addr, u256H(s.key_ptr.*), u256H(s.value_ptr.string)) catch @panic("oom");
        };
    }
}

fn parseAccessList(a: std.mem.Allocator, tx_o: std.json.ObjectMap) []const zeth.tx.AccessEntry {
    var list = std.ArrayList(zeth.tx.AccessEntry).empty;
    if (jarr(tx_o, "accessList")) |al| {
        for (al) |e_v| {
            if (e_v != .object) continue;
            const e = e_v.object;
            var keys = std.ArrayList(u256).empty;
            if (jarr(e, "storageKeys")) |sk| for (sk) |k| {
                if (k == .string) keys.append(a, u256H(k.string)) catch @panic("oom");
            };
            list.append(a, .{ .address = addrH(jstr(e, "address") orelse continue), .keys = keys.items }) catch @panic("oom");
        }
    }
    return list.items;
}

const SYSTEM_ADDRESS = "0xfffffffffffffffffffffffffffffffffffffffe";

/// Run a block-start system call (EIP-4788 / EIP-2935): invoke the system
/// contract from the system address with `data`, persisting its state writes.
fn systemCall(a: std.mem.Allocator, st: *zeth.State, env: *const zeth.Environment, to_hex: []const u8, data: []const u8) void {
    const to = addrH(to_hex);
    if (st.codeOf(to).len == 0) return; // contract not deployed in this fork/pre
    var evm = zeth.vm.processMessage(a, st, env, .{
        .caller = addrH(SYSTEM_ADDRESS),
        .current_target = to,
        .code_address = to,
        .code = st.codeOf(to),
        .data = data,
        .gas = 30_000_000,
        .value = 0,
    }, null);
    evm.deinit();
}

/// Process one block's transactions and withdrawals against `st`. Returns false
/// if the block's resulting state root disagrees with its header.
fn applyBlock(a: std.mem.Allocator, st: *zeth.State, block: std.json.ObjectMap) bool {
    const header = jobj(block, "blockHeader") orelse return false;
    const base_fee = u256H(jstr(header, "baseFeePerGas") orelse "0x0");

    var env = zeth.Environment{
        .coinbase = addrH(jstr(header, "coinbase") orelse "0x0"),
        .number = u64H(jstr(header, "number") orelse "0x0"),
        .time = u256H(jstr(header, "timestamp") orelse "0x0"),
        .gas_limit = u64H(jstr(header, "gasLimit") orelse "0x0"),
        .base_fee = base_fee,
        .prev_randao = u256H(jstr(header, "mixHash") orelse "0x0"),
        .chain_id = 1,
    };

    // Block-start system calls (EIP-4788 beacon roots, EIP-2935 history) write
    // state, so they must run before the transactions.
    if (jstr(header, "parentBeaconBlockRoot")) |r|
        systemCall(a, st, &env, "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02", bytesH(a, r));
    if (jstr(header, "parentHash")) |h|
        systemCall(a, st, &env, "0x0000F90827F1C53a10cb7A02335B175320002935", bytesH(a, h));

    if (jarr(block, "transactions")) |txs| {
        for (txs) |tx_v| {
            if (tx_v != .object) continue;
            const tx_o = tx_v.object;
            const sender = jstr(tx_o, "sender") orelse continue;

            var gas_price: u256 = undefined;
            if (jstr(tx_o, "gasPrice")) |gp| {
                gas_price = u256H(gp);
            } else {
                const mf = u256H(jstr(tx_o, "maxFeePerGas") orelse "0x0");
                const mp = u256H(jstr(tx_o, "maxPriorityFeePerGas") orelse "0x0");
                gas_price = @min(mf, base_fee + mp);
            }
            env.gas_price = gas_price;
            env.origin = addrH(sender);

            // EIP-4844 blob transaction: charge the (burned) blob data fee and
            // expose the versioned hashes + blob base fee to the EVM.
            var blob_data_fee: u256 = 0;
            if (jarr(tx_o, "blobVersionedHashes")) |bh| {
                const excess = u256H(jstr(header, "excessBlobGas") orelse "0x0");
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

            const to_s = jstr(tx_o, "to") orelse "";
            const tx = zeth.tx.Tx{
                .sender = addrH(sender),
                .to = if (to_s.len == 0 or std.mem.eql(u8, to_s, "0x")) null else addrH(to_s),
                .nonce = u64H(jstr(tx_o, "nonce") orelse "0x0"),
                .gas_limit = u64H(jstr(tx_o, "gasLimit") orelse "0x0"),
                .gas_price = gas_price,
                .value = u256H(jstr(tx_o, "value") orelse "0x0"),
                .data = bytesH(a, jstr(tx_o, "data") orelse "0x"),
                .access_list = parseAccessList(a, tx_o),
                .blob_data_fee = blob_data_fee,
            };
            _ = zeth.tx.process(a, st, &env, tx);
        }
    }

    // Withdrawals (Shanghai+): credit balance, amount is in Gwei.
    if (jarr(block, "withdrawals")) |ws| {
        for (ws) |w_v| {
            if (w_v != .object) continue;
            const w = w_v.object;
            const addr = addrH(jstr(w, "address") orelse continue);
            const gwei = u256H(jstr(w, "amount") orelse "0x0");
            st.setBalance(addr, st.balanceOf(addr) + gwei * 1_000_000_000) catch @panic("oom");
        }
    }

    const got = zeth.trie.stateRoot(a, st);
    var want: [32]u8 = undefined;
    const sr = jstr(header, "stateRoot") orelse return false;
    _ = std.fmt.hexToBytes(&want, sr[2..]) catch {};
    return std.mem.eql(u8, &got, &want);
}

fn runTest(gpa: std.mem.Allocator, name: []const u8, obj: std.json.ObjectMap) Verdict {
    const net = jstr(obj, "network") orelse return .skip;
    if (!std.mem.eql(u8, net, FORK)) return .skip;
    const pre = jobj(obj, "pre") orelse return .skip;
    const blocks = jarr(obj, "blocks") orelse return .skip;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var st = zeth.State.init(gpa);
    defer st.deinit();
    loadPre(a, &st, pre);

    // Sanity: our pre-state root must match the genesis header before any block.
    if (jobj(obj, "genesisBlockHeader")) |gh| {
        if (jstr(gh, "stateRoot")) |sr| {
            const got = zeth.trie.stateRoot(a, &st);
            var want: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&want, sr[2..]) catch {};
            if (!std.mem.eql(u8, &got, &want)) {
                std.debug.print("  {s}FAIL{s} {s}\n      {s}genesis state root differs (pre-state load){s}\n", .{ clr(RED), clr(RESET), shortName(name), clr(DIM), clr(RESET) });
                return .fail;
            }
        }
    }

    for (blocks, 0..) |b_v, bn| {
        if (b_v != .object) continue;
        const block = b_v.object;
        // Blocks expected to be rejected are skipped (state unchanged).
        if (block.get("expectException") != null) continue;
        if (block.get("blockHeader") == null) continue;
        if (!applyBlock(a, &st, block)) {
            std.debug.print("  {s}FAIL{s} {s}\n      {s}block {d} post-state root differs:{s}\n", .{ clr(RED), clr(RESET), shortName(name), clr(DIM), bn, clr(RESET) });
            if (jobj(obj, "postState")) |ps| diffState(&st, ps);
            return .fail;
        }
    }
    return .pass;
}

fn runFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) Tally {
    var t = Tally{};
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited) catch return t;
    defer gpa.free(content);
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, content, .{}) catch return t;
    defer parsed.deinit();
    if (parsed.value != .object) return t;

    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .object) continue;
        switch (runTest(gpa, entry.key_ptr.*, entry.value_ptr.object)) {
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
    if (init.environ_map.get("ZETH_ALL") != null) g_stop = false;
    if (args.len < 2) {
        std.debug.print("usage: blocktest <fixture.json> ...\n", .{});
        return error.MissingArgument;
    }

    var total = Tally{};
    for (args[1..]) |path| {
        const t = runFile(gpa, init.io, path);
        total.pass += t.pass;
        total.fail += t.fail;
        total.skip += t.skip;
        if (g_stop and total.fail > 0) break;
    }
    const ok = total.fail == 0;
    std.debug.print("\n{s}{s}{d} passed{s}, {d} failed, {s}{d} skipped{s}\n", .{
        clr(BOLD), if (ok) clr(GREEN) else clr(RED), total.pass, clr(RESET), total.fail, clr(YELLOW), total.skip, clr(RESET),
    });
    if (!ok) return error.ConformanceFailed;
}
