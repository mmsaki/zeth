//! BlockchainTests runner: processes each block's transactions + withdrawals
//! through our tx layer and checks the resulting **state root** against the
//! block header — the same root oracle as the state tests, one level up.
//! Reuses decoded headers/txs from the fixture (no RLP block decoder needed)
//! and targets the Prague fork. This is also the on-ramp to hive `consume-rlp`.
//!
//!   blocktest <fixture.json> [more.json ...]

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

/// A fork to evaluate, paired with the fixture `network` name.
const ForkVariant = struct { name: []const u8, fork: zeth.Fork };
/// Forks we run by default — a fixture is run if its `network` is one of these.
/// Override with ZETH_FORK=<name>.
const DEFAULT_FORKS = [_]ForkVariant{
    .{ .name = "Frontier", .fork = .frontier },
    .{ .name = "Homestead", .fork = .homestead },
    .{ .name = "EIP150", .fork = .tangerine_whistle },
    .{ .name = "EIP158", .fork = .spurious_dragon },
    .{ .name = "Byzantium", .fork = .byzantium },
    .{ .name = "Constantinople", .fork = .constantinople },
    .{ .name = "ConstantinopleFix", .fork = .petersburg },
    .{ .name = "Istanbul", .fork = .istanbul },
    .{ .name = "Berlin", .fork = .berlin },
    .{ .name = "London", .fork = .london },
    .{ .name = "Paris", .fork = .paris },
    .{ .name = "Merge", .fork = .paris },
    .{ .name = "Shanghai", .fork = .shanghai },
    .{ .name = "Cancun", .fork = .cancun },
    .{ .name = "Prague", .fork = .prague },
    .{ .name = "Osaka", .fork = .osaka },
};
var g_forks: []const ForkVariant = &DEFAULT_FORKS;
var g_single: [1]ForkVariant = undefined;
var g_fork: zeth.Fork = .prague; // set per-test from the matched network
var g_check_hash = false; // ZETH_HASH=1: verify block hashes instead of state roots
var g_check_receipts = false; // ZETH_RECEIPTS=1: also verify receipts root + logs bloom
var g_import = false; // ZETH_IMPORT=1: drive the real chain.importBlock pipeline from RLP

/// A fork schedule pinned so `forkAt` always returns `f` (every block in a
/// fixture shares one fork).
fn scheduleForFork(f: zeth.Fork) zeth.genesis.ForkSchedule {
    return .{
        .chain_id = 1,
        .shanghai_time = if (f.atLeast(.shanghai)) 0 else null,
        .cancun_time = if (f.atLeast(.cancun)) 0 else null,
        .prague_time = if (f.atLeast(.prague)) 0 else null,
        .osaka_time = if (f.atLeast(.osaka)) 0 else null,
    };
}
var g_stop = true; // stop at first failure; ZETH_ALL=1 runs everything
const Verdict = enum { pass, fail, skip };

fn shortName(n: []const u8) []const u8 {
    if (std.mem.indexOf(u8, n, "::")) |i| return n[i + 2 ..];
    if (std.mem.lastIndexOfScalar(u8, n, '/')) |i| return n[i + 1 ..];
    return n;
}

/// Print which accounts/slots differ from the fixture's expected post state.
fn diffState(rep: *report.Reporter, st: *zeth.State, post: std.json.ObjectMap) void {
    var it = post.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* != .object) continue;
        const tag = e.key_ptr.*;
        const addr = addrH(tag);
        const exp = e.value_ptr.object;
        const wb = u256H(jstr(exp, "balance") orelse "0x0");
        if (st.balanceOf(addr) != wb) rep.failLine("      {s} balance got {d} want {d}\n", .{ tag, st.balanceOf(addr), wb });
        const wn = u64H(jstr(exp, "nonce") orelse "0x0");
        if (st.nonceOf(addr) != wn) rep.failLine("      {s} nonce got {d} want {d}\n", .{ tag, st.nonceOf(addr), wn });
        if (exp.get("storage")) |sto| if (sto == .object) {
            var sit = sto.object.iterator();
            while (sit.next()) |s| if (s.value_ptr.* == .string) {
                const key = u256H(s.key_ptr.*);
                const wv = u256H(s.value_ptr.string);
                if (st.getStorage(addr, key) != wv) rep.failLine("      {s} slot {x} got {x} want {x}\n", .{ tag, key, st.getStorage(addr, key), wv });
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

/// A field from a block's `blockHeader` (e.g. "hash", "parentHash").
fn hdrStr(block: std.json.ObjectMap, k: []const u8) ?[]const u8 {
    const hdr = jobj(block, "blockHeader") orelse return null;
    return jstr(hdr, k);
}

/// Find the block in `blocks[]` whose header hash equals `hash`.
fn findBlock(blocks: []std.json.Value, hash: []const u8) ?std.json.ObjectMap {
    for (blocks) |b_v| {
        if (b_v != .object) continue;
        const h = hdrStr(b_v.object, "hash") orelse continue;
        if (std.ascii.eqlIgnoreCase(h, hash)) return b_v.object;
    }
    return null;
}

/// Parse a fixed-width hex field (defaults to zero when absent/short).
fn fixedH(comptime N: usize, s: ?[]const u8) [N]u8 {
    var out: [N]u8 = std.mem.zeroes([N]u8);
    if (s) |v| {
        const b = if (std.mem.startsWith(u8, v, "0x")) v[2..] else v;
        _ = std.fmt.hexToBytes(&out, b) catch {};
    }
    return out;
}

/// Build a block.Header from a fixture `blockHeader`/`genesisBlockHeader` object.
fn headerFromJson(a: std.mem.Allocator, hdr: std.json.ObjectMap) zeth.block.Header {
    var h = zeth.block.Header{};
    h.parent_hash = fixedH(32, jstr(hdr, "parentHash"));
    if (jstr(hdr, "uncleHash")) |u| h.ommers_hash = fixedH(32, u);
    h.coinbase = addrH(jstr(hdr, "coinbase") orelse "0x0");
    h.state_root = fixedH(32, jstr(hdr, "stateRoot"));
    h.transactions_root = fixedH(32, jstr(hdr, "transactionsTrie"));
    h.receipts_root = fixedH(32, jstr(hdr, "receiptTrie"));
    h.logs_bloom = fixedH(256, jstr(hdr, "bloom"));
    h.difficulty = u256H(jstr(hdr, "difficulty") orelse "0x0");
    h.number = u64H(jstr(hdr, "number") orelse "0x0");
    h.gas_limit = u64H(jstr(hdr, "gasLimit") orelse "0x0");
    h.gas_used = u64H(jstr(hdr, "gasUsed") orelse "0x0");
    h.timestamp = u64H(jstr(hdr, "timestamp") orelse "0x0");
    h.extra_data = bytesH(a, jstr(hdr, "extraData") orelse "0x");
    h.prev_randao = fixedH(32, jstr(hdr, "mixHash"));
    h.nonce = fixedH(8, jstr(hdr, "nonce"));
    if (jstr(hdr, "baseFeePerGas")) |v| h.base_fee_per_gas = u256H(v);
    if (jstr(hdr, "withdrawalsRoot")) |v| h.withdrawals_root = fixedH(32, v);
    if (jstr(hdr, "blobGasUsed")) |v| h.blob_gas_used = u64H(v);
    if (jstr(hdr, "excessBlobGas")) |v| h.excess_blob_gas = u64H(v);
    if (jstr(hdr, "parentBeaconBlockRoot")) |v| h.parent_beacon_block_root = fixedH(32, v);
    if (jstr(hdr, "requestsHash")) |v| h.requests_hash = fixedH(32, v);
    return h;
}

const HdrEntry = struct { hdr: std.json.ObjectMap, rlp: ?[]const u8, txs: ?[]std.json.Value };

/// ZETH_HASH=1 mode: validate the block.Header + block-body encoding/decoding
/// against the fixtures without running the state transition. For each header it
/// (1) rebuilds the Header from JSON and checks the block hash, and (2) when the
/// fixture carries the block's `rlp`, decodes it and checks the decoded header
/// hash plus the transactions and withdrawals roots. Returns .fail on the first
/// mismatch.
fn checkHashes(a: std.mem.Allocator, rep: *report.Reporter, path: []const u8, name: []const u8, obj: std.json.ObjectMap) Verdict {
    var entries: std.ArrayList(HdrEntry) = .empty;
    if (jobj(obj, "genesisBlockHeader")) |gh|
        entries.append(a, .{ .hdr = gh, .rlp = jstr(obj, "genesisRLP"), .txs = null }) catch @panic("oom");
    if (jarr(obj, "blocks")) |blocks| for (blocks) |b_v| {
        if (b_v != .object) continue;
        if (b_v.object.get("expectException") != null) continue;
        const bh = jobj(b_v.object, "blockHeader") orelse continue;
        entries.append(a, .{ .hdr = bh, .rlp = jstr(b_v.object, "rlp"), .txs = jarr(b_v.object, "transactions") }) catch @panic("oom");
    };

    for (entries.items) |e| {
        const want = jstr(e.hdr, "hash") orelse continue;
        var want_b: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&want_b, if (std.mem.startsWith(u8, want, "0x")) want[2..] else want) catch {};

        // (1) Header built from JSON → block hash.
        const hj = headerFromJson(a, e.hdr);
        if (!checkHash(rep, path, name, "hash(json)", hj, want_b)) return .fail;

        // (2) Decode the block RLP → header hash + transactions/withdrawals roots.
        if (e.rlp) |rlp_hex| {
            const raw = bytesH(a, rlp_hex);
            const blk = zeth.block.decodeBlock(a, raw) catch |err| {
                rep.failLine("  {s}{s}{s}\n    {s}{s}{s} block {d} decode error: {s}\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET), hj.number, @errorName(err) });
                return .fail;
            };
            if (!checkHash(rep, path, name, "hash(rlp)", blk.header, want_b)) return .fail;
            const tr = zeth.block.orderedTrieRoot(a, blk.transactions);
            if (!std.mem.eql(u8, &tr, &blk.header.transactions_root))
                return rootFail(rep, path, name, hj.number, "transactionsRoot", tr, blk.header.transactions_root);
            if (blk.has_withdrawals) {
                const wr = zeth.block.orderedTrieRoot(a, blk.withdrawals);
                if (blk.header.withdrawals_root) |want_wr|
                    if (!std.mem.eql(u8, &wr, &want_wr))
                        return rootFail(rep, path, name, hj.number, "withdrawalsRoot", wr, want_wr);
            }
            // Decode each transaction from RLP and check the recovered sender
            // against the fixture.
            if (e.txs) |txs| if (txs.len == blk.transactions.len) {
                for (blk.transactions, 0..) |enc, i| {
                    if (txs[i] != .object) continue;
                    const want_sender = jstr(txs[i].object, "sender") orelse continue;
                    const dt = zeth.transaction.decode(a, enc) catch |err| {
                        rep.failLine("  {s}{s}{s}\n    {s}{s}{s} block {d} tx {d} decode error: {s}\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET), hj.number, i, @errorName(err) });
                        return .fail;
                    };
                    const sh = std.fmt.bytesToHex(&dt.sender, .lower);
                    const wb = addrH(want_sender);
                    if (!std.mem.eql(u8, &dt.sender, &wb)) {
                        rep.failLine("  {s}{s}{s}\n    {s}{s}{s} block {d} tx {d} sender got 0x{s} want {s}\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET), hj.number, i, &sh, want_sender });
                        return .fail;
                    }
                }
            };
        }
    }
    return .pass;
}

fn checkHash(rep: *report.Reporter, path: []const u8, name: []const u8, label: []const u8, h: zeth.block.Header, want: [32]u8) bool {
    const got = h.hash(std.heap.page_allocator) catch @panic("oom");
    if (std.mem.eql(u8, &got, &want)) return true;
    const got_hex = std.fmt.bytesToHex(&got, .lower);
    const want_hex = std.fmt.bytesToHex(&want, .lower);
    rep.failLine("  {s}{s}{s}\n    {s}{s}{s} block {d} {s} got 0x{s} want 0x{s}\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET), h.number, label, &got_hex, &want_hex });
    return false;
}

fn rootFail(rep: *report.Reporter, path: []const u8, name: []const u8, num: u64, label: []const u8, got: [32]u8, want: [32]u8) Verdict {
    const got_hex = std.fmt.bytesToHex(&got, .lower);
    const want_hex = std.fmt.bytesToHex(&want, .lower);
    rep.failLine("  {s}{s}{s}\n    {s}{s}{s} block {d} {s} got 0x{s} want 0x{s}\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET), num, label, &got_hex, &want_hex });
    return .fail;
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

/// Parse an EIP-7702 `authorizationList` from a fixture transaction object.
fn parseAuthList(a: std.mem.Allocator, tx_o: std.json.ObjectMap) []const zeth.tx.Authorization {
    var list = std.ArrayList(zeth.tx.Authorization).empty;
    if (jarr(tx_o, "authorizationList")) |al| {
        for (al) |e_v| {
            if (e_v != .object) continue;
            const e = e_v.object;
            const yp = jstr(e, "yParity") orelse jstr(e, "v") orelse "0x0";
            list.append(a, .{
                .chain_id = u256H(jstr(e, "chainId") orelse "0x0"),
                .address = addrH(jstr(e, "address") orelse continue),
                .nonce = u64H(jstr(e, "nonce") orelse "0x0"),
                .y_parity = @intCast(u256H(yp)),
                .r = u256H(jstr(e, "r") orelse "0x0"),
                .s = u256H(jstr(e, "s") orelse "0x0"),
            }) catch @panic("oom");
        }
    }
    return list.items;
}

/// RLP-encode a u256 as its minimal big-endian byte string (0 → empty/0x80).
fn rlpQ(a: std.mem.Allocator, v: u256) []const u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, v, .big);
    var s: usize = 0;
    while (s < 32 and buf[s] == 0) s += 1;
    return zeth.rlp.encodeBytes(a, buf[s..]) catch @panic("oom");
}

/// Recover the sender of a legacy transaction from its (v, r, s) signature when
/// the fixture doesn't give `sender` directly. Builds the EIP-155/pre-155
/// signing hash by RLP-encoding the tx fields and runs secp256k1 recovery.
fn recoverSender(a: std.mem.Allocator, tx_o: std.json.ObjectMap) ?Address {
    const v = u64H(jstr(tx_o, "v") orelse return null);
    const to_s = jstr(tx_o, "to") orelse "";
    const to_bytes: []const u8 = if (to_s.len == 0 or std.mem.eql(u8, to_s, "0x")) &.{} else bytesH(a, to_s);

    var items: std.ArrayList([]const u8) = .empty;
    items.append(a, rlpQ(a, u256H(jstr(tx_o, "nonce") orelse "0x0"))) catch @panic("oom");
    items.append(a, rlpQ(a, u256H(jstr(tx_o, "gasPrice") orelse "0x0"))) catch @panic("oom");
    items.append(a, rlpQ(a, u256H(jstr(tx_o, "gasLimit") orelse "0x0"))) catch @panic("oom");
    items.append(a, zeth.rlp.encodeBytes(a, to_bytes) catch @panic("oom")) catch @panic("oom");
    items.append(a, rlpQ(a, u256H(jstr(tx_o, "value") orelse "0x0"))) catch @panic("oom");
    items.append(a, zeth.rlp.encodeBytes(a, bytesH(a, jstr(tx_o, "data") orelse "0x")) catch @panic("oom")) catch @panic("oom");

    var recid: u8 = undefined;
    if (v == 27 or v == 28) {
        recid = @intCast(v - 27);
    } else {
        const chain_id = (v - 35) / 2;
        recid = @intCast((v - 35) % 2);
        items.append(a, rlpQ(a, chain_id)) catch @panic("oom"); // EIP-155: chainId, 0, 0
        items.append(a, zeth.rlp.encodeBytes(a, &.{}) catch @panic("oom")) catch @panic("oom");
        items.append(a, zeth.rlp.encodeBytes(a, &.{}) catch @panic("oom")) catch @panic("oom");
    }
    const payload = zeth.rlp.encodeList(a, items.items) catch @panic("oom");
    const hash = zeth.crypto.keccak256(payload);
    var r: [32]u8 = undefined;
    var s: [32]u8 = undefined;
    std.mem.writeInt(u256, &r, u256H(jstr(tx_o, "r") orelse "0x0"), .big);
    std.mem.writeInt(u256, &s, u256H(jstr(tx_o, "s") orelse "0x0"), .big);
    return zeth.precompiles.recoverAddress(hash, recid, r, s);
}

/// Derive the EIP-2718 transaction type from the fixture's tx fields.
fn deriveTxType(o: std.json.ObjectMap) u8 {
    if (o.get("authorizationList") != null) return 4; // EIP-7702 set code
    if (o.get("maxFeePerBlobGas") != null or o.get("blobVersionedHashes") != null) return 3; // EIP-4844
    if (o.get("maxFeePerGas") != null) return 2; // EIP-1559
    if (o.get("accessList") != null) return 1; // EIP-2930
    return 0; // legacy
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
fn applyBlock(a: std.mem.Allocator, st: *zeth.State, block: std.json.ObjectMap, block_hashes: []const [32]u8) bool {
    const header = jobj(block, "blockHeader") orelse return false;
    const base_fee = u256H(jstr(header, "baseFeePerGas") orelse "0x0");

    var env = zeth.Environment{
        .fork = g_fork,
        .coinbase = addrH(jstr(header, "coinbase") orelse "0x0"),
        .number = u64H(jstr(header, "number") orelse "0x0"),
        .time = u256H(jstr(header, "timestamp") orelse "0x0"),
        .gas_limit = u64H(jstr(header, "gasLimit") orelse "0x0"),
        .base_fee = base_fee,
        .prev_randao = u256H(jstr(header, "mixHash") orelse "0x0"),
        .difficulty = u256H(jstr(header, "difficulty") orelse "0x0"),
        .chain_id = 1,
        .block_hashes = block_hashes, // [genesis, block1, …] for the BLOCKHASH opcode
    };
    // BLOBBASEFEE for any tx, from the block's excess blob gas.
    env.blob_base_fee = zeth.tx.blobGasPrice(u256H(jstr(header, "excessBlobGas") orelse "0x0"), g_fork);

    // Block-start system calls write state, so they must run before the
    // transactions. EIP-4788 (beacon roots) is Cancun+; EIP-2935 (block-hash
    // history) is Prague+.
    if (jstr(header, "parentBeaconBlockRoot")) |r|
        systemCall(a, st, &env, "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02", bytesH(a, r));
    if (g_fork.atLeast(.prague)) if (jstr(header, "parentHash")) |h|
        systemCall(a, st, &env, "0x0000F90827F1C53a10cb7A02335B175320002935", bytesH(a, h));

    var receipts: std.ArrayList(zeth.block.Receipt) = .empty;
    var cumulative_gas: u64 = 0;

    if (jarr(block, "transactions")) |txs| {
        for (txs) |tx_v| {
            if (tx_v != .object) continue;
            const tx_o = tx_v.object;
            // Use the fixture's sender, or recover it from the signature.
            const sender_addr: Address = if (jstr(tx_o, "sender")) |s|
                addrH(s)
            else
                (recoverSender(a, tx_o) orelse continue);

            var gas_price: u256 = undefined;
            if (jstr(tx_o, "gasPrice")) |gp| {
                gas_price = u256H(gp);
            } else {
                const mf = u256H(jstr(tx_o, "maxFeePerGas") orelse "0x0");
                const mp = u256H(jstr(tx_o, "maxPriorityFeePerGas") orelse "0x0");
                gas_price = @min(mf, base_fee + mp);
            }
            env.gas_price = gas_price;
            env.origin = sender_addr;

            // EIP-4844 blob transaction: charge the (burned) blob data fee and
            // expose the versioned hashes + blob base fee to the EVM.
            var blob_data_fee: u256 = 0;
            if (jarr(tx_o, "blobVersionedHashes")) |bh| {
                const excess = u256H(jstr(header, "excessBlobGas") orelse "0x0");
                const price = zeth.tx.blobGasPrice(excess, g_fork);
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
                .sender = sender_addr,
                .to = if (to_s.len == 0 or std.mem.eql(u8, to_s, "0x")) null else addrH(to_s),
                .nonce = u64H(jstr(tx_o, "nonce") orelse "0x0"),
                .gas_limit = u64H(jstr(tx_o, "gasLimit") orelse "0x0"),
                .gas_price = gas_price,
                .value = u256H(jstr(tx_o, "value") orelse "0x0"),
                .data = bytesH(a, jstr(tx_o, "data") orelse "0x"),
                .access_list = parseAccessList(a, tx_o),
                .blob_data_fee = blob_data_fee,
                .authorizations = parseAuthList(a, tx_o),
            };
            if (g_check_receipts) {
                var logs: std.ArrayList(zeth.vm.Log) = .empty;
                const res = zeth.tx.processWithReceipt(a, st, &env, tx, &logs);
                cumulative_gas += res.gas_used;
                receipts.append(a, .{
                    .tx_type = deriveTxType(tx_o),
                    .success = res.success,
                    .cumulative_gas_used = cumulative_gas,
                    .logs = logs.items,
                }) catch @panic("oom");
            } else {
                _ = zeth.tx.process(a, st, &env, tx);
            }
        }
    }

    // Verify the receipts root + logs bloom against the header (ZETH_RECEIPTS=1).
    if (g_check_receipts) {
        const rr = zeth.block.receiptsRoot(a, receipts.items);
        const want_rr = fixedH(32, jstr(header, "receiptTrie"));
        var bloom = std.mem.zeroes([256]u8);
        for (receipts.items) |*r| zeth.block.orBloom(&bloom, zeth.block.logsBloom(r.logs));
        const want_bloom = fixedH(256, jstr(header, "bloom"));
        if (!std.mem.eql(u8, &rr, &want_rr) or !std.mem.eql(u8, &bloom, &want_bloom)) {
            const rh = std.fmt.bytesToHex(&rr, .lower);
            const wh = std.fmt.bytesToHex(&want_rr, .lower);
            std.debug.print("\n  block {d} receiptsRoot got 0x{s} want 0x{s} bloom_ok={}\n", .{ env.number, &rh, &wh, std.mem.eql(u8, &bloom, &want_bloom) });
            return false;
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

    // PoW block rewards (pre-Merge): miner gets the static reward + a 1/32
    // nephew bonus per ommer; each ommer miner gets a stale-depth share. Mirrors
    // chain.importDecoded; blockReward() is zero post-Merge so this is a no-op.
    const reward = g_fork.blockReward();
    if (reward > 0) {
        const uncles = jarr(block, "uncleHeaders") orelse &.{};
        for (uncles) |u_v| {
            if (u_v != .object) continue;
            const u = u_v.object;
            const ucb = addrH(jstr(u, "coinbase") orelse continue);
            const unum = u256H(jstr(u, "number") orelse "0x0");
            const ommer_reward = (unum + 8 - @as(u256, env.number)) * reward / 8;
            st.setBalance(ucb, st.balanceOf(ucb) + ommer_reward) catch @panic("oom");
        }
        const miner_reward = reward + @as(u256, uncles.len) * (reward / 32);
        st.setBalance(env.coinbase, st.balanceOf(env.coinbase) + miner_reward) catch @panic("oom");
    }

    // EIP-7685 (Prague): the withdrawal/consolidation predeploy system calls run
    // at block end and dequeue their request queues, mutating predeploy storage.
    // (Deposits and the requests-hash don't affect the state root, so the
    // JSON-driven path only needs these two calls to match.)
    if (g_fork.atLeast(.prague)) {
        systemCall(a, st, &env, "0x00000961Ef480Eb55e80D19ad83579A64c007002", &.{}); // EIP-7002
        systemCall(a, st, &env, "0x0000BBdDc7CE488642fb579F8B00f3a590007251", &.{}); // EIP-7251
    }

    const got = zeth.trie.stateRoot(a, st);
    var want: [32]u8 = undefined;
    const sr = jstr(header, "stateRoot") orelse return false;
    _ = std.fmt.hexToBytes(&want, sr[2..]) catch {};
    return std.mem.eql(u8, &got, &want);
}

fn runTest(gpa: std.mem.Allocator, rep: *report.Reporter, path: []const u8, name: []const u8, obj: std.json.ObjectMap) Verdict {
    const net = jstr(obj, "network") orelse return .skip;
    // Run the fixture only if its fork is in our supported set; pin g_fork to it.
    {
        var matched = false;
        for (g_forks) |v| if (std.mem.eql(u8, net, v.name)) {
            g_fork = v.fork;
            matched = true;
        };
        if (!matched) return .skip;
    }
    const pre = jobj(obj, "pre") orelse return .skip;
    const blocks = jarr(obj, "blocks") orelse return .skip;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // ZETH_HASH=1: validate block.Header RLP encoding via the block hash instead
    // of running the state transition.
    if (g_check_hash) return checkHashes(a, rep, path, name, obj);

    var st = zeth.State.init(gpa);
    defer st.deinit();
    loadPre(a, &st, pre);

    // Block hashes for the BLOCKHASH opcode, indexed by block number:
    // block_hashes[i] = hash of block i, starting with the genesis block.
    var block_hashes: std.ArrayList([32]u8) = .empty;
    const appendHash = struct {
        fn f(al: *std.ArrayList([32]u8), alloc: std.mem.Allocator, hdr: std.json.ObjectMap) void {
            if (jstr(hdr, "hash")) |h| {
                var hh: [32]u8 = undefined;
                const s = if (std.mem.startsWith(u8, h, "0x")) h[2..] else h;
                _ = std.fmt.hexToBytes(&hh, s) catch return;
                al.append(alloc, hh) catch {};
            }
        }
    }.f;

    // Sanity: our pre-state root must match the genesis header before any block.
    if (jobj(obj, "genesisBlockHeader")) |gh| {
        appendHash(&block_hashes, a, gh);
        if (jstr(gh, "stateRoot")) |sr| {
            const got = zeth.trie.stateRoot(a, &st);
            var want: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&want, sr[2..]) catch {};
            if (!std.mem.eql(u8, &got, &want)) {
                rep.failLine("  {s}{s}{s}\n    {s}{s}{s} genesis state root differs (pre-state load)\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET) });
                return .fail;
            }
        }
    }

    // Determine the canonical chain. Multi-chain tests include side-chain blocks
    // in `blocks[]` that lose the reorg — their transactions must NOT count toward
    // the post state. Walk `parentHash` from `lastblockhash` back to genesis to
    // recover only the winning branch; for a single linear chain this is exactly
    // the array order.
    const genesis_hash: ?[]const u8 = if (jobj(obj, "genesisBlockHeader")) |gh| jstr(gh, "hash") else null;
    var canon: std.ArrayList(std.json.ObjectMap) = .empty;
    if (jstr(obj, "lastblockhash")) |last| {
        var cur = last;
        while (true) {
            if (genesis_hash) |gh| if (std.ascii.eqlIgnoreCase(cur, gh)) break;
            const blk = findBlock(blocks, cur) orelse break;
            canon.append(a, blk) catch @panic("oom");
            cur = hdrStr(blk, "parentHash") orelse break;
        }
        std.mem.reverse(std.json.ObjectMap, canon.items); // genesis-first
    } else {
        // No canonical head given: apply every valid block in array order.
        for (blocks) |b_v| {
            if (b_v != .object) continue;
            const block = b_v.object;
            if (block.get("expectException") != null) continue;
            if (block.get("blockHeader") == null) continue;
            canon.append(a, block) catch @panic("oom");
        }
    }

    // ZETH_IMPORT=1: drive the real node import pipeline (decode → execute →
    // validate every root + gas + bloom) from each block's RLP, instead of the
    // JSON-driven state-root-only path.
    if (g_import) {
        const gh_json = jobj(obj, "genesisBlockHeader") orelse return .skip;
        const g = zeth.genesis.Genesis{ .schedule = scheduleForFork(g_fork), .header = headerFromJson(a, gh_json) };
        var ch = zeth.chain.Chain.initGenesis(a, &st, g) catch return .skip;
        for (canon.items, 0..) |block, bn| {
            const raw_hex = jstr(block, "rlp") orelse continue;
            _ = ch.importBlock(bytesH(a, raw_hex)) catch |err| {
                rep.failLine("  {s}{s}{s}\n    {s}{s}{s} block {d} import failed: {s}\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET), bn, @errorName(err) });
                return .fail;
            };
        }
        return .pass;
    }

    for (canon.items, 0..) |block, bn| {
        if (!applyBlock(a, &st, block, block_hashes.items)) {
            rep.failLine("  {s}{s}{s}\n    {s}{s}{s} block {d} post-state root differs:\n", .{ clr(DIM), path, clr(RESET), clr(RED), shortName(name), clr(RESET), bn });
            if (jobj(obj, "postState")) |ps| diffState(rep, &st, ps);
            return .fail;
        }
        if (jobj(block, "blockHeader")) |bh| appendHash(&block_hashes, a, bh);
    }
    return .pass;
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
        switch (runTest(gpa, rep, path, entry.key_ptr.*, entry.value_ptr.object)) {
            .pass => rep.passed(),
            .fail => {
                rep.failed();
                if (g_stop) return;
            },
            .skip => rep.skipped(),
        }
    }
}

const USAGE =
    \\usage: blocktest [flags] <fixture.json | dir> ...
    \\
    \\flags:
    \\  --all            run every fixture (don't stop at the first failure)
    \\  --fork <name>    run only fixtures for this fork (e.g. --fork London)
    \\  --import         drive the real node import pipeline (chain.importBlock)
    \\  --receipts       also check the receipts root + logs bloom
    \\  --hash           check header RLP via the block hash (skip execution)
    \\  --trace          print an opcode trace
;

/// Pin the runner to a single fork (used by `--fork`/ZETH_FORK).
fn setSingleFork(name: []const u8) !void {
    g_single[0] = .{ .name = name, .fork = zeth.fork.Fork.fromName(name) orelse {
        std.debug.print("unknown fork: {s}\n", .{name});
        return error.MissingArgument;
    } };
    g_forks = &g_single;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const nc = init.environ_map.get("NO_COLOR");
    g_color = nc == null or nc.?.len == 0;
    if (init.environ_map.get("ZETH_TRACE") != null) zeth.vm.trace_enabled = true;
    if (init.environ_map.get("ZETH_ALL") != null) g_stop = false;
    if (init.environ_map.get("ZETH_HASH") != null) g_check_hash = true;
    if (init.environ_map.get("ZETH_RECEIPTS") != null) g_check_receipts = true;
    if (init.environ_map.get("ZETH_IMPORT") != null) g_import = true;
    if (init.environ_map.get("ZETH_FORK")) |f| setSingleFork(f) catch return error.MissingArgument;

    // CLI flags (preferred; env vars above remain a silent fallback). Remaining
    // args are fixture paths.
    var paths: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--all")) {
            g_stop = false;
        } else if (std.mem.eql(u8, arg, "--import")) {
            g_import = true;
        } else if (std.mem.eql(u8, arg, "--receipts")) {
            g_check_receipts = true;
        } else if (std.mem.eql(u8, arg, "--hash")) {
            g_check_hash = true;
        } else if (std.mem.eql(u8, arg, "--trace")) {
            zeth.vm.trace_enabled = true;
        } else if (std.mem.eql(u8, arg, "--fork")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("--fork requires a name (e.g. --fork London)\n", .{});
                return error.MissingArgument;
            }
            setSingleFork(args[i]) catch return error.MissingArgument;
        } else if (std.mem.startsWith(u8, arg, "--fork=")) {
            setSingleFork(arg["--fork=".len..]) catch return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}\n", .{USAGE});
            return;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            std.debug.print("unknown flag: {s}\n{s}\n", .{ arg, USAGE });
            return error.MissingArgument;
        } else {
            paths.append(gpa, arg) catch return error.OutOfMemory;
        }
    }
    if (paths.items.len == 0) {
        std.debug.print("{s}\n", .{USAGE});
        return error.MissingArgument;
    }

    const files = try report.collectJson(gpa, init.io, paths.items);
    var rep = report.Reporter{ .alloc = gpa, .color = g_color };
    std.debug.print("  ", .{});
    // The EVM maps each call frame onto a native stack frame, so a fixture that
    // recurses to the 1024-deep call limit needs far more stack than the default
    // main-thread allowance. Run the suite on a thread with a large stack.
    var ctx = RunCtx{ .gpa = gpa, .io = init.io, .rep = &rep, .files = files };
    const t = try std.Thread.spawn(.{ .stack_size = zeth.vm.NATIVE_STACK_SIZE }, runFilesWorker, .{&ctx});
    t.join();
    const ok = rep.finish("BlockchainTests");
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
        if (g_stop and ctx.rep.fail > 0) break;
    }
}
