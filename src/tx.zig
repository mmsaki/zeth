//! Minimal transaction-level state transition: the wrapper around the EVM that
//! charges intrinsic gas, deducts/refunds fees, pays the coinbase, and applies
//! EIP-3529 refunds — enough to run the GeneralStateTests state-transition
//! fixtures and check the resulting state root. Ported from the relevant parts
//! of `prague/fork.py` (`process_transaction`).

const std = @import("std");
const vm = @import("vm.zig");
const state_mod = @import("state.zig");
const Address = state_mod.Address;
const State = state_mod.State;
const Fork = @import("fork.zig").Fork;

pub const AccessEntry = struct { address: Address, keys: []const u256 };

pub const Tx = struct {
    sender: Address,
    to: ?Address, // null => contract creation
    nonce: u64,
    gas_limit: u64,
    gas_price: u256, // effective gas price (legacy or 1559-resolved)
    value: u256,
    data: []const u8,
    access_list: []const AccessEntry = &.{},
    /// EIP-4844 blob data fee (total_blob_gas × blob_gas_price), paid upfront
    /// and burned (never refunded).
    blob_data_fee: u256 = 0,
};

pub const GAS_PER_BLOB: u64 = 1 << 17; // 131072

/// Max blob gas a block may carry: Cancun allows 6 blobs, Prague raises it to 9
/// (EIP-7691).
pub fn maxBlobGasPerBlock(fork: Fork) u64 {
    return if (fork.atLeast(.prague)) 1179648 else 786432;
}

/// EIP-4844 blob base-fee update fraction. EIP-7691 retunes it for Prague.
fn blobBaseFeeUpdateFraction(fork: Fork) u256 {
    return if (fork.atLeast(.prague)) 5007716 else 3338477;
}

/// `taylor_exponential(1, excess_blob_gas, fraction)` — the EIP-4844 blob gas
/// price (a fake-exponential approximation).
pub fn blobGasPrice(excess_blob_gas: u256, fork: Fork) u256 {
    const fraction = blobBaseFeeUpdateFraction(fork);
    var output: u256 = 0;
    var numerator_accum: u256 = fraction; // factor(1) × denominator
    var i: u256 = 1;
    while (numerator_accum > 0) : (i += 1) {
        output += numerator_accum;
        numerator_accum = (numerator_accum * excess_blob_gas) / (fraction * i);
    }
    return output / fraction;
}

const ACCESS_LIST_ADDRESS: u64 = 2400;
const ACCESS_LIST_KEY: u64 = 1900;

pub const Result = struct { gas_used: u64, success: bool };

const TX_BASE: u64 = 21000;
const TX_CREATE: u64 = 32000;
const INIT_WORD: u64 = 2; // EIP-3860
const FLOOR_PER_TOKEN: u64 = 10; // EIP-7623

const Intrinsic = struct { standard: u64, floor: u64 };

fn intrinsicGas(data: []const u8, is_create: bool) Intrinsic {
    var zero: u64 = 0;
    var nonzero: u64 = 0;
    for (data) |b| {
        if (b == 0) zero += 1 else nonzero += 1;
    }
    const create_extra: u64 = if (is_create) TX_CREATE + INIT_WORD * ((data.len + 31) / 32) else 0;
    const standard: u64 = TX_BASE + zero * 4 + nonzero * 16 + create_extra;
    // EIP-7623 calldata floor — a minimum on the *final* gas used, not intrinsic.
    // The floor is a pure calldata price: no create or EVM costs are included.
    const tokens = zero + 4 * nonzero;
    const floor: u64 = TX_BASE + FLOOR_PER_TOKEN * tokens;
    return .{ .standard = standard, .floor = floor };
}

/// Run a transaction against `state`, mutating it, and return gas used.
/// EIP-7702 delegation indicator: exactly `0xef0100 ‖ address` (23 bytes).
fn isValidDelegation(code: []const u8) bool {
    return code.len == 23 and code[0] == 0xef and code[1] == 0x01 and code[2] == 0x00;
}

/// Pre-execution transaction validity (EELS `check_transaction`). A failing
/// transaction is rejected outright and leaves the state untouched, so callers
/// must run this before `process`. `max_fee_cap`/`max_prio` are the raw 1559
/// fields (for a legacy tx pass gas_price as the cap and 0 as the priority).
pub fn validate(state: *State, env: *const vm.Environment, tx: Tx, max_fee_cap: u256, max_prio: u256) bool {
    // EIP-1559 fee-cap sanity.
    if (max_fee_cap < env.base_fee) return false;
    if (max_fee_cap < max_prio) return false;

    // The transaction's gas limit may not exceed the block gas limit.
    if (tx.gas_limit > env.gas_limit) return false;

    // EIP-3860: a creation transaction's init code is bounded.
    if (tx.to == null and tx.data.len > vm.MAX_INIT_CODE_SIZE) return false;

    // Intrinsic gas must fit within the gas limit.
    const ig = intrinsicGas(tx.data, tx.to == null);
    var intrinsic = ig.standard;
    for (tx.access_list) |e| intrinsic += ACCESS_LIST_ADDRESS + ACCESS_LIST_KEY * e.keys.len;
    if (tx.gas_limit < intrinsic) return false;

    // Nonce must match exactly, and must leave room to increment (EELS rejects
    // a nonce of U64.MAX_VALUE so sender.nonce + 1 cannot overflow).
    if (tx.nonce >= std.math.maxInt(u64)) return false;
    if (state.nonceOf(tx.sender) != tx.nonce) return false;

    // The sender must be able to cover the worst-case fee plus value. Compute in
    // u512 since gas_limit * max_fee_cap can exceed u256 for adversarial prices.
    const max_gas_fee: u512 = @as(u512, tx.gas_limit) * max_fee_cap + tx.blob_data_fee + tx.value;
    if (@as(u512, state.balanceOf(tx.sender)) < max_gas_fee) return false;

    // EIP-3607: the sender must be an EOA (no code). Prague (EIP-7702) makes one
    // exception — an account carrying a valid delegation indicator still
    // originates transactions; pre-Prague, any code disqualifies the sender.
    const code = state.codeOf(tx.sender);
    if (code.len != 0) {
        if (!(env.fork.atLeast(.prague) and isValidDelegation(code))) return false;
    }

    return true;
}

pub fn process(allocator: std.mem.Allocator, state: *State, env: *const vm.Environment, tx: Tx) Result {
    return processImpl(allocator, state, env, tx, null);
}

/// Like `process`, but on success also appends the transaction's logs (deep-
/// copied from `allocator`) to `logs_out` — the inputs a receipt needs.
pub fn processWithReceipt(allocator: std.mem.Allocator, state: *State, env: *const vm.Environment, tx: Tx, logs_out: *std.ArrayList(vm.Log)) Result {
    return processImpl(allocator, state, env, tx, logs_out);
}

fn processImpl(allocator: std.mem.Allocator, state: *State, env: *const vm.Environment, tx: Tx, logs_out: ?*std.ArrayList(vm.Log)) Result {
    state.beginTx(); // reset access lists / transient / originals / created set
    const ig = intrinsicGas(tx.data, tx.to == null);
    var intrinsic = ig.standard;
    for (tx.access_list) |e| intrinsic += ACCESS_LIST_ADDRESS + ACCESS_LIST_KEY * e.keys.len;

    // Upfront: deduct the maximum fee and bump the sender's nonce. These happen
    // before the EVM snapshot, so they persist even if execution reverts.
    // Upfront: the gas allowance plus the (burned, non-refundable) blob fee.
    const max_fee: u256 = @as(u256, tx.gas_limit) * tx.gas_price;
    state.setBalance(tx.sender, state.balanceOf(tx.sender) - max_fee - tx.blob_data_fee) catch @panic("oom");
    state.setNonce(tx.sender, tx.nonce + 1) catch @panic("oom");

    // EIP-2929 / EIP-3651 pre-warming.
    _ = state.accessAddress(tx.sender);
    _ = state.accessAddress(env.coinbase);
    // EIP-2929 pre-warms the precompiles. The active range is fork-dependent:
    // Cancun ends at KZG (0x0a), Prague adds the BLS set through 0x11.
    const last_precompile: u8 = if (env.fork.atLeast(.prague)) 0x11 else if (env.fork.atLeast(.cancun)) 0x0a else 0x09;
    var p: u8 = 1;
    while (p <= last_precompile) : (p += 1) {
        var a = state_mod.zero_address;
        a[19] = p;
        _ = state.accessAddress(a);
    }
    for (tx.access_list) |e| {
        _ = state.accessAddress(e.address);
        for (e.keys) |k| _ = state.accessStorage(e.address, k);
    }

    const exec_gas = tx.gas_limit - intrinsic;

    var evm: vm.Evm = undefined;
    if (tx.to) |to| {
        _ = state.accessAddress(to);
        evm = vm.processMessage(allocator, state, env, .{
            .caller = tx.sender,
            .current_target = to,
            .code_address = to,
            .code = state.codeOf(to),
            .gas = exec_gas,
            .value = tx.value,
            .data = tx.data,
        }, null);
    } else {
        const contract = state_mod.computeContractAddress(allocator, tx.sender, tx.nonce) catch @panic("oom");
        _ = state.accessAddress(contract);
        evm = vm.processCreateMessage(allocator, state, env, .{
            .caller = tx.sender,
            .current_target = contract,
            .code = tx.data,
            .gas = exec_gas,
            .value = tx.value,
        }, null);
    }
    defer evm.deinit();

    const success = evm.halt_error == null and !evm.reverted;
    var gas_used = tx.gas_limit - evm.gas_left;

    // Capture logs for the receipt (only a successful tx contributes logs).
    if (logs_out) |out| if (success) {
        for (evm.logs.items) |lg| {
            out.append(allocator, .{
                .address = lg.address,
                .topics = allocator.dupe([32]u8, lg.topics) catch @panic("oom"),
                .data = allocator.dupe(u8, lg.data) catch @panic("oom"),
            }) catch @panic("oom");
        }
    };

    // EIP-3529 refund, capped at gas_used / 5.
    if (success) {
        var refund: i64 = evm.refund_counter;
        if (refund < 0) refund = 0;
        const max_refund: u64 = gas_used / 5;
        const applied: u64 = @min(@as(u64, @intCast(refund)), max_refund);
        gas_used -= applied;
    }
    // EIP-7623 (Prague): the transaction pays at least the calldata floor.
    if (env.fork.atLeast(.prague)) gas_used = @max(gas_used, ig.floor);

    // Refund the sender the unused gas, and pay the coinbase the priority fee.
    const sender_refund: u256 = @as(u256, tx.gas_limit - gas_used) * tx.gas_price;
    state.setBalance(tx.sender, state.balanceOf(tx.sender) + sender_refund) catch @panic("oom");

    const priority: u256 = tx.gas_price - env.base_fee;
    const fee: u256 = @as(u256, gas_used) * priority;
    if (fee != 0) {
        state.setBalance(env.coinbase, state.balanceOf(env.coinbase) + fee) catch @panic("oom");
    } else {
        state.touch(env.coinbase) catch @panic("oom");
    }

    // Self-destructed accounts are removed; empty accounts are excluded from
    // the state root automatically (EIP-161).
    if (success) {
        var dit = evm.accounts_to_delete.keyIterator();
        while (dit.next()) |addr| state.removeAccount(addr.*);
    }
    return .{ .gas_used = gas_used, .success = success };
}
