//! A faithful Zig port of the Prague-fork EVM (latest mainnet) from the
//! Ethereum execution-specs It implements the complete
//! opcode set — arithmetic, comparison, bitwise (incl. SHL/SHR/SAR),
//! KECCAK, environment & block context (incl. RETURNDATA*, CHAINID,
//! SELFBALANCE, BASEFEE, BLOBHASH/BLOBBASEFEE, PUSH0), account storage with the
//! EIP-2929 access-list and EIP-2200/3529 SSTORE accounting, EIP-1153 transient
//! storage (TLOAD/TSTORE), MCOPY, logs, and the full CREATE/CREATE2/CALL/
//! CALLCODE/DELEGATECALL/STATICCALL/RETURN/REVERT/SELFDESTRUCT system opcodes
//! with message-call recursion, state snapshots, the 63/64 gas rule, and
//! static-context enforcement. Gas is validated against geth (`make bench`).
//!
//! Known gaps: precompiled contracts (0x01–0x12) are not yet wired in, and a
//! handful of post-creation edge cases (EIP-6780 selfdestruct-same-tx) are
//! approximated. Tracked for follow-up.

const std = @import("std");
const word = @import("word.zig");
const crypto = @import("crypto.zig");
const state_mod = @import("state.zig");
const precompiles = @import("precompiles.zig");
const fork_mod = @import("fork.zig");
pub const Fork = fork_mod.Fork;

/// When true, every executed opcode is printed (depth/pc/op/gas) — a debug
/// trace for chasing conformance failures. Toggled via ZETH_TRACE in the runners.
pub var trace_enabled: bool = false;

/// The mnemonic for an opcode byte (for structLog `op` fields).
pub fn opName(op: u8) []const u8 {
    return switch (op) {
        0x00 => "STOP",        0x01 => "ADD",         0x02 => "MUL",         0x03 => "SUB",
        0x04 => "DIV",         0x05 => "SDIV",        0x06 => "MOD",         0x07 => "SMOD",
        0x08 => "ADDMOD",      0x09 => "MULMOD",      0x0a => "EXP",         0x0b => "SIGNEXTEND",
        0x10 => "LT",          0x11 => "GT",          0x12 => "SLT",         0x13 => "SGT",
        0x14 => "EQ",          0x15 => "ISZERO",      0x16 => "AND",         0x17 => "OR",
        0x18 => "XOR",         0x19 => "NOT",         0x1a => "BYTE",        0x1b => "SHL",
        0x1c => "SHR",         0x1d => "SAR",         0x20 => "KECCAK256",
        0x30 => "ADDRESS",     0x31 => "BALANCE",     0x32 => "ORIGIN",      0x33 => "CALLER",
        0x34 => "CALLVALUE",   0x35 => "CALLDATALOAD",0x36 => "CALLDATASIZE",0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",    0x39 => "CODECOPY",    0x3a => "GASPRICE",    0x3b => "EXTCODESIZE",
        0x3c => "EXTCODECOPY", 0x3d => "RETURNDATASIZE",0x3e => "RETURNDATACOPY",0x3f => "EXTCODEHASH",
        0x40 => "BLOCKHASH",   0x41 => "COINBASE",    0x42 => "TIMESTAMP",   0x43 => "NUMBER",
        0x44 => "PREVRANDAO",  0x45 => "GASLIMIT",    0x46 => "CHAINID",     0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",     0x49 => "BLOBHASH",    0x4a => "BLOBBASEFEE",
        0x50 => "POP",         0x51 => "MLOAD",       0x52 => "MSTORE",      0x53 => "MSTORE8",
        0x54 => "SLOAD",       0x55 => "SSTORE",      0x56 => "JUMP",        0x57 => "JUMPI",
        0x58 => "PC",          0x59 => "MSIZE",       0x5a => "GAS",         0x5b => "JUMPDEST",
        0x5c => "TLOAD",       0x5d => "TSTORE",      0x5e => "MCOPY",       0x5f => "PUSH0",
        0x60...0x7f => PUSH_NAMES[op - 0x60],
        0x80...0x8f => DUP_NAMES[op - 0x80],
        0x90...0x9f => SWAP_NAMES[op - 0x90],
        0xa0...0xa4 => LOG_NAMES[op - 0xa0],
        0xf0 => "CREATE",      0xf1 => "CALL",        0xf2 => "CALLCODE",    0xf3 => "RETURN",
        0xf4 => "DELEGATECALL",0xf5 => "CREATE2",     0xfa => "STATICCALL",  0xfd => "REVERT",
        0xfe => "INVALID",     0xff => "SELFDESTRUCT",
        else => "UNKNOWN",
    };
}
const PUSH_NAMES = blk: {
    var n: [32][]const u8 = undefined;
    for (0..32) |i| n[i] = std.fmt.comptimePrint("PUSH{d}", .{i + 1});
    break :blk n;
};
const DUP_NAMES = blk: {
    var n: [16][]const u8 = undefined;
    for (0..16) |i| n[i] = std.fmt.comptimePrint("DUP{d}", .{i + 1});
    break :blk n;
};
const SWAP_NAMES = blk: {
    var n: [16][]const u8 = undefined;
    for (0..16) |i| n[i] = std.fmt.comptimePrint("SWAP{d}", .{i + 1});
    break :blk n;
};
const LOG_NAMES = [_][]const u8{ "LOG0", "LOG1", "LOG2", "LOG3", "LOG4" };

/// One captured EVM step (geth structLog shape, sans the optional memory/storage).
pub const StructLog = struct {
    pc: usize,
    op: u8,
    gas: u64,
    depth: u32,
    stack: []const u256, // snapshot, allocated from the frame allocator
};

/// When set, every executed opcode appends a `StructLog` here (across all call
/// frames). Used by debug_traceTransaction/traceCall. Single-threaded.
pub var trace_sink: ?*std.ArrayList(StructLog) = null;

/// A call-frame in the geth `callTracer` tree (also the data Foundry renders).
pub const CallFrame = struct {
    typ: []const u8, // CALL / STATICCALL / DELEGATECALL / CALLCODE / CREATE / CREATE2
    from: Address,
    to: Address,
    value: u256,
    gas: u64,
    gas_used: u64 = 0,
    input: []const u8 = &.{},
    output: []const u8 = &.{},
    err: ?[]const u8 = null,
    calls: std.ArrayList(*CallFrame) = .empty,
};

/// Builds the call-frame tree as the EVM enters/exits messages.
pub const CallTracer = struct {
    alloc: std.mem.Allocator,
    root: ?*CallFrame = null,
    stack: std.ArrayList(*CallFrame) = .empty,

    pub fn enter(self: *CallTracer, typ: []const u8, from: Address, to: Address, value: u256, gas: u64, input: []const u8) void {
        const f = self.alloc.create(CallFrame) catch return;
        f.* = .{ .typ = typ, .from = from, .to = to, .value = value, .gas = gas, .input = self.alloc.dupe(u8, input) catch &.{} };
        if (self.stack.items.len > 0)
            self.stack.items[self.stack.items.len - 1].calls.append(self.alloc, f) catch {}
        else
            self.root = f;
        self.stack.append(self.alloc, f) catch {};
    }
    pub fn exit(self: *CallTracer, gas_used: u64, output: []const u8, err: ?[]const u8) void {
        if (self.stack.items.len == 0) return;
        const f = self.stack.items[self.stack.items.len - 1];
        self.stack.items.len -= 1;
        f.gas_used = gas_used;
        f.output = self.alloc.dupe(u8, output) catch &.{};
        f.err = err;
    }
};

/// When set, the EVM records the call-frame tree here (debug callTracer).
pub var call_tracer: ?*CallTracer = null;

fn frameError(frame: *const Evm) ?[]const u8 {
    if (frame.halt_error) |e| return @errorName(e);
    if (frame.reverted) return "execution reverted";
    return null;
}

const Address = state_mod.Address;
const State = state_mod.State;

/// Maximum call/stack depth, per the yellow paper.
pub const STACK_DEPTH_LIMIT: u32 = 1024;

/// Maximum operand stack size.
pub const STACK_LIMIT: usize = 1024;

/// Native stack required to execute a transaction. Each EVM call frame recurses
/// through processMessage→genericCall→callOp→run→step on the native stack, so a
/// contract reaching the 1024-deep call limit needs far more than the default
/// thread allowance. Threads that run the EVM (the node's RPC/Engine handlers,
/// the conformance runners) must be spawned with at least this stack size. The
/// reservation is virtual; only touched pages are committed.
pub const NATIVE_STACK_SIZE: usize = 256 * 1024 * 1024;

/// EIP-3860: maximum init-code length (2 * MAX_CODE_SIZE).
pub const MAX_INIT_CODE_SIZE: u256 = 49152;

/// Upper bound on addressable memory. Real execution runs out of gas long
/// before reaching this (memory cost is quadratic); we use it to reject
/// absurd offsets without overflowing the gas math.
const MAX_MEMORY: u128 = 0xFFFF_FFFF; // ~4 GiB

// Opcode families spanning contiguous byte ranges.
const PUSH1_BYTE: u8 = 0x60;
const PUSH32_BYTE: u8 = 0x7F;
const DUP1_BYTE: u8 = 0x80;
const DUP16_BYTE: u8 = 0x8F;
const SWAP1_BYTE: u8 = 0x90;
const SWAP16_BYTE: u8 = 0x9F;
const LOG0_BYTE: u8 = 0xA0;
const LOG4_BYTE: u8 = 0xA4;

/// EVM-defined exceptional halts. Each reverts the frame and consumes all
/// remaining gas, exactly as `ExceptionalHalt` does in the spec.
pub const VmError = error{
    StackUnderflow,
    StackOverflow,
    OutOfGas,
    InvalidJumpDest,
    InvalidOpcode,
    StaticStateChange,
    OutOfBounds,
    AddressCollision,
};

/// Static gas costs, ported from `prague/vm/gas.py` (the latest mainnet fork).
pub const Gas = struct {
    pub const BASE: u64 = 2;
    pub const VERY_LOW: u64 = 3;
    pub const LOW: u64 = 5;
    pub const MID: u64 = 8;
    pub const HIGH: u64 = 10;

    pub const MEMORY_PER_WORD: u64 = 3;
    pub const COPY_PER_WORD: u64 = 3;
    pub const EXP_BASE: u64 = 10;
    pub const EXP_PER_BYTE: u64 = 50; // Spurious Dragon repricing (was 10)
    pub const JUMPDEST: u64 = 1;

    pub const KECCAK_BASE: u64 = 30;
    pub const KECCAK_PER_WORD: u64 = 6;

    // EIP-2929 access lists.
    pub const WARM_ACCESS: u64 = 100;
    pub const COLD_ACCOUNT_ACCESS: u64 = 2600;
    pub const COLD_STORAGE_ACCESS: u64 = 2100;

    pub const STORAGE_SET: u64 = 20000;
    pub const COLD_STORAGE_WRITE: u64 = 5000;
    pub const REFUND_STORAGE_CLEAR: i64 = 4800; // EIP-3529

    pub const BLOCKHASH: u64 = 20;
    pub const BLOBHASH: u64 = 3;

    pub const LOG_BASE: u64 = 375;
    pub const LOG_DATA_PER_BYTE: u64 = 8;
    pub const LOG_TOPIC: u64 = 375;

    pub const CREATE_BASE: u64 = 32000;
    pub const CODE_DEPOSIT_PER_BYTE: u64 = 200;
    pub const CODE_INIT_PER_WORD: u64 = 2; // EIP-3860 initcode

    pub const CALL_VALUE: u64 = 9000;
    pub const CALL_STIPEND: u64 = 2300;
    pub const NEW_ACCOUNT: u64 = 25000;

    pub const SELFDESTRUCT_BASE: u64 = 5000;
    pub const SELFDESTRUCT_NEW_ACCOUNT: u64 = 25000;
};

/// Account-touching opcodes whose pre-Berlin (pre-EIP-2929) gas was a flat,
/// fork-dependent price. Berlin+ replaces these with warm/cold access; this
/// table only covers the historical flat costs (EIP-150 / EIP-1884).
pub const AccountOp = enum {
    balance, // BALANCE
    extcode, // EXTCODESIZE / EXTCODECOPY
    extcodehash, // EXTCODEHASH (introduced Constantinople)
    call, // CALL / CALLCODE / DELEGATECALL / STATICCALL base access

    /// The flat (pre-Berlin) cost of this opcode at fork `f`.
    pub fn flatCost(op: AccountOp, f: Fork) u64 {
        return switch (op) {
            //                Istanbul(1884)            Tangerine(150)              Frontier
            .balance => if (f.atLeast(.istanbul)) 700 else if (f.atLeast(.tangerine_whistle)) 400 else 20,
            .extcode => if (f.atLeast(.tangerine_whistle)) 700 else 20,
            .extcodehash => if (f.atLeast(.istanbul)) 700 else 400, // Constantinople: 400
            .call => if (f.atLeast(.tangerine_whistle)) 700 else 40,
        };
    }
};

/// Flat (pre-Berlin) SLOAD cost: EIP-1884 (Istanbul) 800, EIP-150 (Tangerine)
/// 200, Frontier 50. Berlin+ uses EIP-2929 warm/cold instead.
fn sloadFlatCost(f: Fork) u64 {
    return if (f.atLeast(.istanbul)) 800 else if (f.atLeast(.tangerine_whistle)) 200 else 50;
}

/// EVM opcode encoding. Non-exhaustive so raw bytes with no assigned opcode
/// fall through to `error.InvalidOpcode`.
pub const Op = enum(u8) {
    STOP = 0x00,
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,
    SDIV = 0x05,
    MOD = 0x06,
    SMOD = 0x07,
    ADDMOD = 0x08,
    MULMOD = 0x09,
    EXP = 0x0A,
    SIGNEXTEND = 0x0B,

    LT = 0x10,
    GT = 0x11,
    SLT = 0x12,
    SGT = 0x13,
    EQ = 0x14,
    ISZERO = 0x15,
    AND = 0x16,
    OR = 0x17,
    XOR = 0x18,
    NOT = 0x19,
    BYTE = 0x1A,
    SHL = 0x1B,
    SHR = 0x1C,
    SAR = 0x1D,

    KECCAK = 0x20,

    ADDRESS = 0x30,
    BALANCE = 0x31,
    ORIGIN = 0x32,
    CALLER = 0x33,
    CALLVALUE = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE = 0x38,
    CODECOPY = 0x39,
    GASPRICE = 0x3A,
    EXTCODESIZE = 0x3B,
    EXTCODECOPY = 0x3C,
    RETURNDATASIZE = 0x3D,
    RETURNDATACOPY = 0x3E,
    EXTCODEHASH = 0x3F,

    BLOCKHASH = 0x40,
    COINBASE = 0x41,
    TIMESTAMP = 0x42,
    NUMBER = 0x43,
    DIFFICULTY = 0x44, // PREVRANDAO post-Merge
    GASLIMIT = 0x45,
    CHAINID = 0x46,
    SELFBALANCE = 0x47,
    BASEFEE = 0x48,
    BLOBHASH = 0x49,
    BLOBBASEFEE = 0x4A,

    POP = 0x50,
    MLOAD = 0x51,
    MSTORE = 0x52,
    MSTORE8 = 0x53,
    SLOAD = 0x54,
    SSTORE = 0x55,
    JUMP = 0x56,
    JUMPI = 0x57,
    PC = 0x58,
    MSIZE = 0x59,
    GAS = 0x5A,
    JUMPDEST = 0x5B,
    TLOAD = 0x5C,
    TSTORE = 0x5D,
    MCOPY = 0x5E,
    PUSH0 = 0x5F,

    CREATE = 0xF0,
    CALL = 0xF1,
    CALLCODE = 0xF2,
    RETURN = 0xF3,
    DELEGATECALL = 0xF4,
    CREATE2 = 0xF5,
    STATICCALL = 0xFA,
    REVERT = 0xFD,
    INVALID = 0xFE,
    SELFDESTRUCT = 0xFF,

    _,
};

/// The fork that introduced `op`, or null if it has existed since Frontier.
/// Drives opcode-availability gating: an opcode is an invalid instruction
/// before its activation fork.
fn opcodeMinFork(op: Op) ?Fork {
    return switch (op) {
        .DELEGATECALL => .homestead,
        .RETURNDATASIZE, .RETURNDATACOPY, .STATICCALL, .REVERT => .byzantium,
        .SHL, .SHR, .SAR, .EXTCODEHASH, .CREATE2 => .constantinople,
        .CHAINID, .SELFBALANCE => .istanbul,
        .BASEFEE => .london,
        .PUSH0 => .shanghai,
        .TLOAD, .TSTORE, .MCOPY, .BLOBHASH, .BLOBBASEFEE => .cancun,
        else => null,
    };
}

/// Block- and transaction-level context shared across an entire message tree.
pub const Environment = struct {
    fork: Fork = .osaka, // default to the latest fork
    chain_id: u64 = 1,
    coinbase: Address = state_mod.zero_address,
    number: u64 = 0,
    time: u256 = 0,
    prev_randao: u256 = 0, // post-Merge value behind opcode 0x44
    difficulty: u256 = 0, // pre-Merge PoW difficulty behind opcode 0x44
    base_fee: u256 = 0,
    blob_base_fee: u256 = 0,
    gas_limit: u64 = 0,
    gas_price: u256 = 0,
    origin: Address = state_mod.zero_address,
    /// Up to 256 recent block hashes; the last element is block `number - 1`.
    block_hashes: []const [32]u8 = &.{},
    blob_versioned_hashes: []const [32]u8 = &.{},
};

/// Per-frame call context.
pub const Message = struct {
    caller: Address = state_mod.zero_address,
    current_target: Address = state_mod.zero_address,
    code_address: ?Address = null,
    gas: u64 = 0,
    value: u256 = 0,
    data: []const u8 = &.{},
    code: []const u8 = &.{},
    depth: u32 = 0,
    is_static: bool = false,
    should_transfer_value: bool = true,
    /// Call-frame type for the callTracer (CALL by default; set by CALL/CREATE sites).
    trace_type: []const u8 = "CALL",
};

/// An emitted log entry. `topics` and `data` are heap-owned by the frame that
/// created them (ownership transfers to the parent on successful calls).
pub const Log = struct {
    address: Address,
    topics: [][32]u8,
    data: []u8,
};

/// Fixed-capacity operand stack of 256-bit words.
pub const Stack = struct {
    // Heap-backed (capacity STACK_LIMIT) so the Evm frame stays small — deep
    // call recursion would otherwise overflow the native stack (32KB/frame).
    items: []u256 = &.{},
    len: usize = 0,

    pub inline fn push(self: *Stack, value: u256) VmError!void {
        if (self.len == STACK_LIMIT) return error.StackOverflow;
        self.items[self.len] = value;
        self.len += 1;
    }

    pub inline fn pop(self: *Stack) VmError!u256 {
        if (self.len == 0) return error.StackUnderflow;
        self.len -= 1;
        return self.items[self.len];
    }

    pub inline fn peek(self: *const Stack, n: usize) VmError!u256 {
        if (n >= self.len) return error.StackUnderflow;
        return self.items[self.len - 1 - n];
    }
};

/// Byte-addressable, zero-initialized, dynamically growing EVM memory.
pub const Memory = struct {
    data: []u8 = &.{},
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Memory {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Memory) void {
        self.allocator.free(self.data);
        self.data = &.{};
    }

    fn expand(self: *Memory, by: usize) !void {
        if (by == 0) return;
        const old = self.data.len;
        self.data = try self.allocator.realloc(self.data, old + by);
        @memset(self.data[old..], 0);
    }

    fn write(self: *Memory, start: usize, value: []const u8) void {
        @memcpy(self.data[start .. start + value.len], value);
    }
};

const AddressSet = std.AutoHashMapUnmanaged(Address, void);

/// One EVM execution frame.
pub const Evm = struct {
    pc: usize = 0,
    stack: Stack = .{},
    memory: Memory,
    code: []const u8,
    gas_left: u64,
    valid_jump_destinations: []const bool,
    running: bool = true,
    output: []const u8 = &.{},
    halt_error: ?VmError = null,
    op_count: u64 = 0,

    refund_counter: i64 = 0,
    logs: std.ArrayList(Log) = .empty,
    accounts_to_delete: AddressSet = .{},
    /// Output of the most recent sub-call (for RETURNDATASIZE/RETURNDATACOPY).
    return_data: []const u8 = &.{},
    /// Native precompile output (heap-owned), freed on deinit.
    owned_output: ?[]u8 = null,
    /// This frame's own copy of its code (survives nested state reverts).
    owned_code: []u8 = &.{},
    /// True inside a STATICCALL: state-modifying opcodes raise.
    is_static: bool = false,
    /// Set by REVERT — reverts state like a halt but preserves remaining gas.
    reverted: bool = false,

    message: Message,
    env: *const Environment,
    state: *State,
    parent: ?*Evm = null,
    allocator: std.mem.Allocator,

    // Owned only when constructed via the standalone `init` helper.
    owned_state: ?*State = null,
    owned_env: ?*Environment = null,

    /// Standalone constructor: runs `code` against a fresh, empty world with a
    /// default environment and message. Convenient for executing raw bytecode.
    pub fn init(allocator: std.mem.Allocator, code: []const u8, gas: u64) !Evm {
        const st = try allocator.create(State);
        st.* = State.init(allocator);
        const env = try allocator.create(Environment);
        env.* = .{};
        var evm = newFrame(allocator, st, env, .{ .code = code, .gas = gas }, gas, null);
        evm.owned_state = st;
        evm.owned_env = env;
        return evm;
    }

    pub fn deinit(self: *Evm) void {
        if (self.stack.items.len > 0) self.allocator.free(self.stack.items);
        self.memory.deinit();
        self.allocator.free(self.valid_jump_destinations);
        for (self.logs.items) |*lg| {
            self.allocator.free(lg.topics);
            self.allocator.free(lg.data);
        }
        self.logs.deinit(self.allocator);
        self.accounts_to_delete.deinit(self.allocator);
        if (self.return_data.len > 0) self.allocator.free(self.return_data);
        if (self.owned_output) |o| self.allocator.free(o);
        if (self.owned_code.len > 0) self.allocator.free(self.owned_code);
        if (self.owned_state) |st| {
            st.deinit();
            self.allocator.destroy(st);
        }
        if (self.owned_env) |e| self.allocator.destroy(e);
    }

    /// Fast path for the static, `u64`-sized gas costs that almost every
    /// opcode charges — avoids 128-bit arithmetic in the hot loop.
    inline fn chargeGas(self: *Evm, amount: u64) VmError!void {
        if (amount > self.gas_left) return error.OutOfGas;
        self.gas_left -= amount;
    }

    /// Wide path for costs that include quadratic memory-expansion gas, which
    /// can legitimately exceed `u64` for absurd offsets (and then run out).
    fn chargeGasWide(self: *Evm, amount: u128) VmError!void {
        if (amount > self.gas_left) return error.OutOfGas;
        self.gas_left -= @intCast(amount);
    }

    /// Run the frame's bytecode to completion, recording any exceptional halt
    /// in `halt_error` (which also zeroes gas and reverts at the caller).
    pub fn run(self: *Evm) void {
        while (self.running and self.pc < self.code.len) {
            self.step() catch |err| {
                self.gas_left = 0;
                self.halt_error = err;
                self.running = false;
            };
        }
    }

    // Inlined into `run`'s single call site so `pc`/`gas_left`/`stack.len`
    // stay in registers across opcodes instead of being reloaded each step.
    inline fn step(self: *Evm) VmError!void {
        self.op_count += 1;
        if (trace_enabled) std.debug.print("d{d} pc={d:>4} op=0x{x:0>2} gas={d:>9} stack={d}\n", .{ self.message.depth, self.pc, self.code[self.pc], self.gas_left, self.stack.len });
        if (trace_sink) |sink| {
            const snap = self.allocator.dupe(u256, self.stack.items[0..self.stack.len]) catch &.{};
            sink.append(self.allocator, .{ .pc = self.pc, .op = self.code[self.pc], .gas = self.gas_left, .depth = self.message.depth, .stack = snap }) catch {};
        }
        const op: Op = @enumFromInt(self.code[self.pc]);
        // Opcode availability: a fork-introduced opcode is an invalid
        // instruction before its activation fork (e.g. PUSH0 pre-Shanghai,
        // BASEFEE pre-London, SHL/CREATE2 pre-Constantinople).
        if (opcodeMinFork(op)) |mf| {
            if (!self.env.fork.atLeast(mf)) return error.InvalidOpcode;
        }
        switch (op) {
            .STOP => {
                self.running = false;
                self.pc += 1;
            },

            // --- Arithmetic ---
            .ADD => try self.binOp(Gas.VERY_LOW, word.add),
            .SUB => try self.binOp(Gas.VERY_LOW, word.sub),
            .MUL => try self.binOp(Gas.LOW, word.mul),
            .DIV => try self.binOp(Gas.LOW, word.div),
            .SDIV => try self.binOp(Gas.LOW, word.sdiv),
            .MOD => try self.binOp(Gas.LOW, word.mod),
            .SMOD => try self.binOp(Gas.LOW, word.smod),
            .ADDMOD => try self.ternOp(Gas.MID, word.addmod),
            .MULMOD => try self.ternOp(Gas.MID, word.mulmod),
            .SIGNEXTEND => try self.binOp(Gas.LOW, word.signextend),
            .EXP => try self.exp(),

            // --- Comparison ---
            .LT => try self.binOp(Gas.VERY_LOW, ltFn),
            .GT => try self.binOp(Gas.VERY_LOW, gtFn),
            .SLT => try self.binOp(Gas.VERY_LOW, sltFn),
            .SGT => try self.binOp(Gas.VERY_LOW, sgtFn),
            .EQ => try self.binOp(Gas.VERY_LOW, eqFn),
            .ISZERO => try self.unOp(Gas.VERY_LOW, isZeroFn),

            // --- Bitwise ---
            .AND => try self.binOp(Gas.VERY_LOW, andFn),
            .OR => try self.binOp(Gas.VERY_LOW, orFn),
            .XOR => try self.binOp(Gas.VERY_LOW, xorFn),
            .NOT => try self.unOp(Gas.VERY_LOW, notFn),
            .BYTE => try self.binOp(Gas.VERY_LOW, word.byte),
            .SHL => try self.binOp(Gas.VERY_LOW, word.shl),
            .SHR => try self.binOp(Gas.VERY_LOW, word.shr),
            .SAR => try self.binOp(Gas.VERY_LOW, word.sar),

            .KECCAK => try self.keccak(),

            // --- Environment ---
            .ADDRESS => try self.pushCtx(Gas.BASE, state_mod.addressToWord(self.message.current_target)),
            .BALANCE => try self.balance(),
            .ORIGIN => try self.pushCtx(Gas.BASE, state_mod.addressToWord(self.env.origin)),
            .CALLER => try self.pushCtx(Gas.BASE, state_mod.addressToWord(self.message.caller)),
            .CALLVALUE => try self.pushCtx(Gas.BASE, self.message.value),
            .CALLDATALOAD => try self.calldataload(),
            .CALLDATASIZE => try self.pushCtx(Gas.BASE, self.message.data.len),
            .CALLDATACOPY => try self.copyOp(Gas.VERY_LOW, .calldata),
            .CODESIZE => try self.pushCtx(Gas.BASE, self.code.len),
            .CODECOPY => try self.copyOp(Gas.VERY_LOW, .code),
            .GASPRICE => try self.pushCtx(Gas.BASE, self.env.gas_price),
            .EXTCODESIZE => try self.extcodesize(),
            .EXTCODECOPY => try self.extcodecopy(),
            .RETURNDATASIZE => try self.pushCtx(Gas.BASE, self.return_data.len),
            .RETURNDATACOPY => try self.returndatacopy(),
            .EXTCODEHASH => try self.extcodehash(),

            // --- Block ---
            .BLOCKHASH => try self.blockhash(),
            .COINBASE => try self.pushCtx(Gas.BASE, state_mod.addressToWord(self.env.coinbase)),
            .TIMESTAMP => try self.pushCtx(Gas.BASE, self.env.time),
            .NUMBER => try self.pushCtx(Gas.BASE, self.env.number),
            // Opcode 0x44 is DIFFICULTY pre-Merge, PREVRANDAO post-Merge (EIP-4399).
            .DIFFICULTY => try self.pushCtx(Gas.BASE, if (self.env.fork.atLeast(.paris)) self.env.prev_randao else self.env.difficulty),
            .GASLIMIT => try self.pushCtx(Gas.BASE, self.env.gas_limit),
            .CHAINID => try self.pushCtx(Gas.BASE, self.env.chain_id),
            .SELFBALANCE => try self.selfbalance(),
            .BASEFEE => try self.pushCtx(Gas.BASE, self.env.base_fee),
            .BLOBHASH => try self.blobhash(),
            .BLOBBASEFEE => try self.pushCtx(Gas.BASE, self.env.blob_base_fee),

            // --- Storage ---
            .SLOAD => try self.sload(),
            .SSTORE => try self.sstore(),
            .TLOAD => try self.tload(),
            .TSTORE => try self.tstore(),

            // --- Stack ---
            .POP => {
                try self.chargeGas(Gas.BASE);
                _ = try self.stack.pop();
                self.pc += 1;
            },
            .PUSH0 => try self.pushCtx(Gas.BASE, @as(u256, 0)),

            // --- Memory ---
            .MLOAD => try self.mload(),
            .MSTORE => try self.mstore(),
            .MSTORE8 => try self.mstore8(),
            .MSIZE => try self.pushCtx(Gas.BASE, self.memory.data.len),
            .MCOPY => try self.mcopy(),

            // --- Control flow ---
            .JUMP => try self.jump(),
            .JUMPI => try self.jumpi(),
            .PC => try self.pushCtx(Gas.BASE, self.pc),
            .GAS => {
                try self.chargeGas(Gas.BASE);
                try self.stack.push(self.gas_left);
                self.pc += 1;
            },
            .JUMPDEST => {
                try self.chargeGas(Gas.JUMPDEST);
                self.pc += 1;
            },

            // --- System ---
            .CREATE => try self.create(),
            .CREATE2 => try self.create2(),
            .CALL => try self.callOp(.call),
            .CALLCODE => try self.callOp(.callcode),
            .DELEGATECALL => try self.callOp(.delegatecall),
            .STATICCALL => try self.callOp(.staticcall),
            .RETURN => try self.ret(),
            .REVERT => try self.revert(),
            .INVALID => return error.InvalidOpcode,
            .SELFDESTRUCT => try self.selfdestruct(),

            _ => {
                const raw = self.code[self.pc];
                if (raw >= PUSH1_BYTE and raw <= PUSH32_BYTE) {
                    try self.pushN(raw - PUSH1_BYTE + 1);
                } else if (raw >= DUP1_BYTE and raw <= DUP16_BYTE) {
                    try self.dupN(raw - DUP1_BYTE);
                } else if (raw >= SWAP1_BYTE and raw <= SWAP16_BYTE) {
                    try self.swapN(raw - SWAP1_BYTE + 1);
                } else if (raw >= LOG0_BYTE and raw <= LOG4_BYTE) {
                    try self.logN(raw - LOG0_BYTE);
                } else {
                    return error.InvalidOpcode;
                }
            },
        }
    }

    // --- Operation shapes ---

    // These pure stack shapes validate height once (the arity is comptime-known)
    // and then operate in place — no per-pop/per-push error-union checks, and no
    // overflow check since every shape is net stack-neutral or shrinking.

    inline fn binOp(self: *Evm, gas: u64, comptime f: anytype) VmError!void {
        if (self.stack.len < 2) return error.StackUnderflow;
        try self.chargeGas(gas);
        const top = self.stack.len - 1;
        self.stack.items[top - 1] = f(self.stack.items[top], self.stack.items[top - 1]);
        self.stack.len = top;
        self.pc += 1;
    }

    inline fn ternOp(self: *Evm, gas: u64, comptime f: anytype) VmError!void {
        if (self.stack.len < 3) return error.StackUnderflow;
        try self.chargeGas(gas);
        const top = self.stack.len - 1;
        self.stack.items[top - 2] = f(self.stack.items[top], self.stack.items[top - 1], self.stack.items[top - 2]);
        self.stack.len = top - 1;
        self.pc += 1;
    }

    inline fn unOp(self: *Evm, gas: u64, comptime f: anytype) VmError!void {
        if (self.stack.len < 1) return error.StackUnderflow;
        try self.chargeGas(gas);
        const top = self.stack.len - 1;
        self.stack.items[top] = f(self.stack.items[top]);
        self.pc += 1;
    }

    /// Charge `gas` and push a constant context value (coerced to a word).
    inline fn pushCtx(self: *Evm, gas: u64, value: anytype) VmError!void {
        try self.chargeGas(gas);
        try self.stack.push(@as(u256, value));
        self.pc += 1;
    }

    fn exp(self: *Evm) VmError!void {
        const base = try self.stack.pop();
        const exponent = try self.stack.pop();
        const bits = if (exponent == 0) 0 else 256 - @clz(exponent);
        const bytes: u64 = (@as(u64, bits) + 7) / 8;
        // EIP-160 (Spurious Dragon) repriced the per-byte cost from 10 to 50.
        const per_byte: u64 = if (self.env.fork.atLeast(.spurious_dragon)) Gas.EXP_PER_BYTE else 10;
        try self.chargeGas(Gas.EXP_BASE + per_byte * bytes);
        try self.stack.push(word.exp(base, exponent));
        self.pc += 1;
    }

    // --- Stack instructions ---

    fn pushN(self: *Evm, n: u8) VmError!void {
        try self.chargeGas(Gas.VERY_LOW);
        const start = self.pc + 1;
        const available = if (start < self.code.len) self.code.len - start else 0;
        const take = @min(@as(usize, n), available);
        var value = word.fromBeBytes(self.code[start .. start + take]);
        const shift = 8 * (@as(usize, n) - take);
        value = if (shift >= 256) 0 else value << @intCast(shift);
        try self.stack.push(value);
        self.pc += 1 + n;
    }

    fn dupN(self: *Evm, index: u8) VmError!void {
        try self.chargeGas(Gas.VERY_LOW);
        const value = try self.stack.peek(index);
        try self.stack.push(value);
        self.pc += 1;
    }

    fn swapN(self: *Evm, n: u8) VmError!void {
        try self.chargeGas(Gas.VERY_LOW);
        if (n >= self.stack.len) return error.StackUnderflow;
        const top = self.stack.len - 1;
        std.mem.swap(u256, &self.stack.items[top], &self.stack.items[top - n]);
        self.pc += 1;
    }

    // --- Memory model ---

    const MemExt = struct { cost: u128, expand_by: usize };

    /// Compute the gas cost and byte growth needed to cover a set of
    /// `(start, size)` regions, iterating exactly like the spec's
    /// `calculate_gas_extend_memory`.
    fn extendMemory(self: *Evm, exts: []const [2]u256) VmError!MemExt {
        var expand_by: usize = 0;
        var cost: u128 = 0;
        var current: usize = self.memory.data.len;
        for (exts) |ext| {
            const start = ext[0];
            const size = ext[1];
            if (size == 0) continue;
            if (start > MAX_MEMORY or size > MAX_MEMORY) return error.OutOfGas;
            const end: u128 = @as(u128, @intCast(start)) + @as(u128, @intCast(size));
            if (end > MAX_MEMORY) return error.OutOfGas;
            const before = ceil32(current);
            const after = ceil32(@intCast(end));
            if (after <= before) continue;
            expand_by += after - before;
            cost += memoryCost(after) - memoryCost(before);
            current = after;
        }
        return .{ .cost = cost, .expand_by = expand_by };
    }

    fn growMemory(self: *Evm, by: usize) VmError!void {
        self.memory.expand(by) catch return error.OutOfGas;
    }

    /// Read a memory region given raw 256-bit operands. A zero-size region is
    /// empty and triggers no memory expansion, so its offset is never read nor
    /// even narrowed to usize — the offset may legally exceed memory size (and
    /// exceed usize) when size is 0 (e.g. LOG/RETURN/CALL with size 0).
    fn memRead(self: *Evm, start: u256, size: u256) []u8 {
        if (size == 0) return &.{};
        const s: usize = @intCast(start);
        const n: usize = @intCast(size);
        return self.memory.data[s .. s + n];
    }

    fn mstore(self: *Evm) VmError!void {
        const start = try self.stack.pop();
        const value = word.toBeBytes32(try self.stack.pop());
        const ext = try self.extendMemory(&.{.{ start, 32 }});
        try self.chargeGasWide(Gas.VERY_LOW + ext.cost);
        try self.growMemory(ext.expand_by);
        self.memory.write(@intCast(start), &value);
        self.pc += 1;
    }

    fn mstore8(self: *Evm) VmError!void {
        const start = try self.stack.pop();
        const value = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ start, 1 }});
        try self.chargeGasWide(Gas.VERY_LOW + ext.cost);
        try self.growMemory(ext.expand_by);
        const b: [1]u8 = .{@intCast(value & 0xFF)};
        self.memory.write(@intCast(start), &b);
        self.pc += 1;
    }

    fn mload(self: *Evm) VmError!void {
        const start = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ start, 32 }});
        try self.chargeGasWide(Gas.VERY_LOW + ext.cost);
        try self.growMemory(ext.expand_by);
        const at: usize = @intCast(start);
        try self.stack.push(word.fromBeBytes(self.memory.data[at .. at + 32]));
        self.pc += 1;
    }

    /// Copy bytes from `src` (with zero padding past the end) into memory.
    fn copyToMemory(self: *Evm, src: []const u8, src_start: u256, mem_start: u256, size: u256) void {
        if (size == 0) return; // no copy, no memory growth — offset never narrowed
        const ms: usize = @intCast(mem_start);
        const n: usize = @intCast(size);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            // u512 so a near-2²⁵⁶ source offset can't wrap into a valid index.
            const si: u512 = @as(u512, src_start) + i;
            self.memory.data[ms + i] = if (si < src.len) src[@intCast(si)] else 0;
        }
    }

    const CopySource = enum { calldata, code };

    fn copyOp(self: *Evm, base: u64, source: CopySource) VmError!void {
        const mem_start = try self.stack.pop();
        const data_start = try self.stack.pop();
        const size = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ mem_start, size }});
        const words = numWords(size);
        try self.chargeGasWide(base + Gas.COPY_PER_WORD * words + ext.cost);
        try self.growMemory(ext.expand_by);
        const src = switch (source) {
            .calldata => self.message.data,
            .code => self.code,
        };
        self.copyToMemory(src, data_start, mem_start, size);
        self.pc += 1;
    }

    // --- Environment opcodes that touch state ---

    /// EIP-2929 warm/cold cost for touching `addr` (Berlin+ only).
    inline fn accessAddressCost(self: *Evm, addr: Address) u64 {
        return if (self.state.accessAddress(addr)) Gas.WARM_ACCESS else Gas.COLD_ACCOUNT_ACCESS;
    }

    /// Cost of an account-touching opcode (BALANCE / EXTCODE* / CALL family).
    /// From Berlin it is EIP-2929 warm/cold; before that it is a flat,
    /// fork-dependent price (EIP-150 Tangerine and EIP-1884 Istanbul repriced
    /// these). The account is marked warm regardless — a no-op for pre-Berlin
    /// metering, but keeps the access set correct across the fork boundary.
    inline fn accountAccessCost(self: *Evm, addr: Address, op: AccountOp) u64 {
        const warm = self.state.accessAddress(addr);
        if (self.env.fork.atLeast(.berlin))
            return if (warm) Gas.WARM_ACCESS else Gas.COLD_ACCOUNT_ACCESS;
        return op.flatCost(self.env.fork);
    }

    fn balance(self: *Evm) VmError!void {
        const addr = state_mod.addressFromWord(try self.stack.pop());
        try self.chargeGas(self.accountAccessCost(addr, .balance));
        try self.stack.push(self.state.balanceOf(addr));
        self.pc += 1;
    }

    fn selfbalance(self: *Evm) VmError!void {
        try self.chargeGas(Gas.LOW); // FAST_STEP, no access-list cost
        try self.stack.push(self.state.balanceOf(self.message.current_target));
        self.pc += 1;
    }

    fn calldataload(self: *Evm) VmError!void {
        const start = try self.stack.pop();
        try self.chargeGas(Gas.VERY_LOW);
        try self.stack.push(bufferReadWord(self.message.data, start));
        self.pc += 1;
    }

    fn extcodesize(self: *Evm) VmError!void {
        const addr = state_mod.addressFromWord(try self.stack.pop());
        try self.chargeGas(self.accountAccessCost(addr, .extcode));
        try self.stack.push(self.state.codeOf(addr).len);
        self.pc += 1;
    }

    fn extcodecopy(self: *Evm) VmError!void {
        const addr = state_mod.addressFromWord(try self.stack.pop());
        const mem_start = try self.stack.pop();
        const code_start = try self.stack.pop();
        const size = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ mem_start, size }});
        const words = numWords(size);
        try self.chargeGasWide(@as(u128, self.accountAccessCost(addr, .extcode)) + Gas.COPY_PER_WORD * words + ext.cost);
        try self.growMemory(ext.expand_by);
        self.copyToMemory(self.state.codeOf(addr), code_start, mem_start, size);
        self.pc += 1;
    }

    fn extcodehash(self: *Evm) VmError!void {
        const addr = state_mod.addressFromWord(try self.stack.pop());
        try self.chargeGas(self.accountAccessCost(addr, .extcodehash));
        // Empty or absent accounts hash to 0; otherwise keccak256(code).
        const empty = !self.state.exists(addr) or
            (self.state.nonceOf(addr) == 0 and self.state.balanceOf(addr) == 0 and self.state.codeOf(addr).len == 0);
        if (empty) {
            try self.stack.push(0);
        } else {
            try self.stack.push(word.fromBeBytes(&crypto.keccak256(self.state.codeOf(addr))));
        }
        self.pc += 1;
    }

    fn returndatacopy(self: *Evm) VmError!void {
        const mem_start = try self.stack.pop();
        const data_start = try self.stack.pop();
        const size = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ mem_start, size }});
        const words = numWords(size);
        try self.chargeGasWide(Gas.VERY_LOW + Gas.COPY_PER_WORD * words + ext.cost);
        // EIP-211: reading past the end of the return-data buffer is illegal.
        if (@as(u512, data_start) + @as(u512, size) > self.return_data.len) return error.OutOfBounds;
        try self.growMemory(ext.expand_by);
        self.copyToMemory(self.return_data, data_start, mem_start, size);
        self.pc += 1;
    }

    fn blobhash(self: *Evm) VmError!void {
        const index = try self.stack.pop();
        try self.chargeGas(Gas.BLOBHASH);
        const hashes = self.env.blob_versioned_hashes;
        const result: u256 = if (index < hashes.len) word.fromBeBytes(&hashes[@intCast(index)]) else 0;
        try self.stack.push(result);
        self.pc += 1;
    }

    fn blockhash(self: *Evm) VmError!void {
        const requested = try self.stack.pop();
        try self.chargeGas(Gas.BLOCKHASH);
        const current = self.env.number;
        var result: u256 = 0;
        if (requested < current and current <= requested + 256) {
            const back: usize = @intCast(current - @as(u64, @intCast(requested)));
            const hashes = self.env.block_hashes;
            if (back <= hashes.len) {
                result = word.fromBeBytes(&hashes[hashes.len - back]);
            }
        }
        try self.stack.push(result);
        self.pc += 1;
    }

    // --- Storage opcodes ---

    fn sload(self: *Evm) VmError!void {
        const key = try self.stack.pop();
        const target = self.message.current_target;
        const warm = self.state.accessStorage(target, key);
        // Berlin+ (EIP-2929): warm/cold. Before that, a flat fork-dependent cost.
        const cost: u64 = if (self.env.fork.atLeast(.berlin))
            (if (warm) Gas.WARM_ACCESS else Gas.COLD_STORAGE_ACCESS)
        else
            sloadFlatCost(self.env.fork);
        try self.chargeGas(cost);
        try self.stack.push(self.state.getStorage(target, key));
        self.pc += 1;
    }

    /// SSTORE with the EIP-2200 (net-gas) + EIP-2929 (access list) + EIP-3529
    /// (refund) accounting, ported from `prague/vm/instructions/storage.py`.
    fn sstore(self: *Evm) VmError!void {
        const key = try self.stack.pop();
        const new_value = try self.stack.pop();
        if (self.gas_left <= Gas.CALL_STIPEND) return error.OutOfGas;

        const target = self.message.current_target;
        const original = self.state.getStorageOriginal(target, key);
        const current = self.state.getStorage(target, key);

        var gas_cost: u64 = 0;
        if (!self.state.accessStorage(target, key)) gas_cost += Gas.COLD_STORAGE_ACCESS;
        if (original == current and current != new_value) {
            gas_cost += if (original == 0) Gas.STORAGE_SET else (Gas.COLD_STORAGE_WRITE - Gas.COLD_STORAGE_ACCESS);
        } else {
            gas_cost += Gas.WARM_ACCESS;
        }

        if (current != new_value) {
            if (original != 0 and current != 0 and new_value == 0) self.refund_counter += Gas.REFUND_STORAGE_CLEAR;
            if (original != 0 and current == 0) self.refund_counter -= Gas.REFUND_STORAGE_CLEAR;
            if (original == new_value) {
                self.refund_counter += if (original == 0)
                    @as(i64, Gas.STORAGE_SET - Gas.WARM_ACCESS)
                else
                    @as(i64, Gas.COLD_STORAGE_WRITE - Gas.COLD_STORAGE_ACCESS - Gas.WARM_ACCESS);
            }
        }

        try self.chargeGas(gas_cost);
        if (self.is_static) return error.StaticStateChange;
        self.state.setStorage(target, key, new_value) catch @panic("out of memory");
        self.pc += 1;
    }

    fn tload(self: *Evm) VmError!void {
        const key = try self.stack.pop();
        try self.chargeGas(Gas.WARM_ACCESS);
        try self.stack.push(self.state.getTransient(self.message.current_target, key));
        self.pc += 1;
    }

    fn tstore(self: *Evm) VmError!void {
        const key = try self.stack.pop();
        const new_value = try self.stack.pop();
        try self.chargeGas(Gas.WARM_ACCESS);
        if (self.is_static) return error.StaticStateChange;
        self.state.setTransient(self.message.current_target, key, new_value) catch @panic("out of memory");
        self.pc += 1;
    }

    fn mcopy(self: *Evm) VmError!void {
        const dest = try self.stack.pop();
        const src = try self.stack.pop();
        const size = try self.stack.pop();
        const ext = try self.extendMemory(&.{ .{ dest, size }, .{ src, size } });
        const words = numWords(size);
        try self.chargeGasWide(Gas.VERY_LOW + Gas.COPY_PER_WORD * words + ext.cost);
        try self.growMemory(ext.expand_by);
        const n: usize = @intCast(size);
        if (n > 0) {
            const tmp = self.allocator.dupe(u8, self.memory.data[@intCast(src) .. @as(usize, @intCast(src)) + n]) catch @panic("out of memory");
            defer self.allocator.free(tmp);
            @memcpy(self.memory.data[@intCast(dest) .. @as(usize, @intCast(dest)) + n], tmp);
        }
        self.pc += 1;
    }

    // --- Logging ---

    fn logN(self: *Evm, num_topics: u8) VmError!void {
        const mem_start = try self.stack.pop();
        const size = try self.stack.pop();
        var topics = self.allocator.alloc([32]u8, num_topics) catch @panic("out of memory");
        errdefer self.allocator.free(topics);
        var i: usize = 0;
        while (i < num_topics) : (i += 1) topics[i] = word.toBeBytes32(try self.stack.pop());

        const ext = try self.extendMemory(&.{.{ mem_start, size }});
        try self.chargeGasWide(Gas.LOG_BASE +
            Gas.LOG_DATA_PER_BYTE * @as(u128, @intCast(size)) +
            Gas.LOG_TOPIC * @as(u64, num_topics) + ext.cost);
        try self.growMemory(ext.expand_by);
        if (self.is_static) {
            self.allocator.free(topics);
            return error.StaticStateChange; // LOG mutates state (EIP-214)
        }

        const data = self.allocator.dupe(u8, self.memRead(mem_start, size)) catch @panic("out of memory");
        self.logs.append(self.allocator, .{
            .address = self.message.current_target,
            .topics = topics,
            .data = data,
        }) catch @panic("out of memory");
        self.pc += 1;
    }

    // --- Control flow ---

    fn jump(self: *Evm) VmError!void {
        const dest = try self.stack.pop();
        try self.chargeGas(Gas.MID);
        if (!self.isValidJumpDest(dest)) return error.InvalidJumpDest;
        self.pc = @intCast(dest);
    }

    fn jumpi(self: *Evm) VmError!void {
        const dest = try self.stack.pop();
        const cond = try self.stack.pop();
        try self.chargeGas(Gas.HIGH);
        if (cond == 0) {
            self.pc += 1;
        } else if (!self.isValidJumpDest(dest)) {
            return error.InvalidJumpDest;
        } else {
            self.pc = @intCast(dest);
        }
    }

    fn isValidJumpDest(self: *const Evm, dest: u256) bool {
        if (dest >= self.valid_jump_destinations.len) return false;
        return self.valid_jump_destinations[@intCast(dest)];
    }

    fn ret(self: *Evm) VmError!void {
        const start = try self.stack.pop();
        const size = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ start, size }});
        try self.chargeGasWide(ext.cost);
        try self.growMemory(ext.expand_by);
        self.output = self.memRead(start, size);
        self.running = false;
    }

    fn keccak(self: *Evm) VmError!void {
        const start = try self.stack.pop();
        const size = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ start, size }});
        const words = numWords(size);
        try self.chargeGasWide(Gas.KECCAK_BASE + Gas.KECCAK_PER_WORD * words + ext.cost);
        try self.growMemory(ext.expand_by);
        const hash = crypto.keccak256(self.memRead(start, size));
        try self.stack.push(word.fromBeBytes(&hash));
        self.pc += 1;
    }

    // --- System opcodes: CREATE / CALL / SELFDESTRUCT ---

    fn create(self: *Evm) VmError!void {
        const endowment = try self.stack.pop();
        const mem_start = try self.stack.pop();
        const mem_size = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ mem_start, mem_size }});
        const word_count = numWords(mem_size);
        // EIP-3860 (Shanghai+): init-code word cost + size limit.
        const eip3860 = self.env.fork.atLeast(.shanghai);
        const init_cost: u64 = if (eip3860) Gas.CODE_INIT_PER_WORD * word_count else 0;
        try self.chargeGasWide(Gas.CREATE_BASE + init_cost + ext.cost);
        try self.growMemory(ext.expand_by);
        if (eip3860 and mem_size > MAX_INIT_CODE_SIZE) return error.OutOfGas;
        if (self.is_static) return error.StaticStateChange;

        // EIP-150 (Tangerine): forward all-but-1/64th; before that, all of it.
        const create_gas = if (self.env.fork.atLeast(.tangerine_whistle)) self.gas_left - self.gas_left / 64 else self.gas_left;
        self.gas_left -= create_gas;

        const sender = self.message.current_target;
        const init_code = self.memRead(mem_start, mem_size);
        const contract = state_mod.computeContractAddress(self.allocator, sender, self.state.nonceOf(sender)) catch @panic("out of memory");

        try self.runCreate(sender, contract, endowment, create_gas, init_code, "CREATE");
        self.pc += 1;
    }

    fn create2(self: *Evm) VmError!void {
        const endowment = try self.stack.pop();
        const mem_start = try self.stack.pop();
        const mem_size = try self.stack.pop();
        const salt = word.toBeBytes32(try self.stack.pop());
        const ext = try self.extendMemory(&.{.{ mem_start, mem_size }});
        const words = numWords(mem_size);
        // CREATE2 always pays to hash the init code (KECCAK per-word, since
        // Constantinople); EIP-3860 (Shanghai+) adds the init-code word cost + limit.
        const eip3860 = self.env.fork.atLeast(.shanghai);
        const init_cost: u64 = if (eip3860) Gas.CODE_INIT_PER_WORD * words else 0;
        try self.chargeGasWide(Gas.CREATE_BASE + Gas.KECCAK_PER_WORD * words + init_cost + ext.cost);
        try self.growMemory(ext.expand_by);
        if (eip3860 and mem_size > MAX_INIT_CODE_SIZE) return error.OutOfGas;
        if (self.is_static) return error.StaticStateChange;

        const create_gas = if (self.env.fork.atLeast(.tangerine_whistle)) self.gas_left - self.gas_left / 64 else self.gas_left; // EIP-150
        self.gas_left -= create_gas;

        const sender = self.message.current_target;
        const init_code = self.memRead(mem_start, mem_size);
        const contract = computeCreate2Address(sender, &salt, init_code);

        try self.runCreate(sender, contract, endowment, create_gas, init_code, "CREATE2");
        self.pc += 1;
    }

    /// Shared CREATE/CREATE2 body: collision checks, child execution, result.
    fn runCreate(self: *Evm, sender: Address, contract: Address, endowment: u256, create_gas: u64, init_code: []const u8, trace_type: []const u8) VmError!void {
        const sender_balance = self.state.balanceOf(sender);
        const sender_nonce = self.state.nonceOf(sender);
        _ = self.state.accessAddress(contract); // warm the new address (EIP-2929)

        if (sender_balance < endowment or sender_nonce == std.math.maxInt(u64) or self.message.depth + 1 > STACK_DEPTH_LIMIT) {
            self.setReturnData(&.{});
            try self.stack.push(0);
            self.gas_left += create_gas;
            return;
        }
        if (self.state.hasCodeOrNonce(contract) or self.state.hasStorage(contract)) {
            self.state.incrementNonce(sender) catch @panic("out of memory");
            self.setReturnData(&.{}); // an address collision exposes no return data
            try self.stack.push(0);
            return;
        }
        self.state.incrementNonce(sender) catch @panic("out of memory");

        var child = processCreateMessage(self.allocator, self.state, self.env, .{
            .caller = sender,
            .current_target = contract,
            .code_address = null,
            .gas = create_gas,
            .value = endowment,
            .data = &.{},
            .code = init_code,
            .depth = self.message.depth + 1,
            .trace_type = trace_type,
        }, self);
        defer child.deinit();

        if (child.halt_error != null) {
            self.gas_left += child.gas_left;
            self.setReturnData(&.{});
            try self.stack.push(0);
        } else if (child.reverted) {
            self.gas_left += child.gas_left;
            self.setReturnData(child.output);
            try self.stack.push(0);
        } else {
            self.incorporateSuccess(&child);
            self.setReturnData(&.{}); // a successful create exposes no return data
            try self.stack.push(state_mod.addressToWord(contract));
        }
    }

    const CallKind = enum { call, callcode, delegatecall, staticcall };

    /// An account is "alive" (not subject to the NEW_ACCOUNT surcharge) when it
    /// exists and is non-empty (EIP-161).
    fn accountAlive(self: *const Evm, addr: Address) bool {
        if (!self.state.exists(addr)) return false;
        return !(self.state.nonceOf(addr) == 0 and self.state.balanceOf(addr) == 0 and self.state.codeOf(addr).len == 0);
    }

    fn callOp(self: *Evm, kind: CallKind) VmError!void {
        const gas_req = try self.stack.pop();
        const code_address = state_mod.addressFromWord(try self.stack.pop());
        const value: u256 = switch (kind) {
            .call, .callcode => try self.stack.pop(),
            .delegatecall => self.message.value, // inherited, not transferred
            .staticcall => 0,
        };
        const in_start = try self.stack.pop();
        const in_size = try self.stack.pop();
        const out_start = try self.stack.pop();
        const out_size = try self.stack.pop();

        const to: Address = switch (kind) {
            .call, .staticcall => code_address,
            .callcode, .delegatecall => self.message.current_target,
        };
        const transfers_value = (kind == .call or kind == .callcode) and value != 0;

        const ext = try self.extendMemory(&.{ .{ in_start, in_size }, .{ out_start, out_size } });
        const access_gas: u64 = self.accountAccessCost(code_address, .call);
        // EIP-7702: if the target is a delegated EOA, pay an extra cold/warm
        // charge to access the delegate. `genericCall` runs the delegate's code
        // (keeping code_address = the target, which also disables precompiles).
        var deleg_gas: u64 = 0;
        if (self.env.fork.atLeast(.prague)) {
            const tcode = self.state.codeOf(code_address);
            if (tcode.len == 23 and tcode[0] == 0xef and tcode[1] == 0x01 and tcode[2] == 0x00) {
                var del: Address = undefined;
                @memcpy(&del, tcode[3..23]);
                deleg_gas = if (self.state.accessAddress(del)) Gas.WARM_ACCESS else Gas.COLD_ACCOUNT_ACCESS;
            }
        }
        const create_gas: u64 = if (kind == .call and value != 0 and !self.accountAlive(to)) Gas.NEW_ACCOUNT else 0;
        const transfer_gas: u64 = if (transfers_value) Gas.CALL_VALUE else 0;
        const extra_gas: u64 = access_gas + deleg_gas + create_gas + transfer_gas;

        const mcg = messageCallGas(transfers_value, gas_req, self.gas_left, ext.cost, extra_gas, self.env.fork.atLeast(.tangerine_whistle));
        try self.chargeGasWide(mcg.cost + ext.cost);
        try self.growMemory(ext.expand_by);

        // Only CALL (which can transfer value to *another* account) is barred in
        // a static context. CALLCODE sends value to self, so it is permitted.
        if (self.is_static and kind == .call and value != 0) return error.StaticStateChange;

        if (transfers_value and self.state.balanceOf(self.message.current_target) < value) {
            // Insufficient balance: the call fails immediately, gas refunded.
            self.setReturnData(&.{});
            try self.stack.push(0);
            self.gas_left += mcg.sub_call;
        } else {
            try self.genericCall(.{
                .gas = mcg.sub_call,
                .value = value,
                .caller = if (kind == .delegatecall) self.message.caller else self.message.current_target,
                .to = to,
                .code_address = code_address,
                .should_transfer_value = transfers_value,
                .is_static = self.is_static or kind == .staticcall,
                .in_start = in_start,
                .in_size = in_size,
                .out_start = out_start,
                .out_size = @intCast(out_size),
                .trace_type = switch (kind) {
                    .call => "CALL",
                    .callcode => "CALLCODE",
                    .delegatecall => "DELEGATECALL",
                    .staticcall => "STATICCALL",
                },
            });
        }
        self.pc += 1;
    }

    const GenericCall = struct {
        gas: u64,
        value: u256,
        caller: Address,
        to: Address,
        code_address: Address,
        should_transfer_value: bool,
        is_static: bool,
        in_start: u256,
        in_size: u256,
        out_start: u256,
        out_size: usize,
        trace_type: []const u8 = "CALL",
    };

    /// Replace `return_data` with an owned copy of `bytes`.
    fn setReturnData(self: *Evm, bytes: []const u8) void {
        if (self.return_data.len > 0) self.allocator.free(self.return_data);
        self.return_data = if (bytes.len == 0) &.{} else (self.allocator.dupe(u8, bytes) catch @panic("out of memory"));
    }

    fn genericCall(self: *Evm, p: GenericCall) VmError!void {
        if (self.message.depth + 1 > STACK_DEPTH_LIMIT) {
            self.gas_left += p.gas;
            self.setReturnData(&.{});
            try self.stack.push(0);
            return;
        }
        const call_data = self.memRead(p.in_start, p.in_size);
        // EIP-7702: follow a delegation indicator — execute the delegate's code
        // in the target's context. `code_address` stays the target so precompile
        // dispatch is suppressed (a delegation to a precompile runs nothing).
        var code = self.state.codeOf(p.code_address);
        if (self.env.fork.atLeast(.prague) and code.len == 23 and code[0] == 0xef and code[1] == 0x01 and code[2] == 0x00) {
            var del: Address = undefined;
            @memcpy(&del, code[3..23]);
            code = self.state.codeOf(del);
        }

        var child = processMessage(self.allocator, self.state, self.env, .{
            .caller = p.caller,
            .current_target = p.to,
            .code_address = p.code_address,
            .gas = p.gas,
            .value = p.value,
            .data = call_data,
            .code = code,
            .depth = self.message.depth + 1,
            .is_static = p.is_static,
            .should_transfer_value = p.should_transfer_value,
            .trace_type = p.trace_type,
        }, self);
        defer child.deinit();

        if (child.halt_error != null) {
            self.gas_left += child.gas_left;
            try self.stack.push(0);
        } else if (child.reverted) {
            self.gas_left += child.gas_left;
            try self.stack.push(0);
        } else {
            self.incorporateSuccess(&child);
            try self.stack.push(1);
        }

        // Returned data is available even on revert; copy into the output region.
        self.setReturnData(child.output);
        const n = @min(p.out_size, child.output.len);
        if (n > 0) self.memory.write(@intCast(p.out_start), child.output[0..n]);
    }

    fn revert(self: *Evm) VmError!void {
        const start = try self.stack.pop();
        const size = try self.stack.pop();
        const ext = try self.extendMemory(&.{.{ start, size }});
        try self.chargeGasWide(ext.cost);
        try self.growMemory(ext.expand_by);
        self.output = self.memRead(start, size);
        self.running = false;
        self.reverted = true; // reverts state but keeps remaining gas
    }

    /// Pull a successful child's gas, refunds, logs, and pending deletions into
    /// this frame (`incorporate_child_on_success`).
    fn incorporateSuccess(self: *Evm, child: *Evm) void {
        self.gas_left += child.gas_left;
        self.refund_counter += child.refund_counter;
        self.logs.appendSlice(self.allocator, child.logs.items) catch @panic("out of memory");
        child.logs.clearRetainingCapacity(); // ownership transferred to parent
        var it = child.accounts_to_delete.keyIterator();
        while (it.next()) |k| self.accounts_to_delete.put(self.allocator, k.*, {}) catch @panic("out of memory");
    }

    fn isScheduledForDeletion(self: *const Evm, addr: Address) bool {
        var cur: ?*const Evm = self;
        while (cur) |e| : (cur = e.parent) {
            if (e.accounts_to_delete.contains(addr)) return true;
        }
        return false;
    }

    fn selfdestruct(self: *Evm) VmError!void {
        const beneficiary = state_mod.addressFromWord(try self.stack.pop());
        const originator = self.message.current_target;
        const orig_balance = self.state.balanceOf(originator);

        // Prague gas: base + cold-access of beneficiary + new-account surcharge
        // when sending balance to a dead account. No refund (EIP-3529).
        var gas: u64 = Gas.SELFDESTRUCT_BASE;
        if (!self.state.accessAddress(beneficiary)) gas += Gas.COLD_ACCOUNT_ACCESS;
        if (orig_balance != 0 and !self.accountAlive(beneficiary)) gas += Gas.SELFDESTRUCT_NEW_ACCOUNT;
        try self.chargeGas(gas);
        if (self.is_static) return error.StaticStateChange;

        // Always move the balance to the beneficiary (a no-op self-transfer when
        // beneficiary == originator).
        if (!std.mem.eql(u8, &beneficiary, &originator)) {
            const ben_balance = self.state.balanceOf(beneficiary);
            self.state.setBalance(beneficiary, ben_balance + orig_balance) catch @panic("out of memory");
            self.state.setBalance(originator, 0) catch @panic("out of memory");
        }

        // EIP-6780 (Cancun+): only delete the account (and burn its balance) if it
        // was created in this same transaction. Pre-Cancun, SELFDESTRUCT always
        // deletes.
        if (!self.env.fork.atLeast(.cancun) or self.state.wasCreatedThisTx(originator)) {
            self.state.setBalance(originator, 0) catch @panic("out of memory");
            self.accounts_to_delete.put(self.allocator, originator, {}) catch @panic("out of memory");
        }
        self.running = false;
    }
};

// --- Message-call drivers (free functions to allow recursion) ---

/// Build a fresh execution frame for `message`.
fn newFrame(
    allocator: std.mem.Allocator,
    state: *State,
    env: *const Environment,
    message: Message,
    gas: u64,
    parent: ?*Evm,
) Evm {
    const jumpdests = analyzeJumpDests(allocator, message.code) catch @panic("out of memory");
    // Own a copy of the code: a nested call that reverts will free the account
    // code in `state`, which this frame would otherwise still be executing.
    const owned_code = allocator.dupe(u8, message.code) catch @panic("out of memory");
    const stack_buf = allocator.alloc(u256, STACK_LIMIT) catch @panic("out of memory");
    return .{
        .stack = .{ .items = stack_buf },
        .memory = Memory.init(allocator),
        .code = owned_code,
        .owned_code = owned_code,
        .gas_left = gas,
        .valid_jump_destinations = jumpdests,
        .is_static = message.is_static,
        .message = message,
        .env = env,
        .state = state,
        .parent = parent,
        .allocator = allocator,
    };
}

/// Move ether (if any), execute the code, and revert state on an exceptional
/// halt. Mirrors `process_message`.
pub fn processMessage(
    allocator: std.mem.Allocator,
    state: *State,
    env: *const Environment,
    message: Message,
    parent: ?*Evm,
) Evm {
    var frame = newFrame(allocator, state, env, message, message.gas, parent);
    if (message.depth > STACK_DEPTH_LIMIT) {
        frame.halt_error = error.StackOverflow;
        frame.gas_left = 0;
        return frame;
    }
    if (call_tracer) |t| t.enter(message.trace_type, message.caller, message.current_target, message.value, message.gas, message.data);
    defer if (call_tracer) |t| t.exit(message.gas - frame.gas_left, frame.output, frameError(&frame));

    var snapshot = state.clone() catch @panic("out of memory");
    state.touch(message.current_target) catch @panic("out of memory");
    if (message.value != 0 and message.should_transfer_value) {
        state.moveEther(message.caller, message.current_target, message.value) catch @panic("out of memory");
    }

    // Precompiled contracts (0x01–0x0a) run natively instead of the bytecode.
    if (message.code_address) |ca| {
        if (precompiles.idOf(ca, env.fork)) |id| {
            if (precompiles.run(allocator, id, message.data, frame.gas_left)) |res| {
                frame.gas_left -= res.gas;
                frame.output = res.data;
                frame.owned_output = res.data;
            } else {
                frame.gas_left = 0;
                frame.halt_error = error.OutOfGas; // precompile failure consumes gas
            }
            frame.running = false;
        } else frame.run();
    } else frame.run();

    if (frame.halt_error != null or frame.reverted) {
        state.restoreFrom(&snapshot);
    } else {
        snapshot.deinit();
    }
    return frame;
}

/// Execute contract creation: run the init code, then charge for and install
/// the returned runtime code. Mirrors `process_create_message`.
///
/// Note: the spec's rare `destroy_storage`-on-collision path is omitted; the
/// collision is instead rejected up front in the CREATE opcode.
pub fn processCreateMessage(
    allocator: std.mem.Allocator,
    state: *State,
    env: *const Environment,
    message: Message,
    parent: ?*Evm,
) Evm {
    // EIP-684 address collision: if the target already holds code, a non-zero
    // nonce, or storage, creation aborts and consumes all gas. (The CREATE/
    // CREATE2 opcode path pre-checks this; this guards the transaction-level
    // create that calls in directly.)
    if (state.hasCodeOrNonce(message.current_target) or state.hasStorage(message.current_target)) {
        var frame = newFrame(allocator, state, env, message, 0, parent);
        frame.halt_error = error.AddressCollision;
        frame.running = false;
        return frame;
    }

    // Snapshot so the nonce bump (and all creation effects) revert on failure.
    var snapshot = state.clone() catch @panic("out of memory");
    // EIP-6780: record the address as created this tx (shared, not rolled back)
    // so SELFDESTRUCT may delete it; also a newly created contract starts at
    // nonce 1 (EIP-161, Spurious Dragon) — before that it starts at nonce 0.
    state.markAccountCreated(message.current_target);
    if (env.fork.atLeast(.spurious_dragon))
        state.incrementNonce(message.current_target) catch @panic("out of memory");

    var frame = processMessage(allocator, state, env, message, parent);

    if (frame.halt_error != null or frame.reverted) {
        state.restoreFrom(&snapshot);
        return frame;
    }

    // Validate + charge the runtime-code deposit (EIP-170 size, EIP-3541 0xEF).
    const runtime_code = frame.output;
    const deposit: u128 = @as(u128, runtime_code.len) * Gas.CODE_DEPOSIT_PER_BYTE;
    const invalid = runtime_code.len > 24576 or (runtime_code.len > 0 and runtime_code[0] == 0xEF);
    if (invalid or deposit > frame.gas_left) {
        frame.gas_left = 0;
        frame.halt_error = error.OutOfGas;
        state.restoreFrom(&snapshot);
    } else {
        frame.gas_left -= @intCast(deposit);
        state.setCode(message.current_target, runtime_code) catch @panic("out of memory");
        snapshot.deinit();
    }
    return frame;
}

/// Gas for a CALL: base + forwarded gas + new-account + value-transfer costs,
/// plus the stipend handed to the sub-call. Mirrors `calculate_message_call_gas`.
/// `calculate_message_call_gas`: apply the EIP-150 63/64 rule and the value
/// stipend. `extra_gas` already covers access-list + new-account + transfer.
const MessageCallGas = struct { cost: u128, sub_call: u64 };

fn messageCallGas(transfers_value: bool, gas_req: u256, gas_left: u64, memory_cost: u128, extra_gas: u64, cap_6364: bool) MessageCallGas {
    // The 2300-gas stipend is only granted when value is actually transferred
    // (CALL/CALLCODE with value>0). DELEGATECALL inherits `message.value` but
    // never transfers it, so it must NOT receive the stipend.
    const stipend: u64 = if (transfers_value) Gas.CALL_STIPEND else 0;
    const req: u128 = @intCast(@min(gas_req, @as(u256, std.math.maxInt(u128))));
    const reserved: u128 = @as(u128, extra_gas) + memory_cost;

    var g: u128 = req;
    if (gas_left >= reserved) {
        const avail: u64 = gas_left - @as(u64, @intCast(reserved));
        // EIP-150 (Tangerine): a caller may forward at most all-but-1/64th of
        // its remaining gas. Before Tangerine the full request could be sent.
        const capped: u128 = if (cap_6364) avail - avail / 64 else avail;
        g = @min(req, capped);
    }
    const g64: u64 = @intCast(@min(g, @as(u128, std.math.maxInt(u64) - stipend)));
    return .{ .cost = g + extra_gas, .sub_call = g64 + stipend };
}

// --- Free helpers ---

fn ltFn(x: u256, y: u256) u256 {
    return @intFromBool(x < y);
}
fn gtFn(x: u256, y: u256) u256 {
    return @intFromBool(x > y);
}
fn sltFn(x: u256, y: u256) u256 {
    return @intFromBool(word.toSigned(x) < word.toSigned(y));
}
fn sgtFn(x: u256, y: u256) u256 {
    return @intFromBool(word.toSigned(x) > word.toSigned(y));
}
fn eqFn(x: u256, y: u256) u256 {
    return @intFromBool(x == y);
}
fn isZeroFn(x: u256) u256 {
    return @intFromBool(x == 0);
}
fn andFn(x: u256, y: u256) u256 {
    return x & y;
}
fn orFn(x: u256, y: u256) u256 {
    return x | y;
}
fn xorFn(x: u256, y: u256) u256 {
    return x ^ y;
}
fn notFn(x: u256) u256 {
    return ~x;
}

fn ceil32(x: usize) usize {
    return (x + 31) & ~@as(usize, 31);
}

/// Number of 32-byte words spanned by `size` bytes (size already bounded).
fn numWords(size: u256) u64 {
    return @intCast(ceil32(@intCast(size)) / 32);
}

fn memoryCost(size_in_bytes: usize) u128 {
    const words: u128 = ceil32(size_in_bytes) / 32;
    return words * Gas.MEMORY_PER_WORD + words * words / 512;
}

/// `keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[-20:]` (EIP-1014).
fn computeCreate2Address(sender: Address, salt: *const [32]u8, init_code: []const u8) Address {
    const code_hash = crypto.keccak256(init_code);
    var buf: [85]u8 = undefined; // 1 + 20 + 32 + 32
    buf[0] = 0xff;
    @memcpy(buf[1..21], &sender);
    @memcpy(buf[21..53], salt);
    @memcpy(buf[53..85], &code_hash);
    const h = crypto.keccak256(&buf);
    var addr: Address = undefined;
    @memcpy(&addr, h[12..32]);
    return addr;
}

/// Read 32 big-endian bytes from `src` starting at `start`, zero-padded.
fn bufferReadWord(src: []const u8, start: u256) u256 {
    var v: u256 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const si: u256 = start + i;
        const b: u8 = if (si < src.len) src[@intCast(si)] else 0;
        v = (v << 8) | b;
    }
    return v;
}

/// Precompute which byte offsets are valid `JUMPDEST`s, skipping PUSH data.
fn analyzeJumpDests(allocator: std.mem.Allocator, code: []const u8) ![]bool {
    const dests = try allocator.alloc(bool, code.len);
    @memset(dests, false);
    var pc: usize = 0;
    while (pc < code.len) : (pc += 1) {
        const b = code[pc];
        if (b == @intFromEnum(Op.JUMPDEST)) {
            dests[pc] = true;
        } else if (b >= PUSH1_BYTE and b <= PUSH32_BYTE) {
            pc += b - PUSH1_BYTE + 1;
        }
    }
    return dests;
}

// --- Tests ---

const testing = std.testing;

fn runCode(code: []const u8, gas: u64) !Evm {
    var evm = try Evm.init(testing.allocator, code, gas);
    evm.run();
    return evm;
}

test "PUSH1 + PUSH1 + ADD" {
    const code = [_]u8{ 0x60, 0x06, 0x60, 0x07, 0x01, 0x00 };
    var evm = try runCode(&code, 100);
    defer evm.deinit();
    try testing.expectEqual(@as(?VmError, null), evm.halt_error);
    try testing.expectEqual(@as(u256, 13), try evm.stack.peek(0));
    try testing.expectEqual(@as(u64, 91), evm.gas_left);
}

test "MUL then DUP1 then ADD" {
    const code = [_]u8{ 0x60, 0x03, 0x60, 0x04, 0x02, 0x80, 0x01, 0x00 };
    var evm = try runCode(&code, 100);
    defer evm.deinit();
    try testing.expectEqual(@as(u256, 24), try evm.stack.peek(0));
}

test "JUMP to JUMPDEST" {
    const code = [_]u8{ 0x60, 0x04, 0x56, 0x00, 0x5B, 0x60, 0x2A, 0x00 };
    var evm = try runCode(&code, 100);
    defer evm.deinit();
    try testing.expectEqual(@as(?VmError, null), evm.halt_error);
    try testing.expectEqual(@as(u256, 0x2A), try evm.stack.peek(0));
}

test "invalid JUMP destination halts" {
    const code = [_]u8{ 0x60, 0x03, 0x56, 0x00 };
    var evm = try runCode(&code, 100);
    defer evm.deinit();
    try testing.expectEqual(@as(?VmError, error.InvalidJumpDest), evm.halt_error);
    try testing.expectEqual(@as(u64, 0), evm.gas_left);
}

test "MSTORE then MLOAD round trips" {
    const code = [_]u8{ 0x60, 0xAB, 0x60, 0x00, 0x52, 0x60, 0x00, 0x51, 0x00 };
    var evm = try runCode(&code, 100);
    defer evm.deinit();
    try testing.expectEqual(@as(u256, 0xAB), try evm.stack.peek(0));
    try testing.expectEqual(@as(usize, 32), evm.memory.data.len);
}

test "RETURN sets output" {
    const code = [_]u8{ 0x60, 0xAB, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3 };
    var evm = try runCode(&code, 100);
    defer evm.deinit();
    try testing.expectEqual(@as(usize, 32), evm.output.len);
    try testing.expectEqual(@as(u8, 0xAB), evm.output[31]);
    try testing.expectEqual(false, evm.running);
}

test "out of gas halts and zeroes gas" {
    const code = [_]u8{ 0x60, 0x06, 0x60, 0x07, 0x01, 0x00 };
    var evm = try runCode(&code, 5);
    defer evm.deinit();
    try testing.expectEqual(@as(?VmError, error.OutOfGas), evm.halt_error);
    try testing.expectEqual(@as(u64, 0), evm.gas_left);
}

test "invalid opcode halts" {
    const code = [_]u8{0x0C};
    var evm = try runCode(&code, 100);
    defer evm.deinit();
    try testing.expectEqual(@as(?VmError, error.InvalidOpcode), evm.halt_error);
}

test "KECCAK of 32 zero bytes" {
    // PUSH1 0, PUSH1 0, MSTORE (zero word at 0); PUSH1 32, PUSH1 0, KECCAK
    const code = [_]u8{ 0x60, 0x00, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0x20, 0x00 };
    var evm = try runCode(&code, 1000);
    defer evm.deinit();
    const zeros = std.mem.zeroes([32]u8);
    const expected = word.fromBeBytes(&crypto.keccak256(&zeros));
    try testing.expectEqual(expected, try evm.stack.peek(0));
}

test "SSTORE then SLOAD round trips through state" {
    // PUSH1 0x2A PUSH1 0x01 SSTORE  PUSH1 0x01 SLOAD  STOP
    const code = [_]u8{ 0x60, 0x2A, 0x60, 0x01, 0x55, 0x60, 0x01, 0x54, 0x00 };
    var evm = try runCode(&code, 50000);
    defer evm.deinit();
    try testing.expectEqual(@as(?VmError, null), evm.halt_error);
    try testing.expectEqual(@as(u256, 0x2A), try evm.stack.peek(0));
}

test "CALLDATALOAD reads from message data" {
    var st = State.init(testing.allocator);
    defer st.deinit();
    var env = Environment{};
    // PUSH1 0 CALLDATALOAD STOP
    const code = [_]u8{ 0x60, 0x00, 0x35, 0x00 };
    var data = std.mem.zeroes([32]u8);
    data[0] = 0xAA;
    var evm = processMessage(testing.allocator, &st, &env, .{
        .code = &code,
        .data = &data,
        .gas = 1000,
        .current_target = state_mod.zero_address,
    }, null);
    defer evm.deinit();
    try testing.expectEqual(@as(?VmError, null), evm.halt_error);
    try testing.expectEqual(bufferReadWord(&data, 0), try evm.stack.peek(0));
}

test "LOG1 records an entry" {
    // PUSH1 0xAB PUSH1 0 MSTORE  PUSH1 0xCC(topic) PUSH1 32(size) PUSH1 0(off) LOG1  STOP
    const code = [_]u8{ 0x60, 0xAB, 0x60, 0x00, 0x52, 0x60, 0xCC, 0x60, 0x20, 0x60, 0x00, 0xA1, 0x00 };
    var evm = try runCode(&code, 100000);
    defer evm.deinit();
    try testing.expectEqual(@as(?VmError, null), evm.halt_error);
    try testing.expectEqual(@as(usize, 1), evm.logs.items.len);
    try testing.expectEqual(@as(usize, 1), evm.logs.items[0].topics.len);
    try testing.expectEqual(@as(usize, 32), evm.logs.items[0].data.len);
}

test "CALL into a contract that returns a word" {
    var st = State.init(testing.allocator);
    defer st.deinit();
    var env = Environment{};

    // Callee: PUSH1 0x42 PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
    const callee_code = [_]u8{ 0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3 };
    var callee = state_mod.zero_address;
    callee[19] = 0xCA;
    try st.setCode(callee, &callee_code);

    // Caller: CALL(gas=0xFFFF, to=callee, value=0, in=0,0, out=0,32) then MLOAD 0
    // Stack pushes are reverse order; build with PUSHes.
    const caller_code = [_]u8{
        0x60, 0x20, // out_size 32
        0x60, 0x00, // out_start 0
        0x60, 0x00, // in_size 0
        0x60, 0x00, // in_start 0
        0x60, 0x00, // value 0
        0x73, // PUSH20 callee address
    } ++ callee ++ [_]u8{
        0x62, 0x00, 0xFF, 0xFF, // PUSH3 gas 0xFFFF
        0xF1, // CALL
        0x50, // POP success flag
        0x60, 0x00, 0x51, // PUSH1 0 MLOAD
        0x00, // STOP
    };

    var caller = state_mod.zero_address;
    caller[19] = 0xCB;
    var evm = processMessage(testing.allocator, &st, &env, .{
        .caller = state_mod.zero_address,
        .current_target = caller,
        .code = &caller_code,
        .gas = 1_000_000,
    }, null);
    defer evm.deinit();

    try testing.expectEqual(@as(?VmError, null), evm.halt_error);
    try testing.expectEqual(@as(u256, 0x42), try evm.stack.peek(0));
}

test "CREATE deploys a contract and returns its address" {
    var st = State.init(testing.allocator);
    defer st.deinit();
    var env = Environment{};

    var creator = state_mod.zero_address;
    creator[19] = 0x01;
    try st.setBalance(creator, 0);

    // Init code that returns a 1-byte runtime program (0x00 = STOP):
    //   PUSH1 0x00 PUSH1 0x00 MSTORE8   ; store byte 0x00 at mem[0]
    //   PUSH1 0x01 PUSH1 0x00 RETURN    ; return 1 byte
    const init_code = [_]u8{ 0x60, 0x00, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xF3 };

    // Creator: store init code into memory, then CREATE(value=0, off=0, size=len)
    // Build memory by MSTORE of the init code as a single word is awkward; instead
    // use CODECOPY to copy our own code is also awkward. Simplest: push each byte.
    var prog = std.ArrayList(u8).empty;
    defer prog.deinit(testing.allocator);
    // Write init_code bytes into memory one MSTORE8 at a time.
    for (init_code, 0..) |b, i| {
        try prog.append(testing.allocator, 0x60); // PUSH1 value
        try prog.append(testing.allocator, b);
        try prog.append(testing.allocator, 0x60); // PUSH1 offset
        try prog.append(testing.allocator, @intCast(i));
        try prog.append(testing.allocator, 0x53); // MSTORE8
    }
    // CREATE(value=0, offset=0, size=init_code.len)
    try prog.append(testing.allocator, 0x60); // size
    try prog.append(testing.allocator, init_code.len);
    try prog.append(testing.allocator, 0x60); // offset 0
    try prog.append(testing.allocator, 0x00);
    try prog.append(testing.allocator, 0x60); // value 0
    try prog.append(testing.allocator, 0x00);
    try prog.append(testing.allocator, 0xF0); // CREATE
    try prog.append(testing.allocator, 0x00); // STOP

    var evm = processMessage(testing.allocator, &st, &env, .{
        .caller = state_mod.zero_address,
        .current_target = creator,
        .code = prog.items,
        .gas = 5_000_000,
    }, null);
    defer evm.deinit();

    try testing.expectEqual(@as(?VmError, null), evm.halt_error);
    const expected_addr = try state_mod.computeContractAddress(testing.allocator, creator, 0);
    try testing.expectEqual(state_mod.addressToWord(expected_addr), try evm.stack.peek(0));
    // The deployed account should now have the 1-byte runtime code.
    try testing.expectEqual(@as(usize, 1), st.codeOf(expected_addr).len);
}
