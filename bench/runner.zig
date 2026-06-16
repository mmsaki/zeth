//! Machine-readable single-program runner used by the cross-client benchmark
//! (`scripts/cross_bench.py`). It exposes a fixed corpus of feature-spanning
//! EVM programs and can either list them as hex or time one by hex.
//!
//!   zeth-run --list           -> lines of "<name> <hex>"
//!   zeth-run --bench <hex>    -> "gas <n> ns <min_ns>"
//!
//! Every program is a loop whose body is stack-neutral and uses only opcodes
//! whose gas has never been repriced across forks — so geth (run at its latest
//! fork) reports the *same* gas, making gas-equality a correctness oracle.

const std = @import("std");
const zeth = @import("zeth");

const Clock = std.Io.Clock;
const COUNT: u24 = 250_000;
const SAMPLES = 25;
const WARMUP = 3;

const Workload = struct { name: []const u8, body: []const u8 };

// Each body must leave the loop counter on top of the stack.
const workloads = [_]Workload{
    // DUP1 DUP1 MUL PUSH1 7 ADD POP
    .{ .name = "arithmetic", .body = &.{ 0x80, 0x80, 0x02, 0x60, 0x07, 0x01, 0x50 } },
    // DUP1 DUP1 AND DUP1 OR DUP1 XOR NOT PUSH1 31 BYTE POP
    .{ .name = "bitwise", .body = &.{ 0x80, 0x80, 0x16, 0x80, 0x17, 0x80, 0x18, 0x19, 0x60, 0x1F, 0x1A, 0x50 } },
    // DUP1 DUP1 LT DUP1 DUP1 GT EQ ISZERO POP
    .{ .name = "comparison", .body = &.{ 0x80, 0x80, 0x10, 0x80, 0x80, 0x11, 0x14, 0x15, 0x50 } },
    // PUSH1 32 PUSH1 0 KECCAK POP
    .{ .name = "keccak256", .body = &.{ 0x60, 0x20, 0x60, 0x00, 0x20, 0x50 } },
    // PUSH1 0 MLOAD PUSH1 0 MSTORE MSIZE POP
    .{ .name = "memory", .body = &.{ 0x60, 0x00, 0x51, 0x60, 0x00, 0x52, 0x59, 0x50 } },
    // PUSH1 1 PUSH1 2 DUP2 SWAP1 POP POP POP
    .{ .name = "stack", .body = &.{ 0x60, 0x01, 0x60, 0x02, 0x81, 0x90, 0x50, 0x50, 0x50 } },
    // PC POP GAS POP
    .{ .name = "control", .body = &.{ 0x58, 0x50, 0x5A, 0x50 } },
    // DUP1 PUSH1 1 SHL PUSH1 1 SHR PUSH1 1 SAR POP  (EIP-145 shifts)
    .{ .name = "shifts", .body = &.{ 0x80, 0x60, 0x01, 0x1B, 0x60, 0x01, 0x1C, 0x60, 0x01, 0x1D, 0x50 } },
    // PUSH0 POP  (EIP-3855)
    .{ .name = "push0", .body = &.{ 0x5F, 0x50 } },
    // PUSH1 32 PUSH1 0 PUSH1 0 MCOPY  (EIP-5656)
    .{ .name = "mcopy", .body = &.{ 0x60, 0x20, 0x60, 0x00, 0x60, 0x00, 0x5E } },
    // PUSH1 0 SLOAD POP  (EIP-2929 cold then warm)
    .{ .name = "sload", .body = &.{ 0x60, 0x00, 0x54, 0x50 } },
    // PUSH1 0 PUSH1 0 SSTORE  (EIP-2200/2929/3529)
    .{ .name = "sstore", .body = &.{ 0x60, 0x00, 0x60, 0x00, 0x55 } },
};

fn buildLoop(arena: std.mem.Allocator, body: []const u8, count: u24) ![]u8 {
    var p: std.ArrayList(u8) = .empty;
    try p.appendSlice(arena, &.{
        0x62, @intCast((count >> 16) & 0xFF), @intCast((count >> 8) & 0xFF), @intCast(count & 0xFF), // PUSH3 count
        0x5B, // JUMPDEST (offset 4)
    });
    try p.appendSlice(arena, body);
    try p.appendSlice(arena, &.{ 0x60, 0x01, 0x90, 0x03, 0x80, 0x60, 0x04, 0x57 }); // PUSH1 1 SWAP1 SUB DUP1 PUSH1 4 JUMPI
    return p.items;
}

fn toHex(buf: []u8, bytes: []const u8) []const u8 {
    const hexdig = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        buf[2 * i] = hexdig[b >> 4];
        buf[2 * i + 1] = hexdig[b & 0xF];
    }
    return buf[0 .. 2 * bytes.len];
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    if (args.len >= 2 and std.mem.eql(u8, args[1], "--list")) {
        var hexbuf: [512]u8 = undefined;
        for (workloads) |wl| {
            const code = try buildLoop(arena, wl.body, COUNT);
            std.debug.print("{s} {s}\n", .{ wl.name, toHex(&hexbuf, code) });
        }
        return;
    }

    if (args.len >= 3 and std.mem.eql(u8, args[1], "--bench")) {
        const hex = args[2];
        const code = try gpa.alloc(u8, hex.len / 2);
        defer gpa.free(code);
        _ = try std.fmt.hexToBytes(code, hex);

        var gas_used: u64 = 0;
        var best_ns: u64 = std.math.maxInt(u64);

        var i: usize = 0;
        while (i < WARMUP + SAMPLES) : (i += 1) {
            const t0 = Clock.now(.awake, io);
            var evm = try zeth.Evm.init(gpa, code, std.math.maxInt(u64));
            evm.run();
            const t1 = Clock.now(.awake, io);
            gas_used = std.math.maxInt(u64) - evm.gas_left;
            evm.deinit();
            if (i >= WARMUP) {
                const ns: u64 = @intCast(t0.durationTo(t1).nanoseconds);
                best_ns = @min(best_ns, ns);
            }
        }

        std.debug.print("gas {d} ns {d}\n", .{ gas_used, best_ns });
        return;
    }

    std.debug.print("usage: zeth-run --list | --bench <hex>\n", .{});
}
