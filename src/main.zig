//! Tiny CLI: execute a hex string of EVM bytecode and print the result.
//!
//!   zig build run -- 6006600701    # PUSH1 6, PUSH1 7, ADD

const std = @import("std");
const zeth = @import("zeth");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        std.debug.print("usage: {s} <hex-bytecode> [gas]\n", .{args[0]});
        return error.MissingArgument;
    }

    var hex: []const u8 = args[1];
    if (std.mem.startsWith(u8, hex, "0x")) hex = hex[2..];
    const code = try gpa.alloc(u8, hex.len / 2);
    defer gpa.free(code);
    _ = try std.fmt.hexToBytes(code, hex);

    const gas: u64 = if (args.len >= 3)
        try std.fmt.parseInt(u64, args[2], 10)
    else
        1_000_000;

    var evm = try zeth.Evm.init(gpa, code, gas);
    defer evm.deinit();

    evm.run();

    if (evm.halt_error) |e| {
        std.debug.print("halted: {s}\n", .{@errorName(e)});
    }
    std.debug.print("gas used: {d}\n", .{gas - evm.gas_left});
    std.debug.print("stack ({d}):\n", .{evm.stack.len});
    var i: usize = 0;
    while (i < evm.stack.len) : (i += 1) {
        std.debug.print("  [{d}] 0x{x}\n", .{ i, evm.stack.items[evm.stack.len - 1 - i] });
    }
    if (evm.output.len > 0) {
        std.debug.print("return: 0x{x}\n", .{evm.output});
    }
}
