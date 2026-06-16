//! The `zeth` command-line node. Subcommands:
//!
//!   zeth version                              print the client version
//!   zeth run <hex-bytecode> [gas]             execute raw EVM bytecode (debug)
//!   zeth import <genesis.json> <chain.rlp>…   load genesis, import blocks, print head
//!   zeth node <genesis.json> [chain.rlp…]     load + import + serve (RPC: WIP)
//!
//! `import`/`node` are the hive entry points: they load a geth-format genesis,
//! then ingest RLP block files through the real import pipeline (chain.zig).

const std = @import("std");
const zeth = @import("zeth");
const net = std.Io.net;

const VERSION = "zeth/0.1.0-dev";

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return usage(args[0]);

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "version")) {
        std.debug.print("{s}\n", .{VERSION});
    } else if (std.mem.eql(u8, cmd, "run")) {
        try runBytecode(gpa, args[2..]);
    } else if (std.mem.eql(u8, cmd, "import")) {
        try importChain(gpa, init.io, args[2..]);
    } else if (std.mem.eql(u8, cmd, "node")) {
        try nodeServe(gpa, init.io, args[2..]);
    } else {
        return usage(args[0]);
    }
}

fn usage(prog: []const u8) error{MissingArgument} {
    std.debug.print(
        \\usage: {s} <command> [args]
        \\  version                          print the client version
        \\  run <hex-bytecode> [gas]         execute raw EVM bytecode
        \\  import <genesis.json> <rlp>...   load genesis, import RLP blocks, print head
        \\  node <genesis.json> [rlp]...     load + import + serve (RPC: WIP)
        \\
    , .{prog});
    return error.MissingArgument;
}

fn readFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited);
}

/// Load a geth-format genesis, then import each RLP block file in order.
fn importChain(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("usage: zeth import <genesis.json> [chain.rlp ...]\n", .{});
        return error.MissingArgument;
    }
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // Genesis → world state + genesis header.
    const gjson = try readFile(gpa, io, args[0]);
    defer gpa.free(gjson);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, gjson, .{});
    defer parsed.deinit();
    var st = zeth.State.init(gpa);
    defer st.deinit();
    const g = try zeth.genesis.load(a, &st, parsed.value);
    var ch = try zeth.chain.Chain.initGenesis(gpa, &st, g);
    defer ch.deinit();

    const gh = try g.header.hash(gpa);
    std.debug.print("genesis: chainId={d} hash=0x{s} stateRoot=0x{s}\n", .{
        g.schedule.chain_id, std.fmt.bytesToHex(&gh, .lower), std.fmt.bytesToHex(&g.header.state_root, .lower),
    });

    // Import each RLP file (a concatenation of RLP-encoded blocks).
    var imported: usize = 0;
    for (args[1..]) |path| {
        const data = try readFile(gpa, io, path);
        defer gpa.free(data);
        var off: usize = 0;
        while (off < data.len) {
            const r = zeth.rlp.decodeItem(a, data[off..]) catch |err| {
                std.debug.print("rlp decode error in {s}: {s}\n", .{ path, @errorName(err) });
                break;
            };
            const raw = data[off .. off + r.consumed];
            off += r.consumed;
            const h = ch.importBlock(raw) catch |err| {
                std.debug.print("import failed at block {d}: {s}\n", .{ ch.head.number + 1, @errorName(err) });
                return err;
            };
            imported += 1;
            const bh = try h.hash(gpa);
            std.debug.print("  block {d}: hash=0x{s}\n", .{ h.number, std.fmt.bytesToHex(&bh, .lower) });
        }
    }

    const head_hash = try ch.head.hash(gpa);
    std.debug.print("imported {d} block(s); head: number={d} hash=0x{s} stateRoot=0x{s}\n", .{
        imported, ch.head.number, std.fmt.bytesToHex(&head_hash, .lower), std.fmt.bytesToHex(&ch.head.state_root, .lower),
    });
}

/// `zeth node <genesis.json> [chain.rlp ...] [--http.addr=HOST:PORT]` — load
/// genesis, import the RLP blocks, then serve JSON-RPC. The hive entry point.
fn nodeServe(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var host: []const u8 = "0.0.0.0";
    var port: u16 = 8545;
    var genesis_path: ?[]const u8 = null;
    var rlp_files: std.ArrayList([]const u8) = .empty;
    for (args) |arg| {
        if (std.mem.startsWith(u8, arg, "--http.addr=")) {
            const hp = arg["--http.addr=".len..];
            if (std.mem.lastIndexOfScalar(u8, hp, ':')) |ci| {
                host = hp[0..ci];
                port = std.fmt.parseInt(u16, hp[ci + 1 ..], 10) catch 8545;
            } else host = hp;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            // ignore other flags
        } else if (genesis_path == null) {
            genesis_path = arg;
        } else {
            try rlp_files.append(a, arg);
        }
    }
    const gpath = genesis_path orelse {
        std.debug.print("usage: zeth node <genesis.json> [chain.rlp ...] [--http.addr=HOST:PORT]\n", .{});
        return error.MissingArgument;
    };

    // Genesis → state + chain.
    const gjson = try readFile(gpa, io, gpath);
    defer gpa.free(gjson);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, gjson, .{});
    var st = zeth.State.init(gpa);
    defer st.deinit();
    const g = try zeth.genesis.load(a, &st, parsed.value);
    var ch = try zeth.chain.Chain.initGenesis(gpa, &st, g);
    defer ch.deinit();

    // Import any provided RLP block files.
    for (rlp_files.items) |path| {
        const data = readFile(gpa, io, path) catch |e| {
            std.debug.print("warning: cannot read {s}: {s}\n", .{ path, @errorName(e) });
            continue;
        };
        defer gpa.free(data);
        var off: usize = 0;
        while (off < data.len) {
            const r = zeth.rlp.decodeItem(a, data[off..]) catch break;
            const raw = data[off .. off + r.consumed];
            off += r.consumed;
            _ = ch.importBlock(raw) catch |e| {
                std.debug.print("import failed at block {d}: {s}\n", .{ ch.head.number + 1, @errorName(e) });
                break;
            };
        }
    }
    const hh = try ch.head.hash(gpa);
    std.debug.print("zeth node: chainId={d} head=#{d} hash=0x{s}\n", .{ ch.chain_id, ch.head.number, std.fmt.bytesToHex(&hh, .lower) });

    // Serve JSON-RPC.
    var address = try net.IpAddress.parse(host, port);
    var server = try address.listen(io, .{ .reuse_address = true });
    std.debug.print("JSON-RPC listening on {s}:{d}\n", .{ host, port });
    while (true) {
        const stream = server.accept(io) catch continue;
        serveConn(gpa, io, &ch, stream);
        stream.close(io);
    }
}

/// Serve one connection: a keep-alive loop of HTTP JSON-RPC requests.
fn serveConn(gpa: std.mem.Allocator, io: std.Io, ch: *zeth.chain.Chain, stream: net.Stream) void {
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    var http = std.http.Server.init(&sr.interface, &sw.interface);
    while (true) {
        var req = http.receiveHead() catch return;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var body_buf: [8 * 1024]u8 = undefined;
        const br = req.readerExpectNone(&body_buf);
        const body = br.allocRemaining(a, std.Io.Limit.limited(16 * 1024 * 1024)) catch "";
        const resp = if (req.head.method == .POST and body.len > 0)
            zeth.rpc.handleBody(a, ch, body)
        else
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":null}";
        req.respond(resp, .{ .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }} }) catch return;
    }
}

/// `zeth run <hex> [gas]` — execute raw EVM bytecode and dump the result.
fn runBytecode(gpa: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("usage: zeth run <hex-bytecode> [gas]\n", .{});
        return error.MissingArgument;
    }
    var hex: []const u8 = args[0];
    if (std.mem.startsWith(u8, hex, "0x")) hex = hex[2..];
    const code = try gpa.alloc(u8, hex.len / 2);
    defer gpa.free(code);
    _ = try std.fmt.hexToBytes(code, hex);

    const gas: u64 = if (args.len >= 2) try std.fmt.parseInt(u64, args[1], 10) else 1_000_000;
    var evm = try zeth.Evm.init(gpa, code, gas);
    defer evm.deinit();
    evm.run();

    if (evm.halt_error) |e| std.debug.print("halted: {s}\n", .{@errorName(e)});
    std.debug.print("gas used: {d}\n", .{gas - evm.gas_left});
    std.debug.print("stack ({d}):\n", .{evm.stack.len});
    var i: usize = 0;
    while (i < evm.stack.len) : (i += 1)
        std.debug.print("  [{d}] 0x{x}\n", .{ i, evm.stack.items[evm.stack.len - 1 - i] });

    const mem = evm.memory.data;
    std.debug.print("memory ({d} bytes):\n", .{mem.len});
    var off: usize = 0;
    while (off < mem.len) : (off += 32) {
        const end = @min(off + 32, mem.len);
        std.debug.print("  0x{x:0>4}: ", .{off});
        for (mem[off..end]) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n", .{});
    }
    if (evm.output.len > 0) std.debug.print("return: 0x{x}\n", .{evm.output});
}
