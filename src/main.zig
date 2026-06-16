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

    // Every command that touches the EVM (run/import/node) can recurse to the
    // 1024-deep call limit, which overflows the default main-thread stack. Run
    // the whole dispatch on a thread with a large stack and surface its error.
    var ctx = MainCtx{ .gpa = gpa, .io = init.io, .args = args };
    const t = try std.Thread.spawn(.{ .stack_size = zeth.vm.NATIVE_STACK_SIZE }, dispatch, .{&ctx});
    t.join();
    if (ctx.err) |e| return e;
}

const MainCtx = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    err: ?anyerror = null,
};

fn dispatch(ctx: *MainCtx) void {
    const args = ctx.args;
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "version")) {
        std.debug.print("{s}\n", .{VERSION});
    } else if (std.mem.eql(u8, cmd, "run")) {
        runBytecode(ctx.gpa, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "import")) {
        importChain(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "node")) {
        nodeServe(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "p2p")) {
        p2pConnect(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "sync")) {
        syncCmd(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else {
        ctx.err = usage(args[0]);
    }
}

/// `zeth p2p <enode> [network_id] [genesis_hash]` — dial a peer, run the RLPx
/// handshake, exchange a real eth/68 Status (genesis hash + EIP-2124 forkid),
/// then request and print the first few block headers. Validates the full
/// transport + sync handshake against a real client (e.g. a kurtosis devnet).
fn p2pConnect(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("usage: zeth p2p <enode://...> [network_id] [genesis_hash_hex]\n", .{});
        return error.MissingArgument;
    }
    const enode = try zeth.peer.parseEnode(args[0]);
    const network_id: u64 = if (args.len >= 2) (std.fmt.parseInt(u64, args[1], 10) catch 1) else 1;
    var genesis_hash = std.mem.zeroes([32]u8);
    if (args.len >= 3) {
        const hx = if (std.mem.startsWith(u8, args[2], "0x")) args[2][2..] else args[2];
        _ = std.fmt.hexToBytes(&genesis_hash, hx) catch {};
    }
    // Every fork on the devnet activates at genesis, so the forkid is just
    // CRC32(genesis) with no upcoming fork.
    const fid = zeth.forkid.compute(genesis_hash, &.{}, 0);

    const priv = zeth.ecies.randomPriv(io);
    const pub_key = try zeth.ecies.pubFromPriv(priv);
    std.debug.print("dialing {s}:{d} …\n", .{ enode.host, enode.port });
    const p = try zeth.peer.Peer.dial(gpa, io, enode, priv);
    defer p.destroy();
    std.debug.print("✓ RLPx handshake complete\n", .{});

    try p.sendHello(pub_key);
    std.debug.print("→ sent Hello (eth/69)\n", .{});

    // One scratch arena for all per-message decode/encode, reset each iteration.
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();

    var sent_status = false;
    var requested = false;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        _ = scratch.reset(.retain_capacity);
        const sa = scratch.allocator();
        const msg = p.readMessage(gpa) catch |e| {
            std.debug.print("read ended: {s}\n", .{@errorName(e)});
            break;
        };
        defer gpa.free(msg.payload);
        switch (msg.id) {
            zeth.eth_proto.p2p.hello => {
                std.debug.print("← Hello ({d} bytes) — peer speaks p2p\n", .{msg.payload.len});
                // Decode the peer's advertised capabilities.
                if (zeth.rlp.decode(sa, msg.payload)) |item| {
                    if (item.items()) |hf| {
                        if (hf.len >= 3) if (hf[2].items()) |caps| {
                            for (caps) |c| if (c.items()) |cv| {
                                if (cv.len >= 2) {
                                    const name = cv[0].bytes() catch &.{};
                                    const ver = cv[1].uint(u64) catch 0;
                                    std.debug.print("    cap: {s}/{d}\n", .{ name, ver });
                                }
                            } else |_| {};
                        } else |_| {};
                    } else |_| {}
                } else |_| {}
                if (!sent_status) {
                    const st = zeth.eth_proto.Status69{
                        .version = 69,
                        .network_id = network_id,
                        .genesis_hash = genesis_hash,
                        .fork_hash = fid.hash,
                        .fork_next = fid.next,
                        .earliest_block = 0,
                        .latest_block = 0,
                        .latest_block_hash = genesis_hash,
                    };
                    const payload = try st.encode(sa);
                    try p.writeMessage(zeth.eth_proto.eth.status, payload);
                    sent_status = true;
                    std.debug.print("→ sent Status (networkId={d} forkid=0x{s})\n", .{ network_id, std.fmt.bytesToHex(&fid.hash, .lower) });
                    // Request headers immediately (don't wait for the peer's
                    // Status) — geth may serve the request before dropping a
                    // genesis-only peer as "useless".
                    if (!requested) {
                        const req = zeth.eth_proto.GetBlockHeaders{ .request_id = 1, .origin_number = 0, .amount = 4, .skip = 0, .reverse = false };
                        const rp = try req.encode(sa);
                        try p.writeMessage(zeth.eth_proto.eth.get_block_headers, rp);
                        requested = true;
                        std.debug.print("→ GetBlockHeaders(from=0, amount=4)\n", .{});
                    }
                }
            },
            zeth.eth_proto.p2p.ping => {
                try p.writeMessage(zeth.eth_proto.p2p.pong, "\xc0"); // rlp([])
            },
            zeth.eth_proto.p2p.disconnect => {
                const reason = if (msg.payload.len > 0) msg.payload[msg.payload.len - 1] else 0xff;
                std.debug.print("← Disconnect reason=0x{x} (len={d})\n", .{ reason, msg.payload.len });
                break;
            },
            zeth.eth_proto.eth.status => {
                const st = zeth.eth_proto.Status69.decode(sa, msg.payload) catch {
                    std.debug.print("← Status (undecodable)\n", .{});
                    break;
                };
                std.debug.print("← Status: eth/{d} networkId={d} latest=#{d} forkid=0x{s}\n", .{ st.version, st.network_id, st.latest_block, std.fmt.bytesToHex(&st.fork_hash, .lower) });
                std.debug.print("    genesis=0x{s} latestHash=0x{s}\n", .{ std.fmt.bytesToHex(&st.genesis_hash, .lower), std.fmt.bytesToHex(&st.latest_block_hash, .lower) });
                std.debug.print("✓ eth/69 Status accepted — requesting headers\n", .{});
                if (!requested) {
                    const req = zeth.eth_proto.GetBlockHeaders{ .request_id = 1, .origin_number = 0, .amount = 4, .skip = 0, .reverse = false };
                    const payload = try req.encode(sa);
                    try p.writeMessage(zeth.eth_proto.eth.get_block_headers, payload);
                    requested = true;
                    std.debug.print("→ GetBlockHeaders(from=0, amount=4)\n", .{});
                }
            },
            zeth.eth_proto.eth.block_headers => {
                const resp = zeth.eth_proto.decodeBlockHeaders(sa, msg.payload) catch {
                    std.debug.print("← BlockHeaders (undecodable)\n", .{});
                    break;
                };
                std.debug.print("← BlockHeaders: {d} header(s) (reqId={d})\n", .{ resp.headers.len, resp.request_id });
                for (resp.headers) |*h| {
                    const hh = h.hash(sa) catch continue;
                    std.debug.print("    #{d}  hash=0x{s}  gasLimit={d}\n", .{ h.number, std.fmt.bytesToHex(&hh, .lower), h.gas_limit });
                }
                std.debug.print("✓ downloaded headers from a real peer over devp2p\n", .{});
                break;
            },
            else => std.debug.print("← msg id=0x{x} ({d} bytes)\n", .{ msg.id, msg.payload.len }),
        }
    }
}

/// `zeth sync <enode> <genesis.json>` — load genesis, dial a peer, complete the
/// eth/69 handshake, then download headers + bodies in batches, execute each
/// block through the import pipeline, and follow the peer's head. The first real
/// P2P block sync.
fn syncCmd(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 2) {
        std.debug.print("usage: zeth sync <enode://...> <genesis.json>\n", .{});
        return error.MissingArgument;
    }
    const enode = try zeth.peer.parseEnode(args[0]);
    var datadir: ?[]const u8 = null;
    for (args[2..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--datadir=")) datadir = arg["--datadir=".len..];
    }

    // Genesis → state + chain.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const gjson = try readFile(gpa, io, args[1]);
    defer gpa.free(gjson);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, gjson, .{});
    var st = zeth.State.init(gpa);
    defer st.deinit();
    const g = try zeth.genesis.load(a, &st, parsed.value);
    var ch = try zeth.chain.Chain.initGenesis(gpa, &st, g);
    defer ch.deinit();
    const genesis_hash = try ch.head.hash(gpa);
    const network_id = g.schedule.chain_id;
    const fid = zeth.forkid.compute(genesis_hash, &.{}, 0);
    std.debug.print("genesis #0 0x{s} (chainId={d} forkid=0x{s})\n", .{ std.fmt.bytesToHex(&genesis_hash, .lower), network_id, std.fmt.bytesToHex(&fid.hash, .lower) });

    // Optional persistence: open the store and resume from a prior sync so we
    // only download what's new.
    var db_opt: ?zeth.db.Db = if (datadir) |dir| try zeth.db.Db.open(gpa, io, dir) else null;
    defer if (db_opt) |*d| d.close();
    var store_opt: ?zeth.store.Store = if (db_opt) |*d| zeth.store.Store.init(d) else null;
    if (store_opt) |*store| {
        if (try store.getHead(a)) |head| {
            var n: u64 = 1;
            while (n <= head.number) : (n += 1) {
                const hash = (try store.getCanonical(a, n)) orelse break;
                const henc = (try store.getHeader(a, hash)) orelse break;
                const hdr = zeth.block.headerFromRlp(a, henc) catch break;
                try ch.appendResumed(hdr, hash, henc.len + 16);
            }
            try store.loadState(gpa, &st);
            std.debug.print("resumed from {s}: head #{d}\n", .{ datadir.?, ch.head.number });
        }
    }

    // Dial + RLPx handshake.
    const priv = zeth.ecies.randomPriv(io);
    const pub_key = try zeth.ecies.pubFromPriv(priv);
    const p = try zeth.peer.Peer.dial(gpa, io, enode, priv);
    defer p.destroy();
    std.debug.print("✓ connected to {s}:{d}\n", .{ enode.host, enode.port });

    // p2p Hello, then eth/69 Status.
    try p.sendHello(pub_key);
    gpa.free(try p.readUntil(gpa, zeth.eth_proto.p2p.hello));
    const our_status = zeth.eth_proto.Status69{
        .version = 69,
        .network_id = network_id,
        .genesis_hash = genesis_hash,
        .fork_hash = fid.hash,
        .fork_next = fid.next,
        .latest_block_hash = genesis_hash,
    };
    {
        const sp = try our_status.encode(a);
        try p.writeMessage(zeth.eth_proto.eth.status, sp);
    }
    const status_payload = try p.readUntil(gpa, zeth.eth_proto.eth.status);
    defer gpa.free(status_payload);
    const peer_status = try zeth.eth_proto.Status69.decode(a, status_payload);
    const target = peer_status.latest_block;
    std.debug.print("✓ eth/69 handshake — peer head #{d}\n", .{target});

    // Header → body → execute, in batches, until we reach the peer's head.
    var reqid: u64 = 1;
    while (ch.head.number < target) {
        var batch_arena = std.heap.ArenaAllocator.init(gpa);
        defer batch_arena.deinit();
        const ba = batch_arena.allocator();

        const start = ch.head.number + 1;
        const remaining = target - ch.head.number;
        const amount: u64 = @min(@as(u64, 192), remaining);

        // GetBlockHeaders.
        reqid += 1;
        const hreq = zeth.eth_proto.GetBlockHeaders{ .request_id = reqid, .origin_number = start, .amount = amount };
        try p.writeMessage(zeth.eth_proto.eth.get_block_headers, try hreq.encode(ba));
        const hpayload = try p.readUntil(gpa, zeth.eth_proto.eth.block_headers);
        defer gpa.free(hpayload);
        const hresp = try zeth.eth_proto.decodeBlockHeaders(ba, hpayload);
        if (hresp.headers.len == 0) {
            std.debug.print("peer returned no headers at #{d}; stopping\n", .{start});
            break;
        }

        // GetBlockBodies for those headers.
        var hashes = try ba.alloc([32]u8, hresp.headers.len);
        for (hresp.headers, 0..) |*h, i| hashes[i] = try h.hash(ba);
        reqid += 1;
        try p.writeMessage(zeth.eth_proto.eth.get_block_bodies, try zeth.eth_proto.encodeGetBlockBodies(ba, reqid, hashes));
        const bpayload = try p.readUntil(gpa, zeth.eth_proto.eth.block_bodies);
        defer gpa.free(bpayload);
        const bresp = try zeth.eth_proto.decodeBlockBodies(ba, bpayload);

        const n = @min(hresp.headers.len, bresp.bodies.len);
        for (0..n) |i| {
            const blk = try zeth.eth_proto.assembleBlock(ba, hresp.headers[i], bresp.bodies[i]);
            _ = ch.importBlock(blk) catch |e| {
                std.debug.print("✗ import failed at #{d}: {s}{s}\n", .{ ch.head.number + 1, @errorName(e), if (ch.last_error) |le| le else "" });
                return e;
            };
        }
        std.debug.print("  synced → #{d} / {d}\n", .{ ch.head.number, target });
    }

    if (store_opt) |*store| {
        try ch.persistTo(a, store);
        std.debug.print("persisted to {s}\n", .{datadir.?});
    }

    const hh = try ch.head.hash(gpa);
    std.debug.print("✓ sync complete: head #{d} 0x{s}\n", .{ ch.head.number, std.fmt.bytesToHex(&hh, .lower) });
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
    var auth_host: []const u8 = "0.0.0.0";
    var auth_port: u16 = 8551;
    var jwt_path: ?[]const u8 = null;
    var datadir: ?[]const u8 = null;
    var genesis_path: ?[]const u8 = null;
    var rlp_files: std.ArrayList([]const u8) = .empty;
    for (args) |arg| {
        if (std.mem.startsWith(u8, arg, "--datadir=")) {
            datadir = arg["--datadir=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--http.addr=")) {
            const hp = arg["--http.addr=".len..];
            if (std.mem.lastIndexOfScalar(u8, hp, ':')) |ci| {
                host = hp[0..ci];
                port = std.fmt.parseInt(u16, hp[ci + 1 ..], 10) catch 8545;
            } else host = hp;
        } else if (std.mem.startsWith(u8, arg, "--authrpc.addr=")) {
            const hp = arg["--authrpc.addr=".len..];
            if (std.mem.lastIndexOfScalar(u8, hp, ':')) |ci| {
                auth_host = hp[0..ci];
                auth_port = std.fmt.parseInt(u16, hp[ci + 1 ..], 10) catch 8551;
            } else auth_host = hp;
        } else if (std.mem.startsWith(u8, arg, "--authrpc.jwtsecret=")) {
            jwt_path = arg["--authrpc.jwtsecret=".len..];
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

    // Optional on-disk persistence (`--datadir`). Open the store; if it already
    // holds a head and no RLP files were given, resume from disk instead of
    // re-importing. Otherwise import the RLP and snapshot the result.
    var db_opt: ?zeth.db.Db = if (datadir) |dir| try zeth.db.Db.open(gpa, io, dir) else null;
    defer if (db_opt) |*d| d.close();
    var store_opt: ?zeth.store.Store = if (db_opt) |*d| zeth.store.Store.init(d) else null;

    var resumed = false;
    if (store_opt) |*store| {
        if (rlp_files.items.len == 0) {
            if (try store.getHead(a)) |head| {
                var n: u64 = 1;
                while (n <= head.number) : (n += 1) {
                    const hash = (try store.getCanonical(a, n)) orelse break;
                    const henc = (try store.getHeader(a, hash)) orelse break;
                    defer a.free(henc);
                    const hdr = zeth.block.headerFromRlp(a, henc) catch break;
                    try ch.appendResumed(hdr, hash, henc.len + 16);
                }
                try store.loadState(gpa, &st);
                resumed = (ch.head.number == head.number);
                std.debug.print("resumed from {s}: head=#{d}\n", .{ datadir.?, ch.head.number });
            }
        }
    }

    // Import any provided RLP block files (skipped when resuming from disk).
    if (!resumed) for (rlp_files.items) |path| {
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
    };

    // Persist the imported chain + state for next time.
    if (!resumed) if (store_opt) |*store| {
        ch.persistTo(a, store) catch |e| std.debug.print("warning: persist failed: {s}\n", .{@errorName(e)});
    };

    const hh = try ch.head.hash(gpa);
    std.debug.print("zeth node: chainId={d} head=#{d} hash=0x{s}\n", .{ ch.chain_id, ch.head.number, std.fmt.bytesToHex(&hh, .lower) });

    // Engine API on the authrpc port (JWT-authenticated), in a second thread.
    // (The hive engine simulator drives requests sequentially, so the eth +
    // engine listeners don't access the chain concurrently in practice.)
    if (jwt_path) |jp| {
        const secret = readJwtSecret(gpa, io, jp) catch null;
        if (secret) |s| {
            const ctx = try a.create(ServeCtx);
            ctx.* = .{ .gpa = gpa, .io = io, .ch = &ch, .host = auth_host, .port = auth_port, .jwt = s };
            _ = std.Thread.spawn(.{ .stack_size = zeth.vm.NATIVE_STACK_SIZE }, serveLoop, .{ctx}) catch |e|
                std.debug.print("warning: could not start authrpc thread: {s}\n", .{@errorName(e)});
            std.debug.print("Engine API (JWT) listening on {s}:{d}\n", .{ auth_host, auth_port });
        }
    }

    // eth_ JSON-RPC on the http port (no auth). Run on a dedicated thread with a
    // large stack — serving a request can recurse to the EVM's call-depth limit,
    // which overflows the default main-thread stack. The main thread then joins.
    const eth_ctx = try a.create(ServeCtx);
    eth_ctx.* = .{ .gpa = gpa, .io = io, .ch = &ch, .host = host, .port = port, .jwt = null };
    std.debug.print("JSON-RPC listening on {s}:{d}\n", .{ host, port });
    const eth_thread = try std.Thread.spawn(.{ .stack_size = zeth.vm.NATIVE_STACK_SIZE }, serveLoop, .{eth_ctx});
    eth_thread.join();
}

const ServeCtx = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    ch: *zeth.chain.Chain,
    host: []const u8,
    port: u16,
    jwt: ?[]const u8,
};

/// Accept-and-serve loop for one listener. Runs on a thread spawned with a
/// large stack (zeth.vm.NATIVE_STACK_SIZE) because serving a request can drive
/// the EVM to its 1024-deep call recursion.
fn serveLoop(ctx: *ServeCtx) void {
    var address = net.IpAddress.parse(ctx.host, ctx.port) catch return;
    var server = address.listen(ctx.io, .{ .reuse_address = true }) catch return;
    while (true) {
        const stream = server.accept(ctx.io) catch continue;
        serveConn(ctx.gpa, ctx.io, ctx.ch, ctx.jwt, stream);
        stream.close(ctx.io);
    }
}

/// Read + hex-decode an HS256 JWT secret file (0x-prefixed or bare hex → 32 bytes).
fn readJwtSecret(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const raw = try readFile(gpa, io, path);
    defer gpa.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    const hex = if (std.mem.startsWith(u8, trimmed, "0x")) trimmed[2..] else trimmed;
    const out = try gpa.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// Verify an HS256 JWT bearer header against `secret` (HMAC over `header.payload`).
fn jwtOk(secret: []const u8, auth: ?[]const u8) bool {
    const hdr = auth orelse return false;
    const pfx = "Bearer ";
    if (hdr.len <= pfx.len or !std.mem.startsWith(u8, hdr, pfx)) return false;
    const tok = std.mem.trim(u8, hdr[pfx.len..], " ");
    const dot2 = std.mem.lastIndexOfScalar(u8, tok, '.') orelse return false;
    const signing = tok[0..dot2];
    const sig_b64 = tok[dot2 + 1 ..];
    const Dec = std.base64.url_safe_no_pad.Decoder;
    const sz = Dec.calcSizeForSlice(sig_b64) catch return false;
    if (sz != 32) return false;
    var sig: [32]u8 = undefined;
    Dec.decode(&sig, sig_b64) catch return false;
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, signing, secret);
    return std.mem.eql(u8, &mac, &sig);
}

/// Serve one connection: a keep-alive loop of HTTP JSON-RPC requests. When
/// `jwt` is set, each request must carry a valid bearer token (Engine API).
fn serveConn(gpa: std.mem.Allocator, io: std.Io, ch: *zeth.chain.Chain, jwt: ?[]const u8, stream: net.Stream) void {
    var rbuf: [64 * 1024]u8 = undefined;
    var wbuf: [64 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    var http = std.http.Server.init(&sr.interface, &sw.interface);
    while (true) {
        var req = http.receiveHead() catch return;
        if (jwt) |secret| {
            var auth: ?[]const u8 = null;
            var it = req.iterateHeaders();
            while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
                auth = h.value;
            };
            if (!jwtOk(secret, auth)) {
                req.respond("{\"error\":\"unauthorized\"}", .{ .status = .unauthorized }) catch return;
                continue;
            }
        }
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var body_buf: [8 * 1024]u8 = undefined;
        const br = req.readerExpectNone(&body_buf);
        const body = br.allocRemaining(a, std.Io.Limit.limited(16 * 1024 * 1024)) catch "";
        var resp: []const u8 = "{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":null}";
        if (req.head.method == .POST and body.len > 0)
            resp = zeth.rpc.handleBody(a, ch, body);
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
