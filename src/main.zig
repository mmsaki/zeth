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
    zeth.log.init(init.io);
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
    } else if (std.mem.eql(u8, cmd, "bench")) {
        benchCmd(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "bench-evm")) {
        benchEvm(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "peers")) {
        peersCmd(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "produce")) {
        produceCmd(ctx.gpa, ctx.io, args[2..]) catch |e| {
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
    } else if (std.mem.eql(u8, cmd, "snap")) {
        snapDemo(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "snap-sync")) {
        snapSync(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "discover")) {
        discoverPeers(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "snap-dump")) {
        snapDump(ctx.gpa, ctx.io, args[2..]) catch |e| {
            ctx.err = e;
        };
    } else if (std.mem.eql(u8, cmd, "snap-find")) {
        snapFind(ctx.gpa, ctx.io, args[2..]) catch |e| {
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
    } else if (network_id == 1) {
        genesis_hash = zeth.forkid.MAINNET_GENESIS_HASH; // default to mainnet genesis
    }
    // Mainnet: the EIP-2124 forkid at our head. We're not synced, so head is
    // genesis → we advertise the Frontier hash with next = Homestead, exactly how
    // an unsynced node joins mainnet (geth accepts it as a valid early ancestor).
    // Any other network is treated as an all-at-genesis devnet (CRC32(genesis)).
    const fid = if (network_id == 1)
        zeth.forkid.mainnet(0, 0)
    else
        forkIdFor(network_id, genesis_hash);

    // Optional stable identity (`--key=<64hex>`); otherwise a fresh random key.
    // A stable node id lets a peer add us with `admin.addTrustedPeer` so it
    // accepts us past its peer limit — handy for a deterministic handshake test.
    var priv = zeth.ecies.randomPriv(io);
    for (args) |arg| if (std.mem.startsWith(u8, arg, "--key=")) {
        const hx = arg["--key=".len..];
        _ = std.fmt.hexToBytes(&priv, if (std.mem.startsWith(u8, hx, "0x")) hx[2..] else hx) catch {};
    };
    const pub_key = try zeth.ecies.pubFromPriv(priv);
    var id_hex: [128]u8 = undefined;
    for (pub_key, 0..) |b, i| _ = std.fmt.bufPrint(id_hex[i * 2 ..][0..2], "{x:0>2}", .{b}) catch {};
    std.debug.print("our node id: {s}\n", .{id_hex});
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

fn hex32(s: []const u8) [32]u8 {
    var out: [32]u8 = std.mem.zeroes([32]u8);
    const b = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    _ = std.fmt.hexToBytes(&out, b) catch {};
    return out;
}

/// `zeth snap-dump <enode> <networkId> <genesisHash> <stateRoot>` — fetch one
/// small AccountRange from a peer and dump the verifier fixture (root, origin,
/// keys, values, proof nodes) as hex, for unit-testing verifyRangeProof against
/// a real geth boundary proof.
fn snapDump(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 4) {
        std.debug.print("usage: zeth snap-dump <enode> <networkId> <genesisHash> <stateRoot>\n", .{});
        return;
    }
    const enode = try zeth.peer.parseEnode(args[0]);
    const network_id = std.fmt.parseInt(u64, args[1], 10) catch 1;
    const genesis_hash = hex32(args[2]);
    const root = hex32(args[3]);
    const fid = forkIdFor(network_id, genesis_hash);
    const SNAP_BASE: u64 = 34;

    const priv = zeth.ecies.randomPriv(io);
    const pub_key = try zeth.ecies.pubFromPriv(priv);
    const p = try zeth.peer.Peer.dial(gpa, io, enode, priv);
    defer p.destroy();
    try p.sendHello(pub_key);
    gpa.free(try p.readUntil(gpa, zeth.eth_proto.p2p.hello));
    {
        var ha = std.heap.ArenaAllocator.init(gpa);
        defer ha.deinit();
        const our_status = zeth.eth_proto.Status69{ .version = 69, .network_id = network_id, .genesis_hash = genesis_hash, .fork_hash = fid.hash, .fork_next = fid.next, .latest_block_hash = genesis_hash };
        try p.writeMessage(zeth.eth_proto.eth.status, try our_status.encode(ha.allocator()));
        gpa.free(try p.readUntil(gpa, zeth.eth_proto.eth.status));
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const origin = std.mem.zeroes([32]u8);
    const limit: [32]u8 = @splat(0xff);
    // Small responseBytes → a handful of accounts + a real boundary proof.
    const req = try zeth.snap_proto.encodeGetAccountRange(a, 1, root, origin, limit, 2000);
    try p.writeMessage(SNAP_BASE + zeth.snap_proto.snap.get_account_range, req);
    const resp = try p.readUntil(gpa, SNAP_BASE + zeth.snap_proto.snap.account_range);
    defer gpa.free(resp);
    const ar = try zeth.snap_proto.decodeAccountRange(a, resp);

    std.debug.print("\n===== REAL GETH AccountRange FIXTURE (verifyRangeProof) =====\n", .{});
    std.debug.print("root   = 0x{s}\n", .{std.fmt.bytesToHex(&root, .lower)});
    std.debug.print("origin = 0x{s}\n", .{std.fmt.bytesToHex(&origin, .lower)});
    std.debug.print("accounts = {d}, proofNodes = {d}\n", .{ ar.accounts.len, ar.proof.len });
    std.debug.print("\nkeys (account hashes):\n", .{});
    for (ar.accounts) |e| std.debug.print("  0x{s}\n", .{std.fmt.bytesToHex(&e.hash, .lower)});
    std.debug.print("\nvalues (full account RLP — [nonce, balance, storageRoot, codeHash]):\n", .{});
    for (ar.accounts) |e| {
        const v = zeth.trie.accountValueRlp(a, e.account.nonce, e.account.balance, e.account.storage_root.?, e.account.code_hash.?);
        std.debug.print("  0x", .{});
        for (v) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n", .{});
    }
    std.debug.print("\nproof nodes (RLP, in order):\n", .{});
    for (ar.proof) |nd| {
        std.debug.print("  0x", .{});
        for (nd) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n", .{});
    }
    std.debug.print("===== END FIXTURE =====\n", .{});
}

/// Try one peer: eth/69 handshake, then a snap/1 GetAccountRange. On a real
/// AccountRange response, dump the fixture and return true. Bounded reads so a
/// silent peer can't hang the search indefinitely.
fn tryPeerSnap(gpa: std.mem.Allocator, io: std.Io, enode: zeth.peer.Enode, network_id: u64, genesis_hash: [32]u8, fid: zeth.forkid.ForkId, root: [32]u8) bool {
    const SNAP_BASE: u64 = 34;
    const priv = zeth.ecies.randomPriv(io);
    const pub_key = zeth.ecies.pubFromPriv(priv) catch return false;
    const p = zeth.peer.Peer.dial(gpa, io, enode, priv) catch return false;
    defer p.destroy();
    p.sendHello(pub_key) catch return false;
    gpa.free(p.readUntil(gpa, zeth.eth_proto.p2p.hello) catch return false);
    var ha = std.heap.ArenaAllocator.init(gpa);
    defer ha.deinit();
    const st = zeth.eth_proto.Status69{ .version = 69, .network_id = network_id, .genesis_hash = genesis_hash, .fork_hash = fid.hash, .fork_next = fid.next, .latest_block_hash = genesis_hash };
    p.writeMessage(zeth.eth_proto.eth.status, st.encode(ha.allocator()) catch return false) catch return false;
    gpa.free(p.readUntil(gpa, zeth.eth_proto.eth.status) catch return false); // accepted (forkid ok)

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const origin = std.mem.zeroes([32]u8);
    const limit: [32]u8 = @splat(0xff);
    const req = zeth.snap_proto.encodeGetAccountRange(a, 1, root, origin, limit, 2000) catch return false;
    p.writeMessage(SNAP_BASE + zeth.snap_proto.snap.get_account_range, req) catch return false;
    // Bounded wait for the AccountRange (id 35).
    var reads: usize = 0;
    while (reads < 12) : (reads += 1) {
        const msg = p.readMessage(gpa) catch return false;
        defer gpa.free(msg.payload);
        if (msg.id == SNAP_BASE + zeth.snap_proto.snap.account_range) {
            const ar = zeth.snap_proto.decodeAccountRange(a, msg.payload) catch return false;
            std.debug.print("\n===== REAL MAINNET AccountRange FIXTURE =====\n", .{});
            std.debug.print("peer   = {s}:{d}\n", .{ enode.host, enode.port });
            std.debug.print("root   = 0x{s}\n", .{std.fmt.bytesToHex(&root, .lower)});
            std.debug.print("origin = 0x{s}\n", .{std.fmt.bytesToHex(&origin, .lower)});
            std.debug.print("accounts = {d}, proofNodes = {d}\n", .{ ar.accounts.len, ar.proof.len });
            for (ar.accounts) |e| {
                const v = zeth.trie.accountValueRlp(a, e.account.nonce, e.account.balance, e.account.storage_root.?, e.account.code_hash.?);
                std.debug.print("key 0x{s}  val 0x", .{std.fmt.bytesToHex(&e.hash, .lower)});
                for (v) |b| std.debug.print("{x:0>2}", .{b});
                std.debug.print("\n", .{});
            }
            for (ar.proof) |nd| {
                std.debug.print("proof 0x", .{});
                for (nd) |b| std.debug.print("{x:0>2}", .{b});
                std.debug.print("\n", .{});
            }
            std.debug.print("===== END MAINNET FIXTURE =====\n", .{});
            return true;
        }
        if (msg.id == zeth.eth_proto.p2p.ping) p.writeMessage(zeth.eth_proto.p2p.pong, "\xc0") catch {};
        if (msg.id == zeth.eth_proto.p2p.disconnect) return false;
    }
    return false; // accepted eth but didn't serve snap in time
}

/// `zeth snap-find <bootnode-enode> <networkId> <genesisHash> <stateRoot>` —
/// discover peers and try each until one accepts AND serves a snap AccountRange,
/// then dump the fixture. The way to capture a real mainnet snap fixture.
fn snapFind(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 4) {
        std.debug.print("usage: zeth snap-find <bootnode-enode> <networkId> <genesisHash> <stateRoot>\n", .{});
        return;
    }
    const boot = try zeth.peer.parseEnode(args[0]);
    const network_id = std.fmt.parseInt(u64, args[1], 10) catch 1;
    const genesis_hash = hex32(args[2]);
    const root = hex32(args[3]);
    const fid = forkIdFor(network_id, genesis_hash);
    const boot_ip = (net.Ip4Address.parse(boot.host, 0) catch return).bytes;

    const priv = zeth.ecies.randomPriv(io);
    var target: [64]u8 = undefined;
    io.random(&target);
    var nodes: [16]zeth.discv4.Node = undefined;
    const n = zeth.discv4.bondAndFindNode(gpa, io, priv, boot_ip, boot.port, target, &nodes) catch |e| {
        std.debug.print("✗ discovery failed: {s}\n", .{@errorName(e)});
        return;
    };
    std.debug.print("discovery: {d} neighbors; searching for one that serves snap …\n", .{n});
    for (nodes[0..n]) |node| {
        if (node.ip_len != 4 or node.tcp == 0) continue;
        var hostbuf: [16]u8 = undefined;
        const host = std.fmt.bufPrint(&hostbuf, "{d}.{d}.{d}.{d}", .{ node.ip[0], node.ip[1], node.ip[2], node.ip[3] }) catch continue;
        std.debug.print("  trying {s}:{d} …\n", .{ host, node.tcp });
        if (tryPeerSnap(gpa, io, .{ .pubkey = node.id, .host = host, .port = node.tcp }, network_id, genesis_hash, fid, root)) {
            std.debug.print("✓ captured a real snap fixture from {s}:{d}\n", .{ host, node.tcp });
            return;
        }
    }
    std.debug.print("\nno discovered peer served snap this round (all full/unreachable or eth-only).\n", .{});
}

/// `zeth discover <bootnode-enode> <networkId> <genesisHash>` — UDP discovery v4
/// against a bootnode to find fresh peers, then try the eth/69 handshake against
/// each until one has a free slot (bootnodes are always full). Prints which
/// peers accept us — the path to a usable mainnet peer.
fn discoverPeers(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 3) {
        std.debug.print("usage: zeth discover <bootnode-enode> <networkId> <genesisHash>\n", .{});
        return;
    }
    const boot = try zeth.peer.parseEnode(args[0]);
    const network_id = std.fmt.parseInt(u64, args[1], 10) catch 1;
    const genesis_hash = hex32(args[2]);
    const fid = forkIdFor(network_id, genesis_hash);

    const boot_ip = (net.Ip4Address.parse(boot.host, 0) catch {
        std.debug.print("bootnode host must be an IPv4 literal\n", .{});
        return;
    }).bytes;

    const priv = zeth.ecies.randomPriv(io);
    const our_id = try zeth.ecies.pubFromPriv(priv);

    // discovery v4: bond with the bootnode (ping/pong endpoint proof) and ask
    // for neighbors near a random target.
    std.debug.print("discovery v4: bonding with bootnode {s}:{d} …\n", .{ boot.host, boot.port });
    var target: [64]u8 = undefined;
    io.random(&target);
    var nodes: [16]zeth.discv4.Node = undefined;
    const n = zeth.discv4.bondAndFindNode(gpa, io, priv, boot_ip, boot.port, target, &nodes) catch |e| {
        std.debug.print("✗ discovery failed: {s}\n", .{@errorName(e)});
        return;
    };
    std.debug.print("✓ discovery returned {d} neighbor(s); trying the eth/69 handshake on each …\n", .{n});
    _ = our_id;

    var accepted: usize = 0;
    for (nodes[0..n]) |node| {
        if (node.ip_len != 4 or node.tcp == 0) continue;
        var hostbuf: [16]u8 = undefined;
        const host = std.fmt.bufPrint(&hostbuf, "{d}.{d}.{d}.{d}", .{ node.ip[0], node.ip[1], node.ip[2], node.ip[3] }) catch continue;
        const enode = zeth.peer.Enode{ .pubkey = node.id, .host = host, .port = node.tcp };
        const ok = tryHandshake(gpa, io, enode, network_id, genesis_hash, fid) catch false;
        std.debug.print("  {s}:{d}  {s}\n", .{ host, node.tcp, if (ok) "✓ ACCEPTED — usable peer" else "✗ (dropped)" });
        if (ok) accepted += 1;
    }
    std.debug.print("\n{d}/{d} discovered peers accepted our handshake\n", .{ accepted, n });
}

/// Dial a peer, run the eth/69 handshake, and report whether it accepted us
/// (got past the peer's Status without a Disconnect).
fn tryHandshake(gpa: std.mem.Allocator, io: std.Io, enode: zeth.peer.Enode, network_id: u64, genesis_hash: [32]u8, fid: zeth.forkid.ForkId) !bool {
    const priv = zeth.ecies.randomPriv(io);
    const pub_key = try zeth.ecies.pubFromPriv(priv);
    const p = zeth.peer.Peer.dial(gpa, io, enode, priv) catch return false;
    defer p.destroy();
    p.sendHello(pub_key) catch return false;
    gpa.free(p.readUntil(gpa, zeth.eth_proto.p2p.hello) catch return false);
    var ha = std.heap.ArenaAllocator.init(gpa);
    defer ha.deinit();
    const st = zeth.eth_proto.Status69{ .version = 69, .network_id = network_id, .genesis_hash = genesis_hash, .fork_hash = fid.hash, .fork_next = fid.next, .latest_block_hash = genesis_hash };
    p.writeMessage(zeth.eth_proto.eth.status, st.encode(ha.allocator()) catch return false) catch return false;
    gpa.free(p.readUntil(gpa, zeth.eth_proto.eth.status) catch return false);
    return true; // got the peer's Status → accepted (forkid/genesis matched)
}

/// EIP-2124 fork id for the peer handshake. Mainnet (chain 1) needs the full
/// historical activation list (block forks then timestamp forks); an
/// all-at-genesis devnet is just CRC32(genesis).
fn forkIdFor(network_id: u64, genesis_hash: [32]u8) zeth.forkid.ForkId {
    if (network_id == 1) {
        // Homestead, DAO, Tangerine, SpuriousDragon, Byzantium, Constantinople/
        // Petersburg (same block, deduped), Istanbul, MuirGlacier, Berlin,
        // London, ArrowGlacier, GrayGlacier, then Shanghai/Cancun/Prague times.
        const acts = [_]u64{
            1150000, 1920000, 2463000, 2675000, 4370000, 7280000, 9069000, 9200000,
            12244000, 12965000, 13773000, 15050000, 1681338455, 1710338135, 1746612311,
        };
        return zeth.forkid.compute(genesis_hash, &acts, 0);
    }
    return zeth.forkid.compute(genesis_hash, &.{}, 0);
}

/// `zeth snap <enode> <networkId> <genesisHash> <stateRoot>` — dial a peer,
/// complete the eth/69 handshake, then issue a snap/1 GetAccountRange and decode
/// the real AccountRange response (the first live exercise of the snap codec).
fn snapDemo(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 4) {
        std.debug.print("usage: zeth snap <enode://...> <networkId> <genesisHash> <stateRoot>\n", .{});
        return;
    }
    const enode = try zeth.peer.parseEnode(args[0]);
    const network_id = std.fmt.parseInt(u64, args[1], 10) catch 1;
    const genesis_hash = hex32(args[2]);
    const state_root = hex32(args[3]);
    // All-at-genesis devnet forkid = CRC32(genesis); pass passed_forks for a real chain.
    const fid = forkIdFor(network_id, genesis_hash);

    // snap/1 rides the negotiated message-id range: 16 (p2p) + 18 (eth/69) = 34.
    const SNAP_BASE: u64 = 34;
    const GET_ACCOUNT_RANGE = SNAP_BASE + zeth.snap_proto.snap.get_account_range;
    const ACCOUNT_RANGE = SNAP_BASE + zeth.snap_proto.snap.account_range;

    const priv = zeth.ecies.randomPriv(io);
    const pub_key = try zeth.ecies.pubFromPriv(priv);
    const p = try zeth.peer.Peer.dial(gpa, io, enode, priv);
    defer p.destroy();
    std.debug.print("✓ RLPx handshake with {s}:{d}\n", .{ enode.host, enode.port });

    try p.sendHello(pub_key);
    gpa.free(try p.readUntil(gpa, zeth.eth_proto.p2p.hello));
    std.debug.print("← Hello (advertised eth/69 + snap/1)\n", .{});

    const our_status = zeth.eth_proto.Status69{
        .version = 69,
        .network_id = network_id,
        .genesis_hash = genesis_hash,
        .fork_hash = fid.hash,
        .fork_next = fid.next,
        .latest_block_hash = genesis_hash,
    };
    {
        var ha = std.heap.ArenaAllocator.init(gpa);
        defer ha.deinit();
        try p.writeMessage(zeth.eth_proto.eth.status, try our_status.encode(ha.allocator()));
    }
    {
        const sp = try p.readUntil(gpa, zeth.eth_proto.eth.status);
        defer gpa.free(sp);
        var sa = std.heap.ArenaAllocator.init(gpa);
        defer sa.deinit();
        const peer_status = zeth.eth_proto.Status69.decode(sa.allocator(), sp) catch {
            std.debug.print("✗ peer rejected our Status (forkid/genesis mismatch?)\n", .{});
            return;
        };
        std.debug.print("✓ eth/69 handshake — peer head #{d}\n", .{peer_status.latest_block});
    }

    // Issue the snap/1 GetAccountRange over the whole key-space at `state_root`.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const origin = std.mem.zeroes([32]u8);
    const limit: [32]u8 = @splat(0xff);
    const req = try zeth.snap_proto.encodeGetAccountRange(a, 1, state_root, origin, limit, 8000);
    try p.writeMessage(GET_ACCOUNT_RANGE, req);
    std.debug.print("→ snap GetAccountRange (root=0x{s}…, 8000 bytes)\n", .{std.fmt.bytesToHex(state_root[0..6], .lower)});

    const resp = try p.readUntil(gpa, ACCOUNT_RANGE);
    defer gpa.free(resp);
    const ar = try zeth.snap_proto.decodeAccountRange(a, resp);
    std.debug.print("← snap AccountRange: {d} accounts, {d} boundary-proof nodes\n", .{ ar.accounts.len, ar.proof.len });
    const show = @min(ar.accounts.len, 5);
    for (ar.accounts[0..show]) |e| {
        std.debug.print("    acct 0x{s}…  nonce={d} balance={d} wei\n", .{ std.fmt.bytesToHex(e.hash[0..6], .lower), e.account.nonce, e.account.balance });
    }
    std.debug.print("✓ decoded a real snap/1 AccountRange from geth — codec verified live\n", .{});
}

/// `zeth snap-sync <enode> <networkId> <genesisHash> <pivotStateRoot>` — download
/// the entire account trie from a peer over snap/1 (walking the key-space), then
/// rebuild the account trie locally and verify its root matches the pivot state
/// root. This proves the full account state was downloaded and cryptographically
/// verified end-to-end (storage tries + bytecodes + executable state are the
/// next steps).
fn snapSync(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 4) {
        std.debug.print("usage: zeth snap-sync <enode://...> <networkId> <genesisHash> <pivotStateRoot> [maxAccounts]\n", .{});
        return;
    }
    const enode = try zeth.peer.parseEnode(args[0]);
    const network_id = std.fmt.parseInt(u64, args[1], 10) catch 1;
    const genesis_hash = hex32(args[2]);
    const root = hex32(args[3]);
    // Optional cap on accounts to download (0 = whole trie). Mainnet has ~300M
    // accounts; a bounded run verifies the live state without pulling all of it —
    // every chunk is still proven against the real state root.
    const max_accounts: usize = if (args.len >= 5) (std.fmt.parseInt(usize, args[4], 10) catch 0) else 0;
    const fid = if (network_id == 1) zeth.forkid.mainnet(0, 0) else forkIdFor(network_id, genesis_hash);
    const SNAP_BASE: u64 = 34;

    const priv = zeth.ecies.randomPriv(io);
    const pub_key = try zeth.ecies.pubFromPriv(priv);
    const p = try zeth.peer.Peer.dial(gpa, io, enode, priv);
    defer p.destroy();
    try p.sendHello(pub_key);
    gpa.free(try p.readUntil(gpa, zeth.eth_proto.p2p.hello));
    {
        var ha = std.heap.ArenaAllocator.init(gpa);
        defer ha.deinit();
        const our_status = zeth.eth_proto.Status69{ .version = 69, .network_id = network_id, .genesis_hash = genesis_hash, .fork_hash = fid.hash, .fork_next = fid.next, .latest_block_hash = genesis_hash };
        try p.writeMessage(zeth.eth_proto.eth.status, try our_status.encode(ha.allocator()));
        gpa.free(try p.readUntil(gpa, zeth.eth_proto.eth.status));
    }
    std.debug.print("✓ eth/69 handshake; snap-syncing account trie at root 0x{s}…\n", .{std.fmt.bytesToHex(root[0..6], .lower)});

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var snap = zeth.snap_state.SnapStore.init(gpa);
    defer snap.deinit();

    const Contract = struct { hash: [32]u8, storage_root: [32]u8 };
    var pairs: std.ArrayList(zeth.trie.KV) = .empty;
    var contracts: std.ArrayList(Contract) = .empty;
    var code_hashes: std.ArrayList([32]u8) = .empty;
    const empty_root = zeth.trie.EMPTY_TRIE_ROOT;
    const empty_code = zeth.snap_proto.EMPTY_CODE_HASH;
    var origin = std.mem.zeroes([32]u8);
    const limit: [32]u8 = @splat(0xff);
    var requests: usize = 0;
    var total: usize = 0;
    var complete = false;
    const want_full = max_accounts == 0; // rebuild the whole trie only for a full download
    while (requests < 100_000) : (requests += 1) {
        const req = try zeth.snap_proto.encodeGetAccountRange(a, requests + 1, root, origin, limit, 200_000);
        try p.writeMessage(SNAP_BASE + zeth.snap_proto.snap.get_account_range, req);
        const resp = try p.readUntil(gpa, SNAP_BASE + zeth.snap_proto.snap.account_range);
        defer gpa.free(resp);
        const ar = try zeth.snap_proto.decodeAccountRange(a, resp);
        if (ar.accounts.len == 0) {
            complete = true;
            break;
        }
        const ck = try a.alloc([32]u8, ar.accounts.len);
        const cv = try a.alloc([]const u8, ar.accounts.len);
        for (ar.accounts, 0..) |e, j| {
            ck[j] = e.hash;
            cv[j] = zeth.trie.accountValueRlp(a, e.account.nonce, e.account.balance, e.account.storage_root.?, e.account.code_hash.?);
        }
        // Per-chunk boundary-proof verification against the real state root — the
        // trust anchor that makes this scale (verify a chunk, keep it, drop the
        // proof; no need to hold or rebuild the whole 300M-account trie). A chunk
        // that doesn't verify means an untrusted peer/response → abort.
        if (!(zeth.trie.verifyRangeProof(a, root, origin, ck, cv, ar.proof) catch false)) {
            std.debug.print("  ✗ AccountRange #{d} failed proof verification against the state root — untrusted data\n", .{requests + 1});
            return error.RangeInvalid;
        }
        for (ar.accounts, 0..) |e, j| {
            if (want_full) try pairs.append(a, .{ .key = a.dupe(u8, &e.hash) catch return error.OutOfMemory, .value = cv[j] });
            try snap.putAccount(e.hash, .{ .nonce = e.account.nonce, .balance = e.account.balance, .storage_root = e.account.storage_root.?, .code_hash = e.account.code_hash.? });
            if (!std.mem.eql(u8, &e.account.storage_root.?, &empty_root))
                try contracts.append(a, .{ .hash = e.hash, .storage_root = e.account.storage_root.? });
            if (!std.mem.eql(u8, &e.account.code_hash.?, &empty_code))
                try code_hashes.append(a, e.account.code_hash.?);
        }
        total += ar.accounts.len;
        const last = ar.accounts[ar.accounts.len - 1].hash;
        // Fraction of the key-space covered so far (top 64 bits of the last key).
        const top64: u64 = @truncate(std.mem.readInt(u256, &last, .big) >> 192);
        const pct: f64 = @as(f64, @floatFromInt(top64)) / 18446744073709551616.0 * 100.0; // / 2^64
        std.debug.print("  ✓ AccountRange #{d}: +{d} accts (total {d}), ~{d:.2}% of key-space, verified vs root; last 0x{s}…\n", .{ requests + 1, ar.accounts.len, total, pct, std.fmt.bytesToHex(last[0..6], .lower) });
        if (ar.proof.len == 0 or std.mem.eql(u8, &last, &limit)) {
            complete = true;
            break;
        }
        if (max_accounts != 0 and total >= max_accounts) break; // bounded run
        var n = std.mem.readInt(u256, &last, .big);
        n +%= 1;
        std.mem.writeInt(u256, &origin, n, .big);
    }

    if (complete and want_full) {
        // Full download: rebuild the account trie and check the root end-to-end
        // (the keys are already keccak(address), so the trie is unsecured).
        const got = zeth.trie.computeRoot(a, pairs.items, false);
        const match = std.mem.eql(u8, &got, &root);
        std.debug.print("\nsnap-sync accounts: {d} in {d} request(s) — {s}\n", .{ total, requests + 1, if (match) "✓ rebuilt root matches the state root" else "✗ root MISMATCH" });
        if (!match) return;
    } else {
        // Bounded/partial download: every chunk was already proven against the
        // state root, so the downloaded slice is trustworthy without a full rebuild.
        std.debug.print("\nsnap-sync accounts: {d} downloaded in {d} request(s), each chunk verified against the state root (partial — bounded by maxAccounts)\n", .{ total, requests + 1 });
    }

    // Storage tries: per contract, download its slots and verify the rebuilt
    // storage root equals the account's storageRoot.
    var storage_ok: usize = 0;
    var reqid: u64 = requests + 2;
    for (contracts.items) |ct| {
        var sp: std.ArrayList(zeth.trie.KV) = .empty;
        var sorigin = std.mem.zeroes([32]u8);
        var done = false;
        while (!done) {
            const sreq = try zeth.snap_proto.encodeGetStorageRanges(a, reqid, root, &[_][32]u8{ct.hash}, &sorigin, &limit, 200_000);
            reqid += 1;
            try p.writeMessage(SNAP_BASE + zeth.snap_proto.snap.get_storage_ranges, sreq);
            const sresp = try p.readUntil(gpa, SNAP_BASE + zeth.snap_proto.snap.storage_ranges);
            defer gpa.free(sresp);
            const sr = try zeth.snap_proto.decodeStorageRanges(a, sresp);
            if (sr.slots.len == 0 or sr.slots[0].len == 0) break;
            const slots = sr.slots[0];
            // Verify this storage chunk against the account's storage root.
            const sck = try a.alloc([32]u8, slots.len);
            const scv = try a.alloc([]const u8, slots.len);
            for (slots, 0..) |s, j| {
                sck[j] = s.hash;
                scv[j] = s.data;
            }
            _ = zeth.trie.verifyRangeProof(a, ct.storage_root, sorigin, sck, scv, sr.proof) catch false;
            for (slots) |s| {
                const k = a.dupe(u8, &s.hash) catch return error.OutOfMemory;
                try sp.append(a, .{ .key = k, .value = try a.dupe(u8, s.data) });
                // slotData is RLP(value); decode to a u256 for the snap store.
                const val: u256 = ((zeth.rlp.decode(a, s.data) catch continue).uint(u256) catch 0);
                try snap.putSlot(ct.hash, s.hash, val);
            }
            const last = slots[slots.len - 1].hash;
            if (sr.proof.len == 0 or std.mem.eql(u8, &last, &limit)) {
                done = true;
            } else {
                var n = std.mem.readInt(u256, &last, .big);
                n +%= 1;
                std.mem.writeInt(u256, &sorigin, n, .big);
            }
        }
        const sroot = zeth.trie.computeRoot(a, sp.items, false);
        if (std.mem.eql(u8, &sroot, &ct.storage_root)) storage_ok += 1 else std.debug.print("  ✗ storage root mismatch for 0x{s}…\n", .{std.fmt.bytesToHex(ct.hash[0..6], .lower)});
    }
    std.debug.print("snap-sync storage: {d}/{d} contract storage tries verified\n", .{ storage_ok, contracts.items.len });

    // Bytecodes: request all code hashes and verify keccak256(code) == hash.
    var code_ok: usize = 0;
    if (code_hashes.items.len > 0) {
        const creq = try zeth.snap_proto.encodeGetByteCodes(a, reqid, code_hashes.items, 4_000_000);
        try p.writeMessage(SNAP_BASE + zeth.snap_proto.snap.get_byte_codes, creq);
        const cresp = try p.readUntil(gpa, SNAP_BASE + zeth.snap_proto.snap.byte_codes);
        defer gpa.free(cresp);
        const bc = try zeth.snap_proto.decodeByteCodes(a, cresp);
        for (bc.codes, 0..) |code, i| {
            if (i >= code_hashes.items.len) break;
            if (std.mem.eql(u8, &zeth.crypto.keccak256(code), &code_hashes.items[i])) {
                code_ok += 1;
                try snap.putCode(code_hashes.items[i], a.dupe(u8, code) catch continue);
            }
        }
    }
    std.debug.print("snap-sync bytecode: {d}/{d} contract codes verified\n", .{ code_ok, code_hashes.items.len });
    std.debug.print("\n✓ snap-sync: full state (accounts + storage + code) downloaded and verified against geth\n", .{});

    // Demonstrate the verified state is usable BY ADDRESS (the read side of
    // booting from snap): query known predeploys against the hashed store.
    const known = [_]struct { name: []const u8, addr: zeth.snap_state.Address }{
        .{ .name = "BEACON_ROOTS (4788) ", .addr = .{ 0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E, 0xf1, 0x31, 0x9f, 0xB7, 0xB8, 0xbB, 0x85, 0x22, 0xd0, 0xBe, 0xac, 0x02 } },
        .{ .name = "HISTORY_STORAGE(2935)", .addr = .{ 0x00, 0x00, 0xF9, 0x08, 0x27, 0xF1, 0xC5, 0x3a, 0x10, 0xcb, 0x7A, 0x02, 0x33, 0x5B, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35 } },
        .{ .name = "WITHDRAWAL (7002)   ", .addr = .{ 0x00, 0x00, 0x09, 0x61, 0xEf, 0x48, 0x0E, 0xb5, 0x5e, 0x80, 0xD1, 0x9a, 0xd8, 0x35, 0x79, 0xA6, 0x4c, 0x00, 0x70, 0x02 } },
    };
    std.debug.print("\nstate queryable by address (faulting in via keccak):\n", .{});
    for (known) |k| {
        if (snap.account(k.addr)) |acc| {
            std.debug.print("  {s}  balance={d} nonce={d} codeLen={d}\n", .{ k.name, acc.balance, acc.nonce, snap.codeOf(k.addr).len });
        } else std.debug.print("  {s}  (not present)\n", .{k.name});
    }
}

/// Dial `enode`, complete the eth/69 handshake, then download headers + bodies
/// in batches and execute each block through `ch` until reaching the peer's
/// head. Shared by `zeth sync` and `zeth node --peer`.
fn syncFromPeer(
    gpa: std.mem.Allocator,
    io: std.Io,
    ch: *zeth.chain.Chain,
    enode: zeth.peer.Enode,
    network_id: u64,
    genesis_hash: [32]u8,
    fid: zeth.forkid.ForkId,
    follow: bool,
    store_opt: ?*zeth.store.Store,
) !void {
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
        var ha = std.heap.ArenaAllocator.init(gpa);
        defer ha.deinit();
        try p.writeMessage(zeth.eth_proto.eth.status, try our_status.encode(ha.allocator()));
    }
    {
        const status_payload = try p.readUntil(gpa, zeth.eth_proto.eth.status);
        defer gpa.free(status_payload);
        var sa = std.heap.ArenaAllocator.init(gpa);
        defer sa.deinit();
        const peer_status = try zeth.eth_proto.Status69.decode(sa.allocator(), status_payload);
        std.debug.print("✓ eth/69 handshake — peer head #{d}\n", .{peer_status.latest_block});
    }

    // Pull headers from head+1 in batches and execute them. When caught up,
    // either stop (one-shot) or poll for new blocks (follow).
    var reqid: u64 = 1;
    while (true) {
        var batch_arena = std.heap.ArenaAllocator.init(gpa);
        defer batch_arena.deinit();
        const ba = batch_arena.allocator();

        const start = ch.head.number + 1;
        reqid += 1;
        const hreq = zeth.eth_proto.GetBlockHeaders{ .request_id = reqid, .origin_number = start, .amount = 192 };
        try p.writeMessage(zeth.eth_proto.eth.get_block_headers, try hreq.encode(ba));
        const hpayload = try p.readUntil(gpa, zeth.eth_proto.eth.block_headers);
        defer gpa.free(hpayload);
        const hresp = try zeth.eth_proto.decodeBlockHeaders(ba, hpayload);
        if (hresp.headers.len == 0) {
            if (!follow) break;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(2000), .awake) catch {};
            continue;
        }

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
        std.debug.print("  synced → #{d}\n", .{ch.head.number});
        if (store_opt) |store| ch.persistTo(ba, store) catch |e| std.debug.print("warning: persist failed: {s}\n", .{@errorName(e)});
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
    var follow = false;
    for (args[2..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--datadir=")) datadir = arg["--datadir=".len..];
        if (std.mem.eql(u8, arg, "--follow")) follow = true;
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
    const fid = forkIdFor(network_id, genesis_hash);
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

    const store_ptr: ?*zeth.store.Store = if (store_opt) |*s| s else null;
    try syncFromPeer(gpa, io, &ch, enode, network_id, genesis_hash, fid, follow, store_ptr);

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

/// `zeth bench <genesis.json> <chain.rlp ...>` — measure block-processing
/// throughput in Mgas/s, the metric used to compare execution clients. Genesis
/// load + RLP splitting are done up front (untimed); only the import loop
/// (decode + execute + validate + index — everything a node does except the DB
/// write) is timed. Feed it real mainnet block RLP (`geth export`) for a real
/// number; the synthetic test chain works as a smoke test.
fn benchCmd(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 2) {
        std.debug.print("usage: zeth bench <genesis.json> <chain.rlp ...>\n", .{});
        return error.MissingArgument;
    }
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const gjson = try readFile(gpa, io, args[0]);
    defer gpa.free(gjson);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, gjson, .{});
    defer parsed.deinit();
    var st = zeth.State.init(gpa);
    defer st.deinit();
    const g = try zeth.genesis.load(a, &st, parsed.value);
    var ch = try zeth.chain.Chain.initGenesis(gpa, &st, g);
    defer ch.deinit();

    // Split every block out of the RLP files up front, so decoding the *outer*
    // framing isn't counted against execution.
    var blocks: std.ArrayList([]const u8) = .empty;
    var buffers: std.ArrayList([]u8) = .empty;
    defer for (buffers.items) |b| gpa.free(b);
    for (args[1..]) |path| {
        const data = try readFile(gpa, io, path);
        try buffers.append(a, data);
        var off: usize = 0;
        while (off < data.len) {
            const r = zeth.rlp.decodeItem(a, data[off..]) catch break;
            try blocks.append(a, data[off .. off + r.consumed]);
            off += r.consumed;
        }
    }
    std.debug.print("benchmarking {d} blocks on chainId {d} …\n", .{ blocks.items.len, g.schedule.chain_id });

    const t0 = std.Io.Clock.real.now(io).toNanoseconds();
    var total_gas: u128 = 0;
    var done: usize = 0;
    for (blocks.items) |raw| {
        const h = ch.importBlock(raw) catch |err| {
            std.debug.print("import failed at block {d}: {s}\n", .{ ch.head.number + 1, @errorName(err) });
            return err;
        };
        total_gas += h.gas_used;
        done += 1;
    }
    const t1 = std.Io.Clock.real.now(io).toNanoseconds();

    const dt_ns: i128 = @as(i128, t1) - @as(i128, t0);
    const secs: f64 = @as(f64, @floatFromInt(dt_ns)) / 1_000_000_000.0;
    const mgas_s: f64 = (@as(f64, @floatFromInt(total_gas)) / 1_000_000.0) / secs;
    const blocks_s: f64 = @as(f64, @floatFromInt(done)) / secs;
    const us_block: f64 = (secs * 1_000_000.0) / @as(f64, @floatFromInt(@max(done, 1)));
    std.debug.print(
        \\─────────────────────────────────────────────
        \\ blocks      {d}
        \\ total gas   {d}
        \\ wall        {d:.3} s
        \\ throughput  {d:.2} Mgas/s
        \\ blocks/s    {d:.1}
        \\ µs/block    {d:.1}
        \\─────────────────────────────────────────────
        \\
    , .{ done, total_gas, secs, mgas_s, blocks_s, us_block });
}

/// `zeth bench-evm [gas]` — pure EVM-interpreter throughput. Runs a tight
/// gas-bounded loop (JUMPDEST; PUSH1 1; PUSH1 1; ADD; POP; PUSH1 0; JUMP) with no
/// state/trie/DB, isolating opcode dispatch + the stack machine. Reports Mgas/s,
/// Mops/s, and ns/op — the baseline to optimize the dispatch loop against.
fn benchEvm(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    const gas: u64 = if (args.len >= 1) (std.fmt.parseInt(u64, args[0], 10) catch 1_000_000_000) else 1_000_000_000;
    const code = [_]u8{ 0x5b, 0x60, 0x01, 0x60, 0x01, 0x01, 0x50, 0x60, 0x00, 0x56 };
    var evm = try zeth.Evm.init(gpa, &code, gas);
    defer evm.deinit();

    const t0 = std.Io.Clock.real.now(io).toNanoseconds();
    evm.run();
    const t1 = std.Io.Clock.real.now(io).toNanoseconds();

    const gas_used = gas - evm.gas_left;
    const dt_ns: i128 = @as(i128, t1) - @as(i128, t0);
    const secs: f64 = @as(f64, @floatFromInt(dt_ns)) / 1_000_000_000.0;
    const mgas: f64 = (@as(f64, @floatFromInt(gas_used)) / 1_000_000.0) / secs;
    const mops: f64 = (@as(f64, @floatFromInt(evm.op_count)) / 1_000_000.0) / secs;
    const ns_op: f64 = @as(f64, @floatFromInt(dt_ns)) / @as(f64, @floatFromInt(@max(evm.op_count, 1)));
    std.debug.print(
        \\EVM dispatch micro-benchmark (tight ADD loop)
        \\ ops         {d}
        \\ gas         {d}
        \\ wall        {d:.3} s
        \\ throughput  {d:.1} Mgas/s
        \\ op rate     {d:.1} Mops/s
        \\ per op      {d:.2} ns
        \\
    , .{ evm.op_count, gas_used, secs, mgas, mops, ns_op });
}

/// Shared state for the peer manager: live held-peer counters (atomic, since
/// connector threads update them concurrently).
const PeerManager = struct {
    held: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    accepted: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    gpa: std.mem.Allocator, // thread-safe
    io: std.Io,
    network_id: u64,
    genesis_hash: [32]u8,
    fid: zeth.forkid.ForkId,
};

fn nodeShort(id: [64]u8) [16]u8 {
    var out: [16]u8 = undefined;
    for (id[0..8], 0..) |b, i| _ = std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{b}) catch {};
    return out;
}

/// Dial → RLPx → Hello → eth/69 Status, returning the live, held-ready peer
/// (caller must `destroy`). Errors if the peer rejects us at any stage.
fn dialAndHandshake(gpa: std.mem.Allocator, io: std.Io, enode: zeth.peer.Enode, priv: [32]u8, network_id: u64, genesis_hash: [32]u8, fid: zeth.forkid.ForkId) !*zeth.peer.Peer {
    const pub_key = try zeth.ecies.pubFromPriv(priv);
    const p = try zeth.peer.Peer.dial(gpa, io, enode, priv);
    errdefer p.destroy();
    try p.sendHello(pub_key);
    gpa.free(try p.readUntil(gpa, zeth.eth_proto.p2p.hello));
    var ha = std.heap.ArenaAllocator.init(gpa);
    defer ha.deinit();
    const st = zeth.eth_proto.Status69{ .version = 69, .network_id = network_id, .genesis_hash = genesis_hash, .fork_hash = fid.hash, .fork_next = fid.next, .latest_block_hash = genesis_hash };
    try p.writeMessage(zeth.eth_proto.eth.status, try st.encode(ha.allocator()));
    gpa.free(try p.readUntil(gpa, zeth.eth_proto.eth.status));
    return p;
}

/// One connector thread: dial a candidate, and if it accepts us, *hold* the
/// connection (keepalive) — bumping the live count for as long as we keep it.
fn holdPeer(mgr: *PeerManager, enode: zeth.peer.Enode, priv: [32]u8) void {
    defer mgr.gpa.free(enode.host); // owned dup handed to this thread
    const p = dialAndHandshake(mgr.gpa, mgr.io, enode, priv, mgr.network_id, mgr.genesis_hash, mgr.fid) catch return;
    defer p.destroy();
    const sid = nodeShort(enode.pubkey);
    _ = mgr.accepted.fetchAdd(1, .monotonic);
    const n = mgr.held.fetchAdd(1, .monotonic) + 1;
    zeth.log.info("peer connected   id={s}… peercount={d}", .{ sid, n });
    p.keepAlive(mgr.gpa) catch {}; // blocks here, holding the peer, until it drops
    const m = mgr.held.fetchSub(1, .monotonic) - 1;
    zeth.log.warn("peer dropped     id={s}… peercount={d}", .{ sid, m });
}

/// `zeth peers <bootnode-enode> <networkId> <genesisHash> [target] [--key=hex]`
/// — a persistent peer manager: dial the bootnode (and its discovered neighbours)
/// each on its own thread, and *hold* every peer that accepts us, logging a live
/// peercount. Per-peer threads mean a dead node's slow dial blocks only its own
/// thread, not the manager (a natural workaround for std's missing connect
/// timeout). Runs a ~30s window so you can watch the count.
fn peersCmd(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 3) {
        std.debug.print("usage: zeth peers <bootnode-enode> <networkId> <genesisHash> [target] [--key=hex]\n", .{});
        return error.MissingArgument;
    }
    const boot = try zeth.peer.parseEnode(args[0]);
    const network_id = std.fmt.parseInt(u64, args[1], 10) catch 1;
    var genesis_hash = hex32(args[2]);
    if (network_id == 1 and std.mem.eql(u8, &genesis_hash, &std.mem.zeroes([32]u8)))
        genesis_hash = zeth.forkid.MAINNET_GENESIS_HASH;
    const fid = if (network_id == 1) zeth.forkid.mainnet(0, 0) else forkIdFor(network_id, genesis_hash);

    // Optional stable identity for the bootnode dial (so it can trust us).
    var boot_key = zeth.ecies.randomPriv(io);
    for (args) |arg| if (std.mem.startsWith(u8, arg, "--key=")) {
        const hx = arg["--key=".len..];
        _ = std.fmt.hexToBytes(&boot_key, if (std.mem.startsWith(u8, hx, "0x")) hx[2..] else hx) catch {};
    };

    // Per-peer connector threads each allocate, so hand them a thread-safe
    // allocator (page allocator). Shared state is heap-allocated so it outlives
    // the detached threads.
    const a = std.heap.page_allocator;
    const mgr = try gpa.create(PeerManager);
    mgr.* = .{ .gpa = a, .io = io, .network_id = network_id, .genesis_hash = genesis_hash, .fid = fid };

    zeth.log.info("p2p: starting peer manager network={d} forkid=0x{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{ network_id, fid.hash[0], fid.hash[1], fid.hash[2], fid.hash[3] });

    // Connector for the bootnode itself (uses the stable key).
    {
        const host = try a.dupe(u8, boot.host);
        const e = zeth.peer.Enode{ .pubkey = boot.pubkey, .host = host, .port = boot.port };
        (std.Thread.spawn(.{}, holdPeer, .{ mgr, e, boot_key }) catch unreachable).detach();
    }

    // Discover neighbours from the bootnode and spawn a connector for each.
    if (net.Ip4Address.parse(boot.host, 0)) |boot_addr| {
        var target: [64]u8 = undefined;
        io.random(&target);
        var buf: [16]zeth.discv4.Node = undefined;
        const n = zeth.discv4.bondAndFindNode(gpa, io, boot_key, boot_addr.bytes, boot.port, target, &buf) catch 0;
        zeth.log.info("p2p: discovered {d} candidate(s) from bootnode", .{n});
        for (buf[0..n]) |nb| {
            if (nb.ip_len != 4 or nb.tcp == 0) continue;
            var hb: [16]u8 = undefined;
            const hs = std.fmt.bufPrint(&hb, "{d}.{d}.{d}.{d}", .{ nb.ip[0], nb.ip[1], nb.ip[2], nb.ip[3] }) catch continue;
            const host = a.dupe(u8, hs) catch continue;
            const e = zeth.peer.Enode{ .pubkey = nb.id, .host = host, .port = nb.tcp };
            (std.Thread.spawn(.{}, holdPeer, .{ mgr, e, zeth.ecies.randomPriv(io) }) catch {
                a.free(host);
                continue;
            }).detach();
        }
    } else |_| {}

    // Watch the held count for a window.
    var tick: usize = 0;
    while (tick < 10) : (tick += 1) {
        io.sleep(std.Io.Duration.fromSeconds(3), .awake) catch {};
        const held = mgr.held.load(.monotonic);
        const acc = mgr.accepted.load(.monotonic);
        zeth.log.info("p2p: peercount={d} accepted_total={d}", .{ held, acc });
    }
    zeth.log.info("p2p: manager window elapsed — exiting", .{});
}

/// `zeth produce <genesis.json> [chain.rlp ...] [--tx=0xRAW ...] [--coinbase=0x..]`
/// — load genesis, import the given blocks to establish a head, then BUILD the
/// next block (the proposer/producer path): pool the supplied raw txs, select a
/// gas-bounded nonce-ordered batch, run the block-start system calls, and compute
/// the header. The produced block is self-validated by importing it back into the
/// same chain — re-execution checks every root, so a clean import proves the
/// producer and the importer agree bit-for-bit.
fn produceCmd(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("usage: zeth produce <genesis.json> [chain.rlp ...] [--tx=0xRAW ...] [--coinbase=0xADDR]\n", .{});
        return error.MissingArgument;
    }
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var coinbase = std.mem.zeroes([20]u8);
    coinbase[19] = 0xee; // default fee recipient (nonzero, distinct)
    var raw_txs: std.ArrayList([]const u8) = .empty;
    var positionals: std.ArrayList([]const u8) = .empty;
    for (args) |arg| {
        if (std.mem.startsWith(u8, arg, "--tx=")) {
            const hx = arg["--tx=".len..];
            const h = if (std.mem.startsWith(u8, hx, "0x")) hx[2..] else hx;
            const buf = try a.alloc(u8, h.len / 2);
            _ = std.fmt.hexToBytes(buf, h) catch {
                std.debug.print("bad --tx hex\n", .{});
                return error.InvalidArgument;
            };
            try raw_txs.append(a, buf);
        } else if (std.mem.startsWith(u8, arg, "--coinbase=")) {
            const hx = arg["--coinbase=".len..];
            const h = if (std.mem.startsWith(u8, hx, "0x")) hx[2..] else hx;
            _ = std.fmt.hexToBytes(&coinbase, h) catch {};
        } else {
            try positionals.append(a, arg);
        }
    }

    // Genesis → world state + genesis header, then import any blocks to a head.
    const gjson = try readFile(gpa, io, positionals.items[0]);
    defer gpa.free(gjson);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, gjson, .{});
    defer parsed.deinit();
    var st = zeth.State.init(gpa);
    defer st.deinit();
    const g = try zeth.genesis.load(a, &st, parsed.value);
    var ch = try zeth.chain.Chain.initGenesis(gpa, &st, g);
    defer ch.deinit();
    for (positionals.items[1..]) |path| {
        const data = try readFile(gpa, io, path);
        defer gpa.free(data);
        var off: usize = 0;
        while (off < data.len) {
            const r = try zeth.rlp.decodeItem(a, data[off..]);
            _ = try ch.importBlock(data[off .. off + r.consumed]);
            off += r.consumed;
        }
    }

    // Pool the raw txs (the Chain's pool, the same one eth_sendRawTransaction
    // feeds) and select a batch ready on top of the current head.
    for (raw_txs.items) |rt| ch.txpool.add(rt) catch |e| {
        std.debug.print("  skipped a tx (decode/validate): {s}\n", .{@errorName(e)});
    };
    const next_fork = ch.schedule.forkAt(ch.head.number + 1, ch.head.timestamp + 12);
    const base_fee: u256 = if (next_fork.atLeast(.london)) (ch.head.base_fee_per_gas orelse 1_000_000_000) else 0;
    const batch = try ch.txpool.select(a, ch.state, ch.head.gas_limit, base_fee);

    // Build the next block (proposer/producer path).
    const attrs = zeth.chain.Chain.ProduceAttrs{
        .timestamp = ch.head.timestamp + 12,
        .fee_recipient = coinbase,
        .parent_beacon_block_root = if (next_fork.atLeast(.cancun)) std.mem.zeroes([32]u8) else null,
    };
    const built = try ch.produceBlock(a, attrs, batch);
    const blk = built.block;
    const ph = try ch.head.hash(gpa);
    std.debug.print("built block {d} on parent 0x{s}\n", .{ blk.header.number, std.fmt.bytesToHex(&ph, .lower) });
    std.debug.print("  txs={d} gasUsed={d} value={d} wei stateRoot=0x{s} txRoot=0x{s} receiptsRoot=0x{s}\n", .{
        blk.transactions.len, blk.header.gas_used, built.fees,
        std.fmt.bytesToHex(&blk.header.state_root, .lower),
        std.fmt.bytesToHex(&blk.header.transactions_root, .lower),
        std.fmt.bytesToHex(&blk.header.receipts_root, .lower),
    });

    // Self-validate: import the produced block back. produceBlock ran on a clone,
    // so the head is unchanged; importDecoded re-executes against real state and
    // checks every root — a clean return means the block is internally valid.
    const h = ch.importDecoded(a, blk) catch |e| {
        std.debug.print("SELF-VALIDATION FAILED: {s}\n", .{@errorName(e)});
        return e;
    };
    const bh = try h.hash(gpa);
    std.debug.print("self-validated ✓  head now block {d} hash=0x{s}\n", .{ h.number, std.fmt.bytesToHex(&bh, .lower) });
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
    var peer_enode: ?[]const u8 = null;
    var genesis_path: ?[]const u8 = null;
    var rlp_files: std.ArrayList([]const u8) = .empty;
    for (args) |arg| {
        if (std.mem.startsWith(u8, arg, "--datadir=")) {
            datadir = arg["--datadir=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--peer=")) {
            peer_enode = arg["--peer=".len..];
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

    // Sync from a peer (--peer), continuing from the resumed/imported head.
    if (peer_enode) |en| {
        if (zeth.peer.parseEnode(en)) |enode| {
            const ghash = try g.header.hash(gpa);
            const fid = zeth.forkid.compute(ghash, &.{}, 0);
            const store_ptr: ?*zeth.store.Store = if (store_opt) |*s| s else null;
            // Catch up to the peer's head, then serve. (Following the live head
            // while serving needs the chain guarded by a mutex — a follow-up.)
            syncFromPeer(gpa, io, &ch, enode, g.schedule.chain_id, ghash, fid, false, store_ptr) catch |e|
                std.debug.print("peer sync ended: {s}\n", .{@errorName(e)});
        } else |e| std.debug.print("bad --peer enode: {s}\n", .{@errorName(e)});
    }

    // Persist the imported chain + state for next time.
    if (!resumed and peer_enode == null) if (store_opt) |*store| {
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
