//! Node Discovery Protocol v4 — the Kademlia-like UDP DHT Ethereum nodes use to
//! *find* each other without a hardcoded enode. This module implements the wire
//! codec (the part that's fully unit-testable offline) plus a best-effort live
//! bonding + `FindNode` flow.
//!
//! Wire format (see devp2p/discv4.md):
//!
//!     packet     = packet-header ‖ packet-data
//!     packet-header = hash ‖ signature ‖ packet-type
//!     hash       = keccak256(signature ‖ packet-type ‖ packet-data)
//!     signature  = sign(keccak256(packet-type ‖ packet-data))   (r‖s‖v, 65 bytes)
//!
//! `packet-data` is an RLP list whose shape depends on `packet-type`. The leading
//! `hash` only exists to make the packet recognizable when several protocols share
//! one UDP port — it is not a security feature; the signature is.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const rlp = @import("rlp.zig");
const secp = @import("secp.zig");
const ecies = @import("ecies.zig");
const crypto = @import("crypto.zig");

/// Discovery v4 packet types (the single byte after the signature).
pub const PacketType = enum(u8) {
    ping = 0x01,
    pong = 0x02,
    findnode = 0x03,
    neighbors = 0x04,
    enr_request = 0x05,
    enr_response = 0x06,
};

/// The maximum size of any discovery datagram.
pub const MAX_PACKET = 1280;

/// A node endpoint: IP (4 or 16 bytes) plus the UDP and TCP ports.
pub const Endpoint = struct {
    ip: [16]u8 = std.mem.zeroes([16]u8),
    ip_len: u8 = 4, // 4 (IPv4) or 16 (IPv6)
    udp: u16 = 0,
    tcp: u16 = 0,

    pub fn ip4(a: u8, b: u8, c: u8, d: u8, udp: u16, tcp: u16) Endpoint {
        var e: Endpoint = .{ .ip_len = 4, .udp = udp, .tcp = tcp };
        e.ip[0] = a;
        e.ip[1] = b;
        e.ip[2] = c;
        e.ip[3] = d;
        return e;
    }

    fn ipSlice(self: *const Endpoint) []const u8 {
        return self.ip[0..self.ip_len];
    }

    /// rlp[ip, udp-port, tcp-port]
    fn encode(self: *const Endpoint, a: std.mem.Allocator) ![]u8 {
        const items = [_][]const u8{
            try rlp.encodeBytes(a, self.ipSlice()),
            try rlp.encodeUint(a, self.udp),
            try rlp.encodeUint(a, self.tcp),
        };
        return rlp.encodeList(a, &items);
    }

    fn fromItem(it: rlp.Item) !Endpoint {
        const fields = try it.items();
        if (fields.len < 3) return error.BadEndpoint;
        const ip = try fields[0].bytes();
        if (ip.len != 4 and ip.len != 16) return error.BadIp;
        var e: Endpoint = .{ .ip_len = @intCast(ip.len) };
        @memcpy(e.ip[0..ip.len], ip);
        e.udp = try fields[1].uint(u16);
        // tcp may be encoded as 0 (empty string); tolerate a missing/zero value.
        e.tcp = fields[2].uint(u16) catch 0;
        return e;
    }
};

/// A discovered node: its 64-byte secp256k1 public key (node id) and endpoint.
pub const Node = struct {
    id: [64]u8,
    ip: [16]u8 = std.mem.zeroes([16]u8),
    ip_len: u8 = 4,
    udp: u16 = 0,
    tcp: u16 = 0,
};

// ── signed packet framing ─────────────────────────────────────────────────────

/// Build a signed discovery packet: `hash ‖ sig ‖ type ‖ data`. Caller owns the
/// returned bytes. `data` is the already-RLP-encoded packet-data list.
pub fn encodePacket(a: std.mem.Allocator, io: Io, priv: [32]u8, ptype: PacketType, data: []const u8) ![]u8 {
    const packet = try a.alloc(u8, 32 + 65 + 1 + data.len);
    errdefer a.free(packet);
    // type ‖ data
    packet[97] = @intFromEnum(ptype);
    @memcpy(packet[98..], data);
    // signature = sign(keccak256(type ‖ data))
    const sig_hash = crypto.keccak256(packet[97..]);
    const sig = secp.sign(io, sig_hash, priv);
    @memcpy(packet[32..64], &sig.r);
    @memcpy(packet[64..96], &sig.s);
    packet[96] = sig.v;
    // hash = keccak256(sig ‖ type ‖ data)
    const h = crypto.keccak256(packet[32..]);
    @memcpy(packet[0..32], &h);
    return packet;
}

pub const DecodedPacket = struct {
    sender: [64]u8, // recovered node id (public key) of the sender
    ptype: PacketType,
    hash: [32]u8, // the packet hash (echoed back as ping-hash in a pong)
    data: []const u8, // packet-data (borrows from the input)
};

/// Verify and decode a discovery packet: check the leading hash, recover the
/// sender's public key from the signature, and split out the type and data.
pub fn decodePacket(packet: []const u8) !DecodedPacket {
    if (packet.len < 98 or packet.len > MAX_PACKET) return error.BadPacketLen;
    // The leading hash must equal keccak256(sig ‖ type ‖ data).
    const h = crypto.keccak256(packet[32..]);
    if (!std.mem.eql(u8, packet[0..32], &h)) return error.BadPacketHash;

    var r: [32]u8 = undefined;
    var s: [32]u8 = undefined;
    @memcpy(&r, packet[32..64]);
    @memcpy(&s, packet[64..96]);
    const v = packet[96];
    if (v > 1) return error.BadRecoveryId;
    const sig_hash = crypto.keccak256(packet[97..]);
    const sender = secp.recoverPubkey(sig_hash, v, r, s) orelse return error.BadSignature;

    const ptype: PacketType = switch (packet[97]) {
        0x01 => .ping,
        0x02 => .pong,
        0x03 => .findnode,
        0x04 => .neighbors,
        0x05 => .enr_request,
        0x06 => .enr_response,
        else => return error.UnknownPacketType,
    };
    return .{ .sender = sender, .ptype = ptype, .hash = h, .data = packet[98..] };
}

// ── message encoders ──────────────────────────────────────────────────────────

/// Ping (0x01): packet-data = [version, from, to, expiration].
pub fn encodePing(a: std.mem.Allocator, from: Endpoint, to: Endpoint, expiration: u64) ![]u8 {
    var f = from;
    var t = to;
    const fields = [_][]const u8{
        try rlp.encodeUint(a, 4), // version
        try f.encode(a),
        try t.encode(a),
        try rlp.encodeUint(a, expiration),
    };
    return rlp.encodeList(a, &fields);
}

/// Pong (0x02): packet-data = [to, ping-hash, expiration].
pub fn encodePong(a: std.mem.Allocator, to: Endpoint, ping_hash: [32]u8, expiration: u64) ![]u8 {
    var t = to;
    const fields = [_][]const u8{
        try t.encode(a),
        try rlp.encodeBytes(a, &ping_hash),
        try rlp.encodeUint(a, expiration),
    };
    return rlp.encodeList(a, &fields);
}

/// FindNode (0x03): packet-data = [target, expiration]. `target` is a 64-byte
/// secp256k1 public key.
pub fn encodeFindNode(a: std.mem.Allocator, target: [64]u8, expiration: u64) ![]u8 {
    const fields = [_][]const u8{
        try rlp.encodeBytes(a, &target),
        try rlp.encodeUint(a, expiration),
    };
    return rlp.encodeList(a, &fields);
}

/// Neighbors (0x04): packet-data = [nodes, expiration], nodes = [[ip, udp, tcp, id], …].
pub fn encodeNeighbors(a: std.mem.Allocator, nodes: []const Node, expiration: u64) ![]u8 {
    var encoded_nodes = try a.alloc([]const u8, nodes.len);
    for (nodes, 0..) |n, i| {
        const fields = [_][]const u8{
            try rlp.encodeBytes(a, n.ip[0..n.ip_len]),
            try rlp.encodeUint(a, n.udp),
            try rlp.encodeUint(a, n.tcp),
            try rlp.encodeBytes(a, &n.id),
        };
        encoded_nodes[i] = try rlp.encodeList(a, &fields);
    }
    const nodes_list = try rlp.encodeList(a, encoded_nodes);
    const fields = [_][]const u8{
        nodes_list,
        try rlp.encodeUint(a, expiration),
    };
    return rlp.encodeList(a, &fields);
}

// ── message decoders ──────────────────────────────────────────────────────────

pub const Ping = struct { version: u64, from: Endpoint, to: Endpoint, expiration: u64 };

pub fn decodePing(a: std.mem.Allocator, data: []const u8) !Ping {
    const root = try rlp.decode(a, data);
    const f = try root.items();
    if (f.len < 4) return error.BadPing;
    return .{
        .version = try f[0].uint(u64),
        .from = try Endpoint.fromItem(f[1]),
        .to = try Endpoint.fromItem(f[2]),
        .expiration = try f[3].uint(u64),
    };
}

pub const Pong = struct { to: Endpoint, ping_hash: [32]u8, expiration: u64 };

pub fn decodePong(a: std.mem.Allocator, data: []const u8) !Pong {
    const root = try rlp.decode(a, data);
    const f = try root.items();
    if (f.len < 3) return error.BadPong;
    const ph = try f[1].bytes();
    if (ph.len != 32) return error.BadPingHash;
    var out: Pong = .{ .to = try Endpoint.fromItem(f[0]), .ping_hash = undefined, .expiration = try f[2].uint(u64) };
    @memcpy(&out.ping_hash, ph);
    return out;
}

pub const FindNode = struct { target: [64]u8, expiration: u64 };

pub fn decodeFindNode(a: std.mem.Allocator, data: []const u8) !FindNode {
    const root = try rlp.decode(a, data);
    const f = try root.items();
    if (f.len < 2) return error.BadFindNode;
    const t = try f[0].bytes();
    if (t.len != 64) return error.BadTarget;
    var out: FindNode = .{ .target = undefined, .expiration = try f[1].uint(u64) };
    @memcpy(&out.target, t);
    return out;
}

/// Decode a Neighbors packet's nodes into `out`, returning the count written
/// (capped at `out.len`).
pub fn decodeNeighbors(a: std.mem.Allocator, data: []const u8, out: []Node) !usize {
    const root = try rlp.decode(a, data);
    const f = try root.items();
    if (f.len < 1) return error.BadNeighbors;
    const list = try f[0].items();
    var n: usize = 0;
    for (list) |entry| {
        if (n >= out.len) break;
        const fields = try entry.items();
        if (fields.len < 4) return error.BadNeighborEntry;
        const ip = try fields[0].bytes();
        if (ip.len != 4 and ip.len != 16) continue;
        const id = try fields[3].bytes();
        if (id.len != 64) continue;
        var node: Node = .{ .id = undefined, .ip_len = @intCast(ip.len) };
        @memcpy(node.ip[0..ip.len], ip);
        node.udp = try fields[1].uint(u16);
        node.tcp = fields[2].uint(u16) catch 0;
        @memcpy(&node.id, id);
        out[n] = node;
        n += 1;
    }
    return n;
}

// ── live discovery (best-effort) ──────────────────────────────────────────────

/// Current wall-clock time in Unix seconds.
fn nowSeconds(io: Io) u64 {
    const ts = Io.Clock.real.now(io);
    const s = ts.toSeconds();
    return if (s < 0) 0 else @intCast(s);
}

fn timeoutMs(ms: i64) Io.Timeout {
    return .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(ms), .clock = .awake } };
}

/// Bond with `boot` (ping/pong endpoint proof) and ask it for neighbors near
/// `target`, writing discovered nodes into `out`. Returns the count.
///
/// Discovery requires a mutual endpoint proof: we ping the bootnode and must
/// also answer *its* ping before it will honor our FindNode. This drives that
/// exchange on a single ephemeral UDP socket, then collects Neighbors replies.
pub fn bondAndFindNode(
    gpa: std.mem.Allocator,
    io: Io,
    priv: [32]u8,
    boot_ip: [4]u8,
    boot_udp: u16,
    target: [64]u8,
    out: []Node,
) !usize {
    var bind_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    const sock = try net.Socket.bind(&bind_addr, io, .{ .mode = .dgram });
    defer sock.close(io);

    const dest: net.IpAddress = .{ .ip4 = .{ .bytes = boot_ip, .port = boot_udp } };

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const self_ep = Endpoint.ip4(127, 0, 0, 1, 0, 0);
    const boot_ep = Endpoint.ip4(boot_ip[0], boot_ip[1], boot_ip[2], boot_ip[3], boot_udp, 0);

    // 1. Ping the bootnode.
    {
        const data = try encodePing(a, self_ep, boot_ep, nowSeconds(io) + 20);
        const pkt = try encodePacket(a, io, priv, .ping, data);
        try sock.send(io, &dest, pkt);
    }

    var got_pong = false; // they answered our ping
    var proved = false; // we answered their ping
    var rbuf: [MAX_PACKET]u8 = undefined;
    var found: usize = 0;
    var sent_find = false;

    // 2. Drive the handshake, then collect neighbors. Bounded number of reads.
    var reads: usize = 0;
    while (reads < 32) : (reads += 1) {
        const msg = sock.receiveTimeout(io, &rbuf, timeoutMs(3000)) catch |err| switch (err) {
            error.Timeout => break,
            else => return err,
        };
        const dp = decodePacket(msg.data) catch continue;
        switch (dp.ptype) {
            .ping => {
                // Answer their ping → completes our half of the endpoint proof.
                const data = try encodePong(a, boot_ep, dp.hash, nowSeconds(io) + 20);
                const pkt = try encodePacket(a, io, priv, .pong, data);
                try sock.send(io, &dest, pkt);
                proved = true;
            },
            .pong => got_pong = true,
            .neighbors => {
                found += try decodeNeighbors(a, dp.data, out[found..]);
                if (found >= out.len) break;
            },
            else => {},
        }
        // Once both halves of the proof are done, ask for neighbors (once).
        if (got_pong and proved and !sent_find) {
            const data = try encodeFindNode(a, target, nowSeconds(io) + 20);
            const pkt = try encodePacket(a, io, priv, .findnode, data);
            try sock.send(io, &dest, pkt);
            sent_find = true;
        }
    }
    return found;
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

fn testIo() Io.Threaded {
    return Io.Threaded.init(testing.allocator, .{});
}

test "packet sign/verify round-trip recovers the sender" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const priv = ecies.randomPriv(io);
    const pub_key = try ecies.pubFromPriv(priv);

    const from = Endpoint.ip4(1, 2, 3, 4, 30303, 30303);
    const to = Endpoint.ip4(5, 6, 7, 8, 30303, 0);
    const data = try encodePing(a, from, to, 1_700_000_000);
    const pkt = try encodePacket(a, io, priv, .ping, data);

    const dp = try decodePacket(pkt);
    try testing.expectEqual(PacketType.ping, dp.ptype);
    try testing.expectEqualSlices(u8, &pub_key, &dp.sender);

    // packet-data round-trips back to the same ping.
    const ping = try decodePing(a, dp.data);
    try testing.expectEqual(@as(u64, 4), ping.version);
    try testing.expectEqual(@as(u16, 30303), ping.from.udp);
    try testing.expectEqualSlices(u8, from.ip[0..4], ping.from.ip[0..4]);
    try testing.expectEqual(@as(u64, 1_700_000_000), ping.expiration);
}

test "decodePacket rejects a tampered packet" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const priv = ecies.randomPriv(io);
    const data = try encodeFindNode(a, std.mem.zeroes([64]u8), 123);
    const pkt = try encodePacket(a, io, priv, .findnode, data);

    // Corrupt the data → the leading hash no longer matches.
    pkt[100] ^= 0xff;
    try testing.expectError(error.BadPacketHash, decodePacket(pkt));
}

test "pong round-trip carries the ping hash" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const priv = ecies.randomPriv(io);
    var ping_hash: [32]u8 = undefined;
    io.random(&ping_hash);
    const to = Endpoint.ip4(9, 9, 9, 9, 1234, 0);

    const data = try encodePong(a, to, ping_hash, 42);
    const pkt = try encodePacket(a, io, priv, .pong, data);
    const dp = try decodePacket(pkt);
    try testing.expectEqual(PacketType.pong, dp.ptype);

    const pong = try decodePong(a, dp.data);
    try testing.expectEqualSlices(u8, &ping_hash, &pong.ping_hash);
    try testing.expectEqual(@as(u64, 42), pong.expiration);
    try testing.expectEqual(@as(u16, 1234), pong.to.udp);
}

test "neighbors round-trip preserves node ids and endpoints" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var n0: Node = .{ .id = undefined, .ip_len = 4, .udp = 30303, .tcp = 30303 };
    var n1: Node = .{ .id = undefined, .ip_len = 4, .udp = 40404, .tcp = 0 };
    for (&n0.id, 0..) |*b, i| b.* = @intCast(i & 0xff);
    for (&n1.id, 0..) |*b, i| b.* = @intCast((i * 3) & 0xff);
    n0.ip[0] = 10;
    n0.ip[3] = 1;
    n1.ip[0] = 192;
    n1.ip[1] = 168;
    const nodes = [_]Node{ n0, n1 };

    const data = try encodeNeighbors(a, &nodes, 99);
    var out: [16]Node = undefined;
    const count = try decodeNeighbors(a, data, &out);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualSlices(u8, &n0.id, &out[0].id);
    try testing.expectEqual(@as(u16, 30303), out[0].udp);
    try testing.expectEqualSlices(u8, &n1.id, &out[1].id);
    try testing.expectEqual(@as(u16, 40404), out[1].udp);
    try testing.expectEqual(@as(u8, 192), out[1].ip[0]);
}

test "findnode round-trip preserves the target" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const priv = ecies.randomPriv(io);
    var target: [64]u8 = undefined;
    io.random(&target);
    const data = try encodeFindNode(a, target, 7);
    const pkt = try encodePacket(a, io, priv, .findnode, data);
    const dp = try decodePacket(pkt);
    const fn_msg = try decodeFindNode(a, dp.data);
    try testing.expectEqualSlices(u8, &target, &fn_msg.target);
    try testing.expectEqual(@as(u64, 7), fn_msg.expiration);
}
