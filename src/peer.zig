//! A live devp2p peer over TCP: dial → RLPx handshake → exchange the p2p Hello
//! and eth/68 Status, leaving an authenticated, framed channel for block sync.
//!
//! The auth/ack packets are raw ECIES blobs with a 2-byte length prefix sent
//! before encryption is established; everything after is an RLPx frame.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const rlp = @import("rlp.zig");
const ecies = @import("ecies.zig");
const rlpx = @import("rlpx.zig");
const hsk = @import("handshake.zig");
const eth_proto = @import("eth_proto.zig");

pub const Enode = struct {
    pubkey: [64]u8,
    host: []const u8, // borrows from the input string
    port: u16,
};

/// Parse `enode://<128-hex-pubkey>@<host>:<port>` (query string ignored).
pub fn parseEnode(s: []const u8) !Enode {
    const pfx = "enode://";
    if (!std.mem.startsWith(u8, s, pfx)) return error.NotAnEnode;
    const rest = s[pfx.len..];
    const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.NoAtSign;
    const hex = rest[0..at];
    if (hex.len != 128) return error.BadPubkey;
    var pubkey: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&pubkey, hex) catch return error.BadPubkey;
    var hostport = rest[at + 1 ..];
    if (std.mem.indexOfScalar(u8, hostport, '?')) |q| hostport = hostport[0..q];
    const colon = std.mem.lastIndexOfScalar(u8, hostport, ':') orelse return error.NoPort;
    return .{
        .pubkey = pubkey,
        .host = hostport[0..colon],
        .port = std.fmt.parseInt(u16, hostport[colon + 1 ..], 10) catch return error.BadPort,
    };
}

pub const Hello = struct {
    version: u64,
    client_id: []const u8,
    caps: []const Cap,
    pub const Cap = struct { name: []const u8, version: u64 };
};

pub const Peer = struct {
    gpa: std.mem.Allocator,
    io: Io,
    stream: net.Stream,
    rbuf: [16 * 1024]u8 = undefined,
    wbuf: [16 * 1024]u8 = undefined,
    sr: net.Stream.Reader = undefined,
    sw: net.Stream.Writer = undefined,
    conn: rlpx.Conn = undefined,

    /// Dial a peer and run the RLPx handshake. The returned Peer is heap-owned
    /// (the buffered reader/writer hold internal self-pointers, so it must not
    /// move); free it with `destroy`.
    pub fn dial(gpa: std.mem.Allocator, io: Io, enode: Enode, our_priv: [32]u8) !*Peer {
        var addr = try net.IpAddress.parse(enode.host, enode.port);
        // NB: std.Io connect timeout is unimplemented in the pinned Zig
        // (netConnectIpPosix panics on a non-none timeout), so dead peers use
        // the OS default connect timeout — slow when sweeping many peers.
        const stream = try addr.connect(io, .{ .mode = .stream });

        const self = try gpa.create(Peer);
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa, .io = io, .stream = stream };
        self.sr = stream.reader(io, &self.rbuf);
        self.sw = stream.writer(io, &self.wbuf);

        var handshake = hsk.Handshake.initInitiator(io, our_priv, enode.pubkey);
        const auth = try handshake.createAuth(gpa, io);
        defer gpa.free(auth);
        try self.writeRaw(auth);

        const ack = try self.readPrefixed(gpa);
        defer gpa.free(ack);
        try handshake.readAck(gpa, ack);

        const secrets = try handshake.secrets(auth, ack);
        self.conn = rlpx.Conn.init(secrets);
        return self;
    }

    pub fn destroy(self: *Peer) void {
        self.stream.close(self.io);
        self.gpa.destroy(self);
    }

    // ── raw (pre-encryption) I/O ──────────────────────────────────────────────
    fn writeRaw(self: *Peer, bytes: []const u8) !void {
        try self.sw.interface.writeAll(bytes);
        try self.sw.interface.flush();
    }

    /// Read a 2-byte-length-prefixed ECIES packet (auth/ack), returning the full
    /// packet (prefix ‖ blob), which is what `Handshake.readAck` expects.
    fn readPrefixed(self: *Peer, gpa: std.mem.Allocator) ![]u8 {
        var prefix: [2]u8 = undefined;
        try self.sr.interface.readSliceAll(&prefix);
        const blob_len = std.mem.readInt(u16, &prefix, .big);
        const packet = try gpa.alloc(u8, 2 + blob_len);
        errdefer gpa.free(packet);
        @memcpy(packet[0..2], &prefix);
        try self.sr.interface.readSliceAll(packet[2..]);
        return packet;
    }

    // ── framed (post-handshake) messages ──────────────────────────────────────
    /// Frame and send one capability message (`id` ‖ rlp payload).
    pub fn writeMessage(self: *Peer, id: u64, payload: []const u8) !void {
        const body = try eth_proto.frameBody(self.gpa, id, payload);
        defer self.gpa.free(body);
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(self.gpa);
        try self.conn.writeFrame(&wire, self.gpa, body);
        try self.writeRaw(wire.items);
    }

    /// Read one capability message; caller owns `payload`.
    pub fn readMessage(self: *Peer, gpa: std.mem.Allocator) !struct { id: u64, payload: []u8 } {
        var header: [32]u8 = undefined;
        try self.sr.interface.readSliceAll(&header);
        const size = try self.conn.readHeader(header);
        const blen = rlpx.Conn.bodyLen(size);
        const body = try self.gpa.alloc(u8, blen);
        defer self.gpa.free(body);
        try self.sr.interface.readSliceAll(body);
        const frame = try self.conn.readBody(gpa, size, body);
        defer gpa.free(frame);
        const split = try eth_proto.splitMessage(frame);
        return .{ .id = split.id, .payload = try gpa.dupe(u8, split.payload) };
    }

    /// Read messages until one with id `want` arrives (caller owns its payload),
    /// auto-replying to ping and skipping unrelated announcements. Errors on a
    /// Disconnect.
    pub fn readUntil(self: *Peer, gpa: std.mem.Allocator, want: u64) ![]u8 {
        while (true) {
            const msg = try self.readMessage(gpa);
            if (msg.id == want) return msg.payload;
            defer gpa.free(msg.payload);
            if (msg.id == eth_proto.p2p.ping) {
                try self.writeMessage(eth_proto.p2p.pong, "\xc0"); // rlp([])
            } else if (msg.id == eth_proto.p2p.disconnect) {
                return error.Disconnected;
            }
            // else: NewBlockHashes / Transactions / etc. — ignore.
        }
    }

    /// Hold the connection open: read messages forever, answering p2p pings with
    /// pongs (so the peer doesn't drop us) and ignoring everything else. Returns
    /// when the peer disconnects or the link errors — i.e. when we stop holding
    /// this peer.
    pub fn keepAlive(self: *Peer, gpa: std.mem.Allocator) !void {
        while (true) {
            const msg = try self.readMessage(gpa);
            defer gpa.free(msg.payload);
            if (msg.id == eth_proto.p2p.ping) {
                try self.writeMessage(eth_proto.p2p.pong, "\xc0"); // rlp([])
            } else if (msg.id == eth_proto.p2p.disconnect) {
                return error.Disconnected;
            }
            // else: NewPooledTransactionHashes / BlockHeaders / etc. — ignore.
        }
    }

    /// Send our p2p Hello (announcing eth/69 + snap/1) as the first frame.
    pub fn sendHello(self: *Peer, our_pub: [64]u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const eth_cap = try rlp.encodeList(a, &[_][]const u8{
            try rlp.encodeBytes(a, "eth"),
            try rlp.encodeUint(a, 69), // negotiate eth/69 (geth no longer offers 68)
        });
        const snap_cap = try rlp.encodeList(a, &[_][]const u8{
            try rlp.encodeBytes(a, "snap"),
            try rlp.encodeUint(a, 1), // snap/1 satellite protocol (state-range sync)
        });
        const caps = try rlp.encodeList(a, &[_][]const u8{ eth_cap, snap_cap });
        const fields = [_][]const u8{
            try rlp.encodeUint(a, 4), // p2p protocol version (4 = no snappy)
            try rlp.encodeBytes(a, "zeth/0.1.0"),
            caps,
            try rlp.encodeUint(a, 0), // listen port (0 = not listening)
            try rlp.encodeBytes(a, &our_pub),
        };
        const payload = try rlp.encodeList(a, &fields);
        try self.writeMessage(eth_proto.p2p.hello, payload);
    }
};
