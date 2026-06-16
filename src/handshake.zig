//! The RLPx (EIP-8) auth/ack handshake — the message exchange that establishes
//! the session secrets in `rlpx.zig`.
//!
//!   initiator → auth  = ECIES_pk_resp( rlp[sig, init_static_pub, init_nonce, 4]
//!                                       ‖ pad ),  prefixed with its 2-byte length
//!   responder → ack   = ECIES_pk_init( rlp[resp_eph_pub, resp_nonce, 4] ‖ pad )
//!
//! `sig` signs `static_shared ^ init_nonce` with the initiator's *ephemeral*
//! key, so the responder recovers the initiator's ephemeral pubkey from it. The
//! 2-byte length prefix is authenticated as the ECIES shared-mac data, so a MITM
//! can't truncate. Both sides then derive the same secrets via `Secrets.derive`.

const std = @import("std");
const Io = std.Io;
const rlp = @import("rlp.zig");
const ecies = @import("ecies.zig");
const secp = @import("secp.zig");
const rlpx = @import("rlpx.zig");

const AUTH_VSN: u64 = 4;
const PAD = 100; // EIP-8 anti-fingerprinting padding (bytes; fixed is fine)

pub const Handshake = struct {
    is_initiator: bool,
    static_priv: [32]u8,
    ephemeral_priv: [32]u8,
    nonce: [32]u8,
    remote_static_pub: [64]u8 = undefined,
    remote_ephemeral_pub: [64]u8 = undefined,
    remote_nonce: [32]u8 = undefined,

    pub fn initInitiator(io: Io, static_priv: [32]u8, remote_static_pub: [64]u8) Handshake {
        var nonce: [32]u8 = undefined;
        io.random(&nonce);
        return .{
            .is_initiator = true,
            .static_priv = static_priv,
            .ephemeral_priv = ecies.randomPriv(io),
            .nonce = nonce,
            .remote_static_pub = remote_static_pub,
        };
    }

    pub fn initResponder(io: Io, static_priv: [32]u8) Handshake {
        var nonce: [32]u8 = undefined;
        io.random(&nonce);
        return .{
            .is_initiator = false,
            .static_priv = static_priv,
            .ephemeral_priv = ecies.randomPriv(io),
            .nonce = nonce,
        };
    }

    /// Initiator: build the auth packet (caller owns it).
    pub fn createAuth(self: *Handshake, a: std.mem.Allocator, io: Io) ![]u8 {
        const static_shared = try ecies.ecdhX(self.static_priv, self.remote_static_pub);
        var to_sign: [32]u8 = undefined;
        for (0..32) |i| to_sign[i] = static_shared[i] ^ self.nonce[i];
        const sig = secp.sign(io, to_sign, self.ephemeral_priv);
        var sig65: [65]u8 = undefined;
        @memcpy(sig65[0..32], &sig.r);
        @memcpy(sig65[32..64], &sig.s);
        sig65[64] = sig.v;
        const my_pub = try ecies.pubFromPriv(self.static_priv);

        const body = try encodeBody(a, io, &[_][]const u8{ &sig65, &my_pub, &self.nonce });
        defer a.free(body);
        return seal(a, io, self.remote_static_pub, body);
    }

    /// Responder: parse the auth packet, recovering the initiator's static and
    /// ephemeral pubkeys and nonce.
    pub fn readAuth(self: *Handshake, a: std.mem.Allocator, packet: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const aa = arena.allocator();
        const body = try open(aa, self.static_priv, packet);
        const fields = try decodeBody(aa, body);
        if (fields.len < 3) return error.BadAuth;
        const sig = try fixed(65, fields[0]);
        self.remote_static_pub = try fixed(64, fields[1]);
        self.remote_nonce = try fixed(32, fields[2]);

        const static_shared = try ecies.ecdhX(self.static_priv, self.remote_static_pub);
        var signed: [32]u8 = undefined;
        for (0..32) |i| signed[i] = static_shared[i] ^ self.remote_nonce[i];
        self.remote_ephemeral_pub = secp.recoverPubkey(signed, sig[64], sig[0..32].*, sig[32..64].*) orelse return error.BadAuthSig;
    }

    /// Responder: build the ack packet (caller owns it).
    pub fn createAck(self: *Handshake, a: std.mem.Allocator, io: Io) ![]u8 {
        const eph_pub = try ecies.pubFromPriv(self.ephemeral_priv);
        const body = try encodeBody(a, io, &[_][]const u8{ &eph_pub, &self.nonce });
        defer a.free(body);
        return seal(a, io, self.remote_static_pub, body);
    }

    /// Initiator: parse the ack packet, recovering the responder's ephemeral
    /// pubkey and nonce.
    pub fn readAck(self: *Handshake, a: std.mem.Allocator, packet: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const aa = arena.allocator();
        const body = try open(aa, self.static_priv, packet);
        const fields = try decodeBody(aa, body);
        if (fields.len < 2) return error.BadAck;
        self.remote_ephemeral_pub = try fixed(64, fields[0]);
        self.remote_nonce = try fixed(32, fields[1]);
    }

    /// Derive the session secrets from the completed handshake. `auth`/`ack` are
    /// the full packets as they went on the wire.
    pub fn secrets(self: *const Handshake, auth: []const u8, ack: []const u8) !rlpx.Secrets {
        const eph_shared = try ecies.ecdhX(self.ephemeral_priv, self.remote_ephemeral_pub);
        const init_nonce = if (self.is_initiator) self.nonce else self.remote_nonce;
        const resp_nonce = if (self.is_initiator) self.remote_nonce else self.nonce;
        return rlpx.Secrets.derive(eph_shared, init_nonce, resp_nonce, auth, ack, self.is_initiator);
    }
};

/// rlp([ ...items, version ]) followed by random EIP-8 padding.
fn encodeBody(a: std.mem.Allocator, io: Io, items: []const []const u8) ![]u8 {
    var encoded: std.ArrayList([]const u8) = .empty;
    defer {
        for (encoded.items) |e| a.free(e);
        encoded.deinit(a);
    }
    for (items) |it| try encoded.append(a, try rlp.encodeBytes(a, it));
    try encoded.append(a, try rlp.encodeUint(a, AUTH_VSN));
    const list = try rlp.encodeList(a, encoded.items);
    defer a.free(list);

    const out = try a.alloc(u8, list.len + PAD);
    @memcpy(out[0..list.len], list);
    io.random(out[list.len..]); // trailing padding (decoder ignores it)
    return out;
}

/// ECIES-seal `body` to `remote_pub`, prefixing the 2-byte big-endian total
/// ciphertext length (authenticated as the shared-mac).
fn seal(a: std.mem.Allocator, io: Io, remote_pub: [64]u8, body: []const u8) ![]u8 {
    const blob_len = 65 + 16 + body.len + 32; // ECIES overhead + body
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(blob_len), .big);
    const blob = try ecies.encrypt(a, io, remote_pub, body, &prefix);
    defer a.free(blob);
    const packet = try a.alloc(u8, 2 + blob.len);
    @memcpy(packet[0..2], &prefix);
    @memcpy(packet[2..], blob);
    return packet;
}

/// Strip the 2-byte length prefix and ECIES-open the packet (caller owns body).
fn open(a: std.mem.Allocator, priv: [32]u8, packet: []const u8) ![]u8 {
    if (packet.len < 2) return error.BadPacket;
    return ecies.decrypt(a, priv, packet[2..], packet[0..2]);
}

fn decodeBody(a: std.mem.Allocator, body: []const u8) ![]rlp.Item {
    const decoded = try rlp.decodeItem(a, body); // ignores trailing padding
    return decoded.item.items();
}

fn fixed(comptime n: usize, item: rlp.Item) ![n]u8 {
    const b = try item.bytes();
    if (b.len != n) return error.BadField;
    var out: [n]u8 = undefined;
    @memcpy(&out, b);
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "rlpx handshake establishes matching secrets end to end" {
    var threaded: Io.Threaded = undefined;
    threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const a = testing.allocator;

    const sk_i = ecies.randomPriv(io);
    const sk_r = ecies.randomPriv(io);
    const pk_r = try ecies.pubFromPriv(sk_r);

    var init = Handshake.initInitiator(io, sk_i, pk_r);
    var resp = Handshake.initResponder(io, sk_r);

    const auth = try init.createAuth(a, io);
    defer a.free(auth);
    try resp.readAuth(a, auth);

    const ack = try resp.createAck(a, io);
    defer a.free(ack);
    try init.readAck(a, ack);

    // The responder recovered the initiator's static pubkey + ephemeral pubkey.
    const pk_i = try ecies.pubFromPriv(sk_i);
    try testing.expectEqualSlices(u8, &pk_i, &resp.remote_static_pub);

    const si = try init.secrets(auth, ack);
    const sr = try resp.secrets(auth, ack);
    try testing.expectEqualSlices(u8, &si.aes, &sr.aes);
    try testing.expectEqualSlices(u8, &si.mac, &sr.mac);

    // And a frame written by one side decodes on the other.
    var ci = rlpx.Conn.init(si);
    var cr = rlpx.Conn.init(sr);
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(a);
    try ci.writeFrame(&wire, a, "hello peer");
    const got = try cr.readFrame(a, wire.items);
    defer a.free(got.msg);
    try testing.expectEqualStrings("hello peer", got.msg);
}
