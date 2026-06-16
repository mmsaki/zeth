//! RLPx transport core: post-handshake session secrets and the framed message
//! codec (devp2p). The signed auth/ack handshake *messages* (which also need
//! secp256k1 ECDSA-with-recovery) are a separate layer; this module covers the
//! parts that turn a completed handshake into an encrypted, MAC'd byte stream:
//!
//!   * `Secrets.derive` — from the ephemeral ECDH secret, the two nonces, and
//!     the auth/ack message bytes, derive aes-secret, mac-secret, and the
//!     seeded egress/ingress Keccak MAC states (per the RLPx spec).
//!   * `Conn` — continuous AES-256-CTR over the connection plus the two-step
//!     Keccak frame MAC; `writeFrame`/`readFrame` move capability messages.
//!
//! Frame on the wire: header-ct(16) ‖ header-mac(16) ‖ frame-ct(padded16) ‖
//! frame-mac(16), where header = size(3, BE) ‖ 0xc28080 ‖ zero-pad.

const std = @import("std");
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Aes256 = std.crypto.core.aes.Aes256;

pub const Secrets = struct {
    aes: [32]u8,
    mac: [32]u8,
    egress_mac: Keccak256,
    ingress_mac: Keccak256,

    /// Derive session secrets after a completed handshake.
    /// `eph_shared` is ECDH(our ephemeral priv, peer ephemeral pub).X.
    pub fn derive(
        eph_shared: [32]u8,
        initiator_nonce: [32]u8,
        responder_nonce: [32]u8,
        auth: []const u8,
        ack: []const u8,
        is_initiator: bool,
    ) Secrets {
        // shared-secret = keccak256(eph_shared ‖ keccak256(resp_nonce ‖ init_nonce))
        var nonce_hash: [32]u8 = undefined;
        var h = Keccak256.init(.{});
        h.update(&responder_nonce);
        h.update(&initiator_nonce);
        h.final(&nonce_hash);

        const shared_secret = keccak2(&eph_shared, &nonce_hash);
        const aes_secret = keccak2(&eph_shared, &shared_secret);
        const mac_secret = keccak2(&eph_shared, &aes_secret);

        // egress seeds with (mac_secret ^ peer_nonce) ‖ our_sent_message;
        // ingress with (mac_secret ^ our_nonce) ‖ peer_sent_message.
        const our_nonce = if (is_initiator) initiator_nonce else responder_nonce;
        const peer_nonce = if (is_initiator) responder_nonce else initiator_nonce;
        const our_msg = if (is_initiator) auth else ack;
        const peer_msg = if (is_initiator) ack else auth;

        return .{
            .aes = aes_secret,
            .mac = mac_secret,
            .egress_mac = seedMac(mac_secret, peer_nonce, our_msg),
            .ingress_mac = seedMac(mac_secret, our_nonce, peer_msg),
        };
    }
};

fn keccak2(a: []const u8, b: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    var h = Keccak256.init(.{});
    h.update(a);
    h.update(b);
    h.final(&out);
    return out;
}

fn seedMac(mac_secret: [32]u8, nonce: [32]u8, msg: []const u8) Keccak256 {
    var seed: [32]u8 = undefined;
    for (0..32) |i| seed[i] = mac_secret[i] ^ nonce[i];
    var k = Keccak256.init(.{});
    k.update(&seed);
    k.update(msg);
    return k;
}

/// A live RLPx connection's symmetric state: a continuous AES-256-CTR keystream
/// for ingress and egress, plus the running frame MACs.
pub const Conn = struct {
    enc: Ctr, // egress keystream
    dec: Ctr, // ingress keystream
    mac_secret: [32]u8,
    egress_mac: Keccak256,
    ingress_mac: Keccak256,

    pub fn init(s: Secrets) Conn {
        const zero_iv = std.mem.zeroes([16]u8);
        return .{
            .enc = Ctr.init(s.aes, zero_iv),
            .dec = Ctr.init(s.aes, zero_iv),
            .mac_secret = s.mac,
            .egress_mac = s.egress_mac,
            .ingress_mac = s.ingress_mac,
        };
    }

    /// Encrypt and MAC a capability message, appending the full frame to `out`.
    pub fn writeFrame(self: *Conn, out: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) !void {
        var header = std.mem.zeroes([16]u8);
        std.mem.writeInt(u24, header[0..3], @intCast(data.len), .big);
        header[3] = 0xc2;
        header[4] = 0x80;
        header[5] = 0x80;
        self.enc.xor(&header, &header);
        const hmac = updateMac(&self.egress_mac, self.mac_secret, header[0..16].*);
        try out.appendSlice(allocator, &header);
        try out.appendSlice(allocator, &hmac);

        // Frame body, zero-padded to a 16-byte boundary.
        const padded = (data.len + 15) / 16 * 16;
        const buf = try allocator.alloc(u8, padded);
        defer allocator.free(buf);
        @memset(buf, 0);
        @memcpy(buf[0..data.len], data);
        self.enc.xor(buf, buf);
        self.egress_mac.update(buf);
        var seed: [32]u8 = undefined;
        peek(self.egress_mac, &seed);
        const fmac = updateMac(&self.egress_mac, self.mac_secret, seed[0..16].*);
        try out.appendSlice(allocator, buf);
        try out.appendSlice(allocator, &fmac);
    }

    /// Verify + decrypt a 32-byte frame header (header-ct(16) ‖ header-mac(16)),
    /// returning the frame body size in bytes. Advances the ingress MAC + CTR.
    pub fn readHeader(self: *Conn, header: [32]u8) !usize {
        const want_hmac = updateMac(&self.ingress_mac, self.mac_secret, header[0..16].*);
        if (!std.crypto.timing_safe.eql([16]u8, want_hmac, header[16..32].*)) return error.BadHeaderMac;
        var h: [16]u8 = undefined;
        @memcpy(&h, header[0..16]);
        self.dec.xor(&h, &h);
        return std.mem.readInt(u24, h[0..3], .big);
    }

    /// The on-wire body length following a header of frame size `size`:
    /// the zero-padded ciphertext plus the 16-byte frame MAC.
    pub fn bodyLen(size: usize) usize {
        return (size + 15) / 16 * 16 + 16;
    }

    /// Verify + decrypt a frame body (ciphertext(padded) ‖ frame-mac(16)) of the
    /// `size` reported by `readHeader`, returning the message (caller owns it).
    pub fn readBody(self: *Conn, allocator: std.mem.Allocator, size: usize, body: []const u8) ![]u8 {
        const padded = (size + 15) / 16 * 16;
        if (body.len < padded + 16) return error.ShortFrame;
        const ct = body[0..padded];
        self.ingress_mac.update(ct);
        var seed: [32]u8 = undefined;
        peek(self.ingress_mac, &seed);
        const want_fmac = updateMac(&self.ingress_mac, self.mac_secret, seed[0..16].*);
        if (!std.crypto.timing_safe.eql([16]u8, want_fmac, body[padded..][0..16].*)) return error.BadFrameMac;

        const buf = try allocator.alloc(u8, padded);
        errdefer allocator.free(buf);
        self.dec.xor(buf, ct);
        return allocator.realloc(buf, size);
    }

    /// Read one whole frame from an in-memory buffer (convenience for tests).
    pub fn readFrame(self: *Conn, allocator: std.mem.Allocator, in: []const u8) !struct { msg: []u8, consumed: usize } {
        if (in.len < 32) return error.ShortFrame;
        const size = try self.readHeader(in[0..32].*);
        const blen = bodyLen(size);
        if (in.len < 32 + blen) return error.ShortFrame;
        const msg = try self.readBody(allocator, size, in[32 .. 32 + blen]);
        return .{ .msg = msg, .consumed = 32 + blen };
    }
};

/// One MAC step: `digest = keccak.peek(); mac.update(AES_ECB(mac_secret,
/// digest[:16]) ^ seed); return keccak.peek()[:16]`.
fn updateMac(mac: *Keccak256, mac_secret: [32]u8, seed: [16]u8) [16]u8 {
    var digest: [32]u8 = undefined;
    peek(mac.*, &digest);
    var enc: [16]u8 = undefined;
    // AES-128 ECB on the first 16 bytes of mac_secret (RLPx uses the leading
    // 128 bits of the 256-bit mac-secret as the MAC block-cipher key).
    const ctx = std.crypto.core.aes.Aes128.initEnc(mac_secret[0..16].*);
    ctx.encrypt(&enc, digest[0..16]);
    for (0..16) |i| enc[i] ^= seed[i];
    mac.update(&enc);
    var out_digest: [32]u8 = undefined;
    peek(mac.*, &out_digest);
    var out: [16]u8 = undefined;
    @memcpy(&out, out_digest[0..16]);
    return out;
}

/// Keccak running digest without consuming the state (finalize a copy).
fn peek(state: Keccak256, out: *[32]u8) void {
    var tmp = state;
    tmp.final(out);
}

/// Stateful AES-256-CTR keystream (continuous across frames; IV carried).
const Ctr = struct {
    ctx: std.crypto.core.aes.AesEncryptCtx(Aes256),
    counter: [16]u8,
    keystream: [16]u8 = undefined,
    off: usize = 16,

    fn init(key: [32]u8, iv: [16]u8) Ctr {
        return .{ .ctx = Aes256.initEnc(key), .counter = iv };
    }

    fn xor(self: *Ctr, dst: []u8, src: []const u8) void {
        for (dst, src) |*d, s| {
            if (self.off == 16) {
                self.ctx.encrypt(&self.keystream, &self.counter);
                var i: usize = 16;
                while (i > 0) { // big-endian increment
                    i -= 1;
                    self.counter[i] +%= 1;
                    if (self.counter[i] != 0) break;
                }
                self.off = 0;
            }
            d.* = s ^ self.keystream[self.off];
            self.off += 1;
        }
    }
};

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;
const ecies = @import("ecies.zig");

test "rlpx secrets are symmetric and frames round-trip" {
    var threaded: std.Io.Threaded = undefined;
    threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Two ephemeral keypairs + nonces; the auth/ack bytes are opaque to the
    // derivation (it only hashes them), so stand-in blobs suffice here.
    const init_eph = ecies.randomPriv(io);
    const resp_eph = ecies.randomPriv(io);
    const init_eph_pub = try ecies.pubFromPriv(init_eph);
    const resp_eph_pub = try ecies.pubFromPriv(resp_eph);
    const eph_shared = try ecies.ecdhX(init_eph, resp_eph_pub);
    const eph_shared2 = try ecies.ecdhX(resp_eph, init_eph_pub);
    try testing.expectEqualSlices(u8, &eph_shared, &eph_shared2);

    var in_nonce: [32]u8 = undefined;
    io.random(&in_nonce);
    var re_nonce: [32]u8 = undefined;
    io.random(&re_nonce);
    const auth = "auth-handshake-message-bytes";
    const ack = "ack-handshake-message-bytes";

    const si = Secrets.derive(eph_shared, in_nonce, re_nonce, auth, ack, true);
    const sr = Secrets.derive(eph_shared, in_nonce, re_nonce, auth, ack, false);
    try testing.expectEqualSlices(u8, &si.aes, &sr.aes);
    try testing.expectEqualSlices(u8, &si.mac, &sr.mac);

    var initiator = Conn.init(si);
    var responder = Conn.init(sr);

    // Initiator → responder.
    const msg1 = "hello, this is a capability message over rlpx";
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(testing.allocator);
    try initiator.writeFrame(&wire, testing.allocator, msg1);
    const r1 = try responder.readFrame(testing.allocator, wire.items);
    defer testing.allocator.free(r1.msg);
    try testing.expectEqualStrings(msg1, r1.msg);
    try testing.expectEqual(wire.items.len, r1.consumed);

    // Responder → initiator (a second frame to confirm the MAC/CTR carry state).
    const msg2 = "and a reply frame";
    var wire2: std.ArrayList(u8) = .empty;
    defer wire2.deinit(testing.allocator);
    try responder.writeFrame(&wire2, testing.allocator, msg2);
    const r2 = try initiator.readFrame(testing.allocator, wire2.items);
    defer testing.allocator.free(r2.msg);
    try testing.expectEqualStrings(msg2, r2.msg);
}
