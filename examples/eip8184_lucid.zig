//! EIP-8184 (LUCID) sealed-transaction flow on zeth's codec: encrypt the inner tx
//! into a ciphertext envelope with ChaCha20-Poly1305 (LUCID's AEAD), commit to it
//! by hash *before* reveal, then have the designated key publisher release the DEM
//! key after the schedule is fixed and decrypt it.
//!
//! Unlike EIP-8105 (a key-provider registry + trust graph), LUCID's protection is
//! commit-before-reveal priced by a top-of-block (ToB) fee. The demo also models
//! that fee so the withholding incidence is explicit: on non-reveal the penalty is
//! charged to the *sender*, not to the publisher who actually withheld — the gap
//! the feedback argues should be closed with a slashable publisher bond.
const std = @import("std");
const zeth = @import("zeth");
const rlp = zeth.rlp;
const keccak256 = zeth.crypto.keccak256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

// Illustrative 2718 type ids (LUCID leaves the concrete values TBD).
const ST_TICKET_TX_TYPE: u8 = 0x07;
const ST_TX_TYPE: u8 = 0x08;
// EIP-8184: a successful reveal refunds tob_fee*(N-1)/N; non-reveal forfeits it all.
const TOB_FEE_FRACTION: u64 = 128;

/// The inner transaction, hidden until reveal.
const InnerTx = struct {
    sender: [20]u8,
    nonce: u64,
    destination: [20]u8,
    amount: u256,
    data: []const u8,

    fn encode(self: InnerTx, a: std.mem.Allocator) ![]u8 {
        var amt: [32]u8 = undefined;
        std.mem.writeInt(u256, &amt, self.amount, .big);
        const items = [_][]const u8{
            try rlp.encodeBytes(a, &self.sender),
            try rlp.encodeUint(a, self.nonce),
            try rlp.encodeBytes(a, &self.destination),
            try rlp.encodeBytes(a, &amt),
            try rlp.encodeBytes(a, self.data),
        };
        return rlp.encodeList(a, &items);
    }
};

/// The plaintext ST ticket: validated and charged at commitment, before the key
/// is revealed. `ciphertext_hash` is the commitment that binds the sealed payload.
const Ticket = struct {
    chain_id: u64,
    sender: [20]u8,
    nonce: u64,
    gas_limit: u64,
    max_tob_fee: u64,
    key_publisher: [20]u8,
    ciphertext_hash: [32]u8,

    fn encode(self: Ticket, a: std.mem.Allocator) ![]u8 {
        const items = [_][]const u8{
            try rlp.encodeUint(a, self.chain_id),
            try rlp.encodeBytes(a, &self.sender),
            try rlp.encodeUint(a, self.nonce),
            try rlp.encodeUint(a, self.gas_limit),
            try rlp.encodeUint(a, self.max_tob_fee),
            try rlp.encodeBytes(a, &self.key_publisher),
            try rlp.encodeBytes(a, &self.ciphertext_hash),
        };
        const body = try rlp.encodeList(a, &items);
        const out = try a.alloc(u8, body.len + 1);
        out[0] = ST_TICKET_TX_TYPE;
        @memcpy(out[1..], body);
        return out;
    }
};

/// A sealed transaction: ST_TX_TYPE || rlp([ticket, ciphertext_envelope]). The
/// ciphertext is opaque to the protocol; only its hash is committed.
const SealedTx = struct {
    ticket: Ticket,
    ciphertext: []const u8, // AEAD ciphertext ++ 16-byte tag
};

/// DEM nonce: keccak256(chain_id || sender || nonce)[:12] (LUCID's derivation).
fn demNonce(chain_id: u64, sender: [20]u8, nonce: u64) [12]u8 {
    var buf: [20 + 16]u8 = undefined;
    std.mem.writeInt(u64, buf[0..8], chain_id, .big);
    @memcpy(buf[8..28], &sender);
    std.mem.writeInt(u64, buf[28..36], nonce, .big);
    return keccak256(&buf)[0..12].*;
}

/// The entity named in `ticket.key_publisher`. Holds k_dem; may withhold it.
const KeyPublisher = struct {
    address: [20]u8,
    k_dem: [32]u8,
    withhold: bool = false,

    fn release(self: KeyPublisher) ?[32]u8 {
        return if (self.withhold) null else self.k_dem;
    }
};

/// Encrypt the inner tx into a sealed tx (ChaCha20-Poly1305, empty AAD).
fn seal(a: std.mem.Allocator, inner: InnerTx, pub_addr: [20]u8, k_dem: [32]u8, chain_id: u64) !SealedTx {
    const plain = try inner.encode(a);
    const ct = try a.alloc(u8, plain.len + 16); // ciphertext ++ tag
    var tag: [16]u8 = undefined;
    const nonce = demNonce(chain_id, inner.sender, inner.nonce);
    ChaCha20Poly1305.encrypt(ct[0..plain.len], &tag, plain, "", nonce, k_dem);
    @memcpy(ct[plain.len..], &tag);
    return .{
        .ticket = .{
            .chain_id = chain_id,
            .sender = inner.sender,
            .nonce = inner.nonce,
            .gas_limit = 21_000,
            .max_tob_fee = TOB_FEE_FRACTION, // pick 1 unit of protection
            .key_publisher = pub_addr,
            .ciphertext_hash = keccak256(ct),
        },
        .ciphertext = ct,
    };
}

/// Reveal: verify the commitment, then decrypt with the released key. Returns the
/// inner-tx bytes, or null if the publisher withheld or the ciphertext was tampered.
fn reveal(a: std.mem.Allocator, st: SealedTx, publisher: KeyPublisher) !?[]u8 {
    if (!std.mem.eql(u8, &st.ticket.ciphertext_hash, &keccak256(st.ciphertext))) return null; // commitment broken
    const k_dem = publisher.release() orelse return null; // withheld
    const ct = st.ciphertext;
    const plain = try a.alloc(u8, ct.len - 16);
    const nonce = demNonce(st.ticket.chain_id, st.ticket.sender, st.ticket.nonce);
    ChaCha20Poly1305.decrypt(plain, ct[0 .. ct.len - 16], ct[ct.len - 16 ..][0..16].*, "", nonce, k_dem) catch return null;
    return plain;
}

/// ToB-fee settlement. On reveal the sender is refunded (N-1)/N of max_tob_fee; on
/// non-reveal the sender forfeits all of it. The publisher's balance is untouched
/// either way — the penalty never lands on the party that withheld.
const Settlement = struct { sender_refund: u64, sender_penalty: u64, publisher_loss: u64 };
fn settle(max_tob_fee: u64, revealed: bool) Settlement {
    if (revealed) {
        const refund = max_tob_fee * (TOB_FEE_FRACTION - 1) / TOB_FEE_FRACTION;
        return .{ .sender_refund = refund, .sender_penalty = max_tob_fee - refund, .publisher_loss = 0 };
    }
    return .{ .sender_refund = 0, .sender_penalty = max_tob_fee, .publisher_loss = 0 };
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const inner = InnerTx{ .sender = @splat(0x11), .nonce = 7, .destination = @splat(0x22), .amount = 1_000_000_000_000_000_000, .data = "swap" };
    var publisher = KeyPublisher{ .address = @splat(0x55), .k_dem = @splat(0xab) };
    const st = try seal(a, inner, publisher.address, publisher.k_dem, 1);

    std.debug.print("EIP-8184 (LUCID) sealed-tx flow (zeth codec, ChaCha20-Poly1305)\n", .{});
    std.debug.print("  commit: ciphertext_hash 0x{s}… ({d}B sealed, in beacon block before reveal)\n", .{ std.fmt.bytesToHex(st.ticket.ciphertext_hash[0..6], .lower), st.ciphertext.len });

    const got = (try reveal(a, st, publisher)).?;
    const want = try inner.encode(a);
    const s_ok = settle(st.ticket.max_tob_fee, true);
    std.debug.print("  reveal+decrypt -> inner tx {d}B, matches source: {}\n", .{ got.len, std.mem.eql(u8, got, want) });
    std.debug.print("  ToB fee (max {d}): sender refunded {d}, keeps penalty {d}; publisher loses {d}\n", .{ st.ticket.max_tob_fee, s_ok.sender_refund, s_ok.sender_penalty, s_ok.publisher_loss });

    publisher.withhold = true;
    const withheld = try reveal(a, st, publisher);
    const s_no = settle(st.ticket.max_tob_fee, false);
    std.debug.print("  withheld        -> decrypted: {s}; sender forfeits {d}, publisher loses {d}  <- penalty on the victim\n", .{ if (withheld == null) "none" else "some", s_no.sender_penalty, s_no.publisher_loss });
}

test "seal/reveal round-trips the inner tx under ChaCha20-Poly1305" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inner = InnerTx{ .sender = @splat(0x11), .nonce = 3, .destination = @splat(0x22), .amount = 5, .data = "x" };
    const publisher = KeyPublisher{ .address = @splat(0x55), .k_dem = @splat(0xab) };
    const st = try seal(a, inner, publisher.address, publisher.k_dem, 1);
    const got = (try reveal(a, st, publisher)).?;
    try std.testing.expectEqualSlices(u8, try inner.encode(a), got);
}

test "the commitment binds the ciphertext: tampering breaks reveal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inner = InnerTx{ .sender = @splat(0x11), .nonce = 0, .destination = @splat(0x22), .amount = 1, .data = "" };
    const publisher = KeyPublisher{ .address = @splat(0x55), .k_dem = @splat(0xab) };
    var st = try seal(a, inner, publisher.address, publisher.k_dem, 1);
    const tampered = try a.dupe(u8, st.ciphertext);
    tampered[0] ^= 0xff; // flip a byte; the committed ciphertext_hash still binds the original
    st.ciphertext = tampered;
    try std.testing.expect((try reveal(a, st, publisher)) == null);
}

test "withholding: sender forfeits the full ToB fee, publisher loses nothing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inner = InnerTx{ .sender = @splat(0x11), .nonce = 0, .destination = @splat(0x22), .amount = 1, .data = "" };
    const publisher = KeyPublisher{ .address = @splat(0x55), .k_dem = @splat(0xab), .withhold = true };
    const st = try seal(a, inner, publisher.address, publisher.k_dem, 1);
    try std.testing.expect((try reveal(a, st, publisher)) == null);
    const s = settle(st.ticket.max_tob_fee, false);
    try std.testing.expectEqual(@as(u64, TOB_FEE_FRACTION), s.sender_penalty); // victim pays
    try std.testing.expectEqual(@as(u64, 0), s.publisher_loss); // withholder doesn't
}
