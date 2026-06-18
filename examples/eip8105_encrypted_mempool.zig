//! EIP-8105 encrypted-mempool flow on zeth's RLP codec: build the inner tx,
//! encrypt it into a type-0x05 envelope (plaintext fee header + hidden payload),
//! reveal the key after inclusion, decrypt to the type-0x06 tx.
//!
//! The cipher is a XOR stand-in — EIP-8105 is scheme-agnostic, so the demo is
//! about the EL-visible flow and its failure modes (key withholding, key-id
//! frontrunning), not the cryptography.
const std = @import("std");
const zeth = @import("zeth");
const rlp = zeth.rlp;
const keccak256 = zeth.crypto.keccak256;

const ENCRYPTED_TX_TYPE: u8 = 0x05;
const DECRYPTED_TX_TYPE: u8 = 0x06;

/// The inner transaction (becomes the type-0x06 decrypted tx after reveal).
const InnerTx = struct {
    envelope_signer: [20]u8,
    nonce: u64,
    destination: [20]u8,
    amount: u256,
    data: []const u8,

    fn encode(self: InnerTx, a: std.mem.Allocator) ![]u8 {
        var amt: [32]u8 = undefined;
        std.mem.writeInt(u256, &amt, self.amount, .big);
        const items = [_][]const u8{
            try rlp.encodeBytes(a, &self.envelope_signer),
            try rlp.encodeUint(a, self.nonce),
            try rlp.encodeBytes(a, &self.destination),
            try rlp.encodeBytes(a, &amt),
            try rlp.encodeBytes(a, self.data),
        };
        return rlp.encodeList(a, &items);
    }
};

/// The plaintext envelope of a type-0x05 encrypted tx. The header is plaintext so
/// the EL can validate fees at inclusion; only `encrypted_payload` is hidden.
const Envelope = struct {
    chain_id: u64,
    envelope_nonce: u64,
    max_fee_per_gas: u64,
    gas_amount: u64,
    key_provider_id: u64,
    key_id: [32]u8,
    encrypted_payload: []const u8,

    fn encode(self: Envelope, a: std.mem.Allocator) ![]u8 {
        const items = [_][]const u8{
            try rlp.encodeUint(a, self.chain_id),
            try rlp.encodeUint(a, self.envelope_nonce),
            try rlp.encodeUint(a, self.max_fee_per_gas),
            try rlp.encodeUint(a, self.gas_amount),
            try rlp.encodeUint(a, self.key_provider_id),
            try rlp.encodeBytes(a, &self.key_id),
            try rlp.encodeBytes(a, self.encrypted_payload),
        };
        const body = try rlp.encodeList(a, &items);
        const out = try a.alloc(u8, body.len + 1);
        out[0] = ENCRYPTED_TX_TYPE; // EIP-2718 type prefix
        @memcpy(out[1..], body);
        return out;
    }
};

/// A key provider registered in the (EIP-8105) on-chain registry. The cipher is a
/// XOR stand-in; what matters for the demo is the *namespacing* and *withholding*.
const KeyProvider = struct {
    id: u64,
    secret: [32]u8,
    withhold: bool = false, // the attack the EIP permits and only mitigates off-chain

    /// EIP-8105 mitigation against key-id frontrunning: namespace the key id by
    /// the envelope signer's address, so an attacker can't reuse a victim's id.
    fn keyId(self: KeyProvider, envelope_signer: [20]u8) [32]u8 {
        var buf: [52]u8 = undefined;
        @memcpy(buf[0..32], &self.secret);
        @memcpy(buf[32..52], &envelope_signer);
        return keccak256(&buf);
    }

    fn keystream(self: KeyProvider, key_id: [32]u8, len: usize, a: std.mem.Allocator) ![]u8 {
        const ks = try a.alloc(u8, len);
        var i: usize = 0;
        while (i < len) : (i += 1) ks[i] = self.secret[i % 32] ^ key_id[i % 32] ^ @as(u8, @truncate(i));
        return ks;
    }

    fn encrypt(self: KeyProvider, plain: []const u8, key_id: [32]u8, a: std.mem.Allocator) ![]u8 {
        const ks = try self.keystream(key_id, plain.len, a);
        const out = try a.alloc(u8, plain.len);
        for (plain, 0..) |b, i| out[i] = b ^ ks[i];
        return out;
    }

    /// Reveal-and-decrypt. Returns null when the provider withholds the key — the
    /// envelope fee was already charged at inclusion, so this is a paid-for DoS.
    fn reveal(self: KeyProvider, cipher: []const u8, key_id: [32]u8, a: std.mem.Allocator) !?[]u8 {
        if (self.withhold) return null;
        const ks = try self.keystream(key_id, cipher.len, a);
        const out = try a.alloc(u8, cipher.len);
        for (cipher, 0..) |b, i| out[i] = b ^ ks[i];
        return out;
    }
};

/// Build → encrypt → wrap → reveal → decrypt. Returns the decrypted inner-tx
/// bytes (the type-0x06 body) or null if the key was withheld.
fn runFlow(a: std.mem.Allocator, provider: KeyProvider, inner: InnerTx) !?[]u8 {
    const plain = try inner.encode(a);
    const key_id = provider.keyId(inner.envelope_signer);
    const cipher = try provider.encrypt(plain, key_id, a);
    const env = Envelope{
        .chain_id = 1,
        .envelope_nonce = 0,
        .max_fee_per_gas = 30_000_000_000,
        .gas_amount = 21_000,
        .key_provider_id = provider.id,
        .key_id = key_id,
        .encrypted_payload = cipher,
    };
    const tx05 = try env.encode(a); // what propagates in the encrypted mempool
    _ = tx05;
    // After inclusion the provider reveals the key; the payload decrypts to 0x06.
    return provider.reveal(env.encrypted_payload, env.key_id, a);
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inner = InnerTx{
        .envelope_signer = @splat(0x11),
        .nonce = 7,
        .destination = @splat(0x22),
        .amount = 1_000_000_000_000_000_000,
        .data = "swap",
    };
    var provider = KeyProvider{ .id = 1, .secret = @splat(0xab) };

    std.debug.print("EIP-8105 encrypted-mempool flow (zeth RLP codec)\n", .{});
    const ok = (try runFlow(a, provider, inner)).?;
    const want = try inner.encode(a);
    std.debug.print("  reveal+decrypt -> 0x06 body {d}B, matches source: {}\n", .{ ok.len, std.mem.eql(u8, ok, want) });

    provider.withhold = true;
    const withheld = try runFlow(a, provider, inner);
    std.debug.print("  key withheld    -> decrypted: {s}  (envelope fee already charged → paid DoS)\n", .{if (withheld == null) "none" else "some"});
}

test "reveal/decrypt round-trips the inner tx (order-preserving correspondence)" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const inner = InnerTx{ .envelope_signer = @splat(0x11), .nonce = 7, .destination = @splat(0x22), .amount = 5, .data = "x" };
    const provider = KeyProvider{ .id = 1, .secret = @splat(0xab) };
    const got = (try runFlow(arena.allocator(), provider, inner)).?;
    try std.testing.expectEqualSlices(u8, try inner.encode(arena.allocator()), got);
}

test "key-id namespacing binds the envelope to its signer (frontrunning mitigation)" {
    const provider = KeyProvider{ .id = 1, .secret = @splat(0xab) };
    const victim: [20]u8 = @splat(0x11);
    const attacker: [20]u8 = @splat(0x99);
    // An attacker copying the victim's envelope gets a different key id, so the
    // provider's per-signer key won't decrypt the attacker's copy.
    try std.testing.expect(!std.mem.eql(u8, &provider.keyId(victim), &provider.keyId(attacker)));
}

test "withheld key yields no execution though the fee was charged" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const inner = InnerTx{ .envelope_signer = @splat(0x11), .nonce = 0, .destination = @splat(0x22), .amount = 1, .data = "" };
    const provider = KeyProvider{ .id = 1, .secret = @splat(0xab), .withhold = true };
    try std.testing.expect((try runFlow(arena.allocator(), provider, inner)) == null);
}
