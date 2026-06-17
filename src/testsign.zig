//! Test-only transaction signing. Manufactures a valid signed legacy (EIP-155)
//! transaction so the mempool/producer tests have real, recoverable txs to feed
//! in. This is deliberately *not* part of the node — signing belongs to the
//! sender/wallet, never the block-production path — so it lives here as a shared
//! test helper rather than a public module.

const std = @import("std");
const rlp = @import("rlp.zig");
const secp = @import("secp.zig");
const crypto = @import("crypto.zig");

/// Sign a legacy EIP-155 transaction → raw RLP `[nonce, gasPrice, gas, to,
/// value, data, v, r, s]`. `data` is empty (a plain value transfer).
pub fn signLegacy(a: std.mem.Allocator, io: std.Io, priv: [32]u8, chain_id: u64, nonce: u64, gas_price: u64, gas_limit: u64, to: [20]u8, value: u64) ![]u8 {
    var items: std.ArrayList([]const u8) = .empty;
    try items.append(a, try rlp.encodeUint(a, nonce));
    try items.append(a, try rlp.encodeUint(a, gas_price));
    try items.append(a, try rlp.encodeUint(a, gas_limit));
    try items.append(a, try rlp.encodeBytes(a, &to));
    try items.append(a, try rlp.encodeUint(a, value));
    try items.append(a, try rlp.encodeBytes(a, &.{}));
    // EIP-155 signing payload appends [chainId, 0, 0].
    try items.append(a, try rlp.encodeUint(a, chain_id));
    try items.append(a, try rlp.encodeBytes(a, &.{}));
    try items.append(a, try rlp.encodeBytes(a, &.{}));
    const sig = secp.sign(io, crypto.keccak256(try rlp.encodeList(a, items.items)), priv);
    const v = @as(u64, sig.v) + 35 + chain_id * 2;
    // Final tx replaces the three signing placeholders with v, r, s.
    var f: std.ArrayList([]const u8) = .empty;
    for (items.items[0..6]) |it| try f.append(a, it);
    try f.append(a, try rlp.encodeUint(a, v));
    try f.append(a, try rlp.encodeBytes(a, trimLeadingZeros(&sig.r)));
    try f.append(a, try rlp.encodeBytes(a, trimLeadingZeros(&sig.s)));
    return rlp.encodeList(a, f.items);
}

fn trimLeadingZeros(b: []const u8) []const u8 {
    var i: usize = 0;
    while (i < b.len and b[i] == 0) i += 1;
    return b[i..];
}
