//! Cryptographic primitives used by the EVM.

const std = @import("std");

/// Keccak-256 (the pre-NIST SHA-3 variant Ethereum uses everywhere).
pub fn keccak256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data, &out, .{});
    return out;
}

test "keccak256 of empty input" {
    // The well-known Keccak-256 of the empty string.
    const expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const got = keccak256("");
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&got}) catch unreachable;
    try std.testing.expectEqualStrings(expected, &hex);
}
