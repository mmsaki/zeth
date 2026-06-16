//! EIP-2124 fork identifier: a CRC32 commitment over the genesis hash and the
//! fork activation points the node has already crossed, plus the block/time of
//! the next upcoming fork. Peers exchange it in the eth `Status` to refuse
//! incompatible chains early.

const std = @import("std");

pub const ForkId = struct {
    hash: [4]u8,
    next: u64,
};

/// CRC32 (IEEE 802.3, reflected, poly 0xEDB88320) — the checksum EIP-2124 uses.
pub fn crc32(data: []const u8) u32 {
    var crc: u32 = 0xffff_ffff;
    for (data) |byte| {
        crc ^= byte;
        for (0..8) |_| {
            const mask: u32 = @bitCast(-@as(i32, @intCast(crc & 1)));
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    return ~crc;
}

/// Compute the fork id given the genesis hash and the ascending list of fork
/// activation values (block numbers, then timestamps) the head has already
/// passed — folding each, as a big-endian u64, into the CRC after the genesis
/// hash. `next` is the activation value of the next not-yet-passed fork (0 if
/// none). For a chain where every fork is active at genesis the passed list is
/// empty and the id is simply (CRC32(genesis), 0).
pub fn compute(genesis_hash: [32]u8, passed_forks: []const u64, next: u64) ForkId {
    var crc = crc32(&genesis_hash);
    for (passed_forks) |f| {
        var be: [8]u8 = undefined;
        std.mem.writeInt(u64, &be, f, .big);
        crc = updateCrc(crc, &be);
    }
    var hash: [4]u8 = undefined;
    std.mem.writeInt(u32, &hash, crc, .big);
    return .{ .hash = hash, .next = next };
}

/// Continue a CRC32 over more bytes (EIP-2124 folds each fork value into the
/// running checksum of the genesis hash).
fn updateCrc(prev: u32, data: []const u8) u32 {
    var crc: u32 = ~prev;
    for (data) |byte| {
        crc ^= byte;
        for (0..8) |_| {
            const mask: u32 = @bitCast(-@as(i32, @intCast(crc & 1)));
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    return ~crc;
}

const testing = std.testing;

test "forkid for an all-at-genesis chain is CRC32(genesis)" {
    const gh = [_]u8{
        0xe0, 0xdc, 0x4d, 0x42, 0xe7, 0x49, 0xde, 0x20, 0xb6, 0x84, 0x50, 0xef, 0x23, 0x18, 0x5a, 0xd6,
        0x35, 0x60, 0x52, 0xc0, 0xca, 0xe6, 0x5b, 0xea, 0xd4, 0x1c, 0x72, 0x54, 0x94, 0x50, 0x76, 0x37,
    };
    const id = compute(gh, &.{}, 0);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xf7, 0x65, 0x0e, 0x8e }, &id.hash);
    try testing.expectEqual(@as(u64, 0), id.next);
}

test "crc32 known vector" {
    // CRC32("123456789") = 0xCBF43926
    try testing.expectEqual(@as(u32, 0xCBF4_3926), crc32("123456789"));
}
