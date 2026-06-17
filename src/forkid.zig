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

/// A fork activation point: a block number (pre-Merge) or a unix timestamp
/// (post-Merge). EIP-2124 folds block forks first, then timestamp forks.
pub const Activation = struct { value: u64, is_time: bool };

/// Compute the fork id for a head at (`head_block`, `head_time`) given the
/// genesis hash and the canonical ascending activation `schedule`
/// (deduplicated; block forks before timestamp forks). Forks the head has
/// crossed are folded into the hash; `next` is the first not-yet-crossed
/// activation (0 if none). This is the honest forkid for *any* sync state — at
/// genesis it advertises the Frontier hash with `next` = first fork, exactly how
/// an unsynced node joins the network.
pub fn forkIdAt(genesis_hash: [32]u8, schedule: []const Activation, head_block: u64, head_time: u64) ForkId {
    var passed: [64]u64 = undefined;
    var n: usize = 0;
    var next: u64 = 0;
    for (schedule) |act| {
        const crossed = if (act.is_time) head_time >= act.value else head_block >= act.value;
        if (crossed) {
            passed[n] = act.value;
            n += 1;
        } else {
            next = act.value; // schedule is ordered → first uncrossed is the next fork
            break;
        }
    }
    return compute(genesis_hash, passed[0..n], next);
}

/// Ethereum mainnet (network id 1) genesis block hash.
pub const MAINNET_GENESIS_HASH: [32]u8 = .{
    0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xae, 0xf8, 0xc0, 0x10, 0xb8, 0x6a, 0x40, 0xd5, 0xf5, 0x67,
    0x45, 0xa1, 0x18, 0xd0, 0x90, 0x6a, 0x34, 0xe6, 0x9a, 0xec, 0x8c, 0x0d, 0xb1, 0xcb, 0x8f, 0xa3,
};

/// Mainnet's fork schedule: block-activated forks (Homestead → GrayGlacier;
/// Constantinople+Petersburg share 7280000, folded once) then timestamp forks
/// (Shanghai, Cancun, Prague). The Merge added no forkid entry.
pub const mainnet_schedule = [_]Activation{
    .{ .value = 1150000, .is_time = false }, // Homestead
    .{ .value = 1920000, .is_time = false }, // DAO fork
    .{ .value = 2463000, .is_time = false }, // Tangerine Whistle (EIP-150)
    .{ .value = 2675000, .is_time = false }, // Spurious Dragon (EIP-158)
    .{ .value = 4370000, .is_time = false }, // Byzantium
    .{ .value = 7280000, .is_time = false }, // Constantinople + Petersburg
    .{ .value = 9069000, .is_time = false }, // Istanbul
    .{ .value = 9200000, .is_time = false }, // Muir Glacier
    .{ .value = 12244000, .is_time = false }, // Berlin
    .{ .value = 12965000, .is_time = false }, // London
    .{ .value = 13773000, .is_time = false }, // Arrow Glacier
    .{ .value = 15050000, .is_time = false }, // Gray Glacier
    .{ .value = 1681338455, .is_time = true }, // Shanghai
    .{ .value = 1710338135, .is_time = true }, // Cancun
    .{ .value = 1746612311, .is_time = true }, // Prague
};

/// The mainnet fork id for a node whose head is at (`head_block`, `head_time`).
pub fn mainnet(head_block: u64, head_time: u64) ForkId {
    return forkIdAt(MAINNET_GENESIS_HASH, &mainnet_schedule, head_block, head_time);
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

test "mainnet fork ids match the EIP-2124 vectors" {
    const cases = [_]struct { block: u64, time: u64, hash: [4]u8, next: u64 }{
        .{ .block = 0, .time = 0, .hash = .{ 0xfc, 0x64, 0xec, 0x04 }, .next = 1150000 }, // Frontier
        .{ .block = 1150000, .time = 0, .hash = .{ 0x97, 0xc2, 0xc3, 0x4c }, .next = 1920000 }, // Homestead
        .{ .block = 1920000, .time = 0, .hash = .{ 0x91, 0xd1, 0xf9, 0x48 }, .next = 2463000 }, // DAO
        .{ .block = 4370000, .time = 0, .hash = .{ 0xa0, 0x0b, 0xc3, 0x24 }, .next = 7280000 }, // Byzantium
        .{ .block = 7280000, .time = 0, .hash = .{ 0x66, 0x8d, 0xb0, 0xaf }, .next = 9069000 }, // Constantinople/Petersburg
        .{ .block = 12244000, .time = 0, .hash = .{ 0x0e, 0xb4, 0x40, 0xf6 }, .next = 12965000 }, // Berlin
        .{ .block = 12965000, .time = 0, .hash = .{ 0xb7, 0x15, 0x07, 0x7d }, .next = 13773000 }, // London
    };
    for (cases) |c| {
        const id = mainnet(c.block, c.time);
        try testing.expectEqualSlices(u8, &c.hash, &id.hash);
        try testing.expectEqual(c.next, id.next);
    }
    // Fully synced past Prague → no upcoming fork.
    try testing.expectEqual(@as(u64, 0), mainnet(23_000_000, 1_800_000_000).next);
}
