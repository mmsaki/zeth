//! Hardfork identity + activation ordering. The EVM, the transaction layer, and
//! the conformance runners gate EIP-specific behavior on `Fork.atLeast(...)`.
//! Ordered oldest→newest so the integer tags give a total order.

const std = @import("std");

pub const Fork = enum(u8) {
    frontier,
    homestead,
    tangerine_whistle, // EIP-150
    spurious_dragon, // EIP-158
    byzantium,
    constantinople,
    petersburg, // a.k.a. ConstantinopleFix
    istanbul,
    muir_glacier,
    berlin,
    london,
    arrow_glacier,
    gray_glacier,
    paris, // The Merge
    shanghai,
    cancun,
    prague,
    osaka,

    /// True when `self` is `other` or any later fork — the activation predicate.
    pub inline fn atLeast(self: Fork, other: Fork) bool {
        return @intFromEnum(self) >= @intFromEnum(other);
    }

    /// Resolve a test-fixture network name (e.g. "Cancun", "Prague") to a Fork.
    pub fn fromName(name: []const u8) ?Fork {
        const table = .{
            .{ "Frontier", Fork.frontier },
            .{ "Homestead", Fork.homestead },
            .{ "EIP150", Fork.tangerine_whistle },
            .{ "EIP158", Fork.spurious_dragon },
            .{ "Byzantium", Fork.byzantium },
            .{ "Constantinople", Fork.constantinople },
            .{ "ConstantinopleFix", Fork.petersburg },
            .{ "Petersburg", Fork.petersburg },
            .{ "Istanbul", Fork.istanbul },
            .{ "MuirGlacier", Fork.muir_glacier },
            .{ "Berlin", Fork.berlin },
            .{ "London", Fork.london },
            .{ "ArrowGlacier", Fork.arrow_glacier },
            .{ "GrayGlacier", Fork.gray_glacier },
            .{ "Merge", Fork.paris },
            .{ "Paris", Fork.paris },
            .{ "Shanghai", Fork.shanghai },
            .{ "Cancun", Fork.cancun },
            .{ "Prague", Fork.prague },
            .{ "Osaka", Fork.osaka },
        };
        inline for (table) |e| {
            if (std.mem.eql(u8, name, e[0])) return e[1];
        }
        return null;
    }
};
