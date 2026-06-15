//! Zetherum — a Zig implementation of the Ethereum execution layer.
//!
//! Current surface: the Frontier-fork EVM interpreter core (state-independent
//! opcodes). See `vm.zig` for the interpreter and `word.zig` for 256-bit math.

const std = @import("std");

pub const word = @import("word.zig");
pub const vm = @import("vm.zig");
pub const crypto = @import("crypto.zig");
pub const state = @import("state.zig");
pub const rlp = @import("rlp.zig");
pub const trie = @import("trie.zig");
pub const tx = @import("tx.zig");
pub const precompiles = @import("precompiles.zig");

pub const Evm = vm.Evm;
pub const Op = vm.Op;
pub const VmError = vm.VmError;
pub const Environment = vm.Environment;
pub const Message = vm.Message;
pub const State = state.State;
pub const Address = state.Address;

test {
    // Pull in the unit tests of every module.
    std.testing.refAllDecls(@This());
}
