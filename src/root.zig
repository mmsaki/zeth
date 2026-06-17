//! Zeth — a Zig implementation of the Ethereum execution layer.
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
pub const fork = @import("fork.zig");
pub const block = @import("block.zig");
pub const transaction = @import("transaction.zig");
pub const genesis = @import("genesis.zig");
pub const chain = @import("chain.zig");
pub const rpc = @import("rpc.zig");
pub const db = @import("db.zig");
pub const store = @import("store.zig");
pub const ecies = @import("ecies.zig");
pub const secp = @import("secp.zig");
pub const rlpx = @import("rlpx.zig");
pub const handshake = @import("handshake.zig");
pub const eth_proto = @import("eth_proto.zig");
pub const peer = @import("peer.zig");
pub const forkid = @import("forkid.zig");
pub const discv4 = @import("discv4.zig");
pub const snap_proto = @import("snap_proto.zig");

pub const Evm = vm.Evm;
pub const Op = vm.Op;
pub const VmError = vm.VmError;
pub const Environment = vm.Environment;
pub const Message = vm.Message;
pub const State = state.State;
pub const Address = state.Address;
pub const Fork = fork.Fork;

test {
    // Pull in the unit tests of every module.
    std.testing.refAllDecls(@This());
}
