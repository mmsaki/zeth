# Zetherum

A Zig implementation of the Ethereum execution layer, ported faithfully from
the Python [execution-specs](https://github.com/ethereum/execution-specs)
(EELS) — the canonical, executable specification of the state-transition
function. The specs are vendored under `execution-specs/` and used as the
source of truth for every opcode, gas cost, and edge case.

> Reference clients like reth / zevm / gevm are consulted only for orientation;
> all behavior here is derived from the execution-specs.

## Status

The **Frontier-fork EVM interpreter** is implemented end to end:

| Area | Opcodes |
| --- | --- |
| Arithmetic | `ADD SUB MUL DIV SDIV MOD SMOD ADDMOD MULMOD EXP SIGNEXTEND` |
| Comparison / bitwise | `LT GT SLT SGT EQ ISZERO AND OR XOR NOT BYTE` |
| Keccak | `KECCAK256` |
| Environment | `ADDRESS BALANCE ORIGIN CALLER CALLVALUE CALLDATA* CODE* GASPRICE EXTCODE*` |
| Block | `BLOCKHASH COINBASE TIMESTAMP NUMBER DIFFICULTY GASLIMIT` |
| Storage | `SLOAD SSTORE` (with refunds) |
| Memory | `MLOAD MSTORE MSTORE8 MSIZE` |
| Control flow | `JUMP JUMPI PC GAS JUMPDEST STOP` |
| Stack | `PUSH1..32 DUP1..16 SWAP1..16 POP` |
| Logging | `LOG0..4` |
| System | `CREATE CALL CALLCODE RETURN SELFDESTRUCT` (full recursion + snapshots) |

Backed by an in-memory world state (accounts, balances, nonces, code, storage)
with deep-clone snapshots for revert-on-error, Keccak-256, and a minimal RLP
encoder for `CREATE` address derivation.

**Known gaps** (next milestones): precompiled contracts (`0x01`–`0x04`),
transaction & block processing, the Merkle-Patricia trie / state root, later
fork rules, and the networking + JSON-RPC layers.

## Layout

```
src/
  word.zig    256-bit EVM word arithmetic (native u256)
  crypto.zig  Keccak-256
  rlp.zig     minimal RLP encoder
  state.zig   accounts, storage, snapshots, CREATE addresses
  vm.zig      opcodes, gas, the interpreter, CALL/CREATE drivers
  main.zig    `zig build run` CLI
  root.zig    library root / public API
bench/
  main.zig    throughput benchmark
```

## Build

Requires Zig `0.17.0-dev` (see `build.zig.zon`).

```sh
make build        # compile
make test         # run the unit tests
make bench        # cross-client benchmark vs geth (and reth/evmone if present)
make bench-loop   # internal single-engine throughput loop (poop-style)
make run ARGS="0x6006600701"   # execute hex bytecode (PUSH1 6, PUSH1 7, ADD)
make fmt          # format sources
```

## Benchmark

`make bench` runs a shared corpus of feature-spanning programs through zeth and
every reference EVM it can find — **geth** (the bundled `evm` tool), **reth**
(via `revm`, its engine), and **evmone** — then compares **gas** and **speed**:

```
feature              gas        zeth       geth   vs geth
arithmetic      11250003      1124.4      445.0     2.53x
keccak256       17500006       225.3      127.5     1.77x
...
```

The corpus uses only opcodes whose gas is fork-invariant, so a correct engine
reports **identical gas** — making the gas column an opcode-level correctness
oracle (it matches geth exactly). Mgas/s is the speed metric; on Apple silicon
zeth runs ~1.7–2.8× faster than geth's interpreter. Engines are auto-detected;
to add reth's engine, build `bench/revm-runner` (`cargo build --release`).

`make bench-loop` is a [poop](https://github.com/andrewrk/poop)-style internal
comparison (wall/CPU-time mean ± σ, no external clients) for quick regression
checks. Both honor `NO_COLOR`.
