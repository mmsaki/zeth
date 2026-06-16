# zeth

A Zig implementation of the Ethereum execution layer (EVM, state, MPT, transaction
and block processing), targeting the **Prague** fork. Ported against the
[execution-specs](https://github.com/ethereum/execution-specs) as the source of truth.

## Requirements

- Zig `0.17.0-dev.702` (pinned in `build.zig.zon`)
- Python 3 (optional, for the cross-client benchmark)

## Build

```sh
make build                          # debug build → zig-out/bin
zig build -Doptimize=ReleaseFast    # optimized
```

## Run bytecode

```sh
make run ARGS="6006600701"   # PUSH1 6, PUSH1 7, ADD
```

Prints gas used, the stack, and memory.

## Tests

Tests are grouped by **where the fixtures come from**:

```sh
make test           # unit tests — our own Zig `test {}` blocks (fast inner loop)
make test-ethereum  # ethereum/tests   — classic EF repo: state + blockchain + trie
make test-eest      # execution-spec-tests — modern EF fixtures, ALL forks (local)
make test-hive      # hive — Docker: drives the EEST fixtures at a live zeth over RPC
make test-all       # everything local (no Docker): the three above
```

`test-eest` runs the *same* fixtures hive feeds the client, just locally and far
faster. Populate them once (extracted from the hive simulator image, ~4 GB):

```sh
make fixtures-eest
```

The two fixture runners (`blocktest`, `statetest`) take flags directly:

```sh
./zig-out/bin/blocktest --all --fork London eest-fixtures/blockchain_tests
#   --all   run past failures   --fork <name>  one fork only
#   --import drive the real node pipeline   --trace  per-opcode trace
```

Without `--all` they stop at the first failure (like a compiler). Run
`blocktest --help` / `statetest --help` for the full flag list. Fixtures live
under `ethereum-tests/` and `eest-fixtures/` (both gitignored).

## Benchmark

```sh
make bench         # cross-client throughput vs geth / reth (revm) / evmone
```

Reference engines are auto-detected; whatever is installed is included. Gas
doubles as a correctness oracle (a correct engine reports identical gas),
alongside Mgas/s throughput.

## Layout

| Path | What |
|------|------|
| `src/vm.zig` | EVM interpreter |
| `src/state.zig`, `src/trie.zig` | account state + Merkle-Patricia trie |
| `src/tx.zig` | transaction processing + validation |
| `src/precompiles.zig` | precompiles (incl. bn254, BLS12-381, KZG) |
| `src/bn254.zig`, `src/bls12_381.zig` | pairing-friendly curve crypto |
| `tools/` | fixture-test runners (`statetest`, `blocktest`, `eels`) |
