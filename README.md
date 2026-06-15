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

```sh
make test          # Zig unit tests
make eels          # TrieTests + a slice of GeneralStateTests, root-checked
make conformance   # GeneralStateTests (stops at the first failure)
make hive-tests    # BlockchainTests (stops at the first failure)
make report        # full sweep of both suites: ✓/✗ graph + pass rate
```

`make conformance` and `make hive-tests` stop at the first failure (like a
compiler). Prefix with `ALL=1` to run the whole suite past failures:

```sh
ALL=1 make hive-tests
```

Official fixtures live under `ethereum-tests/` (gitignored). `ZETH_TRACE=1`
prints a per-opcode execution trace; `ZETH_DATA=N` runs only data index `N`.

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
| `tools/` | conformance runners (`statetest`, `blocktest`, `eels`) |
