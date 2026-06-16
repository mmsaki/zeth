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

## Running a node / networking

zeth can serve JSON-RPC + the Engine API, persist to disk (`--datadir`), and
**sync a chain from a real peer over devp2p** (RLPx + eth/69) — verified against
geth on a Kurtosis devnet (synced 233 blocks; head hash matched geth exactly).

- **[docs/production.md](docs/production.md)** — what works today vs what's left,
  how to run the node, and an honest production-readiness status. **Read this
  before running zeth anywhere that matters — it is not yet a mainnet client.**
- **[docs/kurtosis.md](docs/kurtosis.md)** — stand up a local devnet and test
  zeth against a real geth/reth node (handshake + header download).

```sh
# Sync from a peer on startup, persist, then serve JSON-RPC — a syncing node:
zeth node <genesis.json> --peer=<enode://…> --datadir=DIR --http.addr=HOST:PORT

zeth node <genesis.json> [chain.rlp ...] --datadir=DIR   # import/serve, no peer
zeth sync <enode://…> <genesis.json> --datadir=DIR       # sync-only into a datadir
zeth p2p  <enode://…> <networkId> <genesisHash>          # devp2p interop probe
```

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
| `src/chain.zig` | block-import pipeline + in-memory chain |
| `src/db.zig`, `src/store.zig` | durable KV store + typed block/state persistence |
| `src/ecies.zig`, `src/secp.zig`, `src/rlpx.zig`, `src/handshake.zig` | devp2p transport (ECIES, ECDSA, RLPx frames, auth/ack) |
| `src/eth_proto.zig`, `src/forkid.zig`, `src/peer.zig` | eth/69 messages, EIP-2124 forkid, TCP peer |
| `tools/` | fixture-test runners (`statetest`, `blocktest`, `eels`) |
