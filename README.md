# 🦎 zeth

An Ethereum execution-layer client written from scratch in Zig: EVM, state, Merkle-
Patricia trie, transaction and block processing, JSON-RPC + Engine API, and a devp2p
stack. Behavior is ported from the
[execution-specs](https://github.com/ethereum/execution-specs); geth and reth are
referenced only for cross-checking.

Implemented and tested:

- [x] **Conformance** — passes the EF trie tests and the Execution Spec Tests across
  Frontier → Prague (plus Osaka/Fusaka EIPs). Imports the historical chain with the
  head hash matching geth.
- [x] **Block building** — mempool (replace-by-fee, nonce-ordered) + a producer that
  assembles the next block and re-imports it to re-check every root; wired to the
  Engine API (`forkchoiceUpdated(payloadAttributes) → getPayload`).
- [x] **devp2p** — RLPx/ECIES, eth/69, snap/1, discovery v4, and the EIP-2124 mainnet
  forkid. Completes the eth/69 handshake against live mainnet geth and holds the
  connection.
- [x] **EVM throughput** — built-in `Mgas/s` benchmarks (`bench`, `bench-evm`).

**Status:** zeth is a conformance-grade EVM and a devnet/testnet node — not a
production mainnet client. See **[docs/production.md](docs/production.md)** for what is
and isn't ready.

## Quickstart

Requires Zig nightly `0.17.0-dev.702` or newer (minimum set in `build.zig.zon`; install
with `zvm i master`). Full setup — including the
test fixtures, which aren't in the repo — is in **[docs/development.md](docs/development.md)**.

```sh
git clone https://github.com/mmsaki/zeth && cd zeth
zig build -Doptimize=ReleaseFast

./zig-out/bin/zeth run 6006600701            # execute bytecode: PUSH1 6, PUSH1 7, ADD
./zig-out/bin/zeth bench-evm                 # interpreter throughput: Mgas/s + ns/op
./zig-out/bin/zeth produce genesis.json --tx=0x…   # build the next block, re-import to validate roots
./zig-out/bin/zeth peers <enode://…> 1 <genesisHash>   # dial + hold peers, log peercount
```

## Tests

```sh
make test           # Zig unit tests (fast inner loop)
make test-eest      # Execution Spec Tests, all forks (local)
make test-ethereum  # ethereum/tests: state + blockchain + trie
make test-all       # everything local, no Docker
make test-hive      # the hive harness drives a live zeth (see docs/hive.md)
```

Only `make test` runs on a bare clone; the fixture suites need data that isn't in the
repo — see **[docs/development.md](docs/development.md)**. The runners take flags directly
(`--all`, `--fork <name>`, `--trace`):

```sh
./zig-out/bin/blocktest --all --fork Prague eest-fixtures/blockchain_tests
```

## Use cases

- **Reference / conformance EVM** — spec-faithful and gas-exact; an oracle for
  fixtures, differential testing, or validating another implementation.
- **Devnet / testnet EL node** — JSON-RPC + Engine API (JWT), `--datadir` persistence,
  driven by a consensus client over `newPayload` / `forkchoiceUpdated`. Setup in
  **[docs/kurtosis.md](docs/kurtosis.md)**.
- **Block-building / mempool work** — producer + pool + Engine `getPayload` as a base
  for builder/PBS development.
- **devp2p / networking** — RLPx, eth/69, snap/1, discovery v4, and the EIP-2124 forkid
  against live mainnet (handshake, peer-holding, state-range download).
- **EVM performance** — built-in `Mgas/s` benchmarks for interpreter-throughput work.
- **Reading the protocol** — the implementation maps directly to execution-specs rules.

## Running a node

```sh
# Sync from a peer, persist, serve JSON-RPC + Engine API:
zeth node <genesis.json> --peer=<enode://…> --datadir=DIR \
     --http.addr=0.0.0.0:8545 --authrpc.addr=0.0.0.0:8551 --authrpc.jwtsecret=jwt.hex

zeth node <genesis.json> [chain.rlp ...] --datadir=DIR   # import/serve, no peer
zeth sync <enode://…> <genesis.json> --datadir=DIR       # sync-only into a datadir
```

`zeth p2p` / `zeth peers` default to the mainnet genesis + forkid for `networkId 1`.

## Benchmarks

```sh
make bench                                   # cross-client gas-correctness + Mgas/s vs geth/revm/evmone
zeth bench <genesis.json> <chain.rlp ...>    # block-processing Mgas/s (feed it real block RLP)
zeth bench-evm [gas]                         # EVM-dispatch Mgas/s + ns/op
```

## Docs

| | |
|---|---|
| **[docs/development.md](docs/development.md)** | Setup from a clean clone: Zig, build, fixtures. Start here. |
| **[docs/production.md](docs/production.md)** | Readiness status — what works, what's left. |
| **[docs/kurtosis.md](docs/kurtosis.md)** | Test zeth against a geth/reth devnet node. |
| **[docs/hive.md](docs/hive.md)** | Run the hive simulators against zeth. |

Source is under `src/` (EVM, state/trie, tx/chain, precompiles + curve crypto, the
devp2p stack, RPC) with the fixture runners in `tools/`. `build.zig` and `src/root.zig`
are the entry points.
