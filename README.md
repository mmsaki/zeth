# zeth ⚡

**An Ethereum execution client, written from scratch in Zig.**

No GC. No framework. A single static binary that speaks the real protocol —
ported line-for-line against the [execution-specs](https://github.com/ethereum/execution-specs),
so correctness comes from the spec, not from copying another client.

It already:

- [x] **Passes the official tests** — the EF trie tests and the Execution Spec Tests
  across every fork **Frontier → Prague** (plus Osaka/Fusaka EIPs). Imports the full
  historical chain with the head hash matching geth **exactly**.
- [x] **Builds blocks** — a mempool + producer that assembles the next block and
  **self-validates** it (re-imports and re-checks every root), wired to the Engine API
  (`forkchoiceUpdated → getPayload`).
- [x] **Talks to mainnet** — RLPx, eth/69, snap/1, discovery v4, and the real EIP-2124
  forkid. zeth handshakes **live mainnet geth** and **holds the peer**.
- [x] **Built for speed** — a no-GC interpreter with built-in `Mgas/s` benchmarks to
  race it against geth and reth.

> ⚠️ Honest status: zeth is a **conformance-grade EVM and a devnet/testnet node** — not
> yet a production mainnet client. See **[docs/production.md](docs/production.md)** for
> exactly what's ready and what isn't.

## Get hooked in 60 seconds

```sh
git clone https://github.com/mmsaki/zeth && cd zeth
zig build -Doptimize=ReleaseFast       # needs Zig 0.17.0-dev.702 (pinned)

# Run some EVM bytecode (PUSH1 6, PUSH1 7, ADD):
./zig-out/bin/zeth run 6006600701

# How fast is the interpreter?
./zig-out/bin/zeth bench-evm           # → Mgas/s + ns/op

# Build a real block from a signed transaction and prove it's valid:
./zig-out/bin/zeth produce genesis.json --tx=0x… # → "self-validated ✓ head now block 1"

# Dial and hold a live mainnet peer (discovery + eth/69 handshake):
./zig-out/bin/zeth peers <enode://…> 1 <genesisHash>   # → holds peers, logs a live peercount
```

## Prove it — run the tests

```sh
make test           # our Zig unit tests (fast inner loop)
make test-eest      # the modern EF Execution Spec Tests, all forks (local)
make test-ethereum  # the classic ethereum/tests: state + blockchain + trie
make test-all       # everything local, no Docker
make test-hive      # the EF's hive harness drives a live zeth (see docs/hive.md)
```

`make test-eest` runs the *exact* fixtures the EF uses to grade clients — locally and
fast. The fixture runners take flags directly (`--all`, `--fork <name>`, `--trace`):

```sh
./zig-out/bin/blocktest --all --fork Prague eest-fixtures/blockchain_tests
```

## What people use zeth for

- **A reference / conformance EVM.** Spec-faithful, gas-exact, easy to read — a clean
  oracle for fixtures, differential testing, or checking another implementation.
- **A devnet / testnet node.** Serves JSON-RPC + the Engine API with JWT, persists to
  `--datadir`, and is driven by a real consensus client over `engine_newPayload` /
  `forkchoiceUpdated`. Stand one up in minutes with **[docs/kurtosis.md](docs/kurtosis.md)**.
- **Block-building & mempool experiments.** A working producer + pool + Engine
  `getPayload` — a hackable base for builder/MEV/PBS tinkering you fully control.
- **devp2p & networking research.** Real RLPx/eth-69/snap-1/discovery against live
  mainnet — handshakes, forkid, peer-holding, state-range probing.
- **Performance work.** A no-GC, single-binary EVM with built-in `Mgas/s` benchmarks —
  a place to push interpreter throughput and race the incumbents.
- **Learning the protocol.** The cleanest way to *read* how Ethereum execution works,
  one spec rule at a time, in a small language.

## Run it as a node

```sh
# Sync from a peer, persist, serve JSON-RPC + Engine API:
zeth node <genesis.json> --peer=<enode://…> --datadir=DIR \
     --http.addr=0.0.0.0:8545 --authrpc.addr=0.0.0.0:8551 --authrpc.jwtsecret=jwt.hex

zeth node <genesis.json> [chain.rlp ...] --datadir=DIR   # import/serve, no peer
zeth sync <enode://…> <genesis.json> --datadir=DIR       # sync-only into a datadir
```

`zeth p2p`/`zeth peers` default to mainnet genesis + forkid for `networkId 1`.

## Benchmark it

```sh
make bench                                   # cross-client: gas-correctness + Mgas/s vs geth/revm/evmone
zeth bench <genesis.json> <chain.rlp ...>    # block-processing Mgas/s (feed it real mainnet blocks)
zeth bench-evm [gas]                         # pure EVM-dispatch Mgas/s + ns/op
```

## Docs

| | |
|---|---|
| **[docs/production.md](docs/production.md)** | Honest readiness status — what works, what's left. **Read first.** |
| **[docs/kurtosis.md](docs/kurtosis.md)** | Test zeth against a real geth/reth devnet node. |
| **[docs/hive.md](docs/hive.md)** | Run the EF's hive simulators against zeth. |

The implementation is under `src/` (EVM, state/trie, tx/chain, precompiles + curve crypto,
the devp2p stack, RPC) with the fixture runners in `tools/`. The tree moves fast — read the
source; `build.zig` and `src/root.zig` are the entry points.

---

Built in the open as independent Ethereum protocol work. Contributions, spec
clarifications, and benchmarks welcome.
