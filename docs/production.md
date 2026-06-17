# Running zeth — status, usage, and the road to production

> **Read this first.** zeth is a from-scratch Ethereum **execution-layer** client
> with a complete, conformance-tested Frontier→Prague EVM, a working devp2p stack
> (incl. the real mainnet forkid), a mempool + block producer, and the Engine API.
> It is **not yet a production mainnet node.** Do **not** run it on Ethereum mainnet
> (or any network holding real value) as your only client, and do not rely on it for
> validator duties. The sections below are explicit about what is and isn't ready.

## What works today (and is tested)

| Area | Status | Evidence |
|---|---|---|
| **EVM** (Frontier→Prague + Osaka opcodes) | ✅ solid | EEST through Prague; `ethereum-tests` BlockchainTests green |
| Precompiles incl. bn254, **BLS12-381**, **KZG** | ✅ | conformance suites |
| EIP-7702 set-code, EIP-7685 requests, EIP-4844 blobs | ✅ | EEST Prague suites |
| **EIP-7825** tx gas-limit cap (Osaka/Fusaka) | ✅ | EEST Osaka `eip7825…` blockchain 5/5 + state 5/5 |
| **Block import** (state/tx/receipt/bloom roots, gas) | ✅ | `chain.importDecoded` + conformance; full Frontier→Prague chain, head matches geth |
| **Mempool** (replace-by-fee, nonce-ordered selection) | ✅ | `src/mempool.zig`; `eth_sendRawTransaction` admits to the pool |
| **Block producer** (build + self-validate next block) | ✅ | `chain.produceBlock`; `zeth produce` re-imports the built block, every root re-checked |
| **JSON-RPC** (`eth_*`, `debug_*` traces) | ✅ usable | hive `rpc-compat` |
| **Engine API** incl. **block building** | ✅ | `newPayload` / `forkchoiceUpdated(attrs)→payloadId` / `getPayload`; round-trips VALID |
| **Persistence** (`--datadir`: snapshot + resume) | ✅ | round-trips genesis state across restart |
| **devp2p transport** (ECIES, RLPx, eth/69, snap/1) | ✅ vs geth | [kurtosis.md](./kurtosis.md) |
| **EIP-2124 forkid** (real mainnet schedule) | ✅ | verified vs canonical EIP-2124 vectors; accepted by live mainnet geth |
| **Live mainnet handshake + holds a peer** | ✅ | dials mainnet geth, eth/69 Status accepted, `zeth peers` holds peercount=1 |
| **discovery v4** + discovery crawl | ✅ basic | signed ping/pong/findnode/neighbors; `zeth peers` crawls + holds |
| **snap/1 state-range download** | ✅ basic | `snap/1` codec; full devnet state downloaded + root-checked from geth |
| **P2P full sync** (headers→bodies→execute→validate) | ✅ basic | `zeth sync` synced from geth; head hash matched exactly |

## What is NOT ready (required before mainnet)

- **Full mainnet sync at tip.** zeth has snap-downloaded a *devnet's* state and
  full-synced small chains from a single peer, but has not completed a full mainnet
  sync (~25M blocks / hundreds of GB of state). The snap range-proof verifier passes
  on synthetic proofs but **fails on real geth bounded proofs** — an open bug.
- **Robust multi-peer sync.** Single-peer sync + a peer *holder* exist, but not a
  peer *set* that syncs in parallel, scores peers, and recovers from mid-sync drops.
- **Inbound p2p.** zeth dials out and holds peers, but does not yet *listen* for
  inbound connections (no stable node identity / listener), so other clients can't
  dial it (see `hive-client/enode.sh`).
- **Persistent discovery table.** `zeth peers` runs a bounded findnode crawl; there's
  no long-lived Kademlia routing table / continuous bootstrap. Discovery v5 (encrypted
  / ENR / topic) is not started.
- **Tx gossip & block propagation.** A mempool exists, but txs/blocks are not gossiped
  to peers (no `NewPooledTransactionHashes` / block announcement flow).
- **Reorgs / deep fork choice.** No reorg handling beyond linear import.
- **Robustness / DoS hardening.** The EVM maps call depth onto native recursion (run on
  a large-stack thread as a workaround, not an iterative interpreter); adversarial-input
  fuzzing and resource limits are not done. Not safe to expose to untrusted peers at scale.
- **Pre-Berlin historical gas schedules** are incomplete — irrelevant for mainnet
  (post-merge) but worth knowing.

## Where you *can* use it today

1. **As a conformance / execution engine** — `make test-eest`, `make test-ethereum`.
   The most mature surface.
2. **In hive simulators** — `consume-rlp`, `consume-engine`, `rpc-compat`. See
   **[hive.md](./hive.md)**.
3. **As a devnet node driven by a consensus client over the Engine API** — a CL drives
   zeth via `newPayload` / `forkchoiceUpdated`, and zeth executes, builds blocks
   (`getPayload`), and persists. Closest thing to "running a node" that's solid today.
   See **[kurtosis.md](./kurtosis.md)**.
4. **As a block-building / mempool sandbox** — `zeth produce`, the pool, and Engine
   `getPayload` give a hackable base for builder/PBS experiments.
5. **As a devp2p interop probe + peer holder** — `zeth p2p` / `zeth peers` against a
   real (incl. mainnet) node.

## Running the node

```sh
zig build -Doptimize=ReleaseFast

# Sync from a peer on startup, persist to disk, then serve JSON-RPC + Engine API:
./zig-out/bin/zeth node <genesis.json> \
    --peer=<enode://…> --datadir=/path/to/data \
    --http.addr=0.0.0.0:8545 \
    --authrpc.addr=0.0.0.0:8551 --authrpc.jwtsecret=/path/to/jwt.hex

# Restart with the same --datadir → resumes from disk.
```

The genesis you pass must byte-match the network's (the loader reproduces geth's genesis
header for config-style genesis files).

### As a hive client

See **[hive.md](./hive.md)** — `make hive-stage` cross-compiles a static-Linux binary and
stages the client adapter; then run the simulators from the hive checkout.

## Roadmap to production (what's left)

In rough dependency order:

1. **Full mainnet snap sync** — fix the real-geth range-proof verification, then snap a
   mainnet pivot's state and heal to the tip. (Biggest single gap.)
2. **Multi-peer sync + inbound listener** — a peer set that syncs in parallel, recovers
   from drops, and accepts inbound connections (real enode for hive peer tests).
3. **Persistent discovery** — a live Kademlia routing table + bootstrap (then v5/ENR).
4. **Tx + block gossip** — propagate pool txs and new blocks to peers.
5. **Reorgs** — robust fork choice across competing branches.
6. **Hardening** — iterative EVM (drop the large-stack workaround), input fuzzing,
   resource/DoS limits, long-running soak tests.
7. **Mainnet shadow-fork soak** — run alongside a reference client on a shadow/forked
   mainnet for an extended period before anyone trusts it.

Until at least 1–3 and 6 are done and soak-tested, treat zeth as a **devnet / testnet /
conformance** client, not a mainnet one.
