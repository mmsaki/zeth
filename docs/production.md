# Running zeth — status, usage, and the road to production

> **Read this first.** zeth is a from-scratch Ethereum **execution-layer** client
> with a complete, conformance-tested Frontier→Prague EVM, a working devp2p stack
> (incl. the real mainnet forkid), a mempool + block producer, and the Engine API.
> It is **not yet a production mainnet node.** Do **not** run it on Ethereum mainnet
> (or any network holding real value) as your only client, and do not rely on it for
> validator duties. The sections below are explicit about what is and isn't ready.

## What works today (and is tested)

- [x] **EVM** (Frontier→Prague + Osaka opcodes) — conformance-tested via EEST and `ethereum-tests`
- [x] **Precompiles** incl. bn254, BLS12-381, KZG
- [x] **EIP-7702** set-code, **EIP-7685** requests, **EIP-4844** blobs
- [x] **EIP-7825** transaction gas-limit cap (Osaka/Fusaka)
- [x] **Block import** — state/tx/receipt/bloom roots + gas; imports the full Frontier→Prague chain, head matching geth
- [x] **Mempool** — replace-by-fee, nonce-ordered selection; `eth_sendRawTransaction` admits to the pool
- [x] **Block producer** — builds and self-validates the next block (`zeth produce` re-imports it, every root re-checked)
- [x] **JSON-RPC** — `eth_*`, `debug_*` traces
- [x] **Engine API** incl. block building — `newPayload` / `forkchoiceUpdated(attrs)→payloadId` / `getPayload`
- [x] **Persistence** — `--datadir` snapshot + resume across restart
- [x] **devp2p transport** — ECIES, RLPx, eth/69, snap/1 (validated against geth)
- [x] **EIP-2124 forkid** — real mainnet schedule; accepted by live mainnet geth
- [x] **Live mainnet handshake + holds a peer** — dials mainnet geth, eth/69 Status accepted, connection held
- [x] **discovery v4** — signed ping/pong/findnode/neighbors + a discovery crawl
- [x] **snap/1 state-range download** — verified against a devnet geth
- [x] **P2P full sync** — headers→bodies→execute→validate from a peer

See [kurtosis.md](./kurtosis.md) for the networking surfaces and [hive.md](./hive.md)
for the conformance harness.

## What is NOT ready (required before mainnet)

- [ ] **Full mainnet sync at tip** — only devnet state + small single-peer chains so far;
  the snap range-proof verifier still fails on real geth bounded proofs.
- [ ] **Robust multi-peer sync** — a peer *set* that syncs in parallel, scores peers, and
  recovers from mid-sync drops (today: single-peer sync + a peer holder).
- [ ] **Inbound p2p** — zeth dials out and holds peers but does not yet *listen* for
  inbound connections (no stable node identity / listener).
- [ ] **Persistent discovery** — a long-lived routing table + continuous bootstrap
  (today: a bounded crawl). Discovery v5 / ENR not started.
- [ ] **Tx + block gossip** — propagate pool txs and new blocks to peers.
- [ ] **Reorgs / deep fork choice** — beyond linear import.
- [ ] **Robustness / DoS hardening** — iterative EVM (drop the large-stack workaround),
  input fuzzing, resource limits.
- [ ] **Pre-Berlin historical gas schedules** — incomplete (irrelevant for post-merge mainnet).

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
