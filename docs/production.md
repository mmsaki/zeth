# Running zeth — status, usage, and the road to production

> **Read this first.** zeth is a from-scratch Ethereum **execution-layer** client
> with a complete, conformance-tested Prague/Cancun EVM and a working devp2p
> transport. It is **not yet a production mainnet node.** Do **not** run it on
> Ethereum mainnet (or any network holding real value) as your only client, and
> do not rely on it for validator duties. The sections below are explicit about
> what is and isn't ready so you can use it where it's genuinely solid today.

## What works today (and is tested)

| Area | Status | Evidence |
|---|---|---|
| **EVM** (Frontier→Prague + Osaka opcodes) | ✅ solid | EEST: Prague 20858/1, Cancun 17682/3; `ethereum-tests` BlockchainTests 38885/0 |
| Precompiles incl. bn254, **BLS12-381**, **KZG** | ✅ | conformance suites |
| EIP-7702 set-code, EIP-7685 requests, EIP-4844 blobs | ✅ | EEST Prague suites green |
| **Block import** pipeline (state/tx/receipt/bloom roots, gas) | ✅ | `chain.importDecoded` + conformance |
| **JSON-RPC** (`eth_*`, `debug_*` traces) + **Engine API** (`engine_*` + JWT) | ✅ usable | hive `rpc-compat` / `consume-engine` |
| **Persistence** (`--datadir`: snapshot + resume) | ✅ | round-trips genesis state across restart |
| **devp2p transport** (ECIES, RLPx, eth/69 handshake) | ✅ validated vs geth | see [kurtosis.md](./kurtosis.md) |
| Peer **header download** (`GetBlockHeaders`) | ✅ | downloads from geth |

## What is NOT ready (required before mainnet)

- **Full P2P sync loop.** Header download works; the
  header→body→execute→persist loop that actually advances the chain from peers
  is not wired up yet (tracked as the next milestone).
- **Peer discovery (discovery v4/v5).** zeth can't *find* peers — you must hand
  it an enode. No DHT, no bootnodes.
- **Transaction pool / gossip.** No mempool, no tx propagation.
- **Multi-peer management & reorgs.** Single-peer probe today; no peer set,
  scoring, or deep fork-choice/reorg handling.
- **snap sync.** Full (execute-every-block) sync only, once the loop lands;
  no state-range download.
- **Robustness/DoS hardening.** The EVM maps call depth onto native recursion
  (run on a large-stack thread as a workaround, not an iterative interpreter);
  adversarial-input fuzzing and resource limits are not done. Not safe to expose
  to untrusted peers at scale.
- **Pre-Berlin forks** (Frontier→Istanbul historical gas schedules) are
  incomplete — irrelevant for mainnet (post-merge) but worth knowing.

## Where you *can* use it today

1. **As a conformance / execution engine.** Run the EVM against EEST or
   `ethereum-tests` fixtures (`make test-eest`, `make test-ethereum`). This is
   the most mature surface.
2. **In hive simulators** (`make test-hive`) — `consume-rlp`, `consume-engine`,
   `rpc-compat`. The post-merge, Engine-API-driven path is the most complete
   end-to-end exercise.
3. **On a local devnet, driven by a consensus client over the Engine API.** On a
   Kurtosis devnet, a CL can drive zeth via `engine_newPayload` /
   `engine_forkchoiceUpdated` and zeth executes + persists. This is the closest
   thing to "running a node" that's solid today. (Block *gossip* between EL peers
   is the missing piece — see the sync milestone.)
4. **As a devp2p interop probe** (`zeth p2p <enode>`) — see [kurtosis.md](./kurtosis.md).

## Running the node

```sh
zig build -Doptimize=ReleaseFast

# Serve JSON-RPC (:8545) + Engine API (:8551, JWT) from a genesis, persisting to disk.
./zig-out/bin/zeth node <genesis.json> [chain.rlp ...] \
    --datadir=/path/to/data \
    --http.addr=0.0.0.0:8545 \
    --authrpc.addr=0.0.0.0:8551 \
    --authrpc.jwtsecret=/path/to/jwt.hex

# Restart with the same --datadir and no RLP → resumes from disk.
```

Flags: `--http.addr`, `--authrpc.addr`, `--authrpc.jwtsecret`, `--datadir`.

### As a hive client

`make hive-stage` cross-compiles a static-Linux binary and stages the client
adapter into `hive/clients/zeth/`. Then, from the hive checkout:

```sh
./hive --client zeth --sim ethereum/eels/consume-engine \
       --sim.buildarg disable_strict_exception_matching=zeth
```

## Roadmap to production (what's left)

In rough dependency order:

1. **P2P full sync loop** — drive `GetBlockHeaders`→`GetBlockBodies`→
   `importDecoded`→store over a peer connection; resolve the chain head and
   follow it. *(next milestone)*
2. **Discovery v4/v5** — find peers without a hardcoded enode.
3. **Transaction pool + gossip** — accept, validate, propagate, and include txs.
4. **Multi-peer + reorgs** — peer set, scoring, and robust fork choice.
5. **snap sync** — state-range download for fast initial sync.
6. **Hardening** — iterative EVM (drop the large-stack workaround), input
   fuzzing, resource/DoS limits, long-running soak tests.
7. **Mainnet shadow-fork soak** — run alongside a reference client on a
   shadow/forked mainnet for an extended period before anyone trusts it.

Until at least 1–4 and 6 are done and soak-tested, treat zeth as a **devnet /
testnet / conformance** client, not a mainnet one.
