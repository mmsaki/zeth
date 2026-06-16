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
| **P2P full sync** (headers→bodies→execute→validate) | ✅ basic | `zeth sync` synced 233 blocks from geth; head hash matched exactly |
| **Continuous live-head follow** (`zeth sync --follow`) | ✅ basic | tracked geth's live head #336→#337→#338 |

## What is NOT ready (required before mainnet)

- **Robust multi-peer sync.** Batch sync, persisting to `--datadir`, and
  following the live head (`zeth sync --follow`) all work against a single peer.
  Still missing: recovering from a peer that drops mid-sync, and pulling from a
  *set* of peers rather than one.
- **Peer discovery (discovery v4/v5).** The discovery v4 wire codec (signed
  ping/pong/findnode/neighbors + a bonding/`FindNode` flow) is implemented and
  unit-tested (`src/discv4.zig`), but not yet wired into a live routing table /
  bootstrap loop — so in practice you still hand zeth an enode. Discovery v5
  (the encrypted, ENR/topic protocol) is not started.
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

# Sync from a peer on startup, persist to disk, then serve JSON-RPC + Engine API:
./zig-out/bin/zeth node <genesis.json> \
    --peer=<enode://…> \
    --datadir=/path/to/data \
    --http.addr=0.0.0.0:8545 \
    --authrpc.addr=0.0.0.0:8551 \
    --authrpc.jwtsecret=/path/to/jwt.hex

# Restart with the same --datadir → resumes from disk (re-syncs only new blocks).
```

Flags: `--peer`, `--http.addr`, `--authrpc.addr`, `--authrpc.jwtsecret`, `--datadir`.
The genesis you pass must byte-match the network's (the loader reproduces geth's
genesis header for config-style genesis files). Sync currently catches up to the
head learned at the handshake; it does not yet follow the live head.

### As a hive client

`make hive-stage` cross-compiles a static-Linux binary and stages the client
adapter into `hive/clients/zeth/`. Then, from the hive checkout:

```sh
./hive --client zeth --sim ethereum/eels/consume-engine \
       --sim.buildarg disable_strict_exception_matching=zeth
```

## Roadmap to production (what's left)

In rough dependency order:

1. **P2P full sync** — ✅ done (`zeth sync`): header→body→execute→validate from a
   peer, persist to `--datadir` during sync, and follow the live head
   (`--follow`). *Remaining:* handle mid-sync peer drops and pull from a peer set.
2. **Discovery v4/v5** — wire codec done (`src/discv4.zig`, unit-tested);
   *remaining:* a live routing table + bootstrap loop so zeth can find peers
   without a hardcoded enode. Discovery v5 (encrypted/ENR) not started.
3. **Transaction pool + gossip** — accept, validate, propagate, and include txs.
4. **Multi-peer + reorgs** — peer set, scoring, and robust fork choice.
5. **snap sync** — state-range download for fast initial sync.
6. **Hardening** — iterative EVM (drop the large-stack workaround), input
   fuzzing, resource/DoS limits, long-running soak tests.
7. **Mainnet shadow-fork soak** — run alongside a reference client on a
   shadow/forked mainnet for an extended period before anyone trusts it.

Until at least 1–4 and 6 are done and soak-tested, treat zeth as a **devnet /
testnet / conformance** client, not a mainnet one.
