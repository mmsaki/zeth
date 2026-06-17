# Running zeth in hive

[hive](https://github.com/ethereum/hive) is the Ethereum Foundation's
integration-test harness: it builds a client into a Docker image and drives it
through simulators that replay the Execution Spec Tests (EEST) and probe the
JSON-RPC / Engine API of a *running* node. It's the most complete end-to-end
exercise of zeth — the same fixtures `make test-eest` runs locally, but driven
over the wire against a live client, exactly as the EF tests every client.

## The simulators that matter for zeth

| Simulator | What it drives | Notes |
|---|---|---|
| `ethereum/eels/consume-rlp` | Imports EEST blockchain fixtures as RLP blocks (the `consume-rlp` path) | The default; broadest fork coverage |
| `ethereum/eels/consume-engine` | Feeds fixtures via `engine_newPayload` / `engine_forkchoiceUpdated` | The post-merge, Engine-API-driven path |
| `ethereum/rpc-compat` | Exercises `eth_*` JSON-RPC against a synced chain | RPC conformance |

## One-shot: `make test-hive`

```sh
make test-hive                                   # default: consume-rlp
make test-hive ARGS="--sim ethereum/eels/consume-engine"
make test-hive ARGS="--sim ethereum/rpc-compat"
```

`test-hive` first runs `make hive-stage` (below), then from the `hive/` checkout:

```sh
cd hive && ./hive --client zeth --docker.nocache 'clients/zeth' \
    --sim ethereum/eels/consume-rlp
```

Results land in `hive/workspace/logs/` — open `hive.json` / the per-suite HTML, or
run hive's `hiveview` to browse them.

## How the client image is built (`make hive-stage`)

hive needs a Linux client binary + a small adapter that tells hive how to launch
and talk to zeth. `make hive-stage`:

1. Cross-compiles a **static-Linux** zeth (`-Dtarget=<linux> -Doptimize=ReleaseFast`
   → `zig-out-linux/`), matching Docker Desktop's platform. Your native `zig-out`
   is left untouched.
2. Copies the adapter from `hive-client/` into `hive/clients/zeth/`:
   - `Dockerfile` — packages the binary into the client image
   - `zeth.sh` — entrypoint; reads hive's env (genesis, JWT, ports) and launches
     `zeth node …` with the right flags
   - `mapper.jq` — maps hive's client-config env → zeth flags
   - `enode.sh` — reports zeth's enode to hive for peer tests
3. Drops the freshly built binary at `hive/clients/zeth/zeth`.

So the loop is: change Zig → `make hive-stage` → `./hive --client zeth …`.

## Strict exception matching

`consume-engine` can assert the *exact* rejection reason for invalid payloads. zeth
maps its internal errors to EEST's exception strings, but if you hit a mismatch you
can relax the check while iterating:

```sh
./hive --client zeth --sim ethereum/eels/consume-engine \
       --sim.buildarg disable_strict_exception_matching=zeth
```

## Local fixtures = the same tests, faster

hive is Docker-heavy and slow to iterate. The **exact** fixtures the
`consume-rlp` / `consume-engine` simulators feed the client are also runnable
locally without Docker:

```sh
make fixtures-eest    # extract the EEST set from the hive image (~4 GB, once)
make test-eest        # run them locally — much faster inner loop
```

Use local EEST for development; use hive to confirm the wire-level / Engine-API
behavior the EF actually grades.

## See also

- **[production.md](./production.md)** — what's tested and what isn't.
- **[kurtosis.md](./kurtosis.md)** — interop against a real geth/reth devnet node.
