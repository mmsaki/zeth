# Running zeth in hive

[hive](https://github.com/ethereum/hive) builds zeth into a Docker image and drives it
through the EF's simulators — the Execution Spec Tests over the wire and the JSON-RPC /
Engine API of a running node.

Simulators that apply to zeth:

- `ethereum/eels/consume-rlp` — imports EEST blockchain fixtures as RLP blocks (default)
- `ethereum/eels/consume-engine` — feeds fixtures via `newPayload` / `forkchoiceUpdated`
- `ethereum/rpc-compat` — `eth_*` RPC conformance

## Run

```sh
make test-hive                                            # consume-rlp
make test-hive ARGS="--sim ethereum/eels/consume-engine"
```

`make test-hive` runs `make hive-stage` first: it cross-compiles a static-Linux zeth and
copies the client adapter from `hive-client/` (Dockerfile, `zeth.sh`, `mapper.jq`,
`enode.sh`) into `hive/clients/zeth/`. Loop: edit → `make hive-stage` → `./hive …`.
Results land in `hive/workspace/logs/`.

If `consume-engine`'s strict exception matching trips while iterating, relax it:
`--sim.buildarg disable_strict_exception_matching=zeth`.

The same fixtures run locally without Docker (faster): `make fixtures-eest` once, then
`make test-eest`.
