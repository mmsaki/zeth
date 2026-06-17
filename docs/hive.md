# Running zeth in hive

[hive](https://github.com/ethereum/hive) builds zeth into a Docker image and drives it
through the EF's simulators — the Execution Spec Tests over the wire and the JSON-RPC /
Engine API of a running node.

Simulators that apply to zeth:

- `ethereum/eels/consume-rlp` — imports EEST blockchain fixtures as RLP blocks (default)
- `ethereum/eels/consume-engine` — feeds fixtures via `newPayload` / `forkchoiceUpdated`
- `ethereum/rpc-compat` — `eth_*` RPC conformance

## First-time setup

`make test-hive` expects a built [ethereum/hive](https://github.com/ethereum/hive)
checkout at `./hive` (it calls `cd hive && ./hive …`). The Makefile does **not** clone or
build it — do that once. Needs Go and a running Docker daemon.

```sh
git clone https://github.com/ethereum/hive   # into ./hive
cd hive && go build . && cd ..                # produces the ./hive binary
docker info >/dev/null && echo "docker ready" # hive drives client containers
```

`make hive-stage` only creates `hive/clients/zeth/` and copies the adapter in — if you
see `./hive: No such file or directory`, the checkout above is missing.

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
