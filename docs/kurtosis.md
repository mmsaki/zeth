# Testing against a Kurtosis devnet

[Kurtosis](https://docs.kurtosis.com/) + the
[`ethereum-package`](https://github.com/ethpandaops/ethereum-package) run a local
Ethereum network in Docker, so you can point zeth at a real geth/reth node.

Prereqs: Docker, the Kurtosis CLI, and `zig build -Doptimize=ReleaseFast`.

## Start a devnet

```sh
printf 'participants:\n  - el_type: geth\n    cl_type: lighthouse\n' > /tmp/devnet.yaml
kurtosis run --enclave zethnet ./ethereum-package-kurtosis --args-file /tmp/devnet.yaml
kurtosis enclave inspect zethnet   # note geth's mapped rpc + tcp-discovery host ports
```

Dial the **mapped** `127.0.0.1:<P2P_PORT>` — the container's `172.16.x.x` is not
reachable from the host.

## Get enode / network id / genesis, then dial

```sh
RPC=http://127.0.0.1:<RPC_PORT>
ENODE=$(curl -s -X POST -H content-type:application/json --data \
  '{"jsonrpc":"2.0","id":1,"method":"admin_nodeInfo","params":[]}' $RPC | jq -r .result.enode)
DIAL="enode://$(echo "$ENODE" | sed -E 's#enode://([0-9a-f]+)@.*#\1#')@127.0.0.1:<P2P_PORT>"
GH=$(curl -s -X POST -H content-type:application/json --data \
  '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' $RPC | jq -r .result.hash[2:])
NETID=$(curl -s -X POST -H content-type:application/json --data \
  '{"jsonrpc":"2.0","id":1,"method":"net_version","params":[]}' $RPC | jq -r .result)

./zig-out/bin/zeth p2p "$DIAL" "$NETID" "$GH"     # transport + eth/69 handshake probe
```

## Sync from the peer

```sh
docker exec <geth-container> cat /network-configs/genesis.json > /tmp/devnet-genesis.json
./zig-out/bin/zeth sync "$DIAL" /tmp/devnet-genesis.json    # download + execute the chain
```

The synced head hash should match the peer's (`eth_getBlockByNumber`). zeth's genesis
must byte-match the peer's, which is why the same `genesis.json` is used.

Tear down: `kurtosis clean -a`.

## If the handshake fails

- Modern geth advertises eth/69+ and dropped eth/68; zeth speaks eth/69.
- A forkid/genesis mismatch shows up as the peer never sending its `Status` — confirm the
  genesis hash matches `eth_getBlockByNumber("0x0")`.

Conformance harness: [hive.md](./hive.md).
