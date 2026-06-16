# Testing zeth against a Kurtosis devnet

[Kurtosis](https://docs.kurtosis.com/) + the
[`ethereum-package`](https://github.com/ethpandaops/ethereum-package) spin up a
real, local Ethereum network (execution + consensus clients) in Docker. It's the
fastest way to point zeth at a *real* geth/reth/… node and check interop.

This is exactly how the devp2p transport was validated: zeth dials geth, runs the
RLPx handshake, exchanges the eth/69 `Status`, and downloads block headers.

## Prerequisites

- Docker (running)
- Kurtosis CLI: `brew install kurtosis-tech/tap/kurtosis-cli`
- zeth built: `zig build -Doptimize=ReleaseFast`

## 1. Start a devnet

A minimal one geth + one lighthouse network:

```sh
cat > /tmp/devnet.yaml <<'EOF'
participants:
  - el_type: geth
    cl_type: lighthouse
EOF

kurtosis run --enclave zethnet ./ethereum-package-kurtosis --args-file /tmp/devnet.yaml
```

When it's up, `kurtosis enclave inspect zethnet` lists the services and their
mapped host ports. Note geth's:

- `rpc: 8545/tcp -> 127.0.0.1:<RPC_PORT>`
- `tcp-discovery: 30303/tcp -> 127.0.0.1:<P2P_PORT>`

> The container's internal P2P address (`172.16.x.x:30303`) is **not** reachable
> from the host — always dial the mapped `127.0.0.1:<P2P_PORT>`.

## 2. Grab geth's enode, network id, and genesis hash

```sh
RPC=http://127.0.0.1:<RPC_PORT>

# enode (rewrite the host:port to the mapped P2P port)
ENODE=$(curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"admin_nodeInfo","params":[]}' $RPC \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['enode'])")
PUB=$(echo "$ENODE" | sed -E 's#enode://([0-9a-f]+)@.*#\1#')
DIAL="enode://${PUB}@127.0.0.1:<P2P_PORT>"

# network id
NETID=$(curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"net_version","params":[]}' $RPC \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result'])")

# genesis hash
GH=$(curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' $RPC \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['hash'][2:])")
```

## 3. Dial geth with zeth

```sh
./zig-out/bin/zeth p2p "$DIAL" "$NETID" "$GH"
```

Expected output — a full handshake and a header download:

```
✓ RLPx handshake complete
← Hello — caps: eth/69, eth/70, eth/71, snap/1
→ sent Status (networkId=… forkid=0x…)
← Status: eth/69 networkId=… latest=#… forkid=0x…    ← geth accepted us
✓ eth/69 Status accepted — requesting headers
← BlockHeaders: 4 header(s)
    #0 hash=0x…   ← the devnet genesis hash
    …
✓ downloaded headers from a real peer over devp2p
```

`zeth p2p` is a **connectivity probe**, not a full sync — it validates the
transport (ECIES → RLPx frames + MAC → Hello → eth/69 Status with a matching
EIP-2124 forkid → `GetBlockHeaders`/`BlockHeaders`). The forkid for an
all-at-genesis devnet is `CRC32(genesis_hash)`.

## 4. Tear down

```sh
kurtosis clean -a
```

## Notes / gotchas

- **eth version:** modern geth advertises eth/69/70/71 and has dropped eth/68.
  zeth advertises eth/69 and sends the eth/69 `Status` (no total-difficulty;
  carries the `[earliest, latest, latestHash]` range).
- **"useless peer" (disconnect 0x03):** geth drops a peer it shares no `eth`
  capability with — if you see this, the cap negotiation (version) is the
  culprit, not the chain identity.
- **forkid mismatch** shows up as the peer never sending its `Status`. Confirm
  the genesis hash you pass matches `eth_getBlockByNumber("0x0")`.

## Also useful for testing

- **hive** (`make test-hive`) — runs the EEST `consume-rlp` / `consume-engine`
  simulators against zeth in Docker; this is the post-merge, Engine-API-driven
  path and is the most complete end-to-end exercise today.
- **Local EEST fixtures** (`make test-eest`) — the same fixtures hive feeds,
  run locally without Docker (much faster for iteration).
