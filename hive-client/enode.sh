#!/bin/bash
# zeth has a full devp2p stack — RLPx/ECIES, eth/69, snap/1, discovery v4, the
# real EIP-2124 forkid — and can dial and *hold* live peers (incl. mainnet geth).
# But the hive `node` entrypoint runs zeth as a JSON-RPC / Engine-API server and
# does not yet open an *inbound* p2p listener, so there is no stable enode for
# hive to dial. The consume-rlp / consume-engine / rpc-compat simulators drive the
# client over RPC/Engine (not p2p), so they never use this — emit a syntactically
# valid placeholder so hive's helper scripts don't choke.
echo "enode://0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000@127.0.0.1:30303"
