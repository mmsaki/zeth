#!/bin/bash
# zeth has no devp2p stack yet; emit a placeholder enode so hive's helper
# scripts don't fail. (consume-rlp / consume-engine drive the client over
# RPC/Engine, not p2p, so this is unused by those simulators.)
echo "enode://0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000@127.0.0.1:30303"
