#!/bin/bash
# zeth hive entry point. Loads the geth-format genesis hive mounts at
# /genesis.json (folding HIVE_* fork config in via mapper.jq), imports any RLP
# block files (/chain.rlp and /blocks/*.rlp), then serves JSON-RPC on :8545.
set -e

# Fold HIVE_* fork activation config into the genesis (geth format). Write to a
# fresh path so we never depend on /genesis.json being writable (it may be a
# read-only mount).
GENESIS=/genesis.json
if [ -f /genesis.json ]; then
  jq -f /mapper.jq /genesis.json > /genesis-mapped.json
  GENESIS=/genesis-mapped.json
fi

# Collect RLP block files in import order.
RLP_ARGS=()
[ -f /chain.rlp ] && RLP_ARGS+=("/chain.rlp")
if [ -d /blocks ]; then
  while IFS= read -r f; do RLP_ARGS+=("$f"); done < <(ls /blocks/*.rlp 2>/dev/null | sort)
fi

# Enable the Engine API (authrpc + JWT) for post-merge chains, like geth/reth.
# hive's engine simulators use the well-known fixed test secret.
AUTH_ARGS=()
if [ -n "${HIVE_TERMINAL_TOTAL_DIFFICULTY}" ] || [ -n "${HIVE_SHANGHAI_TIMESTAMP}" ] || [ -n "${HIVE_CANCUN_TIMESTAMP}" ]; then
  echo -n "7365637265747365637265747365637265747365637265747365637265747365" > /jwt.secret
  AUTH_ARGS=(--authrpc.addr=0.0.0.0:8551 --authrpc.jwtsecret=/jwt.secret)
fi

echo "zeth: starting node (genesis + ${#RLP_ARGS[@]} rlp file(s); engine=${#AUTH_ARGS[@]})"
exec /usr/local/bin/zeth node "$GENESIS" "${RLP_ARGS[@]}" --http.addr=0.0.0.0:8545 "${AUTH_ARGS[@]}"
