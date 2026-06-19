#!/usr/bin/env bash
# Sandwich vs encrypted mempool against zeth. `zeth node --dev --trace` prints the
# verbose RPC trace (method(params) ← result); this script just drives the user
# and searcher with cast.
#
# Stage 1 (unencrypted): user broadcasts a swap to zeth's public mempool; the
# searcher listens (eth_newPendingTransactionFilter), pulls the signed tx
# (eth_getRawTransactionByHash), bundles [front, user, back] (eth_sendBundle),
# and zeth's --dev builder includes it -> user sandwiched.
# Stage 2 (encrypted/private): the user sends the swap as a private bundle, never
# entering the public mempool; the searcher's filter sees nothing -> fair fill.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
RPC=http://127.0.0.1:8545
B=$'\033[1m'; X=$'\033[0m'; [ -n "${NO_COLOR:-}" ] && { B=; X=; }

D=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VPK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
APK=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
V=$(cast wallet address $VPK)
A=$(cast wallet address $APK)
TRACE=/tmp/zeth-sandwich.trace

(cd "$ROOT" && zig build -Doptimize=ReleaseFast -Ddev=true) >/dev/null   # build zeth (dev RPC on)
forge build >/dev/null                                        # build the AMM
"$ROOT/zig-out/bin/zeth" node --dev -v genesis.json --http.addr=127.0.0.1:8545 >"$TRACE" 2>&1 &
ZETH=$!
trap 'kill $ZETH 2>/dev/null' EXIT
for _ in $(seq 1 400); do cast block-number --rpc-url $RPC >/dev/null 2>&1 && break; done

R=1000000000000000000000
BYTE=$(forge inspect src/MiniAMM.sol:MiniAMM bytecode)
mine()    { cast rpc evm_mine --rpc-url $RPC >/dev/null; }
num()     { cast call "$1" "$2" "${@:3}" --rpc-url $RPC | awk '{print $1}'; }
rawsend() { cast rpc eth_sendRawTransaction "$1" --rpc-url $RPC | tr -d '"'; }
deploy()  { local h; h=$(rawsend "$(cast mktx --private-key $D --rpc-url $RPC --gas-limit 3000000 --create "$BYTE" "constructor(uint256,uint256)" $R $R)"); mine; cast rpc eth_getTransactionReceipt "$h" --rpc-url $RPC | jq -r .contractAddress; }
fund()    { rawsend "$(cast mktx --private-key $D --rpc-url $RPC --gas-limit 300000 "$1" "fund0(address,uint256)" "$2" "$3")" >/dev/null; mine; }
mk()      { cast mktx --rpc-url $RPC --gas-limit 300000 "$@"; }   # signed raw tx (no send)
VIN=100000000000000000000
AIN=300000000000000000000

# Part 1 — plaintext mempool: user to the public pool, searcher sandwiches it.
AMM=$(deploy); fund "$AMM" "$V" $VIN; fund "$AMM" "$A" $AIN
S1=$(wc -c <"$TRACE")
FID=$(cast rpc eth_newPendingTransactionFilter --rpc-url $RPC | tr -d '"')
rawsend "$(mk --private-key $VPK "$AMM" "swap0for1(uint256)" $VIN)" >/dev/null
VHASH=$(cast rpc eth_getFilterChanges "$FID" --rpc-url $RPC | jq -r '.[0]')
VSIG=$(cast rpc eth_getRawTransactionByHash "$VHASH" --rpc-url $RPC | tr -d '"')
r0=$(num "$AMM" "r0()(uint256)"); r1=$(num "$AMM" "r1()(uint256)")
ATK1=$(python3 -c "print($r1-($r0*$r1)//($r0+$AIN))")
FRONT=$(mk --private-key $APK --nonce 0 "$AMM" "swap0for1(uint256)" $AIN)
BACK=$(mk --private-key $APK --nonce 1 "$AMM" "swap1for0(uint256)" "$ATK1")
cast rpc eth_sendBundle "{\"txs\":[\"$FRONT\",\"$VSIG\",\"$BACK\"]}" --rpc-url $RPC >/dev/null
E1=$(wc -c <"$TRACE")
V_CLEAR=$(num "$AMM" "bal1(address)(uint256)" "$V")
A_PROFIT=$(python3 -c "print($(num "$AMM" "bal0(address)(uint256)" "$A")-$AIN)")

# Part 2 — encrypted mempool: user sends a private bundle; the searcher is blind.
AMM2=$(deploy); fund "$AMM2" "$V" $VIN
S2=$(wc -c <"$TRACE")
cast rpc eth_newPendingTransactionFilter --rpc-url $RPC >/dev/null
cast rpc eth_sendBundle "{\"txs\":[\"$(mk --private-key $VPK "$AMM2" "swap0for1(uint256)" $VIN)\"]}" --rpc-url $RPC >/dev/null
E2=$(wc -c <"$TRACE")
V_ENC=$(num "$AMM2" "bal1(address)(uint256)" "$V")

# print the trace slice [from,to) of $TRACE — zeth's -v already filters to
# orderflow methods + the [builder] line, so no extra filtering here.
slice() { tail -c "+$(($1 + 1))" "$TRACE" | head -c "$(($2 - $1))"; }

echo "${B}Part 1 — plaintext mempool${X}"
slice "$S1" "$E1"
echo "  user got $(cast from-wei "$V_CLEAR") token1 (sandwiched); attacker MEV $(cast from-wei "$A_PROFIT") token0"
echo
echo "${B}Part 2 — encrypted mempool (EIP-8105)${X}"
slice "$S2" "$E2"
echo "  user got $(cast from-wei "$V_ENC") token1 (fair — the searcher had nothing to wrap)"
