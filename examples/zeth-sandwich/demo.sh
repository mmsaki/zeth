#!/usr/bin/env bash
# Sandwich vs encrypted mempool, end-to-end against zeth's own RPC.
#
# Stage 1 (unencrypted): the victim broadcasts a swap to zeth's public mempool;
# the searcher listens (eth_newPendingTransactionFilter), pulls the raw signed tx
# (eth_getRawTransactionByHash), wraps [front, victim, back] into an eth_sendBundle,
# and zeth's dev builder includes it in order -> MEV extracted, victim sandwiched.
#
# Stage 2 (encrypted/private): the victim sends the swap as a private bundle, so it
# never hits the public mempool; the searcher's filter sees nothing -> fair fill.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
RPC=http://127.0.0.1:8545

DEPLOYER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VICTIM_PK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
ATTACKER_PK=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
VICTIM=$(cast wallet address $VICTIM_PK)
ATTACKER=$(cast wallet address $ATTACKER_PK)

(cd "$ROOT" && zig build -Doptimize=ReleaseFast) >/dev/null   # build zeth
forge build >/dev/null                                        # build the AMM
"$ROOT/zig-out/bin/zeth" node --dev genesis.json --http.addr=127.0.0.1:8545 >/tmp/zeth-dev.log 2>&1 &
ZETH=$!
trap 'kill $ZETH 2>/dev/null' EXIT
for _ in $(seq 1 400); do cast block-number --rpc-url $RPC >/dev/null 2>&1 && break; done
echo "zeth dev node up (chain $(cast chain-id --rpc-url $RPC))"

rpc()  { cast rpc "$@" --rpc-url $RPC; }
mine() { rpc evm_mine >/dev/null; }
num()  { cast call "$1" "$2" "${@:3}" --rpc-url $RPC | awk '{print $1}'; }   # uint256 -> decimal
send() { rpc eth_sendRawTransaction "$1" | tr -d '"'; }                       # -> tx hash (no wait)

BYTECODE=$(forge inspect src/MiniAMM.sol:MiniAMM bytecode)
R=1000000000000000000000   # 1000e18 reserves
deploy() { # -> deployed address
  local raw hash
  raw=$(cast mktx --private-key $DEPLOYER --rpc-url $RPC --gas-limit 3000000 --create "$BYTECODE" "constructor(uint256,uint256)" $R $R)
  hash=$(send "$raw"); mine
  rpc eth_getTransactionReceipt "$hash" | jq -r .contractAddress
}
fund() { # $1 amm $2 who $3 amount
  local raw; raw=$(cast mktx --private-key $DEPLOYER --rpc-url $RPC --gas-limit 300000 "$1" "fund0(address,uint256)" "$2" "$3")
  send "$raw" >/dev/null; mine
}

echo
echo "== Stage 1: unencrypted mempool =="
AMM=$(deploy)
fund "$AMM" "$VICTIM"   100000000000000000000
fund "$AMM" "$ATTACKER" 300000000000000000000
echo "  MiniAMM @ $AMM  (reserves 1000/1000)"

FID=$(rpc eth_newPendingTransactionFilter | tr -d '"')                       # searcher starts listening
VRAW=$(cast mktx --private-key $VICTIM_PK --rpc-url $RPC --gas-limit 300000 "$AMM" "swap0for1(uint256)" 100000000000000000000)
send "$VRAW" >/dev/null                                                       # victim -> PUBLIC mempool (pending)
echo "  victim broadcast swap (100) to the public mempool"

VHASH=$(rpc eth_getFilterChanges "$FID" | jq -r '.[0]')                       # searcher sees it
VSIG=$(rpc eth_getRawTransactionByHash "$VHASH" | tr -d '"')                  # pulls the signed tx
r0=$(num "$AMM" "r0()(uint256)"); r1=$(num "$AMM" "r1()(uint256)")
ATK1=$(python3 -c "print($r1-($r0*$r1)//($r0+300*10**18))")                   # simulate the front-run output
FRONT=$(cast mktx --private-key $ATTACKER_PK --nonce 0 --rpc-url $RPC --gas-limit 300000 "$AMM" "swap0for1(uint256)" 300000000000000000000)
BACK=$(cast mktx --private-key $ATTACKER_PK --nonce 1 --rpc-url $RPC --gas-limit 300000 "$AMM" "swap1for0(uint256)" "$ATK1")
echo "  searcher saw $VHASH and bundled [front, victim, back]"
rpc eth_sendBundle "{\"txs\":[\"$FRONT\",\"$VSIG\",\"$BACK\"]}" >/dev/null    # -> dev builder includes it

V_CLEAR=$(num "$AMM" "bal1(address)(uint256)" "$VICTIM")
A_PROFIT=$(python3 -c "print($(num "$AMM" "bal0(address)(uint256)" "$ATTACKER")-300*10**18)")

echo
echo "== Stage 2: encrypted/private mempool =="
AMM2=$(deploy)
fund "$AMM2" "$VICTIM" 100000000000000000000
FID2=$(rpc eth_newPendingTransactionFilter | tr -d '"')
VRAW2=$(cast mktx --private-key $VICTIM_PK --rpc-url $RPC --gas-limit 300000 "$AMM2" "swap0for1(uint256)" 100000000000000000000)
rpc eth_sendBundle "{\"txs\":[\"$VRAW2\"]}" >/dev/null                        # victim -> PRIVATE (never public)
SAW=$(rpc eth_getFilterChanges "$FID2" | jq 'length')
echo "  victim sent privately; searcher filter saw $SAW pending txs -> nothing to sandwich"
V_ENC=$(num "$AMM2" "bal1(address)(uint256)" "$VICTIM")

fromwei() { cast from-wei "$1"; }
echo
echo "results (token1 out to the victim):"
echo "  fair / encrypted      : $(fromwei "$V_ENC")"
echo "  unencrypted (sandwiched): $(fromwei "$V_CLEAR")"
echo "  attacker MEV profit   : $(fromwei "$A_PROFIT") token0"
