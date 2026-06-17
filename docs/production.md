# Status & running zeth

zeth is a conformance-grade EVM and a devnet/testnet node. It is **not** a production
mainnet client — don't run it on mainnet or for validator duties.

## Works today

- [x] EVM Frontier→Prague (+ Osaka opcodes), conformance-tested (EEST, ethereum/tests)
- [x] Precompiles incl. bn254, BLS12-381, KZG
- [x] EIP-7702, EIP-7685, EIP-4844; EIP-7825 (Osaka tx gas cap)
- [x] Block import — roots + gas; imports the historical chain, head matches geth
- [x] Mempool + block producer; `zeth produce` re-imports the built block to validate it
- [x] JSON-RPC (`eth_*`, `debug_*`) + Engine API incl. block building (`getPayload`)
- [x] Persistence (`--datadir` snapshot + resume)
- [x] devp2p: RLPx, eth/69, snap/1, discovery v4; EIP-2124 mainnet forkid
- [x] Live mainnet handshake — holds the connection to geth
- [x] snap/1 state-range download; single-peer full sync

## Not ready (before mainnet)

- [ ] Full mainnet sync at tip; the snap range-proof verifier fails on real geth proofs
- [ ] Multi-peer sync (peer set, scoring, drop recovery) + inbound listener
- [ ] Persistent discovery table / bootstrap (today: a bounded crawl); discovery v5
- [ ] Tx + block gossip
- [ ] Reorgs / fork choice
- [ ] Hardening: iterative EVM (drop the large-stack workaround), fuzzing, DoS limits

## Run a node

```sh
zig build -Doptimize=ReleaseFast
zeth node <genesis.json> --peer=<enode://…> --datadir=DIR \
    --http.addr=0.0.0.0:8545 --authrpc.addr=0.0.0.0:8551 --authrpc.jwtsecret=jwt.hex
```

Restart with the same `--datadir` to resume. The genesis must byte-match the network's.
Interop: [kurtosis.md](./kurtosis.md). Conformance harness: [hive.md](./hive.md).
