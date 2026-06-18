# JSON-RPC coverage

Checklist of the standard `debug` / `engine` / `eth` / `net` / `txpool` /
`testing` methods against what zeth implements. `[x]` = implemented.

`*` marks a zeth-only method (not in the standard list).

## debug
- [ ] debug_getBadBlocks
- [ ] debug_getRawBlock
- [ ] debug_getRawBlockAccessList
- [ ] debug_getRawHeader
- [ ] debug_getRawReceipts
- [ ] debug_getRawTransaction
- [x] debug_traceBlockByHash *
- [x] debug_traceBlockByNumber *
- [x] debug_traceCall *
- [x] debug_traceTransaction *

## engine
- [x] engine_exchangeCapabilities
- [ ] engine_exchangeTransitionConfigurationV1
- [x] engine_forkchoiceUpdatedV1
- [x] engine_forkchoiceUpdatedV2
- [x] engine_forkchoiceUpdatedV3
- [ ] engine_forkchoiceUpdatedV4
- [ ] engine_getBlobsV1
- [ ] engine_getBlobsV2
- [ ] engine_getBlobsV3
- [ ] engine_getBlobsV4
- [ ] engine_getPayloadBodiesByHashV1
- [ ] engine_getPayloadBodiesByHashV2
- [ ] engine_getPayloadBodiesByRangeV1
- [ ] engine_getPayloadBodiesByRangeV2
- [x] engine_getPayloadV1
- [x] engine_getPayloadV2
- [x] engine_getPayloadV3
- [x] engine_getPayloadV4
- [ ] engine_getPayloadV5
- [ ] engine_getPayloadV6
- [x] engine_newPayloadV1
- [x] engine_newPayloadV2
- [x] engine_newPayloadV3
- [x] engine_newPayloadV4
- [ ] engine_newPayloadV5

## eth
- [x] eth_accounts
- [x] eth_blobBaseFee
- [x] eth_blockNumber
- [x] eth_call
- [x] eth_capabilities
- [x] eth_chainId
- [x] eth_coinbase
- [ ] eth_config
- [x] eth_createAccessList
- [x] eth_estimateGas
- [x] eth_feeHistory
- [x] eth_gasPrice
- [x] eth_getBalance
- [ ] eth_getBlockAccessList
- [x] eth_getBlockByHash
- [x] eth_getBlockByNumber
- [x] eth_getBlockReceipts
- [x] eth_getBlockTransactionCountByHash
- [x] eth_getBlockTransactionCountByNumber
- [x] eth_getCode
- [x] eth_getFilterChanges
- [ ] eth_getFilterLogs
- [x] eth_getLogs
- [x] eth_getProof
- [x] eth_getStorageAt
- [x] eth_getStorageValues
- [x] eth_getTransactionByBlockHashAndIndex
- [x] eth_getTransactionByBlockNumberAndIndex
- [x] eth_getTransactionByHash
- [x] eth_getTransactionCount
- [x] eth_getTransactionReceipt
- [x] eth_maxPriorityFeePerGas
- [ ] eth_newBlockFilter
- [ ] eth_newFilter
- [x] eth_newPendingTransactionFilter
- [x] eth_sendRawTransaction
- [ ] eth_sendTransaction
- [ ] eth_sign
- [ ] eth_signTransaction
- [x] eth_simulateV1
- [x] eth_syncing
- [ ] eth_uninstallFilter
- [x] eth_baseFee *
- [x] eth_getRawTransactionByHash *
- [x] eth_getUncleCountByBlockHash *
- [x] eth_getUncleCountByBlockNumber *
- [x] eth_protocolVersion *
- [x] eth_sendBundle *

## net
- [x] net_version
- [x] net_listening *
- [x] net_peerCount *

## web3
- [x] web3_clientVersion *
- [x] web3_sha3 *

## txpool
- [ ] txpool_content
- [ ] txpool_contentFrom
- [ ] txpool_status

## testing
- [ ] testing_buildBlockV1
- [x] evm_mine *
- [x] anvil_mine *
