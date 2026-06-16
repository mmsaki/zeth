# Zeth — Zig Ethereum execution client
#
# Thin wrappers around `zig build`. Override the compiler with `ZIG=/path/zig`.

ZIG ?= zig
ARGS ?=

.PHONY: all build test bench bench-loop conformance eels run fmt fmt-check clean hive-stage

# Linux target for the hive client image (matches Docker Desktop's platform).
HIVE_TARGET ?= aarch64-linux-musl

all: build

## Compile everything (debug) and install artifacts to zig-out/.
build:
	$(ZIG) build

## Run the unit test suite.
test:
	$(ZIG) build test --summary all

## Cross-client benchmark vs geth (and revm/evmone if installed): gas + speed.
## This is the productive benchmark — real engines, gas-correctness + Mgas/s.
bench:
	$(ZIG) build -Doptimize=ReleaseFast
	python3 scripts/cross_bench.py

## Internal single-engine throughput loop (poop-style; no external clients).
bench-loop:
	$(ZIG) build bench -Doptimize=ReleaseFast

## EELS conformance: TrieTests + a slice of GeneralStateTests, checked by root.
eels:
	$(ZIG) build -Doptimize=ReleaseFast
	bash scripts/eels.sh

## Conformance: the full sweep of BOTH suites across every supported fork
## (Cancun + Prague), rendered as a ✓/✗ graph + pass rate. This is THE test
## command. Scope to one fork with ZETH_FORK=<name>; stop at the first failure
## by dropping ZETH_ALL (e.g. run the binary directly for bisecting).
conformance:
	$(ZIG) build -Doptimize=ReleaseFast
	ZETH_ALL=1 ./zig-out/bin/statetest ethereum-tests/GeneralStateTests
	ZETH_ALL=1 ./zig-out/bin/blocktest ethereum-tests/BlockchainTests

## Cross-compile a static-Linux zeth and stage the hive client adapter into
## hive/clients/zeth (run `./hive --client zeth --sim ethereum/eels/consume-rlp`).
hive-stage:
	$(ZIG) build -Dtarget=$(HIVE_TARGET) -Doptimize=ReleaseFast
	mkdir -p hive/clients/zeth
	cp hive-client/Dockerfile hive-client/zeth.sh hive-client/mapper.jq hive-client/enode.sh hive/clients/zeth/
	cp zig-out/bin/zeth hive/clients/zeth/zeth
	@echo "staged hive/clients/zeth/ ($(HIVE_TARGET) binary + adapter)"

## Execute hex bytecode: `make run ARGS="0x6006600701"`.
run:
	$(ZIG) build run -- run $(ARGS)

## Format all Zig sources in place.
fmt:
	$(ZIG) fmt build.zig src bench

## Verify formatting without writing (CI-friendly).
fmt-check:
	$(ZIG) fmt --check build.zig src bench

## Remove build cache and outputs.
clean:
	rm -rf .zig-cache zig-out
