# Zeth — Zig Ethereum execution client
#
# Thin wrappers around `zig build`. Override the compiler with `ZIG=/path/zig`.

ZIG ?= zig
ARGS ?=

.PHONY: all build test bench bench-loop conformance hive-tests report eels run fmt fmt-check clean

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

## GeneralStateTests: stop at the first failure (default). ALL=1 for full sweep.
## The runner walks the directory itself and renders a ✓/✗ graph + failures.
conformance:
	$(ZIG) build -Doptimize=ReleaseFast
	$(if $(ALL),ZETH_ALL=1 )./zig-out/bin/statetest ethereum-tests/GeneralStateTests

## BlockchainTests (the hive on-ramp): stop at first failure. ALL=1 for full sweep.
hive-tests:
	$(ZIG) build -Doptimize=ReleaseFast
	$(if $(ALL),ZETH_ALL=1 )./zig-out/bin/blocktest ethereum-tests/BlockchainTests

## Full report: run EVERYTHING (both suites) with the ✓/✗ graph + % pass.
report:
	$(ZIG) build -Doptimize=ReleaseFast
	ZETH_ALL=1 ./zig-out/bin/statetest ethereum-tests/GeneralStateTests
	ZETH_ALL=1 ./zig-out/bin/blocktest ethereum-tests/BlockchainTests

## Execute hex bytecode: `make run ARGS="0x6006600701"`.
run:
	$(ZIG) build run -- $(ARGS)

## Format all Zig sources in place.
fmt:
	$(ZIG) fmt build.zig src bench

## Verify formatting without writing (CI-friendly).
fmt-check:
	$(ZIG) fmt --check build.zig src bench

## Remove build cache and outputs.
clean:
	rm -rf .zig-cache zig-out
