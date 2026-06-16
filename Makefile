# Zeth — Zig Ethereum execution client
#
# Thin wrappers around `zig build`. Override the compiler with `ZIG=/path/zig`.

ZIG ?= zig
ARGS ?=

.PHONY: all build test test-ethereum test-eest test-hive test-all \
        bench bench-loop fixtures-eest hive-stage run fmt fmt-check clean

# Linux target for the hive client image (matches Docker Desktop's platform).
HIVE_TARGET ?= aarch64-linux-musl

all: build

## Compile everything (debug) and install artifacts to zig-out/.
build:
	$(ZIG) build

# ── Tests, grouped by where the fixtures come from ──────────────────────────
# Origins:
#   test           our own Zig `test {}` blocks (unit tests) — the fast loop
#   test-ethereum  ethereum/tests   : the classic EF consensus-test repo
#   test-eest      execution-spec-tests : modern EF fixtures, ALL forks (local)
#   test-hive      hive             : Docker, drives EEST fixtures at the live node
#   test-all       everything that runs locally (no Docker): the three above

## Unit tests: our own Zig `test {}` blocks.
test:
	$(ZIG) build test --summary all

## ethereum/tests — the classic Ethereum Foundation consensus-test repo:
## GeneralStateTests + BlockchainTests (vendored) + TrieTests (fetched).
test-ethereum:
	$(ZIG) build -Doptimize=ReleaseFast
	./zig-out/bin/statetest --all ethereum-tests/GeneralStateTests
	./zig-out/bin/blocktest --all ethereum-tests/BlockchainTests
	bash scripts/eels.sh

## execution-spec-tests (EEST) — the modern EF fixtures, every fork. These are
## the exact fixtures hive's consume-rlp/consume-engine feed to the client, run
## here locally (no Docker). Populate once with `make fixtures-eest`. Scope to a
## fork with `./zig-out/bin/blocktest --fork London eest-fixtures/blockchain_tests`.
test-eest:
	@test -d eest-fixtures || { echo "eest-fixtures/ missing — run 'make fixtures-eest' first"; exit 1; }
	$(ZIG) build -Doptimize=ReleaseFast
	./zig-out/bin/blocktest --all eest-fixtures/blockchain_tests
	./zig-out/bin/statetest --all eest-fixtures/state_tests

## hive — Docker integration: the same EEST fixtures driven against a running
## zeth over JSON-RPC/Engine. Rebuilds the client image from the latest binary.
## Override the simulator with ARGS, e.g. ARGS="--sim ethereum/eels/consume-engine".
test-hive: hive-stage
	cd hive && ./hive --client zeth --docker.nocache 'clients/zeth' \
		$(if $(ARGS),$(ARGS),--sim ethereum/eels/consume-rlp)

## Everything that runs locally (no Docker): unit + ethereum/tests + EEST.
test-all: test test-ethereum test-eest

## Cross-client benchmark vs geth (and revm/evmone if installed): gas + speed.
## This is the productive benchmark — real engines, gas-correctness + Mgas/s.
bench:
	$(ZIG) build -Doptimize=ReleaseFast
	python3 scripts/cross_bench.py

## Internal single-engine throughput loop (poop-style; no external clients).
bench-loop:
	$(ZIG) build bench -Doptimize=ReleaseFast

## Populate eest-fixtures/ by extracting the EEST fixture set baked into the
## hive consume-rlp simulator image (≈4 GB, all forks). Needed by `test-eest`.
fixtures-eest:
	@CID=$$(docker create hive/simulators/ethereum/eels/consume-rlp:latest) && \
	mkdir -p eest-fixtures && \
	docker cp $$CID:/root/.cache/ethereum-execution-spec-tests/cached_downloads/ethereum/execution-spec-tests/v5.4.0/fixtures_stable/fixtures/. eest-fixtures/ && \
	docker rm $$CID >/dev/null && \
	echo "extracted EEST fixtures to eest-fixtures/ ($$(du -sh eest-fixtures | cut -f1))"

## Cross-compile a static-Linux zeth and stage the hive client adapter into
## hive/clients/zeth (run `./hive --client zeth --sim ethereum/eels/consume-rlp`).
hive-stage:
	$(ZIG) build -Dtarget=$(HIVE_TARGET) -Doptimize=ReleaseFast --prefix zig-out-linux
	mkdir -p hive/clients/zeth
	cp hive-client/Dockerfile hive-client/zeth.sh hive-client/mapper.jq hive-client/enode.sh hive/clients/zeth/
	cp zig-out-linux/bin/zeth hive/clients/zeth/zeth
	@echo "staged hive/clients/zeth/ ($(HIVE_TARGET) binary + adapter; native zig-out preserved)"

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
