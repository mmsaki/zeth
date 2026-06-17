# Getting started (development)

What a fresh clone needs, and how to get from zero to running tests.

## 1. Install Zig (nightly master)

zeth needs a Zig nightly `0.17.0-dev.702` or newer (minimum set in `build.zig.zon`):

```sh
# zvm (https://github.com/tristanisham/zvm)
zvm i master && zvm use master
```

Or grab the latest master build from <https://ziglang.org/download/> and put `zig` on
your `PATH`.

Check: `zig version` should print `0.17.0-dev…`. If it still shows an older version,
another `zig` is shadowing zvm's on `PATH`. Remove it:

```sh
brew uninstall zig && hash -r   # if you installed zig via Homebrew
```

(or put `~/.zvm/bin` ahead of it on your `PATH`).

## 2. Build + the tests that need nothing else

```sh
git clone https://github.com/mmsaki/zeth && cd zeth
zig build -Doptimize=ReleaseFast   # binary at zig-out/bin/zeth
make test                          # unit tests — Zig only, no external data
```

These work on a clean clone with just Zig:

```sh
./zig-out/bin/zeth run 6006600701    # execute bytecode
./zig-out/bin/zeth bench-evm         # EVM throughput
./zig-out/bin/zeth produce genesis.json --tx=0x…
```

## 3. Conformance fixtures (optional, external data)

These suites run against fixtures that are **not** in the repo. Fetch what you need:

**ethereum/tests** — `make test-ethereum`:

```sh
git clone --depth 1 https://github.com/ethereum/tests ethereum-tests
```

**Execution Spec Tests (EEST)** — `make test-eest`. Download the release fixtures
(no Docker needed) into `eest-fixtures/`:

```sh
mkdir -p eest-fixtures && curl -L \
  https://github.com/ethereum/execution-spec-tests/releases/download/v5.4.0/fixtures_stable.tar.gz \
  | tar -xz -C eest-fixtures --strip-components=1
```

(`make fixtures-eest` is the alternative — it extracts the same set from a built hive
image, which requires Docker + the hive checkout below.)

## 4. hive (optional, Docker)

`make test-hive` drives a containerized zeth. Needs Docker and a hive checkout next to
the repo; see [hive.md](./hive.md).

## 5. Cross-client benchmark (optional)

`make bench` compares against reference engines (geth / revm / evmone) and needs
Python 3 plus whichever of those you have installed; it auto-detects them.

## Summary

| Command | Needs |
|---|---|
| `make test`, `zeth run/bench-evm/produce/node` | Zig only |
| `make test-ethereum` | `ethereum-tests/` clone |
| `make test-eest` | `eest-fixtures/` (release tarball, §3) |
| `make test-hive` | Docker + hive checkout |
| `make bench` | Python 3 + reference clients |
