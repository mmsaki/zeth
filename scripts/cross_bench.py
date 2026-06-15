#!/usr/bin/env python3
"""Cross-client EVM benchmark: run a shared corpus of feature-spanning programs
through zetherum and any installed reference clients (geth, revm, evmone), then
compare *gas* (a correctness oracle — every program uses only opcodes whose gas
is fork-invariant, so a correct engine reports identical gas) and *speed*.

Usage:  python3 scripts/cross_bench.py        (from the repo root)

Engines are auto-detected; whatever is present is included. Adding an engine is
a single adapter function returning (gas, nanoseconds) from a hex program.
"""

import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZETH_RUN = os.path.join(ROOT, "zig-out", "bin", "zeth-run")
REVM_RUN = os.path.join(ROOT, "bench", "revm-runner", "target", "release", "revm-runner")

# ANSI colors (honor NO_COLOR when non-empty, per no-color.org).
_nc = os.environ.get("NO_COLOR")
COLOR = sys.stdout.isatty() and not (_nc is not None and _nc != "")


def col(s, code):
    return f"\x1b[{code}m{s}\x1b[0m" if COLOR else s


def green(s):
    return col(s, "32")


def red(s):
    return col(s, "31")


def bold(s):
    return col(s, "1")


def dim(s):
    return col(s, "2")


def search(pattern: str, text: str) -> "re.Match[str]":
    m = re.search(pattern, text)
    if not m:
        raise ValueError(f"no match for {pattern!r} in:\n{text}")
    return m


def parse_duration_ns(s):
    """Parse a Go-style duration like '24.9ms', '5.8µs', '1.2s', '900ns'."""
    m = search(r"([0-9.]+)\s*(ns|µs|us|ms|s)", s.strip())
    v = float(m.group(1))
    return v * {"ns": 1, "µs": 1e3, "us": 1e3, "ms": 1e6, "s": 1e9}[m.group(2)]


# --- Engine adapters: hex -> (gas, ns) ------------------------------------

def run_zetherum(hexcode):
    out = subprocess.run([ZETH_RUN, "--bench", hexcode],
                         capture_output=True, text=True).stderr
    m = search(r"gas (\d+) ns (\d+)", out)
    return int(m.group(1)), float(m.group(2))


def run_geth(hexcode):
    out = subprocess.run(["evm", "run", "--bench", hexcode],
                         capture_output=True, text=True)
    text = out.stdout + out.stderr
    gas = int(search(r"gas used:\s*(\d+)", text).group(1))
    ns = parse_duration_ns(search(r"execution time:\s*(\S+)", text).group(1))
    return gas, ns


def run_revm(hexcode):
    out = subprocess.run([REVM_RUN, hexcode],
                         capture_output=True, text=True).stdout
    m = search(r"gas (\d+) ns (\d+)", out)
    return int(m.group(1)), float(m.group(2))


def run_evmone(hexcode):
    # evmone-bench takes a code file + an input; we feed an empty input.
    out = subprocess.run(["evmone-bench", "--code", hexcode],
                         capture_output=True, text=True)
    text = out.stdout + out.stderr
    gas = int(search(r"gas used:\s*(\d+)", text).group(1))
    ns = parse_duration_ns(search(r"time:\s*(\S+)", text).group(1))
    return gas, ns


# Engine registry: (name, availability check, adapter). zeth first = reference.
# "reth" is measured via revm, the EVM engine reth uses.
ENGINES = [
    ("zeth", lambda: os.path.exists(ZETH_RUN), run_zetherum),
    ("geth", lambda: shutil.which("evm") is not None, run_geth),
    ("reth", lambda: os.path.exists(REVM_RUN), run_revm),
    ("evmone", lambda: shutil.which("evmone-bench") is not None, run_evmone),
]


def main():
    if not os.path.exists(ZETH_RUN):
        print("building zeth-run ...")
        subprocess.run(["zig", "build", "-Doptimize=ReleaseFast"], cwd=ROOT, check=True)

    engines = [(n, fn) for (n, avail, fn) in ENGINES if avail()]
    names = [n for n, _ in engines]

    listing = subprocess.run([ZETH_RUN, "--list"], capture_output=True, text=True).stderr
    corpus = [line.split() for line in listing.splitlines() if line.strip()]

    # Header (Mgas/s per engine; gas column doubles as a correctness check).
    print(bold("\nEVM throughput across clients — Mgas/s, per-opcode-family\n"))
    print(dim("matching gas = identical execution; the fastest engine is highlighted\n"))
    hdr = f"{'feature':<12}{'gas':>12} "
    for n in names:
        hdr += f"{n:>11}"
    hdr += f"{'zeth vs slowest':>17}"
    print(dim(hdr))
    for name, hexcode in corpus:
        results = {}
        for engine, fn in engines:
            try:
                results[engine] = fn(hexcode)
            except Exception as e:  # noqa: BLE001
                results[engine] = (None, None)
                print(red(f"  {engine} failed on {name}: {e}"), file=sys.stderr)

        ref_gas = results["zeth"][0]
        gas_ok = all(g == ref_gas for g, _ in results.values() if g is not None)
        gas_cell = green(f"{ref_gas:>12}") if gas_ok else red(f"{ref_gas:>11}✗")

        mgas = {e: (g / ns * 1000.0) for e, (g, ns) in results.items() if ns}
        fastest = max(mgas.values(), default=0.0)
        slowest = min(mgas.values(), default=0.0)

        row = f"{name:<12}{gas_cell} "
        for engine in names:
            v = mgas.get(engine)
            if v is None:
                row += f"{'—':>11}"
                continue
            cell = f"{v:>11.1f}"
            row += green(cell) if abs(v - fastest) < 1e-6 else cell

        # How many times faster zeth runs than the slowest engine in this row.
        if "zeth" in mgas and slowest > 0:
            speedup = mgas["zeth"] / slowest
            tag = f"{speedup:>16.2f}x"
            row += green(tag) if speedup >= 1 else red(tag)
        else:
            row += f"{'—':>17}"
        print(row)


if __name__ == "__main__":
    main()
