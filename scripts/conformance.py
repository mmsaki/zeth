#!/usr/bin/env python3
"""Conformance sweep that streams each test name as it runs, then prints a
per-category and grand total (root-checked). Categories run as a batch; if a
batch crashes (a fixture that segfaults the ReleaseFast binary) it falls back
to per-file so one bad input doesn't poison the rest.

Usage:  python3 scripts/conformance.py [runner] [tests-subdir]
        runner       = statetest (default) | blocktest
        tests-subdir = GeneralStateTests (default) | BlockchainTests
"""

import glob
import os
import re
import shutil
import subprocess
import sys

WIDTH = shutil.get_terminal_size((100, 20)).columns

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = sys.argv[1] if len(sys.argv) > 1 else "statetest"
SUBDIR = sys.argv[2] if len(sys.argv) > 2 else "GeneralStateTests"
BIN = os.path.join(ROOT, "zig-out", "bin", RUNNER)
TESTS = os.path.join(ROOT, "ethereum-tests", SUBDIR)

ANSI = re.compile(r"\x1b\[[0-9;]*m")
SUMMARY = re.compile(r"(\d+) passed.*?(\d+) failed.*?(\d+) skipped")
# Default: stop at the first failing fixture, like a compile error. ALL=1 runs
# the whole suite (past failures) for full pass-rate counts.
ALL = os.environ.get("ALL") not in (None, "", "0")
STOP = not ALL
ENV = dict(os.environ, ZETH_ALL="1") if ALL else dict(os.environ)


PASS_MARK = "\x1b[32m✓\x1b[0m"
FAIL_MARK = "\x1b[31m✗\x1b[0m"


def run(files, live):
    """Run the binary on `files`. In `live` mode print a pytest-style row of
    ✓/✗ marks as each test reports, buffering the verbose failure detail to
    print afterwards. Returns (pass, fail, skip, crashed, fail_lines)."""
    try:
        p = subprocess.Popen([BIN, *files], stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, text=True, bufsize=1, env=ENV)
        res = None
        fail_lines = []        # buffered verbose failure output (with color)
        col = [0]              # marks printed on the current row

        def mark(m):
            if not live:
                return
            sys.stdout.write(m)
            col[0] += 1
            if col[0] % (WIDTH - 4) == 0:
                sys.stdout.write("\n  ")
            sys.stdout.flush()

        for raw in (p.stderr or []):
            clean = ANSI.sub("", raw).rstrip("\n")
            m = SUMMARY.search(clean)
            if m:
                res = (int(m[1]), int(m[2]), int(m[3]))
                continue
            if "FAIL" in clean:
                mark(FAIL_MARK)
                fail_lines.append("  " + raw.rstrip())
            elif any(k in clean for k in ("got ", "want ", "balance", "nonce", "slot", "mismatch")):
                fail_lines.append("    " + clean.strip())   # diff detail
            elif "...OK" in clean or "...ok" in clean.lower():
                mark(PASS_MARK)
        p.wait()
        if res:
            return res[0], res[1], res[2], 0, fail_lines
    except Exception:
        pass
    if len(files) == 1:
        return 0, 0, 0, 1, []
    # Batch crashed — recover by running each file alone (quietly).
    tp = tf = ts = tx = 0
    for one in files:
        dp, df, ds, dx, _ = run([one], False)
        tp += dp; tf += df; ts += ds; tx += dx
    return tp, tf, ts, tx, []


def main():
    if not os.path.exists(BIN):
        print(f"building {RUNNER} ...")
        subprocess.run(["zig", "build", "-Doptimize=ReleaseFast"], cwd=ROOT, check=True)

    cats = sorted(d for d in glob.glob(os.path.join(TESTS, "*")) if os.path.isdir(d))
    print(f"\n\x1b[1m{SUBDIR} conformance — root-checked, fork=Prague\x1b[0m\n")

    tot = [0, 0, 0, 0]
    all_fails = []
    for cat in cats:
        files = [f for f in glob.glob(os.path.join(cat, "**", "*.json"), recursive=True)
                 if ".meta" not in f]
        if not files:
            continue
        name = os.path.basename(cat)
        # Category header, then the ✓/✗ graph row, then the count.
        sys.stdout.write(f"\x1b[36m▶ {name}\x1b[0m \x1b[2m({len(files)} files)\x1b[0m\n  ")
        sys.stdout.flush()
        p, f, s, x, fails = run(files, True)
        for i, v in enumerate((p, f, s, x)):
            tot[i] += v
        tag = PASS_MARK if (f == 0 and x == 0 and p > 0) else FAIL_MARK
        print(f"\n  \x1b[2m{name}: {p} passed, {f} failed, {x} crashed\x1b[0m {tag}\n")
        all_fails += fails
        if STOP and (f > 0 or x > 0):
            print("\n".join(all_fails))
            print("\n\x1b[1mstopped at first failure — run `ALL=1 make ...` for the full sweep\x1b[0m")
            sys.exit(1)

    # After the whole graph, print the verbose failures.
    if all_fails:
        print("\x1b[1m── failures ──\x1b[0m")
        print("\n".join(all_fails))
        print()

    p, f, s, x = tot
    rate = p / max(1, p + f) * 100
    print(f"\x1b[1mTOTAL  {p} passed / {p+f} executed = {rate:.1f}%  "
          f"({f} failed, {s} skipped, {x} crashed)\x1b[0m\n")


if __name__ == "__main__":
    main()
