#!/usr/bin/env bash
# Download official ethereum/tests fixtures (cached) and run them against zeth,
# checking results by 32-byte root. One command: `make eels`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$ROOT/.eels-cache"
EELS="$ROOT/zig-out/bin/eels"

# Provenance: official ethereum/tests, pinned to a ref for reproducibility.
# Override with REF=<branch|tag|commit> make eels.
REPO="ethereum/tests"
REF="${REF:-develop}"
SUITE="TrieTests"
BASE="https://raw.githubusercontent.com/${REPO}/${REF}/${SUITE}"

FILES=(
  trietest.json
  trieanyorder.json
  trietest_secureTrie.json
  trieanyorder_secureTrie.json
  hex_encoded_securetrie_test.json
)

echo "source: https://github.com/${REPO}/tree/${REF}/${SUITE}"
echo "cache:  ${CACHE/#$HOME/~}"
echo
mkdir -p "$CACHE"
for f in "${FILES[@]}"; do
  if [ ! -f "$CACHE/$f" ]; then
    echo "  fetch ${BASE}/$f"
    curl -sL --max-time 30 "$BASE/$f" -o "$CACHE/$f"
  fi
done

STATETEST="$ROOT/zig-out/bin/statetest"
TESTS_REPO="$ROOT/ethereum-tests"

echo "== ${SUITE} (root-checked against zeth's MPT) =="
status=0
"$EELS" 0 "$CACHE/trietest.json" "$CACHE/trieanyorder.json" || status=1
"$EELS" 1 "$CACHE/trietest_secureTrie.json" "$CACHE/trieanyorder_secureTrie.json" \
         "$CACHE/hex_encoded_securetrie_test.json" || status=1

# GeneralStateTests (post-state root checked). Requires the cloned tests repo;
# pass a dir/glob with STATE=... to scope it (default: stExample).
if [ -d "$TESTS_REPO/GeneralStateTests" ]; then
  echo
  echo "== GeneralStateTests :: ${STATE:-stExample} (post-state root, fork=Prague) =="
  ZETH_ALL=1 "$STATETEST" "$TESTS_REPO/GeneralStateTests/"${STATE:-stExample}/*.json || status=1
else
  echo
  echo "(skipping GeneralStateTests: clone ethereum/tests to ./ethereum-tests to enable)"
fi
exit $status
