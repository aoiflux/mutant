#!/usr/bin/env bash
# Measures test coverage per package, both ways, and prints the table.
#
# Unit coverage credits a package only for its own tests; cross-package
# coverage (-coverpkg=./...) credits it for every test in the module that runs
# its code. Both go into the release review's test-coverage report. This is a
# measurement, not a gate. Nothing is written into the working tree.
#
#   scripts/coverage.sh [--go go1.26.2] [--out-dir DIR]

set -u
GO=go
OUT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --go) GO="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "coverage: unknown option $1" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.." || exit 2
[ -z "$OUT_DIR" ] && OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mutant-coverage-XXXXXXXX")"
mkdir -p "$OUT_DIR"

CGO_ENABLED=0 "$GO" test ./... -count=1 -covermode=atomic -coverprofile="$OUT_DIR/unit.out" >"$OUT_DIR/unit.log" 2>&1 ||
  echo "warning: some tests failed; coverage still measured (see $OUT_DIR/unit.log)" >&2
CGO_ENABLED=0 "$GO" test ./... -count=1 -covermode=atomic -coverpkg=./... -coverprofile="$OUT_DIR/cross.out" >"$OUT_DIR/cross.log" 2>&1 ||
  echo "warning: some tests failed under -coverpkg; coverage still measured (see $OUT_DIR/cross.log)" >&2

"$GO" run ./cmd/covreport -unit "$OUT_DIR/unit.out" -cross "$OUT_DIR/cross.out" -o "$OUT_DIR/coverage.md"
echo
echo "Profiles and table in $OUT_DIR"
