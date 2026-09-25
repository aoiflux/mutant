#!/usr/bin/env bash
# Runs every check a Mutant release has to pass, and prints one PASS/FAIL table.
#
# The bash twin of scripts/release_gate.ps1, for Linux, macOS and WSL; on
# Windows use the PowerShell one. The project runs no CI, so these are the
# checks a contributor runs before handing a change over and the owner runs
# before tagging. Nothing is read from the environment: every choice is an
# option, and nothing is written into the working tree -- builds, logs and
# scratch copies go under --log-dir.
#
#   scripts/release_gate.sh [--go go1.26.6] [--fuzz-time 30s] [--quick] [--vuln] [--log-dir DIR]
#
# The expected Go toolchain is read from go.mod, not written here.

set -u

GO=go
FUZZ_TIME=""
QUICK=0
VULN=0
LOG_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --go) GO="$2"; shift 2 ;;
    --fuzz-time) FUZZ_TIME="$2"; shift 2 ;;
    --quick) QUICK=1; shift ;;
    --vuln) VULN=1; shift ;;
    --log-dir) LOG_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "release_gate: unknown option $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

if [ -z "$LOG_DIR" ]; then
  LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mutant-release-gate-XXXXXXXX")"
fi

# absolute_path DIR: DIR made absolute through its deepest existing ancestor, so
# symlinks resolve the same way pwd -P resolves the repository root.
absolute_path() {
  local p="$1" rest=""
  case "$p" in /*) ;; *) p="$PWD/$p" ;; esac
  while [ ! -d "$p" ]; do rest="/$(basename "$p")$rest"; p="$(dirname "$p")"; done
  echo "$(cd "$p" && pwd -P)$rest"
}

# The gofmt step writes an LF copy of every Go file under --log-dir. Inside the
# repository those copies are packages of the module: go test ./... would
# compile them beside the real ones and every tree-walking guard would count
# them twice, so the gate would fail for a reason that is nowhere in the code.
ROOT_PHYSICAL="$(pwd -P)"
case "$(absolute_path "$LOG_DIR")/" in
  "$ROOT_PHYSICAL"/*)
    echo "release_gate: --log-dir $LOG_DIR is inside the repository ($ROOT_PHYSICAL). The gate writes Go files there, which go test ./... would take for part of the module; pick a directory outside it." >&2
    exit 2 ;;
esac
mkdir -p "$LOG_DIR"

TARGETS="windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"
RACE_PACKAGES="./vm/... ./builtin/... ./serve/... ./security/... ./object/... ./runtime/... ./repl/... ./dap/... ./sema/... ./lsp/... ./cli/..."

GO_MOD_VERSION="$(sed -n 's/^go[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' go.mod | head -n 1)"
VERSION="$(sed -n 's/.*const Version = "\([^"]*\)".*/\1/p' global/const.go | head -n 1)"
echo "Mutant $VERSION release gate; go.mod pins go $GO_MOD_VERSION; logs in $LOG_DIR"
echo

RESULTS=()
FAILED=0

# step NAME FUNCTION: runs FUNCTION with the step's log path as $1. A function
# that prints a line starting "SKIP" is recorded as skipped.
step() {
  local name="$1" fn="$2" log
  log="$LOG_DIR/$(echo "$name" | tr -c 'A-Za-z0-9' '_').log"
  local started=$SECONDS status=PASS note code
  echo "==> $name"
  # Assigned apart from any `local`: `local x=$(cmd)` reports local's own
  # status, which would pass every step.
  note="$("$fn" "$log" 2>>"$log")"
  code=$?
  if [ $code -ne 0 ]; then
    status=FAIL
    FAILED=$((FAILED + 1))
    [ -z "$note" ] && note="exit $code (see $log)"
  elif [ "${note#SKIP}" != "$note" ]; then
    status=SKIP
  fi
  RESULTS+=("$(printf '%-48s %-5s %5ss  %s' "$name" "$status" "$((SECONDS - started))" "$note")")
  echo "    $status $note"
}

run() { # run LOG CMD...: append CMD's output to LOG, fail on non-zero exit.
  local log="$1"; shift
  echo "> $*" >>"$log"
  "$@" >>"$log" 2>&1
}

toolchain() {
  local got; got="$("$GO" env GOVERSION)"
  if [ "$got" != "go$GO_MOD_VERSION" ]; then
    echo "go.mod pins go $GO_MOD_VERSION but $GO is $got; install go$GO_MOD_VERSION with golang.org/dl and pass --go go$GO_MOD_VERSION"
    return 1
  fi
}

gofmt_lf() {
  local log="$1" copy="$LOG_DIR/gofmt-lf"
  # Untracked files git does not ignore are the ones a change is about to add.
  git ls-files --cached --others --exclude-standard '*.go' | while IFS= read -r f; do
    mkdir -p "$copy/$(dirname "$f")"
    tr -d '\r' <"$f" >"$copy/$f"
  done
  local unformatted; unformatted="$("$("$GO" env GOROOT)/bin/gofmt" -l "$copy")"
  echo "$unformatted" >"$log"
  if [ -n "$unformatted" ]; then
    echo "$(echo "$unformatted" | wc -l | tr -d ' ') file(s) not gofmt-clean (see $log)"
    return 1
  fi
}

vet_os() { run "$1" env GOOS="$VET_OS" GOARCH=amd64 CGO_ENABLED=0 "$GO" vet ./...; }

cross_compile() {
  local log="$1" out="$LOG_DIR/bin" t os arch suffix
  for t in $TARGETS; do
    os="${t%/*}"; arch="${t#*/}"; suffix=""
    [ "$os" = windows ] && suffix=.exe
    run "$log" env GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 "$GO" build -trimpath -o "$out/mutant-$os-$arch$suffix" . || return 1
    run "$log" env GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 "$GO" build -trimpath -o "$out/mlsp-$os-$arch$suffix" ./lsp/cmd/mlsp || return 1
  done
  run "$log" env GOOS=js GOARCH=wasm CGO_ENABLED=0 "$GO" build -o "$out/mutant_repl.wasm" ./cmd/replwasm
}

go_test() { run "$1" env CGO_ENABLED=0 "$GO" test ./... -count=1; }

race() {
  if ! command -v gcc >/dev/null 2>&1; then echo "SKIP: no gcc; the race detector needs cgo"; return 0; fi
  # shellcheck disable=SC2086
  run "$1" env CGO_ENABLED=1 "$GO" test -race -count=1 -timeout 45m $RACE_PACKAGES
}

fuzz() {
  local log="$1" pending="" ran=0 line target
  if [ -z "$FUZZ_TIME" ]; then echo "SKIP: seed corpora ran in go test; pass --fuzz-time to fuzz"; return 0; fi
  while IFS= read -r line; do
    case "$line" in
      Fuzz*) pending="$pending $line" ;;
      ok*)
        pkg="$(echo "$line" | awk '{print $2}')"
        for target in $pending; do
          run "$log" env CGO_ENABLED=0 "$GO" test -run '^$' -fuzz "^$target\$" -fuzztime "$FUZZ_TIME" "$pkg" || return 1
          ran=$((ran + 1))
        done
        pending="" ;;
    esac
  done < <(env CGO_ENABLED=0 "$GO" test -list '^Fuzz' ./... 2>&1)
  if [ "$ran" -eq 0 ]; then echo "SKIP: no fuzz targets"; else echo "$ran target(s), $FUZZ_TIME each"; fi
}

gendocs_check() { run "$1" env CGO_ENABLED=0 "$GO" run ./cmd/gendocs -check; }

# The sweep runs the binary a release ships -- this toolchain, no cgo -- not
# one it would otherwise build with whatever go is first on the PATH.
sweep_golden() {
  local bin="$LOG_DIR/bin/sweep/mutant"
  run "$1" env CGO_ENABLED=0 "$GO" build -trimpath -o "$bin" . || return 1
  run "$1" env CGO_ENABLED=0 "$GO" run ./cmd/sweep --levels 0,5,10 --golden --mutant "$bin" || return 1
  grep 'printed exactly what' "$1" | tail -n 1
}

mod_check() { run "$1" "$GO" mod verify && run "$1" "$GO" mod tidy -diff; }

changelog_date() {
  local tag="v$VERSION" tag_date stated
  tag_date="$(git for-each-ref --format='%(creatordate:short)' "refs/tags/$tag")"
  if [ -z "$tag_date" ]; then echo "SKIP: $tag is not tagged yet"; return 0; fi
  stated="$(grep -E "^## \[$VERSION\]" CHANGELOG.md | head -n 1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}')"
  if [ "$stated" != "$tag_date" ]; then
    echo "CHANGELOG.md dates $VERSION '$stated'; the tag $tag was made $tag_date"
    return 1
  fi
}

vuln() { run "$1" env CGO_ENABLED=0 "$GO" run golang.org/x/vuln/cmd/govulncheck@latest ./...; }

step "toolchain is the pinned one" toolchain
step "gofmt (on LF copies)" gofmt_lf
for VET_OS in linux windows darwin; do step "go vet ($VET_OS)" vet_os; done
if [ "$QUICK" -eq 1 ]; then RESULTS+=("$(printf '%-48s %-5s' "cross-compile" SKIP)  SKIP: --quick"); else step "cross-compile (6 targets x mutant+mlsp, wasm)" cross_compile; fi
step "go test ./..." go_test
if [ "$QUICK" -eq 1 ]; then RESULTS+=("$(printf '%-48s %-5s' "race detector" SKIP)  SKIP: --quick"); else step "race detector (test binaries only)" race; fi
step "fuzz targets" fuzz
step "generated docs are current" gendocs_check
if [ "$QUICK" -eq 1 ]; then RESULTS+=("$(printf '%-48s %-5s' "example sweep" SKIP)  SKIP: --quick"); else step "example sweep (golden output, levels 0,5,10)" sweep_golden; fi
step "go mod verify / tidy" mod_check
step "CHANGELOG date matches the tag" changelog_date
# A full gate always runs govulncheck: a reachable vulnerability blocks a
# release. --quick skips it unless --vuln asks for it anyway.
if [ "$QUICK" -eq 1 ] && [ "$VULN" -eq 0 ]; then RESULTS+=("$(printf '%-48s %-5s' "govulncheck" SKIP)  SKIP: --quick"); else step "govulncheck" vuln; fi

echo
printf '%s\n' "${RESULTS[@]}"
echo
if [ "$FAILED" -gt 0 ]; then
  echo "$FAILED step(s) failed. Logs: $LOG_DIR"
  exit 1
fi
echo "Release gate passed. Logs: $LOG_DIR"
