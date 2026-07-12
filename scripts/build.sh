#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="dist"
ASSETS_OUT="releaseassets"
FINAL_NAME="mutant"
HOST_ONLY=0
WASM_REPL=0
WASM_OUT_DIR="examples/wasm-repl"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --assets-out)
      ASSETS_OUT="$2"
      shift 2
      ;;
    --final-name)
      FINAL_NAME="$2"
      shift 2
      ;;
    --host-only)
      HOST_ONLY=1
      shift
      ;;
    --wasm-repl)
      WASM_REPL=1
      shift
      ;;
    --wasm-out-dir)
      WASM_OUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/build.sh [options]

Options:
  --output-dir <dir>  Output directory for binaries (default: dist)
  --assets-out <dir>  Release assets output directory (default: releaseassets)
  --final-name <name> Final binary name (default: mutant)
  --host-only         Build only GOHOSTOS/GOHOSTARCH target
  --wasm-repl         Build browser REPL wasm artifact and copy wasm_exec.js
  --wasm-out-dir <d>  Output directory for wasm artifacts (default: examples/wasm-repl)
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="$REPO_ROOT/$OUTPUT_DIR"
BOOTSTRAP_BIN="$OUTPUT_PATH/mutant-bootstrap"

TARGETS=(
  "windows amd64 .exe"
  "windows arm64 .exe"
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
)

resolve_tool() {
  local tool_name="$1"
  local resolved

  if resolved="$(command -v "$tool_name" 2>/dev/null)"; then
    printf '%s\n' "$resolved"
    return 0
  fi

  if command -v cmd.exe >/dev/null 2>&1; then
    resolved="$(cmd.exe /c where "$tool_name" 2>/dev/null | tr -d '\r' | head -n 1 || true)"
    if [[ -n "$resolved" ]]; then
      printf '%s\n' "$resolved"
      return 0
    fi
  fi

  return 1
}

ps_quote() {
  local value="$1"
  value="${value//\'/\'\'}"
  printf "'%s'" "$value"
}

to_windows_path() {
  local value="$1"
  if [[ "$value" =~ ^/mnt/([a-zA-Z])/(.*)$ ]]; then
    local drive="${BASH_REMATCH[1]^^}"
    local rest="${BASH_REMATCH[2]//\//\\}"
    printf '%s:\%s\n' "$drive" "$rest"
    return 0
  fi

  printf '%s\n' "$value"
}

run_tool() {
  local tool_path="$1"
  shift

  if [[ "$tool_path" =~ ^[A-Za-z]:\\ || "$tool_path" =~ \.exe$ ]]; then
    if [[ -z "$POWERSHELL_BIN" ]]; then
      echo "PowerShell not found. Cannot execute Windows tool path: $tool_path" >&2
      return 1
    fi

    local ps_prefix=""
    local ps_command=""
    local env_name
    for env_name in CGO_ENABLED GOOS GOARCH; do
      if [[ -n "${!env_name-}" ]]; then
        ps_prefix+="\$env:$env_name = $(ps_quote "${!env_name}"); "
      fi
    done

    ps_command="$ps_prefix& $(ps_quote "$(to_windows_path "$tool_path")")"
    for arg in "$@"; do
      ps_command+=" $(ps_quote "$(to_windows_path "$arg")")"
    done
    "$POWERSHELL_BIN" -NoProfile -Command "$ps_command"
    return $?
  fi

  "$tool_path" "$@"
}

GO_BIN="$(resolve_tool go || true)"
POWERSHELL_BIN="$(resolve_tool powershell.exe || true)"

if [[ -z "$POWERSHELL_BIN" ]]; then
  POWERSHELL_BIN="$(resolve_tool pwsh || true)"
fi

if [[ -z "$GO_BIN" ]]; then
  echo "go toolchain not found. Install Go or make sure the Go shim is visible to bash." >&2
  exit 1
fi

GO_BUILD_FLAGS=(
  -trimpath
  -buildvcs=false
  -ldflags
  "-s -w -buildid="
)

GO_HOST_OS="$(run_tool "$GO_BIN" env GOHOSTOS)"
GO_HOST_ARCH="$(run_tool "$GO_BIN" env GOHOSTARCH)"

if [[ "$GO_HOST_OS" == "windows" ]]; then
  BOOTSTRAP_BIN+=".exe"
fi

if [[ "$HOST_ONLY" -eq 1 ]]; then
  FILTERED=()
  for target in "${TARGETS[@]}"; do
    read -r GOOS GOARCH _ <<<"$target"
    if [[ "$GOOS" == "$GO_HOST_OS" && "$GOARCH" == "$GO_HOST_ARCH" ]]; then
      FILTERED+=("$target")
    fi
  done

  if [[ "${#FILTERED[@]}" -eq 0 ]]; then
    echo "No host-matching target found for $GO_HOST_OS/$GO_HOST_ARCH" >&2
    exit 1
  fi

  TARGETS=("${FILTERED[@]}")
fi

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

TOTAL_STEPS=3
if [[ "$WASM_REPL" -eq 1 ]]; then
  TOTAL_STEPS=4
fi
CURRENT_STEP=0

draw_progress() {
  local current="$1"
  local total="$2"
  local width=30
  local filled=$(( current * width / total ))
  local empty=$(( width - filled ))
  printf "${YELLOW}["
  printf "%0.s#" $(seq 1 "$filled")
  printf "%0.s-" $(seq 1 "$empty")
  printf "] %d/%d${RESET}\n" "$current" "$total"
}

run_step() {
  CURRENT_STEP=$((CURRENT_STEP + 1))
  local msg="$1"
  echo -e "${CYAN}[$CURRENT_STEP/$TOTAL_STEPS] $msg${RESET}"
  draw_progress "$CURRENT_STEP" "$TOTAL_STEPS"
}

assert_releaseassets_data_clean() {
  local data_dir="$REPO_ROOT/$ASSETS_OUT/data"
  if [[ ! -d "$data_dir" ]]; then
    echo "Required assets data directory not found: $data_dir" >&2
    exit 1
  fi

  local entries
  mapfile -t entries < <(find "$data_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
  local has_placeholder=0
  local unexpected=()

  for entry in "${entries[@]}"; do
    if [[ "$entry" == "placeholder.bin" ]]; then
      has_placeholder=1
    else
      unexpected+=("$entry")
    fi
  done

  if [[ "${#unexpected[@]}" -gt 0 ]]; then
    for entry in "${unexpected[@]}"; do
      rm -rf -- "${data_dir:?}/$entry"
    done
    echo "    Pruned $data_dir to placeholder.bin only."
  fi

  if [[ "$has_placeholder" -ne 1 ]]; then
    echo "Expected '$data_dir' to contain placeholder.bin before build actions, but it is missing." >&2
    exit 1
  fi
}

mkdir -p "$OUTPUT_PATH"
cd "$REPO_ROOT"
assert_releaseassets_data_clean

run_step "Compile Go bootstrap binary"
run_tool "$GO_BIN" build "${GO_BUILD_FLAGS[@]}" -o "$BOOTSTRAP_BIN" .
echo "    Bootstrap binary: $BOOTSTRAP_BIN"

run_step "Generate embedded release assets"
run_tool "$BOOTSTRAP_BIN" gen --release-assets -out "$ASSETS_OUT"
echo "    Assets directory: $REPO_ROOT/$ASSETS_OUT"

run_step "Recompile final Go binaries with release assets"
OLD_CGO_ENABLED="${CGO_ENABLED-}"
OLD_GOOS="${GOOS-}"
OLD_GOARCH="${GOARCH-}"

export CGO_ENABLED=0

for target in "${TARGETS[@]}"; do
  read -r T_GOOS T_GOARCH T_EXE_SUFFIX <<<"$target"

  export GOOS="$T_GOOS"
  export GOARCH="$T_GOARCH"

  FINAL_BIN="$OUTPUT_PATH/$FINAL_NAME-$T_GOOS-$T_GOARCH$T_EXE_SUFFIX"
  echo "    Go => $T_GOOS/$T_GOARCH"
  run_tool "$GO_BIN" build "${GO_BUILD_FLAGS[@]}" -o "$FINAL_BIN" .
  echo "      binary: $FINAL_BIN"
done

export CGO_ENABLED="$OLD_CGO_ENABLED"
export GOOS="$OLD_GOOS"
export GOARCH="$OLD_GOARCH"

if [[ "$WASM_REPL" -eq 1 ]]; then
  run_step "Build browser REPL wasm artifacts"
  mkdir -p "$REPO_ROOT/$WASM_OUT_DIR"

  GO_ROOT="$(run_tool "$GO_BIN" env GOROOT)"
  WASM_EXEC_SRC="$GO_ROOT/lib/wasm/wasm_exec.js"
  if [[ ! -f "$WASM_EXEC_SRC" ]]; then
    WASM_EXEC_SRC="$GO_ROOT/misc/wasm/wasm_exec.js"
  fi
  if [[ ! -f "$WASM_EXEC_SRC" ]]; then
    echo "wasm_exec.js not found under '$GO_ROOT/lib/wasm' or '$GO_ROOT/misc/wasm'" >&2
    exit 1
  fi

  cp "$WASM_EXEC_SRC" "$REPO_ROOT/$WASM_OUT_DIR/wasm_exec.js"

  OLD_GOOS_WASM="${GOOS-}"
  OLD_GOARCH_WASM="${GOARCH-}"
  OLD_CGO_WASM="${CGO_ENABLED-}"
  export GOOS="js"
  export GOARCH="wasm"
  export CGO_ENABLED=0
  run_tool "$GO_BIN" build "${GO_BUILD_FLAGS[@]}" -o "$REPO_ROOT/$WASM_OUT_DIR/mutant_repl.wasm" ./cmd/replwasm

  export GOOS="$OLD_GOOS_WASM"
  export GOARCH="$OLD_GOARCH_WASM"
  export CGO_ENABLED="$OLD_CGO_WASM"

  echo "    wasm: $REPO_ROOT/$WASM_OUT_DIR/mutant_repl.wasm"
  echo "    wasm_exec.js: $REPO_ROOT/$WASM_OUT_DIR/wasm_exec.js"
fi

echo -e "${GREEN}Build complete.${RESET}"
echo -e "${GREEN}  Final binaries in: $OUTPUT_PATH${RESET}"

rm "$BOOTSTRAP_BIN"
echo -e "${CYAN}  Cleaned Bootstrap Bin"
