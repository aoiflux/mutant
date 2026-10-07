#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="dist"
FINAL_NAME="mlsp"
HOST_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
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
    -h|--help)
      cat <<'EOF'
Usage: ./lsp/build.sh [options]

Options:
  --output-dir <dir>  Output directory for binaries (default: dist)
  --final-name <name> Final binary name prefix (default: mlsp)
  --host-only         Build only GOHOSTOS/GOHOSTARCH target

Writes a SHA256SUMS beside the binaries, checkable with
`cd <dir> && sha256sum -c SHA256SUMS`.
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

LSP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="$LSP_ROOT/$OUTPUT_DIR"
MAIN_PACKAGE="./cmd/mlsp"

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

# SHA256SUMS is written in the format `sha256sum -c` reads, so whoever downloads
# a binary can verify it with a tool they already have and nothing from this
# project: lowercase hex, two spaces, the file's bare name. Names are bare and
# the file sits beside what it covers, so checking is `cd <dir> && sha256sum -c
# SHA256SUMS` -- which also means a directory the build writes elsewhere gets its
# own SHA256SUMS rather than a path reaching out of this one.
sha256_of() {
  local file="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$file" | cut -d' ' -f1
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$file" | cut -d' ' -f1
    return
  fi

  # Windows without the coreutils that ship with Git for Windows.
  if command -v powershell.exe >/dev/null 2>&1; then
    local win="$file"
    if command -v cygpath >/dev/null 2>&1; then
      win="$(cygpath -w -- "$file")"
    fi
    win="${win//\'/\'\'}"
    powershell.exe -NoProfile -Command \
      "(Get-FileHash -Algorithm SHA256 -LiteralPath '$win').Hash.ToLower()" | tr -d '\r'
    return
  fi

  echo "No SHA-256 tool found. Install coreutils (sha256sum), or run this on a host with shasum or PowerShell." >&2
  return 1
}

# write_checksums <dir> <name>... -- sorted under LC_ALL=C so the same build
# writes the same file, and refusing rather than recording a hash of nothing if
# a name is missing.
write_checksums() {
  local dir="$1"
  shift

  local sums="$dir/SHA256SUMS"
  local tmp="$sums.tmp"
  : >"$tmp"

  local name
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    if [[ ! -f "$dir/$name" ]]; then
      rm -f -- "$tmp"
      echo "Cannot checksum a file the build did not produce: $dir/$name" >&2
      return 1
    fi
    printf '%s  %s\n' "$(sha256_of "$dir/$name")" "$name" >>"$tmp"
  done < <(printf '%s\n' "$@" | LC_ALL=C sort)

  mv -f -- "$tmp" "$sums"
  echo "    checksums: $sums"
}

mkdir -p "$OUTPUT_PATH"
cd "$LSP_ROOT"

OLD_CGO_ENABLED="${CGO_ENABLED-}"
OLD_GOOS="${GOOS-}"
OLD_GOARCH="${GOARCH-}"

export CGO_ENABLED=0

BINARY_NAMES=()
for target in "${TARGETS[@]}"; do
  read -r T_GOOS T_GOARCH T_EXE_SUFFIX <<<"$target"

  export GOOS="$T_GOOS"
  export GOARCH="$T_GOARCH"

  BINARY_NAME="$FINAL_NAME-$T_GOOS-$T_GOARCH$T_EXE_SUFFIX"
  FINAL_BIN="$OUTPUT_PATH/$BINARY_NAME"
  echo "Building $T_GOOS/$T_GOARCH -> $FINAL_BIN"
  run_tool "$GO_BIN" build "${GO_BUILD_FLAGS[@]}" -o "$FINAL_BIN" "$MAIN_PACKAGE"
  BINARY_NAMES+=("$BINARY_NAME")
done

export CGO_ENABLED="$OLD_CGO_ENABLED"
export GOOS="$OLD_GOOS"
export GOARCH="$OLD_GOARCH"

write_checksums "$OUTPUT_PATH" "${BINARY_NAMES[@]}"

echo "LSP build complete."
echo "  Output directory: $OUTPUT_PATH"
echo "  Verify with: cd \"$OUTPUT_PATH\" && sha256sum -c SHA256SUMS"
