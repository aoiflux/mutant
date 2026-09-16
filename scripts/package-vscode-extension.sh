#!/usr/bin/env bash
set -euo pipefail

EXTENSION_DIR="mutant-vscode-extension"
VSIX_OUT_DIR="dist/vscode-extension"
VSIX_FILE_NAME="mutant-language-tools.vsix"
PUBLISH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --extension-dir)
      EXTENSION_DIR="$2"
      shift 2
      ;;
    --vsix-out-dir)
      VSIX_OUT_DIR="$2"
      shift 2
      ;;
    --vsix-file-name)
      VSIX_FILE_NAME="$2"
      shift 2
      ;;
    --publish)
      PUBLISH=1
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/package-vscode-extension.sh [options]

Options:
  --extension-dir <dir>   Extension directory (default: mutant-vscode-extension)
  --vsix-out-dir <dir>    Output directory for generated vsix (default: dist/vscode-extension)
  --vsix-file-name <name> Output filename for generated vsix (default: mutant-language-tools.vsix)
  --publish               Publish extension instead of packaging a vsix

Packaging also writes a SHA256SUMS beside the vsix. Publishing does not:
there is no local file to vouch for, and the marketplace serves its own.
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

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

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LSP_BUILD_SCRIPT="$REPO_ROOT/lsp/build.sh"
EXT_PATH="$REPO_ROOT/$EXTENSION_DIR"
VSIX_OUT_PATH="$REPO_ROOT/$VSIX_OUT_DIR"
VSIX_PATH="$VSIX_OUT_PATH/$VSIX_FILE_NAME"

if [[ ! -f "$LSP_BUILD_SCRIPT" ]]; then
  echo "LSP build script not found: $LSP_BUILD_SCRIPT" >&2
  exit 1
fi

if [[ ! -d "$EXT_PATH" ]]; then
  echo "Extension directory not found: $EXT_PATH" >&2
  exit 1
fi

echo "[1/3] Build LSP binaries for all supported platforms"
bash "$LSP_BUILD_SCRIPT"

cd "$EXT_PATH"

if [[ ! -d "$EXT_PATH/node_modules" ]]; then
  echo "Installing extension dependencies"
  npm install
fi

# Staging is a separate step: vscode:prepublish compiles only, so that
# package-targets.mjs can stage a single per-target binary without vsce
# re-staging all six behind it. This wrapper builds the universal VSIX, so it
# stages every binary.
echo "[2/3] Stage LSP binaries and compile the extension"
npm run prepare:lsp-bins
npm run vscode:prepublish

mkdir -p "$VSIX_OUT_PATH"

if command -v vsce >/dev/null 2>&1; then
  if [[ "$PUBLISH" -eq 1 ]]; then
    echo "[3/3] Publish extension using vsce"
    vsce publish --allow-missing-repository
  else
    echo "[3/3] Package VSIX using vsce"
    vsce package --allow-missing-repository --out "$VSIX_PATH"
    echo "VSIX created: $VSIX_PATH"
    write_checksums "$VSIX_OUT_PATH" "$VSIX_FILE_NAME"
  fi
else
  if ! command -v npx >/dev/null 2>&1; then
    echo "Neither 'vsce' nor 'npx' was found on PATH. Install Node.js tooling first." >&2
    exit 1
  fi

  if [[ "$PUBLISH" -eq 1 ]]; then
    echo "[3/3] Publish extension using npx @vscode/vsce"
    npx --yes @vscode/vsce publish --allow-missing-repository
  else
    echo "[3/3] Package VSIX using npx @vscode/vsce"
    npx --yes @vscode/vsce package --allow-missing-repository --out "$VSIX_PATH"
    echo "VSIX created: $VSIX_PATH"
    write_checksums "$VSIX_OUT_PATH" "$VSIX_FILE_NAME"
  fi
fi

if [[ "$PUBLISH" -eq 1 ]]; then
  echo "Publish flow complete."
else
  echo "Package flow complete."
fi
