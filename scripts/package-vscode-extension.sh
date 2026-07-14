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

echo "[2/3] Run extension prepublish (stages binaries and compiles)"
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
  fi
fi

if [[ "$PUBLISH" -eq 1 ]]; then
  echo "Publish flow complete."
else
  echo "Package flow complete."
fi
