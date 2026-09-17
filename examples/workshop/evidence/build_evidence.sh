#!/usr/bin/env sh
# Build the QUILLDROP evidence corpus (Linux / macOS).
#
#   sh examples/workshop/evidence/build_evidence.sh
#
# Run from the repository root. Requires fsagen on PATH:
#   go install github.com/aoiflux/fsagen@latest
#
# Note: Mark-of-the-Web and alternate data streams are NTFS features. On ext4 or
# APFS the corpus still builds and five of the six tools are unaffected;
# 07_dropzone.mut reports the MoTW stream as absent, which is the honest answer.

set -eu

SEED=88412
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PLAYBOOK="$HERE/quilldrop.playbook.yaml"
ROOT="$HERE/case_quilldrop"
BODYFILE="$HERE/case_quilldrop.body"
CSV_TL="$HERE/case_quilldrop.csv"

if ! command -v fsagen >/dev/null 2>&1; then
    echo "fsagen not found on PATH."
    echo "  go install github.com/aoiflux/fsagen@latest"
    exit 1
fi

if [ -d "$ROOT" ]; then
    echo "removing previous corpus: $ROOT"
    rm -rf "$ROOT"
fi

echo "generating corpus (seed $SEED)..."
fsagen --seed "$SEED" --playbook "$PLAYBOOK" --timeline "$BODYFILE" "$ROOT"

# --timeline alone regenerates from the existing corpus; it does not rebuild it.
echo "generating CSV timeline..."
fsagen --timeline "$CSV_TL" "$ROOT"

COUNT=$(find "$ROOT" -type f | wc -l | tr -d ' ')

echo ""
echo "evidence ready"
echo "  corpus   : $ROOT"
echo "  files    : $COUNT"
echo "  bodyfile : $BODYFILE"
echo "  csv      : $CSV_TL"
echo ""
echo "Now run the first tool:"
echo "  mutant run examples/workshop/07_dropzone.mut -pwd workshop"
