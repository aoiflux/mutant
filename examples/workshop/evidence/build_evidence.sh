#!/usr/bin/env sh
#
# Build the QUILLDROP evidence corpus (Linux / macOS).
#
#   ./examples/workshop/evidence/build_evidence.sh
#
# Run from the repository root. Requires fsagen on PATH:
#   go install github.com/aoiflux/fsagen@latest
#
# Mark-of-the-Web and the alternate data stream are NTFS features. On ext4 or
# APFS the corpus still builds and nine of the ten steps are unaffected; beat 3
# reports that the stream is not there, which is the honest answer.

set -e

SEED=88412
HERE=$(cd "$(dirname "$0")" && pwd)
PLAYBOOK="$HERE/quilldrop.playbook.yaml"
ROOT="$(dirname "$HERE")/case"
BODYFILE="$(dirname "$HERE")/case_quilldrop.body"

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
fsagen --seed "$SEED" --playbook "$PLAYBOOK" \
       --timeline "$BODYFILE" --timeline-format bodyfile --timeline-source modelled \
       "$ROOT"

echo ""
echo "evidence ready"
echo "  corpus   : $ROOT"
echo "  files    : $(find "$ROOT" -type f | wc -l)"
echo "  bodyfile : $BODYFILE ($(wc -l < "$BODYFILE") rows)"
echo ""
echo "Now run the first step:"
echo "  ./examples/workshop/run.sh 01_scene"
