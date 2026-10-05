#!/usr/bin/env sh
#
# Build the QUILLDROP evidence corpus (Linux / macOS).
#
#   ./examples/workshop/evidence/build_evidence.sh
#
# Run from the repository root. Requires fsagen on PATH, at this exact version
# -- @latest became v0.2.0 on 2026-10-02 and the playbook is written for v0.1.0:
#   go install github.com/aoiflux/fsagen@v0.1.0
#
# Mark-of-the-Web and the alternate data stream are NTFS features, so on ext4 or
# APFS this needs --on-unsupported=skip, which is passed below. Two steps pay
# for it: beat 3's ADS line reports nothing, and -- less obviously -- the
# modelled timeline comes back with every crtime at 0, so beat 6's "older than
# its own birth" finding cannot fire. This script checks for that after the run
# and says so. Prefer NTFS, or take the pre-built corpus.

set -e

SEED=88412
HERE=$(cd "$(dirname "$0")" && pwd)
PLAYBOOK="$HERE/quilldrop.playbook.yaml"
ROOT="$(dirname "$HERE")/case"
BODYFILE="$(dirname "$HERE")/case_quilldrop.body"

if ! command -v fsagen >/dev/null 2>&1; then
    echo "fsagen not found on PATH."
    echo "  go install github.com/aoiflux/fsagen@v0.1.0"
    exit 1
fi

if [ -d "$ROOT" ]; then
    echo "removing previous corpus: $ROOT"
    rm -rf "$ROOT"
fi

echo "generating corpus (seed $SEED)..."
# --on-unsupported=skip is a no-op on NTFS, where nothing here is unsupported.
# Elsewhere it is the difference between a corpus and no corpus at all; every
# skip is recorded in "$ROOT".fsagen/run-manifest.json.
fsagen --seed "$SEED" --playbook "$PLAYBOOK" --on-unsupported=skip \
       --timeline "$BODYFILE" --timeline-format bodyfile --timeline-source modelled \
       "$ROOT"

echo ""
echo "evidence ready"
echo "  corpus   : $ROOT"
echo "  files    : $(find "$ROOT" -type f | wc -l)"
echo "  bodyfile : $BODYFILE ($(wc -l < "$BODYFILE") rows)"
# Beat 6 asks whether any file's mtime precedes its crtime. Ask the timeline
# the same question: if nothing answers yes, the beat will find nothing and the
# attendee should be told now rather than wondering later. This tests the
# output rather than guessing from the platform, so it is right on ReFS, on
# FAT32 and on a network share too.
if [ "$(awk -F'|' '$9 < $11' "$BODYFILE" | wc -l)" -eq 0 ]; then
    echo ""
    echo "NOTE: no row in this timeline has a modification time earlier than its"
    echo "      creation time, so beat 6's \"older than its own birth\" finding"
    echo "      will not fire here. That finding needs crtime, which is NTFS."
    echo "      The pre-built corpus keeps it -- see evidence/README.md."
fi

echo ""
echo "Now run the first step:"
echo "  ./examples/workshop/run.sh 01_scene"
