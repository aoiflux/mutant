#!/usr/bin/env sh
#
# Rehearse the whole QUILLDROP workshop, unattended (Linux / macOS).
#
#   ./examples/workshop/rehearse.sh [--mutant PATH] [--keep] [--beat N]
#
# Run from the repository root: every beat names its evidence with
# repository-relative paths. This is the twin of rehearse.ps1.
#
# What it is for. RUN_SHEET_2H.md tells the instructor to prepare alone before
# the room arrives. This runs all ten beats in order, times each one and says
# whether it did what the run sheet promises, so a beat that cannot work on
# this machine is found the evening before rather than in front of attendees.
#
# It behaves differently depending on what is on disk, because the ten .golden
# files describe the empty case and not the solved one:
#
#   no corpus   the ten beats each print one "missing" line and exit cleanly.
#               That is exactly what the .golden files record, so every beat is
#               compared against its golden byte for byte.
#   corpus      the goldens no longer apply. A beat passes if it exits zero,
#               prints its own QUILLDROP header and prints no "missing" line,
#               and the three machine-dependent findings are reported by name.
#
# Only stdout is compared with the golden, because only stdout is what the
# program prints. `mutant --dev` with no password also writes a one-line notice
# about the development key to stderr, and in a shell the sandbox detector
# flags it writes a warning per stage as well. cmd/sweep never sees either --
# it passes a password, so the notice does not fire -- which is why the goldens
# do not carry them and why reading both streams as one would report all ten
# beats as broken. Everything on stderr is still read, and summarised below.
#
# Unlike evidence/build_evidence.sh this script does NOT set -e. The point is to
# run all ten and report, so a failing beat is recorded and the next one runs.
#
# Exit codes. 0 every beat that ran matched its golden. 1 a beat failed or
# differed. 2 it could not start -- wrong directory, or no mutant. 3 the beats
# ran but no golden could be compared, because the goldens and the tree describe
# different worlds. 3 is deliberately not 0: a run that checked nothing is not a
# run that found nothing wrong.

MUTANT=mutant
KEEP=0
ONLY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --mutant) MUTANT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --beat) ONLY="$2"; shift 2 ;;
        -h|--help) sed -n '2,34p' "$0"; exit 0 ;;
        *) echo "rehearse: unknown option $1" >&2; exit 2 ;;
    esac
done

# --beat 3, --beat 03, --beat lies and --beat 06_lies all name one beat.
case "$ONLY" in
    [1-9]) ONLY="0$ONLY" ;;
esac

BEATS="01_scene 02_lure 03_download 04_binary 05_timeline 06_lies 07_inventory 08_rules 09_verdict 10_seal"
WS="examples/workshop"
CASE_DIR="$WS/case"
BODY="$WS/case_quilldrop.body"

# normalize FILE: the same shape sweep.NormalizeOutput gives a golden, which is
# what wrote these ten -- CRLF to LF, no trailing blanks on any line, and
# exactly one newline at the end. Without the last of those every beat reads as
# different, because a program's output ends in a newline and the golden holds
# the text without it. The scratch-root and host-error rewrites that function
# also does are not needed here: this runs in the repository itself, and in
# guard mode no beat prints a host error.
normalize() {
    printf '%s\n' "$(tr -d '\r' < "$1" | sed 's/[[:blank:]]*$//')"
}

if [ ! -f go.mod ] || [ ! -f "$WS/run.sh" ]; then
    echo "rehearse: run this from the repository root."
    echo "  the beats name their evidence as $WS/case/..., so the working"
    echo "  directory decides whether they find anything."
    exit 2
fi

if ! command -v "$MUTANT" >/dev/null 2>&1 && [ ! -x "$MUTANT" ]; then
    echo "rehearse: $MUTANT not found on PATH."
    echo "  build it with: go build -o mutant ."
    echo "  then: ./examples/workshop/rehearse.sh --mutant ./mutant"
    exit 2
fi

echo "QUILLDROP rehearsal"
echo "  mutant   : $MUTANT"
VERSION=$("$MUTANT" --version 2>&1 | head -n 1)
echo "  version  : $VERSION"
case "$VERSION" in
    *2.5.0*) : ;;
    *) echo "             note: the story targets v2.5.0, which is what attendees"
       echo "             will have downloaded. A newer build runs it fine; this is"
       echo "             only a reminder that you are not rehearsing their binary." ;;
esac

# Which evidence paths exist decides what each beat can do: beats 1, 2, 3, 4, 7
# and 9 need the corpus, beats 5, 6 and 8 need the timeline, and beat 10 needs
# the handover beat 9 writes. Reporting the two inputs separately beats one
# yes/no answer, because a half-built corpus is the confusing case.
HAVE_CASE=0
HAVE_BODY=0
[ -d "$CASE_DIR" ] && HAVE_CASE=1
[ -f "$BODY" ] && HAVE_BODY=1
if [ "$HAVE_CASE" -eq 1 ] || [ "$HAVE_BODY" -eq 1 ]; then
    MODE=case
else
    MODE=guard
fi

# Whether the goldens can be compared is a separate question from whether the
# corpus is there, and it is read off the goldens rather than assumed. Today all
# ten hold the single line lib/quilldrop.mut prints when the evidence is absent.
# The workshop readiness report's item 2 will replace them with real output from
# a pre-built corpus, and on that day the two worlds swap: comparing is right
# when the corpus is present and wrong when it is not. Deciding from the corpus
# alone would mean this script quietly stopped comparing anything on the day the
# goldens became worth comparing.
EMPTY_GOLDENS=0
for b in $BEATS; do
    if grep -q -- '- see examples/workshop/README.md' "$WS/$b.golden" 2>/dev/null; then
        EMPTY_GOLDENS=$((EMPTY_GOLDENS + 1))
    fi
done
if [ "$EMPTY_GOLDENS" -eq 10 ]; then
    GOLDEN_WORLD=empty
elif [ "$EMPTY_GOLDENS" -eq 0 ]; then
    GOLDEN_WORLD=case
else
    GOLDEN_WORLD=mixed
fi
COMPARE=0
if [ "$GOLDEN_WORLD" = empty ] && [ "$MODE" = guard ]; then COMPARE=1; fi
if [ "$GOLDEN_WORLD" = case ] && [ "$MODE" = case ]; then COMPARE=1; fi

echo ""
if [ "$MODE" = guard ]; then
    echo "  evidence : none, $CASE_DIR and $BODY are both absent"
else
    echo "  evidence : present"
fi
case "$GOLDEN_WORLD" in
    empty) echo "  goldens  : record the empty case ($EMPTY_GOLDENS of 10 hold the \"missing\" line)" ;;
    case)  echo "  goldens  : record real output ($EMPTY_GOLDENS of 10 hold the \"missing\" line)" ;;
    *)     echo "  goldens  : are mixed ($EMPTY_GOLDENS of 10 hold the \"missing\" line)" ;;
esac
if [ "$GOLDEN_WORLD" = mixed ]; then
    echo "             MIXED, which no single state of the tree produces. Some goldens"
    echo "             were regenerated and some were not; regenerate them all with"
    echo "             go run ./cmd/sweep --update-golden before trusting this run."
fi
if [ "$COMPARE" -eq 1 ]; then
    echo "  mode     : COMPARE. Each beat is checked against its .golden byte for"
    echo "             byte, which is what the readiness report asks for: the diff"
    echo "             must be empty."
elif [ "$MODE" = guard ]; then
    echo "  mode     : NO CORPUS. The goldens record real output, so every beat will"
    echo "             print its \"missing\" line instead and nothing can be compared."
    echo "             Build the corpus and run this again:"
    echo "               go install github.com/aoiflux/fsagen@v0.1.0"
    echo "               ./examples/workshop/evidence/build_evidence.sh"
else
    echo "  mode     : CASE. The goldens record the empty case, so they are not"
    echo "             compared here. A beat passes if it exits 0, prints its"
    echo "             QUILLDROP header and prints no \"missing\" line."
fi
if [ "$MODE" = guard ]; then
    if [ "$COMPARE" -eq 1 ]; then
        echo ""
        echo "             This tests the guard in lib/quilldrop.mut, not the case. To"
        echo "             rehearse the case itself, build the corpus first:"
        echo "               go install github.com/aoiflux/fsagen@v0.1.0"
        echo "               ./examples/workshop/evidence/build_evidence.sh"
    fi
else
    if [ "$HAVE_CASE" -eq 1 ]; then
        FILES=$(find "$CASE_DIR" -type f | wc -l | tr -d ' ')
        echo "  corpus   : $CASE_DIR, $FILES files (the run sheet says 98)"
        if [ "$FILES" -ne 98 ]; then
            echo "             MISMATCH. Check evidence/README.md before teaching this."
        fi
    else
        echo "  corpus   : MISSING $CASE_DIR, so beats 1, 2, 3, 4, 7 and 9 report missing"
    fi
    if [ "$HAVE_BODY" -eq 1 ]; then
        ROWS=$(wc -l < "$BODY" | tr -d ' ')
        echo "  timeline : $BODY, $ROWS rows (the run sheet says 131)"
        if [ "$ROWS" -ne 131 ]; then
            echo "             MISMATCH. Check evidence/README.md before teaching this."
        fi
    else
        echo "  timeline : MISSING $BODY, so beats 5, 6 and 8 report missing"
    fi
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/quilldrop-rehearse-XXXXXXXX")
SUMMARY="$TMP/summary"
: > "$SUMMARY"
FAILED=0
RUN_TOTAL=0
SANDBOX=0
RAN=0

echo ""
echo "----------------------------------------------------------------------"
for b in $BEATS; do
    if [ -n "$ONLY" ] && [ "$b" != "$ONLY" ] && [ "${b#*_}" != "$ONLY" ] && [ "${b%%_*}" != "$ONLY" ]; then
        continue
    fi
    printf '%-14s ' "$b"
    RAN=$((RAN + 1))
    started=$(date +%s)

    # Status is read on the line after the command, with nothing between: a
    # pipe or an echo first would report that command's status instead.
    "$MUTANT" gen --src "$WS/$b.mut" --dev > "$TMP/$b.gen.out" 2> "$TMP/$b.gen.err"
    gen_rc=$?
    if [ "$gen_rc" -ne 0 ]; then
        elapsed=$(( $(date +%s) - started ))
        echo "COMPILE (${elapsed}s) mutant gen refused the source"
        cat "$TMP/$b.gen.out" "$TMP/$b.gen.err" | sed 's/^/    /' | head -n 20
        printf '%-14s %-8s %4ss  %s\n' "$b" COMPILE "$elapsed" "mutant gen refused the source" >> "$SUMMARY"
        FAILED=$((FAILED + 1))
        continue
    fi

    "$MUTANT" "$WS/$b.mu" --dev > "$TMP/$b.out" 2> "$TMP/$b.err"
    rc=$?
    elapsed=$(( $(date +%s) - started ))
    RUN_TOTAL=$((RUN_TOTAL + elapsed))
    lines=$(wc -l < "$TMP/$b.out" | tr -d ' ')

    # The two stderr lines that are a property of how this script invokes
    # mutant rather than of the beat: the development-key notice, and one
    # sandbox warning per stage where the host looks like an analysis machine.
    # Anything else on stderr is the beat's own and is shown.
    if grep -q 'event=sandbox_detected' "$TMP/$b.err" 2>/dev/null; then
        SANDBOX=$((SANDBOX + 1))
    fi
    grep -v '^\[dev\] ' "$TMP/$b.err" 2>/dev/null \
        | grep -v '^\[security\] event=sandbox_detected ' > "$TMP/$b.err.other"

    status=OK
    note=""
    if [ "$rc" -ne 0 ]; then
        status=FAIL
        note="exited $rc"
    elif [ "$COMPARE" -eq 1 ]; then
        normalize "$TMP/$b.out" > "$TMP/$b.norm"
        normalize "$WS/$b.golden" > "$TMP/$b.gold"
        if cmp -s "$TMP/$b.norm" "$TMP/$b.gold"; then
            note="matches $b.golden"
        else
            status=DIFF
            note="differs from $b.golden"
        fi
    else
        if ! grep -q QUILLDROP "$TMP/$b.out"; then
            status=FAIL
            note="printed no QUILLDROP header"
        elif grep -q '^  missing ' "$TMP/$b.out"; then
            status=GUARD
            note="the guard fired, so evidence this beat needs is not there"
        else
            note="$lines lines"
        fi
    fi

    case "$status" in
        FAIL|DIFF) FAILED=$((FAILED + 1)) ;;
    esac
    echo "$status (${elapsed}s) $note"
    if [ "$status" = DIFF ]; then
        diff "$TMP/$b.gold" "$TMP/$b.norm" | sed 's/^/    /' | head -n 20
    elif [ "$status" = FAIL ]; then
        cat "$TMP/$b.out" | sed 's/^/    /' | head -n 20
    fi
    if [ -s "$TMP/$b.err.other" ]; then
        echo "    unexpected on stderr:"
        sed 's/^/      /' "$TMP/$b.err.other" | head -n 10
    fi
    printf '%-14s %-8s %4ss  %s\n' "$b" "$status" "$elapsed" "$note" >> "$SUMMARY"
done
echo "----------------------------------------------------------------------"

# The three findings the run sheet promises that depend on the volume rather
# than on the code. Each is read out of what the beat actually printed, so this
# is right on NTFS, on ext4, on APFS and on a network share, without guessing
# from the operating system.
if [ "$MODE" = case ]; then
    echo ""
    echo "The findings that depend on this machine:"
    if [ -f "$TMP/03_download.out" ]; then
        if grep -q 'HostUrl=' "$TMP/03_download.out"; then
            echo "  beat 3  the Zone.Identifier stream is there, so the download host"
            echo "          corroborates the email from beat 2. The twist lands."
        else
            echo "  beat 3  no Zone.Identifier: this volume has no named streams, so the"
            echo "          third answer reports nothing. The run sheet calls that the"
            echo "          honest answer, so say it rather than skipping the beat."
        fi
    fi
    if [ -f "$TMP/06_lies.out" ]; then
        if grep -q 'older than its own birth' "$TMP/06_lies.out"; then
            echo "  beat 6  a file is modified before it was born. The central finding fires."
        else
            echo "  beat 6  nothing is older than its own birth. This volume kept no"
            echo "          creation times, so beat 6's central finding cannot fire."
            echo "          Generate on NTFS, or hand out the pre-built corpus"
            echo "          (evidence/README.md, \"Where the pre-built corpus comes from\")."
        fi
    fi
    if [ -f "$TMP/08_rules.out" ]; then
        if grep -q 'fields no event carried' "$TMP/08_rules.out"; then
            echo "  beat 8  the unmatched-fields line is there, which is the beat's point:"
            echo "          the critical rule never ran, so it did not clear the host."
        else
            echo "  beat 8  no unmatched-fields line, and that line is beat 8's twist."
            echo "          Check that quilldrop.sigma.yaml reached sigma_scan."
        fi
    fi
fi

if [ "$SANDBOX" -gt 0 ]; then
    echo ""
    echo "This shell looks like an analysis sandbox to mutant ($SANDBOX of the beats"
    echo "warned). --dev downgrades that to a warning, which is why they ran. An"
    echo "attendee who drops --dev here is halted instead, so teach from PowerShell"
    echo "or cmd on Windows, as README.md says."
fi

echo ""
echo "Summary"
sed 's/^/  /' "$SUMMARY"
echo ""
echo "  machine time: ${RUN_TOTAL}s across the beats that ran. That is compile and"
echo "  run only. RUN_SHEET_2H.md allocates ten minutes a beat for asking the"
echo "  question, writing the file and reading the output, which is teaching time"
echo "  and is not measured here."

# A .mu is build output: mutant gen rewrites one in about a second from a
# committed source, and *.mu is gitignored. All ten go, not only the ones this
# run made -- preserving whatever happened to be there already meant the litter
# from one interrupted run stayed for every later run to step around, and made
# the count printed below depend on history rather than on the tree. --keep is
# for when you want to inspect a compiled beat afterwards.
if [ "$KEEP" -eq 0 ]; then
    removed=0
    for b in $BEATS; do
        if [ -f "$WS/$b.mu" ]; then
            # ${WS:?} and ${b:?} stop the shell rather than letting an empty
            # variable turn this into a removal of something else entirely.
            rm -f "${WS:?}/${b:?}.mu"
            removed=$((removed + 1))
        fi
    done
    if [ "$removed" -gt 0 ]; then
        echo "  removed $removed compiled .mu file(s); --keep leaves them in place"
    fi
fi
rm -rf "${TMP:?}"

echo ""
if [ "$FAILED" -gt 0 ]; then
    echo "$FAILED beat(s) did not do what this mode expects. Not ready to teach."
    exit 1
fi
# "All ten" is only true of a whole run: --beat names one, and saying ten of it
# would be the kind of claim this script exists to stop someone making.
WHICH="All ten beats"
if [ "$RAN" -ne 10 ]; then
    WHICH="$RAN of ten beats (--beat)"
fi
if [ "$COMPARE" -eq 1 ] && [ "$MODE" = guard ]; then
    echo "$WHICH printed what the golden records. The guard works, and the case"
    echo "itself is untested until you build the corpus and run this again."
elif [ "$COMPARE" -eq 1 ]; then
    echo "$WHICH matched its golden with the corpus in place. The diff is empty,"
    echo "which is what the readiness report asks of a rehearsal."
else
    echo "$WHICH ran, and nothing was compared with a golden -- see the mode line"
    echo "above for why. Read the machine-dependent findings before teaching, and"
    echo "treat this as unverified rather than passed."
    exit 3
fi
