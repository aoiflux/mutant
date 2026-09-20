package builtin

import (
	"errors"
	"testing"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libntfs "github.com/aoiflux/libntfs"

	"mutant/object"
)

// --- the envelope -----------------------------------------------------------

func TestTheTwoByteClassesAreCountedApart(t *testing.T) {
	scan := newSlackScan("ntfs", "/a")
	scan.add(fsSlackRange{Class: fsSlackClassFileSlack, FileOffset: 100, Offset: 4096, Length: 28})
	scan.add(fsSlackRange{Class: fsSlackClassUnwritten, FileOffset: 60, Offset: 8192, Length: 40})
	scan.add(fsSlackRange{Class: fsSlackClassUnwritten, FileOffset: 0, Offset: -1, Length: 2})

	if got := scan.FileSlackBytes; got != 28 {
		t.Errorf("file_slack_bytes = %d, want 28", got)
	}
	if got := scan.UnwrittenBytes; got != 42 {
		t.Errorf("unwritten_bytes = %d, want 42", got)
	}

	hash := scan.toHash("h")
	// A slack total and a valid-data-length gap added together would be a
	// number describing nothing, which is exactly what the class field exists
	// to prevent.
	if got := mustHashIntValue(t, hash, "file_slack_bytes"); got != 28 {
		t.Errorf("rendered file_slack_bytes = %d, want 28", got)
	}
	if got := mustHashIntValue(t, hash, "located_bytes"); got != 68 {
		t.Errorf("located_bytes = %d, want 68", got)
	}
	if got := mustHashIntValue(t, hash, "unlocated_bytes"); got != 2 {
		t.Errorf("unlocated_bytes = %d, want 2", got)
	}
}

func TestAQuestionNeverAskedIsNotAnAnswerOfZero(t *testing.T) {
	scan := newSlackScan("fat", "/deleted.bin")

	hash := scan.toHash("h")
	if mustHashBoolValue(t, hash, "file_slack_checked") {
		t.Error("a scan that never looked reported having looked")
	}
	if got := mustHashIntValue(t, hash, "file_slack_bytes"); got != -1 {
		t.Errorf("file_slack_bytes = %d, want -1 on an unasked question", got)
	}

	scan.answered(fsSlackClassFileSlack)
	answered := scan.toHash("h")
	if !mustHashBoolValue(t, answered, "file_slack_checked") {
		t.Error("an answered question still reported unchecked")
	}
	if got := mustHashIntValue(t, answered, "file_slack_bytes"); got != 0 {
		t.Errorf("file_slack_bytes = %d, want 0 once the question was answered", got)
	}
}

func TestAClassThisFormatCannotRecordIsNamedRatherThanLeftEmpty(t *testing.T) {
	scan := newSlackScan("fat", "/a")
	scan.Classes = []string{fsSlackClassFileSlack}
	scan.unavailable(fsSlackClassUnwritten)

	hash := scan.toHash("h")
	unavailable := mustHashStringArray(t, hash, "classes_unavailable")
	if len(unavailable) != 1 || unavailable[0] != fsSlackClassUnwritten {
		t.Fatalf("classes_unavailable = %v, want [%s]", unavailable, fsSlackClassUnwritten)
	}
	// An empty unwritten list on FAT means the format has no such boundary,
	// not that this file happened to have none.
	if mustHashBoolValue(t, hash, "unwritten_checked") {
		t.Error("a format with no valid-data length reported having checked for one")
	}
}

func TestEveryCountedByteHasARangeBehindIt(t *testing.T) {
	scan := newSlackScan("ntfs", "/a")
	scan.add(fsSlackRange{Class: fsSlackClassFileSlack, FileOffset: 0, Offset: -1, Length: 512})

	hash := scan.toHash("h")
	ranges := mustHashArrayValue(t, hash, "ranges")
	if len(ranges) != 1 {
		t.Fatalf("ranges = %d, want 1", len(ranges))
	}
	// A total with nothing in the array behind it cannot be examined, so an
	// unlocatable byte still gets a row, at offset -1.
	entry, ok := ranges[0].(*object.Hash)
	if !ok {
		t.Fatalf("range is not a HASH. got=%T", ranges[0])
	}
	if got := mustHashIntValue(t, entry, "offset"); got != -1 {
		t.Errorf("offset = %d, want -1", got)
	}
	if got := mustHashIntValue(t, hash, "file_slack_bytes"); got != 512 {
		t.Errorf("file_slack_bytes = %d, want 512", got)
	}
}

func TestARangeOfNoLengthIsNotARange(t *testing.T) {
	scan := newSlackScan("hfs", "/a")
	if scan.add(fsSlackRange{Class: fsSlackClassFileSlack, Offset: 4096, Length: 0}) {
		t.Error("a zero-length range was stored")
	}
	if scan.RangeCount != 0 {
		t.Errorf("range_count = %d, want 0", scan.RangeCount)
	}
	// libhfs returns a final range with Length zero for an over-allocated
	// fork; it is the slack on it that matters, and it arrives as its own row.
	if scan.FileSlackBytes != -1 {
		t.Errorf("file_slack_bytes = %d, want -1", scan.FileSlackBytes)
	}
}

func TestTheRangeCapKeepsTheByteTotalHonestPastIt(t *testing.T) {
	scan := newSlackScan("ext", "/fragmented")
	for i := 0; i < fsSlackMaxRanges+25; i++ {
		scan.add(fsSlackRange{
			Class:      fsSlackClassFileSlack,
			FileOffset: int64(i) * 4096,
			Offset:     int64(i) * 4096,
			Length:     10,
		})
	}

	hash := scan.toHash("h")
	if got := len(mustHashArrayValue(t, hash, "ranges")); got != fsSlackMaxRanges {
		t.Errorf("rendered ranges = %d, want %d", got, fsSlackMaxRanges)
	}
	if got := mustHashIntValue(t, hash, "range_count"); got != int64(fsSlackMaxRanges+25) {
		t.Errorf("range_count = %d, want %d", got, fsSlackMaxRanges+25)
	}
	if !mustHashBoolValue(t, hash, "ranges_truncated") {
		t.Error("a truncated list did not say so")
	}
	// The byte total is the figure that goes into a report, so it counts every
	// range and not only the ones that fitted.
	if got := mustHashIntValue(t, hash, "file_slack_bytes"); got != int64(fsSlackMaxRanges+25)*10 {
		t.Errorf("file_slack_bytes = %d, want %d", got, int64(fsSlackMaxRanges+25)*10)
	}
}

func TestTheFirstReasonASlackScanStoppedIsTheOneKept(t *testing.T) {
	scan := newSlackScan("xfat", "/a")
	scan.incomplete("the chain broke")
	scan.incomplete("and then something else")

	if got := mustHashStringValue(t, scan.toHash("h"), "incomplete_reason"); got != "the chain broke" {
		t.Errorf("incomplete_reason = %q, want the first one", got)
	}
	if mustHashBoolValue(t, scan.toHash("h"), "complete") {
		t.Error("a scan with a known gap reported complete")
	}
}

func TestSlackWarningCodesAreDedupedAndSorted(t *testing.T) {
	scan := newSlackScan("xfs", "/a")
	scan.warn(fsSlackWarnUnresolvedOffset, "/a", "first")
	scan.warn(fsSlackWarnAllocationGap, "/a", "second")
	scan.warn(fsSlackWarnUnresolvedOffset, "/a", "third")

	codes := mustHashStringArray(t, scan.toHash("h"), "warning_codes")
	want := []string{fsSlackWarnAllocationGap, fsSlackWarnUnresolvedOffset}
	if len(codes) != len(want) {
		t.Fatalf("warning_codes = %v, want %v", codes, want)
	}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("warning_codes = %v, want %v", codes, want)
		}
	}
	// Every warning is still rendered in full; only the code set is deduped.
	if got := len(mustHashArrayValue(t, scan.toHash("h"), "warnings")); got != 3 {
		t.Errorf("warnings = %d, want 3", got)
	}
}

func TestTheWarningsChannelIsThisPackagesOwnAndAlwaysOpen(t *testing.T) {
	// Unlike the deleted and journal families, where the bit reports whether
	// the library has a channel at all, these warnings are produced here for
	// every format -- so an empty list means nothing went wrong rather than
	// that nobody could have said.
	for _, filesystem := range []string{"ntfs", "fat", "exfat", "ext", "hfs", "xfs"} {
		scan := newSlackScan(filesystem, "/a")
		if !mustHashBoolValue(t, scan.toHash("h"), "warnings_available") {
			t.Errorf("%s: warnings_available = false", filesystem)
		}
	}
}

// --- carving a window out of an allocation ----------------------------------

func TestSpansWithinIntersectsAndDoesNotInvent(t *testing.T) {
	spans := []fsAllocSpan{
		{FileOffset: 0, Length: 4096, Offset: 1 << 20},
		{FileOffset: 4096, Length: 4096, Offset: 1<<20 + 40960},
	}

	cases := []struct {
		name   string
		from   int64
		to     int64
		want   []fsSlackRange
		length int
	}{
		{
			name:   "the tail of the last span",
			from:   6000,
			to:     8192,
			length: 1,
			want: []fsSlackRange{{
				Class:      fsSlackClassFileSlack,
				FileOffset: 6000,
				Offset:     1<<20 + 40960 + 1904,
				Length:     2192,
			}},
		},
		{
			name:   "a window spanning both",
			from:   4000,
			to:     4200,
			length: 2,
		},
		{
			name:   "a window past every span",
			from:   9000,
			to:     10000,
			length: 0,
		},
		{
			name:   "an empty window",
			from:   4096,
			to:     4096,
			length: 0,
		},
		{
			name:   "an inverted window",
			from:   8192,
			to:     4096,
			length: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := spansWithin(spans, tc.from, tc.to, fsSlackClassFileSlack)
			if len(got) != tc.length {
				t.Fatalf("got %d ranges, want %d: %+v", len(got), tc.length, got)
			}
			for i, want := range tc.want {
				if got[i] != want {
					t.Errorf("range %d = %+v, want %+v", i, got[i], want)
				}
			}
		})
	}
}

func TestAnUnlocatedSpanKeepsMinusOneRatherThanAnOffset(t *testing.T) {
	// A sparse run has no place on the medium. Deriving one from the run
	// before it would name a location that is wrong rather than missing, and
	// reading there returns plausible bytes belonging to something else.
	spans := []fsAllocSpan{
		{FileOffset: 0, Length: 4096, Offset: 8192},
		{FileOffset: 4096, Length: 4096, Offset: -1},
	}

	got := spansWithin(spans, 0, 8192, fsSlackClassUnwritten)
	if len(got) != 2 {
		t.Fatalf("got %d ranges, want 2", len(got))
	}
	if got[1].Offset != -1 {
		t.Errorf("a sparse span was placed at %d", got[1].Offset)
	}
	if got[0].Offset != 8192 {
		t.Errorf("a located span moved to %d", got[0].Offset)
	}
}

func TestRoundingUpToAnAllocationUnit(t *testing.T) {
	cases := []struct{ value, unit, want int64 }{
		{0, 4096, 0},
		{1, 4096, 4096},
		{4096, 4096, 4096},
		{4097, 4096, 8192},
		{100, 0, 100},
		{-5, 4096, -5},
	}
	for _, tc := range cases {
		if got := roundUpTo(tc.value, tc.unit); got != tc.want {
			t.Errorf("roundUpTo(%d, %d) = %d, want %d", tc.value, tc.unit, got, tc.want)
		}
	}
}

// --- what the libraries decline to say --------------------------------------

func TestABrokenChainIsNotAFileEndingOnAClusterBoundary(t *testing.T) {
	// libfat answers both with the same false, which is the single most
	// misleading thing in this family: the slack of a deleted file is the most
	// valuable slack on a FAT volume, and it arrives looking like a file that
	// has none. Each way the walk can fail gets its own sentence.
	cases := []struct {
		name   string
		result *libfat.FragmentResult
		want   string
	}{
		{"nothing at all", nil, "no result"},
		{
			"a reallocated first cluster",
			&libfat.FragmentResult{FirstClusterReallocated: true, Truncated: true},
			"marked in use again",
		},
		{
			"a freed chain",
			&libfat.FragmentResult{ChainBroken: true, Truncated: true},
			"end-of-chain marker",
		},
		{
			"a loop",
			&libfat.FragmentResult{LoopDetected: true, Truncated: true},
			"revisited a cluster",
		},
		{
			"runs simply short",
			&libfat.FragmentResult{Truncated: true},
			"cover less than the size",
		},
		{
			"no runs and no flags",
			&libfat.FragmentResult{},
			"produced no runs",
		},
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detail := fatAllocationGapDetail(tc.result)
			if !containsSubstring(detail, tc.want) {
				t.Errorf("detail %q does not mention %q", detail, tc.want)
			}
			if seen[detail] {
				t.Errorf("two different failures produced the same sentence: %q", detail)
			}
			seen[detail] = true
		})
	}
}

func TestTheUnnamedStreamIsPickedByNameAndNotByPosition(t *testing.T) {
	// An alternate data stream reported under the file's own path would put
	// another stream's slack in a report about this one. The unnamed stream is
	// not reliably first in the record, so it is found by having no name.
	named := &libntfs.Attribute{
		Header:      libntfs.AttributeHeader{Type: libntfs.AttrTypeData},
		NonResident: &libntfs.NonResidentAttribute{Name: "Zone.Identifier", RealSize: 26},
	}
	unnamed := &libntfs.Attribute{
		Header:      libntfs.AttributeHeader{Type: libntfs.AttrTypeData},
		NonResident: &libntfs.NonResidentAttribute{Name: "", RealSize: 4096},
	}

	entry := &libntfs.MFTEntry{Attributes: []*libntfs.Attribute{named, unnamed}}
	if got := ntfsDefaultDataAttribute(entry); got != unnamed {
		t.Error("an alternate data stream was picked as the file's own")
	}

	// A record carrying only an alternate stream has no default stream, and
	// saying so is better than returning the alternate one.
	onlyNamed := &libntfs.MFTEntry{Attributes: []*libntfs.Attribute{named}}
	if got := ntfsDefaultDataAttribute(onlyNamed); got != nil {
		t.Error("a record with no unnamed stream reported one")
	}
	if got := ntfsDefaultDataAttribute(nil); got != nil {
		t.Error("a nil record reported an attribute")
	}
}

func TestAResidentStreamIsPickedToo(t *testing.T) {
	resident := &libntfs.Attribute{
		Header:   libntfs.AttributeHeader{Type: libntfs.AttrTypeData},
		Resident: &libntfs.ResidentAttribute{Name: "", Value: []byte("small")},
	}
	entry := &libntfs.MFTEntry{Attributes: []*libntfs.Attribute{resident}}
	if got := ntfsDefaultDataAttribute(entry); got != resident {
		t.Error("a resident default stream was not found")
	}
}

// --- ext directory-record slack ---------------------------------------------

func TestARecordsPositionInTheStreamIsMappedOntoTheImage(t *testing.T) {
	// libext reports a position inside the directory's data stream and stops
	// there. A finding nobody can re-read is not a finding, so the mapping is
	// done here.
	runs := []libext.ByteRange{
		{FileOffset: 0, DiskOffset: 1 << 20, Length: 4096},
		{FileOffset: 4096, DiskOffset: 1<<20 + 65536, Length: 4096},
	}

	cases := []struct {
		name   string
		offset int64
		want   int64
	}{
		{"in the first run", 100, 1<<20 + 100},
		{"the first byte of the second run", 4096, 1<<20 + 65536},
		{"inside the second run", 4200, 1<<20 + 65536 + 104},
		{"past every run", 9000, -1},
		{"a negative position", -1, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extStreamOffsetToImage(runs, tc.offset); got != tc.want {
				t.Errorf("extStreamOffsetToImage(%d) = %d, want %d", tc.offset, got, tc.want)
			}
		})
	}
}

func TestARecordInsideAHoleHasNoPlaceOnTheImage(t *testing.T) {
	// A sparse ByteRange carries DiskOffset zero, and zero is the start of the
	// image. A record claimed to be there is a contradiction, not a location.
	runs := []libext.ByteRange{{FileOffset: 0, DiskOffset: 0, Length: 4096, Sparse: true}}
	if got := extStreamOffsetToImage(runs, 10); got != -1 {
		t.Errorf("a record inside a hole was placed at %d", got)
	}
	if got := extStreamOffsetToImage(nil, 10); got != -1 {
		t.Errorf("a record in a directory with no runs was placed at %d", got)
	}
}

func TestAFileTypeByteThatNamesNothingIsNotTheSameAsUnknown(t *testing.T) {
	// Zero is ext's own "unknown" value, written by filesystems that do not
	// carry the type in the record. A value past the defined set came out of
	// slack and means the record is damaged, which is a different reading.
	if got := extFileTypeName(0); got != "unknown" {
		t.Errorf("extFileTypeName(0) = %q, want unknown", got)
	}
	if got := extFileTypeName(2); got != "directory" {
		t.Errorf("extFileTypeName(2) = %q, want directory", got)
	}
	if got := extFileTypeName(9); got != "unrecognised" {
		t.Errorf("extFileTypeName(9) = %q, want unrecognised", got)
	}
}

func TestARecordShadowingALiveEntryIsFlaggedRatherThanDropped(t *testing.T) {
	scan := fsDirSlackScan{Filesystem: "ext", Path: "/etc", Inode: 12, Complete: true}
	scan.add(fsDirSlackEntry{Name: "gone", Inode: 40, Offset: 4096})
	scan.add(fsDirSlackEntry{Name: "still-here", Inode: 41, Offset: 4128, ShadowsLive: true})
	scan.add(fsDirSlackEntry{Name: "unplaced", Inode: 42, Offset: -1})

	hash := scan.toHash("h")
	if got := mustHashIntValue(t, hash, "entry_count"); got != 3 {
		t.Errorf("entry_count = %d, want 3", got)
	}
	// ext_deleted filters these out; this deliberately does not, because a
	// directory rewrite leaving copies behind is itself worth seeing.
	if got := mustHashIntValue(t, hash, "shadows_live_count"); got != 1 {
		t.Errorf("shadows_live_count = %d, want 1", got)
	}
	// located is the denominator for "could this be re-examined", and it is
	// not the entry count.
	if got := mustHashIntValue(t, hash, "located"); got != 2 {
		t.Errorf("located = %d, want 2", got)
	}
}

// --- volume free space ------------------------------------------------------

func TestTheCountedAndClaimedFreeTotalsAreTwoNumbers(t *testing.T) {
	scan := fsFreeSpaceScan{
		Filesystem:        "hfs",
		BlockSize:         4096,
		TotalBlocks:       1000,
		ClaimedFreeBlocks: 40,
		Complete:          true,
		WarningsAvailable: true,
	}
	scan.add(fsFreeRun{StartBlock: 10, BlockCount: 8, Offset: 40960, Length: 8 * 4096})
	scan.add(fsFreeRun{StartBlock: 100, BlockCount: 30, Offset: 409600, Length: 30 * 4096})
	scan.ClaimMatches = scan.FreeBlocks == scan.ClaimedFreeBlocks

	hash := scan.toHash("h")
	if got := mustHashIntValue(t, hash, "free_blocks"); got != 38 {
		t.Errorf("free_blocks = %d, want 38", got)
	}
	if got := mustHashIntValue(t, hash, "free_blocks_claimed"); got != 40 {
		t.Errorf("free_blocks_claimed = %d, want 40", got)
	}
	// The header's claim and the bits do not agree, which is a finding about
	// the volume rather than an error in the walk.
	if mustHashBoolValue(t, hash, "claim_matches") {
		t.Error("a counted total that differs from the claim reported a match")
	}
	if got := mustHashIntValue(t, hash, "largest_run_bytes"); got != 30*4096 {
		t.Errorf("largest_run_bytes = %d, want %d", got, 30*4096)
	}
	if got := mustHashIntValue(t, hash, "free_bytes"); got != 38*4096 {
		t.Errorf("free_bytes = %d, want %d", got, 38*4096)
	}
}

func TestAFreeRunThatDoesNotResolveIsAtMinusOne(t *testing.T) {
	scan := fsFreeSpaceScan{Filesystem: "hfs", BlockSize: 4096, Complete: true}
	scan.add(fsFreeRun{StartBlock: 7, BlockCount: 1, Offset: -1, Length: 4096})

	runs := mustHashArrayValue(t, scan.toHash("h"), "runs")
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	run, ok := runs[0].(*object.Hash)
	if !ok {
		t.Fatalf("run is not a HASH. got=%T", runs[0])
	}
	if got := mustHashIntValue(t, run, "offset"); got != -1 {
		t.Errorf("offset = %d, want -1 rather than the start of the volume", got)
	}
	// Its blocks are still counted: not knowing where they are does not make
	// them allocated.
	if got := mustHashIntValue(t, scan.toHash("h"), "free_blocks"); got != 1 {
		t.Errorf("free_blocks = %d, want 1", got)
	}
}

func TestTheFreeRunCapKeepsTheFreeTotalHonestPastIt(t *testing.T) {
	scan := fsFreeSpaceScan{Filesystem: "hfs", BlockSize: 512, Complete: true}
	for i := 0; i < fsSlackMaxRuns+7; i++ {
		scan.add(fsFreeRun{StartBlock: int64(i) * 2, BlockCount: 1, Offset: int64(i) * 1024, Length: 512})
	}

	hash := scan.toHash("h")
	if got := len(mustHashArrayValue(t, hash, "runs")); got != fsSlackMaxRuns {
		t.Errorf("rendered runs = %d, want %d", got, fsSlackMaxRuns)
	}
	if got := mustHashIntValue(t, hash, "run_count"); got != int64(fsSlackMaxRuns+7) {
		t.Errorf("run_count = %d, want %d", got, fsSlackMaxRuns+7)
	}
	if got := mustHashIntValue(t, hash, "free_blocks"); got != int64(fsSlackMaxRuns+7) {
		t.Errorf("free_blocks = %d, want %d", got, fsSlackMaxRuns+7)
	}
	if !mustHashBoolValue(t, hash, "runs_truncated") {
		t.Error("a truncated run list did not say so")
	}
}

// --- the builtins ------------------------------------------------------------

type slackCase struct {
	name    string
	install func(t *testing.T, scan fsSlackScan, err error)
	open    func() object.Object
	call    func(handle string) object.Object
	seen    func() string
}

func slackCases(t *testing.T) []slackCase {
	t.Helper()

	ntfs := &fakeNTFSSession{}
	fat := &fakeFATSession{}
	xfat := &fakeXFATSession{}
	ext := &fakeEXTSession{}
	hfs := &fakeHFSSession{}
	xfs := &fakeXFSSession{}

	return []slackCase{
		{
			BuiltinNameNtfsSlack,
			func(t *testing.T, s fsSlackScan, err error) {
				ntfs.slack, ntfs.slackErr = s, err
				installFakeNTFSBackend(t, &fakeNTFSBackend{session: ntfs})
			},
			func() object.Object { return NtfsOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return NtfsSlack(stringObj(h), stringObj("/probe")) },
			func() string { return ntfs.slackPath },
		},
		{
			BuiltinNameFatSlack,
			func(t *testing.T, s fsSlackScan, err error) {
				fat.slack, fat.slackErr = s, err
				installFakeFATBackend(t, &fakeFATBackend{session: fat})
			},
			func() object.Object { return FatOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return FatSlack(stringObj(h), stringObj("/probe")) },
			func() string { return fat.slackPath },
		},
		{
			BuiltinNameXfatSlack,
			func(t *testing.T, s fsSlackScan, err error) {
				xfat.slack, xfat.slackErr = s, err
				installFakeXFATBackend(t, &fakeXFATBackend{session: xfat})
			},
			func() object.Object { return XFATOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return XFATSlack(stringObj(h), stringObj("/probe")) },
			func() string { return xfat.slackPath },
		},
		{
			BuiltinNameExtSlack,
			func(t *testing.T, s fsSlackScan, err error) {
				ext.slack, ext.slackErr = s, err
				installFakeEXTBackend(t, &fakeEXTBackend{session: ext})
			},
			func() object.Object { return ExtOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return ExtSlack(stringObj(h), stringObj("/probe")) },
			func() string { return ext.slackPath },
		},
		{
			BuiltinNameHfsSlack,
			func(t *testing.T, s fsSlackScan, err error) {
				hfs.slack, hfs.slackErr = s, err
				installFakeHFSBackend(t, &fakeHFSBackend{session: hfs})
			},
			func() object.Object { return HFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return HFSSlack(stringObj(h), stringObj("/probe")) },
			func() string { return hfs.slackPath },
		},
		{
			BuiltinNameXfsSlack,
			func(t *testing.T, s fsSlackScan, err error) {
				xfs.slack, xfs.slackErr = s, err
				installFakeXFSBackend(t, &fakeXFSBackend{session: xfs})
			},
			func() object.Object { return XFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return XFSSlack(stringObj(h), stringObj("/probe")) },
			func() string { return xfs.slackPath },
		},
	}
}

func TestEverySlackBuiltinReturnsTheDeclaredFields(t *testing.T) {
	for _, tc := range slackCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t, newSlackScan("fs", "/probe"), nil)

			handle := openJournalHandle(t, tc.open)
			payload, err := unwrapPair(t, tc.call(handle))
			if err != nil {
				t.Fatalf("%s returned error: %s", tc.name, err.Inspect())
			}
			assertDeclaredFields(t, tc.name, payload, handle)
		})
	}
}

func TestExtDirSlackReturnsTheDeclaredFields(t *testing.T) {
	ext := &fakeEXTSession{dirSlack: fsDirSlackScan{Filesystem: "ext", Path: "/etc", Inode: 12}}
	installFakeEXTBackend(t, &fakeEXTBackend{session: ext})

	handle := openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("synthetic.img")) })
	payload, err := unwrapPair(t, ExtDirSlack(stringObj(handle), stringObj("/etc")))
	if err != nil {
		t.Fatalf("ext_dir_slack returned error: %s", err.Inspect())
	}
	assertDeclaredFields(t, BuiltinNameExtDirSlack, payload, handle)

	if ext.dirSlackPath != "/etc" {
		t.Errorf("the directory argument reached the session as %q", ext.dirSlackPath)
	}
}

func TestHfsUnallocatedReturnsTheDeclaredFields(t *testing.T) {
	hfs := &fakeHFSSession{freeSpace: fsFreeSpaceScan{Filesystem: "hfs", BlockSize: 4096}}
	installFakeHFSBackend(t, &fakeHFSBackend{session: hfs})

	handle := openJournalHandle(t, func() object.Object { return HFSOpen(stringObj("synthetic.img")) })
	payload, err := unwrapPair(t, HFSUnallocated(stringObj(handle)))
	if err != nil {
		t.Fatalf("hfs_unallocated returned error: %s", err.Inspect())
	}
	assertDeclaredFields(t, BuiltinNameHfsUnallocated, payload, handle)
}

// assertDeclaredFields checks a payload against the metadata entry both ways:
// nothing declared is missing, and nothing returned is undeclared. The second
// direction is the one that catches a field added to a renderer and never
// written down, which is how hover and completion come to describe a shape the
// runtime no longer has.
func assertDeclaredFields(t *testing.T, name string, payload object.Object, handle string) {
	t.Helper()

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("%s payload is not HASH. got=%T", name, payload)
	}

	got := map[string]bool{}
	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			t.Fatalf("%s returned a non-STRING key %s", name, pair.Key.Inspect())
		}
		got[key.Value] = true
	}

	declared, ok := builtinDocs[name]
	if !ok {
		t.Fatalf("%s has no metadata entry", name)
	}
	for _, field := range declared.returns.fields {
		if !got[field] {
			t.Errorf("%s declares field %q but did not return it", name, field)
		}
		delete(got, field)
	}
	for field := range got {
		t.Errorf("%s returned undeclared field %q", name, field)
	}

	if mustHashStringValue(t, hash, "handle") != handle {
		t.Errorf("%s did not echo its handle", name)
	}
}

// TestEachSlackBuiltinReadsItsOwnVolume pins the dispatch. Six builtins over
// six sessions with one method name between them is exactly the shape where a
// copied line returns another filesystem's answer and nothing looks wrong.
func TestEachSlackBuiltinReadsItsOwnVolume(t *testing.T) {
	for _, tc := range slackCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			scan := newSlackScan(tc.name, "/probe")
			tc.install(t, scan, nil)

			handle := openJournalHandle(t, tc.open)
			payload, err := unwrapPair(t, tc.call(handle))
			if err != nil {
				t.Fatalf("%s returned error: %s", tc.name, err.Inspect())
			}
			hash, ok := payload.(*object.Hash)
			if !ok {
				t.Fatalf("%s payload is not HASH. got=%T", tc.name, payload)
			}
			// The fake stamps filesystem with the builtin's own name, so a
			// result routed to the wrong session carries another's.
			if got := mustHashStringValue(t, hash, "filesystem"); got != tc.name {
				t.Errorf("%s returned a scan from %q", tc.name, got)
			}
			if got := tc.seen(); got != "/probe" {
				t.Errorf("%s passed the path through as %q", tc.name, got)
			}
		})
	}
}

func TestASlackLibraryErrorIsReportedAndNotRendered(t *testing.T) {
	for _, tc := range slackCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t, fsSlackScan{}, errors.New("the volume went away"))

			handle := openJournalHandle(t, tc.open)
			payload, err := unwrapPair(t, tc.call(handle))
			if err == nil {
				t.Fatalf("%s rendered an empty scan instead of reporting the failure", tc.name)
			}
			if !containsSubstring(err.Message, "the volume went away") {
				t.Errorf("%s lost the library's own words: %q", tc.name, err.Message)
			}
			if !containsSubstring(err.Message, tc.name) {
				t.Errorf("%s did not name itself in its refusal: %q", tc.name, err.Message)
			}
			if payload != nil && payload.Type() != object.NULL_OBJ {
				t.Errorf("%s returned a payload beside its error: %s", tc.name, payload.Inspect())
			}
		})
	}
}

func TestEverySlackBuiltinChecksItsArity(t *testing.T) {
	handles := map[string]string{}
	install := func(t *testing.T) {
		installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{}})
		installFakeFATBackend(t, &fakeFATBackend{session: &fakeFATSession{}})
		installFakeXFATBackend(t, &fakeXFATBackend{session: &fakeXFATSession{}})
		installFakeEXTBackend(t, &fakeEXTBackend{session: &fakeEXTSession{}})
		installFakeHFSBackend(t, &fakeHFSBackend{session: &fakeHFSSession{}})
		installFakeXFSBackend(t, &fakeXFSBackend{session: &fakeXFSSession{}})

		handles["ntfs"] = openJournalHandle(t, func() object.Object { return NtfsOpen(stringObj("a.img")) })
		handles["fat"] = openJournalHandle(t, func() object.Object { return FatOpen(stringObj("a.img")) })
		handles["xfat"] = openJournalHandle(t, func() object.Object { return XFATOpen(stringObj("a.img")) })
		handles["ext"] = openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("a.img")) })
		handles["hfs"] = openJournalHandle(t, func() object.Object { return HFSOpen(stringObj("a.img")) })
		handles["xfs"] = openJournalHandle(t, func() object.Object { return XFSOpen(stringObj("a.img")) })
	}
	install(t)

	cases := []struct {
		name string
		call func() object.Object
	}{
		{BuiltinNameNtfsSlack, func() object.Object { return NtfsSlack(stringObj(handles["ntfs"])) }},
		{BuiltinNameFatSlack, func() object.Object { return FatSlack(stringObj(handles["fat"])) }},
		{BuiltinNameXfatSlack, func() object.Object { return XFATSlack(stringObj(handles["xfat"])) }},
		{BuiltinNameExtSlack, func() object.Object { return ExtSlack(stringObj(handles["ext"])) }},
		{BuiltinNameHfsSlack, func() object.Object { return HFSSlack(stringObj(handles["hfs"])) }},
		{BuiltinNameXfsSlack, func() object.Object { return XFSSlack(stringObj(handles["xfs"])) }},
		{BuiltinNameExtDirSlack, func() object.Object { return ExtDirSlack(stringObj(handles["ext"])) }},
		{
			BuiltinNameHfsUnallocated,
			func() object.Object {
				return HFSUnallocated(stringObj(handles["hfs"]), stringObj("extra"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unwrapPairNoFatal(tc.call())
			if err == nil {
				t.Fatalf("%s accepted the wrong number of arguments", tc.name)
			}
			if !containsSubstring(err.Message, "wrong number of arguments") {
				t.Errorf("%s refused for the wrong reason: %q", tc.name, err.Message)
			}
		})
	}
}

func TestASlackPathMustBeAString(t *testing.T) {
	installFakeEXTBackend(t, &fakeEXTBackend{session: &fakeEXTSession{}})
	handle := openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("a.img")) })

	for _, call := range []func() object.Object{
		func() object.Object { return ExtSlack(stringObj(handle), intObj(7)) },
		func() object.Object { return ExtDirSlack(stringObj(handle), intObj(7)) },
	} {
		if _, err := unwrapPairNoFatal(call()); err == nil {
			t.Error("a non-string path was accepted")
		}
	}
}

// containsSubstring keeps these assertions readable without pulling strings in
// for one call.
func containsSubstring(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
