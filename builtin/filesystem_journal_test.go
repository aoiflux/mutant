package builtin

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	libext "github.com/aoiflux/libext"
	libntfs "github.com/aoiflux/libntfs"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

// --- the envelope -----------------------------------------------------------

func TestAJournalThatIsNotThereIsNotAJournalWithNoRecords(t *testing.T) {
	absent := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	present := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	present.Present = true

	absentHash := absent.toHash("h")
	presentHash := present.toHash("h")

	if mustHashBoolValue(t, absentHash, "present") {
		t.Error("a scan that found no journal reported one")
	}
	if !mustHashBoolValue(t, presentHash, "present") {
		t.Error("a scan of a real journal reported none")
	}
	// Both report zero entries, which is the whole point of the bit.
	for name, hash := range map[string]*object.Hash{"absent": absentHash, "present": presentHash} {
		if got := len(mustHashArrayValue(t, hash, "entries")); got != 0 {
			t.Errorf("%s: entries = %d, want 0", name, got)
		}
	}
}

func TestTheWrapIsFoundWhereThePositionsGoBackwards(t *testing.T) {
	cases := []struct {
		name      string
		positions []int64
		wrapped   bool
	}{
		{"rising", []int64{10, 20, 30, 40}, false},
		{"flat", []int64{10, 10, 10}, false},
		{"one step back", []int64{10, 20, 15, 30}, true},
		{"the seam at the end", []int64{100, 200, 3}, true},
		{"a single record", []int64{7}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan := newJournalScan("ntfs", fsJournalLogFile, fsJournalOrderPhysical)
			for _, position := range tc.positions {
				scan.observeOrder(position)
			}
			if scan.Wrapped != tc.wrapped {
				t.Errorf("wrapped = %v, want %v for %v", scan.Wrapped, tc.wrapped, tc.positions)
			}
		})
	}
}

func TestAWrapCheckThatDidNotRunIsNotANegativeResult(t *testing.T) {
	scan := newJournalScan("ntfs", fsJournalLogFile, fsJournalOrderPhysical)
	hash := scan.toHash("h")

	if mustHashBoolValue(t, hash, "wrap_checked") {
		t.Error("a scan that never set wrap_checked reported having checked")
	}
	if mustHashBoolValue(t, hash, "wrapped") {
		t.Error("a scan that never checked reported a confident false")
	}
	// The pair is the contract: wrapped false alone says nothing, exactly as
	// reallocated false alone says nothing in the *_deleted family.
	scan.WrapChecked = true
	if mustHashBoolValue(t, scan.toHash("h"), "wrapped") {
		t.Error("a checked scan over no records invented a wrap")
	}
}

func TestTheWindowIsTheExtremesAndNotTheEnds(t *testing.T) {
	// Physical order: the first entry is not the lowest and the last is not
	// the highest, which is exactly the case the field names have to survive.
	scan := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	for _, position := range []int64{500, 100, 900, 300} {
		scan.position(position)
	}

	hash := scan.toHash("h")
	if got := mustHashIntValue(t, hash, "lowest_position"); got != 100 {
		t.Errorf("lowest_position = %d, want 100", got)
	}
	if got := mustHashIntValue(t, hash, "highest_position"); got != 900 {
		t.Errorf("highest_position = %d, want 900", got)
	}
}

func TestAnUnwalkedJournalReportsNoWindowRatherThanZero(t *testing.T) {
	scan := newJournalScan("xfs", fsJournalXLOG, fsJournalOrderLSN)
	hash := scan.toHash("h")

	for _, field := range []string{"lowest_position", "highest_position", "journal_offset", "journal_bytes"} {
		if got := mustHashIntValue(t, hash, field); got != -1 {
			t.Errorf("%s = %d, want -1: zero is a real offset and a real position", field, got)
		}
	}
}

func TestTheEntryCapKeepsTheCountHonestPastIt(t *testing.T) {
	scan := newJournalScan("ntfs", fsJournalUSN, fsJournalOrderStream)
	total := fsJournalMaxEntries + 250
	for i := 0; i < total; i++ {
		stored := scan.add(stringObj("record"))
		if want := i < fsJournalMaxEntries; stored != want {
			t.Fatalf("add #%d stored=%v, want %v", i, stored, want)
		}
	}

	hash := scan.toHash("h")
	if got := len(mustHashArrayValue(t, hash, "entries")); got != fsJournalMaxEntries {
		t.Errorf("entries = %d, want %d", got, fsJournalMaxEntries)
	}
	if got := mustHashIntValue(t, hash, "entry_count"); got != int64(total) {
		t.Errorf("entry_count = %d, want %d: the count must not stop at the cap", got, total)
	}
	if !mustHashBoolValue(t, hash, "entries_truncated") {
		t.Error("a capped scan did not say it was truncated")
	}
}

func TestTheFirstReasonForAGapIsTheOneKept(t *testing.T) {
	scan := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	scan.incomplete("the first gap")
	scan.incomplete("a later gap")

	hash := scan.toHash("h")
	if mustHashBoolValue(t, hash, "complete") {
		t.Error("a scan with a known gap reported complete")
	}
	if got := mustHashStringValue(t, hash, "incomplete_reason"); got != "the first gap" {
		t.Errorf("incomplete_reason = %q, want the first one", got)
	}
}

func TestJournalWarningCodesAreDedupedAndSorted(t *testing.T) {
	scan := newJournalScan("xfs", fsJournalXLOG, fsJournalOrderLSN)
	scan.warn("zebra", "a", "one")
	scan.warn("alpha", "b", "two")
	scan.warn("zebra", "c", "three")

	hash := scan.toHash("h")
	if got := len(mustHashArrayValue(t, hash, "warnings")); got != 3 {
		t.Errorf("warnings = %d, want 3: every occurrence is kept", got)
	}

	codes := mustHashArrayValue(t, hash, "warning_codes")
	var got []string
	for _, code := range codes {
		got = append(got, code.(*object.String).Value)
	}
	if strings.Join(got, ",") != "alpha,zebra" {
		t.Errorf("warning_codes = %v, want [alpha zebra]", got)
	}
}

func TestAnUnsignedPositionSaturatesRatherThanWrapping(t *testing.T) {
	cases := []struct {
		in   uint64
		want int64
	}{
		{0, 0},
		{1 << 40, 1 << 40},
		{math.MaxInt64, math.MaxInt64},
		{math.MaxInt64 + 1, math.MaxInt64},
		{math.MaxUint64, math.MaxInt64},
	}
	for _, tc := range cases {
		if got := journalPosition(tc.in); got != tc.want {
			t.Errorf("journalPosition(%d) = %d, want %d: a wrapped conversion "+
				"reads as a real position and orders wrongly", tc.in, got, tc.want)
		}
	}
}

// --- dispatch ---------------------------------------------------------------

type journalCase struct {
	name    string
	install func(t *testing.T, scan fsJournalScan, err error)
	open    func() object.Object
	call    func(handle string) object.Object
	extra   func() map[string]object.Object
}

func journalCases(t *testing.T) []journalCase {
	t.Helper()

	ntfs := &fakeNTFSSession{}
	ext := &fakeEXTSession{}
	xfs := &fakeXFSSession{}

	ntfsLogExtra := func() map[string]object.Object {
		return ntfsLogDescription(nil, nil, false)
	}
	extExtra := func() map[string]object.Object {
		return extJournalDescription(8, false, "", nil, false, map[string]bool{})
	}

	installNTFS := func(t *testing.T) { installFakeNTFSBackend(t, &fakeNTFSBackend{session: ntfs}) }
	installEXT := func(t *testing.T) { installFakeEXTBackend(t, &fakeEXTBackend{session: ext}) }
	installXFS := func(t *testing.T) { installFakeXFSBackend(t, &fakeXFSBackend{session: xfs}) }

	openNTFS := func() object.Object { return NtfsOpen(stringObj("synthetic.img")) }
	openEXT := func() object.Object { return ExtOpen(stringObj("synthetic.img")) }
	openXFS := func() object.Object { return XFSOpen(stringObj("synthetic.img")) }

	return []journalCase{
		{
			BuiltinNameNtfsUsnJournal,
			func(t *testing.T, s fsJournalScan, err error) {
				ntfs.usn, ntfs.usnErr = s, err
				installNTFS(t)
			},
			openNTFS,
			func(h string) object.Object { return NtfsUSNJournal(stringObj(h)) },
			nil,
		},
		{
			BuiltinNameNtfsLogRecords,
			func(t *testing.T, s fsJournalScan, err error) {
				ntfs.logRecords, ntfs.logRecordsErr = s, err
				installNTFS(t)
			},
			openNTFS,
			func(h string) object.Object { return NtfsLogRecords(stringObj(h)) },
			ntfsLogExtra,
		},
		{
			BuiltinNameNtfsLogTransactions,
			func(t *testing.T, s fsJournalScan, err error) {
				ntfs.logTxns, ntfs.logTxnsErr = s, err
				installNTFS(t)
			},
			openNTFS,
			func(h string) object.Object { return NtfsLogTransactions(stringObj(h)) },
			ntfsLogExtra,
		},
		{
			BuiltinNameExtJournal,
			func(t *testing.T, s fsJournalScan, err error) {
				ext.journal, ext.journalErr = s, err
				installEXT(t)
			},
			openEXT,
			func(h string) object.Object { return ExtJournal(stringObj(h)) },
			extExtra,
		},
		{
			BuiltinNameExtJournalBlockCopies,
			func(t *testing.T, s fsJournalScan, err error) {
				ext.copies, ext.copiesErr = s, err
				installEXT(t)
			},
			openEXT,
			func(h string) object.Object { return ExtJournalBlockCopies(stringObj(h), intObj(42)) },
			func() map[string]object.Object {
				fields := extExtra()
				fields["fs_block"] = intObj(42)
				return fields
			},
		},
		{
			BuiltinNameExtInodeVersions,
			func(t *testing.T, s fsJournalScan, err error) {
				ext.versions, ext.versionsErr = s, err
				installEXT(t)
			},
			openEXT,
			func(h string) object.Object { return ExtInodeVersions(stringObj(h), intObj(12)) },
			func() map[string]object.Object {
				fields := extExtra()
				fields["inode"] = intObj(12)
				return fields
			},
		},
		{
			BuiltinNameXfsLogRecords,
			func(t *testing.T, s fsJournalScan, err error) {
				xfs.logRecords, xfs.logRecordsErr = s, err
				installXFS(t)
			},
			openXFS,
			func(h string) object.Object { return XFSLogRecords(stringObj(h)) },
			func() map[string]object.Object {
				return map[string]object.Object{
					"cleared_blocks":     intObj(0),
					"has_unmount_record": boolObj(false),
				}
			},
		},
		{
			BuiltinNameXfsLogTransactions,
			func(t *testing.T, s fsJournalScan, err error) {
				xfs.logTxns, xfs.logTxnsErr = s, err
				installXFS(t)
			},
			openXFS,
			func(h string) object.Object { return XFSLogTransactions(stringObj(h)) },
			func() map[string]object.Object {
				return map[string]object.Object{
					"record_count":       intObj(0),
					"has_unmount_record": boolObj(false),
				}
			},
		},
	}
}

func TestEveryJournalBuiltinReturnsTheDeclaredFields(t *testing.T) {
	for _, tc := range journalCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			scan := newJournalScan("fs", "journal", fsJournalOrderLSN)
			scan.Present = true
			if tc.extra != nil {
				mergeExtra(&scan, tc.extra())
			}
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

			got := map[string]bool{}
			for _, pair := range hash.Pairs {
				key, ok := pair.Key.(*object.String)
				if !ok {
					t.Fatalf("%s returned a non-STRING key %s", tc.name, pair.Key.Inspect())
				}
				got[key.Value] = true
			}

			declared, ok := builtinDocs[tc.name]
			if !ok {
				t.Fatalf("%s has no metadata entry", tc.name)
			}
			for _, field := range declared.returns.fields {
				if !got[field] {
					t.Errorf("%s declares field %q but did not return it", tc.name, field)
				}
				delete(got, field)
			}
			for field := range got {
				t.Errorf("%s returned undeclared field %q", tc.name, field)
			}

			if mustHashStringValue(t, hash, "handle") != handle {
				t.Errorf("%s did not echo its handle", tc.name)
			}
		})
	}
}

// TestEachJournalBuiltinReadsItsOwnJournal pins the dispatch.
//
// Three of these eight sit on one session and two of those read the same file,
// so a wiring mistake would return a $LogFile record stream from
// ntfs_usn_journal and nothing about the result would look wrong.
func TestEachJournalBuiltinReadsItsOwnJournal(t *testing.T) {
	for _, tc := range journalCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			scan := newJournalScan("fs", tc.name, fsJournalOrderLSN)
			if tc.extra != nil {
				mergeExtra(&scan, tc.extra())
			}
			tc.install(t, scan, nil)

			handle := openJournalHandle(t, tc.open)
			payload, err := unwrapPair(t, tc.call(handle))
			if err != nil {
				t.Fatalf("%s returned error: %s", tc.name, err.Inspect())
			}
			// The fake stamps the journal field with the builtin's own name,
			// so a result routed to the wrong scanner carries another's.
			if got := mustHashStringValue(t, payload.(*object.Hash), "journal"); got != tc.name {
				t.Errorf("%s returned the result of %s", tc.name, got)
			}
		})
	}
}

func TestAJournalLibraryErrorIsReportedAndNotRendered(t *testing.T) {
	for _, tc := range journalCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t, fsJournalScan{}, errors.New("the log region is unreadable"))

			handle := openJournalHandle(t, tc.open)
			payload, err := unwrapPair(t, tc.call(handle))
			if err == nil {
				t.Fatalf("%s reported success on a library error", tc.name)
			}
			if payload != nil && payload.Type() != object.NULL_OBJ {
				t.Errorf("%s returned a payload beside its error: %s", tc.name, payload.Inspect())
			}
			if !strings.Contains(err.Message, "the log region is unreadable") {
				t.Errorf("%s swallowed the library's message: %s", tc.name, err.Message)
			}
			if !strings.Contains(err.Message, tc.name) {
				t.Errorf("%s did not name itself in its error: %s", tc.name, err.Message)
			}
		})
	}
}

func TestTheBlockAndInodeArgumentsReachTheLibrary(t *testing.T) {
	ext := &fakeEXTSession{}
	ext.copies = newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	ext.versions = newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	installFakeEXTBackend(t, &fakeEXTBackend{session: ext})

	handle := openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("synthetic.img")) })

	if _, err := unwrapPair(t, ExtJournalBlockCopies(stringObj(handle), intObj(4711))); err != nil {
		t.Fatalf("ext_journal_block_copies returned error: %s", err.Inspect())
	}
	if ext.copiesBlock != 4711 {
		t.Errorf("the library saw block %d, want 4711", ext.copiesBlock)
	}

	if _, err := unwrapPair(t, ExtInodeVersions(stringObj(handle), intObj(1337))); err != nil {
		t.Fatalf("ext_journal_inode_versions returned error: %s", err.Inspect())
	}
	if ext.versionsInode != 1337 {
		t.Errorf("the library saw inode %d, want 1337", ext.versionsInode)
	}
}

func TestAnImpossibleBlockOrInodeIsRefusedBeforeTheWalk(t *testing.T) {
	ext := &fakeEXTSession{}
	installFakeEXTBackend(t, &fakeEXTBackend{session: ext})
	handle := openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("synthetic.img")) })

	cases := map[string]object.Object{
		"a negative block":  ExtJournalBlockCopies(stringObj(handle), intObj(-1)),
		"inode zero":        ExtInodeVersions(stringObj(handle), intObj(0)),
		"a negative inode":  ExtInodeVersions(stringObj(handle), intObj(-9)),
		"version below nil": ExtRecoverJournalledFile(stringObj(handle), intObj(12), intObj(-1), stringObj("x")),
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := unwrapPairNoFatal(result); err == nil {
				t.Error("accepted an argument that names nothing")
			}
		})
	}
	// Inode 0 is not an inode on any ext filesystem, so the refusal has to
	// happen here rather than becoming a whole-journal walk that finds nothing.
	if ext.versionsInode != 0 {
		t.Error("a refused inode still reached the library")
	}
}

func TestEveryJournalBuiltinChecksItsArity(t *testing.T) {
	oneArg := map[string]func(...object.Object) object.Object{
		BuiltinNameNtfsUsnJournal:      NtfsUSNJournal,
		BuiltinNameNtfsLogRecords:      NtfsLogRecords,
		BuiltinNameNtfsLogTransactions: NtfsLogTransactions,
		BuiltinNameExtJournal:          ExtJournal,
		BuiltinNameXfsLogRecords:       XFSLogRecords,
		BuiltinNameXfsLogTransactions:  XFSLogTransactions,
	}
	for name, fn := range oneArg {
		t.Run(name, func(t *testing.T) {
			for _, args := range [][]object.Object{{}, {stringObj("h"), intObj(1)}} {
				if _, err := unwrapPairNoFatal(fn(args...)); err == nil {
					t.Errorf("%s accepted %d arguments", name, len(args))
				}
			}
		})
	}

	twoArg := map[string]func(...object.Object) object.Object{
		BuiltinNameExtJournalBlockCopies: ExtJournalBlockCopies,
		BuiltinNameExtInodeVersions:      ExtInodeVersions,
	}
	for name, fn := range twoArg {
		t.Run(name, func(t *testing.T) {
			for _, args := range [][]object.Object{
				{},
				{stringObj("h")},
				{stringObj("h"), intObj(1), intObj(2)},
			} {
				if _, err := unwrapPairNoFatal(fn(args...)); err == nil {
					t.Errorf("%s accepted %d arguments", name, len(args))
				}
			}
		})
	}

	t.Run(BuiltinNameExtRecoverJournalled, func(t *testing.T) {
		for _, args := range [][]object.Object{
			{},
			{stringObj("h")},
			{stringObj("h"), intObj(1)},
			{stringObj("h"), intObj(1), intObj(0)},
			{stringObj("h"), intObj(1), intObj(0), stringObj("d"), stringObj("x")},
		} {
			if _, err := unwrapPairNoFatal(ExtRecoverJournalledFile(args...)); err == nil {
				t.Errorf("ext_recover_journalled_file accepted %d arguments", len(args))
			}
		}
	})
}

// --- the journalled-file recovery -------------------------------------------

func TestAJournalledRecoveryReturnsTheDeclaredFields(t *testing.T) {
	ext := &fakeEXTSession{journalled: syntheticRecovery([]byte("the extent tree survived"))}
	installFakeEXTBackend(t, &fakeEXTBackend{session: ext})
	handle := openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("synthetic.img")) })

	dest := filepath.Join(t.TempDir(), "out.bin")
	payload, err := unwrapPair(t, ExtRecoverJournalledFile(
		stringObj(handle), intObj(77), intObj(2), stringObj(dest)))
	if err != nil {
		t.Fatalf("ext_recover_journalled_file returned error: %s", err.Inspect())
	}
	hash := payload.(*object.Hash)

	got := map[string]bool{}
	for _, pair := range hash.Pairs {
		got[pair.Key.(*object.String).Value] = true
	}
	declared := builtinDocs[BuiltinNameExtRecoverJournalled]
	for _, field := range declared.returns.fields {
		if !got[field] {
			t.Errorf("declares field %q but did not return it", field)
		}
		delete(got, field)
	}
	for field := range got {
		t.Errorf("returned undeclared field %q", field)
	}

	// The inode and the version are what the caller named, echoed so that a
	// report can assert it recovered the version it meant to.
	if v := mustHashIntValue(t, hash, "inode"); v != 77 {
		t.Errorf("inode = %d, want 77", v)
	}
	if v := mustHashIntValue(t, hash, "version"); v != 2 {
		t.Errorf("version = %d, want 2", v)
	}
	if ext.journalledInode != 77 || ext.journalledVersion != 2 {
		t.Errorf("the library saw inode %d version %d, want 77 and 2",
			ext.journalledInode, ext.journalledVersion)
	}
}

func TestAJournalledRecoveryNeverWritesOverAnExistingFile(t *testing.T) {
	ext := &fakeEXTSession{journalled: syntheticRecovery([]byte("new bytes"))}
	installFakeEXTBackend(t, &fakeEXTBackend{session: ext})
	handle := openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("synthetic.img")) })

	dest := filepath.Join(t.TempDir(), "taken.bin")
	if err := os.WriteFile(dest, []byte("evidence already here"), 0o600); err != nil {
		t.Fatalf("seed the destination: %s", err)
	}

	if _, err := unwrapPairNoFatal(ExtRecoverJournalledFile(
		stringObj(handle), intObj(1), intObj(0), stringObj(dest))); err == nil {
		t.Fatal("wrote over an existing file")
	}
	content, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("read back the destination: %s", readErr)
	}
	if string(content) != "evidence already here" {
		t.Errorf("the existing file was modified: %q", content)
	}
}

func TestAJournalledRecoveryThatLocatedNothingIsNotAnEmptyFile(t *testing.T) {
	ext := &fakeEXTSession{journalled: fsRecovery{}}
	installFakeEXTBackend(t, &fakeEXTBackend{session: ext})
	handle := openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("synthetic.img")) })

	dest := filepath.Join(t.TempDir(), "never.bin")
	if _, err := unwrapPairNoFatal(ExtRecoverJournalledFile(
		stringObj(handle), intObj(1), intObj(0), stringObj(dest))); err == nil {
		t.Fatal("a recovery that located no bytes produced a file")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("an empty file was left under the recovered name")
	}
}

// --- NTFS: the USN change journal -------------------------------------------

func TestAVersionFourUSNRecordReportsNoTimeRatherThanYearOne(t *testing.T) {
	// A v4 record tracks extents: it carries neither a timestamp nor a name.
	// Rendered as a zero time it would take its place in a timeline as a date
	// in the year 1, which sorts before every real event.
	v4 := &libntfs.USNRecord{MajorVersion: 4, USN: 512, FileReference: 9}
	v3 := &libntfs.USNRecord{
		MajorVersion: 3,
		MinorVersion: 0,
		USN:          1024,
		Timestamp:    time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC),
		Name:         "notes.txt",
	}

	v4Hash := ntfsUSNRecordHash(v4).(*object.Hash)
	if mustHashBoolValue(t, v4Hash, "has_timestamp") {
		t.Error("a v4 record claimed a timestamp")
	}
	if mustHashBoolValue(t, v4Hash, "has_name") {
		t.Error("a v4 record claimed a name")
	}
	if got := mustHashStringValue(t, v4Hash, "timestamp"); got != "" {
		t.Errorf("timestamp = %q, want empty rather than a year-1 date", got)
	}
	if got := mustHashStringValue(t, v4Hash, "version"); got != "4.0" {
		t.Errorf("version = %q, want 4.0", got)
	}

	v3Hash := ntfsUSNRecordHash(v3).(*object.Hash)
	if !mustHashBoolValue(t, v3Hash, "has_timestamp") || !mustHashBoolValue(t, v3Hash, "has_name") {
		t.Error("a v3 record with both was reported as having neither")
	}
	if got := mustHashStringValue(t, v3Hash, "name"); got != "notes.txt" {
		t.Errorf("name = %q, want notes.txt", got)
	}
}

func TestAUSNRecordCarriesTheSequenceThatTiesItToARecordOccupant(t *testing.T) {
	// The MFT record number alone is not an identity: NTFS reuses records, and
	// the sequence number is what says which occupant a journal entry is about.
	record := &libntfs.USNRecord{
		MajorVersion: 2, USN: 8,
		FileReference: 42, FileSequence: 7,
		ParentReference: 5, ParentSequence: 3,
		Reason: libntfs.USNReasonFileDelete | libntfs.USNReasonClose,
	}
	hash := ntfsUSNRecordHash(record).(*object.Hash)

	for field, want := range map[string]int64{
		"file_reference": 42, "file_sequence": 7,
		"parent_reference": 5, "parent_sequence": 3,
	} {
		if got := mustHashIntValue(t, hash, field); got != want {
			t.Errorf("%s = %d, want %d", field, got, want)
		}
	}

	reasons := mustHashArrayValue(t, hash, "reasons")
	var names []string
	for _, reason := range reasons {
		names = append(names, reason.(*object.String).Value)
	}
	if !strings.Contains(strings.Join(names, ","), "FileDelete") {
		t.Errorf("reasons = %v, want the delete bit decoded", names)
	}
}

// --- NTFS: $LogFile ---------------------------------------------------------

func TestAnUnresolvedTargetAttributeIsEmptyRatherThanInvented(t *testing.T) {
	// A log written round past its last attribute-table dump resolves nothing.
	// The fields have to come back empty rather than as a plausible default:
	// target_record 0 is the $MFT itself.
	record := &libntfs.LogRecord{LSN: 900, TargetAttribute: 0x1f8, RecordType: 1}
	hash := ntfsLogRecordHash(record, nil).(*object.Hash)

	if got := mustHashStringValue(t, hash, "target_attribute_name"); got != "" {
		t.Errorf("target_attribute_name = %q, want empty", got)
	}
	if got := mustHashStringValue(t, hash, "target_attribute_type"); got != "" {
		t.Errorf("target_attribute_type = %q, want empty", got)
	}
	if got := mustHashIntValue(t, hash, "target_record"); got != -1 {
		t.Errorf("target_record = %d, want -1: record 0 is $MFT and not a miss", got)
	}
	if got := mustHashIntValue(t, hash, "target_attribute"); got != 0x1f8 {
		t.Errorf("target_attribute = %d, want the raw offset kept", got)
	}
}

func TestATransactionMissingItsBeginningSaysSo(t *testing.T) {
	// The grouping reports the first surviving record as FirstLSN whether or
	// not it is the transaction's first. A record naming a previous record of
	// its own is not a beginning.
	whole := libntfs.LogTransaction{
		ID: 3, FirstLSN: 100, LastLSN: 140,
		Records:   []*libntfs.LogRecord{{LSN: 100, ClientPreviousLSN: 0}, {LSN: 140, ClientPreviousLSN: 100}},
		Committed: true,
	}
	clipped := libntfs.LogTransaction{
		ID: 4, FirstLSN: 200, LastLSN: 240,
		Records:   []*libntfs.LogRecord{{LSN: 200, ClientPreviousLSN: 180}, {LSN: 240, ClientPreviousLSN: 200}},
		Forgotten: true,
	}

	wholeHash := ntfsLogTransactionHash(whole).(*object.Hash)
	if !mustHashBoolValue(t, wholeHash, "start_present") {
		t.Error("a transaction whose first record names no predecessor was called clipped")
	}
	clippedHash := ntfsLogTransactionHash(clipped).(*object.Hash)
	if mustHashBoolValue(t, clippedHash, "start_present") {
		t.Error("a transaction whose beginning was overwritten was presented as whole")
	}
}

func TestCommittedAndForgottenAreTwoBitsAndNotOne(t *testing.T) {
	// NTFS ends almost every transaction with ForgetTransaction, so committed
	// false is the normal reading rather than a finding. end_state is what a
	// report should quote.
	cases := []struct {
		name      string
		txn       libntfs.LogTransaction
		endState  string
		committed bool
		forgotten bool
	}{
		{"committed", libntfs.LogTransaction{Committed: true}, "committed", true, false},
		{"forgotten", libntfs.LogTransaction{Forgotten: true}, "forgotten", false, true},
		{"still open", libntfs.LogTransaction{}, "open", false, false},
		{"both seen", libntfs.LogTransaction{Committed: true, Forgotten: true}, "committed", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash := ntfsLogTransactionHash(tc.txn).(*object.Hash)
			if got := mustHashStringValue(t, hash, "end_state"); got != tc.endState {
				t.Errorf("end_state = %q, want %q", got, tc.endState)
			}
			if mustHashBoolValue(t, hash, "committed") != tc.committed {
				t.Errorf("committed = %v, want %v", !tc.committed, tc.committed)
			}
			if mustHashBoolValue(t, hash, "forgotten") != tc.forgotten {
				t.Errorf("forgotten = %v, want %v", !tc.forgotten, tc.forgotten)
			}
		})
	}
}

func TestARestartAreaThatCouldNotBeReadIsNotAZeroOne(t *testing.T) {
	missing := ntfsRestartHash(nil).(*object.Hash)
	if mustHashBoolValue(t, missing, "available") {
		t.Error("a missing restart area reported itself available")
	}
	for _, field := range []string{"current_lsn", "chkdsk_lsn", "open_count", "file_size"} {
		if got := mustHashIntValue(t, missing, field); got != -1 {
			t.Errorf("%s = %d, want -1 when the area could not be read", field, got)
		}
	}

	// chkdsk_lsn zero on a real area is a finding -- chkdsk has never run --
	// and must survive as the zero it is rather than becoming the -1 that
	// means unknown.
	present := ntfsRestartHash(&libntfs.LogRestartArea{
		CurrentLSN: 4096, ChkdskLSN: 0, RestartOpenCount: 9, FileSize: 67108864,
	}).(*object.Hash)
	if !mustHashBoolValue(t, present, "available") {
		t.Error("a real restart area reported itself unavailable")
	}
	if got := mustHashIntValue(t, present, "chkdsk_lsn"); got != 0 {
		t.Errorf("chkdsk_lsn = %d, want 0: never run is not unknown", got)
	}
	if got := mustHashIntValue(t, present, "open_count"); got != 9 {
		t.Errorf("open_count = %d, want 9", got)
	}
}

// --- ext: JBD2 --------------------------------------------------------------

func TestAnExternalJournalIsNotAMissingJournal(t *testing.T) {
	// libext's own status string calls both "Journal disabled or external".
	// A filesystem journalled onto another device is fully journalled and its
	// evidence is simply elsewhere, which is not the same finding as one that
	// journals nothing.
	external := extJournalDescription(0, true, "", nil, false, map[string]bool{"has_journal": true})
	none := extJournalDescription(0, false, "", nil, false, map[string]bool{})

	if !external["external"].(*object.Boolean).Value {
		t.Error("an external journal did not report itself external")
	}
	if none["external"].(*object.Boolean).Value {
		t.Error("a filesystem with no journal was called external")
	}

	features := external["features"].(*object.Hash)
	if !mustHashBoolValue(t, features, "has_journal") {
		t.Error("an externally journalled filesystem reported has_journal false")
	}
}

func TestJournalFeaturesReadFromNoSuperblockAreNotNegativeResults(t *testing.T) {
	// The six journal_* bits live in the journal's own superblock. Where it
	// could not be read they come back false, and superblock.available is the
	// only thing that says nobody looked.
	fields := extJournalDescription(8, false, "", nil, false, map[string]bool{"has_journal": true})

	superblock := fields["superblock"].(*object.Hash)
	if mustHashBoolValue(t, superblock, "available") {
		t.Error("an unread journal superblock reported itself available")
	}
	features := fields["features"].(*object.Hash)
	for _, name := range []string{"journal_revoke", "journal_checksum_v2", "journal_64bit"} {
		if mustHashBoolValue(t, features, name) {
			t.Errorf("%s was true although nothing read the journal superblock", name)
		}
	}
	// Every declared key is present whether or not it was readable, so a
	// script never has to test for a missing one.
	for _, name := range []string{"has_journal", "needs_recovery", "journal_async_commit",
		"journal_fast_commit", "journal_checksum_v3"} {
		if _, ok := hashLookup(features, name); !ok {
			t.Errorf("feature %q is missing from the result", name)
		}
	}
}

func TestATransactionThatNeverCommittedHasNoCommitTime(t *testing.T) {
	committed := libext.JournalTransaction{
		Sequence: 12, Type: "descriptor", IsCommitted: true,
		Timestamp: time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC),
		Tags:      []libext.JournalBlockTag{{FSBlock: 90, JournalBlock: 4}},
	}
	open := libext.JournalTransaction{Sequence: 13, Type: "descriptor"}

	committedHash := extJournalTransactionHash(committed).(*object.Hash)
	if !mustHashBoolValue(t, committedHash, "has_timestamp") {
		t.Error("a committed transaction lost its commit time")
	}
	if got := mustHashIntValue(t, committedHash, "tag_count"); got != 1 {
		t.Errorf("tag_count = %d, want 1", got)
	}

	openHash := extJournalTransactionHash(open).(*object.Hash)
	if mustHashBoolValue(t, openHash, "has_timestamp") {
		t.Error("a transaction with no commit block claimed a commit time")
	}
	if got := mustHashStringValue(t, openHash, "timestamp"); got != "" {
		t.Errorf("timestamp = %q, want empty: rendering the zero time invents "+
			"the very event its absence is evidence against", got)
	}
}

func TestAWrappedExtJournalDisownsItsOwnCommitBits(t *testing.T) {
	// The false-positive is one libext creates itself: a commit block on the
	// low side of the seam is processed before its descriptor, matched against
	// nothing and discarded, so a transaction that did commit reports false.
	wrapped := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	wrapped.WrapChecked = true
	for _, position := range []int64{40, 41, 5, 6} {
		wrapped.observeOrder(position)
	}
	noteEXTWrap(&wrapped)

	codes := warningCodesOf(wrapped)
	if !codes[fsJournalWarnWrapped] {
		t.Error("a wrapped journal raised no ordering warning")
	}
	if !codes[fsJournalWarnCommitUnreliable] {
		t.Error("a wrapped ext journal did not disown its commit bits")
	}

	straight := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	straight.WrapChecked = true
	for _, position := range []int64{1, 2, 3} {
		straight.observeOrder(position)
	}
	noteEXTWrap(&straight)
	if len(straight.Warnings) != 0 {
		t.Errorf("an unwrapped journal invented %d warnings", len(straight.Warnings))
	}
}

func TestAJournalledBlockCopyCarriesItsOwnDigest(t *testing.T) {
	content := []byte("a group descriptor as it was three transactions ago")
	hash := extBlockCopyHash(2, content).(*object.Hash)

	if got := mustHashIntValue(t, hash, "version"); got != 2 {
		t.Errorf("version = %d, want 2", got)
	}
	if got := mustHashIntValue(t, hash, "size"); got != int64(len(content)) {
		t.Errorf("size = %d, want %d", got, len(content))
	}
	if got := mustHashStringValue(t, hash, "digest"); got != sha256Hex(content) {
		t.Errorf("digest = %q, want the sha256 of the copy", got)
	}

	bytesValue, ok := hashLookup(hash, "bytes")
	if !ok {
		t.Fatal("the copy carries no bytes")
	}
	buffer, ok := bytesValue.(*object.Bytes)
	if !ok {
		t.Fatalf("bytes is not BYTES. got=%T", bytesValue)
	}
	if string(buffer.Value) != string(content) {
		t.Error("the copy's bytes are not the block's")
	}
	// The buffer must not alias the library's, which libext reuses.
	buffer.Value[0] = 'X'
	if content[0] == 'X' {
		t.Error("the returned buffer aliases the library's own")
	}
}

func TestAnInodeVersionWithNoSurvivingTreeReportsNoneNotZeroBytes(t *testing.T) {
	inode := libext.Inode{Number: 12, Size: 4096, IsRegular: true, HasExtents: true}

	located := extInodeVersionHash(0, inode, []fsDeletedRun{
		{FileOffset: 0, Offset: 1 << 20, Length: 4096},
	}, fsDeletedContentPreserved).(*object.Hash)
	if got := mustHashStringValue(t, located, "content_state"); got != fsDeletedContentPreserved {
		t.Errorf("content_state = %q, want preserved", got)
	}
	if got := mustHashIntValue(t, located, "located_bytes"); got != 4096 {
		t.Errorf("located_bytes = %d, want 4096", got)
	}

	zeroed := extInodeVersionHash(1, inode, nil, fsDeletedContentNone).(*object.Hash)
	if got := mustHashStringValue(t, zeroed, "content_state"); got != fsDeletedContentNone {
		t.Errorf("content_state = %q, want none", got)
	}
	if got := mustHashIntValue(t, zeroed, "located_bytes"); got != 0 {
		t.Errorf("located_bytes = %d, want 0", got)
	}
	if got := len(mustHashArrayValue(t, zeroed, "runs")); got != 0 {
		t.Errorf("runs = %d, want none", got)
	}
}

func TestAnOrphanListDeletionTimeIsCarriedRawBesideTheDate(t *testing.T) {
	// ext4 reuses the deletion-time field to hold the next inode number while
	// an inode sits on the legacy orphan list. Read as a date, inode 11 is a
	// timestamp eleven seconds after the epoch.
	inode := libext.Inode{Number: 30, DtimeRaw: 11, Dtime: time.Unix(11, 0).UTC()}
	hash := extInodeVersionHash(0, inode, nil, fsDeletedContentNone).(*object.Hash)

	if got := mustHashIntValue(t, hash, "deleted_at_raw"); got != 11 {
		t.Errorf("deleted_at_raw = %d, want 11", got)
	}
	if got := mustHashStringValue(t, hash, "deleted_at"); !strings.HasPrefix(got, "1970-01-01") {
		t.Errorf("deleted_at = %q, want the decoded field beside the raw one", got)
	}
}

// --- XFS: XLOG --------------------------------------------------------------

func TestMoreThanOneCycleIsTheWrapItself(t *testing.T) {
	// The cycle is the number of times the log has been written round, so this
	// is a reading of the format and not an inference from the order.
	one := newJournalScan("xfs", fsJournalXLOG, fsJournalOrderLSN)
	two := newJournalScan("xfs", fsJournalXLOG, fsJournalOrderLSN)

	cyclesOf := func(scan *fsJournalScan, cycles ...uint32) {
		seen := map[uint32]bool{}
		for _, cycle := range cycles {
			seen[cycle] = true
		}
		scan.Wrapped = len(seen) > 1
	}
	cyclesOf(&one, 7, 7, 7)
	cyclesOf(&two, 7, 7, 8)

	if one.Wrapped {
		t.Error("a log with one cycle was reported as wrapped")
	}
	if !two.Wrapped {
		t.Error("a log carrying two cycles was not reported as wrapped")
	}
}

func TestAPackedLSNOrdersByCycleThenBlock(t *testing.T) {
	older := xfsPackedLSN(libxfs.LSN{Cycle: 7, Block: 90000})
	newer := xfsPackedLSN(libxfs.LSN{Cycle: 8, Block: 1})
	if !(older < newer) {
		t.Errorf("a high block in an old cycle (%d) outranked a new cycle (%d)", older, newer)
	}
}

func TestTheChecksumBitsAreTwoAndNotOne(t *testing.T) {
	// checked is false for four unrelated reasons -- a v4 image, a stored CRC
	// of zero, checksums skipped, a short header -- so valid means nothing on
	// its own.
	unchecked := xfsLogRecordHash(libxfs.LogRecord{
		LSN: libxfs.LSN{Cycle: 1, Block: 2}, ChecksumChecked: false, ChecksumValid: false,
	}).(*object.Hash)
	failed := xfsLogRecordHash(libxfs.LogRecord{
		LSN: libxfs.LSN{Cycle: 1, Block: 3}, ChecksumChecked: true, ChecksumValid: false,
	}).(*object.Hash)

	if mustHashBoolValue(t, unchecked, "checksum_checked") {
		t.Error("an unchecked record claimed to have been checked")
	}
	if !mustHashBoolValue(t, failed, "checksum_checked") || mustHashBoolValue(t, failed, "checksum_valid") {
		t.Error("a record that failed its checksum was not reported as checked and invalid")
	}
}

func TestItemCountAndItemsRecoveredAreTwoNumbers(t *testing.T) {
	// libxfs stops at 65536 items in one transaction and raises no anomaly,
	// so the header's claim disagreeing with what was rebuilt is the only sign.
	transaction := libxfs.LogTransaction{
		TransactionID: 9,
		LSN:           libxfs.LSN{Cycle: 2, Block: 40},
		ItemCount:     5,
		Items:         []libxfs.LogItem{{Type: 0x123b, TypeName: "inode"}, {Type: 0x123c, TypeName: "buffer"}},
		Committed:     false,
	}
	hash := xfsLogTransactionHash(transaction).(*object.Hash)

	if got := mustHashIntValue(t, hash, "item_count"); got != 5 {
		t.Errorf("item_count = %d, want the header's claim of 5", got)
	}
	if got := mustHashIntValue(t, hash, "items_recovered"); got != 2 {
		t.Errorf("items_recovered = %d, want the 2 that were rebuilt", got)
	}
	if mustHashBoolValue(t, hash, "committed") {
		t.Error("a transaction with no commit region was reported as committed")
	}
}

func TestABufferItemAtTwoZeroesIsNotAtOffsetZero(t *testing.T) {
	// Both ends zero means libxfs read a negative block number. Offset zero is
	// the superblock, and a report placing a logged buffer there is placing it
	// on the one structure it certainly was not.
	negative := xfsLogItemHash(libxfs.LogItem{
		Type: 0x123c, TypeName: "buffer", RegionCount: 2,
		Buffer: &libxfs.LogBufferItem{BlockNumber: -1, StartOffset: 0, EndOffset: 0},
	}).(*object.Hash)
	if got := mustHashIntValue(t, negative, "offset"); got != -1 {
		t.Errorf("offset = %d, want -1 for a negative block number", got)
	}

	real := xfsLogItemHash(libxfs.LogItem{
		Type: 0x123c, TypeName: "buffer", RegionCount: 2,
		Buffer: &libxfs.LogBufferItem{BlockNumber: 64, StartOffset: 32768, EndOffset: 36864},
	}).(*object.Hash)
	if got := mustHashIntValue(t, real, "offset"); got != 32768 {
		t.Errorf("offset = %d, want 32768", got)
	}
	if got := mustHashIntValue(t, real, "length"); got != 4096 {
		t.Errorf("length = %d, want 4096", got)
	}
	if got := mustHashIntValue(t, real, "inode"); got != -1 {
		t.Errorf("inode = %d, want -1 on an item that names no inode", got)
	}

	inodeItem := xfsLogItemHash(libxfs.LogItem{
		Type: 0x123b, TypeName: "inode", RegionCount: 3,
		Inode: &libxfs.LogInodeItem{InodeNumber: 8419, StartOffset: 100, EndOffset: 356},
	}).(*object.Hash)
	if got := mustHashIntValue(t, inodeItem, "inode"); got != 8419 {
		t.Errorf("inode = %d, want 8419", got)
	}
}

// --- metadata agrees with the implementation --------------------------------

// TestEveryJournalBuiltinDeclaresExactlyTheEnvelopeItReturns checks the two
// copies of each field list against each other.
//
// metadata.go spells the field names a second time, as literals, and the
// editor's hover card and a .mut program's key lookups both read that copy.
// Nothing else links it to the functions that produce the keys.
func TestEveryJournalBuiltinDeclaresExactlyTheEnvelopeItReturns(t *testing.T) {
	envelope := []string{}
	for _, pair := range newJournalScan("fs", "j", fsJournalOrderLSN).toHash("h").Pairs {
		envelope = append(envelope, pair.Key.(*object.String).Value)
	}

	ntfsLog := keysOf(ntfsLogDescription(nil, nil, false))
	extJournal := keysOf(extJournalDescription(0, false, "", nil, false, nil))

	cases := map[string][]string{
		BuiltinNameNtfsUsnJournal:        envelope,
		BuiltinNameNtfsLogRecords:        append(append([]string{}, envelope...), ntfsLog...),
		BuiltinNameNtfsLogTransactions:   append(append([]string{}, envelope...), ntfsLog...),
		BuiltinNameExtJournal:            append(append([]string{}, envelope...), extJournal...),
		BuiltinNameExtJournalBlockCopies: append(append(append([]string{}, envelope...), extJournal...), "fs_block"),
		BuiltinNameExtInodeVersions:      append(append(append([]string{}, envelope...), extJournal...), "inode"),
		BuiltinNameXfsLogRecords:         append(append([]string{}, envelope...), "cleared_blocks", "has_unmount_record"),
		BuiltinNameXfsLogTransactions:    append(append([]string{}, envelope...), "record_count", "has_unmount_record"),
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			declared := append([]string{}, builtinDocs[name].returns.fields...)
			sort.Strings(declared)
			sort.Strings(want)
			if strings.Join(declared, ",") != strings.Join(want, ",") {
				t.Errorf("%s declares\n  %v\nbut returns\n  %v", name, declared, want)
			}
		})
	}
}

// --- helpers ----------------------------------------------------------------

func openJournalHandle(t *testing.T, open func() object.Object) string {
	t.Helper()
	payload, err := unwrapPair(t, open())
	if err != nil {
		t.Fatalf("open returned error: %s", err.Inspect())
	}
	return mustHashStringValue(t, payload.(*object.Hash), "handle")
}

func hashLookup(hash *object.Hash, key string) (object.Object, bool) {
	for _, pair := range hash.Pairs {
		if name, ok := pair.Key.(*object.String); ok && name.Value == key {
			return pair.Value, true
		}
	}
	return nil, false
}

func warningCodesOf(scan fsJournalScan) map[string]bool {
	codes := map[string]bool{}
	for _, warning := range scan.Warnings {
		codes[warning.Code] = true
	}
	return codes
}

func keysOf(fields map[string]object.Object) []string {
	out := make([]string, 0, len(fields))
	for key := range fields {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
