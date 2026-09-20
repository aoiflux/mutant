package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

// syntheticReport is a small report in the shape the six real ones produce, so
// that the rules every report shares can be tested without a real volume.
func syntheticReport(filesystem string) fsReport {
	return fsReport{
		Filesystem:             filesystem,
		SchemaVersion:          1,
		LibraryVersion:         "0.0.0-test",
		Generated:              "2026-09-20T00:00:00Z",
		Name:                   "synthetic",
		StartOffset:            0,
		EndOffset:              1 << 20,
		FragmentsAvailable:     true,
		IdentityKind:           fsIdentityInode,
		IdentityStable:         true,
		IdentityStableAnswered: true,
		Complete:               true,
		WarningsAvailable:      true,
		Volume:                 map[string]object.Object{"type": stringObj(filesystem)},
		Scope:                  "synthetic",
	}
}

// The trap, pinned. libntfs leaves both offsets at zero on a sparse run and
// libxfs leaves them at zero on a hole and on a run whose block number will not
// resolve -- and zero is the first byte of the image. A consumer that seeked
// there would read the boot sector and call it file content.
func TestAFragmentWithNoPlaceInTheImageIsNotAtOffsetZero(t *testing.T) {
	nowhere := fsLocatedFragment(0, 0, 4096, 4096, true, false)

	if nowhere.Located {
		t.Fatal("a run with no offsets should not claim a location")
	}
	if nowhere.StartOffset != -1 || nowhere.EndOffset != -1 {
		t.Fatalf("start/end = %d/%d, want -1/-1", nowhere.StartOffset, nowhere.EndOffset)
	}
	// The rest of the run is still a fact about the file and must survive.
	if nowhere.FileOffset != 4096 || nowhere.Length != 4096 || !nowhere.Sparse {
		t.Fatalf("an unlocated run lost the facts it did have: %+v", nowhere)
	}
}

func TestALocatedFragmentKeepsItsOffsetsAndDerivesItsLength(t *testing.T) {
	// A library that reports the span and not the length gets one derived, so
	// the shape is uniform whichever of the six filled it in.
	derived := fsLocatedFragment(1024, 5120, 0, 0, false, false)
	if !derived.Located {
		t.Fatal("a run with real offsets should be located")
	}
	if derived.Length != 4096 {
		t.Fatalf("length = %d, want 4096 derived from the span", derived.Length)
	}

	// A length the library did state is never recomputed: on a run whose span
	// and length disagree, the library's own number is the evidence.
	stated := fsLocatedFragment(1024, 5120, 0, 512, false, false)
	if stated.Length != 512 {
		t.Fatalf("length = %d, want the library's own 512", stated.Length)
	}
}

// A truncated listing must not also truncate the numbers beside it, or a
// document quoting "1000 deleted files" would mean "1000 of the first 50000
// rows".
func TestTheFileCapKeepsEveryCountHonestPastIt(t *testing.T) {
	report := syntheticReport("ext")
	total := fsReportMaxFiles + 250
	for i := 0; i < total; i++ {
		report.add(fsReportFile{
			IsDeleted:    i%2 == 0,
			IsDirectory:  i%3 == 0,
			IsFragmented: i%5 == 0,
		})
	}

	if len(report.Files) != fsReportMaxFiles {
		t.Fatalf("rendered %d rows, want the cap of %d", len(report.Files), fsReportMaxFiles)
	}
	if report.FileCount != int64(total) {
		t.Fatalf("file_count = %d, want %d", report.FileCount, total)
	}
	if want := int64((total + 1) / 2); report.DeletedCount != want {
		t.Fatalf("deleted_count = %d, want %d", report.DeletedCount, want)
	}

	report.finish()
	hash := report.toHash("handle-1")
	if truncated, ok := hashValueByKey(hash, "files_truncated").(*object.Boolean); !ok || !truncated.Value {
		t.Fatal("a capped listing should say it was truncated")
	}
	if !hasWarningCode(t, hash, fsReportWarnFilesTruncated) {
		t.Fatal("a capped listing should raise its own warning")
	}
	if complete, ok := hashValueByKey(hash, "complete").(*object.Boolean); !ok || complete.Value {
		t.Fatal("a truncated listing is not complete")
	}
}

func TestTheFragmentCapKeepsItsCountHonestPastIt(t *testing.T) {
	file := fsReportFile{}
	for i := 0; i < fsReportMaxFragments+7; i++ {
		fsAddFragment(&file, fsLocatedFragment(int64(i+1)*512, int64(i+2)*512, 0, 512, false, false))
	}

	if len(file.Fragments) != fsReportMaxFragments {
		t.Fatalf("rendered %d runs, want the cap of %d", len(file.Fragments), fsReportMaxFragments)
	}
	if file.FragmentCount != int64(fsReportMaxFragments+7) {
		t.Fatalf("fragment_count = %d, want %d", file.FragmentCount, fsReportMaxFragments+7)
	}

	row, ok := file.toHash(0).(*object.Hash)
	if !ok {
		t.Fatal("a row should render as a HASH")
	}
	if truncated, ok := hashValueByKey(row, "fragments_truncated").(*object.Boolean); !ok || !truncated.Value {
		t.Fatal("a capped run list should say so on its own row")
	}
}

// Five of the six libraries can say what their walk reached and none of them
// can say what it missed. Saying nothing about that is how a listing comes to
// be read as an inventory.
func TestAListingNothingReconciledSaysSo(t *testing.T) {
	report := syntheticReport("fat")
	report.finish()

	hash := report.toHash("handle-1")
	if !hasWarningCode(t, hash, fsReportWarnNotReconciled) {
		t.Fatal("a listing nothing reconciled should say so")
	}
	if checked, ok := hashValueByKey(hash, "completeness_checked").(*object.Boolean); !ok || checked.Value {
		t.Fatal("completeness_checked should be false when nothing reconciled the listing")
	}
	// And `complete` must not be read as a completeness claim: the walk had no
	// known gap, which is a different statement.
	if complete, ok := hashValueByKey(hash, "complete").(*object.Boolean); !ok || !complete.Value {
		t.Fatal("a walk with no known gap is still complete in the envelope's sense")
	}
}

func TestAReconciliationThatDidNotBalanceIsNotACompletenessClaim(t *testing.T) {
	report := syntheticReport("xfs")
	report.CompletenessChecked = true
	report.CompletenessProven = false
	report.finish()

	hash := report.toHash("handle-1")
	if hasWarningCode(t, hash, fsReportWarnNotReconciled) {
		t.Fatal("a reconciliation did run, so the not-reconciled warning is wrong")
	}
	if !hasWarningCode(t, hash, fsReportWarnNotBalanced) {
		t.Fatal("a reconciliation that did not balance should say so")
	}
}

func TestAReconciledAndBalancedListingRaisesNeither(t *testing.T) {
	report := syntheticReport("xfs")
	report.CompletenessChecked = true
	report.CompletenessProven = true
	report.finish()

	hash := report.toHash("handle-1")
	if hasWarningCode(t, hash, fsReportWarnNotReconciled) || hasWarningCode(t, hash, fsReportWarnNotBalanced) {
		t.Fatal("a proven listing should raise neither completeness warning")
	}
}

// The report never decides whether an identity is stable. It reads the same
// Capabilities the sibling builtin reports, so the two cannot drift, and it
// carries the answered bit because two of the six libraries never say.
func TestIdentityStabilityIsReadFromTheCapabilitySetAndNotDecidedHere(t *testing.T) {
	cases := []struct {
		name     string
		caps     fsCapabilitySet
		answered bool
		stable   bool
	}{
		{
			"declared stable",
			fsCapabilitySet{Caps: []fsCapability{{Name: "stable_file_identity", Supported: true, Source: fsCapFromFormat}}},
			true, true,
		},
		{
			"declared unstable",
			fsCapabilitySet{Caps: []fsCapability{{Name: "stable_file_identity", Supported: false, Source: fsCapFromFormat}}},
			true, false,
		},
		{
			// libhfs and libxfs do not declare it at all. Reading that absence
			// as "no" would be this file asserting what the library declined to.
			"never declared",
			fsCapabilitySet{Caps: []fsCapability{{Name: "hard_links", Supported: true, Source: fsCapFromFormat}}},
			false, false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := fsReport{}
			fsReportIdentity(&report, tc.caps, fsIdentityCatalogID)

			if report.IdentityKind != fsIdentityCatalogID {
				t.Fatalf("identity_kind = %q", report.IdentityKind)
			}
			if report.IdentityStableAnswered != tc.answered {
				t.Fatalf("identity_stable_answered = %v, want %v", report.IdentityStableAnswered, tc.answered)
			}
			if report.IdentityStable != tc.stable {
				t.Fatalf("identity_stable = %v, want %v", report.IdentityStable, tc.stable)
			}
		})
	}
}

// "This identity is reused" and "nobody said whether this identity is reused"
// are different findings, and a script that treated them alike would diff a FAT
// volume on a slot number believing it had checked.
func TestAnUnstableIdentityAndAnUndeclaredOneAreDifferentWarnings(t *testing.T) {
	unstable := syntheticReport("fat")
	unstable.IdentityKind = fsIdentityDirSlot
	unstable.IdentityStableAnswered = true
	unstable.IdentityStable = false
	unstable.finish()

	unstableHash := unstable.toHash("handle-1")
	if !hasWarningCode(t, unstableHash, fsReportWarnIdentityUnstable) {
		t.Fatal("a declared-unstable identity should raise the unstable warning")
	}
	if hasWarningCode(t, unstableHash, fsReportWarnIdentityUnanswered) {
		t.Fatal("a declared-unstable identity was answered, so the unanswered warning is wrong")
	}

	silent := syntheticReport("hfs")
	silent.IdentityKind = fsIdentityCatalogID
	silent.IdentityStableAnswered = false
	silent.finish()

	silentHash := silent.toHash("handle-1")
	if !hasWarningCode(t, silentHash, fsReportWarnIdentityUnanswered) {
		t.Fatal("an undeclared identity stability should raise the unanswered warning")
	}
	if hasWarningCode(t, silentHash, fsReportWarnIdentityUnstable) {
		t.Fatal("an undeclared stability is not a statement that the identity is unstable")
	}
}

func TestTheFirstReasonAReportIsIncompleteIsTheOneKept(t *testing.T) {
	report := syntheticReport("ext")
	report.incomplete("the first thing that went wrong")
	report.incomplete("a later consequence of it")

	if report.Complete {
		t.Fatal("a report with a known gap is not complete")
	}
	if report.IncompleteReason != "the first thing that went wrong" {
		t.Fatalf("incomplete_reason = %q, want the first reason", report.IncompleteReason)
	}
}

func TestALayoutWithNoDerivationRendersAsUnavailable(t *testing.T) {
	hash, ok := (fsReportLayout{}).toHash().(*object.Hash)
	if !ok {
		t.Fatal("a layout should render as a HASH")
	}
	if got := mustHashStringValue(t, hash, "derived"); got != fsLayoutUnavailable {
		t.Fatalf("derived = %q, want %q", got, fsLayoutUnavailable)
	}
}

// --- through the builtins ---------------------------------------------------

func TestEveryReportBuiltinReturnsTheDeclaredFields(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.ReportBuiltin, func(t *testing.T) {
			handle := openFamily(t, family, fsCapabilitySet{}, nil, syntheticReport(family.Name), nil)

			payload, errObj := unwrapPair(t, family.Report(handle))
			if errObj != nil {
				t.Fatalf("%s returned error: %s", family.ReportBuiltin, errObj.Inspect())
			}
			assertDeclaredFields(t, family.ReportBuiltin, payload, handle)
		})
	}
}

func TestEachReportBuiltinAsksItsOwnHandle(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.ReportBuiltin, func(t *testing.T) {
			report := syntheticReport(family.Name)
			report.add(fsReportFile{Filesystem: family.Name, Path: "/one", Name: "one"})
			handle := openFamily(t, family, fsCapabilitySet{}, nil, report, nil)

			payload, errObj := unwrapPair(t, family.Report(handle))
			if errObj != nil {
				t.Fatalf("%s returned error: %s", family.ReportBuiltin, errObj.Inspect())
			}
			hash := payload.(*object.Hash)
			if got := mustHashStringValue(t, hash, "filesystem"); got != family.Name {
				t.Fatalf("%s reported filesystem %q, want %q", family.ReportBuiltin, got, family.Name)
			}
			if count, ok := hashValueByKey(hash, "file_count").(*object.Integer); !ok || count.Value != 1 {
				t.Fatalf("%s did not carry the session's own report", family.ReportBuiltin)
			}
		})
	}
}

func TestAFilesystemReportErrorIsReportedAndNotRendered(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.ReportBuiltin, func(t *testing.T) {
			handle := openFamily(t, family, fsCapabilitySet{}, nil, fsReport{}, errFakeFilesystemLibrary)

			payload, errObj := unwrapPair(t, family.Report(handle))
			if errObj == nil {
				t.Fatalf("%s rendered a document for a failed walk: %s", family.ReportBuiltin, payload.Inspect())
			}
			if _, rendered := payload.(*object.Hash); rendered {
				t.Fatalf("%s rendered a document beside its error: %s", family.ReportBuiltin, payload.Inspect())
			}
			if !strings.Contains(errObj.Message, family.ReportBuiltin) {
				t.Fatalf("the error should name the builtin, got %q", errObj.Message)
			}
			if !strings.Contains(errObj.Message, errFakeFilesystemLibrary.Error()) {
				t.Fatalf("the error should quote the library, got %q", errObj.Message)
			}
		})
	}
}

func TestEveryReportBuiltinChecksItsArity(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.ReportBuiltin, func(t *testing.T) {
			handle := openFamily(t, family, fsCapabilitySet{}, nil, syntheticReport(family.Name), nil)

			for _, args := range [][]object.Object{
				{},
				{stringObj(handle), stringObj("extra")},
			} {
				_, errObj := unwrapPair(t, callBuiltinByName(t, family.ReportBuiltin, args...))
				if errObj == nil {
					t.Fatalf("%s accepted %d arguments", family.ReportBuiltin, len(args))
				}
				if !strings.Contains(errObj.Message, "wrong number of arguments") {
					t.Fatalf("unexpected arity error: %q", errObj.Message)
				}
			}
		})
	}
}

func TestAReportHandleMustBeAKnownOne(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.ReportBuiltin, func(t *testing.T) {
			family.Install(t, fsCapabilitySet{}, nil, fsReport{}, nil)
			if _, errObj := unwrapPair(t, family.Report("no-such-handle")); errObj == nil {
				t.Fatalf("%s accepted an unknown handle", family.ReportBuiltin)
			}
		})
	}
}

// --- into the schemas -------------------------------------------------------

// timelineReport is a two-row document with every timestamp a row can carry,
// so the event source can be exercised on all five.
func timelineReport() fsReport {
	report := syntheticReport("ext")
	report.add(fsReportFile{
		Filesystem:      "ext",
		Path:            "/home/analyst/notes.txt",
		Name:            "notes.txt",
		Type:            "file",
		Size:            1234,
		Identity:        "42-7",
		Created:         "2026-01-01T00:00:00Z",
		Modified:        "2026-01-02T00:00:00Z",
		MetadataChanged: "2026-01-03T00:00:00Z",
		Accessed:        "2026-01-04T00:00:00Z",
	})
	report.add(fsReportFile{
		Filesystem: "ext",
		Path:       "/home/analyst/gone.txt",
		Name:       "gone.txt",
		Type:       "file",
		Size:       0,
		IsDeleted:  true,
		Identity:   "43-1",
		Modified:   "2026-01-05T00:00:00Z",
		DeletedAt:  "2026-01-06T00:00:00Z",
	})
	return report
}

// The plan's actual deliverable: a report is not a dead end, it is the input
// to the emitters. One source spec covers all six filesystems because the six
// documents already share a row shape.
func TestAReportBecomesASupertimeline(t *testing.T) {
	document := timelineReport().toHash("handle-1")

	payload, errObj := unwrapPair(t, EventsFrom(document, stringObj("fs_report")))
	if errObj != nil {
		t.Fatalf("events_from returned error: %s", errObj.Inspect())
	}
	events, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("events_from payload is not ARRAY. got=%T", payload)
	}

	// Four times on the first row, two on the second.
	if len(events.Elements) != 6 {
		t.Fatalf("got %d events, want 6", len(events.Elements))
	}

	descriptions := map[string]bool{}
	for _, element := range events.Elements {
		event, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("an event is not a HASH. got=%T", element)
		}
		descriptions[mustHashStringValue(t, event, "ts_desc")] = true

		if got := mustHashStringValue(t, event, "kind"); got != "fs_report" {
			t.Fatalf("kind = %q, want fs_report", got)
		}
		// The filesystem reaches the envelope as the dataset, which is what
		// keeps a timeline merged from two volumes able to say which is which.
		if got := mustHashStringValue(t, event, "dataset"); got != "ext" {
			t.Fatalf("dataset = %q, want ext", got)
		}
		// Nothing is lost on the way through: the whole row travels in extra.
		if _, ok := hashValueByKey(event, "extra").(*object.Hash); !ok {
			t.Fatal("an event should carry its source row verbatim in extra")
		}
	}

	for _, want := range []string{
		"Creation Time",
		"Content Modification Time",
		"Metadata Modification Time",
		"Last Access Time",
		"Deletion Time",
	} {
		if !descriptions[want] {
			t.Errorf("no event described as %q", want)
		}
	}
}

// ext's dtime is the only timestamp in this tree that records a deletion. The
// is_deleted bit says a record is currently unallocated, which is a different
// claim and not an event, so it must not produce one.
func TestOnlyADeletionTimeCarriesTheDeleteAction(t *testing.T) {
	document := timelineReport().toHash("handle-1")

	payload, errObj := unwrapPair(t, EventsFrom(document, stringObj("fs_report")))
	if errObj != nil {
		t.Fatalf("events_from returned error: %s", errObj.Inspect())
	}

	deletes := 0
	for _, element := range payload.(*object.Array).Elements {
		event := element.(*object.Hash)
		action, hasAction := hashValueByKey(event, "action").(*object.String)
		isDeletion := mustHashStringValue(t, event, "ts_desc") == "Deletion Time"

		switch {
		case isDeletion:
			if !hasAction || action.Value != "delete" {
				t.Fatal("a deletion time should carry the delete action")
			}
			deletes++
		case hasAction:
			t.Fatalf("a %q event carries the action %q", mustHashStringValue(t, event, "ts_desc"), action.Value)
		}
	}

	if deletes != 1 {
		t.Fatalf("got %d delete actions, want 1", deletes)
	}
}

// plaso has a data type for an NTFS stat row and one generic type for
// everything else. Borrowing fs:stat:ntfs for an ext row would make
// Timesketch's NTFS analyzers run over it.
func TestAnNtfsRowGetsThePlasoNtfsTypeAndTheOthersTheGenericOne(t *testing.T) {
	cases := []struct {
		filesystem string
		want       string
	}{
		{"ntfs", "fs:stat:ntfs"},
		{"ext", "fs:stat"},
		{"hfs", "fs:stat"},
		{"exfat", "fs:stat"},
	}

	for _, tc := range cases {
		t.Run(tc.filesystem, func(t *testing.T) {
			report := syntheticReport(tc.filesystem)
			report.add(fsReportFile{
				Filesystem: tc.filesystem,
				Path:       "/one",
				Name:       "one",
				Modified:   "2026-01-02T00:00:00Z",
			})

			events, errObj := unwrapPair(t, EventsFrom(report.toHash("handle-1"), stringObj("fs_report")))
			if errObj != nil {
				t.Fatalf("events_from returned error: %s", errObj.Inspect())
			}

			docs, errObj := unwrapPair(t, TimesketchEvent(events))
			if errObj != nil {
				t.Fatalf("timesketch_event returned error: %s", errObj.Inspect())
			}
			rows := docs.(*object.Array)
			if len(rows.Elements) != 1 {
				t.Fatalf("got %d rows, want 1", len(rows.Elements))
			}
			if got := mustHashStringValue(t, rows.Elements[0].(*object.Hash), "data_type"); got != tc.want {
				t.Fatalf("data_type = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- against real bytes -----------------------------------------------------

// One of the six real Report bodies, run over an image this package builds
// itself: three records in the root directory, one live and two unlinked.
func TestARealFatReportListsWhatTheVolumeStillHolds(t *testing.T) {
	session := openRealFATDeletedSession(t, buildFAT16DeletedImage(t), 0)

	report, err := session.Report()
	if err != nil {
		t.Fatalf("fat report: %v", err)
	}

	if report.Filesystem != "fat" {
		t.Fatalf("filesystem = %q", report.Filesystem)
	}
	if report.FileCount < 3 {
		t.Fatalf("file_count = %d, want at least the three root records", report.FileCount)
	}
	if report.DeletedCount != 2 {
		t.Fatalf("deleted_count = %d, want the two unlinked records", report.DeletedCount)
	}
	if report.SchemaVersion == 0 || report.LibraryVersion == "" || report.Generated == "" {
		t.Fatalf("the library's own provenance did not travel: %+v", report)
	}

	// The identity is read from the real capability set rather than decided
	// here, so a FAT volume's slot addressing arrives already marked unusable
	// for a diff.
	if report.IdentityKind != fsIdentityDirSlot {
		t.Fatalf("identity_kind = %q", report.IdentityKind)
	}
	if !report.IdentityStableAnswered || report.IdentityStable {
		t.Fatalf("identity stability = %v/%v, want answered and unstable",
			report.IdentityStableAnswered, report.IdentityStable)
	}

	// FAT has no metadata-change time. Every row's field is empty, and
	// fat_capabilities is what tells that apart from a volume that never set it.
	for _, file := range report.Files {
		if file.MetadataChanged != "" {
			t.Fatalf("%q carries a metadata-change time FAT cannot record: %q", file.Path, file.MetadataChanged)
		}
		if file.DeletedAt != "" {
			t.Fatalf("%q carries a deletion time FAT cannot record: %q", file.Path, file.DeletedAt)
		}
	}

	live := fsReportFile{}
	for _, file := range report.Files {
		if strings.Contains(strings.ToUpper(file.Path), "KEEP") {
			live = file
		}
	}
	if live.Path == "" {
		t.Fatalf("the live record is not in the listing: %+v", report.Files)
	}
	if live.IsDeleted {
		t.Fatal("KEEP.TXT is linked and should not be reported as deleted")
	}
	if live.FragmentCount == 0 {
		t.Fatal("the live record should have its cluster located")
	}
	if run := live.Fragments[0]; !run.Located || run.StartOffset <= 0 {
		t.Fatalf("the live record's run is not placed in the image: %+v", run)
	}

	hash := report.toHash("handle-1")
	if !hasWarningCode(t, hash, fsReportWarnIdentityUnstable) {
		t.Fatal("a FAT report should warn that its identity does not survive reuse")
	}
	if !hasWarningCode(t, hash, fsReportWarnNotReconciled) {
		t.Fatal("nothing reconciled this listing and the document should say so")
	}
}

// A record with no timestamp produces no timeline row. Every FAT directory
// entry in this fixture is undated, and the envelope's rule is that a zero
// timestamp yields no event at all -- a supertimeline full of 1970 rows is
// worse than a shorter one.
func TestARealFatReportOfUndatedRecordsProducesNoEvents(t *testing.T) {
	session := openRealFATDeletedSession(t, buildFAT16DeletedImage(t), 0)
	report, err := session.Report()
	if err != nil {
		t.Fatalf("fat report: %v", err)
	}
	if report.FileCount == 0 {
		t.Fatal("the fixture should still have records")
	}

	events, errObj := unwrapPair(t, EventsFrom(report.toHash("handle-1"), stringObj("fs_report")))
	if errObj != nil {
		t.Fatalf("events_from returned error: %s", errObj.Inspect())
	}
	if rows := events.(*object.Array); len(rows.Elements) != 0 {
		t.Fatalf("undated records produced %d events", len(rows.Elements))
	}
}

// And the positive path over the same real bytes: one record given one write
// time produces exactly one row, in the schema the next tool reads.
func TestARealFatReportReachesTheEmitters(t *testing.T) {
	image := buildFAT16DeletedImage(t)
	// 2026-01-02 03:04:10 in the FAT encoding: the date packs year-1980, month
	// and day, and the time packs hours, minutes and two-second units.
	root := image[fatDeletedRootOffset:]
	putUint16LE(root, 22, (3<<11)|(4<<5)|5)
	putUint16LE(root, 24, (46<<9)|(1<<5)|2)

	report, err := openRealFATDeletedSession(t, image, 0).Report()
	if err != nil {
		t.Fatalf("fat report: %v", err)
	}

	events, errObj := unwrapPair(t, EventsFrom(report.toHash("handle-1"), stringObj("fs_report")))
	if errObj != nil {
		t.Fatalf("events_from returned error: %s", errObj.Inspect())
	}
	rows := events.(*object.Array)
	if len(rows.Elements) != 1 {
		t.Fatalf("got %d events, want the one dated record", len(rows.Elements))
	}

	event := rows.Elements[0].(*object.Hash)
	if got := mustHashStringValue(t, event, "dataset"); got != "fat" {
		t.Fatalf("dataset = %q, want fat", got)
	}
	if got := mustHashStringValue(t, event, "ts_desc"); got != "Content Modification Time" {
		t.Fatalf("ts_desc = %q", got)
	}
	if got := mustHashStringValue(t, event, "iso"); !strings.HasPrefix(got, "2026-01-02T03:04:10") {
		t.Fatalf("iso = %q, want the stamp written into the directory record", got)
	}

	docs, errObj := unwrapPair(t, TimesketchEvent(events))
	if errObj != nil {
		t.Fatalf("timesketch_event returned error: %s", errObj.Inspect())
	}
	row := docs.(*object.Array).Elements[0].(*object.Hash)
	if got := mustHashStringValue(t, row, "data_type"); got != "fs:stat" {
		t.Fatalf("data_type = %q, want the generic fs:stat for a non-NTFS volume", got)
	}
}
