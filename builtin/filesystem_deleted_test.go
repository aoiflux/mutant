package builtin

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	libfat "github.com/aoiflux/libfat"

	"mutant/object"
)

// --- the shared contract ----------------------------------------------------

// The two bits are the point of the shape, so they are pinned on their own
// rather than only through the seven builtins that carry them. An entry that
// nobody could cross-reference and one whose clusters are demonstrably still
// free must not render identically.
func TestAnUncheckedAllocationDoesNotReadAsAFreeOne(t *testing.T) {
	cases := []struct {
		name    string
		entry   fsDeletedEntry
		checked bool
		reused  bool
	}{
		{
			// NTFS. The library has no cluster-allocation query at all, so the
			// question was never put.
			"nobody looked",
			fsDeletedEntry{AllocationChecked: false, Reallocated: false},
			false, false,
		},
		{
			"looked, and the clusters are still free",
			fsDeletedEntry{AllocationChecked: true, Reallocated: false},
			true, false,
		},
		{
			"looked, and something else owns them now",
			fsDeletedEntry{AllocationChecked: true, Reallocated: true},
			true, true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash, ok := tc.entry.toHash().(*object.Hash)
			if !ok {
				t.Fatalf("an entry did not render as a HASH")
			}
			if got := mustHashBoolValue(t, hash, "allocation_checked"); got != tc.checked {
				t.Errorf("allocation_checked = %v, want %v", got, tc.checked)
			}
			if got := mustHashBoolValue(t, hash, "reallocated"); got != tc.reused {
				t.Errorf("reallocated = %v, want %v", got, tc.reused)
			}
		})
	}
}

// A library with no warnings channel reports an empty list for the same reason
// a library with a clean scan does, and the reader has to be able to tell them
// apart.
func TestAnEmptyWarningListIsNotTheSameAsHavingNowhereToPutOne(t *testing.T) {
	silent := fsDeletedScan{Filesystem: "ntfs", WarningsAvailable: false}
	clean := fsDeletedScan{Filesystem: "ext", WarningsAvailable: true}

	silentHash := silent.toHash("h")
	cleanHash := clean.toHash("h")

	if len(mustHashArrayValue(t, silentHash, "warnings")) != 0 {
		t.Fatal("a library with no warnings channel reported warnings")
	}
	if len(mustHashArrayValue(t, cleanHash, "warnings")) != 0 {
		t.Fatal("a clean scan reported warnings")
	}
	if mustHashBoolValue(t, silentHash, "warnings_available") {
		t.Error("libntfs was reported as having a warnings channel")
	}
	if !mustHashBoolValue(t, cleanHash, "warnings_available") {
		t.Error("libext was reported as having no warnings channel")
	}
}

// The cap bounds what is rendered, never what is counted: the figure an
// examiner quotes has to stay right when the list they scroll is short.
func TestTheEntryListIsCappedAndTheCountIsNot(t *testing.T) {
	scan := fsDeletedScan{Filesystem: "ntfs"}
	for i := 0; i < fsDeletedMaxEntries+37; i++ {
		scan.add(fsDeletedEntry{RecordID: int64(i)})
	}

	hash := scan.toHash("h")
	if got := mustHashIntValue(t, hash, "entry_count"); got != int64(fsDeletedMaxEntries+37) {
		t.Errorf("entry_count = %d, want %d", got, fsDeletedMaxEntries+37)
	}
	if got := len(mustHashArrayValue(t, hash, "entries")); got != fsDeletedMaxEntries {
		t.Errorf("rendered %d entries, want the cap of %d", got, fsDeletedMaxEntries)
	}
	if !mustHashBoolValue(t, hash, "entries_truncated") {
		t.Error("entries_truncated is false past the cap")
	}
}

// A scan below the cap must not claim truncation, or the flag means nothing.
func TestAShortListIsNotReportedAsTruncated(t *testing.T) {
	scan := fsDeletedScan{Filesystem: "fat"}
	scan.add(fsDeletedEntry{RecordID: 1})

	if mustHashBoolValue(t, scan.toHash("h"), "entries_truncated") {
		t.Fatal("a one-entry scan reported itself truncated")
	}
}

// The first reason is kept because it explains the earliest missing evidence;
// a later gap is often a consequence of it.
func TestTheFirstGapIsTheOneReported(t *testing.T) {
	scan := fsDeletedScan{Filesystem: "xfs", Complete: true}
	scan.incomplete("the inode table ended early")
	scan.incomplete("and then a cap was reached")

	hash := scan.toHash("h")
	if mustHashBoolValue(t, hash, "complete") {
		t.Fatal("a scan with a known gap reported itself complete")
	}
	if got := mustHashStringValue(t, hash, "incomplete_reason"); got != "the inode table ended early" {
		t.Errorf("incomplete_reason = %q, want the first one", got)
	}
}

// warning_codes is the deduped set a script branches on, and it is sorted so
// that a report of it does not reorder between runs.
func TestWarningCodesAreDedupedAndSorted(t *testing.T) {
	scan := fsDeletedScan{Filesystem: "hfs", WarningsAvailable: true}
	scan.warn("node_read", "12", "a leaf would not read")
	scan.warn("bitmap_read", "0", "the allocation file would not read")
	scan.warn("node_read", "48", "another leaf would not read")

	hash := scan.toHash("h")
	codes := mustHashStringArray(t, hash, "warning_codes")
	if len(codes) != 2 || codes[0] != "bitmap_read" || codes[1] != "node_read" {
		t.Fatalf("warning_codes = %v, want the sorted deduped pair", codes)
	}
	if got := len(mustHashArrayValue(t, hash, "warnings")); got != 3 {
		t.Errorf("warnings holds %d entries, want all 3", got)
	}
}

// A sparse run occupies file space and no image space, so it must not be
// counted as bytes that were found.
func TestASparseRunIsNotCountedAsLocatedBytes(t *testing.T) {
	runs := []fsDeletedRun{
		{FileOffset: 0, Offset: 4096, Length: 512},
		{FileOffset: 512, Offset: -1, Length: 1024, Sparse: true},
		{FileOffset: 1536, Offset: 8192, Length: 512},
	}
	if got := sumRuns(runs); got != 1024 {
		t.Fatalf("sumRuns = %d, want 1024", got)
	}
}

// --- the builtins over fakes ------------------------------------------------

type deletedCase struct {
	name    string
	install func(*testing.T, fsDeletedScan, error)
	open    func() object.Object
	scan    func(string) object.Object
}

func deletedCases() []deletedCase {
	return []deletedCase{
		{
			BuiltinNameNtfsDeleted,
			func(t *testing.T, scan fsDeletedScan, err error) {
				installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{
					deleted: scan, deletedErr: err,
				}})
			},
			func() object.Object { return NtfsOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return NtfsDeleted(stringObj(h)) },
		},
		{
			BuiltinNameFatDeleted,
			func(t *testing.T, scan fsDeletedScan, err error) {
				installFakeFATBackend(t, &fakeFATBackend{session: &fakeFATSession{
					deleted: scan, deletedErr: err,
				}})
			},
			func() object.Object { return FatOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return FatDeleted(stringObj(h)) },
		},
		{
			BuiltinNameXfatDeleted,
			func(t *testing.T, scan fsDeletedScan, err error) {
				installFakeXFATBackend(t, &fakeXFATBackend{session: &fakeXFATSession{
					deleted: scan, deletedErr: err,
				}})
			},
			func() object.Object { return XFATOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return XFATDeleted(stringObj(h)) },
		},
		{
			BuiltinNameExtDeleted,
			func(t *testing.T, scan fsDeletedScan, err error) {
				installFakeEXTBackend(t, &fakeEXTBackend{session: &fakeEXTSession{
					deleted: scan, deletedErr: err,
				}})
			},
			func() object.Object { return ExtOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return ExtDeleted(stringObj(h)) },
		},
		{
			BuiltinNameHfsDeleted,
			func(t *testing.T, scan fsDeletedScan, err error) {
				installFakeHFSBackend(t, &fakeHFSBackend{session: &fakeHFSSession{
					deleted: scan, deletedErr: err,
				}})
			},
			func() object.Object { return HFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return HFSDeleted(stringObj(h)) },
		},
		{
			BuiltinNameXfsDeleted,
			func(t *testing.T, scan fsDeletedScan, err error) {
				installFakeXFSBackend(t, &fakeXFSBackend{session: &fakeXFSSession{
					deleted: scan, deletedErr: err,
				}})
			},
			func() object.Object { return XFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return XFSDeleted(stringObj(h), stringObj("/home")) },
		},
		{
			BuiltinNameXfsUnlinked,
			func(t *testing.T, scan fsDeletedScan, err error) {
				installFakeXFSBackend(t, &fakeXFSBackend{session: &fakeXFSSession{
					unlinked: scan, unlinkedErr: err,
				}})
			},
			func() object.Object { return XFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return XFSUnlinked(stringObj(h)) },
		},
	}
}

// The return-fields conformance probe cannot reach these -- they need a live
// handle -- so the agreement between metadata and implementation is pinned
// here, exactly as the *_verify family pins its own.
func TestDeletedBuiltinsReturnTheDeclaredFields(t *testing.T) {
	for _, tc := range deletedCases() {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t, fsDeletedScan{Filesystem: "synthetic"}, nil)

			openPayload, openErr := unwrapPair(t, tc.open())
			if openErr != nil {
				t.Fatalf("open returned error: %s", openErr.Inspect())
			}
			handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

			payload, err := unwrapPair(t, tc.scan(handle))
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

// A scan that failed is an error, never a result reporting nothing deleted:
// the second would read as evidence of absence.
func TestADeletedScanThatFailedIsNotAnEmptyResult(t *testing.T) {
	for _, tc := range deletedCases() {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t, fsDeletedScan{}, errors.New("the catalog would not read"))

			openPayload, openErr := unwrapPair(t, tc.open())
			if openErr != nil {
				t.Fatalf("open returned error: %s", openErr.Inspect())
			}
			handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

			payload, err := unwrapPair(t, tc.scan(handle))
			if err == nil {
				t.Fatalf("%s returned a result for a failed scan: %s", tc.name, payload.Inspect())
			}
			if !strings.Contains(err.Message, "the catalog would not read") {
				t.Errorf("%s lost the library's message: %s", tc.name, err.Message)
			}
			if !strings.Contains(err.Message, tc.name) {
				t.Errorf("%s did not name itself in its error: %s", tc.name, err.Message)
			}
		})
	}
}

func TestEveryDeletedBuiltinChecksItsArity(t *testing.T) {
	cases := []struct {
		name string
		call func() object.Object
	}{
		{BuiltinNameNtfsDeleted, func() object.Object { return NtfsDeleted() }},
		{BuiltinNameFatDeleted, func() object.Object { return FatDeleted(stringObj("a"), stringObj("b")) }},
		{BuiltinNameXfatDeleted, func() object.Object { return XFATDeleted() }},
		{BuiltinNameExtDeleted, func() object.Object { return ExtDeleted() }},
		{BuiltinNameHfsDeleted, func() object.Object { return HFSDeleted() }},
		{BuiltinNameXfsDeleted, func() object.Object { return XFSDeleted(stringObj("a")) }},
		{BuiltinNameXfsUnlinked, func() object.Object { return XFSUnlinked() }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := unwrapPairNoFatal(tc.call()); err == nil {
				t.Fatalf("%s accepted the wrong number of arguments", tc.name)
			}
		})
	}
}

// xfs_deleted reads one directory, so the directory it was asked about has to
// reach the library. Defaulting to the root would answer a question nobody put.
func TestTheDirectoryXfsWasAskedAboutReachesTheLibrary(t *testing.T) {
	session := &fakeXFSSession{deleted: fsDeletedScan{Filesystem: "xfs"}}
	installFakeXFSBackend(t, &fakeXFSBackend{session: session})

	openPayload, openErr := unwrapPair(t, XFSOpen(stringObj("synthetic.img")))
	if openErr != nil {
		t.Fatalf("xfs_open returned error: %s", openErr.Inspect())
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	if _, err := unwrapPair(t, XFSDeleted(stringObj(handle), stringObj("/var/log"))); err != nil {
		t.Fatalf("xfs_deleted returned error: %s", err.Inspect())
	}
	if session.deletedDir != "/var/log" {
		t.Fatalf("libxfs was asked about %q, want /var/log", session.deletedDir)
	}
}

// The two XFS builtins answer different questions and must not share a path:
// one carves names out of a directory, the other reads what the filesystem
// itself recorded.
func TestTheTwoXfsQuestionsAreAskedSeparately(t *testing.T) {
	session := &fakeXFSSession{
		deleted:  fsDeletedScan{Filesystem: "xfs", Sources: []string{fsDeletedSourceCarved}},
		unlinked: fsDeletedScan{Filesystem: "xfs", Sources: []string{fsDeletedSourceUnlinkedList}},
	}
	installFakeXFSBackend(t, &fakeXFSBackend{session: session})

	openPayload, openErr := unwrapPair(t, XFSOpen(stringObj("synthetic.img")))
	if openErr != nil {
		t.Fatalf("xfs_open returned error: %s", openErr.Inspect())
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	carved, err := unwrapPair(t, XFSDeleted(stringObj(handle), stringObj("/")))
	if err != nil {
		t.Fatalf("xfs_deleted returned error: %s", err.Inspect())
	}
	asserted, err := unwrapPair(t, XFSUnlinked(stringObj(handle)))
	if err != nil {
		t.Fatalf("xfs_unlinked returned error: %s", err.Inspect())
	}

	if got := mustHashStringArray(t, carved.(*object.Hash), "sources"); len(got) != 1 || got[0] != fsDeletedSourceCarved {
		t.Errorf("xfs_deleted sources = %v", got)
	}
	if got := mustHashStringArray(t, asserted.(*object.Hash), "sources"); len(got) != 1 || got[0] != fsDeletedSourceUnlinkedList {
		t.Errorf("xfs_unlinked sources = %v", got)
	}
}

// --- a real FAT16 volume ----------------------------------------------------
//
// Five of the six libraries need an image this package cannot build by hand,
// and their integrations are covered by the fakes above plus the shared
// rendering contract. FAT is the exception, so the claims that only a real
// parse can settle -- that a deleted entry is located for exactly one cluster,
// that the reallocation bit comes from the allocation table, and that the
// offsets are image-absolute -- are settled here against libfat itself.

const (
	fatDeletedReserved   = 1
	fatDeletedFATs       = 2
	fatDeletedFATSectors = fatTestFATSectors
	fatDeletedRootSector = fatTestRootDirSector
)

// fatDeletedRootOffset is where the fixed root directory region begins.
const fatDeletedRootOffset = (fatDeletedReserved + fatDeletedFATs*fatDeletedFATSectors) * fatTestSectorSize

// fatDeletedDataOffset is where cluster 2 begins.
const fatDeletedDataOffset = fatDeletedRootOffset + fatDeletedRootSector*fatTestSectorSize

// buildFAT16DeletedImage lays out a root directory holding one live file and
// two deleted ones: the first whose cluster is still free, the second whose
// cluster the allocation table has since handed to something else.
func buildFAT16DeletedImage(t *testing.T) []byte {
	t.Helper()

	totalSectors := fatDeletedReserved + fatDeletedFATs*fatDeletedFATSectors +
		fatDeletedRootSector + fatTestClusters
	image := make([]byte, totalSectors*fatTestSectorSize)

	boot := image[:fatTestSectorSize]
	copy(boot[0:3], []byte{0xEB, 0x3C, 0x90})
	copy(boot[3:11], []byte("MUTANT  "))
	putUint16LE(boot, 11, fatTestSectorSize)
	boot[13] = 1 // one sector per cluster, so a cluster is 512 bytes
	putUint16LE(boot, 14, fatDeletedReserved)
	boot[16] = fatDeletedFATs
	putUint16LE(boot, 17, 512)
	putUint16LE(boot, 19, uint16(totalSectors))
	boot[21] = 0xF8
	putUint16LE(boot, 22, fatDeletedFATSectors)
	putUint16LE(boot, 24, 63)
	putUint16LE(boot, 26, 255)
	boot[38] = 0x29
	copy(boot[43:54], []byte("MUTANTTEST "))
	copy(boot[54:62], []byte("FAT16   "))
	putUint16LE(boot, 510, 0xAA55)

	fat := make([]byte, fatDeletedFATSectors*fatTestSectorSize)
	putUint16LE(fat, 0, 0xFFF8)
	putUint16LE(fat, 2, 0xFFFF)
	putUint16LE(fat, 4, 0xFFFF) // cluster 2: the live file, end of chain
	// Cluster 3 is left free: the first deleted file's content is still there.
	// Cluster 4 has been given to something else since.
	putUint16LE(fat, 8, 0xFFFF)

	firstFAT := fatDeletedReserved * fatTestSectorSize
	copy(image[firstFAT:], fat)
	copy(image[firstFAT+len(fat):], fat)

	root := image[fatDeletedRootOffset:]
	writeFATDirEntry(root, "KEEP    TXT", 0x20, 2, 100)
	writeFATDirEntry(root[32:], "GONE    TXT", 0x20, 3, 2048)
	root[32] = 0xE5 // unlink overwrites the first character of the name
	writeFATDirEntry(root[64:], "TAKEN   TXT", 0x20, 4, 600)
	root[64] = 0xE5

	return image
}

func openRealFATDeletedSession(t *testing.T, image []byte, base int64) *realFATSession {
	t.Helper()

	volume, err := libfat.OpenWithOptions(bytes.NewReader(image), libfat.OpenOptions{BaseOffset: base})
	if err != nil {
		t.Fatalf("libfat could not open the built image: %v", err)
	}
	return &realFATSession{volume: volume}
}

func scanEntryNamed(t *testing.T, scan fsDeletedScan, suffix string) fsDeletedEntry {
	t.Helper()

	for _, entry := range scan.Entries {
		if strings.HasSuffix(strings.ToUpper(entry.Name), suffix) {
			return entry
		}
	}
	t.Fatalf("no entry ending in %q among %d: %+v", suffix, len(scan.Entries), scan.Entries)
	return fsDeletedEntry{}
}

// Deletion frees the chain, so the only location the record itself still
// states is its first cluster. located_bytes has to report that and not the
// size the record kept claiming.
func TestARealDeletedFATEntryIsLocatedForOneClusterOnly(t *testing.T) {
	session := openRealFATDeletedSession(t, buildFAT16DeletedImage(t), 0)

	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted returned an error: %v", err)
	}
	if scan.EntryCount != 2 {
		t.Fatalf("found %d deleted entries, want 2: %+v", scan.EntryCount, scan.Entries)
	}

	gone := scanEntryNamed(t, scan, "ONE.TXT")
	if gone.ContentState != fsDeletedContentFirstOnly {
		t.Errorf("content_state = %q, want %q", gone.ContentState, fsDeletedContentFirstOnly)
	}
	if gone.Size != 2048 {
		t.Errorf("size = %d, want the 2048 the record still claims", gone.Size)
	}
	if gone.LocatedBytes != fatTestSectorSize {
		t.Errorf("located_bytes = %d, want one cluster of %d", gone.LocatedBytes, fatTestSectorSize)
	}
	if len(gone.Runs) != 1 {
		t.Fatalf("got %d runs, want 1: %+v", len(gone.Runs), gone.Runs)
	}
	if want := int64(fatDeletedDataOffset + fatTestSectorSize); gone.Runs[0].Offset != want {
		t.Errorf("run offset = %d, want cluster 3 at %d", gone.Runs[0].Offset, want)
	}

	// The name reported is not the name that was written: deletion took its
	// first character and there were no long-name slots to recover it from.
	if gone.NameSource != fsDeletedNameReconstruct {
		t.Errorf("name_source = %q, want %q", gone.NameSource, fsDeletedNameReconstruct)
	}
	if gone.IDKind != "first_cluster" || gone.RecordID != 3 {
		t.Errorf("id = %d/%q, want 3/first_cluster", gone.RecordID, gone.IDKind)
	}
	if want := int64(fatDeletedRootOffset + 32); gone.EntryOffset != want {
		t.Errorf("entry_offset = %d, want the root slot at %d", gone.EntryOffset, want)
	}
	if !scan.Complete {
		t.Errorf("a clean scan reported itself incomplete: %q", scan.IncompleteReason)
	}
	if scan.WarningsAvailable {
		t.Error("libfat was reported as having a warnings channel")
	}
}

// The reallocation bit is the difference between content that is probably
// still there and content that has certainly been written over, and it comes
// from the allocation table rather than from the record.
func TestARealDeletedFATEntryWhoseClusterWasTakenSaysSo(t *testing.T) {
	session := openRealFATDeletedSession(t, buildFAT16DeletedImage(t), 0)

	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted returned an error: %v", err)
	}

	free := scanEntryNamed(t, scan, "ONE.TXT")
	taken := scanEntryNamed(t, scan, "AKEN.TXT")

	if !free.AllocationChecked || !taken.AllocationChecked {
		t.Fatal("FAT has an allocation table, so both entries should report the check as run")
	}
	if free.Reallocated {
		t.Error("a cluster the FAT still marks free was reported as reallocated")
	}
	if !taken.Reallocated {
		t.Error("a cluster the FAT marks in use was not reported as reallocated")
	}
}

// The inheritance from opening a volume at an offset: every run a deleted
// entry reports has to be an offset into the image, not into the partition.
// The two are indistinguishable by looking at them, which is why this is
// asserted against a volume that genuinely starts part-way in.
func TestDeletedRunsAreImageAbsoluteWhenTheVolumeIsNotAtZero(t *testing.T) {
	const base = 1 << 20

	volume := buildFAT16DeletedImage(t)
	padded := make([]byte, base+len(volume))
	copy(padded[base:], volume)

	atZero, err := openRealFATDeletedSession(t, volume, 0).ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted on the bare volume returned an error: %v", err)
	}
	inImage, err := openRealFATDeletedSession(t, padded, base).ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted on the embedded volume returned an error: %v", err)
	}

	bare := scanEntryNamed(t, atZero, "ONE.TXT")
	embedded := scanEntryNamed(t, inImage, "ONE.TXT")

	if len(bare.Runs) != 1 || len(embedded.Runs) != 1 {
		t.Fatalf("expected one run each, got %d and %d", len(bare.Runs), len(embedded.Runs))
	}
	if got, want := embedded.Runs[0].Offset, bare.Runs[0].Offset+base; got != want {
		t.Errorf("embedded run offset = %d, want %d -- the base offset was lost", got, want)
	}
	if got, want := embedded.EntryOffset, bare.EntryOffset+base; got != want {
		t.Errorf("embedded entry_offset = %d, want %d -- the base offset was lost", got, want)
	}
}

// A live file is not deletion evidence and must not appear, or every listing
// this family produces overstates what was removed.
func TestARealScanLeavesTheLiveFilesOut(t *testing.T) {
	session := openRealFATDeletedSession(t, buildFAT16DeletedImage(t), 0)

	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted returned an error: %v", err)
	}
	for _, entry := range scan.Entries {
		if strings.Contains(strings.ToUpper(entry.Name), "KEEP") {
			t.Fatalf("a live file was reported as deleted: %+v", entry)
		}
	}
}

// --- the manifest's arithmetic ----------------------------------------------

// One call is one touch. The manifest's per-builtin counts are numbers an
// examiner quotes, and a builtin that records its own touch on top of the one
// its handle resolution already recorded asserts twice the work it did.
//
// fat_verify did exactly that until this was written, so both families are
// pinned here rather than only the newer one.
func TestOneCallIsOneTouch(t *testing.T) {
	path, _ := writeTestImage(t, "volume.dd", 2048)
	openTestCase(t, "IR-TOUCH", "examiner")

	installFakeFATBackend(t, &fakeFATBackend{session: &fakeFATSession{
		verify:  fsVerifyResult{Filesystem: "fat"},
		deleted: fsDeletedScan{Filesystem: "fat"},
		meta:    map[string]fatMetadata{"/keep.txt": {Path: "/keep.txt", Name: "keep.txt"}},
	}})

	openPayload, openErr := unwrapPair(t, FatOpen(stringObj(path)))
	if openErr != nil {
		t.Fatalf("fat_open failed: %s", openErr.Message)
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	if _, errObj := unwrapPair(t, FatVerify(stringObj(handle))); errObj != nil {
		t.Fatalf("fat_verify failed: %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, FatDeleted(stringObj(handle))); errObj != nil {
		t.Fatalf("fat_deleted failed: %s", errObj.Message)
	}
	// The control: a builtin that has always resolved its handle and left the
	// recording to that resolution.
	if _, errObj := unwrapPair(t, FatMetadata(stringObj(handle), stringObj("/keep.txt"))); errObj != nil {
		t.Fatalf("fat_metadata failed: %s", errObj.Message)
	}

	touches, ok := mustHashValue(t, evidenceEntries(t, currentManifest(t))[0], "touches").(*object.Array)
	if !ok {
		t.Fatal("touches is not an ARRAY")
	}
	counted := map[string]int64{}
	for _, element := range touches.Elements {
		entry := element.(*object.Hash)
		counted[mustHashStringValue(t, entry, "builtin")] = mustHashIntValue(t, entry, "count")
	}

	for _, name := range []string{BuiltinNameFatVerify, BuiltinNameFatDeleted, BuiltinNameFatMetadata} {
		if counted[name] != 1 {
			t.Errorf("%s counted %d times for one call, want 1", name, counted[name])
		}
	}
}
