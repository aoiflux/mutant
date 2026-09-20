package builtin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	libfat "github.com/aoiflux/libfat"

	"mutant/object"
)

// --- the accounting ---------------------------------------------------------

// Three different things become zeros in a recovered file and only one of them
// is the file's content. A single "bytes we could not read" number would let a
// report present a library's failure to place a run as a run of zeros the file
// contained.
func TestZerosFromAHoleAndZerosFromNowhereAreCountedApart(t *testing.T) {
	image := bytes.NewReader(bytes.Repeat([]byte{0xAA}, 8192))
	entry := fsDeletedEntry{Size: 2048, ContentState: fsDeletedContentPreserved}

	runs := []fsDeletedRun{
		{FileOffset: 0, Offset: 4096, Length: 512},
		{FileOffset: 512, Offset: -1, Length: 512, Sparse: true},
		// Neither sparse nor located: the library reported a run it could not
		// place. The file has to stay this long for the offsets after it to
		// land, so the range is written as zeros and named.
		{FileOffset: 1024, Offset: -1, Length: 512},
		{FileOffset: 1536, Offset: 6144, Length: 512},
	}

	recovery, err := recoveryFromRuns(image, entry, runs)
	if err != nil {
		t.Fatalf("recoveryFromRuns: %v", err)
	}

	if recovery.LocatedBytes != 1024 {
		t.Errorf("located_bytes = %d, want 1024", recovery.LocatedBytes)
	}
	if recovery.SparseBytes != 512 {
		t.Errorf("sparse_bytes = %d, want 512", recovery.SparseBytes)
	}
	if recovery.UnlocatedBytes != 512 {
		t.Errorf("unlocated_bytes = %d, want 512", recovery.UnlocatedBytes)
	}
	if total := recovery.LocatedBytes + recovery.SparseBytes + recovery.UnlocatedBytes; total != recovery.Length {
		t.Errorf("the three counts sum to %d and the output is %d bytes", total, recovery.Length)
	}
}

// A gap no run claims is not evidence of anything either, and it must land in
// the same column as a run that could not be placed rather than being lost.
func TestAGapNoRunClaimsIsNotCountedAsLocated(t *testing.T) {
	image := bytes.NewReader(bytes.Repeat([]byte{0xAA}, 8192))
	entry := fsDeletedEntry{Size: 1024}

	recovery, err := recoveryFromRuns(image, entry, []fsDeletedRun{
		{FileOffset: 0, Offset: 4096, Length: 256},
		{FileOffset: 768, Offset: 5120, Length: 256},
	})
	if err != nil {
		t.Fatalf("recoveryFromRuns: %v", err)
	}

	if recovery.LocatedBytes != 512 {
		t.Errorf("located_bytes = %d, want 512", recovery.LocatedBytes)
	}
	if recovery.UnlocatedBytes != 512 {
		t.Errorf("unlocated_bytes = %d, want 512 -- the gap between the runs", recovery.UnlocatedBytes)
	}
}

// -1 is this family's "nowhere". Reading the image there would either fail or,
// on an API that takes a signed offset, succeed somewhere else entirely.
func TestARunReaderNeverReadsAtAnOffsetThatMeansNowhere(t *testing.T) {
	image := bytes.NewReader(bytes.Repeat([]byte{0xFF}, 4096))
	reader := &fsRunReader{
		image: image,
		size:  16,
		runs: []fsDeletedRun{
			{FileOffset: 0, Offset: -1, Length: 8},
			{FileOffset: 8, Offset: 100, Length: 8},
		},
	}

	buffer := make([]byte, 16)
	if _, err := reader.ReadAt(buffer, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buffer[:8], make([]byte, 8)) {
		t.Errorf("an unplaceable run produced %x, want zeros", buffer[:8])
	}
	if !bytes.Equal(buffer[8:], bytes.Repeat([]byte{0xFF}, 8)) {
		t.Errorf("the located run produced %x, want 0xFF", buffer[8:])
	}
}

// Runs are cluster-aligned and the last one routinely overshoots. A file
// longer than its own surviving entry claims is a recovery nobody could
// explain, and the tail is allocation slack rather than content.
func TestTheOutputStopsAtTheRecordedSize(t *testing.T) {
	image := bytes.NewReader(bytes.Repeat([]byte{0xAA}, 8192))

	recovery, err := recoveryFromRuns(image,
		fsDeletedEntry{Size: 600},
		[]fsDeletedRun{{FileOffset: 0, Offset: 1024, Length: 1024}})
	if err != nil {
		t.Fatalf("recoveryFromRuns: %v", err)
	}
	if recovery.Length != 600 {
		t.Errorf("output length = %d, want 600", recovery.Length)
	}

	// A size of zero is a record that kept no length, not a claim that the file
	// was empty, so the runs stand.
	unsized, err := recoveryFromRuns(image,
		fsDeletedEntry{Size: 0},
		[]fsDeletedRun{{FileOffset: 0, Offset: 1024, Length: 1024}})
	if err != nil {
		t.Fatalf("recoveryFromRuns: %v", err)
	}
	if unsized.Length != 1024 {
		t.Errorf("unsized output length = %d, want 1024", unsized.Length)
	}
}

// A zero-byte file under a deleted file's name is indistinguishable from a
// recovery that worked on an empty file, and it would be attached to a report
// as one.
func TestAnEntryWithNoByteMapIsRefusedRatherThanWrittenEmpty(t *testing.T) {
	for _, state := range []string{fsDeletedContentNone, fsDeletedContentUnsupported, ""} {
		if err := recoverableState(fsDeletedEntry{ContentState: state}); err == nil {
			t.Errorf("content_state %q was accepted for recovery", state)
		}
	}
	for _, state := range []string{
		fsDeletedContentResident,
		fsDeletedContentPreserved,
		fsDeletedContentDeclared,
		fsDeletedContentFirstOnly,
	} {
		if err := recoverableState(fsDeletedEntry{ContentState: state}); err != nil {
			t.Errorf("content_state %q was refused: %v", state, err)
		}
	}
}

// --- naming an entry --------------------------------------------------------

// "You never scanned" and "that number is past the end" call for different
// fixes, and a single not-found would leave a script unable to tell a missing
// call from a stale index.
func TestARecoveryWithoutAScanSaysWhichCallIsMissing(t *testing.T) {
	var cache fsRecoveryCache

	_, err := cache.lookup(0)
	if err == nil {
		t.Fatal("a recovery before any scan was allowed")
	}
	if !strings.Contains(err.Error(), "no deleted scan has been run") {
		t.Errorf("the error does not name the missing call: %v", err)
	}

	cache.remember([]fsDeletedEntry{{Name: "one"}})
	if _, err := cache.lookup(0); err != nil {
		t.Fatalf("index 0 after a scan of one entry: %v", err)
	}
	for _, index := range []int64{-1, 1, 1 << 40} {
		if _, err := cache.lookup(index); err == nil {
			t.Errorf("index %d was accepted against a scan of one entry", index)
		}
	}
}

// A scan replaces the cache rather than adding to it, so an index always means
// a position in the most recent one.
func TestASecondScanReplacesWhatTheFirstOneLeft(t *testing.T) {
	var cache fsRecoveryCache

	cache.remember([]fsDeletedEntry{{Name: "a"}, {Name: "b"}, {Name: "c"}})
	cache.remember([]fsDeletedEntry{{Name: "only"}})

	entry, err := cache.lookup(0)
	if err != nil || entry.Name != "only" {
		t.Fatalf("lookup(0) = %+v, %v -- want the second scan's entry", entry, err)
	}
	if _, err := cache.lookup(2); err == nil {
		t.Error("an index from the first scan still resolved against the second")
	}
}

// The library's own record is kept beside the rendered entry for the families
// that need it, and the two lists are addressed by the same index. Past the
// cap they would drift apart unless add says whether it stored anything, which
// would recover the wrong file under the right name.
func TestTheEntryCapDoesNotDesynchroniseTheLibraryRecords(t *testing.T) {
	scan := fsDeletedScan{}
	var natives []int

	for i := 0; i < fsDeletedMaxEntries+5; i++ {
		if scan.add(fsDeletedEntry{RecordID: int64(i)}) {
			natives = append(natives, i)
		}
	}

	if len(scan.Entries) != fsDeletedMaxEntries {
		t.Fatalf("entries = %d, want the cap of %d", len(scan.Entries), fsDeletedMaxEntries)
	}
	if len(natives) != len(scan.Entries) {
		t.Fatalf("%d library records against %d entries", len(natives), len(scan.Entries))
	}
	if scan.EntryCount != int64(fsDeletedMaxEntries+5) {
		t.Errorf("entry_count = %d, want %d", scan.EntryCount, fsDeletedMaxEntries+5)
	}
	for i, entry := range scan.Entries {
		if natives[i] != int(entry.RecordID) {
			t.Fatalf("at index %d the library record is %d and the entry is %d",
				i, natives[i], entry.RecordID)
		}
	}
}

// The index is what a recovery is addressed by, so a scan that did not report
// it would leave the family unusable from a script.
func TestEveryScannedEntryCarriesItsIndex(t *testing.T) {
	scan := fsDeletedScan{Filesystem: "synthetic"}
	scan.add(fsDeletedEntry{Name: "first"})
	scan.add(fsDeletedEntry{Name: "second"})
	scan.add(fsDeletedEntry{Name: "third"})

	entries := mustHashArrayValue(t, scan.toHash("h"), "entries")
	for want, element := range entries {
		entry, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("entry %d is not a HASH", want)
		}
		if got := mustHashIntValue(t, entry, "index"); got != int64(want) {
			t.Errorf("the entry at position %d reports index %d", want, got)
		}
	}
}

// --- the caveats ------------------------------------------------------------

// Every caveat is derivable from the other fields, and that is the point: the
// prose an examiner has to write by hand is the prose that gets left out.
func TestCaveatsNameWhatTheRecoveryDoesNotEstablish(t *testing.T) {
	cases := []struct {
		name     string
		recovery fsRecovery
		written  int64
		phrase   string
	}{
		{
			"an assumed layout is a hypothesis",
			fsRecovery{Assumed: true, AllocationChecked: true},
			10, "hypothesis",
		},
		{
			"reallocated blocks are probably another file's",
			fsRecovery{Reallocated: true, AllocationChecked: true},
			10, "allocated to a live",
		},
		{
			"an unchecked allocation means nobody looked",
			fsRecovery{AllocationChecked: false},
			10, "nobody looked",
		},
		{
			"zeros from nowhere are not zeros the file held",
			fsRecovery{AllocationChecked: true, UnlocatedBytes: 512},
			10, "not evidence that the file held zeros",
		},
		{
			"zeros from a hole are the file's own content",
			fsRecovery{AllocationChecked: true, SparseBytes: 512},
			10, "the file's own content",
		},
		{
			"a short write against the recorded size",
			fsRecovery{AllocationChecked: true, Entry: fsDeletedEntry{Size: 2048}},
			512, "512 were written",
		},
		{
			"a directory is not file content",
			fsRecovery{AllocationChecked: true, Entry: fsDeletedEntry{IsDirectory: true}},
			10, "directory records",
		},
		{
			"a synthetic name is not the name as written",
			fsRecovery{AllocationChecked: true, Entry: fsDeletedEntry{NameSource: fsDeletedNameSynthetic}},
			10, "not the name as the filesystem wrote it",
		},
		{
			"only the first cluster was ever known",
			fsRecovery{AllocationChecked: true, ContentState: fsDeletedContentFirstOnly},
			10, "freed the chain",
		},
		{
			"a declared layout is a record, not a guess",
			fsRecovery{AllocationChecked: true, ContentState: fsDeletedContentDeclared},
			10, "record rather than a",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			joined := strings.Join(recoveryCaveats(tc.recovery, tc.written), " | ")
			if !strings.Contains(joined, tc.phrase) {
				t.Errorf("no caveat mentions %q; got: %s", tc.phrase, joined)
			}
		})
	}
}

// A recovery that found everything it was looking for still carries the
// caveats that are true of it, and none that are not.
func TestACleanRecoveryDoesNotInventCaveats(t *testing.T) {
	clean := fsRecovery{
		AllocationChecked: true,
		ContentState:      fsDeletedContentPreserved,
		Entry:             fsDeletedEntry{Size: 512, NameSource: fsDeletedNameIntact},
	}
	if got := recoveryCaveats(clean, 512); len(got) != 0 {
		t.Errorf("a complete, checked, intact recovery produced caveats: %v", got)
	}
}

// --- writing the output -----------------------------------------------------

// Two deleted entries in one image can carry the same name, and evidence
// written over by accident is not recoverable.
func TestAnExistingDestinationIsNeverOverwritten(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "recovered.bin")
	if err := os.WriteFile(dest, []byte("the evidence already here"), 0o600); err != nil {
		t.Fatalf("seeding the destination: %v", err)
	}

	_, _, errObj := fsWriteEvidenceFile("test_recover", dest, bytes.NewReader([]byte("new")))
	if errObj == nil {
		t.Fatal("an existing destination was written over")
	}

	kept, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading the destination back: %v", err)
	}
	if string(kept) != "the evidence already here" {
		t.Errorf("the destination now holds %q", kept)
	}
}

// --- the builtins over fakes ------------------------------------------------

type recoverCase struct {
	name     string
	install  func(*testing.T, fsRecovery, error)
	open     func() object.Object
	recover  func(handle, dest string) object.Object
	asked    func() (int64, bool)
	assuming bool
}

func recoverCases(t *testing.T) []recoverCase {
	t.Helper()

	ntfs := &fakeNTFSSession{}
	fat := &fakeFATSession{}
	xfat := &fakeXFATSession{}
	ext := &fakeEXTSession{}
	hfs := &fakeHFSSession{}
	xfs := &fakeXFSSession{}

	return []recoverCase{
		{
			BuiltinNameNtfsRecoverFile,
			func(t *testing.T, r fsRecovery, err error) {
				ntfs.recovery, ntfs.recoveryErr = r, err
				installFakeNTFSBackend(t, &fakeNTFSBackend{session: ntfs})
			},
			func() object.Object { return NtfsOpen(stringObj("synthetic.img")) },
			func(h, d string) object.Object {
				return NtfsRecoverFile(stringObj(h), intObj(3), stringObj(d))
			},
			func() (int64, bool) { return ntfs.recoveryIndex, ntfs.recoveryAssumed },
			false,
		},
		{
			BuiltinNameFatRecoverFile,
			func(t *testing.T, r fsRecovery, err error) {
				fat.recovery, fat.recoveryErr = r, err
				installFakeFATBackend(t, &fakeFATBackend{session: fat})
			},
			func() object.Object { return FatOpen(stringObj("synthetic.img")) },
			func(h, d string) object.Object {
				return FatRecoverFile(stringObj(h), intObj(3), stringObj(d))
			},
			func() (int64, bool) { return fat.recoveryIndex, fat.recoveryAssumed },
			false,
		},
		{
			BuiltinNameFatRecoverContiguous,
			func(t *testing.T, r fsRecovery, err error) {
				fat.recovery, fat.recoveryErr = r, err
				installFakeFATBackend(t, &fakeFATBackend{session: fat})
			},
			func() object.Object { return FatOpen(stringObj("synthetic.img")) },
			func(h, d string) object.Object {
				return FatRecoverFileAssumingContiguous(stringObj(h), intObj(3), stringObj(d))
			},
			func() (int64, bool) { return fat.recoveryIndex, fat.recoveryAssumed },
			true,
		},
		{
			BuiltinNameXfatRecoverFile,
			func(t *testing.T, r fsRecovery, err error) {
				xfat.recovery, xfat.recoveryErr = r, err
				installFakeXFATBackend(t, &fakeXFATBackend{session: xfat})
			},
			func() object.Object { return XFATOpen(stringObj("synthetic.img")) },
			func(h, d string) object.Object {
				return XFATRecoverFile(stringObj(h), intObj(3), stringObj(d))
			},
			func() (int64, bool) { return xfat.recoveryIndex, xfat.recoveryAssumed },
			false,
		},
		{
			BuiltinNameXfatRecoverContiguous,
			func(t *testing.T, r fsRecovery, err error) {
				xfat.recovery, xfat.recoveryErr = r, err
				installFakeXFATBackend(t, &fakeXFATBackend{session: xfat})
			},
			func() object.Object { return XFATOpen(stringObj("synthetic.img")) },
			func(h, d string) object.Object {
				return XFATRecoverFileAssumingContiguous(stringObj(h), intObj(3), stringObj(d))
			},
			func() (int64, bool) { return xfat.recoveryIndex, xfat.recoveryAssumed },
			true,
		},
		{
			BuiltinNameExtRecoverFile,
			func(t *testing.T, r fsRecovery, err error) {
				ext.recovery, ext.recoveryErr = r, err
				installFakeEXTBackend(t, &fakeEXTBackend{session: ext})
			},
			func() object.Object { return ExtOpen(stringObj("synthetic.img")) },
			func(h, d string) object.Object {
				return ExtRecoverFile(stringObj(h), intObj(3), stringObj(d))
			},
			func() (int64, bool) { return ext.recoveryIndex, ext.recoveryAssumed },
			false,
		},
		{
			BuiltinNameHfsRecoverFile,
			func(t *testing.T, r fsRecovery, err error) {
				hfs.recovery, hfs.recoveryErr = r, err
				installFakeHFSBackend(t, &fakeHFSBackend{session: hfs})
			},
			func() object.Object { return HFSOpen(stringObj("synthetic.img")) },
			func(h, d string) object.Object {
				return HFSRecoverFile(stringObj(h), intObj(3), stringObj(d))
			},
			func() (int64, bool) { return hfs.recoveryIndex, hfs.recoveryAssumed },
			false,
		},
		{
			BuiltinNameXfsRecoverFile,
			func(t *testing.T, r fsRecovery, err error) {
				xfs.recovery, xfs.recoveryErr = r, err
				installFakeXFSBackend(t, &fakeXFSBackend{session: xfs})
			},
			func() object.Object { return XFSOpen(stringObj("synthetic.img")) },
			func(h, d string) object.Object {
				return XFSRecoverFile(stringObj(h), intObj(3), stringObj(d))
			},
			func() (int64, bool) { return xfs.recoveryIndex, xfs.recoveryAssumed },
			false,
		},
	}
}

// A recovery that produced something the caller can hold.
func syntheticRecovery(payload []byte) fsRecovery {
	return fsRecovery{
		Entry: fsDeletedEntry{
			Name:         "GONE.TXT",
			Path:         "/GONE.TXT",
			NameSource:   fsDeletedNameIntact,
			Size:         int64(len(payload)),
			RecordID:     7,
			IDKind:       "first_cluster",
			ContentState: fsDeletedContentPreserved,
			Confidence:   "likely",
		},
		Content:           bytes.NewReader(payload),
		Length:            int64(len(payload)),
		Runs:              []fsDeletedRun{{FileOffset: 0, Offset: 4096, Length: int64(len(payload))}},
		ContentState:      fsDeletedContentPreserved,
		AllocationChecked: true,
		LocatedBytes:      int64(len(payload)),
	}
}

// The return-fields conformance probe cannot reach these -- they need a live
// handle and a destination -- so the agreement between metadata and
// implementation is pinned here, as the *_deleted family pins its own.
func TestRecoverBuiltinsReturnTheDeclaredFields(t *testing.T) {
	for _, tc := range recoverCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t, syntheticRecovery([]byte("recovered content")), nil)

			openPayload, openErr := unwrapPair(t, tc.open())
			if openErr != nil {
				t.Fatalf("open returned error: %s", openErr.Inspect())
			}
			handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

			dest := filepath.Join(t.TempDir(), "out.bin")
			payload, err := unwrapPair(t, tc.recover(handle, dest))
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
			if mustHashStringValue(t, hash, "dest") != dest {
				t.Errorf("%s did not echo its destination", tc.name)
			}
		})
	}
}

// Which entry was asked for, and whether the contiguity hypothesis travelled
// with the request, are both the builtin's responsibility and neither is
// visible in the result it returns.
func TestTheIndexAndTheHypothesisReachTheLibrary(t *testing.T) {
	for _, tc := range recoverCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t, syntheticRecovery([]byte("x")), nil)

			openPayload, openErr := unwrapPair(t, tc.open())
			if openErr != nil {
				t.Fatalf("open returned error: %s", openErr.Inspect())
			}
			handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

			dest := filepath.Join(t.TempDir(), "out.bin")
			if _, err := unwrapPair(t, tc.recover(handle, dest)); err != nil {
				t.Fatalf("%s returned error: %s", tc.name, err.Inspect())
			}

			index, assuming := tc.asked()
			if index != 3 {
				t.Errorf("%s asked for index %d, want 3", tc.name, index)
			}
			if assuming != tc.assuming {
				t.Errorf("%s passed assumeContiguous=%v, want %v", tc.name, assuming, tc.assuming)
			}
		})
	}
}

// A failed recovery is an error and no file. An empty file left behind under a
// deleted file's name reads as a recovery that found nothing to recover.
func TestARecoveryThatFailedLeavesNoFileBehind(t *testing.T) {
	for _, tc := range recoverCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t, fsRecovery{}, errors.New("the record could not be read"))

			openPayload, openErr := unwrapPair(t, tc.open())
			if openErr != nil {
				t.Fatalf("open returned error: %s", openErr.Inspect())
			}
			handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

			dest := filepath.Join(t.TempDir(), "out.bin")
			payload, err := unwrapPair(t, tc.recover(handle, dest))
			if err == nil {
				t.Fatalf("%s reported success on a failed recovery: %s", tc.name, payload.Inspect())
			}
			if !strings.Contains(err.Message, "could not be read") {
				t.Errorf("%s dropped the library's reason: %s", tc.name, err.Message)
			}
			if _, statErr := os.Stat(dest); statErr == nil {
				t.Errorf("%s wrote a file for a recovery that failed", tc.name)
			}
		})
	}
}

func TestEveryRecoverBuiltinChecksItsArity(t *testing.T) {
	builtins := map[string]func(...object.Object) object.Object{
		BuiltinNameNtfsRecoverFile:       NtfsRecoverFile,
		BuiltinNameFatRecoverFile:        FatRecoverFile,
		BuiltinNameFatRecoverContiguous:  FatRecoverFileAssumingContiguous,
		BuiltinNameXfatRecoverFile:       XFATRecoverFile,
		BuiltinNameXfatRecoverContiguous: XFATRecoverFileAssumingContiguous,
		BuiltinNameExtRecoverFile:        ExtRecoverFile,
		BuiltinNameHfsRecoverFile:        HFSRecoverFile,
		BuiltinNameXfsRecoverFile:        XFSRecoverFile,
	}

	for name, fn := range builtins {
		t.Run(name, func(t *testing.T) {
			for _, args := range [][]object.Object{
				{},
				{stringObj("h")},
				{stringObj("h"), intObj(0)},
				{stringObj("h"), intObj(0), stringObj("dest"), stringObj("extra")},
			} {
				_, err := unwrapPair(t, fn(args...))
				if err == nil {
					t.Errorf("%s accepted %d arguments", name, len(args))
				}
			}
		})
	}
}

// --- a real FAT16 volume ----------------------------------------------------

// fatRecoverClusterOffset is where a cluster's bytes begin in the built image.
func fatRecoverClusterOffset(cluster int) int {
	return fatDeletedDataOffset + (cluster-2)*fatTestSectorSize
}

// buildFAT16RecoverableImage is the deleted-scan image with distinguishable
// bytes in the clusters the deleted entries point at, so that what a recovery
// wrote can be told from what it should have written.
//
// GONE.TXT records 2048 bytes from cluster 3, which is four clusters at this
// geometry. Only the first of them is anywhere in the entry; clusters 4 to 6
// are what the contiguity hypothesis reaches for, and cluster 4 has since been
// handed to something else.
func buildFAT16RecoverableImage(t *testing.T) []byte {
	t.Helper()

	image := buildFAT16DeletedImage(t)
	for cluster, fill := range map[int]byte{3: 'A', 4: 'B', 5: 'C', 6: 'D'} {
		at := fatRecoverClusterOffset(cluster)
		copy(image[at:at+fatTestSectorSize], bytes.Repeat([]byte{fill}, fatTestSectorSize))
	}
	return image
}

func digestOf(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// The chain is gone, so a plain recovery writes the one cluster the record
// still names and says that is what it did.
func TestARealFATRecoveryWritesTheFirstClusterAndSaysSo(t *testing.T) {
	image := buildFAT16RecoverableImage(t)
	session := openRealFATDeletedSession(t, image, 0)

	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted: %v", err)
	}
	index := indexOfScannedEntry(t, scan, "ONE.TXT")

	recovery, err := session.RecoverDeleted(index, false)
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}

	if recovery.Length != fatTestSectorSize {
		t.Errorf("recovered %d bytes, want one cluster of %d", recovery.Length, fatTestSectorSize)
	}
	if recovery.ContentState != fsDeletedContentFirstOnly {
		t.Errorf("content_state = %q, want %q", recovery.ContentState, fsDeletedContentFirstOnly)
	}
	if recovery.Assumed {
		t.Error("a recovery that was not asked to assume anything reported assumed")
	}
	if recovery.Reallocated {
		t.Error("the entry's first cluster is free in the FAT but reallocated is true")
	}

	written := mustReadRecovery(t, recovery)
	if want := bytes.Repeat([]byte{'A'}, fatTestSectorSize); !bytes.Equal(written, want) {
		t.Errorf("the recovered bytes are not cluster 3's: %q...", written[:16])
	}
}

// The library's own Assumed flag is what gets reported, not the fact that the
// assuming builtin was the one called.
func TestTheContiguityHypothesisIsReportedAsTheLibrarySawIt(t *testing.T) {
	image := buildFAT16RecoverableImage(t)
	session := openRealFATDeletedSession(t, image, 0)

	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted: %v", err)
	}
	index := indexOfScannedEntry(t, scan, "ONE.TXT")

	recovery, err := session.RecoverDeleted(index, true)
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}

	if !recovery.Assumed {
		t.Fatal("libfat synthesised the runs and the recovery did not say so")
	}
	if recovery.ContentState != fsRecoveredContentAssumed {
		t.Errorf("content_state = %q, want %q", recovery.ContentState, fsRecoveredContentAssumed)
	}
	if recovery.Length != 2048 {
		t.Errorf("recovered %d bytes, want the recorded 2048", recovery.Length)
	}

	written := mustReadRecovery(t, recovery)
	want := bytes.Join([][]byte{
		bytes.Repeat([]byte{'A'}, fatTestSectorSize),
		bytes.Repeat([]byte{'B'}, fatTestSectorSize),
		bytes.Repeat([]byte{'C'}, fatTestSectorSize),
		bytes.Repeat([]byte{'D'}, fatTestSectorSize),
	}, nil)
	if !bytes.Equal(written, want) {
		t.Errorf("the assumed recovery did not read clusters 3 to 6 in order")
	}

	joined := strings.Join(recoveryCaveats(recovery, recovery.Length), " | ")
	if !strings.Contains(joined, "hypothesis") {
		t.Errorf("an assumed recovery carried no hypothesis caveat: %s", joined)
	}
}

// libfat cross-references the first cluster against the allocation table, so
// this is the one filesystem here where "somebody else owns these bytes now"
// is a reading rather than a silence.
func TestARecoveryOfAReallocatedEntrySaysTheBytesAreProbablyNotItsOwn(t *testing.T) {
	image := buildFAT16RecoverableImage(t)
	session := openRealFATDeletedSession(t, image, 0)

	scan, err := session.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted: %v", err)
	}
	index := indexOfScannedEntry(t, scan, "AKEN.TXT")

	recovery, err := session.RecoverDeleted(index, false)
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	if !recovery.Reallocated {
		t.Fatal("the entry's first cluster is marked in use and reallocated is false")
	}
	if !recovery.AllocationChecked {
		t.Error("libfat read the allocation table and allocation_checked is false")
	}

	joined := strings.Join(recoveryCaveats(recovery, recovery.Length), " | ")
	if !strings.Contains(joined, "allocated to a live") {
		t.Errorf("a reallocated recovery carried no caveat about it: %s", joined)
	}
}

// The runs a recovery reports are the same claim as the runs the scan showed,
// in the same coordinate system, whatever the volume is sitting inside.
func TestRecoveredRunsStayImageAbsoluteAtABaseOffset(t *testing.T) {
	const base = 1 << 20

	image := buildFAT16RecoverableImage(t)
	embedded := append(make([]byte, base), image...)

	bare := openRealFATDeletedSession(t, image, 0)
	shifted := openRealFATDeletedSession(t, embedded, base)

	bareScan, err := bare.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted: %v", err)
	}
	shiftedScan, err := shifted.ScanDeleted()
	if err != nil {
		t.Fatalf("ScanDeleted at a base offset: %v", err)
	}

	bareRecovery, err := bare.RecoverDeleted(indexOfScannedEntry(t, bareScan, "ONE.TXT"), false)
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	shiftedRecovery, err := shifted.RecoverDeleted(indexOfScannedEntry(t, shiftedScan, "ONE.TXT"), false)
	if err != nil {
		t.Fatalf("RecoverDeleted at a base offset: %v", err)
	}

	if len(bareRecovery.Runs) != 1 || len(shiftedRecovery.Runs) != 1 {
		t.Fatalf("expected one run each, got %d and %d",
			len(bareRecovery.Runs), len(shiftedRecovery.Runs))
	}
	if got, want := shiftedRecovery.Runs[0].Offset, bareRecovery.Runs[0].Offset+base; got != want {
		t.Errorf("the run offset is %d, want %d -- the base offset was lost", got, want)
	}

	// And the bytes those offsets locate are still the file's.
	if !bytes.Equal(mustReadRecovery(t, bareRecovery), mustReadRecovery(t, shiftedRecovery)) {
		t.Error("the same entry recovered different bytes at a base offset")
	}
}

// Recovering before scanning is refused rather than scanning implicitly: the
// enumeration is where an entry's provenance is established, and an implicit
// one would leave the manifest with no record of it.
func TestRecoveringWithoutScanningFirstIsRefused(t *testing.T) {
	session := openRealFATDeletedSession(t, buildFAT16RecoverableImage(t), 0)

	if _, err := session.RecoverDeleted(0, false); err == nil {
		t.Fatal("a recovery ran without a scan having enumerated anything")
	} else if !strings.Contains(err.Error(), "fat_deleted") &&
		!strings.Contains(err.Error(), "*_deleted") {
		t.Errorf("the error does not say which call is missing: %v", err)
	}
}

// --- the manifest's arithmetic ----------------------------------------------

// One call is one touch, for the recovery half as for the rest.
func TestOneRecoveryIsOneTouch(t *testing.T) {
	path, _ := writeTestImage(t, "volume.dd", 2048)
	openTestCase(t, "IR-RECOVER", "examiner")

	session := &fakeFATSession{
		deleted:  fsDeletedScan{Filesystem: "fat"},
		recovery: syntheticRecovery([]byte("recovered")),
	}
	installFakeFATBackend(t, &fakeFATBackend{session: session})

	openPayload, openErr := unwrapPair(t, FatOpen(stringObj(path)))
	if openErr != nil {
		t.Fatalf("fat_open failed: %s", openErr.Message)
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	if _, errObj := unwrapPair(t, FatDeleted(stringObj(handle))); errObj != nil {
		t.Fatalf("fat_deleted failed: %s", errObj.Message)
	}
	dest := filepath.Join(t.TempDir(), "out.bin")
	if _, errObj := unwrapPair(t, FatRecoverFile(stringObj(handle), intObj(0), stringObj(dest))); errObj != nil {
		t.Fatalf("fat_recover_file failed: %s", errObj.Message)
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

	for _, name := range []string{BuiltinNameFatDeleted, BuiltinNameFatRecoverFile} {
		if counted[name] != 1 {
			t.Errorf("%s counted %d times for one call, want 1", name, counted[name])
		}
	}
}

// --- helpers ----------------------------------------------------------------

func indexOfScannedEntry(t *testing.T, scan fsDeletedScan, suffix string) int64 {
	t.Helper()

	for i, entry := range scan.Entries {
		if strings.HasSuffix(strings.ToUpper(entry.Name), suffix) {
			return int64(i)
		}
	}
	t.Fatalf("no entry ending in %q among %d", suffix, len(scan.Entries))
	return -1
}

func mustReadRecovery(t *testing.T, recovery fsRecovery) []byte {
	t.Helper()

	buffer := make([]byte, recovery.Length)
	if _, err := recovery.Content.ReadAt(buffer, 0); err != nil {
		t.Fatalf("reading the recovered content: %v", err)
	}
	return buffer
}

// A guard against the test image drifting out from under the arithmetic above.
func TestTheBuiltImageMatchesWhatTheRecoveryTestsAssume(t *testing.T) {
	image := buildFAT16RecoverableImage(t)

	if got := image[fatRecoverClusterOffset(3)]; got != 'A' {
		t.Errorf("cluster 3 begins with %q, want 'A'", got)
	}
	if _, err := libfat.OpenWithOptions(bytes.NewReader(image), libfat.OpenOptions{}); err != nil {
		t.Fatalf("libfat rejected the image the recovery tests use: %v", err)
	}
}
