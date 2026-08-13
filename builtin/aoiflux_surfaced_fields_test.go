package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

// These tests pin the forensic signal the aoiflux libraries produce and mutant
// used to discard. They run through the fake backends, so they assert the
// builtin-level contract (which keys appear, and that values reach the DSL)
// rather than the libraries' own parsing.

func mustHashStringArray(t *testing.T, hash *object.Hash, key string) []string {
	t.Helper()
	value := hashValueByKey(hash, key)
	if value == nil {
		t.Fatalf("key %q missing from hash", key)
	}
	arr, ok := value.(*object.Array)
	if !ok {
		t.Fatalf("key %q is not ARRAY. got=%T", key, value)
	}
	out := make([]string, 0, len(arr.Elements))
	for _, e := range arr.Elements {
		s, ok := e.(*object.String)
		if !ok {
			t.Fatalf("key %q holds a non-STRING element. got=%T", key, e)
		}
		out = append(out, s.Value)
	}
	return out
}

func TestTableSurfacesByteOffsetsWarningsAndCandidates(t *testing.T) {
	session := &fakeTableSession{
		info: tableInfo{
			TableType:      "gpt",
			BlockSize:      512,
			Offset:         1048576, // table parsed inside a container, not at 0
			PartitionCount: 1,
			Warnings:       []string{"out-of-bounds: entry past end of device (lba 999)"},
			Candidates:     []string{"gpt", "mbr"},
		},
		partitions: []tablePartition{{
			Index: 1, StartLBA: 2048, LengthLBA: 4096, EndLBA: 6143,
			TypeName: "Linux filesystem", Name: "rootfs",
			// Absolute, i.e. table offset + StartLBA*BlockSize.
			StartByte: 1048576 + 2048*512, LengthByte: 4096 * 512,
		}},
	}
	installFakeTableBackend(t, fakeTableBackend{session: session})

	openPayload, errObj := unwrapPair(t, TableOpen(stringObj("synthetic.img")))
	if errObj != nil {
		t.Fatalf("table_open returned error: %s", errObj.Inspect())
	}
	openHash := openPayload.(*object.Hash)

	if got := mustHashStringArray(t, openHash, "warnings"); len(got) != 1 || !strings.Contains(got[0], "out-of-bounds") {
		t.Errorf("warnings = %v, want the out-of-bounds warning", got)
	}
	if got := mustHashStringArray(t, openHash, "candidates"); len(got) != 2 {
		t.Errorf("candidates = %v, want two entries (ambiguous media)", got)
	}

	handle := mustHashStringValue(t, openHash, "handle")
	partPayload, errObj := unwrapPair(t, TablePartitionInfo(stringObj(handle), intObj(1)))
	if errObj != nil {
		t.Fatalf("table_partition_info returned error: %s", errObj.Inspect())
	}
	partHash := partPayload.(*object.Hash)

	// The whole point: start_byte accounts for the table's own offset, so it is
	// not start_lba * block_size.
	wantStart := int64(1048576 + 2048*512)
	if got := mustHashIntValue(t, partHash, "start_byte"); got != wantStart {
		t.Errorf("start_byte = %d, want %d", got, wantStart)
	}
	if naive := int64(2048 * 512); wantStart == naive {
		t.Fatal("test is not exercising a non-zero table offset")
	}
	if got := mustHashIntValue(t, partHash, "length_byte"); got != 4096*512 {
		t.Errorf("length_byte = %d, want %d", got, 4096*512)
	}
}

func TestVHDIMetadataSurfacesChainAndLogState(t *testing.T) {
	session := &fakeVHDISession{
		meta: vhdiMetadata{
			Format:         "VHDX",
			DiskType:       "differencing",
			IsDifferencing: true,
			// A differencing disk still opens when its parent cannot be found;
			// only reads fail. This is how a script learns that up front.
			NeedsParent:        true,
			ChainComplete:      false,
			ChainDepth:         1,
			ParentResolveError: "parent not found: base.vhdx",
			IsDirty:            true,
			HasLog:             true,
			LogReplayed:        false,
		},
	}
	installFakeVHDIBackend(t, fakeVHDIBackend{session: session})

	openPayload, errObj := unwrapPair(t, VHDIOpen(stringObj("child.vhdx")))
	if errObj != nil {
		t.Fatalf("vhdi_open returned error: %s", errObj.Inspect())
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	metaPayload, errObj := unwrapPair(t, VHDIMetadata(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("vhdi_metadata returned error: %s", errObj.Inspect())
	}
	meta := metaPayload.(*object.Hash)

	if !mustHashBoolValue(t, meta, "needs_parent") {
		t.Error("needs_parent should be true")
	}
	if mustHashBoolValue(t, meta, "chain_complete") {
		t.Error("chain_complete should be false for an unresolved parent")
	}
	if got := mustHashStringValue(t, meta, "parent_resolve_error"); got == "" {
		t.Error("parent_resolve_error should explain why the chain is broken")
	}
	if !mustHashBoolValue(t, meta, "is_dirty") {
		t.Error("is_dirty should be true when a VHDX log was not replayed")
	}
	if mustHashBoolValue(t, meta, "log_replayed") {
		t.Error("log_replayed should be false")
	}
	if got := mustHashIntValue(t, meta, "chain_depth"); got != 1 {
		t.Errorf("chain_depth = %d, want 1", got)
	}
}

func TestEWFMetadataSurfacesChunkTableIntegrity(t *testing.T) {
	session := &fakeEWFSession{
		meta: ewfMetadata{
			MajorVersion: 1,
			HasMedia:     true,
			// Size comes from the reader, not from multiplying two media fields
			// that some images do not carry.
			TotalLogicalBytes: 1 << 30,
			SectorSize:        512,
			CompressionMethod: 1,
			// Chunk tables whose primary and backup copies both failed: the data
			// they describe decoded unverified.
			ChunkTablesInvalid:    2,
			ChunkTablesRecovered:  5,
			ObservedChunkCount:    4096,
			AcquisitionErrorCount: 3,
		},
	}
	installFakeEWFBackend(t, fakeEWFBackend{session: session})

	openPayload, errObj := unwrapPair(t, EWFOpen(&object.Array{Elements: []object.Object{stringObj("image.E01")}}))
	if errObj != nil {
		t.Fatalf("ewf_open returned error: %s", errObj.Inspect())
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	metaPayload, errObj := unwrapPair(t, EWFMetadata(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("ewf_metadata returned error: %s", errObj.Inspect())
	}
	meta := metaPayload.(*object.Hash)

	if got := mustHashIntValue(t, meta, "chunk_tables_invalid"); got != 2 {
		t.Errorf("chunk_tables_invalid = %d, want 2", got)
	}
	if got := mustHashIntValue(t, meta, "chunk_tables_recovered"); got != 5 {
		t.Errorf("chunk_tables_recovered = %d, want 5", got)
	}
	if got := mustHashIntValue(t, meta, "observed_chunk_count"); got != 4096 {
		t.Errorf("observed_chunk_count = %d, want 4096", got)
	}
	if got := mustHashIntValue(t, meta, "acquisition_error_count"); got != 3 {
		t.Errorf("acquisition_error_count = %d, want 3", got)
	}
	if got := mustHashIntValue(t, meta, "total_logical_bytes"); got != 1<<30 {
		t.Errorf("total_logical_bytes = %d, want %d", got, 1<<30)
	}
	if got := mustHashIntValue(t, meta, "sector_size"); got != 512 {
		t.Errorf("sector_size = %d, want 512", got)
	}
}

func TestNTFSMetadataReportsAllFourMACTimes(t *testing.T) {
	const created = "2024-01-02T03:04:05Z"
	const modified = "2024-02-03T04:05:06Z"
	const accessed = "2024-03-04T05:06:07Z"
	const changed = "2024-04-05T06:07:08Z"

	session := &fakeNTFSSession{
		meta: map[string]ntfsMetadata{
			"/notes.txt": {
				Path: "/notes.txt", Name: "notes.txt",
				CreatedAt: created, ModifiedAt: modified, AccessedAt: accessed, ChangedAt: changed,
			},
		},
	}
	installFakeNTFSBackend(t, fakeNTFSBackend{session: session})

	openPayload, errObj := unwrapPair(t, NtfsOpen(stringObj("synthetic.img")))
	if errObj != nil {
		t.Fatalf("ntfs_open returned error: %s", errObj.Inspect())
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	metaPayload, errObj := unwrapPair(t, NtfsMetadata(stringObj(handle), stringObj("/notes.txt")))
	if errObj != nil {
		t.Fatalf("ntfs_metadata returned error: %s", errObj.Inspect())
	}
	meta := metaPayload.(*object.Hash)

	// created_at and modified_at used to be empty on every real volume: the
	// reflection helper probed field names $STANDARD_INFORMATION does not have.
	for key, want := range map[string]string{
		"created_at":  created,
		"modified_at": modified,
		"accessed_at": accessed,
		"changed_at":  changed,
	} {
		if got := mustHashStringValue(t, meta, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestXFSListFilesReportsUnreadableInodeWithoutAborting(t *testing.T) {
	session := &fakeXFSSession{
		entries: map[string][]xfsListEntry{
			"/": {
				{Name: "etc", Path: "/etc", Inode: 32, IsDirectory: true, FileType: "directory"},
				// A damaged inode used to abort the whole listing.
				{Name: "broken", Path: "/broken", Inode: 33, FileType: "regular", InodeError: "inode 33 unreadable"},
			},
		},
	}
	installFakeXFSBackend(t, fakeXFSBackend{session: session})

	openPayload, errObj := unwrapPair(t, XFSOpen(stringObj("synthetic-xfs.img")))
	if errObj != nil {
		t.Fatalf("xfs_open returned error: %s", errObj.Inspect())
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	listPayload, errObj := unwrapPair(t, XFSListFiles(stringObj(handle), stringObj("/")))
	if errObj != nil {
		t.Fatalf("xfs_list_files returned error: %s", errObj.Inspect())
	}
	entries := listPayload.(*object.Array)
	if len(entries.Elements) != 2 {
		t.Fatalf("entry count = %d, want 2 — a bad inode must not drop its sibling", len(entries.Elements))
	}

	var broken *object.Hash
	for _, e := range entries.Elements {
		h := e.(*object.Hash)
		if mustHashStringValue(t, h, "name") == "broken" {
			broken = h
		}
	}
	if broken == nil {
		t.Fatal("the entry with an unreadable inode was dropped from the listing")
	}
	if got := mustHashStringValue(t, broken, "inode_error"); got == "" {
		t.Error("inode_error should explain why this entry is incomplete")
	}
	if got := mustHashStringValue(t, broken, "file_type"); got != "regular" {
		t.Errorf("file_type = %q, want regular (from the directory record, not the inode)", got)
	}
}

func TestXFATListFilesNamesUnnamedEntriesDeterministically(t *testing.T) {
	// joinFSPath used to synthesise "entry-<UnixNano>" for a nameless entry, so
	// listing the same image twice produced different paths.
	first := joinFSPath("/dir", "")
	second := joinFSPath("/dir", "")
	if first != second {
		t.Fatalf("nameless entry path is not reproducible: %q vs %q", first, second)
	}
	if !strings.HasSuffix(first, unnamedEntryPlaceholder) {
		t.Errorf("nameless entry path = %q, want it to end in %q", first, unnamedEntryPlaceholder)
	}
}

func TestNormalizeFSPathCannotEscapeVolumeRoot(t *testing.T) {
	for _, in := range []string{"..", "../..", `\..\..`, "/../etc", ""} {
		if got := normalizeFSPath(in); !strings.HasPrefix(got, "/") || strings.HasPrefix(got, "/..") {
			t.Errorf("normalizeFSPath(%q) = %q, want an absolute path inside the volume", in, got)
		}
	}
	if got := normalizeFSPath(`\Windows\System32`); got != "/Windows/System32" {
		t.Errorf("normalizeFSPath = %q, want /Windows/System32", got)
	}
}
