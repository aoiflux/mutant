package builtin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	libewf "github.com/aoiflux/libewf"

	"mutant/object"
)

type fakeVHDIBackend struct {
	session vhdiSession
	err     error
}

func (f fakeVHDIBackend) Open(imagePath string) (vhdiSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeVHDISession struct {
	data   map[int64][]byte
	meta   vhdiMetadata
	mapped map[int64]struct {
		fileOffset int64
		ok         bool
	}
}

type fakeEWFBackend struct {
	session ewfSession
	err     error
	// discovered, when set, is what Discover expands the path into, so a test
	// can exercise segment discovery without any file existing on disk. Left
	// nil, discovery returns the path unchanged, which is what a lone segment
	// really does discover to.
	discovered  []string
	discoverSet *ewfSegmentSet
	discoverErr error
	// discoverCalls records the paths Discover was asked about, so a test can
	// assert that an explicit segment list is *not* expanded.
	discoverCalls *[]string
	// openOpts records the evidentiary decisions each Open was made under, so
	// a test can assert the policy the caller named is the policy libewf would
	// have been given.
	openOpts *[]ewfOpenOptions
}

func (f fakeEWFBackend) Discover(segmentPath string) (ewfSegmentSet, error) {
	if f.discoverCalls != nil {
		*f.discoverCalls = append(*f.discoverCalls, segmentPath)
	}
	if f.discoverErr != nil {
		return ewfSegmentSet{}, f.discoverErr
	}
	if f.discoverSet != nil {
		return *f.discoverSet, nil
	}
	paths := f.discovered
	if paths == nil {
		paths = []string{segmentPath}
	}
	return ewfSegmentSet{Paths: paths, Contiguous: true, PresentCount: len(paths)}, nil
}

func (f fakeEWFBackend) Open(segmentPaths []string, opts ewfOpenOptions) (ewfSession, error) {
	if f.openOpts != nil {
		*f.openOpts = append(*f.openOpts, opts)
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeEWFSession struct {
	data      map[int64][]byte
	meta      ewfMetadata
	verify    ewfVerifyResult
	verifyErr error
}

type fakeRAWBackend struct {
	session rawSession
	err     error
}

func (f fakeRAWBackend) Open(imagePath string) (rawSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeRAWSession struct {
	data map[int64][]byte
	meta rawMetadata
}

func (f *fakeRAWSession) ReadAt(offset int64, length int64) ([]byte, error) {
	if b, ok := f.data[offset]; ok {
		if int64(len(b)) > length {
			return b[:length], nil
		}
		return b, nil
	}
	return nil, errors.New("offset not found")
}

func (f *fakeRAWSession) Metadata() (rawMetadata, error) {
	return f.meta, nil
}

func (f *fakeRAWSession) Close() error { return nil }

func (f *fakeEWFSession) ReadAt(offset int64, length int64) ([]byte, error) {
	if b, ok := f.data[offset]; ok {
		if int64(len(b)) > length {
			return b[:length], nil
		}
		return b, nil
	}
	return nil, errors.New("offset not found")
}

func (f *fakeEWFSession) Metadata() (ewfMetadata, error) {
	return f.meta, nil
}

func (f *fakeEWFSession) Verify(ctx context.Context) (ewfVerifyResult, error) {
	if f.verifyErr != nil {
		return ewfVerifyResult{}, f.verifyErr
	}
	return f.verify, nil
}

func (f *fakeEWFSession) Close() error { return nil }

type trackingEWFBackend struct {
	session    ewfSession
	opened     [][]string
	openOpts   []ewfOpenOptions
	openErr    error
	discovered []string
}

func (b *trackingEWFBackend) Discover(segmentPath string) (ewfSegmentSet, error) {
	paths := b.discovered
	if paths == nil {
		paths = []string{segmentPath}
	}
	return ewfSegmentSet{Paths: paths, Contiguous: true, PresentCount: len(paths)}, nil
}

func (b *trackingEWFBackend) Open(segmentPaths []string, opts ewfOpenOptions) (ewfSession, error) {
	b.openOpts = append(b.openOpts, opts)
	if b.openErr != nil {
		return nil, b.openErr
	}
	cloned := append([]string(nil), segmentPaths...)
	b.opened = append(b.opened, cloned)
	return b.session, nil
}

func (f *fakeVHDISession) ReadAt(offset int64, length int64) ([]byte, error) {
	if b, ok := f.data[offset]; ok {
		if int64(len(b)) > length {
			return b[:length], nil
		}
		return b, nil
	}
	return nil, errors.New("offset not found")
}

func (f *fakeVHDISession) Metadata() (vhdiMetadata, error) {
	return f.meta, nil
}

func (f *fakeVHDISession) MapOffset(virtualOffset int64) (int64, bool, error) {
	if v, ok := f.mapped[virtualOffset]; ok {
		return v.fileOffset, v.ok, nil
	}
	return 0, false, errors.New("map failed")
}

func (f *fakeVHDISession) Close() error { return nil }

func installFakeVHDIBackend(t *testing.T, backend vhdiBackend) {
	t.Helper()

	vhdiStore.Lock()
	prevBackend := vhdiStore.backend
	prevHandles := vhdiStore.handles
	prevNextID := vhdiStore.nextID
	vhdiStore.backend = backend
	vhdiStore.handles = map[string]vhdiHandleState{}
	vhdiStore.nextID = 0
	vhdiStore.Unlock()

	t.Cleanup(func() {
		vhdiStore.Lock()
		for _, state := range vhdiStore.handles {
			_ = state.Session.Close()
		}
		vhdiStore.backend = prevBackend
		vhdiStore.handles = prevHandles
		vhdiStore.nextID = prevNextID
		vhdiStore.Unlock()
	})
}

func installFakeEWFBackend(t *testing.T, backend ewfBackend) {
	t.Helper()

	ewfStore.Lock()
	prevBackend := ewfStore.backend
	prevHandles := ewfStore.handles
	prevNextID := ewfStore.nextID
	ewfStore.backend = backend
	ewfStore.handles = map[string]ewfHandleState{}
	ewfStore.nextID = 0
	ewfStore.Unlock()

	t.Cleanup(func() {
		ewfStore.Lock()
		for _, state := range ewfStore.handles {
			_ = state.Session.Close()
		}
		ewfStore.backend = prevBackend
		ewfStore.handles = prevHandles
		ewfStore.nextID = prevNextID
		ewfStore.Unlock()
	})
}

func installFakeRAWBackend(t *testing.T, backend rawBackend) {
	t.Helper()

	rawStore.Lock()
	prevBackend := rawStore.backend
	prevHandles := rawStore.handles
	prevNextID := rawStore.nextID
	rawStore.backend = backend
	rawStore.handles = map[string]rawHandleState{}
	rawStore.nextID = 0
	rawStore.Unlock()

	t.Cleanup(func() {
		rawStore.Lock()
		for _, state := range rawStore.handles {
			_ = state.Session.Close()
		}
		rawStore.backend = prevBackend
		rawStore.handles = prevHandles
		rawStore.nextID = prevNextID
		rawStore.Unlock()
	})
}

func TestVHDIBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeVHDISession{
		data: map[int64][]byte{
			0: []byte("MZ...."),
		},
		meta: vhdiMetadata{
			Format:           "VHDX",
			DiskType:         "dynamic",
			VirtualSize:      1 << 30,
			BlockSize:        1 << 20,
			SectorSize:       512,
			Identifier:       "11111111-2222-3333-4444-555555555555",
			IsDifferencing:   true,
			ParentFilename:   "base.vhdx",
			ParentIdentifier: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		},
		mapped: map[int64]struct {
			fileOffset int64
			ok         bool
		}{
			0: {fileOffset: 65536, ok: true},
		},
	}
	installFakeVHDIBackend(t, fakeVHDIBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, VHDIOpen(stringObj("synthetic.vhdx")))
	if openErr != nil {
		t.Fatalf("vhdi_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("vhdi_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "vhdi-handle-") {
		t.Fatalf("unexpected vhdi handle format: %s", handle)
	}

	metaPayload, metaErr := unwrapPair(t, VHDIMetadata(stringObj(handle)))
	if metaErr != nil {
		t.Fatalf("vhdi_metadata returned error: %s", metaErr.Inspect())
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("vhdi_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashStringValue(t, metaHash, "format") != "VHDX" {
		t.Fatalf("unexpected format")
	}
	if mustHashStringValue(t, metaHash, "disk_type") != "dynamic" {
		t.Fatalf("unexpected disk type")
	}

	readPayload, readErr := unwrapPair(t, VHDIReadAt(stringObj(handle), intObj(0), intObj(6)))
	if readErr != nil {
		t.Fatalf("vhdi_read_at returned error: %s", readErr.Inspect())
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("vhdi_read_at payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "MZ...." {
		t.Fatalf("unexpected vhdi_read_at payload. got=%q", readString.Value)
	}

	mapPayload, mapErr := unwrapPair(t, VHDIMapOffset(stringObj(handle), intObj(0)))
	if mapErr != nil {
		t.Fatalf("vhdi_map_offset returned error: %s", mapErr.Inspect())
	}
	mapHash, ok := mapPayload.(*object.Hash)
	if !ok {
		t.Fatalf("vhdi_map_offset payload is not HASH. got=%T", mapPayload)
	}
	if mustHashIntValue(t, mapHash, "file_offset") != 65536 {
		t.Fatalf("unexpected file_offset")
	}
}

func TestVHDIBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeVHDIBackend(t, fakeVHDIBackend{err: errors.New("vhdi backend failed")})

	_, errObj := unwrapPair(t, VHDIOpen(stringObj("broken.vhdx")))
	if errObj == nil || !strings.Contains(errObj.Message, "vhdi_open") {
		t.Fatalf("expected vhdi_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, VHDIMetadata(stringObj("missing")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown vhdi handle") {
		t.Fatalf("expected unknown vhdi handle error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, VHDIReadAt(stringObj("missing"), intObj(-1), intObj(4)))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown vhdi handle") {
		t.Fatalf("expected unknown vhdi handle error, got: %v", errObj)
	}

	fakeSession := &fakeVHDISession{data: map[int64][]byte{}, mapped: map[int64]struct {
		fileOffset int64
		ok         bool
	}{}, meta: vhdiMetadata{}}
	installFakeVHDIBackend(t, fakeVHDIBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, VHDIOpen(stringObj("ok.vhd")))
	if openErr != nil {
		t.Fatalf("unexpected open error: %v", openErr)
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	_, errObj = unwrapPair(t, VHDIReadAt(stringObj(handle), intObj(-1), intObj(1)))
	if errObj == nil || !strings.Contains(errObj.Message, "offset must be >= 0") {
		t.Fatalf("expected negative offset error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, VHDIReadAt(stringObj(handle), intObj(0), intObj(33554433)))
	if errObj == nil || !strings.Contains(errObj.Message, "length too large") {
		t.Fatalf("expected max length error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, VHDIMapOffset(stringObj(handle), &object.Boolean{Value: true}))
	if errObj == nil || !strings.Contains(errObj.Message, "must be INTEGER") {
		t.Fatalf("expected integer type error, got: %v", errObj)
	}

	closePayload, closeErr := unwrapPair(t, VHDIClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("unexpected close error: %v", closeErr)
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("vhdi_close payload is not HASH. got=%T", closePayload)
	}
	if !mustHashBoolValue(t, closeHash, "closed") {
		t.Fatalf("expected closed=true")
	}

	_, errObj = unwrapPair(t, VHDIMetadata(stringObj(handle)))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown vhdi handle") {
		t.Fatalf("expected unknown handle after close, got: %v", errObj)
	}
}

func TestEWFBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeEWFSession{
		data: map[int64][]byte{
			0: []byte("EWF_DATA"),
		},
		meta: ewfMetadata{
			MajorVersion:      1,
			MinorVersion:      0,
			SegmentNumber:     1,
			SectionCount:      12,
			HasDoneSection:    true,
			HasNextSection:    false,
			IsEncrypted:       false,
			HasIntegrityHash:  true,
			HasMD5Digest:      true,
			MD5DigestHex:      "00112233445566778899aabbccddeeff",
			HasSHA1Digest:     true,
			SHA1DigestHex:     "00112233445566778899aabbccddeeff00112233",
			HasMedia:          true,
			BytesPerSector:    512,
			SectorsPerChunk:   64,
			NumberOfSectors:   2048,
			NumberOfChunks:    32,
			TotalLogicalBytes: 1048576,
		},
	}
	installFakeEWFBackend(t, fakeEWFBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, EWFOpen(stringObj("image.E01")))
	if openErr != nil {
		t.Fatalf("ewf_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("ewf_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "ewf-handle-") {
		t.Fatalf("unexpected ewf handle format: %s", handle)
	}

	metaPayload, metaErr := unwrapPair(t, EWFMetadata(stringObj(handle)))
	if metaErr != nil {
		t.Fatalf("ewf_metadata returned error: %s", metaErr.Inspect())
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("ewf_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashIntValue(t, metaHash, "bytes_per_sector") != 512 {
		t.Fatalf("unexpected bytes_per_sector")
	}
	if mustHashIntValue(t, metaHash, "total_logical_bytes") != 1048576 {
		t.Fatalf("unexpected total_logical_bytes")
	}

	readPayload, readErr := unwrapPair(t, EWFReadAt(stringObj(handle), intObj(0), intObj(8)))
	if readErr != nil {
		t.Fatalf("ewf_read_at returned error: %s", readErr.Inspect())
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("ewf_read_at payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "EWF_DATA" {
		t.Fatalf("unexpected ewf_read_at payload. got=%q", readString.Value)
	}
}

func TestEWFBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{err: errors.New("ewf backend failed")})

	_, errObj := unwrapPair(t, EWFOpen(stringObj("broken.E01")))
	if errObj == nil || !strings.Contains(errObj.Message, "ewf_open") {
		t.Fatalf("expected ewf_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, EWFMetadata(stringObj("missing")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown ewf handle") {
		t.Fatalf("expected unknown ewf handle error, got: %v", errObj)
	}

	fakeSession := &fakeEWFSession{data: map[int64][]byte{}, meta: ewfMetadata{}}
	installFakeEWFBackend(t, fakeEWFBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, EWFOpen(stringObj("ok.E01")))
	if openErr != nil {
		t.Fatalf("unexpected open error: %v", openErr)
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	_, errObj = unwrapPair(t, EWFReadAt(stringObj(handle), intObj(-1), intObj(1)))
	if errObj == nil || !strings.Contains(errObj.Message, "offset must be >= 0") {
		t.Fatalf("expected negative offset error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, EWFReadAt(stringObj(handle), intObj(0), intObj(33554433)))
	if errObj == nil || !strings.Contains(errObj.Message, "length too large") {
		t.Fatalf("expected max length error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, EWFOpen(&object.Array{Elements: []object.Object{}}))
	if errObj == nil || !strings.Contains(errObj.Message, "must not be an empty ARRAY") {
		t.Fatalf("expected empty array error, got: %v", errObj)
	}
}

func TestEWFBuiltinOpenMultiSegmentAndCloseLifecycle(t *testing.T) {
	backend := &trackingEWFBackend{
		session: &fakeEWFSession{
			data: map[int64][]byte{0: []byte("ABCD")},
			meta: ewfMetadata{},
		},
	}
	installFakeEWFBackend(t, backend)

	segments := &object.Array{Elements: []object.Object{stringObj("image.E01"), stringObj("image.E02")}}
	openPayload, openErr := unwrapPair(t, EWFOpen(segments))
	if openErr != nil {
		t.Fatalf("ewf_open multi-segment returned error: %v", openErr)
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("ewf_open payload is not HASH. got=%T", openPayload)
	}
	if mustHashIntValue(t, openHash, "segment_count") != 2 {
		t.Fatalf("expected segment_count=2")
	}
	if len(backend.opened) != 1 || len(backend.opened[0]) != 2 {
		t.Fatalf("backend did not receive expected segment paths")
	}
	if backend.opened[0][0] != "image.E01" || backend.opened[0][1] != "image.E02" {
		t.Fatalf("segment order mismatch: %#v", backend.opened)
	}

	handle := mustHashStringValue(t, openHash, "handle")
	closePayload, closeErr := unwrapPair(t, EWFClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("ewf_close returned error: %v", closeErr)
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("ewf_close payload is not HASH. got=%T", closePayload)
	}
	if mustHashStringValue(t, closeHash, "handle") != handle {
		t.Fatalf("unexpected closed handle")
	}

	_, errObj := unwrapPair(t, EWFMetadata(stringObj(handle)))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown ewf handle") {
		t.Fatalf("expected unknown handle after close, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, EWFClose(stringObj(handle)))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown ewf handle") {
		t.Fatalf("expected unknown handle on second close, got: %v", errObj)
	}
}

func TestRAWBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeRAWSession{
		data: map[int64][]byte{0: []byte("RAW_BYTES")},
		meta: rawMetadata{FileSize: 4096, SectorSize: 512},
	}
	installFakeRAWBackend(t, fakeRAWBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, RAWOpen(stringObj("image.raw")))
	if openErr != nil {
		t.Fatalf("raw_open returned error: %v", openErr)
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("raw_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "raw-handle-") {
		t.Fatalf("unexpected raw handle format: %s", handle)
	}

	metaPayload, metaErr := unwrapPair(t, RAWMetadata(stringObj(handle)))
	if metaErr != nil {
		t.Fatalf("raw_metadata returned error: %v", metaErr)
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("raw_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashIntValue(t, metaHash, "file_size") != 4096 {
		t.Fatalf("unexpected file_size")
	}
	if mustHashIntValue(t, metaHash, "assumed_sector_size") != 512 {
		t.Fatalf("unexpected assumed_sector_size")
	}

	readPayload, readErr := unwrapPair(t, RAWReadAt(stringObj(handle), intObj(0), intObj(9)))
	if readErr != nil {
		t.Fatalf("raw_read_at returned error: %v", readErr)
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("raw_read_at payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "RAW_BYTES" {
		t.Fatalf("unexpected raw_read_at payload. got=%q", readString.Value)
	}

	closePayload, closeErr := unwrapPair(t, RAWClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("raw_close returned error: %v", closeErr)
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("raw_close payload is not HASH. got=%T", closePayload)
	}
	if mustHashStringValue(t, closeHash, "handle") != handle {
		t.Fatalf("raw_close returned wrong handle")
	}
}

func TestRAWBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeRAWBackend(t, fakeRAWBackend{err: errors.New("raw backend failed")})

	_, errObj := unwrapPair(t, RAWOpen(stringObj("broken.raw")))
	if errObj == nil || !strings.Contains(errObj.Message, "raw_open") {
		t.Fatalf("expected raw_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, RAWMetadata(stringObj("missing")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown raw handle") {
		t.Fatalf("expected unknown raw handle error, got: %v", errObj)
	}

	fakeSession := &fakeRAWSession{data: map[int64][]byte{}, meta: rawMetadata{}}
	installFakeRAWBackend(t, fakeRAWBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, RAWOpen(stringObj("ok.raw")))
	if openErr != nil {
		t.Fatalf("unexpected open error: %v", openErr)
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	_, errObj = unwrapPair(t, RAWReadAt(stringObj(handle), intObj(-1), intObj(1)))
	if errObj == nil || !strings.Contains(errObj.Message, "offset must be >= 0") {
		t.Fatalf("expected negative offset error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, RAWReadAt(stringObj(handle), intObj(0), intObj(33554433)))
	if errObj == nil || !strings.Contains(errObj.Message, "length too large") {
		t.Fatalf("expected max length error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, RAWClose(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("unexpected close error: %v", errObj)
	}

	_, errObj = unwrapPair(t, RAWClose(stringObj(handle)))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown raw handle") {
		t.Fatalf("expected unknown raw handle on second close, got: %v", errObj)
	}
}

func mustHashBoolValue(t *testing.T, hash *object.Hash, key string) bool {
	t.Helper()
	obj := mustHashValue(t, hash, key)
	value, ok := obj.(*object.Boolean)
	if !ok {
		t.Fatalf("key %s is not BOOLEAN", key)
	}
	return value.Value
}

func TestEWFVerifyReportsStoredAndComputedDigests(t *testing.T) {
	fakeSession := &fakeEWFSession{
		verify: ewfVerifyResult{
			Size:          1048576,
			BytesHashed:   1048576,
			HasStoredMD5:  true,
			StoredMD5:     "00112233445566778899aabbccddeeff",
			ComputedMD5:   "00112233445566778899aabbccddeeff",
			MD5Match:      true,
			HasStoredSHA1: true,
			StoredSHA1:    "00112233445566778899aabbccddeeff00112233",
			ComputedSHA1:  "00112233445566778899aabbccddeeff00112233",
			SHA1Match:     true,
			OK:            true,
		},
	}
	installFakeEWFBackend(t, fakeEWFBackend{session: fakeSession})

	handle := mustOpenFakeEWF(t)

	payload, errObj := unwrapPair(t, EWFVerify(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("ewf_verify returned error: %s", errObj.Inspect())
	}
	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("ewf_verify payload is not HASH. got=%T", payload)
	}

	if got := mustHashIntValue(t, hash, "size"); got != 1048576 {
		t.Fatalf("size = %d, want 1048576", got)
	}
	if got := mustHashIntValue(t, hash, "bytes_hashed"); got != 1048576 {
		t.Fatalf("bytes_hashed = %d, want 1048576", got)
	}
	if !mustHashBoolValue(t, hash, "md5_match") || !mustHashBoolValue(t, hash, "sha1_match") {
		t.Fatalf("expected both digests to match")
	}
	if !mustHashBoolValue(t, hash, "ok") {
		t.Fatalf("expected ok = true")
	}
	// Both the claim and the check travel, so a report can show what the image
	// said alongside what the data actually hashed to.
	if got := mustHashStringValue(t, hash, "stored_md5"); got != "00112233445566778899aabbccddeeff" {
		t.Fatalf("stored_md5 = %q", got)
	}
	if got := mustHashStringValue(t, hash, "computed_md5"); got != "00112233445566778899aabbccddeeff" {
		t.Fatalf("computed_md5 = %q", got)
	}
	if elems := mustHashArrayValue(t, hash, "bad_ranges"); len(elems) != 0 {
		t.Fatalf("bad_ranges = %d entries, want 0", len(elems))
	}
}

func TestEWFVerifyReportsBadRanges(t *testing.T) {
	fakeSession := &fakeEWFSession{
		verify: ewfVerifyResult{
			Size:         4096,
			BytesHashed:  4096,
			HasStoredMD5: true,
			StoredMD5:    "00112233445566778899aabbccddeeff",
			ComputedMD5:  "ffeeddccbbaa99887766554433221100",
			MD5Match:     false,
			BadRanges: []ewfBadRange{
				{Offset: 512, Length: 1024, Err: "chunk table invalid"},
			},
			OK: false,
		},
	}
	installFakeEWFBackend(t, fakeEWFBackend{session: fakeSession})

	handle := mustOpenFakeEWF(t)

	payload, errObj := unwrapPair(t, EWFVerify(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("ewf_verify returned error: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if mustHashBoolValue(t, hash, "ok") {
		t.Fatalf("expected ok = false for an image with undecodable spans")
	}

	elems := mustHashArrayValue(t, hash, "bad_ranges")
	if len(elems) != 1 {
		t.Fatalf("bad_ranges = %d entries, want 1", len(elems))
	}
	entry, ok := elems[0].(*object.Hash)
	if !ok {
		t.Fatalf("bad_ranges[0] is not HASH. got=%T", elems[0])
	}
	if got := mustHashIntValue(t, entry, "offset"); got != 512 {
		t.Fatalf("bad_ranges[0].offset = %d, want 512", got)
	}
	if got := mustHashIntValue(t, entry, "length"); got != 1024 {
		t.Fatalf("bad_ranges[0].length = %d, want 1024", got)
	}
	if got := mustHashStringValue(t, entry, "error"); got != "chunk table invalid" {
		t.Fatalf("bad_ranges[0].error = %q", got)
	}
}

func TestEWFVerifyUnknownHandleIsRefused(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{session: &fakeEWFSession{}})

	_, errObj := unwrapPair(t, EWFVerify(stringObj("ewf-handle-nope")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown ewf handle") {
		t.Fatalf("expected unknown ewf handle error, got: %v", errObj)
	}
}

func TestEWFVerifyPropagatesSessionError(t *testing.T) {
	fakeSession := &fakeEWFSession{verifyErr: errors.New("short read at 4096")}
	installFakeEWFBackend(t, fakeEWFBackend{session: fakeSession})

	handle := mustOpenFakeEWF(t)

	_, errObj := unwrapPair(t, EWFVerify(stringObj(handle)))
	if errObj == nil || !strings.Contains(errObj.Message, "short read at 4096") {
		t.Fatalf("expected the session error to survive, got: %v", errObj)
	}
}

// TestLibewfOKRefusesAnImageWithNoStoredDigest pins the contract ewf_verify's
// `ok` field is a pass-through of. The fake session cannot prove this: it
// carries whatever OK the test sets, whereas the real session takes it from
// libewf. If libewf ever decided that an image storing no digest "verified",
// ewf_verify would start reporting ok=true for an unverifiable image and
// nothing else in this package would notice.
func TestLibewfOKRefusesAnImageWithNoStoredDigest(t *testing.T) {
	noDigests := &libewf.VerifyResult{Size: 4096, BytesHashed: 4096}
	if noDigests.OK() {
		t.Fatalf("libewf.VerifyResult.OK() returned true for an image storing no digest; " +
			"ewf_verify's `ok` field and its documented meaning both depend on this being false")
	}

	matched := &libewf.VerifyResult{
		Size: 4096, BytesHashed: 4096,
		HasStoredMD5: true, MD5Match: true,
	}
	if !matched.OK() {
		t.Fatalf("libewf.VerifyResult.OK() returned false for a reproduced digest")
	}

	damaged := &libewf.VerifyResult{
		Size: 4096, BytesHashed: 4096,
		HasStoredMD5: true, MD5Match: true,
		BadRanges: []libewf.BadRange{{Offset: 0, Length: 512, Err: "unreadable"}},
	}
	if damaged.OK() {
		t.Fatalf("libewf.VerifyResult.OK() returned true despite an undecodable span")
	}
}

func mustOpenFakeEWF(t *testing.T) string {
	t.Helper()

	openPayload, openErr := unwrapPair(t, EWFOpen(stringObj("image.E01")))
	if openErr != nil {
		t.Fatalf("ewf_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("ewf_open payload is not HASH. got=%T", openPayload)
	}
	return mustHashStringValue(t, openHash, "handle")
}

// TestEWFOpenExpandsASingleSegmentPathIntoItsSet is the regression this whole
// seam exists for: before discovery ran, ewf_open("disk.E01") on a multi-segment
// set handed libewf exactly one reader and decoded only the first segment, so
// every read past its end and every digest over the result described something
// that was never acquired -- silently.
func TestEWFOpenExpandsASingleSegmentPathIntoItsSet(t *testing.T) {
	backend := &trackingEWFBackend{
		session:    &fakeEWFSession{data: map[int64][]byte{0: []byte("ABCD")}},
		discovered: []string{"image.E01", "image.E02", "image.E03"},
	}
	installFakeEWFBackend(t, backend)

	payload, errObj := unwrapPair(t, EWFOpen(stringObj("image.E01")))
	if errObj != nil {
		t.Fatalf("ewf_open returned error: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if got := mustHashIntValue(t, hash, "segment_count"); got != 3 {
		t.Fatalf("segment_count = %d, want 3 -- the count must describe the set decoded, not the path named", got)
	}
	assertStringArray(t, hash, "segments", []string{"image.E01", "image.E02", "image.E03"})

	if len(backend.opened) != 1 {
		t.Fatalf("backend opened %d times, want 1", len(backend.opened))
	}
	if len(backend.opened[0]) != 3 {
		t.Fatalf("backend was opened with %#v; the discovered set must be what is opened", backend.opened[0])
	}
}

// TestEWFOpenDiscoversFromANonFirstSegment pins that the path is an entry point
// into the set rather than its start. libewf identifies the set by stem and
// family and then enumerates from segment 1, so naming .E03 still decodes from
// .E01 -- and an examiner who tab-completed onto the wrong segment gets the
// whole image rather than a truncated one.
func TestEWFOpenDiscoversFromANonFirstSegment(t *testing.T) {
	backend := &trackingEWFBackend{
		session:    &fakeEWFSession{},
		discovered: []string{"image.E01", "image.E02", "image.E03"},
	}
	installFakeEWFBackend(t, backend)

	payload, errObj := unwrapPair(t, EWFOpen(stringObj("image.E03")))
	if errObj != nil {
		t.Fatalf("ewf_open returned error: %s", errObj.Inspect())
	}
	assertStringArray(t, payload.(*object.Hash), "segments", []string{"image.E01", "image.E02", "image.E03"})
	if backend.opened[0][0] != "image.E01" {
		t.Fatalf("opened starting at %q, want image.E01", backend.opened[0][0])
	}
}

// TestEWFOpenTakesAnExplicitSegmentListAsGiven guards the other half of the
// contract. Discovery must not run over a list the caller spelled out, or a set
// whose members were deliberately gathered from separate directories -- the
// normal shape of evidence restored from more than one source -- would become
// impossible to open.
func TestEWFOpenTakesAnExplicitSegmentListAsGiven(t *testing.T) {
	var asked []string
	installFakeEWFBackend(t, fakeEWFBackend{
		session:       &fakeEWFSession{},
		discovered:    []string{"discovery", "must", "not", "run"},
		discoverCalls: &asked,
	})

	segments := &object.Array{Elements: []object.Object{stringObj("vol1/image.E01"), stringObj("vol2/image.E02")}}
	payload, errObj := unwrapPair(t, EWFOpen(segments))
	if errObj != nil {
		t.Fatalf("ewf_open returned error: %s", errObj.Inspect())
	}
	if len(asked) != 0 {
		t.Fatalf("Discover was called with %#v for an explicit segment list", asked)
	}
	assertStringArray(t, payload.(*object.Hash), "segments", []string{"vol1/image.E01", "vol2/image.E02"})
}

// TestEWFOpenRefusesASetWithAHole pins the refusal. An image decoded across a
// hole is not the image that was acquired, and every digest taken over it would
// be a digest of something else -- so the open fails rather than succeeding into
// a manifest that looks ordinary.
func TestEWFOpenRefusesASetWithAHole(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{
		session: &fakeEWFSession{},
		discoverSet: &ewfSegmentSet{
			Contiguous:     false,
			PresentCount:   3,
			MissingNumbers: []int64{2, 4},
			MissingFiles:   []string{"image.E02", "image.E04"},
		},
	})

	_, errObj := unwrapPair(t, EWFOpen(stringObj("image.E01")))
	if errObj == nil {
		t.Fatalf("expected ewf_open to refuse a set with a hole")
	}
	// The message has to name the files: an examiner told only that something
	// is missing cannot go and find it.
	for _, want := range []string{"incomplete", "image.E02", "image.E04", "ewf_segments"} {
		if !strings.Contains(errObj.Message, want) {
			t.Fatalf("refusal message %q does not mention %q", errObj.Message, want)
		}
	}
}

func TestEWFOpenPropagatesDiscoveryErrors(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{
		session:     &fakeEWFSession{},
		discoverErr: errors.New("stat image.E01: no such file or directory"),
	})

	_, errObj := unwrapPair(t, EWFOpen(stringObj("image.E01")))
	if errObj == nil || !strings.Contains(errObj.Message, "no such file or directory") {
		t.Fatalf("expected the discovery error to survive, got: %v", errObj)
	}
}

func TestEWFSegmentsReportsTheWholeSet(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{
		session:    &fakeEWFSession{},
		discovered: []string{"image.E01", "image.E02"},
	})

	payload, errObj := unwrapPair(t, EWFSegments(stringObj("image.E01")))
	if errObj != nil {
		t.Fatalf("ewf_segments returned error: %s", errObj.Inspect())
	}
	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("ewf_segments payload is not HASH. got=%T", payload)
	}

	if !mustHashBoolValue(t, hash, "contiguous") {
		t.Fatalf("expected contiguous = true")
	}
	if got := mustHashStringValue(t, hash, "path"); got != "image.E01" {
		t.Fatalf("path = %q, want image.E01", got)
	}
	if got := mustHashIntValue(t, hash, "segment_count"); got != 2 {
		t.Fatalf("segment_count = %d, want 2", got)
	}
	if got := mustHashIntValue(t, hash, "present_count"); got != 2 {
		t.Fatalf("present_count = %d, want 2", got)
	}
	assertStringArray(t, hash, "segments", []string{"image.E01", "image.E02"})
	if elems := mustHashArrayValue(t, hash, "missing_segments"); len(elems) != 0 {
		t.Fatalf("missing_segments = %d entries, want 0", len(elems))
	}
	if elems := mustHashArrayValue(t, hash, "missing_files"); len(elems) != 0 {
		t.Fatalf("missing_files = %d entries, want 0", len(elems))
	}
}

// TestEWFSegmentsReportsAHoleRatherThanRaising is the reason this builtin is
// separate from ewf_open. Which files are absent is a finding about the
// evidence, so it comes back as data an examiner can put in a report -- not as
// an error string they would have to parse to learn anything from.
func TestEWFSegmentsReportsAHoleRatherThanRaising(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{
		session: &fakeEWFSession{},
		discoverSet: &ewfSegmentSet{
			Contiguous:     false,
			PresentCount:   3,
			MissingNumbers: []int64{2},
			MissingFiles:   []string{"image.E02"},
		},
	})

	payload, errObj := unwrapPair(t, EWFSegments(stringObj("image.E01")))
	if errObj != nil {
		t.Fatalf("ewf_segments raised on a hole; it must report one: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if mustHashBoolValue(t, hash, "contiguous") {
		t.Fatalf("expected contiguous = false")
	}
	if got := mustHashIntValue(t, hash, "present_count"); got != 3 {
		t.Fatalf("present_count = %d, want 3", got)
	}
	// segments stays empty, because the set was never resolved. Returning the
	// three files that happen to be present under a key named "segments" would
	// invite a report that names them as the image.
	if elems := mustHashArrayValue(t, hash, "segments"); len(elems) != 0 {
		t.Fatalf("segments = %d entries, want 0 for an unresolved set", len(elems))
	}
	if got := mustHashIntValue(t, hash, "segment_count"); got != 0 {
		t.Fatalf("segment_count = %d, want 0", got)
	}

	missing := mustHashArrayValue(t, hash, "missing_segments")
	if len(missing) != 1 {
		t.Fatalf("missing_segments = %d entries, want 1", len(missing))
	}
	number, ok := missing[0].(*object.Integer)
	if !ok || number.Value != 2 {
		t.Fatalf("missing_segments[0] = %v, want INTEGER 2", missing[0])
	}
	assertStringArray(t, hash, "missing_files", []string{"image.E02"})
}

func TestEWFSegmentsArgumentErrors(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{session: &fakeEWFSession{}})

	if _, errObj := unwrapPair(t, EWFSegments()); errObj == nil ||
		!strings.Contains(errObj.Message, "wrong number of arguments") {
		t.Fatalf("expected an arity error, got: %v", errObj)
	}
	if _, errObj := unwrapPair(t, EWFSegments(intObj(1))); errObj == nil ||
		!strings.Contains(errObj.Message, "must be STRING") {
		t.Fatalf("expected a type error, got: %v", errObj)
	}
}

// TestLibewfSegmentPathsReportsAHoleStructurally pins the libewf contract that
// realEWFBackend.Discover translates. The fake backend cannot prove it: it
// carries whatever set a test builds, whereas the real one has to recognise
// *MissingSegmentsError and convert it into a report instead of an error. If
// libewf ever stopped distinguishing a holed set, Discover would pass the
// failure through as a plain error and ewf_segments would raise where it is
// documented to report.
func TestLibewfSegmentPathsReportsAHoleStructurally(t *testing.T) {
	dir := t.TempDir()
	// Segments 1 and 3, so 2 is a hole. libewf stats the named path, so these
	// have to be real files.
	for _, name := range []string{"image.E01", "image.E03"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("EVF\x09\x0d\x0a\xff\x00"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	_, err := libewf.SegmentPaths(filepath.Join(dir, "image.E01"))
	if err == nil {
		t.Fatalf("libewf.SegmentPaths accepted a set missing segment 2")
	}

	var missing *libewf.MissingSegmentsError
	if !errors.As(err, &missing) {
		t.Fatalf("libewf reported the hole as %T (%v), not as *MissingSegmentsError; "+
			"realEWFBackend.Discover translates that type and ewf_segments' contract depends on it", err, err)
	}
	if len(missing.Missing) != 1 || missing.Missing[0] != 2 {
		t.Fatalf("missing segments = %v, want [2]", missing.Missing)
	}
	if len(missing.Present) != 2 {
		t.Fatalf("present segments = %v, want two of them", missing.Present)
	}
	if len(missing.Expected) != 1 || missing.Expected[0] != "image.E02" {
		t.Fatalf("expected names = %v, want [image.E02]; these are the files "+
			"ewf_segments reports as missing_files", missing.Expected)
	}
}

// TestRealEWFDiscoverTranslatesAHoleIntoAReport runs the real backend against
// that same set, closing the loop between the libewf contract above and what
// the builtin returns.
func TestRealEWFDiscoverTranslatesAHoleIntoAReport(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"image.E01", "image.E03"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("EVF\x09\x0d\x0a\xff\x00"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	set, err := realEWFBackend{}.Discover(filepath.Join(dir, "image.E01"))
	if err != nil {
		t.Fatalf("Discover raised on a hole instead of reporting it: %v", err)
	}
	if set.Contiguous {
		t.Fatalf("Discover reported a holed set as contiguous")
	}
	if len(set.Paths) != 0 {
		t.Fatalf("Discover returned paths %v for an unresolved set", set.Paths)
	}
	if len(set.MissingNumbers) != 1 || set.MissingNumbers[0] != 2 {
		t.Fatalf("MissingNumbers = %v, want [2]", set.MissingNumbers)
	}
	if len(set.MissingFiles) != 1 || set.MissingFiles[0] != "image.E02" {
		t.Fatalf("MissingFiles = %v, want [image.E02]", set.MissingFiles)
	}

	// A genuine failure still has to be a failure: a path that is not there is
	// not a set with a hole in it.
	if _, err := (realEWFBackend{}).Discover(filepath.Join(dir, "absent.E01")); err == nil {
		t.Fatalf("Discover accepted a path that does not exist")
	}
}

// TestRealEWFDiscoverResolvesAContiguousSet covers the success side against the
// real backend, including that the path need not be the first segment.
func TestRealEWFDiscoverResolvesAContiguousSet(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"image.E01", "image.E02", "image.E03"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("EVF\x09\x0d\x0a\xff\x00"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	set, err := realEWFBackend{}.Discover(filepath.Join(dir, "image.E03"))
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if !set.Contiguous || set.PresentCount != 3 || len(set.Paths) != 3 {
		t.Fatalf("Discover = %+v, want a contiguous 3-segment set", set)
	}
	for i, want := range []string{"image.E01", "image.E02", "image.E03"} {
		if filepath.Base(set.Paths[i]) != want {
			t.Fatalf("segment %d = %q, want %q -- naming .E03 must still decode from .E01",
				i, set.Paths[i], want)
		}
	}
}

// TestRealEWFDiscoverAcceptsALoneLetterPairName covers the hazard that
// discovery introduced and that nothing else would catch.
//
// ".ewf" parses as a letter-pair segment extension naming segment 676, so
// libewf reports a lone acquired.ewf as a set missing its first 675 segments --
// and a refusal on that would make an entirely ordinary single-file image
// unopenable because of how it is named. libewf states the rule that settles it
// ("a letter-pair extension names segment 100 or beyond, which cannot exist
// unless all 99 numeric segments do") and applies it to the files it scans for,
// but not to the path it was handed; Discover applies it to that one too.
func TestRealEWFDiscoverAcceptsALoneLetterPairName(t *testing.T) {
	for _, name := range []string{"acquired.ewf", "acquired.EAA"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("EVF\x09\x0d\x0a\xff\x00"), 0o600); err != nil {
				t.Fatalf("writing %s: %v", path, err)
			}

			set, err := realEWFBackend{}.Discover(path)
			if err != nil {
				t.Fatalf("Discover returned error: %v", err)
			}
			if !set.Contiguous || len(set.Paths) != 1 || set.Paths[0] != path {
				t.Fatalf("Discover = %+v, want the path resolving to itself", set)
			}
		})
	}
}

// TestRealEWFDiscoverStillReportsALoneNumberedSegment is the other side of that
// exception, and the reason it is written as narrowly as it is. .E05 standing
// alone really is segment 5 of a set, and opening it without .E01 through .E04
// decodes four segments of nothing -- so it stays a hole.
func TestRealEWFDiscoverStillReportsALoneNumberedSegment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.E05")
	if err := os.WriteFile(path, []byte("EVF\x09\x0d\x0a\xff\x00"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	set, err := realEWFBackend{}.Discover(path)
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if set.Contiguous {
		t.Fatalf("Discover accepted segment 5 standing alone as a whole set")
	}
	if len(set.MissingNumbers) != 4 {
		t.Fatalf("MissingNumbers = %v, want segments 1 through 4", set.MissingNumbers)
	}
}

// TestRealEWFDiscoverAcceptsAPathWithNoSegmentFamily covers an extension that
// names no EWF family at all, where there is no numbering to have a hole in.
func TestRealEWFDiscoverAcceptsAPathWithNoSegmentFamily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acquired.img")
	if err := os.WriteFile(path, []byte("EVF\x09\x0d\x0a\xff\x00"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	set, err := realEWFBackend{}.Discover(path)
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if !set.Contiguous || len(set.Paths) != 1 || set.Paths[0] != path {
		t.Fatalf("Discover = %+v, want the path resolving to itself", set)
	}
}

// TestEWFOpenCarriesTheChecksumPolicyThrough asserts the policy the caller
// named is the policy the library is opened under. The chunk table maps offsets
// to compressed chunks, so an unverified one means the decoded bytes may not be
// the bytes written -- a policy that stopped at the builtin boundary would let
// a script believe it had asked for strictness it never got.
func TestEWFOpenCarriesTheChecksumPolicyThrough(t *testing.T) {
	for _, testCase := range []struct {
		policy string
		want   ewfChecksumPolicy
	}{
		{"warn", ewfChecksumWarn},
		{"strict", ewfChecksumStrict},
		{"ignore", ewfChecksumIgnore},
	} {
		t.Run(testCase.policy, func(t *testing.T) {
			backend := &trackingEWFBackend{session: &fakeEWFSession{}}
			installFakeEWFBackend(t, backend)

			payload, errObj := unwrapPair(t, EWFOpen(stringObj("image.E01"), stringObj(testCase.policy)))
			if errObj != nil {
				t.Fatalf("ewf_open returned error: %s", errObj.Inspect())
			}
			if len(backend.openOpts) != 1 {
				t.Fatalf("backend opened %d times, want 1", len(backend.openOpts))
			}
			if got := backend.openOpts[0].ChecksumPolicy; got != testCase.want {
				t.Fatalf("backend opened under policy %v, want %v", got, testCase.want)
			}
			if backend.openOpts[0].AllowIncomplete {
				t.Fatalf("ewf_open must never allow an incomplete set")
			}
			// It also travels back, so a manifest records the posture the image
			// was read under rather than leaving a reader to assume the default.
			if got := mustHashStringValue(t, payload.(*object.Hash), "checksum_policy"); got != testCase.policy {
				t.Fatalf("checksum_policy = %q, want %q", got, testCase.policy)
			}
		})
	}
}

func TestEWFOpenDefaultsToWarn(t *testing.T) {
	backend := &trackingEWFBackend{session: &fakeEWFSession{}}
	installFakeEWFBackend(t, backend)

	payload, errObj := unwrapPair(t, EWFOpen(stringObj("image.E01")))
	if errObj != nil {
		t.Fatalf("ewf_open returned error: %s", errObj.Inspect())
	}
	if got := backend.openOpts[0].ChecksumPolicy; got != ewfChecksumWarn {
		t.Fatalf("default policy = %v, want warn -- damaged evidence should still yield what is readable, reported", got)
	}
	if got := mustHashStringValue(t, payload.(*object.Hash), "checksum_policy"); got != "warn" {
		t.Fatalf("checksum_policy = %q, want warn", got)
	}
}

// TestEWFOpenRefusesAnUnknownChecksumPolicy pins that the names are a closed
// set. Falling back to the default on a typo would turn an examiner's explicit
// decision into its opposite with nothing downstream showing it happened.
func TestEWFOpenRefusesAnUnknownChecksumPolicy(t *testing.T) {
	backend := &trackingEWFBackend{session: &fakeEWFSession{}}
	installFakeEWFBackend(t, backend)

	_, errObj := unwrapPair(t, EWFOpen(stringObj("image.E01"), stringObj("Strict")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown checksum_policy") {
		t.Fatalf("expected an unknown-policy error, got: %v", errObj)
	}
	if len(backend.openOpts) != 0 {
		t.Fatalf("the image was opened despite an unusable policy")
	}

	if _, errObj := unwrapPair(t, EWFOpen(stringObj("image.E01"), intObj(1))); errObj == nil ||
		!strings.Contains(errObj.Message, "must be STRING") {
		t.Fatalf("expected a type error, got: %v", errObj)
	}
	if _, errObj := unwrapPair(t, EWFOpen(stringObj("a"), stringObj("warn"), stringObj("b"))); errObj == nil ||
		!strings.Contains(errObj.Message, "wrong number of arguments") {
		t.Fatalf("expected an arity error, got: %v", errObj)
	}
}

// TestEWFOpenPartialProceedsPastAHoleAndSaysSo covers the escape hatch that
// keeps damaged evidence analysable. The caveat has to survive into the result:
// an image decoded from an incomplete set is not the image that was acquired,
// and a report built from it must be able to say so.
func TestEWFOpenPartialProceedsPastAHoleAndSaysSo(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{
		session: &fakeEWFSession{},
		discoverSet: &ewfSegmentSet{
			Paths:          []string{"image.E01", "image.E03"},
			Contiguous:     false,
			PresentCount:   2,
			MissingNumbers: []int64{2},
			MissingFiles:   []string{"image.E02"},
		},
	})

	payload, errObj := unwrapPair(t, EWFOpenPartial(stringObj("image.E01")))
	if errObj != nil {
		t.Fatalf("ewf_open_partial refused a holed set: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if !mustHashBoolValue(t, hash, "partial") {
		t.Fatalf("expected partial = true")
	}
	missing := mustHashArrayValue(t, hash, "missing_segments")
	if len(missing) != 1 {
		t.Fatalf("missing_segments = %d entries, want 1", len(missing))
	}
	if number, ok := missing[0].(*object.Integer); !ok || number.Value != 2 {
		t.Fatalf("missing_segments[0] = %v, want INTEGER 2", missing[0])
	}
}

// TestEWFOpenPartialPassesAllowIncompleteToTheLibrary is the other half of the
// escape hatch. Discovery only sees holes in the numbering; a set that stops
// short of its true end is indistinguishable in a directory and is caught by
// the reader instead -- so the permission has to reach libewf, not just the
// refusal in EWFOpen.
func TestEWFOpenPartialPassesAllowIncompleteToTheLibrary(t *testing.T) {
	backend := &trackingEWFBackend{session: &fakeEWFSession{}}
	installFakeEWFBackend(t, backend)

	if _, errObj := unwrapPair(t, EWFOpenPartial(stringObj("image.E01"), stringObj("ignore"))); errObj != nil {
		t.Fatalf("ewf_open_partial returned error: %s", errObj.Inspect())
	}
	if !backend.openOpts[0].AllowIncomplete {
		t.Fatalf("ewf_open_partial did not permit an incomplete set at the library")
	}
	if backend.openOpts[0].ChecksumPolicy != ewfChecksumIgnore {
		t.Fatalf("ewf_open_partial dropped the checksum policy")
	}
}

// TestEWFOpenReportsNotPartialForAWholeSet keeps the caveat fields honest in
// the ordinary case: a report template reading `partial` must get false, not a
// missing key, so it cannot be written to depend on which builtin opened the
// image.
func TestEWFOpenReportsNotPartialForAWholeSet(t *testing.T) {
	installFakeEWFBackend(t, fakeEWFBackend{
		session:    &fakeEWFSession{},
		discovered: []string{"image.E01", "image.E02"},
	})

	payload, errObj := unwrapPair(t, EWFOpen(stringObj("image.E01")))
	if errObj != nil {
		t.Fatalf("ewf_open returned error: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if mustHashBoolValue(t, hash, "partial") {
		t.Fatalf("expected partial = false for a whole set")
	}
	if elems := mustHashArrayValue(t, hash, "missing_segments"); len(elems) != 0 {
		t.Fatalf("missing_segments = %d entries, want 0", len(elems))
	}
}

func assertStringArray(t *testing.T, hash *object.Hash, key string, want []string) {
	t.Helper()

	elems := mustHashArrayValue(t, hash, key)
	if len(elems) != len(want) {
		t.Fatalf("%s = %d entries, want %d", key, len(elems), len(want))
	}
	for i, expected := range want {
		value, ok := elems[i].(*object.String)
		if !ok {
			t.Fatalf("%s[%d] is not STRING. got=%T", key, i, elems[i])
		}
		if value.Value != expected {
			t.Fatalf("%s[%d] = %q, want %q", key, i, value.Value, expected)
		}
	}
}

func mustHashArrayValue(t *testing.T, hash *object.Hash, key string) []object.Object {
	t.Helper()
	obj := mustHashValue(t, hash, key)
	value, ok := obj.(*object.Array)
	if !ok {
		t.Fatalf("key %s is not ARRAY", key)
	}
	return value.Elements
}
