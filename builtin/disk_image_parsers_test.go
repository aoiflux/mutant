package builtin

import (
	"errors"
	"strings"
	"testing"

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
}

func (f fakeEWFBackend) Open(segmentPaths []string) (ewfSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeEWFSession struct {
	data map[int64][]byte
	meta ewfMetadata
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

func (f *fakeEWFSession) Close() error { return nil }

type trackingEWFBackend struct {
	session ewfSession
	opened  [][]string
	openErr error
}

func (b *trackingEWFBackend) Open(segmentPaths []string) (ewfSession, error) {
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
	if mustHashIntValue(t, metaHash, "sector_size") != 512 {
		t.Fatalf("unexpected sector_size")
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
