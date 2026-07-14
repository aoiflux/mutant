package builtin

import (
	"errors"
	"strings"
	"testing"

	libxfat "github.com/aoiflux/libxfat"

	"mutant/object"
)

type fakeNTFSBackend struct {
	session ntfsSession
	err     error
}

func (f fakeNTFSBackend) Open(volumePath string) (ntfsSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeNTFSSession struct {
	entries map[string][]ntfsListEntry
	files   map[string][]byte
	meta    map[string]ntfsMetadata
}

type fakeFATBackend struct {
	session fatSession
	err     error
}

func (f fakeFATBackend) Open(volumePath string) (fatSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeFATSession struct {
	entries map[string][]fatListEntry
	files   map[string][]byte
	meta    map[string]fatMetadata
}

type fakeXFATBackend struct {
	session xfatSession
	err     error
}

func (f fakeXFATBackend) Open(volumePath string) (xfatSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeXFATSession struct {
	entries map[string][]xfatListEntry
	files   map[string][]byte
	meta    map[string]xfatMetadata
}

type fakeEXTBackend struct {
	session extSession
	err     error
}

func (f fakeEXTBackend) Open(volumePath string) (extSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeEXTSession struct {
	entries map[string][]extListEntry
	files   map[string][]byte
	meta    map[string]extMetadata
}

type fakeHFSBackend struct {
	session hfsSession
	err     error
}

func (f fakeHFSBackend) Open(volumePath string) (hfsSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeHFSSession struct {
	entries map[string][]hfsListEntry
	files   map[string][]byte
	meta    map[string]hfsMetadata
}

type fakeXFSBackend struct {
	session xfsSession
	err     error
}

func (f fakeXFSBackend) Open(volumePath string) (xfsSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeXFSSession struct {
	entries map[string][]xfsListEntry
	files   map[string][]byte
	meta    map[string]xfsMetadata
}

func (f *fakeXFSSession) ListFiles(dirPath string) ([]xfsListEntry, error) {
	if v, ok := f.entries[normalizeXFSPath(dirPath)]; ok {
		return v, nil
	}
	return nil, errors.New("path not found")
}

func (f *fakeXFSSession) ReadFile(filePath string) ([]byte, error) {
	if v, ok := f.files[normalizeXFSPath(filePath)]; ok {
		return v, nil
	}
	return nil, errors.New("file not found")
}

func (f *fakeXFSSession) Metadata(filePath string) (xfsMetadata, error) {
	if v, ok := f.meta[normalizeXFSPath(filePath)]; ok {
		return v, nil
	}
	return xfsMetadata{}, errors.New("metadata not found")
}

func (f *fakeXFSSession) Close() error {
	return nil
}

func (f *fakeHFSSession) ListFiles(dirPath string) ([]hfsListEntry, error) {
	if v, ok := f.entries[normalizeHFSPath(dirPath)]; ok {
		return v, nil
	}
	return nil, errors.New("path not found")
}

func (f *fakeHFSSession) ReadFile(filePath string) ([]byte, error) {
	if v, ok := f.files[normalizeHFSPath(filePath)]; ok {
		return v, nil
	}
	return nil, errors.New("file not found")
}

func (f *fakeHFSSession) Metadata(filePath string) (hfsMetadata, error) {
	if v, ok := f.meta[normalizeHFSPath(filePath)]; ok {
		return v, nil
	}
	return hfsMetadata{}, errors.New("metadata not found")
}

func (f *fakeHFSSession) Close() error {
	return nil
}

func (f *fakeEXTSession) ListFiles(dirPath string) ([]extListEntry, error) {
	if v, ok := f.entries[normalizeEXTPath(dirPath)]; ok {
		return v, nil
	}
	return nil, errors.New("path not found")
}

func (f *fakeEXTSession) ReadFile(filePath string) ([]byte, error) {
	if v, ok := f.files[normalizeEXTPath(filePath)]; ok {
		return v, nil
	}
	return nil, errors.New("file not found")
}

func (f *fakeEXTSession) Metadata(filePath string) (extMetadata, error) {
	if v, ok := f.meta[normalizeEXTPath(filePath)]; ok {
		return v, nil
	}
	return extMetadata{}, errors.New("metadata not found")
}

func (f *fakeEXTSession) Close() error {
	return nil
}

func (f *fakeXFATSession) ListFiles(dirPath string) ([]xfatListEntry, error) {
	if v, ok := f.entries[normalizeXFATPath(dirPath)]; ok {
		return v, nil
	}
	return nil, errors.New("path not found")
}

func (f *fakeXFATSession) ReadFile(filePath string) ([]byte, error) {
	if v, ok := f.files[normalizeXFATPath(filePath)]; ok {
		return v, nil
	}
	return nil, errors.New("file not found")
}

func (f *fakeXFATSession) Metadata(filePath string) (xfatMetadata, error) {
	if v, ok := f.meta[normalizeXFATPath(filePath)]; ok {
		return v, nil
	}
	return xfatMetadata{}, errors.New("metadata not found")
}

func (f *fakeXFATSession) Close() error {
	return nil
}

func (f *fakeFATSession) ListFiles(dirPath string) ([]fatListEntry, error) {
	if v, ok := f.entries[normalizeFATPath(dirPath)]; ok {
		return v, nil
	}
	return nil, errors.New("path not found")
}

func (f *fakeFATSession) ReadFile(filePath string) ([]byte, error) {
	if v, ok := f.files[normalizeFATPath(filePath)]; ok {
		return v, nil
	}
	return nil, errors.New("file not found")
}

func (f *fakeFATSession) Metadata(filePath string) (fatMetadata, error) {
	if v, ok := f.meta[normalizeFATPath(filePath)]; ok {
		return v, nil
	}
	return fatMetadata{}, errors.New("metadata not found")
}

func (f *fakeFATSession) Close() error {
	return nil
}

func (f *fakeNTFSSession) ListFiles(dirPath string) ([]ntfsListEntry, error) {
	if v, ok := f.entries[normalizeNTFSPath(dirPath)]; ok {
		return v, nil
	}
	return nil, errors.New("path not found")
}

func (f *fakeNTFSSession) ReadFile(filePath string) ([]byte, error) {
	if v, ok := f.files[normalizeNTFSPath(filePath)]; ok {
		return v, nil
	}
	return nil, errors.New("file not found")
}

func (f *fakeNTFSSession) Metadata(filePath string) (ntfsMetadata, error) {
	if v, ok := f.meta[normalizeNTFSPath(filePath)]; ok {
		return v, nil
	}
	return ntfsMetadata{}, errors.New("metadata not found")
}

func (f *fakeNTFSSession) Close() error {
	return nil
}

func installFakeNTFSBackend(t *testing.T, backend ntfsBackend) {
	t.Helper()

	ntfsStore.Lock()
	prevBackend := ntfsStore.backend
	prevHandles := ntfsStore.handles
	prevNextID := ntfsStore.nextID
	ntfsStore.backend = backend
	ntfsStore.handles = map[string]ntfsHandleState{}
	ntfsStore.nextID = 0
	ntfsStore.Unlock()

	t.Cleanup(func() {
		ntfsStore.Lock()
		for _, state := range ntfsStore.handles {
			_ = state.Session.Close()
		}
		ntfsStore.backend = prevBackend
		ntfsStore.handles = prevHandles
		ntfsStore.nextID = prevNextID
		ntfsStore.Unlock()
	})
}

func installFakeFATBackend(t *testing.T, backend fatBackend) {
	t.Helper()

	fatStore.Lock()
	prevBackend := fatStore.backend
	prevHandles := fatStore.handles
	prevNextID := fatStore.nextID
	fatStore.backend = backend
	fatStore.handles = map[string]fatHandleState{}
	fatStore.nextID = 0
	fatStore.Unlock()

	t.Cleanup(func() {
		fatStore.Lock()
		for _, state := range fatStore.handles {
			_ = state.Session.Close()
		}
		fatStore.backend = prevBackend
		fatStore.handles = prevHandles
		fatStore.nextID = prevNextID
		fatStore.Unlock()
	})
}

func installFakeXFATBackend(t *testing.T, backend xfatBackend) {
	t.Helper()

	xfatStore.Lock()
	prevBackend := xfatStore.backend
	prevHandles := xfatStore.handles
	prevNextID := xfatStore.nextID
	xfatStore.backend = backend
	xfatStore.handles = map[string]xfatHandleState{}
	xfatStore.nextID = 0
	xfatStore.Unlock()

	t.Cleanup(func() {
		xfatStore.Lock()
		for _, state := range xfatStore.handles {
			_ = state.Session.Close()
		}
		xfatStore.backend = prevBackend
		xfatStore.handles = prevHandles
		xfatStore.nextID = prevNextID
		xfatStore.Unlock()
	})
}

func installFakeEXTBackend(t *testing.T, backend extBackend) {
	t.Helper()

	extStore.Lock()
	prevBackend := extStore.backend
	prevHandles := extStore.handles
	prevNextID := extStore.nextID
	extStore.backend = backend
	extStore.handles = map[string]extHandleState{}
	extStore.nextID = 0
	extStore.Unlock()

	t.Cleanup(func() {
		extStore.Lock()
		for _, state := range extStore.handles {
			_ = state.Session.Close()
		}
		extStore.backend = prevBackend
		extStore.handles = prevHandles
		extStore.nextID = prevNextID
		extStore.Unlock()
	})
}

func installFakeHFSBackend(t *testing.T, backend hfsBackend) {
	t.Helper()

	hfsStore.Lock()
	prevBackend := hfsStore.backend
	prevHandles := hfsStore.handles
	prevNextID := hfsStore.nextID
	hfsStore.backend = backend
	hfsStore.handles = map[string]hfsHandleState{}
	hfsStore.nextID = 0
	hfsStore.Unlock()

	t.Cleanup(func() {
		hfsStore.Lock()
		for _, state := range hfsStore.handles {
			_ = state.Session.Close()
		}
		hfsStore.backend = prevBackend
		hfsStore.handles = prevHandles
		hfsStore.nextID = prevNextID
		hfsStore.Unlock()
	})
}

func installFakeXFSBackend(t *testing.T, backend xfsBackend) {
	t.Helper()

	xfsStore.Lock()
	prevBackend := xfsStore.backend
	prevHandles := xfsStore.handles
	prevNextID := xfsStore.nextID
	xfsStore.backend = backend
	xfsStore.handles = map[string]xfsHandleState{}
	xfsStore.nextID = 0
	xfsStore.Unlock()

	t.Cleanup(func() {
		xfsStore.Lock()
		for _, state := range xfsStore.handles {
			_ = state.Session.Close()
		}
		xfsStore.backend = prevBackend
		xfsStore.handles = prevHandles
		xfsStore.nextID = prevNextID
		xfsStore.Unlock()
	})
}

func TestNTFSBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeNTFSSession{
		entries: map[string][]ntfsListEntry{
			"/": {
				{Name: "docs", Path: "/docs", EntryNum: 5, SequenceNum: 1, IsDirectory: true},
				{Name: "note.txt", Path: "/note.txt", EntryNum: 6, SequenceNum: 1, Size: 11, AllocatedSize: 4096},
			},
		},
		files: map[string][]byte{
			"/note.txt": []byte("hello mutant"),
		},
		meta: map[string]ntfsMetadata{
			"/note.txt": {
				Path:       "/note.txt",
				Name:       "note.txt",
				EntryNum:   6,
				Size:       11,
				HasData:    true,
				Resident:   true,
				Readable:   true,
				CreatedAt:  "2026-01-01T00:00:00Z",
				ModifiedAt: "2026-01-01T00:00:00Z",
				AccessedAt: "2026-01-01T00:00:00Z",
			},
		},
	}
	installFakeNTFSBackend(t, fakeNTFSBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, NtfsOpen(stringObj("synthetic.img")))
	if openErr != nil {
		t.Fatalf("ntfs_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("ntfs_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "ntfs-handle-") {
		t.Fatalf("unexpected handle format: %s", handle)
	}

	listPayload, listErr := unwrapPair(t, NtfsListFiles(stringObj(handle), stringObj("/")))
	if listErr != nil {
		t.Fatalf("ntfs_list_files returned error: %s", listErr.Inspect())
	}
	entries, ok := listPayload.(*object.Array)
	if !ok {
		t.Fatalf("ntfs_list_files payload is not ARRAY. got=%T", listPayload)
	}
	if len(entries.Elements) != 2 {
		t.Fatalf("unexpected ntfs_list_files entry count. got=%d, want=2", len(entries.Elements))
	}

	readPayload, readErr := unwrapPair(t, NtfsReadFile(stringObj(handle), stringObj("/note.txt")))
	if readErr != nil {
		t.Fatalf("ntfs_read_file returned error: %s", readErr.Inspect())
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("ntfs_read_file payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "hello mutant" {
		t.Fatalf("unexpected ntfs_read_file payload. got=%q", readString.Value)
	}

	metaPayload, metaErr := unwrapPair(t, NtfsMetadata(stringObj(handle), stringObj("/note.txt")))
	if metaErr != nil {
		t.Fatalf("ntfs_metadata returned error: %s", metaErr.Inspect())
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("ntfs_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashStringValue(t, metaHash, "name") != "note.txt" {
		t.Fatalf("unexpected metadata name")
	}
	if mustHashIntValue(t, metaHash, "size") != 11 {
		t.Fatalf("unexpected metadata size")
	}

	closePayload, closeErr := unwrapPair(t, NtfsClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("ntfs_close returned error: %s", closeErr.Inspect())
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("ntfs_close payload is not HASH. got=%T", closePayload)
	}
	if mustHashStringValue(t, closeHash, "status") != "ok" {
		t.Fatalf("unexpected ntfs_close status")
	}

	_, errObj := unwrapPair(t, NtfsMetadata(stringObj(handle), stringObj("/note.txt")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown ntfs handle") {
		t.Fatalf("expected unknown ntfs handle after close, got: %v", errObj)
	}
}

func TestNTFSBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeNTFSBackend(t, fakeNTFSBackend{err: errors.New("boom")})

	_, errObj := unwrapPair(t, NtfsOpen(stringObj("broken.img")))
	if errObj == nil || !strings.Contains(errObj.Message, "ntfs_open") {
		t.Fatalf("expected ntfs_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, NtfsListFiles(stringObj("nope"), stringObj("/")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown ntfs handle") {
		t.Fatalf("expected unknown handle error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, NtfsReadFile(&object.Integer{Value: 1}, stringObj("/a")))
	if errObj == nil || !strings.Contains(errObj.Message, "must be STRING handle") {
		t.Fatalf("expected type error for handle, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, NtfsMetadata(stringObj("h")))
	if errObj == nil || !strings.Contains(errObj.Message, "wrong number of arguments") {
		t.Fatalf("expected arity error, got: %v", errObj)
	}
}

func TestFATBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeFATSession{
		entries: map[string][]fatListEntry{
			"/": {
				{Name: "docs", Path: "/docs", IsDirectory: true, Attributes: 0x10},
				{Name: "hello.txt", Path: "/hello.txt", ShortName: "HELLO.TXT", Size: 12, FirstCluster: 4, ClusterAllocated: true, Attributes: 0x20},
			},
		},
		files: map[string][]byte{
			"/hello.txt": []byte("hello from fat"),
		},
		meta: map[string]fatMetadata{
			"/hello.txt": {
				Path:           "/hello.txt",
				Name:           "hello.txt",
				ShortName:      "HELLO.TXT",
				Size:           14,
				FirstCluster:   4,
				Attributes:     0x20,
				CreatedAt:      "2026-01-01T00:00:00Z",
				ModifiedAt:     "2026-01-01T00:00:00Z",
				AccessedAt:     "2026-01-01T00:00:00Z",
				FileSystem:     "FAT16",
				VolumeLabel:    "MUTANTVOL",
				ClusterCount:   1024,
				ClusterSize:    4096,
				BytesPerSector: 512,
			},
		},
	}
	installFakeFATBackend(t, fakeFATBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, FatOpen(stringObj("synthetic-fat.img")))
	if openErr != nil {
		t.Fatalf("fat_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("fat_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "fat-handle-") {
		t.Fatalf("unexpected fat handle format: %s", handle)
	}

	listPayload, listErr := unwrapPair(t, FatListFiles(stringObj(handle), stringObj("/")))
	if listErr != nil {
		t.Fatalf("fat_list_files returned error: %s", listErr.Inspect())
	}
	entries, ok := listPayload.(*object.Array)
	if !ok {
		t.Fatalf("fat_list_files payload is not ARRAY. got=%T", listPayload)
	}
	if len(entries.Elements) != 2 {
		t.Fatalf("unexpected fat_list_files entry count. got=%d, want=2", len(entries.Elements))
	}

	readPayload, readErr := unwrapPair(t, FatReadFile(stringObj(handle), stringObj("/hello.txt")))
	if readErr != nil {
		t.Fatalf("fat_read_file returned error: %s", readErr.Inspect())
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("fat_read_file payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "hello from fat" {
		t.Fatalf("unexpected fat_read_file payload. got=%q", readString.Value)
	}

	metaPayload, metaErr := unwrapPair(t, FatMetadata(stringObj(handle), stringObj("/hello.txt")))
	if metaErr != nil {
		t.Fatalf("fat_metadata returned error: %s", metaErr.Inspect())
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("fat_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashStringValue(t, metaHash, "filesystem") != "FAT16" {
		t.Fatalf("unexpected filesystem type")
	}
	if mustHashStringValue(t, metaHash, "volume_label") != "MUTANTVOL" {
		t.Fatalf("unexpected volume label")
	}

	closePayload, closeErr := unwrapPair(t, FatClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("fat_close returned error: %s", closeErr.Inspect())
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("fat_close payload is not HASH. got=%T", closePayload)
	}
	if mustHashStringValue(t, closeHash, "status") != "ok" {
		t.Fatalf("unexpected fat_close status")
	}

	_, errObj := unwrapPair(t, FatMetadata(stringObj(handle), stringObj("/hello.txt")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown fat handle") {
		t.Fatalf("expected unknown fat handle after close, got: %v", errObj)
	}
}

func TestFATBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeFATBackend(t, fakeFATBackend{err: errors.New("fat backend failed")})

	_, errObj := unwrapPair(t, FatOpen(stringObj("broken-fat.img")))
	if errObj == nil || !strings.Contains(errObj.Message, "fat_open") {
		t.Fatalf("expected fat_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, FatListFiles(stringObj("missing"), stringObj("/")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown fat handle") {
		t.Fatalf("expected unknown fat handle error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, FatReadFile(&object.Integer{Value: 7}, stringObj("/a")))
	if errObj == nil || !strings.Contains(errObj.Message, "must be STRING handle") {
		t.Fatalf("expected type error for fat handle, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, FatMetadata(stringObj("h")))
	if errObj == nil || !strings.Contains(errObj.Message, "wrong number of arguments") {
		t.Fatalf("expected fat_metadata arity error, got: %v", errObj)
	}
}

func TestXFATBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeXFATSession{
		entries: map[string][]xfatListEntry{
			"/": {
				{Name: "folder", Path: "/folder", EntryCluster: 7, IsDirectory: true, Indexed: true},
				{Name: "report.txt", Path: "/report.txt", EntryCluster: 8, Size: 17, Indexed: true, HasFATChain: true},
				{Name: "$BitMap", Path: "/$BitMap", EntryCluster: 3, Size: 256, Special: true},
			},
		},
		files: map[string][]byte{
			"/report.txt": []byte("hello from exfat"),
		},
		meta: map[string]xfatMetadata{
			"/report.txt": {
				Path:         "/report.txt",
				Name:         "report.txt",
				EntryCluster: 8,
				Size:         16,
				Indexed:      true,
				HasFATChain:  true,
				VolumeLabel:  "EXFATVOL",
				ClusterSize:  4096,
			},
		},
	}
	installFakeXFATBackend(t, fakeXFATBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, XFATOpen(stringObj("synthetic-xfat.img")))
	if openErr != nil {
		t.Fatalf("xfat_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("xfat_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "xfat-handle-") {
		t.Fatalf("unexpected xfat handle format: %s", handle)
	}

	listPayload, listErr := unwrapPair(t, XFATListFiles(stringObj(handle), stringObj("/")))
	if listErr != nil {
		t.Fatalf("xfat_list_files returned error: %s", listErr.Inspect())
	}
	entries, ok := listPayload.(*object.Array)
	if !ok {
		t.Fatalf("xfat_list_files payload is not ARRAY. got=%T", listPayload)
	}
	if len(entries.Elements) != 3 {
		t.Fatalf("unexpected xfat_list_files entry count. got=%d, want=3", len(entries.Elements))
	}

	readPayload, readErr := unwrapPair(t, XFATReadFile(stringObj(handle), stringObj("/report.txt")))
	if readErr != nil {
		t.Fatalf("xfat_read_file returned error: %s", readErr.Inspect())
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("xfat_read_file payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "hello from exfat" {
		t.Fatalf("unexpected xfat_read_file payload. got=%q", readString.Value)
	}

	metaPayload, metaErr := unwrapPair(t, XFATMetadata(stringObj(handle), stringObj("/report.txt")))
	if metaErr != nil {
		t.Fatalf("xfat_metadata returned error: %s", metaErr.Inspect())
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("xfat_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashStringValue(t, metaHash, "volume_label") != "EXFATVOL" {
		t.Fatalf("unexpected xfat volume label")
	}
	if mustHashIntValue(t, metaHash, "cluster_size") != 4096 {
		t.Fatalf("unexpected xfat cluster size")
	}

	closePayload, closeErr := unwrapPair(t, XFATClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("xfat_close returned error: %s", closeErr.Inspect())
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("xfat_close payload is not HASH. got=%T", closePayload)
	}
	if mustHashStringValue(t, closeHash, "status") != "ok" {
		t.Fatalf("unexpected xfat_close status")
	}

	_, errObj := unwrapPair(t, XFATMetadata(stringObj(handle), stringObj("/report.txt")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown xfat handle") {
		t.Fatalf("expected unknown xfat handle after close, got: %v", errObj)
	}
}

func TestXFATBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeXFATBackend(t, fakeXFATBackend{err: errors.New("xfat backend failed")})

	_, errObj := unwrapPair(t, XFATOpen(stringObj("broken-xfat.img")))
	if errObj == nil || !strings.Contains(errObj.Message, "xfat_open") {
		t.Fatalf("expected xfat_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, XFATListFiles(stringObj("missing"), stringObj("/")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown xfat handle") {
		t.Fatalf("expected unknown xfat handle error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, XFATReadFile(&object.Integer{Value: 11}, stringObj("/a")))
	if errObj == nil || !strings.Contains(errObj.Message, "must be STRING handle") {
		t.Fatalf("expected type error for xfat handle, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, XFATMetadata(stringObj("h")))
	if errObj == nil || !strings.Contains(errObj.Message, "wrong number of arguments") {
		t.Fatalf("expected xfat_metadata arity error, got: %v", errObj)
	}
}

func TestXFATFindEntryByNameHelper(t *testing.T) {
	entries := []libxfat.Entry{}
	if _, found := xfatFindEntryByName(entries, "file.txt"); found {
		t.Fatalf("expected not found on empty entries")
	}
}

func TestEXTBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeEXTSession{
		entries: map[string][]extListEntry{
			"/": {
				{Name: "etc", Path: "/etc", Inode: 20, IsDirectory: true, Size: 0},
				{Name: "hosts", Path: "/hosts", Inode: 21, IsDirectory: false, Size: 18},
			},
		},
		files: map[string][]byte{
			"/hosts": []byte("127.0.0.1 localhost"),
		},
		meta: map[string]extMetadata{
			"/hosts": {
				Path:        "/hosts",
				Name:        "hosts",
				Inode:       21,
				IsDirectory: false,
				Size:        18,
				Kind:        "ext4",
				BlockSize:   4096,
				InodesCount: 1024,
			},
		},
	}
	installFakeEXTBackend(t, fakeEXTBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, ExtOpen(stringObj("synthetic-ext.img")))
	if openErr != nil {
		t.Fatalf("ext_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("ext_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "ext-handle-") {
		t.Fatalf("unexpected ext handle format: %s", handle)
	}

	listPayload, listErr := unwrapPair(t, ExtListFiles(stringObj(handle), stringObj("/")))
	if listErr != nil {
		t.Fatalf("ext_list_files returned error: %s", listErr.Inspect())
	}
	entries, ok := listPayload.(*object.Array)
	if !ok {
		t.Fatalf("ext_list_files payload is not ARRAY. got=%T", listPayload)
	}
	if len(entries.Elements) != 2 {
		t.Fatalf("unexpected ext_list_files entry count. got=%d, want=2", len(entries.Elements))
	}

	readPayload, readErr := unwrapPair(t, ExtReadFile(stringObj(handle), stringObj("/hosts")))
	if readErr != nil {
		t.Fatalf("ext_read_file returned error: %s", readErr.Inspect())
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("ext_read_file payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "127.0.0.1 localhost" {
		t.Fatalf("unexpected ext_read_file payload. got=%q", readString.Value)
	}

	metaPayload, metaErr := unwrapPair(t, ExtMetadata(stringObj(handle), stringObj("/hosts")))
	if metaErr != nil {
		t.Fatalf("ext_metadata returned error: %s", metaErr.Inspect())
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("ext_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashStringValue(t, metaHash, "kind") != "ext4" {
		t.Fatalf("unexpected ext filesystem kind")
	}
	if mustHashIntValue(t, metaHash, "block_size") != 4096 {
		t.Fatalf("unexpected ext block size")
	}

	closePayload, closeErr := unwrapPair(t, ExtClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("ext_close returned error: %s", closeErr.Inspect())
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("ext_close payload is not HASH. got=%T", closePayload)
	}
	if mustHashStringValue(t, closeHash, "status") != "ok" {
		t.Fatalf("unexpected ext_close status")
	}

	_, errObj := unwrapPair(t, ExtMetadata(stringObj(handle), stringObj("/hosts")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown ext handle") {
		t.Fatalf("expected unknown ext handle after close, got: %v", errObj)
	}
}

func TestEXTBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeEXTBackend(t, fakeEXTBackend{err: errors.New("ext backend failed")})

	_, errObj := unwrapPair(t, ExtOpen(stringObj("broken-ext.img")))
	if errObj == nil || !strings.Contains(errObj.Message, "ext_open") {
		t.Fatalf("expected ext_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, ExtListFiles(stringObj("missing"), stringObj("/")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown ext handle") {
		t.Fatalf("expected unknown ext handle error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, ExtReadFile(&object.Integer{Value: 2}, stringObj("/a")))
	if errObj == nil || !strings.Contains(errObj.Message, "must be STRING handle") {
		t.Fatalf("expected type error for ext handle, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, ExtMetadata(stringObj("h")))
	if errObj == nil || !strings.Contains(errObj.Message, "wrong number of arguments") {
		t.Fatalf("expected ext_metadata arity error, got: %v", errObj)
	}
}

func TestHFSBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeHFSSession{
		entries: map[string][]hfsListEntry{
			"/": {
				{Name: "System", Path: "/System", CNID: 2, IsDirectory: true, IsSystem: true},
				{Name: "note.txt", Path: "/note.txt", CNID: 42, IsDirectory: false},
			},
		},
		files: map[string][]byte{
			"/note.txt": []byte("hello from hfs"),
		},
		meta: map[string]hfsMetadata{
			"/note.txt": {
				Path:        "/note.txt",
				Name:        "note.txt",
				CNID:        42,
				IsDirectory: false,
				Size:        14,
				Kind:        "HFS+",
				BlockSize:   4096,
				TotalBlocks: 1200,
				FreeBlocks:  200,
				FileCount:   100,
				FolderCount: 20,
			},
		},
	}
	installFakeHFSBackend(t, fakeHFSBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, HFSOpen(stringObj("synthetic-hfs.img")))
	if openErr != nil {
		t.Fatalf("hfs_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("hfs_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "hfs-handle-") {
		t.Fatalf("unexpected hfs handle format: %s", handle)
	}

	listPayload, listErr := unwrapPair(t, HFSListFiles(stringObj(handle), stringObj("/")))
	if listErr != nil {
		t.Fatalf("hfs_list_files returned error: %s", listErr.Inspect())
	}
	entries, ok := listPayload.(*object.Array)
	if !ok {
		t.Fatalf("hfs_list_files payload is not ARRAY. got=%T", listPayload)
	}
	if len(entries.Elements) != 2 {
		t.Fatalf("unexpected hfs_list_files entry count. got=%d, want=2", len(entries.Elements))
	}

	readPayload, readErr := unwrapPair(t, HFSReadFile(stringObj(handle), stringObj("/note.txt")))
	if readErr != nil {
		t.Fatalf("hfs_read_file returned error: %s", readErr.Inspect())
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("hfs_read_file payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "hello from hfs" {
		t.Fatalf("unexpected hfs_read_file payload. got=%q", readString.Value)
	}

	metaPayload, metaErr := unwrapPair(t, HFSMetadata(stringObj(handle), stringObj("/note.txt")))
	if metaErr != nil {
		t.Fatalf("hfs_metadata returned error: %s", metaErr.Inspect())
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("hfs_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashStringValue(t, metaHash, "kind") != "HFS+" {
		t.Fatalf("unexpected hfs kind")
	}
	if mustHashIntValue(t, metaHash, "block_size") != 4096 {
		t.Fatalf("unexpected hfs block size")
	}

	closePayload, closeErr := unwrapPair(t, HFSClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("hfs_close returned error: %s", closeErr.Inspect())
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("hfs_close payload is not HASH. got=%T", closePayload)
	}
	if mustHashStringValue(t, closeHash, "status") != "ok" {
		t.Fatalf("unexpected hfs_close status")
	}

	_, errObj := unwrapPair(t, HFSMetadata(stringObj(handle), stringObj("/note.txt")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown hfs handle") {
		t.Fatalf("expected unknown hfs handle after close, got: %v", errObj)
	}
}

func TestHFSBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeHFSBackend(t, fakeHFSBackend{err: errors.New("hfs backend failed")})

	_, errObj := unwrapPair(t, HFSOpen(stringObj("broken-hfs.img")))
	if errObj == nil || !strings.Contains(errObj.Message, "hfs_open") {
		t.Fatalf("expected hfs_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, HFSListFiles(stringObj("missing"), stringObj("/")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown hfs handle") {
		t.Fatalf("expected unknown hfs handle error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, HFSReadFile(&object.Integer{Value: 3}, stringObj("/a")))
	if errObj == nil || !strings.Contains(errObj.Message, "must be STRING handle") {
		t.Fatalf("expected type error for hfs handle, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, HFSMetadata(stringObj("h")))
	if errObj == nil || !strings.Contains(errObj.Message, "wrong number of arguments") {
		t.Fatalf("expected hfs_metadata arity error, got: %v", errObj)
	}
}

func TestXFSBuiltinFlowWithSyntheticDataset(t *testing.T) {
	fakeSession := &fakeXFSSession{
		entries: map[string][]xfsListEntry{
			"/": {
				{Name: "etc", Path: "/etc", Inode: 32, IsDirectory: true, Size: 0},
				{Name: "hosts", Path: "/hosts", Inode: 33, IsDirectory: false, Size: 15},
			},
		},
		files: map[string][]byte{
			"/hosts": []byte("hello from xfs"),
		},
		meta: map[string]xfsMetadata{
			"/hosts": {
				Path:          "/hosts",
				Name:          "hosts",
				Inode:         33,
				IsDirectory:   false,
				Size:          14,
				FormatVersion: 5,
				BlockSize:     4096,
				InodeSize:     512,
				VolumeBlocks:  2048,
				RootInode:     32,
			},
		},
	}
	installFakeXFSBackend(t, fakeXFSBackend{session: fakeSession})

	openPayload, openErr := unwrapPair(t, XFSOpen(stringObj("synthetic-xfs.img")))
	if openErr != nil {
		t.Fatalf("xfs_open returned error: %s", openErr.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("xfs_open payload is not HASH. got=%T", openPayload)
	}
	handle := mustHashStringValue(t, openHash, "handle")
	if !strings.HasPrefix(handle, "xfs-handle-") {
		t.Fatalf("unexpected xfs handle format: %s", handle)
	}

	listPayload, listErr := unwrapPair(t, XFSListFiles(stringObj(handle), stringObj("/")))
	if listErr != nil {
		t.Fatalf("xfs_list_files returned error: %s", listErr.Inspect())
	}
	entries, ok := listPayload.(*object.Array)
	if !ok {
		t.Fatalf("xfs_list_files payload is not ARRAY. got=%T", listPayload)
	}
	if len(entries.Elements) != 2 {
		t.Fatalf("unexpected xfs_list_files entry count. got=%d, want=2", len(entries.Elements))
	}

	readPayload, readErr := unwrapPair(t, XFSReadFile(stringObj(handle), stringObj("/hosts")))
	if readErr != nil {
		t.Fatalf("xfs_read_file returned error: %s", readErr.Inspect())
	}
	readString, ok := readPayload.(*object.String)
	if !ok {
		t.Fatalf("xfs_read_file payload is not STRING. got=%T", readPayload)
	}
	if readString.Value != "hello from xfs" {
		t.Fatalf("unexpected xfs_read_file payload. got=%q", readString.Value)
	}

	metaPayload, metaErr := unwrapPair(t, XFSMetadata(stringObj(handle), stringObj("/hosts")))
	if metaErr != nil {
		t.Fatalf("xfs_metadata returned error: %s", metaErr.Inspect())
	}
	metaHash, ok := metaPayload.(*object.Hash)
	if !ok {
		t.Fatalf("xfs_metadata payload is not HASH. got=%T", metaPayload)
	}
	if mustHashIntValue(t, metaHash, "format_version") != 5 {
		t.Fatalf("unexpected xfs format_version")
	}
	if mustHashIntValue(t, metaHash, "block_size") != 4096 {
		t.Fatalf("unexpected xfs block size")
	}

	closePayload, closeErr := unwrapPair(t, XFSClose(stringObj(handle)))
	if closeErr != nil {
		t.Fatalf("xfs_close returned error: %s", closeErr.Inspect())
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("xfs_close payload is not HASH. got=%T", closePayload)
	}
	if mustHashStringValue(t, closeHash, "status") != "ok" {
		t.Fatalf("unexpected xfs_close status")
	}

	_, errObj := unwrapPair(t, XFSMetadata(stringObj(handle), stringObj("/hosts")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown xfs handle") {
		t.Fatalf("expected unknown xfs handle after close, got: %v", errObj)
	}
}

func TestXFSBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeXFSBackend(t, fakeXFSBackend{err: errors.New("xfs backend failed")})

	_, errObj := unwrapPair(t, XFSOpen(stringObj("broken-xfs.img")))
	if errObj == nil || !strings.Contains(errObj.Message, "xfs_open") {
		t.Fatalf("expected xfs_open error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, XFSListFiles(stringObj("missing"), stringObj("/")))
	if errObj == nil || !strings.Contains(errObj.Message, "unknown xfs handle") {
		t.Fatalf("expected unknown xfs handle error, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, XFSReadFile(&object.Integer{Value: 4}, stringObj("/a")))
	if errObj == nil || !strings.Contains(errObj.Message, "must be STRING handle") {
		t.Fatalf("expected type error for xfs handle, got: %v", errObj)
	}

	_, errObj = unwrapPair(t, XFSMetadata(stringObj("h")))
	if errObj == nil || !strings.Contains(errObj.Message, "wrong number of arguments") {
		t.Fatalf("expected xfs_metadata arity error, got: %v", errObj)
	}
}
