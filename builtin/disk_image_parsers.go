package builtin

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"

	libewf "github.com/aoiflux/libewf"
	libvhdi "github.com/aoiflux/libvhdi"

	"mutant/object"
)

type vhdiMetadata struct {
	Format           string
	DiskType         string
	VirtualSize      uint64
	BlockSize        uint32
	SectorSize       uint32
	Identifier       string
	IsDifferencing   bool
	ParentFilename   string
	ParentIdentifier string
}

type vhdiSession interface {
	ReadAt(offset int64, length int64) ([]byte, error)
	Metadata() (vhdiMetadata, error)
	MapOffset(virtualOffset int64) (int64, bool, error)
	Close() error
}

type vhdiBackend interface {
	Open(imagePath string) (vhdiSession, error)
}

type realVHDIBackend struct{}

type realVHDISession struct {
	disk *libvhdi.Disk
}

type vhdiHandleState struct {
	ImagePath string
	Session   vhdiSession
}

type ewfMetadata struct {
	MajorVersion      uint8
	MinorVersion      uint8
	SegmentNumber     uint32
	SectionCount      int
	HasDoneSection    bool
	HasNextSection    bool
	IsEncrypted       bool
	HasIntegrityHash  bool
	HasMD5Digest      bool
	MD5DigestHex      string
	HasSHA1Digest     bool
	SHA1DigestHex     string
	HasMedia          bool
	BytesPerSector    uint32
	SectorsPerChunk   uint32
	NumberOfSectors   uint64
	NumberOfChunks    uint64
	TotalLogicalBytes uint64
}

type ewfSession interface {
	ReadAt(offset int64, length int64) ([]byte, error)
	Metadata() (ewfMetadata, error)
	Close() error
}

type ewfBackend interface {
	Open(segmentPaths []string) (ewfSession, error)
}

type realEWFBackend struct{}

type realEWFSession struct {
	reader libewf.Reader
	files  []*os.File
}

type ewfHandleState struct {
	SegmentPaths []string
	Session      ewfSession
}

type rawMetadata struct {
	FileSize   int64
	SectorSize uint32
}

type rawSession interface {
	ReadAt(offset int64, length int64) ([]byte, error)
	Metadata() (rawMetadata, error)
	Close() error
}

type rawBackend interface {
	Open(imagePath string) (rawSession, error)
}

type realRawBackend struct{}

type realRawSession struct {
	file *os.File
	size int64
}

type rawHandleState struct {
	ImagePath string
	Session   rawSession
}

var vhdiStore = struct {
	sync.RWMutex
	nextID  int64
	backend vhdiBackend
	handles map[string]vhdiHandleState
}{
	backend: realVHDIBackend{},
	handles: map[string]vhdiHandleState{},
}

var ewfStore = struct {
	sync.RWMutex
	nextID  int64
	backend ewfBackend
	handles map[string]ewfHandleState
}{
	backend: realEWFBackend{},
	handles: map[string]ewfHandleState{},
}

var rawStore = struct {
	sync.RWMutex
	nextID  int64
	backend rawBackend
	handles map[string]rawHandleState
}{
	backend: realRawBackend{},
	handles: map[string]rawHandleState{},
}

func VHDIOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `vhdi_open` must be STRING, got %s", args[0].Type()))
	}

	vhdiStore.RLock()
	backend := vhdiStore.backend
	vhdiStore.RUnlock()

	session, err := backend.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("vhdi_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&vhdiStore.nextID, 1)
	handle := fmt.Sprintf("vhdi-handle-%d", handleID)

	vhdiStore.Lock()
	vhdiStore.handles[handle] = vhdiHandleState{ImagePath: pathObj.Value, Session: session}
	vhdiStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(pathObj.Value),
		"status": stringObj("ok"),
	}), nil)
}

func VHDIMetadata(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], "vhdi_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	metadata, err := state.Session.Metadata()
	if err != nil {
		return resultAndError(nil, newError("vhdi_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"format":            stringObj(metadata.Format),
		"disk_type":         stringObj(metadata.DiskType),
		"virtual_size":      intObj(int64(metadata.VirtualSize)),
		"block_size":        intObj(int64(metadata.BlockSize)),
		"sector_size":       intObj(int64(metadata.SectorSize)),
		"identifier":        stringObj(metadata.Identifier),
		"is_differencing":   boolObj(metadata.IsDifferencing),
		"parent_filename":   stringObj(metadata.ParentFilename),
		"parent_identifier": stringObj(metadata.ParentIdentifier),
	}), nil)
}

func VHDIReadAt(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], "vhdi_read_at")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `vhdi_read_at` must be INTEGER, got %s", args[1].Type()))
	}
	lengthObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `vhdi_read_at` must be INTEGER, got %s", args[2].Type()))
	}
	if offsetObj.Value < 0 {
		return resultAndError(nil, newError("vhdi_read_at: offset must be >= 0"))
	}
	if lengthObj.Value < 0 {
		return resultAndError(nil, newError("vhdi_read_at: length must be >= 0"))
	}
	if lengthObj.Value > 32*1024*1024 {
		return resultAndError(nil, newError("vhdi_read_at: length too large (max 33554432)"))
	}

	content, err := state.Session.ReadAt(offsetObj.Value, lengthObj.Value)
	if err != nil {
		return resultAndError(nil, newError("vhdi_read_at: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func VHDIMapOffset(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], "vhdi_map_offset")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `vhdi_map_offset` must be INTEGER, got %s", args[1].Type()))
	}
	if offsetObj.Value < 0 {
		return resultAndError(nil, newError("vhdi_map_offset: offset must be >= 0"))
	}

	fileOffset, mapped, err := state.Session.MapOffset(offsetObj.Value)
	if err != nil {
		return resultAndError(nil, newError("vhdi_map_offset: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"virtual_offset": intObj(offsetObj.Value),
		"mapped":         boolObj(mapped),
		"file_offset":    intObj(fileOffset),
	}), nil)
}

func VHDIClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `vhdi_close` must be STRING handle, got %s", args[0].Type()))
	}

	vhdiStore.Lock()
	state, exists := vhdiStore.handles[handleObj.Value]
	if exists {
		delete(vhdiStore.handles, handleObj.Value)
	}
	vhdiStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("vhdi_close: unknown vhdi handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("vhdi_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func EWFOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	segmentPaths, errObj := parseEWFSegmentPaths(args[0], "ewf_open")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	ewfStore.RLock()
	backend := ewfStore.backend
	ewfStore.RUnlock()

	session, err := backend.Open(segmentPaths)
	if err != nil {
		return resultAndError(nil, newError("ewf_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&ewfStore.nextID, 1)
	handle := fmt.Sprintf("ewf-handle-%d", handleID)

	ewfStore.Lock()
	ewfStore.handles[handle] = ewfHandleState{SegmentPaths: segmentPaths, Session: session}
	ewfStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":        stringObj(handle),
		"segment_count": intObj(int64(len(segmentPaths))),
		"status":        stringObj("ok"),
	}), nil)
}

func EWFMetadata(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveEWFHandle(args[0], "ewf_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	metadata, err := state.Session.Metadata()
	if err != nil {
		return resultAndError(nil, newError("ewf_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"major_version":       intObj(int64(metadata.MajorVersion)),
		"minor_version":       intObj(int64(metadata.MinorVersion)),
		"segment_number":      intObj(int64(metadata.SegmentNumber)),
		"section_count":       intObj(int64(metadata.SectionCount)),
		"has_done_section":    boolObj(metadata.HasDoneSection),
		"has_next_section":    boolObj(metadata.HasNextSection),
		"is_encrypted":        boolObj(metadata.IsEncrypted),
		"has_integrity_hash":  boolObj(metadata.HasIntegrityHash),
		"has_md5_digest":      boolObj(metadata.HasMD5Digest),
		"md5_digest":          stringObj(metadata.MD5DigestHex),
		"has_sha1_digest":     boolObj(metadata.HasSHA1Digest),
		"sha1_digest":         stringObj(metadata.SHA1DigestHex),
		"has_media":           boolObj(metadata.HasMedia),
		"bytes_per_sector":    intObj(int64(metadata.BytesPerSector)),
		"sectors_per_chunk":   intObj(int64(metadata.SectorsPerChunk)),
		"number_of_sectors":   intObj(int64(metadata.NumberOfSectors)),
		"number_of_chunks":    intObj(int64(metadata.NumberOfChunks)),
		"total_logical_bytes": intObj(int64(metadata.TotalLogicalBytes)),
	}), nil)
}

func EWFReadAt(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	state, errObj := resolveEWFHandle(args[0], "ewf_read_at")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `ewf_read_at` must be INTEGER, got %s", args[1].Type()))
	}
	lengthObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `ewf_read_at` must be INTEGER, got %s", args[2].Type()))
	}
	if offsetObj.Value < 0 {
		return resultAndError(nil, newError("ewf_read_at: offset must be >= 0"))
	}
	if lengthObj.Value < 0 {
		return resultAndError(nil, newError("ewf_read_at: length must be >= 0"))
	}
	if lengthObj.Value > 32*1024*1024 {
		return resultAndError(nil, newError("ewf_read_at: length too large (max 33554432)"))
	}

	content, err := state.Session.ReadAt(offsetObj.Value, lengthObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ewf_read_at: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func EWFClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `ewf_close` must be STRING handle, got %s", args[0].Type()))
	}

	ewfStore.Lock()
	state, exists := ewfStore.handles[handleObj.Value]
	if exists {
		delete(ewfStore.handles, handleObj.Value)
	}
	ewfStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("ewf_close: unknown ewf handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("ewf_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func RAWOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `raw_open` must be STRING, got %s", args[0].Type()))
	}
	if pathObj.Value == "" {
		return resultAndError(nil, newError("argument 1 to `raw_open` must not be empty"))
	}

	rawStore.RLock()
	backend := rawStore.backend
	rawStore.RUnlock()

	session, err := backend.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("raw_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&rawStore.nextID, 1)
	handle := fmt.Sprintf("raw-handle-%d", handleID)

	rawStore.Lock()
	rawStore.handles[handle] = rawHandleState{ImagePath: pathObj.Value, Session: session}
	rawStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(pathObj.Value),
		"status": stringObj("ok"),
	}), nil)
}

func RAWMetadata(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveRAWHandle(args[0], "raw_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	metadata, err := state.Session.Metadata()
	if err != nil {
		return resultAndError(nil, newError("raw_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"file_size":   intObj(metadata.FileSize),
		"sector_size": intObj(int64(metadata.SectorSize)),
	}), nil)
}

func RAWReadAt(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	state, errObj := resolveRAWHandle(args[0], "raw_read_at")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `raw_read_at` must be INTEGER, got %s", args[1].Type()))
	}
	lengthObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `raw_read_at` must be INTEGER, got %s", args[2].Type()))
	}
	if offsetObj.Value < 0 {
		return resultAndError(nil, newError("raw_read_at: offset must be >= 0"))
	}
	if lengthObj.Value < 0 {
		return resultAndError(nil, newError("raw_read_at: length must be >= 0"))
	}
	if lengthObj.Value > 32*1024*1024 {
		return resultAndError(nil, newError("raw_read_at: length too large (max 33554432)"))
	}

	content, err := state.Session.ReadAt(offsetObj.Value, lengthObj.Value)
	if err != nil {
		return resultAndError(nil, newError("raw_read_at: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func RAWClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `raw_close` must be STRING handle, got %s", args[0].Type()))
	}

	rawStore.Lock()
	state, exists := rawStore.handles[handleObj.Value]
	if exists {
		delete(rawStore.handles, handleObj.Value)
	}
	rawStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("raw_close: unknown raw handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("raw_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func resolveVHDIHandle(arg object.Object, op string) (vhdiHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return vhdiHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	vhdiStore.RLock()
	state, exists := vhdiStore.handles[handleObj.Value]
	vhdiStore.RUnlock()
	if !exists {
		return vhdiHandleState{}, newError("%s: unknown vhdi handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func resolveEWFHandle(arg object.Object, op string) (ewfHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return ewfHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	ewfStore.RLock()
	state, exists := ewfStore.handles[handleObj.Value]
	ewfStore.RUnlock()
	if !exists {
		return ewfHandleState{}, newError("%s: unknown ewf handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func resolveRAWHandle(arg object.Object, op string) (rawHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return rawHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	rawStore.RLock()
	state, exists := rawStore.handles[handleObj.Value]
	rawStore.RUnlock()
	if !exists {
		return rawHandleState{}, newError("%s: unknown raw handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func (realVHDIBackend) Open(imagePath string) (vhdiSession, error) {
	disk, err := libvhdi.OpenFile(imagePath)
	if err != nil {
		return nil, err
	}
	return &realVHDISession{disk: disk}, nil
}

func (realEWFBackend) Open(segmentPaths []string) (ewfSession, error) {
	files := make([]*os.File, 0, len(segmentPaths))
	sources := make([]io.ReaderAt, 0, len(segmentPaths))

	for _, p := range segmentPaths {
		f, err := os.Open(p)
		if err != nil {
			for _, opened := range files {
				_ = opened.Close()
			}
			return nil, err
		}
		files = append(files, f)
		sources = append(sources, f)
	}

	var (
		reader libewf.Reader
		err    error
	)
	if len(sources) == 1 {
		reader, err = libewf.Open(sources[0])
	} else {
		reader, err = libewf.OpenSegments(sources)
	}
	if err != nil {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, err
	}

	return &realEWFSession{reader: reader, files: files}, nil
}

func (realRawBackend) Open(imagePath string) (rawSession, error) {
	f, err := os.Open(imagePath)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	return &realRawSession{file: f, size: info.Size()}, nil
}

func (s *realVHDISession) ReadAt(offset int64, length int64) ([]byte, error) {
	if length == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	n, err := s.disk.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

func (s *realVHDISession) Metadata() (vhdiMetadata, error) {
	meta := vhdiMetadata{
		VirtualSize:    s.disk.Size(),
		BlockSize:      s.disk.BlockSize(),
		SectorSize:     s.disk.SectorSize(),
		Identifier:     s.disk.GUIDString(),
		IsDifferencing: s.disk.IsDifferencing(),
	}

	switch s.disk.Format() {
	case libvhdi.FormatVHD:
		meta.Format = "VHD"
	case libvhdi.FormatVHDX:
		meta.Format = "VHDX"
	default:
		meta.Format = "UNKNOWN"
	}

	switch s.disk.DiskType() {
	case libvhdi.DiskTypeFixed:
		meta.DiskType = "fixed"
	case libvhdi.DiskTypeDynamic:
		meta.DiskType = "dynamic"
	case libvhdi.DiskTypeDifferential:
		meta.DiskType = "differencing"
	default:
		meta.DiskType = "unknown"
	}

	if meta.IsDifferencing {
		meta.ParentFilename = s.disk.ParentFilename()
		meta.ParentIdentifier = guidBytesToString(s.disk.ParentIdentifier())
	}

	return meta, nil
}

func (s *realVHDISession) MapOffset(virtualOffset int64) (int64, bool, error) {
	return s.disk.VirtualToFileOffset(virtualOffset)
}

func (s *realVHDISession) Close() error {
	if s == nil || s.disk == nil {
		return nil
	}
	return s.disk.Close()
}

func (s *realEWFSession) ReadAt(offset int64, length int64) ([]byte, error) {
	if length == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	n, err := s.reader.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

func (s *realEWFSession) Metadata() (ewfMetadata, error) {
	meta := s.reader.Metadata()
	out := ewfMetadata{
		MajorVersion:     meta.MajorVersion,
		MinorVersion:     meta.MinorVersion,
		SegmentNumber:    meta.SegmentNumber,
		SectionCount:     meta.SectionCount,
		HasDoneSection:   meta.HasDoneSection,
		HasNextSection:   meta.HasNextSection,
		IsEncrypted:      meta.IsEncrypted,
		HasIntegrityHash: meta.HasIntegrityHashBlocks,
		HasMD5Digest:     meta.HasMD5Digest,
		HasSHA1Digest:    meta.HasSHA1Digest,
	}

	if meta.HasMD5Digest {
		out.MD5DigestHex = hex.EncodeToString(meta.MD5Digest[:])
	}
	if meta.HasSHA1Digest {
		out.SHA1DigestHex = hex.EncodeToString(meta.SHA1Digest[:])
	}
	if meta.Media != nil {
		out.HasMedia = true
		out.BytesPerSector = meta.Media.BytesPerSector
		out.SectorsPerChunk = meta.Media.SectorsPerChunk
		out.NumberOfSectors = meta.Media.NumberOfSectors
		out.NumberOfChunks = meta.Media.NumberOfChunks
		out.TotalLogicalBytes = uint64(meta.Media.BytesPerSector) * meta.Media.NumberOfSectors
	}

	return out, nil
}

func (s *realEWFSession) Close() error {
	if s == nil {
		return nil
	}

	var closeErr error
	if s.reader != nil {
		closeErr = s.reader.Close()
	}
	for _, f := range s.files {
		if fErr := f.Close(); closeErr == nil {
			closeErr = fErr
		}
	}
	return closeErr
}

func (s *realRawSession) ReadAt(offset int64, length int64) ([]byte, error) {
	if length == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	n, err := s.file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

func (s *realRawSession) Metadata() (rawMetadata, error) {
	if s == nil || s.file == nil {
		return rawMetadata{}, fmt.Errorf("raw session is not initialized")
	}
	return rawMetadata{FileSize: s.size, SectorSize: 512}, nil
}

func (s *realRawSession) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	return s.file.Close()
}

func parseEWFSegmentPaths(arg object.Object, op string) ([]string, *object.Error) {
	if pathObj, ok := arg.(*object.String); ok {
		if pathObj.Value == "" {
			return nil, newError("argument 1 to `%s` must not be empty", op)
		}
		return []string{pathObj.Value}, nil
	}

	arrObj, ok := arg.(*object.Array)
	if !ok {
		return nil, newError("argument 1 to `%s` must be STRING or ARRAY of STRING, got %s", op, arg.Type())
	}
	if len(arrObj.Elements) == 0 {
		return nil, newError("argument 1 to `%s` must not be an empty ARRAY", op)
	}

	paths := make([]string, 0, len(arrObj.Elements))
	for i, elem := range arrObj.Elements {
		s, ok := elem.(*object.String)
		if !ok {
			return nil, newError("argument 1 to `%s` index %d must be STRING, got %s", op, i, elem.Type())
		}
		if s.Value == "" {
			return nil, newError("argument 1 to `%s` index %d must not be empty", op, i)
		}
		paths = append(paths, s.Value)
	}

	return paths, nil
}

func guidBytesToString(guid [16]byte) string {
	parts := []int{4, 2, 2, 2, 6}
	buf := make([]byte, 0, 36)
	idx := 0
	for i, n := range parts {
		for j := 0; j < n; j++ {
			buf = append(buf, fmt.Sprintf("%02x", guid[idx])...)
			idx++
		}
		if i < len(parts)-1 {
			buf = append(buf, '-')
		}
	}
	return string(buf)
}

func sortedVHDIHandles() []string {
	vhdiStore.RLock()
	defer vhdiStore.RUnlock()
	keys := make([]string, 0, len(vhdiStore.handles))
	for k := range vhdiStore.handles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
