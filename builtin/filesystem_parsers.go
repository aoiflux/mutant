package builtin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libhfs "github.com/aoiflux/libhfs"
	libntfs "github.com/aoiflux/libntfs"
	libxfat "github.com/aoiflux/libxfat"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

type ntfsListEntry struct {
	Name          string
	Path          string
	EntryNum      uint64
	SequenceNum   uint16
	IsDirectory   bool
	Deleted       bool
	Size          uint64
	AllocatedSize uint64
}

type ntfsMetadata struct {
	Path          string
	Name          string
	EntryNum      uint64
	IsDirectory   bool
	Size          int64
	HasData       bool
	Resident      bool
	NonResident   bool
	Sparse        bool
	Compressed    bool
	Encrypted     bool
	Readable      bool
	BlockingError string
	CreatedAt     string
	ModifiedAt    string
	AccessedAt    string
}

type ntfsSession interface {
	ListFiles(dirPath string) ([]ntfsListEntry, error)
	ReadFile(filePath string) ([]byte, error)
	Metadata(filePath string) (ntfsMetadata, error)
	Close() error
}

type ntfsBackend interface {
	Open(volumePath string) (ntfsSession, error)
}

type realNTFSBackend struct{}

type realNTFSSession struct {
	img    *os.File
	volume *libntfs.Volume
}

type ntfsHandleState struct {
	VolumePath string
	Session    ntfsSession
}

type fatListEntry struct {
	Name             string
	Path             string
	ShortName        string
	IsDirectory      bool
	Size             uint64
	FirstCluster     uint32
	ClusterAllocated bool
	Deleted          bool
	Recovered        bool
	Virtual          bool
	Attributes       uint8
	CreatedAt        string
	ModifiedAt       string
	AccessedAt       string
}

type fatMetadata struct {
	Path           string
	Name           string
	ShortName      string
	IsDirectory    bool
	Size           int64
	FirstCluster   uint32
	Deleted        bool
	Recovered      bool
	Virtual        bool
	Attributes     uint8
	CreatedAt      string
	ModifiedAt     string
	AccessedAt     string
	FileSystem     string
	VolumeLabel    string
	ClusterCount   uint32
	ClusterSize    uint32
	BytesPerSector uint32
}

type fatSession interface {
	ListFiles(dirPath string) ([]fatListEntry, error)
	ReadFile(filePath string) ([]byte, error)
	Metadata(filePath string) (fatMetadata, error)
	Close() error
}

type fatBackend interface {
	Open(volumePath string) (fatSession, error)
}

type realFATBackend struct{}

type realFATSession struct {
	img    *os.File
	volume *libfat.Volume
}

type fatHandleState struct {
	VolumePath string
	Session    fatSession
}

type xfatListEntry struct {
	Name         string
	Path         string
	EntryCluster uint32
	Size         uint64
	IsDirectory  bool
	Deleted      bool
	Special      bool
	Virtual      bool
	Indexed      bool
	HasFATChain  bool
}

type xfatMetadata struct {
	Path         string
	Name         string
	EntryCluster uint32
	Size         uint64
	IsDirectory  bool
	Deleted      bool
	Special      bool
	Virtual      bool
	Indexed      bool
	HasFATChain  bool
	VolumeLabel  string
	ClusterSize  uint64
}

type xfatSession interface {
	ListFiles(dirPath string) ([]xfatListEntry, error)
	ReadFile(filePath string) ([]byte, error)
	Metadata(filePath string) (xfatMetadata, error)
	Close() error
}

type xfatBackend interface {
	Open(volumePath string) (xfatSession, error)
}

type realXFATBackend struct{}

type realXFATSession struct {
	img   *os.File
	fs    *libxfat.ExFAT
	cache map[string]libxfat.Entry
}

type xfatHandleState struct {
	VolumePath string
	Session    xfatSession
}

type extListEntry struct {
	Name        string
	Path        string
	Inode       uint32
	IsDirectory bool
	Size        uint64
}

type extMetadata struct {
	Path        string
	Name        string
	Inode       uint32
	IsDirectory bool
	Size        int64
	Kind        string
	BlockSize   uint32
	InodesCount uint32
}

type extSession interface {
	ListFiles(dirPath string) ([]extListEntry, error)
	ReadFile(filePath string) ([]byte, error)
	Metadata(filePath string) (extMetadata, error)
	Close() error
}

type extBackend interface {
	Open(volumePath string) (extSession, error)
}

type realEXTBackend struct{}

type realEXTSession struct {
	img *os.File
	fs  *libext.FS
}

type extHandleState struct {
	VolumePath string
	Session    extSession
}

type hfsListEntry struct {
	Name        string
	Path        string
	CNID        uint32
	IsDirectory bool
	IsSystem    bool
}

type hfsMetadata struct {
	Path        string
	Name        string
	CNID        uint32
	IsDirectory bool
	Size        int64
	Kind        string
	BlockSize   uint32
	TotalBlocks uint32
	FreeBlocks  uint32
	FileCount   uint32
	FolderCount uint32
}

type hfsSession interface {
	ListFiles(dirPath string) ([]hfsListEntry, error)
	ReadFile(filePath string) ([]byte, error)
	Metadata(filePath string) (hfsMetadata, error)
	Close() error
}

type hfsBackend interface {
	Open(volumePath string) (hfsSession, error)
}

type realHFSBackend struct{}

type realHFSSession struct {
	img    *os.File
	volume *libhfs.Volume
}

type hfsHandleState struct {
	VolumePath string
	Session    hfsSession
}

type xfsListEntry struct {
	Name        string
	Path        string
	Inode       uint64
	IsDirectory bool
	Size        uint64
}

type xfsMetadata struct {
	Path          string
	Name          string
	Inode         uint64
	IsDirectory   bool
	Size          int64
	FormatVersion uint8
	BlockSize     uint32
	InodeSize     uint16
	VolumeBlocks  uint64
	RootInode     uint64
}

type xfsSession interface {
	ListFiles(dirPath string) ([]xfsListEntry, error)
	ReadFile(filePath string) ([]byte, error)
	Metadata(filePath string) (xfsMetadata, error)
	Close() error
}

type xfsBackend interface {
	Open(volumePath string) (xfsSession, error)
}

type realXFSBackend struct{}

type realXFSSession struct {
	volume *libxfs.Volume
}

type xfsHandleState struct {
	VolumePath string
	Session    xfsSession
}

var ntfsStore = struct {
	sync.RWMutex
	nextID  int64
	backend ntfsBackend
	handles map[string]ntfsHandleState
}{
	backend: realNTFSBackend{},
	handles: map[string]ntfsHandleState{},
}

var fatStore = struct {
	sync.RWMutex
	nextID  int64
	backend fatBackend
	handles map[string]fatHandleState
}{
	backend: realFATBackend{},
	handles: map[string]fatHandleState{},
}

var xfatStore = struct {
	sync.RWMutex
	nextID  int64
	backend xfatBackend
	handles map[string]xfatHandleState
}{
	backend: realXFATBackend{},
	handles: map[string]xfatHandleState{},
}

var extStore = struct {
	sync.RWMutex
	nextID  int64
	backend extBackend
	handles map[string]extHandleState
}{
	backend: realEXTBackend{},
	handles: map[string]extHandleState{},
}

var hfsStore = struct {
	sync.RWMutex
	nextID  int64
	backend hfsBackend
	handles map[string]hfsHandleState
}{
	backend: realHFSBackend{},
	handles: map[string]hfsHandleState{},
}

var xfsStore = struct {
	sync.RWMutex
	nextID  int64
	backend xfsBackend
	handles map[string]xfsHandleState
}{
	backend: realXFSBackend{},
	handles: map[string]xfsHandleState{},
}

func NtfsOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	volumePathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `ntfs_open` must be STRING, got %s", args[0].Type()))
	}

	ntfsStore.RLock()
	backend := ntfsStore.backend
	ntfsStore.RUnlock()

	session, err := backend.Open(volumePathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ntfs_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&ntfsStore.nextID, 1)
	handle := fmt.Sprintf("ntfs-handle-%d", handleID)

	ntfsStore.Lock()
	ntfsStore.handles[handle] = ntfsHandleState{
		VolumePath: volumePathObj.Value,
		Session:    session,
	}
	ntfsStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(volumePathObj.Value),
		"status": stringObj("ok"),
	}), nil)
}

func NtfsListFiles(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveNTFSHandle(args[0], "ntfs_list_files")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `ntfs_list_files` must be STRING, got %s", args[1].Type()))
	}

	entries, err := state.Session.ListFiles(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ntfs_list_files: %s", err.Error()))
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Path < entries[j].Path
	})

	items := make([]object.Object, 0, len(entries))
	for _, entry := range entries {
		items = append(items, makeHashObject(map[string]object.Object{
			"name":           stringObj(entry.Name),
			"path":           stringObj(entry.Path),
			"entry_num":      intObj(int64(entry.EntryNum)),
			"sequence_num":   intObj(int64(entry.SequenceNum)),
			"is_dir":         boolObj(entry.IsDirectory),
			"deleted":        boolObj(entry.Deleted),
			"size":           intObj(int64(entry.Size)),
			"allocated_size": intObj(int64(entry.AllocatedSize)),
		}))
	}

	return resultAndError(&object.Array{Elements: items}, nil)
}

func NtfsReadFile(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveNTFSHandle(args[0], "ntfs_read_file")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `ntfs_read_file` must be STRING, got %s", args[1].Type()))
	}

	content, err := state.Session.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ntfs_read_file: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func NtfsMetadata(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveNTFSHandle(args[0], "ntfs_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `ntfs_metadata` must be STRING, got %s", args[1].Type()))
	}

	metadata, err := state.Session.Metadata(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ntfs_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":           stringObj(metadata.Path),
		"name":           stringObj(metadata.Name),
		"entry_num":      intObj(int64(metadata.EntryNum)),
		"is_dir":         boolObj(metadata.IsDirectory),
		"size":           intObj(metadata.Size),
		"has_data":       boolObj(metadata.HasData),
		"resident":       boolObj(metadata.Resident),
		"non_resident":   boolObj(metadata.NonResident),
		"sparse":         boolObj(metadata.Sparse),
		"compressed":     boolObj(metadata.Compressed),
		"encrypted":      boolObj(metadata.Encrypted),
		"readable":       boolObj(metadata.Readable),
		"blocking_error": stringObj(metadata.BlockingError),
		"created_at":     stringObj(metadata.CreatedAt),
		"modified_at":    stringObj(metadata.ModifiedAt),
		"accessed_at":    stringObj(metadata.AccessedAt),
	}), nil)
}

func NtfsClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `ntfs_close` must be STRING handle, got %s", args[0].Type()))
	}

	ntfsStore.Lock()
	state, exists := ntfsStore.handles[handleObj.Value]
	if exists {
		delete(ntfsStore.handles, handleObj.Value)
	}
	ntfsStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("ntfs_close: unknown ntfs handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("ntfs_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func FatOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	volumePathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fat_open` must be STRING, got %s", args[0].Type()))
	}

	fatStore.RLock()
	backend := fatStore.backend
	fatStore.RUnlock()

	session, err := backend.Open(volumePathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fat_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&fatStore.nextID, 1)
	handle := fmt.Sprintf("fat-handle-%d", handleID)

	fatStore.Lock()
	fatStore.handles[handle] = fatHandleState{
		VolumePath: volumePathObj.Value,
		Session:    session,
	}
	fatStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(volumePathObj.Value),
		"status": stringObj("ok"),
	}), nil)
}

func FatListFiles(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveFATHandle(args[0], "fat_list_files")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fat_list_files` must be STRING, got %s", args[1].Type()))
	}

	entries, err := state.Session.ListFiles(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fat_list_files: %s", err.Error()))
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Path < entries[j].Path
	})

	items := make([]object.Object, 0, len(entries))
	for _, entry := range entries {
		items = append(items, makeHashObject(map[string]object.Object{
			"name":              stringObj(entry.Name),
			"path":              stringObj(entry.Path),
			"short_name":        stringObj(entry.ShortName),
			"is_dir":            boolObj(entry.IsDirectory),
			"size":              intObj(int64(entry.Size)),
			"first_cluster":     intObj(int64(entry.FirstCluster)),
			"cluster_allocated": boolObj(entry.ClusterAllocated),
			"deleted":           boolObj(entry.Deleted),
			"recovered":         boolObj(entry.Recovered),
			"virtual":           boolObj(entry.Virtual),
			"attributes":        intObj(int64(entry.Attributes)),
			"created_at":        stringObj(entry.CreatedAt),
			"modified_at":       stringObj(entry.ModifiedAt),
			"accessed_at":       stringObj(entry.AccessedAt),
		}))
	}

	return resultAndError(&object.Array{Elements: items}, nil)
}

func FatReadFile(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveFATHandle(args[0], "fat_read_file")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fat_read_file` must be STRING, got %s", args[1].Type()))
	}

	content, err := state.Session.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fat_read_file: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func FatMetadata(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveFATHandle(args[0], "fat_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fat_metadata` must be STRING, got %s", args[1].Type()))
	}

	metadata, err := state.Session.Metadata(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fat_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":             stringObj(metadata.Path),
		"name":             stringObj(metadata.Name),
		"short_name":       stringObj(metadata.ShortName),
		"is_dir":           boolObj(metadata.IsDirectory),
		"size":             intObj(metadata.Size),
		"first_cluster":    intObj(int64(metadata.FirstCluster)),
		"deleted":          boolObj(metadata.Deleted),
		"recovered":        boolObj(metadata.Recovered),
		"virtual":          boolObj(metadata.Virtual),
		"attributes":       intObj(int64(metadata.Attributes)),
		"created_at":       stringObj(metadata.CreatedAt),
		"modified_at":      stringObj(metadata.ModifiedAt),
		"accessed_at":      stringObj(metadata.AccessedAt),
		"filesystem":       stringObj(metadata.FileSystem),
		"volume_label":     stringObj(metadata.VolumeLabel),
		"cluster_count":    intObj(int64(metadata.ClusterCount)),
		"cluster_size":     intObj(int64(metadata.ClusterSize)),
		"bytes_per_sector": intObj(int64(metadata.BytesPerSector)),
	}), nil)
}

func FatClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fat_close` must be STRING handle, got %s", args[0].Type()))
	}

	fatStore.Lock()
	state, exists := fatStore.handles[handleObj.Value]
	if exists {
		delete(fatStore.handles, handleObj.Value)
	}
	fatStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("fat_close: unknown fat handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("fat_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func XFATOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	volumePathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `xfat_open` must be STRING, got %s", args[0].Type()))
	}

	xfatStore.RLock()
	backend := xfatStore.backend
	xfatStore.RUnlock()

	session, err := backend.Open(volumePathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("xfat_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&xfatStore.nextID, 1)
	handle := fmt.Sprintf("xfat-handle-%d", handleID)

	xfatStore.Lock()
	xfatStore.handles[handle] = xfatHandleState{
		VolumePath: volumePathObj.Value,
		Session:    session,
	}
	xfatStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(volumePathObj.Value),
		"status": stringObj("ok"),
	}), nil)
}

func XFATListFiles(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveXFATHandle(args[0], "xfat_list_files")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `xfat_list_files` must be STRING, got %s", args[1].Type()))
	}

	entries, err := state.Session.ListFiles(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("xfat_list_files: %s", err.Error()))
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Path < entries[j].Path
	})

	items := make([]object.Object, 0, len(entries))
	for _, entry := range entries {
		items = append(items, makeHashObject(map[string]object.Object{
			"name":          stringObj(entry.Name),
			"path":          stringObj(entry.Path),
			"entry_cluster": intObj(int64(entry.EntryCluster)),
			"size":          intObj(int64(entry.Size)),
			"is_dir":        boolObj(entry.IsDirectory),
			"deleted":       boolObj(entry.Deleted),
			"special":       boolObj(entry.Special),
			"virtual":       boolObj(entry.Virtual),
			"indexed":       boolObj(entry.Indexed),
			"has_fat_chain": boolObj(entry.HasFATChain),
		}))
	}

	return resultAndError(&object.Array{Elements: items}, nil)
}

func XFATReadFile(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveXFATHandle(args[0], "xfat_read_file")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `xfat_read_file` must be STRING, got %s", args[1].Type()))
	}

	content, err := state.Session.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("xfat_read_file: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func XFATMetadata(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveXFATHandle(args[0], "xfat_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `xfat_metadata` must be STRING, got %s", args[1].Type()))
	}

	metadata, err := state.Session.Metadata(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("xfat_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":          stringObj(metadata.Path),
		"name":          stringObj(metadata.Name),
		"entry_cluster": intObj(int64(metadata.EntryCluster)),
		"size":          intObj(int64(metadata.Size)),
		"is_dir":        boolObj(metadata.IsDirectory),
		"deleted":       boolObj(metadata.Deleted),
		"special":       boolObj(metadata.Special),
		"virtual":       boolObj(metadata.Virtual),
		"indexed":       boolObj(metadata.Indexed),
		"has_fat_chain": boolObj(metadata.HasFATChain),
		"volume_label":  stringObj(metadata.VolumeLabel),
		"cluster_size":  intObj(int64(metadata.ClusterSize)),
	}), nil)
}

func XFATClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `xfat_close` must be STRING handle, got %s", args[0].Type()))
	}

	xfatStore.Lock()
	state, exists := xfatStore.handles[handleObj.Value]
	if exists {
		delete(xfatStore.handles, handleObj.Value)
	}
	xfatStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("xfat_close: unknown xfat handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("xfat_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func ExtOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	volumePathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `ext_open` must be STRING, got %s", args[0].Type()))
	}

	extStore.RLock()
	backend := extStore.backend
	extStore.RUnlock()

	session, err := backend.Open(volumePathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ext_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&extStore.nextID, 1)
	handle := fmt.Sprintf("ext-handle-%d", handleID)

	extStore.Lock()
	extStore.handles[handle] = extHandleState{
		VolumePath: volumePathObj.Value,
		Session:    session,
	}
	extStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(volumePathObj.Value),
		"status": stringObj("ok"),
	}), nil)
}

func ExtListFiles(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveEXTHandle(args[0], "ext_list_files")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `ext_list_files` must be STRING, got %s", args[1].Type()))
	}

	entries, err := state.Session.ListFiles(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ext_list_files: %s", err.Error()))
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Path < entries[j].Path
	})

	items := make([]object.Object, 0, len(entries))
	for _, entry := range entries {
		items = append(items, makeHashObject(map[string]object.Object{
			"name":   stringObj(entry.Name),
			"path":   stringObj(entry.Path),
			"inode":  intObj(int64(entry.Inode)),
			"is_dir": boolObj(entry.IsDirectory),
			"size":   intObj(int64(entry.Size)),
		}))
	}

	return resultAndError(&object.Array{Elements: items}, nil)
}

func ExtReadFile(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveEXTHandle(args[0], "ext_read_file")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `ext_read_file` must be STRING, got %s", args[1].Type()))
	}

	content, err := state.Session.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ext_read_file: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func ExtMetadata(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveEXTHandle(args[0], "ext_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `ext_metadata` must be STRING, got %s", args[1].Type()))
	}

	metadata, err := state.Session.Metadata(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ext_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":         stringObj(metadata.Path),
		"name":         stringObj(metadata.Name),
		"inode":        intObj(int64(metadata.Inode)),
		"is_dir":       boolObj(metadata.IsDirectory),
		"size":         intObj(metadata.Size),
		"kind":         stringObj(metadata.Kind),
		"block_size":   intObj(int64(metadata.BlockSize)),
		"inodes_count": intObj(int64(metadata.InodesCount)),
	}), nil)
}

func ExtClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `ext_close` must be STRING handle, got %s", args[0].Type()))
	}

	extStore.Lock()
	state, exists := extStore.handles[handleObj.Value]
	if exists {
		delete(extStore.handles, handleObj.Value)
	}
	extStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("ext_close: unknown ext handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("ext_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func HFSOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	volumePathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `hfs_open` must be STRING, got %s", args[0].Type()))
	}

	hfsStore.RLock()
	backend := hfsStore.backend
	hfsStore.RUnlock()

	session, err := backend.Open(volumePathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("hfs_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&hfsStore.nextID, 1)
	handle := fmt.Sprintf("hfs-handle-%d", handleID)

	hfsStore.Lock()
	hfsStore.handles[handle] = hfsHandleState{
		VolumePath: volumePathObj.Value,
		Session:    session,
	}
	hfsStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(volumePathObj.Value),
		"status": stringObj("ok"),
	}), nil)
}

func HFSListFiles(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveHFSHandle(args[0], "hfs_list_files")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `hfs_list_files` must be STRING, got %s", args[1].Type()))
	}

	entries, err := state.Session.ListFiles(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("hfs_list_files: %s", err.Error()))
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Path < entries[j].Path
	})

	items := make([]object.Object, 0, len(entries))
	for _, entry := range entries {
		items = append(items, makeHashObject(map[string]object.Object{
			"name":      stringObj(entry.Name),
			"path":      stringObj(entry.Path),
			"cnid":      intObj(int64(entry.CNID)),
			"is_dir":    boolObj(entry.IsDirectory),
			"is_system": boolObj(entry.IsSystem),
		}))
	}

	return resultAndError(&object.Array{Elements: items}, nil)
}

func HFSReadFile(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveHFSHandle(args[0], "hfs_read_file")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `hfs_read_file` must be STRING, got %s", args[1].Type()))
	}

	content, err := state.Session.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("hfs_read_file: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func HFSMetadata(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveHFSHandle(args[0], "hfs_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `hfs_metadata` must be STRING, got %s", args[1].Type()))
	}

	metadata, err := state.Session.Metadata(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("hfs_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":         stringObj(metadata.Path),
		"name":         stringObj(metadata.Name),
		"cnid":         intObj(int64(metadata.CNID)),
		"is_dir":       boolObj(metadata.IsDirectory),
		"size":         intObj(metadata.Size),
		"kind":         stringObj(metadata.Kind),
		"block_size":   intObj(int64(metadata.BlockSize)),
		"total_blocks": intObj(int64(metadata.TotalBlocks)),
		"free_blocks":  intObj(int64(metadata.FreeBlocks)),
		"file_count":   intObj(int64(metadata.FileCount)),
		"folder_count": intObj(int64(metadata.FolderCount)),
	}), nil)
}

func HFSClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `hfs_close` must be STRING handle, got %s", args[0].Type()))
	}

	hfsStore.Lock()
	state, exists := hfsStore.handles[handleObj.Value]
	if exists {
		delete(hfsStore.handles, handleObj.Value)
	}
	hfsStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("hfs_close: unknown hfs handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("hfs_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func XFSOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	volumePathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `xfs_open` must be STRING, got %s", args[0].Type()))
	}

	xfsStore.RLock()
	backend := xfsStore.backend
	xfsStore.RUnlock()

	session, err := backend.Open(volumePathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("xfs_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&xfsStore.nextID, 1)
	handle := fmt.Sprintf("xfs-handle-%d", handleID)

	xfsStore.Lock()
	xfsStore.handles[handle] = xfsHandleState{
		VolumePath: volumePathObj.Value,
		Session:    session,
	}
	xfsStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"path":   stringObj(volumePathObj.Value),
		"status": stringObj("ok"),
	}), nil)
}

func XFSListFiles(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveXFSHandle(args[0], "xfs_list_files")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `xfs_list_files` must be STRING, got %s", args[1].Type()))
	}

	entries, err := state.Session.ListFiles(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("xfs_list_files: %s", err.Error()))
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Path < entries[j].Path
	})

	items := make([]object.Object, 0, len(entries))
	for _, entry := range entries {
		items = append(items, makeHashObject(map[string]object.Object{
			"name":   stringObj(entry.Name),
			"path":   stringObj(entry.Path),
			"inode":  intObj(int64(entry.Inode)),
			"is_dir": boolObj(entry.IsDirectory),
			"size":   intObj(int64(entry.Size)),
		}))
	}

	return resultAndError(&object.Array{Elements: items}, nil)
}

func XFSReadFile(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveXFSHandle(args[0], "xfs_read_file")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `xfs_read_file` must be STRING, got %s", args[1].Type()))
	}

	content, err := state.Session.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("xfs_read_file: %s", err.Error()))
	}

	return resultAndError(stringObj(string(content)), nil)
}

func XFSMetadata(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveXFSHandle(args[0], "xfs_metadata")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `xfs_metadata` must be STRING, got %s", args[1].Type()))
	}

	metadata, err := state.Session.Metadata(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("xfs_metadata: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":           stringObj(metadata.Path),
		"name":           stringObj(metadata.Name),
		"inode":          intObj(int64(metadata.Inode)),
		"is_dir":         boolObj(metadata.IsDirectory),
		"size":           intObj(metadata.Size),
		"format_version": intObj(int64(metadata.FormatVersion)),
		"block_size":     intObj(int64(metadata.BlockSize)),
		"inode_size":     intObj(int64(metadata.InodeSize)),
		"volume_blocks":  intObj(int64(metadata.VolumeBlocks)),
		"root_inode":     intObj(int64(metadata.RootInode)),
	}), nil)
}

func XFSClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `xfs_close` must be STRING handle, got %s", args[0].Type()))
	}

	xfsStore.Lock()
	state, exists := xfsStore.handles[handleObj.Value]
	if exists {
		delete(xfsStore.handles, handleObj.Value)
	}
	xfsStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("xfs_close: unknown xfs handle: %s", handleObj.Value))
	}

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("xfs_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func resolveNTFSHandle(arg object.Object, op string) (ntfsHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return ntfsHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	ntfsStore.RLock()
	state, exists := ntfsStore.handles[handleObj.Value]
	ntfsStore.RUnlock()
	if !exists {
		return ntfsHandleState{}, newError("%s: unknown ntfs handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func resolveFATHandle(arg object.Object, op string) (fatHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return fatHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	fatStore.RLock()
	state, exists := fatStore.handles[handleObj.Value]
	fatStore.RUnlock()
	if !exists {
		return fatHandleState{}, newError("%s: unknown fat handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func resolveXFATHandle(arg object.Object, op string) (xfatHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return xfatHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	xfatStore.RLock()
	state, exists := xfatStore.handles[handleObj.Value]
	xfatStore.RUnlock()
	if !exists {
		return xfatHandleState{}, newError("%s: unknown xfat handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func resolveEXTHandle(arg object.Object, op string) (extHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return extHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	extStore.RLock()
	state, exists := extStore.handles[handleObj.Value]
	extStore.RUnlock()
	if !exists {
		return extHandleState{}, newError("%s: unknown ext handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func resolveHFSHandle(arg object.Object, op string) (hfsHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return hfsHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	hfsStore.RLock()
	state, exists := hfsStore.handles[handleObj.Value]
	hfsStore.RUnlock()
	if !exists {
		return hfsHandleState{}, newError("%s: unknown hfs handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func resolveXFSHandle(arg object.Object, op string) (xfsHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return xfsHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", op, arg.Type())
	}

	xfsStore.RLock()
	state, exists := xfsStore.handles[handleObj.Value]
	xfsStore.RUnlock()
	if !exists {
		return xfsHandleState{}, newError("%s: unknown xfs handle: %s", op, handleObj.Value)
	}

	return state, nil
}

func (realNTFSBackend) Open(volumePath string) (ntfsSession, error) {
	img, err := os.Open(volumePath)
	if err != nil {
		return nil, err
	}

	volume, err := libntfs.Open(img)
	if err != nil {
		_ = img.Close()
		return nil, err
	}

	return &realNTFSSession{img: img, volume: volume}, nil
}

func (realFATBackend) Open(volumePath string) (fatSession, error) {
	img, err := os.Open(volumePath)
	if err != nil {
		return nil, err
	}

	volume, err := libfat.Open(img)
	if err != nil {
		_ = img.Close()
		return nil, err
	}

	return &realFATSession{img: img, volume: volume}, nil
}

func (realXFATBackend) Open(volumePath string) (xfatSession, error) {
	img, err := os.Open(volumePath)
	if err != nil {
		return nil, err
	}

	fs, err := libxfat.New(img, false)
	if err != nil {
		_ = img.Close()
		return nil, err
	}

	return &realXFATSession{img: img, fs: &fs, cache: map[string]libxfat.Entry{}}, nil
}

func (realEXTBackend) Open(volumePath string) (extSession, error) {
	img, err := os.Open(volumePath)
	if err != nil {
		return nil, err
	}

	fs, err := libext.Open(img)
	if err != nil {
		_ = img.Close()
		return nil, err
	}

	return &realEXTSession{img: img, fs: fs}, nil
}

func (realHFSBackend) Open(volumePath string) (hfsSession, error) {
	img, err := os.Open(volumePath)
	if err != nil {
		return nil, err
	}

	volume, err := libhfs.Open(img)
	if err != nil {
		_ = img.Close()
		return nil, err
	}

	return &realHFSSession{img: img, volume: volume}, nil
}

func (realXFSBackend) Open(volumePath string) (xfsSession, error) {
	volume, err := libxfs.OpenVolumeFromPath(volumePath)
	if err != nil {
		return nil, err
	}

	return &realXFSSession{volume: volume}, nil
}

func (s *realNTFSSession) ListFiles(dirPath string) ([]ntfsListEntry, error) {
	cleanPath := normalizeNTFSPath(dirPath)

	dir, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return nil, err
	}
	if !dir.IsDirectory() {
		return nil, errors.New("target path is not a directory")
	}

	entries, err := dir.ReadDir()
	if err != nil {
		return nil, err
	}

	out := make([]ntfsListEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, ntfsListEntry{
			Name:          entry.Name,
			Path:          joinNTFSPath(cleanPath, entry.Name),
			EntryNum:      entry.EntryNum,
			SequenceNum:   entry.SequenceNum,
			IsDirectory:   entry.IsDirectory,
			Deleted:       entry.Deleted,
			Size:          entry.Size,
			AllocatedSize: entry.AllocatedSize,
		})
	}

	return out, nil
}

func (s *realFATSession) ListFiles(dirPath string) ([]fatListEntry, error) {
	cleanPath := normalizeFATPath(dirPath)

	dir, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return nil, err
	}
	if !dir.IsDirectory() {
		return nil, errors.New("target path is not a directory")
	}

	entries, err := dir.ReadDir()
	if err != nil {
		return nil, err
	}

	out := make([]fatListEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, fatListEntry{
			Name:             entry.Name,
			Path:             entry.Path,
			ShortName:        entry.ShortName,
			IsDirectory:      entry.IsDirectory,
			Size:             entry.Size,
			FirstCluster:     entry.FirstCluster,
			ClusterAllocated: entry.ClusterAllocated,
			Deleted:          entry.Deleted,
			Recovered:        entry.Recovered,
			Virtual:          entry.Virtual,
			Attributes:       entry.Attributes,
			CreatedAt:        formatTime(entry.CreatedAt),
			ModifiedAt:       formatTime(entry.ModifiedAt),
			AccessedAt:       formatTime(entry.AccessedAt),
		})
	}

	return out, nil
}

func (s *realXFATSession) ListFiles(dirPath string) ([]xfatListEntry, error) {
	cleanPath := normalizeXFATPath(dirPath)

	entries, err := s.readDirAtPath(cleanPath)
	if err != nil {
		return nil, err
	}

	out := make([]xfatListEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.GetName()
		out = append(out, xfatListEntry{
			Name:         name,
			Path:         joinXFATPath(cleanPath, name),
			EntryCluster: entry.GetEntryCluster(),
			Size:         entry.GetSize(),
			IsDirectory:  entry.IsDir(),
			Deleted:      entry.IsDeleted(),
			Special:      entry.IsSpecialFile(),
			Virtual:      entry.IsVirtualEntry(),
			Indexed:      entry.IsIndexed(),
			HasFATChain:  entry.HasFatChain(),
		})
	}

	return out, nil
}

func (s *realEXTSession) ListFiles(dirPath string) ([]extListEntry, error) {
	cleanPath := normalizeEXTPath(dirPath)

	dir, err := s.fs.OpenPath(cleanPath)
	if err != nil {
		return nil, err
	}
	if !dir.IsDirectory() {
		return nil, errors.New("target path is not a directory")
	}

	entries, err := dir.ReadDir()
	if err != nil {
		return nil, err
	}

	out := make([]extListEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name == "." || entry.Name == ".." {
			continue
		}
		out = append(out, extListEntry{
			Name:        entry.Name,
			Path:        joinEXTPath(cleanPath, entry.Name),
			Inode:       entry.Inode,
			IsDirectory: entry.IsDirectory,
			Size:        entry.Size,
		})
	}

	return out, nil
}

func (s *realHFSSession) ListFiles(dirPath string) ([]hfsListEntry, error) {
	cleanPath := normalizeHFSPath(dirPath)

	entries, err := s.volume.ReadDir(cleanPath)
	if err != nil {
		return nil, err
	}

	out := make([]hfsListEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name == "" {
			continue
		}
		out = append(out, hfsListEntry{
			Name:        entry.Name,
			Path:        joinHFSPath(cleanPath, entry.Name),
			CNID:        entry.CNID,
			IsDirectory: entry.IsDirectory,
			IsSystem:    entry.IsSystem,
		})
	}

	return out, nil
}

func (s *realXFSSession) ListFiles(dirPath string) ([]xfsListEntry, error) {
	cleanPath := normalizeXFSPath(dirPath)

	entries, err := s.volume.ListDirectoryEntriesByPath(cleanPath)
	if err != nil {
		return nil, err
	}

	out := make([]xfsListEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name == "." || entry.Name == ".." || entry.Name == "" {
			continue
		}

		inode, inodeErr := s.volume.OpenInode(entry.InodeNumber)
		if inodeErr != nil {
			return nil, inodeErr
		}

		out = append(out, xfsListEntry{
			Name:        entry.Name,
			Path:        joinXFSPath(cleanPath, entry.Name),
			Inode:       entry.InodeNumber,
			IsDirectory: inode.IsDirectory(),
			Size:        inode.Size,
		})
	}

	return out, nil
}

func (s *realNTFSSession) ReadFile(filePath string) ([]byte, error) {
	cleanPath := normalizeNTFSPath(filePath)

	f, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return nil, err
	}
	if f.IsDirectory() {
		return nil, errors.New("target path is a directory")
	}

	return f.ReadAll()
}

func (s *realFATSession) ReadFile(filePath string) ([]byte, error) {
	cleanPath := normalizeFATPath(filePath)

	f, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return nil, err
	}
	if f.IsDirectory() {
		return nil, errors.New("target path is a directory")
	}

	return f.ReadAll()
}

func (s *realXFATSession) ReadFile(filePath string) ([]byte, error) {
	cleanPath := normalizeXFATPath(filePath)
	entry, err := s.findEntryByPath(cleanPath)
	if err != nil {
		return nil, err
	}
	if entry.IsDir() {
		return nil, errors.New("target path is a directory")
	}

	tmpFile, err := os.CreateTemp("", "mutant-xfat-read-*.bin")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := s.fs.ExtractEntryContent(entry, tmpPath); err != nil {
		return nil, err
	}

	return os.ReadFile(tmpPath)
}

func (s *realEXTSession) ReadFile(filePath string) ([]byte, error) {
	cleanPath := normalizeEXTPath(filePath)

	f, err := s.fs.OpenPath(cleanPath)
	if err != nil {
		return nil, err
	}
	if f.IsDirectory() {
		return nil, errors.New("target path is a directory")
	}

	return f.ReadAll()
}

func (s *realHFSSession) ReadFile(filePath string) ([]byte, error) {
	cleanPath := normalizeHFSPath(filePath)

	f, err := s.volume.OpenFileByPath(cleanPath)
	if err != nil {
		return nil, err
	}

	return f.ReadAll()
}

func (s *realXFSSession) ReadFile(filePath string) ([]byte, error) {
	cleanPath := normalizeXFSPath(filePath)
	return s.volume.ReadFileDataByPath(cleanPath)
}

func (s *realNTFSSession) Metadata(filePath string) (ntfsMetadata, error) {
	cleanPath := normalizeNTFSPath(filePath)

	f, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return ntfsMetadata{}, err
	}

	support := f.ReadSupport()
	md := ntfsMetadata{
		Path:          cleanPath,
		Name:          f.Name(),
		EntryNum:      f.EntryNumber(),
		IsDirectory:   f.IsDirectory(),
		Size:          f.Size(),
		HasData:       support.HasData,
		Resident:      support.Resident,
		NonResident:   support.NonResident,
		Sparse:        support.Sparse,
		Compressed:    support.Compressed,
		Encrypted:     support.Encrypted,
		Readable:      support.Readable,
		BlockingError: errorString(support.BlockingError),
	}

	if stdInfo, stdErr := f.GetMetadata(); stdErr == nil {
		md.CreatedAt = extractTimeField(stdInfo, "CreationTime", "CreatedAt", "Created")
		md.ModifiedAt = extractTimeField(stdInfo, "ModificationTime", "ModifiedAt", "LastWriteTime", "Modified")
		md.AccessedAt = extractTimeField(stdInfo, "AccessTime", "AccessedAt", "Accessed")
	}

	return md, nil
}

func (s *realFATSession) Metadata(filePath string) (fatMetadata, error) {
	cleanPath := normalizeFATPath(filePath)

	f, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fatMetadata{}, err
	}
	entry := f.Entry()

	return fatMetadata{
		Path:           cleanPath,
		Name:           f.Name(),
		ShortName:      entry.ShortName,
		IsDirectory:    f.IsDirectory(),
		Size:           f.Size(),
		FirstCluster:   entry.FirstCluster,
		Deleted:        entry.Deleted,
		Recovered:      entry.Recovered,
		Virtual:        entry.Virtual,
		Attributes:     entry.Attributes,
		CreatedAt:      formatTime(entry.CreatedAt),
		ModifiedAt:     formatTime(entry.ModifiedAt),
		AccessedAt:     formatTime(entry.AccessedAt),
		FileSystem:     s.volume.FATType(),
		VolumeLabel:    s.volume.VolumeLabel(),
		ClusterCount:   s.volume.ClusterCount(),
		ClusterSize:    s.volume.BytesPerCluster(),
		BytesPerSector: s.volume.BytesPerSector(),
	}, nil
}

func (s *realXFATSession) Metadata(filePath string) (xfatMetadata, error) {
	cleanPath := normalizeXFATPath(filePath)
	entry, err := s.findEntryByPath(cleanPath)
	if err != nil {
		return xfatMetadata{}, err
	}

	return xfatMetadata{
		Path:         cleanPath,
		Name:         entry.GetName(),
		EntryCluster: entry.GetEntryCluster(),
		Size:         entry.GetSize(),
		IsDirectory:  entry.IsDir(),
		Deleted:      entry.IsDeleted(),
		Special:      entry.IsSpecialFile(),
		Virtual:      entry.IsVirtualEntry(),
		Indexed:      entry.IsIndexed(),
		HasFATChain:  entry.HasFatChain(),
		VolumeLabel:  s.fs.GetVolumeLabel(),
		ClusterSize:  s.fs.GetClusterSize(),
	}, nil
}

func (s *realEXTSession) Metadata(filePath string) (extMetadata, error) {
	cleanPath := normalizeEXTPath(filePath)

	f, err := s.fs.OpenPath(cleanPath)
	if err != nil {
		return extMetadata{}, err
	}

	sb := s.fs.Superblock()

	return extMetadata{
		Path:        cleanPath,
		Name:        f.Name(),
		Inode:       f.InodeNumber(),
		IsDirectory: f.IsDirectory(),
		Size:        f.Size(),
		Kind:        string(s.fs.Kind()),
		BlockSize:   sb.BlockSize,
		InodesCount: sb.InodesCount,
	}, nil
}

func (s *realHFSSession) Metadata(filePath string) (hfsMetadata, error) {
	cleanPath := normalizeHFSPath(filePath)

	rec, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return hfsMetadata{}, err
	}

	hdr := s.volume.Header()
	size := int64(0)
	if !rec.IsDirectory() {
		f, openErr := s.volume.OpenFileByPath(cleanPath)
		if openErr != nil {
			return hfsMetadata{}, openErr
		}
		size = f.Size()
	}

	return hfsMetadata{
		Path:        cleanPath,
		Name:        rec.Name,
		CNID:        rec.CNID,
		IsDirectory: rec.IsDirectory(),
		Size:        size,
		Kind:        string(s.volume.Kind()),
		BlockSize:   hdr.BlockSize,
		TotalBlocks: hdr.TotalBlocks,
		FreeBlocks:  hdr.FreeBlocks,
		FileCount:   hdr.FileCount,
		FolderCount: hdr.FolderCount,
	}, nil
}

func (s *realXFSSession) Metadata(filePath string) (xfsMetadata, error) {
	cleanPath := normalizeXFSPath(filePath)

	inodeNumber, err := s.volume.ResolveInodeByPath(cleanPath)
	if err != nil {
		return xfsMetadata{}, err
	}

	inode, err := s.volume.OpenInode(inodeNumber)
	if err != nil {
		return xfsMetadata{}, err
	}

	sb := s.volume.Superblock()
	name := path.Base(cleanPath)
	if cleanPath == "/" {
		name = "/"
	}

	return xfsMetadata{
		Path:          cleanPath,
		Name:          name,
		Inode:         inodeNumber,
		IsDirectory:   inode.IsDirectory(),
		Size:          int64(inode.Size),
		FormatVersion: sb.FormatVersion,
		BlockSize:     sb.BlockSize,
		InodeSize:     sb.InodeSize,
		VolumeBlocks:  sb.NumberOfBlocks,
		RootInode:     sb.RootDirectoryInodeNumber,
	}, nil
}

func (s *realNTFSSession) Close() error {
	if s == nil {
		return nil
	}
	if s.volume != nil {
		_ = s.volume.Close()
	}
	if s.img != nil {
		return s.img.Close()
	}
	return nil
}

func (s *realFATSession) Close() error {
	if s == nil {
		return nil
	}
	if s.volume != nil {
		_ = s.volume.Close()
	}
	if s.img != nil {
		return s.img.Close()
	}
	return nil
}

func (s *realXFATSession) Close() error {
	if s == nil {
		return nil
	}
	if s.img != nil {
		return s.img.Close()
	}
	return nil
}

func (s *realEXTSession) Close() error {
	if s == nil {
		return nil
	}
	if s.fs != nil {
		_ = s.fs.Close()
	}
	if s.img != nil {
		return s.img.Close()
	}
	return nil
}

func (s *realHFSSession) Close() error {
	if s == nil {
		return nil
	}
	if s.volume != nil {
		_ = s.volume.Close()
	}
	if s.img != nil {
		return s.img.Close()
	}
	return nil
}

func (s *realXFSSession) Close() error {
	if s == nil {
		return nil
	}
	if s.volume != nil {
		return s.volume.Close()
	}
	return nil
}

func (s *realXFATSession) readDirAtPath(dirPath string) ([]libxfat.Entry, error) {
	if dirPath == "/" {
		return s.fs.ReadRootDir()
	}
	entry, err := s.findEntryByPath(dirPath)
	if err != nil {
		return nil, err
	}
	if !entry.IsDir() {
		return nil, errors.New("target path is not a directory")
	}
	return s.fs.ReadDir(entry)
}

func (s *realXFATSession) findEntryByPath(targetPath string) (libxfat.Entry, error) {
	if s.cache == nil {
		s.cache = map[string]libxfat.Entry{}
	}
	if entry, ok := s.cache[targetPath]; ok {
		return entry, nil
	}

	if targetPath == "/" {
		return libxfat.Entry{}, errors.New("root path does not map to a single entry")
	}

	parts := strings.Split(strings.Trim(targetPath, "/"), "/")
	currentEntries, err := s.fs.ReadRootDir()
	if err != nil {
		return libxfat.Entry{}, err
	}

	for i, part := range parts {
		match, found := xfatFindEntryByName(currentEntries, part)
		if !found {
			return libxfat.Entry{}, fmt.Errorf("entry not found: %s", targetPath)
		}

		matchedPath := "/" + strings.Join(parts[:i+1], "/")
		s.cache[matchedPath] = match

		if i == len(parts)-1 {
			return match, nil
		}

		if !match.IsDir() {
			return libxfat.Entry{}, fmt.Errorf("path segment is not a directory: %s", matchedPath)
		}

		nextEntries, nextErr := s.fs.ReadDir(match)
		if nextErr != nil && !errors.Is(nextErr, io.EOF) {
			return libxfat.Entry{}, nextErr
		}
		currentEntries = nextEntries
	}

	return libxfat.Entry{}, fmt.Errorf("entry not found: %s", targetPath)
}

func xfatFindEntryByName(entries []libxfat.Entry, name string) (libxfat.Entry, bool) {
	for _, entry := range entries {
		entryName := strings.TrimSpace(entry.GetName())
		if strings.EqualFold(entryName, name) {
			return entry, true
		}
		if strings.EqualFold(strings.TrimSuffix(entryName, " (deleted)"), name) {
			return entry, true
		}
	}
	return libxfat.Entry{}, false
}

func normalizeNTFSPath(p string) string {
	v := strings.TrimSpace(p)
	if v == "" {
		return "/"
	}
	v = strings.ReplaceAll(v, "\\", "/")
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return path.Clean(v)
}

func normalizeFATPath(p string) string {
	v := strings.TrimSpace(p)
	if v == "" {
		return "/"
	}
	v = strings.ReplaceAll(v, "\\", "/")
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return path.Clean(v)
}

func normalizeXFATPath(p string) string {
	v := strings.TrimSpace(p)
	if v == "" {
		return "/"
	}
	v = strings.ReplaceAll(v, "\\", "/")
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return path.Clean(v)
}

func normalizeEXTPath(p string) string {
	v := strings.TrimSpace(p)
	v = strings.ReplaceAll(v, "\\", "/")
	v = path.Clean(v)
	if v == "" || v == "." {
		return "/"
	}
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return v
}

func normalizeHFSPath(p string) string {
	v := strings.TrimSpace(p)
	v = strings.ReplaceAll(v, "\\", "/")
	v = path.Clean(v)
	if v == "" || v == "." {
		return "/"
	}
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return v
}

func normalizeXFSPath(p string) string {
	v := strings.TrimSpace(p)
	v = strings.ReplaceAll(v, "\\", "/")
	v = path.Clean(v)
	if v == "" || v == "." {
		return "/"
	}
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return v
}

func joinNTFSPath(base string, child string) string {
	return path.Clean(strings.TrimSuffix(base, "/") + "/" + child)
}

func joinXFATPath(base string, child string) string {
	if strings.TrimSpace(child) == "" {
		child = "entry-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return path.Clean(strings.TrimSuffix(base, "/") + "/" + child)
}

func joinEXTPath(base string, child string) string {
	return path.Clean(strings.TrimSuffix(base, "/") + "/" + child)
}

func joinHFSPath(base string, child string) string {
	return path.Clean(strings.TrimSuffix(base, "/") + "/" + child)
}

func joinXFSPath(base string, child string) string {
	return path.Clean(strings.TrimSuffix(base, "/") + "/" + child)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func extractTimeField(value any, candidateFields ...string) string {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return ""
	}
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return ""
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return ""
	}

	for _, fieldName := range candidateFields {
		field := rv.FieldByName(fieldName)
		if !field.IsValid() || !field.CanInterface() {
			continue
		}

		timeValue, ok := field.Interface().(time.Time)
		if !ok || timeValue.IsZero() {
			continue
		}

		return timeValue.UTC().Format(time.RFC3339Nano)
	}

	return ""
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
