package builtin

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	libewf "github.com/aoiflux/libewf"
	libvhdi "github.com/aoiflux/libvhdi"

	"mutant/object"
)

// maxInMemoryReadBytes caps how much image content a single builtin call will
// materialise as a mutant string. Shared by the *_read_at builtins and by
// xfat_read_file, which has to stage its content through a temp file.
const maxInMemoryReadBytes = 32 * 1024 * 1024

// ewfLetterPairSegment is the first segment number an EWF extension spells with
// a letter pair. Numbering runs .E01 to .E99 and then continues .EAA rather
// than .E100, so 100 is where a two-digit extension stops being possible.
const ewfLetterPairSegment = 100

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
	// Chain state. A differencing disk whose parent could not be resolved still
	// opens; only reads fail. Without these a script sees is_differencing=true
	// and has no way to learn the chain is broken until a read errors.
	NeedsParent        bool
	ChainComplete      bool
	ChainDepth         int
	ParentResolveError string
	// VHDX log state. A dirty image did not reflect its last committed state,
	// which is forensically material.
	IsDirty     bool
	HasLog      bool
	LogReplayed bool
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
	SectorSize        int
	CompressionMethod uint16
	// Chunk-table integrity. ChunkTablesInvalid counts groups where neither the
	// primary table nor its table2 backup validated: their chunks were decoded
	// unverified and the data they describe should be treated as suspect.
	ChunkTablesInvalid    int
	ChunkTablesRecovered  int
	ObservedChunkCount    uint64
	AcquisitionErrorCount int
}

// ewfBadRange is a span of the decoded device that could not be read. libewf
// substitutes zero bytes for it and keeps hashing, so any entry here means the
// computed digests describe something other than the acquired media.
type ewfBadRange struct {
	Offset int64
	Length int64
	Err    string
}

// ewfVerifyResult reports recomputing the acquisition digests over the decoded
// device and comparing them against the ones the acquisition tool stored in the
// image.
//
// OK is libewf's own verdict and is deliberately not re-derived here: an image
// that stores no digest at all is *not* verified, because there is nothing to
// verify against. Reporting "no mismatch" for such an image would be the exact
// failure docs/EVIDENCE_HANDLING_POLICY.md warns about -- an assertion that
// looks like verification and is not.
type ewfVerifyResult struct {
	Size          int64
	BytesHashed   int64
	HasStoredMD5  bool
	StoredMD5     string
	ComputedMD5   string
	MD5Match      bool
	HasStoredSHA1 bool
	StoredSHA1    string
	ComputedSHA1  string
	SHA1Match     bool
	BadRanges     []ewfBadRange
	OK            bool
}

// ewfSegmentSet is one segment path expanded into the set it belongs to.
//
// Contiguous means the numbering has no holes. It deliberately does not mean
// the set is whole: a set truncated at its end is indistinguishable from a
// complete one by looking at a directory, because nothing there records how
// many segments the acquisition wrote. That case is caught only when the
// segments are read and the last one carries no done-section, which is what
// ewf_metadata's has_done_section reports. Naming this field "complete" would
// be the assertion docs/EVIDENCE_HANDLING_POLICY.md warns against.
type ewfSegmentSet struct {
	Paths          []string
	Contiguous     bool
	PresentCount   int
	MissingNumbers []int64
	MissingFiles   []string
}

// ewfChecksumPolicy is what to do about a chunk table that fails its stored
// Adler-32. A chunk table maps offsets to compressed chunks, so an unverified
// one means the bytes being decoded may not be the bytes that were written --
// which is why this is a decision an examiner makes explicitly rather than a
// default buried in a library.
type ewfChecksumPolicy int

const (
	// ewfChecksumWarn decodes the image and records the failure in
	// ewf_metadata's chunk_tables_invalid. libewf's default, and Mutant's:
	// damaged evidence should still yield whatever is readable, as long as the
	// damage is reported rather than hidden.
	ewfChecksumWarn ewfChecksumPolicy = iota
	// ewfChecksumStrict refuses to open an image with an unverifiable chunk
	// table, for when unverified chunk offsets are worse than no image at all.
	ewfChecksumStrict
	// ewfChecksumIgnore suppresses checksum accounting entirely. It makes
	// chunk_tables_invalid report zero whether or not tables failed, so an
	// image opened this way must never be the source of an integrity claim.
	ewfChecksumIgnore
)

// ewfOpenOptions carries the evidentiary decisions an open is made under.
//
// It is a typed struct at the backend seam and never an options hash at the
// language surface: each field changes what a subsequent digest or carve
// actually describes, so each arrives as a named argument the editor can check
// and a typo cannot silently turn into a default.
type ewfOpenOptions struct {
	ChecksumPolicy ewfChecksumPolicy
	// AllowIncomplete permits a set that does not begin at segment 1 or whose
	// final segment carries no done-section. Such a set decodes only part of
	// the device -- Size reports the full declared size while reads past the
	// supplied data return EOF -- so it is for triage, never for content that
	// will be hashed or carved.
	AllowIncomplete bool
}

type ewfSession interface {
	ReadAt(offset int64, length int64) ([]byte, error)
	Metadata() (ewfMetadata, error)
	Verify(ctx context.Context) (ewfVerifyResult, error)
	Close() error
}

type ewfBackend interface {
	// Discover expands one segment path into the whole set it belongs to.
	//
	// It is separate from Open because the paths it returns are what the case
	// manifest records: an examiner's report that names every file the image
	// was decoded from is worth more than one asserting the set was complete.
	// It is also separate because a hole in the numbering is a fact about the
	// evidence rather than a failure of the call, so it comes back as data and
	// the refusal to open on it is made here, not in the library.
	Discover(segmentPath string) (ewfSegmentSet, error)
	Open(segmentPaths []string, opts ewfOpenOptions) (ewfSession, error)
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

	custodyRecordOpen(BuiltinNameVhdiOpen, handle, pathObj.Value)

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

	state, errObj := resolveVHDIHandle(args[0], BuiltinNameVhdiMetadata)
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

		"needs_parent":         boolObj(metadata.NeedsParent),
		"chain_complete":       boolObj(metadata.ChainComplete),
		"chain_depth":          intObj(int64(metadata.ChainDepth)),
		"parent_resolve_error": stringObj(metadata.ParentResolveError),
		"is_dirty":             boolObj(metadata.IsDirty),
		"has_log":              boolObj(metadata.HasLog),
		"log_replayed":         boolObj(metadata.LogReplayed),
	}), nil)
}

// VHDIReadAt reads a span of the image as text, and VHDIReadAtBytes reads it as a
// buffer. The pair shares one implementation and differs only in the type of
// the value it returns.
//
// A span of a disk image is the least text-like thing this language handles, so
// the Bytes form is the right one for nearly every caller. The text form stays
// because every program written before the type existed calls it.
func VHDIReadAt(args ...object.Object) object.Object {
	return vhdiReadAt(args, BuiltinNameVhdiReadAt, false)
}

func VHDIReadAtBytes(args ...object.Object) object.Object {
	return vhdiReadAt(args, BuiltinNameVhdiReadAtBytes, true)
}

func vhdiReadAt(args []object.Object, opName string, binary bool) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], opName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", opName, args[1].Type()))
	}
	lengthObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `%s` must be INTEGER, got %s", opName, args[2].Type()))
	}
	if offsetObj.Value < 0 {
		return resultAndError(nil, newError("%s: offset must be >= 0", opName))
	}
	if lengthObj.Value < 0 {
		return resultAndError(nil, newError("%s: length must be >= 0", opName))
	}
	if lengthObj.Value > maxInMemoryReadBytes {
		return resultAndError(nil, newError("%s: length too large (max 33554432)", opName))
	}

	content, err := state.Session.ReadAt(offsetObj.Value, lengthObj.Value)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}

	return resultAndError(binaryResult(binary, content), nil)
}

func VHDIMapOffset(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], BuiltinNameVhdiMapOffset)
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

	custodyRecordTouch(BuiltinNameVhdiClose, handleObj.Value)

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
	return ewfOpen(BuiltinNameEwfOpen, false, args...)
}

// EWFOpenPartial opens a segment set that ewf_open refuses.
//
// It is a separate builtin rather than a flag on ewf_open because an image
// decoded from an incomplete set is not the image that was acquired, and the
// difference has to be visible at the call site, in the audit trail and in the
// returned hash -- not hidden in an argument that defaults to the safe thing
// and is easy to leave set to the other one.
func EWFOpenPartial(args ...object.Object) object.Object {
	return ewfOpen(BuiltinNameEwfOpenPartial, true, args...)
}

func ewfOpen(op string, allowIncomplete bool, args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	segmentPaths, errObj := parseEWFSegmentPaths(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	opts := ewfOpenOptions{AllowIncomplete: allowIncomplete}
	if len(args) == 2 {
		policy, errObj := parseEWFChecksumPolicy(args[1], op)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		opts.ChecksumPolicy = policy
	}

	ewfStore.RLock()
	backend := ewfStore.backend
	ewfStore.RUnlock()

	// Discovery runs before the open so that the segment list custody records,
	// and the segments returned here, describe the set actually decoded rather
	// than the one path the caller happened to name.
	//
	// An explicit list of two or more paths is taken as given and not expanded:
	// the caller named the files, and second-guessing that would make it
	// impossible to open a set whose members were deliberately gathered from
	// elsewhere.
	var discovered ewfSegmentSet
	if len(segmentPaths) == 1 {
		set, err := backend.Discover(segmentPaths[0])
		if err != nil {
			return resultAndError(nil, newError("%s: %s", op, err.Error()))
		}
		discovered = set
		if !set.Contiguous && !allowIncomplete {
			// Refused rather than opened with a hole: decoding a set that is
			// missing a segment yields an image that is not the one acquired,
			// and every digest computed over it would describe something else.
			return resultAndError(nil, newError(
				"%s: segment set %s is incomplete: %d file(s) missing%s; ewf_segments reports which, ewf_open_partial proceeds anyway",
				op, segmentPaths[0], len(set.MissingNumbers), formatMissingSegmentFiles(set.MissingFiles)))
		}
		if len(set.Paths) > 0 {
			segmentPaths = set.Paths
		}
	}

	session, err := backend.Open(segmentPaths, opts)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}

	handleID := atomic.AddInt64(&ewfStore.nextID, 1)
	handle := fmt.Sprintf("ewf-handle-%d", handleID)

	ewfStore.Lock()
	ewfStore.handles[handle] = ewfHandleState{SegmentPaths: segmentPaths, Session: session}
	ewfStore.Unlock()

	custodyRecordOpen(op, handle, segmentPaths...)

	missingNumbers := make([]object.Object, 0, len(discovered.MissingNumbers))
	for _, number := range discovered.MissingNumbers {
		missingNumbers = append(missingNumbers, intObj(number))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":        stringObj(handle),
		"segment_count": intObj(int64(len(segmentPaths))),
		// The paths travel back, not just their count, because a report that
		// names the files an image was decoded from is worth more than one
		// asserting a set was complete -- and after discovery the caller can no
		// longer derive them from what it passed in.
		"segments": stringArrayLiteral(segmentPaths),
		// partial and missing_segments are on every open, not only the partial
		// one, so that a report template reads the same field either way and
		// cannot omit the caveat by having been written against ewf_open.
		"partial":          boolObj(len(discovered.MissingNumbers) > 0),
		"missing_segments": &object.Array{Elements: missingNumbers},
		"checksum_policy":  stringObj(ewfChecksumPolicyName(opts.ChecksumPolicy)),
		"status":           stringObj("ok"),
	}), nil)
}

// parseEWFChecksumPolicy reads the policy argument.
//
// The names are a closed set and an unknown one is an error rather than a
// fallback to the default: silently treating "Strict" as warn would turn an
// examiner's explicit decision into its opposite, and nothing downstream would
// show that it had happened.
func parseEWFChecksumPolicy(arg object.Object, op string) (ewfChecksumPolicy, *object.Error) {
	nameObj, ok := arg.(*object.String)
	if !ok {
		return 0, newError("%s: checksum_policy must be STRING, got %s", op, arg.Type())
	}

	switch nameObj.Value {
	case "warn":
		return ewfChecksumWarn, nil
	case "strict":
		return ewfChecksumStrict, nil
	case "ignore":
		return ewfChecksumIgnore, nil
	default:
		return 0, newError("%s: unknown checksum_policy %q; want \"warn\", \"strict\" or \"ignore\"", op, nameObj.Value)
	}
}

func ewfChecksumPolicyName(policy ewfChecksumPolicy) string {
	switch policy {
	case ewfChecksumStrict:
		return "strict"
	case ewfChecksumIgnore:
		return "ignore"
	default:
		return "warn"
	}
}

// formatMissingSegmentFiles renders the names to go and find, for the refusal
// message. It returns an empty string when libewf could not express them, so
// the message degrades to the count rather than to an empty parenthesis.
func formatMissingSegmentFiles(files []string) string {
	if len(files) == 0 {
		return ""
	}
	return " (" + strings.Join(files, ", ") + ")"
}

// EWFSegments reports the segment set a path belongs to without opening it.
//
// A hole in the numbering is returned as data rather than as an error: which
// files are absent is a finding about the evidence, and an examiner needs it in
// a report, not in an error string they have to parse.
func EWFSegments(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("ewf_segments: segment path must be STRING, got %s", args[0].Type()))
	}

	ewfStore.RLock()
	backend := ewfStore.backend
	ewfStore.RUnlock()

	set, err := backend.Discover(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("ewf_segments: %s", err.Error()))
	}

	missingNumbers := make([]object.Object, 0, len(set.MissingNumbers))
	for _, number := range set.MissingNumbers {
		missingNumbers = append(missingNumbers, intObj(number))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":             stringObj(pathObj.Value),
		"segments":         stringArrayLiteral(set.Paths),
		"segment_count":    intObj(int64(len(set.Paths))),
		"present_count":    intObj(int64(set.PresentCount)),
		"contiguous":       boolObj(set.Contiguous),
		"missing_segments": &object.Array{Elements: missingNumbers},
		"missing_files":    stringArrayLiteral(set.MissingFiles),
	}), nil)
}

func EWFMetadata(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveEWFHandle(args[0], BuiltinNameEwfMetadata)
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

		"sector_size":             intObj(int64(metadata.SectorSize)),
		"compression_method":      intObj(int64(metadata.CompressionMethod)),
		"chunk_tables_invalid":    intObj(int64(metadata.ChunkTablesInvalid)),
		"chunk_tables_recovered":  intObj(int64(metadata.ChunkTablesRecovered)),
		"observed_chunk_count":    intObj(int64(metadata.ObservedChunkCount)),
		"acquisition_error_count": intObj(int64(metadata.AcquisitionErrorCount)),
	}), nil)
}

func EWFVerify(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveEWFHandle(args[0], BuiltinNameEwfVerify)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	result, err := state.Session.Verify(context.Background())
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameEwfVerify, err.Error()))
	}

	badRanges := make([]object.Object, 0, len(result.BadRanges))
	for _, br := range result.BadRanges {
		badRanges = append(badRanges, makeHashObject(map[string]object.Object{
			"offset": intObj(br.Offset),
			"length": intObj(br.Length),
			"error":  stringObj(br.Err),
		}))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"size":            intObj(result.Size),
		"bytes_hashed":    intObj(result.BytesHashed),
		"has_stored_md5":  boolObj(result.HasStoredMD5),
		"stored_md5":      stringObj(result.StoredMD5),
		"computed_md5":    stringObj(result.ComputedMD5),
		"md5_match":       boolObj(result.MD5Match),
		"has_stored_sha1": boolObj(result.HasStoredSHA1),
		"stored_sha1":     stringObj(result.StoredSHA1),
		"computed_sha1":   stringObj(result.ComputedSHA1),
		"sha1_match":      boolObj(result.SHA1Match),
		"bad_ranges":      &object.Array{Elements: badRanges},
		"ok":              boolObj(result.OK),
	}), nil)
}

func EWFReadAt(args ...object.Object) object.Object {
	return ewfReadAt(args, BuiltinNameEwfReadAt, false)
}

func EWFReadAtBytes(args ...object.Object) object.Object {
	return ewfReadAt(args, BuiltinNameEwfReadAtBytes, true)
}

func ewfReadAt(args []object.Object, opName string, binary bool) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	state, errObj := resolveEWFHandle(args[0], opName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", opName, args[1].Type()))
	}
	lengthObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `%s` must be INTEGER, got %s", opName, args[2].Type()))
	}
	if offsetObj.Value < 0 {
		return resultAndError(nil, newError("%s: offset must be >= 0", opName))
	}
	if lengthObj.Value < 0 {
		return resultAndError(nil, newError("%s: length must be >= 0", opName))
	}
	if lengthObj.Value > maxInMemoryReadBytes {
		return resultAndError(nil, newError("%s: length too large (max 33554432)", opName))
	}

	content, err := state.Session.ReadAt(offsetObj.Value, lengthObj.Value)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}

	return resultAndError(binaryResult(binary, content), nil)
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

	custodyRecordTouch(BuiltinNameEwfClose, handleObj.Value)

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

	custodyRecordOpen(BuiltinNameRawOpen, handle, pathObj.Value)

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

	state, errObj := resolveRAWHandle(args[0], BuiltinNameRawMetadata)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	metadata, err := state.Session.Metadata()
	if err != nil {
		return resultAndError(nil, newError("raw_metadata: %s", err.Error()))
	}

	// A raw disk image carries no stored sector-size metadata, so 512 is an
	// assumption (the near-universal default), surfaced honestly as such rather
	// than as a discovered value.
	return resultAndError(makeHashObject(map[string]object.Object{
		"file_size":           intObj(metadata.FileSize),
		"assumed_sector_size": intObj(int64(metadata.SectorSize)),
		"sector_size_assumed": boolObj(true),
	}), nil)
}

func RAWReadAt(args ...object.Object) object.Object {
	return rawReadAt(args, BuiltinNameRawReadAt, false)
}

func RAWReadAtBytes(args ...object.Object) object.Object {
	return rawReadAt(args, BuiltinNameRawReadAtBytes, true)
}

func rawReadAt(args []object.Object, opName string, binary bool) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	state, errObj := resolveRAWHandle(args[0], opName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", opName, args[1].Type()))
	}
	lengthObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `%s` must be INTEGER, got %s", opName, args[2].Type()))
	}
	if offsetObj.Value < 0 {
		return resultAndError(nil, newError("%s: offset must be >= 0", opName))
	}
	if lengthObj.Value < 0 {
		return resultAndError(nil, newError("%s: length must be >= 0", opName))
	}
	if lengthObj.Value > maxInMemoryReadBytes {
		return resultAndError(nil, newError("%s: length too large (max 33554432)", opName))
	}

	content, err := state.Session.ReadAt(offsetObj.Value, lengthObj.Value)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}

	return resultAndError(binaryResult(binary, content), nil)
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

	custodyRecordTouch(BuiltinNameRawClose, handleObj.Value)

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

	custodyRecordTouch(op, handleObj.Value)

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

	custodyRecordTouch(op, handleObj.Value)

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

	custodyRecordTouch(op, handleObj.Value)

	return state, nil
}

func (realVHDIBackend) Open(imagePath string) (vhdiSession, error) {
	disk, err := libvhdi.OpenFile(imagePath)
	if err != nil {
		return nil, err
	}
	return &realVHDISession{disk: disk}, nil
}

// Discover expands one segment path into its whole set.
//
// An E01 set numbers .E01 to .E99 and then continues .EAA rather than .E100, so
// a caller that enumerates segments by hand gets it wrong at the 100th -- which
// is why libewf exposes the progression and this asks it rather than walking the
// directory here. The path need not be the first segment: the set is identified
// by the stem and family of the name and then enumerated from segment 1, so an
// image named by its .E03 still decodes from its .E01.
//
// A hole in the numbering comes back as MissingNumbers/MissingFiles rather than
// as an error, because which files are absent is a finding about the evidence
// and belongs in a report. Whether to proceed on a holed set is a decision for
// the caller; EWFOpen refuses, ewf_segments reports.
func (realEWFBackend) Discover(segmentPath string) (ewfSegmentSet, error) {
	discovered, err := libewf.SegmentPaths(segmentPath)
	if err == nil {
		return ewfSegmentSet{
			Paths:        discovered,
			Contiguous:   true,
			PresentCount: len(discovered),
		}, nil
	}

	var missing *libewf.MissingSegmentsError
	if !errors.As(err, &missing) {
		return ewfSegmentSet{}, err
	}

	// A lone file whose extension parses as a letter-pair segment is not
	// segment 100-or-beyond of a set; it is a file that happens to be named
	// that way. libewf states the rule itself -- a letter-pair extension names
	// segment 100 or more, "which cannot exist unless all 99 numeric segments
	// do" -- and applies it to the files its directory scan turns up, but not
	// to the path it was handed. So acquired.ewf, an entirely ordinary name for
	// a single-file image, reads as segment 676 with 675 segments missing.
	//
	// Refusing it would be worse than the bug being fixed here: a whole image
	// would become unopenable because of its file extension. A numbered segment
	// standing alone is a different matter and stays a hole -- opening .E05
	// without .E01 through .E04 yields four segments of nothing.
	if len(missing.Present) == 1 && missing.Present[0] >= ewfLetterPairSegment {
		return ewfSegmentSet{
			Paths:        []string{segmentPath},
			Contiguous:   true,
			PresentCount: 1,
		}, nil
	}

	numbers := make([]int64, 0, len(missing.Missing))
	for _, number := range missing.Missing {
		numbers = append(numbers, int64(number))
	}
	return ewfSegmentSet{
		Contiguous:     false,
		PresentCount:   len(missing.Present),
		MissingNumbers: numbers,
		// Expected is empty when the naming family cannot express the missing
		// numbers, so it is carried as libewf gives it rather than back-filled
		// with names that would be wrong.
		MissingFiles: missing.Expected,
	}, nil
}

func (realEWFBackend) Open(segmentPaths []string, opts ewfOpenOptions) (ewfSession, error) {
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

	libewfOpts := make([]libewf.Option, 0, 2)
	switch opts.ChecksumPolicy {
	case ewfChecksumStrict:
		libewfOpts = append(libewfOpts, libewf.WithChecksumPolicy(libewf.ChecksumStrict))
	case ewfChecksumIgnore:
		libewfOpts = append(libewfOpts, libewf.WithChecksumPolicy(libewf.ChecksumIgnore))
	default:
		libewfOpts = append(libewfOpts, libewf.WithChecksumPolicy(libewf.ChecksumWarn))
	}
	if opts.AllowIncomplete {
		libewfOpts = append(libewfOpts, libewf.AllowIncompleteSegmentSet())
	}

	var (
		reader libewf.Reader
		err    error
	)
	if len(sources) == 1 {
		reader, err = libewf.OpenWithOptions(sources[0], libewfOpts...)
	} else {
		reader, err = libewf.OpenSegmentsWithOptions(sources, libewfOpts...)
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
	if err != nil && !errors.Is(err, io.EOF) {
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
		NeedsParent:    s.disk.NeedsParent(),
		ChainComplete:  s.disk.ChainComplete(),
		ChainDepth:     s.disk.ChainDepth(),
		IsDirty:        s.disk.IsDirty(),
		HasLog:         s.disk.HasLog(),
		LogReplayed:    s.disk.LogReplayed(),
	}
	if err := s.disk.ParentResolveError(); err != nil {
		meta.ParentResolveError = err.Error()
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
		// Take the parent GUID from the parent disk's own GUIDString so it is
		// formatted identically to Identifier above. A hand-rolled big-endian
		// formatter over ParentIdentifier() produces a string that can never
		// match the parent's reported identifier, since the library byte-swaps
		// the first three GUID fields.
		if parent := s.disk.Parent(); parent != nil {
			meta.ParentIdentifier = parent.GUIDString()
		}
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
	if err != nil && !errors.Is(err, io.EOF) {
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
		// The decoded device size comes from the reader, not from multiplying
		// two media fields that are absent on some images.
		TotalLogicalBytes:     uint64(s.reader.Size()),
		SectorSize:            s.reader.SectorSize(),
		CompressionMethod:     meta.CompressionMethod,
		ChunkTablesInvalid:    meta.ChunkTablesInvalid,
		ChunkTablesRecovered:  meta.ChunkTablesRecovered,
		ObservedChunkCount:    meta.ObservedChunkCount,
		AcquisitionErrorCount: len(meta.AcquisitionErrors),
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
	}

	return out, nil
}

// Verify recomputes MD5 and SHA-1 over the whole decoded device and compares
// them against the digests stored at acquisition time. It reads the entire
// image, so it is O(image size) -- the one builtin here that is not a seek.
func (s *realEWFSession) Verify(ctx context.Context) (ewfVerifyResult, error) {
	res, err := libewf.Verify(ctx, s.reader)
	if err != nil {
		return ewfVerifyResult{}, err
	}

	out := ewfVerifyResult{
		Size:          res.Size,
		BytesHashed:   res.BytesHashed,
		HasStoredMD5:  res.HasStoredMD5,
		MD5Match:      res.MD5Match,
		HasStoredSHA1: res.HasStoredSHA1,
		SHA1Match:     res.SHA1Match,
		OK:            res.OK(),
	}

	// A stored digest is only rendered when the image actually carries one, so
	// an absent digest reads as "" rather than as a string of zeroes that looks
	// like a value.
	if res.HasStoredMD5 {
		out.StoredMD5 = hex.EncodeToString(res.StoredMD5)
	}
	if res.HasStoredSHA1 {
		out.StoredSHA1 = hex.EncodeToString(res.StoredSHA1)
	}
	out.ComputedMD5 = hex.EncodeToString(res.ComputedMD5)
	out.ComputedSHA1 = hex.EncodeToString(res.ComputedSHA1)

	for _, br := range res.BadRanges {
		out.BadRanges = append(out.BadRanges, ewfBadRange{
			Offset: br.Offset,
			Length: br.Length,
			Err:    br.Err,
		})
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
	if err != nil && !errors.Is(err, io.EOF) {
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
