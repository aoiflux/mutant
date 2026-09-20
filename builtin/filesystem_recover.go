package builtin

// The *_recover_file family: writing out the bytes a deleted entry still
// points at.
//
// The *_deleted family answers "what does this filesystem still remember".
// This one answers the question that follows it, and the two are deliberately
// separate calls rather than one builtin with a destination argument. A scan
// is a reading of the volume; a recovery produces a new file that an examiner
// will hash, attach and hand to somebody else. What content_state already said
// about the byte map is what decides whether that file is worth anything, and
// a script has to have seen it before it writes one.
//
// # Naming an entry
//
// A recovery names an entry by its index in the most recent scan on that
// handle -- the index field each scanned entry now carries -- and nothing
// else. The alternatives were all worse. record_id is not unique: HFS+ carving
// routinely finds several records with the same CNID, and FAT and exFAT have
// no surviving identifier at all and report their first cluster, which two
// deleted files can share once the chain has been reused. A path is not unique
// either and on a carved entry is frequently invented. The index is exactly as
// stable as the scan it came from, which is the honest scope of the claim: the
// recovery is of the thing the scan reported at that position, and the result
// echoes name, path and record_id so a script can assert it recovered what it
// meant to.
//
// Calling a recovery before a scan is an error rather than an implicit scan.
// An implicit one would make the enumeration invisible in the manifest, and
// the enumeration is where the entry's provenance is established.
//
// # Where the bytes come from
//
// Four of the six families read the image at the runs the scan reported, which
// makes the output byte-for-byte accountable: the runs in the recovery result
// are the same claim as the runs in the scan, and the file is those ranges
// concatenated. The other two go through their library's own reader, because
// the library knows something the run list does not -- libhfs clamps a
// recovered record's size to what its extents can actually hold, and libxfs's
// unlinked inodes are still allocated, so the ordinary inode reader is both
// available and correct for them.
//
// NTFS is the one that would be wrong done naively. A resident $DATA value
// lives inside the MFT record, and an MFT record carries update-sequence
// fixups: the last two bytes of every sector hold the record's sequence number
// rather than content. Reading a resident value off the image at its reported
// offset therefore succeeds and returns two corrupt bytes whenever the value
// crosses a sector boundary. libntfs applied the fixups when it parsed the
// record, so the recovery takes the parsed value and never re-reads it.
//
// # The zeros
//
// Three different things become zeros in an output file and they are counted
// separately, because only one of them is evidence:
//
//	located_bytes    read from the image at a run's offset
//	sparse_bytes     a hole the filesystem recorded; zeros here are content
//	unlocated_bytes  inside the output, covered by no locatable run
//
// The third is the one a report must never present as content. It happens
// where a library reports a run it could not place -- libxfs's unresolvable
// fsblock, a sparse NTFS fragment on a stream that is not sparse -- and the
// file has to be that long for the offsets after it to land correctly, so the
// gap is written and named rather than skipped.
//
// # The contiguity hypothesis
//
// fat_recover_file_assuming_contiguous and its exFAT twin are separate
// builtins and not a flag, because a caller has to say the word at the call
// site. Both libraries will synthesise a run of ceil(size/cluster) clusters
// following the first when the chain has been freed, and both set their own
// Assumed flag when they do. That flag is what this family reports, not the
// argument the caller passed: when the chain turned out to be walkable, or
// when exFAT had declared the stream contiguous while the file was live, the
// hypothesis was not needed and assumed comes back false. A recovery that says
// assumed true is a recovery of bytes nothing in the filesystem connects to
// this file beyond their position.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libhfs "github.com/aoiflux/libhfs"
	libxfat "github.com/aoiflux/libxfat"

	"mutant/object"
)

// fsRecoveredContentAssumed is the one content_state a recovery can report
// that no scan ever does. The six the *_deleted family documents all say
// where a surviving map came from; this one says there was none and the
// caller asked for a layout to be invented anyway, so it must not be
// spelled as any of them.
const fsRecoveredContentAssumed = "assumed_contiguous"

// fsRecovery is one deleted entry's content, located and ready to be written.
type fsRecovery struct {
	// Entry is the scanned entry as it was reported, unmodified. The recovery
	// result echoes its name, path and record_id so that what was written can
	// be tied back to what was enumerated.
	Entry fsDeletedEntry

	// Content covers Length bytes beginning at the file's first byte.
	Content io.ReaderAt
	Length  int64

	// Runs is the layout Content was built from. It is empty for a resident
	// value, which has no layout, and it is not always Entry.Runs: the
	// assuming-contiguous builtins re-derive it.
	Runs []fsDeletedRun

	// ContentState, Assumed, Reallocated and AllocationChecked describe this
	// recovery rather than the scan. They usually match the entry and are
	// carried separately for the case where they do not -- a re-derived layout
	// changes the first two, and it is the recovery's own answer that belongs
	// beside the bytes it produced.
	ContentState      string
	Assumed           bool
	Reallocated       bool
	AllocationChecked bool

	LocatedBytes   int64
	SparseBytes    int64
	UnlocatedBytes int64

	// Caveats are what this recovery does not establish, in the order they
	// were found. The family adds the ones only it knows about; the shared
	// path adds the rest.
	Caveats []string
}

// --- the scan cache ---------------------------------------------------------

// fsRecoveryCache remembers the entries of the last deleted scan on a handle.
//
// It is replaced wholesale by every scan rather than accumulated, so an index
// always refers to the most recent one. The lock is its own: a recovery
// resolves no paths and shares nothing with the rest of the session.
type fsRecoveryCache struct {
	mu      sync.Mutex
	scanned bool
	entries []fsDeletedEntry
}

func (c *fsRecoveryCache) remember(entries []fsDeletedEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scanned = true
	c.entries = entries
}

// lookup returns the entry at index, or says why there is none.
//
// "No scan has run" and "that index is past the end" are different errors
// because they call for different fixes, and a single "not found" would leave
// a script unable to tell a missing call from a stale number.
func (c *fsRecoveryCache) lookup(index int64) (fsDeletedEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.scanned {
		return fsDeletedEntry{}, errors.New(
			"no deleted scan has been run on this handle, and the scan is what " +
				"enumerates the entries a recovery can name; run the *_deleted " +
				"builtin for this filesystem first and pass an entry's index")
	}
	if index < 0 || index >= int64(len(c.entries)) {
		return fsDeletedEntry{}, fmt.Errorf(
			"index %d is outside the %d entries the last scan on this handle reported",
			index, len(c.entries))
	}
	return c.entries[index], nil
}

// fatRecoveryCache also keeps libfat's own directory entries.
//
// The contiguity hypothesis is the library's arithmetic over the entry, not
// this package's over a cluster number, and a deleted FAT entry carries no
// identifier that would let it be found again -- so the entry itself is what
// has to be kept.
type fatRecoveryCache struct {
	fsRecoveryCache
	natives []libfat.DirEntry
}

func (c *fatRecoveryCache) remember(entries []fsDeletedEntry, natives []libfat.DirEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scanned = true
	c.entries = entries
	c.natives = natives
}

func (c *fatRecoveryCache) native(index int64) (libfat.DirEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if index < 0 || index >= int64(len(c.natives)) {
		return libfat.DirEntry{}, false
	}
	return c.natives[index], true
}

// xfatRecoveryCache is fatRecoveryCache for exFAT. See it for why.
type xfatRecoveryCache struct {
	fsRecoveryCache
	natives []libxfat.Entry
}

func (c *xfatRecoveryCache) remember(entries []fsDeletedEntry, natives []libxfat.Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scanned = true
	c.entries = entries
	c.natives = natives
}

func (c *xfatRecoveryCache) native(index int64) (libxfat.Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if index < 0 || index >= int64(len(c.natives)) {
		return libxfat.Entry{}, false
	}
	return c.natives[index], true
}

// hfsRecoveryCache keeps libhfs's own DeletedRecord values, because OpenDeleted
// takes the record and a CNID cannot find it again: carving finds several
// records with the same CNID routinely.
type hfsRecoveryCache struct {
	fsRecoveryCache
	natives []libhfs.DeletedRecord
}

func (c *hfsRecoveryCache) remember(entries []fsDeletedEntry, natives []libhfs.DeletedRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scanned = true
	c.entries = entries
	c.natives = natives
}

func (c *hfsRecoveryCache) native(index int64) (libhfs.DeletedRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if index < 0 || index >= int64(len(c.natives)) {
		return libhfs.DeletedRecord{}, false
	}
	return c.natives[index], true
}

// --- reading a run list -----------------------------------------------------

// fsRunReader presents a list of image-absolute runs as one byte space.
//
// Anything the runs do not cover reads as zero: a recorded hole, a run the
// library could not place, and a gap between runs all produce the same bytes
// and are counted apart from each other by recoveryFromRuns, which is where
// the distinction is preserved. A run whose offset is negative is never read
// from, because -1 is this family's "nowhere" and seeking to it would either
// fail or, worse on a signed API, succeed somewhere else.
type fsRunReader struct {
	image io.ReaderAt
	runs  []fsDeletedRun
	size  int64
}

func (r *fsRunReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= r.size {
		return 0, io.EOF
	}

	short := false
	if remaining := r.size - off; int64(len(p)) > remaining {
		p = p[:remaining]
		short = true
	}
	for i := range p {
		p[i] = 0
	}

	end := off + int64(len(p))
	for _, run := range r.runs {
		if run.Sparse || run.Offset < 0 || run.Length <= 0 {
			continue
		}
		lo, hi := run.FileOffset, run.FileOffset+run.Length
		if lo < off {
			lo = off
		}
		if hi > end {
			hi = end
		}
		if lo >= hi {
			continue
		}
		at := run.Offset + (lo - run.FileOffset)
		if _, err := r.image.ReadAt(p[lo-off:hi-off], at); err != nil && err != io.EOF {
			return 0, fmt.Errorf("reading %d bytes at image offset %d: %w", hi-lo, at, err)
		}
	}

	if short {
		return len(p), io.EOF
	}
	return len(p), nil
}

// recoveryFromRuns builds a recovery out of a layout and the image behind it.
//
// The output length is what the runs cover, capped at the size the surviving
// metadata recorded. Runs past the recorded end are allocation slack rather
// than content, and a file longer than its own entry says it is would be a
// recovery nobody could explain.
func recoveryFromRuns(image io.ReaderAt, entry fsDeletedEntry, runs []fsDeletedRun) (fsRecovery, error) {
	var covered int64
	for _, run := range runs {
		if run.Length <= 0 {
			continue
		}
		if end := run.FileOffset + run.Length; end > covered {
			covered = end
		}
	}
	if covered == 0 {
		return fsRecovery{}, errors.New(
			"the entry's surviving layout covers no bytes, so there is nothing to write")
	}

	length := covered
	if entry.Size > 0 && entry.Size < length {
		length = entry.Size
	}

	recovery := fsRecovery{
		Entry:             entry,
		Content:           &fsRunReader{image: image, runs: runs, size: length},
		Length:            length,
		Runs:              runs,
		ContentState:      entry.ContentState,
		Reallocated:       entry.Reallocated,
		AllocationChecked: entry.AllocationChecked,
	}

	for _, run := range runs {
		lo, hi := run.FileOffset, run.FileOffset+run.Length
		if hi > length {
			hi = length
		}
		if lo >= hi {
			continue
		}
		switch {
		case run.Sparse:
			recovery.SparseBytes += hi - lo
		case run.Offset < 0:
			recovery.UnlocatedBytes += hi - lo
		default:
			recovery.LocatedBytes += hi - lo
		}
	}

	// Anything no run claimed at all is zeros too, and belongs with the
	// ranges that could not be placed rather than with the holes. Runs are
	// documented gap-free by every library here, so this is normally nothing;
	// it is worked out rather than assumed, because a gap that went
	// unreported would otherwise be written into the file as content.
	recovery.UnlocatedBytes = length - recovery.LocatedBytes - recovery.SparseBytes

	return recovery, nil
}

// recoveryFromReader builds a recovery around a reader a library supplied.
//
// The runs are still reported -- they are what the scan said and what a report
// will quote -- but they are not what was read, so nothing here is derived
// from them.
func recoveryFromReader(entry fsDeletedEntry, reader io.ReaderAt, length int64) fsRecovery {
	return fsRecovery{
		Entry:             entry,
		Content:           reader,
		Length:            length,
		Runs:              entry.Runs,
		ContentState:      entry.ContentState,
		Reallocated:       entry.Reallocated,
		AllocationChecked: entry.AllocationChecked,
		LocatedBytes:      length,
	}
}

// --- the shared builtin -----------------------------------------------------

// fsDeletedRecoverer is the seam every family with a *_recover_file builtin
// implements. assumeContiguous is passed rather than being a second method so
// that a family which cannot honour it refuses in one place.
type fsDeletedRecoverer interface {
	RecoverDeleted(index int64, assumeContiguous bool) (fsRecovery, error)
}

// fsRecoverFile writes one deleted entry's content to a new file.
func fsRecoverFile(op string, args []object.Object, assumeContiguous bool,
	resolve func(object.Object, string) (fsDeletedRecoverer, *object.Error),
) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	session, errObj := resolve(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	index, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	destination, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	recovery, err := session.RecoverDeleted(index, assumeContiguous)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}

	if recovery.Content == nil || recovery.Length <= 0 {
		return resultAndError(nil, newError(
			"%s: the recovery located no bytes, and an empty file under a deleted "+
				"file's name reads as a file that was empty", op))
	}

	written, digest, errObj := fsWriteEvidenceFile(op, destination,
		io.NewSectionReader(recovery.Content, 0, recovery.Length))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The touch is recorded by the resolve*Handle this went through, which is
	// also where an unknown handle is refused.
	handle := ""
	if handleObj, ok := args[0].(*object.String); ok {
		handle = handleObj.Value
	}

	entry := recovery.Entry
	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":          stringObj(handle),
		"index":           intObj(index),
		"name":            stringObj(entry.Name),
		"path":            stringObj(entry.Path),
		"name_source":     stringObj(entry.NameSource),
		"is_directory":    boolObj(entry.IsDirectory),
		"record_id":       intObj(entry.RecordID),
		"id_kind":         stringObj(entry.IDKind),
		"dest":            stringObj(destination),
		"size":            intObj(entry.Size),
		"bytes_written":   intObj(written),
		"located_bytes":   intObj(recovery.LocatedBytes),
		"sparse_bytes":    intObj(recovery.SparseBytes),
		"unlocated_bytes": intObj(recovery.UnlocatedBytes),
		// Not "complete": one builtin away, on the scan this entry came
		// from, complete means the enumeration was not cut short. A
		// recovery that is entirely a contiguity hypothesis can write
		// exactly as many bytes as the record claimed, and "complete: true"
		// beside it would read as a verdict on the recovery rather than an
		// observation about two numbers.
		"size_matched":       boolObj(entry.Size > 0 && written == entry.Size),
		"content_state":      stringObj(recovery.ContentState),
		"assumed":            boolObj(recovery.Assumed),
		"runs":               runsArray(recovery.Runs),
		"allocation_checked": boolObj(recovery.AllocationChecked),
		"reallocated":        boolObj(recovery.Reallocated),
		"confidence":         stringObj(entry.Confidence),
		"algorithm":          stringObj("sha256"),
		"digest":             stringObj(digest),
		"caveats":            stringArray(recoveryCaveats(recovery, written)),
		"status":             stringObj("ok"),
	}), nil)
}

// recoveryCaveats states what this recovery does not establish.
//
// Every one of these is derivable from the other fields, and that is the
// point: a report renders prose, and the prose an examiner has to write by
// hand is the prose that gets left out. The family-specific ones are already
// on the recovery and come first, because they are the ones a reader of this
// file cannot predict.
func recoveryCaveats(recovery fsRecovery, written int64) []string {
	caveats := append([]string{}, recovery.Caveats...)
	entry := recovery.Entry

	switch recovery.ContentState {
	case fsDeletedContentFirstOnly:
		caveats = append(caveats, "only the entry's first cluster was locatable: "+
			"deletion freed the chain, and the FAT now describes whatever was "+
			"written to those clusters next rather than the rest of this file")
	case fsDeletedContentDeclared:
		caveats = append(caveats, "the layout is the one the volume declared "+
			"contiguous while the file was live, so it is a record rather than a "+
			"guess; whether those clusters still hold this file's bytes is a "+
			"separate question and is not answered here")
	case fsDeletedContentResident:
		caveats = append(caveats, "the content was stored inside the metadata "+
			"record itself and was read from the record, not from allocated "+
			"clusters")
	}

	if recovery.Assumed {
		caveats = append(caveats, "the layout was assumed contiguous rather than "+
			"read from the filesystem: nothing connects these bytes to this file "+
			"beyond their position, and they are a hypothesis")
	}
	if recovery.Reallocated {
		caveats = append(caveats, "the entry's blocks are allocated to a live "+
			"file, so what was read is most likely that file's content and not "+
			"this one's")
	} else if !recovery.AllocationChecked {
		caveats = append(caveats, "nothing cross-referenced these ranges against "+
			"the allocation map, so reallocated false here means nobody looked, "+
			"not that the blocks are still free")
	}
	if recovery.UnlocatedBytes > 0 {
		caveats = append(caveats, fmt.Sprintf("%d bytes of the output are zeros "+
			"standing in for ranges the library could not place; they are not "+
			"evidence that the file held zeros there",
			recovery.UnlocatedBytes))
	}
	if recovery.SparseBytes > 0 {
		caveats = append(caveats, fmt.Sprintf("%d bytes are a hole the filesystem "+
			"recorded, so zeros there are the file's own content",
			recovery.SparseBytes))
	}
	if entry.IsDirectory {
		caveats = append(caveats, "the entry is a directory, so what was written "+
			"is directory records rather than file content")
	}
	if entry.Size > 0 && written < entry.Size {
		caveats = append(caveats, fmt.Sprintf("the surviving metadata records %d "+
			"bytes and %d were written", entry.Size, written))
	}
	if entry.NameSource == fsDeletedNameSynthetic || entry.NameSource == fsDeletedNameReconstruct {
		caveats = append(caveats, "the name reported for this entry is "+
			entry.NameSource+" and is not the name as the filesystem wrote it")
	}

	return caveats
}

// recoverableState refuses an entry with no byte map before anything is
// opened, named or written.
//
// A zero-byte file carrying a deleted file's name is the worst possible
// output: it is indistinguishable from a recovery that worked on an empty
// file, and it would be attached to a report as one.
func recoverableState(entry fsDeletedEntry) error {
	switch entry.ContentState {
	case fsDeletedContentNone:
		return errors.New("this entry has no surviving byte map -- content_state " +
			"is none -- so the file is described and cannot be located; there is " +
			"nothing to recover")
	case fsDeletedContentUnsupported:
		return errors.New("this library offers no content path for this entry -- " +
			"content_state is unsupported -- so no recovery is possible from it")
	case "":
		return errors.New("the entry reports no content_state at all")
	}
	return nil
}

// --- the builtins -----------------------------------------------------------

func NtfsRecoverFile(args ...object.Object) object.Object {
	return fsRecoverFile(BuiltinNameNtfsRecoverFile, args, false, ntfsRecoveryResolver)
}

func FatRecoverFile(args ...object.Object) object.Object {
	return fsRecoverFile(BuiltinNameFatRecoverFile, args, false, fatRecoveryResolver)
}

// FatRecoverFileAssumingContiguous recovers a deleted FAT entry as though the
// clusters after its first one followed it in order.
//
// The hypothesis is the whole of this builtin and is why it is not a flag on
// the one above. It is frequently right -- small files on a freshly formatted
// volume are usually laid out contiguously -- and it is unfalsifiable from
// inside the filesystem, because the evidence that would test it is the chain
// deletion freed.
func FatRecoverFileAssumingContiguous(args ...object.Object) object.Object {
	return fsRecoverFile(BuiltinNameFatRecoverContiguous, args, true, fatRecoveryResolver)
}

func XFATRecoverFile(args ...object.Object) object.Object {
	return fsRecoverFile(BuiltinNameXfatRecoverFile, args, false, xfatRecoveryResolver)
}

// XFATRecoverFileAssumingContiguous is FatRecoverFileAssumingContiguous for
// exFAT. One difference is worth knowing: an entry whose stream extension
// recorded NoFatChain needs no hypothesis, because the volume already stated
// the layout, and for those this builtin reports assumed false and returns the
// same bytes as xfat_recover_file.
func XFATRecoverFileAssumingContiguous(args ...object.Object) object.Object {
	return fsRecoverFile(BuiltinNameXfatRecoverContiguous, args, true, xfatRecoveryResolver)
}

func ExtRecoverFile(args ...object.Object) object.Object {
	return fsRecoverFile(BuiltinNameExtRecoverFile, args, false, extRecoveryResolver)
}

func HFSRecoverFile(args ...object.Object) object.Object {
	return fsRecoverFile(BuiltinNameHfsRecoverFile, args, false, hfsRecoveryResolver)
}

// XFSRecoverFile recovers an inode from an allocation group's unlinked chain.
//
// It is the only XFS recovery there is, and it recovers rather than carves:
// an inode reaches an unlinked bucket because the filesystem put it there when
// a file was unlinked while still open, and it is still allocated and still
// fully readable. An entry from xfs_deleted, whose evidence is a directory
// record and whose inode has had di_mode cleared, reports content_state
// unsupported and is refused here.
func XFSRecoverFile(args ...object.Object) object.Object {
	return fsRecoverFile(BuiltinNameXfsRecoverFile, args, false, xfsRecoveryResolver)
}

func ntfsRecoveryResolver(arg object.Object, op string) (fsDeletedRecoverer, *object.Error) {
	state, errObj := resolveNTFSHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session, nil
}

func fatRecoveryResolver(arg object.Object, op string) (fsDeletedRecoverer, *object.Error) {
	state, errObj := resolveFATHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session, nil
}

func xfatRecoveryResolver(arg object.Object, op string) (fsDeletedRecoverer, *object.Error) {
	state, errObj := resolveXFATHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session, nil
}

func extRecoveryResolver(arg object.Object, op string) (fsDeletedRecoverer, *object.Error) {
	state, errObj := resolveEXTHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session, nil
}

func hfsRecoveryResolver(arg object.Object, op string) (fsDeletedRecoverer, *object.Error) {
	state, errObj := resolveHFSHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session, nil
}

func xfsRecoveryResolver(arg object.Object, op string) (fsDeletedRecoverer, *object.Error) {
	state, errObj := resolveXFSHandle(arg, op)
	if errObj != nil {
		return nil, errObj
	}
	return state.Session, nil
}

// --- NTFS -------------------------------------------------------------------

func (s *realNTFSSession) RecoverDeleted(index int64, assumeContiguous bool) (fsRecovery, error) {
	if assumeContiguous {
		return fsRecovery{}, errors.New(
			"NTFS leaves a deleted file's run list intact, so there is no " +
				"contiguity to assume and no builtin that asks for one")
	}

	entry, err := s.recovery.lookup(index)
	if err != nil {
		return fsRecovery{}, err
	}
	if err := recoverableState(entry); err != nil {
		return fsRecovery{}, err
	}

	record, err := s.volume.GetMFTEntry(uint64(entry.RecordID))
	if err != nil {
		return fsRecovery{}, err
	}
	if record.IsInUse() {
		// Not a paranoid check against a read-only image: it is what catches an
		// index taken from a scan of a different volume, which would otherwise
		// read a live file's clusters and report them under a deleted name.
		return fsRecovery{}, fmt.Errorf(
			"MFT record %d is in use, so it is not the deleted entry the scan "+
				"reported at index %d", entry.RecordID, index)
	}

	attr := record.FindPrimaryDataAttribute()
	if attr == nil {
		return fsRecovery{}, errors.New("the record carries no $DATA attribute")
	}
	if attr.IsEncrypted() {
		return fsRecovery{}, errors.New(
			"the $DATA attribute is EFS-encrypted; its clusters hold ciphertext " +
				"and the keys are not in the filesystem")
	}
	if attr.IsCompressed() {
		// libntfs is explicit that a compressed run list maps compression units
		// rather than stream bytes, and the decompressing reader is only
		// reachable through a File, which the library refuses to open on a
		// record that is not in use. Writing the units out under the file's name
		// would produce something that is neither the file nor labelled as not
		// being it.
		return fsRecovery{}, errors.New(
			"the $DATA attribute is compressed, and a compressed run list " +
				"describes compression units rather than the file's bytes; " +
				"libntfs decompresses only through a file handle, which it will " +
				"not open on a record that is not in use, so the units are " +
				"reachable through the runs ntfs_deleted reported and not through " +
				"this builtin")
	}

	if attr.Resident != nil {
		// The parsed value, never the image at its offset: an MFT record carries
		// update-sequence fixups, so the last two bytes of each sector hold the
		// record's sequence number rather than content, and a resident value
		// crossing a sector boundary read off the disk is quietly two bytes
		// wrong. libntfs applied the fixups when it read the record.
		value := attr.Resident.Value
		if len(value) == 0 {
			return fsRecovery{}, errors.New("the resident $DATA attribute is empty")
		}
		recovery := recoveryFromReader(entry, bytes.NewReader(value), int64(len(value)))
		recovery.ContentState = fsDeletedContentResident
		return recovery, nil
	}

	fragments, err := s.volume.AttributeFragments(attr)
	if err != nil {
		return fsRecovery{}, err
	}
	runs := make([]fsDeletedRun, 0, len(fragments))
	for _, fragment := range fragments {
		offset := fragment.StartOffset
		if fragment.Sparse {
			offset = -1
		}
		runs = append(runs, fsDeletedRun{
			FileOffset: fragment.FileOffset,
			Offset:     offset,
			Length:     fragment.Length,
			Sparse:     fragment.Sparse,
		})
	}

	return recoveryFromRuns(s.reader, entry, runs)
}

// --- FAT --------------------------------------------------------------------

func (s *realFATSession) RecoverDeleted(index int64, assumeContiguous bool) (fsRecovery, error) {
	entry, err := s.recovery.lookup(index)
	if err != nil {
		return fsRecovery{}, err
	}
	if !assumeContiguous {
		// With the chain freed there is only the first cluster, and refusing a
		// state of none here is what stops an empty file being written under a
		// deleted file's name. The assuming variant is allowed past this,
		// because its whole job is to locate bytes the entry itself cannot.
		if err := recoverableState(entry); err != nil {
			return fsRecovery{}, err
		}
	}

	native, ok := s.recovery.native(index)
	if !ok {
		return fsRecovery{}, fmt.Errorf(
			"the directory entry libfat reported at index %d is no longer held; "+
				"run fat_deleted again", index)
	}

	result, err := s.volume.FragmentOffsetsWithOptions(native,
		libfat.FragmentOptions{AssumeContiguous: assumeContiguous})
	if err != nil && result == nil {
		return fsRecovery{}, err
	}
	if result == nil || len(result.Ranges) == 0 {
		return fsRecovery{}, errors.New(
			"libfat located no ranges for this entry, so there is nothing to write")
	}

	runs := make([]fsDeletedRun, 0, len(result.Ranges))
	for _, fatRange := range result.Ranges {
		runs = append(runs, fsDeletedRun{
			FileOffset: fatRange.FileOffset,
			Offset:     fatRange.StartByte,
			Length:     fatRange.Length,
		})
	}

	recovery, err := recoveryFromRuns(s.reader, entry, runs)
	if err != nil {
		return fsRecovery{}, err
	}
	recovery.Assumed = result.Assumed
	recovery.Reallocated = result.FirstClusterReallocated
	recovery.AllocationChecked = native.FirstCluster != 0
	recovery.ContentState = fatRecoveredState(result.ChainWalked, result.Assumed)
	recovery.Caveats = fatRecoveryCaveats(result.ChainBroken, result.LoopDetected)
	return recovery, nil
}

// fatRecoveredState names the provenance of the layout that was actually used,
// which is not always the one the scan reported: the assuming builtins derive
// a new one.
func fatRecoveredState(chainWalked, assumed bool) string {
	switch {
	case assumed:
		return fsRecoveredContentAssumed
	case chainWalked:
		return fsDeletedContentPreserved
	default:
		return fsDeletedContentFirstOnly
	}
}

func fatRecoveryCaveats(chainBroken, loopDetected bool) []string {
	var caveats []string
	if chainBroken {
		caveats = append(caveats, "the chain walk stopped on a free, bad or "+
			"out-of-range entry rather than an end-of-chain marker, so the runs "+
			"before that point are what was located")
	}
	if loopDetected {
		caveats = append(caveats, "the chain revisited a cluster and the walk "+
			"stopped there; the runs before the repeat remain what the FAT said")
	}
	return caveats
}

// --- exFAT ------------------------------------------------------------------

func (s *realXFATSession) RecoverDeleted(index int64, assumeContiguous bool) (fsRecovery, error) {
	entry, err := s.recovery.lookup(index)
	if err != nil {
		return fsRecovery{}, err
	}
	if !assumeContiguous {
		if err := recoverableState(entry); err != nil {
			return fsRecovery{}, err
		}
	}

	native, ok := s.recovery.native(index)
	if !ok {
		return fsRecovery{}, fmt.Errorf(
			"the entry libxfat reported at index %d is no longer held; "+
				"run xfat_deleted again", index)
	}

	result, err := s.fs.FragmentOffsetsWithOptions(native,
		libxfat.FragmentOptions{AssumeContiguous: assumeContiguous})
	if err != nil && result == nil {
		return fsRecovery{}, err
	}
	if result == nil || len(result.Ranges) == 0 {
		return fsRecovery{}, errors.New(
			"libxfat located no ranges for this entry, so there is nothing to write")
	}

	runs := make([]fsDeletedRun, 0, len(result.Ranges))
	for _, xfatRange := range result.Ranges {
		runs = append(runs, fsDeletedRun{
			FileOffset: xfatRange.FileOffset,
			Offset:     xfatRange.StartByte,
			Length:     xfatRange.Length,
		})
	}

	recovery, err := recoveryFromRuns(s.reader, entry, runs)
	if err != nil {
		return fsRecovery{}, err
	}
	recovery.Assumed = result.Assumed
	recovery.Reallocated = result.FirstClusterReallocated
	recovery.AllocationChecked = native.AllocationPossible()
	switch {
	case result.NoFatChain:
		recovery.ContentState = fsDeletedContentDeclared
	default:
		recovery.ContentState = fatRecoveredState(result.ChainWalked, result.Assumed)
	}
	recovery.Caveats = fatRecoveryCaveats(result.ChainBroken, result.LoopDetected)

	if result.AllocationContradiction {
		recovery.Caveats = append(recovery.Caveats, "the stream extension left "+
			"the allocation-possible bit clear while still naming a first cluster "+
			"and a length, so these ranges were located from fields the volume "+
			"declared meaningless")
	}
	// ValidDataLength is exFAT's record of how much of the allocation was ever
	// written. Past it the clusters are allocated and readable and hold
	// whatever was there before this file, which is a different thing from a
	// hole and from content.
	if result.ValidBytes > 0 && result.ValidBytes < recovery.Length {
		recovery.Caveats = append(recovery.Caveats, fmt.Sprintf(
			"the entry's valid-data length is %d, so the %d bytes after it were "+
				"allocated to this file but never written by it and hold whatever "+
				"was in those clusters before",
			result.ValidBytes, recovery.Length-result.ValidBytes))
	}
	return recovery, nil
}

// --- ext --------------------------------------------------------------------

func (s *realEXTSession) RecoverDeleted(index int64, assumeContiguous bool) (fsRecovery, error) {
	if assumeContiguous {
		return fsRecovery{}, errors.New(
			"ext zeroes the extent tree on unlink, so there is no first block to " +
				"assume a run from and no builtin that asks for one")
	}

	entry, err := s.recovery.lookup(index)
	if err != nil {
		return fsRecovery{}, err
	}
	if err := recoverableState(entry); err != nil {
		return fsRecovery{}, err
	}

	// DataRuns rather than Open: libext's File reads through the block map and
	// would zero-fill past the end of a partial one without saying so, and a
	// deleted inode's map is partial exactly when it is worth anything. The
	// runs are also what makes DiskOffset image-absolute -- Extent.PhysicalBlock
	// is volume-relative, and the multiplication belongs to the library.
	ranges, err := s.fs.DataRuns(uint32(entry.RecordID))
	if err != nil {
		return fsRecovery{}, err
	}
	if len(ranges) == 0 {
		return fsRecovery{}, fmt.Errorf(
			"inode %d has no surviving extents, so there is nothing to write",
			entry.RecordID)
	}

	runs := make([]fsDeletedRun, 0, len(ranges))
	unwritten := int64(0)
	for _, byteRange := range ranges {
		offset := byteRange.DiskOffset
		if byteRange.Sparse {
			offset = -1
		}
		if byteRange.Unwritten {
			unwritten += byteRange.Length
		}
		runs = append(runs, fsDeletedRun{
			FileOffset: byteRange.FileOffset,
			Offset:     offset,
			Length:     byteRange.Length,
			Sparse:     byteRange.Sparse,
		})
	}

	recovery, err := recoveryFromRuns(s.reader, entry, runs)
	if err != nil {
		return fsRecovery{}, err
	}
	if unwritten > 0 {
		recovery.Caveats = append(recovery.Caveats, fmt.Sprintf(
			"%d bytes lie in unwritten extents: blocks reserved for this file "+
				"that it never wrote, whose contents are whatever the allocator "+
				"left there", unwritten))
	}
	// libext grades partial for a block that has been reallocated and for a
	// bitmap it could not read, and does not distinguish them.
	if entry.Confidence == libext.RecoveryPartial.String() {
		recovery.Caveats = append(recovery.Caveats, "libext graded this entry "+
			"partial, which means either that a block has been reallocated or "+
			"that the block bitmap could not be read; the library does not "+
			"distinguish the two")
	}
	return recovery, nil
}

// --- HFS+ -------------------------------------------------------------------

func (s *realHFSSession) RecoverDeleted(index int64, assumeContiguous bool) (fsRecovery, error) {
	if assumeContiguous {
		return fsRecovery{}, errors.New(
			"HFS+ recovery works from the extents in the recovered catalog " +
				"record, so there is no contiguity to assume and no builtin that " +
				"asks for one")
	}

	entry, err := s.recovery.lookup(index)
	if err != nil {
		return fsRecovery{}, err
	}
	if err := recoverableState(entry); err != nil {
		return fsRecovery{}, err
	}

	native, ok := s.recovery.native(index)
	if !ok {
		return fsRecovery{}, fmt.Errorf(
			"the record libhfs reported at index %d is no longer held; "+
				"run hfs_deleted again", index)
	}

	// OpenDeleted rather than the scan's runs: it clamps a corrupt recorded
	// size to what the extents can actually hold, which is the difference
	// between a recovery that stops at the data and one that runs off the end
	// of it into whatever follows.
	file, err := s.volume.OpenDeleted(native)
	if err != nil {
		return fsRecovery{}, err
	}

	recovery := recoveryFromReader(entry, file, file.Size())
	// The eight extents in the catalog record are all OpenDeleted uses; a file
	// that overflowed into the extents B-tree is recovered only as far as they
	// reach, and the recorded size is what says so.
	if entry.Size > file.Size() {
		recovery.Caveats = append(recovery.Caveats, fmt.Sprintf(
			"the record names %d bytes and libhfs could open %d: only the eight "+
				"extents held in the catalog record are used, and anything that "+
				"overflowed into the extents B-tree is not among them",
			entry.Size, file.Size()))
	}
	if native.StaleCopy {
		recovery.Caveats = append(recovery.Caveats, "an identical record is "+
			"still live in the catalog, so this may be a copy left in node slack "+
			"by a B-tree insert rather than a deleted file")
	}
	return recovery, nil
}

// --- XFS --------------------------------------------------------------------

func (s *realXFSSession) RecoverDeleted(index int64, assumeContiguous bool) (fsRecovery, error) {
	if assumeContiguous {
		return fsRecovery{}, errors.New(
			"XFS recovery reads an inode that is still allocated, so there is no " +
				"contiguity to assume and no builtin that asks for one")
	}

	entry, err := s.recovery.lookup(index)
	if err != nil {
		return fsRecovery{}, err
	}
	if err := recoverableState(entry); err != nil {
		return fsRecovery{}, err
	}
	if entry.Source != fsDeletedSourceUnlinkedList {
		return fsRecovery{}, fmt.Errorf(
			"this entry came from %s, and the only XFS deletion evidence that "+
				"carries content is an inode on an allocation group's unlinked "+
				"chain; use xfs_unlinked and recover from that scan",
			entry.Source)
	}

	// The inode is still allocated -- that is what being on an unlinked chain
	// means -- so the ordinary reader is both available and correct, holes and
	// unwritten extents included.
	reader, err := s.volume.OpenInodeReader(uint64(entry.RecordID))
	if err != nil {
		return fsRecovery{}, err
	}

	length := entry.Size
	if length <= 0 {
		length = entry.LocatedBytes
	}
	if length <= 0 {
		return fsRecovery{}, fmt.Errorf(
			"inode %d records no size and no located bytes", entry.RecordID)
	}
	return recoveryFromReader(entry, reader, length), nil
}

// --- writing the output -----------------------------------------------------

// fsWriteEvidenceFile streams src into a new file, digesting it in the same
// pass so nothing has to read the result back to obtain one.
//
// O_EXCL: the output is a new piece of evidence, and overwriting an existing
// one because two deleted entries in an image share a name is not something a
// forensics tool should be able to do by accident.
func fsWriteEvidenceFile(op, destination string, src io.Reader) (int64, string, *object.Error) {
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, "", newError("%s: %s", op, err.Error())
	}

	digest := sha256.New()
	written, copyErr := io.CopyBuffer(
		io.MultiWriter(out, digest),
		src,
		make([]byte, fsStreamChunkBytes),
	)
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}

	if copyErr != nil {
		// A prefix left behind under the name of the whole file reads as the
		// file. Remove it, and say either way what became of it.
		if removeErr := os.Remove(destination); removeErr != nil {
			return 0, "", newError("%s: %s; the partial output at %s could not be removed: %s",
				op, copyErr.Error(), destination, removeErr.Error())
		}
		return 0, "", newError("%s: %s; the partial output at %s was removed",
			op, copyErr.Error(), destination)
	}

	return written, hex.EncodeToString(digest.Sum(nil)), nil
}
