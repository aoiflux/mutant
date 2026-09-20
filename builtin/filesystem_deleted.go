package builtin

// The *_deleted family: what a filesystem still remembers about a file it no
// longer lists.
//
// Six formats destroy six different things when a file is unlinked, and the
// shared return shape exists so that an examiner can compare them -- not to
// suggest they are the same thing. What survives, per format:
//
//   - NTFS clears the in-use bit on the MFT record and nothing else. The name,
//     the timestamps and, crucially, the run list survive intact. It is the
//     only one of the six whose deleted block map is neither zeroed nor
//     guessed -- and the only one that then cannot say whether those clusters
//     have since been handed to another file, because libntfs exposes no
//     cluster-allocation query at all.
//   - ext4 zeroes the extent tree on unlink. The inode-table slot keeps mode,
//     size, owner and times, so the usual outcome is a file that is fully
//     described and cannot be located. Directory slack keeps the name the
//     inode never held, and the orphan list records files unlinked while still
//     open, which a clean unmount would otherwise leave no trace of.
//   - FAT frees the cluster chain and overwrites the first character of the
//     name. The chain is gone, and following the FAT from a deleted entry
//     follows whatever now owns those clusters.
//   - exFAT frees the chain too, but a file whose stream extension recorded
//     NoFatChain was declared contiguous by the volume before it was deleted,
//     and deletion did not erase that statement. It is the only format here
//     that reports a deleted file's whole layout as a fact rather than a
//     hypothesis.
//   - HFS+ removes the catalog record and frees the blocks. Recovery is
//     carving: records are found in B-tree node slack, in free nodes and in
//     unallocated space, each with the library's own confidence grade.
//   - XFS clears di_mode and refuses to open an unallocated inode, so names
//     come back and content does not -- except on the AGI unlinked chains,
//     whose inodes are still allocated and still fully readable. Those are the
//     only filesystem-asserted deletion evidence in the entire set; everywhere
//     else the library is inferring.
//
// Two questions, never one. "Was something deleted here" and "can its bytes be
// read" are independent, and a single `recoverable` boolean answers neither
// honestly. Every entry therefore reports content_state -- the provenance of
// its byte map -- and that is the field a script branches on before it reads
// anything:
//
//	resident             the bytes are inside the metadata record itself
//	preserved            the filesystem's own map survived the unlink
//	declared_contiguous  the volume declared the run contiguous before deletion
//	first_cluster_only   only the starting cluster is known; the chain is freed
//	none                 no map survives; the file is described but not located
//	unsupported          this library offers no content path for this entry
//
// The two bits, again. allocation_checked and reallocated are separate for the
// same reason checked and passed are separate in the *_verify family: a
// cross-reference that never ran says nothing about the file, and one boolean
// cannot tell "these clusters are still free" from "nobody looked". NTFS is
// the case that forces the distinction -- it reports allocation_checked false
// for every entry, because the question has no answer in that library.
//
// An empty warnings list is not the same as silence. libext accumulates
// Warnings, libhfs Anomalies, libxfs per-listing ReportAnomaly -- and libntfs
// and libfat have no such channel at all, so a skipped record there leaves no
// trace anywhere. warnings_available says which situation the reader is in. It
// is the same refusal the *_verify family makes: a format with nothing to
// check does not get to report a pass.
//
// Names are graded too. FAT brute-forces the deletion-clobbered first
// character out of the short-name checksum and substitutes '_' when it cannot,
// and exFAT gives a carved entry with no surviving name a placeholder derived
// from its cluster number. Both are reported through name_source, because a
// synthetic name written into a report as a filename is fabricated evidence.

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libhfs "github.com/aoiflux/libhfs"
	libntfs "github.com/aoiflux/libntfs"
	libxfat "github.com/aoiflux/libxfat"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

// Content-map provenance. These are the stable codes a script branches on.
const (
	fsDeletedContentResident    = "resident"
	fsDeletedContentPreserved   = "preserved"
	fsDeletedContentDeclared    = "declared_contiguous"
	fsDeletedContentFirstOnly   = "first_cluster_only"
	fsDeletedContentNone        = "none"
	fsDeletedContentUnsupported = "unsupported"
)

// Where a piece of deletion evidence was found. The weight of a finding
// depends far more on this than on anything else in the entry: an inode on the
// AGI unlinked chain is the filesystem itself saying a file was deleted, while
// a record carved out of unallocated space is this library's opinion that some
// bytes look like a record.
const (
	fsDeletedSourceDirectory    = "directory"
	fsDeletedSourceOrphanScan   = "orphan_scan"
	fsDeletedSourceMFTRecord    = "mft_record"
	fsDeletedSourceIndexSlack   = "index_slack"
	fsDeletedSourceInodeTable   = "inode_table"
	fsDeletedSourceOrphanList   = "orphan_list"
	fsDeletedSourceOrphanFile   = "orphan_file"
	fsDeletedSourceDirSlack     = "dir_slack"
	fsDeletedSourceJournal      = "journal"
	fsDeletedSourceNodeSlack    = "node_slack"
	fsDeletedSourceFreeNode     = "free_node"
	fsDeletedSourceUnallocated  = "unallocated"
	fsDeletedSourceFreeSlot     = "free_slot"
	fsDeletedSourceCarved       = "carved"
	fsDeletedSourceUnlinkedList = "unlinked_list"
)

// extModeTypeMask and extModeDirectory read the file type out of an ext inode
// mode. libext keeps its own copies unexported, so these are declared here
// rather than derived from a DeletedEntry field that does not exist: a
// DeletedEntry carries the raw mode and no IsDirectory bit.
const (
	extModeTypeMask  = 0xF000
	extModeDirectory = 0x4000
)

// How the name in an entry was arrived at.
const (
	fsDeletedNameIntact      = "intact"
	fsDeletedNameReconstruct = "reconstructed"
	fsDeletedNameSynthetic   = "synthetic"
	fsDeletedNameNone        = "none"
)

// fsDeletedMaxEntries bounds the entries array.
//
// The same reasoning as fsVerifyMaxFindings: a volume holding more deleted
// records than this has already made its point, and the extra hundred thousand
// hash objects buy nothing a report can render. entry_count is the true number
// and is never truncated, so the figure an examiner quotes stays right even
// when the list they scroll is short.
const fsDeletedMaxEntries = 10000

// fsDeletedRun is one contiguous piece of a deleted file's content, located in
// the image.
//
// Offset is image-absolute and includes the base offset of the partition the
// volume was opened at, so a run from a FAT volume a megabyte into a disk
// image can be compared directly with one from an ext volume elsewhere in the
// same image. It is -1, never 0, when the range has no location: libxfs
// reports an unresolvable fsblock as offset zero, and zero is a real offset.
type fsDeletedRun struct {
	FileOffset int64
	Offset     int64
	Length     int64
	Sparse     bool
}

// fsDeletedEntry is one thing a filesystem still remembers.
type fsDeletedEntry struct {
	Name        string
	Path        string
	NameSource  string
	IsDirectory bool

	// Size is what the surviving metadata records, which on a deleted file is
	// frequently more than can be found. LocatedBytes is the sum of the runs,
	// and the two are reported separately for the reason the *_extract_file
	// family reports them separately: the clusters past a recoverable prefix
	// hold whatever was written there since.
	Size         int64
	LocatedBytes int64

	// RecordID is the library's own identifier for the record, and IDKind says
	// which kind of identifier it is. FAT and exFAT have none that survives
	// deletion, so they report -1 and "none" and are addressed by EntryOffset.
	RecordID int64
	IDKind   string
	ParentID int64

	Source     string
	Confidence string
	Reasons    []string

	ContentState string
	Runs         []fsDeletedRun

	// AllocationChecked and Reallocated are two bits, not one. See the file
	// comment.
	AllocationChecked bool
	Reallocated       bool

	// EntryOffset is the image-absolute offset of the record itself -- the
	// directory slot, the MFT record, the catalog record -- or -1 when the
	// library cannot place it. libhfs is why this is never silently zero: its
	// ByteOffset means an image offset, a node-relative offset or nothing at
	// all depending on which pass found the record, and seeking to a
	// node-relative offset in the image succeeds and returns unrelated bytes.
	EntryOffset int64

	CreatedAt  string
	ModifiedAt string
	AccessedAt string
	DeletedAt  string
}

// fsDeletedWarning is something the scan could not do, in the library's own
// words. Code is stable and is what a script matches on; Detail is prose.
type fsDeletedWarning struct {
	Code     string
	Detail   string
	Location string
}

// fsDeletedScan is what a *_deleted builtin reports.
type fsDeletedScan struct {
	Filesystem string
	Entries    []fsDeletedEntry
	EntryCount int64

	// Sources are the passes that ran; SourcesUnavailable are the ones this
	// format or this library does not offer. Naming the second is the point:
	// "no journal evidence was found" and "nothing looked in the journal" are
	// different findings and read identically in a list of entries.
	Sources            []string
	SourcesUnavailable []string

	// Examined is how many records, inodes or clusters the scan looked at, and
	// Unreadable how many of those would not parse. A scan that examined two
	// hundred slots and one that examined two million are not the same
	// evidence for the same empty result.
	Examined   int64
	Unreadable int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsDeletedWarning

	// Scope states what the scan covered and what it did not. Every one of
	// these scans has a boundary, and a recovery whose boundary is not written
	// down invites the reader to assume it had none.
	Scope string
}

// add appends an entry, keeping the count honest past the cap.
//
// It reports whether the entry was stored. A caller keeping the library's
// own record beside it -- which the recovery half needs, because a CNID or
// a freed first cluster is not enough to find the record again -- appends
// to its own slice only when this says yes, so index i means the same
// entry in both lists however many were dropped at the cap.
func (s *fsDeletedScan) add(entry fsDeletedEntry) bool {
	s.EntryCount++
	if len(s.Entries) >= fsDeletedMaxEntries {
		return false
	}
	s.Entries = append(s.Entries, entry)
	return true
}

// warn records something the scan could not do.
func (s *fsDeletedScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsDeletedWarning{Code: code, Location: location, Detail: detail})
}

// incomplete marks the scan as having a known gap, keeping the first reason.
// The first is kept rather than the last because it is the one that explains
// the earliest missing evidence, and a later gap is often a consequence of it.
func (s *fsDeletedScan) incomplete(reason string) {
	s.Complete = false
	if s.IncompleteReason == "" {
		s.IncompleteReason = reason
	}
}

func (s fsDeletedScan) toHash(handle string) *object.Hash {
	entries := make([]object.Object, 0, len(s.Entries))
	for i, entry := range s.Entries {
		entries = append(entries, entry.toHash(int64(i)))
	}

	warnings := make([]object.Object, 0, len(s.Warnings))
	codes := make([]string, 0, len(s.Warnings))
	seen := map[string]bool{}
	for _, warning := range s.Warnings {
		warnings = append(warnings, makeHashObject(map[string]object.Object{
			"code":     stringObj(warning.Code),
			"location": stringObj(warning.Location),
			"detail":   stringObj(warning.Detail),
		}))
		if !seen[warning.Code] {
			seen[warning.Code] = true
			codes = append(codes, warning.Code)
		}
	}
	sort.Strings(codes)

	return makeHashObject(map[string]object.Object{
		"handle":              stringObj(handle),
		"filesystem":          stringObj(s.Filesystem),
		"entries":             &object.Array{Elements: entries},
		"entry_count":         intObj(s.EntryCount),
		"entries_truncated":   boolObj(s.EntryCount > int64(len(s.Entries))),
		"sources":             stringArray(s.Sources),
		"sources_unavailable": stringArray(s.SourcesUnavailable),
		"examined":            intObj(s.Examined),
		"unreadable":          intObj(s.Unreadable),
		"complete":            boolObj(s.Complete),
		"incomplete_reason":   stringObj(s.IncompleteReason),
		"warnings_available":  boolObj(s.WarningsAvailable),
		"warnings":            &object.Array{Elements: warnings},
		"warning_codes":       stringArray(codes),
		"scope":               stringObj(s.Scope),
		"status":              stringObj("ok"),
	})
}

// toHash renders one entry. index is its position in this scan's entries
// array, and it is carried in the entry rather than left to the caller to
// count because it is the argument the *_recover_file family takes. It is
// not an identifier of the file: record_id is the library's own, and a
// second scan of the same image renumbers nothing but a shorter one would.
func (e fsDeletedEntry) toHash(index int64) object.Object {
	return makeHashObject(map[string]object.Object{
		"index":              intObj(index),
		"name":               stringObj(e.Name),
		"path":               stringObj(e.Path),
		"name_source":        stringObj(e.NameSource),
		"is_directory":       boolObj(e.IsDirectory),
		"size":               intObj(e.Size),
		"located_bytes":      intObj(e.LocatedBytes),
		"record_id":          intObj(e.RecordID),
		"id_kind":            stringObj(e.IDKind),
		"parent_id":          intObj(e.ParentID),
		"source":             stringObj(e.Source),
		"confidence":         stringObj(e.Confidence),
		"reasons":            stringArray(e.Reasons),
		"content_state":      stringObj(e.ContentState),
		"runs":               runsArray(e.Runs),
		"allocation_checked": boolObj(e.AllocationChecked),
		"reallocated":        boolObj(e.Reallocated),
		"entry_offset":       intObj(e.EntryOffset),
		"created_at":         stringObj(e.CreatedAt),
		"modified_at":        stringObj(e.ModifiedAt),
		"accessed_at":        stringObj(e.AccessedAt),
		"deleted_at":         stringObj(e.DeletedAt),
	})
}

// runsArray renders a run list. The *_deleted and *_recover_file families
// both report one and they have to read identically: a run in a recovery
// result is the same claim about the same bytes as the run the scan showed.
func runsArray(runs []fsDeletedRun) object.Object {
	out := make([]object.Object, 0, len(runs))
	for _, run := range runs {
		out = append(out, makeHashObject(map[string]object.Object{
			"file_offset": intObj(run.FileOffset),
			"offset":      intObj(run.Offset),
			"length":      intObj(run.Length),
			"sparse":      boolObj(run.Sparse),
		}))
	}
	return &object.Array{Elements: out}
}

// stringArray renders a string slice, never nil, so a script can loop over it
// without checking.
func stringArray(values []string) object.Object {
	out := make([]object.Object, 0, len(values))
	for _, value := range values {
		out = append(out, stringObj(value))
	}
	return &object.Array{Elements: out}
}

// sumRuns totals the located bytes of a run list.
func sumRuns(runs []fsDeletedRun) int64 {
	var total int64
	for _, run := range runs {
		if run.Sparse {
			continue
		}
		total += run.Length
	}
	return total
}

// --- the builtins -----------------------------------------------------------

// fsDeletedScanner is the one method the five volume-wide sessions have in
// common. XFS is not among them: its deleted-name recovery reads one directory
// at a time, so xfs_deleted takes a path and xfs_unlinked answers the
// volume-wide question the AGI can answer.
type fsDeletedScanner interface {
	ScanDeleted() (fsDeletedScan, error)
}

func NtfsDeleted(args ...object.Object) object.Object {
	return deletedScanBuiltin(args, BuiltinNameNtfsDeleted, func(arg object.Object, op string) (fsDeletedScanner, *object.Error) {
		resolved, err := resolveNTFSHandle(arg, op)
		return resolved.Session, err
	})
}

func FatDeleted(args ...object.Object) object.Object {
	return deletedScanBuiltin(args, BuiltinNameFatDeleted, func(arg object.Object, op string) (fsDeletedScanner, *object.Error) {
		resolved, err := resolveFATHandle(arg, op)
		return resolved.Session, err
	})
}

func XFATDeleted(args ...object.Object) object.Object {
	return deletedScanBuiltin(args, BuiltinNameXfatDeleted, func(arg object.Object, op string) (fsDeletedScanner, *object.Error) {
		resolved, err := resolveXFATHandle(arg, op)
		return resolved.Session, err
	})
}

func ExtDeleted(args ...object.Object) object.Object {
	return deletedScanBuiltin(args, BuiltinNameExtDeleted, func(arg object.Object, op string) (fsDeletedScanner, *object.Error) {
		resolved, err := resolveEXTHandle(arg, op)
		return resolved.Session, err
	})
}

func HFSDeleted(args ...object.Object) object.Object {
	return deletedScanBuiltin(args, BuiltinNameHfsDeleted, func(arg object.Object, op string) (fsDeletedScanner, *object.Error) {
		resolved, err := resolveHFSHandle(arg, op)
		return resolved.Session, err
	})
}

// XFSDeleted recovers deleted names from one directory.
//
// It takes a path where the other five take only a handle, and that asymmetry
// is the format's rather than an oversight. XFS deleted-entry recovery reads
// the free slots and carves the tail of a directory's own data blocks, so
// there is a directory to name; libxfs offers no volume-wide sweep, and
// silently scanning the root instead would report "/" as though it were the
// volume.
func XFSDeleted(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	resolved, errObj := resolveXFSHandle(args[0], BuiltinNameXfsDeleted)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	dirPath, errObj := requireStringArg(BuiltinNameXfsDeleted, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	session := resolved.Session
	return runDeletedScan(BuiltinNameXfsDeleted, args[0], func() (fsDeletedScan, error) {
		return session.ScanDeletedDirectory(dirPath)
	})
}

// XFSUnlinked reports the inodes on the allocation groups' unlinked chains.
//
// This is not carving and not inference. An inode reaches an AGI unlinked
// bucket because the filesystem put it there when a file was unlinked while
// still open, and it is still allocated, still fully readable, and still
// carries its own generation number. It is the only place in any of the six
// libraries where the filesystem itself asserts that a deletion happened.
func XFSUnlinked(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	resolved, errObj := resolveXFSHandle(args[0], BuiltinNameXfsUnlinked)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	session := resolved.Session
	return runDeletedScan(BuiltinNameXfsUnlinked, args[0], session.UnlinkedInodes)
}

func deletedScanBuiltin(args []object.Object, op string,
	resolve func(object.Object, string) (fsDeletedScanner, *object.Error),
) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	session, errObj := resolve(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return runDeletedScan(op, args[0], session.ScanDeleted)
}

func runDeletedScan(op string, handleArg object.Object, scan func() (fsDeletedScan, error)) object.Object {
	// The touch is recorded by whichever resolve*Handle the caller went
	// through, which is also where a handle that does not exist is refused.
	// Recording it again here would count one call as two in the manifest.
	handle := ""
	if handleObj, ok := handleArg.(*object.String); ok {
		handle = handleObj.Value
	}

	result, err := scan()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}

	return resultAndError(result.toHash(handle), nil)
}

// --- NTFS -------------------------------------------------------------------

// ntfsDeletedScope is what an MFT sweep does and does not cover.
const ntfsDeletedScope = "Every MFT record on the volume is read in entry-number " +
	"order and those whose in-use flag is clear are reported. NTFS does not " +
	"erase a record when a file is unlinked, so the name, the timestamps and " +
	"the data runs are the ones the filesystem wrote -- this is the only " +
	"format here whose deleted block map is neither zeroed nor guessed. What " +
	"it cannot say is whether those clusters have since been given to another " +
	"file: libntfs exposes no cluster-allocation query, so every entry reports " +
	"allocation_checked false and reallocated false, and the second of those " +
	"means nobody looked. A record that would not parse is counted in " +
	"unreadable, which is a number libntfs itself does not keep -- but an " +
	"unreadable record may equally be a slot never used, a record marked BAAD, " +
	"or one whose fixups failed because it was partly overwritten, and nothing " +
	"in the library distinguishes them. Names surviving in a parent " +
	"directory's index slack after the record itself was reused are not swept " +
	"here; ntfs_list_files reports those, marked deleted, per directory."

func (s *realNTFSSession) ScanDeleted() (fsDeletedScan, error) {
	scan := fsDeletedScan{
		Filesystem: "ntfs",
		Complete:   true,
		Sources:    []string{fsDeletedSourceMFTRecord},
		SourcesUnavailable: []string{
			fsDeletedSourceIndexSlack,
			fsDeletedSourceUnallocated,
		},
		WarningsAvailable: false,
		Scope:             ntfsDeletedScope,
	}

	count, err := s.volume.MFTEntryCount()
	if err != nil {
		return fsDeletedScan{}, err
	}

	// Every row is collected, not only the deleted ones: a deleted file's
	// parent directory is usually still in use, and its record is what turns a
	// name into a path.
	rows := make([]mftRow, 0, count)
	content := make(map[uint64]fsDeletedContent)

	for entryNum := uint64(0); entryNum < count; entryNum++ {
		scan.Examined++

		entry, err := s.volume.GetMFTEntry(entryNum)
		if err != nil {
			if errors.Is(err, libntfs.ErrVolumeClosed) {
				return fsDeletedScan{}, err
			}
			scan.Unreadable++
			continue
		}

		rows = append(rows, mftRowFromEntry(entry, entryNum))
		if !entry.IsInUse() {
			content[entryNum] = s.deletedContent(entry)
		}
	}

	if scan.Unreadable > 0 {
		scan.incomplete(fmt.Sprintf("%d of %d MFT records would not parse and were skipped",
			scan.Unreadable, scan.Examined))
	}

	paths := reconstructMFTPaths(rows)
	for _, row := range rows {
		if row.inUse {
			continue
		}
		scan.add(ntfsDeletedEntry(row, paths[row.record], content[row.record]))
	}

	s.recovery.remember(scan.Entries)
	return scan, nil
}

// fsDeletedContent is a byte map and the provenance of that map.
type fsDeletedContent struct {
	State string
	Runs  []fsDeletedRun
}

// deletedContent reads the surviving layout of a deleted record's $DATA.
//
// AttributeFragments covers both shapes: a resident attribute yields one
// fragment inside the MFT record itself, a non-resident one yields the run
// list as written. Neither is a reconstruction -- NTFS leaves both alone on
// unlink -- so the state is preserved rather than assumed.
func (s *realNTFSSession) deletedContent(entry *libntfs.MFTEntry) fsDeletedContent {
	attr := entry.FindPrimaryDataAttribute()
	if attr == nil {
		return fsDeletedContent{State: fsDeletedContentNone}
	}

	fragments, err := s.volume.AttributeFragments(attr)
	if err != nil || len(fragments) == 0 {
		return fsDeletedContent{State: fsDeletedContentNone}
	}

	state := fsDeletedContentPreserved
	runs := make([]fsDeletedRun, 0, len(fragments))
	for _, fragment := range fragments {
		if fragment.Resident {
			state = fsDeletedContentResident
		}
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

	return fsDeletedContent{State: state, Runs: runs}
}

func ntfsDeletedEntry(row mftRow, fullPath string, content fsDeletedContent) fsDeletedEntry {
	entry := fsDeletedEntry{
		Name:        row.name,
		Path:        fullPath,
		NameSource:  fsDeletedNameIntact,
		IsDirectory: row.isDir,
		Size:        int64(row.size),
		RecordID:    int64(row.record),
		IDKind:      "mft_record",
		ParentID:    int64(row.parent),
		Source:      fsDeletedSourceMFTRecord,
		// libntfs grades nothing here: a record either parsed or it did not,
		// and there is no second signal to weigh it against. Reporting a
		// confidence this library never computed would be inventing one.
		Confidence:   "",
		ContentState: content.State,
		Runs:         content.Runs,
		LocatedBytes: sumRuns(content.Runs),
		EntryOffset:  -1,
	}
	if row.name == "" {
		entry.NameSource = fsDeletedNameNone
	}

	// NTFS records four timestamps and none of them is a deletion time: the
	// $STANDARD_INFORMATION change time moves when the record is updated, which
	// is not the same event.
	times := siTimes(row.si)
	if row.si == nil {
		times = fnTimes(row.fn)
	}
	entry.CreatedAt = formatTime(times.created)
	entry.ModifiedAt = formatTime(times.modified)
	entry.AccessedAt = formatTime(times.accessed)

	return entry
}

// --- ext --------------------------------------------------------------------

const extDeletedScope = "Three sources are consulted and all three run: the " +
	"inode table, whose slots keep mode, size, owner and times until reused; " +
	"the orphan list and ext4 orphan file, which record inodes unlinked while " +
	"still open; and directory slack, which keeps the name the inode never " +
	"held. Block groups whose inode tables were never initialised are not " +
	"scanned, because what is in them predates the filesystem and is not a " +
	"deleted file. Two limits worth stating. ext4 zeroes the extent tree on " +
	"unlink, so content_state is usually none: the file is fully described and " +
	"cannot be located. And libext's confidence of partial means either that a " +
	"block has been reallocated or that the bitmap could not be read -- it " +
	"does not distinguish them, so reallocated true on an ext entry may mean " +
	"nobody could check. Entries on the legacy orphan chain carry no deletion " +
	"time by design, because ext stores the next-orphan pointer in the same " +
	"field; an empty deleted_at there is not an absence of evidence."

func (s *realEXTSession) ScanDeleted() (fsDeletedScan, error) {
	scan := fsDeletedScan{
		Filesystem: "ext",
		Complete:   true,
		Sources: []string{
			fsDeletedSourceInodeTable,
			fsDeletedSourceOrphanList,
			fsDeletedSourceOrphanFile,
			fsDeletedSourceDirSlack,
		},
		SourcesUnavailable: []string{fsDeletedSourceJournal},
		WarningsAvailable:  true,
		Scope:              extDeletedScope,
	}

	// The warning list is a property of the volume, not of this call, so only
	// what arrived during the scan belongs to the scan. Anything already there
	// was reported by whatever produced it.
	before := len(s.fs.Warnings())

	// The zero value consults every source and skips uninitialised groups. Its
	// negative-sense fields are what make that true, so it is passed rather
	// than assembled.
	entries, err := s.fs.DeletedEntriesWithOptions(libext.DeletedScanOptions{})
	if err != nil {
		return fsDeletedScan{}, err
	}

	for _, warning := range s.fs.Warnings()[min(before, len(s.fs.Warnings())):] {
		scan.warn(warning.Code.String(), warning.Feature, warning.Detail)
	}
	if len(scan.Warnings) > 0 {
		scan.incomplete("the scan recorded warnings; see warning_codes")
	}

	for _, deleted := range entries {
		scan.Examined++
		scan.add(s.extDeletedEntry(deleted))
	}

	s.recovery.remember(scan.Entries)
	return scan, nil
}

func (s *realEXTSession) extDeletedEntry(deleted libext.DeletedEntry) fsDeletedEntry {
	entry := fsDeletedEntry{
		Name:        deleted.Name,
		Path:        deleted.Path,
		NameSource:  fsDeletedNameIntact,
		IsDirectory: deleted.Mode&extModeTypeMask == extModeDirectory,
		Size:        int64(deleted.Size),
		RecordID:    int64(deleted.Inode),
		IDKind:      "inode",
		ParentID:    int64(deleted.ParentInode),
		Source:      deleted.Source.String(),
		Confidence:  deleted.Recoverable.String(),
		EntryOffset: -1,
		CreatedAt:   formatTime(deleted.Times.Crtime),
		ModifiedAt:  formatTime(deleted.Times.Mtime),
		AccessedAt:  formatTime(deleted.Times.Atime),
		DeletedAt:   formatTime(deleted.Times.Dtime),
	}
	if deleted.Name == "" {
		entry.NameSource = fsDeletedNameNone
	}

	// Whether a map survived is the scan's finding; converting it to image
	// offsets is the library's arithmetic. Extent.PhysicalBlock is
	// volume-relative and DataRuns is what adds the base offset, so the two
	// are kept apart deliberately: doing the multiplication here would produce
	// a partition-relative offset that looks exactly like an absolute one.
	if len(deleted.Extents) == 0 {
		entry.ContentState = fsDeletedContentNone
		return entry
	}

	ranges, err := s.fs.DataRuns(deleted.Inode)
	if err != nil {
		entry.ContentState = fsDeletedContentNone
		return entry
	}

	entry.ContentState = fsDeletedContentPreserved
	for _, byteRange := range ranges {
		offset := byteRange.DiskOffset
		if byteRange.Sparse {
			offset = -1
		}
		entry.Runs = append(entry.Runs, fsDeletedRun{
			FileOffset: byteRange.FileOffset,
			Offset:     offset,
			Length:     byteRange.Length,
			Sparse:     byteRange.Sparse,
		})
	}
	entry.LocatedBytes = sumRuns(entry.Runs)

	// judgeRecovery tested every physical block against the block bitmap, so
	// the cross-reference genuinely ran. What it cannot tell apart is a block
	// handed to another file from a bitmap it could not read; both grade
	// partial, and the scope says so.
	entry.AllocationChecked = true
	entry.Reallocated = deleted.Recoverable == libext.RecoveryPartial

	return entry
}

// --- FAT --------------------------------------------------------------------

const fatDeletedScope = "One walk reports three populations: records still in " +
	"a reachable directory with the 0xE5 deletion marker, records surviving in " +
	"the first cluster of a deleted directory, and records swept out of " +
	"clusters nothing references. The sweep examines free clusters only and " +
	"requires the '.' and '..' records to agree with the cluster they were " +
	"found in, which is what separates surviving directory data from a later " +
	"file that happens to start with entry-shaped bytes; the wider settings " +
	"that drop those guards are not used here, so a fragment whose start was " +
	"overwritten is not found. Content is located for one cluster and no " +
	"further. Deletion frees the FAT chain, so following it from a deleted " +
	"entry follows whatever owns those clusters now -- the first cluster is " +
	"the only location the surviving record itself states, and located_bytes " +
	"reports exactly that. Deletion also overwrites the first character of the " +
	"short name; where it could not be brute-forced back out of the name " +
	"checksum the library substitutes '_', and those entries report " +
	"name_source reconstructed."

func (s *realFATSession) ScanDeleted() (fsDeletedScan, error) {
	scan := fsDeletedScan{
		Filesystem: "fat",
		Complete:   true,
		Sources: []string{
			fsDeletedSourceDirectory,
			fsDeletedSourceOrphanScan,
		},
		WarningsAvailable: false,
		Scope:             fatDeletedScope,
	}

	opts := libfat.WalkOptions{
		IncludeDeleted:            true,
		DescendDeletedDirectories: true,
		IncludeOrphans:            true,
	}

	var natives []libfat.DirEntry
	err := s.volume.WalkWithOptions(context.Background(), opts,
		func(path string, parentFirstCluster uint32, dirEntry libfat.DirEntry) error {
			scan.Examined++
			if !dirEntry.Deleted && !dirEntry.Orphaned {
				return nil
			}
			if scan.add(s.fatDeletedEntry(dirEntry)) {
				natives = append(natives, dirEntry)
			}
			return nil
		})
	if err != nil {
		return fsDeletedScan{}, err
	}

	s.recovery.remember(scan.Entries, natives)
	return scan, nil
}

func (s *realFATSession) fatDeletedEntry(dirEntry libfat.DirEntry) fsDeletedEntry {
	entry := fsDeletedEntry{
		Name:        dirEntry.Name,
		Path:        dirEntry.Path,
		NameSource:  fatNameSource(dirEntry),
		IsDirectory: dirEntry.IsDirectory,
		Size:        int64(dirEntry.Size),
		RecordID:    int64(dirEntry.FirstCluster),
		IDKind:      "first_cluster",
		ParentID:    int64(dirEntry.ParentFirstCluster),
		Source:      fsDeletedSourceDirectory,
		EntryOffset: dirEntry.EntryAbsoluteOffset,
		CreatedAt:   formatTime(dirEntry.CreatedAt),
		ModifiedAt:  formatTime(dirEntry.ModifiedAt),
		AccessedAt:  formatTime(dirEntry.AccessedAt),
	}
	if dirEntry.Orphaned {
		entry.Source = fsDeletedSourceOrphanScan
	}

	// FragmentOffsets refuses to walk the FAT for a deleted entry and returns
	// the first cluster alone, which is the honest answer: the chain was freed
	// and now describes whatever came next. AssumeContiguous is the other
	// answer and it is a hypothesis, so it is not taken here -- it belongs to
	// a builtin a script has to name.
	result, err := s.volume.FragmentOffsetsWithOptions(dirEntry, libfat.FragmentOptions{})
	if err != nil || result == nil {
		entry.ContentState = fsDeletedContentNone
		return entry
	}

	entry.ContentState = fsDeletedContentFirstOnly
	if result.ChainWalked {
		entry.ContentState = fsDeletedContentPreserved
	}
	for _, fatRange := range result.Ranges {
		entry.Runs = append(entry.Runs, fsDeletedRun{
			FileOffset: fatRange.FileOffset,
			Offset:     fatRange.StartByte,
			Length:     fatRange.Length,
		})
	}
	entry.LocatedBytes = sumRuns(entry.Runs)
	entry.AllocationChecked = dirEntry.FirstCluster != 0
	entry.Reallocated = result.FirstClusterReallocated

	return entry
}

func fatNameSource(dirEntry libfat.DirEntry) string {
	switch {
	case dirEntry.Name == "":
		return fsDeletedNameNone
	case dirEntry.NameSource == libfat.NameSourceRecoveredLFN:
		return fsDeletedNameReconstruct
	case dirEntry.Deleted:
		// The short name's first character was overwritten by the deletion
		// marker. Whether it was brute-forced back or replaced with '_', the
		// name as reported is not the name as written.
		return fsDeletedNameReconstruct
	default:
		return fsDeletedNameIntact
	}
}

// --- exFAT ------------------------------------------------------------------

const xfatDeletedScope = "One walk reports records marked deleted in a " +
	"reachable directory, records surviving inside a deleted directory, and " +
	"entry sets carved out of unallocated clusters. The carve accepts a set " +
	"only when every secondary record agrees with its primary on allocation " +
	"state and a stream extension was seen, so a half-overwritten set is " +
	"dropped rather than reported half-read. exFAT is the one format here " +
	"that can state a deleted file's whole layout as a fact: a stream " +
	"extension carrying NoFatChain means the volume declared the run " +
	"contiguous before the file was deleted, and deletion did not erase that " +
	"statement, so those entries report content_state declared_contiguous " +
	"rather than a guess. Everything else reports first_cluster_only, because " +
	"the chain was freed. A carved entry whose name did not survive is given a " +
	"placeholder derived from its cluster number and reports name_source " +
	"synthetic; it is not a filename and must not be written into a report as " +
	"one."

func (s *realXFATSession) ScanDeleted() (fsDeletedScan, error) {
	scan := fsDeletedScan{
		Filesystem: "exfat",
		Complete:   true,
		Sources: []string{
			fsDeletedSourceDirectory,
			fsDeletedSourceOrphanScan,
		},
		WarningsAvailable: false,
		Scope:             xfatDeletedScope,
	}

	opts := libxfat.WalkOptions{
		IncludeDeleted:            true,
		DescendDeletedDirectories: true,
		IncludeRecovered:          true,
	}

	var natives []libxfat.Entry
	err := s.fs.WalkWithOptions(context.Background(), opts,
		func(path string, parentFirstCluster uint32, xfatEntry libxfat.Entry) error {
			scan.Examined++
			carved := strings.HasPrefix(path, libxfat.RecoveredPath)
			if !xfatEntry.IsDeleted() && !carved {
				return nil
			}
			if scan.add(s.xfatDeletedEntry(path, xfatEntry, carved)) {
				natives = append(natives, xfatEntry)
			}
			return nil
		})
	if err != nil {
		return fsDeletedScan{}, err
	}

	s.recovery.remember(scan.Entries, natives)
	return scan, nil
}

func (s *realXFATSession) xfatDeletedEntry(path string, xfatEntry libxfat.Entry, carved bool) fsDeletedEntry {
	times := xfatEntry.Timestamps()

	entry := fsDeletedEntry{
		Name:        xfatEntry.Name(),
		Path:        path,
		NameSource:  fsDeletedNameIntact,
		IsDirectory: xfatEntry.IsDir(),
		Size:        int64(xfatEntry.Size()),
		RecordID:    int64(xfatEntry.FirstCluster()),
		IDKind:      "first_cluster",
		ParentID:    int64(xfatEntry.ParentFirstCluster()),
		Source:      fsDeletedSourceDirectory,
		EntryOffset: -1,
		CreatedAt:   formatTime(times.Created),
		ModifiedAt:  formatTime(times.Modified),
		AccessedAt:  formatTime(times.Accessed),
	}
	if carved {
		entry.Source = fsDeletedSourceOrphanScan
	}
	if xfatEntry.HasSyntheticName() {
		entry.NameSource = fsDeletedNameSynthetic
	} else if xfatEntry.Name() == "" {
		entry.NameSource = fsDeletedNameNone
	}
	if offset, ok := xfatEntry.EntrySetOffset(); ok {
		entry.EntryOffset = offset
	}

	result, err := s.fs.FragmentOffsetsWithOptions(xfatEntry, libxfat.FragmentOptions{})
	if err != nil || result == nil {
		entry.ContentState = fsDeletedContentNone
		return entry
	}

	switch {
	case result.NoFatChain:
		// Not a guess the library made. The volume recorded the stream as
		// contiguous and the FAT entries for it were undefined even while the
		// file was live, so freeing the chain took nothing away.
		entry.ContentState = fsDeletedContentDeclared
	case result.ChainWalked:
		entry.ContentState = fsDeletedContentPreserved
	default:
		entry.ContentState = fsDeletedContentFirstOnly
	}

	for _, xfatRange := range result.Ranges {
		entry.Runs = append(entry.Runs, fsDeletedRun{
			FileOffset: xfatRange.FileOffset,
			Offset:     xfatRange.StartByte,
			Length:     xfatRange.Length,
		})
	}
	entry.LocatedBytes = sumRuns(entry.Runs)

	// libxfat is the only library of the six that documents the difference
	// between "the first cluster has been taken by something else" and "the
	// bitmap could not be read", and it leaves the flag false in the second
	// case. AllocationPossible is what says the record's cluster fields mean
	// anything at all.
	entry.AllocationChecked = xfatEntry.AllocationPossible()
	entry.Reallocated = result.FirstClusterReallocated

	return entry
}

// --- HFS+ -------------------------------------------------------------------

const hfsDeletedScope = "All three recovery sources run: the free space inside " +
	"live B-tree nodes, nodes the tree marks free, and catalog nodes carved " +
	"out of unallocated blocks. The third reads a large part of the image and " +
	"the library leaves it off by default for that reason; it is on here " +
	"because a scan that quietly skipped a source would report the same empty " +
	"list as one that found nothing. Records still live in the catalog are " +
	"excluded: a B-tree insert shifts records within a node and leaves the " +
	"previous bytes behind it, so a live file's record routinely appears in " +
	"slack, and reporting one as a deletion would tell an examiner a file was " +
	"removed when it never was. Two limits. The extent list on a recovered " +
	"record is the eight inline descriptors only -- the extents overflow " +
	"B-tree is not consulted for a deleted record -- so a fragmented file " +
	"reports located_bytes short of size, and the difference is map that was " +
	"never read, not content that is missing. And entry_offset is image-" +
	"absolute only for records carved from unallocated space; for the two " +
	"node-based sources the library measures from the node instead, so it is " +
	"reported as -1 with node provenance kept in record_id's neighbours rather " +
	"than handed over as an offset that would read unrelated bytes."

func (s *realHFSSession) ScanDeleted() (fsDeletedScan, error) {
	scan := fsDeletedScan{
		Filesystem: "hfs",
		Complete:   true,
		Sources: []string{
			fsDeletedSourceNodeSlack,
			fsDeletedSourceFreeNode,
			fsDeletedSourceUnallocated,
		},
		WarningsAvailable: true,
		Scope:             hfsDeletedScope,
	}

	before := len(s.volume.Anomalies())

	// A non-nil RecoveryOptions replaces the defaults rather than adding to
	// them, so every source has to be named even though two of the three are
	// what nil would have selected. MinConfidence is left at zero on purpose:
	// discarding graded evidence silently is worse than reporting it graded.
	opts := &libhfs.RecoveryOptions{
		ScanNodeSlack:   true,
		ScanFreeNodes:   true,
		ScanUnallocated: true,
	}

	var natives []libhfs.DeletedRecord
	err := s.volume.WalkDeleted(opts, func(record libhfs.DeletedRecord) error {
		scan.Examined++
		if scan.add(s.hfsDeletedEntry(record)) {
			natives = append(natives, record)
		}
		return nil
	})
	if err != nil {
		return fsDeletedScan{}, err
	}

	anomalies := s.volume.Anomalies()
	if before > len(anomalies) {
		before = len(anomalies)
	}
	for _, anomaly := range anomalies[before:] {
		scan.warn(anomaly.Op, fmt.Sprintf("%d", anomaly.Offset), anomaly.Detail)
	}
	if len(scan.Warnings) > 0 {
		scan.incomplete("the scan recorded anomalies; see warning_codes")
	}

	s.recovery.remember(scan.Entries, natives)
	return scan, nil
}

func (s *realHFSSession) hfsDeletedEntry(record libhfs.DeletedRecord) fsDeletedEntry {
	entry := fsDeletedEntry{
		Name:        record.Record.Name,
		NameSource:  fsDeletedNameIntact,
		IsDirectory: record.Record.Type == libhfs.CatalogRecordFolder,
		Size:        int64(record.Record.DataFork.LogicalSize),
		RecordID:    int64(record.Record.CNID),
		IDKind:      "cnid",
		ParentID:    int64(record.Record.ParentCNID),
		Source:      fsDeletedSourceCode(record.Source.String()),
		Confidence:  record.Confidence.String(),
		// The blocks the record points at were tested against the allocation
		// file; Overwritten is that test's answer and it is the field the
		// library calls the most important one here.
		AllocationChecked: true,
		Reallocated:       record.Overwritten,
		EntryOffset:       -1,
		CreatedAt:         formatTime(record.Record.Times.Created),
		ModifiedAt:        formatTime(record.Record.Times.ContentModified),
		AccessedAt:        formatTime(record.Record.Times.Accessed),
	}
	if record.Record.Name == "" {
		entry.NameSource = fsDeletedNameNone
	}
	if record.Source == libhfs.RecoveredFromUnallocated {
		entry.EntryOffset = record.ByteOffset
	}

	ranges, err := s.volume.ExtentRanges(record.Record.DataFork.Extents[:],
		int64(record.Record.DataFork.LogicalSize))
	if err != nil || len(ranges) == 0 {
		entry.ContentState = fsDeletedContentNone
		return entry
	}

	entry.ContentState = fsDeletedContentPreserved
	for _, byteRange := range ranges {
		entry.Runs = append(entry.Runs, fsDeletedRun{
			FileOffset: byteRange.ForkOffset,
			Offset:     byteRange.DiskOffset,
			Length:     byteRange.Length,
		})
	}
	entry.LocatedBytes = sumRuns(entry.Runs)

	return entry
}

// fsDeletedSourceCode turns a library's prose label into a code. libhfs writes
// its sources with spaces ("node slack"); every other source in this family is
// snake_case, and a script branching on a source should not have to know which
// library spelled it which way.
func fsDeletedSourceCode(label string) string {
	return strings.ReplaceAll(label, " ", "_")
}

// --- XFS --------------------------------------------------------------------

const xfsDeletedScope = "One directory is scanned: its free slots and the " +
	"records carved out of the tail of its data blocks. libxfs offers no " +
	"volume-wide sweep, which is why this takes a path where the other five " +
	"take only a handle -- scanning the root instead and calling it the volume " +
	"would be a claim about every directory from evidence about one. Best-" +
	"effort parsing is on, so a malformed block is resynchronised past and " +
	"recorded as an anomaly instead of ending the scan. Content is not " +
	"recoverable through this route at all and every entry says so: XFS clears " +
	"di_mode when an inode is freed and libxfs refuses to open an unallocated " +
	"inode, with no raw escape hatch. Names come back, bytes do not. " +
	"Short-form directories -- small ones stored inline in the inode -- carry " +
	"no deleted-entry recovery whatever, and a scan of one reports complete " +
	"false rather than an empty list. The one place XFS does yield deleted " +
	"content is xfs_unlinked."

func (s *realXFSSession) ScanDeletedDirectory(dirPath string) (fsDeletedScan, error) {
	scan := fsDeletedScan{
		Filesystem: "xfs",
		Complete:   true,
		Sources: []string{
			fsDeletedSourceFreeSlot,
			fsDeletedSourceCarved,
		},
		SourcesUnavailable: []string{fsDeletedSourceUnlinkedList},
		WarningsAvailable:  true,
		Scope:              xfsDeletedScope,
	}

	// IncludeDeleted is force-set by this API, so only BestEffort is a choice
	// here, and it is the one forensic callers want: keep what was recovered
	// from a damaged block rather than discarding the directory.
	listing, err := s.volume.ScanDirectoryRecordsByPathWithOptions(dirPath,
		libxfs.DirectoryScanOptions{BestEffort: true})
	if err != nil {
		return fsDeletedScan{}, err
	}

	for _, anomaly := range listing.Anomalies {
		scan.warn(anomaly.Code, anomaly.Path, anomaly.Message)
	}

	// Truncated is the field to read, not the error: a cap the caller set
	// himself returns no error at all, so a scan that stopped early would
	// otherwise look like one that finished.
	if listing.Truncated {
		scan.incomplete("a scan cap was reached before the directory ended")
	}
	if listing.SourceFormat == "short_form" {
		scan.incomplete("short-form directories carry no deleted-entry recovery in libxfs")
	}

	for _, record := range listing.Records {
		scan.Examined++
		if record.Kind == libxfs.RecordKindActive || (!record.IsDeleted && !record.IsCarved) {
			continue
		}
		scan.add(xfsDeletedEntry(dirPath, record))
	}

	s.recovery.remember(scan.Entries)
	return scan, nil
}

func xfsDeletedEntry(dirPath string, record libxfs.DirectoryRecord) fsDeletedEntry {
	entry := fsDeletedEntry{
		Name:       record.Name,
		Path:       path.Join(dirPath, record.Name),
		NameSource: fsDeletedNameIntact,
		RecordID:   int64(record.InodeNumber),
		IDKind:     "inode",
		ParentID:   -1,
		Source:     string(record.Kind),
		Confidence: string(record.Confidence),
		Reasons:    record.ConfidenceReasons,
		// XFS refuses to open an unallocated inode and clears di_mode when it
		// frees one, so there is no content path to report on -- not a map
		// that failed to survive, an operation the library does not offer.
		ContentState: fsDeletedContentUnsupported,
		EntryOffset:  -1,
	}
	if record.Name == "" {
		entry.NameSource = fsDeletedNameNone
		entry.Path = ""
	}
	if record.IsCarved {
		// A carved candidate is bytes that parsed as a record. The name is
		// real if it is there at all, but the framing around it was inferred.
		entry.NameSource = fsDeletedNameReconstruct
	}
	return entry
}

const xfsUnlinkedScope = "The allocation groups' unlinked inode buckets are " +
	"followed chain by chain. This is the only evidence in any of the six " +
	"filesystems that the filesystem itself asserts: an inode reaches a bucket " +
	"because it was unlinked while a process still held it open, and until " +
	"that process closes it the inode stays allocated, keeps its generation " +
	"number and stays fully readable. Content is therefore genuinely " +
	"recoverable here, and the extents reported are the live ones, not a stale " +
	"map. What the chain does not carry is a name: the directory entry is " +
	"already gone, which is what unlinked means, so name is empty and " +
	"name_source is none. A zeroed bucket array is reported once as an anomaly " +
	"rather than read as sixty-four empty chains."

func (s *realXFSSession) UnlinkedInodes() (fsDeletedScan, error) {
	scan := fsDeletedScan{
		Filesystem:         "xfs",
		Complete:           true,
		Sources:            []string{fsDeletedSourceUnlinkedList},
		SourcesUnavailable: []string{fsDeletedSourceFreeSlot, fsDeletedSourceCarved},
		WarningsAvailable:  true,
		Scope:              xfsUnlinkedScope,
	}

	ctx := context.Background()
	inodes, anomalies, err := s.volume.UnlinkedInodes(ctx)
	if err != nil {
		return fsDeletedScan{}, err
	}

	for _, anomaly := range anomalies {
		scan.warn(anomaly.Code, anomaly.Path, anomaly.Message)
	}
	if len(scan.Warnings) > 0 {
		scan.incomplete("the scan recorded anomalies; see warning_codes")
	}

	for _, unlinked := range inodes {
		scan.Examined++
		scan.add(s.xfsUnlinkedEntry(ctx, &scan, unlinked))
	}

	// The two XFS scans share one cache, so xfs_recover_file works off
	// whichever ran last. They answer different questions and only this one
	// yields content, which is why the recovery refuses an entry from the
	// other by its content_state rather than by remembering which ran.
	s.recovery.remember(scan.Entries)
	return scan, nil
}

func (s *realXFSSession) xfsUnlinkedEntry(ctx context.Context, scan *fsDeletedScan,
	unlinked libxfs.UnlinkedInode,
) fsDeletedEntry {
	entry := fsDeletedEntry{
		NameSource:   fsDeletedNameNone,
		RecordID:     int64(unlinked.InodeNumber),
		IDKind:       "inode",
		ParentID:     -1,
		Source:       fsDeletedSourceUnlinkedList,
		ContentState: fsDeletedContentNone,
		EntryOffset:  -1,
	}

	inode, err := s.volume.OpenInode(unlinked.InodeNumber)
	if err != nil {
		scan.Unreadable++
		scan.warn("inode_unreadable", fmt.Sprintf("inode %d", unlinked.InodeNumber), err.Error())
		return entry
	}

	entry.Size = int64(inode.Size)
	entry.IsDirectory = inode.IsDirectory()
	entry.ModifiedAt = formatTime(time.Unix(0, inode.ModificationTimeNS).UTC())
	entry.AccessedAt = formatTime(time.Unix(0, inode.AccessTimeNS).UTC())
	entry.CreatedAt = formatTime(time.Unix(0, inode.CreationTimeNS).UTC())

	runs, err := s.volume.DataRuns(ctx, unlinked.InodeNumber)
	if err != nil {
		scan.warn("data_runs_unavailable", fmt.Sprintf("inode %d", unlinked.InodeNumber), err.Error())
		return entry
	}

	entry.ContentState = fsDeletedContentPreserved
	for _, byteRange := range runs {
		offset := int64(byteRange.StartOffset)
		if byteRange.IsSparse {
			offset = -1
		} else if byteRange.StartOffset == 0 && byteRange.EndOffset == 0 {
			// Neither sparse nor located: the fsblock did not resolve against
			// this volume's geometry. Zero is a real offset, so it must not be
			// handed back as one.
			offset = -1
		}
		entry.Runs = append(entry.Runs, fsDeletedRun{
			FileOffset: int64(byteRange.FileOffset),
			Offset:     offset,
			Length:     int64(byteRange.LengthBytes),
			Sparse:     byteRange.IsSparse,
		})
	}
	entry.LocatedBytes = sumRuns(entry.Runs)

	// The inode is still allocated, to this file, which is precisely what
	// being on an unlinked chain means. The cross-reference is the chain
	// itself.
	entry.AllocationChecked = true

	return entry
}
