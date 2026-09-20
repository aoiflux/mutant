package builtin

// The journal families: what a filesystem wrote down about a change before it
// made the change.
//
// Everywhere else in this package a filesystem is read as a statement about
// the present -- these are the files, this is where their bytes are, this
// record is no longer in use. A journal is the one structure that is a
// statement about the past, and it is the only place a filesystem keeps its
// own history of operations that have since been superseded, undone or
// deliberately erased. Three of the six formats here keep one, and each keeps
// a different kind:
//
//   - NTFS keeps two, and they answer different questions. $LogFile is the
//     transaction log the filesystem itself replays after a crash: it records
//     the metadata operations, by LSN, with redo and undo images. The USN
//     change journal ($Extend\$UsnJrnl:$J) is not a transaction log at all --
//     it is a notification stream for applications, it carries wall-clock
//     timestamps and filenames, and it is the single richest timeline artifact
//     on a Windows volume.
//   - ext keeps JBD2, which journals whole blocks rather than operations. That
//     makes it weaker as a timeline and far stronger as a recovery source: a
//     journalled copy of an inode-table block from before an unlink still
//     carries the extent tree the unlink zeroed, which is the one thing that
//     turns an ext4 deleted file from described-but-unlocatable into
//     locatable. ext_journal_inode_versions is that path.
//   - XFS keeps XLOG, which journals operations against buffers and inodes.
//     It is the best-instrumented of the three -- checksums, cycle numbers,
//     coded anomalies -- and it has no wall-clock time anywhere at all. An XFS
//     log can say what happened and in what order, and can never say when.
//
// Circularity is the fact everything here turns on. All three journals are
// fixed regions written round and round, so the order records sit in is only
// the order they happened in until the writer laps itself. After that a
// physical walk interleaves the newest records with the oldest survivors, and
// nothing about a record's contents says which side of the seam it fell on.
// The three libraries handle this differently and none of them handles it
// invisibly, so every scan here reports:
//
//	ordering   lsn       sorted by log sequence number: the order of events
//	           stream    the order of an append-only stream: also the order of
//	                     events, because nothing was overwritten in place
//	           physical  the order records sit in the region: NOT the order of
//	                     events once the region has been written round
//
// and, beside it, the two bits. wrap_checked says whether this scan was able
// to look for the seam; wrapped says whether it found one. They are separate
// for the same reason allocation_checked and reallocated are separate in the
// *_deleted family: a check that never ran is not a negative result. Where the
// library orders by sequence number the question is already settled and the
// seam does not matter; where it hands back physical order, wrapped true means
// the array is not a timeline and must not be read as one.
//
// libext is where that distinction stops being academic. Its transaction list
// walks the journal linearly from the first block to the last, parses the
// superblock's Start and Sequence fields and then uses neither, so a wrapped
// journal comes back with stale pre-wrap transactions interleaved among new
// ones in physical order -- and its "newest first" ordering of block copies
// and inode versions is wrong in exactly that case. Mutant does not reorder
// them, because an order this library did not establish is not one this
// package gets to assert. It reports that the seam is there and leaves the
// claim unmade.
//
// The same library creates a second trap the wrap bit is the only warning of:
// a transaction whose commit block sits at a lower physical block than its
// descriptor -- which is precisely what spanning the seam means -- has its
// commit processed before the descriptor is seen, finds nothing to match, and
// is discarded. A fully committed transaction is then reported as never having
// committed, and nothing in the library flags it. Where wrapped is true this
// package says so in a warning, because committed false is otherwise read as
// evidence that an operation did not complete.
//
// Timestamps are not a property of journals, they are a property of these
// three journals individually, and timestamps_available says which one a
// reader has. USN records carry them; JBD2 carries a commit time on the commit
// block, and a transaction that never committed therefore has none rather than
// a zero one; $LogFile carries none; XLOG carries none. A timeline assembled
// from a journal with no clock is an ordering, and calling it a timeline is
// the mistake this field exists to prevent.
//
// What none of the three can report is what it skipped. libntfs has no
// warnings channel at all, and its log page walker drops an entire page -- and
// the partial record carried into it -- when the update-sequence fixups fail,
// which is to say when it meets a torn write, which is the single most
// forensically interesting event a log page can hold. It is discarded with no
// counter and no error, so a $LogFile whose every page failed its fixups and a
// pristine one both produce zero records and a nil error. libext reports
// unreadable journal blocks through a warnings channel capped at 256 for the
// lifetime of the handle. libxfs raises a coded anomaly at every failure point
// and is the only one of the three that does. warnings_available says which of
// those three situations a reader is in, and an empty warnings list means
// nothing at all when it is false.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"

	libext "github.com/aoiflux/libext"
	libntfs "github.com/aoiflux/libntfs"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

// fsJournalMaxEntries caps how many entries are rendered into the result. A
// USN journal on a working volume holds millions of records and rendering them
// all would exhaust memory long before it produced anything readable.
//
// The cap keeps the first entries in the order the library produced them and
// entry_count keeps counting past it, so entries_truncated plus entry_count
// always say how much of the journal the array is. The walk itself is never cut
// short by the cap: the wrap check and the position window cover every record,
// so a truncated result still reports honestly on the whole journal.
const fsJournalMaxEntries = 50000

// fsJournalMaxCopies caps the journalled copies of one block that are returned.
// Each carries a whole filesystem block of bytes, so this bound is on memory
// rather than on legibility.
const fsJournalMaxCopies = 256

// Which journal a result came from.
const (
	fsJournalUSN     = "usn"
	fsJournalLogFile = "logfile"
	fsJournalJBD2    = "jbd2"
	fsJournalXLOG    = "xlog"
)

// How the entries array is ordered, and therefore whether it is a timeline.
// See the file comment.
const (
	fsJournalOrderLSN      = "lsn"
	fsJournalOrderStream   = "stream"
	fsJournalOrderPhysical = "physical"
)

// Stable warning codes. A script matches on these; the detail is prose.
const (
	fsJournalWarnWrapped          = "journal_wrapped"
	fsJournalWarnCommitUnreliable = "commit_state_unreliable"
	fsJournalWarnRevokeNotParsed  = "revoke_records_not_parsed"
	fsJournalWarnNoAttributeTable = "attribute_table_empty"
	fsJournalWarnNoRestartArea    = "restart_area_unreadable"
	fsJournalWarnItemsDropped     = "transaction_items_dropped"
	fsJournalWarnTransactionLost  = "transaction_replaced"
	fsJournalWarnSuperblock       = "journal_superblock_unreadable"
)

// fsJournalWarning is the same {code, location, detail} shape the *_deleted
// family reports, deliberately: a reader who has learned to branch on one
// should not have to learn a second vocabulary for the same kind of fact.
type fsJournalWarning = fsDeletedWarning

// fsJournalScan is the envelope every journal builtin returns.
//
// The entries themselves are rendered per subsystem and carried as objects,
// because a USN record, a $LogFile transaction, a JBD2 descriptor and an XLOG
// transaction are four different claims about four different things and
// flattening them into one row shape would invent a similarity that is not
// there. What is shared is everything a reader has to know before quoting any
// of them: which journal, in what order, over what window, with what left out.
type fsJournalScan struct {
	Filesystem string
	Journal    string

	// Present reports that this volume has this journal. A volume with no
	// journal and a journal with no records both return zero entries, and
	// they are not the same finding.
	Present bool

	Entries    []object.Object
	EntryCount int64

	Ordering    string
	WrapChecked bool
	Wrapped     bool

	TimestampsAvailable bool

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsJournalWarning

	// JournalOffset and JournalBytes locate the region that was walked, or -1
	// where the library does not say. An empty result over a 128 MiB journal
	// and an empty result over a journal that does not exist read identically
	// without them.
	JournalOffset int64
	JournalBytes  int64

	// LowestPosition and HighestPosition bound the window the surviving
	// records cover, in the journal's own unit: a USN is a byte offset into
	// the $J stream, an NTFS LSN is a log sequence number, a JBD2 position is
	// a transaction sequence, an XFS position is a packed LSN. They are the
	// extremes rather than the first and last entry, so they mean the same
	// thing under physical ordering as under sequence ordering.
	LowestPosition  int64
	HighestPosition int64

	// Extra carries the fields that belong to one subsystem and have no
	// meaning in the others -- $LogFile's restart area, JBD2's superblock.
	// Each builtin's key set is fixed and declared in metadata.go, where the
	// return-fields conformance probe checks it against what is actually
	// emitted.
	Extra map[string]object.Object

	Scope string

	// lastPosition is the previous position seen in the order the library
	// produced, which is how the wrap is found. It is not rendered.
	lastPosition int64
	orderStarted bool
}

// newJournalScan starts a scan with the fields that have no sensible zero.
func newJournalScan(filesystem, journal, ordering string) fsJournalScan {
	return fsJournalScan{
		Filesystem:      filesystem,
		Journal:         journal,
		Ordering:        ordering,
		Complete:        true,
		JournalOffset:   -1,
		JournalBytes:    -1,
		LowestPosition:  -1,
		HighestPosition: -1,
		Extra:           map[string]object.Object{},
	}
}

// add renders one entry, keeping the count honest past the cap.
func (s *fsJournalScan) add(entry object.Object) bool {
	s.EntryCount++
	if len(s.Entries) >= fsJournalMaxEntries {
		return false
	}
	s.Entries = append(s.Entries, entry)
	return true
}

// position widens the window this scan covers.
func (s *fsJournalScan) position(p int64) {
	if p < 0 {
		return
	}
	if s.LowestPosition < 0 || p < s.LowestPosition {
		s.LowestPosition = p
	}
	if p > s.HighestPosition {
		s.HighestPosition = p
	}
}

// observeOrder watches the positions go by in the order the library produced
// them. A position lower than the one before it means the walk crossed the
// point where the circular region was written round, so everything after that
// point in the array is older than what came before it.
//
// It is called only where the scan has established that it can make this
// check; wrap_checked is set explicitly rather than inferred from here, so
// that a subsystem which cannot check does not report a confident false.
func (s *fsJournalScan) observeOrder(p int64) {
	if p < 0 {
		return
	}
	if s.orderStarted && p < s.lastPosition {
		s.Wrapped = true
	}
	s.lastPosition = p
	s.orderStarted = true
}

// warn records something the scan could not do, or something it can see that
// the library does not flag.
func (s *fsJournalScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsJournalWarning{Code: code, Location: location, Detail: detail})
}

// incomplete marks a known gap, keeping the first reason for it.
func (s *fsJournalScan) incomplete(reason string) {
	s.Complete = false
	if s.IncompleteReason == "" {
		s.IncompleteReason = reason
	}
}

// noteWrap raises the standing warning a wrapped physical walk earns.
func (s *fsJournalScan) noteWrap(detail string) {
	if !s.Wrapped {
		return
	}
	s.warn(fsJournalWarnWrapped, "", detail)
}

func (s fsJournalScan) toHash(handle string) *object.Hash {
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

	entries := s.Entries
	if entries == nil {
		entries = []object.Object{}
	}

	fields := map[string]object.Object{
		"handle":               stringObj(handle),
		"filesystem":           stringObj(s.Filesystem),
		"journal":              stringObj(s.Journal),
		"present":              boolObj(s.Present),
		"entries":              &object.Array{Elements: entries},
		"entry_count":          intObj(s.EntryCount),
		"entries_truncated":    boolObj(s.EntryCount > int64(len(s.Entries))),
		"ordering":             stringObj(s.Ordering),
		"wrap_checked":         boolObj(s.WrapChecked),
		"wrapped":              boolObj(s.Wrapped),
		"timestamps_available": boolObj(s.TimestampsAvailable),
		"complete":             boolObj(s.Complete),
		"incomplete_reason":    stringObj(s.IncompleteReason),
		"warnings_available":   boolObj(s.WarningsAvailable),
		"warnings":             &object.Array{Elements: warnings},
		"warning_codes":        stringArray(codes),
		"journal_offset":       intObj(s.JournalOffset),
		"journal_bytes":        intObj(s.JournalBytes),
		"lowest_position":      intObj(s.LowestPosition),
		"highest_position":     intObj(s.HighestPosition),
		"scope":                stringObj(s.Scope),
		"status":               stringObj("ok"),
	}
	for key, value := range s.Extra {
		fields[key] = value
	}
	return makeHashObject(fields)
}

// journalPosition narrows an unsigned journal position to the signed integer
// the language carries, saturating rather than wrapping.
//
// A wrapped conversion produces a large negative number that reads as a real
// position and orders wrongly against every other one; a saturated one is
// visibly the maximum and cannot be mistaken for a measurement. Neither is
// reachable on any real volume -- NTFS LSNs and XFS packed LSNs are nowhere
// near 2^63 -- which is exactly why the case would otherwise go untested.
func journalPosition(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// --- the builtins -----------------------------------------------------------

// fsJournalScanner is one journal walk, whichever subsystem it reads.
type fsJournalScanner func() (fsJournalScan, error)

// journalScanBuiltin drives every one-argument journal builtin.
func journalScanBuiltin(args []object.Object, op string,
	scan func(object.Object, string) (fsJournalScanner, *object.Error),
) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	walk, errObj := scan(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return runJournalScan(op, args[0], walk)
}

func runJournalScan(op string, handleArg object.Object, walk fsJournalScanner) object.Object {
	// The custody touch is recorded by whichever resolve*Handle the caller
	// went through, which is also where an unknown handle is refused.
	// Recording it again here would count one call as two in the manifest.
	handle := ""
	if handleObj, ok := handleArg.(*object.String); ok {
		handle = handleObj.Value
	}

	result, err := walk()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(result.toHash(handle), nil)
}

// NtfsUSNJournal reports the USN change journal.
func NtfsUSNJournal(args ...object.Object) object.Object {
	return journalScanBuiltin(args, BuiltinNameNtfsUsnJournal,
		func(arg object.Object, op string) (fsJournalScanner, *object.Error) {
			resolved, err := resolveNTFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.ScanUSNJournal, nil
		})
}

// NtfsLogRecords reports the $LogFile record stream.
func NtfsLogRecords(args ...object.Object) object.Object {
	return journalScanBuiltin(args, BuiltinNameNtfsLogRecords,
		func(arg object.Object, op string) (fsJournalScanner, *object.Error) {
			resolved, err := resolveNTFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.ScanLogRecords, nil
		})
}

// NtfsLogTransactions reports $LogFile records grouped into transactions.
func NtfsLogTransactions(args ...object.Object) object.Object {
	return journalScanBuiltin(args, BuiltinNameNtfsLogTransactions,
		func(arg object.Object, op string) (fsJournalScanner, *object.Error) {
			resolved, err := resolveNTFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.ScanLogTransactions, nil
		})
}

// ExtJournal reports the JBD2 journal's transactions and its own superblock.
func ExtJournal(args ...object.Object) object.Object {
	return journalScanBuiltin(args, BuiltinNameExtJournal,
		func(arg object.Object, op string) (fsJournalScanner, *object.Error) {
			resolved, err := resolveEXTHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.ScanJournal, nil
		})
}

// ExtJournalBlockCopies reports every journalled copy of one filesystem block.
func ExtJournalBlockCopies(args ...object.Object) object.Object {
	op := BuiltinNameExtJournalBlockCopies
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	resolved, errObj := resolveEXTHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	block, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if block < 0 {
		return resultAndError(nil, newError("%s: block number must not be negative, got %d", op, block))
	}
	session := resolved.Session
	return runJournalScan(op, args[0], func() (fsJournalScan, error) {
		return session.JournalBlockCopies(block)
	})
}

// ExtInodeVersions reports prior on-disk states of one inode, recovered from
// journalled copies of the inode-table block that holds it.
func ExtInodeVersions(args ...object.Object) object.Object {
	op := BuiltinNameExtInodeVersions
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	resolved, errObj := resolveEXTHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	inode, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if inode <= 0 {
		return resultAndError(nil, newError("%s: inode number must be positive, got %d", op, inode))
	}
	session := resolved.Session
	return runJournalScan(op, args[0], func() (fsJournalScan, error) {
		return session.JournalInodeVersions(inode)
	})
}

// ExtRecoverJournalledFile writes out the bytes a journalled inode version
// points at.
//
// It takes the inode number and the version index rather than a scan index,
// because unlike a deleted entry this one has an identifier that survives:
// the inode number is the inode number, and the version list for it is
// derived the same way on every call over the same image. What the version
// index is not is a date. Where the journal has wrapped, libext's "newest
// first" ordering is not newest first, and the version field of the result
// echoes the index so that a report cannot quietly become a claim about when.
func ExtRecoverJournalledFile(args ...object.Object) object.Object {
	op := BuiltinNameExtRecoverJournalled
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	resolved, errObj := resolveEXTHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	inode, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	version, errObj := requireIntArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	destination, errObj := requireStringArg(op, args[3], 4)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if inode <= 0 {
		return resultAndError(nil, newError("%s: inode number must be positive, got %d", op, inode))
	}
	if version < 0 {
		return resultAndError(nil, newError("%s: version must not be negative, got %d", op, version))
	}

	recovery, err := resolved.Session.RecoverJournalledFile(inode, version)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	if recovery.Content == nil || recovery.Length <= 0 {
		return resultAndError(nil, newError(
			"%s: the journalled version located no bytes, and an empty file under "+
				"a recovered file's name reads as a file that was empty", op))
	}

	written, digest, errObj := fsWriteEvidenceFile(op, destination,
		io.NewSectionReader(recovery.Content, 0, recovery.Length))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	handle := ""
	if handleObj, ok := args[0].(*object.String); ok {
		handle = handleObj.Value
	}
	return resultAndError(recoveryResultHash(handle, destination, written, digest, recovery,
		map[string]object.Object{
			"inode":   intObj(inode),
			"version": intObj(version),
		}), nil)
}

// XFSLogRecords reports the XLOG record stream.
func XFSLogRecords(args ...object.Object) object.Object {
	return journalScanBuiltin(args, BuiltinNameXfsLogRecords,
		func(arg object.Object, op string) (fsJournalScanner, *object.Error) {
			resolved, err := resolveXFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.ScanLogRecords, nil
		})
}

// XFSLogTransactions reports XLOG records grouped into transactions.
func XFSLogTransactions(args ...object.Object) object.Object {
	return journalScanBuiltin(args, BuiltinNameXfsLogTransactions,
		func(arg object.Object, op string) (fsJournalScanner, *object.Error) {
			resolved, err := resolveXFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.ScanLogTransactions, nil
		})
}

// --- NTFS: the USN change journal -------------------------------------------

const ntfsUSNScope = "The $J data stream of $Extend\\$UsnJrnl is read from its " +
	"first allocated byte to its end, and every record that parses is reported " +
	"in stream order. $J is sparse and is trimmed from the front, so the " +
	"records that survive are a contiguous window ending at the most recent " +
	"change: lowest_position and highest_position are its bounds, in USN, " +
	"which is itself a byte offset into the stream. The stream is appended to " +
	"and never overwritten in place, so stream order is the order the changes " +
	"happened in and wrapped is false as a property of the format rather than " +
	"as a measurement. What this cannot see is a journal that was deleted and " +
	"recreated -- the $Max stream carries the journal's identifier, its maximum " +
	"size and its lowest valid USN, and libntfs reads none of them, so a " +
	"journal wiped and started again looks like a volume with a short history. " +
	"Version 4 records track extents rather than names: they carry neither a " +
	"timestamp nor a filename, and report has_timestamp and has_name false " +
	"rather than a zero time and an empty string. A record libntfs cannot parse " +
	"is skipped silently and counted nowhere, and a read error partway through " +
	"the stream ends the walk with no error at all, so a truncated journal and " +
	"a short one are not distinguishable here."

func (s *realNTFSSession) ScanUSNJournal() (fsJournalScan, error) {
	scan := newJournalScan("ntfs", fsJournalUSN, fsJournalOrderStream)
	scan.TimestampsAvailable = true
	scan.WarningsAvailable = false
	// $J is appended to and trimmed from the front; nothing in it is ever
	// overwritten in place, so the seam this bit reports on cannot occur.
	scan.WrapChecked = true
	scan.Scope = ntfsUSNScope

	present, err := s.volume.HasChangeJournal()
	if err != nil {
		// "Could not check" is not "no journal", and this is the one place
		// libntfs offers the distinction -- Capabilities().ChangeJournal
		// discards this error and reports false.
		return fsJournalScan{}, fmt.Errorf("check for a change journal: %w", err)
	}
	scan.Present = present
	if !present {
		return scan, nil
	}

	if journal, openErr := s.volume.OpenUSNJournal(); openErr == nil {
		scan.JournalBytes = journal.Size()
	}

	walkErr := s.volume.EachUSNRecord(func(record *libntfs.USNRecord) error {
		scan.add(ntfsUSNRecordHash(record))
		scan.position(record.USN)
		return nil
	})
	if walkErr != nil {
		return fsJournalScan{}, walkErr
	}

	return scan, nil
}

func ntfsUSNRecordHash(record *libntfs.USNRecord) object.Object {
	// A version 4 record carries no timestamp and no name. Rendering the zero
	// time as a date would put the year 1 into a timeline beside real ones,
	// and an empty name is indistinguishable from a name that was empty.
	hasTimestamp := !record.Timestamp.IsZero()
	return makeHashObject(map[string]object.Object{
		"usn":              intObj(record.USN),
		"version":          stringObj(fmt.Sprintf("%d.%d", record.MajorVersion, record.MinorVersion)),
		"timestamp":        stringObj(formatTime(record.Timestamp)),
		"has_timestamp":    boolObj(hasTimestamp),
		"name":             stringObj(record.Name),
		"has_name":         boolObj(record.Name != ""),
		"is_directory":     boolObj(record.IsDirectory()),
		"file_reference":   intObj(journalPosition(record.FileReference)),
		"file_sequence":    intObj(int64(record.FileSequence)),
		"parent_reference": intObj(journalPosition(record.ParentReference)),
		"parent_sequence":  intObj(int64(record.ParentSequence)),
		"reason":           intObj(int64(record.Reason)),
		"reasons":          stringArray(record.ReasonNames()),
		"source_info":      intObj(int64(record.SourceInfo)),
		"security_id":      intObj(int64(record.SecurityID)),
		"file_attributes":  intObj(int64(record.FileAttributes)),
	})
}

// --- NTFS: $LogFile ---------------------------------------------------------

const ntfsLogScope = "$LogFile is read page by page and every record that " +
	"parses is reported. The log is circular and libntfs hands records back in " +
	"the order the pages sit in the file, which is the order they were written " +
	"only until the log was written round; wrapped reports whether the LSNs go " +
	"backwards anywhere in that order, which is where the seam is. $LogFile " +
	"carries no wall-clock time anywhere, so an ordering by LSN is the only " +
	"chronology available from it. The restart area bounds the log and says how " +
	"recent its contents are, and restart.open_count is a rough count of the " +
	"times the volume has been mounted. target_attribute is an offset into the " +
	"open attribute table, which is itself dumped into the log periodically: " +
	"where a dump survives, target_attribute_name and target_record resolve it " +
	"to the stream and the MFT record the operation touched, and where the log " +
	"has been written round past the last dump the table comes back empty and " +
	"every record's target stays unresolved. A page whose update-sequence " +
	"fixups fail is dropped whole, along with the partial record carried into " +
	"it, with no counter and no error -- and a fixup failure is a torn write, " +
	"so the pages most worth seeing are the ones that vanish without trace."

func (s *realNTFSSession) ScanLogRecords() (fsJournalScan, error) {
	scan := newJournalScan("ntfs", fsJournalLogFile, fsJournalOrderPhysical)
	scan.TimestampsAvailable = false
	scan.WarningsAvailable = false
	scan.WrapChecked = true
	scan.Scope = ntfsLogScope

	table := s.ntfsLogPreamble(&scan)
	if !scan.Present {
		return scan, nil
	}

	walkErr := s.volume.EachLogRecord(func(record *libntfs.LogRecord) error {
		scan.add(ntfsLogRecordHash(record, table))
		position := journalPosition(record.LSN)
		scan.position(position)
		scan.observeOrder(position)
		return nil
	})
	if walkErr != nil {
		return fsJournalScan{}, walkErr
	}

	scan.noteWrap("the LSNs go backwards partway through the page order, so the " +
		"log has been written round: entries after that point are older than the " +
		"ones before it and this array is not a timeline. Sort by lsn, or read " +
		"ntfs_log_transactions, which is ordered by it.")

	return scan, nil
}

func (s *realNTFSSession) ScanLogTransactions() (fsJournalScan, error) {
	scan := newJournalScan("ntfs", fsJournalLogFile, fsJournalOrderLSN)
	scan.TimestampsAvailable = false
	scan.WarningsAvailable = false
	scan.WrapChecked = true
	scan.Scope = ntfsLogTransactionScope

	s.ntfsLogPreamble(&scan)
	if !scan.Present {
		return scan, nil
	}

	// The grouping needs every record at once, so the wrap is observed here on
	// the physical order the walk produces, before the sort that grouping
	// applies hides it.
	var records []*libntfs.LogRecord
	walkErr := s.volume.EachLogRecord(func(record *libntfs.LogRecord) error {
		records = append(records, record)
		position := journalPosition(record.LSN)
		scan.position(position)
		scan.observeOrder(position)
		return nil
	})
	if walkErr != nil {
		return fsJournalScan{}, walkErr
	}

	scan.noteWrap("the LSNs go backwards partway through the page order, so the " +
		"log has been written round. The transactions themselves are ordered by " +
		"LSN and reading them in order is sound; what the seam costs is the " +
		"transactions whose records fell on both sides of it, which are reported " +
		"as whatever part of them survived.")

	for _, transaction := range libntfs.GroupLogTransactions(records) {
		scan.add(ntfsLogTransactionHash(transaction))
	}

	return scan, nil
}

const ntfsLogTransactionScope = "The $LogFile records are grouped into the " +
	"transactions they belong to and ordered by the LSN each began at. " +
	"TransactionID is a slot in NTFS's transaction table and not an identifier: " +
	"the table is small and its slots are reused constantly, so the same ID " +
	"belongs to thousands of unrelated transactions over the life of a log, and " +
	"a transaction is closed here when its end record appears rather than when " +
	"the ID changes. committed and forgotten are two bits and neither is the " +
	"negation of the other: NTFS ends almost every transaction with " +
	"ForgetTransaction rather than CommitTransaction, so a log holding tens of " +
	"thousands of records may contain no commit record at all, and committed " +
	"false across a whole volume is the normal reading rather than evidence " +
	"that nothing completed. end_state names which of the two was seen. " +
	"start_present reports whether the transaction's earliest surviving record " +
	"is one that names no previous record of its own -- where it is false the " +
	"beginning was overwritten by the wrap and first_lsn is merely the oldest " +
	"part that survived, which libntfs otherwise presents as the beginning."

// ntfsLogDescription is what the $LogFile scans carry about the log itself
// rather than about its contents.
//
// The key set lives in one function, called on every path including the ones
// that failed, because metadata.go declares the same set a second time and a
// path that quietly omitted one would leave the contract quoting a field that
// is not there.
func ntfsLogDescription(restart *libntfs.LogRestartArea,
	table *libntfs.LogAttributeTable, tableAvailable bool,
) map[string]object.Object {
	return map[string]object.Object{
		"restart":                   ntfsRestartHash(restart),
		"attribute_table_available": boolObj(tableAvailable),
		// Len is nil-safe, and a nil table and an empty one both report zero:
		// attribute_table_available is what tells them apart.
		"attribute_table_entries": intObj(int64(table.Len())),
	}
}

// mergeExtra folds a subsystem's own fields into the envelope.
func mergeExtra(scan *fsJournalScan, fields map[string]object.Object) {
	for key, value := range fields {
		scan.Extra[key] = value
	}
}

// ntfsLogPreamble reads the log's geometry and its open attribute table,
// filling in the parts of the scan that describe the log rather than its
// contents. It returns the table, which may be nil.
func (s *realNTFSSession) ntfsLogPreamble(scan *fsJournalScan) *libntfs.LogAttributeTable {
	restart, restartErr := s.volume.LogRestartArea()
	if restartErr != nil || restart == nil {
		detail := "the restart area could not be read, so the log's geometry and " +
			"how recent its contents are is unknown"
		if restartErr != nil {
			detail = restartErr.Error()
		}
		scan.warn(fsJournalWarnNoRestartArea, "$LogFile", detail)
		restart = nil
	} else {
		scan.JournalBytes = journalPosition(restart.FileSize)
	}

	// $LogFile is a system file and always present on an NTFS volume; what
	// varies is whether it can be opened.
	if _, openErr := s.volume.OpenLogFile(); openErr != nil {
		scan.Present = false
		scan.incomplete("$LogFile could not be opened: " + openErr.Error())
		mergeExtra(scan, ntfsLogDescription(restart, nil, false))
		return nil
	}
	scan.Present = true

	table, tableErr := s.volume.LogAttributeTable()
	available := tableErr == nil && table != nil
	mergeExtra(scan, ntfsLogDescription(restart, table, available))
	if available && table.Len() == 0 {
		// An empty table is not an error and is not an empty volume: it means
		// the log was written round past the last dump of it. Saying so is the
		// difference between "this record touched nothing" and "what it
		// touched is no longer recorded".
		scan.warn(fsJournalWarnNoAttributeTable, "$LogFile",
			"the log holds no surviving dump of the open attribute table, so "+
				"target_attribute cannot be resolved for any record: the log has "+
				"been written round since the last dump, which is the normal state "+
				"of a busy volume rather than damage")
	}
	return table
}

func ntfsRestartHash(restart *libntfs.LogRestartArea) object.Object {
	if restart == nil {
		return makeHashObject(map[string]object.Object{
			"available":     boolObj(false),
			"current_lsn":   intObj(-1),
			"chkdsk_lsn":    intObj(-1),
			"open_count":    intObj(-1),
			"log_page_size": intObj(-1),
			"file_size":     intObj(-1),
			"client_count":  intObj(-1),
			"version":       stringObj(""),
		})
	}
	return makeHashObject(map[string]object.Object{
		"available":   boolObj(true),
		"current_lsn": intObj(journalPosition(restart.CurrentLSN)),
		// Zero means chkdsk has never run on this volume, which is a finding
		// rather than a missing value, so it is reported as the zero it is.
		"chkdsk_lsn":    intObj(journalPosition(restart.ChkdskLSN)),
		"open_count":    intObj(int64(restart.RestartOpenCount)),
		"log_page_size": intObj(int64(restart.LogPageSize)),
		"file_size":     intObj(journalPosition(restart.FileSize)),
		"client_count":  intObj(int64(restart.LogClientCount)),
		"version":       stringObj(fmt.Sprintf("%d.%d", restart.MajorVersion, restart.MinorVersion)),
	})
}

func ntfsLogRecordHash(record *libntfs.LogRecord, table *libntfs.LogAttributeTable) object.Object {
	lcns := make([]object.Object, 0, len(record.LCNs))
	for _, lcn := range record.LCNs {
		lcns = append(lcns, intObj(journalPosition(lcn)))
	}

	attributeName := ""
	attributeType := ""
	targetRecord := int64(-1)
	targetSequence := int64(-1)
	if entry, ok := table.Resolve(record); ok {
		attributeName = entry.Name
		attributeType = entry.AttributeTypeName()
		targetRecord = journalPosition(entry.RecordNumber)
		targetSequence = int64(entry.SequenceNumber)
	}

	return makeHashObject(map[string]object.Object{
		"lsn":                   intObj(journalPosition(record.LSN)),
		"previous_lsn":          intObj(journalPosition(record.ClientPreviousLSN)),
		"undo_next_lsn":         intObj(journalPosition(record.ClientUndoNextLSN)),
		"transaction_id":        intObj(int64(record.TransactionID)),
		"record_type":           intObj(int64(record.RecordType)),
		"is_client_record":      boolObj(record.IsClientRecord()),
		"redo_operation":        intObj(int64(record.RedoOperation)),
		"redo_operation_name":   stringObj(record.RedoOperationName()),
		"undo_operation":        intObj(int64(record.UndoOperation)),
		"undo_operation_name":   stringObj(record.UndoOperationName()),
		"target_attribute":      intObj(int64(record.TargetAttribute)),
		"target_attribute_type": stringObj(attributeType),
		"target_attribute_name": stringObj(attributeName),
		"target_record":         intObj(targetRecord),
		"target_sequence":       intObj(targetSequence),
		"target_vcn":            intObj(record.TargetVCN),
		"mft_cluster_index":     intObj(int64(record.MFTClusterIndex)),
		"record_offset":         intObj(int64(record.RecordOffset)),
		"attribute_offset":      intObj(int64(record.AttributeOffset)),
		"lcns":                  &object.Array{Elements: lcns},
		"redo_length":           intObj(int64(len(record.RedoData))),
		"undo_length":           intObj(int64(len(record.UndoData))),
	})
}

func ntfsLogTransactionHash(transaction libntfs.LogTransaction) object.Object {
	endState := "open"
	switch {
	case transaction.Committed:
		endState = "committed"
	case transaction.Forgotten:
		endState = "forgotten"
	}

	// A record that names no previous record of its own is the first record of
	// its transaction. Where the earliest surviving record names one that is
	// no longer in the log, the transaction began before the window this scan
	// can see and first_lsn is not its beginning.
	startPresent := false
	if len(transaction.Records) > 0 && transaction.Records[0] != nil {
		startPresent = transaction.Records[0].ClientPreviousLSN == 0
	}

	return makeHashObject(map[string]object.Object{
		"transaction_id": intObj(int64(transaction.ID)),
		"first_lsn":      intObj(journalPosition(transaction.FirstLSN)),
		"last_lsn":       intObj(journalPosition(transaction.LastLSN)),
		"record_count":   intObj(int64(len(transaction.Records))),
		"committed":      boolObj(transaction.Committed),
		"forgotten":      boolObj(transaction.Forgotten),
		"end_state":      stringObj(endState),
		"start_present":  boolObj(startPresent),
		"operations":     stringArray(transaction.Operations()),
	})
}

// --- ext: the JBD2 journal --------------------------------------------------

const extJournalScope = "The JBD2 journal is walked from its first block to " +
	"its last and every descriptor and revoke record found is reported. The " +
	"journal is circular; libext reads it linearly and parses the journal " +
	"superblock's Start and Sequence fields without using either, so where the " +
	"log has been written round the transactions come back in the order their " +
	"blocks sit in, with stale pre-wrap transactions interleaved among new " +
	"ones. wrapped reports whether the sequence numbers go backwards anywhere " +
	"in that order. Where it is true, committed must not be read as a finding: " +
	"a transaction whose commit block sits at a lower physical block than its " +
	"descriptor has the commit processed first, matched against nothing and " +
	"discarded, so a transaction that did commit is reported as one that never " +
	"did. Revoke records are identified and not parsed -- they carry no tags " +
	"and a block count of zero -- and a revoke is precisely the statement that " +
	"a journalled copy must not be replayed, so the copies ext_journal_block_" +
	"copies returns cannot be known to be valid. No checksum is verified " +
	"anywhere in this journal: the v2 and v3 checksum features are read only to " +
	"decide a tag size. Unreadable journal blocks are reported through the " +
	"warnings channel, which is capped at 256 entries for the life of the " +
	"handle."

func (s *realEXTSession) ScanJournal() (fsJournalScan, error) {
	scan := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	scan.TimestampsAvailable = true
	scan.WarningsAvailable = true
	scan.WrapChecked = true
	scan.Scope = extJournalScope

	if !s.describeJournal(&scan) {
		return scan, nil
	}

	transactions, err := s.fs.ListJournalTransactionsContext(context.Background())
	if err != nil {
		return fsJournalScan{}, err
	}

	revokes := 0
	for _, transaction := range transactions {
		scan.add(extJournalTransactionHash(transaction))
		position := int64(transaction.Sequence)
		scan.position(position)
		scan.observeOrder(position)
		if len(transaction.Tags) == 0 {
			revokes++
		}
	}

	s.collectEXTWarnings(&scan)
	noteEXTWrap(&scan)

	if revokes > 0 {
		scan.warn(fsJournalWarnRevokeNotParsed, "",
			fmt.Sprintf("%d transactions carry no block tags, which is how a revoke "+
				"record reads here: libext identifies revokes and does not parse them, "+
				"so the blocks they invalidate are not known and a journalled copy "+
				"cannot be shown not to have been revoked", revokes))
	}

	return scan, nil
}

// describeJournal fills in the journal's own description and reports whether
// there is a journal here to walk.
//
// The distinction it draws is one libext's own DescribeJournalStatus does not:
// that returns "Journal disabled or external" for both, and an external
// journal is a volume that is fully journalled with the evidence on another
// device, which is not the same finding as a volume with no journal at all.
func (s *realEXTSession) describeJournal(scan *fsJournalScan) bool {
	features := s.fs.GetJournalFeatures()
	inode := s.fs.GetJournalInode()
	hasJournal := features["has_journal"]
	external := hasJournal && inode == 0

	scan.Present = hasJournal && !external

	status, statusErr := s.fs.DescribeJournalStatus()
	if statusErr != nil {
		status = ""
	}

	superblock, sbErr := s.fs.JournalSuperblock()
	available := sbErr == nil && superblock != nil
	mergeExtra(scan, extJournalDescription(inode, external, status, superblock, available, features))
	if !available && hasJournal {
		detail := "the journal superblock could not be read"
		if sbErr != nil {
			detail = sbErr.Error()
		}
		scan.warn(fsJournalWarnSuperblock, "journal superblock", detail)
	}

	if available {
		scan.JournalBytes = int64(superblock.MaxLen) * int64(superblock.BlockSize)
	}
	// GetJournalLocation is not called: its journalBlock return is never
	// assigned and is always zero, so it reports the superblock as the
	// journal's location on every filesystem. The journal is a file, and where
	// its first data run starts is where it starts.
	if inode != 0 {
		if runs, runErr := s.fs.DataRuns(inode); runErr == nil && len(runs) > 0 {
			scan.JournalOffset = runs[0].DiskOffset
		}
	}

	if external {
		scan.incomplete("the journal is on an external device, which this image " +
			"does not contain: the filesystem is journalled and the journal is not here")
	} else if !hasJournal {
		scan.incomplete("this filesystem has no journal")
	}

	return scan.Present
}

// collectEXTWarnings drains libext's warnings channel into the scan.
func (s *realEXTSession) collectEXTWarnings(scan *fsJournalScan) {
	warnings := s.fs.Warnings()
	for _, warning := range warnings {
		scan.warn(warning.Code.String(), warning.Feature, warning.Detail)
	}
	if len(warnings) >= extWarningCap {
		scan.warn(fsJournalWarnSuperblock, "",
			"libext's warnings channel is full at its cap of 256 for the life of "+
				"this handle, so anything it would have reported after this point is lost")
	}
}

// extWarningCap is libext's own bound on how many warnings it accumulates.
const extWarningCap = 256

// noteEXTWrap raises the two warnings a wrapped JBD2 journal earns: the
// ordering one every wrapped journal earns, and the commit one that is
// specific to how this library matches commit blocks to descriptors.
func noteEXTWrap(scan *fsJournalScan) {
	scan.noteWrap("the transaction sequence numbers go backwards partway through " +
		"the block order, so the journal has been written round: transactions " +
		"from before the seam are interleaved among newer ones and this array is " +
		"not a timeline")
	if !scan.Wrapped {
		return
	}
	scan.warn(fsJournalWarnCommitUnreliable, "",
		"the journal has wrapped, and libext matches a commit block only against "+
			"descriptors it has already passed in block order: a transaction whose "+
			"commit block fell on the low side of the seam has its commit discarded "+
			"and is reported as committed false although it did commit")
}

// extJournalDescription is what every ext journal builtin carries about the
// journal itself rather than about its contents. Like ntfsLogDescription, the
// key set lives in one function because metadata.go declares it twice.
func extJournalDescription(inode uint32, external bool, status string,
	superblock *libext.JournalSuperblock, available bool, features map[string]bool,
) map[string]object.Object {
	return map[string]object.Object{
		"journal_inode": intObj(int64(inode)),
		"external":      boolObj(external),
		"status_text":   stringObj(status),
		"superblock":    extJournalSuperblockHash(superblock, available),
		// The six journal_* feature bits live in the journal's own superblock,
		// so a superblock that could not be read leaves them false without
		// anything having looked. superblock.available says which it is.
		"features": extJournalFeaturesHash(features),
	}
}

func extJournalSuperblockHash(superblock *libext.JournalSuperblock, available bool) object.Object {
	if !available || superblock == nil {
		return makeHashObject(map[string]object.Object{
			"available":          boolObj(false),
			"block_size":         intObj(-1),
			"max_len":            intObj(-1),
			"first_block":        intObj(-1),
			"sequence":           intObj(-1),
			"start":              intObj(-1),
			"error_code":         intObj(-1),
			"users":              intObj(-1),
			"checksum_type":      intObj(-1),
			"fast_commit_blocks": intObj(-1),
		})
	}
	return makeHashObject(map[string]object.Object{
		"available":   boolObj(true),
		"block_size":  intObj(int64(superblock.BlockSize)),
		"max_len":     intObj(int64(superblock.MaxLen)),
		"first_block": intObj(int64(superblock.FirstBlock)),
		// Sequence and Start are where the journal's head is, which is what
		// libext's own transaction walk declines to use. They are reported so
		// that a script can see the head the ordering ignores.
		"sequence":           intObj(int64(superblock.Sequence)),
		"start":              intObj(int64(superblock.Start)),
		"error_code":         intObj(int64(superblock.ErrCode)),
		"users":              intObj(int64(superblock.NumUsers)),
		"checksum_type":      intObj(int64(superblock.ChecksumType)),
		"fast_commit_blocks": intObj(int64(superblock.FastCommitBlocks)),
	})
}

func extJournalFeaturesHash(features map[string]bool) object.Object {
	names := []string{
		"has_journal",
		"needs_recovery",
		"journal_async_commit",
		"journal_revoke",
		"journal_checksum_v2",
		"journal_checksum_v3",
		"journal_64bit",
		"journal_fast_commit",
	}
	fields := make(map[string]object.Object, len(names))
	for _, name := range names {
		fields[name] = boolObj(features[name])
	}
	return makeHashObject(fields)
}

func extJournalTransactionHash(transaction libext.JournalTransaction) object.Object {
	tags := make([]object.Object, 0, len(transaction.Tags))
	for _, tag := range transaction.Tags {
		tags = append(tags, makeHashObject(map[string]object.Object{
			"fs_block":      intObj(journalPosition(tag.FSBlock)),
			"journal_block": intObj(journalPosition(tag.JournalBlock)),
			"escaped":       boolObj(tag.Escaped),
			"same_uuid":     boolObj(tag.SameUUID),
			"last_tag":      boolObj(tag.LastTag),
		}))
	}

	// A transaction that never committed has no commit block and therefore no
	// commit time. Rendering the zero time would invent the very event its
	// absence is evidence against.
	hasTimestamp := !transaction.Timestamp.IsZero()

	return makeHashObject(map[string]object.Object{
		"sequence":      intObj(int64(transaction.Sequence)),
		"start_block":   intObj(int64(transaction.StartBlock)),
		"type":          stringObj(transaction.Type),
		"timestamp":     stringObj(formatTime(transaction.Timestamp)),
		"has_timestamp": boolObj(hasTimestamp),
		"committed":     boolObj(transaction.IsCommitted),
		// BlockCount is len(Tags) rather than a count of blocks, and is zero
		// for every revoke; tag_count is the same number under a name that
		// does not claim to be something else.
		"block_count": intObj(int64(transaction.BlockCount)),
		"tag_count":   intObj(int64(len(transaction.Tags))),
		"tags":        &object.Array{Elements: tags},
	})
}

// --- ext: journalled copies of one block ------------------------------------

const extBlockCopiesScope = "Every journalled copy of the named filesystem " +
	"block is returned, each being that block's contents at the moment a " +
	"transaction was written. libext documents them as newest first, and that " +
	"holds only while the journal has not been written round: it orders them by " +
	"the order their tags were met walking the journal linearly, so where " +
	"wrapped is true a copy from before the seam can be handed back as the " +
	"newest. This scan walks the journal a second time to establish that bit, " +
	"because a prior state of a metadata block quoted as the state immediately " +
	"before an event is a claim about time, and the ordering it rests on is the " +
	"one the library declined to make. Copies are not checked against revoke " +
	"records, which libext does not parse, so a copy here may be one the " +
	"filesystem had already declared must not be replayed. A tag naming block " +
	"zero yields a zero-filled buffer with no error, so an all-zero copy is as " +
	"likely to be a block that was never read as a block that was zeroed."

func (s *realEXTSession) JournalBlockCopies(fsBlock int64) (fsJournalScan, error) {
	scan := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	scan.TimestampsAvailable = false
	scan.WarningsAvailable = true
	scan.WrapChecked = true
	scan.Scope = extBlockCopiesScope
	scan.Extra["fs_block"] = intObj(fsBlock)

	if !s.describeJournal(&scan) {
		return scan, nil
	}
	if err := s.observeJournalOrder(&scan); err != nil {
		return fsJournalScan{}, err
	}

	copies, err := s.fs.JournalBlockCopiesContext(context.Background(), uint64(fsBlock))
	if err != nil {
		return fsJournalScan{}, err
	}

	for index, content := range copies {
		if scan.EntryCount >= fsJournalMaxCopies {
			scan.EntryCount = int64(len(copies))
			scan.incomplete(fmt.Sprintf(
				"only the first %d of %d copies are returned; each carries a whole "+
					"filesystem block", fsJournalMaxCopies, len(copies)))
			break
		}
		scan.add(extBlockCopyHash(index, content))
	}

	s.collectEXTWarnings(&scan)
	noteEXTWrap(&scan)

	return scan, nil
}

func extBlockCopyHash(index int, content []byte) object.Object {
	return makeHashObject(map[string]object.Object{
		"version":   intObj(int64(index)),
		"size":      intObj(int64(len(content))),
		"algorithm": stringObj("sha256"),
		"digest":    stringObj(sha256Hex(content)),
		"bytes":     &object.Bytes{Value: append([]byte(nil), content...)},
	})
}

// observeJournalOrder walks the transaction list for the sole purpose of
// finding the seam, and pays a whole journal walk for it.
//
// It is worth the walk. Both of the builtins that use it hand back a prior
// state of something, ordered newest first, and a prior state quoted as the
// state immediately before an event is a claim about when. Where the journal
// has wrapped that claim is unfounded, and no part of the result these
// functions return would otherwise say so.
func (s *realEXTSession) observeJournalOrder(scan *fsJournalScan) error {
	transactions, err := s.fs.ListJournalTransactionsContext(context.Background())
	if err != nil {
		return err
	}
	for _, transaction := range transactions {
		position := int64(transaction.Sequence)
		scan.position(position)
		scan.observeOrder(position)
	}
	return nil
}

// --- ext: prior states of one inode -----------------------------------------

const extInodeVersionsScope = "Prior on-disk states of the named inode are " +
	"recovered from journalled copies of the inode-table block that holds it. " +
	"This is the one path in this package that can locate an ext4 file the " +
	"filesystem itself can no longer locate: unlink zeroes the extent tree in " +
	"the live inode and leaves the rest of it, so the usual deleted ext4 file " +
	"is fully described and entirely unfindable, and a journalled copy of the " +
	"same block from before the unlink still carries the tree. Each version " +
	"reports content_state with the same vocabulary the *_deleted family uses, " +
	"and runs as image-absolute byte ranges, so a version whose content_state " +
	"is preserved can be read with raw_read_at_bytes or written out with " +
	"ext_recover_journalled_file. The ordering is libext's, which is newest " +
	"first only while the journal has not been written round, so version 0 is " +
	"the most recent surviving copy and not necessarily the state just before " +
	"the deletion. deleted_at_raw is carried beside deleted_at because ext4 " +
	"reuses the deletion-time field to hold the next inode number while an " +
	"inode sits on the legacy orphan list, and that value read as a date is a " +
	"timestamp somewhere in 1970."

func (s *realEXTSession) JournalInodeVersions(inode int64) (fsJournalScan, error) {
	scan := newJournalScan("ext", fsJournalJBD2, fsJournalOrderPhysical)
	scan.TimestampsAvailable = true
	scan.WarningsAvailable = true
	scan.WrapChecked = true
	scan.Scope = extInodeVersionsScope
	scan.Extra["inode"] = intObj(inode)

	if !s.describeJournal(&scan) {
		return scan, nil
	}
	if err := s.observeJournalOrder(&scan); err != nil {
		return fsJournalScan{}, err
	}

	versions, err := s.fs.JournalInodeVersionsContext(context.Background(), uint32(inode))
	if err != nil {
		return fsJournalScan{}, err
	}

	for index, version := range versions {
		runs, state := s.journalledInodeRuns(version)
		scan.add(extInodeVersionHash(index, version, runs, state))
	}

	s.collectEXTWarnings(&scan)
	noteEXTWrap(&scan)

	return scan, nil
}

// journalledInodeRuns converts a journalled inode's surviving extent tree into
// the image-absolute byte ranges every other run list in this package reports.
//
// libext applies this conversion itself in DataRuns, and exposes it only for
// an inode it reads from the live inode table -- byteRanges is unexported and
// there is no DataRuns that takes an Inode. So it is reproduced here, from the
// library's own block size and base offset rather than from anything this
// package assumes, because a run list in a different unit from every other run
// list in this package is a run list that will eventually be read in the wrong
// one.
func (s *realEXTSession) journalledInodeRuns(inode libext.Inode) ([]fsDeletedRun, string) {
	if s.fs.HasInlineData(inode) {
		// The content is inside the inode itself. libext reads inline data only
		// through a live inode, so this copy can be described and not read.
		return nil, fsDeletedContentResident
	}

	extents, err := s.fs.InodeExtents(inode, libext.ExtentOptions{})
	if err != nil || len(extents) == 0 {
		return nil, fsDeletedContentNone
	}

	blockSize := int64(s.fs.Superblock().BlockSize)
	base := s.fs.Options().BaseOffset
	size := int64(inode.Size)
	if blockSize <= 0 || size <= 0 {
		return nil, fsDeletedContentNone
	}

	runs := make([]fsDeletedRun, 0, len(extents))
	for _, extent := range extents {
		if extent.Inline() {
			continue
		}
		fileOffset := int64(extent.LogicalBlock) * blockSize
		if fileOffset >= size {
			break
		}
		length := int64(extent.Blocks) * blockSize
		if fileOffset+length > size {
			length = size - fileOffset
		}

		// A sparse run's offset is -1 and never 0: zero is a real image offset
		// and seeking to it returns the boot sector rather than a hole.
		offset := int64(-1)
		if !extent.Sparse() {
			offset = int64(extent.PhysicalBlock)*blockSize + base
		}
		runs = append(runs, fsDeletedRun{
			FileOffset: fileOffset,
			Offset:     offset,
			Length:     length,
			Sparse:     extent.Sparse(),
		})
	}

	if len(runs) == 0 {
		return nil, fsDeletedContentNone
	}
	return runs, fsDeletedContentPreserved
}

func extInodeVersionHash(index int, inode libext.Inode, runs []fsDeletedRun, state string) object.Object {
	return makeHashObject(map[string]object.Object{
		"version":        intObj(int64(index)),
		"inode":          intObj(int64(inode.Number)),
		"mode":           intObj(int64(inode.Mode)),
		"uid":            intObj(int64(inode.UID)),
		"gid":            intObj(int64(inode.GID)),
		"size":           intObj(int64(inode.Size)),
		"links_count":    intObj(int64(inode.LinksCount)),
		"generation":     intObj(int64(inode.Generation)),
		"flags":          intObj(int64(inode.Flags)),
		"blocks_512":     intObj(journalPosition(inode.Blocks512)),
		"is_directory":   boolObj(inode.IsDirectory),
		"is_regular":     boolObj(inode.IsRegular),
		"is_symlink":     boolObj(inode.IsSymlink),
		"has_extents":    boolObj(inode.HasExtents),
		"has_inline":     boolObj(inode.HasInline),
		"created_at":     stringObj(formatTime(inode.Crtime)),
		"has_created":    boolObj(inode.HasCrtime),
		"modified_at":    stringObj(formatTime(inode.Mtime)),
		"accessed_at":    stringObj(formatTime(inode.Atime)),
		"changed_at":     stringObj(formatTime(inode.Ctime)),
		"deleted_at":     stringObj(formatTime(inode.Dtime)),
		"deleted_at_raw": intObj(int64(inode.DtimeRaw)),
		"content_state":  stringObj(state),
		"runs":           runsArray(runs),
		"located_bytes":  intObj(sumRuns(runs)),
	})
}

// RecoverJournalledFile rebuilds one journalled version of an inode.
func (s *realEXTSession) RecoverJournalledFile(inodeNum, version int64) (fsRecovery, error) {
	versions, err := s.fs.JournalInodeVersionsContext(context.Background(), uint32(inodeNum))
	if err != nil {
		return fsRecovery{}, err
	}
	if len(versions) == 0 {
		return fsRecovery{}, fmt.Errorf(
			"the journal holds no copy of the inode-table block for inode %d, so "+
				"there is no prior state of it to recover", inodeNum)
	}
	if version < 0 || version >= int64(len(versions)) {
		return fsRecovery{}, fmt.Errorf(
			"version %d is out of range: the journal holds %d versions of inode %d, "+
				"numbered 0 to %d", version, len(versions), inodeNum, len(versions)-1)
	}

	inode := versions[version]
	runs, state := s.journalledInodeRuns(inode)
	entry := fsDeletedEntry{
		NameSource:   fsDeletedNameNone,
		IsDirectory:  inode.IsDirectory,
		Size:         int64(inode.Size),
		LocatedBytes: sumRuns(runs),
		RecordID:     int64(inode.Number),
		IDKind:       "inode",
		ParentID:     -1,
		Source:       fsDeletedSourceJournal,
		Confidence:   "",
		ContentState: state,
		Runs:         runs,
		EntryOffset:  -1,
		ModifiedAt:   formatTime(inode.Mtime),
		AccessedAt:   formatTime(inode.Atime),
		DeletedAt:    formatTime(inode.Dtime),
	}

	switch state {
	case fsDeletedContentResident:
		return fsRecovery{}, errors.New(
			"this version records inline data, held inside the inode rather than " +
				"in blocks; libext reads inline content only through a live inode, so " +
				"the copy can be described and not read")
	case fsDeletedContentNone:
		return fsRecovery{}, errors.New(
			"this version carries no extent tree either, so the copy is of the " +
				"inode after the tree had already been zeroed: an earlier version, if " +
				"the journal holds one, is where the tree would be")
	}

	recovery, err := recoveryFromRuns(s.reader, entry, runs)
	if err != nil {
		return fsRecovery{}, err
	}
	recovery.Caveats = append(recovery.Caveats,
		"the byte map is the one a journalled copy of the inode-table block "+
			"recorded, not the one the live inode holds: the filesystem has since "+
			"reallocated those blocks freely and nothing here checks whether they "+
			"still hold this file's content",
		"libext orders the versions of an inode newest first only while the "+
			"journal has not been written round; ext_journal_inode_versions reports "+
			"whether it has, and where it has this version's place in the sequence "+
			"is not a place in time")
	return recovery, nil
}

// --- XFS: the XLOG ----------------------------------------------------------

const xfsLogRecordScope = "The XFS log is read from the log region named in " +
	"the superblock and every record found is reported, sorted by log sequence " +
	"number. An LSN is a cycle and a block, and the cycle is the number of " +
	"times the log has been written round, so ordering by it is exact and " +
	"wrapped here reports a fact about the log rather than a hazard in the " +
	"ordering. cleared_blocks counts basic blocks holding a cleared record " +
	"stamp -- the well-formed zero-cycle header mkfs.xfs writes across the " +
	"whole log -- which is the difference between a log that has been quiet and " +
	"one whose records have been overwritten. checksum_checked and " +
	"checksum_valid are two bits: checked is false on a v4 image, on a record " +
	"whose stored CRC is zero, and on a header shorter than 328 bytes, and " +
	"valid means nothing unless checked is true. There is no wall-clock time " +
	"anywhere in an XFS log; this scan can say what happened and in what order, " +
	"and can never say when. The scan is bounded by libxfs's own block limit " +
	"and stops after eight unreadable blocks, and truncated rather than an " +
	"error is what says so."

func (s *realXFSSession) ScanLogRecords() (fsJournalScan, error) {
	scan := newJournalScan("xfs", fsJournalXLOG, fsJournalOrderLSN)
	scan.TimestampsAvailable = false
	scan.WarningsAvailable = true
	scan.WrapChecked = true
	scan.Scope = xfsLogRecordScope

	// The WithOptions form, always: LogRecords returns only the slice and
	// discards Truncated, ClearedBlocks, the offsets and every anomaly, so a
	// scan that stopped at a cap or after eight unreadable blocks comes back
	// looking complete with a nil error.
	result, err := s.volume.LogRecordsWithOptions(context.Background(), libxfs.LogOptions{})
	if err != nil {
		if errors.Is(err, libxfs.ErrLogNotPresent) {
			scan.Present = false
			scan.incomplete("this image holds no log: the filesystem's log is on an " +
				"external device, which is not part of this image")
			return scan, nil
		}
		return fsJournalScan{}, err
	}
	scan.Present = true
	scan.JournalOffset = journalPosition(result.StartOffset)
	if result.EndOffset > result.StartOffset {
		scan.JournalBytes = journalPosition(result.EndOffset - result.StartOffset)
	}
	scan.Extra["cleared_blocks"] = intObj(journalPosition(result.ClearedBlocks))
	scan.Extra["has_unmount_record"] = boolObj(result.HasUnmountRecord())

	cycles := map[uint32]bool{}
	for _, record := range result.Records {
		scan.add(xfsLogRecordHash(record))
		scan.position(xfsPackedLSN(record.LSN))
		cycles[record.LSN.Cycle] = true
	}
	// The cycle is the wrap count, so more than one of them among the
	// surviving records is the seam itself rather than an inference from the
	// order they came back in.
	scan.Wrapped = len(cycles) > 1

	for _, anomaly := range result.Anomalies {
		scan.warn(anomaly.Code, anomaly.Path, anomaly.Message)
	}
	if result.Truncated {
		scan.incomplete("the scan reached libxfs's own block limit before the end " +
			"of the log, so these records are not all of it")
	}
	scan.noteWrap("the surviving records carry more than one cycle number, so the " +
		"log has been written round at least once: the records are still ordered " +
		"correctly, because an LSN carries its cycle, and what the seam costs is " +
		"the records that were overwritten rather than the order of those left")

	return scan, nil
}

const xfsLogTransactionScope = "The XFS log's records are grouped into the " +
	"transactions their operations belong to, ordered by the LSN each started " +
	"at. item_count is what the transaction header claimed and items_recovered " +
	"is how many were actually rebuilt: libxfs stops at 65536 items per " +
	"transaction without raising an anomaly, so the two numbers disagreeing is " +
	"the only sign of it. committed reports that a commit region was found, and " +
	"a transaction without one was in flight when the image was captured and " +
	"never reached the filesystem, which makes it evidence of intent rather " +
	"than of change. unmount marks the record the kernel writes on a clean " +
	"unmount, so has_unmount_record false says the image was taken from a " +
	"running or a crashed system. A LOG_TRANSACTION_RESTARTED anomaly is graded " +
	"low by libxfs and means a transaction was discarded: XFS reuses " +
	"transaction identifiers aggressively, and a second start for a live one " +
	"replaces the builder and throws the first away. Transactions whose start " +
	"region was overwritten by the wrap are dropped silently, so this is a " +
	"lower bound on what the log recorded. There is no wall-clock time anywhere " +
	"in it."

func (s *realXFSSession) ScanLogTransactions() (fsJournalScan, error) {
	scan := newJournalScan("xfs", fsJournalXLOG, fsJournalOrderLSN)
	scan.TimestampsAvailable = false
	scan.WarningsAvailable = true
	scan.WrapChecked = true
	scan.Scope = xfsLogTransactionScope

	result, err := s.volume.LogTransactionsWithOptions(context.Background(), libxfs.LogOptions{})
	if err != nil {
		if errors.Is(err, libxfs.ErrLogNotPresent) {
			scan.Present = false
			scan.incomplete("this image holds no log: the filesystem's log is on an " +
				"external device, which is not part of this image")
			return scan, nil
		}
		return fsJournalScan{}, err
	}
	scan.Present = true
	scan.Extra["record_count"] = intObj(int64(result.RecordCount))
	scan.Extra["has_unmount_record"] = boolObj(result.HasUnmountRecord)

	cycles := map[uint32]bool{}
	dropped := 0
	for _, transaction := range result.Transactions {
		scan.add(xfsLogTransactionHash(transaction))
		scan.position(xfsPackedLSN(transaction.LSN))
		cycles[transaction.LSN.Cycle] = true
		if int64(transaction.ItemCount) > int64(len(transaction.Items)) {
			dropped++
		}
		for _, anomaly := range transaction.Anomalies {
			scan.warn(anomaly.Code, anomaly.Path, anomaly.Message)
		}
	}
	scan.Wrapped = len(cycles) > 1

	for _, anomaly := range result.Anomalies {
		scan.warn(anomaly.Code, anomaly.Path, anomaly.Message)
		if anomaly.Code == xfsTransactionRestarted {
			scan.warn(fsJournalWarnTransactionLost, anomaly.Path,
				"a second start for a transaction identifier still in flight replaced "+
					"the one being built and discarded it: libxfs grades this low because "+
					"XFS reuses identifiers constantly, but the transaction it replaced is "+
					"gone from this result rather than merely noted")
		}
	}
	if dropped > 0 {
		scan.warn(fsJournalWarnItemsDropped, "",
			fmt.Sprintf("%d transactions rebuilt fewer items than their headers "+
				"claimed; libxfs stops at 65536 items in one transaction and raises "+
				"no anomaly when it does", dropped))
	}
	if result.Truncated {
		scan.incomplete("the record scan the transactions were rebuilt from " +
			"stopped early, so these transactions are not all of them")
	}
	scan.noteWrap("the surviving transactions carry more than one cycle number, " +
		"so the log has been written round at least once: the ordering holds, " +
		"because an LSN carries its cycle, and the transactions whose start region " +
		"fell on the overwritten side were dropped without a trace")

	return scan, nil
}

// xfsTransactionRestarted is the anomaly libxfs raises when a transaction is
// replaced rather than merely noted.
const xfsTransactionRestarted = "LOG_TRANSACTION_RESTARTED"

// xfsPackedLSN is the LSN as one orderable number, which is how libxfs itself
// sorts. Both halves are 32 bits, so this cannot overflow the signed range
// until the cycle count passes two billion.
func xfsPackedLSN(lsn libxfs.LSN) int64 {
	return int64(lsn.Cycle)<<32 | int64(lsn.Block)
}

func xfsLogRecordHash(record libxfs.LogRecord) object.Object {
	return makeHashObject(map[string]object.Object{
		"lsn":              intObj(xfsPackedLSN(record.LSN)),
		"lsn_cycle":        intObj(int64(record.LSN.Cycle)),
		"lsn_block":        intObj(int64(record.LSN.Block)),
		"tail_lsn":         intObj(xfsPackedLSN(record.TailLSN)),
		"cycle":            intObj(int64(record.Cycle)),
		"version":          intObj(int64(record.Version)),
		"length_bytes":     intObj(int64(record.LengthBytes)),
		"operation_count":  intObj(int64(record.OperationCount)),
		"previous_block":   intObj(int64(record.PreviousBlock)),
		"start_offset":     intObj(journalPosition(record.StartOffset)),
		"end_offset":       intObj(journalPosition(record.EndOffset)),
		"checksum_checked": boolObj(record.ChecksumChecked),
		"checksum_valid":   boolObj(record.ChecksumValid),
		"checksum":         intObj(int64(record.Checksum)),
	})
}

func xfsLogTransactionHash(transaction libxfs.LogTransaction) object.Object {
	items := make([]object.Object, 0, len(transaction.Items))
	for _, item := range transaction.Items {
		items = append(items, xfsLogItemHash(item))
	}

	return makeHashObject(map[string]object.Object{
		"transaction_id": intObj(int64(transaction.TransactionID)),
		"lsn":            intObj(xfsPackedLSN(transaction.LSN)),
		"lsn_cycle":      intObj(int64(transaction.LSN.Cycle)),
		"lsn_block":      intObj(int64(transaction.LSN.Block)),
		"end_lsn":        intObj(xfsPackedLSN(transaction.EndLSN)),
		"type":           intObj(int64(transaction.Type)),
		// What the header claimed, beside what was rebuilt. libxfs truncates
		// at 65536 items in silence, and these two numbers are the only sign.
		"item_count":      intObj(int64(transaction.ItemCount)),
		"items_recovered": intObj(int64(len(transaction.Items))),
		"committed":       boolObj(transaction.Committed),
		"unmount":         boolObj(transaction.Unmount),
		"items":           &object.Array{Elements: items},
	})
}

func xfsLogItemHash(item libxfs.LogItem) object.Object {
	inode := int64(-1)
	offset := int64(-1)
	length := int64(0)

	switch {
	case item.Inode != nil:
		inode = journalPosition(item.Inode.InodeNumber)
		offset = journalPosition(item.Inode.StartOffset)
		if item.Inode.EndOffset > item.Inode.StartOffset {
			length = journalPosition(item.Inode.EndOffset - item.Inode.StartOffset)
		}
	case item.Buffer != nil:
		// Both offsets zero means the block number was negative, not that the
		// buffer sits at offset zero -- which is the superblock.
		if item.Buffer.StartOffset != 0 || item.Buffer.EndOffset != 0 {
			offset = journalPosition(item.Buffer.StartOffset)
			if item.Buffer.EndOffset > item.Buffer.StartOffset {
				length = journalPosition(item.Buffer.EndOffset - item.Buffer.StartOffset)
			}
		}
	}

	return makeHashObject(map[string]object.Object{
		"type":            intObj(int64(item.Type)),
		"type_name":       stringObj(item.TypeName),
		"host_byte_order": stringObj(item.HostByteOrder),
		"region_count":    intObj(int64(item.RegionCount)),
		"data_bytes":      intObj(int64(item.DataBytes)),
		"inode":           intObj(inode),
		"offset":          intObj(offset),
		"length":          intObj(length),
	})
}
