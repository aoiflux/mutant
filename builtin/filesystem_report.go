package builtin

// The *_report family: one document per volume, in one shape for all six.
//
// Nothing in this tree walked a volume before this file. `*_list_files` reads
// one directory, `*_metadata` one file, `*_deleted` only what was unlinked --
// so a script that wanted a timeline of a whole image had to recurse through
// the directory tree itself, one builtin call per directory, reconstructing on
// the way up what each library had already assembled on the way down. Every one
// of the six ships a Report method that does it properly, in a single pass,
// with a schema version stamped into the result so a tool reading it a year
// later can refuse a document it does not understand. Mutant called none of
// them.
//
// The six documents do not agree with each other, and the disagreement is not
// cosmetic. A file's identity is an MFT entry with a sequence number on NTFS,
// an inode with a generation on ext and XFS, a catalog node ID on HFS, and on
// FAT and exFAT a slot in a directory that the next file to be created may
// occupy. Its times are four on NTFS, five on ext -- ext is the only one of the
// six that records when a file was deleted -- three on FAT, and on HFS a set
// whose names do not line up with anyone else's. Rendering six shapes would
// push the reconciling back onto every script; rendering one and dropping what
// does not fit would throw away the evidence. So there is one shape, the fields
// that mean the same thing everywhere are named the same way, and everything a
// format records that the others do not travels verbatim in `extra`. That is
// the rule `schema_events.go` already established for artifacts, applied here
// to volumes: normalization is additive, never lossy.
//
// Three things this family refuses to round off.
//
// A fragment offset of zero is not a fragment at offset zero. libntfs leaves
// StartOffset and EndOffset at zero for a sparse run, and libxfs leaves them at
// zero both for a hole and for a run whose block number would not resolve
// against the volume's geometry. Zero is a real offset -- it is the first byte
// of the image -- so a consumer seeking there would read the boot sector and
// call it file content. Every unlocated fragment here reports `located: false`
// and offsets of -1. It is the third time this exact trap has appeared in this
// tree, after libvhdi's Extent.FileOffset, and it is the same answer each time.
//
// `complete` is not "the walk finished". Five of the six libraries can say what
// their walk reached and none of them can say what it missed; a directory tree
// walk cannot find a file no directory names, and an examiner reading a listing
// has no way to tell a volume with nothing hidden from a listing that could not
// see it. libxfs alone reconciles the walk against every inode the allocation
// groups say exists, from three independently maintained counters, and reports
// whether they balance. So completeness is two bits like everything else here:
// `completeness_checked` says whether anything reconciled the listing against
// the filesystem's own accounting, and `completeness_proven` is meaningful only
// beside it.
//
// The identity column says how to read itself. `identity_kind` names the
// addressing, and `identity_stable` says whether that identity survives the
// slot being reused -- read out of the same Capabilities the sibling
// `*_capabilities` builtin reports, never from this file's own opinion, and
// carrying `identity_stable_answered` because two of the six libraries do not
// declare it. Diffing two readings of a FAT volume on identity reports a
// deleted file whose slot was reused as a modified one, and the row that would
// have said so is here.
//
// What the reports do not do is decide anything. Fragments are read from the
// allocation structures and never assumed: `fat_recover_file_assuming_contiguous`
// is where a hypothesis about a deleted file's layout is asked for by name, and
// a report that quietly synthesised the same extents would put a guess in a
// document that reads like a record.

import (
	"context"
	"fmt"
	"sort"
	"time"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libhfs "github.com/aoiflux/libhfs"
	libxfat "github.com/aoiflux/libxfat"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

// How a file's identity is addressed on each format. The name is a code a
// script branches on, so a row from one volume can be joined to a row from
// another only when the codes match.
const (
	fsIdentityMFTEntry  = "mft_entry_sequence"
	fsIdentityInode     = "inode_generation"
	fsIdentityDirSlot   = "directory_slot"
	fsIdentityCatalogID = "catalog_node_id"
)

// How a file's fragments were derived. It is the part of a row that separates a
// fact from a hypothesis, and libfat and libxfat both say so in as many words.
const (
	fsLayoutChainWalked = "chain_walked"
	fsLayoutExtentMap   = "extent_map"
	fsLayoutRunList     = "run_list"
	fsLayoutUnavailable = "unavailable"
)

// Warning codes a report can raise.
const (
	fsReportWarnFilesTruncated     = "file_list_truncated"
	fsReportWarnFragmentsTruncated = "fragment_list_truncated"
	fsReportWarnAnomaliesTruncated = "anomaly_list_truncated"
	fsReportWarnLayoutFailed       = "layout_not_resolved"
	fsReportWarnChainBroken        = "cluster_chain_broken"
	fsReportWarnUnlocatedFragment  = "fragment_has_no_location"
	fsReportWarnNotReconciled      = "listing_not_reconciled"
	fsReportWarnNotBalanced        = "inode_accounting_does_not_balance"
	fsReportWarnIdentityUnstable   = "identity_does_not_survive_reuse"
	fsReportWarnIdentityUnanswered = "identity_stability_not_declared"
	fsReportWarnVolumeDirty        = "volume_not_cleanly_unmounted"
	fsReportWarnMirrorMismatch     = "allocation_tables_disagree"
	fsReportWarnBackupBootUsed     = "opened_from_backup_boot_sector"
	fsReportWarnOrphansTruncated   = "orphan_list_truncated"
)

const (
	// fsReportMaxFiles bounds the rendered listing. A volume with more files
	// than this has already told a script everything a truncated document can,
	// and the remainder would buy a hash large enough to exhaust memory
	// rendering it. file_count is the number the walk found and is never
	// truncated, so the figure an examiner quotes stays right even when the
	// list they read is short.
	fsReportMaxFiles = 50000

	// fsReportMaxFragments bounds one file's runs. A badly fragmented file on a
	// full FAT volume can have tens of thousands, and a report is a listing
	// rather than an extent map: *_slack and the recovery family are where a
	// file's complete layout is asked for by name.
	fsReportMaxFragments = 256

	// fsReportMaxAnomalies matches the cap the verify family already applies to
	// findings, for the same reason.
	fsReportMaxAnomalies = 1000
)

// fsReportFragment is one contiguous run of a file's data in the image.
//
// StartOffset and EndOffset are image-absolute and carry the volume's base
// offset, so a fragment from a partition opened at an offset can be compared
// with one from anywhere else without knowing where either came from. They are
// -1, and Located is false, whenever the run has no place in the image: a hole
// has none, and neither does a run whose block number would not resolve.
type fsReportFragment struct {
	StartOffset int64
	EndOffset   int64
	FileOffset  int64
	Length      int64
	Located     bool
	Sparse      bool
	Unwritten   bool
}

// fsReportLayout records how a row's fragments were derived.
type fsReportLayout struct {
	Derived      string
	Assumed      bool
	Truncated    bool
	BytesCovered int64
	Error        string
}

// fsReportFile is one file or directory, in the shape all six share.
//
// A timestamp is an RFC 3339 string or empty, never a zero date: on every one
// of these formats an unset time field reads back as an epoch, and a
// supertimeline full of 1970 rows is worse than a shorter one. Extra carries
// what this format records and the others do not.
type fsReportFile struct {
	Filesystem string
	Path       string
	Name       string
	Type       string

	Size         int64
	IsDirectory  bool
	IsDeleted    bool
	IsFragmented bool

	Identity       string
	ParentIdentity string

	Created         string
	Modified        string
	MetadataChanged string
	Accessed        string
	DeletedAt       string

	Layout        fsReportLayout
	Fragments     []fsReportFragment
	FragmentCount int64

	Extra map[string]object.Object
}

// fsReportAnomaly is one thing the library objected to while building the
// document. Severity is the library's own word where it has one.
type fsReportAnomaly struct {
	Code     string
	Severity string
	Location string
	Message  string
}

// fsReport is what a *_report builtin reports.
type fsReport struct {
	Filesystem string

	// SchemaVersion, LibraryVersion and Generated are the library's own
	// provenance, carried rather than restated. The schema version describes
	// the document's shape and the library version what produced it; they are
	// different facts and a reader who conflates them will accept a document
	// from a release that changed what a field means.
	SchemaVersion  int64
	LibraryVersion string
	Generated      string
	Name           string

	StartOffset int64
	EndOffset   int64

	Volume map[string]object.Object

	IdentityKind           string
	IdentityStable         bool
	IdentityStableAnswered bool
	FragmentsAvailable     bool
	AnomaliesAvailable     bool
	CompletenessChecked    bool
	CompletenessProven     bool

	Files           []fsReportFile
	FileCount       int64
	DeletedCount    int64
	DirectoryCount  int64
	FragmentedCount int64

	Anomalies    []fsReportAnomaly
	AnomalyCount int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsDeletedWarning

	// Scope states what the walk covered and what it did not. Every one of
	// these documents has a boundary -- a tree walk reaches only what a
	// directory names, an MFT report skips the reserved records -- and a
	// listing whose boundary is not written down invites the reader to assume
	// it had none.
	Scope string
}

// add appends a row, keeping every count honest past the cap.
//
// The per-state counts are incremented before the cap is consulted, so a
// truncated document still reports how many deleted files the walk found
// rather than how many of them fitted.
func (r *fsReport) add(file fsReportFile) {
	r.FileCount++
	if file.IsDeleted {
		r.DeletedCount++
	}
	if file.IsDirectory {
		r.DirectoryCount++
	}
	if file.IsFragmented {
		r.FragmentedCount++
	}
	if len(r.Files) < fsReportMaxFiles {
		r.Files = append(r.Files, file)
	}
}

// addAnomaly records one, keeping the count honest past the cap.
func (r *fsReport) addAnomaly(anomaly fsReportAnomaly) {
	r.AnomalyCount++
	if len(r.Anomalies) < fsReportMaxAnomalies {
		r.Anomalies = append(r.Anomalies, anomaly)
	}
}

// warn records something the report could not do, or something about the
// document a reader has to know before quoting it.
func (r *fsReport) warn(code, location, detail string) {
	r.Warnings = append(r.Warnings, fsDeletedWarning{Code: code, Location: location, Detail: detail})
}

// incomplete marks a known gap, keeping the first reason: it is the one that
// explains the earliest missing evidence, and a later gap is often its
// consequence.
func (r *fsReport) incomplete(reason string) {
	r.Complete = false
	if r.IncompleteReason == "" {
		r.IncompleteReason = reason
	}
}

// finish applies the checks every report shares, whatever produced it.
//
// It runs after the library's own answer has been read, so that truncation, an
// identity that cannot be diffed and a listing nothing reconciled are reported
// the same way on all six rather than six times over.
func (r *fsReport) finish() {
	if r.FileCount > int64(len(r.Files)) {
		r.warn(fsReportWarnFilesTruncated, "files",
			fmt.Sprintf("the walk found %d entries and this document carries the first %d; every count beside the list is of all %d",
				r.FileCount, len(r.Files), r.FileCount))
		r.incomplete("the file list was truncated at the rendering cap")
	}
	if r.AnomalyCount > int64(len(r.Anomalies)) {
		r.warn(fsReportWarnAnomaliesTruncated, "anomalies",
			fmt.Sprintf("%d anomalies were observed and the first %d are listed", r.AnomalyCount, len(r.Anomalies)))
	}

	switch {
	case !r.IdentityStableAnswered:
		r.warn(fsReportWarnIdentityUnanswered, "identity",
			"this library does not declare whether "+r.IdentityKind+" survives the slot being reused, so two readings of this volume cannot be diffed on it without deciding that question elsewhere")
	case !r.IdentityStable:
		r.warn(fsReportWarnIdentityUnstable, "identity",
			"an identity here names a slot rather than a file: a slot reused after a deletion carries its predecessor's identity exactly, so diffing two readings on it reports a replaced file as a modified one")
	}

	if !r.CompletenessChecked {
		r.warn(fsReportWarnNotReconciled, "files",
			"this listing is what the walk reached. Nothing reconciled it against the filesystem's own record of which files exist, so it cannot say that nothing else does")
		return
	}
	if !r.CompletenessProven {
		r.warn(fsReportWarnNotBalanced, "files",
			"the reconciliation ran and did not balance, so no completeness claim should be made from this listing")
	}
}

func (f fsReportFragment) toHash() object.Object {
	return makeHashObject(map[string]object.Object{
		"start_offset": intObj(f.StartOffset),
		"end_offset":   intObj(f.EndOffset),
		"file_offset":  intObj(f.FileOffset),
		"length":       intObj(f.Length),
		"located":      boolObj(f.Located),
		"sparse":       boolObj(f.Sparse),
		"unwritten":    boolObj(f.Unwritten),
	})
}

func (f fsReportFile) toHash(index int64) object.Object {
	fragments := make([]object.Object, 0, len(f.Fragments))
	for _, fragment := range f.Fragments {
		fragments = append(fragments, fragment.toHash())
	}

	extra := map[string]object.Object{}
	for key, value := range f.Extra {
		extra[key] = value
	}

	return makeHashObject(map[string]object.Object{
		"index":               intObj(index),
		"filesystem":          stringObj(f.Filesystem),
		"path":                stringObj(f.Path),
		"name":                stringObj(f.Name),
		"type":                stringObj(f.Type),
		"size":                intObj(f.Size),
		"is_directory":        boolObj(f.IsDirectory),
		"is_deleted":          boolObj(f.IsDeleted),
		"is_fragmented":       boolObj(f.IsFragmented),
		"identity":            stringObj(f.Identity),
		"parent_identity":     stringObj(f.ParentIdentity),
		"created":             stringObj(f.Created),
		"modified":            stringObj(f.Modified),
		"metadata_changed":    stringObj(f.MetadataChanged),
		"accessed":            stringObj(f.Accessed),
		"deleted_at":          stringObj(f.DeletedAt),
		"layout":              f.Layout.toHash(),
		"fragments":           &object.Array{Elements: fragments},
		"fragment_count":      intObj(f.FragmentCount),
		"fragments_truncated": boolObj(f.FragmentCount > int64(len(f.Fragments))),
		"extra":               makeHashObject(extra),
	})
}

func (l fsReportLayout) toHash() object.Object {
	derived := l.Derived
	if derived == "" {
		derived = fsLayoutUnavailable
	}
	return makeHashObject(map[string]object.Object{
		"derived":       stringObj(derived),
		"assumed":       boolObj(l.Assumed),
		"truncated":     boolObj(l.Truncated),
		"bytes_covered": intObj(l.BytesCovered),
		"error":         stringObj(l.Error),
	})
}

func (r fsReport) toHash(handle string) *object.Hash {
	files := make([]object.Object, 0, len(r.Files))
	for i, file := range r.Files {
		files = append(files, file.toHash(int64(i)))
	}

	anomalies := make([]object.Object, 0, len(r.Anomalies))
	for _, anomaly := range r.Anomalies {
		anomalies = append(anomalies, makeHashObject(map[string]object.Object{
			"code":     stringObj(anomaly.Code),
			"severity": stringObj(anomaly.Severity),
			"location": stringObj(anomaly.Location),
			"message":  stringObj(anomaly.Message),
		}))
	}

	warnings := make([]object.Object, 0, len(r.Warnings))
	codes := make([]string, 0, len(r.Warnings))
	seen := map[string]bool{}
	for _, warning := range r.Warnings {
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

	volume := map[string]object.Object{}
	for key, value := range r.Volume {
		volume[key] = value
	}

	return makeHashObject(map[string]object.Object{
		"handle":                   stringObj(handle),
		"filesystem":               stringObj(r.Filesystem),
		"schema_version":           intObj(r.SchemaVersion),
		"library_version":          stringObj(r.LibraryVersion),
		"generated":                stringObj(r.Generated),
		"name":                     stringObj(r.Name),
		"start_offset":             intObj(r.StartOffset),
		"end_offset":               intObj(r.EndOffset),
		"volume":                   makeHashObject(volume),
		"identity_kind":            stringObj(r.IdentityKind),
		"identity_stable":          boolObj(r.IdentityStable),
		"identity_stable_answered": boolObj(r.IdentityStableAnswered),
		"fragments_available":      boolObj(r.FragmentsAvailable),
		"files":                    &object.Array{Elements: files},
		"file_count":               intObj(r.FileCount),
		"files_truncated":          boolObj(r.FileCount > int64(len(r.Files))),
		"deleted_count":            intObj(r.DeletedCount),
		"directory_count":          intObj(r.DirectoryCount),
		"fragmented_count":         intObj(r.FragmentedCount),
		"anomalies":                &object.Array{Elements: anomalies},
		"anomaly_count":            intObj(r.AnomalyCount),
		"anomalies_truncated":      boolObj(r.AnomalyCount > int64(len(r.Anomalies))),
		"anomalies_available":      boolObj(r.AnomaliesAvailable),
		"completeness_checked":     boolObj(r.CompletenessChecked),
		"completeness_proven":      boolObj(r.CompletenessProven),
		"complete":                 boolObj(r.Complete),
		"incomplete_reason":        stringObj(r.IncompleteReason),
		"warnings_available":       boolObj(r.WarningsAvailable),
		"warnings":                 &object.Array{Elements: warnings},
		"warning_codes":            stringArray(codes),
		"scope":                    stringObj(r.Scope),
		"status":                   stringObj("ok"),
	})
}

// --- the builtins -----------------------------------------------------------

func NtfsReport(args ...object.Object) object.Object {
	return runReport(args, BuiltinNameNtfsReport, func(arg object.Object, op string) (fsReporter, *object.Error) {
		resolved, err := resolveNTFSHandle(arg, op)
		return resolved.Session, err
	})
}

func FatReport(args ...object.Object) object.Object {
	return runReport(args, BuiltinNameFatReport, func(arg object.Object, op string) (fsReporter, *object.Error) {
		resolved, err := resolveFATHandle(arg, op)
		return resolved.Session, err
	})
}

func XFATReport(args ...object.Object) object.Object {
	return runReport(args, BuiltinNameXfatReport, func(arg object.Object, op string) (fsReporter, *object.Error) {
		resolved, err := resolveXFATHandle(arg, op)
		return resolved.Session, err
	})
}

func ExtReport(args ...object.Object) object.Object {
	return runReport(args, BuiltinNameExtReport, func(arg object.Object, op string) (fsReporter, *object.Error) {
		resolved, err := resolveEXTHandle(arg, op)
		return resolved.Session, err
	})
}

func HFSReport(args ...object.Object) object.Object {
	return runReport(args, BuiltinNameHfsReport, func(arg object.Object, op string) (fsReporter, *object.Error) {
		resolved, err := resolveHFSHandle(arg, op)
		return resolved.Session, err
	})
}

func XFSReport(args ...object.Object) object.Object {
	return runReport(args, BuiltinNameXfsReport, func(arg object.Object, op string) (fsReporter, *object.Error) {
		resolved, err := resolveXFSHandle(arg, op)
		return resolved.Session, err
	})
}

// fsReporter is the one method the six sessions have in common here.
type fsReporter interface {
	Report() (fsReport, error)
}

func runReport(args []object.Object, op string,
	resolve func(object.Object, string) (fsReporter, *object.Error),
) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	session, errObj := resolve(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	handle := ""
	if handleObj, ok := args[0].(*object.String); ok {
		handle = handleObj.Value
	}

	report, err := session.Report()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(report.toHash(handle), nil)
}

// --- shared helpers ---------------------------------------------------------

// fsReportIdentity reads the stability of a format's identity out of the
// capability set rather than deciding it here.
//
// The report and *_capabilities therefore answer the same question from the
// same place: if a library stops declaring stable_file_identity, or starts,
// both move together and neither can drift into asserting what the library
// never said.
func fsReportIdentity(report *fsReport, caps fsCapabilitySet, kind string) {
	report.IdentityKind = kind
	for _, cap := range caps.Caps {
		if cap.Name == "stable_file_identity" {
			report.IdentityStableAnswered = true
			report.IdentityStable = cap.Supported
			return
		}
	}
}

// fsLocatedFragment builds a fragment from a pair of image offsets, treating a
// zero pair as no location at all.
//
// libntfs zeroes both offsets on a sparse run and libxfs zeroes them on a hole
// and on a run whose block number will not resolve, and in both libraries zero
// is also the first byte of the image. Every consumer of this family sees -1
// for "nowhere" instead, which is the same answer the virtual-disk family gives
// for libvhdi's Extent.FileOffset.
func fsLocatedFragment(start, end, fileOffset, length int64, sparse, unwritten bool) fsReportFragment {
	fragment := fsReportFragment{
		FileOffset: fileOffset,
		Length:     length,
		Sparse:     sparse,
		Unwritten:  unwritten,
		Located:    !(start == 0 && end == 0),
	}
	if !fragment.Located {
		fragment.StartOffset, fragment.EndOffset = -1, -1
		return fragment
	}
	fragment.StartOffset, fragment.EndOffset = start, end
	if fragment.Length == 0 && end > start {
		fragment.Length = end - start
	}
	return fragment
}

// fsAddFragment stores a run under the per-file cap, keeping the count honest.
func fsAddFragment(file *fsReportFile, fragment fsReportFragment) {
	file.FragmentCount++
	if len(file.Fragments) < fsReportMaxFragments {
		file.Fragments = append(file.Fragments, fragment)
	}
}

// fsReportFragmentWarnings raises the per-document warnings that follow from
// the rows, once, rather than once per row.
func fsReportFragmentWarnings(report *fsReport, truncatedRows, unlocatedRows, failedRows int64) {
	if truncatedRows > 0 {
		report.warn(fsReportWarnFragmentsTruncated, "files",
			fmt.Sprintf("%d files have more runs than this document carries per row; each row's fragment_count is the true number", truncatedRows))
	}
	if unlocatedRows > 0 {
		report.warn(fsReportWarnUnlocatedFragment, "files",
			fmt.Sprintf("%d files have at least one run with no place in the image -- a hole, or an address that would not resolve -- reported as located false with offsets of -1 rather than as offset zero", unlocatedRows))
	}
	if failedRows > 0 {
		report.warn(fsReportWarnLayoutFailed, "files",
			fmt.Sprintf("%d files have no resolved layout; the row is kept either way, and layout.error says why", failedRows))
		report.incomplete("some files' data could not be located")
	}
}

// fsReportTime renders one library time, leaving an unset one empty.
func fsReportTime(t time.Time) string { return formatTime(t) }

// fsReportTimePtr renders an optional library time. libhfs is the one library
// here that encodes an absent date as nil rather than as the zero value, which
// is the honest encoding and the reason this exists.
func fsReportTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}

// --- ntfs -------------------------------------------------------------------

// libntfs reports every user-space MFT record, deleted and orphaned entries
// included, with a path reconstructed by following $FILE_NAME parent
// references. The twelve reserved records -- $MFT, $LogFile, $Bitmap and the
// rest -- are skipped by the library, which is a boundary rather than a gap and
// is named in the scope.
func (s *realNTFSSession) Report() (fsReport, error) {
	raw, err := s.volume.Report()
	if err != nil {
		return fsReport{}, err
	}

	report := fsReport{
		Filesystem:         "ntfs",
		SchemaVersion:      int64(raw.SchemaVersion),
		LibraryVersion:     raw.LibraryVersion,
		Generated:          fsReportTime(raw.Generated),
		Name:               raw.Name,
		StartOffset:        raw.StartOffset,
		EndOffset:          raw.EndOffset,
		FragmentsAvailable: true,
		Complete:           true,
		WarningsAvailable:  true,
		Volume: map[string]object.Object{
			"type":       stringObj(raw.Filesystem.Type),
			"block_size": intObj(int64(raw.Filesystem.BlockSize)),
			"mft_offset": intObj(raw.Filesystem.Offset),
		},
		Scope: "every user-space MFT record on this volume, deleted and " +
			"orphaned entries included, with paths reconstructed from " +
			"$FILE_NAME parent references. The twelve reserved metadata " +
			"records are not listed: libntfs starts after them, so $MFT, " +
			"$LogFile and $Bitmap are absent by design rather than missing. " +
			"Times are the $STANDARD_INFORMATION set, which is the set an " +
			"anti-forensic tool rewrites; the $FILE_NAME copy most tools do " +
			"not touch is not in this document, and ntfs_metadata is where " +
			"the two are compared. Records that would not parse are skipped " +
			"by the library without being counted.",
	}
	fsReportIdentity(&report, ntfsCapabilitySet(s.volume.Capabilities()), fsIdentityMFTEntry)

	var truncated, unlocated int64
	for _, entry := range raw.Files {
		file := fsReportFile{
			Filesystem:      "ntfs",
			Path:            entry.Filename,
			Name:            pathBase(entry.Filename),
			Type:            entry.Type,
			Size:            entry.Size,
			IsDirectory:     entry.Type == "directory",
			IsDeleted:       entry.IsDeleted,
			IsFragmented:    entry.IsFragmented,
			Identity:        fmt.Sprintf("%d-%d", entry.EntryNumber, entry.SequenceNumber),
			ParentIdentity:  fmt.Sprintf("%d-%d", entry.ParentReference, entry.ParentSequence),
			Created:         fsReportTime(entry.Timestamps.Created),
			Modified:        fsReportTime(entry.Timestamps.Modified),
			MetadataChanged: fsReportTime(entry.Timestamps.MFTChanged),
			Accessed:        fsReportTime(entry.Timestamps.Accessed),
			Layout:          fsReportLayout{Derived: fsLayoutRunList},
			Extra: map[string]object.Object{
				"entry_number":     intObj(int64(entry.EntryNumber)),
				"sequence_number":  intObj(int64(entry.SequenceNumber)),
				"parent_reference": intObj(int64(entry.ParentReference)),
				"parent_sequence":  intObj(int64(entry.ParentSequence)),
				"file_attributes":  intObj(int64(entry.FileAttributes)),
				"hard_link_count":  intObj(int64(entry.HardLinkCount)),
			},
		}

		streams := make([]string, 0, len(entry.Streams))
		alternates := 0
		resident := false
		for _, stream := range entry.Streams {
			streams = append(streams, stream.Name)
			if stream.IsAlternate() {
				alternates++
			}
			if stream.Name == "" && stream.Resident {
				resident = true
			}
		}
		file.Extra["stream_names"] = stringArray(streams)
		file.Extra["alternate_stream_count"] = intObj(int64(alternates))
		file.Extra["resident"] = boolObj(resident)

		rowUnlocated := false
		for _, fragment := range entry.Fragments {
			run := fsLocatedFragment(fragment.StartOffset, fragment.EndOffset,
				fragment.FileOffset, fragment.Length, fragment.Sparse, false)
			if !run.Located {
				rowUnlocated = true
			}
			if fragment.Resident {
				// A resident stream lives inside the MFT record rather than in
				// allocated clusters, so its bytes are in the image but not at a
				// cluster the run list names.
				run.Located = false
				run.StartOffset, run.EndOffset = -1, -1
				rowUnlocated = true
			}
			file.Layout.BytesCovered += run.Length
			fsAddFragment(&file, run)
		}
		if file.FragmentCount > int64(len(file.Fragments)) {
			file.Layout.Truncated = true
			truncated++
		}
		if rowUnlocated {
			unlocated++
		}
		if file.FragmentCount == 0 && !file.IsDirectory && file.Size > 0 {
			file.Layout.Derived = fsLayoutUnavailable
			file.Layout.Error = "the record carries no $DATA run list"
		}

		report.add(file)
	}

	fsReportFragmentWarnings(&report, truncated, unlocated, 0)
	report.finish()
	return report, nil
}

// --- ext --------------------------------------------------------------------

// The deep scan is on: it reads the whole inode table rather than only what the
// directory tree reaches, which is the difference between a listing of live
// files and one that includes inodes nothing names any more. ext is also the
// only one of the six that records when a file was deleted, and that stamp is
// carried as deleted_at rather than folded into the other four.
func (s *realEXTSession) Report() (fsReport, error) {
	name := ""
	if s.img != nil {
		name = s.img.Name()
	}

	raw, err := s.fs.ReportWithOptionsContext(context.Background(), name, libext.ReportOptions{DeepScan: true})
	if err != nil {
		return fsReport{}, err
	}

	report := fsReport{
		Filesystem:         "ext",
		SchemaVersion:      int64(raw.SchemaVersion),
		LibraryVersion:     raw.LibraryVersion,
		Generated:          fsReportTime(raw.Generated),
		Name:               raw.Name,
		StartOffset:        raw.StartOffset,
		EndOffset:          raw.EndOffset,
		FragmentsAvailable: true,
		Complete:           true,
		WarningsAvailable:  true,
		Volume: map[string]object.Object{
			"type":       stringObj(raw.Filesystem.Type),
			"block_size": intObj(int64(raw.Filesystem.BlockSize)),
			"offset":     intObj(raw.Filesystem.Offset),
		},
		Scope: "every inode in the table, not only what the directory tree " +
			"reaches, so an inode nothing names any more is listed with " +
			"whatever path index could be built for it. dtime is carried as " +
			"deleted_at: ext is the only one of the six formats here that " +
			"records when a file was deleted, and a deletion time is not one " +
			"of the four times the others have. Fragments describe written " +
			"data only -- a preallocated span reads as zeros through the file " +
			"interface and may still hold prior contents, which is ext_slack's " +
			"question rather than this document's. Timestamps come from the " +
			"inode; on a volume whose inodes are 128 bytes there is no birth " +
			"time and no sub-second fraction at all, which ext_capabilities " +
			"reports for this volume.",
	}
	fsReportIdentity(&report, extCapabilitySet(s.fs.Capabilities()), fsIdentityInode)

	var truncated, unlocated int64
	for _, entry := range raw.Files {
		file := fsReportFile{
			Filesystem:      "ext",
			Path:            entry.Filename,
			Name:            pathBase(entry.Filename),
			Type:            entry.Type,
			Size:            entry.Size,
			IsDirectory:     entry.Type == "directory",
			IsDeleted:       entry.IsDeleted,
			IsFragmented:    entry.IsFragmented,
			Identity:        fmt.Sprintf("%d-%d", entry.InodeNumber, entry.Generation),
			ParentIdentity:  fmt.Sprintf("%d", entry.ParentInode),
			Created:         fsReportTime(entry.Times.Crtime),
			Modified:        fsReportTime(entry.Times.Mtime),
			MetadataChanged: fsReportTime(entry.Times.Ctime),
			Accessed:        fsReportTime(entry.Times.Atime),
			DeletedAt:       fsReportTime(entry.Times.Dtime),
			Layout:          fsReportLayout{Derived: fsLayoutExtentMap},
			Extra: map[string]object.Object{
				"inode_number": intObj(int64(entry.InodeNumber)),
				"generation":   intObj(int64(entry.Generation)),
				"parent_inode": intObj(int64(entry.ParentInode)),
			},
		}

		rowUnlocated := false
		for _, fragment := range entry.Fragments {
			// libext's report fragment carries no file offset of its own: the
			// runs tile the file in order, so the offset is the bytes already
			// covered. Reporting zero for every run would say every fragment
			// begins the file.
			run := fsLocatedFragment(fragment.StartOffset, fragment.EndOffset,
				file.Layout.BytesCovered, 0, false, fragment.Unwritten)
			if !run.Located {
				rowUnlocated = true
			}
			file.Layout.BytesCovered += run.Length
			fsAddFragment(&file, run)
		}
		if file.FragmentCount > int64(len(file.Fragments)) {
			file.Layout.Truncated = true
			truncated++
		}
		if rowUnlocated {
			unlocated++
		}

		report.add(file)
	}

	fsReportFragmentWarnings(&report, truncated, unlocated, 0)
	report.finish()
	return report, nil
}

// --- fat --------------------------------------------------------------------

// Deleted entries are reported at the slot they physically occupy, and a
// deleted directory is descended into under libfat's own stale-copy guard.
// Nothing is assumed: FragmentOptions is left at its zero value, which walks
// the FAT and never fabricates an extent, because a deleted entry's chain has
// been freed and a report that synthesised one would put a hypothesis in a
// document that reads like a record. fat_recover_file_assuming_contiguous is
// where that hypothesis is asked for by name.
//
// The orphan sweep is off. It is a pass over the whole data area that reports
// records no directory reaches, under a synthetic path, and can report the same
// record twice; fat_deleted is where it belongs.
func (s *realFATSession) Report() (fsReport, error) {
	name := ""
	if s.img != nil {
		name = s.img.Name()
	}

	raw, err := s.volume.ReportWithOptionsContext(context.Background(), name, libfat.ReportOptions{
		IncludeDeleted:            true,
		DescendDeletedDirectories: true,
	})
	if err != nil {
		return fsReport{}, err
	}

	report := fsReport{
		Filesystem:         "fat",
		SchemaVersion:      int64(raw.SchemaVersion),
		LibraryVersion:     raw.LibraryVersion,
		Generated:          fsReportTime(raw.Generated),
		Name:               raw.Name,
		StartOffset:        raw.StartOffset,
		EndOffset:          raw.EndOffset,
		FragmentsAvailable: true,
		Complete:           true,
		WarningsAvailable:  true,
		Volume: map[string]object.Object{
			"type":                    stringObj(raw.Filesystem.Type),
			"block_size":              intObj(int64(raw.Filesystem.BlockSize)),
			"offset":                  intObj(raw.Filesystem.Offset),
			"sector_size":             intObj(int64(raw.Filesystem.SectorSize)),
			"cluster_count":           intObj(int64(raw.Filesystem.ClusterCount)),
			"volume_label":            stringObj(raw.Filesystem.VolumeLabel),
			"volume_label_source":     stringObj(raw.Filesystem.VolumeLabelSource),
			"volume_serial":           intObj(int64(raw.Filesystem.VolumeSerial)),
			"used_backup_boot_sector": boolObj(raw.Filesystem.UsedBackupBootSector),
			"fat_mirror_mismatches":   intObj(int64(raw.Filesystem.FATMirrorMismatches)),
		},
		Scope: "the reachable directory tree with deleted entries reported at " +
			"the slots they occupy, and deleted directories descended into " +
			"where their first cluster is still free and still begins with its " +
			"own dot records. No extent is assumed: a deleted entry's FAT " +
			"chain has been freed, so its layout past the first cluster is " +
			"absent here rather than guessed. The unreferenced-cluster sweep " +
			"is not run -- fat_deleted is where records no directory reaches " +
			"are looked for. FAT records no metadata-change time at all, so " +
			"metadata_changed is empty on every row of this document for a " +
			"reason fat_capabilities states.",
	}
	fsReportIdentity(&report, fatCapabilitySet(s.volume.Capabilities()), fsIdentityDirSlot)

	if raw.Filesystem.FATMirrorMismatches > 0 {
		report.warn(fsReportWarnMirrorMismatch, "volume",
			fmt.Sprintf("%d FAT entries disagree between this volume's allocation tables, which is a tamper and damage indicator rather than a reporting problem",
				raw.Filesystem.FATMirrorMismatches))
	}
	if raw.Filesystem.UsedBackupBootSector {
		report.warn(fsReportWarnBackupBootUsed, "volume",
			"this volume was opened from its backup boot sector, so its geometry is the backup's account of itself")
	}

	var truncated, unlocated, failed int64
	for _, entry := range raw.Files {
		file := fsReportFile{
			Filesystem:     "fat",
			Path:           entry.Path,
			Name:           entry.Name,
			Type:           entry.Type,
			Size:           entry.Size,
			IsDirectory:    entry.Type == "directory",
			IsDeleted:      entry.IsDeleted,
			IsFragmented:   entry.IsFragmented,
			Identity:       fmt.Sprintf("%d:%d", entry.ParentFirstCluster, entry.EntrySlotIndex),
			ParentIdentity: fmt.Sprintf("%d", entry.ParentFirstCluster),
			Created:        fsReportTime(entry.Timestamps.Created),
			Modified:       fsReportTime(entry.Timestamps.Modified),
			Accessed:       fsReportTime(entry.Timestamps.Accessed),
			Layout: fsReportLayout{
				Derived:      fsLayoutChainWalked,
				Assumed:      entry.Layout.Assumed,
				Truncated:    entry.Layout.Truncated,
				BytesCovered: entry.Layout.BytesCovered,
				Error:        entry.Layout.Error,
			},
			Extra: map[string]object.Object{
				"short_name":                stringObj(entry.ShortName),
				"name_source":               stringObj(string(entry.NameSource)),
				"attributes":                intObj(int64(entry.Attributes)),
				"first_cluster":             intObj(int64(entry.FirstCluster)),
				"parent_first_cluster":      intObj(int64(entry.ParentFirstCluster)),
				"entry_slot_index":          intObj(int64(entry.EntrySlotIndex)),
				"entry_absolute_offset":     intObj(entry.EntryAbsoluteOffset),
				"lfn_entry_offset":          intObj(entry.LFNEntryOffset),
				"cluster_allocated":         boolObj(entry.ClusterAllocated),
				"is_orphaned":               boolObj(entry.IsOrphaned),
				"is_virtual":                boolObj(entry.IsVirtual),
				"chain_walked":              boolObj(entry.Layout.ChainWalked),
				"chain_broken":              boolObj(entry.Layout.ChainBroken),
				"loop_detected":             boolObj(entry.Layout.LoopDetected),
				"clusters_walked":           intObj(int64(entry.Layout.ClustersWalked)),
				"first_cluster_reallocated": boolObj(entry.Layout.FirstClusterReallocated),
			},
		}
		if !entry.Layout.ChainWalked {
			file.Layout.Derived = fsLayoutUnavailable
		}
		if entry.Layout.Error != "" {
			failed++
		}
		if entry.Layout.ChainBroken || entry.Layout.LoopDetected {
			report.warn(fsReportWarnChainBroken, entry.Path,
				"the cluster chain walk stopped on a free, bad or repeated entry rather than an end-of-chain marker")
		}

		rowUnlocated := false
		for _, fragment := range entry.Fragments {
			run := fsLocatedFragment(fragment.StartOffset, fragment.EndOffset,
				fragment.FileOffset, fragment.Length, fragment.Sparse, false)
			if !run.Located {
				rowUnlocated = true
			}
			fsAddFragment(&file, run)
		}
		if file.FragmentCount > int64(len(file.Fragments)) {
			file.Layout.Truncated = true
			truncated++
		}
		if rowUnlocated {
			unlocated++
		}

		report.add(file)
	}

	fsReportFragmentWarnings(&report, truncated, unlocated, failed)
	report.finish()
	return report, nil
}

// --- exfat ------------------------------------------------------------------

// The same posture as FAT, and one thing more that exFAT records and FAT does
// not: a valid data length. The bytes between it and the file size are
// allocated, readable and were never written by this file, so they are carried
// as valid_size rather than folded into the size.
func (s *realXFATSession) Report() (fsReport, error) {
	name := ""
	if s.img != nil {
		name = s.img.Name()
	}

	raw, err := s.fs.ReportWithOptionsContext(context.Background(), name, libxfat.ReportOptions{
		IncludeDeleted:            true,
		DescendDeletedDirectories: true,
	})
	if err != nil {
		return fsReport{}, err
	}

	report := fsReport{
		Filesystem:         "exfat",
		SchemaVersion:      int64(raw.SchemaVersion),
		LibraryVersion:     raw.LibraryVersion,
		Generated:          fsReportTime(raw.Generated),
		Name:               raw.Name,
		StartOffset:        raw.StartOffset,
		EndOffset:          raw.EndOffset,
		FragmentsAvailable: true,
		Complete:           true,
		WarningsAvailable:  true,
		Volume: map[string]object.Object{
			"type":                stringObj(raw.Filesystem.Type),
			"block_size":          intObj(int64(raw.Filesystem.BlockSize)),
			"offset":              intObj(raw.Filesystem.Offset),
			"sector_size":         intObj(int64(raw.Filesystem.SectorSize)),
			"sectors_per_cluster": intObj(int64(raw.Filesystem.SectorsPerCluster)),
			"cluster_count":       intObj(int64(raw.Filesystem.ClusterCount)),
			"volume_label":        stringObj(raw.Filesystem.VolumeLabel),
			"volume_serial":       intObj(int64(raw.Filesystem.VolumeSerial)),
			"revision":            stringObj(raw.Filesystem.Revision),
			"volume_dirty":        boolObj(raw.Filesystem.VolumeDirty),
			"media_failure":       boolObj(raw.Filesystem.MediaFailure),
			"active_fat":          intObj(int64(raw.Filesystem.ActiveFAT)),
			"allocated_clusters":  intObj(int64(raw.Filesystem.AllocatedClusters)),
		},
		Scope: "the reachable directory tree with deleted entries reported at " +
			"the slots they occupy. No extent is assumed, and the sweep for " +
			"records carved out of unallocated space is not run here -- " +
			"xfat_deleted is where those are looked for, with the confidence " +
			"grading this shape has nowhere to put. Each row carries its entry " +
			"set checksum as two bits, checked beside verified, because the " +
			"comparison does not happen for a synthetic entry and a verified " +
			"that nothing checked says nothing. exFAT records no " +
			"metadata-change time, so metadata_changed is empty on every row.",
	}
	fsReportIdentity(&report, xfatCapabilitySet(s.fs.Capabilities()), fsIdentityDirSlot)

	if raw.Filesystem.VolumeDirty {
		report.warn(fsReportWarnVolumeDirty, "volume",
			"this volume's flags say it was not cleanly unmounted, so its allocation bitmap and directory entries may disagree with each other")
	}

	var truncated, unlocated, failed int64
	for _, entry := range raw.Files {
		identity := ""
		if entry.Identified {
			identity = fmt.Sprintf("%d:%d", entry.ParentFirstCluster, entry.EntrySlotIndex)
		}

		file := fsReportFile{
			Filesystem:     "exfat",
			Path:           entry.Path,
			Name:           entry.Name,
			Type:           entry.Type,
			Size:           entry.Size,
			IsDirectory:    entry.IsDirectory,
			IsDeleted:      entry.IsDeleted,
			IsFragmented:   entry.IsFragmented,
			Identity:       identity,
			ParentIdentity: fmt.Sprintf("%d", entry.ParentFirstCluster),
			Created:        fsReportTime(entry.Timestamps.Created),
			Modified:       fsReportTime(entry.Timestamps.Modified),
			Accessed:       fsReportTime(entry.Timestamps.Accessed),
			Layout: fsReportLayout{
				Derived:      fsLayoutChainWalked,
				Assumed:      entry.Layout.Assumed,
				Truncated:    entry.Layout.Truncated,
				BytesCovered: entry.Layout.BytesCovered,
				Error:        entry.Layout.Error,
			},
			Extra: map[string]object.Object{
				"valid_size":            intObj(entry.ValidSize),
				"attributes":            intObj(int64(entry.Attributes)),
				"secondary_flags":       intObj(int64(entry.SecondaryFlags)),
				"record_type":           intObj(int64(entry.RecordType)),
				"first_cluster":         intObj(int64(entry.FirstCluster)),
				"parent_first_cluster":  intObj(int64(entry.ParentFirstCluster)),
				"entry_slot_index":      intObj(int64(entry.EntrySlotIndex)),
				"entry_absolute_offset": intObj(entry.EntryAbsoluteOffset),
				"identified":            boolObj(entry.Identified),
				"cluster_allocated":     boolObj(entry.ClusterAllocated),
				"allocation_possible":   boolObj(entry.AllocationPossible),
				"is_recovered":          boolObj(entry.IsRecovered),
				"is_virtual":            boolObj(entry.IsVirtual),
				"synthetic_name":        boolObj(entry.SyntheticName),
				"checksum_checked":      boolObj(entry.ChecksumChecked),
				"checksum_verified":     boolObj(entry.ChecksumVerified),
				"created_offset_valid":  boolObj(entry.Timestamps.CreatedOffsetValid),
				"modified_offset_valid": boolObj(entry.Timestamps.ModifiedOffsetValid),
				"accessed_offset_valid": boolObj(entry.Timestamps.AccessedOffsetValid),
				"chain_walked":          boolObj(entry.Layout.ChainWalked),
				"chain_broken":          boolObj(entry.Layout.ChainBroken),
				"loop_detected":         boolObj(entry.Layout.LoopDetected),
				"clusters_walked":       intObj(int64(entry.Layout.ClustersWalked)),
				"no_fat_chain":          boolObj(entry.Layout.NoFatChain),
			},
		}
		if !entry.Layout.ChainWalked {
			file.Layout.Derived = fsLayoutUnavailable
		}
		if entry.Layout.Error != "" {
			failed++
		}
		if entry.Layout.ChainBroken || entry.Layout.LoopDetected {
			report.warn(fsReportWarnChainBroken, entry.Path,
				"the cluster chain walk stopped on a free, bad or repeated entry rather than an end-of-chain marker")
		}

		rowUnlocated := false
		for _, fragment := range entry.Fragments {
			run := fsLocatedFragment(fragment.StartOffset, fragment.EndOffset,
				fragment.FileOffset, fragment.Length, fragment.Sparse, false)
			if !run.Located {
				rowUnlocated = true
			}
			fsAddFragment(&file, run)
		}
		if file.FragmentCount > int64(len(file.Fragments)) {
			file.Layout.Truncated = true
			truncated++
		}
		if rowUnlocated {
			unlocated++
		}

		report.add(file)
	}

	fsReportFragmentWarnings(&report, truncated, unlocated, failed)
	report.finish()
	return report, nil
}

// --- hfs --------------------------------------------------------------------

// The file listing is off by default in libhfs and unbounded here, because a
// bound would make file_count the cap rather than the number of records on the
// volume. The system files are kept: the private directories hard links are
// stored in are exactly where an examination looks, and leaving them out would
// be a listing of user data rather than of the volume.
//
// This is the one of the six with no per-file layout. libhfs's report carries a
// catalog record and its path and no extents, so fragments_available is false
// rather than every row carrying an empty list that reads like a file with no
// data.
func (s *realHFSSession) Report() (fsReport, error) {
	raw, err := s.volume.ReportContext(context.Background(), &libhfs.ReportOptions{
		IncludeFiles:       true,
		MaxFiles:           -1,
		IncludeSystemFiles: true,
	})
	if err != nil {
		return fsReport{}, err
	}

	report := fsReport{
		Filesystem:         "hfs",
		SchemaVersion:      int64(raw.SchemaVersion),
		LibraryVersion:     raw.LibraryVersion,
		Generated:          fsReportTime(raw.Generated),
		Name:               raw.Volume.Name,
		StartOffset:        raw.Volume.BaseOffset,
		EndOffset:          raw.Volume.BaseOffset + int64(raw.Volume.TotalBytes),
		FragmentsAvailable: false,
		AnomaliesAvailable: true,
		Complete:           true,
		WarningsAvailable:  true,
		Volume: map[string]object.Object{
			"kind":            stringObj(raw.Volume.Kind),
			"version":         intObj(int64(raw.Volume.Version)),
			"identifier":      stringObj(raw.Volume.Identifier),
			"uuid":            stringObj(raw.Volume.UUID),
			"block_size":      intObj(int64(raw.Volume.BlockSize)),
			"total_blocks":    intObj(int64(raw.Volume.TotalBlocks)),
			"free_blocks":     intObj(int64(raw.Volume.FreeBlocks)),
			"total_bytes":     intObj(int64(raw.Volume.TotalBytes)),
			"free_bytes":      intObj(int64(raw.Volume.FreeBytes)),
			"file_count":      intObj(int64(raw.Volume.FileCount)),
			"folder_count":    intObj(int64(raw.Volume.FolderCount)),
			"next_catalog_id": intObj(int64(raw.Volume.NextCatalogID)),
			"journaled":       boolObj(raw.Volume.Journaled),
			"created":         stringObj(fsReportTimePtr(raw.Volume.Created)),
			"modified":        stringObj(fsReportTimePtr(raw.Volume.Modified)),
			"backup":          stringObj(fsReportTimePtr(raw.Volume.Backup)),
			"checked":         stringObj(fsReportTimePtr(raw.Volume.Checked)),
		},
		Scope: "every catalog record on the volume, the filesystem's own " +
			"metadata included, with no bound on the listing. There are no " +
			"fragments: libhfs's report carries catalog records and paths and " +
			"no extents, so fragments_available is false rather than every row " +
			"claiming a file with no data. metadata_changed is the HFS+ " +
			"attribute-modification date, which is the field that moves when a " +
			"record's metadata changes and so is this format's ctime; the " +
			"volume's own backup date and each record's are carried " +
			"separately. On a classic HFS volume the stored times are local " +
			"wall clock with no recorded offset and are read as UTC because " +
			"there is nothing else to read them as -- each row's time_source " +
			"says which kind it is, and comparing across the two compares " +
			"different clocks. The block counts are the volume header's claim " +
			"rather than a count of the allocation bitmap, and a disagreement " +
			"between the two is itself a finding.",
	}
	fsReportIdentity(&report, hfsCapabilitySet(s.volume.Capabilities()), fsIdentityCatalogID)

	if raw.FilesTruncated {
		report.incomplete("libhfs truncated its own catalog listing")
	}

	for _, anomaly := range raw.Anomalies {
		report.addAnomaly(fsReportAnomaly{
			Code:     anomaly.Op,
			Severity: "",
			Location: fmt.Sprintf("%d", anomaly.Offset),
			Message:  anomaly.Detail,
		})
	}
	// libhfs counts repeats of an (Op, Detail) pair without appending them, so
	// its own total is the authority for how many were observed.
	if int64(raw.AnomalyTotal) > report.AnomalyCount {
		report.AnomalyCount = int64(raw.AnomalyTotal)
	}

	for _, entry := range raw.Files {
		file := fsReportFile{
			Filesystem:      "hfs",
			Path:            entry.Path,
			Name:            entry.Name,
			Type:            entry.Type,
			Size:            int64(entry.Size),
			IsDirectory:     entry.Type == "folder" || entry.Type == "directory",
			IsDeleted:       false,
			Identity:        fmt.Sprintf("%d", entry.CNID),
			ParentIdentity:  fmt.Sprintf("%d", entry.ParentCNID),
			Created:         fsReportTimePtr(entry.Times.Created),
			Modified:        fsReportTimePtr(entry.Times.ContentModified),
			MetadataChanged: fsReportTimePtr(entry.Times.AttrModified),
			Accessed:        fsReportTimePtr(entry.Times.Accessed),
			Layout:          fsReportLayout{Derived: fsLayoutUnavailable},
			Extra: map[string]object.Object{
				"cnid":             intObj(int64(entry.CNID)),
				"parent_cnid":      intObj(int64(entry.ParentCNID)),
				"record_identity":  stringObj(entry.Identity),
				"resource_size":    intObj(int64(entry.ResourceSize)),
				"compressed":       boolObj(entry.Compressed),
				"compression_type": intObj(int64(entry.CompressionType)),
				"link":             stringObj(entry.Link),
				"link_target":      intObj(int64(entry.LinkTarget)),
				"mode":             intObj(int64(entry.Mode)),
				"uid":              intObj(int64(entry.UID)),
				"gid":              intObj(int64(entry.GID)),
				"system":           boolObj(entry.System),
				"backup":           stringObj(fsReportTimePtr(entry.Times.Backup)),
				"attr_modified":    stringObj(fsReportTimePtr(entry.Times.AttrModified)),
				"time_source":      stringObj(entry.Times.Source),
				"finder_info":      stringObj(entry.FinderInfo),
			},
		}
		report.add(file)
	}

	report.finish()
	return report, nil
}

// --- xfs --------------------------------------------------------------------

// XFS is the only one of the six that can say its listing is complete, and the
// reconciliation that lets it is turned on here.
//
// It walks every allocation group's inode b-tree and compares what the walk
// reached against the superblock's counters and the per-group headers -- three
// independently maintained sources -- and reports whether they balance. It also
// surfaces the inodes that exist and hold data but that no directory walk would
// ever produce: the unlinked, which are deleted-but-still-open, and the
// unreferenced. That costs a second pass over the metadata, which is why it is
// off in libxfs; the alternative is a document that cannot say what it missed.
//
// Verification is best-effort rather than strict: a checksum mismatch is
// recorded as an anomaly and the walk continues, because a report that stops at
// the first damaged inode of a damaged volume is the one case where stopping
// helps least.
//
// Carved directory records are not here. xfs_deleted reports those per
// directory with a confidence grade, and a candidate carved out of a directory
// block is not the same kind of thing as an inode the walk reached.
func (s *realXFSSession) Report() (fsReport, error) {
	raw, err := s.volume.ReportWithContext(context.Background(), libxfs.ReportOptions{
		RootPath:                 "/",
		VerificationMode:         libxfs.VerificationModeBestEffort,
		IncludeInodeCompleteness: true,
	})
	if err != nil {
		return fsReport{}, err
	}

	report := fsReport{
		Filesystem:         "xfs",
		SchemaVersion:      int64(raw.SchemaVersion),
		LibraryVersion:     raw.Provenance.LibraryVersion,
		Generated:          fsReportTime(raw.GeneratedAt),
		Name:               raw.Volume.VolumeLabel,
		FragmentsAvailable: true,
		AnomaliesAvailable: true,
		Complete:           true,
		WarningsAvailable:  true,
		Volume: map[string]object.Object{
			"type":                   stringObj(raw.Volume.Type),
			"format_version":         intObj(int64(raw.Volume.FormatVersion)),
			"block_size":             intObj(int64(raw.Volume.BlockSize)),
			"inode_size":             intObj(int64(raw.Volume.InodeSize)),
			"directory_block_size":   intObj(int64(raw.Volume.DirectoryBlockSize)),
			"root_directory_inode":   intObj(int64(raw.Volume.RootDirectoryInodeNumber)),
			"allocation_group_size":  intObj(int64(raw.Volume.AllocationGroupSize)),
			"allocation_groups":      intObj(int64(raw.Volume.NumberOfAllocationGroups)),
			"blocks":                 intObj(int64(raw.Volume.NumberOfBlocks)),
			"volume_label":           stringObj(raw.Volume.VolumeLabel),
			"volume_uuid":            stringObj(raw.Volume.VolumeUUID),
			"metadata_uuid":          stringObj(raw.Volume.MetadataUUID),
			"superblock_crc_checked": boolObj(raw.Volume.SuperblockCRCChecked),
			"superblock_crc_valid":   boolObj(raw.Volume.SuperblockCRCValid),
			"verification_mode":      stringObj(string(raw.Provenance.VerificationMode)),
			"root_path":              stringObj(raw.RootPath),
		},
		Scope: "every inode the walk from the root reached, reconciled against " +
			"every inode the allocation groups say exists. This is the one " +
			"document of the six that can say its listing is complete: " +
			"completeness_proven is libxfs's own conclusion from three " +
			"independently maintained counters, and the inodes that exist but " +
			"that no directory names -- unlinked and unreferenced -- are " +
			"counted in the volume hash. Checksum mismatches are recorded as " +
			"anomalies rather than ending the walk. Carved directory records " +
			"are not here; xfs_deleted reports those per directory, graded. " +
			"A v4 filesystem records no birth time at all, which " +
			"xfs_capabilities reports for this volume.",
	}
	fsReportIdentity(&report, xfsCapabilitySet(s.volume.Capabilities()), fsIdentityInode)

	for _, anomaly := range raw.Volume.Anomalies {
		report.addAnomaly(xfsReportAnomaly(anomaly))
	}
	for _, anomaly := range raw.Anomalies {
		report.addAnomaly(xfsReportAnomaly(anomaly))
	}

	if raw.Completeness != nil {
		completeness := raw.Completeness
		report.CompletenessChecked = true
		report.CompletenessProven = completeness.Balanced
		report.Volume["allocated_inodes"] = intObj(int64(completeness.AllocationGroupAllocated))
		report.Volume["enumerated_inodes"] = intObj(int64(completeness.EnumeratedAllocated))
		report.Volume["reachable_inodes"] = intObj(int64(completeness.ReachableInodes))
		report.Volume["metadata_inodes"] = intObj(int64(completeness.MetadataInodes))
		report.Volume["unlinked_inodes"] = intObj(int64(completeness.UnlinkedInodes))
		report.Volume["unreferenced_inodes"] = intObj(int64(completeness.UnreferencedInodes))
		report.Volume["superblock_counters_lazy"] = boolObj(completeness.SuperblockLazy)
		report.Volume["inode_source"] = stringObj(string(completeness.Source))
		for _, anomaly := range completeness.Anomalies {
			report.addAnomaly(xfsReportAnomaly(anomaly))
		}
		if completeness.OrphansTruncated {
			report.warn(fsReportWarnOrphansTruncated, "volume",
				"libxfs truncated its own list of inodes no directory reaches, so the orphan counts beside it are the authority")
		}
		if !completeness.Balanced {
			report.incomplete("the inode accounting did not balance, so this listing cannot be called complete")
		}
	}

	var truncated, unlocated int64
	for _, entry := range raw.Files {
		file := fsReportFile{
			Filesystem:      "xfs",
			Path:            entry.Path,
			Name:            pathBase(entry.Path),
			Type:            entry.Type,
			Size:            int64(entry.Size),
			IsDirectory:     entry.Type == "directory",
			IsFragmented:    entry.Fragmentation.HasPhysicalFragmentation,
			Identity:        fmt.Sprintf("%d-%d", entry.InodeNumber, entry.Generation),
			Created:         fsReportTime(entry.CreationTime),
			Modified:        fsReportTime(entry.ModificationTime),
			MetadataChanged: fsReportTime(entry.InodeChangeTime),
			Accessed:        fsReportTime(entry.AccessTime),
			Layout:          fsReportLayout{Derived: fsLayoutExtentMap},
			Extra: map[string]object.Object{
				"inode_number":             intObj(int64(entry.InodeNumber)),
				"generation":               intObj(int64(entry.Generation)),
				"file_mode":                intObj(int64(entry.FileMode)),
				"fork_type":                intObj(int64(entry.ForkType)),
				"owner_id":                 intObj(int64(entry.OwnerID)),
				"group_id":                 intObj(int64(entry.GroupID)),
				"number_of_links":          intObj(int64(entry.NumberOfLinks)),
				"data_extent_count":        intObj(int64(entry.DataExtentCount)),
				"attributes_extent_count":  intObj(int64(entry.AttributesExtentCount)),
				"has_inline_data":          boolObj(entry.HasInlineData),
				"sparse_extent_count":      intObj(int64(entry.Fragmentation.SparseExtentCount)),
				"physical_fragment_runs":   intObj(int64(entry.Fragmentation.PhysicalFragmentRuns)),
				"has_logical_holes":        boolObj(entry.Fragmentation.HasLogicalHoles),
				"extended_attribute_names": stringArray(entry.ExtendedAttributeNames),
			},
		}
		if entry.HasInlineData {
			file.Layout.Derived = fsLayoutUnavailable
			file.Layout.Error = "the data is stored inline in the inode and occupies no extent"
		}

		rowUnlocated := false
		for _, fragment := range entry.Fragments {
			run := fsLocatedFragment(int64(fragment.StartOffset), int64(fragment.EndOffset),
				int64(fragment.FileOffset), int64(fragment.LengthBytes),
				fragment.IsSparse, fragment.IsUnwritten)
			if !run.Located {
				rowUnlocated = true
			}
			file.Layout.BytesCovered += run.Length
			fsAddFragment(&file, run)
		}
		if file.FragmentCount > int64(len(file.Fragments)) {
			file.Layout.Truncated = true
			truncated++
		}
		if rowUnlocated {
			unlocated++
		}

		for _, anomaly := range entry.Anomalies {
			report.addAnomaly(xfsReportAnomaly(anomaly))
		}

		report.add(file)
	}

	fsReportFragmentWarnings(&report, truncated, unlocated, 0)
	report.finish()
	return report, nil
}

// xfsReportAnomaly quotes one libxfs anomaly. The location is the path where
// there is one and the inode number otherwise, because an anomaly attached to
// neither cannot be looked up again.
func xfsReportAnomaly(anomaly libxfs.ReportAnomaly) fsReportAnomaly {
	location := anomaly.Path
	if location == "" && anomaly.Inode != 0 {
		location = fmt.Sprintf("inode %d", anomaly.Inode)
	}
	return fsReportAnomaly{
		Code:     anomaly.Code,
		Severity: anomaly.Severity,
		Location: location,
		Message:  anomaly.Message,
	}
}
