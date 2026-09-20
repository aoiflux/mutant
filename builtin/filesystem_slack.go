package builtin

// The *_slack family: the bytes inside a file's allocation that the file never
// put there.
//
// Three different things get called slack in this field and they are not
// interchangeable, so this family names two of them and refuses to merge them:
//
//   - file_slack is the space between where a file ends and where its
//     allocation ends. The filesystem handed the file a whole cluster, block or
//     allocation block and the file used part of it; the rest still holds
//     whatever the previous occupant left, because nothing zeroes it. This is
//     the classic slack, and it is the one every format here has.
//   - unwritten is the space inside the recorded size that the file never wrote
//     to. It is allocated, it is readable, it is within the length the
//     directory entry claims -- and it was preallocated and skipped, so reading
//     the file back through the filesystem returns zeros while the blocks
//     themselves hold what was on the disk before. Only four of the six formats
//     record the boundary: NTFS as InitializedSize, exFAT as ValidDataLength,
//     ext4 and XFS as a per-extent flag. FAT and HFS+ have no such concept at
//     all.
//
// The third thing -- space allocated to nobody -- is not slack, is a property
// of the volume rather than of a file, and gets its own builtin. Only libhfs
// walks it; see hfs_unallocated at the bottom of this file.
//
// Every range carries its class for one reason: a range reported without it
// invites a report to say "slack" about a valid-data-length gap. They are found
// in different places, they mean different things about what the user did, and
// an examiner quoting one as the other has said something false. class is the
// field a script branches on before it carves.
//
// Two levels of "we did not look", and they are different questions.
//
//	classes / classes_unavailable  what this library can report for this format
//	*_checked / *_bytes            whether this file's question got an answer
//
// The first is about the library: FAT records no valid-data length, so
// fat_slack reports unwritten as unavailable on every file, for ever. The
// second is about the file: libfat refuses to report slack for a file whose
// cluster chain it could not walk, and file_slack_checked is false there, with
// file_slack_bytes at -1 rather than 0, because zero is an answer and this is
// not one.
//
// That distinction is the whole reason this family does not simply call
// SlackRange and render what comes back. libfat returns (Range{}, false, nil)
// from five different situations and only one of them means the file ends on a
// cluster boundary; libxfat from six. Rendering that bool as "no slack" would
// report a broken chain, a directory and a genuinely aligned file with the same
// three words. So each family asks the allocation itself what happened and says
// which of the situations it is in.
//
// What none of these can reach, and it is worth being plain about it: these
// builtins address a live file by its path, and a deleted entry cannot be
// opened by one -- the listers return its name and the openers refuse it. The
// slack of a deleted file is the most valuable slack there is, and reaching it
// needs the scan index the *_deleted family hands out, which this family does
// not take. Four of the six libraries could answer for a deleted entry if it
// did: NTFS keeps the whole run list and both sizes through an unlink, exFAT
// keeps the layout of an entry it had declared contiguous, libhfs carries fork
// extents on a carved catalog record, and an XFS inode on an unlinked chain is
// still allocated and still readable. FAT and ext could not -- the chain is
// freed and the extent tree zeroed.
//
// What each library actually offers:
//
//   - libhfs has the best slack API of the six and carries Slack on every
//     extent rather than only the last, which is the honest shape: an
//     over-allocated fork has whole extents that are slack from their first
//     byte, and a final range with Length zero and the entire span as slack is
//     a fact about the volume, not an empty result.
//   - libxfat reports directory slack and libfat does not, a divergence
//     libxfat's own doc comment calls deliberate -- directory cluster slack is
//     where deleted directory records survive.
//   - libntfs has no slack API of any kind. The numbers are there in published
//     metadata all the same: AllocatedSize, RealSize and InitializedSize on the
//     non-resident $DATA attribute, and a run list to locate them in. So NTFS
//     slack here is computed rather than read, which is stated in scope. It is
//     refused outright on a compressed stream, whose runs map compression units
//     rather than stream bytes, and on a sparse one, whose allocated size is
//     smaller than its recorded size so the difference is not a tail.
//   - libext has no file-slack API either. Extents keeps the blocks past the
//     end of the file that DataRuns drops, and the difference between the two
//     is the slack; both are public, so this is arithmetic on the library's own
//     output rather than a reimplementation of it.
//   - libxfs has no last-block-tail API, but DataRuns does not trim to the
//     inode's size, so the tail is what is left over. Its unwritten extents are
//     first-class and carry real offsets, which libxfs says plainly is the
//     point: they occupy real blocks, and where those blocks are is what makes
//     them worth reading.
//
// Offsets are image-absolute and already carry the base offset of the partition
// the volume was opened at, so a slack range from a FAT volume and one from an
// ext volume elsewhere in the same disk image are directly comparable. An
// offset of -1, never 0, means the range has no location: libxfs reports an
// fsblock it could not resolve as offset zero, and zero is a real place.
//
// Every byte counted is also a range. file_slack_bytes is the sum of the
// file_slack ranges and unwritten_bytes the sum of the unwritten ones, so a
// total that cannot be located still appears in the list with offset -1 rather
// than vanishing into a number with nothing behind it.

import (
	"context"
	"errors"
	"fmt"
	"sort"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libhfs "github.com/aoiflux/libhfs"
	libntfs "github.com/aoiflux/libntfs"
	libxfat "github.com/aoiflux/libxfat"

	"mutant/object"
)

// The two byte classes. These are stable codes a script matches on.
const (
	fsSlackClassFileSlack = "file_slack"
	fsSlackClassUnwritten = "unwritten"
)

// Warning codes. Code is what a script matches; detail is prose.
const (
	fsSlackWarnAllocationGap     = "allocation_incomplete"
	fsSlackWarnPastVolumeEnd     = "slack_past_volume_end"
	fsSlackWarnDirectorySkipped  = "directory_slack_not_reported"
	fsSlackWarnCompressedLayout  = "compressed_stream_layout"
	fsSlackWarnPayloadElsewhere  = "payload_not_in_this_fork"
	fsSlackWarnSparseAllocation  = "sparse_allocation"
	fsSlackWarnUnresolvedOffset  = "extent_offset_unresolved"
	fsSlackWarnUnwrittenShort    = "unwritten_possibly_short"
	fsSlackWarnUnlocatedSlack    = "slack_not_located"
	fsSlackWarnBitmapUnreadable  = "bitmap_unreadable"
	fsSlackWarnDirInline         = "directory_data_inline"
	fsSlackWarnDirUnmapped       = "record_offset_unmapped"
	fsSlackWarnShadowsUnfiltered = "shadowing_records_included"
)

// fsSlackMaxRanges bounds the rendered ranges of one file, and fsSlackMaxRuns
// the free runs of one volume. The same reasoning as everywhere else in this
// package: the counts keep counting past the cap, so the figure an examiner
// quotes stays right even when the list they scroll is short.
const (
	fsSlackMaxRanges  = 4096
	fsSlackMaxRuns    = 20000
	fsSlackMaxEntries = 10000
)

// fsSlackWarning is something a scan could not do. Same three fields as the
// deleted and journal families, and deliberately the same type: a report that
// renders warnings from one of them renders warnings from all of them.
type fsSlackWarning = fsDeletedWarning

// fsSlackRange is one span of bytes that belongs to the file's allocation and
// not to the file.
//
// FileOffset is where the span begins in the file's own byte space. For a
// file_slack range that is at or past the recorded size -- it is the one file
// offset in this package that does not name a position inside the file, which
// is exactly what makes it slack.
type fsSlackRange struct {
	Class      string
	FileOffset int64
	Offset     int64
	Length     int64
}

// fsAllocSpan is a piece of a file's allocation expressed uniformly, so that
// carving a byte window out of it is written once rather than per format.
// Offset is -1 for a span with no location on the medium.
type fsAllocSpan struct {
	FileOffset int64
	Length     int64
	Offset     int64
}

// fsSlackScan is what a *_slack builtin reports about one file.
type fsSlackScan struct {
	Filesystem  string
	Path        string
	Name        string
	IsDirectory bool

	// Size is the length the volume records. AllocatedBytes is how much the
	// allocation covers, which is the larger of the two whenever there is any
	// slack at all. Either is -1 when the library does not say.
	Size           int64
	AllocatedBytes int64

	// Classes is what was examined; ClassesUnavailable is what this format or
	// this library cannot report at all. Naming the second is the point: "no
	// unwritten bytes were found" and "this format records no valid-data
	// length" read identically in an empty array.
	Classes            []string
	ClassesUnavailable []string

	FileSlackChecked bool
	FileSlackBytes   int64
	UnwrittenChecked bool
	UnwrittenBytes   int64

	Ranges     []fsSlackRange
	RangeCount int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsSlackWarning

	Scope string
}

// newSlackScan starts a scan with both answers unanswered. -1 rather than 0
// throughout: a count of zero is a finding and has to be arrived at.
//
// WarningsAvailable is true for every format here, which is not what it means
// in the deleted and journal families. There it says whether the library has a
// channel to report what it skipped, and libntfs and libfat have none. The
// warnings in this family are not the library's: they are this package's own
// account of why a question went unanswered, and every one of the six produces
// them. What each library drops in silence -- a directory block abandoned on a
// bad record length, a name discarded for holding a control byte -- is named in
// scope instead, because no warning can be raised about something that left no
// trace.
func newSlackScan(filesystem, filePath string) fsSlackScan {
	return fsSlackScan{
		Filesystem:        filesystem,
		Path:              filePath,
		Size:              -1,
		AllocatedBytes:    -1,
		FileSlackBytes:    -1,
		UnwrittenBytes:    -1,
		Complete:          true,
		WarningsAvailable: true,
	}
}

// add records a range, counting it past the cap and adding its length to its
// class total. The totals are kept here rather than summed from the rendered
// array so that a truncated list still reports the true number of bytes.
func (s *fsSlackScan) add(r fsSlackRange) bool {
	if r.Length <= 0 {
		return false
	}
	s.RangeCount++
	switch r.Class {
	case fsSlackClassFileSlack:
		if s.FileSlackBytes < 0 {
			s.FileSlackBytes = 0
		}
		s.FileSlackBytes += r.Length
	case fsSlackClassUnwritten:
		if s.UnwrittenBytes < 0 {
			s.UnwrittenBytes = 0
		}
		s.UnwrittenBytes += r.Length
	}
	if len(s.Ranges) >= fsSlackMaxRanges {
		return false
	}
	s.Ranges = append(s.Ranges, r)
	return true
}

// answered marks a class as having been examined, so that a file with none of
// it reports zero rather than -1.
func (s *fsSlackScan) answered(class string) {
	switch class {
	case fsSlackClassFileSlack:
		s.FileSlackChecked = true
		if s.FileSlackBytes < 0 {
			s.FileSlackBytes = 0
		}
	case fsSlackClassUnwritten:
		s.UnwrittenChecked = true
		if s.UnwrittenBytes < 0 {
			s.UnwrittenBytes = 0
		}
	}
}

// unavailable records a class this library cannot report for this format.
func (s *fsSlackScan) unavailable(classes ...string) {
	s.ClassesUnavailable = append(s.ClassesUnavailable, classes...)
}

func (s *fsSlackScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsSlackWarning{Code: code, Location: location, Detail: detail})
}

// incomplete marks a known gap, keeping the first reason -- the one that
// explains the earliest missing evidence.
func (s *fsSlackScan) incomplete(reason string) {
	s.Complete = false
	if s.IncompleteReason == "" {
		s.IncompleteReason = reason
	}
}

func (s fsSlackScan) toHash(handle string) *object.Hash {
	ranges := make([]object.Object, 0, len(s.Ranges))
	var located, unlocated int64
	for _, r := range s.Ranges {
		ranges = append(ranges, makeHashObject(map[string]object.Object{
			"class":       stringObj(r.Class),
			"file_offset": intObj(r.FileOffset),
			"offset":      intObj(r.Offset),
			"length":      intObj(r.Length),
		}))
		if r.Offset >= 0 {
			located += r.Length
			continue
		}
		unlocated += r.Length
	}

	return makeHashObject(map[string]object.Object{
		"handle":              stringObj(handle),
		"filesystem":          stringObj(s.Filesystem),
		"path":                stringObj(s.Path),
		"name":                stringObj(s.Name),
		"is_directory":        boolObj(s.IsDirectory),
		"size":                intObj(s.Size),
		"allocated_bytes":     intObj(s.AllocatedBytes),
		"classes":             stringArray(s.Classes),
		"classes_unavailable": stringArray(s.ClassesUnavailable),
		"file_slack_checked":  boolObj(s.FileSlackChecked),
		"file_slack_bytes":    intObj(s.FileSlackBytes),
		"unwritten_checked":   boolObj(s.UnwrittenChecked),
		"unwritten_bytes":     intObj(s.UnwrittenBytes),
		"ranges":              &object.Array{Elements: ranges},
		"range_count":         intObj(s.RangeCount),
		"ranges_truncated":    boolObj(s.RangeCount > int64(len(s.Ranges))),
		"located_bytes":       intObj(located),
		"unlocated_bytes":     intObj(unlocated),
		"complete":            boolObj(s.Complete),
		"incomplete_reason":   stringObj(s.IncompleteReason),
		"warnings_available":  boolObj(s.WarningsAvailable),
		"warnings":            warningArray(s.Warnings),
		"warning_codes":       warningCodeArray(s.Warnings),
		"scope":               stringObj(s.Scope),
		"status":              stringObj("ok"),
	})
}

// warningArray renders the warnings of any of the three filesystem families;
// they share a type so that a report does not have to know which produced them.
func warningArray(warnings []fsDeletedWarning) object.Object {
	out := make([]object.Object, 0, len(warnings))
	for _, warning := range warnings {
		out = append(out, makeHashObject(map[string]object.Object{
			"code":     stringObj(warning.Code),
			"location": stringObj(warning.Location),
			"detail":   stringObj(warning.Detail),
		}))
	}
	return &object.Array{Elements: out}
}

// warningCodeArray is the deduped, sorted set of codes, which is what a script
// matches on when it does not care how many times something went wrong.
func warningCodeArray(warnings []fsDeletedWarning) object.Object {
	codes := make([]string, 0, len(warnings))
	seen := map[string]bool{}
	for _, warning := range warnings {
		if seen[warning.Code] {
			continue
		}
		seen[warning.Code] = true
		codes = append(codes, warning.Code)
	}
	sort.Strings(codes)
	return stringArray(codes)
}

// spansWithin carves the byte window [from, to) out of an allocation map and
// returns it as ranges of one class.
//
// It intersects and never invents: a span with no location yields a range with
// offset -1 rather than an offset derived from the span before it, and a part
// of the window that no span covers yields nothing at all. A caller that knows
// the window must be covered -- NTFS, whose AllocatedSize is an authoritative
// total independent of the run list -- accounts for the remainder itself.
func spansWithin(spans []fsAllocSpan, from, to int64, class string) []fsSlackRange {
	if to <= from {
		return nil
	}

	out := make([]fsSlackRange, 0, len(spans))
	for _, span := range spans {
		if span.Length <= 0 {
			continue
		}
		start := span.FileOffset
		if start < from {
			start = from
		}
		end := span.FileOffset + span.Length
		if end > to {
			end = to
		}
		if end <= start {
			continue
		}

		offset := int64(-1)
		if span.Offset >= 0 {
			offset = span.Offset + (start - span.FileOffset)
		}
		out = append(out, fsSlackRange{
			Class:      class,
			FileOffset: start,
			Offset:     offset,
			Length:     end - start,
		})
	}
	return out
}

// sumRangeLengths totals a set of ranges, which is how a caller learns whether
// the spans covered the window it asked for.
func sumRangeLengths(ranges []fsSlackRange) int64 {
	var total int64
	for _, r := range ranges {
		total += r.Length
	}
	return total
}

// fsSlackScanner examines one file inside an already-open volume.
type fsSlackScanner func(filePath string) (fsSlackScan, error)

// slackBuiltin is the shared entry point of the six *_slack builtins.
func slackBuiltin(args []object.Object, op string,
	resolve func(object.Object, string) (fsSlackScanner, *object.Error),
) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	// The custody touch is recorded by whichever resolve*Handle this goes
	// through, which is also where an unknown handle is refused.
	scan, errObj := resolve(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	filePath, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	handle := ""
	if handleObj, ok := args[0].(*object.String); ok {
		handle = handleObj.Value
	}

	result, err := scan(filePath)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(result.toHash(handle), nil)
}

// NtfsSlack reports an NTFS file's slack and uninitialised ranges.
func NtfsSlack(args ...object.Object) object.Object {
	return slackBuiltin(args, BuiltinNameNtfsSlack,
		func(arg object.Object, op string) (fsSlackScanner, *object.Error) {
			resolved, err := resolveNTFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Slack, nil
		})
}

// FatSlack reports a FAT file's cluster slack.
func FatSlack(args ...object.Object) object.Object {
	return slackBuiltin(args, BuiltinNameFatSlack,
		func(arg object.Object, op string) (fsSlackScanner, *object.Error) {
			resolved, err := resolveFATHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Slack, nil
		})
}

// XFATSlack reports an exFAT entry's cluster slack and unwritten tail.
func XFATSlack(args ...object.Object) object.Object {
	return slackBuiltin(args, BuiltinNameXfatSlack,
		func(arg object.Object, op string) (fsSlackScanner, *object.Error) {
			resolved, err := resolveXFATHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Slack, nil
		})
}

// ExtSlack reports an ext file's block slack and preallocated ranges.
func ExtSlack(args ...object.Object) object.Object {
	return slackBuiltin(args, BuiltinNameExtSlack,
		func(arg object.Object, op string) (fsSlackScanner, *object.Error) {
			resolved, err := resolveEXTHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Slack, nil
		})
}

// HFSSlack reports an HFS+ data fork's per-extent slack.
func HFSSlack(args ...object.Object) object.Object {
	return slackBuiltin(args, BuiltinNameHfsSlack,
		func(arg object.Object, op string) (fsSlackScanner, *object.Error) {
			resolved, err := resolveHFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Slack, nil
		})
}

// XFSSlack reports an XFS inode's block slack and unwritten extents.
func XFSSlack(args ...object.Object) object.Object {
	return slackBuiltin(args, BuiltinNameXfsSlack,
		func(arg object.Object, op string) (fsSlackScanner, *object.Error) {
			resolved, err := resolveXFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Slack, nil
		})
}

// ---------------------------------------------------------------- NTFS

const ntfsSlackScope = "the file's unnamed $DATA stream only; alternate data streams are not " +
	"examined, and the free space inside the MFT record of a resident file is record slack " +
	"rather than file slack and is not reported. libntfs has no slack API: these figures are " +
	"computed from the attribute's AllocatedSize, RealSize and InitializedSize and located " +
	"through its run list."

func (s *realNTFSSession) Slack(filePath string) (fsSlackScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newSlackScan("ntfs", cleanPath)
	scan.Classes = []string{fsSlackClassFileSlack, fsSlackClassUnwritten}
	scan.Scope = ntfsSlackScope

	file, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsSlackScan{}, err
	}
	scan.Name = file.Name()
	scan.IsDirectory = file.IsDirectory()
	scan.Size = file.Size()

	entry, err := s.volume.GetMFTEntry(file.EntryNumber())
	if err != nil {
		return fsSlackScan{}, err
	}

	attribute := ntfsDefaultDataAttribute(entry)
	switch {
	case attribute == nil:
		// No $DATA at all: a directory, or a record whose data attribute did
		// not survive. Nothing was allocated, so nothing is slack.
		scan.AllocatedBytes = 0
		scan.answered(fsSlackClassFileSlack)
		scan.answered(fsSlackClassUnwritten)
		return scan, nil

	case attribute.Resident != nil:
		// The content is inside the MFT record. It owns no clusters, so it has
		// no cluster tail, and the record's own unused space is a different
		// thing that scope disclaims.
		scan.AllocatedBytes = int64(len(attribute.Resident.Value))
		scan.answered(fsSlackClassFileSlack)
		scan.answered(fsSlackClassUnwritten)
		return scan, nil

	case attribute.NonResident == nil:
		scan.incomplete("the $DATA attribute is neither resident nor non-resident")
		return scan, nil
	}

	nonResident := attribute.NonResident
	realSize := int64(nonResident.RealSize)
	allocated := int64(nonResident.AllocatedSize)
	initialised := int64(nonResident.InitializedSize)
	scan.AllocatedBytes = allocated

	if attribute.IsCompressed() {
		// A compressed run list maps compression units, not stream bytes, so
		// neither the tail nor the initialised boundary can be placed on the
		// medium from it. Computing them anyway would name locations that are
		// wrong rather than missing.
		scan.warn(fsSlackWarnCompressedLayout, cleanPath,
			"the stream is compressed, so its data runs describe compression units rather than "+
				"stream bytes and neither boundary can be located")
		scan.incomplete("compressed stream")
		return scan, nil
	}

	spans := ntfsAllocationSpans(s.volume, nonResident)

	// Uninitialised bytes first: they sit inside the recorded size, which is
	// the part of the allocation the run list actually describes.
	if initialised < realSize {
		for _, r := range spansWithin(spans, initialised, realSize, fsSlackClassUnwritten) {
			scan.add(r)
		}
	}
	scan.answered(fsSlackClassUnwritten)

	if file.IsSparse() && allocated <= realSize {
		// On a sparse stream the allocated size is smaller than the recorded
		// one, so their difference is not a tail and there is nothing here to
		// subtract. libntfs has no per-cluster allocation map to fall back on.
		scan.warn(fsSlackWarnSparseAllocation, cleanPath,
			"the stream is sparse and its allocated size is not greater than its recorded size, "+
				"so no tail can be derived from the difference")
		scan.incomplete("sparse stream")
		return scan, nil
	}

	if allocated > realSize {
		located := spansWithin(spans, realSize, allocated, fsSlackClassFileSlack)
		for _, r := range located {
			scan.add(r)
		}
		// AllocatedSize is the volume's own statement and does not depend on
		// the run list, so a run list that covers less than it leaves slack
		// that exists and cannot be placed. It is reported as a range with no
		// location rather than dropped, so that the byte total still adds up.
		if covered := sumRangeLengths(located); covered < allocated-realSize {
			scan.add(fsSlackRange{
				Class:      fsSlackClassFileSlack,
				FileOffset: realSize + covered,
				Offset:     -1,
				Length:     allocated - realSize - covered,
			})
			scan.warn(fsSlackWarnUnlocatedSlack, cleanPath,
				"the attribute's allocated size exceeds what its run list describes, so part of "+
					"the slack is counted but has no location")
			scan.incomplete("run list shorter than the allocated size")
		}
	}
	scan.answered(fsSlackClassFileSlack)

	return scan, nil
}

// ntfsDefaultDataAttribute picks the unnamed $DATA attribute out of an entry.
//
// An entry may carry several: the unnamed stream and any number of alternate
// data streams. Only the unnamed one is this builtin's subject, and picking by
// position rather than by name would silently report an ADS's slack under the
// file's own path.
func ntfsDefaultDataAttribute(entry *libntfs.MFTEntry) *libntfs.Attribute {
	if entry == nil {
		return nil
	}
	for _, attribute := range entry.DataStreams() {
		switch {
		case attribute == nil:
			continue
		case attribute.NonResident != nil && attribute.NonResident.Name == "":
			return attribute
		case attribute.Resident != nil && attribute.Resident.Name == "":
			return attribute
		}
	}
	return nil
}

// ntfsAllocationSpans maps a non-resident attribute's whole allocation,
// including the clusters past the end of the stream that Fragments drops.
//
// Those dropped clusters are the entire point here: a file truncated in place
// keeps its old allocation, and the runs beyond the new length still hold what
// it used to be.
func ntfsAllocationSpans(volume *libntfs.Volume, attribute *libntfs.NonResidentAttribute) []fsAllocSpan {
	bytesPerCluster := int64(volume.BytesPerCluster())
	if bytesPerCluster <= 0 {
		return nil
	}

	spans := make([]fsAllocSpan, 0, len(attribute.DataRuns))
	fileOffset := int64(0)
	for _, run := range attribute.DataRuns {
		length := int64(run.LengthClusters) * bytesPerCluster
		if length <= 0 {
			continue
		}
		span := fsAllocSpan{FileOffset: fileOffset, Length: length, Offset: -1}
		if !run.IsSparse && run.StartCluster >= 0 {
			span.Offset = volume.ClusterToOffset(uint64(run.StartCluster))
		}
		spans = append(spans, span)
		fileOffset += length
	}
	return spans
}

// ---------------------------------------------------------------- FAT

const fatSlackScope = "one live file's cluster tail, addressed by path. A deleted entry cannot be " +
	"opened by path, so its slack is not reachable here even though it is the slack most worth " +
	"having. FAT records no valid-data length, so there is no such thing as an unwritten range " +
	"on this format. libfat does not report slack for directories, and a directory's cluster " +
	"tail is where deleted short and long name records survive, so it is named as unchecked " +
	"rather than reported as empty. Volume slack -- the sectors past the last cluster -- is not " +
	"covered by any libfat API."

func (s *realFATSession) Slack(filePath string) (fsSlackScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newSlackScan("fat", cleanPath)
	scan.Classes = []string{fsSlackClassFileSlack}
	scan.unavailable(fsSlackClassUnwritten)
	scan.Scope = fatSlackScope

	file, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsSlackScan{}, err
	}
	scan.Name = file.Name()
	scan.IsDirectory = file.IsDirectory()
	scan.Size = file.Size()

	if file.IsDirectory() {
		scan.warn(fsSlackWarnDirectorySkipped, cleanPath,
			"libfat reports no slack for directories, and its exFAT sibling calls that a "+
				"deliberate divergence because directory cluster slack is where deleted "+
				"directory records survive")
		scan.incomplete("directories are outside this library's slack API")
		return scan, nil
	}

	entry := file.Entry()
	if entry.Size == 0 {
		// An empty file owns no cluster, so it has no tail. That is an answer.
		scan.AllocatedBytes = 0
		scan.answered(fsSlackClassFileSlack)
		return scan, nil
	}

	result, err := s.volume.FragmentOffsetsWithOptions(entry, libfat.FragmentOptions{})
	if err != nil {
		return fsSlackScan{}, err
	}

	bytesPerCluster := int64(s.volume.BytesPerCluster())
	if bytesPerCluster <= 0 {
		scan.incomplete("the volume reports no cluster size")
		return scan, nil
	}

	if len(result.Ranges) == 0 || result.Truncated {
		// libfat returns the same false here that it returns for a file
		// ending exactly on a cluster boundary, and reporting zero would hide
		// a chain that could not be followed behind a number that looks like a
		// measurement. A deleted entry's chain is freed and looks exactly like
		// this -- though one cannot be reached through a path argument at all;
		// see the file comment.
		scan.warn(fsSlackWarnAllocationGap, cleanPath, fatAllocationGapDetail(result))
		scan.incomplete("the cluster chain could not be walked to the end of the file")
		return scan, nil
	}

	last := result.Ranges[len(result.Ranges)-1]
	scan.AllocatedBytes = roundUpTo(result.BytesCovered, bytesPerCluster)
	if used := last.Length % bytesPerCluster; used == 0 {
		scan.answered(fsSlackClassFileSlack)
		return scan, nil
	}

	slack, ok, err := s.volume.SlackRange(entry)
	if err != nil {
		return fsSlackScan{}, err
	}
	if !ok {
		// Every other reason libfat declines has been ruled out above, so the
		// remaining one is that the tail would run past the end of the volume.
		scan.warn(fsSlackWarnPastVolumeEnd, cleanPath,
			"the cluster tail computed for this file ends past the end of the volume, so libfat "+
				"declines to name it")
		scan.incomplete("the computed slack lies outside the volume")
		return scan, nil
	}

	scan.add(fsSlackRange{
		Class:      fsSlackClassFileSlack,
		FileOffset: slack.FileOffset,
		Offset:     slack.StartByte,
		Length:     slack.Length,
	})
	scan.answered(fsSlackClassFileSlack)
	return scan, nil
}

// fatAllocationGapDetail says which way the chain walk failed, because
// "reallocated" and "broken" lead to different next steps.
func fatAllocationGapDetail(result *libfat.FragmentResult) string {
	switch {
	case result == nil:
		return "the chain walk returned no result"
	case result.FirstClusterReallocated:
		return "the entry's first cluster is marked in use again, so the clusters behind it " +
			"belong to a later file and its tail cannot be attributed to this one"
	case result.ChainBroken:
		return "the chain walk stopped on a free, bad or out-of-range FAT entry rather than an " +
			"end-of-chain marker, which is what a deleted file's freed chain looks like"
	case result.LoopDetected:
		return "the chain revisited a cluster, so the runs stop at the repeat and the file's " +
			"last cluster is not known"
	case result.Truncated:
		return "the runs cover less than the size the directory entry records, so which cluster " +
			"holds the last byte is not established"
	default:
		return "the chain walk produced no runs"
	}
}

// roundUpTo rounds a byte count up to a whole allocation unit.
func roundUpTo(value, unit int64) int64 {
	if unit <= 0 || value <= 0 {
		return value
	}
	if remainder := value % unit; remainder != 0 {
		return value + unit - remainder
	}
	return value
}

// ---------------------------------------------------------------- exFAT

const xfatSlackScope = "one live entry's cluster tail and the part of its allocation past " +
	"ValidDataLength, addressed by path. A deleted entry cannot be opened by path, so the one " +
	"case libxfat would answer -- an entry the volume had declared contiguous, whose layout " +
	"deletion did not erase -- is not reachable here. Unlike its FAT sibling libxfat does " +
	"report directory slack, which is where deleted directory records survive. Volume slack " +
	"past the cluster heap is not covered by any libxfat API."

func (s *realXFATSession) Slack(filePath string) (fsSlackScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newSlackScan("exfat", cleanPath)
	scan.Classes = []string{fsSlackClassFileSlack, fsSlackClassUnwritten}
	scan.Scope = xfatSlackScope

	entry, err := s.findEntryByPath(cleanPath)
	if err != nil {
		return fsSlackScan{}, err
	}
	scan.Name = entry.Name()
	scan.IsDirectory = entry.IsDir()
	scan.Size = int64(entry.Size())

	if entry.IsRegion() {
		// A region entry is libxfat's synthetic handle for a span of the
		// volume rather than a directory record, so it has no allocation of
		// its own to have a tail.
		scan.incomplete("the path names a synthetic region entry rather than a directory record")
		return scan, nil
	}

	if entry.Size() == 0 {
		scan.AllocatedBytes = 0
		scan.answered(fsSlackClassFileSlack)
		scan.answered(fsSlackClassUnwritten)
		return scan, nil
	}

	result, err := s.fs.FragmentOffsetsWithOptions(entry, libxfat.FragmentOptions{})
	if err != nil {
		return fsSlackScan{}, err
	}

	// The unwritten tail is asked for whatever the chain did, because
	// ValidDataLength is a field in the directory entry rather than a property
	// of the layout. libxfat does not check Truncated before iterating the
	// runs, so on a short walk it reports a shorter unwritten region than
	// exists and says nothing; that silence is filled in below.
	if err := s.addXFATUnwritten(&scan, entry, result); err != nil {
		return fsSlackScan{}, err
	}

	clusterSize := int64(s.fs.ClusterSize())
	if clusterSize <= 0 {
		scan.incomplete("the volume reports no cluster size")
		return scan, nil
	}

	if len(result.Ranges) == 0 || result.Truncated {
		scan.warn(fsSlackWarnAllocationGap, cleanPath,
			"the runs cover less than the size the entry records, which is what a deleted "+
				"non-contiguous entry looks like once its chain has been freed")
		scan.incomplete("the allocation could not be walked to the end of the entry")
		return scan, nil
	}

	last := result.Ranges[len(result.Ranges)-1]
	scan.AllocatedBytes = roundUpTo(result.BytesCovered, clusterSize)
	if used := last.Length % clusterSize; used == 0 {
		scan.answered(fsSlackClassFileSlack)
		return scan, nil
	}

	slack, ok, err := s.fs.SlackRange(entry)
	if err != nil {
		return fsSlackScan{}, err
	}
	if !ok {
		scan.warn(fsSlackWarnPastVolumeEnd, cleanPath,
			"the cluster tail computed for this entry ends past the end of the cluster heap, "+
				"which bounds the volume more tightly than the image does")
		scan.incomplete("the computed slack lies outside the cluster heap")
		return scan, nil
	}

	scan.add(fsSlackRange{
		Class:      fsSlackClassFileSlack,
		FileOffset: slack.FileOffset,
		Offset:     slack.StartByte,
		Length:     slack.Length,
	})
	scan.answered(fsSlackClassFileSlack)
	return scan, nil
}

// addXFATUnwritten records the part of the allocation past ValidDataLength.
func (s *realXFATSession) addXFATUnwritten(scan *fsSlackScan, entry libxfat.Entry,
	result *libxfat.FragmentResult,
) error {
	if entry.ValidDataSize() >= entry.Size() {
		scan.answered(fsSlackClassUnwritten)
		return nil
	}

	unwritten, err := s.fs.UnwrittenRanges(entry)
	if err != nil {
		return err
	}
	for _, r := range unwritten {
		scan.add(fsSlackRange{
			Class:      fsSlackClassUnwritten,
			FileOffset: r.FileOffset,
			Offset:     r.StartByte,
			Length:     r.Length,
		})
	}
	scan.answered(fsSlackClassUnwritten)

	if result != nil && result.Truncated {
		// What was reported is real; how much of it there is, is a lower bound.
		scan.warn(fsSlackWarnUnwrittenShort, scan.Path,
			"the runs stop short of the recorded size and libxfat does not check for that "+
				"before mapping the unwritten region, so the bytes named here are a lower bound")
		scan.incomplete("the unwritten region was mapped over an incomplete run list")
	}
	return nil
}

// ---------------------------------------------------------------- ext

const extSlackScope = "one inode's blocks. libext exposes no file-slack API: the tail is the " +
	"difference between Extents, which keeps whole blocks including preallocation past the end " +
	"of the file, and DataRuns, which trims to the recorded size. A file whose data is inline " +
	"in the inode owns no blocks and so has no tail. Directory-record slack is a different " +
	"artifact and has its own builtin, ext_dir_slack."

func (s *realEXTSession) Slack(filePath string) (fsSlackScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newSlackScan("ext", cleanPath)
	scan.Classes = []string{fsSlackClassFileSlack, fsSlackClassUnwritten}
	scan.Scope = extSlackScope

	file, err := s.fs.OpenPath(cleanPath)
	if err != nil {
		return fsSlackScan{}, err
	}
	inode := file.Inode()
	scan.Name = pathBase(cleanPath)
	scan.IsDirectory = file.IsDirectory()
	scan.Size = file.Size()

	if s.fs.HasInlineData(inode) {
		scan.AllocatedBytes = 0
		scan.answered(fsSlackClassFileSlack)
		scan.answered(fsSlackClassUnwritten)
		return scan, nil
	}

	blockSize := int64(s.fs.Superblock().BlockSize)
	if blockSize <= 0 {
		scan.incomplete("the superblock reports no block size")
		return scan, nil
	}
	baseOffset := s.fs.Options().BaseOffset

	extents, err := s.fs.InodeExtents(inode, libext.ExtentOptions{})
	if err != nil {
		return fsSlackScan{}, err
	}

	var (
		spans        []fsAllocSpan
		allocatedEnd int64
	)
	for _, extent := range extents {
		if extent.Inline() || extent.Blocks == 0 {
			continue
		}
		fileOffset := int64(extent.LogicalBlock) * blockSize
		length := int64(extent.Blocks) * blockSize
		span := fsAllocSpan{FileOffset: fileOffset, Length: length, Offset: -1}
		if !extent.Sparse() {
			span.Offset = int64(extent.PhysicalBlock)*blockSize + baseOffset
		}
		spans = append(spans, span)
		if end := fileOffset + length; end > allocatedEnd {
			allocatedEnd = end
		}

		// A run flagged unwritten was allocated and never written to, and the
		// part of it inside the recorded size is the file's own uninitialised
		// region. The part past the size is slack and is counted below.
		if extent.Unwritten() && !extent.Sparse() {
			for _, r := range spansWithin([]fsAllocSpan{span}, 0, scan.Size, fsSlackClassUnwritten) {
				scan.add(r)
			}
		}
	}
	scan.AllocatedBytes = allocatedEnd
	scan.answered(fsSlackClassUnwritten)

	for _, r := range spansWithin(spans, scan.Size, allocatedEnd, fsSlackClassFileSlack) {
		scan.add(r)
	}
	scan.answered(fsSlackClassFileSlack)

	return scan, nil
}

// ---------------------------------------------------------------- HFS+

const hfsSlackScope = "the data fork of one file. libhfs reports slack on every extent rather " +
	"than only the last, so an over-allocated fork contributes whole extents. The resource " +
	"fork is not examined, and a decmpfs-compressed file's payload lives there or in an " +
	"extended attribute, which is why its empty data fork is reported as unchecked rather " +
	"than as a file with no slack. HFS+ records no valid-data length, so the format has no " +
	"unwritten ranges."

func (s *realHFSSession) Slack(filePath string) (fsSlackScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newSlackScan("hfs", cleanPath)
	scan.Classes = []string{fsSlackClassFileSlack}
	scan.unavailable(fsSlackClassUnwritten)
	scan.Scope = hfsSlackScope

	record, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsSlackScan{}, err
	}
	scan.Name = record.Name
	scan.IsDirectory = record.Type == libhfs.CatalogRecordFolder
	scan.Size = int64(record.DataFork.LogicalSize)

	if scan.IsDirectory {
		// An HFS+ directory is a B-tree record, not an allocation of blocks,
		// so it owns no tail.
		scan.AllocatedBytes = 0
		scan.answered(fsSlackClassFileSlack)
		return scan, nil
	}

	ranges, err := s.volume.DataForkRanges(record.CNID)
	if err != nil {
		return fsSlackScan{}, err
	}

	if record.Compressed && len(ranges) == 0 {
		scan.warn(fsSlackWarnPayloadElsewhere, cleanPath,
			"the file is decmpfs-compressed, so its data fork is genuinely empty on disk and "+
				"its payload is in the resource fork or an extended attribute, neither of "+
				"which this builtin examines")
		scan.incomplete("the compressed payload is not in the data fork")
		return scan, nil
	}

	var allocated int64
	for _, r := range ranges {
		allocated += r.AllocatedLength()
		if r.Slack <= 0 {
			continue
		}
		scan.add(fsSlackRange{
			Class:      fsSlackClassFileSlack,
			FileOffset: r.ForkOffset + r.Length,
			Offset:     r.DiskOffset + r.Length,
			Length:     r.Slack,
		})
	}
	scan.AllocatedBytes = allocated
	scan.answered(fsSlackClassFileSlack)

	return scan, nil
}

// ---------------------------------------------------------------- XFS

const xfsSlackScope = "one inode's data fork. libxfs offers no last-block-tail API, but DataRuns " +
	"does not trim to the inode's size, so the tail is what the runs hold past it. An " +
	"unwritten extent carries a real location because the blocks are real, which is what makes " +
	"them worth reading; a hole does not. DataRuns discards the anomalies its conversion " +
	"raises, so a range whose block number did not resolve is detected here by the rule libxfs " +
	"documents -- neither sparse nor located -- and reported at offset -1."

func (s *realXFSSession) Slack(filePath string) (fsSlackScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newSlackScan("xfs", cleanPath)
	scan.Classes = []string{fsSlackClassFileSlack, fsSlackClassUnwritten}
	scan.Scope = xfsSlackScope

	ctx := context.Background()

	inodeNumber, err := s.volume.ResolveInodeByPath(cleanPath)
	if err != nil {
		return fsSlackScan{}, err
	}
	inode, err := s.volume.OpenInode(inodeNumber)
	if err != nil {
		return fsSlackScan{}, err
	}
	scan.Name = pathBase(cleanPath)
	scan.IsDirectory = inode.IsDirectory()
	scan.Size = int64(inode.Size)

	ranges, err := s.volume.DataRuns(ctx, inodeNumber)
	if err != nil {
		return fsSlackScan{}, err
	}

	var (
		spans     []fsAllocSpan
		allocated int64
	)
	for _, r := range ranges {
		length := int64(r.LengthBytes)
		if length <= 0 {
			continue
		}
		fileOffset := int64(r.FileOffset)

		offset := int64(-1)
		switch {
		case r.StartOffset != 0 || r.EndOffset != 0:
			offset = int64(r.StartOffset)
		case r.IsSparse && !r.IsUnwritten:
			// A hole has no location and never had one.
		default:
			// Neither sparse nor located: libxfs could not resolve the
			// fsblock and dropped the anomaly saying so on the way out.
			scan.warn(fsSlackWarnUnresolvedOffset, cleanPath,
				fmt.Sprintf("the range at file offset %d names real blocks whose fsblock did "+
					"not resolve against this volume's geometry, so it has no location",
					fileOffset))
			scan.incomplete("a mapped range could not be placed on the medium")
		}

		spans = append(spans, fsAllocSpan{FileOffset: fileOffset, Length: length, Offset: offset})
		if end := fileOffset + length; end > allocated {
			allocated = end
		}

		if r.IsUnwritten {
			for _, part := range spansWithin(
				[]fsAllocSpan{{FileOffset: fileOffset, Length: length, Offset: offset}},
				0, scan.Size, fsSlackClassUnwritten,
			) {
				scan.add(part)
			}
		}
	}
	scan.AllocatedBytes = allocated
	scan.answered(fsSlackClassUnwritten)

	for _, r := range spansWithin(spans, scan.Size, allocated, fsSlackClassFileSlack) {
		scan.add(r)
	}
	scan.answered(fsSlackClassFileSlack)

	return scan, nil
}

// ---------------------------------------------- ext directory-record slack

// fsDirSlackEntry is a directory record found in the gap a live record's
// rec_len was extended to cover.
//
// DirOffset is where the record sits inside the directory's own data stream,
// which is what libext reports and all it reports. Offset is that position
// mapped onto the image through the directory's data runs, which nothing in
// libext does: without it the finding cannot be re-examined, quoted by offset
// or handed to a carver.
type fsDirSlackEntry struct {
	Name         string
	Inode        int64
	FileType     int64
	FileTypeName string
	DirOffset    int64
	Offset       int64
	ShadowsLive  bool
}

// fsDirSlackScan is what ext_dir_slack reports.
type fsDirSlackScan struct {
	Filesystem string
	Path       string
	Inode      int64

	Entries    []fsDirSlackEntry
	EntryCount int64

	// Located is how many of the entries could be placed on the image. A
	// directory whose data runs could not be read yields records that are real
	// and unplaceable, and the two numbers differing is the only sign of it.
	Located int64

	// ShadowsLiveCount is how many of the records duplicate a live entry. They
	// are evidence of a directory having been rewritten rather than of anything
	// having been deleted, and libext does not filter them out of this call the
	// way it does out of DeletedEntries.
	ShadowsLiveCount int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsSlackWarning

	Scope string
}

func (s *fsDirSlackScan) add(entry fsDirSlackEntry) bool {
	s.EntryCount++
	if entry.Offset >= 0 {
		s.Located++
	}
	if entry.ShadowsLive {
		s.ShadowsLiveCount++
	}
	if len(s.Entries) >= fsSlackMaxEntries {
		return false
	}
	s.Entries = append(s.Entries, entry)
	return true
}

func (s *fsDirSlackScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsSlackWarning{Code: code, Location: location, Detail: detail})
}

func (s *fsDirSlackScan) incomplete(reason string) {
	s.Complete = false
	if s.IncompleteReason == "" {
		s.IncompleteReason = reason
	}
}

func (s fsDirSlackScan) toHash(handle string) *object.Hash {
	entries := make([]object.Object, 0, len(s.Entries))
	for _, entry := range s.Entries {
		entries = append(entries, makeHashObject(map[string]object.Object{
			"name":           stringObj(entry.Name),
			"inode":          intObj(entry.Inode),
			"file_type":      intObj(entry.FileType),
			"file_type_name": stringObj(entry.FileTypeName),
			"dir_offset":     intObj(entry.DirOffset),
			"offset":         intObj(entry.Offset),
			"shadows_live":   boolObj(entry.ShadowsLive),
		}))
	}

	return makeHashObject(map[string]object.Object{
		"handle":             stringObj(handle),
		"filesystem":         stringObj(s.Filesystem),
		"path":               stringObj(s.Path),
		"inode":              intObj(s.Inode),
		"entries":            &object.Array{Elements: entries},
		"entry_count":        intObj(s.EntryCount),
		"entries_truncated":  boolObj(s.EntryCount > int64(len(s.Entries))),
		"located":            intObj(s.Located),
		"shadows_live_count": intObj(s.ShadowsLiveCount),
		"complete":           boolObj(s.Complete),
		"incomplete_reason":  stringObj(s.IncompleteReason),
		"warnings_available": boolObj(s.WarningsAvailable),
		"warnings":           warningArray(s.Warnings),
		"warning_codes":      warningCodeArray(s.Warnings),
		"scope":              stringObj(s.Scope),
		"status":             stringObj("ok"),
	})
}

// ExtDirSlack reports the directory records surviving in one directory's slack.
func ExtDirSlack(args ...object.Object) object.Object {
	op := BuiltinNameExtDirSlack
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	resolved, errObj := resolveEXTHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	dirPath, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	handle := ""
	if handleObj, ok := args[0].(*object.String); ok {
		handle = handleObj.Value
	}

	result, err := resolved.Session.DirSlack(dirPath)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(result.toHash(handle), nil)
}

const extDirSlackScope = "one directory, not its children. Every name here is a candidate: the " +
	"record is real, but the inode it names may since have been reused by an unrelated file, " +
	"so it has to be cross-checked against the inode table before it is called a recovered " +
	"file. Records that duplicate a live entry are included and flagged rather than dropped, " +
	"because a directory rewrite leaving copies behind is itself worth seeing; ext_deleted " +
	"filters them out and this does not. A record whose inode field was cleared -- the classic " +
	"ext2 and ext3 unlink marker -- is not recovered by libext at all, so this cannot report " +
	"one. A block with an implausible rec_len is abandoned from that point on with no flag, " +
	"and a name carrying a control byte is discarded and counted nowhere."

func (s *realEXTSession) DirSlack(dirPath string) (fsDirSlackScan, error) {
	cleanPath := normalizeFSPath(dirPath)

	scan := fsDirSlackScan{
		Filesystem:        "ext",
		Path:              cleanPath,
		Inode:             -1,
		Complete:          true,
		WarningsAvailable: true,
		Scope:             extDirSlackScope,
	}

	file, err := s.fs.OpenPath(cleanPath)
	if err != nil {
		return fsDirSlackScan{}, err
	}
	if !file.IsDirectory() {
		return fsDirSlackScan{}, errors.New("target path is not a directory")
	}

	inodeNumber := file.InodeNumber()
	scan.Inode = int64(inodeNumber)

	if s.fs.HasInlineData(file.Inode()) {
		// libext returns nothing at all for an inline directory, silently. The
		// records are in the inode rather than in blocks, and its slack scanner
		// only reads blocks.
		scan.warn(fsSlackWarnDirInline, cleanPath,
			"the directory's records are stored inline in its inode rather than in blocks, and "+
				"libext's slack scanner reads blocks only, so it reports nothing for one")
		scan.incomplete("inline directory data is outside this library's slack scan")
		return scan, nil
	}

	slack, err := s.fs.ScanDirSlackContext(context.Background(), inodeNumber)
	if err != nil {
		return fsDirSlackScan{}, err
	}

	// libext reports a position inside the directory's data stream and stops
	// there. Mapping it onto the image is what turns a finding into something
	// that can be re-read, and nothing in libext does it.
	runs, runsErr := s.fs.DataRuns(inodeNumber)
	if runsErr != nil {
		scan.warn(fsSlackWarnDirUnmapped, cleanPath,
			"the directory's data runs could not be read, so its records are reported at their "+
				"position within the directory stream and at no position on the image: "+
				runsErr.Error())
		scan.incomplete("the directory's blocks could not be located")
	}

	shadowed := false
	for _, entry := range slack {
		if entry.ShadowsLive {
			shadowed = true
		}
		scan.add(fsDirSlackEntry{
			Name:         entry.Name,
			Inode:        int64(entry.Inode),
			FileType:     int64(entry.FileType),
			FileTypeName: extFileTypeName(entry.FileType),
			DirOffset:    entry.Offset,
			Offset:       extStreamOffsetToImage(runs, entry.Offset),
			ShadowsLive:  entry.ShadowsLive,
		})
	}

	if shadowed {
		scan.warn(fsSlackWarnShadowsUnfiltered, cleanPath,
			"some records duplicate a live entry in this directory: they are residue from the "+
				"directory being rewritten, not evidence of a deletion, and are flagged rather "+
				"than removed")
	}

	return scan, nil
}

// extStreamOffsetToImage maps a position inside a directory's data stream onto
// the image, or reports -1 when no run covers it.
//
// A sparse run has no location, and a directory record found at an offset a
// hole covers is a contradiction rather than a finding, so it gets -1 too
// rather than the offset zero a sparse ByteRange carries.
func extStreamOffsetToImage(runs []libext.ByteRange, streamOffset int64) int64 {
	if streamOffset < 0 {
		return -1
	}
	for _, run := range runs {
		if streamOffset < run.FileOffset || streamOffset >= run.FileOffset+run.Length {
			continue
		}
		if run.Sparse || run.DiskOffset <= 0 {
			return -1
		}
		return run.DiskOffset + (streamOffset - run.FileOffset)
	}
	return -1
}

// extFileTypeName decodes the ext directory-record file type byte. The number
// is carried beside it because a record found in slack may hold a value that
// names nothing, and reporting that as "unknown" alone would lose it.
func extFileTypeName(fileType uint8) string {
	switch fileType {
	case 0:
		return "unknown"
	case 1:
		return "regular"
	case 2:
		return "directory"
	case 3:
		return "character_device"
	case 4:
		return "block_device"
	case 5:
		return "fifo"
	case 6:
		return "socket"
	case 7:
		return "symlink"
	default:
		return "unrecognised"
	}
}

// ------------------------------------------------------ volume free space

// fsFreeRun is one maximal run of consecutive unallocated allocation blocks.
type fsFreeRun struct {
	StartBlock int64
	BlockCount int64
	Offset     int64
	Length     int64
}

// fsFreeSpaceScan is what hfs_unallocated reports.
//
// The counted and the claimed free-block totals are both reported because they
// are different kinds of statement. libhfs counts bits in the allocation file;
// the volume header records what the last writer believed. A mismatch means the
// volume was not unmounted cleanly or its metadata is inconsistent, and either
// is worth knowing before anything carved out of this space is relied on.
type fsFreeSpaceScan struct {
	Filesystem  string
	BlockSize   int64
	TotalBlocks int64

	FreeBlocks        int64
	FreeBytes         int64
	ClaimedFreeBlocks int64
	ClaimMatches      bool

	Runs            []fsFreeRun
	RunCount        int64
	LargestRunBytes int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsSlackWarning

	Scope string
}

func (s *fsFreeSpaceScan) add(run fsFreeRun) bool {
	s.RunCount++
	s.FreeBlocks += run.BlockCount
	s.FreeBytes += run.Length
	if run.Length > s.LargestRunBytes {
		s.LargestRunBytes = run.Length
	}
	if len(s.Runs) >= fsSlackMaxRuns {
		return false
	}
	s.Runs = append(s.Runs, run)
	return true
}

func (s *fsFreeSpaceScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsSlackWarning{Code: code, Location: location, Detail: detail})
}

func (s fsFreeSpaceScan) toHash(handle string) *object.Hash {
	runs := make([]object.Object, 0, len(s.Runs))
	for _, run := range s.Runs {
		runs = append(runs, makeHashObject(map[string]object.Object{
			"start_block": intObj(run.StartBlock),
			"block_count": intObj(run.BlockCount),
			"offset":      intObj(run.Offset),
			"length":      intObj(run.Length),
		}))
	}

	return makeHashObject(map[string]object.Object{
		"handle":              stringObj(handle),
		"filesystem":          stringObj(s.Filesystem),
		"block_size":          intObj(s.BlockSize),
		"total_blocks":        intObj(s.TotalBlocks),
		"free_blocks":         intObj(s.FreeBlocks),
		"free_bytes":          intObj(s.FreeBytes),
		"free_blocks_claimed": intObj(s.ClaimedFreeBlocks),
		"claim_matches":       boolObj(s.ClaimMatches),
		"runs":                &object.Array{Elements: runs},
		"run_count":           intObj(s.RunCount),
		"runs_truncated":      boolObj(s.RunCount > int64(len(s.Runs))),
		"largest_run_bytes":   intObj(s.LargestRunBytes),
		"complete":            boolObj(s.Complete),
		"incomplete_reason":   stringObj(s.IncompleteReason),
		"warnings_available":  boolObj(s.WarningsAvailable),
		"warnings":            warningArray(s.Warnings),
		"warning_codes":       warningCodeArray(s.Warnings),
		"scope":               stringObj(s.Scope),
		"status":              stringObj("ok"),
	})
}

// HFSUnallocated reports the runs of an HFS+ volume that belong to no file.
func HFSUnallocated(args ...object.Object) object.Object {
	op := BuiltinNameHfsUnallocated
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	resolved, errObj := resolveHFSHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	handle := ""
	if handleObj, ok := args[0].(*object.String); ok {
		handle = handleObj.Value
	}

	result, err := resolved.Session.Unallocated()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(result.toHash(handle), nil)
}

const hfsUnallocatedScope = "the allocation file of this volume, read bit by bit. A free block " +
	"is one no live file claims; it is not a statement that anything was ever written there, " +
	"nor that what is there now was deleted rather than never used. Of the six filesystem " +
	"libraries this is the only one that walks free space: the others offer a per-cluster or " +
	"per-block query, a raw bitmap, or a count the volume merely claims, and none of them a " +
	"traversal. Blocks in use by a file that was deleted are not free and will not appear here."

func (s *realHFSSession) Unallocated() (fsFreeSpaceScan, error) {
	header := s.volume.Header()

	scan := fsFreeSpaceScan{
		Filesystem:        "hfs",
		BlockSize:         int64(header.BlockSize),
		TotalBlocks:       int64(header.TotalBlocks),
		ClaimedFreeBlocks: int64(header.FreeBlocks),
		Complete:          true,
		WarningsAvailable: true,
		Scope:             hfsUnallocatedScope,
	}

	blockSize := scan.BlockSize
	if blockSize <= 0 {
		scan.Complete = false
		scan.IncompleteReason = "the volume header reports no block size"
		return scan, nil
	}

	unresolved := 0
	err := s.volume.WalkUnallocated(func(start, count uint32) error {
		run := fsFreeRun{
			StartBlock: int64(start),
			BlockCount: int64(count),
			Offset:     -1,
			Length:     int64(count) * blockSize,
		}
		if offset, offsetErr := s.volume.BlockOffset(start); offsetErr == nil {
			run.Offset = offset
		} else {
			unresolved++
		}
		scan.add(run)
		return nil
	})
	if err != nil {
		// A partial walk is still evidence, so what was found is kept and the
		// gap is named rather than the whole answer being thrown away.
		scan.warn(fsSlackWarnBitmapUnreadable, "allocation file", err.Error())
		scan.Complete = false
		scan.IncompleteReason = "the allocation file could not be read to the end"
	}
	if unresolved > 0 {
		scan.warn(fsSlackWarnUnresolvedOffset, "allocation file",
			fmt.Sprintf("%d free runs name blocks that do not resolve to an offset on this "+
				"volume, and are reported at offset -1", unresolved))
		scan.Complete = false
		if scan.IncompleteReason == "" {
			scan.IncompleteReason = "some free runs could not be placed on the medium"
		}
	}

	scan.ClaimMatches = scan.FreeBlocks == scan.ClaimedFreeBlocks

	return scan, nil
}
