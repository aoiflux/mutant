package builtin

// The *_capabilities family: what a filesystem can record, as distinct from
// what it happened to record.
//
// Every builtin in this tree that reports a file's times, its owner or its
// identity has the same hole under it. A field that comes back empty means one
// of two things and the value cannot tell them apart: the volume recorded
// nothing there, or the format has nowhere to record it. Merge six filesystems
// into one timeline without that distinction and every FAT file appears to have
// lost permissions it never had, every ext2 file a birth time that never
// existed, and an examiner reading the result has no way to see it.
//
// The six libraries answer this themselves -- each ships a Capabilities struct
// whose doc comments are explicit that a false means "this format does not keep
// that" -- and Mutant has never called any of them. This family does.
//
// Two bits, not one, exactly as the *_verify family reports checked beside
// passed. A capability is `supported` only where it is `answered`, and the
// answers a library does not give are named in `unanswered` rather than
// rendered as false. That distinction is not pedantry here: libhfs declares
// nine capabilities to libntfs's twenty-two, and of the eighteen questions this
// family asks of every filesystem it answers eight. HFS+ has recorded a
// creation date since 1985, and a reader that turned libhfs's silence into
// `creation_times: false` would be asserting the opposite, in a document an
// examiner would quote.
//
// Nothing here fills a gap from its own knowledge of the format. The whole
// family quotes the parser; inventing an answer the library declined to give
// would make this the one place in the tree where a capability report is
// evidence of what Mutant believes rather than of what was read.
//
// The other half of the shape is `source`. Most of these are constants of the
// format, but not all, and which is which decides whether an answer may be
// cached across volumes. ext2, ext3 and ext4 are one on-disk format governed by
// feature flags, so eleven of libext's twenty-three answers are read from this
// volume's superblock and two ext volumes will disagree. On HFS every one of
// the nine is volume state, because "HFS" names three formats -- classic HFS,
// HFS+ and HFSX -- and libhfs branches on which it opened before it answers
// anything at all.

import (
	"fmt"
	"sort"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libhfs "github.com/aoiflux/libhfs"
	libntfs "github.com/aoiflux/libntfs"
	libxfat "github.com/aoiflux/libxfat"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

// Where an answer came from. A format answer is the same on every volume of
// that filesystem; a volume answer was read from the superblock, boot record or
// volume header in hand and says nothing about the next volume.
const (
	fsCapFromFormat = "format"
	fsCapFromVolume = "volume"
)

// fsCoreCapabilities are the questions asked of all six filesystems.
//
// They are the ones a cross-filesystem report has to resolve before it can put
// two volumes in the same table: which times exist, what identity a file has,
// whether a deleted record survives. Anything a single format has and the others
// do not -- NTFS's alternate data streams, ext's extent trees, XFS's reflinks --
// is reported just as fully, but it is not asked of the others, because
// `alternate_data_streams: false` on an ext volume is a true statement that
// answers a question nobody sensible asked.
var fsCoreCapabilities = []string{
	"access_times",
	"case_sensitive",
	"compression",
	"creation_times",
	"deleted_entries_survive",
	"extended_attributes",
	"hard_links",
	"identity_reuse_counter",
	"journaled",
	"metadata_change_times",
	"modification_times",
	"posix_permissions",
	"sparse_files",
	"stable_file_identity",
	"sub_second_timestamps",
	"symbolic_links",
	"timezone_offsets",
	"unicode_names",
}

// fsCapabilityAliases renames a library's own spelling onto the one the rest of
// the family uses.
//
// libfat and libxfat call the journal question `journal` where the other four
// call it `journaled`. A code a script branches on should not differ between
// filesystems by a suffix, for the same reason the virtual-disk family folds
// libvhdi's `zeroed-by-child` into `zeroed_by_child`: a consumer writing
// `caps["journaled"]` should not silently miss two of the six.
//
// The direction is library spelling -> family spelling, and the conformance
// test reads it in that direction too, so an alias that stops matching a field
// fails the build rather than quietly dropping a capability.
var fsCapabilityAliases = map[string]string{"journal": "journaled"}

// fsCapabilityNonBool records the fields in a library's Capabilities struct
// that are not capabilities at all, so that a new one appearing in a future
// release fails the conformance test rather than being dropped.
//
// There is exactly one. libxfs carries the superblock's format version in its
// capability struct, which is the volume's variant rather than something it can
// or cannot record -- and xfs_metadata already reports it, so repeating it here
// would put the same number in two places with no way to tell which was read.
var fsCapabilityNonBool = map[string][]string{
	"xfs": {"format_version"},
}

// fsCapability is one thing a format can or cannot record.
//
// Supported is meaningful only because this struct exists at all: a capability
// the library does not declare produces no fsCapability, and so is reported in
// `unanswered` rather than as a false here.
type fsCapability struct {
	Name      string
	Supported bool
	Source    string
}

// fsCapabilitySet is what a *_capabilities builtin reports.
type fsCapabilitySet struct {
	Filesystem string
	Caps       []fsCapability

	// Scope states what this answer covers and what it does not. Every entry
	// here describes the format or the volume; none of them describes the
	// contents, and a reader who takes `access_times: true` as evidence that
	// any particular atime is meaningful has read it wrong.
	Scope string
}

// answered returns the names the library declared, sorted.
func (s fsCapabilitySet) answered() []string {
	names := make([]string, 0, len(s.Caps))
	for _, cap := range s.Caps {
		names = append(names, cap.Name)
	}
	sort.Strings(names)
	return names
}

// unanswered returns the core questions this library does not declare, sorted.
func (s fsCapabilitySet) unanswered() []string {
	declared := make(map[string]bool, len(s.Caps))
	for _, cap := range s.Caps {
		declared[cap.Name] = true
	}
	missing := make([]string, 0)
	for _, name := range fsCoreCapabilities {
		if !declared[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

// split divides the declared capabilities into the supported and the not.
func (s fsCapabilitySet) split() (supported, unsupported []string) {
	supported = make([]string, 0, len(s.Caps))
	unsupported = make([]string, 0, len(s.Caps))
	for _, cap := range s.Caps {
		if cap.Supported {
			supported = append(supported, cap.Name)
			continue
		}
		unsupported = append(unsupported, cap.Name)
	}
	sort.Strings(supported)
	sort.Strings(unsupported)
	return supported, unsupported
}

// volumeSpecific returns the names whose answer was read from this volume.
//
// It is the list a caller must not cache: every other answer is a constant of
// the format and holds for the next volume of the same kind.
func (s fsCapabilitySet) volumeSpecific() []string {
	names := make([]string, 0, len(s.Caps))
	for _, cap := range s.Caps {
		if cap.Source == fsCapFromVolume {
			names = append(names, cap.Name)
		}
	}
	sort.Strings(names)
	return names
}

func (s fsCapabilitySet) toHash(handle string) *object.Hash {
	caps := make([]object.Object, 0, len(s.Caps))
	sorted := append([]fsCapability(nil), s.Caps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, cap := range sorted {
		caps = append(caps, makeHashObject(map[string]object.Object{
			"name":      stringObj(cap.Name),
			"supported": boolObj(cap.Supported),
			"source":    stringObj(cap.Source),
		}))
	}

	supported, unsupported := s.split()
	unanswered := s.unanswered()

	// The reason names the count rather than the missing fields, which are in
	// `unanswered` beside it. A reason that repeated the list would be the one
	// part of the answer that goes stale when the library grows a field.
	reason := ""
	if len(unanswered) > 0 {
		reason = fmt.Sprintf(
			"this reader declares %d of the %d questions asked of every filesystem here; the other %d are unanswered rather than answered no",
			len(fsCoreCapabilities)-len(unanswered), len(fsCoreCapabilities), len(unanswered))
	}

	return makeHashObject(map[string]object.Object{
		"handle":            stringObj(handle),
		"filesystem":        stringObj(s.Filesystem),
		"capabilities":      &object.Array{Elements: caps},
		"capability_count":  intObj(int64(len(s.Caps))),
		"answered":          stringArray(s.answered()),
		"supported":         stringArray(supported),
		"unsupported":       stringArray(unsupported),
		"unanswered":        stringArray(unanswered),
		"unanswered_count":  intObj(int64(len(unanswered))),
		"core_questions":    stringArray(append([]string(nil), fsCoreCapabilities...)),
		"volume_specific":   stringArray(s.volumeSpecific()),
		"complete":          boolObj(len(unanswered) == 0),
		"incomplete_reason": stringObj(reason),
		"scope":             stringObj(s.Scope),
		"status":            stringObj("ok"),
	})
}

// --- the builtins -----------------------------------------------------------

func NtfsCapabilities(args ...object.Object) object.Object {
	return runCapabilities(args, BuiltinNameNtfsCapabilities, func(arg object.Object, op string) (fsCapabilityReader, *object.Error) {
		resolved, err := resolveNTFSHandle(arg, op)
		return resolved.Session, err
	})
}

func FatCapabilities(args ...object.Object) object.Object {
	return runCapabilities(args, BuiltinNameFatCapabilities, func(arg object.Object, op string) (fsCapabilityReader, *object.Error) {
		resolved, err := resolveFATHandle(arg, op)
		return resolved.Session, err
	})
}

func XFATCapabilities(args ...object.Object) object.Object {
	return runCapabilities(args, BuiltinNameXfatCapabilities, func(arg object.Object, op string) (fsCapabilityReader, *object.Error) {
		resolved, err := resolveXFATHandle(arg, op)
		return resolved.Session, err
	})
}

func ExtCapabilities(args ...object.Object) object.Object {
	return runCapabilities(args, BuiltinNameExtCapabilities, func(arg object.Object, op string) (fsCapabilityReader, *object.Error) {
		resolved, err := resolveEXTHandle(arg, op)
		return resolved.Session, err
	})
}

func HFSCapabilities(args ...object.Object) object.Object {
	return runCapabilities(args, BuiltinNameHfsCapabilities, func(arg object.Object, op string) (fsCapabilityReader, *object.Error) {
		resolved, err := resolveHFSHandle(arg, op)
		return resolved.Session, err
	})
}

func XFSCapabilities(args ...object.Object) object.Object {
	return runCapabilities(args, BuiltinNameXfsCapabilities, func(arg object.Object, op string) (fsCapabilityReader, *object.Error) {
		resolved, err := resolveXFSHandle(arg, op)
		return resolved.Session, err
	})
}

// fsCapabilityReader is the one method the six sessions have in common here.
type fsCapabilityReader interface {
	Capabilities() (fsCapabilitySet, error)
}

func runCapabilities(args []object.Object, op string,
	resolve func(object.Object, string) (fsCapabilityReader, *object.Error),
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

	set, err := session.Capabilities()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(set.toHash(handle), nil)
}

// --- ntfs -------------------------------------------------------------------

// The one volume-dependent answer is the change journal, and it is the one that
// matters most: $UsnJrnl is a per-volume feature that can be enabled, filled,
// deleted and re-created, and libntfs reads it rather than assuming it. Every
// other line here is true of NTFS itself.
func (s *realNTFSSession) Capabilities() (fsCapabilitySet, error) {
	return ntfsCapabilitySet(s.volume.Capabilities()), nil
}

func ntfsCapabilitySet(caps libntfs.Capabilities) fsCapabilitySet {
	return fsCapabilitySet{
		Filesystem: "ntfs",
		Caps: []fsCapability{
			{"unicode_names", caps.UnicodeNames, fsCapFromFormat},
			{"case_sensitive", caps.CaseSensitive, fsCapFromFormat},
			{"creation_times", caps.CreationTimes, fsCapFromFormat},
			{"modification_times", caps.ModificationTimes, fsCapFromFormat},
			{"access_times", caps.AccessTimes, fsCapFromFormat},
			{"metadata_change_times", caps.MetadataChangeTimes, fsCapFromFormat},
			{"sub_second_timestamps", caps.SubSecondTimestamps, fsCapFromFormat},
			{"timezone_offsets", caps.TimezoneOffsets, fsCapFromFormat},
			{"posix_permissions", caps.POSIXPermissions, fsCapFromFormat},
			{"security_descriptors", caps.SecurityDescriptors, fsCapFromFormat},
			{"hard_links", caps.HardLinks, fsCapFromFormat},
			{"symbolic_links", caps.SymbolicLinks, fsCapFromFormat},
			{"extended_attributes", caps.ExtendedAttributes, fsCapFromFormat},
			{"alternate_data_streams", caps.AlternateDataStreams, fsCapFromFormat},
			{"sparse_files", caps.SparseFiles, fsCapFromFormat},
			{"compression", caps.Compression, fsCapFromFormat},
			{"encryption", caps.Encryption, fsCapFromFormat},
			{"stable_file_identity", caps.StableFileIdentity, fsCapFromFormat},
			{"identity_reuse_counter", caps.IdentityReuseCounter, fsCapFromFormat},
			{"deleted_entries_survive", caps.DeletedEntriesSurvive, fsCapFromFormat},
			{"journaled", caps.Journaled, fsCapFromFormat},
			{"change_journal", caps.ChangeJournal, fsCapFromVolume},
		},
		Scope: "what NTFS records and what this volume was formatted with. " +
			"change_journal was read from this volume -- $UsnJrnl can be enabled, " +
			"deleted and re-created -- and libntfs cannot tell a journal that was " +
			"never enabled from an $Extend directory too damaged to read, so a " +
			"false there is not proof of absence. Everything else is a constant " +
			"of the format. None of it describes the contents: a true " +
			"access_times says the record has the field, not that any atime on " +
			"this volume was maintained.",
	}
}

// --- fat --------------------------------------------------------------------

// Three of the twenty-four come from the boot record, and all three are about
// what this volume can be checked or recovered against rather than what it
// records: a second allocation table to compare, an FSInfo sector to read hints
// from, a backup boot sector that may be what let the volume be opened at all.
func (s *realFATSession) Capabilities() (fsCapabilitySet, error) {
	return fatCapabilitySet(s.volume.Capabilities()), nil
}

func fatCapabilitySet(caps libfat.Capabilities) fsCapabilitySet {
	return fsCapabilitySet{
		Filesystem: "fat",
		Caps: []fsCapability{
			{"unicode_names", caps.UnicodeNames, fsCapFromFormat},
			{"case_sensitive", caps.CaseSensitive, fsCapFromFormat},
			{"creation_times", caps.CreationTimes, fsCapFromFormat},
			{"modification_times", caps.ModificationTimes, fsCapFromFormat},
			{"access_times", caps.AccessTimes, fsCapFromFormat},
			{"metadata_change_times", caps.MetadataChangeTimes, fsCapFromFormat},
			{"sub_second_timestamps", caps.SubSecondTimestamps, fsCapFromFormat},
			{"timezone_offsets", caps.TimezoneOffsets, fsCapFromFormat},
			{"posix_permissions", caps.POSIXPermissions, fsCapFromFormat},
			{"hard_links", caps.HardLinks, fsCapFromFormat},
			{"symbolic_links", caps.SymbolicLinks, fsCapFromFormat},
			{"extended_attributes", caps.ExtendedAttributes, fsCapFromFormat},
			{"sparse_files", caps.SparseFiles, fsCapFromFormat},
			{"compression", caps.Compression, fsCapFromFormat},
			{"stable_file_identity", caps.StableFileIdentity, fsCapFromFormat},
			{"identity_reuse_counter", caps.IdentityReuseCounter, fsCapFromFormat},
			{"allocation_bitmap", caps.AllocationBitmap, fsCapFromFormat},
			{"valid_data_length", caps.ValidDataLength, fsCapFromFormat},
			{"declared_contiguity", caps.DeclaredContiguity, fsCapFromFormat},
			{"deleted_entries_survive", caps.DeletedEntriesSurvive, fsCapFromFormat},
			{"journaled", caps.Journal, fsCapFromFormat},
			{"second_fat", caps.SecondFAT, fsCapFromVolume},
			{"fs_info_sector", caps.FSInfoSector, fsCapFromVolume},
			{"backup_boot_sector", caps.BackupBootSector, fsCapFromVolume},
		},
		Scope: "what FAT records and what this volume's boot record says. " +
			"sub_second_timestamps is true of one timestamp only: creation is " +
			"recorded to 10 milliseconds, modification to 2 seconds and last " +
			"access to the day, so equal timestamps on FAT are not evidence that " +
			"nothing changed. stable_file_identity false is the consequential " +
			"one -- a directory slot reused after a deletion carries its " +
			"predecessor's identity exactly, so two readings of this volume " +
			"cannot be diffed on it.",
	}
}

// --- exfat ------------------------------------------------------------------

func (s *realXFATSession) Capabilities() (fsCapabilitySet, error) {
	return xfatCapabilitySet(s.fs.Capabilities()), nil
}

func xfatCapabilitySet(caps libxfat.Capabilities) fsCapabilitySet {
	return fsCapabilitySet{
		Filesystem: "exfat",
		Caps: []fsCapability{
			{"unicode_names", caps.UnicodeNames, fsCapFromFormat},
			{"case_sensitive", caps.CaseSensitive, fsCapFromFormat},
			{"creation_times", caps.CreationTimes, fsCapFromFormat},
			{"modification_times", caps.ModificationTimes, fsCapFromFormat},
			{"access_times", caps.AccessTimes, fsCapFromFormat},
			{"metadata_change_times", caps.MetadataChangeTimes, fsCapFromFormat},
			{"sub_second_timestamps", caps.SubSecondTimestamps, fsCapFromFormat},
			{"timezone_offsets", caps.TimezoneOffsets, fsCapFromFormat},
			{"posix_permissions", caps.POSIXPermissions, fsCapFromFormat},
			{"hard_links", caps.HardLinks, fsCapFromFormat},
			{"symbolic_links", caps.SymbolicLinks, fsCapFromFormat},
			{"extended_attributes", caps.ExtendedAttributes, fsCapFromFormat},
			{"sparse_files", caps.SparseFiles, fsCapFromFormat},
			{"compression", caps.Compression, fsCapFromFormat},
			{"stable_file_identity", caps.StableFileIdentity, fsCapFromFormat},
			{"identity_reuse_counter", caps.IdentityReuseCounter, fsCapFromFormat},
			{"allocation_bitmap", caps.AllocationBitmap, fsCapFromFormat},
			{"valid_data_length", caps.ValidDataLength, fsCapFromFormat},
			{"declared_contiguity", caps.DeclaredContiguity, fsCapFromFormat},
			{"deleted_entries_survive", caps.DeletedEntriesSurvive, fsCapFromFormat},
			{"journaled", caps.Journal, fsCapFromFormat},
			{"second_fat", caps.SecondFAT, fsCapFromVolume},
		},
		Scope: "what exFAT records and what this volume's boot record says. " +
			"exFAT is the sibling of FAT that gained three things FAT has none " +
			"of -- an allocation bitmap independent of the table, a valid data " +
			"length distinguishing written bytes from allocated ones, and a " +
			"NoFatChain flag declaring contiguity -- and gained no metadata " +
			"change time, no owner and no identity that survives reuse. " +
			"timezone_offsets is the one timestamp question it answers " +
			"differently from FAT: exFAT stores the offset beside the stamp.",
	}
}

// --- ext --------------------------------------------------------------------

// Eleven of the twenty-three are read from this volume's superblock, which is
// more than any other filesystem here and is a property of ext rather than of
// libext: ext2, ext3 and ext4 are one on-disk format separated by feature
// flags. creation_times and sub_second_timestamps both follow the inode size,
// and that single difference is most of what separates an ext2 volume from an
// ext4 one.
func (s *realEXTSession) Capabilities() (fsCapabilitySet, error) {
	return extCapabilitySet(s.fs.Capabilities()), nil
}

func extCapabilitySet(caps libext.Capabilities) fsCapabilitySet {
	return fsCapabilitySet{
		Filesystem: "ext",
		Caps: []fsCapability{
			{"unicode_names", caps.UnicodeNames, fsCapFromFormat},
			{"case_sensitive", caps.CaseSensitive, fsCapFromVolume},
			{"creation_times", caps.CreationTimes, fsCapFromVolume},
			{"modification_times", caps.ModificationTimes, fsCapFromFormat},
			{"access_times", caps.AccessTimes, fsCapFromFormat},
			{"metadata_change_times", caps.MetadataChangeTimes, fsCapFromFormat},
			{"sub_second_timestamps", caps.SubSecondTimestamps, fsCapFromVolume},
			{"timezone_offsets", caps.TimezoneOffsets, fsCapFromFormat},
			{"posix_permissions", caps.POSIXPermissions, fsCapFromFormat},
			{"hard_links", caps.HardLinks, fsCapFromFormat},
			{"symbolic_links", caps.SymbolicLinks, fsCapFromFormat},
			{"extended_attributes", caps.ExtendedAttributes, fsCapFromVolume},
			{"sparse_files", caps.SparseFiles, fsCapFromFormat},
			{"compression", caps.Compression, fsCapFromFormat},
			{"stable_file_identity", caps.StableFileIdentity, fsCapFromFormat},
			{"identity_reuse_counter", caps.IdentityReuseCounter, fsCapFromFormat},
			{"journaled", caps.Journaled, fsCapFromVolume},
			{"extents", caps.Extents, fsCapFromVolume},
			{"sixty_four_bit", caps.SixtyFourBit, fsCapFromVolume},
			{"directory_index", caps.DirectoryIndex, fsCapFromVolume},
			{"inline_data", caps.InlineData, fsCapFromVolume},
			{"metadata_checksums", caps.MetadataChecksums, fsCapFromVolume},
			{"bigalloc", caps.Bigalloc, fsCapFromVolume},
		},
		Scope: "what ext records and what this volume's superblock enables. " +
			"Eleven answers are volume state, because ext2, ext3 and ext4 are one " +
			"format governed by feature flags: two volumes opened by the same " +
			"library will disagree, and an answer cached from one of them is " +
			"wrong about the other. journaled is true only when the journal is " +
			"on this volume -- a volume using an external journal device reports " +
			"false, meaning the journal exists but not here. " +
			"deleted_entries_survive is not among the questions libext answers, " +
			"so it is unanswered rather than false; ext_deleted is what reports " +
			"on that.",
	}
}

// --- hfs --------------------------------------------------------------------

// Every one of the nine is volume state, because "HFS" names three formats.
// libhfs branches on which it opened before it answers anything: classic HFS
// returns two answers and eight zero values, HFS+ reads the attributes file and
// the journal bit off the volume header, and HFSX reads the catalog B-tree
// header to find out whether its names compare case-sensitively.
func (s *realHFSSession) Capabilities() (fsCapabilitySet, error) {
	return hfsCapabilitySet(s.volume.Capabilities()), nil
}

func hfsCapabilitySet(caps libhfs.Capabilities) fsCapabilitySet {
	return fsCapabilitySet{
		Filesystem: "hfs",
		Caps: []fsCapability{
			{"unicode_names", caps.UnicodeNames, fsCapFromVolume},
			{"case_sensitive", caps.CaseSensitive, fsCapFromVolume},
			{"access_times", caps.AccessTimes, fsCapFromVolume},
			{"attr_mod_times", caps.AttrModTimes, fsCapFromVolume},
			{"posix_permissions", caps.POSIXPermissions, fsCapFromVolume},
			{"hard_links", caps.HardLinks, fsCapFromVolume},
			{"extended_attributes", caps.ExtendedAttributes, fsCapFromVolume},
			{"compression", caps.Compression, fsCapFromVolume},
			{"journaled", caps.Journaled, fsCapFromVolume},
		},
		Scope: "what this HFS volume's kind records. All nine answers are volume " +
			"state: classic HFS, HFS+ and HFSX are three formats behind one name " +
			"and libhfs decides which it opened before answering. This is the " +
			"shortest capability set of the six -- ten of the questions asked of " +
			"every filesystem here go unanswered, creation and modification times " +
			"among them. HFS has recorded both since 1985, so read the silence as " +
			"a gap in what libhfs declares and not as an absence on the volume; " +
			"hfs_metadata reports the dates themselves.",
	}
}

// --- xfs --------------------------------------------------------------------

// Thirteen format constants and twelve answers off the superblock, the split
// falling almost exactly on the v4/v5 line: creation_times and
// metadata_checksums are both "is this a v5 filesystem", and the rest are
// feature bits a v5 filesystem may or may not carry.
func (s *realXFSSession) Capabilities() (fsCapabilitySet, error) {
	return xfsCapabilitySet(s.volume.Capabilities()), nil
}

func xfsCapabilitySet(caps libxfs.Capabilities) fsCapabilitySet {
	return fsCapabilitySet{
		Filesystem: "xfs",
		Caps: []fsCapability{
			{"unicode_names", caps.UnicodeNames, fsCapFromFormat},
			{"case_sensitive", caps.CaseSensitive, fsCapFromFormat},
			{"modification_times", caps.ModificationTimes, fsCapFromFormat},
			{"access_times", caps.AccessTimes, fsCapFromFormat},
			{"metadata_change_times", caps.MetadataChangeTimes, fsCapFromFormat},
			{"sub_second_timestamps", caps.SubSecondTimestamps, fsCapFromFormat},
			{"timezone_offsets", caps.TimezoneOffsets, fsCapFromFormat},
			{"posix_permissions", caps.POSIXPermissions, fsCapFromFormat},
			{"hard_links", caps.HardLinks, fsCapFromFormat},
			{"symbolic_links", caps.SymbolicLinks, fsCapFromFormat},
			{"extended_attributes", caps.ExtendedAttributes, fsCapFromFormat},
			{"sparse_files", caps.SparseFiles, fsCapFromFormat},
			{"compression", caps.Compression, fsCapFromFormat},
			{"creation_times", caps.CreationTimes, fsCapFromVolume},
			{"journaled", caps.Journaled, fsCapFromVolume},
			{"metadata_checksums", caps.MetadataChecksums, fsCapFromVolume},
			{"directory_entry_file_types", caps.DirectoryEntryFileTypes, fsCapFromVolume},
			{"big_timestamps", caps.BigTimestamps, fsCapFromVolume},
			{"large_extent_counts", caps.LargeExtentCounts, fsCapFromVolume},
			{"sparse_inodes", caps.SparseInodes, fsCapFromVolume},
			{"separate_metadata_uuid", caps.SeparateMetadataUUID, fsCapFromVolume},
			{"reflink", caps.Reflink, fsCapFromVolume},
			{"free_inode_btree", caps.FreeInodeBtree, fsCapFromVolume},
			{"reverse_mapping", caps.ReverseMapping, fsCapFromVolume},
			{"needs_repair", caps.NeedsRepair, fsCapFromVolume},
		},
		Scope: "what XFS records and what this superblock enables. " +
			"creation_times is the v5 line: a v4 filesystem has no birth time at " +
			"all, and journaled is true only for an internal log, so a filesystem " +
			"with an external log device reports false. needs_repair is the one " +
			"entry here that is not a capability -- it is the superblock's own " +
			"statement that this filesystem was not cleanly unmounted, quoted " +
			"where libxfs put it rather than moved somewhere tidier.",
	}
}
