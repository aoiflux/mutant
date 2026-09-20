package builtin

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	libvhdi "github.com/aoiflux/libvhdi"

	"mutant/object"
)

// A virtual disk is not a file, and that is the whole subject of this file.
//
// Three facts about VHD and VHDX make the builtins here necessary, and every
// one of them is invisible to a tool that treats the image as a byte stream.
//
// The first is that most of the address space may not exist. A dynamic image
// stores only the blocks something wrote, and the rest reads back as zeroes
// that are nowhere in the file. An acquisition that reads the device end to
// end moves the whole virtual size through memory, most of it zeroes the image
// never stored, and a carve that treats those zeroes as content is carving the
// absence of data. `vhdi_extents` says which ranges are real.
//
// The second is that the device is often several files. A differencing disk
// holds only what was written since its parent, and what an examiner sees is
// the chain read together. Those files are what an evidence record has to name,
// and `vhdi_chain` names them -- with what produced each one, because the links
// of a chain are routinely made by different tools at different times and
// flattening that into one record loses the detail that explains the chain.
//
// The third is that "what changed" is answerable at block level with no
// filesystem knowledge at all, which is what makes a checkpoint chain worth
// keeping. `vhdi_changed_extents` and `vhdi_changed_since` answer it.
//
// Four things this file refuses to round off.
//
// A range with no bytes behind it has no file offset, so `file_offset` is -1
// there rather than 0. libvhdi leaves the field at its zero value for every
// kind but mapped, and 0 is a real offset: the first byte of the file.
//
// A range nothing in the chain ever wrote and a range a child explicitly
// cleared both read back as zeroes, and they are different facts. The second is
// a write. A deletion that clears its blocks shows up only that way, so folding
// the two together would under-report deletions and do it silently. They are
// separate kinds here and separate totals.
//
// VHD cannot express the second at all. Its per-block sector bitmap
// distinguishes only "this sector is mine" from "read this sector from the
// parent", and there is no state meaning zero, so a region cleared on a VHD
// chain reads back as the parent's old contents. The clearing is not merely
// invisible to change tracking; at the format level it did not happen. Every
// changed-range answer that crosses a VHD link says so.
//
// An image that never returns written blocks to the free pool keeps them
// mapped after the guest has deleted what was in them. The mapped total then
// overstates what is in use, and that is a property of the image rather than of
// the reading, so it rides on the answer as a warning rather than sitting in
// prose somewhere else.
//
// One boundary is drawn deliberately. `vhdi_probe` registers the image it reads
// as evidence and `vhdi_discover` registers nothing, and the difference is who
// named the file. A program that passes a path has said that file is evidence.
// A program that passes a directory has asked what is in it. Registering every
// image a directory happens to hold would put files in the manifest the
// examination never opened, and would hash each of them -- turning the one call
// in this family that reads nothing but headers into the most expensive call in
// the language.

// Extent kinds, as a script matches on them.
//
// libvhdi spells the fourth "zeroed-by-child". The hyphen is the only one in
// any stable code this language hands out, and a value a script compares
// against should not differ from its neighbours by punctuation, so the names
// are mapped here rather than passed through. The same goes for the footer
// sources below.
const (
	vhdiExtentZero          = "zero"
	vhdiExtentMapped        = "mapped"
	vhdiExtentUnresolved    = "unresolved"
	vhdiExtentZeroedByChild = "zeroed_by_child"
	vhdiExtentUnknown       = "unknown"
)

// Warning codes. Stable; the prose beside them is not.
const (
	vhdiWarnWindowClamped       = "window_clamped_to_device"
	vhdiWarnExtentsTruncated    = "extent_list_truncated"
	vhdiWarnChainIncomplete     = "chain_incomplete"
	vhdiWarnUnresolvedRange     = "unresolved_range_in_answer"
	vhdiWarnBlocksNeverFreed    = "allocated_blocks_never_freed"
	vhdiWarnImageDirty          = "image_log_not_replayed"
	vhdiWarnDeletionsNotStored  = "deletions_not_expressible"
	vhdiWarnNamedDiskIsLeaf     = "named_disk_is_the_leaf"
	vhdiWarnIndexUnresolved     = "chain_index_not_resolved"
	vhdiWarnImageExpanded       = "image_expanded_since_creation"
	vhdiWarnSavedState          = "saved_from_running_machine"
	vhdiWarnFooterRecovered     = "footer_recovered"
	vhdiWarnExtensionMismatch   = "checkpoint_extension_mismatch"
	vhdiWarnUnreplayedLogOnDisk = "image_carries_unreplayed_log"
	vhdiWarnZeroLinkIdentity    = "image_records_no_link_identity"
	vhdiWarnDuplicateLink       = "duplicate_link_identity"
	vhdiWarnOrphanedChild       = "parent_not_in_directory"
	vhdiWarnTreeBranched        = "checkpoint_tree_branched"
	vhdiWarnLineageIncomplete   = "lineage_missing_its_base"
	vhdiWarnImageUnreadable     = "image_could_not_be_probed"
	vhdiWarnNodesTruncated      = "node_list_truncated"
)

const (
	// vhdiMaxExtents caps the rendered extent list. The totals beside it are
	// computed over every extent libvhdi returned, so a truncated list still
	// sits beside an honest account of the whole window.
	vhdiMaxExtents = 20000

	// vhdiMaxNodes and vhdiMaxLineages cap what a directory scan renders.
	// libvhdi refuses a directory holding more than 4096 images before this can
	// bite, and the cap stays because a refusal there is its decision to change
	// and not one this language should inherit silently.
	vhdiMaxNodes    = 4096
	vhdiMaxLineages = 256
)

// The chain itself is not capped. libvhdi bounds a differencing chain at
// DefaultMaxChainDepth links and refuses anything longer, so a cap here would
// be a number that can never be reached.

const vhdiScopeExtents = "vhdi_extents maps the requested window of the virtual address space to what backs it, reading block allocation tables and, for a partially written differencing block, its sector bitmap. It reads the contents of nothing. A mapped range means bytes exist at that place in that file; it does not mean those bytes are live data, because an image that never returns written blocks to the free pool keeps them mapped after the guest deleted what was in them. A range that resolves to a parent which is not attached is reported as unresolved, and is neither zero nor mapped."

const vhdiScopeChain = "vhdi_chain names every image file that together constitutes this device, from the disk that was opened outwards to its base, with what produced each one. It describes the links attached at the moment it was called: a chain whose parent could not be resolved is shorter than the device requires, and complete says so. Nothing here is read from the guest's filesystem, and no image content is read at all."

const vhdiScopeChanged = "vhdi_changed_extents reports which ranges of the virtual disk were written by the links nearer the leaf than the named chain index, from block allocation tables and sector bitmaps alone. It is a statement about which ranges were written, not about what was written there, by whom, or when. A range a child explicitly cleared counts as written. A VHD link cannot record an explicit clear at all, so across one, deletions are absent from the format rather than merely unreported."

const vhdiScopeChangedSince = "vhdi_changed_since is vhdi_changed_extents addressed by the path of a disk in the chain rather than by its index, and reports the index it resolved to. It carries the same boundaries: block allocation tables and sector bitmaps only, a cleared range counted as a write, and no claim about what was written. Naming the disk that was opened yields nothing, because nothing can have been written since the leaf."

const vhdiScopeDiscover = "vhdi_discover reads the headers of every disk image in the directory and joins them into the parent-to-child tree they record. It parses no block allocation table, replays no log and reads no image content, so each image here is described by what it says about itself. Children are joined to parents by recorded identity alone, and a child whose parent is not in the directory stays a root rather than being matched on size or on a filename. The images are not registered as evidence: naming a directory is not the same as naming the files an examination read."

const vhdiScopeProbe = "vhdi_probe reads one image's headers without opening it. No block allocation table is parsed, no log is replayed and no content is read, so the answer is what the file says about itself and what chain it records. The image is registered as evidence, because the program named this file."

// vhdiExtent is one contiguous run of the virtual address space and what backs
// it.
//
// FileOffset is -1 for every kind but mapped. Path is empty for an unresolved
// run, because the file that would back it is the one that is missing, and
// ChainIndex there names that missing link rather than a link that is present.
type vhdiExtent struct {
	VirtualOffset int64
	Length        int64
	Kind          string
	IsWrite       bool
	ReadsAsZero   bool
	FileOffset    int64
	ChainIndex    int64
	Path          string
}

func (e vhdiExtent) toHash(index int64) *object.Hash {
	return makeHashObject(map[string]object.Object{
		"index":          intObj(index),
		"virtual_offset": intObj(e.VirtualOffset),
		"length":         intObj(e.Length),
		"kind":           stringObj(e.Kind),
		"is_write":       boolObj(e.IsWrite),
		"reads_as_zero":  boolObj(e.ReadsAsZero),
		"file_offset":    intObj(e.FileOffset),
		"chain_index":    intObj(e.ChainIndex),
		"path":           stringObj(e.Path),
	})
}

// vhdiExtentList accumulates extents and their totals, keeping the totals
// honest past the cap.
//
// The four totals are kept apart rather than summed because each answers a
// different question: mapped is what an acquisition has to read, zero is what
// it may skip, zeroed_by_child is what it must write zeroes over, and
// unresolved is what it cannot account for at all.
type vhdiExtentList struct {
	Extents            []vhdiExtent
	Count              int64
	Truncated          bool
	MappedBytes        int64
	ZeroBytes          int64
	UnresolvedBytes    int64
	ZeroedByChildBytes int64
}

func (l *vhdiExtentList) add(raw libvhdi.Extent) {
	l.Count++

	kind := vhdiExtentKindName(raw.Kind)
	switch raw.Kind {
	case libvhdi.ExtentMapped:
		l.MappedBytes += raw.Length
	case libvhdi.ExtentZero:
		l.ZeroBytes += raw.Length
	case libvhdi.ExtentZeroedByChild:
		l.ZeroedByChildBytes += raw.Length
	case libvhdi.ExtentUnresolved:
		l.UnresolvedBytes += raw.Length
	}

	if len(l.Extents) >= vhdiMaxExtents {
		l.Truncated = true
		return
	}

	// The file offset is only a place in a file when there are bytes there.
	// Everywhere else libvhdi leaves the field at zero, which is an offset a
	// caller can seek to.
	fileOffset := int64(-1)
	if raw.Kind == libvhdi.ExtentMapped {
		fileOffset = raw.FileOffset
	}

	l.Extents = append(l.Extents, vhdiExtent{
		VirtualOffset: raw.VirtualOffset,
		Length:        raw.Length,
		Kind:          kind,
		IsWrite:       raw.Kind.IsWrite(),
		ReadsAsZero:   raw.Kind.ReadsAsZero(),
		FileOffset:    fileOffset,
		ChainIndex:    int64(raw.ChainIndex),
		Path:          raw.Path,
	})
}

func (l vhdiExtentList) array() object.Object {
	out := make([]object.Object, 0, len(l.Extents))
	for i, extent := range l.Extents {
		out = append(out, extent.toHash(int64(i)))
	}
	return &object.Array{Elements: out}
}

// vhdiFindings is the warning and completeness bookkeeping every scan here
// carries. It is one type rather than a field set repeated six times because
// all six builtins answer the same two questions beside their own: what could
// this call not do, and is the answer whole.
type vhdiFindings struct {
	Complete         bool
	IncompleteReason string
	Warnings         []fsDeletedWarning
}

func (f *vhdiFindings) warn(code, location, detail string) {
	f.Warnings = append(f.Warnings, fsDeletedWarning{Code: code, Location: location, Detail: detail})
}

// incomplete keeps the first reason. The first is the one that explains the
// earliest missing evidence, and a later gap is frequently a consequence of it.
func (f *vhdiFindings) incomplete(reason string) {
	f.Complete = false
	if f.IncompleteReason == "" {
		f.IncompleteReason = reason
	}
}

// chainWarnings folds in what libvhdi raised about this disk and every parent
// below it.
//
// They are carried on every answer that depends on the chain rather than only
// on vhdi_chain, because a differencing disk is only as trustworthy as the
// chain behind it: an extent map of a device reconstructed from a parent whose
// identity could not be verified is a map of a device that may not be the one
// the examiner thinks they have.
func (f *vhdiFindings) chainWarnings(warnings []libvhdi.Warning) {
	for _, warning := range warnings {
		f.warn(string(warning.Kind), warning.Path, warning.Detail)
	}
}

func (f vhdiFindings) into(fields map[string]object.Object) {
	fields["complete"] = boolObj(f.Complete)
	fields["incomplete_reason"] = stringObj(f.IncompleteReason)
	fields["warnings_available"] = boolObj(true)
	fields["warnings"] = warningArray(f.Warnings)
	fields["warning_codes"] = warningCodeArray(f.Warnings)
}

// vhdiExtentScan is what vhdi_extents reports.
type vhdiExtentScan struct {
	vhdiFindings
	Path          string
	VirtualOffset int64
	Length        int64
	VirtualSize   int64
	ChainComplete bool
	List          vhdiExtentList
	Scope         string
}

func (s vhdiExtentScan) toHash(handle string) *object.Hash {
	fields := map[string]object.Object{
		"handle":                stringObj(handle),
		"path":                  stringObj(s.Path),
		"virtual_offset":        intObj(s.VirtualOffset),
		"length":                intObj(s.Length),
		"virtual_size":          intObj(s.VirtualSize),
		"chain_complete":        boolObj(s.ChainComplete),
		"extents":               s.List.array(),
		"extent_count":          intObj(s.List.Count),
		"extents_truncated":     boolObj(s.List.Truncated),
		"mapped_bytes":          intObj(s.List.MappedBytes),
		"zero_bytes":            intObj(s.List.ZeroBytes),
		"zeroed_by_child_bytes": intObj(s.List.ZeroedByChildBytes),
		"unresolved_bytes":      intObj(s.List.UnresolvedBytes),
		"scope":                 stringObj(s.Scope),
		"status":                stringObj("ok"),
	}
	s.into(fields)
	return makeHashObject(fields)
}

// vhdiChangedScan is what vhdi_changed_extents and vhdi_changed_since report.
// They share one envelope because they ask one question and differ only in how
// the disk being asked about was named.
type vhdiChangedScan struct {
	vhdiFindings
	Path                 string
	SinceChainIndex      int64
	SincePath            string
	ChainDepth           int64
	ChainComplete        bool
	DeletionsExpressible bool
	List                 vhdiExtentList
	Scope                string
}

func (s vhdiChangedScan) toHash(handle string) *object.Hash {
	fields := map[string]object.Object{
		"handle":                stringObj(handle),
		"path":                  stringObj(s.Path),
		"since_chain_index":     intObj(s.SinceChainIndex),
		"since_path":            stringObj(s.SincePath),
		"chain_depth":           intObj(s.ChainDepth),
		"chain_complete":        boolObj(s.ChainComplete),
		"deletions_expressible": boolObj(s.DeletionsExpressible),
		"extents":               s.List.array(),
		"extent_count":          intObj(s.List.Count),
		"extents_truncated":     boolObj(s.List.Truncated),
		"changed_bytes":         intObj(s.List.MappedBytes + s.List.ZeroedByChildBytes),
		"mapped_bytes":          intObj(s.List.MappedBytes),
		"zeroed_by_child_bytes": intObj(s.List.ZeroedByChildBytes),
		"unresolved_bytes":      intObj(s.List.UnresolvedBytes),
		"scope":                 stringObj(s.Scope),
		"status":                stringObj("ok"),
	}
	s.into(fields)
	return makeHashObject(fields)
}

// vhdiChainLink is one image in the chain that constitutes the device, with
// what is known about its origin.
//
// Provenance is per link rather than per device because the links were often
// produced by different tools at different times, and one flattened record
// loses exactly the detail that makes a chain explicable.
type vhdiChainLink struct {
	Index            int64
	Path             string
	Identifier       string
	ParentIdentifier string
	ParentFilename   string
	Format           string
	DiskType         string
	VirtualSize      int64
	FileSize         int64
	IsDifferencing   bool

	HasLog               bool
	LogReplayed          bool
	LogReplayEntries     int64
	LogReplayDescriptors int64
	LogReplaySectors     int64

	CreatorApplication  string
	CreatorVersion      string
	CreatorOS           string
	Created             string
	DataWriteIdentifier string
	OriginalSize        int64
	SavedState          bool

	LeaveBlocksAllocated bool
	FooterSource         string
	FooterRecovered      bool
}

func (l vhdiChainLink) toHash() *object.Hash {
	return makeHashObject(map[string]object.Object{
		"index":             intObj(l.Index),
		"path":              stringObj(l.Path),
		"identifier":        stringObj(l.Identifier),
		"parent_identifier": stringObj(l.ParentIdentifier),
		"parent_filename":   stringObj(l.ParentFilename),
		"format":            stringObj(l.Format),
		"disk_type":         stringObj(l.DiskType),
		"virtual_size":      intObj(l.VirtualSize),
		"file_size":         intObj(l.FileSize),
		"is_differencing":   boolObj(l.IsDifferencing),

		"has_log":                boolObj(l.HasLog),
		"log_replayed":           boolObj(l.LogReplayed),
		"log_replay_entries":     intObj(l.LogReplayEntries),
		"log_replay_descriptors": intObj(l.LogReplayDescriptors),
		"log_replay_sectors":     intObj(l.LogReplaySectors),

		"creator_application":   stringObj(l.CreatorApplication),
		"creator_version":       stringObj(l.CreatorVersion),
		"creator_os":            stringObj(l.CreatorOS),
		"created":               stringObj(l.Created),
		"data_write_identifier": stringObj(l.DataWriteIdentifier),
		"original_size":         intObj(l.OriginalSize),
		"saved_state":           boolObj(l.SavedState),

		"leave_blocks_allocated": boolObj(l.LeaveBlocksAllocated),
		"footer_source":          stringObj(l.FooterSource),
		"footer_recovered":       boolObj(l.FooterRecovered),
	})
}

// vhdiChainScan is what vhdi_chain reports.
//
// complete here means every file the device needs is named below. It is the
// same fact as ChainComplete and is not reported twice under two names.
type vhdiChainScan struct {
	vhdiFindings
	Path               string
	Depth              int64
	NeedsParent        bool
	ParentResolveError string
	Links              []vhdiChainLink
	Scope              string
}

func (s vhdiChainScan) toHash(handle string) *object.Hash {
	links := make([]object.Object, 0, len(s.Links))
	paths := make([]string, 0, len(s.Links))
	for _, link := range s.Links {
		links = append(links, link.toHash())
		paths = append(paths, link.Path)
	}

	fields := map[string]object.Object{
		"handle":               stringObj(handle),
		"path":                 stringObj(s.Path),
		"depth":                intObj(s.Depth),
		"needs_parent":         boolObj(s.NeedsParent),
		"parent_resolve_error": stringObj(s.ParentResolveError),
		"links":                &object.Array{Elements: links},
		"link_count":           intObj(int64(len(s.Links))),
		"paths":                stringArray(paths),
		"scope":                stringObj(s.Scope),
		"status":               stringObj("ok"),
	}
	s.into(fields)
	return makeHashObject(fields)
}

// vhdiImageInfo is what a header-only probe can say about one image. It backs
// both vhdi_probe and each node of vhdi_discover, so a script reads one shape
// whichever way it arrived at the file.
type vhdiImageInfo struct {
	Path     string
	Readable bool
	Error    string

	Format   string
	DiskType string
	Role     string

	Identifier       string
	LinkIdentity     string
	ParentIdentifier string
	ParentFilename   string
	ParentLocators   []string

	VirtualSize int64
	FileSize    int64

	HasLog          bool
	FooterSource    string
	FooterRecovered bool

	IsDifferencing         bool
	HasCheckpointExtension bool
}

func (i vhdiImageInfo) into(fields map[string]object.Object) {
	fields["path"] = stringObj(i.Path)
	fields["readable"] = boolObj(i.Readable)
	fields["error"] = stringObj(i.Error)
	fields["format"] = stringObj(i.Format)
	fields["disk_type"] = stringObj(i.DiskType)
	fields["role"] = stringObj(i.Role)
	fields["identifier"] = stringObj(i.Identifier)
	fields["link_identity"] = stringObj(i.LinkIdentity)
	fields["parent_identifier"] = stringObj(i.ParentIdentifier)
	fields["parent_filename"] = stringObj(i.ParentFilename)
	fields["parent_locators"] = stringArray(i.ParentLocators)
	fields["virtual_size"] = intObj(i.VirtualSize)
	fields["file_size"] = intObj(i.FileSize)
	fields["has_log"] = boolObj(i.HasLog)
	fields["footer_source"] = stringObj(i.FooterSource)
	fields["footer_recovered"] = boolObj(i.FooterRecovered)
	fields["is_differencing"] = boolObj(i.IsDifferencing)
	fields["has_checkpoint_extension"] = boolObj(i.HasCheckpointExtension)
}

// vhdiProbeScan is what vhdi_probe reports.
type vhdiProbeScan struct {
	vhdiFindings
	Info  vhdiImageInfo
	Scope string
}

func (s vhdiProbeScan) toHash() *object.Hash {
	fields := map[string]object.Object{
		"scope":  stringObj(s.Scope),
		"status": stringObj("ok"),
	}
	s.Info.into(fields)
	s.into(fields)
	return makeHashObject(fields)
}

// vhdiTreeNode is one image in a discovered tree, placed relative to the rest.
type vhdiTreeNode struct {
	Index      int64
	Info       vhdiImageInfo
	Depth      int64
	IsRoot     bool
	IsLeaf     bool
	ParentPath string
	ChildPaths []string
}

func (n vhdiTreeNode) toHash() *object.Hash {
	fields := map[string]object.Object{
		"index":       intObj(n.Index),
		"depth":       intObj(n.Depth),
		"is_root":     boolObj(n.IsRoot),
		"is_leaf":     boolObj(n.IsLeaf),
		"parent_path": stringObj(n.ParentPath),
		"child_paths": stringArray(n.ChildPaths),
		"child_count": intObj(int64(len(n.ChildPaths))),
	}
	n.Info.into(fields)
	return makeHashObject(fields)
}

// vhdiLineage is one path through a discovered tree: the set of files that
// together constitute one device, root first.
type vhdiLineage struct {
	Index           int64
	Paths           []string
	RootPath        string
	LeafPath        string
	Depth           int64
	Complete        bool
	CheckpointCount int64
}

func (l vhdiLineage) toHash() *object.Hash {
	return makeHashObject(map[string]object.Object{
		"index":            intObj(l.Index),
		"paths":            stringArray(l.Paths),
		"root_path":        stringObj(l.RootPath),
		"leaf_path":        stringObj(l.LeafPath),
		"depth":            intObj(l.Depth),
		"complete":         boolObj(l.Complete),
		"checkpoint_count": intObj(l.CheckpointCount),
	})
}

// vhdiDiscoverScan is what vhdi_discover reports.
type vhdiDiscoverScan struct {
	vhdiFindings
	Dir            string
	Nodes          []vhdiTreeNode
	NodeCount      int64
	NodesTruncated bool
	RootPaths      []string
	LeafPaths      []string
	Branched       bool
	Lineages       []vhdiLineage
	LineageCount   int64
	UnreadablePath []string
	SkippedPaths   []string
	Scope          string
}

func (s vhdiDiscoverScan) toHash() *object.Hash {
	nodes := make([]object.Object, 0, len(s.Nodes))
	for _, node := range s.Nodes {
		nodes = append(nodes, node.toHash())
	}
	lineages := make([]object.Object, 0, len(s.Lineages))
	for _, lineage := range s.Lineages {
		lineages = append(lineages, lineage.toHash())
	}

	fields := map[string]object.Object{
		"dir":              stringObj(s.Dir),
		"nodes":            &object.Array{Elements: nodes},
		"node_count":       intObj(s.NodeCount),
		"nodes_truncated":  boolObj(s.NodesTruncated),
		"root_paths":       stringArray(s.RootPaths),
		"leaf_paths":       stringArray(s.LeafPaths),
		"branched":         boolObj(s.Branched),
		"lineages":         &object.Array{Elements: lineages},
		"lineage_count":    intObj(s.LineageCount),
		"unreadable":       stringArray(s.UnreadablePath),
		"unreadable_count": intObj(int64(len(s.UnreadablePath))),
		"skipped":          stringArray(s.SkippedPaths),
		"skipped_count":    intObj(int64(len(s.SkippedPaths))),
		"scope":            stringObj(s.Scope),
		"status":           stringObj("ok"),
	}
	s.into(fields)
	return makeHashObject(fields)
}

func vhdiExtentKindName(kind libvhdi.ExtentKind) string {
	switch kind {
	case libvhdi.ExtentZero:
		return vhdiExtentZero
	case libvhdi.ExtentMapped:
		return vhdiExtentMapped
	case libvhdi.ExtentUnresolved:
		return vhdiExtentUnresolved
	case libvhdi.ExtentZeroedByChild:
		return vhdiExtentZeroedByChild
	default:
		return vhdiExtentUnknown
	}
}

// vhdiFormatName keeps this family's existing spelling of the two formats.
// libvhdi renders the third case as "unknown" and vhdi_metadata has always
// rendered it "UNKNOWN"; one builtin disagreeing with its neighbour about the
// spelling of the same fact is worse than either spelling.
func vhdiFormatName(rendered string) string {
	switch rendered {
	case "VHD":
		return "VHD"
	case "VHDX":
		return "VHDX"
	default:
		return "UNKNOWN"
	}
}

func vhdiFooterSourceName(source libvhdi.FooterSource) string {
	switch source {
	case libvhdi.FooterSourceTrailing:
		return "trailing"
	case libvhdi.FooterSourceTrailingLegacy:
		return "trailing_legacy_511"
	case libvhdi.FooterSourceMirror:
		return "mirror_at_zero"
	default:
		return "unknown"
	}
}

// vhdiGUID renders a GUID, and renders the zero GUID as nothing at all.
//
// An image that recorded no identifier and an image whose identifier is all
// zeroes are the same file, and printing "00000000-0000-0000-0000-000000000000"
// invites a reader to match it against another image that recorded nothing
// either. libvhdi's own Provenance leaves the field empty for the same reason.
func vhdiGUID(guid [16]byte) string {
	if guid == ([16]byte{}) {
		return ""
	}
	return libvhdi.GUIDString(guid)
}

// vhdiNormalisePath renders a path for comparison the way libvhdi does when it
// matches a path against a chain: absolute, cleaned, and lowered on Windows.
//
// It is reproduced rather than imported because libvhdi keeps it unexported.
// Nothing here depends on the two agreeing: the resolved index is reported as a
// field, and a disagreement shows up as `chain_index_not_resolved` beside an
// answer libvhdi itself produced, rather than as a wrong number.
func vhdiNormalisePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// vhdiFirstVHDLink returns the index of the first link among the first
// `reporting` that is a VHD, or -1 when none of them is.
//
// It decides whether a change answer can speak about deletions at all. A VHD's
// per-block sector bitmap says only whether a sector belongs to the child or is
// to be read from the parent, and there is no third state meaning zero, so a
// region the guest cleared is recorded as the parent's and reads back as the
// parent's old contents. Across such a link a deletion is absent from the
// format rather than merely absent from the answer, which is a different and
// much worse thing for a reader to assume they are being told.
//
// Only the links being reported on matter. A VHD base under a VHDX checkpoint
// does not stop the checkpoint from recording its own clears.
func vhdiFirstVHDLink(chain []libvhdi.ChainEntry, reporting int64) int64 {
	for i := int64(0); i < reporting && i < int64(len(chain)); i++ {
		if chain[i].Format == libvhdi.FormatVHD {
			return i
		}
	}
	return -1
}

// vhdiChainIndexOf finds the link a path names, or -1.
func vhdiChainIndexOf(chain []libvhdi.ChainEntry, path string) int64 {
	want := vhdiNormalisePath(path)
	for _, entry := range chain {
		if entry.Path == "" {
			continue
		}
		if vhdiNormalisePath(entry.Path) == want {
			return int64(entry.Index)
		}
	}
	return -1
}

// vhdiImageInfoFrom renders one header-only probe.
func vhdiImageInfoFrom(info libvhdi.DiskInfo, path string, probeErr error) vhdiImageInfo {
	out := vhdiImageInfo{Path: path, Readable: probeErr == nil}
	if probeErr != nil {
		out.Error = probeErr.Error()
		out.Format = "UNKNOWN"
		out.DiskType = "unknown"
		out.Role = "unknown"
		out.FooterSource = "unknown"
		return out
	}

	out.Path = info.Path
	if out.Path == "" {
		out.Path = path
	}
	out.Format = vhdiFormatName(info.Format.String())
	out.DiskType = info.DiskType.String()
	out.Role = info.Role().String()
	out.Identifier = vhdiGUID(info.Identifier)
	out.LinkIdentity = vhdiGUID(info.LinkIdentity)
	out.ParentIdentifier = vhdiGUID(info.ParentIdentifier)
	out.ParentFilename = info.ParentFilename
	// The candidate parent paths an image records matter exactly when the
	// parent is missing: they are the only record of where the image expected
	// to find it. They are read in place because the entry type lives in
	// libvhdi/types, which the facade does not re-export, and reading a field
	// needs no import while naming the type would.
	locators := make([]string, 0, len(info.ParentLocators))
	seenLocator := map[string]bool{}
	for _, entry := range info.ParentLocators {
		value := strings.TrimSpace(entry.Value)
		if value == "" || seenLocator[value] {
			continue
		}
		seenLocator[value] = true
		locators = append(locators, value)
	}
	out.ParentLocators = locators
	out.VirtualSize = int64(info.VirtualSize)
	out.FileSize = info.FileSize
	out.HasLog = info.HasLog
	out.FooterSource = vhdiFooterSourceName(info.FooterSource)
	out.FooterRecovered = info.FooterSource.Recovered()
	out.IsDifferencing = info.IsDifferencing()
	out.HasCheckpointExtension = info.HasCheckpointExtension()
	return out
}

// vhdiImageFindings raises what one probed image says about itself, for both
// vhdi_probe and vhdi_discover.
func vhdiImageFindings(f *vhdiFindings, info vhdiImageInfo) {
	if !info.Readable {
		f.warn(vhdiWarnImageUnreadable, info.Path, info.Error)
		return
	}
	if info.FooterRecovered {
		f.warn(vhdiWarnFooterRecovered, info.Path,
			"the conformant trailing footer could not be read and the image was opened from a fallback copy ("+
				info.FooterSource+"), so the file is damaged even though it parsed")
	}
	if info.HasLog {
		f.warn(vhdiWarnUnreplayedLogOnDisk, info.Path,
			"the image carries a VHDX log; a header-only probe does not replay it, so the structures read here may be stale")
	}
	if info.HasCheckpointExtension != info.IsDifferencing {
		f.warn(vhdiWarnExtensionMismatch, info.Path,
			"the file's extension and its disk type disagree about whether this is a checkpoint; the disk type decides, and the disagreement means the file was renamed or converted")
	}
	if info.LinkIdentity == "" {
		f.warn(vhdiWarnZeroLinkIdentity, info.Path,
			"the image records no link identity, so no differencing child can be matched to it by identity and it can never be joined to one as a parent")
	}
}

// ---------------------------------------------------------------------------
// What the chain behind an answer says about the answer
// ---------------------------------------------------------------------------

// vhdiWalk visits the disk and each of its attached parents in chain order, so
// index i here is the same link as index i in Chain() and in Extent.ChainIndex.
func vhdiWalk(disk *libvhdi.Disk, visit func(index int, link *libvhdi.Disk)) {
	for link, i := disk, 0; link != nil; link, i = link.Parent(), i+1 {
		visit(i, link)
	}
}

// vhdiChainFindings raises what the chain behind this disk says about anything
// derived from it.
//
// It runs for every handle-addressed builtin in this family rather than only
// for vhdi_chain. A differencing disk is only as trustworthy as the chain
// behind it: an extent map of a device reconstructed through a parent whose
// identity could not be verified is a map of a device that may not be the one
// the examiner believes they are holding, and a script that called only
// vhdi_extents would otherwise never learn that.
func vhdiChainFindings(f *vhdiFindings, disk *libvhdi.Disk) {
	// libvhdi's own caveats first. Each carries the path of the image it
	// concerns, so attribution survives being flattened into one list.
	f.chainWarnings(disk.Warnings())

	if !disk.ChainComplete() {
		detail := "a differencing disk in this chain has no parent attached, so ranges resolving to it cannot be described at all"
		if err := disk.ParentResolveError(); err != nil {
			detail += ": " + err.Error()
		}
		f.warn(vhdiWarnChainIncomplete, disk.Path(), detail)
	}

	vhdiWalk(disk, func(_ int, link *libvhdi.Disk) {
		path := link.Path()
		provenance := link.Provenance()

		if link.IsDirty() {
			f.warn(vhdiWarnImageDirty, path,
				"this image carries a log that could not be replayed, so its block allocation table and metadata may be stale and what is decoded here may not be the last committed state")
		}
		if provenance.LeaveBlocksAllocated {
			f.warn(vhdiWarnBlocksNeverFreed, path,
				"this image never returns a written block to the free pool, so a block stays mapped after the guest deleted what was in it; the mapped total therefore overstates what is in use")
		}
		if provenance.SavedState {
			f.warn(vhdiWarnSavedState, path,
				"this image was saved from a running machine, so its filesystem is a crash-consistent snapshot rather than a cleanly unmounted one, which changes what its contents can be taken to mean")
		}
		if provenance.OriginalSize != 0 && provenance.OriginalSize != link.Size() {
			f.warn(vhdiWarnImageExpanded, path, fmt.Sprintf(
				"this image was created at %d bytes and now presents %d; the recorded original size is the only record that the expansion happened",
				provenance.OriginalSize, link.Size()))
		}
	})
}

// vhdiListFindings raises what an extent list could not account for.
//
// An unresolved range is reported before a truncated list because it is the
// deeper gap: the truncation is a limit on what was rendered, while an
// unresolved range is evidence that is not present to render.
func vhdiListFindings(f *vhdiFindings, list vhdiExtentList, location string) {
	if list.UnresolvedBytes > 0 {
		f.warn(vhdiWarnUnresolvedRange, location, fmt.Sprintf(
			"%d byte(s) of this answer resolve to a parent that is not attached; they are neither mapped nor zero, because the disk that would say is missing",
			list.UnresolvedBytes))
		f.incomplete("part of the range resolves to a parent that is not attached")
	}
	if list.Truncated {
		f.warn(vhdiWarnExtentsTruncated, location, fmt.Sprintf(
			"%d extents were found and the first %d are listed; the byte totals beside the list are computed over all of them",
			list.Count, vhdiMaxExtents))
		f.incomplete(fmt.Sprintf("the extent list stops at %d of %d extents", vhdiMaxExtents, list.Count))
	}
}

// ---------------------------------------------------------------------------
// The real session
// ---------------------------------------------------------------------------

func (s *realVHDISession) Extents(offset, length int64) (vhdiExtentScan, error) {
	virtualSize := int64(s.disk.Size())

	scan := vhdiExtentScan{
		Path:          s.disk.Path(),
		VirtualOffset: offset,
		Length:        length,
		VirtualSize:   virtualSize,
		ChainComplete: s.disk.ChainComplete(),
		Scope:         vhdiScopeExtents,
	}
	scan.Complete = true

	var (
		raw []libvhdi.Extent
		err error
	)
	ctx := context.Background()
	switch {
	case length == 0 || offset >= virtualSize:
		raw = nil
	case offset == 0 && length >= virtualSize:
		// The whole device. AllExtentsContext walks it in bounded chunks and
		// checks for cancellation between them, where Extents resolves the
		// whole span in one pass; the results are identical and the peak
		// intermediate allocation is not.
		raw, err = s.disk.AllExtentsContext(ctx)
	default:
		raw, err = s.disk.ExtentsContext(ctx, offset, length)
	}
	if err != nil {
		return vhdiExtentScan{}, err
	}

	for _, extent := range raw {
		scan.List.add(extent)
	}

	// The comparison is written this way round because offset+length overflows
	// for a length a script is free to pass.
	if offset >= virtualSize || length > virtualSize-offset {
		scan.warn(vhdiWarnWindowClamped, scan.Path, fmt.Sprintf(
			"the window [%d, %d) was asked for and the device is %d bytes, so the map covers only what exists",
			offset, offset+length, virtualSize))
	}

	vhdiChainFindings(&scan.vhdiFindings, s.disk)
	vhdiListFindings(&scan.vhdiFindings, scan.List, scan.Path)
	return scan, nil
}

func (s *realVHDISession) Chain() (vhdiChainScan, error) {
	scan := vhdiChainScan{
		Path:        s.disk.Path(),
		Depth:       int64(s.disk.ChainDepth()),
		NeedsParent: s.disk.NeedsParent(),
		Scope:       vhdiScopeChain,
	}
	scan.Complete = true
	if err := s.disk.ParentResolveError(); err != nil {
		scan.ParentResolveError = err.Error()
	}

	// Chain() is the record and the Parent() walk is how provenance is reached,
	// so the two are collected together and indexed the same way. libvhdi walks
	// the same pointers for both, which is what lets index i mean one image.
	disks := make([]*libvhdi.Disk, 0, scan.Depth)
	vhdiWalk(s.disk, func(_ int, link *libvhdi.Disk) { disks = append(disks, link) })

	for i, entry := range s.disk.Chain() {
		link := vhdiChainLink{
			Index:            int64(entry.Index),
			Path:             entry.Path,
			Identifier:       vhdiGUID(entry.Identifier),
			ParentIdentifier: vhdiGUID(entry.ParentIdentifier),
			ParentFilename:   entry.ParentFilename,
			Format:           vhdiFormatName(entry.Format.String()),
			DiskType:         entry.DiskType.String(),
			VirtualSize:      int64(entry.VirtualSize),
			IsDifferencing:   entry.IsDifferencing,
			HasLog:           entry.HasLog,
			LogReplayed:      entry.LogReplayed,
		}

		if i < len(disks) {
			disk := disks[i]
			provenance := disk.Provenance()
			link.FileSize = provenance.FileSize
			link.CreatorApplication = provenance.CreatorApplication
			link.CreatorVersion = provenance.CreatorVersionString()
			link.CreatorOS = provenance.CreatorOS
			link.Created = formatTime(provenance.Created)
			link.DataWriteIdentifier = provenance.DataWriteIdentifier
			link.OriginalSize = int64(provenance.OriginalSize)
			link.SavedState = provenance.SavedState
			link.LeaveBlocksAllocated = provenance.LeaveBlocksAllocated
			link.FooterSource = vhdiFooterSourceName(provenance.FooterSource)
			link.FooterRecovered = provenance.FooterSource.Recovered()

			if stats, replayed := disk.LogReplayStats(); replayed {
				link.LogReplayEntries = int64(stats.Entries)
				link.LogReplayDescriptors = int64(stats.Descriptors)
				link.LogReplaySectors = int64(stats.Sectors)
			}
		}

		scan.Links = append(scan.Links, link)
	}

	vhdiChainFindings(&scan.vhdiFindings, s.disk)
	if !s.disk.ChainComplete() {
		scan.incomplete("a link this device needs was never attached, so the files named here are not all of it")
	}
	return scan, nil
}

func (s *realVHDISession) Changed(since int64) (vhdiChangedScan, error) {
	chain := s.disk.Chain()
	depth := int64(len(chain))

	// since names the disk being asked about, and the answer is what the disks
	// in front of it wrote. Index 0 is the disk that was opened, so there is
	// nothing in front of it; the last index has nothing behind it to be a
	// baseline for, but it is still a disk that can be asked about.
	if depth < 2 {
		return vhdiChangedScan{}, fmt.Errorf(
			"this disk has no parent chain, so there is no earlier disk for a change to be measured against")
	}
	if since < 1 || since > depth-1 {
		return vhdiChangedScan{}, fmt.Errorf(
			"since_chain_index %d names no earlier disk: this chain has %d attached links numbered 0 to %d, and 0 is the disk that was opened",
			since, depth, depth-1)
	}

	extents, err := s.disk.ChangedExtents(context.Background(), int(since))
	if err != nil {
		return vhdiChangedScan{}, err
	}
	return s.assembleChanged(chain, since, extents, vhdiScopeChanged), nil
}

func (s *realVHDISession) ChangedSince(path string) (vhdiChangedScan, error) {
	chain := s.disk.Chain()

	// libvhdi resolves the path itself, against a normalisation it keeps
	// unexported, and that answer is the authoritative one. The index is
	// resolved again here only so the report can name it, and a disagreement
	// between the two shows up as a warning beside an answer libvhdi produced
	// rather than as a number nothing checked.
	extents, err := s.disk.ChangedSince(context.Background(), path)
	if err != nil {
		return vhdiChangedScan{}, err
	}

	index := vhdiChainIndexOf(chain, path)
	scan := s.assembleChanged(chain, index, extents, vhdiScopeChangedSince)

	switch {
	case index < 0:
		scan.warn(vhdiWarnIndexUnresolved, path,
			"libvhdi found this path in the chain and this builtin did not, so since_chain_index is -1; the extents below are libvhdi's answer and are unaffected")
	case index == 0:
		scan.warn(vhdiWarnNamedDiskIsLeaf, path,
			"this is the disk that was opened, so nothing can have been written since it and the empty answer is the definition rather than a finding")
	}
	return scan, nil
}

// assembleChanged builds the envelope both change builtins return.
//
// since may be -1, meaning the disk was named in a way this builtin could not
// place; the format check below then runs over the whole chain, which is the
// conservative direction.
func (s *realVHDISession) assembleChanged(chain []libvhdi.ChainEntry, since int64, extents []libvhdi.Extent, scope string) vhdiChangedScan {
	depth := int64(len(chain))

	scan := vhdiChangedScan{
		Path:                 s.disk.Path(),
		SinceChainIndex:      since,
		ChainDepth:           depth,
		ChainComplete:        s.disk.ChainComplete(),
		DeletionsExpressible: true,
		Scope:                scope,
	}
	scan.Complete = true
	if since >= 0 && since < depth {
		scan.SincePath = chain[since].Path
	}

	// The links whose writes this answer is about are those in front of since.
	reporting := since
	if since < 0 {
		reporting = depth
	}
	if at := vhdiFirstVHDLink(chain, reporting); at >= 0 {
		scan.DeletionsExpressible = false
		scan.warn(vhdiWarnDeletionsNotStored, chain[at].Path,
			"this is a VHD link, and VHD has no block state meaning zero: a region the guest cleared is recorded as belonging to the parent and reads back as the parent's old contents, so deletions across this link are invisible here because the format never stored them")
	}

	for _, extent := range extents {
		scan.List.add(extent)
	}

	vhdiChainFindings(&scan.vhdiFindings, s.disk)
	vhdiListFindings(&scan.vhdiFindings, scan.List, scan.Path)
	return scan
}

// ---------------------------------------------------------------------------
// The real backend: header-only reads that need no handle
// ---------------------------------------------------------------------------

func (realVHDIBackend) Probe(imagePath string) (vhdiProbeScan, error) {
	info, err := libvhdi.ProbeFile(imagePath)
	if err != nil {
		return vhdiProbeScan{}, err
	}

	scan := vhdiProbeScan{Info: vhdiImageInfoFrom(info, imagePath, nil), Scope: vhdiScopeProbe}
	scan.Complete = true
	vhdiImageFindings(&scan.vhdiFindings, scan.Info)
	return scan, nil
}

func (realVHDIBackend) Discover(dir string) (vhdiDiscoverScan, error) {
	tree, err := libvhdi.DiscoverChain(context.Background(), dir, nil)
	if err != nil {
		return vhdiDiscoverScan{}, err
	}

	scan := vhdiDiscoverScan{
		Dir:          dir,
		Branched:     tree.Branched(),
		SkippedPaths: append([]string(nil), tree.Skipped...),
		Scope:        vhdiScopeDiscover,
	}
	scan.Complete = true

	// libvhdi joins a child to a parent by recorded identity and keeps the
	// first image claiming a given one. Two images claiming the same identity
	// is a copy, and the tree below then attaches that identity's children to
	// whichever of them sorted first -- a plausible tree that may be the wrong
	// one. The library cannot say so from inside a single lookup, so the clash
	// is counted here.
	byIdentity := map[string][]string{}

	for i, node := range tree.Nodes {
		info := vhdiImageInfoFrom(node.Info, node.Path, node.Err)
		scan.NodeCount++
		vhdiImageFindings(&scan.vhdiFindings, info)

		if info.Readable && info.LinkIdentity != "" {
			byIdentity[info.LinkIdentity] = append(byIdentity[info.LinkIdentity], info.Path)
		}
		if info.Readable && info.IsDifferencing && node.Parent == nil {
			scan.warn(vhdiWarnOrphanedChild, info.Path,
				"this image differences against a parent that is not in the scanned directory, so it is a root that cannot be read to completion; parent_locators lists where it expected to find one")
		}
		if node.Err != nil {
			scan.UnreadablePath = append(scan.UnreadablePath, node.Path)
		}

		if len(scan.Nodes) >= vhdiMaxNodes {
			scan.NodesTruncated = true
			continue
		}

		rendered := vhdiTreeNode{
			Index:  int64(i),
			Info:   info,
			Depth:  int64(node.Depth()),
			IsRoot: node.Parent == nil,
			IsLeaf: node.IsLeaf(),
		}
		if node.Parent != nil {
			rendered.ParentPath = node.Parent.Path
		}
		for _, child := range node.Children {
			rendered.ChildPaths = append(rendered.ChildPaths, child.Path)
		}
		scan.Nodes = append(scan.Nodes, rendered)
	}

	for identity, paths := range byIdentity {
		if len(paths) < 2 {
			continue
		}
		scan.warn(vhdiWarnDuplicateLink, paths[0], fmt.Sprintf(
			"%d images record the link identity %s (%s); a differencing child naming it is joined to one of them and the tree below may therefore be the wrong one",
			len(paths), identity, strings.Join(paths, ", ")))
	}

	for _, root := range tree.Roots() {
		scan.RootPaths = append(scan.RootPaths, root.Path)
	}
	for _, leaf := range tree.Leaves() {
		scan.LeafPaths = append(scan.LeafPaths, leaf.Path)
	}
	if scan.Branched {
		scan.warn(vhdiWarnTreeBranched, dir,
			"this directory holds more than one leaf, so the checkpoint tree has branched; which branch a virtual machine is using is recorded in the machine's configuration and not in the disks, so it is not decided here")
	}

	for i, lineage := range tree.Lineages() {
		scan.LineageCount++
		if len(scan.Lineages) >= vhdiMaxLineages {
			continue
		}

		rendered := vhdiLineage{
			Index:           int64(i),
			Paths:           lineage.Paths(),
			Depth:           int64(len(lineage.Nodes)),
			Complete:        lineage.Complete(),
			CheckpointCount: int64(len(lineage.Checkpoints())),
		}
		if root := lineage.Root(); root != nil {
			rendered.RootPath = root.Path
		}
		if leaf := lineage.Leaf(); leaf != nil {
			rendered.LeafPath = leaf.Path
		}
		if !rendered.Complete {
			scan.warn(vhdiWarnLineageIncomplete, rendered.LeafPath,
				"this lineage starts at an image that itself needs a parent, so the files present cannot reconstruct the device and reads into the missing ranges fail rather than returning zeroes")
		}
		scan.Lineages = append(scan.Lineages, rendered)
	}

	if scan.NodesTruncated {
		scan.warn(vhdiWarnNodesTruncated, dir, fmt.Sprintf(
			"%d images were probed and the first %d are listed", scan.NodeCount, vhdiMaxNodes))
		scan.incomplete(fmt.Sprintf("the node list stops at %d of %d images", vhdiMaxNodes, scan.NodeCount))
	}
	if len(scan.UnreadablePath) > 0 {
		scan.incomplete(fmt.Sprintf("%d file(s) in this directory could not be probed", len(scan.UnreadablePath)))
	}
	return scan, nil
}

// ---------------------------------------------------------------------------
// The builtins
// ---------------------------------------------------------------------------

func VHDIExtents(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], BuiltinNameVhdiExtents)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offsetObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", BuiltinNameVhdiExtents, args[1].Type()))
	}
	lengthObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `%s` must be INTEGER, got %s", BuiltinNameVhdiExtents, args[2].Type()))
	}
	if offsetObj.Value < 0 {
		return resultAndError(nil, newError("%s: offset must be >= 0", BuiltinNameVhdiExtents))
	}
	if lengthObj.Value < 0 {
		return resultAndError(nil, newError("%s: length must be >= 0", BuiltinNameVhdiExtents))
	}

	scan, err := state.Session.Extents(offsetObj.Value, lengthObj.Value)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameVhdiExtents, err.Error()))
	}
	return resultAndError(scan.toHash(handleName(args[0])), nil)
}

func VHDIChain(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], BuiltinNameVhdiChain)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	scan, err := state.Session.Chain()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameVhdiChain, err.Error()))
	}
	return resultAndError(scan.toHash(handleName(args[0])), nil)
}

func VHDIChangedExtents(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], BuiltinNameVhdiChangedExtents)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	sinceObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", BuiltinNameVhdiChangedExtents, args[1].Type()))
	}

	scan, err := state.Session.Changed(sinceObj.Value)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameVhdiChangedExtents, err.Error()))
	}
	return resultAndError(scan.toHash(handleName(args[0])), nil)
}

func VHDIChangedSince(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveVHDIHandle(args[0], BuiltinNameVhdiChangedSince)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be STRING, got %s", BuiltinNameVhdiChangedSince, args[1].Type()))
	}
	if strings.TrimSpace(pathObj.Value) == "" {
		return resultAndError(nil, newError("%s: the path must name a disk in the chain; vhdi_chain lists them", BuiltinNameVhdiChangedSince))
	}

	scan, err := state.Session.ChangedSince(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameVhdiChangedSince, err.Error()))
	}
	return resultAndError(scan.toHash(handleName(args[0])), nil)
}

func VHDIProbe(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be STRING, got %s", BuiltinNameVhdiProbe, args[0].Type()))
	}

	vhdiStore.RLock()
	backend := vhdiStore.backend
	vhdiStore.RUnlock()

	scan, err := backend.Probe(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameVhdiProbe, err.Error()))
	}

	// Reading an image's headers is reading the evidence, so the case records
	// it -- with a handle that names what read it and is never issued to the
	// script, which is how table_detect records a read that hands back no
	// handle either.
	probeID := atomic.AddInt64(&vhdiStore.nextID, 1)
	custodyRecordOpen(BuiltinNameVhdiProbe, fmt.Sprintf("vhdi-probe-%d", probeID), pathObj.Value)

	return resultAndError(scan.toHash(), nil)
}

func VHDIDiscover(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	dirObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be STRING, got %s", BuiltinNameVhdiDiscover, args[0].Type()))
	}

	vhdiStore.RLock()
	backend := vhdiStore.backend
	vhdiStore.RUnlock()

	scan, err := backend.Discover(dirObj.Value)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameVhdiDiscover, err.Error()))
	}

	// Nothing is registered as evidence here. See the note at the top of this
	// file: a directory is not a file an examination named.
	return resultAndError(scan.toHash(), nil)
}
