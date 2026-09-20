package builtin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	libhfs "github.com/aoiflux/libhfs"
	libntfs "github.com/aoiflux/libntfs"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

// A file's bytes are not all of a file.
//
// Every filesystem here lets a file carry content and metadata that its path
// does not name and that a directory listing does not show. NTFS calls the
// content an alternate data stream; HFS+ calls it a resource fork; ext, XFS and
// HFS+ all carry labelled values called extended attributes; NTFS carries a
// security descriptor and a reparse point. What they share is the addressing:
// the content is reached by a *pair* -- the path and a name -- and a tool that
// walks a volume by path alone sees none of it. That is exactly why things are
// put there.
//
// This family keeps two questions apart, because merging them produces a report
// that reads as though a file were twice its size.
//
//   - A named body of bytes: an alternate data stream, a resource fork, a
//     fork-backed extended attribute. It has a length, a location on the image,
//     and can be read out and hashed like any other file content.
//   - A label: security.selinux, com.apple.quarantine, a security descriptor, a
//     reparse tag. It holds no file content. It holds an assertion *about* the
//     file, which is a different kind of evidence and is frequently the more
//     useful one -- the Zone.Identifier stream on a downloaded executable names
//     the URL it came from, and no amount of reading the executable will.
//
// The third thing this file refuses to do is decide anything.
//
// An access control list is not an access decision. libntfs says so in its own
// doc comment and it is worth repeating here, because getting it wrong inverts
// the answer: a security descriptor with no DACL at all grants *everyone* full
// access, and a descriptor carrying a DACL with no entries in it denies
// everyone. Rendered as an empty array those two are the same value. So
// dacl_present is a field of its own, separate from the entry count and from
// the array, and there is no builtin here that answers "could this account read
// this file" -- that computation needs group memberships, privilege
// assignments and an inheritance walk that a disk image does not contain.
//
// What each library actually offers, which is not what the names suggest:
//
//   - libntfs is the complete one. Streams, OpenStream, SecurityDescriptor,
//     EachSecurityDescriptor over the whole $Secure:$SDS, ReparsePoint with the
//     symlink, junction and WSL layouts decoded, and SID/ACE renderers that
//     name unknown bits in hex rather than dropping them.
//   - libext has GetXAttrs, and GetXAttrs alone is a trap: it follows the
//     inode's external attribute block and nothing else, and on an inode with
//     no such block it returns an empty list with a nil error. The library's
//     own comment on the other entry point says where that leaves you --
//     "security.selinux and system.posix_acl_access live [inline] on a typical
//     modern system: they are small enough never to need an external block, so
//     a reader that only follows the external block reports no attributes at
//     all." Both are read here and the storage of each is recorded.
//   - libxfs decodes short-form and block attributes, and documents that it
//     performs no deduplication: two records with the same fully-qualified name
//     both come back. That is an anomaly, not a rendering detail, so it is
//     counted and warned on rather than quietly collapsed.
//   - libhfs has the richest attribute layer -- inline and fork-backed storage,
//     per-attribute extents, a volume-wide walk -- and returns the system
//     attributes com.apple.decmpfs and com.apple.ResourceFork like any other,
//     calling the decision to filter them "a policy decision that belongs to
//     the caller". They are kept and flagged, because the presence of decmpfs
//     is the reason hfs_slack reported that file's data fork empty.
//
// Values are rendered as hex, capped, with the length always reported in full,
// and a value that is printable text is offered as text beside the hex rather
// than instead of it. A value too long to render carries its location instead,
// so the bytes stay reachable through raw_read_at_bytes. An attribute value is
// not a string simply because this one happens to be.

// Where an attribute's value is kept. The distinction is not cosmetic: an
// inline value lives in the metadata record and travels with it, a block or
// fork value lives in allocation blocks and can outlive the record pointing at
// it.
const (
	fsAttrStorageInline = "inline"
	fsAttrStorageBlock  = "block"
	fsAttrStorageFork   = "fork"
)

const (
	fsAttrNodeInode = "inode"
	fsAttrNodeCNID  = "cnid"
)

const (
	fsAttrWarnUnsupported       = "extended_attributes_unsupported"
	fsAttrWarnDuplicateName     = "duplicate_attribute_name"
	fsAttrWarnCompressedPayload = "compressed_payload_attribute"
	fsAttrWarnResourceForkAttr  = "resource_fork_attribute"
	fsAttrWarnValueUnrendered   = "value_longer_than_render_cap"
	fsAttrWarnValueUnlocated    = "value_not_located"
	fsAttrWarnDirectoryStream   = "directory_carries_stream"
	fsAttrWarnStreamUnreadable  = "stream_unreadable"
	fsAttrWarnNoDefaultStream   = "no_unnamed_stream"
	fsAttrWarnNoDACL            = "no_dacl_present"
	fsAttrWarnEmptyDACL         = "dacl_present_and_empty"
	fsAttrWarnSACLPresent       = "sacl_present"
	fsAttrWarnDescriptorShared  = "descriptor_shared_by_security_id"
	fsAttrWarnThirdPartyTag     = "third_party_reparse_tag"
	fsAttrWarnTargetUndecoded   = "reparse_target_not_decoded"
	fsAttrWarnForkIsPayload     = "resource_fork_holds_payload"
)

const (
	// fsAttrMaxValueBytes bounds how much of one value is rendered as hex. A
	// value past it reports its true length and its location, so nothing is
	// lost -- only moved to a builtin that streams.
	fsAttrMaxValueBytes = 4096

	fsAttrMaxAttributes  = 4096
	fsAttrMaxStreams     = 1024
	fsAttrMaxACEs        = 4096
	fsAttrMaxDescriptors = 20000
	fsAttrMaxRanges      = 4096

	// fsAttrMaxReparseHex bounds the tag-specific data of a reparse point,
	// which Windows itself caps at 16 KiB.
	fsAttrMaxReparseHex = 16 << 10
)

// Warnings here share the shape the deleted, journal and slack families use, so
// a report does not have to know which family produced one.
type fsAttrWarning = fsDeletedWarning

// ------------------------------------------------------------ shared rendering

// attrValueHex renders a value up to the cap, reporting whether it was cut.
func attrValueHex(value []byte) (string, bool) {
	if len(value) > fsAttrMaxValueBytes {
		return hex.EncodeToString(value[:fsAttrMaxValueBytes]), true
	}
	return hex.EncodeToString(value), false
}

// attrValueText offers a value as text when it is one.
//
// A single trailing NUL is dropped first: security.selinux and most of the
// label attributes store a C string, and refusing to call the most common
// extended attribute on Linux text because of its terminator would make the
// field useless exactly where it is wanted. Anything else unprintable -- any
// control character, any invalid UTF-8 -- means the value is not text and the
// hex is the only honest rendering.
func attrValueText(value []byte) (string, bool) {
	trimmed := value
	if n := len(trimmed); n > 0 && trimmed[n-1] == 0x00 {
		trimmed = trimmed[:n-1]
	}
	if !utf8.Valid(trimmed) {
		return "", false
	}
	for _, r := range string(trimmed) {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return string(trimmed), true
}

// attrNamespaceOf splits a fully-qualified attribute name at its first dot.
// ext reports names already qualified and carries the namespace nowhere else.
func attrNamespaceOf(name string) string {
	if idx := strings.Index(name, "."); idx > 0 {
		return name[:idx]
	}
	return ""
}

// ------------------------------------------------------------ extended attributes

type fsXattrEntry struct {
	Name      string
	Namespace string
	Storage   string
	Size      int64
	Value     []byte
	Offset    int64 // -1 when the value has no place on the image
}

type fsXattrScan struct {
	Filesystem string
	Path       string
	Name       string
	NodeID     int64
	NodeIDKind string

	// Supported is about the volume, not the file: a filesystem without the
	// extended-attribute feature can never carry one, and reporting that as a
	// file with none is a different claim.
	Supported       bool
	StoragesChecked []string

	Attributes      []fsXattrEntry
	AttributeCount  int64
	TotalValueBytes int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsAttrWarning
	Scope             string
}

func newXattrScan(filesystem, filePath, nodeKind string) fsXattrScan {
	return fsXattrScan{
		Filesystem:        filesystem,
		Path:              filePath,
		Name:              pathBase(filePath),
		NodeID:            -1,
		NodeIDKind:        nodeKind,
		Complete:          true,
		WarningsAvailable: true,
	}
}

// add records one attribute, counting it past the cap so that the total stays
// true even when the list is truncated.
func (s *fsXattrScan) add(entry fsXattrEntry) bool {
	s.AttributeCount++
	s.TotalValueBytes += entry.Size
	if len(s.Attributes) >= fsAttrMaxAttributes {
		return false
	}
	s.Attributes = append(s.Attributes, entry)
	return true
}

func (s *fsXattrScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsAttrWarning{Code: code, Location: location, Detail: detail})
}

func (s *fsXattrScan) incomplete(reason string) {
	s.Complete = false
	if s.IncompleteReason == "" {
		s.IncompleteReason = reason
	}
}

// flagWellKnown names the attributes whose presence changes how the rest of the
// file should be read.
func (s *fsXattrScan) flagWellKnown(name string) {
	switch name {
	case "com.apple.decmpfs":
		s.warn(fsAttrWarnCompressedPayload, name,
			"this file is decmpfs-compressed: its data fork is empty on disk and its payload is "+
				"held either in this attribute or in the resource fork, which is why a slack or "+
				"size reading of the data fork reports nothing")
	case "com.apple.ResourceFork":
		s.warn(fsAttrWarnResourceForkAttr, name,
			"the resource fork is exposed here as an attribute as well as through "+
				"hfs_resource_fork; on a compressed file it holds the payload")
	}
}

func (s fsXattrScan) toHash(handle string) *object.Hash {
	attributes := make([]object.Object, 0, len(s.Attributes))
	for _, a := range s.Attributes {
		valueHex, truncated := attrValueHex(a.Value)
		text, isText := attrValueText(a.Value)
		attributes = append(attributes, makeHashObject(map[string]object.Object{
			"name":            stringObj(a.Name),
			"namespace":       stringObj(a.Namespace),
			"storage":         stringObj(a.Storage),
			"size":            intObj(a.Size),
			"offset":          intObj(a.Offset),
			"located":         boolObj(a.Offset >= 0),
			"value_hex":       stringObj(valueHex),
			"value_truncated": boolObj(truncated || int64(len(a.Value)) < a.Size),
			"value_text":      stringObj(text),
			"text_available":  boolObj(isText),
		}))
	}

	return makeHashObject(map[string]object.Object{
		"handle":               stringObj(handle),
		"filesystem":           stringObj(s.Filesystem),
		"path":                 stringObj(s.Path),
		"name":                 stringObj(s.Name),
		"node_id":              intObj(s.NodeID),
		"node_id_kind":         stringObj(s.NodeIDKind),
		"supported":            boolObj(s.Supported),
		"storages_checked":     stringArray(s.StoragesChecked),
		"attributes":           &object.Array{Elements: attributes},
		"attribute_count":      intObj(s.AttributeCount),
		"attributes_truncated": boolObj(s.AttributeCount > int64(len(s.Attributes))),
		"total_value_bytes":    intObj(s.TotalValueBytes),
		"complete":             boolObj(s.Complete),
		"incomplete_reason":    stringObj(s.IncompleteReason),
		"warnings_available":   boolObj(s.WarningsAvailable),
		"warnings":             warningArray(s.Warnings),
		"warning_codes":        warningCodeArray(s.Warnings),
		"scope":                stringObj(s.Scope),
		"status":               stringObj("ok"),
	})
}

// ------------------------------------------------------------ data streams

type fsStreamEntry struct {
	Name           string
	IsAlternate    bool
	Size           int64
	AllocatedBytes int64
	Resident       bool
	Readable       bool
	BlockingReason string
}

type fsStreamScan struct {
	Filesystem  string
	Path        string
	Name        string
	IsDirectory bool

	Streams        []fsStreamEntry
	StreamCount    int64
	AlternateCount int64
	AlternateBytes int64

	DefaultPresent bool
	DefaultSize    int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsAttrWarning
	Scope             string
}

func newStreamScan(filesystem, filePath string) fsStreamScan {
	return fsStreamScan{
		Filesystem:        filesystem,
		Path:              filePath,
		DefaultSize:       -1,
		Complete:          true,
		WarningsAvailable: true,
	}
}

func (s *fsStreamScan) add(entry fsStreamEntry) bool {
	s.StreamCount++
	if entry.IsAlternate {
		s.AlternateCount++
		s.AlternateBytes += entry.Size
	} else {
		s.DefaultPresent = true
		s.DefaultSize = entry.Size
	}
	if len(s.Streams) >= fsAttrMaxStreams {
		return false
	}
	s.Streams = append(s.Streams, entry)
	return true
}

func (s *fsStreamScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsAttrWarning{Code: code, Location: location, Detail: detail})
}

func (s fsStreamScan) toHash(handle string) *object.Hash {
	streams := make([]object.Object, 0, len(s.Streams))
	for _, entry := range s.Streams {
		streams = append(streams, makeHashObject(map[string]object.Object{
			"name":            stringObj(entry.Name),
			"is_alternate":    boolObj(entry.IsAlternate),
			"size":            intObj(entry.Size),
			"allocated_bytes": intObj(entry.AllocatedBytes),
			"resident":        boolObj(entry.Resident),
			"readable":        boolObj(entry.Readable),
			"blocking_reason": stringObj(entry.BlockingReason),
		}))
	}

	return makeHashObject(map[string]object.Object{
		"handle":             stringObj(handle),
		"filesystem":         stringObj(s.Filesystem),
		"path":               stringObj(s.Path),
		"name":               stringObj(s.Name),
		"is_directory":       boolObj(s.IsDirectory),
		"streams":            &object.Array{Elements: streams},
		"stream_count":       intObj(s.StreamCount),
		"streams_truncated":  boolObj(s.StreamCount > int64(len(s.Streams))),
		"alternate_count":    intObj(s.AlternateCount),
		"alternate_bytes":    intObj(s.AlternateBytes),
		"default_present":    boolObj(s.DefaultPresent),
		"default_size":       intObj(s.DefaultSize),
		"complete":           boolObj(s.Complete),
		"incomplete_reason":  stringObj(s.IncompleteReason),
		"warnings_available": boolObj(s.WarningsAvailable),
		"warnings":           warningArray(s.Warnings),
		"warning_codes":      warningCodeArray(s.Warnings),
		"scope":              stringObj(s.Scope),
		"status":             stringObj("ok"),
	})
}

// ------------------------------------------------------------ security descriptors

type fsACE struct {
	Type         int64
	TypeName     string
	Flags        int64
	Inherited    bool
	Mask         int64
	Rights       []string
	TrusteeSID   string
	TrusteeName  string
	TrusteeKnown bool
}

// fsACL carries presence separately from contents. Present is false when the
// descriptor had no such list at all, which is the opposite of a list that is
// there and empty; see the file comment.
type fsACL struct {
	Present  bool
	Revision int64
	Count    int64
	ACEs     []fsACE
}

type fsSecurityScan struct {
	Filesystem string
	Path       string

	// Source says where the descriptor was read from: the file's own
	// $SECURITY_DESCRIPTOR attribute, or the volume's $Secure:$SDS resolved
	// through the entry's security ID. They are different provenance and a
	// descriptor found on the entry overrides the shared one.
	Source     string
	SecurityID int64

	Revision     int64
	Control      int64
	ControlFlags []string

	OwnerSID   string
	OwnerName  string
	OwnerKnown bool
	GroupSID   string
	GroupName  string
	GroupKnown bool

	DACL fsACL
	SACL fsACL

	DescriptorBytes  int64
	DescriptorSHA256 string

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsAttrWarning
	Scope             string
}

func (s *fsSecurityScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsAttrWarning{Code: code, Location: location, Detail: detail})
}

func (s *fsSecurityScan) incomplete(reason string) {
	s.Complete = false
	if s.IncompleteReason == "" {
		s.IncompleteReason = reason
	}
}

func aceArray(aces []fsACE) object.Object {
	out := make([]object.Object, 0, len(aces))
	for _, ace := range aces {
		out = append(out, makeHashObject(map[string]object.Object{
			"type":          intObj(ace.Type),
			"type_name":     stringObj(ace.TypeName),
			"flags":         intObj(ace.Flags),
			"inherited":     boolObj(ace.Inherited),
			"mask":          intObj(ace.Mask),
			"rights":        stringArray(ace.Rights),
			"trustee_sid":   stringObj(ace.TrusteeSID),
			"trustee_name":  stringObj(ace.TrusteeName),
			"trustee_known": boolObj(ace.TrusteeKnown),
		}))
	}
	return &object.Array{Elements: out}
}

func (s fsSecurityScan) toHash(handle string) *object.Hash {
	return makeHashObject(map[string]object.Object{
		"handle":             stringObj(handle),
		"filesystem":         stringObj(s.Filesystem),
		"path":               stringObj(s.Path),
		"source":             stringObj(s.Source),
		"security_id":        intObj(s.SecurityID),
		"revision":           intObj(s.Revision),
		"control":            intObj(s.Control),
		"control_flags":      stringArray(s.ControlFlags),
		"owner_sid":          stringObj(s.OwnerSID),
		"owner_name":         stringObj(s.OwnerName),
		"owner_known":        boolObj(s.OwnerKnown),
		"group_sid":          stringObj(s.GroupSID),
		"group_name":         stringObj(s.GroupName),
		"group_known":        boolObj(s.GroupKnown),
		"dacl_present":       boolObj(s.DACL.Present),
		"dacl_revision":      intObj(s.DACL.Revision),
		"dacl_ace_count":     intObj(s.DACL.Count),
		"dacl":               aceArray(s.DACL.ACEs),
		"sacl_present":       boolObj(s.SACL.Present),
		"sacl_ace_count":     intObj(s.SACL.Count),
		"sacl":               aceArray(s.SACL.ACEs),
		"descriptor_bytes":   intObj(s.DescriptorBytes),
		"descriptor_sha256":  stringObj(s.DescriptorSHA256),
		"complete":           boolObj(s.Complete),
		"incomplete_reason":  stringObj(s.IncompleteReason),
		"warnings_available": boolObj(s.WarningsAvailable),
		"warnings":           warningArray(s.Warnings),
		"warning_codes":      warningCodeArray(s.Warnings),
		"scope":              stringObj(s.Scope),
		"status":             stringObj("ok"),
	})
}

type fsSecurityIndexEntry struct {
	SecurityID       int64
	OwnerSID         string
	OwnerName        string
	GroupSID         string
	DACLPresent      bool
	DACLACECount     int64
	SACLPresent      bool
	SACLACECount     int64
	DescriptorBytes  int64
	DescriptorSHA256 string
}

type fsSecurityIndex struct {
	Filesystem string

	Entries    []fsSecurityIndexEntry
	EntryCount int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsAttrWarning
	Scope             string
}

func (s *fsSecurityIndex) add(entry fsSecurityIndexEntry) bool {
	s.EntryCount++
	if len(s.Entries) >= fsAttrMaxDescriptors {
		return false
	}
	s.Entries = append(s.Entries, entry)
	return true
}

func (s *fsSecurityIndex) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsAttrWarning{Code: code, Location: location, Detail: detail})
}

func (s fsSecurityIndex) toHash(handle string) *object.Hash {
	entries := make([]object.Object, 0, len(s.Entries))
	for _, e := range s.Entries {
		entries = append(entries, makeHashObject(map[string]object.Object{
			"security_id":       intObj(e.SecurityID),
			"owner_sid":         stringObj(e.OwnerSID),
			"owner_name":        stringObj(e.OwnerName),
			"group_sid":         stringObj(e.GroupSID),
			"dacl_present":      boolObj(e.DACLPresent),
			"dacl_ace_count":    intObj(e.DACLACECount),
			"sacl_present":      boolObj(e.SACLPresent),
			"sacl_ace_count":    intObj(e.SACLACECount),
			"descriptor_bytes":  intObj(e.DescriptorBytes),
			"descriptor_sha256": stringObj(e.DescriptorSHA256),
		}))
	}

	return makeHashObject(map[string]object.Object{
		"handle":                stringObj(handle),
		"filesystem":            stringObj(s.Filesystem),
		"descriptors":           &object.Array{Elements: entries},
		"descriptor_count":      intObj(s.EntryCount),
		"descriptors_truncated": boolObj(s.EntryCount > int64(len(s.Entries))),
		"complete":              boolObj(s.Complete),
		"incomplete_reason":     stringObj(s.IncompleteReason),
		"warnings_available":    boolObj(s.WarningsAvailable),
		"warnings":              warningArray(s.Warnings),
		"warning_codes":         warningCodeArray(s.Warnings),
		"scope":                 stringObj(s.Scope),
		"status":                stringObj("ok"),
	})
}

// ntfsSIDStrings renders a SID and its conventional name, if it has one.
func ntfsSIDStrings(sid *libntfs.SID) (string, string, bool) {
	if sid == nil {
		return "", "", false
	}
	text := sid.String()
	name, known := sid.WellKnownName()
	return text, name, known
}

// ntfsControlFlags names the set bits of a descriptor's control word. A bit
// with no name would be dropped silently, so the remainder is rendered in hex.
func ntfsControlFlags(control uint16) []string {
	named := []struct {
		bit  uint16
		name string
	}{
		{libntfs.SEOwnerDefaulted, "OWNER_DEFAULTED"},
		{libntfs.SEGroupDefaulted, "GROUP_DEFAULTED"},
		{libntfs.SEDACLPresent, "DACL_PRESENT"},
		{libntfs.SEDACLDefaulted, "DACL_DEFAULTED"},
		{libntfs.SESACLPresent, "SACL_PRESENT"},
		{libntfs.SESACLDefaulted, "SACL_DEFAULTED"},
		{libntfs.SEDACLAutoInherited, "DACL_AUTO_INHERITED"},
		{libntfs.SESACLAutoInherited, "SACL_AUTO_INHERITED"},
		{libntfs.SEDACLProtected, "DACL_PROTECTED"},
		{libntfs.SESACLProtected, "SACL_PROTECTED"},
		{libntfs.SESelfRelative, "SELF_RELATIVE"},
	}

	flags := make([]string, 0, len(named))
	remaining := control
	for _, entry := range named {
		if control&entry.bit != 0 {
			flags = append(flags, entry.name)
			remaining &^= entry.bit
		}
	}
	if remaining != 0 {
		flags = append(flags, fmt.Sprintf("0x%04X", remaining))
	}
	return flags
}

// ntfsRenderACL converts one of a descriptor's two lists.
//
// A nil list is not an empty one. The caller distinguishes them through
// Present, and every field below a nil list stays zero rather than describing a
// list that is not there.
func ntfsRenderACL(acl *libntfs.ACL) fsACL {
	if acl == nil {
		return fsACL{}
	}

	out := fsACL{Present: true, Revision: int64(acl.Revision), Count: int64(len(acl.ACEs))}
	for i, ace := range acl.ACEs {
		if i >= fsAttrMaxACEs {
			break
		}
		sid, name, known := ntfsSIDStrings(ace.Trustee)
		out.ACEs = append(out.ACEs, fsACE{
			Type:         int64(ace.Type),
			TypeName:     ace.TypeName(),
			Flags:        int64(ace.Flags),
			Inherited:    ace.IsInherited(),
			Mask:         int64(ace.Mask),
			Rights:       ace.RightsNames(),
			TrusteeSID:   sid,
			TrusteeName:  name,
			TrusteeKnown: known,
		})
	}
	return out
}

// ------------------------------------------------------------ reparse points

type fsReparseScan struct {
	Filesystem string
	Path       string

	IsReparsePoint bool
	Tag            int64
	TagName        string
	MicrosoftOwned bool
	GUID           string

	Target          string
	PrintName       string
	TargetAvailable bool
	Relative        bool

	DataBytes     int64
	DataHex       string
	DataTruncated bool

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsAttrWarning
	Scope             string
}

func (s *fsReparseScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsAttrWarning{Code: code, Location: location, Detail: detail})
}

func (s fsReparseScan) toHash(handle string) *object.Hash {
	return makeHashObject(map[string]object.Object{
		"handle":             stringObj(handle),
		"filesystem":         stringObj(s.Filesystem),
		"path":               stringObj(s.Path),
		"is_reparse_point":   boolObj(s.IsReparsePoint),
		"tag":                intObj(s.Tag),
		"tag_name":           stringObj(s.TagName),
		"microsoft_owned":    boolObj(s.MicrosoftOwned),
		"guid":               stringObj(s.GUID),
		"target":             stringObj(s.Target),
		"print_name":         stringObj(s.PrintName),
		"target_available":   boolObj(s.TargetAvailable),
		"relative":           boolObj(s.Relative),
		"data_bytes":         intObj(s.DataBytes),
		"data_hex":           stringObj(s.DataHex),
		"data_truncated":     boolObj(s.DataTruncated),
		"complete":           boolObj(s.Complete),
		"incomplete_reason":  stringObj(s.IncompleteReason),
		"warnings_available": boolObj(s.WarningsAvailable),
		"warnings":           warningArray(s.Warnings),
		"warning_codes":      warningCodeArray(s.Warnings),
		"scope":              stringObj(s.Scope),
		"status":             stringObj("ok"),
	})
}

// ------------------------------------------------------------ resource fork

type fsForkRange struct {
	ForkOffset int64
	Offset     int64
	Length     int64
	Slack      int64
}

type fsForkScan struct {
	Filesystem string
	Path       string
	Name       string
	CNID       int64

	Present      bool
	Size         int64
	LocatedBytes int64
	DataForkSize int64

	Compressed      bool
	CompressionType int64
	HoldsPayload    bool

	Ranges     []fsForkRange
	RangeCount int64

	Complete         bool
	IncompleteReason string

	WarningsAvailable bool
	Warnings          []fsAttrWarning
	Scope             string
}

func (s *fsForkScan) add(r fsForkRange) bool {
	s.RangeCount++
	if r.Offset >= 0 {
		s.LocatedBytes += r.Length
	}
	if len(s.Ranges) >= fsAttrMaxRanges {
		return false
	}
	s.Ranges = append(s.Ranges, r)
	return true
}

func (s *fsForkScan) warn(code, location, detail string) {
	s.Warnings = append(s.Warnings, fsAttrWarning{Code: code, Location: location, Detail: detail})
}

func (s *fsForkScan) incomplete(reason string) {
	s.Complete = false
	if s.IncompleteReason == "" {
		s.IncompleteReason = reason
	}
}

func (s fsForkScan) toHash(handle string) *object.Hash {
	ranges := make([]object.Object, 0, len(s.Ranges))
	for _, r := range s.Ranges {
		ranges = append(ranges, makeHashObject(map[string]object.Object{
			"fork_offset": intObj(r.ForkOffset),
			"offset":      intObj(r.Offset),
			"length":      intObj(r.Length),
			"slack":       intObj(r.Slack),
		}))
	}

	return makeHashObject(map[string]object.Object{
		"handle":                   stringObj(handle),
		"filesystem":               stringObj(s.Filesystem),
		"path":                     stringObj(s.Path),
		"name":                     stringObj(s.Name),
		"cnid":                     intObj(s.CNID),
		"present":                  boolObj(s.Present),
		"size":                     intObj(s.Size),
		"located_bytes":            intObj(s.LocatedBytes),
		"data_fork_size":           intObj(s.DataForkSize),
		"compressed":               boolObj(s.Compressed),
		"compression_type":         intObj(s.CompressionType),
		"holds_compressed_payload": boolObj(s.HoldsPayload),
		"ranges":                   &object.Array{Elements: ranges},
		"range_count":              intObj(s.RangeCount),
		"ranges_truncated":         boolObj(s.RangeCount > int64(len(s.Ranges))),
		"complete":                 boolObj(s.Complete),
		"incomplete_reason":        stringObj(s.IncompleteReason),
		"warnings_available":       boolObj(s.WarningsAvailable),
		"warnings":                 warningArray(s.Warnings),
		"warning_codes":            warningCodeArray(s.Warnings),
		"scope":                    stringObj(s.Scope),
		"status":                   stringObj("ok"),
	})
}

// ---------------------------------------------------------------- NTFS

const ntfsStreamsScope = "the $DATA attributes of one live file or directory. The unnamed stream is " +
	"listed beside the alternate ones so that a report shows what the path addresses and what it " +
	"does not. $EA and $EA_INFORMATION, the extended attributes NTFS inherited from OS/2 and that " +
	"WSL uses for its metadata, are a different attribute type and are not listed here. Neither " +
	"is $INDEX_ALLOCATION, which is how a directory stores its entries rather than a stream of " +
	"content."

func (s *realNTFSSession) Streams(filePath string) (fsStreamScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newStreamScan("ntfs", cleanPath)
	scan.Scope = ntfsStreamsScope

	file, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsStreamScan{}, err
	}
	scan.Name = file.Name()
	scan.IsDirectory = file.IsDirectory()

	for _, info := range file.Streams() {
		entry := fsStreamEntry{
			Name:           info.Name,
			IsAlternate:    info.IsAlternate(),
			Size:           int64(info.Size),
			AllocatedBytes: int64(info.AllocatedSize),
			Resident:       info.Resident,
			Readable:       info.Support.Readable,
			BlockingReason: errorString(info.Support.BlockingError),
		}
		scan.add(entry)

		if !entry.Readable {
			scan.warn(fsAttrWarnStreamUnreadable, entry.Name,
				"libntfs reports this stream as unreadable before any byte is asked for: "+
					errorString(info.Support.BlockingError))
		}
	}

	switch {
	case scan.IsDirectory && scan.AlternateCount > 0:
		// A directory has no unnamed stream but can carry named ones, and a
		// stream on a directory is invisible to every tool that lists files.
		scan.warn(fsAttrWarnDirectoryStream, cleanPath,
			"a directory carries no content of its own, so a named stream on one was put there "+
				"deliberately and is reachable only by naming it")
	case !scan.IsDirectory && !scan.DefaultPresent:
		scan.warn(fsAttrWarnNoDefaultStream, cleanPath,
			"this entry is not a directory and has no unnamed $DATA attribute, so the path names "+
				"no content at all")
	}

	return scan, nil
}

// OpenStream reaches one named $DATA stream, which the path alone cannot.
//
// An empty name selects the unnamed stream, so this is a superset of
// OpenReader. Names are matched case-insensitively, as NTFS itself matches
// them. A directory's named stream opens: libntfs is explicit that a named
// stream holds content even when its host entry is a directory, and does not
// let it inherit the directory's read block.
func (s *realNTFSSession) OpenStream(filePath, streamName string) (fsFileReader, error) {
	cleanPath := normalizeFSPath(filePath)

	file, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsFileReader{}, err
	}

	stream, err := file.OpenStream(streamName)
	if err != nil {
		return fsFileReader{}, err
	}

	// As in OpenReader: what blocks a stream is known before the first byte is
	// asked for, and during an extraction that is before the destination file
	// has been created.
	if support := stream.ReadSupport(); !support.Readable && support.BlockingError != nil {
		return fsFileReader{}, support.BlockingError
	}

	size := stream.Size()
	return fsFileReader{ReaderAt: stream, Size: size, Located: size}, nil
}

const ntfsSecurityScope = "the security descriptor governing one live file: its owner, its group, " +
	"and the entries of its DACL and SACL as they are stored. It is a reading of what is on the " +
	"volume, not an access decision -- resolving whether a particular account could open this " +
	"file needs group memberships, privileges and an inheritance walk that a disk image does not " +
	"contain, so no field here answers that question. A descriptor on the entry itself takes " +
	"precedence over the one its security ID names in $Secure:$SDS, and source says which was " +
	"read. SIDs are rendered in S-R-I-S notation with a conventional name only where the SID is " +
	"a well-known one; an account SID from a domain names nobody without that domain's directory."

func (s *realNTFSSession) Security(filePath string) (fsSecurityScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := fsSecurityScan{
		Filesystem:        "ntfs",
		Path:              cleanPath,
		SecurityID:        -1,
		Complete:          true,
		WarningsAvailable: true,
		Scope:             ntfsSecurityScope,
	}

	file, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsSecurityScan{}, err
	}

	// libntfs resolves the descriptor without saying which of the two places
	// it came from, and the provenance matters: a descriptor on the entry is
	// this file's alone, while one from $SDS is shared with every other file
	// carrying the same security ID. The entry is consulted here for that
	// reason only.
	entry, entryErr := s.volume.GetMFTEntry(file.EntryNumber())
	switch {
	case entryErr != nil:
		scan.incomplete("the MFT entry could not be re-read, so the descriptor's provenance is unknown")
	case entry.FindAttribute(libntfs.AttrTypeSecurityDesc, "") != nil:
		scan.Source = "attribute"
	default:
		scan.Source = "sds"
		if si, siErr := entry.GetStandardInformation(); siErr == nil {
			scan.SecurityID = int64(si.SecurityID)
			scan.warn(fsAttrWarnDescriptorShared, cleanPath,
				fmt.Sprintf("this descriptor is $Secure:$SDS entry %d and is shared with every "+
					"other file carrying that security ID; it is not a property of this file alone",
					si.SecurityID))
		}
	}

	descriptor, err := file.SecurityDescriptor()
	if err != nil {
		return fsSecurityScan{}, err
	}
	if descriptor == nil {
		scan.incomplete("no security descriptor was found for this entry")
		return scan, nil
	}

	scan.Revision = int64(descriptor.Revision)
	scan.Control = int64(descriptor.Control)
	scan.ControlFlags = ntfsControlFlags(descriptor.Control)
	scan.OwnerSID, scan.OwnerName, scan.OwnerKnown = ntfsSIDStrings(descriptor.Owner)
	scan.GroupSID, scan.GroupName, scan.GroupKnown = ntfsSIDStrings(descriptor.Group)
	scan.DACL = ntfsRenderACL(descriptor.DACL)
	scan.SACL = ntfsRenderACL(descriptor.SACL)
	scan.DescriptorBytes = int64(len(descriptor.Raw))
	sum := sha256.Sum256(descriptor.Raw)
	scan.DescriptorSHA256 = hex.EncodeToString(sum[:])

	// The two opposite meanings of an empty ACE list. Both are reported, so
	// neither can be read off the array length alone.
	switch {
	case !scan.DACL.Present:
		scan.warn(fsAttrWarnNoDACL, cleanPath,
			"this descriptor carries no DACL at all, which grants everyone full access -- the "+
				"opposite of a DACL that is present and holds no entries")
	case scan.DACL.Count == 0:
		scan.warn(fsAttrWarnEmptyDACL, cleanPath,
			"this descriptor's DACL is present and holds no entries, which denies everyone -- the "+
				"opposite of a descriptor carrying no DACL")
	}
	if scan.SACL.Present {
		scan.warn(fsAttrWarnSACLPresent, cleanPath,
			"this file carries a system ACL, which records what Windows was asked to audit about "+
				"access to it")
	}

	return scan, nil
}

const ntfsSecurityIndexScope = "every descriptor in the volume's $Secure:$SDS stream, in ascending " +
	"security ID order -- the whole vocabulary of permissions the volume uses, without a lookup " +
	"per file. It says which descriptors exist, not which files use them: the join is through the " +
	"security ID in each entry's $STANDARD_INFORMATION, which ntfs_security reports per file. A " +
	"descriptor stored directly on an entry, as older volumes and some system files do, is not in " +
	"$SDS and so is not here. Deleted descriptors are not distinguished: $SDS is append-only and " +
	"libntfs indexes what it holds."

func (s *realNTFSSession) SecurityIndex() (fsSecurityIndex, error) {
	index := fsSecurityIndex{
		Filesystem:        "ntfs",
		Complete:          true,
		WarningsAvailable: true,
		Scope:             ntfsSecurityIndexScope,
	}

	err := s.volume.EachSecurityDescriptor(func(securityID uint32, sd *libntfs.SecurityDescriptor) error {
		if sd == nil {
			index.EntryCount++
			return nil
		}

		ownerSID, ownerName, _ := ntfsSIDStrings(sd.Owner)
		groupSID, _, _ := ntfsSIDStrings(sd.Group)
		sum := sha256.Sum256(sd.Raw)

		entry := fsSecurityIndexEntry{
			SecurityID:       int64(securityID),
			OwnerSID:         ownerSID,
			OwnerName:        ownerName,
			GroupSID:         groupSID,
			DescriptorBytes:  int64(len(sd.Raw)),
			DescriptorSHA256: hex.EncodeToString(sum[:]),
		}
		if sd.DACL != nil {
			entry.DACLPresent = true
			entry.DACLACECount = int64(len(sd.DACL.ACEs))
		}
		if sd.SACL != nil {
			entry.SACLPresent = true
			entry.SACLACECount = int64(len(sd.SACL.ACEs))
		}

		if !entry.DACLPresent {
			index.warn(fsAttrWarnNoDACL, fmt.Sprintf("security id %d", securityID),
				"this descriptor carries no DACL at all, which grants everyone full access")
		}
		index.add(entry)
		return nil
	})
	if err != nil {
		return fsSecurityIndex{}, err
	}

	return index, nil
}

const ntfsReparseScope = "one live entry's $REPARSE_POINT attribute. A target is decoded for the " +
	"three tags that name one -- symbolic links, mount points, and WSL symlinks -- and for every " +
	"other tag the tag-specific bytes are handed back as hex rather than guessed at, which covers " +
	"deduplication, cloud placeholders, WOF-compressed files and anything Microsoft ships next. " +
	"The link is never followed: a directory carrying a reparse point lists its own index, which " +
	"is usually empty, and not the target's. Whether the target exists is not checked, and on an " +
	"image of one volume it frequently cannot be."

func (s *realNTFSSession) Reparse(filePath string) (fsReparseScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := fsReparseScan{
		Filesystem:        "ntfs",
		Path:              cleanPath,
		Complete:          true,
		WarningsAvailable: true,
		Scope:             ntfsReparseScope,
	}

	file, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsReparseScan{}, err
	}

	reparse, err := file.ReparsePoint()
	if err != nil {
		return fsReparseScan{}, err
	}
	if reparse == nil {
		// Having none is an answer, and a different one from a reparse point
		// whose target could not be decoded. Every field below stays zero and
		// is_reparse_point says which case this is.
		return scan, nil
	}

	scan.IsReparsePoint = true
	scan.Tag = int64(reparse.ReparseType)
	scan.TagName = reparse.TagName()
	scan.MicrosoftOwned = reparse.IsMicrosoft()
	scan.Relative = reparse.IsRelative()
	scan.DataBytes = int64(len(reparse.Data))

	if !scan.MicrosoftOwned {
		scan.GUID = hex.EncodeToString(reparse.GUID[:])
		scan.warn(fsAttrWarnThirdPartyTag, cleanPath,
			"this reparse tag is not Microsoft-owned, so it carries an owner GUID and its data "+
				"layout is defined by whoever wrote the filter driver")
	}

	target, printName, ok := reparse.Target()
	scan.Target = target
	scan.PrintName = printName
	scan.TargetAvailable = ok
	if !ok {
		scan.warn(fsAttrWarnTargetUndecoded, cleanPath,
			"this tag names no target that libntfs decodes; the tag-specific bytes are in data_hex")
	}

	data := reparse.Data
	if len(data) > fsAttrMaxReparseHex {
		data = data[:fsAttrMaxReparseHex]
		scan.DataTruncated = true
	}
	scan.DataHex = hex.EncodeToString(data)

	return scan, nil
}

// ---------------------------------------------------------------- ext

const extXattrScope = "the extended attributes of one live inode, read from both places ext keeps " +
	"them. libext's GetXAttrs follows the inode's external attribute block alone, and its own " +
	"documentation says where that leaves a caller: security.selinux and system.posix_acl_access " +
	"are small enough never to need an external block on a typical modern system, so a reader " +
	"that follows only the block reports no attributes at all. Both storages are consulted here " +
	"and each attribute says which it came from. A value held in its own inode, which ext4 uses " +
	"for large attributes, is followed by libext and reported as though it were stored with the " +
	"rest; a failure to follow one arrives as a library warning rather than as an empty value. " +
	"The attributes of a deleted inode are not reachable: this addresses a live file by path."

func (s *realEXTSession) Xattrs(filePath string) (fsXattrScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newXattrScan("ext", cleanPath, fsAttrNodeInode)
	scan.Scope = extXattrScope
	scan.Supported = s.fs.Capabilities().ExtendedAttributes

	file, err := s.fs.OpenPath(cleanPath)
	if err != nil {
		return fsXattrScan{}, err
	}
	inode := file.Inode()
	scan.NodeID = int64(inode.Number)

	if !scan.Supported {
		// The feature bit is off, so no file on this volume can carry one.
		// That is a statement about the filesystem, not about this inode.
		scan.warn(fsAttrWarnUnsupported, cleanPath,
			"this volume does not have the ext_attr feature set, so no inode on it carries "+
				"extended attributes and an empty list here is a property of the filesystem")
		return scan, nil
	}

	// The warning list belongs to the volume rather than to this call, so only
	// what arrives during it belongs to the result.
	before := len(s.fs.Warnings())

	seen := map[string]string{}
	blockOffset := int64(-1)
	if inode.FileACL != 0 {
		if blockSize := int64(s.fs.Superblock().BlockSize); blockSize > 0 {
			blockOffset = int64(inode.FileACL)*blockSize + s.fs.Options().BaseOffset
		}
	}

	scan.StoragesChecked = []string{fsAttrStorageInline, fsAttrStorageBlock}

	inlineList, err := s.fs.GetInlineXAttrs(&inode)
	if err != nil {
		scan.incomplete("the inline attribute area could not be read: " + err.Error())
	}
	for _, attr := range inlineList.Attrs {
		seen[attr.Name] = fsAttrStorageInline
		scan.add(fsXattrEntry{
			Name:      attr.Name,
			Namespace: attrNamespaceOf(attr.Name),
			Storage:   fsAttrStorageInline,
			Size:      int64(len(attr.Value)),
			Value:     attr.Value,
			Offset:    -1,
		})
	}

	blockList, err := s.fs.GetXAttrs(inode.Number)
	if err != nil {
		scan.incomplete("the external attribute block could not be read: " + err.Error())
	}
	for _, attr := range blockList.Attrs {
		if where, duplicate := seen[attr.Name]; duplicate {
			scan.warn(fsAttrWarnDuplicateName, attr.Name,
				"this name is present both "+where+" and in the external block; both are reported "+
					"because which one the kernel would return is not recorded on disk")
		}
		seen[attr.Name] = fsAttrStorageBlock
		scan.add(fsXattrEntry{
			Name:      attr.Name,
			Namespace: attrNamespaceOf(attr.Name),
			Storage:   fsAttrStorageBlock,
			Size:      int64(len(attr.Value)),
			Value:     attr.Value,
			Offset:    blockOffset,
		})
	}
	if blockOffset < 0 && len(blockList.Attrs) > 0 {
		scan.warn(fsAttrWarnValueUnlocated, cleanPath,
			"the external attribute block's position could not be computed, so the values read "+
				"from it are reported without a place on the image")
	}

	warnings := s.fs.Warnings()
	if before > len(warnings) {
		before = len(warnings)
	}
	for _, warning := range warnings[before:] {
		scan.warn(warning.Code.String(), warning.Feature, warning.Detail)
	}

	return scan, nil
}

// ---------------------------------------------------------------- XFS

const xfsXattrScope = "the extended attributes of one live inode, short-form or block-backed. " +
	"libxfs performs no deduplication and says so: two records carrying the same fully-qualified " +
	"name both come back, which is an inconsistency in the attribute fork rather than a rendering " +
	"artifact, so it is counted and warned on here. A remote value -- one large enough that XFS " +
	"stores it in its own blocks -- is followed by the library and reported like any other. " +
	"Attribute values carry no location: libxfs exposes the attribute fork's extents nowhere that " +
	"a per-value offset can be derived from, so offset is -1 throughout, unlike the ext and HFS+ " +
	"siblings. Namespaces are the three XFS records -- user, trusted and security; a record " +
	"flagged with anything else is one libxfs refuses to name rather than guess at."

func (s *realXFSSession) Xattrs(filePath string) (fsXattrScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newXattrScan("xfs", cleanPath, fsAttrNodeInode)
	scan.Scope = xfsXattrScope
	scan.Supported = true

	inodeNumber, err := s.volume.ResolveInodeByPath(cleanPath)
	if err != nil {
		return fsXattrScan{}, err
	}
	scan.NodeID = int64(inodeNumber)

	inode, err := s.volume.OpenInode(inodeNumber)
	if err != nil {
		return fsXattrScan{}, err
	}

	switch {
	case inode.AttributesForkSize == 0:
		// No attribute fork at all. That is an answer, and the storage list
		// says nothing was consulted because there was nothing to consult.
		return scan, nil
	case inode.AttributesForkType == libxfs.ForkTypeInlineData:
		scan.StoragesChecked = []string{fsAttrStorageInline}
	default:
		scan.StoragesChecked = []string{fsAttrStorageBlock}
	}

	attributes, err := s.volume.ListInodeExtendedAttributes(inodeNumber)
	if err != nil {
		return fsXattrScan{}, err
	}

	seen := map[string]bool{}
	for _, attr := range attributes {
		name := attr.Name
		if attr.Namespace != "" && !strings.HasPrefix(name, attr.Namespace+".") {
			name = attr.Namespace + "." + name
		}
		if seen[name] {
			scan.warn(fsAttrWarnDuplicateName, name,
				"the attribute fork holds more than one record under this name; libxfs preserves "+
					"duplicates rather than collapsing them, and both are reported here")
		}
		seen[name] = true

		scan.add(fsXattrEntry{
			Name:      name,
			Namespace: attr.Namespace,
			Storage:   scan.StoragesChecked[0],
			Size:      int64(len(attr.Value)),
			Value:     attr.Value,
			Offset:    -1,
		})
	}

	return scan, nil
}

// ---------------------------------------------------------------- HFS+

const hfsXattrScope = "the extended attributes of one live catalog node, inline or fork-backed, in " +
	"B-tree key order. The system attributes com.apple.decmpfs and com.apple.ResourceFork are " +
	"returned like any other and flagged rather than filtered -- libhfs calls filtering them a " +
	"policy decision for the caller, and the presence of decmpfs is precisely why that file's " +
	"data fork reads as empty. A fork-backed value carries its position on the image, so a value " +
	"too large to render is still reachable with raw_read_at_bytes; an inline value lives in the " +
	"B-tree record itself and has no allocation-block address, which is reported as -1 rather " +
	"than as zero. Classic HFS has no attributes B-tree at all, and an HFS+ volume that has never " +
	"had an attribute written to it may have an empty one; supported distinguishes the first from " +
	"a node that simply carries none."

func (s *realHFSSession) Xattrs(filePath string) (fsXattrScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := newXattrScan("hfs", cleanPath, fsAttrNodeCNID)
	scan.Scope = hfsXattrScope
	scan.Supported = s.volume.Kind() != libhfs.KindHFS

	record, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsXattrScan{}, err
	}
	scan.Name = record.Name
	scan.NodeID = int64(record.CNID)

	if !scan.Supported {
		// storages_checked stays empty: nothing was consulted, because on this
		// volume there is nothing to consult. Naming a storage here would say
		// a place was looked in that does not exist.
		scan.warn(fsAttrWarnUnsupported, cleanPath,
			"this is a classic HFS volume, which has no attributes B-tree, so no node on it can "+
				"carry an extended attribute")
		return scan, nil
	}
	scan.StoragesChecked = []string{fsAttrStorageInline, fsAttrStorageFork}

	before := len(s.volume.Anomalies())

	attributes, err := s.volume.ListXAttrs(record.CNID)
	if err != nil {
		return fsXattrScan{}, err
	}

	for _, attr := range attributes {
		entry := fsXattrEntry{
			Name:      attr.Name,
			Namespace: "",
			Storage:   fsAttrStorageInline,
			Size:      int64(attr.Size),
			Offset:    -1,
		}
		if attr.Storage == libhfs.XAttrFork {
			entry.Storage = fsAttrStorageFork
			if ranges, rangeErr := s.volume.XAttrRanges(record.CNID, attr.Name); rangeErr == nil && len(ranges) > 0 {
				entry.Offset = ranges[0].DiskOffset
			}
			if entry.Offset < 0 {
				scan.warn(fsAttrWarnValueUnlocated, attr.Name,
					"this attribute's value is fork-backed and its extents did not resolve to a "+
						"position on the image")
			}
		}

		// Values are read only while they fit the render cap. A larger one
		// reports its true length and, when fork-backed, where it is; reading
		// it through here would put an unbounded allocation behind a builtin
		// whose subject is metadata.
		if attr.Size <= fsAttrMaxValueBytes {
			if value, readErr := s.volume.ReadXAttr(record.CNID, attr.Name); readErr == nil {
				entry.Value = value
			}
		} else {
			scan.warn(fsAttrWarnValueUnrendered, attr.Name,
				fmt.Sprintf("this value is %d bytes, past the %d byte render cap; its length and "+
					"position are reported and the bytes stay readable from the image",
					attr.Size, fsAttrMaxValueBytes))
		}

		scan.add(entry)
		scan.flagWellKnown(attr.Name)
	}

	anomalies := s.volume.Anomalies()
	if before > len(anomalies) {
		before = len(anomalies)
	}
	for _, anomaly := range anomalies[before:] {
		scan.warn(anomaly.Op, fmt.Sprintf("%d", anomaly.Offset), anomaly.Detail)
	}

	return scan, nil
}

const hfsResourceForkScope = "one live file's resource fork: its size, and the image ranges holding " +
	"it. The fork is never decompressed on the way out, which is libhfs's own rule and the right " +
	"one here -- on a decmpfs-compressed file this fork holds the compressed payload, and that is " +
	"the artifact worth preserving. It is the companion to hfs_slack's report that a compressed " +
	"file's data fork is empty: this is where those bytes went. A fork whose extents describe " +
	"more space than its recorded size reports the surplus as slack on the range that holds it, " +
	"because an attribute record carries no block total to trim against. Folders have no fork."

func (s *realHFSSession) ResourceFork(filePath string) (fsForkScan, error) {
	cleanPath := normalizeFSPath(filePath)

	scan := fsForkScan{
		Filesystem:        "hfs",
		Path:              cleanPath,
		CNID:              -1,
		Size:              -1,
		DataForkSize:      -1,
		Complete:          true,
		WarningsAvailable: true,
		Scope:             hfsResourceForkScope,
	}

	record, err := s.volume.OpenPath(cleanPath)
	if err != nil {
		return fsForkScan{}, err
	}
	scan.Name = record.Name
	scan.CNID = int64(record.CNID)
	scan.Compressed = record.Compressed
	scan.CompressionType = int64(record.CompressionType)

	if record.Type == libhfs.CatalogRecordFolder {
		scan.Size = 0
		scan.DataForkSize = 0
		return scan, nil
	}

	scan.DataForkSize = int64(record.DataFork.LogicalSize)
	scan.Size = int64(record.RsrcFork.LogicalSize)
	scan.Present = scan.Size > 0

	ranges, err := s.volume.ResourceForkRanges(record.CNID)
	if err != nil {
		return fsForkScan{}, err
	}
	for _, r := range ranges {
		scan.add(fsForkRange{
			ForkOffset: r.ForkOffset,
			Offset:     r.DiskOffset,
			Length:     r.Length,
			Slack:      r.Slack,
		})
	}

	// The fork's own extents are the evidence that the payload is here rather
	// than in the data fork, so the claim is made only when there is something
	// in it to claim.
	scan.HoldsPayload = record.Compressed && scan.Size > 0
	switch {
	case scan.HoldsPayload:
		scan.warn(fsAttrWarnForkIsPayload, cleanPath,
			"this file is decmpfs-compressed and its resource fork is not empty, so the fork holds "+
				"the compressed payload that its data fork does not; the bytes are not "+
				"decompressed on the way out")
	case record.Compressed && scan.Size == 0:
		scan.warn(fsAttrWarnCompressedPayload, cleanPath,
			"this file is decmpfs-compressed and its resource fork is empty, so the payload is "+
				"small enough to be held inline in the com.apple.decmpfs attribute; hfs_xattrs "+
				"reaches it")
		scan.incomplete("the compressed payload is in an extended attribute rather than in this fork")
	}

	return scan, nil
}

// ------------------------------------------------------------ dispatch

// fsXattrScanner examines one file inside an already-open volume.
type fsXattrScanner func(filePath string) (fsXattrScan, error)

// handleName recovers the handle string for the envelope. The resolver has
// already refused anything that is not a live handle by the time this runs.
func handleName(arg object.Object) string {
	if handle, ok := arg.(*object.String); ok {
		return handle.Value
	}
	return ""
}

// xattrBuiltin is the shared entry point of the three *_xattrs builtins.
func xattrBuiltin(args []object.Object, op string,
	resolve func(object.Object, string) (fsXattrScanner, *object.Error),
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

	result, err := scan(filePath)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(result.toHash(handleName(args[0])), nil)
}

// ExtXattrs lists an ext inode's extended attributes from both storages.
func ExtXattrs(args ...object.Object) object.Object {
	return xattrBuiltin(args, BuiltinNameExtXattrs,
		func(arg object.Object, op string) (fsXattrScanner, *object.Error) {
			resolved, err := resolveEXTHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Xattrs, nil
		})
}

// XFSXattrs lists an XFS inode's extended attributes.
func XFSXattrs(args ...object.Object) object.Object {
	return xattrBuiltin(args, BuiltinNameXfsXattrs,
		func(arg object.Object, op string) (fsXattrScanner, *object.Error) {
			resolved, err := resolveXFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Xattrs, nil
		})
}

// HFSXattrs lists an HFS+ catalog node's extended attributes.
func HFSXattrs(args ...object.Object) object.Object {
	return xattrBuiltin(args, BuiltinNameHfsXattrs,
		func(arg object.Object, op string) (fsXattrScanner, *object.Error) {
			resolved, err := resolveHFSHandle(arg, op)
			if err != nil {
				return nil, err
			}
			return resolved.Session.Xattrs, nil
		})
}

// NtfsStreams lists a file's $DATA streams, named and unnamed.
func NtfsStreams(args ...object.Object) object.Object {
	op := BuiltinNameNtfsStreams
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	resolved, errObj := resolveNTFSHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	filePath, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	scan, err := resolved.Session.Streams(filePath)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(scan.toHash(handleName(args[0])), nil)
}

// NtfsSecurity reports the security descriptor governing one file.
func NtfsSecurity(args ...object.Object) object.Object {
	op := BuiltinNameNtfsSecurity
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	resolved, errObj := resolveNTFSHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	filePath, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	scan, err := resolved.Session.Security(filePath)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(scan.toHash(handleName(args[0])), nil)
}

// NtfsSecurityDescriptors reports every descriptor in $Secure:$SDS.
func NtfsSecurityDescriptors(args ...object.Object) object.Object {
	op := BuiltinNameNtfsSecurityIndex
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	resolved, errObj := resolveNTFSHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	index, err := resolved.Session.SecurityIndex()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(index.toHash(handleName(args[0])), nil)
}

// NtfsReparse reports one entry's reparse point, or that it has none.
func NtfsReparse(args ...object.Object) object.Object {
	op := BuiltinNameNtfsReparse
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	resolved, errObj := resolveNTFSHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	filePath, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	scan, err := resolved.Session.Reparse(filePath)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(scan.toHash(handleName(args[0])), nil)
}

// HFSResourceFork reports where an HFS+ file's resource fork lives.
func HFSResourceFork(args ...object.Object) object.Object {
	op := BuiltinNameHfsResourceFork
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	resolved, errObj := resolveHFSHandle(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	filePath, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	scan, err := resolved.Session.ResourceFork(filePath)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(scan.toHash(handleName(args[0])), nil)
}

// ntfsStreamOpen resolves the handle, path and stream-name arguments the two
// stream-content builtins share.
func ntfsStreamOpen(op string, args []object.Object) (string, string, fsFileReader, *object.Error) {
	resolved, errObj := resolveNTFSHandle(args[0], op)
	if errObj != nil {
		return "", "", fsFileReader{}, errObj
	}

	filePath, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return "", "", fsFileReader{}, errObj
	}

	streamName, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return "", "", fsFileReader{}, errObj
	}

	reader, err := resolved.Session.OpenStream(filePath, streamName)
	if err != nil {
		return "", "", fsFileReader{}, newError("%s: %s", op, err.Error())
	}
	return filePath, streamName, reader, nil
}

// NtfsReadStream reads one window of a named $DATA stream.
//
// This is the small-value path: an ADS is usually a few dozen bytes -- a
// Zone.Identifier naming the URL a file was downloaded from is the common case
// -- and writing one to disk in order to read it would be absurd. A stream too
// large for that is what ntfs_extract_stream is for.
func NtfsReadStream(args ...object.Object) object.Object {
	op := BuiltinNameNtfsReadStream
	if len(args) != 5 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=5", len(args)))
	}

	_, _, reader, errObj := ntfsStreamOpen(op, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offset, errObj := requireIntArg(op, args[3], 4)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	length, errObj := requireIntArg(op, args[4], 5)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return fsReadWindow(op, reader, offset, length)
}

// NtfsExtractStream streams a named $DATA stream out of an image and onto disk.
func NtfsExtractStream(args ...object.Object) object.Object {
	op := BuiltinNameNtfsExtractStream
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}

	filePath, streamName, reader, errObj := ntfsStreamOpen(op, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	destination, errObj := requireStringArg(op, args[3], 4)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	written, digest, errObj := fsWriteEvidenceFile(op, destination, fsStreamSection(reader))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":          stringObj(filePath),
		"stream":        stringObj(streamName),
		"dest":          stringObj(destination),
		"size":          intObj(reader.Size),
		"located_bytes": intObj(reader.Located),
		"bytes_written": intObj(written),
		"truncated":     boolObj(reader.truncated()),
		"algorithm":     stringObj("sha256"),
		"digest":        stringObj(digest),
	}), nil)
}
