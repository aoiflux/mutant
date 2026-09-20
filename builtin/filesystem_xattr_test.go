package builtin

import (
	"errors"
	"strings"
	"testing"

	libntfs "github.com/aoiflux/libntfs"

	"mutant/object"
)

// errFakeLibrary stands in for a failure inside one of the parsing libraries,
// which is the case the dispatch tests care about: an error there must reach
// the script rather than be rendered as an envelope holding nothing.
var errFakeLibrary = errors.New("synthetic library failure")

// The two opposite empty DACLs. This is the finding the whole security half of
// this family exists to keep straight, so it is the first test in the file.
func TestANilDACLIsNotAnEmptyOne(t *testing.T) {
	absent := ntfsRenderACL(nil)
	if absent.Present {
		t.Error("a descriptor with no DACL reported one as present")
	}
	if absent.Count != 0 || len(absent.ACEs) != 0 {
		t.Errorf("a DACL that is not there described %d entries", absent.Count)
	}

	empty := ntfsRenderACL(&libntfs.ACL{Revision: 2})
	if !empty.Present {
		t.Error("a DACL that is present and empty reported as absent")
	}
	if empty.Count != 0 {
		t.Errorf("an empty DACL counted %d entries", empty.Count)
	}

	// Both render zero entries. Only dacl_present separates "everyone has full
	// access" from "nobody has any", and they must not share a warning either.
	if fsAttrWarnNoDACL == fsAttrWarnEmptyDACL {
		t.Error("the two opposite empty-DACL cases share one warning code")
	}
}

func TestAnACEKeepsItsTrusteeAndItsRights(t *testing.T) {
	everyone := &libntfs.SID{Revision: 1, IdentifierAuthority: 1, SubAuthorities: []uint32{0}}
	acl := &libntfs.ACL{
		Revision: 2,
		ACEs: []libntfs.ACE{{
			Type:    libntfs.ACETypeAccessAllowed,
			Flags:   libntfs.ACEFlagInherited,
			Mask:    libntfs.AccessReadData | libntfs.AccessWriteData,
			Trustee: everyone,
		}},
	}

	rendered := ntfsRenderACL(acl)
	if !rendered.Present || rendered.Count != 1 || len(rendered.ACEs) != 1 {
		t.Fatalf("a one-entry DACL rendered as %d entries", rendered.Count)
	}

	ace := rendered.ACEs[0]
	if ace.TrusteeSID != "S-1-1-0" {
		t.Errorf("trustee SID = %q, want S-1-1-0", ace.TrusteeSID)
	}
	if !ace.TrusteeKnown || ace.TrusteeName != "Everyone" {
		t.Errorf("the Everyone SID was not recognised: name=%q known=%v", ace.TrusteeName, ace.TrusteeKnown)
	}
	if !ace.Inherited {
		t.Error("an ACE carrying the INHERITED flag did not report as inherited")
	}
	if ace.TypeName == "" {
		t.Error("an ACE type rendered without a name")
	}
	if len(ace.Rights) == 0 {
		t.Error("an access mask with two bits set decoded to no rights")
	}
}

// A trustee this package cannot decode is nil, and a SID that is nil is not the
// SID "". The fields are separate so a report cannot read one as the other.
func TestAnUndecodedTrusteeIsNotAnEmptySID(t *testing.T) {
	rendered := ntfsRenderACL(&libntfs.ACL{
		Revision: 2,
		ACEs:     []libntfs.ACE{{Type: libntfs.ACETypeAccessAllowedObject}},
	})
	if len(rendered.ACEs) != 1 {
		t.Fatalf("rendered %d entries, want 1", len(rendered.ACEs))
	}
	if rendered.ACEs[0].TrusteeKnown {
		t.Error("an ACE with no trustee reported a known one")
	}
	if rendered.ACEs[0].TrusteeSID != "" {
		t.Errorf("an ACE with no trustee rendered a SID %q", rendered.ACEs[0].TrusteeSID)
	}
}

func TestTheACECapKeepsTheCountHonestPastIt(t *testing.T) {
	acl := &libntfs.ACL{Revision: 2, ACEs: make([]libntfs.ACE, fsAttrMaxACEs+25)}
	rendered := ntfsRenderACL(acl)

	if rendered.Count != int64(fsAttrMaxACEs+25) {
		t.Errorf("ace count = %d, want the true %d", rendered.Count, fsAttrMaxACEs+25)
	}
	if len(rendered.ACEs) != fsAttrMaxACEs {
		t.Errorf("rendered %d entries, want the cap of %d", len(rendered.ACEs), fsAttrMaxACEs)
	}
}

func TestAnUnknownControlBitIsNamedRatherThanDropped(t *testing.T) {
	flags := ntfsControlFlags(libntfs.SEDACLPresent | libntfs.SESelfRelative | 0x0040)

	var named, hexed bool
	for _, flag := range flags {
		switch {
		case flag == "DACL_PRESENT":
			named = true
		case strings.HasPrefix(flag, "0x"):
			hexed = true
		}
	}
	if !named {
		t.Error("a control bit with a name was not named")
	}
	if !hexed {
		t.Error("a control bit with no name was dropped instead of rendered in hex")
	}
}

func TestAControlWordOfZeroNamesNothing(t *testing.T) {
	if flags := ntfsControlFlags(0); len(flags) != 0 {
		t.Errorf("an empty control word produced %v", flags)
	}
}

// ------------------------------------------------------------ value rendering

func TestAValueIsOfferedAsTextOnlyWhenItIsText(t *testing.T) {
	cases := []struct {
		name      string
		value     []byte
		wantText  string
		available bool
	}{
		{"plain ascii", []byte("unconfined_u:object_r:user_home_t:s0"),
			"unconfined_u:object_r:user_home_t:s0", true},
		// The most common extended attribute on Linux stores a C string, and
		// refusing to call it text because of its terminator would make the
		// field useless where it is most wanted.
		{"one trailing nul", []byte("system_u\x00"), "system_u", true},
		{"embedded nul", []byte("sys\x00tem"), "", false},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff}, "", false},
		{"invalid utf8", []byte{0xc3, 0x28}, "", false},
		{"empty", []byte{}, "", true},
		{"utf8 beyond ascii", []byte("café"), "café", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, ok := attrValueText(tc.value)
			if ok != tc.available {
				t.Fatalf("text_available = %v, want %v", ok, tc.available)
			}
			if text != tc.wantText {
				t.Errorf("value_text = %q, want %q", text, tc.wantText)
			}
		})
	}
}

func TestAValuePastTheRenderCapSaysSo(t *testing.T) {
	short := make([]byte, 8)
	if encoded, truncated := attrValueHex(short); truncated || len(encoded) != 16 {
		t.Errorf("a short value rendered as %d characters, truncated=%v", len(encoded), truncated)
	}

	long := make([]byte, fsAttrMaxValueBytes+1)
	encoded, truncated := attrValueHex(long)
	if !truncated {
		t.Error("a value past the cap did not report as truncated")
	}
	if len(encoded) != fsAttrMaxValueBytes*2 {
		t.Errorf("rendered %d hex characters, want %d", len(encoded), fsAttrMaxValueBytes*2)
	}
}

// A value whose bytes were never read reports its true length, and the rendered
// envelope says the rendering is short -- otherwise a 2 MiB attribute reported
// with an empty value reads as an attribute that is empty.
func TestAnUnreadValueIsTruncatedRatherThanEmpty(t *testing.T) {
	scan := newXattrScan("hfs", "/probe", fsAttrNodeCNID)
	scan.add(fsXattrEntry{Name: "com.apple.ResourceFork", Storage: fsAttrStorageFork,
		Size: 2 << 20, Offset: 4096})

	hash := scan.toHash("h1")
	attributes := mustHashArrayValue(t, hash, "attributes")
	if len(attributes) != 1 {
		t.Fatalf("rendered %d attributes, want 1", len(attributes))
	}
	entry := attributes[0].(*object.Hash)

	if size := mustHashIntValue(t, entry, "size"); size != 2<<20 {
		t.Errorf("size = %d, want the recorded %d", size, 2<<20)
	}
	if !mustHashBoolValue(t, entry, "value_truncated") {
		t.Error("an attribute whose value was not read did not report value_truncated")
	}
	if !mustHashBoolValue(t, entry, "located") {
		t.Error("an attribute with an offset did not report as located")
	}
	if total := mustHashIntValue(t, hash, "total_value_bytes"); total != 2<<20 {
		t.Errorf("total_value_bytes = %d, want the recorded length", total)
	}
}

func TestANamespaceIsAPrefixAndNotAGuess(t *testing.T) {
	cases := map[string]string{
		"user.foo":                "user",
		"security.selinux":        "security",
		"system.posix_acl_access": "system",
		"com.apple.quarantine":    "com",
		"bare":                    "",
		".leading":                "",
		"":                        "",
	}
	for name, want := range cases {
		if got := attrNamespaceOf(name); got != want {
			t.Errorf("attrNamespaceOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestTheAttributeCapKeepsTheTotalHonestPastIt(t *testing.T) {
	scan := newXattrScan("ext", "/probe", fsAttrNodeInode)
	for i := 0; i < fsAttrMaxAttributes+10; i++ {
		scan.add(fsXattrEntry{Name: "user.a", Storage: fsAttrStorageInline, Size: 4, Offset: -1})
	}

	hash := scan.toHash("h1")
	if count := mustHashIntValue(t, hash, "attribute_count"); count != int64(fsAttrMaxAttributes+10) {
		t.Errorf("attribute_count = %d, want the true %d", count, fsAttrMaxAttributes+10)
	}
	if total := mustHashIntValue(t, hash, "total_value_bytes"); total != int64((fsAttrMaxAttributes+10)*4) {
		t.Errorf("total_value_bytes = %d, want every attribute counted", total)
	}
	if !mustHashBoolValue(t, hash, "attributes_truncated") {
		t.Error("a list past the cap did not report as truncated")
	}
	if rendered := mustHashArrayValue(t, hash, "attributes"); len(rendered) != fsAttrMaxAttributes {
		t.Errorf("rendered %d attributes, want the cap of %d", len(rendered), fsAttrMaxAttributes)
	}
}

// Unsupported and absent are different answers, and a script that carves on the
// strength of "no attributes" needs to know which it got.
func TestAFormatThatCannotCarryAttributesSaysSoRatherThanReturningNone(t *testing.T) {
	unsupported := newXattrScan("hfs", "/probe", fsAttrNodeCNID)
	unsupported.Supported = false

	supported := newXattrScan("ext", "/probe", fsAttrNodeInode)
	supported.Supported = true

	if mustHashBoolValue(t, unsupported.toHash("h1"), "supported") {
		t.Error("a volume with no attribute support reported as supporting them")
	}
	if !mustHashBoolValue(t, supported.toHash("h1"), "supported") {
		t.Error("a volume that supports attributes reported otherwise")
	}
	// Both carry an empty list; only `supported` tells them apart.
	for _, scan := range []fsXattrScan{unsupported, supported} {
		if count := mustHashIntValue(t, scan.toHash("h1"), "attribute_count"); count != 0 {
			t.Errorf("an empty scan counted %d attributes", count)
		}
	}
}

func TestTheFirstReasonAnAttributeScanStoppedIsTheOneKept(t *testing.T) {
	scan := newXattrScan("ext", "/probe", fsAttrNodeInode)
	scan.incomplete("the inline area could not be read")
	scan.incomplete("the external block could not be read")

	hash := scan.toHash("h1")
	if mustHashBoolValue(t, hash, "complete") {
		t.Error("a scan with a recorded gap reported complete")
	}
	if reason := mustHashStringValue(t, hash, "incomplete_reason"); reason != "the inline area could not be read" {
		t.Errorf("incomplete_reason = %q, want the first one recorded", reason)
	}
}

func TestADecmpfsAttributeExplainsAnEmptyDataFork(t *testing.T) {
	scan := newXattrScan("hfs", "/probe", fsAttrNodeCNID)
	scan.flagWellKnown("com.apple.decmpfs")
	scan.flagWellKnown("com.apple.ResourceFork")
	scan.flagWellKnown("user.ordinary")

	codes := map[string]bool{}
	for _, warning := range scan.Warnings {
		codes[warning.Code] = true
	}
	if !codes[fsAttrWarnCompressedPayload] {
		t.Error("com.apple.decmpfs did not raise the compressed-payload warning")
	}
	if !codes[fsAttrWarnResourceForkAttr] {
		t.Error("com.apple.ResourceFork was not flagged")
	}
	if len(scan.Warnings) != 2 {
		t.Errorf("an ordinary attribute raised a warning: %d warnings total", len(scan.Warnings))
	}
}

// ------------------------------------------------------------ streams

func TestTheUnnamedStreamIsCountedApartFromTheAlternates(t *testing.T) {
	scan := newStreamScan("ntfs", "/probe")
	scan.add(fsStreamEntry{Name: "", IsAlternate: false, Size: 1024, Readable: true})
	scan.add(fsStreamEntry{Name: "Zone.Identifier", IsAlternate: true, Size: 26, Readable: true})
	scan.add(fsStreamEntry{Name: "payload", IsAlternate: true, Size: 4096, Readable: true})

	hash := scan.toHash("h1")
	if count := mustHashIntValue(t, hash, "stream_count"); count != 3 {
		t.Errorf("stream_count = %d, want 3", count)
	}
	if alt := mustHashIntValue(t, hash, "alternate_count"); alt != 2 {
		t.Errorf("alternate_count = %d, want 2", alt)
	}
	// The file's own size is not the sum of its streams, and a report that adds
	// them together says the file is larger than it is.
	if bytes := mustHashIntValue(t, hash, "alternate_bytes"); bytes != 26+4096 {
		t.Errorf("alternate_bytes = %d, want only the alternates", bytes)
	}
	if !mustHashBoolValue(t, hash, "default_present") {
		t.Error("a file with an unnamed stream reported none")
	}
	if size := mustHashIntValue(t, hash, "default_size"); size != 1024 {
		t.Errorf("default_size = %d, want 1024", size)
	}
}

// A directory has no unnamed stream. -1 rather than 0 keeps that apart from a
// file whose unnamed stream is empty.
func TestAnEntryWithNoUnnamedStreamReportsMinusOneRatherThanZero(t *testing.T) {
	scan := newStreamScan("ntfs", "/dir")
	scan.IsDirectory = true
	scan.add(fsStreamEntry{Name: "hidden", IsAlternate: true, Size: 64, Readable: true})

	hash := scan.toHash("h1")
	if mustHashBoolValue(t, hash, "default_present") {
		t.Error("a directory reported an unnamed stream")
	}
	if size := mustHashIntValue(t, hash, "default_size"); size != -1 {
		t.Errorf("default_size = %d, want -1 for an entry that has none", size)
	}
}

func TestTheStreamCapKeepsTheCountHonestPastIt(t *testing.T) {
	scan := newStreamScan("ntfs", "/probe")
	for i := 0; i < fsAttrMaxStreams+5; i++ {
		scan.add(fsStreamEntry{Name: "ads", IsAlternate: true, Size: 1})
	}

	hash := scan.toHash("h1")
	if count := mustHashIntValue(t, hash, "stream_count"); count != int64(fsAttrMaxStreams+5) {
		t.Errorf("stream_count = %d, want the true %d", count, fsAttrMaxStreams+5)
	}
	if !mustHashBoolValue(t, hash, "streams_truncated") {
		t.Error("a list past the cap did not report as truncated")
	}
}

// ------------------------------------------------------------ reparse points

// Having no reparse point and having one whose target could not be decoded are
// different findings, and the second must never be read as the first.
func TestAnEntryWithNoReparsePointIsNotOneWithNoTarget(t *testing.T) {
	none := fsReparseScan{Filesystem: "ntfs", Path: "/plain", Complete: true, WarningsAvailable: true}
	undecoded := fsReparseScan{
		Filesystem: "ntfs", Path: "/dedup", IsReparsePoint: true,
		Tag: 0x80000013, TagName: "DEDUP", MicrosoftOwned: true,
		Complete: true, WarningsAvailable: true,
	}

	noneHash := none.toHash("h1")
	if mustHashBoolValue(t, noneHash, "is_reparse_point") {
		t.Error("an ordinary file reported a reparse point")
	}
	if mustHashIntValue(t, noneHash, "tag") != 0 {
		t.Error("an entry with no reparse point rendered a tag")
	}

	undecodedHash := undecoded.toHash("h1")
	if !mustHashBoolValue(t, undecodedHash, "is_reparse_point") {
		t.Error("a reparse point reported as absent")
	}
	if mustHashBoolValue(t, undecodedHash, "target_available") {
		t.Error("a tag that names no target reported one as available")
	}
	if name := mustHashStringValue(t, undecodedHash, "tag_name"); name != "DEDUP" {
		t.Errorf("tag_name = %q, want the tag named even where its target is not", name)
	}
}

// ------------------------------------------------------------ resource fork

func TestOnlyLocatedResourceForkBytesAreCountedAsLocated(t *testing.T) {
	scan := fsForkScan{Filesystem: "hfs", Path: "/probe", Complete: true, WarningsAvailable: true}
	scan.add(fsForkRange{ForkOffset: 0, Offset: 8192, Length: 4096})
	scan.add(fsForkRange{ForkOffset: 4096, Offset: -1, Length: 4096})
	scan.add(fsForkRange{ForkOffset: 8192, Offset: 65536, Length: 1024, Slack: 3072})

	hash := scan.toHash("h1")
	if count := mustHashIntValue(t, hash, "range_count"); count != 3 {
		t.Errorf("range_count = %d, want 3", count)
	}
	if located := mustHashIntValue(t, hash, "located_bytes"); located != 4096+1024 {
		t.Errorf("located_bytes = %d, want only the ranges with a place on the image", located)
	}
}

// A compressed file whose resource fork is empty has its payload somewhere
// else, and saying so is the difference between a finding and a dead end.
func TestACompressedFileWithAnEmptyForkPointsElsewhere(t *testing.T) {
	empty := fsForkScan{
		Filesystem: "hfs", Path: "/small.txt", Compressed: true, Size: 0,
		Complete: true, WarningsAvailable: true,
	}
	if empty.HoldsPayload {
		t.Error("an empty fork claimed to hold a payload")
	}

	full := fsForkScan{
		Filesystem: "hfs", Path: "/big.txt", Compressed: true, Size: 40960,
		HoldsPayload: true, Complete: true, WarningsAvailable: true,
	}
	if !mustHashBoolValue(t, full.toHash("h1"), "holds_compressed_payload") {
		t.Error("a compressed file with a non-empty resource fork did not report the payload")
	}
}

// ------------------------------------------------------------ descriptor index

func TestTheDescriptorCapKeepsTheCountHonestPastIt(t *testing.T) {
	index := fsSecurityIndex{Filesystem: "ntfs", Complete: true, WarningsAvailable: true}
	for i := 0; i < fsAttrMaxDescriptors+3; i++ {
		index.add(fsSecurityIndexEntry{SecurityID: int64(i), DACLPresent: true})
	}

	hash := index.toHash("h1")
	if count := mustHashIntValue(t, hash, "descriptor_count"); count != int64(fsAttrMaxDescriptors+3) {
		t.Errorf("descriptor_count = %d, want the true %d", count, fsAttrMaxDescriptors+3)
	}
	if !mustHashBoolValue(t, hash, "descriptors_truncated") {
		t.Error("a list past the cap did not report as truncated")
	}
}

// ------------------------------------------------------------ the shared read window

// The rule the window read enforces is about the file, not about how it was
// named, which is why ntfs_read_stream and ntfs_read_file_at share it.
func TestAWindowInsideTheRecordedSizeButPastWhatWasLocatedIsAnError(t *testing.T) {
	reader := fsFileReader{ReaderAt: strings.NewReader("abcdefgh"), Size: 64, Located: 8}

	payload, errObj := unwrapPairNoFatal(fsReadWindow("probe", reader, 0, 4))
	if errObj != nil {
		t.Fatalf("a window inside the located bytes errored: %s", errObj.Inspect())
	}
	if bytes, ok := payload.(*object.Bytes); !ok || string(bytes.Value) != "abcd" {
		t.Fatalf("read returned %s", payload.Inspect())
	}

	// At or past the recorded size: an empty answer, which is how a caller
	// walks off the end.
	payload, errObj = unwrapPairNoFatal(fsReadWindow("probe", reader, 64, 4))
	if errObj != nil {
		t.Fatalf("a window past the recorded size errored: %s", errObj.Inspect())
	}
	if bytes, ok := payload.(*object.Bytes); !ok || len(bytes.Value) != 0 {
		t.Fatalf("a window past the end returned %s", payload.Inspect())
	}

	// Inside the recorded size, past what was located: the two numbers are the
	// finding, and zeroes would hide them.
	_, errObj = unwrapPairNoFatal(fsReadWindow("probe", reader, 16, 4))
	if errObj == nil {
		t.Fatal("a window past the located bytes returned data instead of an error")
	}
	for _, want := range []string{"16", "64", "8"} {
		if !containsSubstring(errObj.Message, want) {
			t.Errorf("the refusal did not name %s: %s", want, errObj.Message)
		}
	}
}

// ------------------------------------------------------------ dispatch

type xattrCase struct {
	name    string
	install func(t *testing.T)
	open    func() object.Object
	call    func(handle string) object.Object
	seen    func() string
	fail    func(t *testing.T, err error)
}

func xattrCases(t *testing.T) []xattrCase {
	t.Helper()

	ext := &fakeEXTSession{}
	hfs := &fakeHFSSession{}
	xfs := &fakeXFSSession{}

	return []xattrCase{
		{
			BuiltinNameExtXattrs,
			func(t *testing.T) {
				ext.xattrs = newXattrScan("ext", "/probe", fsAttrNodeInode)
				installFakeEXTBackend(t, &fakeEXTBackend{session: ext})
			},
			func() object.Object { return ExtOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return ExtXattrs(stringObj(h), stringObj("/probe")) },
			func() string { return ext.xattrsPath },
			func(t *testing.T, err error) { ext.xattrsErr = err },
		},
		{
			BuiltinNameHfsXattrs,
			func(t *testing.T) {
				hfs.xattrs = newXattrScan("hfs", "/probe", fsAttrNodeCNID)
				installFakeHFSBackend(t, &fakeHFSBackend{session: hfs})
			},
			func() object.Object { return HFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return HFSXattrs(stringObj(h), stringObj("/probe")) },
			func() string { return hfs.xattrsPath },
			func(t *testing.T, err error) { hfs.xattrsErr = err },
		},
		{
			BuiltinNameXfsXattrs,
			func(t *testing.T) {
				xfs.xattrs = newXattrScan("xfs", "/probe", fsAttrNodeInode)
				installFakeXFSBackend(t, &fakeXFSBackend{session: xfs})
			},
			func() object.Object { return XFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return XFSXattrs(stringObj(h), stringObj("/probe")) },
			func() string { return xfs.xattrsPath },
			func(t *testing.T, err error) { xfs.xattrsErr = err },
		},
	}
}

// Three builtins over three sessions sharing one method name is exactly the
// shape where a copied line returns another filesystem's answer silently.
func TestEachXattrBuiltinReadsItsOwnVolume(t *testing.T) {
	for _, tc := range xattrCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t)

			handle := openJournalHandle(t, tc.open)
			payload, err := unwrapPair(t, tc.call(handle))
			if err != nil {
				t.Fatalf("%s returned error: %s", tc.name, err.Inspect())
			}
			if seen := tc.seen(); seen != "/probe" {
				t.Errorf("%s passed %q to its session", tc.name, seen)
			}
			assertDeclaredFields(t, tc.name, payload, handle)
		})
	}
}

func TestAnAttributeLibraryErrorIsReportedAndNotRendered(t *testing.T) {
	for _, tc := range xattrCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t)
			tc.fail(t, errFakeLibrary)
			t.Cleanup(func() { tc.fail(t, nil) })

			handle := openJournalHandle(t, tc.open)
			payload, err := unwrapPairNoFatal(tc.call(handle))
			if err == nil {
				t.Fatalf("%s rendered an empty envelope instead of reporting the failure: %s",
					tc.name, payload.Inspect())
			}
			if !containsSubstring(err.Message, tc.name) {
				t.Errorf("%s did not name itself in its refusal: %s", tc.name, err.Message)
			}
		})
	}
}

func TestEveryNtfsAttributeBuiltinReturnsTheDeclaredFields(t *testing.T) {
	ntfs := &fakeNTFSSession{
		streams:       newStreamScan("ntfs", "/probe"),
		security:      fsSecurityScan{Filesystem: "ntfs", Path: "/probe", SecurityID: -1, Complete: true, WarningsAvailable: true},
		securityIndex: fsSecurityIndex{Filesystem: "ntfs", Complete: true, WarningsAvailable: true},
		reparse:       fsReparseScan{Filesystem: "ntfs", Path: "/probe", Complete: true, WarningsAvailable: true},
	}
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: ntfs})
	handle := openJournalHandle(t, func() object.Object { return NtfsOpen(stringObj("synthetic.img")) })

	cases := []struct {
		name string
		call func() object.Object
	}{
		{BuiltinNameNtfsStreams, func() object.Object {
			return NtfsStreams(stringObj(handle), stringObj("/probe"))
		}},
		{BuiltinNameNtfsSecurity, func() object.Object {
			return NtfsSecurity(stringObj(handle), stringObj("/probe"))
		}},
		{BuiltinNameNtfsSecurityIndex, func() object.Object {
			return NtfsSecurityDescriptors(stringObj(handle))
		}},
		{BuiltinNameNtfsReparse, func() object.Object {
			return NtfsReparse(stringObj(handle), stringObj("/probe"))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := unwrapPair(t, tc.call())
			if err != nil {
				t.Fatalf("%s returned error: %s", tc.name, err.Inspect())
			}
			assertDeclaredFields(t, tc.name, payload, handle)
		})
	}
}

func TestHfsResourceForkReturnsTheDeclaredFields(t *testing.T) {
	hfs := &fakeHFSSession{
		resourceFork: fsForkScan{
			Filesystem: "hfs", Path: "/probe", CNID: 42, Size: -1, DataForkSize: -1,
			Complete: true, WarningsAvailable: true,
		},
	}
	installFakeHFSBackend(t, &fakeHFSBackend{session: hfs})

	handle := openJournalHandle(t, func() object.Object { return HFSOpen(stringObj("synthetic.img")) })
	payload, err := unwrapPair(t, HFSResourceFork(stringObj(handle), stringObj("/probe")))
	if err != nil {
		t.Fatalf("hfs_resource_fork returned error: %s", err.Inspect())
	}
	assertDeclaredFields(t, BuiltinNameHfsResourceFork, payload, handle)
	if hfs.resourcePath != "/probe" {
		t.Errorf("hfs_resource_fork passed %q to its session", hfs.resourcePath)
	}
}

// The stream-content pair is addressed by three arguments rather than two, so
// the stream name has to reach the session intact.
func TestAStreamIsNamedToTheSessionAndNotGuessed(t *testing.T) {
	ntfs := &fakeNTFSSession{
		streamReader: fsFileReader{ReaderAt: strings.NewReader("[ZoneTransfer]"), Size: 14, Located: 14},
	}
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: ntfs})
	handle := openJournalHandle(t, func() object.Object { return NtfsOpen(stringObj("synthetic.img")) })

	payload, err := unwrapPair(t, NtfsReadStream(
		stringObj(handle), stringObj("/download.exe"), stringObj("Zone.Identifier"),
		intObj(0), intObj(14)))
	if err != nil {
		t.Fatalf("ntfs_read_stream returned error: %s", err.Inspect())
	}
	if ntfs.streamName != "Zone.Identifier" {
		t.Errorf("stream name reached the session as %q", ntfs.streamName)
	}
	if ntfs.streamsPath != "/download.exe" {
		t.Errorf("path reached the session as %q", ntfs.streamsPath)
	}
	bytes, ok := payload.(*object.Bytes)
	if !ok {
		t.Fatalf("ntfs_read_stream returned %T, want BYTES", payload)
	}
	if string(bytes.Value) != "[ZoneTransfer]" {
		t.Errorf("read back %q", string(bytes.Value))
	}
}

func TestExtractStreamReturnsTheDeclaredFields(t *testing.T) {
	ntfs := &fakeNTFSSession{
		streamReader: fsFileReader{ReaderAt: strings.NewReader("payload"), Size: 7, Located: 7},
	}
	installFakeNTFSBackend(t, &fakeNTFSBackend{session: ntfs})
	handle := openJournalHandle(t, func() object.Object { return NtfsOpen(stringObj("synthetic.img")) })

	dest := t.TempDir() + "/ads.bin"
	payload, err := unwrapPair(t, NtfsExtractStream(
		stringObj(handle), stringObj("/host.txt"), stringObj("payload"), stringObj(dest)))
	if err != nil {
		t.Fatalf("ntfs_extract_stream returned error: %s", err.Inspect())
	}
	assertDeclaredStreamExtractFields(t, payload)
	hash := payload.(*object.Hash)
	if name := mustHashStringValue(t, hash, "stream"); name != "payload" {
		t.Errorf("the envelope named the stream %q", name)
	}
	if written := mustHashIntValue(t, hash, "bytes_written"); written != 7 {
		t.Errorf("bytes_written = %d, want 7", written)
	}
}

// assertDeclaredStreamExtractFields checks the extraction envelope both ways,
// since the shared conformance probe does not cover filesystem forensics.
func assertDeclaredStreamExtractFields(t *testing.T, payload object.Object) {
	t.Helper()
	assertDeclaredFieldsNoHandle(t, BuiltinNameNtfsExtractStream, payload)
}

func assertDeclaredFieldsNoHandle(t *testing.T, name string, payload object.Object) {
	t.Helper()

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("%s payload is not HASH. got=%T", name, payload)
	}

	got := map[string]bool{}
	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			t.Fatalf("%s returned a non-STRING key %s", name, pair.Key.Inspect())
		}
		got[key.Value] = true
	}

	declared, ok := builtinDocs[name]
	if !ok {
		t.Fatalf("%s has no metadata entry", name)
	}
	for _, field := range declared.returns.fields {
		if !got[field] {
			t.Errorf("%s declares field %q but did not return it", name, field)
		}
		delete(got, field)
	}
	for field := range got {
		t.Errorf("%s returned undeclared field %q", name, field)
	}
}

func TestEveryAttributeBuiltinChecksItsArity(t *testing.T) {
	cases := []struct {
		name string
		call func(args ...object.Object) object.Object
		want int
	}{
		{BuiltinNameNtfsStreams, NtfsStreams, 2},
		{BuiltinNameNtfsReadStream, NtfsReadStream, 5},
		{BuiltinNameNtfsExtractStream, NtfsExtractStream, 4},
		{BuiltinNameNtfsSecurity, NtfsSecurity, 2},
		{BuiltinNameNtfsSecurityIndex, NtfsSecurityDescriptors, 1},
		{BuiltinNameNtfsReparse, NtfsReparse, 2},
		{BuiltinNameExtXattrs, ExtXattrs, 2},
		{BuiltinNameXfsXattrs, XFSXattrs, 2},
		{BuiltinNameHfsXattrs, HFSXattrs, 2},
		{BuiltinNameHfsResourceFork, HFSResourceFork, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := make([]object.Object, 0, tc.want+1)
			for i := 0; i < tc.want+1; i++ {
				args = append(args, stringObj("x"))
			}

			_, err := unwrapPairNoFatal(tc.call(args...))
			if err == nil {
				t.Fatalf("%s accepted %d arguments, wants %d", tc.name, tc.want+1, tc.want)
			}
			if !containsSubstring(err.Message, "wrong number of arguments") {
				t.Errorf("%s refused too many arguments with: %s", tc.name, err.Message)
			}
		})
	}
}

func TestAnAttributePathMustBeAString(t *testing.T) {
	ext := &fakeEXTSession{xattrs: newXattrScan("ext", "/probe", fsAttrNodeInode)}
	installFakeEXTBackend(t, &fakeEXTBackend{session: ext})

	handle := openJournalHandle(t, func() object.Object { return ExtOpen(stringObj("synthetic.img")) })
	_, err := unwrapPairNoFatal(ExtXattrs(stringObj(handle), intObj(7)))
	if err == nil {
		t.Fatal("ext_xattrs accepted an INTEGER where a path belongs")
	}
	if !containsSubstring(err.Message, BuiltinNameExtXattrs) {
		t.Errorf("the refusal did not name the builtin: %s", err.Message)
	}
}
