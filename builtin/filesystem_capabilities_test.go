package builtin

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libhfs "github.com/aoiflux/libhfs"
	libntfs "github.com/aoiflux/libntfs"
	libxfat "github.com/aoiflux/libxfat"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

var errFakeFilesystemLibrary = errors.New("synthetic filesystem failure")

// fsFamily is one of the six filesystems wired so that a test written once
// runs against all of them. The *_capabilities and *_report builtins share the
// handle, the fake and the resolve path, so they share this table too.
type fsFamily struct {
	Name          string
	CapsBuiltin   string
	ReportBuiltin string
	Install       func(t *testing.T, caps fsCapabilitySet, capsErr error, report fsReport, reportErr error)
	Open          func() object.Object
	Capabilities  func(handle string) object.Object
	Report        func(handle string) object.Object
}

func fsFamilies() []fsFamily {
	return []fsFamily{
		{
			Name: "ntfs", CapsBuiltin: BuiltinNameNtfsCapabilities, ReportBuiltin: BuiltinNameNtfsReport,
			Install: func(t *testing.T, caps fsCapabilitySet, capsErr error, report fsReport, reportErr error) {
				installFakeNTFSBackend(t, &fakeNTFSBackend{session: &fakeNTFSSession{
					capabilities: caps, capabilitiesErr: capsErr, report: report, reportErr: reportErr,
				}})
			},
			Open:         func() object.Object { return NtfsOpen(stringObj("synthetic.img")) },
			Capabilities: func(h string) object.Object { return NtfsCapabilities(stringObj(h)) },
			Report:       func(h string) object.Object { return NtfsReport(stringObj(h)) },
		},
		{
			Name: "fat", CapsBuiltin: BuiltinNameFatCapabilities, ReportBuiltin: BuiltinNameFatReport,
			Install: func(t *testing.T, caps fsCapabilitySet, capsErr error, report fsReport, reportErr error) {
				installFakeFATBackend(t, &fakeFATBackend{session: &fakeFATSession{
					capabilities: caps, capabilitiesErr: capsErr, report: report, reportErr: reportErr,
				}})
			},
			Open:         func() object.Object { return FatOpen(stringObj("synthetic.img")) },
			Capabilities: func(h string) object.Object { return FatCapabilities(stringObj(h)) },
			Report:       func(h string) object.Object { return FatReport(stringObj(h)) },
		},
		{
			Name: "xfat", CapsBuiltin: BuiltinNameXfatCapabilities, ReportBuiltin: BuiltinNameXfatReport,
			Install: func(t *testing.T, caps fsCapabilitySet, capsErr error, report fsReport, reportErr error) {
				installFakeXFATBackend(t, &fakeXFATBackend{session: &fakeXFATSession{
					capabilities: caps, capabilitiesErr: capsErr, report: report, reportErr: reportErr,
				}})
			},
			Open:         func() object.Object { return XFATOpen(stringObj("synthetic.img")) },
			Capabilities: func(h string) object.Object { return XFATCapabilities(stringObj(h)) },
			Report:       func(h string) object.Object { return XFATReport(stringObj(h)) },
		},
		{
			Name: "ext", CapsBuiltin: BuiltinNameExtCapabilities, ReportBuiltin: BuiltinNameExtReport,
			Install: func(t *testing.T, caps fsCapabilitySet, capsErr error, report fsReport, reportErr error) {
				installFakeEXTBackend(t, &fakeEXTBackend{session: &fakeEXTSession{
					capabilities: caps, capabilitiesErr: capsErr, report: report, reportErr: reportErr,
				}})
			},
			Open:         func() object.Object { return ExtOpen(stringObj("synthetic.img")) },
			Capabilities: func(h string) object.Object { return ExtCapabilities(stringObj(h)) },
			Report:       func(h string) object.Object { return ExtReport(stringObj(h)) },
		},
		{
			Name: "hfs", CapsBuiltin: BuiltinNameHfsCapabilities, ReportBuiltin: BuiltinNameHfsReport,
			Install: func(t *testing.T, caps fsCapabilitySet, capsErr error, report fsReport, reportErr error) {
				installFakeHFSBackend(t, &fakeHFSBackend{session: &fakeHFSSession{
					capabilities: caps, capabilitiesErr: capsErr, report: report, reportErr: reportErr,
				}})
			},
			Open:         func() object.Object { return HFSOpen(stringObj("synthetic.img")) },
			Capabilities: func(h string) object.Object { return HFSCapabilities(stringObj(h)) },
			Report:       func(h string) object.Object { return HFSReport(stringObj(h)) },
		},
		{
			Name: "xfs", CapsBuiltin: BuiltinNameXfsCapabilities, ReportBuiltin: BuiltinNameXfsReport,
			Install: func(t *testing.T, caps fsCapabilitySet, capsErr error, report fsReport, reportErr error) {
				installFakeXFSBackend(t, &fakeXFSBackend{session: &fakeXFSSession{
					capabilities: caps, capabilitiesErr: capsErr, report: report, reportErr: reportErr,
				}})
			},
			Open:         func() object.Object { return XFSOpen(stringObj("synthetic.img")) },
			Capabilities: func(h string) object.Object { return XFSCapabilities(stringObj(h)) },
			Report:       func(h string) object.Object { return XFSReport(stringObj(h)) },
		},
	}
}

// openFamily installs the fake, opens a handle and returns it.
func openFamily(t *testing.T, family fsFamily, caps fsCapabilitySet, capsErr error, report fsReport, reportErr error) string {
	t.Helper()
	family.Install(t, caps, capsErr, report, reportErr)
	payload, errObj := unwrapPair(t, family.Open())
	if errObj != nil {
		t.Fatalf("%s open returned error: %s", family.Name, errObj.Inspect())
	}
	return mustHashStringValue(t, payload.(*object.Hash), "handle")
}

// theSixCapabilitySets pairs each library's own Capabilities struct with the
// set this tree renders from it.
func theSixCapabilitySets() []struct {
	Library any
	Set     fsCapabilitySet
} {
	return []struct {
		Library any
		Set     fsCapabilitySet
	}{
		{libntfs.Capabilities{}, ntfsCapabilitySet(libntfs.Capabilities{})},
		{libfat.Capabilities{}, fatCapabilitySet(libfat.Capabilities{})},
		{libxfat.Capabilities{}, xfatCapabilitySet(libxfat.Capabilities{})},
		{libext.Capabilities{}, extCapabilitySet(libext.Capabilities{})},
		{libhfs.Capabilities{}, hfsCapabilitySet(libhfs.Capabilities{})},
		{libxfs.Capabilities{}, xfsCapabilitySet(libxfs.Capabilities{})},
	}
}

// The drift guard. A capability this tree does not read is one a script will
// never see, and nothing else in the build would notice a library growing a
// field -- the answer would simply be quietly shorter than the library's.
//
// It runs in the other direction too: a name here that no longer matches a
// field means the rendering has outlived what it was written against.
func TestEveryCapabilityTheLibraryDeclaresIsReported(t *testing.T) {
	for _, pair := range theSixCapabilitySets() {
		set := pair.Set
		t.Run(set.Filesystem, func(t *testing.T) {
			rendered := map[string]int{}
			for _, capability := range set.Caps {
				rendered[capability.Name]++
			}

			nonBool := map[string]bool{}
			for _, name := range fsCapabilityNonBool[set.Filesystem] {
				nonBool[name] = true
			}

			declared := map[string]bool{}
			structType := reflect.TypeOf(pair.Library)
			for i := 0; i < structType.NumField(); i++ {
				field := structType.Field(i)
				tag := strings.Split(field.Tag.Get("json"), ",")[0]
				if tag == "" || tag == "-" {
					t.Fatalf("%s.%s carries no json name to match on", structType, field.Name)
				}

				if field.Type.Kind() != reflect.Bool {
					if !nonBool[tag] {
						t.Fatalf("%s.%s is a %s rather than a capability and is not listed in fsCapabilityNonBool; decide what it is before it is dropped",
							structType, field.Name, field.Type.Kind())
					}
					continue
				}

				name := tag
				if alias, ok := fsCapabilityAliases[tag]; ok {
					name = alias
				}
				declared[name] = true

				switch rendered[name] {
				case 1:
				case 0:
					t.Errorf("%s declares %q and %s_capabilities does not report it", structType, tag, set.Filesystem)
				default:
					t.Errorf("%s_capabilities reports %q %d times", set.Filesystem, name, rendered[name])
				}
			}

			for name := range rendered {
				if !declared[name] {
					t.Errorf("%s_capabilities reports %q, which %s does not declare", set.Filesystem, name, structType)
				}
			}
		})
	}
}

// Every answer has to say where it came from, or volume_specific is a list
// assembled from whichever rows happened to be filled in.
func TestEveryCapabilityKnowsWhetherItCameFromTheFormatOrTheVolume(t *testing.T) {
	for _, pair := range theSixCapabilitySets() {
		set := pair.Set
		t.Run(set.Filesystem, func(t *testing.T) {
			for _, capability := range set.Caps {
				switch capability.Source {
				case fsCapFromFormat, fsCapFromVolume:
				default:
					t.Errorf("%s: %q has source %q, want %q or %q",
						set.Filesystem, capability.Name, capability.Source, fsCapFromFormat, fsCapFromVolume)
				}
			}
		})
	}
}

// The headline. libhfs declares nine capabilities and none of them is a
// creation time -- yet HFS has recorded one since 1985. Rendering the silence
// as false would put the opposite of the truth in an examiner's document, so
// the question comes back unanswered and appears in neither supported nor
// unsupported.
func TestAQuestionAReaderDoesNotAnswerIsNotAnsweredNo(t *testing.T) {
	set := hfsCapabilitySet(libhfs.Capabilities{})

	for _, capability := range set.Caps {
		if capability.Name == "creation_times" {
			t.Fatal("libhfs has grown a creation_times capability; this test and the prose around it are now wrong")
		}
	}

	supported, unsupported := set.split()
	if contains(supported, "creation_times") || contains(unsupported, "creation_times") {
		t.Fatal("creation_times was answered for HFS, which libhfs never said")
	}
	if !contains(set.unanswered(), "creation_times") {
		t.Fatal("creation_times should be unanswered for HFS")
	}
	if set.unanswered()[0] == "" {
		t.Fatal("unanswered should be a list of names")
	}
}

// The six do not answer the same number of questions, and the spread is the
// reason `unanswered` exists at all. These counts are quoted in the docs and in
// each builtin's summary, so a library that grows or drops a field fails here
// beside the prose it would have made wrong.
func TestTheSixAnswerDifferentNumbersOfTheSameQuestions(t *testing.T) {
	want := map[string]int{
		"ntfs":  18,
		"fat":   18,
		"exfat": 18,
		"ext":   17,
		"xfs":   15,
		"hfs":   8,
	}

	for _, pair := range theSixCapabilitySets() {
		set := pair.Set
		answered := len(fsCoreCapabilities) - len(set.unanswered())
		if answered != want[set.Filesystem] {
			t.Errorf("%s answers %d of the %d core questions, want %d (unanswered: %v)",
				set.Filesystem, answered, len(fsCoreCapabilities), want[set.Filesystem], set.unanswered())
		}
	}
}

// Two libraries call the journal question `journal` and four call it
// `journaled`. A script branching on a capability name should not have to know
// which filesystem it is looking at to spell it.
func TestTheJournalQuestionIsSpelledTheSameOnAllSix(t *testing.T) {
	for _, pair := range theSixCapabilitySets() {
		set := pair.Set
		if set.Filesystem == "hfs" || contains(set.answered(), "journaled") {
			continue
		}
		t.Errorf("%s does not report a journaled capability: %v", set.Filesystem, set.answered())
	}

	// And the un-normalised spelling must not leak through beside it.
	for _, pair := range theSixCapabilitySets() {
		if contains(pair.Set.answered(), "journal") {
			t.Errorf("%s reports the library's own spelling `journal` as well", pair.Set.Filesystem)
		}
	}
}

// ext2, ext3 and ext4 are one format behind feature flags, so an answer cached
// from one volume is wrong about the next. That is what volume_specific exists
// to say, and ext is where it says the most.
func TestAnAnswerReadFromTheVolumeIsMarkedAsSuch(t *testing.T) {
	cases := []struct {
		set      fsCapabilitySet
		volume   []string
		notCount int
	}{
		{ntfsCapabilitySet(libntfs.Capabilities{}), []string{"change_journal"}, 1},
		{extCapabilitySet(libext.Capabilities{}), []string{"creation_times", "sub_second_timestamps", "journaled", "bigalloc", "case_sensitive"}, 11},
		{fatCapabilitySet(libfat.Capabilities{}), []string{"second_fat", "fs_info_sector", "backup_boot_sector"}, 3},
		{xfatCapabilitySet(libxfat.Capabilities{}), []string{"second_fat"}, 1},
		{hfsCapabilitySet(libhfs.Capabilities{}), []string{"unicode_names", "journaled", "case_sensitive"}, 9},
		{xfsCapabilitySet(libxfs.Capabilities{}), []string{"creation_times", "metadata_checksums", "needs_repair"}, 12},
	}

	for _, tc := range cases {
		t.Run(tc.set.Filesystem, func(t *testing.T) {
			specific := tc.set.volumeSpecific()
			for _, name := range tc.volume {
				if !contains(specific, name) {
					t.Errorf("%q should be volume state on %s; volume_specific is %v", name, tc.set.Filesystem, specific)
				}
			}
			if len(specific) != tc.notCount {
				t.Errorf("%s has %d volume-specific answers, want %d: %v",
					tc.set.Filesystem, len(specific), tc.notCount, specific)
			}
		})
	}
}

// On HFS every answer is volume state, because "HFS" names three formats and
// libhfs decides which it opened before it answers anything.
func TestOnHfsThereIsNoSuchThingAsAFormatAnswer(t *testing.T) {
	set := hfsCapabilitySet(libhfs.Capabilities{})
	if len(set.volumeSpecific()) != len(set.Caps) {
		t.Fatalf("%d of %d HFS answers are volume state, want all of them",
			len(set.volumeSpecific()), len(set.Caps))
	}
}

// The complete/incomplete_reason pair follows the same rule as everywhere else
// in this family: complete only when there is no known gap, and a reason that
// counts rather than lists, because the list is the field beside it.
func TestACapabilitySetWithNothingUnansweredIsComplete(t *testing.T) {
	full := fsCapabilitySet{Filesystem: "synthetic"}
	for _, name := range fsCoreCapabilities {
		full.Caps = append(full.Caps, fsCapability{Name: name, Supported: true, Source: fsCapFromFormat})
	}

	hash := full.toHash("handle-1")
	if complete, ok := hashValueByKey(hash, "complete").(*object.Boolean); !ok || !complete.Value {
		t.Fatal("a set answering every core question should be complete")
	}
	if reason := mustHashStringValue(t, hash, "incomplete_reason"); reason != "" {
		t.Fatalf("a complete set should carry no reason, got %q", reason)
	}

	short := hfsCapabilitySet(libhfs.Capabilities{}).toHash("handle-1")
	if complete, ok := hashValueByKey(short, "complete").(*object.Boolean); !ok || complete.Value {
		t.Fatal("HFS answers ten fewer questions and should not be complete")
	}
	if reason := mustHashStringValue(t, short, "incomplete_reason"); !strings.Contains(reason, "unanswered rather than answered no") {
		t.Fatalf("the reason should say what unanswered means, got %q", reason)
	}
}

// --- through the builtins ---------------------------------------------------

func TestEveryCapabilitiesBuiltinReturnsTheDeclaredFields(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.CapsBuiltin, func(t *testing.T) {
			handle := openFamily(t, family, fsCapabilitySet{Filesystem: family.Name}, nil, fsReport{}, nil)

			payload, errObj := unwrapPair(t, family.Capabilities(handle))
			if errObj != nil {
				t.Fatalf("%s returned error: %s", family.CapsBuiltin, errObj.Inspect())
			}
			assertDeclaredFields(t, family.CapsBuiltin, payload, handle)
		})
	}
}

func TestEachCapabilitiesBuiltinAsksItsOwnHandle(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.CapsBuiltin, func(t *testing.T) {
			handle := openFamily(t, family,
				fsCapabilitySet{Filesystem: family.Name, Caps: []fsCapability{
					{Name: "sparse_files", Supported: true, Source: fsCapFromFormat},
				}}, nil, fsReport{}, nil)

			payload, errObj := unwrapPair(t, family.Capabilities(handle))
			if errObj != nil {
				t.Fatalf("%s returned error: %s", family.CapsBuiltin, errObj.Inspect())
			}
			hash := payload.(*object.Hash)
			if got := mustHashStringValue(t, hash, "filesystem"); got != family.Name {
				t.Fatalf("%s reported filesystem %q, want %q", family.CapsBuiltin, got, family.Name)
			}
			if count, ok := hashValueByKey(hash, "capability_count").(*object.Integer); !ok || count.Value != 1 {
				t.Fatalf("%s did not carry the session's own capability set", family.CapsBuiltin)
			}
		})
	}
}

func TestAFilesystemLibraryErrorIsReportedAndNotRendered(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.CapsBuiltin, func(t *testing.T) {
			handle := openFamily(t, family, fsCapabilitySet{}, errFakeFilesystemLibrary, fsReport{}, nil)

			payload, errObj := unwrapPair(t, family.Capabilities(handle))
			if errObj == nil {
				t.Fatalf("%s rendered an answer for a failed read: %s", family.CapsBuiltin, payload.Inspect())
			}
			if _, rendered := payload.(*object.Hash); rendered {
				t.Fatalf("%s rendered an answer beside its error: %s", family.CapsBuiltin, payload.Inspect())
			}
			if !strings.Contains(errObj.Message, family.CapsBuiltin) {
				t.Fatalf("the error should name the builtin, got %q", errObj.Message)
			}
			if !strings.Contains(errObj.Message, errFakeFilesystemLibrary.Error()) {
				t.Fatalf("the error should quote the library, got %q", errObj.Message)
			}
		})
	}
}

func TestEveryCapabilitiesBuiltinChecksItsArity(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.CapsBuiltin, func(t *testing.T) {
			handle := openFamily(t, family, fsCapabilitySet{Filesystem: family.Name}, nil, fsReport{}, nil)

			for _, args := range [][]object.Object{
				{},
				{stringObj(handle), stringObj("extra")},
			} {
				result := callBuiltinByName(t, family.CapsBuiltin, args...)
				_, errObj := unwrapPair(t, result)
				if errObj == nil {
					t.Fatalf("%s accepted %d arguments", family.CapsBuiltin, len(args))
				}
				if !strings.Contains(errObj.Message, "wrong number of arguments") {
					t.Fatalf("unexpected arity error: %q", errObj.Message)
				}
			}
		})
	}
}

func TestACapabilitiesHandleMustBeAKnownOne(t *testing.T) {
	for _, family := range fsFamilies() {
		t.Run(family.CapsBuiltin, func(t *testing.T) {
			family.Install(t, fsCapabilitySet{}, nil, fsReport{}, nil)
			if _, errObj := unwrapPair(t, family.Capabilities("no-such-handle")); errObj == nil {
				t.Fatalf("%s accepted an unknown handle", family.CapsBuiltin)
			}
		})
	}
}

// --- helpers ----------------------------------------------------------------

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// callBuiltinByName reaches a builtin through the registry, so an arity test
// exercises the same entry point a program does.
func callBuiltinByName(t *testing.T, name string, args ...object.Object) object.Object {
	t.Helper()
	for _, entry := range Builtins {
		if entry.Name == name {
			return entry.Builtin.Fn(args...)
		}
	}
	t.Fatalf("no builtin named %q is registered", name)
	return nil
}

// --- against real bytes -----------------------------------------------------

// `source` is a claim about where an answer came from, and this is what makes
// it a fact rather than a label: two images identical but for the number of
// allocation tables must differ in exactly the one answer that is read from the
// boot record, and in nothing else.
func TestARealFatVolumeAnswersSecondFatFromItsBootRecord(t *testing.T) {
	mirrored, err := openRealFATSession(t, buildFAT16Image(t, 2, 0)).Capabilities()
	if err != nil {
		t.Fatalf("capabilities of the mirrored image: %v", err)
	}
	single, err := openRealFATSession(t, buildFAT16Image(t, 1, 0)).Capabilities()
	if err != nil {
		t.Fatalf("capabilities of the single-FAT image: %v", err)
	}

	if len(mirrored.Caps) != len(single.Caps) {
		t.Fatalf("the two images declared %d and %d capabilities", len(mirrored.Caps), len(single.Caps))
	}

	found := false
	for i := range mirrored.Caps {
		a, b := mirrored.Caps[i], single.Caps[i]
		if a.Name != "second_fat" {
			if a != b {
				t.Errorf("%q differs between two images that differ only in their FAT count: %+v vs %+v", a.Name, a, b)
			}
			continue
		}
		found = true
		if !a.Supported {
			t.Error("the two-FAT image should report second_fat")
		}
		if b.Supported {
			t.Error("the one-FAT image should not report second_fat")
		}
		if a.Source != fsCapFromVolume {
			t.Errorf("second_fat is read from the boot record, not fixed by FAT; source = %q", a.Source)
		}
	}
	if !found {
		t.Fatal("libfat no longer declares second_fat")
	}
}

// The consequential answer, from the real library rather than a fake: a FAT
// identity is a slot, and the report family reads this to decide whether its
// own identity column can be diffed.
func TestARealFatVolumeDeclaresItsIdentityUnstable(t *testing.T) {
	set, err := openRealFATSession(t, buildFAT16Image(t, 2, 0)).Capabilities()
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}

	_, unsupported := set.split()
	if !contains(unsupported, "stable_file_identity") {
		t.Fatalf("FAT should declare no stable identity; unsupported = %v", unsupported)
	}
	if contains(set.unanswered(), "stable_file_identity") {
		t.Fatal("libfat does answer this one, so it must not be reported as unanswered")
	}

	report := fsReport{}
	fsReportIdentity(&report, set, fsIdentityDirSlot)
	if !report.IdentityStableAnswered || report.IdentityStable {
		t.Fatalf("a report over this volume should carry answered=true stable=false, got %v/%v",
			report.IdentityStableAnswered, report.IdentityStable)
	}
}
