package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

// openTestCase opens a case and registers its cleanup. Tests in this package
// share a process, so a case left open by one would be recorded into by the
// next.
func openTestCase(t *testing.T, id, examiner string, options ...object.Object) *object.Hash {
	t.Helper()
	resetCustodyForTesting()
	t.Cleanup(resetCustodyForTesting)

	args := append([]object.Object{stringObj(id), stringObj(examiner)}, options...)
	value, errObj := unwrapPair(t, CaseOpen(args...))
	if errObj != nil {
		t.Fatalf("case_open failed: %s", errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("case_open returned %T, want HASH", value)
	}
	return hash
}

// manifestSection pulls one top-level section out of a manifest.
func manifestSection(t *testing.T, manifest *object.Hash, key string) *object.Hash {
	t.Helper()
	section, ok := mustHashValue(t, manifest, key).(*object.Hash)
	if !ok {
		t.Fatalf("manifest section %q is not a HASH", key)
	}
	return section
}

func manifestArray(t *testing.T, manifest *object.Hash, key string) []object.Object {
	t.Helper()
	array, ok := mustHashValue(t, manifest, key).(*object.Array)
	if !ok {
		t.Fatalf("manifest section %q is not an ARRAY", key)
	}
	return array.Elements
}

func currentManifest(t *testing.T) *object.Hash {
	t.Helper()
	value, errObj := unwrapPair(t, CaseManifest())
	if errObj != nil {
		t.Fatalf("case_manifest failed: %s", errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("case_manifest returned %T, want HASH", value)
	}
	return hash
}

func TestCaseOpenRecordsWhoAndWhen(t *testing.T) {
	opened := openTestCase(t, "IR-2026-0413", "G. Gogia")

	if got := mustHashStringValue(t, opened, "id"); got != "IR-2026-0413" {
		t.Fatalf("id = %q", got)
	}
	if got := mustHashStringValue(t, opened, "examiner"); got != "G. Gogia" {
		t.Fatalf("examiner = %q", got)
	}
	if got := mustHashStringValue(t, opened, "hash_policy"); got != "none" {
		t.Fatalf("hash_policy = %q, want the default \"none\"", got)
	}
	if mustHashStringValue(t, opened, "opened_at") == "" {
		t.Fatal("opened_at is empty")
	}

	manifest := currentManifest(t)
	caseInfo := manifestSection(t, manifest, "case")
	if got := mustHashStringValue(t, caseInfo, "status"); got != "open" {
		t.Fatalf("status = %q, want open", got)
	}
	if got := mustHashStringValue(t, caseInfo, "closed_at"); got != "" {
		t.Fatalf("closed_at = %q on an open case; a zero time in a court document is worse than a blank", got)
	}

	tool := manifestSection(t, manifest, "tool")
	for _, key := range []string{"version", "go_version", "os", "arch"} {
		if mustHashStringValue(t, tool, key) == "" {
			t.Fatalf("tool.%s is empty; the manifest cannot name the build that produced it", key)
		}
	}
}

// The whole design rests on this: a program that does not open a case must be
// unaffected by the feature existing.
func TestNothingIsRecordedWithoutACase(t *testing.T) {
	resetCustodyForTesting()

	if custodyActive.Load() {
		t.Fatal("custody is active with no case open")
	}

	// The hooks the openers and resolvers call must be safe to invoke with no
	// case, because that is the overwhelmingly common state.
	custodyRecordOpen("raw_open", "raw-handle-1", "some-image.dd")
	custodyRecordTouch("raw_read_at", "raw-handle-1")

	if _, errObj := unwrapPairNoFatal(CaseManifest()); errObj == nil {
		t.Fatal("case_manifest succeeded with no case ever opened")
	}
}

func TestCaseOpenRefusesWhatItCannotStandBehind(t *testing.T) {
	cases := []struct {
		name string
		args []object.Object
		want string
	}{
		{"no examiner", []object.Object{stringObj("IR-1"), stringObj("   ")}, "examiner must not be empty"},
		{"no id", []object.Object{stringObj(""), stringObj("examiner")}, "case id must not be empty"},
		{"too few arguments", []object.Object{stringObj("IR-1")}, "wrong number of arguments"},
		{"a non-string id", []object.Object{intObj(1), stringObj("examiner")}, "argument 1 to `case_open` must be STRING"},
		{
			"an unknown hash policy",
			[]object.Object{stringObj("IR-1"), stringObj("examiner"), makeHashObject(map[string]object.Object{"hash": stringObj("sha3")})},
			"unknown hash policy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetCustodyForTesting()
			t.Cleanup(resetCustodyForTesting)

			_, errObj := unwrapPairNoFatal(CaseOpen(tc.args...))
			if errObj == nil {
				t.Fatal("want an error, got none")
			}
			if !strings.Contains(errObj.Message, tc.want) {
				t.Fatalf("message %q does not contain %q", errObj.Message, tc.want)
			}
		})
	}
}

// Two open cases would mean evidence recorded against whichever happened to be
// last, which is the one failure mode a custody record cannot have.
func TestOnlyOneCaseIsOpenAtATime(t *testing.T) {
	openTestCase(t, "IR-1", "examiner")

	_, errObj := unwrapPairNoFatal(CaseOpen(stringObj("IR-2"), stringObj("examiner")))
	if errObj == nil {
		t.Fatal("a second case opened while the first was still open")
	}
	if !strings.Contains(errObj.Message, "still open") {
		t.Fatalf("unhelpful message: %s", errObj.Message)
	}

	if _, errObj := unwrapPair(t, CaseClose()); errObj != nil {
		t.Fatalf("case_close failed: %s", errObj.Message)
	}
	if _, errObj := unwrapPairNoFatal(CaseOpen(stringObj("IR-2"), stringObj("examiner"))); errObj != nil {
		t.Fatalf("a new case could not be opened after the first closed: %s", errObj.Message)
	}
	resetCustodyForTesting()
}

func TestCaseNoteLandsInTheTimeline(t *testing.T) {
	openTestCase(t, "IR-1", "examiner")

	if _, errObj := unwrapPair(t, CaseNote(stringObj("acquired the image from the evidence locker"))); errObj != nil {
		t.Fatalf("case_note failed: %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, CaseNote(
		stringObj("seal number"),
		makeHashObject(map[string]object.Object{"seal": stringObj("EV-99812")}),
	)); errObj != nil {
		t.Fatalf("case_note with data failed: %s", errObj.Message)
	}

	timeline := manifestArray(t, currentManifest(t), "timeline")
	if len(timeline) != 3 {
		t.Fatalf("timeline has %d entries, want case_open plus two notes", len(timeline))
	}

	second, ok := timeline[2].(*object.Hash)
	if !ok {
		t.Fatalf("timeline entry is %T, want HASH", timeline[2])
	}
	if got := mustHashStringValue(t, second, "detail"); got != "seal number" {
		t.Fatalf("detail = %q", got)
	}
	data, ok := mustHashValue(t, second, "data").(*object.Hash)
	if !ok {
		t.Fatal("the note's data did not survive into the manifest")
	}
	if got := mustHashStringValue(t, data, "seal"); got != "EV-99812" {
		t.Fatalf("seal = %q", got)
	}
}

func TestCaseCloseSealsTheRecord(t *testing.T) {
	openTestCase(t, "IR-1", "examiner")

	value, errObj := unwrapPair(t, CaseClose())
	if errObj != nil {
		t.Fatalf("case_close failed: %s", errObj.Message)
	}
	manifest, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("case_close returned %T, want HASH", value)
	}

	caseInfo := manifestSection(t, manifest, "case")
	if got := mustHashStringValue(t, caseInfo, "status"); got != "closed" {
		t.Fatalf("status = %q, want closed", got)
	}
	if mustHashStringValue(t, caseInfo, "closed_at") == "" {
		t.Fatal("closed_at is empty on a closed case")
	}

	if custodyActive.Load() {
		t.Fatal("custody is still active after case_close; the openers would keep recording")
	}

	// A closed case can still be read -- that is the entire point of it -- but
	// nothing more can be added to it.
	if _, errObj := unwrapPairNoFatal(CaseNote(stringObj("an afterthought"))); errObj == nil {
		t.Fatal("a note was accepted after the case closed")
	}
	if _, errObj := unwrapPairNoFatal(CaseClose()); errObj == nil {
		t.Fatal("a closed case closed again")
	}
	if _, errObj := unwrapPairNoFatal(CaseManifest()); errObj != nil {
		t.Fatalf("a closed case's manifest is unreadable: %s", errObj.Message)
	}
}

// The manifest has to answer "was anything abnormal while this ran?" with a
// number rather than a reassurance.
func TestManifestCarriesTheSecurityTelemetry(t *testing.T) {
	openTestCase(t, "IR-1", "examiner")

	telemetry := manifestSection(t, currentManifest(t), "security_telemetry")
	for _, key := range []string{"signature_failed", "debugger_detected", "command_attempt"} {
		if _, ok := telemetry.Pairs[(&object.String{Value: key}).HashKey()]; !ok {
			t.Fatalf("security_telemetry is missing %q", key)
		}
	}
}

func TestManifestReportsTheHashPolicyItActuallyUsed(t *testing.T) {
	openTestCase(t, "IR-1", "examiner",
		makeHashObject(map[string]object.Object{"hash": stringObj("sha256")}))

	integrity := manifestSection(t, currentManifest(t), "integrity")
	if got := mustHashStringValue(t, integrity, "hash_policy"); got != "sha256" {
		t.Fatalf("hash_policy = %q", got)
	}
	if got := mustHashIntValue(t, integrity, "sources_total"); got != 0 {
		t.Fatalf("sources_total = %d on a case with no evidence", got)
	}
}

func TestCustodyBuiltinsAreRegistered(t *testing.T) {
	for _, name := range []string{
		BuiltinNameCaseOpen,
		BuiltinNameCaseNote,
		BuiltinNameCaseManifest,
		BuiltinNameCaseClose,
	} {
		if GetBuiltinByName(name) == nil {
			t.Fatalf("%s is not registered", name)
		}
		if got := CapabilityCategory(name); got != "chain of custody" {
			t.Fatalf("CapabilityCategory(%q) = %q", name, got)
		}
	}
}
