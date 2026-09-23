package builtin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// viewTestRecord seals the 200-byte fixture with 30..180 carrying `restricted`
// and the rest `open`, at 64-byte segments: five segments, the middle three of
// which are restricted.
func viewTestRecord(t *testing.T) object.Object {
	t.Helper()
	source, dest, _ := recordFixture(t)
	restricted := mustHash(t, RecordClassifyRange(intObj(30), intObj(150), stringObj("restricted")))
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest),
		recordArray(restricted), recordSealOpts(nil)))
	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	t.Cleanup(func() { RecordClose(handle) })
	return handle
}

func viewArray(labels ...string) object.Object {
	elements := make([]object.Object, 0, len(labels))
	for _, label := range labels {
		elements = append(elements, stringObj(label))
	}
	return &object.Array{Elements: elements}
}

// A view releases the classes it names and holds back everything else, and the
// two sides add up to the record.
func TestAViewReleasesWhatItNamesAndHoldsBackTheRest(t *testing.T) {
	recordTestCase(t)
	handle := viewTestRecord(t)
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open")))

	preview := mustHash(t, ViewPreview(handle, stringObj("counsel")))

	total := mustHashIntValue(t, preview, "plaintext_length")
	granted := mustHashIntValue(t, preview, "granted_bytes")
	withheld := mustHashIntValue(t, preview, "withheld_bytes")
	if total != 200 || granted+withheld != total {
		t.Fatalf("granted %d + withheld %d does not account for %d bytes", granted, withheld, total)
	}
	// The spans are 0..30 open, 30..180 restricted, 180..200 open, split at 64
	// bytes. A segment never straddles a span, so the open side is segment 0
	// (30 bytes) and the last segment (20 bytes).
	if granted != 50 {
		t.Fatalf("the open spans are 30 and 20 bytes, so a view over `open` grants 50, got %d", granted)
	}
	if mustHashIntValue(t, preview, "granted_segments") != 2 {
		t.Fatalf("two segments carry `open`, preview says %d",
			mustHashIntValue(t, preview, "granted_segments"))
	}
	if mustHashBoolValue(t, preview, "discloses_whole_record") {
		t.Fatal("a view over one of two classes claims to disclose the whole record")
	}
	if mustHashBoolValue(t, preview, "discloses_nothing") {
		t.Fatal("a view granting 50 bytes claims to disclose nothing")
	}
	if !mustHashBoolValue(t, preview, "reads_no_plaintext") {
		t.Fatal("a preview should not need plaintext and should say so")
	}

	// The two open runs are not adjacent, so they must not have merged.
	runs, ok := mustHashValue(t, preview, "granted_runs").(*object.Array)
	if !ok || len(runs.Elements) != 2 {
		t.Fatalf("expected two granted runs at 0 and 180, got %s",
			mustHashValue(t, preview, "granted_runs").Inspect())
	}
	first, _ := runs.Elements[0].(*object.Hash)
	last, _ := runs.Elements[1].(*object.Hash)
	if mustHashIntValue(t, first, "offset") != 0 || mustHashIntValue(t, first, "length") != 30 {
		t.Fatalf("the first granted run is not 0+30: %s", runs.Elements[0].Inspect())
	}
	if mustHashIntValue(t, last, "offset") != 180 || mustHashIntValue(t, last, "length") != 20 {
		t.Fatalf("the last granted run is not 180+20: %s", runs.Elements[1].Inspect())
	}
	if mustHashStringValue(t, first, "label") != "open" {
		t.Fatalf("the granted run is not labelled open: %s", runs.Elements[0].Inspect())
	}

	// The restricted middle is three contiguous segments of one class, so it
	// merges into exactly one withheld run.
	withheldRuns, ok := mustHashValue(t, preview, "withheld_runs").(*object.Array)
	if !ok || len(withheldRuns.Elements) != 1 {
		t.Fatalf("three adjacent restricted segments should merge into one run, got %s",
			mustHashValue(t, preview, "withheld_runs").Inspect())
	}
	middle, _ := withheldRuns.Elements[0].(*object.Hash)
	if mustHashIntValue(t, middle, "offset") != 30 || mustHashIntValue(t, middle, "length") != 150 {
		t.Fatalf("the withheld run is not 30+150: %s", withheldRuns.Elements[0].Inspect())
	}
	if mustHashIntValue(t, middle, "first_segment") != 1 || mustHashIntValue(t, middle, "last_segment") != 3 {
		t.Fatalf("the withheld run does not cite segments 1..3: %s", withheldRuns.Elements[0].Inspect())
	}
	t.Logf("a view over `open` releases %d bytes in 2 runs and holds back %d in 1", granted, withheld)
}

// The trap this family could most easily fall into: a view whose spelling
// differs from the declaration silently granting nothing.
func TestAViewResolvesClassesThroughTheRuleThatTaggedThem(t *testing.T) {
	recordTestCase(t)
	handle := viewTestRecord(t)

	// Declared as "open"; named here with different case and spacing, which is
	// what an examiner types at two in the morning.
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("  OPEN  ")))
	preview := mustHash(t, ViewPreview(handle, stringObj("counsel")))
	if got := mustHashIntValue(t, preview, "granted_bytes"); got != 50 {
		t.Fatalf("a view naming `  OPEN  ` granted %d bytes, want the 50 that `open` carries", got)
	}
	// And the view itself is found under a differently spelled name too.
	if _, errObj := unwrapPairNoFatal(ViewPreview(handle, stringObj("Counsel"))); errObj != nil {
		t.Fatalf("a view declared as `counsel` is not found as `Counsel`: %s", errObj.Message)
	}
	t.Log("spacing and case reach the same classes the declaration tagged")
}

// The same rounding reads opposite ways for two views, and the record cannot
// state the direction on its own because nothing orders the classes.
func TestARoundingReadsOppositeWaysForTwoViews(t *testing.T) {
	recordTestCase(t)
	source, dest, _ := recordFixture(t)

	// The shape of a disclosure review: withhold by default, release the
	// passage that was read. Rounding grows the released class, so it releases
	// bytes nobody cleared -- 12 of them.
	ranges := recordArray(mustHash(t, RecordClassifyRange(intObj(20), intObj(4), stringObj("open"))))
	sealed := mustHash(t, RecordSealQuantised(stringObj(source), stringObj(dest), ranges,
		makeHashObject(map[string]object.Object{
			"default": stringObj("restricted"), "segment_size": intObj(16),
			"quantum": intObj(16), "sign": boolObj(false), "rounds_to": stringObj("open"),
		})))
	if extra := mustHashIntValue(t, sealed, "quantised_extra"); extra != 12 {
		t.Fatalf("12 bytes should have moved into open, record says %d", extra)
	}

	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)

	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open")))
	mustHash(t, ViewDefine(stringObj("internal"), viewArray("restricted")))

	// The view that GRANTS the rounded class receives the moved bytes.
	wide := mustHash(t, ViewPreview(handle, stringObj("counsel")))
	if !mustHashBoolValue(t, wide, "rounds_to_granted") {
		t.Fatal("a view granting `open` does not notice that rounding grew `open`")
	}
	wideEffect := mustHashStringValue(t, wide, "rounding_effect")
	if !strings.Contains(wideEffect, "releases up to 12 bytes") {
		t.Fatalf("the granting view is not told it receives the rounded bytes: %s", wideEffect)
	}

	// The view that does NOT grant it has those bytes held back instead. Same
	// record, same rounding, opposite consequence.
	narrow := mustHash(t, ViewPreview(handle, stringObj("internal")))
	if mustHashBoolValue(t, narrow, "rounds_to_granted") {
		t.Fatal("a view granting only `restricted` claims the rounding grew a class it grants")
	}
	narrowEffect := mustHashStringValue(t, narrow, "rounding_effect")
	if !strings.Contains(narrowEffect, "holds back up to 12 bytes") {
		t.Fatalf("the withholding view is not told the rounded bytes are held back: %s", narrowEffect)
	}
	if wideEffect == narrowEffect {
		t.Fatal("one rounding read the same way to a view that grants it and one that does not")
	}
	if mustHashStringValue(t, wide, "rounds_to_label") != "open" {
		t.Fatalf("the preview does not name the class rounding grew: %s",
			mustHashStringValue(t, wide, "rounds_to_label"))
	}
	t.Logf("counsel: %s", wideEffect)
	t.Logf("internal: %s", narrowEffect)
}

// An unquantised record says so rather than leaving the field blank.
func TestAnUnquantisedRecordStatesThatItsBoundariesAreTheOnesDrawn(t *testing.T) {
	recordTestCase(t)
	handle := viewTestRecord(t)
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open")))

	preview := mustHash(t, ViewPreview(handle, stringObj("counsel")))
	if mustHashBoolValue(t, preview, "quantised") {
		t.Fatal("a record sealed by record_seal reports itself as quantised")
	}
	if got := mustHashStringValue(t, preview, "rounding_effect"); !strings.Contains(got, "boundaries the examiner drew") {
		t.Fatalf("an unquantised record does not say its boundaries are the ones drawn: %s", got)
	}
}

// A view naming a class nobody declared is refused at the entry that named it.
func TestAViewCannotNameAClassNobodyDeclared(t *testing.T) {
	recordTestCase(t)

	_, errObj := unwrapPairNoFatal(ViewDefine(stringObj("counsel"), viewArray("open", "secret")))
	if errObj == nil {
		t.Fatal("a view granting an undeclared class was accepted")
	}
	if !strings.Contains(errObj.Message, "entry 2") {
		t.Fatalf("the refusal does not say which entry was wrong: %s", errObj.Message)
	}
	if !strings.Contains(errObj.Message, "open, restricted") {
		t.Fatalf("the refusal does not say what is declared: %s", errObj.Message)
	}
	t.Logf("refused: %s", errObj.Message)
}

// A class named twice is refused rather than collapsed.
func TestAViewCannotNameOneClassTwice(t *testing.T) {
	recordTestCase(t)

	_, errObj := unwrapPairNoFatal(ViewDefine(stringObj("counsel"), viewArray("open", " Open ")))
	if errObj == nil {
		t.Fatal("a view naming one class twice was accepted, so a list nobody was tracking passed")
	}
	if !strings.Contains(errObj.Message, "entry 2") {
		t.Fatalf("the refusal does not say which entry repeated: %s", errObj.Message)
	}
	t.Logf("refused: %s", errObj.Message)
}

// Two postures that differ only in spacing are one posture nobody could tell
// apart in a disclosure record.
func TestTwoViewsCannotShareAName(t *testing.T) {
	recordTestCase(t)
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open")))

	_, errObj := unwrapPairNoFatal(ViewDefine(stringObj(" Counsel "), viewArray("restricted")))
	if errObj == nil {
		t.Fatal("two views with one name were accepted")
	}
	if !strings.Contains(errObj.Message, "already defined") {
		t.Fatalf("the refusal does not say the name is taken: %s", errObj.Message)
	}
}

// A view granting nothing is legal, says so, and discloses no content.
func TestAViewMayGrantNothingAndSaysSo(t *testing.T) {
	recordTestCase(t)
	handle := viewTestRecord(t)

	defined := mustHash(t, ViewDefine(stringObj("existence only"), viewArray()))
	if !mustHashBoolValue(t, defined, "grants_nothing") {
		t.Fatal("a view over no class does not report that it grants nothing")
	}
	preview := mustHash(t, ViewPreview(handle, stringObj("existence only")))
	if !mustHashBoolValue(t, preview, "discloses_nothing") {
		t.Fatal("a view granting no class claims to disclose something")
	}
	if got := mustHashIntValue(t, preview, "granted_bytes"); got != 0 {
		t.Fatalf("a view granting no class released %d bytes", got)
	}
	if got := mustHashIntValue(t, preview, "withheld_bytes"); got != 200 {
		t.Fatalf("a view granting no class should hold back all 200 bytes, holds %d", got)
	}
	// And it still says what the recipient learns anyway, which is the point of
	// the posture existing at all.
	says, ok := mustHashValue(t, preview, "does_not_say").(*object.Array)
	if !ok || len(says.Elements) == 0 {
		t.Fatal("a preview does not state what it fails to establish")
	}
	if !strings.Contains(says.Inspect(), "whole record file") {
		t.Fatalf("a preview does not say the recipient receives the whole file: %s", says.Inspect())
	}
}

// A record outlives the session that named its classes. The binding is
// cryptographic and survives; the naming is documentary and does not.
func TestAPreviewWillNotNameAClassThisCaseCannotName(t *testing.T) {
	recordTestCase(t)

	// Sealed while a third class is declared.
	mustHash(t, ClassDefine(stringObj("secret")))
	source, dest, _ := recordFixture(t)
	secret := mustHash(t, RecordClassifyRange(intObj(64), intObj(64), stringObj("secret")))
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest),
		recordArray(secret), recordSealOpts(nil)))

	// A later session over the same key file, which never declares `secret`.
	// The case uid comes from the key file, so the record still opens.
	keyPath := viewCaseKeyPath(t)
	mustHash(t, CaseClose())
	// The same investigation, reopened later. A case key is bound to its case
	// id, so this is the only shape a second session can take -- and it is the
	// shape that loses the class table, which lives on the session.
	openTestCase(t, "IR-REC", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	mustHash(t, CaseKeyOpen(stringObj(keyPath)))
	mustHash(t, ClassDefine(stringObj("open")))
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open")))

	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)

	preview := mustHash(t, ViewPreview(handle, stringObj("counsel")))
	if got := mustHashIntValue(t, preview, "unnamed_classes"); got != 1 {
		t.Fatalf("the record carries one class this case cannot name and the preview counts %d", got)
	}
	classes, _ := mustHashValue(t, preview, "classes").(*object.Array)
	var sawUnnamed bool
	for _, element := range classes.Elements {
		row, _ := element.(*object.Hash)
		if mustHashBoolValue(t, row, "declared") {
			continue
		}
		sawUnnamed = true
		if mustHashStringValue(t, row, "label") != "" {
			t.Fatalf("an undeclared class was given a name anyway: %s", element.Inspect())
		}
		if mustHashBoolValue(t, row, "granted") {
			t.Fatalf("a class this case cannot name was granted: %s", element.Inspect())
		}
		if mustHashIntValue(t, row, "bytes") != 64 {
			t.Fatalf("the unnamed class should cover 64 bytes: %s", element.Inspect())
		}
	}
	if !sawUnnamed {
		t.Fatal("the class table does not show the class it could not name")
	}
	t.Log("a record separated from the session that named its classes reports the tag, not a guess")
}

// viewCaseKeyPath reports the key file the open case was keyed from.
func viewCaseKeyPath(t *testing.T) string {
	t.Helper()
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	if custodyStore.session == nil || custodyStore.session.keyPath == "" {
		t.Fatal("no case key is open")
	}
	return custodyStore.session.keyPath
}

// view_list answers with the same keys whether or not a case is open.
func TestViewListAnswersWithNoCaseOpen(t *testing.T) {
	resetCustodyForTesting()
	t.Cleanup(resetCustodyForTesting)

	listed := mustHash(t, ViewList())
	if mustHashBoolValue(t, listed, "open") {
		t.Fatal("view_list says a case is open when none is")
	}
	if mustHashIntValue(t, listed, "count") != 0 {
		t.Fatal("view_list reports views with no case open")
	}

	recordTestCase(t)
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open"),
		makeHashObject(map[string]object.Object{"description": stringObj("released to counsel")})))
	listed = mustHash(t, ViewList())
	if !mustHashBoolValue(t, listed, "open") || mustHashIntValue(t, listed, "count") != 1 {
		t.Fatalf("view_list does not report the declared posture: %s", listed.Inspect())
	}
	views, _ := mustHashValue(t, listed, "views").(*object.Array)
	row, _ := views.Elements[0].(*object.Hash)
	if mustHashStringValue(t, row, "description") != "released to counsel" {
		t.Fatalf("the description did not survive: %s", views.Elements[0].Inspect())
	}
	if mustHashIntValue(t, row, "grant_count") != 1 {
		t.Fatalf("the posture does not report what it grants: %s", views.Elements[0].Inspect())
	}
}

// A declared posture is a row in the manifest, which is the form a person can
// review.
func TestADeclaredViewIsInTheManifest(t *testing.T) {
	recordTestCase(t)
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open")))

	classification := manifestSection(t, mustHash(t, CaseManifest()), "classification")
	if mustHashIntValue(t, classification, "view_count") != 1 {
		t.Fatalf("the manifest does not count the declared view: %s", classification.Inspect())
	}
	views, ok := mustHashValue(t, classification, "views").(*object.Array)
	if !ok || len(views.Elements) != 1 {
		t.Fatalf("the manifest has no view row: %s", classification.Inspect())
	}
	row, _ := views.Elements[0].(*object.Hash)
	if mustHashStringValue(t, row, "label") != "counsel" {
		t.Fatalf("the manifest view row is not the one declared: %s", views.Elements[0].Inspect())
	}
	grants, ok := mustHashValue(t, row, "grants").(*object.Array)
	if !ok || len(grants.Elements) != 1 {
		t.Fatalf("the manifest does not say what the view grants: %s", views.Elements[0].Inspect())
	}
	grant, _ := grants.Elements[0].(*object.Hash)
	if mustHashStringValue(t, grant, "label") != "open" {
		t.Fatalf("the manifest names the wrong class: %s", grants.Elements[0].Inspect())
	}
	// The tag travels beside the label, so a reader can match the row against a
	// record's segments without re-deriving anything.
	if len(mustHashStringValue(t, grant, "tag")) != 64 {
		t.Fatalf("the manifest grant row carries no class tag: %s", grants.Elements[0].Inspect())
	}
}

// A view is resolved against the case, and a record handle is not a view.
func TestViewPreviewRefusesAHandleFromAnotherFamily(t *testing.T) {
	recordTestCase(t)
	handle := viewTestRecord(t)

	_, errObj := unwrapPairNoFatal(ViewPreview(handle, stringObj("counsel")))
	if errObj == nil {
		t.Fatal("a preview of a view nobody declared was accepted")
	}
	if !strings.Contains(errObj.Message, "declared none") {
		t.Fatalf("the refusal does not say the case has declared no view: %s", errObj.Message)
	}

	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open")))
	if _, errObj = unwrapPairNoFatal(ViewPreview(intObj(9999), stringObj("counsel"))); errObj == nil {
		t.Fatal("a preview against an unknown record handle was accepted")
	}
	if _, errObj = unwrapPairNoFatal(ViewPreview(handle, stringObj("legal"))); errObj == nil {
		t.Fatal("a preview of an undeclared view was accepted")
	}
	if !strings.Contains(errObj.Message, "counsel") {
		t.Fatalf("the refusal does not list the postures that exist: %s", errObj.Message)
	}
}

// A view cannot be declared before there is a key to tag classes under.
func TestAViewNeedsAKeyedCase(t *testing.T) {
	openTestCase(t, "IR-VIEW", "examiner")

	_, errObj := unwrapPairNoFatal(ViewDefine(stringObj("counsel"), viewArray()))
	if errObj == nil {
		t.Fatal("a view was declared with no case key open")
	}
	if !strings.Contains(errObj.Message, "case_key_open") {
		t.Fatalf("the refusal does not say what to call first: %s", errObj.Message)
	}
}

// The same rule that refuses an unreadable class label refuses an unreadable
// view name, because both end up in the same documents.
func TestAViewNameThatIsNotValidTextIsRefused(t *testing.T) {
	recordTestCase(t)

	_, errObj := unwrapPairNoFatal(ViewDefine(stringObj(string([]byte{0xff, 0xfe})), viewArray()))
	if errObj == nil {
		t.Fatal("a view name that is not valid UTF-8 was accepted")
	}
	if !strings.Contains(errObj.Message, "view name") {
		t.Fatalf("the refusal does not name what was wrong: %s", errObj.Message)
	}
	if _, errObj = unwrapPairNoFatal(ViewDefine(stringObj("a\u0000b"), viewArray())); errObj == nil {
		t.Fatal("a view name carrying a control character was accepted")
	}
}

// A path that never touches the filesystem: the preview is arithmetic over the
// header, so it must work on a record whose segments are all one class.
func TestAViewOverTheOnlyClassDisclosesTheWholeRecord(t *testing.T) {
	recordTestCase(t)
	source := filepath.Join(t.TempDir(), "uniform.bin")
	dest := filepath.Join(t.TempDir(), "uniform.mrec")
	if err := writeViewFixture(source, 128); err != nil {
		t.Fatal(err)
	}
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest),
		recordArray(), recordSealOpts(nil)))
	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)

	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open")))
	preview := mustHash(t, ViewPreview(handle, stringObj("counsel")))
	if !mustHashBoolValue(t, preview, "discloses_whole_record") {
		t.Fatal("a view over the only class in the record does not disclose all of it")
	}
	if got := mustHashIntValue(t, preview, "withheld_bytes"); got != 0 {
		t.Fatalf("a view over the only class holds back %d bytes", got)
	}
	// Two contiguous 64-byte segments of one class are one run, not two.
	runs, _ := mustHashValue(t, preview, "granted_runs").(*object.Array)
	if len(runs.Elements) != 1 {
		t.Fatalf("adjacent segments of one class did not merge: %s", runs.Inspect())
	}
	row, _ := runs.Elements[0].(*object.Hash)
	if mustHashIntValue(t, row, "length") != 128 {
		t.Fatalf("the merged run is not the whole record: %s", runs.Elements[0].Inspect())
	}
}

// writeViewFixture writes n bytes of predictable filler.
func writeViewFixture(path string, n int) error {
	buffer := make([]byte, n)
	for i := range buffer {
		buffer[i] = byte('a' + i%26)
	}
	return os.WriteFile(path, buffer, 0o600)
}
