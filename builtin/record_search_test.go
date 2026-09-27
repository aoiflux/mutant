package builtin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"mutant/object"
	"mutant/security"
)

// The disclose fixture's record, and what each of its views reads of it:
//
//	segment  0    1    2    3     4     5    6    7
//	bytes    0    64   100  160   224   250  300  364
//	class    open open pii  restr restr pii  open open
//
// counsel reads segments 0-2 and 5-7, the regulator 3-4. The plaintext is the
// alphabet over and over, so a pattern recurs every 26 bytes.
var (
	searchCounselRuns   = [][2]int{{0, 160}, {250, 400}}
	searchRegulatorRuns = [][2]int{{160, 250}}
)

// searchRecord runs record_search and returns its result.
func searchRecord(t *testing.T, record, pattern object.Object, options map[string]object.Object) *object.Hash {
	t.Helper()
	args := []object.Object{record, pattern}
	if options != nil {
		args = append(args, makeHashObject(options))
	}
	return mustHash(t, RecordSearch(args...))
}

// underView is the options naming a view.
func underView(view string) map[string]object.Object {
	return map[string]object.Object{"view": stringObj(view)}
}

// searchHitRows returns a result's hits.
func searchHitRows(t *testing.T, result *object.Hash) []*object.Hash {
	t.Helper()
	array, ok := mustHashValue(t, result, "hits").(*object.Array)
	if !ok {
		t.Fatal("hits is not an ARRAY")
	}
	rows := make([]*object.Hash, len(array.Elements))
	for i, element := range array.Elements {
		row, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("hit %d is %T", i, element)
		}
		rows[i] = row
	}
	return rows
}

// searchOffsets lists where a result's hits begin.
func searchOffsets(t *testing.T, result *object.Hash) []int64 {
	t.Helper()
	var offsets []int64
	for _, row := range searchHitRows(t, result) {
		offsets = append(offsets, mustHashIntValue(t, row, "offset"))
	}
	return offsets
}

// searchHitAt is the hit beginning at offset.
func searchHitAt(t *testing.T, result *object.Hash, offset int64) *object.Hash {
	t.Helper()
	for _, row := range searchHitRows(t, result) {
		if mustHashIntValue(t, row, "offset") == offset {
			return row
		}
	}
	t.Fatalf("no hit at %d; the hits begin at %v", offset, searchOffsets(t, result))
	return nil
}

// oracleHit is a match found the slow way.
type oracleHit struct {
	offset        int
	length        int
	contextOffset int
	context       []byte
}

// searchOracle is the search done the slow way: every offset of each readable
// run whose pattern-length bytes all lie inside that run, compared byte by
// byte, with the context cut straight out of the run.
func searchOracle(text []byte, runs [][2]int, pattern []byte, width int, fold bool) []oracleHit {
	lower := func(c byte) byte {
		if 'A' <= c && c <= 'Z' {
			return c - 'A' + 'a'
		}
		return c
	}
	same := func(a, b []byte) bool {
		for i := range a {
			x, y := a[i], b[i]
			if fold {
				x, y = lower(x), lower(y)
			}
			if x != y {
				return false
			}
		}
		return true
	}
	var out []oracleHit
	for _, run := range runs {
		for i := run[0]; i+len(pattern) <= run[1]; i++ {
			if same(text[i:i+len(pattern)], pattern) {
				from, to := max(run[0], i-width), min(run[1], i+len(pattern)+width)
				out = append(out, oracleHit{offset: i, length: len(pattern), contextOffset: from, context: text[from:to]})
			}
		}
	}
	return out
}

// checkAgainstOracle holds a result to the slow search's answer.
func checkAgainstOracle(t *testing.T, what string, result *object.Hash, want []oracleHit) {
	t.Helper()
	if got := mustHashIntValue(t, result, "count"); got != int64(len(want)) {
		t.Errorf("%s: count %d, and the slow search finds %d", what, got, len(want))
	}
	rows := searchHitRows(t, result)
	if len(rows) != len(want) {
		t.Fatalf("%s: %d hits at %v, and the slow search finds %d", what, len(rows), searchOffsets(t, result), len(want))
	}
	for i, row := range rows {
		offset := mustHashIntValue(t, row, "offset")
		at := mustHashIntValue(t, row, "context_offset")
		context := recordBytes(t, mustHashValue(t, row, "context"))
		if offset != int64(want[i].offset) || at != int64(want[i].contextOffset) || !bytes.Equal(context, want[i].context) {
			t.Errorf("%s: hit %d is at %d with context %q from %d; the slow search has %d with %q from %d",
				what, i, offset, context, at, want[i].offset, want[i].context, want[i].contextOffset)
		}
		if got := mustHashIntValue(t, row, "length"); got != int64(want[i].length) {
			t.Errorf("%s: hit %d says its length is %d, want %d", what, i, got, want[i].length)
		}
	}
}

// A search reads exactly what a grant under its view would open, and every
// number it reports is about that: what it read, what it did not, whether
// that was everything.
func TestASearchReadsWhatAGrantUnderItsViewWouldOpen(t *testing.T) {
	f := newDiscloseFixture(t)
	mustHash(t, ViewDefine(stringObj("everything"), viewArray("open", "pii", "restricted")))

	for _, tc := range []struct {
		view                 string
		runs                 [][2]int
		searched, withheld   int64
		searchedB, withheldB int64
		complete             bool
	}{
		{"counsel", searchCounselRuns, 6, 2, 310, 90, false},
		{"regulator", searchRegulatorRuns, 2, 6, 90, 310, false},
		{"everything", [][2]int{{0, 400}}, 8, 0, 400, 0, true},
	} {
		result := searchRecord(t, f.record, stringObj("XYZ"), underView(tc.view))
		checkAgainstOracle(t, tc.view, result, searchOracle(f.plaintext, tc.runs, []byte("XYZ"), defaultSearchContext, false))
		for key, want := range map[string]int64{
			"segments": 8, "searched_segments": tc.searched, "withheld_segments": tc.withheld, "failed_segments": 0,
			"searched_bytes": tc.searchedB, "withheld_bytes": tc.withheldB,
		} {
			if got := mustHashIntValue(t, result, key); got != want {
				t.Errorf("%s: %s is %d, want %d", tc.view, key, got, want)
			}
		}
		if got := mustHashBoolValue(t, result, "complete"); got != tc.complete {
			t.Errorf("%s: complete is %v, want %v", tc.view, got, tc.complete)
		}
		if got := keyFieldString(t, result, "view"); got != tc.view {
			t.Errorf("%s: the result names view %q", tc.view, got)
		}
		if got := keyFieldString(t, result, "opened_with"); got != "case_key" {
			t.Errorf("%s: opened_with is %q", tc.view, got)
		}
		if mustHashBoolValue(t, result, "truncated") {
			t.Errorf("%s: a search that returned every hit says it was truncated", tc.view)
		}
	}

	// A view is named as a view is declared, however it is spelt at the call,
	// and the result names it as declared.
	if got := keyFieldString(t, searchRecord(t, f.record, stringObj("XYZ"), underView(" COUNSEL ")), "view"); got != "counsel" {
		t.Errorf("a search under \" COUNSEL \" names view %q, want counsel", got)
	}

	// Counted once by hand, so the test is not only one search against another:
	// XYZ begins at every 26th byte from 23, and counsel reads twelve of them.
	counsel := searchRecord(t, f.record, stringObj("XYZ"), underView("counsel"))
	if got := searchOffsets(t, counsel); !slices.Equal(got,
		[]int64{23, 49, 75, 101, 127, 153, 257, 283, 309, 335, 361, 387}) {
		t.Errorf("counsel's hits begin at %v", got)
	}

	// Every field the result carries is one the metadata declares, and back.
	got := map[string]bool{}
	for _, pair := range counsel.Pairs {
		got[pair.Key.(*object.String).Value] = true
	}
	for _, field := range builtinDocs[BuiltinNameRecordSearch].returns.fields {
		if !got[field] {
			t.Errorf("declares field %q and does not return it", field)
		}
		delete(got, field)
	}
	for field := range got {
		t.Errorf("returns field %q and does not declare it", field)
	}
}

// The boundary between what a reader can read and what it cannot is where a
// careless search reports a match it could not have made.
func TestAMatchThatWouldNeedAnUnreadByteIsNeverReported(t *testing.T) {
	f := newDiscloseFixture(t)

	// BCDEFG at 157 runs from pii into restricted: counsel reads its first
	// three bytes and not the rest.
	counsel := searchOffsets(t, searchRecord(t, f.record, stringObj("BCDEFG"), underView("counsel")))
	if slices.Contains(counsel, 157) {
		t.Error("counsel's search reports BCDEFG at 157, which needs three bytes of restricted")
	}
	if !slices.Contains(counsel, 131) || !slices.Contains(counsel, 261) {
		t.Errorf("counsel's search for BCDEFG misses what it reads: %v", counsel)
	}

	// NOPQRS at 221 runs from segment 3 into segment 4, both restricted, and
	// the regulator reads both: the match is carried across the boundary. At
	// 247 it runs out of restricted into pii, which the regulator does not read.
	regulator := searchRecord(t, f.record, stringObj("NOPQRS"), underView("regulator"))
	if got := searchOffsets(t, regulator); !slices.Equal(got, []int64{169, 195, 221}) {
		t.Errorf("the regulator's hits begin at %v, want 169, 195 and 221", got)
	}
	hit := searchHitAt(t, regulator, 221)
	if got := mustHashValue(t, hit, "segments").Inspect(); got != "[3, 4]" {
		t.Errorf("the match at 221 lies in segments %s, want [3, 4]", got)
	}

	// At 299 it runs from pii into open, both counsel's, so it is counsel's
	// hit -- and it carries both classes, in the order the match meets them.
	across := searchHitAt(t, searchRecord(t, f.record, stringObj("NOPQRS"), underView("counsel")), 299)
	if got := mustHashValue(t, across, "segments").Inspect(); got != "[5, 6]" {
		t.Errorf("the match at 299 lies in segments %s, want [5, 6]", got)
	}
	var labels []string
	for _, row := range mustHashValue(t, across, "classes").(*object.Array).Elements {
		class := row.(*object.Hash)
		if !mustHashBoolValue(t, class, "declared") {
			t.Errorf("the class %s of a declared label says it is undeclared", keyFieldString(t, class, "tag"))
		}
		labels = append(labels, keyFieldString(t, class, "label"))
	}
	if !slices.Equal(labels, []string{"pii", "open"}) {
		t.Errorf("the match at 299 is classed %v, want pii then open", labels)
	}
}

// Small segments put a pattern across many of them, and overlapping
// occurrences are each a hit: both against the slow search, sealed for real.
func TestASearchCarriesMatchesAcrossSmallSegmentsAndReportsEveryOverlap(t *testing.T) {
	newDiscloseFixture(t)
	text := []byte(strings.Repeat("aaab", 15))
	dir := t.TempDir()
	source, dest := filepath.Join(dir, "small.bin"), filepath.Join(dir, "small.mrec")
	if err := os.WriteFile(source, text, 0o600); err != nil {
		t.Fatal(err)
	}
	ranges := recordArray(mustHash(t, RecordClassifyRange(intObj(21), intObj(12), stringObj("restricted"))))
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), ranges,
		recordSealOpts(map[string]object.Object{"segment_size": intObj(3)})))
	handle := mustHashValue(t, mustHash(t, RecordOpen(stringObj(dest))), "handle")
	t.Cleanup(func() { RecordClose(handle) })

	for _, pattern := range []string{"a", "aa", "aab", "baaa", "abaa", "aaaba"} {
		for _, width := range []int{0, 2, 7} {
			result := searchRecord(t, handle, stringObj(pattern), map[string]object.Object{
				"view": stringObj("counsel"), "context": intObj(int64(width))})
			checkAgainstOracle(t, fmt.Sprintf("%q with %d bytes of context", pattern, width), result,
				searchOracle(text, [][2]int{{0, 21}, {33, 60}}, []byte(pattern), width, false))
		}
	}
}

// A context stops where the readable bytes stop, and is never padded.
func TestASearchContextStopsWhereTheReadableBytesStop(t *testing.T) {
	f := newDiscloseFixture(t)

	// XYZ at 153 ends four bytes before restricted begins: its context runs
	// the whole 32 bytes back and only those four forward.
	hit := searchHitAt(t, searchRecord(t, f.record, stringObj("XYZ"), underView("counsel")), 153)
	if got := mustHashIntValue(t, hit, "context_offset"); got != 121 {
		t.Errorf("the context of 153 begins at %d, want 121", got)
	}
	if got := recordBytes(t, mustHashValue(t, hit, "context")); !bytes.Equal(got, f.plaintext[121:160]) {
		t.Errorf("the context of 153 is %q, want the 39 bytes up to where counsel's reading stops", got)
	}

	// The regulator's reading begins at 160, so XYZ at 179 has 19 bytes of
	// context behind it and the whole 32 in front.
	hit = searchHitAt(t, searchRecord(t, f.record, stringObj("XYZ"), underView("regulator")), 179)
	if got := mustHashIntValue(t, hit, "context_offset"); got != 160 {
		t.Errorf("the context of 179 begins at %d, want 160", got)
	}
	if got := recordBytes(t, mustHashValue(t, hit, "context")); !bytes.Equal(got, f.plaintext[160:214]) {
		t.Errorf("the context of 179 is %q", got)
	}

	// No context is the match alone; a wider one is wider on both sides.
	for _, row := range searchHitRows(t, searchRecord(t, f.record, stringObj("XYZ"),
		map[string]object.Object{"view": stringObj("counsel"), "context": intObj(0)})) {
		if got := recordBytes(t, mustHashValue(t, row, "context")); string(got) != "XYZ" ||
			mustHashIntValue(t, row, "context_offset") != mustHashIntValue(t, row, "offset") {
			t.Errorf("with no context asked for, a hit's context is %q", got)
		}
	}
	wide := searchHitAt(t, searchRecord(t, f.record, stringObj("XYZ"),
		map[string]object.Object{"view": stringObj("counsel"), "context": intObj(maxSearchContext)}), 101)
	if got := recordBytes(t, mustHashValue(t, wide, "context")); !bytes.Equal(got, f.plaintext[0:160]) {
		t.Errorf("the widest context of 101 is %d bytes, want all 160 of its run", len(got))
	}
}

// The context is plaintext, and it is marked: with the record, and with the
// class of every byte in it, not only the match's.
func TestASearchContextIsMarkedWithTheClassesItHolds(t *testing.T) {
	f := newDiscloseFixture(t)
	result := searchRecord(t, f.record, stringObj("XYZ"), underView("counsel"))
	uid := keyFieldString(t, result, "record_uid")

	// XYZ at 101 is pii, and the 32 bytes before it are open.
	hit := searchHitAt(t, result, 101)
	context, ok := mustHashValue(t, hit, "context").(*object.Bytes)
	if !ok || context.Classified == nil {
		t.Fatal("a hit's context is not marked")
	}
	if context.Classified.RecordUID != uid {
		t.Errorf("the context is marked with record %q, want %q", context.Classified.RecordUID, uid)
	}
	if !slices.Equal(context.Classified.Labels, []string{"open", "pii"}) {
		t.Errorf("the context is marked %v, want the open bytes before it and the pii of the match", context.Classified.Labels)
	}
	classes := mustHashValue(t, hit, "classes").(*object.Array).Elements
	if len(classes) != 1 || keyFieldString(t, classes[0].(*object.Hash), "label") != "pii" ||
		keyFieldString(t, classes[0].(*object.Hash), "tag") != context.Classified.Tags[1] {
		t.Errorf("the match at 101 is classed %v, want pii alone, by the tag its context carries", classes)
	}
	if got := mustHashValue(t, hit, "segments").Inspect(); got != "[2]" {
		t.Errorf("the match at 101 lies in segments %s, want [2]", got)
	}

	// A context wholly in one class is marked with that class once.
	if got := mustHashValue(t, searchHitAt(t, result, 49), "context").(*object.Bytes).Classified.Labels; !slices.Equal(got, []string{"open"}) {
		t.Errorf("a context over two open segments is marked %v", got)
	}

	// A sink refuses it, saying where it came from and nothing of what it is.
	errObj := refuseClassified(BuiltinNamePutln, mustHashValue(t, result, "hits"))
	if errObj == nil {
		t.Fatal("putln would print a search's hits")
	}
	if !strings.Contains(errObj.Message, uid) || strings.Contains(errObj.Message, "XYZ") {
		t.Errorf("the refusal does not name the record, or quotes what it refused: %s", errObj.Message)
	}
	released, ok := mustValue(t, RecordRelease(context, stringObj("quoted in the report"))).(*object.Bytes)
	if !ok || released.Classified != nil || !bytes.Equal(released.Value, context.Value) {
		t.Fatal("record_release does not let a search's context go as it lets a read's")
	}
}

// A search under a grant is the search its recipient can make, and it finds
// exactly what the examiner's search under the grant's view found.
func TestASearchUnderAGrantFindsWhatTheSearchUnderItsViewFound(t *testing.T) {
	f := newDiscloseFixture(t)
	examiner := searchRecord(t, f.record, stringObj("XYZ"), underView("counsel"))
	disclosure := f.issue(t, "counsel", "outside counsel")
	dir, _ := f.bundle(t, keyFieldString(t, disclosure, "disclosure_uid"))

	// The recipient's process: no case of the examiner's, open or closed.
	mustHash(t, CaseClose())
	resetCustodyForTesting()
	purposeStub(t, map[string]string{BuiltinNameRecordOpen: testGrantPassphrase})
	opened := mustHash(t, RecordOpen(stringObj(filepath.Join(dir, discloseRecordName)),
		makeHashObject(map[string]object.Object{"grant": stringObj(filepath.Join(dir, discloseGrantName))})))
	handle := mustHashValue(t, opened, "handle")
	t.Cleanup(func() { RecordClose(handle) })

	recipient := searchRecord(t, handle, stringObj("XYZ"), nil)
	checkAgainstOracle(t, "the recipient", recipient,
		searchOracle(f.plaintext, searchCounselRuns, []byte("XYZ"), defaultSearchContext, false))
	theirs, ours := searchHitRows(t, recipient), searchHitRows(t, examiner)
	for i := range min(len(theirs), len(ours)) {
		if !bytes.Equal(recordBytes(t, mustHashValue(t, theirs[i], "context")), recordBytes(t, mustHashValue(t, ours[i], "context"))) {
			t.Errorf("hit %d's context differs between the grant and the view", i)
		}
	}
	if got := keyFieldString(t, recipient, "opened_with"); got != "grant" {
		t.Errorf("opened_with is %q", got)
	}
	if got := keyFieldString(t, recipient, "view"); got != "" {
		t.Errorf("a search under a grant names view %q", got)
	}
	if got := mustHashIntValue(t, recipient, "withheld_segments"); got != 2 {
		t.Errorf("the grant withholds %d segments from the search, want 2", got)
	}
	// Nobody's case is open on the recipient's side, so the search is written
	// nowhere and no digest of the pattern is made -- and no class can be named.
	if mustHashBoolValue(t, recipient, "recorded") || keyFieldString(t, recipient, "pattern_digest") != "" {
		t.Error("a search with no case open says it was recorded")
	}
	class := mustHashValue(t, searchHitAt(t, recipient, 101), "classes").(*object.Array).Elements[0].(*object.Hash)
	if mustHashBoolValue(t, class, "declared") || keyFieldString(t, class, "label") != "" || keyFieldString(t, class, "tag") == "" {
		t.Errorf("with no case to name it, a hit's class is %s", class.Inspect())
	}

	// A granted segment that does not open is a finding, said as the grant's.
	data, err := os.ReadFile(filepath.Join(dir, discloseRecordName))
	if err != nil {
		t.Fatal(err)
	}
	segments := mustHashValue(t, mustHash(t, RecordLayout(handle)), "segments").(*object.Array).Elements
	data[mustHashIntValue(t, segments[2].(*object.Hash), "stored_offset")] ^= 0xff
	tamperedPath := filepath.Join(t.TempDir(), "tampered.mrec")
	if err := os.WriteFile(tamperedPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := mustHashValue(t, mustHash(t, RecordOpen(stringObj(tamperedPath),
		makeHashObject(map[string]object.Object{"grant": stringObj(filepath.Join(dir, discloseGrantName))}))), "handle")
	t.Cleanup(func() { RecordClose(tampered) })
	failures := mustHashValue(t, searchRecord(t, tampered, stringObj("XYZ"), nil), "failures").(*object.Array).Elements
	if len(failures) != 1 || !strings.Contains(keyFieldString(t, failures[0].(*object.Hash), "reason"),
		"does not open under the material granted for it") {
		t.Errorf("a broken granted segment is reported as %v", failures)
	}

	// A view can neither widen nor narrow what a grant opens.
	_, errObj := unwrapPairNoFatal(RecordSearch(handle, stringObj("XYZ"), makeHashObject(underView("counsel"))))
	if errObj == nil || !strings.Contains(errObj.Message, "opened under a grant") {
		t.Errorf("a view on a search under a grant was not refused: %v", errObj)
	}

	// A recipient with a case of their own and no case key has the search
	// written into it, and the pattern in no form at all.
	openTestCase(t, "IR-RECIPIENT", "outside counsel")
	keyless := searchRecord(t, handle, stringObj("XYZ"), nil)
	if !mustHashBoolValue(t, keyless, "recorded") || keyFieldString(t, keyless, "pattern_digest") != "" {
		t.Errorf("a search in a case with no key: recorded %v, digest %q",
			mustHashBoolValue(t, keyless, "recorded"), keyFieldString(t, keyless, "pattern_digest"))
	}
	event := lastSearchEvent(t)
	if !strings.Contains(event.Detail, "under its grant") || !strings.Contains(event.Detail, "not written in any form") {
		t.Errorf("the timeline says %q", event.Detail)
	}
	if data := event.Data.(map[string]any); data["pattern_digest"] != "" || data["opened_with"] != "grant" {
		t.Errorf("the timeline records %v", data)
	}
}

// lastSearchEvent is the latest record_search entry in the open case's timeline.
func lastSearchEvent(t *testing.T) custodyEvent {
	t.Helper()
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	for _, event := range slices.Backward(custodyStore.session.timeline) {
		if event.Event == BuiltinNameRecordSearch {
			return event
		}
	}
	t.Fatal("the timeline holds no search")
	return custodyEvent{}
}

// The timeline says a search happened, under what, and what it found -- and
// names the pattern only by a digest keyed to the case key.
func TestASearchIsWrittenIntoTheTimelineWithoutItsPattern(t *testing.T) {
	f := newDiscloseFixture(t)
	const pattern = "QRSTUV"
	result := searchRecord(t, f.record, stringObj(pattern), underView("counsel"))
	if !mustHashBoolValue(t, result, "recorded") {
		t.Fatal("a search with a case open was not recorded")
	}
	digest := keyFieldString(t, result, "pattern_digest")

	custodyStore.RLock()
	want, err := security.SearchPatternDigest(custodyStore.session.caseKey, []byte(pattern))
	custodyStore.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	if digest != hex.EncodeToString(want[:]) {
		t.Fatalf("the digest is %s, and the pattern's digest under the case key is %x", digest, want)
	}
	if bare := sha256.Sum256([]byte(pattern)); digest == hex.EncodeToString(bare[:]) {
		t.Fatal("the digest is the bare SHA-256 of the pattern, which confirms any guess to anyone")
	}

	event := lastSearchEvent(t)
	data := event.Data.(map[string]any)
	for key, want := range map[string]any{
		"pattern_digest": digest, "view": "counsel", "opened_with": "case_key", "record_uid": keyFieldString(t, result, "record_uid"),
		"matches": mustHashIntValue(t, result, "count"), "searched_segments": int64(6), "withheld_segments": int64(2),
		"failed_segments": int64(0), "ignore_ascii_case": false,
	} {
		if data[key] != want {
			t.Errorf("the timeline records %s as %v, want %v", key, data[key], want)
		}
	}
	if found := fmt.Sprintf("%d found in 6 of 8 segments", mustHashIntValue(t, result, "count")); !strings.Contains(event.Detail, `under view "counsel"`) ||
		!strings.Contains(event.Detail, found) || !strings.Contains(event.Detail, "written as its digest under the case key") {
		t.Errorf("the timeline says %q", event.Detail)
	}
	custodyStore.RLock()
	rendered, err := json.Marshal(custodyStore.session.timeline)
	custodyStore.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rendered), pattern) {
		t.Fatal("the pattern is in the timeline")
	}

	// The same pattern is the same digest whatever it was searched under, and
	// another pattern another digest.
	again := searchRecord(t, f.record, stringObj(pattern), map[string]object.Object{
		"view": stringObj("regulator"), "ignore_ascii_case": boolObj(true)})
	if keyFieldString(t, again, "pattern_digest") != digest {
		t.Error("one pattern searched twice has two digests")
	}
	if lastSearchEvent(t).Data.(map[string]any)["ignore_ascii_case"] != true {
		t.Error("the timeline does not say the second search folded case")
	}
	if keyFieldString(t, searchRecord(t, f.record, stringObj(pattern+"W"), underView("counsel")), "pattern_digest") == digest {
		t.Error("two patterns have one digest")
	}
}

// Every refusal names what was wrong.
func TestASearchRefusesWhatItCannotAnswer(t *testing.T) {
	f := newDiscloseFixture(t)
	counsel := stringObj("counsel")
	with := func(pairs map[string]object.Object) object.Object {
		if _, named := pairs["view"]; !named {
			pairs["view"] = counsel
		}
		return makeHashObject(pairs)
	}
	for _, tc := range []struct {
		name string
		args []object.Object
		want string
	}{
		{"no view for a record opened with the case key", []object.Object{f.record, stringObj("XYZ")}, "whose reading it stands for"},
		{"an undeclared view", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"view": stringObj("press")})}, "not a declared view"},
		{"an empty pattern", []object.Object{f.record, stringObj(""), with(map[string]object.Object{})}, "empty pattern"},
		{"an empty buffer", []object.Object{f.record, &object.Bytes{}, with(map[string]object.Object{})}, "empty pattern"},
		{"a pattern past the limit", []object.Object{f.record, stringObj(strings.Repeat("A", maxSearchPattern+1)), with(map[string]object.Object{})}, "at most 4096 bytes and this one is 4097"},
		{"a pattern that is neither", []object.Object{f.record, intObj(7), with(map[string]object.Object{})}, "must be BYTES or STRING, got INTEGER"},
		{"a negative max_hits", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"max_hits": intObj(-1)})}, `"max_hits" is -1`},
		{"too many hits", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"max_hits": intObj(maxSearchHits + 1)})}, `"max_hits" is 1001`},
		{"a context past the limit", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"context": intObj(maxSearchContext + 1)})}, `"context" is 4097`},
		{"a negative context", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"context": intObj(-1)})}, `"context" is -1`},
		{"a context that is not a number", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"context": stringObj("wide")})}, `"context" must be INTEGER`},
		{"a fold that is not a boolean", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"ignore_ascii_case": stringObj("yes")})}, `"ignore_ascii_case" must be BOOLEAN`},
		{"a view that is not a name", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"view": intObj(1)})}, `"view" must be STRING`},
		{"an unknown option", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"regex": boolObj(true)})}, `unknown option "regex"`},
		{"a secret by name", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{"passphrase": stringObj("x")})}, "a passphrase is not an argument"},
		{"too few arguments", []object.Object{f.record}, "want=2 or 3"},
		{"too many arguments", []object.Object{f.record, stringObj("XYZ"), with(map[string]object.Object{}), intObj(1)}, "want=2 or 3"},
		{"not a record handle", []object.Object{intObj(424242), stringObj("XYZ"), with(map[string]object.Object{})}, "is not an open record handle"},
		{"a handle that is not a number", []object.Object{stringObj("r"), stringObj("XYZ"), with(map[string]object.Object{})}, "must be INTEGER"},
	} {
		_, errObj := unwrapPairNoFatal(RecordSearch(tc.args...))
		if errObj == nil || !strings.Contains(errObj.Message, tc.want) {
			t.Errorf("%s: want a refusal saying %q, got %v", tc.name, tc.want, errObj)
		}
	}

	// The bounds themselves are allowed.
	for _, options := range []map[string]object.Object{
		{"max_hits": intObj(0)}, {"max_hits": intObj(maxSearchHits)},
		{"context": intObj(0)}, {"context": intObj(maxSearchContext)},
	} {
		if _, errObj := unwrapPairNoFatal(RecordSearch(f.record, stringObj(strings.Repeat("A", maxSearchPattern)), with(options))); errObj != nil {
			t.Errorf("%v was refused: %s", options, errObj.Message)
		}
	}
}

// count is every match; hits is the first max_hits of them, in order.
func TestASearchCountsEveryMatchAndReturnsTheFirstMaxHits(t *testing.T) {
	f := newDiscloseFixture(t)
	all := searchOffsets(t, searchRecord(t, f.record, stringObj("XYZ"), underView("counsel")))
	if len(all) != 12 {
		t.Fatalf("counsel's search finds %d, want 12", len(all))
	}
	for _, limit := range []int64{0, 1, 5, 11, 12, maxSearchHits} {
		result := searchRecord(t, f.record, stringObj("XYZ"), map[string]object.Object{
			"view": stringObj("counsel"), "max_hits": intObj(limit)})
		if got := mustHashIntValue(t, result, "count"); got != 12 {
			t.Errorf("max_hits %d: count %d, want every one of the 12", limit, got)
		}
		kept := min(limit, 12)
		if got := searchOffsets(t, result); !slices.Equal(got, all[:kept]) {
			t.Errorf("max_hits %d: hits begin at %v, want %v", limit, got, all[:kept])
		}
		if got := mustHashBoolValue(t, result, "truncated"); got != (limit < 12) {
			t.Errorf("max_hits %d: truncated is %v", limit, got)
		}
	}
}

// Case is folded only when asked, only for ASCII, and never in what comes back.
func TestASearchFoldsASCIICaseOnlyWhenAsked(t *testing.T) {
	f := newDiscloseFixture(t)
	if got := mustHashIntValue(t, searchRecord(t, f.record, stringObj("xyz"), underView("counsel")), "count"); got != 0 {
		t.Errorf("xyz matched %d times in a record written in capitals", got)
	}
	folded := searchRecord(t, f.record, stringObj("xYz"), map[string]object.Object{
		"view": stringObj("counsel"), "ignore_ascii_case": boolObj(true)})
	checkAgainstOracle(t, "folded", folded, searchOracle(f.plaintext, searchCounselRuns, []byte("xyz"), defaultSearchContext, true))

	for _, tc := range []struct{ in, out byte }{
		{'A', 'a'}, {'Z', 'z'}, {'M', 'm'}, {'a', 'a'}, {'z', 'z'},
		{'@', '@'}, {'[', '['}, {'`', '`'}, {'{', '{'}, {'0', '0'}, {0xC4, 0xC4}, {0xE4, 0xE4},
	} {
		if got := searchFold(tc.in); got != tc.out {
			t.Errorf("searchFold(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

// A pattern is its bytes, whichever type carries them -- a buffer read out of
// the record included, which the search copies and never zeroes.
func TestASearchTakesThePatternAsBytesOrAsAString(t *testing.T) {
	f := newDiscloseFixture(t)
	want := searchOffsets(t, searchRecord(t, f.record, stringObj("XYZ"), underView("counsel")))
	if got := searchOffsets(t, searchRecord(t, f.record, &object.Bytes{Value: []byte("XYZ")}, underView("counsel"))); !slices.Equal(got, want) {
		t.Errorf("as BYTES the hits begin at %v, as a STRING at %v", got, want)
	}
	read := mustValue(t, RecordRead(f.record, intObj(23), intObj(3))).(*object.Bytes)
	if got := searchOffsets(t, searchRecord(t, f.record, read, underView("counsel"))); !slices.Equal(got, want) {
		t.Errorf("as a buffer read out of the record the hits begin at %v, want %v", got, want)
	}
	if string(read.Value) != "XYZ" {
		t.Fatalf("the search zeroed the caller's pattern: %q", read.Value)
	}
}

// A segment the reader should open and cannot is a finding; one the reader
// does not read is never read at all, so breaking it changes nothing.
func TestASegmentThatDoesNotOpenIsAFindingAndOneNotReadIsNot(t *testing.T) {
	f := newDiscloseFixture(t)
	layout := mustHash(t, RecordLayout(f.record))
	segments := mustHashValue(t, layout, "segments").(*object.Array).Elements
	broken := func(index int) object.Object {
		t.Helper()
		data, err := os.ReadFile(f.recordPath)
		if err != nil {
			t.Fatal(err)
		}
		data[mustHashIntValue(t, segments[index].(*object.Hash), "stored_offset")] ^= 0xff
		path := filepath.Join(t.TempDir(), "broken.mrec")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		handle := mustHashValue(t, mustHash(t, RecordOpen(stringObj(path))), "handle")
		t.Cleanup(func() { RecordClose(handle) })
		return handle
	}

	// Segment 2 is pii, which counsel reads. It no longer opens: the search
	// says so, finds nothing in it and nothing across it.
	result := searchRecord(t, broken(2), stringObj("XYZ"), underView("counsel"))
	failures := mustHashValue(t, result, "failures").(*object.Array).Elements
	if len(failures) != 1 {
		t.Fatalf("%d failures, want the one broken segment", len(failures))
	}
	failure := failures[0].(*object.Hash)
	if mustHashIntValue(t, failure, "segment") != 2 || mustHashIntValue(t, failure, "offset") != 100 ||
		mustHashIntValue(t, failure, "length") != 60 ||
		!strings.Contains(keyFieldString(t, failure, "reason"), "does not open under this record's key") {
		t.Errorf("the failure is %s", failure.Inspect())
	}
	for key, want := range map[string]int64{"failed_segments": 1, "searched_segments": 5, "withheld_segments": 2, "searched_bytes": 250} {
		if got := mustHashIntValue(t, result, key); got != want {
			t.Errorf("%s is %d, want %d", key, got, want)
		}
	}
	if mustHashBoolValue(t, result, "complete") {
		t.Error("a search that could not open a segment says it was complete")
	}
	checkAgainstOracle(t, "around a broken segment", result,
		searchOracle(f.plaintext, [][2]int{{0, 100}, {250, 400}}, []byte("XYZ"), defaultSearchContext, false))
	if got := lastSearchEvent(t).Data.(map[string]any)["failed_segments"]; got != int64(1) {
		t.Errorf("the timeline records %v failed segments, want 1", got)
	}

	// Under a view that withholds nothing, a segment that does not open still
	// leaves the search incomplete.
	mustHash(t, ViewDefine(stringObj("everything"), viewArray("open", "pii", "restricted")))
	whole := searchRecord(t, broken(2), stringObj("XYZ"), underView("everything"))
	for key, want := range map[string]int64{"failed_segments": 1, "searched_segments": 7, "withheld_segments": 0} {
		if got := mustHashIntValue(t, whole, key); got != want {
			t.Errorf("under everything, %s is %d, want %d", key, got, want)
		}
	}
	if mustHashBoolValue(t, whole, "complete") {
		t.Error("a search that withheld nothing and could not open a segment says it was complete")
	}

	// A segment whose bytes cannot be read from the file at all is a finding
	// of its own kind: here the file is closed under the search.
	closed := mustHashValue(t, mustHash(t, RecordOpen(stringObj(f.recordPath))), "handle")
	t.Cleanup(func() { RecordClose(closed) })
	session, _ := recordGet(closed.(*object.Integer).Value)
	session.file.Close()
	unreadable := searchRecord(t, closed, stringObj("XYZ"), underView("counsel"))
	if got := mustHashIntValue(t, unreadable, "failed_segments"); got != 6 || mustHashIntValue(t, unreadable, "count") != 0 {
		t.Errorf("a closed file failed %d of counsel's 6 segments and found %d", got, mustHashIntValue(t, unreadable, "count"))
	}
	for _, row := range mustHashValue(t, unreadable, "failures").(*object.Array).Elements {
		if reason := keyFieldString(t, row.(*object.Hash), "reason"); !strings.Contains(reason, "could not be read from the file") {
			t.Errorf("an unreadable segment is reported as %q", reason)
		}
	}

	// Segment 3 is restricted, which counsel does not read: breaking it changes
	// nothing for counsel, because it is never read from the file. The
	// regulator, who does read it, is told.
	unread := broken(3)
	result = searchRecord(t, unread, stringObj("XYZ"), underView("counsel"))
	if got := mustHashIntValue(t, result, "failed_segments"); got != 0 {
		t.Errorf("counsel's search reports %d failures in segments it does not read", got)
	}
	checkAgainstOracle(t, "beside a broken unread segment", result,
		searchOracle(f.plaintext, searchCounselRuns, []byte("XYZ"), defaultSearchContext, false))
	if got := mustHashIntValue(t, searchRecord(t, unread, stringObj("XYZ"), underView("regulator")), "failed_segments"); got != 1 {
		t.Errorf("the regulator's search reports %d failures, want the broken segment it reads", got)
	}
}

// The documented limits are the enforced ones.
func TestRecordSearchDocumentsItsOwnLimits(t *testing.T) {
	doc := builtinDocs[BuiltinNameRecordSearch]
	if len(doc.params) != 3 {
		t.Fatalf("record_search documents %d parameters", len(doc.params))
	}
	pattern, options := doc.params[1].doc, doc.params[2].doc
	if !strings.Contains(pattern, "1 to "+strconv.Itoa(maxSearchPattern)+" bytes") {
		t.Errorf("the pattern's documentation does not give its limit of %d: %q", maxSearchPattern, pattern)
	}
	for _, want := range []string{
		"0 to " + strconv.Itoa(maxSearchHits) + ", default " + strconv.Itoa(defaultSearchHits),
		"0 to " + strconv.Itoa(maxSearchContext) + ", default " + strconv.Itoa(defaultSearchContext),
	} {
		if !strings.Contains(options, want) {
			t.Errorf("the options' documentation does not say %q: %q", want, options)
		}
	}
}

// The matcher against the slow search, over thousands of generated texts,
// patterns, segmentings and gaps -- small alphabets, so that partial matches
// and overlaps are common and the failure table is exercised in every way.
func TestTheMatcherFindsWhatTheSlowSearchFinds(t *testing.T) {
	rng := rand.New(rand.NewPCG(26, 400))
	alphabet := []byte("abAB")
	type segment struct{ index, offset, size int }
	for trial := range 3000 {
		text := make([]byte, 1+rng.IntN(120))
		for i := range text {
			text[i] = alphabet[rng.IntN(len(alphabet))]
		}
		pattern := make([]byte, 1+rng.IntN(6))
		for i := range pattern {
			pattern[i] = alphabet[rng.IntN(len(alphabet))]
		}
		width, fold, limit := rng.IntN(6), rng.IntN(2) == 0, rng.IntN(4)
		if rng.IntN(2) == 0 {
			limit = maxSearchHits
		}

		s := newRecordSearcher(nil, pattern, fold, uint64(width), limit, nil)
		var runs [][2]int
		var readSegments []segment
		begun := -1
		for offset, index := 0, 0; offset < len(text); index++ {
			size := min(len(text)-offset, 1+rng.IntN(9))
			if rng.IntN(5) != 0 {
				chunk := append([]byte(nil), text[offset:offset+size]...)
				s.extend(security.RecordSegment{Index: uint64(index), Offset: uint64(offset), Length: uint32(size)},
					"class"+strconv.Itoa(index%3), chunk)
				readSegments = append(readSegments, segment{index, offset, size})
				if begun < 0 {
					begun = offset
				}
			} else {
				s.endRun()
				if begun >= 0 {
					runs = append(runs, [2]int{begun, offset})
					begun = -1
				}
			}
			offset += size
		}
		s.endRun()
		if begun >= 0 {
			runs = append(runs, [2]int{begun, len(text)})
		}

		want := searchOracle(text, runs, pattern, width, fold)
		if s.count != int64(len(want)) || len(s.hits) != min(limit, len(want)) {
			t.Fatalf("trial %d: %q in %q over %v: counted %d and kept %d, want %d and %d",
				trial, pattern, text, runs, s.count, len(s.hits), len(want), min(limit, len(want)))
		}
		for i, hit := range s.hits {
			w := want[i]
			var segments []uint64
			var classes, contextClasses []string
			for _, seg := range readSegments {
				class := "class" + strconv.Itoa(seg.index%3)
				if seg.offset < w.offset+len(pattern) && seg.offset+seg.size > w.offset {
					segments = append(segments, uint64(seg.index))
					if !slices.Contains(classes, class) {
						classes = append(classes, class)
					}
				}
				if seg.offset < w.contextOffset+len(w.context) && seg.offset+seg.size > w.contextOffset {
					if !slices.Contains(contextClasses, class) {
						contextClasses = append(contextClasses, class)
					}
				}
			}
			if hit.offset != uint64(w.offset) || hit.contextOffset != uint64(w.contextOffset) ||
				!bytes.Equal(hit.context, w.context) || !slices.Equal(hit.segments, segments) ||
				!slices.Equal(hit.classes, classes) || !slices.Equal(hit.contextClasses, contextClasses) {
				t.Fatalf("trial %d: %q in %q over %v: hit %d is %+v, want offset %d context %q from %d in %v, %v, %v",
					trial, pattern, text, runs, i, hit, w.offset, w.context, w.contextOffset, segments, classes, contextClasses)
			}
		}
	}
}

// However long the run, the search holds a bounded stretch of it: the
// pattern's length and the context width behind the matcher, the width ahead
// of it, and the segment being read -- never the run itself.
func TestASearchHoldsOnlyWhatALaterMatchCanNeed(t *testing.T) {
	s := newRecordSearcher(nil, []byte("zz"), false, 1, maxSearchHits, nil)
	most, pieces := 0, 0
	for i := range 200 {
		s.extend(security.RecordSegment{Index: uint64(i), Offset: uint64(8 * i), Length: 8}, "t", []byte("abcdefgh"))
		most, pieces = max(most, cap(s.buf)), max(pieces, len(s.pieces))
	}
	if most > 64 || pieces > 4 {
		t.Errorf("after 1600 bytes the run held a buffer of up to %d bytes and up to %d segments", most, pieces)
	}
}

// Two segments that do not meet are two runs, whatever order they arrive in:
// no match joins them and no context reaches across the gap.
func TestASearchRunNeverBridgesAGap(t *testing.T) {
	s := newRecordSearcher(nil, []byte("cd"), false, 8, maxSearchHits, nil)
	s.extend(security.RecordSegment{Index: 0, Offset: 0, Length: 3}, "t", []byte("abc"))
	s.extend(security.RecordSegment{Index: 1, Offset: 5, Length: 3}, "t", []byte("def"))
	s.endRun()
	if s.count != 0 {
		t.Fatalf("cd was found across the gap between 3 and 5: %+v", s.hits)
	}

	s = newRecordSearcher(nil, []byte("de"), false, 8, maxSearchHits, nil)
	s.extend(security.RecordSegment{Index: 0, Offset: 0, Length: 3}, "t", []byte("abc"))
	s.extend(security.RecordSegment{Index: 1, Offset: 5, Length: 3}, "t", []byte("def"))
	s.endRun()
	if len(s.hits) != 1 || s.hits[0].offset != 5 || s.hits[0].contextOffset != 5 || string(s.hits[0].context) != "def" {
		t.Fatalf("de after the gap: %+v", s.hits)
	}
}

// Plaintext the search is done with is zeroed: the segment it is handed, the
// bytes it drops behind the matcher, the run it ends, the array it outgrows,
// and its copy of the pattern.
func TestASearchZeroesThePlaintextItIsDoneWith(t *testing.T) {
	zero := func(b []byte) bool { return !slices.ContainsFunc(b, func(c byte) bool { return c != 0 }) }

	s := newRecordSearcher(nil, []byte("zz"), false, 1, maxSearchHits, nil)
	handed := []byte("abcdefgh")
	s.extend(security.RecordSegment{Index: 0, Offset: 0, Length: 8}, "t", handed)
	if !zero(handed) {
		t.Errorf("the segment handed to the run still holds %q", handed)
	}
	// Past the pattern's length less one plus the context, the bytes behind
	// the matcher are dropped, and the space they leave is zero.
	s.extend(security.RecordSegment{Index: 1, Offset: 8, Length: 8}, "t", []byte("ijklmnop"))
	if s.start == 0 {
		t.Fatal("nothing behind the matcher was dropped")
	}
	if tail := s.buf[len(s.buf):cap(s.buf)]; !zero(tail) {
		t.Errorf("the dropped bytes are still in the buffer: %q", tail)
	}
	backing := s.buf[:cap(s.buf)]
	s.endRun()
	if !zero(backing) {
		t.Errorf("the ended run still holds %q", backing)
	}

	old := []byte("abc")
	grown := searchAppend(old[:3:3], []byte("def"))
	if string(grown) != "abcdef" || !zero(old) {
		t.Errorf("grew to %q and left %q in the outgrown array", grown, old)
	}

	f := newDiscloseFixture(t)
	session, _ := recordGet(f.record.(*object.Integer).Value)
	searcher := newRecordSearcher(session, []byte("XYZ"), false, 4, maxSearchHits, func(uint64) bool { return true })
	needle := searcher.needle
	if errObj := searcher.run(BuiltinNameRecordSearch); errObj != nil {
		t.Fatal(errObj.Message)
	}
	if searcher.count != 15 || !zero(needle) {
		t.Errorf("found %d of 15, and the pattern's copy holds %q afterwards", searcher.count, needle)
	}
}
