package builtin

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// redactSecret is the needle every byte-level test in this file looks for. Long
// and distinctive, so a hit in a store file is the value and not a collision.
const redactSecret = "SSN-000-11-2222-REDACTME"

// ledgerFilesHolding reports which files in a ledger directory contain needle.
//
// The only honest way to ask whether a redaction destroyed anything. Every
// other check in this file reads what the tool says; this one reads the disk.
func ledgerFilesHolding(t *testing.T, dir, needle string) []string {
	t.Helper()

	var hits []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if bytes.Contains(data, []byte(needle)) {
			hits = append(hits, filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %s", dir, err)
	}
	sort.Strings(hits)
	return hits
}

// ledgerHasFileMatching reports whether any hit has the given prefix.
func ledgerHasFileMatching(hits []string, prefix string) bool {
	for _, hit := range hits {
		if strings.HasPrefix(hit, prefix) {
			return true
		}
	}
	return false
}

// ledgerIntList reads an array of integers out of a returned hash.
func ledgerIntList(t *testing.T, hash *object.Hash, key string) []int64 {
	t.Helper()

	value, ok := hashValueByStringKey(hash, key)
	if !ok {
		t.Fatalf("no %q field", key)
	}
	list, ok := value.(*object.Array)
	if !ok {
		t.Fatalf("%q is %T, want ARRAY", key, value)
	}
	out := make([]int64, 0, len(list.Elements))
	for i, element := range list.Elements {
		number, ok := element.(*object.Integer)
		if !ok {
			t.Fatalf("%s[%d] is %T, want INTEGER", key, i, element)
		}
		out = append(out, number.Value)
	}
	return out
}

// ledgerStringList reads an array of strings out of a returned hash.
func ledgerStringList(t *testing.T, hash *object.Hash, key string) []string {
	t.Helper()

	value, ok := hashValueByStringKey(hash, key)
	if !ok {
		t.Fatalf("no %q field", key)
	}
	list, ok := value.(*object.Array)
	if !ok {
		t.Fatalf("%q is %T, want ARRAY", key, value)
	}
	out := make([]string, 0, len(list.Elements))
	for i, element := range list.Elements {
		text, ok := element.(*object.String)
		if !ok {
			t.Fatalf("%s[%d] is %T, want STRING", key, i, element)
		}
		out = append(out, text.Value)
	}
	return out
}

// ledgerProofBytes pulls the exported proof out of a proof result.
func ledgerProofBytes(t *testing.T, name string, hash *object.Hash) []byte {
	t.Helper()

	value, ok := hashValueByStringKey(hash, "proof")
	if !ok {
		t.Fatalf("%s returned no proof field", name)
	}
	blob, ok := value.(*object.Bytes)
	if !ok {
		t.Fatalf("%s returned proof of type %T, want BYTES", name, value)
	}
	return blob.Value
}

// ledgerRefusal insists a call failed and returns what it said.
func ledgerRefusal(t *testing.T, name string, result object.Object) string {
	t.Helper()

	payload, errObj := unwrapPairNoFatal(result)
	if errObj == nil {
		t.Fatalf("%s returned %s where a refusal was expected", name, payload.Inspect())
	}
	return errObj.Message
}

// redactableTestLedger is a ledger holding one node with a sensitive property,
// a second node, and an edge between them, compacted once so that everything is
// in the image and one segment has been retired.
func redactableTestLedger(t *testing.T) (handle int64, dir string, subject, other, edge int64) {
	t.Helper()

	handle, dir = openTestLedger(t, "G. Gogia")
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"uid": "rec-0001", "ssn": redactSecret})))
	subject = mustHashIntValue(t, written, "id")

	second := mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"uid": "rec-0002"})))
	other = mustHashIntValue(t, second, "id")

	joined := mustLedgerHash(t, BuiltinNameLedgerAddEdge, LedgerAddEdge(intObj(handle),
		intObj(subject), intObj(other), ledgerProps(map[string]string{"kind": "KNOWS"})))
	edge = mustHashIntValue(t, joined, "id")

	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))
	return handle, dir, subject, other, edge
}

// TestARedactionKeepsEverythingAboutItselfAndDestroysOnlyTheContent is the
// shape of the family: the record is complete, the entity survives, and the
// value it carried does not.
func TestARedactionKeepsEverythingAboutItselfAndDestroysOnlyTheContent(t *testing.T) {
	handle, _, subject, _, edge := redactableTestLedger(t)

	const reason = "subject access request 2026-114, lawful erasure of personal data"
	record := mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj(reason)))

	if got := mustHashIntValue(t, record, "seq"); got != 1 {
		t.Errorf("the first redaction is sequence %d, want 1", got)
	}
	if got := mustHashStringValue(t, record, "scope"); got != "properties" {
		t.Errorf("scope is %q, want properties", got)
	}
	if got := mustHashIntValue(t, record, "node_id"); got != subject {
		t.Errorf("node_id is %d, want %d", got, subject)
	}
	if got := mustHashStringValue(t, record, "reason"); got != reason {
		t.Errorf("reason is %q, want the one supplied", got)
	}
	if got := mustHashStringValue(t, record, "actor"); got != "G. Gogia" {
		t.Errorf("actor is %q, want the name the session asserted", got)
	}
	if !mustHashBoolValue(t, record, "signed") {
		t.Error("a redaction in a strict ledger came back unsigned")
	}
	if mustHashIntValue(t, record, "unix") <= 0 {
		t.Error("the record carries no time")
	}

	// The three hashes that make the record mean something. version_hash is
	// what was destroyed, surviving_hash what was left, prior_properties_hash
	// the separated digest that makes the removal provable without the content.
	for _, field := range []string{"version_hash", "surviving_hash", "prior_properties_hash", "hash"} {
		if got := mustHashStringValue(t, record, field); len(got) != ledgerRootHexLen || strings.Trim(got, "0") == "" {
			t.Errorf("%s is %q, want a non-zero 64-character hash", field, got)
		}
	}
	// The first record in the chain links to nothing.
	if got := mustHashStringValue(t, record, "prev"); strings.Trim(got, "0") != "" {
		t.Errorf("the first record's prev is %q, want all zeroes", got)
	}

	// The entity and its relationships survive: this is the lawful-erasure
	// scope, and the graph's shape was never in scope.
	session := ledgerSessionFor(t, handle)
	if _, err := session.store.RedactionImpactFor(store.NodeID(subject)); err != nil {
		t.Errorf("the node did not survive a property redaction: %s", err)
	}
	if _, err := session.store.ProveEdgeRedaction(store.EdgeID(edge)); err == nil {
		t.Error("a property redaction removed an edge")
	}

	// And the value is no longer answerable from the property index, which is
	// separate storage from the blob and would otherwise keep it queryable.
	for _, entry := range session.graph.NodePropertyEntries(store.NodeID(subject)) {
		t.Errorf("the property index still holds %s = %q after a redaction", entry.Key, entry.Value)
	}
}

// TestTheContentSurvivesInARetiredSegmentAndTheReportSaysSo is the finding this
// item turns on.
//
// A redaction rewrites the live graph and, at the next compaction, the image.
// It rewrites no retired write-ahead segment, and ledger_open keeps every one of
// them so that each commit's actor, timestamp and signature survive compaction.
// So the content is still in the directory, and a report that did not say so
// would let a ledger be handed over as redacted.
func TestTheContentSurvivesInARetiredSegmentAndTheReportSaysSo(t *testing.T) {
	handle, dir, subject, _, _ := redactableTestLedger(t)

	before := ledgerFilesHolding(t, dir, redactSecret)
	if !ledgerHasFileMatching(before, "graphene.csr") {
		t.Fatalf("the compacted image does not hold the value to begin with: %v", before)
	}

	record := mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure order 2026-114")))
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	after := ledgerFilesHolding(t, dir, redactSecret)
	if ledgerHasFileMatching(after, "graphene.csr") {
		t.Errorf("the compacted image still holds the redacted value: %v", after)
	}
	if len(after) == 0 {
		t.Fatalf("the value is gone from the whole directory, so this ledger's retention " +
			"policy no longer keeps retired segments and the gap below is now false")
	}

	// It is in a retired segment, and that is the one copy nothing here removes.
	segments, err := disk.ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments: %s", err)
	}
	if len(segments) == 0 {
		t.Fatal("no segment was retired, so there is nothing to make this claim about")
	}
	if got := mustHashIntValue(t, record, "retained_segments"); got <= 0 {
		t.Errorf("the redaction reports %d retained segments over a ledger that has %d", got, len(segments))
	}
	if got := mustHashIntValue(t, record, "retained_segment_bytes"); got <= 0 {
		t.Errorf("retained_segment_bytes is %d over %d segment(s)", got, len(segments))
	}

	// And custody says it, as a gap this tool wrote rather than one graphene
	// did -- graphene cannot know what retention policy it was opened under.
	report := mustLedgerHash(t, BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(subject)))
	found := false
	for _, gap := range gapsInLayer(ledgerGaps(t, BuiltinNameLedgerCustody, report), "redaction") {
		if gap.source != "mutant" {
			continue
		}
		found = true
		if !strings.Contains(gap.detail, "write-ahead segment") {
			t.Errorf("the retained-content gap does not name the segments: %q", gap.detail)
		}
		if !strings.Contains(gap.remedy, "none in this language") {
			t.Errorf("the retained-content gap offers a remedy this language does not have: %q", gap.remedy)
		}
		if gap.fatal {
			t.Error("the retained-content gap is fatal; nothing is broken, the trade is deliberate")
		}
	}
	if !found {
		t.Error("a custody report on a redacted entity says nothing about the retired segments")
	}
}

// TestRedactingBeforeTheFirstCompactionDoesNotAvoidTheSegment is the other half
// of the same finding, and the one that makes it unconditional.
//
// The obvious workaround -- redact before anything has been compacted -- does
// not work, because the compaction that makes a redaction permanent is the same
// operation that rotates the live log into a retired segment, content and all.
func TestRedactingBeforeTheFirstCompactionDoesNotAvoidTheSegment(t *testing.T) {
	handle, dir := openTestLedger(t, "G. Gogia")
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"uid": "rec-0001", "ssn": redactSecret})))
	subject := mustHashIntValue(t, written, "id")

	record := mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure before any compaction")))

	// Nothing has been compacted, so nothing has been retired yet.
	if got := mustHashIntValue(t, record, "retained_segments"); got != 0 {
		t.Errorf("an uncompacted ledger reports %d retained segments", got)
	}

	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	hits := ledgerFilesHolding(t, dir, redactSecret)
	if ledgerHasFileMatching(hits, "graphene.csr") {
		t.Errorf("the image built after the redaction holds the redacted value: %v", hits)
	}
	if !ledgerHasFileMatching(hits, "graphene.0") {
		t.Errorf("the first compaction did not archive the pre-redaction write into a segment, "+
			"which is what this test exists to pin: %v", hits)
	}
}

// TestAReasonThatNamesWhatIsBeingDestroyedIsRefused guards the one free-text
// field, which is written to two append-only files neither of which is
// redactable.
func TestAReasonThatNamesWhatIsBeingDestroyedIsRefused(t *testing.T) {
	handle, _, subject, _, edge := redactableTestLedger(t)

	message := ledgerRefusal(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject),
			stringObj("erasing "+redactSecret+" under order 2026-114")))
	for _, want := range []string{"ssn", "audit log", "Say why, not what"} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal does not mention %q: %s", want, message)
		}
	}

	// It is the values that are checked, not the keys: a reason may name the
	// field it is erasing, which is how an order is usually written.
	mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject),
			stringObj("erasure of the ssn field under order 2026-114")))

	// And it applies to edges, from the edge's own index entries.
	if message := ledgerRefusal(t, BuiltinNameLedgerRedactEdgeProperties,
		LedgerRedactEdgeProperties(intObj(handle), intObj(edge),
			stringObj("the KNOWS relationship is disputed"))); !strings.Contains(message, "kind") {
		t.Errorf("an edge reason repeating a property value was not refused by value: %s", message)
	}
}

// TestAShortValueIsNotComparedBecauseTheMatchWouldMeanNothing keeps the leak
// check from becoming noise, which is how a check comes to be worked around.
func TestAShortValueIsNotComparedBecauseTheMatchWouldMeanNothing(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"n": "42", "uid": "rec-0001"})))
	subject := mustHashIntValue(t, written, "id")

	// "42" appears in the reason, and is below the length at which a match says
	// anything. The redaction goes ahead.
	mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject),
			stringObj("erasure under order 2026-42, paragraph 7")))
}

// TestWhitespaceIsNotAReasonAlthoughGrapheneAcceptsIt pins both halves: what
// the library does, and the line this language draws instead.
func TestWhitespaceIsNotAReasonAlthoughGrapheneAcceptsIt(t *testing.T) {
	handle, _, subject, other, _ := redactableTestLedger(t)

	for _, reason := range []string{"", "   ", "\t\n"} {
		message := ledgerRefusal(t, BuiltinNameLedgerRedactNodeProperties,
			LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj(reason)))
		if !strings.Contains(message, "must state a reason") {
			t.Errorf("reason %q was refused for the wrong reason: %s", reason, message)
		}
	}

	// graphene refuses only the empty string. If that ever changes, or if the
	// check above is ever dropped, this says so rather than letting an
	// unexplained redaction into a ledger.
	session := ledgerSessionFor(t, handle)
	if _, err := session.store.RedactNodeProperties(store.NodeID(other),
		disk.RedactionRequest{ActorID: session.actorID, Reason: "   "}); err != nil {
		t.Fatalf("graphene now refuses a whitespace reason (%s), so the compensation above "+
			"is no longer what makes this safe", err)
	}
}

// TestTheFourScopesAreFourDifferentOperations is why there is no scope
// argument: collapsing them would let a script erase a subgraph while believing
// it erased a field.
func TestTheFourScopesAreFourDifferentOperations(t *testing.T) {
	t.Run("node properties leave the node and its edges", func(t *testing.T) {
		handle, _, subject, _, edge := redactableTestLedger(t)
		record := mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
			LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure")))
		if got := mustHashIntValue(t, record, "cascade_count"); got != 0 {
			t.Errorf("a property strip cascaded to %d edges", got)
		}
		if got := mustHashStringValue(t, record, "surviving_hash"); strings.Trim(got, "0") == "" {
			t.Error("a property strip recorded no surviving hash, so nothing survived")
		}
		session := ledgerSessionFor(t, handle)
		if found, _, err := session.graph.GetEdges([]store.EdgeID{store.EdgeID(edge)}); err != nil || len(found) != 1 {
			t.Errorf("the edge did not survive: %d found, err=%v", len(found), err)
		}
	})

	t.Run("a node takes every edge touching it", func(t *testing.T) {
		handle, _, subject, _, edge := redactableTestLedger(t)
		record := mustLedgerHash(t, BuiltinNameLedgerRedactNode,
			LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116")))
		if got := mustHashStringValue(t, record, "scope"); got != "node" {
			t.Errorf("scope is %q, want node", got)
		}
		cascaded := ledgerIntList(t, record, "cascaded_edges")
		if len(cascaded) != 1 || cascaded[0] != edge {
			t.Errorf("cascaded_edges is %v, want [%d]", cascaded, edge)
		}
		// Each cascaded edge is identified, not merely named: an edge taken as
		// collateral gets the same standing as one removed deliberately.
		if got := ledgerStringList(t, record, "cascaded_hashes"); len(got) != len(cascaded) {
			t.Errorf("%d cascaded edges carry %d hashes", len(cascaded), len(got))
		}
		if got := mustHashStringValue(t, record, "surviving_hash"); strings.Trim(got, "0") != "" {
			t.Errorf("a whole-node redaction recorded a surviving hash %q", got)
		}
	})

	t.Run("an edge goes on its own, leaving both endpoints", func(t *testing.T) {
		handle, _, subject, other, edge := redactableTestLedger(t)
		record := mustLedgerHash(t, BuiltinNameLedgerRedactEdge,
			LedgerRedactEdge(intObj(handle), intObj(edge), stringObj("relationship disputed")))
		if got := mustHashStringValue(t, record, "scope"); got != "edge" {
			t.Errorf("scope is %q, want edge", got)
		}
		if got := mustHashIntValue(t, record, "edge_id"); got != edge {
			t.Errorf("edge_id is %d, want %d", got, edge)
		}
		if got := mustHashIntValue(t, record, "node_id"); got != 0 {
			t.Errorf("an edge redaction names node %d; the namespaces are separate", got)
		}
		session := ledgerSessionFor(t, handle)
		for _, id := range []int64{subject, other} {
			if _, err := session.store.RedactionImpactFor(store.NodeID(id)); err != nil {
				t.Errorf("endpoint %d did not survive an edge redaction: %s", id, err)
			}
		}
	})

	t.Run("edge properties leave the relationship", func(t *testing.T) {
		handle, _, _, _, edge := redactableTestLedger(t)
		record := mustLedgerHash(t, BuiltinNameLedgerRedactEdgeProperties,
			LedgerRedactEdgeProperties(intObj(handle), intObj(edge), stringObj("erasure order 2026-115")))
		if got := mustHashStringValue(t, record, "scope"); got != "properties" {
			t.Errorf("scope is %q, want properties", got)
		}
		if got := mustHashIntValue(t, record, "edge_id"); got != edge {
			t.Errorf("edge_id is %d, want %d", got, edge)
		}
		session := ledgerSessionFor(t, handle)
		if found, _, err := session.graph.GetEdges([]store.EdgeID{store.EdgeID(edge)}); err != nil || len(found) != 1 {
			t.Errorf("the relationship did not survive a property strip: %d found, err=%v", len(found), err)
		}
	})
}

// TestARedactionIsAllOfAnEntitysPropertiesOrNoneOfThem states the limit at the
// point where somebody would otherwise discover it by losing a field.
func TestARedactionIsAllOfAnEntitysPropertiesOrNoneOfThem(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"uid": "rec-0001", "ssn": redactSecret, "case": "IR-2026-0944"})))
	subject := mustHashIntValue(t, written, "id")

	mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure of one field")))

	session := ledgerSessionFor(t, handle)
	for _, entry := range session.graph.NodePropertyEntries(store.NodeID(subject)) {
		t.Errorf("%s survived a redaction aimed at one field: %q", entry.Key, entry.Value)
	}
}

// TestARedactionIsRecordedBeforeItIsProvable pins the window, and the remedy
// for it, and that the remedy goes away once it has been followed.
func TestARedactionIsRecordedBeforeItIsProvable(t *testing.T) {
	handle, _, subject, _, _ := redactableTestLedger(t)

	record := mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure order 2026-114")))
	if mustHashBoolValue(t, record, "provable") {
		t.Error("a redaction reported itself provable before any compaction bound it into the image")
	}

	before := mustLedgerHash(t, BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(subject)))
	if mustHashBoolValue(t, before, "removal_provable") {
		t.Error("custody reports removal_provable inside the window")
	}
	window := gapsInLayer(ledgerGaps(t, BuiltinNameLedgerCustody, before), "redaction")
	remedied := false
	for _, gap := range window {
		if gap.source == "graphene" && strings.Contains(gap.remedy, BuiltinNameLedgerCompact) {
			remedied = true
		}
	}
	if !remedied {
		t.Errorf("no graphene redaction gap carries the compaction remedy: %+v", window)
	}

	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	after := mustLedgerHash(t, BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(subject)))
	if !mustHashBoolValue(t, after, "removal_provable") {
		t.Error("custody still reports removal_provable false after the compaction that binds it")
	}
	for _, gap := range gapsInLayer(ledgerGaps(t, BuiltinNameLedgerCustody, after), "redaction") {
		if gap.source == "graphene" && strings.Contains(gap.remedy, BuiltinNameLedgerCompact) {
			t.Errorf("the compaction remedy survived the compaction: %q", gap.detail)
		}
	}
}

// TestAnImpactPreviewIsTheSetTheRecordDescribes is why the preview hashes what
// it reports: a manifest can record the set an examiner was shown, and a
// recipient can check that it is the set that went.
func TestAnImpactPreviewIsTheSetTheRecordDescribes(t *testing.T) {
	handle, _, subject, other, edge := redactableTestLedger(t)
	second := mustLedgerHash(t, BuiltinNameLedgerAddEdge, LedgerAddEdge(intObj(handle),
		intObj(other), intObj(subject), ledgerProps(map[string]string{"kind": "SEEN"})))
	secondEdge := mustHashIntValue(t, second, "id")

	impact := mustLedgerHash(t, BuiltinNameLedgerRedactionImpact,
		LedgerRedactionImpact(intObj(handle), intObj(subject)))
	if got := mustHashIntValue(t, impact, "cascade_count"); got != 2 {
		t.Errorf("cascade_count is %d over two incident edges", got)
	}
	previewed := ledgerIntList(t, impact, "cascaded_edges")
	sort.Slice(previewed, func(i, j int) bool { return previewed[i] < previewed[j] })
	if len(previewed) != 2 || previewed[0] != edge || previewed[1] != secondEdge {
		t.Fatalf("cascaded_edges is %v, want [%d %d]", previewed, edge, secondEdge)
	}
	previewHashes := ledgerStringList(t, impact, "cascaded_hashes")

	// Nothing has been destroyed: the preview is callable twice, and so is the
	// proof that the entity is still there.
	mustLedgerHash(t, BuiltinNameLedgerRedactionImpact, LedgerRedactionImpact(intObj(handle), intObj(subject)))

	record := mustLedgerHash(t, BuiltinNameLedgerRedactNode,
		LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116")))
	recorded := ledgerIntList(t, record, "cascaded_edges")
	sort.Slice(recorded, func(i, j int) bool { return recorded[i] < recorded[j] })
	if len(recorded) != len(previewed) {
		t.Fatalf("the record removed %d edges where the preview showed %d", len(recorded), len(previewed))
	}
	for i := range recorded {
		if recorded[i] != previewed[i] {
			t.Errorf("edge %d in the record is %d, in the preview %d", i, recorded[i], previewed[i])
		}
	}
	recordedHashes := ledgerStringList(t, record, "cascaded_hashes")
	sort.Strings(previewHashes)
	sort.Strings(recordedHashes)
	for i := range recordedHashes {
		if recordedHashes[i] != previewHashes[i] {
			t.Errorf("hash %d differs between the preview and the record", i)
		}
	}
	if got := mustHashStringValue(t, record, "version_hash"); got != mustHashStringValue(t, impact, "version_hash") {
		t.Error("the version hash the preview showed is not the one the record carries")
	}
}

// TestThereIsNoExceedsPolicyFieldBecauseNoPolicyIsSet pins the reason the field
// is absent rather than false, and fails if the posture ever gains a limit
// without the field coming back.
func TestThereIsNoExceedsPolicyFieldBecauseNoPolicyIsSet(t *testing.T) {
	handle, _, subject, _, _ := redactableTestLedger(t)

	session := ledgerSessionFor(t, handle)
	impact, err := session.store.RedactionImpactFor(store.NodeID(subject))
	if err != nil {
		t.Fatalf("RedactionImpactFor: %s", err)
	}
	if impact.ExceedsPolicy {
		t.Fatal("this posture now sets a cascade limit, so an exceeds_policy field would mean something")
	}

	report := mustLedgerHash(t, BuiltinNameLedgerRedactionImpact,
		LedgerRedactionImpact(intObj(handle), intObj(subject)))
	if _, ok := hashValueByStringKey(report, "exceeds_policy"); ok {
		t.Error("ledger_redaction_impact reports exceeds_policy, which is false on every ledger it can open")
	}
}

// TestARemovalProofTellsDeliberateFromNeverExisted is what a tombstone is for:
// to the party handed one image and nothing else, an absence is an absence.
func TestARemovalProofTellsDeliberateFromNeverExisted(t *testing.T) {
	handle, _, subject, _, _ := redactableTestLedger(t)
	mustLedgerHash(t, BuiltinNameLedgerRedactNode,
		LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116")))
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	root := mustHashStringValue(t,
		mustLedgerHash(t, BuiltinNameLedgerRootExport, LedgerRootExport(intObj(handle))), "snapshot_root")

	proof := mustLedgerHash(t, BuiltinNameLedgerProveRedaction,
		LedgerProveRedaction(intObj(handle), intObj(subject)))
	if got := mustHashStringValue(t, proof, "scope"); got != "node" {
		t.Errorf("the proof's scope is %q, want node", got)
	}
	if got := mustHashIntValue(t, proof, "redaction_seq"); got != 1 {
		t.Errorf("the proof names redaction %d, want 1", got)
	}

	// The whole point: a proof built here is checked by the verifier that takes
	// the root as an argument, with no ledger involved.
	verdict := mustLedgerHash(t, BuiltinNameLedgerVerifyProof,
		LedgerVerifyProof(&object.Bytes{Value: ledgerProofBytes(t, BuiltinNameLedgerProveRedaction, proof)},
			stringObj(root)))
	if !mustHashBoolValue(t, verdict, "verified") {
		t.Errorf("a removal proof did not verify: %s", mustHashStringValue(t, verdict, "reason"))
	}
	if got := mustHashStringValue(t, verdict, "kind"); got != "redaction" {
		t.Errorf("the verifier read the proof as %q", got)
	}

	// And the entity's absence now reads as a removal rather than as a typo.
	message := ledgerRefusal(t, BuiltinNameLedgerProveNode, LedgerProveNode(intObj(handle), intObj(subject)))
	if !strings.Contains(message, "redacted") || !strings.Contains(message, "court order 2026-116") {
		t.Errorf("ledger_prove_node reports a redacted entity as merely absent: %s", message)
	}
}

// TestACascadedEdgeGetsAProofOfItsOwn -- an edge removed as collateral is as
// absent as one removed deliberately.
func TestACascadedEdgeGetsAProofOfItsOwn(t *testing.T) {
	handle, _, subject, _, edge := redactableTestLedger(t)
	mustLedgerHash(t, BuiltinNameLedgerRedactNode,
		LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116")))
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	root := mustHashStringValue(t,
		mustLedgerHash(t, BuiltinNameLedgerRootExport, LedgerRootExport(intObj(handle))), "snapshot_root")

	proof := mustLedgerHash(t, BuiltinNameLedgerProveEdgeRedaction,
		LedgerProveEdgeRedaction(intObj(handle), intObj(edge)))
	if got := mustHashIntValue(t, proof, "edge_id"); got != edge {
		t.Errorf("the proof is about edge %d, want %d", got, edge)
	}
	if got := mustHashIntValue(t, proof, "node_id"); got != 0 {
		t.Errorf("an edge tombstone names node %d", got)
	}
	verdict := mustLedgerHash(t, BuiltinNameLedgerVerifyProof,
		LedgerVerifyProof(&object.Bytes{Value: ledgerProofBytes(t, BuiltinNameLedgerProveEdgeRedaction, proof)},
			stringObj(root)))
	if !mustHashBoolValue(t, verdict, "verified") {
		t.Errorf("a cascaded edge's removal proof did not verify: %s", mustHashStringValue(t, verdict, "reason"))
	}
}

// TestAPropertyRedactionProofCarriesNoContent is the claim that proof exists to
// make, checked the only way that means anything: by looking at the bytes.
func TestAPropertyRedactionProofCarriesNoContent(t *testing.T) {
	handle, _, subject, _, _ := redactableTestLedger(t)
	mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure order 2026-114")))
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	root := mustHashStringValue(t,
		mustLedgerHash(t, BuiltinNameLedgerRootExport, LedgerRootExport(intObj(handle))), "snapshot_root")

	proof := mustLedgerHash(t, BuiltinNameLedgerProvePropertyRedaction,
		LedgerProvePropertyRedaction(intObj(handle), intObj(subject)))

	blob := ledgerProofBytes(t, BuiltinNameLedgerProvePropertyRedaction, proof)
	if bytes.Contains(blob, []byte(redactSecret)) {
		t.Error("a content-free proof carries the content it was built to conceal")
	}

	// The prior and surviving leaves are the same shape and differ only in
	// their last 32 bytes. That is the entire claim, and a reader seeing two
	// lengths is looking at a proof about something else.
	prior := mustHashIntValue(t, proof, "prior_leaf_bytes")
	surviving := mustHashIntValue(t, proof, "surviving_leaf_bytes")
	if prior != surviving {
		t.Errorf("prior_leaf_bytes %d and surviving_leaf_bytes %d differ", prior, surviving)
	}
	if prior <= 0 {
		t.Error("the proof carries no prior leaf")
	}

	verdict := mustLedgerHash(t, BuiltinNameLedgerVerifyProof,
		LedgerVerifyProof(&object.Bytes{Value: blob}, stringObj(root)))
	if !mustHashBoolValue(t, verdict, "verified") {
		t.Errorf("a property-redaction proof did not verify: %s", mustHashStringValue(t, verdict, "reason"))
	}
	if got := mustHashStringValue(t, verdict, "kind"); got != "property-redaction" {
		t.Errorf("the verifier read the proof as %q", got)
	}
}

// TestEachRefusalSeparatesWhatGrapheneConflates is the file's compensation
// layer: every case below is one graphene error standing for two situations
// with opposite responses.
func TestEachRefusalSeparatesWhatGrapheneConflates(t *testing.T) {
	t.Run("an id this ledger never held", func(t *testing.T) {
		handle, _, _, _, _ := redactableTestLedger(t)
		message := ledgerRefusal(t, BuiltinNameLedgerRedactNode,
			LedgerRedactNode(intObj(handle), intObj(424242), stringObj("absent")))
		if !strings.Contains(message, "no record of ever having had one") {
			t.Errorf("an absent id was not reported as absent: %s", message)
		}
	})

	t.Run("an id it held and redacted", func(t *testing.T) {
		handle, _, subject, _, _ := redactableTestLedger(t)
		mustLedgerHash(t, BuiltinNameLedgerRedactNode,
			LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116")))
		message := ledgerRefusal(t, BuiltinNameLedgerRedactNode,
			LedgerRedactNode(intObj(handle), intObj(subject), stringObj("and again")))
		if !strings.Contains(message, "was redacted at") || !strings.Contains(message, "court order 2026-116") {
			t.Errorf("a redacted entity reads as one that never existed: %s", message)
		}
	})

	t.Run("properties that are already gone", func(t *testing.T) {
		handle, _, subject, _, _ := redactableTestLedger(t)
		mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
			LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure order 2026-114")))
		message := ledgerRefusal(t, BuiltinNameLedgerRedactNodeProperties,
			LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("again")))
		if !strings.Contains(message, "already redacted") {
			t.Errorf("a second strip does not name the first: %s", message)
		}
	})

	t.Run("an entity written without properties", func(t *testing.T) {
		handle, _, _, _, _ := redactableTestLedger(t)
		// A node whose properties were never written at all, which is the other
		// situation graphene's one message covers. ledger_add_node says so at
		// write time -- redactable comes back false -- and this is what happens
		// to a caller who did not read it.
		bare := mustLedgerHash(t, BuiltinNameLedgerAddNode,
			LedgerAddNode(intObj(handle), makeHashObject(nil)))
		if mustHashBoolValue(t, bare, "redactable") {
			t.Error("an entity written with no properties reports itself redactable")
		}
		message := ledgerRefusal(t, BuiltinNameLedgerRedactNodeProperties,
			LedgerRedactNodeProperties(intObj(handle), intObj(mustHashIntValue(t, bare, "id")), stringObj("erasure")))
		if !strings.Contains(message, "written without properties") {
			t.Errorf("an entity that never had properties reads as one already stripped: %s", message)
		}
	})

	t.Run("a removal proof for an entity nobody redacted", func(t *testing.T) {
		handle, _, _, other, _ := redactableTestLedger(t)
		message := ledgerRefusal(t, BuiltinNameLedgerProveRedaction,
			LedgerProveRedaction(intObj(handle), intObj(other)))
		if !strings.Contains(message, "records no redaction") || !strings.Contains(message, BuiltinNameLedgerProveNode) {
			t.Errorf("the refusal does not send a caller to the proof they wanted: %s", message)
		}
	})

	t.Run("a removal proof inside the window", func(t *testing.T) {
		handle, _, subject, _, _ := redactableTestLedger(t)
		mustLedgerHash(t, BuiltinNameLedgerRedactNode,
			LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116")))
		message := ledgerRefusal(t, BuiltinNameLedgerProveRedaction,
			LedgerProveRedaction(intObj(handle), intObj(subject)))
		if !strings.Contains(message, BuiltinNameLedgerCompact) || !strings.Contains(message, "redaction 1") {
			t.Errorf("a recorded-but-unbound removal reads as one that never happened: %s", message)
		}
	})

	t.Run("a property proof for an entity removed outright", func(t *testing.T) {
		handle, _, subject, _, _ := redactableTestLedger(t)
		mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
			LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure order 2026-114")))
		mustLedgerHash(t, BuiltinNameLedgerRedactNode,
			LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116")))
		mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))
		message := ledgerRefusal(t, BuiltinNameLedgerProvePropertyRedaction,
			LedgerProvePropertyRedaction(intObj(handle), intObj(subject)))
		if !strings.Contains(message, BuiltinNameLedgerProveRedaction) {
			t.Errorf("the refusal does not name the proof that is true of this entity: %s", message)
		}
	})

	t.Run("an edge a node redaction took as collateral", func(t *testing.T) {
		handle, _, subject, _, edge := redactableTestLedger(t)
		mustLedgerHash(t, BuiltinNameLedgerRedactNode,
			LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116")))

		// The edge is gone, and the ledger holds a signed record naming it in
		// that order's cascade -- so "this ledger never had it" would be false.
		// It was not the subject of the decision either, so reporting the court
		// order as an edge redaction would be false the other way.
		message := ledgerRefusal(t, BuiltinNameLedgerRedactEdge,
			LedgerRedactEdge(intObj(handle), intObj(edge), stringObj("relationship disputed")))
		if strings.Contains(message, "no record of ever having had one") {
			t.Errorf("an edge removed as collateral reads as one that never existed: %s", message)
		}
		for _, want := range []string{"collateral", "court order 2026-116", BuiltinNameLedgerProveEdgeRedaction} {
			if !strings.Contains(message, want) {
				t.Errorf("the refusal does not mention %q: %s", want, message)
			}
		}
	})

	t.Run("a node id where an edge id belongs", func(t *testing.T) {
		handle, _, _, _, _ := redactableTestLedger(t)
		for _, bad := range []object.Object{intObj(0), intObj(-1), stringObj("1")} {
			if message := ledgerRefusal(t, BuiltinNameLedgerRedactEdge,
				LedgerRedactEdge(intObj(handle), bad, stringObj("reason"))); !strings.Contains(message, "edge") {
				t.Errorf("an edge builtin refused %s without naming its namespace: %s", bad.Inspect(), message)
			}
		}
	})
}

// TestTheRedactionLedgerIsChainedAndOutlivesACompaction -- the ledger is its own
// append-only file, which is why a redaction record outlives the entity.
func TestTheRedactionLedgerIsChainedAndOutlivesACompaction(t *testing.T) {
	handle, _, subject, _, edge := redactableTestLedger(t)

	empty := mustLedgerHash(t, BuiltinNameLedgerRedactions, LedgerRedactions(intObj(handle)))
	if got := mustHashIntValue(t, empty, "count"); got != 0 {
		t.Errorf("a ledger that has redacted nothing reports %d records", got)
	}
	if !mustHashBoolValue(t, empty, "chain_intact") {
		t.Error("an empty chain is reported as broken")
	}

	mustLedgerHash(t, BuiltinNameLedgerRedactEdgeProperties,
		LedgerRedactEdgeProperties(intObj(handle), intObj(edge), stringObj("erasure order 2026-115")))
	mustLedgerHash(t, BuiltinNameLedgerRedactNodeProperties,
		LedgerRedactNodeProperties(intObj(handle), intObj(subject), stringObj("erasure order 2026-114")))
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	list := mustLedgerHash(t, BuiltinNameLedgerRedactions, LedgerRedactions(intObj(handle)))
	if got := mustHashIntValue(t, list, "count"); got != 2 {
		t.Fatalf("count is %d after two redactions and a compaction", got)
	}
	if !mustHashBoolValue(t, list, "chain_intact") {
		t.Errorf("the chain does not verify: %s", mustHashStringValue(t, list, "chain_reason"))
	}
	if got := mustHashStringValue(t, list, "chain_reason"); got != "" {
		t.Errorf("an intact chain carries the explanation %q", got)
	}

	value, ok := hashValueByStringKey(list, "redactions")
	if !ok {
		t.Fatal("no redactions array")
	}
	records, ok := value.(*object.Array)
	if !ok || len(records.Elements) != 2 {
		t.Fatalf("redactions is %T with %d elements", value, len(records.Elements))
	}

	// Oldest first, sequences from one, each linking to the one before it.
	first, _ := records.Elements[0].(*object.Hash)
	second, _ := records.Elements[1].(*object.Hash)
	if got := mustHashIntValue(t, first, "seq"); got != 1 {
		t.Errorf("the first record is sequence %d", got)
	}
	if got := mustHashIntValue(t, second, "seq"); got != 2 {
		t.Errorf("the second record is sequence %d", got)
	}
	if mustHashStringValue(t, second, "prev") != mustHashStringValue(t, first, "hash") {
		t.Error("the second record does not link to the first")
	}
	if got := mustHashStringValue(t, list, "head"); got != mustHashStringValue(t, second, "hash") {
		t.Errorf("head is %q, want the last record's hash", got)
	}
	// The record still names the edge whose properties went, after the
	// compaction that rebuilt the image around it.
	if got := mustHashIntValue(t, first, "edge_id"); got != edge {
		t.Errorf("the edge record names edge %d, want %d", got, edge)
	}
}

// TestEveryRedactionBuiltinRefusesAHandleThatIsNotOne.
func TestEveryRedactionBuiltinRefusesAHandleThatIsNotOne(t *testing.T) {
	handle, _, subject, _, edge := redactableTestLedger(t)
	reason := stringObj("a reason")

	for _, tc := range []struct {
		name string
		call func(object.Object) object.Object
	}{
		{BuiltinNameLedgerRedactNode, func(h object.Object) object.Object {
			return LedgerRedactNode(h, intObj(subject), reason)
		}},
		{BuiltinNameLedgerRedactNodeProperties, func(h object.Object) object.Object {
			return LedgerRedactNodeProperties(h, intObj(subject), reason)
		}},
		{BuiltinNameLedgerRedactEdge, func(h object.Object) object.Object {
			return LedgerRedactEdge(h, intObj(edge), reason)
		}},
		{BuiltinNameLedgerRedactEdgeProperties, func(h object.Object) object.Object {
			return LedgerRedactEdgeProperties(h, intObj(edge), reason)
		}},
		{BuiltinNameLedgerRedactionImpact, func(h object.Object) object.Object {
			return LedgerRedactionImpact(h, intObj(subject))
		}},
		{BuiltinNameLedgerRedactions, func(h object.Object) object.Object { return LedgerRedactions(h) }},
		{BuiltinNameLedgerProveRedaction, func(h object.Object) object.Object {
			return LedgerProveRedaction(h, intObj(subject))
		}},
		{BuiltinNameLedgerProveEdgeRedaction, func(h object.Object) object.Object {
			return LedgerProveEdgeRedaction(h, intObj(edge))
		}},
		{BuiltinNameLedgerProvePropertyRedaction, func(h object.Object) object.Object {
			return LedgerProvePropertyRedaction(h, intObj(subject))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bad := range []object.Object{stringObj("1"), intObj(handle + 9999)} {
				if _, errObj := unwrapPair(t, tc.call(bad)); errObj == nil {
					t.Errorf("%s accepted %s as a ledger handle", tc.name, bad.Inspect())
				}
			}
		})
	}
}

// TestEveryRedactionBuiltinChecksItsArity keeps a missing reason from being read
// as an empty one.
func TestEveryRedactionBuiltinChecksItsArity(t *testing.T) {
	handle, _, subject, _, edge := redactableTestLedger(t)
	reason := stringObj("a reason")

	for _, tc := range []struct {
		name string
		call func(...object.Object) object.Object
		args [][]object.Object
	}{
		{BuiltinNameLedgerRedactNode, LedgerRedactNode, [][]object.Object{
			{}, {intObj(handle)}, {intObj(handle), intObj(subject)},
			{intObj(handle), intObj(subject), reason, intObj(1)}}},
		{BuiltinNameLedgerRedactNodeProperties, LedgerRedactNodeProperties, [][]object.Object{
			{}, {intObj(handle), intObj(subject)}, {intObj(handle), intObj(subject), reason, intObj(1)}}},
		{BuiltinNameLedgerRedactEdge, LedgerRedactEdge, [][]object.Object{
			{}, {intObj(handle), intObj(edge)}, {intObj(handle), intObj(edge), reason, intObj(1)}}},
		{BuiltinNameLedgerRedactEdgeProperties, LedgerRedactEdgeProperties, [][]object.Object{
			{}, {intObj(handle), intObj(edge)}, {intObj(handle), intObj(edge), reason, intObj(1)}}},
		{BuiltinNameLedgerRedactionImpact, LedgerRedactionImpact, [][]object.Object{
			{}, {intObj(handle)}, {intObj(handle), intObj(subject), intObj(1)}}},
		{BuiltinNameLedgerRedactions, LedgerRedactions, [][]object.Object{
			{}, {intObj(handle), intObj(1)}}},
		{BuiltinNameLedgerProveRedaction, LedgerProveRedaction, [][]object.Object{
			{}, {intObj(handle)}, {intObj(handle), intObj(subject), intObj(1)}}},
		{BuiltinNameLedgerProveEdgeRedaction, LedgerProveEdgeRedaction, [][]object.Object{
			{}, {intObj(handle)}, {intObj(handle), intObj(edge), intObj(1)}}},
		{BuiltinNameLedgerProvePropertyRedaction, LedgerProvePropertyRedaction, [][]object.Object{
			{}, {intObj(handle)}, {intObj(handle), intObj(subject), intObj(1)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, args := range tc.args {
				if _, errObj := unwrapPair(t, tc.call(args...)); errObj == nil {
					t.Errorf("%s accepted %d arguments", tc.name, len(args))
				}
			}
		})
	}
}

// TestEveryRedactionBuiltinReturnsTheDeclaredFields keeps the metadata and the
// implementations from drifting, which is what hover, completion and the
// conformance probes all read.
func TestEveryRedactionBuiltinReturnsTheDeclaredFields(t *testing.T) {
	handle, _, subject, other, edge := redactableTestLedger(t)
	second := mustLedgerHash(t, BuiltinNameLedgerAddEdge, LedgerAddEdge(intObj(handle),
		intObj(other), intObj(subject), ledgerProps(map[string]string{"kind": "SEEN"})))
	secondEdge := mustHashIntValue(t, second, "id")

	// Each scope is exercised on an entity of its own, because every one of
	// them destroys what it touches.
	stripped := mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"uid": "rec-0003"})))
	strippedID := mustHashIntValue(t, stripped, "id")
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	for _, tc := range []struct {
		name   string
		result object.Object
	}{
		{BuiltinNameLedgerRedactionImpact, LedgerRedactionImpact(intObj(handle), intObj(subject))},
		{BuiltinNameLedgerRedactEdgeProperties, LedgerRedactEdgeProperties(intObj(handle), intObj(secondEdge), stringObj("erasure order 2026-115"))},
		{BuiltinNameLedgerRedactEdge, LedgerRedactEdge(intObj(handle), intObj(secondEdge), stringObj("relationship disputed"))},
		{BuiltinNameLedgerRedactNodeProperties, LedgerRedactNodeProperties(intObj(handle), intObj(strippedID), stringObj("erasure order 2026-114"))},
		{BuiltinNameLedgerRedactNode, LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-116"))},
		{BuiltinNameLedgerRedactions, LedgerRedactions(intObj(handle))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, errObj := unwrapPair(t, tc.result)
			if errObj != nil {
				t.Fatalf("%s: %s", tc.name, errObj.Message)
			}
			assertLedgerDeclaredFields(t, tc.name, payload)
		})
	}

	// The three proofs need the compaction that binds the removals above.
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))
	for _, tc := range []struct {
		name   string
		result object.Object
	}{
		{BuiltinNameLedgerProveRedaction, LedgerProveRedaction(intObj(handle), intObj(subject))},
		{BuiltinNameLedgerProveEdgeRedaction, LedgerProveEdgeRedaction(intObj(handle), intObj(edge))},
		{BuiltinNameLedgerProvePropertyRedaction, LedgerProvePropertyRedaction(intObj(handle), intObj(strippedID))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, errObj := unwrapPair(t, tc.result)
			if errObj != nil {
				t.Fatalf("%s: %s", tc.name, errObj.Message)
			}
			assertLedgerDeclaredFields(t, tc.name, payload)
		})
	}
}
