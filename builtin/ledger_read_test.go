package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

// readableTestLedger is a small graph with a provenance shape in it:
//
//	image -> file -> artefact        (CONTAINS, type 1)
//	         other -> artefact       (a second parent, so the chain branches)
//
// Written unconpacted; the tests that need a compaction ask for one, because
// two of them are about what a compaction does and does not change.
func readableTestLedger(t *testing.T) (handle int64, image, file, artefact, other, edge int64) {
	t.Helper()

	handle, _ = openTestLedger(t, "G. Gogia")
	add := func(props map[string]string, nodeType int64) int64 {
		written := mustLedgerHash(t, BuiltinNameLedgerAddNode,
			LedgerAddNode(intObj(handle), ledgerProps(props), intObj(nodeType)))
		return mustHashIntValue(t, written, "id")
	}
	join := func(src, dst int64, kind string) int64 {
		written := mustLedgerHash(t, BuiltinNameLedgerAddEdge,
			LedgerAddEdge(intObj(handle), intObj(src), intObj(dst), ledgerProps(map[string]string{"kind": kind})))
		return mustHashIntValue(t, written, "id")
	}

	image = add(map[string]string{"uid": "img-0001", "role": "image"}, 1)
	file = add(map[string]string{"uid": "fil-0002", "role": "file"}, 2)
	artefact = add(map[string]string{"uid": "art-0003", "role": "artefact"}, 3)
	other = add(map[string]string{"uid": "oth-0004", "role": "file"}, 2)

	join(image, file, "CONTAINS")
	edge = join(file, artefact, "CONTAINS")
	join(other, artefact, "CONTAINS")
	return handle, image, file, artefact, other, edge
}

// scoredTestLedger writes the five values whose two orderings disagree.
func scoredTestLedger(t *testing.T) (handle int64, byValue map[string]int64) {
	t.Helper()

	handle, _ = openTestLedger(t, "G. Gogia")
	byValue = map[string]int64{}
	for _, value := range []string{"9", "10", "1x", "100", "2"} {
		written := mustLedgerHash(t, BuiltinNameLedgerAddNode,
			LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"score": value})))
		byValue[value] = mustHashIntValue(t, written, "id")
	}
	return handle, byValue
}

// ledgerBetween is the range query whose answer a declaration changes.
func ledgerBetween(t *testing.T, handle int64, key, lower, upper string) *object.Hash {
	t.Helper()

	return mustLedgerHash(t, BuiltinNameLedgerQueryNodes, LedgerQueryNodes(intObj(handle),
		makeHashObject(map[string]object.Object{
			"filters": &object.Array{Elements: []object.Object{
				makeHashObject(map[string]object.Object{
					"key":         stringObj(key),
					"op":          stringObj("between"),
					"value":       stringObj(lower),
					"value_upper": stringObj(upper),
				}),
			}},
		})))
}

// TestDeclaringAnOrderedKeyChangesWhichRecordsMatch is the finding this whole
// file is shaped around.
//
// An index declaration is a performance decision. Here it turns a query that
// matched four records into one that matches none, with no change to the
// query's text and no error anywhere -- absence of evidence manufactured by a
// schema change. If this test ever passes trivially because the two answers
// agree, the reporting below has stopped being necessary and should be
// reconsidered rather than deleted.
func TestDeclaringAnOrderedKeyChangesWhichRecordsMatch(t *testing.T) {
	handle, byValue := scoredTestLedger(t)

	before := ledgerBetween(t, handle, "score", "2", "100")
	beforeIDs := ledgerIntList(t, before, "ids")
	if len(beforeIDs) != 4 {
		t.Fatalf("undeclared, between 2 and 100 matched %d records, want 4 (9, 10, 100, 2)", len(beforeIDs))
	}
	if got := mustHashStringValue(t, before, "comparison"); got != "numeric-then-bytes" {
		t.Errorf("comparison before the declaration is %q, want numeric-then-bytes", got)
	}

	declared := mustLedgerHash(t, BuiltinNameLedgerDeclareOrdered,
		LedgerDeclareOrdered(intObj(handle), stringObj("score"), stringObj("node")))
	if !mustHashBoolValue(t, declared, "order_differs") {
		t.Error("the declaration did not notice that these values reorder")
	}
	example, ok := mustHashValueByStringKey(t, declared, "example").(*object.Hash)
	if !ok {
		t.Fatal("example is not a HASH")
	}
	lower := mustHashValueByStringKey(t, example, "numerically_lower")
	higher := mustHashValueByStringKey(t, example, "byte_wise_lower")
	lowerBytes, ok := lower.(*object.Bytes)
	if !ok {
		t.Fatalf("the example's numerically_lower is %T, want BYTES", lower)
	}
	higherBytes, ok := higher.(*object.Bytes)
	if !ok {
		t.Fatalf("the example's byte_wise_lower is %T, want BYTES", higher)
	}
	if string(lowerBytes.Value) != "9" || string(higherBytes.Value) != "10" {
		t.Errorf("the example pair is %q/%q, want 9/10 -- 9 is the smaller number and the larger string",
			lowerBytes.Value, higherBytes.Value)
	}

	after := ledgerBetween(t, handle, "score", "2", "100")
	afterIDs := ledgerIntList(t, after, "ids")
	if len(afterIDs) != 0 {
		t.Errorf("declared, between 2 and 100 matched %d records, want none -- byte-wise, \"2\" is already past \"100\"", len(afterIDs))
	}
	if got := mustHashStringValue(t, after, "comparison"); got != "bytes" {
		t.Errorf("comparison after the declaration is %q, want bytes", got)
	}
	if got := ledgerStringList(t, after, "range_keys"); len(got) != 1 || got[0] != "score" {
		t.Errorf("range_keys is %v, want [score]", got)
	}
	_ = byValue
}

// TestAKeyWhoseValuesDoNotReorderSaysSo is the other half: the report is a
// finding about the data, not a warning attached to every declaration.
func TestAKeyWhoseValuesDoNotReorderSaysSo(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	for _, value := range []string{"0009", "0010", "0100"} {
		mustLedgerHash(t, BuiltinNameLedgerAddNode,
			LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"score": value})))
	}

	declared := mustLedgerHash(t, BuiltinNameLedgerDeclareOrdered,
		LedgerDeclareOrdered(intObj(handle), stringObj("score"), stringObj("node")))
	if mustHashBoolValue(t, declared, "order_differs") {
		t.Error("zero-padded fixed-width values were reported as reordering; byte order is numeric order for these")
	}
	if got := mustHashIntValue(t, declared, "distinct_values"); got != 3 {
		t.Errorf("distinct_values is %d, want 3", got)
	}
}

// TestATruncatedProvenanceChainSaysSo covers the second silent wrong answer:
// graphene returns the deepest path it found either way.
func TestATruncatedProvenanceChainSaysSo(t *testing.T) {
	handle, image, _, artefact, _, _ := readableTestLedger(t)

	full := mustLedgerHash(t, BuiltinNameLedgerProvenance,
		LedgerProvenance(intObj(handle), intObj(artefact), intObj(10)))
	if got := mustHashStringValue(t, full, "stopped_at"); got != "root" {
		t.Errorf("a walk that reached the source reports stopped_at %q, want root", got)
	}
	if !mustHashBoolValue(t, full, "complete") {
		t.Error("a walk that reached the source is not reported complete")
	}
	if got := mustHashIntValue(t, full, "root"); got != image {
		t.Errorf("root is %d, want the image %d", got, image)
	}

	cut := mustLedgerHash(t, BuiltinNameLedgerProvenance,
		LedgerProvenance(intObj(handle), intObj(artefact), intObj(1)))
	if got := mustHashStringValue(t, cut, "stopped_at"); got != "depth" {
		t.Errorf("a walk stopped by its depth limit reports stopped_at %q, want depth", got)
	}
	if mustHashBoolValue(t, cut, "complete") {
		t.Error("a walk stopped by its depth limit is reported complete, which is the claim this field exists to prevent")
	}
	if got := mustHashIntValue(t, cut, "root"); got == image {
		t.Error("the truncated walk reports the image as its root")
	}
}

// TestAProvenanceChainNamesTheParentsItDidNotFollow covers the third: the walk
// is called a chain and the graph is frequently not one.
func TestAProvenanceChainNamesTheParentsItDidNotFollow(t *testing.T) {
	handle, _, file, artefact, other, _ := readableTestLedger(t)

	walk := mustLedgerHash(t, BuiltinNameLedgerProvenance,
		LedgerProvenance(intObj(handle), intObj(artefact), intObj(10)))
	if got := mustHashIntValue(t, walk, "branch_point_count"); got != 1 {
		t.Fatalf("branch_point_count is %d, want 1 -- the artefact has two parents", got)
	}
	points := mustHashArrayValue(t, walk, "branch_points")
	point, ok := points[0].(*object.Hash)
	if !ok {
		t.Fatalf("a branch point is %T, want HASH", points[0])
	}
	if got := mustHashIntValue(t, point, "node"); got != artefact {
		t.Errorf("the branch point is node %d, want the artefact %d", got, artefact)
	}
	if got := mustHashIntValue(t, point, "parents"); got != 2 {
		t.Errorf("the branch point reports %d parents, want 2", got)
	}
	notFollowed := ledgerIntList(t, point, "not_followed")
	if len(notFollowed) != 1 {
		t.Fatalf("not_followed holds %d ids, want 1", len(notFollowed))
	}
	followed := mustHashIntValue(t, point, "followed")
	if followed != file && followed != other {
		t.Errorf("followed is %d, which is neither parent (%d, %d)", followed, file, other)
	}
	if notFollowed[0] == followed {
		t.Error("the parent reported as not followed is the one that was followed")
	}
	if notFollowed[0] != file && notFollowed[0] != other {
		t.Errorf("not_followed names %d, which is neither parent", notFollowed[0])
	}
}

// TestAProvenanceWalkThatMeetsACycleSaysCycleRatherThanDepth keeps the three
// stop reasons apart: a cycle is not a truncation and not a root.
func TestAProvenanceWalkThatMeetsACycleSaysCycleRatherThanDepth(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	first := mustHashIntValue(t, mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "a"}))), "id")
	second := mustHashIntValue(t, mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "b"}))), "id")
	mustLedgerHash(t, BuiltinNameLedgerAddEdge,
		LedgerAddEdge(intObj(handle), intObj(first), intObj(second), ledgerProps(nil)))
	mustLedgerHash(t, BuiltinNameLedgerAddEdge,
		LedgerAddEdge(intObj(handle), intObj(second), intObj(first), ledgerProps(nil)))

	walk := mustLedgerHash(t, BuiltinNameLedgerProvenance,
		LedgerProvenance(intObj(handle), intObj(first), intObj(100)))
	if got := mustHashStringValue(t, walk, "stopped_at"); got != "cycle" {
		t.Errorf("a walk that closed a loop reports stopped_at %q, want cycle", got)
	}
	if mustHashBoolValue(t, walk, "complete") {
		t.Error("a walk that closed a loop is reported complete")
	}
}

// TestANonPositiveDepthIsRefusedRatherThanSubstituted -- graphene silently
// substitutes 64, which would be reported here as the caller's own limit.
func TestANonPositiveDepthIsRefusedRatherThanSubstituted(t *testing.T) {
	handle, _, _, artefact, _, _ := readableTestLedger(t)

	for _, depth := range []int64{0, -1} {
		message := ledgerRefusal(t, BuiltinNameLedgerProvenance,
			LedgerProvenance(intObj(handle), intObj(artefact), intObj(depth)))
		if !strings.Contains(message, "64") {
			t.Errorf("the refusal for depth %d does not say what graphene would have substituted: %s", depth, message)
		}
	}
}

// TestAnUnlabelledPatternWithNoScopeIsRefusedRatherThanAnswered covers the
// fourth silent wrong answer, which graphene documents inside its own
// candidate builder and reports as an empty result.
func TestAnUnlabelledPatternWithNoScopeIsRefusedRatherThanAnswered(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	pattern := makeHashObject(map[string]object.Object{
		"nodes": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"id": intObj(0)}),
			makeHashObject(map[string]object.Object{"id": intObj(1)}),
		}},
		"edges": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"src": intObj(0), "dst": intObj(1)}),
		}},
	})
	message := ledgerRefusal(t, BuiltinNameLedgerPatterns,
		LedgerPatterns(intObj(handle), pattern, intObj(0), intObj(0)))
	if !strings.Contains(message, "no labels") || !strings.Contains(message, "scope") {
		t.Errorf("the refusal does not explain that an unlabelled node needs a scope: %s", message)
	}

	// The same pattern with a scope is a legitimate question.
	scope := &object.Array{Elements: []object.Object{intObj(1), intObj(2), intObj(3)}}
	found := mustLedgerHash(t, BuiltinNameLedgerPatterns,
		LedgerPatterns(intObj(handle), pattern, scope, intObj(0)))
	if mustHashIntValue(t, found, "count") == 0 {
		t.Error("an unlabelled pattern with a scope found nothing, although the scope is connected")
	}
	if !mustHashBoolValue(t, found, "scoped") {
		t.Error("a scoped search does not report itself scoped")
	}
}

// TestAPatternEdgeNamingAMissingNodeIsRefusedBeforeItPanics is the crash
// guard. graphene indexes its mapping slice with this number without checking
// it, and the failure is a panic that ends the process rather than the call --
// so the test reaching its assertions at all is half of what it asserts.
func TestAPatternEdgeNamingAMissingNodeIsRefusedBeforeItPanics(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	pattern := makeHashObject(map[string]object.Object{
		"nodes": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"id": intObj(0), "labels": &object.Array{Elements: []object.Object{intObj(1)}}}),
			makeHashObject(map[string]object.Object{"id": intObj(1), "labels": &object.Array{Elements: []object.Object{intObj(2)}}}),
		}},
		"edges": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"src": intObj(0), "dst": intObj(7)}),
		}},
	})
	message := ledgerRefusal(t, BuiltinNameLedgerPatterns,
		LedgerPatterns(intObj(handle), pattern, intObj(0), intObj(0)))
	if !strings.Contains(message, "panic") {
		t.Errorf("the refusal does not say what it prevented: %s", message)
	}
	if !strings.Contains(message, "0..1") {
		t.Errorf("the refusal does not name the valid range: %s", message)
	}
}

// TestAPatternNodeIdMustEqualItsPosition -- graphene matches by position and
// never reads the id, so disagreeing ids match a different shape in silence.
func TestAPatternNodeIdMustEqualItsPosition(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	pattern := makeHashObject(map[string]object.Object{
		"nodes": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"id": intObj(1), "labels": &object.Array{Elements: []object.Object{intObj(1)}}}),
			makeHashObject(map[string]object.Object{"id": intObj(0), "labels": &object.Array{Elements: []object.Object{intObj(2)}}}),
		}},
		"edges": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"src": intObj(0), "dst": intObj(1)}),
		}},
	})
	message := ledgerRefusal(t, BuiltinNameLedgerPatterns,
		LedgerPatterns(intObj(handle), pattern, intObj(0), intObj(0)))
	if !strings.Contains(message, "position") {
		t.Errorf("the refusal does not explain that a pattern node's id is its position: %s", message)
	}
}

// TestACappedPatternSearchSaysItWasCapped -- maxMatches is a truncation, and
// graphene reports nothing about having performed one.
func TestACappedPatternSearchSaysItWasCapped(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	// file -CONTAINS-> artefact and other -CONTAINS-> artefact both match.
	pattern := makeHashObject(map[string]object.Object{
		"nodes": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"id": intObj(0), "labels": &object.Array{Elements: []object.Object{intObj(2)}}}),
			makeHashObject(map[string]object.Object{"id": intObj(1), "labels": &object.Array{Elements: []object.Object{intObj(3)}}}),
		}},
		"edges": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"src": intObj(0), "dst": intObj(1)}),
		}},
	})

	all := mustLedgerHash(t, BuiltinNameLedgerPatterns,
		LedgerPatterns(intObj(handle), pattern, intObj(0), intObj(0)))
	if got := mustHashIntValue(t, all, "count"); got != 2 {
		t.Fatalf("uncapped, the pattern matched %d times, want 2", got)
	}
	if mustHashBoolValue(t, all, "capped") {
		t.Error("an uncapped search reports itself capped")
	}

	capped := mustLedgerHash(t, BuiltinNameLedgerPatterns,
		LedgerPatterns(intObj(handle), pattern, intObj(0), intObj(1)))
	if got := mustHashIntValue(t, capped, "count"); got != 1 {
		t.Fatalf("capped at 1, the pattern matched %d times", got)
	}
	if !mustHashBoolValue(t, capped, "capped") {
		t.Error("a search that reached its cap does not say so, which reads as a complete match set")
	}
}

// TestAnInducedSubgraphOverAMissingEntityIsRefused -- the claim is "these are
// all the relationships among these entities", which a missing entity makes
// false rather than incomplete.
func TestAnInducedSubgraphOverAMissingEntityIsRefused(t *testing.T) {
	handle, image, file, artefact, _, _ := readableTestLedger(t)

	ok := mustLedgerHash(t, BuiltinNameLedgerSubgraph, LedgerSubgraph(intObj(handle),
		&object.Array{Elements: []object.Object{intObj(image), intObj(file), intObj(artefact)}}))
	if got := mustHashIntValue(t, ok, "node_count"); got != 3 {
		t.Errorf("node_count is %d, want 3", got)
	}
	if got := mustHashIntValue(t, ok, "edge_count"); got != 2 {
		t.Errorf("edge_count is %d, want 2 (image->file, file->artefact)", got)
	}

	message := ledgerRefusal(t, BuiltinNameLedgerSubgraph, LedgerSubgraph(intObj(handle),
		&object.Array{Elements: []object.Object{intObj(image), intObj(424242)}}))
	if !strings.Contains(message, "424242") {
		t.Errorf("the refusal does not name the missing id: %s", message)
	}
}

// TestAnIdGivenTwiceIsCountedOnce -- graphene returns the record once per
// occurrence, which would report more entities than were asked about.
func TestAnIdGivenTwiceIsCountedOnce(t *testing.T) {
	handle, image, file, _, _, _ := readableTestLedger(t)

	result := mustLedgerHash(t, BuiltinNameLedgerSubgraph, LedgerSubgraph(intObj(handle),
		&object.Array{Elements: []object.Object{intObj(image), intObj(file), intObj(image)}}))
	if got := mustHashIntValue(t, result, "node_count"); got != 2 {
		t.Errorf("node_count is %d, want 2 -- the repeated id is one entity", got)
	}
	if got := mustHashIntValue(t, result, "duplicates"); got != 1 {
		t.Errorf("duplicates is %d, want 1", got)
	}
	if got := mustHashIntValue(t, result, "requested"); got != 3 {
		t.Errorf("requested is %d, want 3 -- what the caller passed, before deduplication", got)
	}
}

// TestAnEmptySubgraphRequestIsAQuestionWithNoSubject
func TestAnEmptySubgraphRequestIsAQuestionWithNoSubject(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	message := ledgerRefusal(t, BuiltinNameLedgerSubgraph,
		LedgerSubgraph(intObj(handle), &object.Array{Elements: []object.Object{}}))
	if !strings.Contains(message, "no subject") {
		t.Errorf("an empty id list was not refused as a question with no subject: %s", message)
	}
}

// TestACostModelIsANameBecauseAFunctionCannotBeChecked pins the three models
// and the refusal of anything else.
func TestACostModelIsANameBecauseAFunctionCannotBeChecked(t *testing.T) {
	handle, image, _, artefact, _, _ := readableTestLedger(t)

	for _, model := range []string{"hops", "weight", "similarity"} {
		path := mustLedgerHash(t, BuiltinNameLedgerPath,
			LedgerPath(intObj(handle), intObj(image), intObj(artefact), stringObj(model)))
		if !mustHashBoolValue(t, path, "found") {
			t.Fatalf("%s: no path from the image to the artefact", model)
		}
		if got := mustHashStringValue(t, path, "cost_model"); got != model {
			t.Errorf("cost_model is %q, want %q", got, model)
		}
		if got := mustHashIntValue(t, path, "hops"); got != 2 {
			t.Errorf("%s: hops is %d, want 2", model, got)
		}
	}

	// Every edge in this ledger has weight 0, so the three models price the
	// same two hops differently -- which is the point of naming the reading.
	hops := mustLedgerHash(t, BuiltinNameLedgerPath,
		LedgerPath(intObj(handle), intObj(image), intObj(artefact), stringObj("hops")))
	weight := mustLedgerHash(t, BuiltinNameLedgerPath,
		LedgerPath(intObj(handle), intObj(image), intObj(artefact), stringObj("weight")))
	if mustHashFloatValue(t, hops, "cost") != 2 {
		t.Errorf("the hops model priced two hops at %g, want 2", mustHashFloatValue(t, hops, "cost"))
	}
	if mustHashFloatValue(t, weight, "cost") != 0 {
		t.Errorf("the weight model priced two zero-weight hops at %g, want 0", mustHashFloatValue(t, weight, "cost"))
	}

	message := ledgerRefusal(t, BuiltinNameLedgerPath,
		LedgerPath(intObj(handle), intObj(image), intObj(artefact), stringObj("euclidean")))
	for _, want := range []string{"deterministic", "hops", "similarity", "weight"} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal does not mention %q: %s", want, message)
		}
	}
}

// TestTwoUnconnectedEntitiesAreAnAnswerNotAnError -- folding this into the
// error channel would make a script's error branch mean both "not related"
// and "bad handle".
func TestTwoUnconnectedEntitiesAreAnAnswerNotAnError(t *testing.T) {
	handle, image, _, _, _, _ := readableTestLedger(t)
	lonely := mustHashIntValue(t, mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "alone"}))), "id")

	payload, errObj := unwrapPair(t, LedgerPath(intObj(handle), intObj(image), intObj(lonely), stringObj("hops")))
	if errObj != nil {
		t.Fatalf("two unconnected entities came back as an error: %s", errObj.Message)
	}
	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("payload is %T, want HASH", payload)
	}
	if mustHashBoolValue(t, hash, "found") {
		t.Error("found is true for two entities with no path between them")
	}
	if got := mustHashIntValue(t, hash, "hops"); got != 0 {
		t.Errorf("hops is %d on a path that was not found, want 0", got)
	}
}

// TestEveryDriverTheQueryPlannerCanFallBackTo pins what an examiner would read
// off a plan, and in particular the three ways a query ends up scanning.
func TestEveryDriverTheQueryPlannerCanFallBackTo(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	explain := func(query object.Object) *object.Hash {
		t.Helper()
		return mustLedgerHash(t, BuiltinNameLedgerExplainQuery, LedgerExplainQuery(intObj(handle), query))
	}
	filter := func(key, op, value string) object.Object {
		return makeHashObject(map[string]object.Object{
			"filters": &object.Array{Elements: []object.Object{
				makeHashObject(map[string]object.Object{
					"key": stringObj(key), "op": stringObj(op), "value": stringObj(value),
				}),
			}},
		})
	}

	t.Run("an equality filter is served from the postings", func(t *testing.T) {
		plan := explain(filter("role", "eq", "file"))
		if got := mustHashStringValue(t, plan, "driver"); got != "equality" {
			t.Errorf("driver is %q, want equality", got)
		}
		if mustHashBoolValue(t, plan, "scanned") {
			t.Error("an equality lookup reports itself as a scan")
		}
	})

	t.Run("contains can never be served by any index", func(t *testing.T) {
		plan := explain(filter("uid", "contains", "000"))
		if !mustHashBoolValue(t, plan, "scanned") {
			t.Error("a contains filter did not report a scan; no ordering can bound it")
		}
	})

	t.Run("a range on an undeclared key scans", func(t *testing.T) {
		plan := explain(filter("uid", "gt", "art"))
		if !mustHashBoolValue(t, plan, "scanned") {
			t.Error("a range on an undeclared key did not report a scan")
		}
	})

	t.Run("and stops scanning once the key is declared", func(t *testing.T) {
		mustLedgerHash(t, BuiltinNameLedgerDeclareOrdered,
			LedgerDeclareOrdered(intObj(handle), stringObj("uid"), stringObj("node")))
		plan := explain(filter("uid", "gt", "art"))
		if got := mustHashStringValue(t, plan, "driver"); got != "ordered" {
			t.Errorf("driver is %q, want ordered", got)
		}
		if got := mustHashStringValue(t, plan, "driver_key"); got != "uid" {
			t.Errorf("driver_key is %q, want uid", got)
		}
	})

	t.Run("two filters under mode any cannot be driven", func(t *testing.T) {
		plan := explain(makeHashObject(map[string]object.Object{
			"mode": stringObj("any"),
			"filters": &object.Array{Elements: []object.Object{
				makeHashObject(map[string]object.Object{"key": stringObj("role"), "op": stringObj("eq"), "value": stringObj("file")}),
				makeHashObject(map[string]object.Object{"key": stringObj("uid"), "op": stringObj("eq"), "value": stringObj("img-0001")}),
			}},
		}))
		if !mustHashBoolValue(t, plan, "scanned") {
			t.Error("a union of two filters did not report a scan; the result is not contained in either one")
		}
	})

	t.Run("a composite tuple is one lookup", func(t *testing.T) {
		mustLedgerHash(t, BuiltinNameLedgerDeclareComposite, LedgerDeclareComposite(intObj(handle),
			&object.Array{Elements: []object.Object{stringObj("role"), stringObj("uid")}}, stringObj("node")))
		plan := explain(makeHashObject(map[string]object.Object{
			"filters": &object.Array{Elements: []object.Object{
				makeHashObject(map[string]object.Object{"key": stringObj("role"), "op": stringObj("eq"), "value": stringObj("file")}),
				makeHashObject(map[string]object.Object{"key": stringObj("uid"), "op": stringObj("eq"), "value": stringObj("fil-0002")}),
			}},
		}))
		if got := mustHashStringValue(t, plan, "driver"); got != "composite" {
			t.Errorf("driver is %q, want composite", got)
		}
	})

	t.Run("an id list drives itself", func(t *testing.T) {
		plan := explain(makeHashObject(map[string]object.Object{
			"ids": &object.Array{Elements: []object.Object{intObj(1), intObj(2)}},
		}))
		if got := mustHashStringValue(t, plan, "driver"); got != "ids" {
			t.Errorf("driver is %q, want ids", got)
		}
	})
}

// TestAUniqueDeclarationIsAStatementAboutTheEvidence -- unlike the other two
// declarations it is checked against what is already written.
func TestAUniqueDeclarationIsAStatementAboutTheEvidence(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	for i := 0; i < 2; i++ {
		mustLedgerHash(t, BuiltinNameLedgerAddNode,
			LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "same"})))
	}

	message := ledgerRefusal(t, BuiltinNameLedgerDeclareUnique,
		LedgerDeclareUnique(intObj(handle), stringObj("uid"), stringObj("node")))
	if !strings.Contains(message, "same") {
		t.Errorf("the refusal does not name the value held twice: %s", message)
	}
	if !strings.Contains(message, "about the evidence") {
		t.Errorf("the refusal does not say this is a check against the data: %s", message)
	}

	clean, _ := openTestLedger(t, "G. Gogia")
	mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(clean), ledgerProps(map[string]string{"uid": "only"})))
	declared := mustLedgerHash(t, BuiltinNameLedgerDeclareUnique,
		LedgerDeclareUnique(intObj(clean), stringObj("uid"), stringObj("node")))
	if !mustHashBoolValue(t, declared, "checked") {
		t.Error("a unique declaration does not report that it checked")
	}

	// And afterwards a duplicate is refused at write time.
	_, writeErr := unwrapPair(t, LedgerAddNode(intObj(clean), ledgerProps(map[string]string{"uid": "only"})))
	if writeErr == nil {
		t.Error("a duplicate was accepted after the key was declared unique")
	}
}

// TestAUniqueEdgeTypeIsEnforcedAtCommit -- the structural counterpart, and it
// is the write that refuses, not the declaration.
func TestAUniqueEdgeTypeIsEnforcedAtCommit(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	src := mustHashIntValue(t, mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "a"}))), "id")
	dst := mustHashIntValue(t, mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "b"}))), "id")
	mustLedgerHash(t, BuiltinNameLedgerAddEdge,
		LedgerAddEdge(intObj(handle), intObj(src), intObj(dst), ledgerProps(nil), intObj(7)))

	declared := mustLedgerHash(t, BuiltinNameLedgerDeclareUniqueEdge,
		LedgerDeclareUniqueEdge(intObj(handle), intObj(7)))
	if got := mustHashIntValue(t, declared, "edge_type"); got != 7 {
		t.Errorf("edge_type comes back as %d, want the offset 7 that was passed in", got)
	}
	if !strings.Contains(mustHashStringValue(t, declared, "enforced"), "commit") {
		t.Error("the declaration does not say where it is enforced")
	}

	_, writeErr := unwrapPair(t, LedgerAddEdge(intObj(handle), intObj(src), intObj(dst), ledgerProps(nil), intObj(7)))
	if writeErr == nil {
		t.Error("a second edge of a type declared unique was accepted")
	}
}

// TestIndexDeclarationsSurviveACompaction -- a ledger handed over carries the
// schema decisions that shaped whatever was reported from it.
func TestIndexDeclarationsSurviveACompaction(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	mustLedgerHash(t, BuiltinNameLedgerDeclareOrdered,
		LedgerDeclareOrdered(intObj(handle), stringObj("uid"), stringObj("node")))
	mustLedgerHash(t, BuiltinNameLedgerDeclareComposite, LedgerDeclareComposite(intObj(handle),
		&object.Array{Elements: []object.Object{stringObj("role"), stringObj("uid")}}, stringObj("node")))
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))

	indexes := mustLedgerHash(t, BuiltinNameLedgerIndexes, LedgerIndexes(intObj(handle)))
	if got := ledgerStringList(t, indexes, "ordered_node_keys"); len(got) != 1 || got[0] != "uid" {
		t.Errorf("ordered_node_keys after a compaction is %v, want [uid]", got)
	}
	tuples := mustHashArrayValue(t, indexes, "composite_node_keys")
	if len(tuples) != 1 {
		t.Fatalf("composite_node_keys holds %d tuples, want 1", len(tuples))
	}
	if got := mustHashIntValue(t, indexes, "count"); got != 2 {
		t.Errorf("count is %d, want 2", got)
	}
}

// TestAReadOfARedactedEntityNamesTheRedaction composes with the redaction
// family: graphene reports a removed id and an id that never existed as the
// same error, and telling an examiner their evidence never existed is the
// worst answer this family can give.
func TestAReadOfARedactedEntityNamesTheRedaction(t *testing.T) {
	handle, _, subject, _, edge := redactableTestLedger(t)

	mustLedgerHash(t, BuiltinNameLedgerRedactNode,
		LedgerRedactNode(intObj(handle), intObj(subject), stringObj("court order 2026-118")))

	t.Run("reading the node", func(t *testing.T) {
		message := ledgerRefusal(t, BuiltinNameLedgerNode, LedgerNode(intObj(handle), intObj(subject)))
		if strings.Contains(message, "no record of ever having had one") {
			t.Errorf("a redacted entity reads as one that never existed: %s", message)
		}
		if !strings.Contains(message, "court order 2026-118") {
			t.Errorf("the refusal does not carry the reason: %s", message)
		}
	})

	t.Run("reading an edge it took as collateral", func(t *testing.T) {
		message := ledgerRefusal(t, BuiltinNameLedgerEdge, LedgerEdge(intObj(handle), intObj(edge)))
		if !strings.Contains(message, "collateral") {
			t.Errorf("the refusal does not say the edge was collateral: %s", message)
		}
	})

	t.Run("walking from it", func(t *testing.T) {
		message := ledgerRefusal(t, BuiltinNameLedgerProvenance,
			LedgerProvenance(intObj(handle), intObj(subject), intObj(5)))
		if !strings.Contains(message, "redacted") {
			t.Errorf("the refusal does not name the redaction: %s", message)
		}
	})

	t.Run("an id that really was never here", func(t *testing.T) {
		message := ledgerRefusal(t, BuiltinNameLedgerNode, LedgerNode(intObj(handle), intObj(424242)))
		if !strings.Contains(message, "no record of ever having had one") {
			t.Errorf("an id that was never written does not read as one: %s", message)
		}
	})
}

// TestPropertiesComeBackAsTheBytesThatWereCommitted
func TestPropertiesComeBackAsTheBytesThatWereCommitted(t *testing.T) {
	handle, image, _, _, _, edge := readableTestLedger(t)

	node := mustLedgerHash(t, BuiltinNameLedgerNode, LedgerNode(intObj(handle), intObj(image)))
	props, ok := mustHashValueByStringKey(t, node, "properties").(*object.Hash)
	if !ok {
		t.Fatal("properties is not a HASH")
	}
	value := mustHashValueByStringKey(t, props, "uid")
	bytesValue, ok := value.(*object.Bytes)
	if !ok {
		t.Fatalf("a property came back as %T, want BYTES -- the store holds bytes and does not record which of the two types wrote them", value)
	}
	if string(bytesValue.Value) != "img-0001" {
		t.Errorf("uid is %q, want img-0001", bytesValue.Value)
	}
	if got := mustHashIntValue(t, node, "property_count"); got != 2 {
		t.Errorf("property_count is %d, want 2", got)
	}
	if !mustHashBoolValue(t, node, "redactable") {
		t.Error("a node with properties reports itself not redactable")
	}
	if got := ledgerIntList(t, node, "labels"); len(got) != 1 || got[0] != 1 {
		t.Errorf("labels is %v, want [1] -- the offset that was written, not graphene's internal number", got)
	}

	relation := mustLedgerHash(t, BuiltinNameLedgerEdge, LedgerEdge(intObj(handle), intObj(edge)))
	if got := mustHashIntValue(t, relation, "src"); got == 0 {
		t.Error("an edge came back with no source")
	}
	if got := mustHashFloatValue(t, relation, "weight"); got != 0 {
		t.Errorf("weight is %g, want 0 -- graphene sets it only for its own SimilarTo type", got)
	}
}

// ledgerReadBuiltins is every builtin this file adds, with arguments that are
// well-formed for everything except the handle.
func ledgerReadBuiltins(handle int64) []struct {
	name string
	call func() object.Object
	args []object.Object
} {
	h := intObj(handle)
	pattern := makeHashObject(map[string]object.Object{
		"nodes": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"id": intObj(0), "labels": &object.Array{Elements: []object.Object{intObj(1)}}}),
			makeHashObject(map[string]object.Object{"id": intObj(1), "labels": &object.Array{Elements: []object.Object{intObj(2)}}}),
		}},
		"edges": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"src": intObj(0), "dst": intObj(1)}),
		}},
	})
	query := makeHashObject(map[string]object.Object{
		"types": &object.Array{Elements: []object.Object{intObj(1)}},
	})
	return []struct {
		name string
		call func() object.Object
		args []object.Object
	}{
		{BuiltinNameLedgerNode, func() object.Object { return LedgerNode(h, intObj(1)) }, []object.Object{h, intObj(1)}},
		{BuiltinNameLedgerEdge, func() object.Object { return LedgerEdge(h, intObj(1)) }, []object.Object{h, intObj(1)}},
		{BuiltinNameLedgerProvenance, func() object.Object { return LedgerProvenance(h, intObj(1), intObj(5)) }, []object.Object{h, intObj(1), intObj(5)}},
		{BuiltinNameLedgerPath, func() object.Object {
			return LedgerPath(h, intObj(1), intObj(2), stringObj("hops"))
		}, []object.Object{h, intObj(1), intObj(2), stringObj("hops")}},
		{BuiltinNameLedgerSubgraph, func() object.Object {
			return LedgerSubgraph(h, &object.Array{Elements: []object.Object{intObj(1)}})
		}, []object.Object{h, &object.Array{Elements: []object.Object{intObj(1)}}}},
		{BuiltinNameLedgerPatterns, func() object.Object {
			return LedgerPatterns(h, pattern, intObj(0), intObj(0))
		}, []object.Object{h, pattern, intObj(0), intObj(0)}},
		{BuiltinNameLedgerQueryNodes, func() object.Object { return LedgerQueryNodes(h, query) }, []object.Object{h, query}},
		{BuiltinNameLedgerExplainQuery, func() object.Object { return LedgerExplainQuery(h, query) }, []object.Object{h, query}},
		{BuiltinNameLedgerDeclareOrdered, func() object.Object {
			return LedgerDeclareOrdered(h, stringObj("uid"), stringObj("node"))
		}, []object.Object{h, stringObj("uid"), stringObj("node")}},
		{BuiltinNameLedgerDeclareUnique, func() object.Object {
			return LedgerDeclareUnique(h, stringObj("uid"), stringObj("node"))
		}, []object.Object{h, stringObj("uid"), stringObj("node")}},
		{BuiltinNameLedgerDeclareUniqueEdge, func() object.Object {
			return LedgerDeclareUniqueEdge(h, intObj(9))
		}, []object.Object{h, intObj(9)}},
		{BuiltinNameLedgerDeclareComposite, func() object.Object {
			return LedgerDeclareComposite(h, &object.Array{Elements: []object.Object{stringObj("uid"), stringObj("role")}}, stringObj("node"))
		}, []object.Object{h, &object.Array{Elements: []object.Object{stringObj("uid"), stringObj("role")}}, stringObj("node")}},
		{BuiltinNameLedgerIndexes, func() object.Object { return LedgerIndexes(h) }, []object.Object{h}},
	}
}

// TestEveryReadBuiltinRefusesAHandleThatIsNotOne -- the likeliest mix-up is a
// db_open_disk handle, and the refusal has to say which of the two spaces the
// caller is in.
func TestEveryReadBuiltinRefusesAHandleThatIsNotOne(t *testing.T) {
	for _, builtin := range ledgerReadBuiltins(987654) {
		_, errObj := unwrapPairNoFatal(builtin.call())
		if errObj == nil {
			t.Errorf("%s accepted a handle no ledger_open issued", builtin.name)
			continue
		}
		if !strings.Contains(errObj.Message, "ledger_open") {
			t.Errorf("%s does not name the family its handle comes from: %s", builtin.name, errObj.Message)
		}
	}
}

// TestEveryReadBuiltinChecksItsArity
func TestEveryReadBuiltinChecksItsArity(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	for _, builtin := range ledgerReadBuiltins(handle) {
		want := len(builtin.args)
		for _, got := range []int{want - 1, want + 1} {
			if got < 0 {
				continue
			}
			args := make([]object.Object, 0, got)
			for i := 0; i < got; i++ {
				if i < len(builtin.args) {
					args = append(args, builtin.args[i])
					continue
				}
				args = append(args, intObj(0))
			}
			entry, ok := builtinDocs[builtin.name]
			if !ok {
				t.Fatalf("%s has no metadata entry", builtin.name)
			}
			_ = entry
			fn, ok := lookupReadBuiltin(builtin.name)
			if !ok {
				t.Fatalf("%s is not registered", builtin.name)
			}
			_, errObj := unwrapPairNoFatal(fn(args...))
			if errObj == nil {
				t.Errorf("%s accepted %d arguments, want %d", builtin.name, got, want)
				continue
			}
			if !strings.Contains(errObj.Message, "wrong number of arguments") {
				t.Errorf("%s with %d arguments refused for another reason: %s", builtin.name, got, errObj.Message)
			}
		}
	}
}

// lookupReadBuiltin finds a registered builtin by name, which is also a check
// that every one of them reached the Builtins slice.
func lookupReadBuiltin(name string) (func(...object.Object) object.Object, bool) {
	for _, entry := range Builtins {
		if entry.Name == name {
			return entry.Builtin.Fn, true
		}
	}
	return nil, false
}

// TestEveryReadBuiltinReturnsTheDeclaredFields
func TestEveryReadBuiltinReturnsTheDeclaredFields(t *testing.T) {
	handle, image, file, artefact, _, edge := readableTestLedger(t)

	cases := []struct {
		name   string
		result object.Object
	}{
		{BuiltinNameLedgerNode, LedgerNode(intObj(handle), intObj(image))},
		{BuiltinNameLedgerEdge, LedgerEdge(intObj(handle), intObj(edge))},
		{BuiltinNameLedgerProvenance, LedgerProvenance(intObj(handle), intObj(artefact), intObj(10))},
		{BuiltinNameLedgerPath, LedgerPath(intObj(handle), intObj(image), intObj(artefact), stringObj("hops"))},
		{BuiltinNameLedgerSubgraph, LedgerSubgraph(intObj(handle),
			&object.Array{Elements: []object.Object{intObj(image), intObj(file)}})},
		{BuiltinNameLedgerPatterns, LedgerPatterns(intObj(handle),
			makeHashObject(map[string]object.Object{
				"nodes": &object.Array{Elements: []object.Object{
					makeHashObject(map[string]object.Object{"id": intObj(0), "labels": &object.Array{Elements: []object.Object{intObj(1)}}}),
					makeHashObject(map[string]object.Object{"id": intObj(1), "labels": &object.Array{Elements: []object.Object{intObj(2)}}}),
				}},
				"edges": &object.Array{Elements: []object.Object{
					makeHashObject(map[string]object.Object{"src": intObj(0), "dst": intObj(1)}),
				}},
			}), intObj(0), intObj(0))},
		{BuiltinNameLedgerQueryNodes, LedgerQueryNodes(intObj(handle),
			makeHashObject(map[string]object.Object{"types": &object.Array{Elements: []object.Object{intObj(1)}}}))},
		{BuiltinNameLedgerExplainQuery, LedgerExplainQuery(intObj(handle),
			makeHashObject(map[string]object.Object{"types": &object.Array{Elements: []object.Object{intObj(1)}}}))},
		{BuiltinNameLedgerDeclareOrdered, LedgerDeclareOrdered(intObj(handle), stringObj("uid"), stringObj("node"))},
		{BuiltinNameLedgerDeclareUnique, LedgerDeclareUnique(intObj(handle), stringObj("uid"), stringObj("node"))},
		{BuiltinNameLedgerDeclareUniqueEdge, LedgerDeclareUniqueEdge(intObj(handle), intObj(11))},
		{BuiltinNameLedgerDeclareComposite, LedgerDeclareComposite(intObj(handle),
			&object.Array{Elements: []object.Object{stringObj("uid"), stringObj("role")}}, stringObj("node"))},
		{BuiltinNameLedgerIndexes, LedgerIndexes(intObj(handle))},
	}

	for _, testCase := range cases {
		payload, errObj := unwrapPair(t, testCase.result)
		if errObj != nil {
			t.Fatalf("%s: %s", testCase.name, errObj.Message)
		}
		assertLedgerDeclaredFields(t, testCase.name, payload)
	}
}

// TestAPathThatIsNotFoundStillDeclaresEveryField -- the two shapes a path can
// return must agree, or a script reading cost off a miss gets nothing.
func TestAPathThatIsNotFoundStillDeclaresEveryField(t *testing.T) {
	handle, image, _, _, _, _ := readableTestLedger(t)
	lonely := mustHashIntValue(t, mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "alone"}))), "id")

	payload, errObj := unwrapPair(t, LedgerPath(intObj(handle), intObj(image), intObj(lonely), stringObj("hops")))
	if errObj != nil {
		t.Fatalf("ledger_path: %s", errObj.Message)
	}
	assertLedgerDeclaredFields(t, BuiltinNameLedgerPath, payload)
}

// TestADeclarationTargetIsNodeOrEdgeAndNothingElse -- the two index spaces are
// separate in graphene and a key declared on one is not declared on the other.
func TestADeclarationTargetIsNodeOrEdgeAndNothingElse(t *testing.T) {
	handle, _, _, _, _, _ := readableTestLedger(t)

	message := ledgerRefusal(t, BuiltinNameLedgerDeclareOrdered,
		LedgerDeclareOrdered(intObj(handle), stringObj("uid"), stringObj("both")))
	if !strings.Contains(message, "separate") {
		t.Errorf("the refusal does not explain that the two index spaces are separate: %s", message)
	}

	mustLedgerHash(t, BuiltinNameLedgerDeclareOrdered,
		LedgerDeclareOrdered(intObj(handle), stringObj("uid"), stringObj("edge")))
	indexes := mustLedgerHash(t, BuiltinNameLedgerIndexes, LedgerIndexes(intObj(handle)))
	if got := ledgerStringList(t, indexes, "ordered_edge_keys"); len(got) != 1 || got[0] != "uid" {
		t.Errorf("ordered_edge_keys is %v, want [uid]", got)
	}
	if got := ledgerStringList(t, indexes, "ordered_node_keys"); len(got) != 0 {
		t.Errorf("declaring an edge key also declared it on the node side: %v", got)
	}
}
