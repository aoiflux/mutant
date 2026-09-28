package builtin

import (
	"errors"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// refusalOf is the message a call was refused with.
func refusalOf(t *testing.T, result object.Object) string {
	t.Helper()
	_, errObj := unwrapPairNoFatal(result)
	if errObj == nil {
		t.Fatal("the call was not refused")
	}
	return errObj.Message
}

var anyNumber = regexp.MustCompile(`[0-9]+`)

// withoutNumbers lets two refusals that differ only in the ids they name be
// compared.
func withoutNumbers(message string) string { return anyNumber.ReplaceAllString(message, "N") }

func idArray(ids ...int64) *object.Array {
	out := &object.Array{}
	for _, id := range ids {
		out.Elements = append(out.Elements, intObj(id))
	}
	return out
}

// idsOf is the ids of the node or edge records a result lists under key.
func idsOf(t *testing.T, hash *object.Hash, key string) []int64 {
	t.Helper()
	var out []int64
	for _, element := range mustHashArrayValue(t, hash, key) {
		switch value := element.(type) {
		case *object.Hash:
			out = append(out, mustHashIntValue(t, value, "id"))
		case *object.Integer:
			out = append(out, value.Value)
		default:
			t.Fatalf("%s holds a %T", key, element)
		}
	}
	return out
}

func (f *viewFixture) ids(names ...string) []int64 {
	out := make([]int64, 0, len(names))
	for _, name := range names {
		out = append(out, f.node[name])
	}
	return out
}

// A read under a view shows the nodes the view shows, whole, and gives one
// answer for a node it does not show, a node the ledger never held and a node
// a redaction removed -- while the ledger's own handle still says which.
func TestAReadUnderAViewShowsWhatTheViewShows(t *testing.T) {
	f := newViewFixture(t)
	counsel, regulator := f.under(t, "counsel"), f.under(t, "regulator")
	for handle, names := range map[int64][]string{counsel: {"pii", "open", "far"}, regulator: {"restricted"}} {
		for name, id := range f.node {
			result := LedgerNode(intObj(handle), intObj(id))
			if !slices.Contains(names, name) {
				mustRefuse(t, name+" under a view", result, "is not visible under view")
				continue
			}
			props := mustHashValue(t, mustLedgerHash(t, "ledger_node", result), "properties").(*object.Hash)
			if got := string(hashValueByKey(props, "name").(*object.Bytes).Value); got != name {
				t.Errorf("node %s reads back as %q", name, got)
			}
		}
	}
	mustLedgerHash(t, "ledger_edge", LedgerEdge(intObj(counsel), intObj(f.edge["open->pii"])))
	for name, id := range f.edge {
		if name != "open->pii" {
			mustRefuse(t, name+" under counsel", LedgerEdge(intObj(counsel), intObj(id)), "is not visible under view")
		}
		mustRefuse(t, name+" under regulator", LedgerEdge(intObj(regulator), intObj(id)), "is not visible under view")
	}

	withheld := refusalOf(t, LedgerNode(intObj(counsel), intObj(f.node["unclassified"])))
	missing := refusalOf(t, LedgerNode(intObj(counsel), intObj(999999)))
	mustLedgerHash(t, "ledger_redact_node", LedgerRedactNode(intObj(f.ledger), intObj(f.node["far"]), stringObj("court order 9")))
	redacted := refusalOf(t, LedgerNode(intObj(counsel), intObj(f.node["far"])))
	if withoutNumbers(withheld) != withoutNumbers(missing) || withoutNumbers(redacted) != withoutNumbers(missing) {
		t.Errorf("three absences, three answers:\n%s\n%s\n%s", withheld, missing, redacted)
	}
	if !strings.Contains(missing, `is not visible under view "counsel": the ledger does not hold it, or holds it `+
		"and the view does not show it, and a read under a view does not say which") {
		t.Errorf("the answer is %q", missing)
	}
	edgeWithheld := refusalOf(t, LedgerEdge(intObj(counsel), intObj(f.edge["both->unclassified"])))
	edgeMissing := refusalOf(t, LedgerEdge(intObj(counsel), intObj(999999)))
	if withoutNumbers(edgeWithheld) != withoutNumbers(edgeMissing) ||
		!strings.Contains(edgeMissing, `edge 999999 is not visible under view "counsel"`) {
		t.Errorf("two absent edges, two answers:\n%s\n%s", edgeWithheld, edgeMissing)
	}
	mustRefuse(t, "a redacted node on the ledger's own handle", LedgerNode(intObj(f.ledger), intObj(f.node["far"])),
		"because it was redacted")
}

// A walk under a view never crosses a node the view does not show, and what it
// says about where it stopped is about what the view shows.
func TestAWalkUnderAViewNeverCrossesWhatItDoesNotShow(t *testing.T) {
	f := newViewFixture(t)
	ledger, counsel := intObj(f.ledger), intObj(f.under(t, "counsel"))
	pii, open, far := intObj(f.node["pii"]), intObj(f.node["open"]), intObj(f.node["far"])

	whole := mustLedgerHash(t, "ledger_provenance", LedgerProvenance(ledger, pii, intObj(8)))
	if mustHashIntValue(t, whole, "branch_point_count") != 1 || mustHashStringValue(t, whole, "view") != "" {
		t.Errorf("the whole ledger's provenance of pii: %s", whole.Inspect())
	}
	viewed := mustLedgerHash(t, "ledger_provenance", LedgerProvenance(counsel, pii, intObj(8)))
	if got := idsOf(t, viewed, "chain"); !slices.Equal(got, f.ids("pii", "open")) {
		t.Errorf("the chain under counsel is %v", got)
	}
	if mustHashStringValue(t, viewed, "stopped_at") != "root" || !mustHashBoolValue(t, viewed, "complete") ||
		mustHashIntValue(t, viewed, "branch_point_count") != 0 || mustHashIntValue(t, viewed, "root") != open.Value ||
		mustHashStringValue(t, viewed, "view") != "counsel" {
		t.Errorf("the provenance under counsel: %s", viewed.Inspect())
	}
	mustRefuse(t, "a walk from a node the view does not show",
		LedgerProvenance(counsel, intObj(f.node["both"]), intObj(8)), `is not visible under view "counsel"`)

	joined := mustLedgerHash(t, "ledger_path", LedgerPath(ledger, pii, far, stringObj("hops")))
	if !mustHashBoolValue(t, joined, "found") || mustHashIntValue(t, joined, "hops") != 2 {
		t.Fatalf("pii and far are not joined through the whole ledger: %s", joined.Inspect())
	}
	apart := mustLedgerHash(t, "ledger_path", LedgerPath(counsel, pii, far, stringObj("hops")))
	if mustHashBoolValue(t, apart, "found") || mustHashStringValue(t, apart, "view") != "counsel" {
		t.Errorf("a path under counsel crossed unclassified: %s", apart.Inspect())
	}
	near := mustLedgerHash(t, "ledger_path", LedgerPath(counsel, pii, open, stringObj("hops")))
	if !mustHashBoolValue(t, near, "found") || mustHashIntValue(t, near, "hops") != 1 ||
		mustHashStringValue(t, near, "view") != "counsel" {
		t.Errorf("pii and open under counsel: %s", near.Inspect())
	}
	mustRefuse(t, "a path to a node the view does not show",
		LedgerPath(counsel, pii, intObj(f.node["unclassified"]), stringObj("hops")), "say which (argument 3)")

	sub := mustLedgerHash(t, "ledger_subgraph", LedgerSubgraph(counsel, idArray(f.ids("pii", "open", "far")...)))
	if mustHashIntValue(t, sub, "node_count") != 3 || !slices.Equal(idsOf(t, sub, "edges"), []int64{f.edge["open->pii"]}) ||
		mustHashStringValue(t, sub, "view") != "counsel" {
		t.Errorf("the subgraph under counsel: %s", sub.Inspect())
	}
	// open -> pii leaves {open, far}: that the view shows pii does not make it
	// one of the entities asked about.
	apartSub := mustLedgerHash(t, "ledger_subgraph", LedgerSubgraph(counsel, idArray(f.ids("open", "far")...)))
	if mustHashIntValue(t, apartSub, "node_count") != 2 || len(idsOf(t, apartSub, "edges")) != 0 {
		t.Errorf("the subgraph over open and far under counsel: %s", apartSub.Inspect())
	}
	mustRefuse(t, "a subgraph over what the view does not show",
		LedgerSubgraph(counsel, idArray(f.ids("pii", "unclassified", "both")...)),
		`2 of the 3 ids given are not visible under view "counsel"`)
}

// patternOf is a pattern of n nodes and the edges given, every node carrying
// label and every edge edgeLabel; a negative label leaves them unlabelled.
func patternOf(n int, label int64, edges [][2]int64, edgeLabel int64) *object.Hash {
	nodes := &object.Array{}
	for i := range n {
		node := map[string]object.Object{"id": intObj(int64(i))}
		if label >= 0 {
			node["labels"] = idArray(label)
		}
		nodes.Elements = append(nodes.Elements, makeHashObject(node))
	}
	links := &object.Array{}
	for _, e := range edges {
		edge := map[string]object.Object{"src": intObj(e[0]), "dst": intObj(e[1])}
		if edgeLabel >= 0 {
			edge["labels"] = idArray(edgeLabel)
		}
		links.Elements = append(links.Elements, makeHashObject(edge))
	}
	return makeHashObject(map[string]object.Object{"nodes": nodes, "edges": links})
}

func mappingsOf(t *testing.T, hash *object.Hash) [][]int64 {
	t.Helper()
	var out [][]int64
	for _, match := range mustHashArrayValue(t, hash, "matches") {
		var ids []int64
		for _, id := range match.(*object.Array).Elements {
			ids = append(ids, id.(*object.Integer).Value)
		}
		out = append(out, ids)
	}
	return out
}

// A match under a view is over what the view shows, and a scope's id the view
// does not show is in no match: graphene takes a scope's ids as an unlabelled
// node's candidates without reading them, and every pattern node is on an edge
// that is checked through the view.
func TestAMatchUnderAViewIsOverWhatItShows(t *testing.T) {
	f := newViewFixture(t)
	ledger, counsel, regulator := intObj(f.ledger), intObj(f.under(t, "counsel")), intObj(f.under(t, "regulator"))
	labelled := patternOf(2, viewFixtureLabel, [][2]int64{{0, 1}}, viewFixtureEdge)
	if whole := mustLedgerHash(t, "ledger_patterns", LedgerPatterns(ledger, labelled, intObj(0), intObj(0))); mustHashIntValue(t, whole, "count") != 5 {
		t.Fatalf("the whole ledger's matches: %s", whole.Inspect())
	}
	viewed := mustLedgerHash(t, "ledger_patterns", LedgerPatterns(counsel, labelled, intObj(0), intObj(0)))
	if got := mappingsOf(t, viewed); len(got) != 1 || !slices.Equal(got[0], f.ids("open", "pii")) ||
		mustHashStringValue(t, viewed, "view") != "counsel" {
		t.Errorf("the matches under counsel: %s", viewed.Inspect())
	}
	if none := mustLedgerHash(t, "ledger_patterns", LedgerPatterns(regulator, labelled, intObj(0), intObj(0))); mustHashIntValue(t, none, "count") != 0 {
		t.Errorf("the matches under regulator: %s", none.Inspect())
	}

	loose := patternOf(2, -1, [][2]int64{{0, 1}}, -1)
	scope := idArray(f.ids("open", "pii", "unclassified")...)
	unclassified := f.node["unclassified"]
	holds := func(mappings [][]int64) bool {
		for _, mapping := range mappings {
			if slices.Contains(mapping, unclassified) {
				return true
			}
		}
		return false
	}
	whole := mustLedgerHash(t, "ledger_patterns", LedgerPatterns(ledger, loose, scope, intObj(0)))
	if !holds(mappingsOf(t, whole)) {
		t.Fatalf("the scope's unclassified node matched nothing even through the whole ledger: %s", whole.Inspect())
	}
	scoped := mustLedgerHash(t, "ledger_patterns", LedgerPatterns(counsel, loose, scope, intObj(0)))
	if holds(mappingsOf(t, scoped)) || mustHashIntValue(t, scoped, "scope_size") != 3 {
		t.Errorf("a match under counsel names a node counsel does not show: %s", scoped.Inspect())
	}
}

func queryOf(fields map[string]object.Object) *object.Hash { return makeHashObject(fields) }

// A query under a view answers with what the view shows, applies its offset
// and limit to that, and says nothing about the index: whether a key is
// indexed anywhere says whether a withheld node holds it.
func TestAQueryUnderAViewCountsOnlyWhatItShows(t *testing.T) {
	f := newViewFixture(t)
	ledger, counsel := intObj(f.ledger), intObj(f.under(t, "counsel"))
	typed := func(extra map[string]object.Object) *object.Hash {
		fields := map[string]object.Object{"types": idArray(viewFixtureLabel)}
		maps.Copy(fields, extra)
		return queryOf(fields)
	}
	if all := mustLedgerHash(t, "ledger_query_nodes", LedgerQueryNodes(ledger, typed(nil))); mustHashIntValue(t, all, "count") != 7 {
		t.Fatalf("the whole ledger's nodes: %s", all.Inspect())
	}
	shown := mustLedgerHash(t, "ledger_query_nodes", LedgerQueryNodes(counsel, typed(nil)))
	if got := idsOf(t, shown, "ids"); !slices.Equal(got, f.ids("pii", "open", "far")) ||
		mustHashIntValue(t, shown, "count") != 3 || mustHashStringValue(t, shown, "view") != "counsel" ||
		mustHashBoolValue(t, shown, "index_keys_known") || len(mustHashStringArray(t, shown, "unindexed_keys")) != 0 {
		t.Errorf("the query under counsel: %s", shown.Inspect())
	}
	paged := mustLedgerHash(t, "ledger_query_nodes", LedgerQueryNodes(counsel,
		typed(map[string]object.Object{"offset": intObj(1), "limit": intObj(1)})))
	if got := idsOf(t, paged, "ids"); !slices.Equal(got, f.ids("open")) || !mustHashBoolValue(t, paged, "limited") {
		t.Errorf("the second page of one under counsel: %s", paged.Inspect())
	}
	first := mustLedgerHash(t, "ledger_query_nodes", LedgerQueryNodes(counsel,
		typed(map[string]object.Object{"limit": intObj(2)})))
	if got := idsOf(t, first, "ids"); !slices.Equal(got, f.ids("pii", "open")) {
		t.Errorf("the first two under counsel: %v", got)
	}

	for key, unindexed := range map[string][]string{"name": {}, "nosuchkey": {"nosuchkey"}} {
		filter := queryOf(map[string]object.Object{"filters": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"key": stringObj(key), "op": stringObj("eq"),
				"value": stringObj("unclassified")})}}})
		own := mustLedgerHash(t, "ledger_query_nodes", LedgerQueryNodes(ledger, filter))
		if !mustHashBoolValue(t, own, "index_keys_known") ||
			!slices.Equal(mustHashStringArray(t, own, "unindexed_keys"), unindexed) {
			t.Errorf("%s on the ledger's own handle: %s", key, own.Inspect())
		}
		viewed := mustLedgerHash(t, "ledger_query_nodes", LedgerQueryNodes(counsel, filter))
		if mustHashIntValue(t, viewed, "count") != 0 || mustHashBoolValue(t, viewed, "index_keys_known") ||
			len(mustHashStringArray(t, viewed, "unindexed_keys")) != 0 {
			t.Errorf("%s under counsel: %s", key, viewed.Inspect())
		}
	}
}

// A proof under a view is only of a node the view shows, and a node it does
// not show is refused before anything is proved, as one never held is.
func TestAProofUnderAViewIsOnlyOfANodeItShows(t *testing.T) {
	f := newViewFixture(t)
	mustLedgerHash(t, "ledger_compact", LedgerCompact(intObj(f.ledger)))
	counsel := intObj(f.under(t, "counsel"))
	proved := mustLedgerHash(t, "ledger_prove_node", LedgerProveNode(counsel, intObj(f.node["pii"])))
	assertLedgerDeclaredFields(t, BuiltinNameLedgerProveNode, proved)
	if mustHashStringValue(t, proved, "view") != "counsel" || mustHashIntValue(t, proved, "proof_bytes") == 0 {
		t.Errorf("the proof under counsel: %s", proved.Inspect())
	}
	withheld := refusalOf(t, LedgerProveNode(counsel, intObj(f.node["both"])))
	missing := refusalOf(t, LedgerProveNode(counsel, intObj(999999)))
	if withoutNumbers(withheld) != withoutNumbers(missing) || !strings.Contains(missing, "is not visible under view") {
		t.Errorf("two absences, two answers:\n%s\n%s", withheld, missing)
	}
	if own := mustLedgerHash(t, "ledger_prove_node", LedgerProveNode(intObj(f.ledger), intObj(f.node["both"]))); mustHashStringValue(t, own, "view") != "" {
		t.Errorf("the ledger's own proof names a view: %s", own.Inspect())
	}
}

// Of what this program writes, a view shows its case's Case and Record nodes,
// the Classification nodes of the classes it grants, and the IN_CASE and
// CLASSIFIED_AS edges among them. Nothing else it writes is shown.
func TestAViewShowsItsCaseRecordsAndTheClassesItGrants(t *testing.T) {
	f := newViewFixture(t)
	f.issue(t, "counsel", "Counsel")
	session, _ := ledgerGet(f.ledger)
	g := session.graph
	find := func(label store.NodeType, key, value string) int64 {
		t.Helper()
		node, found, err := disclosureFind(g, label, key, value)
		if err != nil || !found {
			t.Fatalf("%s %s = %s: %v %v", label, key, value, found, err)
		}
		return int64(node.id)
	}
	caseNode := find(disclosureNodeCase, "case.uid", strings.ToLower(openCaseUID(t)))
	record := find(disclosureNodeRecord, "record.uid", strings.ToLower(recordUIDOf(t, f.record)))
	tags := map[string]string{}
	custodyStore.RLock()
	for _, class := range custodyStore.session.classes {
		tags[class.Label] = strings.ToLower(class.Tag)
	}
	custodyStore.RUnlock()
	classNode := map[string]int64{}
	for _, label := range []string{"pii", "restricted"} {
		classNode[label] = find(disclosureNodeClass, "class.tag", tags[label])
	}
	withheldLabels := []store.NodeType{disclosureNodeActor, disclosureNodeView, disclosureNodeRecipient,
		disclosureNodeDisclosure, disclosureNodeAssignment, disclosureNodeRole, disclosureNodeRoleBundle,
		disclosureNodeClassEvent, disclosureNodeRedactionVersion}

	for view, grants := range map[string][]string{"counsel": {"open", "pii"}, "regulator": {"restricted"}} {
		handle := intObj(f.under(t, view))
		mustLedgerHash(t, "the Case node", LedgerNode(handle, intObj(caseNode)))
		mustLedgerHash(t, "the Record node", LedgerNode(handle, intObj(record)))
		for label, id := range classNode {
			result := LedgerNode(handle, intObj(id))
			if slices.Contains(grants, label) {
				mustLedgerHash(t, "a granted class", result)
			} else {
				mustRefuse(t, view+" and class "+label, result, "is not visible under view")
			}
		}
		for _, label := range withheldLabels {
			nodes, err := disclosureAll(g, label)
			if err != nil || len(nodes) == 0 {
				t.Fatalf("the fixture wrote no %s: %v", label, err)
			}
			for _, node := range nodes {
				mustRefuse(t, view+" and a "+label.String(), LedgerNode(handle, intObj(int64(node.id))),
					"is not visible under view")
			}
		}
		edges, err := g.EdgesOf(store.NodeID(record), store.DirectionBoth, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, edge := range edges {
			shown := edge.Labels[0] == disclosureEdgeInCase && int64(edge.Dst) == caseNode
			if edge.Labels[0] == disclosureEdgeClassifiedAs {
				far, err := g.GetNode(edge.Dst)
				if err != nil {
					t.Fatal(err)
				}
				props, _ := ledgerDecodeProperties(far.Properties)
				for _, label := range grants {
					shown = shown || string(props["class.tag"]) == tags[label]
				}
			}
			result := LedgerEdge(handle, intObj(int64(edge.ID)))
			if shown {
				mustLedgerHash(t, "an edge the view shows", result)
			} else {
				mustRefuse(t, view+" and the record's "+ledgerSchemaEdgeName(edge.Labels)+" edge", result,
					"is not visible under view")
			}
		}
	}

	// Another case's Case and Record are not this view's, and neither is a node
	// that carries a label a view shows beside one it does not.
	caseUID := strings.ToLower(openCaseUID(t))
	blob, err := ledgerPropertyBlob(map[string][]byte{"record.case_uid": []byte(caseUID)})
	if err != nil {
		t.Fatal(err)
	}
	disclosureLedgerMu.Lock()
	w, err := caseBeginWrite(session, caseUID, "IR-REC", custodyNow())
	var otherCase, otherRecord store.NodeID
	if err == nil {
		otherCase, err = w.tx.node(disclosureNodeCase, map[string]string{"case.uid": strings.Repeat("f", 32)})
	}
	if err == nil {
		otherRecord, err = w.tx.node(disclosureNodeRecord, map[string]string{"record.uid": strings.Repeat("e", 32),
			"record.case_uid": strings.Repeat("f", 32)})
	}
	twoLabels := w.tx.tx.AddNode(&store.Node{Labels: []store.NodeType{disclosureNodeRecord, disclosureNodeDisclosure},
		Properties: blob})
	if err == nil {
		err = w.tx.commit()
	}
	disclosureLedgerMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	counsel := intObj(f.under(t, "counsel"))
	for what, id := range map[string]store.NodeID{"another case's Case": otherCase, "another case's Record": otherRecord,
		"a Record that is also a Disclosure": twoLabels} {
		mustRefuse(t, what, LedgerNode(counsel, intObj(int64(id))), "is not visible under view")
	}
}

// Every builtin that takes a ledger refuses a handle under a view, by name,
// except the reads that read through one -- so a builtin added later reads or
// writes the whole ledger through such a handle only if somebody decides it
// may. ledger_close is the other exception, and drops it.
func TestEveryBuiltinTakingALedgerRefusesAHandleUnderAViewUnlessItReadsThroughOne(t *testing.T) {
	f := newViewFixture(t)
	handle := intObj(f.under(t, "counsel"))
	seen := 0
	for name, doc := range builtinDocs {
		if len(doc.params) == 0 || strings.TrimSuffix(doc.params[0].name, "?") != "ledger" || name == BuiltinNameLedgerClose {
			continue
		}
		seen++
		args := make([]object.Object, len(doc.params))
		args[0] = handle
		for i := 1; i < len(args); i++ {
			args[i] = intObj(1)
			if strings.HasPrefix(doc.params[i].name, "options") {
				args[i] = makeHashObject(nil)
			}
		}
		_, errObj := unwrapPairNoFatal(GetBuiltinByName(name).Fn(args...))
		refused := errObj != nil && strings.Contains(errObj.Message, "does not read under a view")
		// The editor's filteredLedgerHandle rule reports exactly the builtins
		// RefusesLedgerViewHandle names, so that is what each one is held to.
		switch refuses := RefusesLedgerViewHandle(name); {
		case !refuses && refused:
			t.Errorf("%s reads under a view and refused a handle under one: %s", name, errObj.Message)
		case refuses && !refused:
			t.Errorf("%s took a handle under a view: %v", name, errObj)
		case refuses && !strings.Contains(errObj.Message, "Pass the ledger's own handle ("):
			t.Errorf("%s refused a handle under a view without naming the ledger's own: %s", name, errObj.Message)
		}
	}
	if seen < len(ledgerViewReads)+30 {
		t.Fatalf("found %d builtins taking a ledger handle; the scan is not reaching them", seen)
	}
	if got := LedgerViewReads(); !slices.Equal(got, ledgerViewReads) {
		t.Errorf("LedgerViewReads is %v", got)
	}
	for name, want := range map[string]bool{BuiltinNameLedgerAddNode: true, BuiltinNameLedgerStats: true,
		BuiltinNameLedgerNode: false, BuiltinNameLedgerClose: false, BuiltinNameDbNode: false, BuiltinNamePutln: false} {
		if got := RefusesLedgerViewHandle(name); got != want {
			t.Errorf("RefusesLedgerViewHandle(%s) = %v, want %v", name, got, want)
		}
	}
}

// The reader under a view has graphene's twelve reader methods and nothing
// else, and embeds nothing: graphene's walks prefer a reader's AdjacencyReader
// methods to its EdgesOf, so one promoted from an embedded snapshot would hand
// every walk the unfiltered graph.
func TestTheViewReaderIsOnlyAGraphReader(t *testing.T) {
	methods := func(typ reflect.Type) []string {
		var out []string
		for i := range typ.NumMethod() {
			out = append(out, typ.Method(i).Name)
		}
		return out
	}
	want := methods(reflect.TypeFor[store.GraphReader]())
	if got := methods(reflect.TypeFor[*ledgerViewReader]()); !slices.Equal(got, want) {
		t.Errorf("the reader's methods are %v, want exactly %v", got, want)
	}
	fields := reflect.TypeFor[ledgerViewReader]()
	for i := range fields.NumField() {
		if fields.Field(i).Anonymous {
			t.Errorf("the reader embeds %s", fields.Field(i).Name)
		}
	}
	if _, fast := any(&ledgerViewReader{}).(store.AdjacencyReader); fast {
		t.Error("the reader offers graphene's adjacency fast path")
	}
}

// Every reader method answers only with what the view shows, including the
// ones no builtin calls yet.
func TestTheViewReaderAnswersEveryQuestionWithWhatItShows(t *testing.T) {
	f := newViewFixture(t)
	session, _ := ledgerGet(f.ledger)
	pii, open, far := store.NodeID(f.node["pii"]), store.NodeID(f.node["open"]), store.NodeID(f.node["far"])
	// Three edges from far to pii, the first one no view shows: a neighbour
	// joined by an edge a view shows is its neighbour whatever else joins them,
	// and a neighbour joined twice is one neighbour.
	tx := session.graph.Begin().As(session.txContext())
	tx.AddEdge(&store.Edge{Src: far, Dst: pii, Labels: []store.EdgeType{disclosureEdgeGrants}})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var farToPii []store.EdgeID
	for range 2 {
		joined := mustLedgerHash(t, "ledger_add_edge", LedgerAddEdge(intObj(f.ledger), intObj(int64(far)), intObj(int64(pii)),
			ledgerProps(map[string]string{"relation": "far->pii"}), intObj(viewFixtureEdge)))
		farToPii = append(farToPii, store.EdgeID(mustHashIntValue(t, joined, "id")))
	}
	openToPii := store.EdgeID(f.edge["open->pii"])

	view, _ := ledgerHandles.Load(f.under(t, "counsel"))
	g, done, errObj := ledgerReading{session: session, view: view.(*ledgerView)}.reader("test")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	defer done()

	nodes := func(ids []store.NodeID, err error) []store.NodeID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	edges := func(ids []store.EdgeID, err error) []store.EdgeID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	if got := nodes(g.NodesByType(store.CustomNodeType(viewFixtureLabel))); !slices.Equal(got, []store.NodeID{pii, open, far}) {
		t.Errorf("NodesByType: %v", got)
	}
	if got := nodes(g.NodesByProperty("kind", []byte("artefact"))); !slices.Equal(got, []store.NodeID{pii, open, far}) {
		t.Errorf("NodesByProperty: %v", got)
	}
	if got := edges(g.EdgesByType(store.CustomEdgeType(viewFixtureEdge))); !slices.Equal(got, []store.EdgeID{openToPii, farToPii[0], farToPii[1]}) {
		t.Errorf("EdgesByType: %v", got)
	}
	if got := edges(g.EdgesByProperty("relation", []byte("unclassified->pii"))); len(got) != 0 {
		t.Errorf("EdgesByProperty of an edge not shown: %v", got)
	}
	if got := edges(g.EdgesByProperty("relation", []byte("open->pii"))); !slices.Equal(got, []store.EdgeID{openToPii}) {
		t.Errorf("EdgesByProperty: %v", got)
	}
	if got := edges(g.QueryEdgeIDs(store.EdgeQuery{Types: []store.EdgeType{store.CustomEdgeType(viewFixtureEdge)},
		Offset: 1, Limit: 1})); !slices.Equal(got, []store.EdgeID{farToPii[0]}) {
		t.Errorf("QueryEdgeIDs, the second of one: %v", got)
	}
	inbound, err := g.EdgesOf(pii, store.DirectionInbound, nil)
	if err != nil || len(inbound) != 3 || inbound[0].ID != openToPii || inbound[1].ID != farToPii[0] ||
		inbound[2].ID != farToPii[1] {
		t.Errorf("EdgesOf: %v %v", inbound, err)
	}
	neighbours, err := g.Neighbours(pii, store.DirectionInbound, nil)
	if err != nil || len(neighbours) != 2 || neighbours[0].Node.ID != open || neighbours[1].Node.ID != far ||
		neighbours[1].Edge.ID != farToPii[0] {
		t.Errorf("Neighbours: %v %v", neighbours, err)
	}
	if hidden, err := g.EdgesOf(store.NodeID(f.node["unclassified"]), store.DirectionBoth, nil); err != nil || hidden != nil {
		t.Errorf("EdgesOf a node the view does not show: %v %v", hidden, err)
	}
	if hidden, err := g.Neighbours(store.NodeID(f.node["unclassified"]), store.DirectionBoth, nil); err != nil || hidden != nil {
		t.Errorf("Neighbours of a node the view does not show: %v %v", hidden, err)
	}
	var notFound *store.ErrNotFound
	if _, err := g.GetEdge(store.EdgeID(f.edge["both->unclassified"])); !errors.As(err, &notFound) {
		t.Errorf("GetEdge of an edge not shown: %v", err)
	}
	for _, count := range []func() (uint64, error){g.NodeCount, g.EdgeCount} {
		if n, err := count(); !errors.Is(err, errLedgerViewCount) || n != 0 {
			t.Errorf("a count under a view: %d %v", n, err)
		}
	}
}

// A handle under a view holds nothing open: closing it leaves the ledger open,
// closing the ledger leaves it only able to refuse, and the end of a program
// drops it without a word.
func TestAHandleUnderAViewHoldsNothingOpen(t *testing.T) {
	f := newViewFixture(t)
	pii := intObj(f.node["pii"])
	under := f.under(t, "counsel")
	if closed, errObj := unwrapPair(t, LedgerClose(intObj(under))); errObj != nil || !closed.(*object.Boolean).Value {
		t.Fatalf("ledger_close of a handle under a view: %v %v", closed, errObj)
	}
	mustLedgerHash(t, "the ledger itself", LedgerNode(intObj(f.ledger), pii))
	mustRefuse(t, "a dropped view", LedgerNode(intObj(under), pii), "unknown ledger handle")

	again := f.under(t, "counsel")
	if _, errObj := unwrapPair(t, LedgerClose(intObj(f.ledger))); errObj != nil {
		t.Fatal(errObj.Message)
	}
	mustRefuse(t, "a view of a closed ledger", LedgerNode(intObj(again), pii), "has been closed")
	for _, note := range CloseForgottenHandles() {
		t.Errorf("the end of the program said %q", note)
	}
	if _, left := ledgerHandles.Load(again); left {
		t.Error("the end of the program left the handle under a view")
	}
}

// ledger_under_view takes the ledger's own handle and a view the open case
// declared, and says what it is and is not.
func TestLedgerUnderViewTakesADeclaredViewOfTheLedgersOwnHandle(t *testing.T) {
	f := newViewFixture(t)
	result := mustHash(t, LedgerUnderView(intObj(f.ledger), stringObj(" Counsel ")))
	assertLedgerDeclaredFields(t, BuiltinNameLedgerUnderView, result)
	if mustHashStringValue(t, result, "view") != "counsel" || mustHashBoolValue(t, result, "access_control") ||
		mustHashIntValue(t, result, "ledger") != f.ledger || mustHashStringValue(t, result, "case_id") != "IR-REC" {
		t.Errorf("the handle says %s", result.Inspect())
	}
	assertStrings(t, "grants", mustHashStringArray(t, result, "grants"), "open", "pii")
	assertStrings(t, "reads", mustHashStringArray(t, result, "reads"), ledgerViewReads...)
	mustRefuse(t, "an undeclared view", LedgerUnderView(intObj(f.ledger), stringObj("press")),
		`"press" is not a declared view. This case declares counsel, regulator`)
	mustRefuse(t, "a view of a view", LedgerUnderView(intObj(mustHashIntValue(t, result, "handle")), stringObj("counsel")),
		"does not read under a view")
	resetCustodyForTesting()
	mustRefuse(t, "no case", LedgerUnderView(intObj(f.ledger), stringObj("counsel")), "no case is open")
}
