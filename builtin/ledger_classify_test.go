package builtin

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// viewFixtureLabel is the script label the view fixture's nodes are written
// under, and viewFixtureEdge the label of its edges.
const (
	viewFixtureLabel = 7
	viewFixtureEdge  = 1
)

// viewFixture is the disclosure fixture's case -- classes open, pii and
// restricted; views counsel (open, pii) and regulator (restricted) -- with
// seven nodes a script wrote into its ledger, classified as named, and five
// edges among them:
//
//	open -> pii, unclassified -> pii, unclassified -> far,
//	restricted -> open, both -> unclassified
//
// "both" holds pii and restricted, "nothing" was classified as holding
// nothing, and "unclassified" never was. Under counsel the nodes pii, open and
// far are shown, and the one edge open -> pii; under regulator, restricted and
// no edge.
type viewFixture struct {
	*discloseFixture
	node map[string]int64
	edge map[string]int64
}

func newViewFixture(t *testing.T) *viewFixture {
	t.Helper()
	f := &viewFixture{discloseFixture: newDiscloseFixture(t), node: map[string]int64{}, edge: map[string]int64{}}
	classes := map[string][]string{
		"pii": {"pii"}, "open": {"open"}, "restricted": {"restricted"}, "both": {"pii", "restricted"},
		"nothing": {}, "far": {"pii"},
	}
	for _, name := range []string{"pii", "open", "restricted", "both", "nothing", "unclassified", "far"} {
		added := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(f.ledger),
			ledgerProps(map[string]string{"name": name, "kind": "artefact"}), intObj(viewFixtureLabel)))
		f.node[name] = mustHashIntValue(t, added, "id")
		if held, classified := classes[name]; classified {
			f.classify(t, name, held...)
		}
	}
	for _, e := range [][2]string{{"open", "pii"}, {"unclassified", "pii"}, {"unclassified", "far"},
		{"restricted", "open"}, {"both", "unclassified"}} {
		name := e[0] + "->" + e[1]
		added := mustLedgerHash(t, "ledger_add_edge", LedgerAddEdge(intObj(f.ledger), intObj(f.node[e[0]]),
			intObj(f.node[e[1]]), ledgerProps(map[string]string{"relation": name}), intObj(viewFixtureEdge)))
		f.edge[name] = mustHashIntValue(t, added, "id")
	}
	return f
}

// classify classifies one of the fixture's nodes.
func (f *viewFixture) classify(t *testing.T, name string, classes ...string) *object.Hash {
	t.Helper()
	list := make([]object.Object, 0, len(classes))
	for _, class := range classes {
		list = append(list, stringObj(class))
	}
	return mustHash(t, LedgerClassify(intObj(f.ledger), intObj(f.node[name]), &object.Array{Elements: list},
		stringObj("what the node holds")))
}

// under returns a handle to the fixture's ledger under a view.
func (f *viewFixture) under(t *testing.T, view string) int64 {
	t.Helper()
	return mustHashIntValue(t, mustHash(t, LedgerUnderView(intObj(f.ledger), stringObj(view))), "handle")
}

// sortedStrings is a hash's string list, sorted: classes come back in tag
// order, which is the order of their HMACs.
func sortedStrings(t *testing.T, hash *object.Hash, key string) []string {
	t.Helper()
	out := mustHashStringArray(t, hash, key)
	sort.Strings(out)
	return out
}

func assertStrings(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s is %q, want %q", what, got, want)
	}
}

// A node's classifications are one chain in its case: each is the next event,
// one that changes nothing is refused, and a node may be classified as
// holding nothing, which no view shows.
func TestLedgerClassifyKeepsAChainPerNode(t *testing.T) {
	f := newViewFixture(t)
	ledger, pii := intObj(f.ledger), intObj(f.node["pii"])

	mustRefuse(t, "the same classes again", LedgerClassify(ledger, pii, stringObj("PII"), stringObj("x")),
		`node `+pii.Inspect()+` is already classified as "pii" in case IR-REC`)

	second := mustHash(t, LedgerClassify(ledger, pii, viewArray("restricted", "pii"), stringObj("both, on a second look")))
	assertLedgerDeclaredFields(t, BuiltinNameLedgerClassify, second)
	if seq := mustHashIntValue(t, second, "seq"); seq != 2 {
		t.Errorf("the reclassification is event %d, want 2", seq)
	}
	assertStrings(t, "classes", sortedStrings(t, second, "classes"), "pii", "restricted")
	assertStrings(t, "previous_classes", mustHashStringArray(t, second, "previous_classes"), "pii")
	assertStrings(t, "shown_under", mustHashStringArray(t, second, "shown_under"))
	if len(mustHashStringArray(t, second, "tags")) != 2 || mustHashBoolValue(t, second, "role_authenticated") {
		t.Errorf("the reclassification says %v", second.Inspect())
	}
	if by := mustHashStringValue(t, second, "by"); by != "examiner" {
		t.Errorf("by is %q", by)
	}

	third := mustHash(t, LedgerClassify(ledger, pii, &object.Array{}, stringObj("nothing here is for anybody")))
	assertStrings(t, "classes", mustHashStringArray(t, third, "classes"))
	assertStrings(t, "shown_under", mustHashStringArray(t, third, "shown_under"))
	mustRefuse(t, "nothing again", LedgerClassify(ledger, pii, &object.Array{}, stringObj("x")),
		"is already classified as holding nothing")

	fourth := mustHash(t, LedgerClassify(ledger, pii, stringObj("open"), stringObj("released in full")))
	assertStrings(t, "shown_under", mustHashStringArray(t, fourth, "shown_under"), "counsel")

	listed := mustHash(t, LedgerClassifications(ledger, pii))
	assertLedgerDeclaredFields(t, BuiltinNameLedgerClassifications, listed)
	rows := mustHashArrayValue(t, listed, "classifications")
	if len(rows) != 1 || mustHashIntValue(t, listed, "count") != 1 || !mustHashBoolValue(t, listed, "keyed") {
		t.Fatalf("one node's classifications: %s", listed.Inspect())
	}
	row := rows[0].(*object.Hash)
	assertStrings(t, "classes in force", mustHashStringArray(t, row, "classes"), "open")
	assertStrings(t, "shown_under", mustHashStringArray(t, row, "shown_under"), "counsel")
	if !mustHashBoolValue(t, row, "present") || mustHashIntValue(t, row, "node") != pii.Value ||
		mustHashStringValue(t, row, "case_uid") != strings.ToLower(openCaseUID(t)) {
		t.Errorf("the row says %s", row.Inspect())
	}
	events := mustHashArrayValue(t, row, "events")
	var history []string
	for _, event := range events {
		h := event.(*object.Hash)
		classes := sortedStrings(t, h, "classes")
		history = append(history, fmt.Sprintf("%d:%s", mustHashIntValue(t, h, "seq"), strings.Join(classes, "+")))
	}
	assertStrings(t, "the chain", history, "1:pii", "2:pii+restricted", "3:", "4:open")
	if reason := mustHashStringValue(t, events[3].(*object.Hash), "reason"); reason != "released in full" {
		t.Errorf("event 4's reason is %q", reason)
	}

	// Every classified node of the case, and not the one nobody classified.
	all := mustHash(t, LedgerClassifications(ledger))
	var nodes []int64
	for _, row := range mustHashArrayValue(t, all, "classifications") {
		nodes = append(nodes, mustHashIntValue(t, row.(*object.Hash), "node"))
	}
	want := []int64{f.node["pii"], f.node["open"], f.node["restricted"], f.node["both"], f.node["nothing"], f.node["far"]}
	if !slices.Equal(nodes, want) || mustHashIntValue(t, all, "node") != 0 {
		t.Errorf("the case's classified nodes are %v, want %v", nodes, want)
	}
}

// What is classified is a node a script wrote, under declared classes named
// once; anything else is refused and nothing is recorded.
func TestLedgerClassifyRefusesWhatItDoesNotClassify(t *testing.T) {
	f := newViewFixture(t)
	ledger, node, reason := intObj(f.ledger), intObj(f.node["unclassified"]), stringObj("x")

	mustRefuse(t, "an undeclared class", LedgerClassify(ledger, node, viewArray("pii", "secret"), reason),
		`entry 2 names "secret", which is not a declared classification. This case declares open, restricted, pii`)
	mustRefuse(t, "a repeated class", LedgerClassify(ledger, node, viewArray("pii", " PII "), reason),
		`entry 2 names " PII ", which this classification already holds as "pii"`)
	mustRefuse(t, "a list of numbers", LedgerClassify(ledger, node, &object.Array{Elements: []object.Object{intObj(1)}},
		reason), "entry 1 of the class list must be STRING")
	mustRefuse(t, "a number", LedgerClassify(ledger, node, intObj(1), reason), "must be STRING or ARRAY")
	mustRefuse(t, "no reason", LedgerClassify(ledger, node, stringObj("pii"), stringObj("  ")), "reason must not be empty")
	mustRefuse(t, "a node never written", LedgerClassify(ledger, intObj(99999), stringObj("pii"), reason),
		"this ledger has no node 99999")

	f.issue(t, "counsel", "Counsel")
	session, _ := ledgerGet(f.ledger)
	caseNode, found, err := disclosureFind(session.graph, disclosureNodeCase, "case.uid", strings.ToLower(openCaseUID(t)))
	if err != nil || !found {
		t.Fatalf("the Case node: %v %v", found, err)
	}
	mustRefuse(t, "the Case node", LedgerClassify(ledger, intObj(int64(caseNode.id)), stringObj("pii"), reason),
		"is a Case record, which this program writes")

	mustLedgerHash(t, "ledger_redact_node", LedgerRedactNode(ledger, intObj(f.node["nothing"]), stringObj("court order 7")))
	mustRefuse(t, "a redacted node", LedgerClassify(ledger, intObj(f.node["nothing"]), stringObj("pii"), reason),
		"because it was redacted")

	if listed := mustHash(t, LedgerClassifications(ledger, node)); mustHashIntValue(t, listed, "count") != 0 {
		t.Errorf("a refused classification was recorded: %s", listed.Inspect())
	}
}

// A node is classified under a case's classes, which need its key.
func TestLedgerClassifyAndReadsUnderAViewNeedTheCaseKey(t *testing.T) {
	openTestCase(t, "IR-NOKEY", "examiner")
	handle, _ := openTestLedger(t, "examiner")
	node := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"k": "v"})))
	mustRefuse(t, "a classification with no key", LedgerClassify(intObj(handle), intObj(mustHashIntValue(t, node, "id")),
		stringObj("pii"), stringObj("x")), "no case key is open")
	mustRefuse(t, "a view with no key", LedgerUnderView(intObj(handle), stringObj("counsel")), "no case key is open")
}

// A case attached to a ledger is classified in that ledger and nowhere else,
// and not while it is in review or disposed.
func TestLedgerClassifyWritesOnlyWhereTheCaseIs(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustHash(t, ClassDefine(stringObj("pii")))
	other, _ := openTestLedger(t, "examiner")
	elsewhere := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(other), ledgerProps(map[string]string{"k": "v"})))
	mustRefuse(t, "another ledger", LedgerClassify(intObj(other), intObj(mustHashIntValue(t, elsewhere, "id")),
		stringObj("pii"), stringObj("x")), "is attached to ledger")

	ledger := intObj(run.ledger)
	node := intObj(mustHashIntValue(t, mustLedgerHash(t, "ledger_add_node",
		LedgerAddNode(ledger, ledgerProps(map[string]string{"k": "v"}))), "id"))
	mustHash(t, LedgerClassify(ledger, node, stringObj("pii"), stringObj("found in the mailbox")))

	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateActive, caseStateInReview)
	mustRefuse(t, "a classification in review", LedgerClassify(ledger, node, &object.Array{}, stringObj("x")),
		"takes no definition of a class, a view or a role's bundle, or record of a classification")
	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateConcluded)
	mustHash(t, LedgerClassify(ledger, node, &object.Array{}, stringObj("withdrawn from every view")))
	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateRetained, caseStateDisposed)
	mustRefuse(t, "a classification once disposed", LedgerClassify(ledger, node, stringObj("pii"), stringObj("x")),
		"takes no definition")
}

// A classification names its node by id and no edge joins them, so redacting
// a classified node reaches nothing of the schema: the node goes, its
// classification stays, and the listing says the node is gone.
func TestAClassifiedNodeCanStillBeRedacted(t *testing.T) {
	f := newViewFixture(t)
	session, _ := ledgerGet(f.ledger)
	for name, id := range f.node {
		edges, err := session.graph.EdgesOf(store.NodeID(id), store.DirectionBoth, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, edge := range edges {
			if !ledgerScriptEdgeLabels(edge.Labels) {
				t.Errorf("node %s has a %s edge", name, ledgerSchemaEdgeName(edge.Labels))
			}
		}
	}
	ledger, far := intObj(f.ledger), intObj(f.node["far"])
	mustLedgerHash(t, "ledger_redact_node", LedgerRedactNode(ledger, far, stringObj("court order 9")))
	listed := mustHash(t, LedgerClassifications(ledger, far))
	rows := mustHashArrayValue(t, listed, "classifications")
	if len(rows) != 1 || mustHashBoolValue(t, rows[0].(*object.Hash), "present") {
		t.Fatalf("the redacted node's classification: %s", listed.Inspect())
	}
	assertStrings(t, "classes", mustHashStringArray(t, rows[0].(*object.Hash), "classes"), "pii")
}

// ledger_classifications needs no case open: an auditor reads every case's
// classifications with the ledger alone.
func TestLedgerClassificationsNeedNoCase(t *testing.T) {
	f := newViewFixture(t)
	caseUID := strings.ToLower(openCaseUID(t))
	resetCustodyForTesting()
	listed := mustHash(t, LedgerClassifications(intObj(f.ledger)))
	if mustHashBoolValue(t, listed, "keyed") || mustHashIntValue(t, listed, "count") != 6 ||
		mustHashStringValue(t, listed, "case_id") != "" {
		t.Fatalf("with no case open: %s", listed.Inspect())
	}
	for _, row := range mustHashArrayValue(t, listed, "classifications") {
		h := row.(*object.Hash)
		if mustHashStringValue(t, h, "case_uid") != caseUID || len(mustHashStringArray(t, h, "shown_under")) != 0 {
			t.Errorf("row %s", h.Inspect())
		}
	}
	one := mustHash(t, LedgerClassifications(intObj(f.ledger), intObj(f.node["both"])))
	if rows := mustHashArrayValue(t, one, "classifications"); len(rows) != 1 {
		t.Fatalf("one node with no case open: %s", one.Inspect())
	}
}

// The keys every reader looks a ClassEvent up by are indexed. Named here, not
// read from disclosureKeys, so that a key dropped from that table fails this
// test instead of quietly leaving it.
func TestAClassEventIsFoundByEachOfItsLookupKeys(t *testing.T) {
	f := newViewFixture(t)
	session, _ := ledgerGet(f.ledger)
	classification, err := classificationRead(session.graph, openCaseUID(t), store.NodeID(f.node["both"]))
	if err != nil {
		t.Fatal(err)
	}
	head := classification.head()
	for _, key := range []string{"classify.uid", "classify.chain", "classify.case_uid", "classify.target"} {
		ids, err := session.graph.NodesByProperty(key, []byte(head.get(key)))
		if err != nil || !slices.Contains(ids, head.id) {
			t.Errorf("the ClassEvent is not found by %s = %q: %v %v", key, head.get(key), ids, err)
		}
	}
}

// A ClassEvent is joined to its case, to the actor who recorded it, under the
// role they asserted, and to each class it names -- and to nothing a script
// wrote.
func TestAClassEventIsJoinedToItsCaseItsActorAndItsClasses(t *testing.T) {
	f := newViewFixture(t)
	session, _ := ledgerGet(f.ledger)
	g := session.graph
	caseUID := strings.ToLower(openCaseUID(t))
	classification, err := classificationRead(g, caseUID, store.NodeID(f.node["both"]))
	if err != nil {
		t.Fatal(err)
	}
	head := classification.head()
	edges, err := g.EdgesOf(head.id, store.DirectionOutbound, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, edge := range edges {
		far, err := g.GetNode(edge.Dst)
		if err != nil {
			t.Fatal(err)
		}
		props, _ := ledgerDecodeProperties(far.Properties)
		edgeProps, _ := ledgerDecodeProperties(edge.Properties)
		switch {
		case edge.Labels[0] == disclosureEdgeInCase && far.HasLabel(disclosureNodeCase):
			got = append(got, "IN_CASE "+string(props["case.uid"]))
		case edge.Labels[0] == disclosureEdgePerformedBy && far.HasLabel(disclosureNodeActor):
			got = append(got, "PERFORMED_BY "+string(props["actor.name"])+" as "+string(edgeProps["role"]))
		case edge.Labels[0] == disclosureEdgeClassifiedAs && far.HasLabel(disclosureNodeClass):
			got = append(got, "CLASSIFIED_AS "+string(props["class.tag"]))
		default:
			t.Errorf("the ClassEvent has a %s edge to node %d", ledgerSchemaEdgeName(edge.Labels), edge.Dst)
		}
	}
	sort.Strings(got)
	want := []string{"CLASSIFIED_AS " + head.tags[0], "CLASSIFIED_AS " + head.tags[1], "IN_CASE " + caseUID,
		"PERFORMED_BY examiner as " + session.role.Name}
	sort.Strings(want)
	assertStrings(t, "the ClassEvent's edges", got, want...)
}

// forgeClassification appends events to a node's classification chain the way
// this program does, with props written over its head's, and twice after the
// same head when fork is set.
func forgeClassification(t *testing.T, f *viewFixture, name string, props map[string]string, fork bool) {
	t.Helper()
	session, _ := ledgerGet(f.ledger)
	caseUID := strings.ToLower(openCaseUID(t))
	node := store.NodeID(f.node[name])
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	current, err := classificationRead(session.graph, caseUID, node)
	if err != nil {
		t.Fatal(err)
	}
	head := current.head()
	all := map[string]string{}
	for key, value := range head.props {
		switch key {
		case "classify.chain", "classify.seq", "classify.prev_uid", "classify.uid":
		default:
			all[key] = value
		}
	}
	maps.Copy(all, props)
	w, err := caseBeginWrite(session, caseUID, "IR-REC", custodyNow())
	if err != nil {
		t.Fatal(err)
	}
	events := 1
	if fork {
		events = 2
	}
	for i := range events {
		all["classify.reason"] = fmt.Sprintf("forged %d", i)
		if _, _, err := w.tx.chainAppend(classifyChain, classifyChainKey(caseUID, node), &head.caseChainEvent, all); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.tx.commit(); err != nil {
		t.Fatal(err)
	}
}

// forgeClassEvent writes one ClassEvent node as it stands, outside any chain
// this program would have kept it in.
func forgeClassEvent(t *testing.T, f *viewFixture, props map[string]string) {
	t.Helper()
	session, _ := ledgerGet(f.ledger)
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	w, err := caseBeginWrite(session, openCaseUID(t), "IR-REC", custodyNow())
	if err == nil {
		if _, err = w.tx.node(disclosureNodeClassEvent, props); err == nil {
			err = w.tx.commit()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

// A classification chain says one thing about one node in one case, in terms
// this program writes. Anything else is refused by every reader of it: the
// listing, a reclassification, and a read under a view -- which says only that
// the node's classification cannot be read, and where to ask why.
func TestAClassificationChainThisProgramDidNotWriteIsRefused(t *testing.T) {
	tag := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	for _, c := range []struct {
		name  string
		props map[string]string
		fork  bool
		want  string
	}{
		{"two classifications after one", nil, true, "two classify events after"},
		{"another node's classification", map[string]string{"classify.target": "999999"}, false,
			"and says it classifies node 999999"},
		{"a tag of 64 characters that are not hex", map[string]string{"classify.tags": strings.Repeat("z", 64),
			"classify.classes": `["x"]`}, false, "as a class tag"},
		{"another case's classification", map[string]string{"classify.case_uid": strings.Repeat("f", 32)}, false,
			"in case " + strings.Repeat("f", 32)},
		{"a tag that is not one", map[string]string{"classify.tags": "zz", "classify.classes": `["x"]`}, false,
			`it records "zz" as a class tag`},
		{"an upper-case tag", map[string]string{"classify.tags": strings.ToUpper(tag), "classify.classes": `["x"]`},
			false, "as a class tag"},
		{"a short tag", map[string]string{"classify.tags": tag[:62], "classify.classes": `["x"]`}, false,
			"as a class tag"},
		{"tags out of order", map[string]string{"classify.tags": other + "," + tag, "classify.classes": `["x","y"]`},
			false, "not in ascending order, each once"},
		{"a tag twice", map[string]string{"classify.tags": tag + "," + tag, "classify.classes": `["x","y"]`},
			false, "not in ascending order, each once"},
		{"labels that are not a list", map[string]string{"classify.classes": "pii"}, false,
			"its class labels are not a list"},
		{"a label short", map[string]string{"classify.classes": "[]"}, false, "records 0 class labels for 1 class tags"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newViewFixture(t)
			forgeClassification(t, f, "pii", c.props, c.fork)
			ledger, pii := intObj(f.ledger), intObj(f.node["pii"])
			mustRefuse(t, "the listing", LedgerClassifications(ledger), c.want)
			mustRefuse(t, "the node's listing", LedgerClassifications(ledger, pii), c.want)
			mustRefuse(t, "a reclassification", LedgerClassify(ledger, pii, stringObj("open"), stringObj("x")), c.want)
			mustRefuse(t, "a read under a view", LedgerNode(intObj(f.under(t, "counsel")), pii),
				"cannot be read, so whether view \"counsel\" shows it is not decided; ledger_classifications on "+
					"the ledger's own handle says why")
			// An event that names another node is read -- and refused -- with
			// the chain it is kept in, not with the node it names.
			if c.props["classify.target"] != "" {
				named := mustHash(t, LedgerClassifications(ledger, intObj(999999)))
				if mustHashIntValue(t, named, "count") != 0 {
					t.Errorf("the node the forged event names: %s", named.Inspect())
				}
			}
		})
	}

	// An event of this case kept in another case's chain: read with that
	// chain, so the case's own listing is not stopped by it, and the listing of
	// every case refuses it.
	t.Run("an event kept in another case's chain", func(t *testing.T) {
		f := newViewFixture(t)
		caseUID := strings.ToLower(openCaseUID(t))
		pii := fmt.Sprint(f.node["pii"])
		session, _ := ledgerGet(f.ledger)
		disclosureLedgerMu.Lock()
		w, err := caseBeginWrite(session, caseUID, "IR-REC", custodyNow())
		if err == nil {
			if _, _, err = w.tx.chainAppend(classifyChain, strings.Repeat("f", 32)+"|"+pii, nil, map[string]string{
				"classify.case_uid": caseUID, "classify.target": pii, "classify.tags": "",
				"classify.classes": "[]"}); err == nil {
				err = w.tx.commit()
			}
		}
		disclosureLedgerMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if listed := mustHash(t, LedgerClassifications(intObj(f.ledger))); mustHashIntValue(t, listed, "count") != 6 {
			t.Errorf("the case's own listing: %s", listed.Inspect())
		}
		resetCustodyForTesting()
		mustRefuse(t, "every case's listing", LedgerClassifications(intObj(f.ledger)),
			"is kept with node "+pii+"'s classifications in case "+strings.Repeat("f", 32))
	})

	// Kept under a name this program does not give a chain.
	for _, chain := range []string{"no-node-at-all", "|5", "{case}|007", "{case}|0"} {
		t.Run("a chain named "+chain, func(t *testing.T) {
			f := newViewFixture(t)
			caseUID := strings.ToLower(openCaseUID(t))
			forgeClassEvent(t, f, map[string]string{"classify.chain": strings.ReplaceAll(chain, "{case}", caseUID),
				"classify.case_uid": caseUID, "classify.target": "7", "classify.uid": tag})
			mustRefuse(t, "the listing", LedgerClassifications(intObj(f.ledger)), "names a case and a node in no way "+
				"this program names them")
		})
	}
}
