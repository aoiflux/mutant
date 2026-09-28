package builtin

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// reviewRun is a case attached to its ledger and active, owned by alice with
// bob assigned as its reviewer, holding one sealed record and a redaction
// version of it committed under counsel.
type reviewRun struct {
	*lifecycleRun
	record     object.Object
	recordFile string
	recordUID  string
	versionUID string
	partition  string
}

func openReviewRun(t *testing.T) *reviewRun {
	t.Helper()
	useTestKeyStore(t)
	run := openLifecycleRun(t, "alice", "case_owner", "", "")
	run.attach(t)
	ledger := intObj(run.ledger)
	mustHash(t, CaseTransition(ledger, stringObj("active"), stringObj("work begins")))
	mustHash(t, CaseAssign(ledger, stringObj("bob"), stringObj("reviewer"), stringObj("peer review")))
	mustHash(t, ClassDefine(stringObj("open")))
	mustHash(t, ClassDefine(stringObj("pii")))
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open", "pii")))
	mustHash(t, ViewDefine(stringObj("desk"), viewArray("open")))
	source, dest, _ := recordFixture(t)
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(
		mustHash(t, RecordClassifyRange(intObj(10), intObj(20), stringObj("pii")))), recordSealOpts(nil)))
	record := mustHashValue(t, mustHash(t, RecordOpen(stringObj(dest))), "handle")
	t.Cleanup(func() { RecordClose(record) })
	version := mustHash(t, RedactionCommit(ledger, record, stringObj("counsel"), stringObj("the redaction for review")))
	return &reviewRun{lifecycleRun: run, record: record, recordFile: dest, recordUID: recordUIDOf(t, record),
		versionUID: mustHashStringValue(t, version, "uid"), partition: mustHashStringValue(t, version, "partition")}
}

// as ends this run and opens the case again, attached, as examiner under
// role, and returns what the attach read back.
func (r *reviewRun) as(t *testing.T, examiner, role string) *object.Hash {
	t.Helper()
	r.lifecycleRun = r.next(t, examiner, role)
	return r.attach(t)
}

func (r *reviewRun) handle() object.Object { return intObj(r.ledger) }

// requestCase writes a manifest of the case as it stands and asks for a
// review of the case bound to it.
func (r *reviewRun) requestCase(t *testing.T, note string) (*object.Hash, string) {
	t.Helper()
	path := writeManifest(t)
	return mustHash(t, ReviewRequest(r.handle(), stringObj("case"), stringObj(note), manifestOption(path))), path
}

func manifestOption(path string) object.Object {
	return makeHashObject(map[string]object.Object{"manifest": stringObj(path)})
}

// reviewRows reads review_list and its rows.
func reviewRows(t *testing.T, ledger object.Object, options ...object.Object) (*object.Hash, []*object.Hash) {
	t.Helper()
	list := mustHash(t, ReviewList(append([]object.Object{ledger}, options...)...))
	var rows []*object.Hash
	for _, row := range mustHashArrayValue(t, list, "requests") {
		rows = append(rows, row.(*object.Hash))
	}
	return list, rows
}

// timelineData is the data of the last entry the open case's timeline holds
// for an event.
func timelineData(t *testing.T, event string) *object.Hash {
	t.Helper()
	var data *object.Hash
	for _, entry := range mustHashArrayValue(t, mustHash(t, CaseManifest()), "timeline") {
		e := entry.(*object.Hash)
		if mustHashStringValue(t, e, "event") == event {
			data = mustHashValue(t, e, "data").(*object.Hash)
		}
	}
	if data == nil {
		t.Fatalf("the timeline records no %s", event)
	}
	return data
}

// rewriteManifest decodes a written manifest, lets edit change it, seals it
// again unsigned when reseal is set, and writes it to a file of its own.
func rewriteManifest(t *testing.T, path string, reseal bool, edit func(map[string]any)) string {
	t.Helper()
	document, errObj := custodyManifestDocument("test", path)
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	edit(document)
	if reseal {
		if err := custodySeal(document, false); err != nil {
			t.Fatal(err)
		}
	}
	out, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "rewritten.json")
	if err := os.WriteFile(dest, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return dest
}

// schemaNode finds the node of a schema label its key names.
func schemaNode(t *testing.T, session *ledgerSession, label store.NodeType, key, value string) disclosureNode {
	t.Helper()
	node, found, err := disclosureFind(session.graph, label, key, value)
	if err != nil || !found {
		t.Fatalf("no %s node has %s = %s: %v", label.String(), key, value, err)
	}
	return node
}

// edgeTo reads the one edge of a label that leaves a node, and the node it
// reaches.
func edgeTo(t *testing.T, session *ledgerSession, from store.NodeID, label store.EdgeType) disclosureNode {
	t.Helper()
	edges, err := session.store.EdgesOf(from, store.DirectionOutbound, []store.EdgeType{label})
	if err != nil || len(edges) != 1 {
		t.Fatalf("node %d has %d edges of label %v: %v", from, len(edges), label, err)
	}
	node, err := session.graph.GetNode(edges[0].Dst)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := disclosureDecode(node)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// assertCaseRecordEdges holds a case record to the IN_CASE and PERFORMED_BY
// edges every one carries.
func assertCaseRecordEdges(t *testing.T, session *ledgerSession, node store.NodeID, caseUID, actor string) {
	t.Helper()
	if got := edgeTo(t, session, node, disclosureEdgeInCase).get("case.uid"); got != strings.ToLower(caseUID) {
		t.Errorf("node %d is IN_CASE %q, want %q", node, got, caseUID)
	}
	if got := edgeTo(t, session, node, disclosureEdgePerformedBy).get("actor.name"); got != actor {
		t.Errorf("node %d is PERFORMED_BY %q, want %q", node, got, actor)
	}
}

// forgeCaseRecord commits what write buffers through a writer of the open
// case, the way this program's own writers do: for the shapes they never
// write.
func forgeCaseRecord(t *testing.T, ledger *ledgerSession, write func(w *caseWriter) error) {
	t.Helper()
	caseUID := openCaseUID(t)
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	w, err := caseBeginWrite(ledger, caseUID, "IR-LIFE", custodyNow())
	if err == nil {
		if err = write(w); err == nil {
			err = w.tx.commit()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

// A case is submitted for review bound to a written manifest, which moves it
// into review; a reviewer's approval concludes it; the lifecycle says which
// review each move was made for; and a request is decided once.
func TestACaseReviewMovesTheCaseIntoReviewAndOn(t *testing.T) {
	r := openReviewRun(t)
	caseUID := openCaseUID(t)
	requested, manifest := r.requestCase(t, "ready for peer review")
	hash := mustHashStringValue(t, verifyManifest(t, manifest), "manifest_hash")
	if mustHashStringValue(t, requested, "subject_kind") != reviewSubjectCase ||
		mustHashStringValue(t, requested, "subject") != caseUID || mustHashStringValue(t, requested, "subject_hash") != hash ||
		!mustHashBoolValue(t, requested, "manifest_signed") || mustHashStringValue(t, requested, "manifest") != manifest ||
		mustHashStringValue(t, requested, "from") != caseStateActive ||
		mustHashStringValue(t, requested, "state") != caseStateInReview || !mustHashBoolValue(t, requested, "moved") ||
		mustHashIntValue(t, requested, "seq") != 1 || mustHashStringValue(t, requested, "by") != "alice" {
		t.Fatalf("review_request gave %s", requested.Inspect())
	}
	requestUID := mustHashStringValue(t, requested, "uid")
	if data := timelineData(t, BuiltinNameReviewRequest); mustHashStringValue(t, data, "subject_hash") != hash ||
		mustHashStringValue(t, data, "uid") != requestUID {
		t.Fatalf("the timeline records the request as %s", data.Inspect())
	}
	session := r.session(t)
	requestNode := schemaNode(t, session, disclosureNodeReviewRequest, "review.uid", requestUID)
	if got := edgeTo(t, session, requestNode.id, disclosureEdgeReviews).get("case.uid"); got != caseUID {
		t.Fatalf("a review of the case REVIEWS %q", got)
	}
	// The run's copy of the case moved with the ledger, so what a review
	// freezes is refused here as well.
	mustRefuse(t, "a definition in review", ClassDefine(stringObj("late")), "takes no definition")
	mustRefuse(t, "a decision by the case's owner", ReviewDecide(r.handle(), stringObj(requestUID),
		stringObj("approved"), stringObj("x")), "is acting as case_owner, and a review is decided by a reviewer")

	r.as(t, "bob", "reviewer")
	decided := mustHash(t, ReviewDecide(r.handle(), stringObj(strings.ToUpper(requestUID)), stringObj(" Approved "),
		stringObj("the findings follow from the evidence")))
	if mustHashStringValue(t, decided, "decision") != reviewApproved || mustHashStringValue(t, decided, "request_uid") != requestUID ||
		mustHashStringValue(t, decided, "from") != caseStateInReview ||
		mustHashStringValue(t, decided, "state") != caseStateConcluded || !mustHashBoolValue(t, decided, "moved") ||
		mustHashStringValue(t, decided, "requested_by") != "alice" || mustHashStringValue(t, decided, "by") != "bob" ||
		mustHashStringValue(t, decided, "by_role") != "reviewer" || mustHashStringValue(t, decided, "subject_hash") != hash ||
		mustHashStringValue(t, decided, "subject") != caseUID {
		t.Fatalf("review_decide gave %s", decided.Inspect())
	}
	if state := manifestSection(t, mustHash(t, CaseManifest()), "ledger_state"); mustHashStringValue(t, state, "state") != caseStateConcluded {
		t.Fatalf("the run's copy of the case is %s", state.Inspect())
	}
	if data := timelineData(t, BuiltinNameReviewDecide); mustHashStringValue(t, data, "decision") != reviewApproved {
		t.Fatalf("the timeline records the decision as %s", data.Inspect())
	}
	mustRefuse(t, "a second decision", ReviewDecide(r.handle(), stringObj(requestUID), stringObj("rejected"),
		stringObj("on reflection")), "was decided at")
	session = r.session(t)
	decisionNode := schemaNode(t, session, disclosureNodeReviewDecision, "decision.uid",
		mustHashStringValue(t, decided, "uid"))
	if got := edgeTo(t, session, decisionNode.id, disclosureEdgeReviews).get("review.uid"); got != requestUID {
		t.Fatalf("the decision REVIEWS %q", got)
	}
	assertCaseRecordEdges(t, session, decisionNode.id, caseUID, "bob")

	list, rows := reviewRows(t, r.handle())
	if len(rows) != 1 || mustHashIntValue(t, list, "approved") != 1 || mustHashIntValue(t, list, "pending") != 0 ||
		!mustHashBoolValue(t, rows[0], "decided") || mustHashStringValue(t, rows[0], "decided_by") != "bob" ||
		mustHashStringValue(t, rows[0], "decision_uid") != mustHashStringValue(t, decided, "uid") ||
		mustHashStringValue(t, rows[0], "by") != "alice" || mustHashStringValue(t, rows[0], "manifest") != manifest ||
		!mustHashBoolValue(t, rows[0], "manifest_signed") {
		t.Fatalf("review_list gave %s", list.Inspect())
	}

	attached := r.as(t, "alice", "case_owner")
	lifecycle := mustHashArrayValue(t, attached, "lifecycle")
	if len(lifecycle) != 4 {
		t.Fatalf("the lifecycle holds %d events", len(lifecycle))
	}
	for i, want := range []string{"", "", requestUID, requestUID} {
		if got := mustHashStringValue(t, lifecycle[i].(*object.Hash), "review_uid"); got != want {
			t.Errorf("lifecycle event %d names review %q, want %q", i+1, got, want)
		}
	}
}

// A review that asks for changes, or rejects, sends the case back to active.
// The next request is bound to a manifest of the case as it then stands, and
// the one written before the last move is refused.
func TestAReviewThatIsNotApprovedSendsTheCaseBack(t *testing.T) {
	for _, decision := range []string{reviewChangesRequested, reviewRejected} {
		t.Run(decision, func(t *testing.T) {
			r := openReviewRun(t)
			requested, manifest := r.requestCase(t, "a first look")
			r.as(t, "bob", "reviewer")
			decided := mustHash(t, ReviewDecide(r.handle(), stringObj(mustHashStringValue(t, requested, "uid")),
				stringObj(decision), stringObj("the timeline has a gap")))
			if mustHashStringValue(t, decided, "state") != caseStateActive || !mustHashBoolValue(t, decided, "moved") {
				t.Fatalf("%s gave %s", decision, decided.Inspect())
			}
			r.as(t, "alice", "case_owner")
			mustRefuse(t, "the manifest the first request was bound to", ReviewRequest(r.handle(), stringObj("case"),
				stringObj("again"), manifestOption(manifest)), "was written when case IR-LIFE's lifecycle stood at")
			again, _ := r.requestCase(t, "the gap is explained")
			if mustHashIntValue(t, again, "seq") != 2 || mustHashStringValue(t, again, "state") != caseStateInReview {
				t.Fatalf("the second request gave %s", again.Inspect())
			}
			list, _ := reviewRows(t, r.handle())
			if mustHashIntValue(t, list, decision) != 1 || mustHashIntValue(t, list, "pending") != 1 ||
				mustHashIntValue(t, list, "count") != 2 {
				t.Fatalf("review_list gave %s", list.Inspect())
			}
		})
	}
}

// A review of a record or of a redaction version is bound to its digest and
// moves nothing. One request is open at a time for a subject, the one who
// asked cannot decide it, and a subject once decided can be asked about again.
func TestAReviewOfARecordOrARedactionMovesNothing(t *testing.T) {
	r := openReviewRun(t)
	ledger := r.handle()
	raw, err := os.ReadFile(r.recordFile)
	if err != nil {
		t.Fatal(err)
	}
	record := mustHash(t, ReviewRequest(ledger, stringObj(" "+strings.ToUpper(r.recordUID)+" "),
		stringObj("is the pii span right?")))
	if mustHashStringValue(t, record, "subject_kind") != reviewSubjectRecord ||
		mustHashStringValue(t, record, "subject") != r.recordUID || mustHashStringValue(t, record, "subject_hash") != sha256Hex(raw) ||
		mustHashBoolValue(t, record, "moved") || mustHashStringValue(t, record, "state") != caseStateActive ||
		mustHashStringValue(t, record, "manifest") != "" || mustHashBoolValue(t, record, "manifest_signed") {
		t.Fatalf("a review of the record gave %s", record.Inspect())
	}
	version := mustHash(t, ReviewRequest(ledger, stringObj(r.versionUID), stringObj("does counsel see too much?")))
	if mustHashStringValue(t, version, "subject_kind") != reviewSubjectRedaction ||
		mustHashStringValue(t, version, "subject") != r.versionUID ||
		mustHashStringValue(t, version, "subject_hash") != r.partition || mustHashBoolValue(t, version, "moved") ||
		mustHashIntValue(t, version, "seq") != 2 {
		t.Fatalf("a review of the redaction version gave %s", version.Inspect())
	}
	session := r.session(t)
	for _, reviewed := range []struct {
		request   *object.Hash
		key, want string
	}{
		{record, "record.uid", r.recordUID},
		{version, "redaction.uid", r.versionUID},
	} {
		node := schemaNode(t, session, disclosureNodeReviewRequest, "review.uid",
			mustHashStringValue(t, reviewed.request, "uid"))
		if got := edgeTo(t, session, node.id, disclosureEdgeReviews).get(reviewed.key); got != reviewed.want {
			t.Errorf("a review of %s REVIEWS %q", reviewed.want, got)
		}
		assertCaseRecordEdges(t, session, node.id, openCaseUID(t), "alice")
	}
	// Another version is another subject, and is asked about while the first
	// is still open.
	other := mustHash(t, RedactionCommit(ledger, r.record, stringObj("desk"), stringObj("the desk's redaction")))
	mustHash(t, ReviewRequest(ledger, stringObj(mustHashStringValue(t, other, "uid")), stringObj("and the desk's?")))
	mustRefuse(t, "a second open request for the record", ReviewRequest(ledger, stringObj(r.recordUID),
		stringObj("again")), "One request is open at a time")
	mustRefuse(t, "a manifest for a record", ReviewRequest(ledger, stringObj(r.recordUID), stringObj("x"),
		manifestOption("m.json")), "a review of a record is bound to the record itself")
	mustRefuse(t, "a manifest for a redaction version", ReviewRequest(ledger, stringObj(r.versionUID),
		stringObj("x"), manifestOption("")), "a review of a redaction version is bound to the redaction version itself")

	r.as(t, "bob", "reviewer")
	ledger = r.handle()
	decided := mustHash(t, ReviewDecide(ledger, stringObj(mustHashStringValue(t, record, "uid")), stringObj("rejected"),
		stringObj("the span stops short of the address")))
	if mustHashBoolValue(t, decided, "moved") || mustHashStringValue(t, decided, "state") != caseStateActive ||
		mustHashStringValue(t, decided, "from") != caseStateActive || mustHashStringValue(t, decided, "subject_kind") != reviewSubjectRecord {
		t.Fatalf("a decision of the record's review gave %s", decided.Inspect())
	}
	asked := mustHash(t, ReviewRequest(ledger, stringObj(r.recordUID), stringObj("a second opinion")))
	mustRefuse(t, "a decision of one's own request", ReviewDecide(ledger, stringObj(mustHashStringValue(t, asked, "uid")),
		stringObj("approved"), stringObj("x")), "bob asked for this review, and a review is decided by a reviewer "+
		"other than whoever asked for it. A role is asserted")
	mustRefuse(t, "a request the case does not have", ReviewDecide(ledger, stringObj(strings.Repeat("ab", 32)),
		stringObj("approved"), stringObj("x")), "has no review request")
	mustRefuse(t, "a decision this program does not record", ReviewDecide(ledger,
		stringObj(mustHashStringValue(t, version, "uid")), stringObj("maybe"), stringObj("x")), "is not a decision")
	list, rows := reviewRows(t, ledger)
	if mustHashIntValue(t, list, "count") != 4 || mustHashIntValue(t, list, "pending") != 3 ||
		mustHashIntValue(t, list, "rejected") != 1 || mustHashStringValue(t, rows[3], "by") != "bob" ||
		mustHashStringValue(t, rows[0], "decision") != reviewRejected || mustHashStringValue(t, rows[1], "decision") != "" {
		t.Fatalf("review_list gave %s", list.Inspect())
	}
}

// A request binds only what the ledger holds of the case, and a case only as a
// manifest of the case as it stands shows it.
func TestAReviewRequestIsBoundToWhatTheLedgerHolds(t *testing.T) {
	r := openReviewRun(t)
	ledger := r.handle()
	caseUID := strings.ToLower(openCaseUID(t))
	for _, bad := range []struct{ name, subject, want string }{
		{"a word", "exhibit", "is not something a review is of"},
		{"a uid of a length nothing has", strings.Repeat("a", 40), "is not something a review is of"},
		{"not hex", strings.Repeat("g", 32), "is not something a review is of"},
		{"a record the ledger does not hold", strings.Repeat("0", 32), "the ledger holds no record"},
		{"a version the ledger does not hold", strings.Repeat("0", 64), "the ledger holds no redaction version"},
	} {
		mustRefuse(t, bad.name, ReviewRequest(ledger, stringObj(bad.subject), stringObj("x")), bad.want)
	}
	mustRefuse(t, "a case with no manifest", ReviewRequest(ledger, stringObj("case"), stringObj("x")),
		"a case is reviewed as a manifest shows it")
	mustRefuse(t, "a case with an empty manifest", ReviewRequest(ledger, stringObj("case"), stringObj("x"),
		manifestOption("  ")), "a case is reviewed as a manifest shows it")
	mustRefuse(t, "a manifest that is not there", ReviewRequest(ledger, stringObj("case"), stringObj("x"),
		manifestOption(filepath.Join(t.TempDir(), "none.json"))), "review_request: ")

	manifest := writeManifest(t)
	for _, bad := range []struct {
		name   string
		reseal bool
		edit   func(map[string]any)
		want   string
	}{
		{"a manifest changed after it was written", false, func(d map[string]any) {
			d["case"].(map[string]any)["examiner"] = "mallory"
		}, "does not hash to its seal"},
		{"a manifest whose signature does not hold", false, func(d map[string]any) {
			seal := d["seal"].(map[string]any)
			signature := []byte(seal["signature"].(string))
			if signature[0] == '0' {
				signature[0] = '1'
			} else {
				signature[0] = '0'
			}
			seal["signature"] = string(signature)
		}, "its signature does not hold"},
		{"another case's manifest", true, func(d map[string]any) {
			d["case"].(map[string]any)["id"] = "IR-OTHER"
		}, "is case \"IR-OTHER\"'s"},
		{"a manifest written with the case attached to no ledger", true, func(d map[string]any) {
			d["ledger_state"] = map[string]any{"attached": false}
		}, "attached to no ledger"},
		{"a manifest of the case as it was", true, func(d map[string]any) {
			d["ledger_state"].(map[string]any)["lifecycle_head"] = strings.Repeat("ab", 32)
		}, "stood at " + strings.Repeat("ab", 32)},
	} {
		mustRefuse(t, bad.name, ReviewRequest(ledger, stringObj("case"), stringObj("x"),
			manifestOption(rewriteManifest(t, manifest, bad.reseal, bad.edit))), bad.want)
	}

	other := strings.Repeat("0b", 16)
	stray := strings.Repeat("cd", 32)
	forgeCaseRecord(t, r.session(t), func(w *caseWriter) error {
		for _, forged := range []struct {
			label store.NodeType
			props map[string]string
		}{
			{disclosureNodeRecord, map[string]string{"record.uid": strings.Repeat("1", 32), "record.case_uid": other}},
			{disclosureNodeRedactionVersion, map[string]string{"redaction.uid": strings.Repeat("2", 64),
				"redaction.case_uid": other}},
			{disclosureNodeRedactionVersion, map[string]string{"redaction.uid": stray, "redaction.case_uid": caseUID,
				"redaction.line": r.recordUID, "redaction.view_canonical": "counsel", "redaction.chain": "elsewhere"}},
		} {
			if _, err := w.tx.node(forged.label, forged.props); err != nil {
				return err
			}
		}
		return nil
	})
	mustRefuse(t, "another case's record", ReviewRequest(ledger, stringObj(strings.Repeat("1", 32)), stringObj("x")),
		"is case "+other+"'s")
	mustRefuse(t, "another case's redaction version", ReviewRequest(ledger, stringObj(strings.Repeat("2", 64)),
		stringObj("x")), "is case "+other+"'s")
	mustRefuse(t, "a redaction version outside its chain", ReviewRequest(ledger, stringObj(stray), stringObj("x")),
		"is not in the chain its line and view name")

	unsigned := writeManifest(t, makeHashObject(map[string]object.Object{"sign": boolObj(false)}))
	accepted := mustHash(t, ReviewRequest(ledger, stringObj("case"), stringObj("x"), manifestOption(unsigned)))
	if mustHashBoolValue(t, accepted, "manifest_signed") ||
		mustHashStringValue(t, accepted, "subject_hash") != mustHashStringValue(t, verifyManifest(t, unsigned), "manifest_hash") {
		t.Fatalf("a review bound to an unsigned manifest gave %s", accepted.Inspect())
	}
	mustRefuse(t, "a case already in review", ReviewRequest(ledger, stringObj("case"), stringObj("again"),
		manifestOption(writeManifest(t))), "is in_review, and a case is submitted for review when it is active")
}

// A decision moves on only the review its request put the case in: a case
// whose lifecycle left that review without a decision -- which this program
// never writes -- is not moved by one, and a disposed case takes no review.
func TestADecisionMovesOnlyTheReviewItsRequestBegan(t *testing.T) {
	r := openReviewRun(t)
	requested, _ := r.requestCase(t, "first")
	record := mustHash(t, ReviewRequest(r.handle(), stringObj(r.recordUID), stringObj("the record too")))
	caseUID := openCaseUID(t)
	forceLifecycle(t, r.session(t), caseUID, caseStateActive)
	r.as(t, "bob", "reviewer")
	decide := func() object.Object {
		return ReviewDecide(r.handle(), stringObj(mustHashStringValue(t, requested, "uid")), stringObj("approved"),
			stringObj("x"))
	}
	mustRefuse(t, "a decision of a review the case left", decide(), "is active, not in review under request")
	forceLifecycle(t, r.session(t), caseUID, caseStateInReview)
	mustRefuse(t, "a decision of a review the case is not in", decide(), "is in_review, not in review under request")

	forceLifecycle(t, r.session(t), caseUID, caseStateConcluded, caseStateRetained, caseStateDisposed)
	mustRefuse(t, "a decision once disposed", ReviewDecide(r.handle(), stringObj(mustHashStringValue(t, record, "uid")),
		stringObj("approved"), stringObj("x")), "takes no request for a review, or decision of one")
	mustRefuse(t, "a request once disposed", ReviewRequest(r.handle(), stringObj(r.versionUID), stringObj("x")),
		"takes no request for a review, or decision of one")
}

// The keys every reader looks the review and retention labels up by are
// indexed. They are named here, not read from disclosureKeys, so a key
// dropped from that table fails this test instead of quietly leaving it.
func TestEveryReviewAndRetentionLabelIsFoundByEachOfItsLookupKeys(t *testing.T) {
	r := openReviewRun(t)
	requested := mustHash(t, ReviewRequest(r.handle(), stringObj(r.recordUID), stringObj("look")))
	hold := mustHash(t, RetentionHold(r.handle(), stringObj("a claim is threatened")))
	mustHash(t, RetentionRelease(r.handle(), stringObj(mustHashStringValue(t, hold, "uid")), stringObj("withdrawn")))
	r.as(t, "bob", "reviewer")
	mustHash(t, ReviewDecide(r.handle(), stringObj(mustHashStringValue(t, requested, "uid")), stringObj("approved"),
		stringObj("x")))
	g := r.session(t).graph
	for _, lookup := range []struct {
		label store.NodeType
		keys  []string
	}{
		{disclosureNodeReviewRequest, []string{"review.uid", "review.chain"}},
		{disclosureNodeReviewDecision, []string{"decision.uid", "decision.chain"}},
		{disclosureNodeRetention, []string{"retention.uid", "retention.chain"}},
	} {
		nodes, err := disclosureAll(g, lookup.label)
		if err != nil || len(nodes) == 0 {
			t.Fatalf("no %s node was written: %v", lookup.label.String(), err)
		}
		for _, node := range nodes {
			for _, key := range lookup.keys {
				ids, err := g.NodesByProperty(key, []byte(node.get(key)))
				if err != nil || !slices.Contains(ids, node.id) {
					t.Errorf("%s node %d is not found by %s = %q", lookup.label.String(), node.id, key, node.get(key))
				}
			}
		}
	}
}

// A chain of reviews this program did not write is refused by every reader
// rather than resolved.
func TestAReviewChainThisProgramDidNotWriteIsRefused(t *testing.T) {
	requestLike := func(w *caseWriter, extra map[string]string) map[string]string {
		props := map[string]string{"review.case_uid": w.caseUID, "review.case_id": w.caseID,
			"review.subject_kind": reviewSubjectRecord, "review.subject": "x", "review.note": "forged",
			"review.by": "mallory"}
		maps.Copy(props, extra)
		return props
	}
	decisionLike := func(w *caseWriter, request caseChainEvent, extra map[string]string) map[string]string {
		props := map[string]string{"decision.request_uid": request.uid, "decision.case_uid": w.caseUID,
			"decision.decision": reviewApproved, "decision.by": "mallory"}
		maps.Copy(props, extra)
		return props
	}
	appendRequest := func(extra map[string]string) func(w *caseWriter, request caseChainEvent) error {
		return func(w *caseWriter, request caseChainEvent) error {
			_, _, err := w.tx.chainAppend(reviewRequestChain, w.caseUID, &request, requestLike(w, extra))
			return err
		}
	}
	decide := func(extra map[string]string) func(w *caseWriter, request caseChainEvent) error {
		return func(w *caseWriter, request caseChainEvent) error {
			_, _, err := w.tx.chainAppend(reviewDecisionChain, request.uid, nil, decisionLike(w, request, extra))
			return err
		}
	}
	for _, tc := range []struct {
		name  string
		forge func(w *caseWriter, request caseChainEvent) error
		want  string
	}{
		{"a request naming another case", appendRequest(map[string]string{"review.case_uid": "another"}),
			"names case another"},
		{"a request of what this program does not review", appendRequest(map[string]string{
			"review.subject_kind": "exhibit"}), "which this program does not review"},
		{"a review of another case", appendRequest(map[string]string{"review.subject_kind": reviewSubjectCase,
			"review.subject": "another"}), "asks for a review of case another"},
		{"a decision of another request", decide(map[string]string{"decision.request_uid": "another"}),
			"answers request another"},
		{"a decision of another case", decide(map[string]string{"decision.case_uid": "another"}),
			"of case another, in the chain of request"},
		{"a decision this program does not record", decide(map[string]string{"decision.decision": "maybe"}),
			"which is not a decision this program records"},
		{"two decisions of one request", func(w *caseWriter, request caseChainEvent) error {
			_, first, err := w.tx.chainAppend(reviewDecisionChain, request.uid, nil, decisionLike(w, request, nil))
			if err == nil {
				_, _, err = w.tx.chainAppend(reviewDecisionChain, request.uid, &first, decisionLike(w, request,
					map[string]string{"decision.decision": reviewRejected}))
			}
			return err
		}, "is decided 2 times"},
		{"two first decisions", func(w *caseWriter, request caseChainEvent) error {
			if err := decide(nil)(w, request); err != nil {
				return err
			}
			return decide(map[string]string{"decision.decision": reviewRejected})(w, request)
		}, "two decision events after the start of the chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := openReviewRun(t)
			mustHash(t, ReviewRequest(r.handle(), stringObj(r.recordUID), stringObj("look")))
			disclosureLedgerMu.Lock()
			reviews, err := reviewsRead(r.session(t).graph, openCaseUID(t))
			disclosureLedgerMu.Unlock()
			if err != nil || len(reviews) != 1 {
				t.Fatal(err, len(reviews))
			}
			forgeCaseRecord(t, r.session(t), func(w *caseWriter) error { return tc.forge(w, reviews[0].request) })
			mustRefuse(t, "review_list", ReviewList(r.handle()), tc.want)
			mustRefuse(t, "review_request", ReviewRequest(r.handle(), stringObj(r.versionUID), stringObj("x")), tc.want)
			r.as(t, "bob", "reviewer")
			mustRefuse(t, "review_decide", ReviewDecide(r.handle(), stringObj(reviews[0].request.uid),
				stringObj("approved"), stringObj("x")), tc.want)
		})
	}
}

func TestEveryReviewAndRetentionBuiltinReturnsTheDeclaredFields(t *testing.T) {
	r := openReviewRun(t)
	ledger := r.handle()
	type call struct {
		name   string
		result object.Object
	}
	requested, _ := r.requestCase(t, "for review")
	calls := []call{
		{BuiltinNameReviewRequest, ReviewRequest(ledger, stringObj(r.recordUID), stringObj("look"))},
		{BuiltinNameReviewList, ReviewList(ledger)},
	}
	hold := mustHash(t, RetentionHold(ledger, stringObj("a claim"), makeHashObject(map[string]object.Object{
		"authority": stringObj("Legal department")})))
	calls = append(calls,
		call{BuiltinNameRetentionHold, RetentionHold(ledger, stringObj("another claim"))},
		call{BuiltinNameRetentionRelease, RetentionRelease(ledger, stringObj(mustHashStringValue(t, hold, "uid")),
			stringObj("settled"))},
	)
	for _, c := range calls {
		payload, errObj := unwrapPairNoFatal(c.result)
		if errObj != nil {
			t.Fatalf("%s: %s", c.name, errObj.Message)
		}
		assertLedgerDeclaredFields(t, c.name, payload)
	}
	r.as(t, "bob", "reviewer")
	ledger = r.handle()
	calls = []call{{BuiltinNameReviewDecide, ReviewDecide(ledger, stringObj(mustHashStringValue(t, requested, "uid")),
		stringObj("approved"), stringObj("x"))}}
	calls = append(calls,
		call{BuiltinNameRetentionSet, RetentionSet(ledger, stringObj("2033-09-28"), stringObj("seven years"))},
		call{BuiltinNameRetentionList, RetentionList(ledger)},
	)
	for _, c := range calls {
		payload, errObj := unwrapPairNoFatal(c.result)
		if errObj != nil {
			t.Fatalf("%s: %s", c.name, errObj.Message)
		}
		assertLedgerDeclaredFields(t, c.name, payload)
	}
}
