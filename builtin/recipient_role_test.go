package builtin

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// A disclosure is issued against the role the ledger assigns its recipient. A
// recipient nobody assigned -- names are exact, so "partner" is not "Partner"
// -- one whose role was ended, one whose role has no bundle, and one whose
// bundle holds nothing or not this view are all refused, before any key
// material is derived and before any passphrase is asked for.
func TestADisclosureIsIssuedAgainstTheRecipientsRole(t *testing.T) {
	f := newDiscloseFixture(t)
	mustHash(t, RoleDefine(stringObj("external_partner"), viewArray("regulator")))
	mustHash(t, RoleDefine(stringObj("restricted_viewer"), viewArray()))
	ledger := intObj(f.ledger)
	assign := func(recipient, role string) {
		mustHash(t, RoleAssign(ledger, stringObj(recipient), stringObj(role), stringObj("named for the test")))
	}
	assign("Partner", "external_partner")
	assign("Viewer", "restricted_viewer")
	assign("Reviewer", "reviewer")
	assign("Former", "legal")
	assign("Former", "none")

	issued, prompts := countDisclosureWork(t)
	for _, c := range []struct{ recipient, want string }{
		{"Nobody", `assigns "Nobody" no recipient role`},
		{"partner", `assigns "partner" no recipient role`},
		{"Former", "was ended"},
		{"Reviewer", "no bundle for reviewer"},
		{"Viewer", "to hold no view"},
		{"Partner", `holds "regulator", not "counsel"`},
	} {
		result := DiscloseToPassphrase(ledger, f.record, stringObj("counsel"), stringObj(c.recipient))
		mustRefuse(t, c.recipient, result, c.want)
		mustRefuse(t, c.recipient, result, "is not access control")
	}
	if *issued != 0 || *prompts != 0 {
		t.Fatalf("refused disclosures derived %d grants and asked %d passphrases first", *issued, *prompts)
	}

	granted := mustHash(t, DiscloseToPassphrase(ledger, f.record, stringObj("regulator"), stringObj("Partner")))
	if mustHashStringValue(t, granted, "recipient_role") != "external_partner" ||
		mustHashBoolValue(t, granted, "role_authenticated") || *issued != 1 {
		t.Fatalf("the disclosure to the partner gave %s", granted.Inspect())
	}

	// The ledger holds the role, the assignment and the bundle beside the
	// disclosure, and the bundle's node names the one view it holds.
	session, _ := ledgerGet(f.ledger)
	g := session.graph
	node, found, err := disclosureFind(g, disclosureNodeDisclosure, "disclosure.uid",
		mustHashStringValue(t, granted, "disclosure_uid"))
	if err != nil || !found {
		t.Fatalf("the disclosure is not in the ledger: %v", err)
	}
	partner, _, err := recipientAssignmentOf(g, openCaseUID(t), "Partner")
	if err != nil {
		t.Fatal(err)
	}
	var fp string
	for _, row := range mustHashArrayValue(t, mustHash(t, RoleList()), "bundles") {
		if mustHashStringValue(t, row.(*object.Hash), "role") == "external_partner" {
			fp = mustHashStringValue(t, row.(*object.Hash), "fingerprint")
		}
	}
	if node.get("disclosure.role") != "external_partner" || node.get("disclosure.assignment_uid") != partner.head.uid ||
		node.get("disclosure.role_bundle_fp") != fp || fp == "" {
		t.Fatalf("the Disclosure node records role %q, assignment %q and bundle %q", node.get("disclosure.role"),
			node.get("disclosure.assignment_uid"), node.get("disclosure.role_bundle_fp"))
	}
	under, err := session.store.EdgesOf(node.id, store.DirectionOutbound, []store.EdgeType{disclosureEdgeIssuedUnder})
	if err != nil || len(under) != 1 {
		t.Fatalf("the disclosure has %d ISSUED_UNDER edges: %v", len(under), err)
	}
	bundleNode, err := g.GetNode(under[0].Dst)
	if err != nil || !bundleNode.HasLabel(disclosureNodeRoleBundle) {
		t.Fatalf("the disclosure is issued under node %d, which is not a role bundle: %v", under[0].Dst, err)
	}
	bundled, err := session.store.EdgesOf(bundleNode.ID, store.DirectionOutbound, []store.EdgeType{disclosureEdgeBundles})
	if err != nil || len(bundled) != 1 {
		t.Fatalf("the external_partner bundle BUNDLES %d views: %v", len(bundled), err)
	}
	view, _ := g.GetNode(bundled[0].Dst)
	if decoded, err := disclosureDecode(view); err != nil || decoded.get("view.label") != "regulator" {
		t.Fatalf("the bundle's view node reads %v, %v", decoded.props, err)
	}
	rows := mustHashArrayValue(t, mustHash(t, DiscloseHistory(ledger)), "disclosures")
	if len(rows) != 1 || mustHashStringValue(t, rows[0].(*object.Hash), "recipient_role") != "external_partner" ||
		mustHashIntValue(t, rows[0].(*object.Hash), "redaction_version") != 1 ||
		mustHashStringValue(t, rows[0].(*object.Hash), "redaction_uid") != mustHashStringValue(t, granted, "redaction_uid") {
		t.Fatalf("disclose_history reports %v", rows)
	}
}

// The assignment is read again under the ledger lock before the write, so a
// role changed while the disclosure was being prepared -- by a spawned task,
// between the preflight and the write -- stops it, and nothing is recorded.
func TestTheRecipientsRoleIsAskedAgainBeforeTheWrite(t *testing.T) {
	f := newDiscloseFixture(t)
	f.assign(t, "Counsel")
	previous := disclosureIssueGrant
	disclosureIssueGrant = func(keys *security.RecordKeys, descriptors []security.SegmentAAD) (*security.RecordGrant, error) {
		mustHash(t, RoleAssign(intObj(f.ledger), stringObj("Counsel"), stringObj("reviewer"),
			stringObj("moved while the grant was being issued")))
		return previous(keys, descriptors)
	}
	t.Cleanup(func() { disclosureIssueGrant = previous })
	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	mustRefuse(t, "a disclosure whose recipient's role changed", DiscloseToPassphrase(intObj(f.ledger), f.record,
		stringObj("counsel"), stringObj("Counsel")), "changed while this disclosure was prepared")
	if got := mustHashIntValue(t, mustHash(t, DiscloseHistory(intObj(f.ledger))), "count"); got != 0 {
		t.Fatalf("the ledger records %d disclosures", got)
	}
}

// A bundle is for a recipient role, and names views the case declared, each
// once. An empty one is legal and says so.
func TestRoleDefineTakesARecipientRoleAndDeclaredViews(t *testing.T) {
	openTestCase(t, "IR-ROLES", "examiner")
	mustRefuse(t, "a bundle with no case key", RoleDefine(stringObj("legal"), viewArray()), "no case key is open")
	unkeyed, _ := openTestLedger(t, "examiner")
	mustRefuse(t, "an assignment with no case key", RoleAssign(intObj(unkeyed), stringObj("Counsel"), stringObj("legal"),
		stringObj("x")), "no case key is open")

	recordTestCase(t)
	mustHash(t, ClassDefine(stringObj("pii")))
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open", "pii")))
	mustHash(t, ViewDefine(stringObj("desk"), viewArray("open", "restricted")))
	for _, c := range []struct {
		name   string
		result object.Object
		want   string
	}{
		{"an examiner role", RoleDefine(stringObj("investigator"), viewArray("counsel")), "is an examiner role"},
		{"no role at all", RoleDefine(stringObj("counsel"), viewArray("counsel")), "is not a role"},
		{"the word that ends an assignment", RoleDefine(stringObj("none"), viewArray()), "is not a role"},
		{"an undeclared view", RoleDefine(stringObj("legal"), viewArray("counsel", "press")),
			`entry 2 names "press", which is not a declared view`},
		{"a repeated view", RoleDefine(stringObj("legal"), viewArray("counsel", " Counsel ")), "already holds"},
		{"a view that is not a string", RoleDefine(stringObj("legal"), recordArray(intObj(1))), "must be STRING"},
	} {
		mustRefuse(t, c.name, c.result, c.want)
	}

	legal := mustHash(t, RoleDefine(stringObj(" Legal "), viewArray("desk", "counsel"),
		makeHashObject(map[string]object.Object{"description": stringObj("counsel for either side")})))
	views := mustHashValue(t, legal, "views").Inspect()
	classes := mustHashValue(t, legal, "classes").Inspect()
	if mustHashStringValue(t, legal, "role") != "legal" || views != "[desk, counsel]" ||
		classes != "[open, pii, restricted]" || mustHashBoolValue(t, legal, "grants_nothing") ||
		mustHashBoolValue(t, legal, "in_ledger") || mustHashBoolValue(t, legal, "already_defined") ||
		mustHashStringValue(t, legal, "description") != "counsel for either side" {
		t.Fatalf("role_define gave %s", legal.Inspect())
	}
	mustRefuse(t, "a second bundle for legal", RoleDefine(stringObj("legal"), viewArray("counsel")),
		"already has a bundle")
	nothing := mustHash(t, RoleDefine(stringObj("restricted_viewer"), viewArray()))
	if !mustHashBoolValue(t, nothing, "grants_nothing") || mustHashIntValue(t, nothing, "view_count") != 0 {
		t.Fatalf("an empty bundle gave %s", nothing.Inspect())
	}

	// The fingerprint names the role and what its views grant, in no order.
	custodyStore.RLock()
	counsel, _ := viewByCanonicalLocked(custodyStore.session, "counsel")
	desk, _ := viewByCanonicalLocked(custodyStore.session, "desk")
	custodyStore.RUnlock()
	role, _ := roleNamed("legal")
	other, _ := roleNamed("external_partner")
	a, b, c := caseBundle{Role: role}, caseBundle{Role: role}, caseBundle{Role: other}
	a.add(counsel)
	a.add(desk)
	b.add(desk)
	b.add(counsel)
	c.add(counsel)
	c.add(desk)
	if a.fingerprint() != b.fingerprint() || a.fingerprint() == c.fingerprint() ||
		a.fingerprint() != mustHashStringValue(t, legal, "fingerprint") {
		t.Fatal("a bundle's fingerprint follows the order of its views, or not its role")
	}

	classification := manifestSection(t, mustHash(t, CaseManifest()), "classification")
	if mustHashIntValue(t, classification, "role_bundle_count") != 2 {
		t.Fatalf("the manifest carries %s", classification.Inspect())
	}
}

// Each recipient's assignments are a chain of their own: assigned, moved,
// ended, assigned again. Names are exact, and none of it is an examiner's.
func TestRoleAssignKeepsEachRecipientsChain(t *testing.T) {
	f := newDiscloseFixture(t)
	ledger := intObj(f.ledger)
	assign := func(recipient, role, reason string) *object.Hash {
		return mustHash(t, RoleAssign(ledger, stringObj(recipient), stringObj(role), stringObj(reason)))
	}
	first := assign("Counsel", "Legal", "instructed")
	if mustHashIntValue(t, first, "seq") != 1 || mustHashStringValue(t, first, "previous_role") != "none" ||
		mustHashStringValue(t, first, "role") != "legal" || !mustHashBoolValue(t, first, "in_force") ||
		!mustHashBoolValue(t, first, "bundled") || mustHashValue(t, first, "grants").Inspect() != "[counsel, regulator]" ||
		mustHashBoolValue(t, first, "role_authenticated") {
		t.Fatalf("the first assignment gave %s", first.Inspect())
	}
	moved := assign("Counsel", "external_partner", "now advising the partner")
	if mustHashIntValue(t, moved, "seq") != 2 || mustHashStringValue(t, moved, "previous_role") != "legal" ||
		mustHashBoolValue(t, moved, "bundled") || mustHashValue(t, moved, "grants").Inspect() != "[]" {
		t.Fatalf("the move gave %s", moved.Inspect())
	}
	ended := assign("Counsel", "none", "the instruction ended")
	if mustHashIntValue(t, ended, "seq") != 3 || mustHashBoolValue(t, ended, "in_force") {
		t.Fatalf("the end gave %s", ended.Inspect())
	}
	for _, c := range []struct {
		name   string
		result object.Object
		want   string
	}{
		{"an end with nothing in force", RoleAssign(ledger, stringObj("Counsel"), stringObj("none"), stringObj("x")),
			"holds no recipient role"},
		{"an examiner role", RoleAssign(ledger, stringObj("Counsel"), stringObj("investigator"), stringObj("x")),
			"is an examiner role"},
		{"no role at all", RoleAssign(ledger, stringObj("Counsel"), stringObj("friend"), stringObj("x")),
			"is not a role"},
		{"no reason", RoleAssign(ledger, stringObj("Counsel"), stringObj("legal"), stringObj("  ")),
			"must not be empty"},
	} {
		mustRefuse(t, c.name, c.result, c.want)
	}
	assign("Counsel", "legal", "instructed again")
	mustRefuse(t, "the same role again", RoleAssign(ledger, stringObj("Counsel"), stringObj("legal"),
		stringObj("x")), "already assigned as legal")
	if lower := assign("counsel", "legal", "a different person"); mustHashIntValue(t, lower, "seq") != 1 {
		t.Fatalf("counsel and Counsel share a chain: %s", lower.Inspect())
	}

	list := mustHash(t, RoleList(ledger))
	if mustHashIntValue(t, list, "recipient_count") != 2 || mustHashIntValue(t, list, "in_force") != 2 {
		t.Fatalf("role_list gave %s", list.Inspect())
	}
	session, _ := ledgerGet(f.ledger)
	if examiners, err := caseAssignmentsRead(session.graph, openCaseUID(t)); err != nil || len(examiners) != 0 {
		t.Fatalf("the examiner readers see %d assignments: %v", len(examiners), err)
	}
}

// forgeAssignment appends an event to a recipient's chain the way chainAppend
// does: well formed, hash-linked, and not one this program would write.
func forgeAssignment(t *testing.T, ledger int64, recipient string, props map[string]string) {
	t.Helper()
	session, _ := ledgerGet(ledger)
	caseUID := openCaseUID(t)
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	current, _, err := recipientAssignmentOf(session.graph, caseUID, recipient)
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]string{"assignment.case_uid": caseUID, "assignment.subject": recipient}
	maps.Copy(all, props)
	w, err := caseBeginWrite(session, caseUID, "IR-REC", custodyNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.tx.chainAppend(caseAssignmentChain, recipientAssignmentChainKey(caseUID, recipient),
		&current.head, all); err != nil {
		t.Fatal(err)
	}
	if err := w.tx.commit(); err != nil {
		t.Fatal(err)
	}
}

// One chain says one thing about one person. A recipient's chain holding an
// examiner's event, or an event of another case, is refused by every reader,
// and an assignment to a role that is not a recipient's grants nothing.
func TestARecipientChainThisProgramDidNotWriteIsRefused(t *testing.T) {
	for _, c := range []struct {
		name  string
		props map[string]string
		want  string
		list  bool
	}{
		{"an examiner's event", map[string]string{"assignment.side": caseAssignmentExaminer,
			"assignment.role": "investigator"}, "is on the examiner side, in a chain of recipient assignments", true},
		{"another case's event", map[string]string{"assignment.side": caseAssignmentRecipient,
			"assignment.role": "legal", "assignment.case_uid": strings.Repeat("f", 32)}, "names case ffff", true},
		{"an examiner role", map[string]string{"assignment.side": caseAssignmentRecipient,
			"assignment.role": "investigator"}, `as "investigator", which is not a recipient role`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newDiscloseFixture(t)
			f.assign(t, "Counsel")
			forgeAssignment(t, f.ledger, "Counsel", c.props)
			if c.list {
				mustRefuse(t, "role_list", RoleList(intObj(f.ledger)), c.want)
			}
			purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
			mustRefuse(t, "a disclosure", DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"),
				stringObj("Counsel")), c.want)
		})
	}
}

// role_list answers with the same keys whether or not a case is open, and
// with the ledger alone lists every case's recipients.
func TestRoleListReadsBundlesAndRecipients(t *testing.T) {
	resetCustodyForTesting()
	closed := mustHash(t, RoleList())
	if mustHashBoolValue(t, closed, "open") || mustHashIntValue(t, closed, "count") != 0 ||
		mustHashIntValue(t, closed, "recipient_count") != 0 {
		t.Fatalf("role_list with no case gave %s", closed.Inspect())
	}
	f := newDiscloseFixture(t)
	f.assign(t, "Counsel")
	mustHash(t, RoleAssign(intObj(f.ledger), stringObj("Former"), stringObj("legal"), stringObj("x")))
	mustHash(t, RoleAssign(intObj(f.ledger), stringObj("Former"), stringObj("none"), stringObj("y")))
	list := mustHash(t, RoleList(intObj(f.ledger)))
	rows := mustHashArrayValue(t, list, "recipients")
	if mustHashIntValue(t, list, "count") != 1 || len(rows) != 2 || mustHashIntValue(t, list, "in_force") != 1 ||
		mustHashStringValue(t, list, "ledger") != f.ledgerDir {
		t.Fatalf("role_list gave %s", list.Inspect())
	}
	counsel, former := rows[0].(*object.Hash), rows[1].(*object.Hash)
	if mustHashStringValue(t, counsel, "recipient") != "Counsel" || !mustHashBoolValue(t, counsel, "bundled") ||
		mustHashValue(t, counsel, "grants").Inspect() != "[counsel, regulator]" ||
		mustHashStringValue(t, former, "role") != "none" || mustHashBoolValue(t, former, "in_force") {
		t.Fatalf("role_list's recipients are %v", rows)
	}

	firstUID := openCaseUID(t)
	LedgerClose(intObj(f.ledger))

	// A second case, under a key of its own, in the same ledger: its
	// role_list is its own recipients and not the first case's.
	recordTestCase(t)
	secondUID := openCaseUID(t)
	opened, errObj := ledgerOpenAs(t, f.ledgerDir, "examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	second := intObj(mustHashIntValue(t, opened, "handle"))
	mustHash(t, RoleAssign(second, stringObj("Other"), stringObj("legal"), stringObj("the second case's counsel")))
	own := mustHashArrayValue(t, mustHash(t, RoleList(second)), "recipients")
	if len(own) != 1 || mustHashStringValue(t, own[0].(*object.Hash), "recipient") != "Other" ||
		mustHashStringValue(t, own[0].(*object.Hash), "case_uid") != secondUID {
		t.Fatalf("the second case's role_list is %v", own)
	}
	LedgerClose(second)
	resetCustodyForTesting()

	// With the ledger alone, an auditor reads every case's.
	opened, errObj = ledgerOpenAs(t, f.ledgerDir, "auditor", "auditor")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	audited := mustHash(t, RoleList(intObj(mustHashIntValue(t, opened, "handle"))))
	byCase := map[string]int{}
	for _, row := range mustHashArrayValue(t, audited, "recipients") {
		byCase[mustHashStringValue(t, row.(*object.Hash), "case_uid")]++
		if mustHashBoolValue(t, row.(*object.Hash), "bundled") {
			t.Errorf("an auditor with no case open was told a role is bundled: %s", row.Inspect())
		}
	}
	if mustHashBoolValue(t, audited, "open") || byCase[firstUID] != 2 || byCase[secondUID] != 1 {
		t.Fatalf("an auditor's role_list gave %s", audited.Inspect())
	}
}

// A bundle defined while the case is attached is in the ledger, and a later
// attach reads it back: the same bundle again is answered, another refused.
func TestABundleIsReadBackByALaterAttach(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustHash(t, ClassDefine(stringObj("open")))
	mustHash(t, ClassDefine(stringObj("pii")))
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open", "pii")))
	defined := mustHash(t, RoleDefine(stringObj("legal"), viewArray("counsel")))
	if !mustHashBoolValue(t, defined, "in_ledger") {
		t.Fatalf("a bundle defined while attached gave %s", defined.Inspect())
	}

	run = run.next(t, "examiner", "case_owner")
	again := run.attach(t)
	if mustHashIntValue(t, again, "bundles_read") != 1 {
		t.Fatalf("the later attach gave %s", again.Inspect())
	}
	bundles := mustHashArrayValue(t, mustHash(t, RoleList()), "bundles")
	if len(bundles) != 1 || mustHashStringValue(t, bundles[0].(*object.Hash), "source") != "ledger" ||
		mustHashStringValue(t, bundles[0].(*object.Hash), "fingerprint") != mustHashStringValue(t, defined, "fingerprint") {
		t.Fatalf("role_list after the attach is %v", bundles)
	}
	if same := mustHash(t, RoleDefine(stringObj("legal"), viewArray("counsel"))); !mustHashBoolValue(t, same, "already_defined") {
		t.Fatalf("defining the ledger's bundle again gave %s", same.Inspect())
	}
	mustRefuse(t, "a bundle the ledger defines, holding something else", RoleDefine(stringObj("legal"),
		viewArray()), "written once")
	state := manifestSection(t, mustHash(t, CaseManifest()), "ledger_state")
	if mustHashIntValue(t, state, "bundles_read") != 1 {
		t.Fatalf("the manifest's ledger_state is %s", state.Inspect())
	}
}

// Each state refuses what it says: in review no bundle is defined and no
// redaction version committed, a recipient may still be assigned, and a
// disposed case assigns nobody.
func TestTheCaseStateRefusesBundlesVersionsAndAssignments(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustHash(t, ClassDefine(stringObj("open")))
	mustHash(t, ClassDefine(stringObj("pii")))
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open", "pii")))
	source, dest, _ := recordFixture(t)
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(
		mustHash(t, RecordClassifyRange(intObj(10), intObj(20), stringObj("pii")))), recordSealOpts(nil)))
	record := mustHashValue(t, mustHash(t, RecordOpen(stringObj(dest))), "handle")
	t.Cleanup(func() { RecordClose(record) })
	ledger := intObj(run.ledger)

	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateActive, caseStateInReview)
	mustRefuse(t, "a bundle in review", RoleDefine(stringObj("legal"), viewArray("counsel")), "takes no definition")
	mustRefuse(t, "a redaction version in review", RedactionCommit(ledger, record, stringObj("counsel"),
		stringObj("x")), "takes no commitment of a redaction version")
	mustHash(t, RoleAssign(ledger, stringObj("Counsel"), stringObj("legal"), stringObj("instructed")))

	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateConcluded)
	mustHash(t, RedactionCommit(ledger, record, stringObj("counsel"), stringObj("the redaction for release")))

	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateRetained, caseStateDisposed)
	mustRefuse(t, "an assignment once disposed", RoleAssign(ledger, stringObj("Counsel"), stringObj("none"),
		stringObj("x")), "takes no assignment of a role")
	mustRefuse(t, "a redaction version once disposed", RedactionCommit(ledger, record, stringObj("counsel"),
		stringObj("x")), "takes no commitment of a redaction version")
}

// The keys every reader looks these labels up by are indexed. They are named
// here, not read from disclosureKeys, so that a key dropped from that table
// fails this test instead of quietly leaving it.
func TestEveryRoleAndRedactionLabelIsFoundByEachOfItsLookupKeys(t *testing.T) {
	f := newDiscloseFixture(t)
	f.issue(t, "counsel", "Counsel")
	session, _ := ledgerGet(f.ledger)
	g := session.graph
	for _, lookup := range []struct {
		label store.NodeType
		keys  []string
	}{
		{disclosureNodeRoleBundle, []string{"bundle.fp"}},
		{disclosureNodeAssignment, []string{"assignment.uid", "assignment.chain", "assignment.case_uid"}},
		{disclosureNodeRedactionVersion, []string{"redaction.uid", "redaction.chain", "redaction.line"}},
		{disclosureNodeRecipient, []string{"recipient.fp"}},
		{disclosureNodeDisclosure, []string{"disclosure.uid", "disclosure.record_uid", "disclosure.recipient_fp"}},
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

func TestEveryRoleAndRedactionBuiltinReturnsTheDeclaredFields(t *testing.T) {
	f := newDiscloseFixture(t)
	ledger := intObj(f.ledger)
	type call struct {
		name   string
		result object.Object
	}
	calls := []call{
		{BuiltinNameRoleDefine, RoleDefine(stringObj("external_partner"), viewArray("regulator"))},
		{BuiltinNameRoleAssign, RoleAssign(ledger, stringObj("Partner"), stringObj("external_partner"), stringObj("x"))},
		{BuiltinNameRoleList, RoleList()},
		{BuiltinNameRoleList, RoleList(ledger)},
		{BuiltinNameRedactionCommit, RedactionCommit(ledger, f.record, stringObj("regulator"), stringObj("for review"))},
		{BuiltinNameRedactionCommit, RedactionCommit(ledger, f.record, stringObj("regulator"), stringObj("again"))},
	}
	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	calls = append(calls,
		call{BuiltinNameDiscloseToPassphrase, DiscloseToPassphrase(ledger, f.record, stringObj("regulator"),
			stringObj("Partner"))},
		call{BuiltinNameRedactionVersions, RedactionVersions(ledger, stringObj(recordUIDOf(t, f.record)))},
	)
	for _, c := range calls {
		payload, errObj := unwrapPairNoFatal(c.result)
		if errObj != nil {
			t.Fatalf("%s: %s", c.name, errObj.Message)
		}
		assertDeclaredFieldsNoHandle(t, c.name, payload)
	}
}

// recordUIDOf is an open record's uid, which a preview names.
func recordUIDOf(t *testing.T, record object.Object) string {
	t.Helper()
	return mustHashStringValue(t, mustHash(t, ViewPreview(record, stringObj("counsel"))), "record_uid")
}
