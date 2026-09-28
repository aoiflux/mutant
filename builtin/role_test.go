package builtin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// A role id is written into redaction records that are never compacted away,
// so the numbers are a format: once an id has meant a role, it means that role
// forever. This test is the record of what each one means.
func TestRoleIDsAreAFormat(t *testing.T) {
	want := []struct {
		name      string
		id        uint32
		examiner  bool
		recipient bool
	}{
		{"administrator", 1, true, false},
		{"case_owner", 2, true, false},
		{"lead_investigator", 3, true, false},
		{"investigator", 4, true, false},
		{"reviewer", 5, true, true},
		{"auditor", 6, true, true},
		{"legal", 7, false, true},
		{"external_partner", 8, false, true},
		{"restricted_viewer", 9, false, true},
	}
	if len(caseRoles) != len(want) {
		t.Fatalf("there are %d roles, want %d: a role is appended, never removed", len(caseRoles), len(want))
	}
	for i, w := range want {
		got := caseRoles[i]
		if got.Name != w.name || got.ID != w.id || got.examinerSide() != w.examiner || got.recipientSide() != w.recipient {
			t.Errorf("role %d is %+v (examiner %v, recipient %v), want %+v", i, got, got.examinerSide(), got.recipientSide(), w)
		}
		if roleNameForID(w.id) != w.name {
			t.Errorf("id %d reads back as %q, want %q", w.id, roleNameForID(w.id), w.name)
		}
	}
	if roleIDUnasserted != 0xFFFFFFFF || roleNameForID(roleIDUnasserted) != "unasserted" {
		t.Errorf("unasserted is %#x (%q)", roleIDUnasserted, roleNameForID(roleIDUnasserted))
	}
	// Zero is what every record written before roles carries.
	if roleNameForID(0) != "" || roleNameForID(10) != "unknown" {
		t.Errorf("0 reads as %q and 10 as %q", roleNameForID(0), roleNameForID(10))
	}
	if got := strings.Join(ExaminerRoles(), ","); got != "administrator,case_owner,lead_investigator,investigator,reviewer,auditor" {
		t.Errorf("ExaminerRoles = %s", got)
	}
	if got := strings.Join(RecipientRoles(), ","); got != "reviewer,auditor,legal,external_partner,restricted_viewer" {
		t.Errorf("RecipientRoles = %s", got)
	}
}

// Every timeline entry goes through appendEvent, which is what stamps the role;
// an entry appended any other way would be the one entry without it.
func TestEveryTimelineEntryIsAppendedThroughAppendEvent(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, ".timeline = append(") && !strings.Contains(line, "s.timeline = append(s.timeline, custodyEvent{") {
				t.Errorf("%s:%d appends to the timeline without appendEvent: %s", file, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestTheCaseRecordsItsRoleAndSaysNothingCheckedIt(t *testing.T) {
	opened := openTestCase(t, "IR-ROLE", "examiner", makeHashObject(map[string]object.Object{"role": stringObj("Case_Owner")}))
	if got := keyFieldString(t, opened, "role"); got != "case_owner" {
		t.Fatalf("case_open reported role %q, want case_owner", got)
	}
	if discloseBool(t, opened, "role_authenticated") {
		t.Fatal("case_open says the role was authenticated")
	}
	mustHash(t, CaseNote(stringObj("a note")))
	manifest := mustHash(t, CaseManifest())
	caseBlock := mustHashValue(t, manifest, "case").(*object.Hash)
	if got := keyFieldString(t, caseBlock, "role"); got != "case_owner" {
		t.Fatalf("the manifest's case block says role %q", got)
	}
	if discloseBool(t, caseBlock, "role_authenticated") {
		t.Fatal("the manifest says the role was authenticated")
	}
	timeline := mustHashValue(t, manifest, "timeline").(*object.Array)
	if len(timeline.Elements) < 2 {
		t.Fatalf("the timeline has %d entries", len(timeline.Elements))
	}
	for i, entry := range timeline.Elements {
		if got := keyFieldString(t, entry.(*object.Hash), "role"); got != "case_owner" {
			t.Errorf("timeline entry %d carries role %q", i, got)
		}
	}

	mustHash(t, CaseClose())
	plain := openTestCase(t, "IR-ROLE-2", "examiner")
	if got := keyFieldString(t, plain, "role"); got != "unasserted" {
		t.Fatalf("a case opened with no role reports %q, want unasserted", got)
	}
}

// Only the fixed examiner-side roles can be asserted, and saying nothing is
// done by leaving the option out, not by spelling the placeholder.
func TestOnlyAnExaminerRoleCanBeAsserted(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, bad := range []struct {
		value object.Object
		want  string
	}{
		{stringObj("detective"), "is not a role"},
		{stringObj("legal"), "is a recipient role"},
		{stringObj("restricted_viewer"), "is a recipient role"},
		{stringObj("unasserted"), "leave the role option out"},
		{intObj(2), "must be STRING"},
	} {
		options := makeHashObject(map[string]object.Object{"role": bad.value})
		resetCustodyForTesting()
		if _, errObj := unwrapPairNoFatal(CaseOpen(stringObj("IR-1"), stringObj("examiner"), options)); errObj == nil ||
			!strings.Contains(errObj.Message, bad.want) {
			t.Errorf("case_open with role %s: %v, want %q", bad.value.Inspect(), errObj, bad.want)
		}
		if _, errObj := unwrapPairNoFatal(LedgerOpen(stringObj("ledger"), stringObj("examiner"), options)); errObj == nil ||
			!strings.Contains(errObj.Message, bad.want) {
			t.Errorf("ledger_open with role %s: %v, want %q", bad.value.Inspect(), errObj, bad.want)
		}
	}
	resetCustodyForTesting()
	if _, err := os.Stat("ledger"); err == nil {
		t.Fatal("a refused ledger_open created the ledger anyway")
	}
}

func ledgerOpenAs(t *testing.T, dir, actor string, role string) (*object.Hash, *object.Error) {
	t.Helper()
	args := []object.Object{stringObj(dir), stringObj(actor)}
	if role != "" {
		args = append(args, makeHashObject(map[string]object.Object{"role": stringObj(role)}))
	}
	payload, errObj := unwrapPairNoFatal(LedgerOpen(args...))
	if errObj != nil {
		return nil, errObj
	}
	hash := payload.(*object.Hash)
	handle := mustHashIntValue(t, hash, "handle")
	t.Cleanup(func() { LedgerClose(intObj(handle)) })
	return hash, nil
}

// A ledger opened by the case's examiner is opened under the case's role, and
// one person asserting two roles in one process is refused wherever the second
// one is asserted.
func TestALedgerTakesTheCaseRoleAndOneExaminerHasOneRole(t *testing.T) {
	openTestCase(t, "IR-ROLE", "examiner", makeHashObject(map[string]object.Object{"role": stringObj("reviewer")}))
	root := t.TempDir()

	inherited, errObj := ledgerOpenAs(t, filepath.Join(root, "a"), "examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	if role, source := keyFieldString(t, inherited, "role"), keyFieldString(t, inherited, "role_source"); role != "reviewer" || source != "case" {
		t.Fatalf("the case's examiner opened a ledger as %q (%s), want reviewer from the case", role, source)
	}
	if keyFieldString(t, inherited, "role_id") != "5" || discloseBool(t, inherited, "role_authenticated") {
		t.Fatalf("role_id %s, role_authenticated %v", keyFieldString(t, inherited, "role_id"), discloseBool(t, inherited, "role_authenticated"))
	}
	custodyEntry := false
	for _, entry := range mustHashValue(t, mustHash(t, CaseManifest()), "timeline").(*object.Array).Elements {
		e := entry.(*object.Hash)
		if keyFieldString(t, e, "event") == BuiltinNameLedgerOpen {
			data := mustHashValue(t, e, "data").(*object.Hash)
			custodyEntry = keyFieldString(t, data, "role") == "reviewer" && keyFieldString(t, data, "role_source") == "case"
		}
	}
	if !custodyEntry {
		t.Fatal("the manifest does not record the role the ledger was opened under")
	}

	if _, errObj := ledgerOpenAs(t, filepath.Join(root, "b"), "examiner", "investigator"); errObj == nil ||
		!strings.Contains(errObj.Message, "one examiner has one role") {
		t.Fatalf("the case's examiner opened a ledger as investigator while the case says reviewer: %v", errObj)
	}
	if _, err := os.Stat(filepath.Join(root, "b")); err == nil {
		t.Fatal("the refused open created the ledger anyway")
	}
	if _, errObj := ledgerOpenAs(t, filepath.Join(root, "c"), "examiner", "reviewer"); errObj != nil {
		t.Fatalf("asserting the same role again was refused: %s", errObj.Message)
	}

	// Somebody else in the same process is somebody else.
	other, errObj := ledgerOpenAs(t, filepath.Join(root, "d"), "second examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	if role, source := keyFieldString(t, other, "role"), keyFieldString(t, other, "role_source"); role != "unasserted" || source != "unasserted" {
		t.Fatalf("another actor inherited the case's role: %q (%s)", role, source)
	}
	if _, errObj := ledgerOpenAs(t, filepath.Join(root, "e"), "second examiner", "investigator"); errObj != nil {
		t.Fatal(errObj.Message)
	}
	if _, errObj := ledgerOpenAs(t, filepath.Join(root, "f"), "second examiner", "administrator"); errObj == nil ||
		!strings.Contains(errObj.Message, "one examiner has one role") {
		t.Fatalf("one actor held two ledgers under two roles: %v", errObj)
	}
}

// An auditor reads what it audits. Every builtin that writes to a ledger
// refuses an auditor's handle before it looks at anything else, and says the
// refusal is not access control; every builtin that only reads takes it.
func TestAnAuditorWritesNothingIntoALedger(t *testing.T) {
	resetCustodyForTesting()
	t.Cleanup(resetCustodyForTesting)
	dir := filepath.Join(t.TempDir(), "ledger")
	if _, errObj := ledgerOpenAs(t, filepath.Join(t.TempDir(), "new"), "auditor", "auditor"); errObj == nil ||
		!strings.Contains(errObj.Message, "opening it would create one") {
		t.Fatalf("an auditor created a ledger: %v", errObj)
	}

	written, errObj := ledgerOpenAs(t, dir, "investigator", "investigator")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	writer := mustHashIntValue(t, written, "handle")
	mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(writer), ledgerProps(map[string]string{"k": "v"})))
	LedgerClose(intObj(writer))

	audited, errObj := ledgerOpenAs(t, dir, "auditor", "auditor")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	handle := intObj(mustHashIntValue(t, audited, "handle"))
	before := mustLedgerHash(t, "ledger_stats", LedgerStats(handle))

	writers := map[string]bool{
		BuiltinNameLedgerAddNode: true, BuiltinNameLedgerAddEdge: true, BuiltinNameLedgerCompact: true,
		BuiltinNameLedgerCheckpoint: true, BuiltinNameLedgerRedactNode: true, BuiltinNameLedgerRedactNodeProperties: true,
		BuiltinNameLedgerRedactEdge: true, BuiltinNameLedgerRedactEdgeProperties: true,
		BuiltinNameDiscloseToPassphrase: true, BuiltinNameDiscloseWithdraw: true, BuiltinNameDiscloseReclassified: true,
		BuiltinNameCaseAttach: true, BuiltinNameCaseTransition: true, BuiltinNameCaseAssign: true,
		BuiltinNameEvidenceIntake: true, BuiltinNameEvidenceRelease: true, BuiltinNameEvidenceAccept: true,
		BuiltinNameEvidenceReturn: true, BuiltinNameEvidenceDispose: true,
		BuiltinNameRoleAssign: true, BuiltinNameRedactionCommit: true, BuiltinNameLedgerClassify: true,
		BuiltinNameLedgerRedactionsReview: true, BuiltinNameReviewRequest: true, BuiltinNameReviewDecide: true,
		BuiltinNameRetentionSet: true, BuiltinNameRetentionHold: true, BuiltinNameRetentionRelease: true,
	}
	seen := 0
	for name, doc := range builtinDocs {
		// ledger_close takes the handle too, and would take it away from
		// every builtin after it.
		if len(doc.params) == 0 || doc.params[0].name != "ledger" || name == BuiltinNameLedgerClose {
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
		refused := errObj != nil && strings.Contains(errObj.Message, "an auditor reads what it audits")
		switch {
		case writers[name] && !refused:
			t.Errorf("%s took an auditor's handle: %v", name, errObj)
		case writers[name] && !strings.Contains(errObj.Message, "is not access control"):
			t.Errorf("%s refused an auditor without saying it is not access control: %s", name, errObj.Message)
		case !writers[name] && refused:
			t.Errorf("%s only reads, and refused an auditor", name)
		}
	}
	if seen < len(writers)+10 {
		t.Fatalf("found %d builtins taking a ledger handle; the scan is not reaching them", seen)
	}
	after := mustLedgerHash(t, "ledger_stats", LedgerStats(handle))
	for _, field := range []string{"nodes", "edges", "delta_records", "commit_seq", "redactions"} {
		if a, b := mustHashIntValue(t, before, field), mustHashIntValue(t, after, field); a != b {
			t.Errorf("%s moved from %d to %d under an auditor", field, a, b)
		}
	}
}

// M26-REC-002. A withdrawal recorded who did it and not on whose authority,
// though DISCLOSURE_POLICY promised both. It now records the authority as a
// name and an AUTHORISED_BY edge, and the role the examiner acted under on the
// PERFORMED_BY edge.
func TestAWithdrawalRecordsOnWhoseAuthority(t *testing.T) {
	f := newDiscloseFixture(t)
	counsel := keyFieldString(t, f.issue(t, "counsel", "Counsel for the respondent"), "disclosure_uid")
	regulator := keyFieldString(t, f.issue(t, "regulator", "The regulator"), "disclosure_uid")

	withdrawn := mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(counsel), stringObj("scope changed"),
		makeHashObject(map[string]object.Object{"authorised_by": stringObj(" Head of Legal ")})))
	if got := keyFieldString(t, withdrawn, "authorised_by"); got != "Head of Legal" {
		t.Fatalf("authorised_by = %q", got)
	}
	if got := keyFieldString(t, withdrawn, "authority_basis"); got != "named" {
		t.Fatalf("authority_basis = %q, want named", got)
	}
	if got := keyFieldString(t, withdrawn, "role"); got != "unasserted" {
		t.Fatalf("role = %q, want unasserted (the fixture's ledger names none)", got)
	}
	self := mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(regulator), stringObj("closed")))
	if got, basis := keyFieldString(t, self, "authorised_by"), keyFieldString(t, self, "authority_basis"); got != "examiner" || basis != "self" {
		t.Fatalf("a withdrawal with no authority named says %q (%s), want the examiner's own", got, basis)
	}

	session, _ := ledgerGet(f.ledger)
	edgesOf := func(withdrawal map[string]object.Object) map[string]*store.Edge {
		t.Helper()
		id := store.NodeID(withdrawal["ledger_node"].(*object.Integer).Value)
		edges, err := session.graph.EdgesOf(id, store.DirectionOutbound, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, names := disclosureTypeNames()
		out := map[string]*store.Edge{}
		for _, e := range edges {
			out[names[e.Labels[0]]] = e
		}
		return out
	}
	actorName := func(id store.NodeID) string {
		t.Helper()
		node, err := session.graph.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		props, err := ledgerDecodeProperties(node.Properties)
		if err != nil {
			t.Fatal(err)
		}
		return string(props["actor.name"])
	}
	edgeProps := func(e *store.Edge) map[string][]byte {
		t.Helper()
		props, err := ledgerDecodeProperties(e.Properties)
		if err != nil {
			t.Fatal(err)
		}
		return props
	}

	named := edgesOf(hashPairs(withdrawn))
	if named["AUTHORISED_BY"] == nil || named["PERFORMED_BY"] == nil || named["WITHDREW"] == nil {
		t.Fatalf("the withdrawal's edges are %v", named)
	}
	if got := actorName(named["AUTHORISED_BY"].Dst); got != "Head of Legal" {
		t.Fatalf("AUTHORISED_BY points at %q", got)
	}
	if got := actorName(named["PERFORMED_BY"].Dst); got != "examiner" {
		t.Fatalf("PERFORMED_BY points at %q", got)
	}
	if got := string(edgeProps(named["PERFORMED_BY"])["role"]); got != "unasserted" {
		t.Fatalf("PERFORMED_BY carries role %q", got)
	}
	if got := string(edgeProps(named["AUTHORISED_BY"])["basis"]); got != "named" {
		t.Fatalf("AUTHORISED_BY carries basis %q", got)
	}
	own := edgesOf(hashPairs(self))
	if own["AUTHORISED_BY"] == nil || own["AUTHORISED_BY"].Dst != own["PERFORMED_BY"].Dst {
		t.Fatal("a withdrawal on the examiner's own authority does not point AUTHORISED_BY at the examiner")
	}

	rows := mustHashValue(t, mustHash(t, DiscloseHistory(intObj(f.ledger))), "disclosures").(*object.Array)
	byUID := map[string]*object.Hash{}
	for _, row := range rows.Elements {
		byUID[keyFieldString(t, row.(*object.Hash), "disclosure_uid")] = row.(*object.Hash)
	}
	if got := keyFieldString(t, byUID[counsel], "withdrawal_authorised_by"); got != "Head of Legal" {
		t.Fatalf("the history says counsel's withdrawal was authorised by %q", got)
	}
	if got := keyFieldString(t, byUID[regulator], "withdrawal_authority_basis"); got != "self" {
		t.Fatalf("the history says the regulator's withdrawal basis is %q", got)
	}
	if got := keyFieldString(t, byUID[counsel], "actor_role"); got != "unasserted" {
		t.Fatalf("the history says counsel's disclosure was made as %q", got)
	}
}

func TestAWithdrawalAuthorityMustNameSomebody(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel for the respondent"), "disclosure_uid")
	for _, bad := range []object.Object{stringObj("   "), intObj(7), stringObj("\xff\xfe")} {
		_, errObj := unwrapPairNoFatal(DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("reason"),
			makeHashObject(map[string]object.Object{"authorised_by": bad})))
		if errObj == nil {
			t.Fatalf("authorised_by %s was accepted", bad.Inspect())
		}
	}
	history := mustHash(t, DiscloseHistory(intObj(f.ledger)))
	if mustHashIntValue(t, history, "withdrawn") != 0 {
		t.Fatal("a refused withdrawal was recorded")
	}
}

// The role goes where graphene keeps one: on the redaction record, across a
// reopen, under the name it was asserted as.
func TestARedactionRecordKeepsItsRole(t *testing.T) {
	resetCustodyForTesting()
	t.Cleanup(resetCustodyForTesting)
	dir := filepath.Join(t.TempDir(), "ledger")
	opened, errObj := ledgerOpenAs(t, dir, "Alice Examiner", "lead_investigator")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	handle := mustHashIntValue(t, opened, "handle")
	node := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"k": "value"})))
	redacted := mustLedgerHash(t, "ledger_redact_node", LedgerRedactNode(intObj(handle),
		intObj(mustHashIntValue(t, node, "id")), stringObj("court order 12")))
	if got := keyFieldString(t, redacted, "role"); got != "lead_investigator" {
		t.Fatalf("the redaction reports role %q", got)
	}
	LedgerClose(intObj(handle))

	reread, errObj := ledgerOpenAs(t, dir, "Bob Reviewer", "reviewer")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	list := mustLedgerHash(t, "ledger_redactions", LedgerRedactions(intObj(mustHashIntValue(t, reread, "handle"))))
	records := mustHashValue(t, list, "redactions").(*object.Array)
	if len(records.Elements) != 1 {
		t.Fatalf("%d redaction records", len(records.Elements))
	}
	record := records.Elements[0].(*object.Hash)
	if got := keyFieldString(t, record, "role"); got != "lead_investigator" {
		t.Fatalf("after a reopen the record's role is %q", got)
	}
	if got := keyFieldString(t, record, "role_id"); got != "3" {
		t.Fatalf("after a reopen the record's role_id is %q", got)
	}
}

// M26-CUS-007. ledger_redactions put the reading session's actor name on every
// record, so a redaction Alice made was attributed by name to Bob when Bob read
// the ledger. The name is now the one behind the record's own actor id, or
// empty and marked unknown.
func TestARedactionIsNeverAttributedToTheReader(t *testing.T) {
	resetCustodyForTesting()
	t.Cleanup(resetCustodyForTesting)
	dir := filepath.Join(t.TempDir(), "ledger")
	alice, errObj := ledgerOpenAs(t, dir, "Alice Examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	handle := mustHashIntValue(t, alice, "handle")
	node := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"k": "value"})))
	mustLedgerHash(t, "ledger_redact_node", LedgerRedactNode(intObj(handle), intObj(mustHashIntValue(t, node, "id")),
		stringObj("court order 12")))
	own := mustHashValue(t, mustLedgerHash(t, "ledger_redactions", LedgerRedactions(intObj(handle))), "redactions").(*object.Array)
	if got, source := keyFieldString(t, own.Elements[0].(*object.Hash), "actor"), keyFieldString(t, own.Elements[0].(*object.Hash), "actor_source"); got != "Alice Examiner" || source != "session" {
		t.Fatalf("Alice's own session names her record's actor %q (%s)", got, source)
	}
	LedgerClose(intObj(handle))

	bob, errObj := ledgerOpenAs(t, dir, "Bob Reviewer", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	read := mustHashValue(t, mustLedgerHash(t, "ledger_redactions", LedgerRedactions(intObj(mustHashIntValue(t, bob, "handle")))), "redactions").(*object.Array)
	record := read.Elements[0].(*object.Hash)
	if got := keyFieldString(t, record, "actor"); got == "Bob Reviewer" {
		t.Fatal("Alice's redaction is attributed to Bob, who only read the ledger")
	}
	if got, source := keyFieldString(t, record, "actor"), keyFieldString(t, record, "actor_source"); got != "" || source != "unknown" {
		t.Fatalf("a record by an actor this ledger never named reports %q (%s), want empty and unknown", got, source)
	}
}

func hashPairs(h *object.Hash) map[string]object.Object {
	out := map[string]object.Object{}
	for _, pair := range h.Pairs {
		if key, ok := pair.Key.(*object.String); ok {
			out[key.Value] = pair.Value
		}
	}
	return out
}
