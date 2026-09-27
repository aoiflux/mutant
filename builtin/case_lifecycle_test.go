package builtin

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// lifecycleRun is one run of a case: the case open under a key, a ledger
// open by its examiner, and the paths a later run reopens.
type lifecycleRun struct {
	keyPath   string
	ledgerDir string
	ledger    int64
}

// openLifecycleRun opens case IR-LIFE for examiner under role, opens (or
// creates) the key at keyPath, and opens the ledger at ledgerDir as the same
// examiner. Nothing is attached and nothing is defined.
func openLifecycleRun(t *testing.T, examiner, role, keyPath, ledgerDir string) *lifecycleRun {
	t.Helper()
	if role == "" {
		openTestCase(t, "IR-LIFE", examiner)
	} else {
		openTestCase(t, "IR-LIFE", examiner, makeHashObject(map[string]object.Object{"role": stringObj(role)}))
	}
	stubPassphrase(t, testCasePassphrase)
	if keyPath == "" {
		keyPath = filepath.Join(t.TempDir(), "case.mkey")
		mustHash(t, CaseKeyCreate(stringObj(keyPath)))
	}
	mustHash(t, CaseKeyOpen(stringObj(keyPath)))
	if ledgerDir == "" {
		ledgerDir = filepath.Join(t.TempDir(), "ledger")
	}
	opened, errObj := ledgerOpenAs(t, ledgerDir, examiner, "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	return &lifecycleRun{keyPath: keyPath, ledgerDir: ledgerDir, ledger: mustHashIntValue(t, opened, "handle")}
}

// next ends this run -- the ledger closed, the case gone -- and opens the
// next one over the same key and ledger.
func (r *lifecycleRun) next(t *testing.T, examiner, role string) *lifecycleRun {
	t.Helper()
	LedgerClose(intObj(r.ledger))
	resetCustodyForTesting()
	return openLifecycleRun(t, examiner, role, r.keyPath, r.ledgerDir)
}

func (r *lifecycleRun) attach(t *testing.T) *object.Hash {
	t.Helper()
	return mustHash(t, CaseAttach(intObj(r.ledger)))
}

func (r *lifecycleRun) session(t *testing.T) *ledgerSession {
	t.Helper()
	session, ok := ledgerGet(r.ledger)
	if !ok {
		t.Fatal("the run's ledger is not open")
	}
	return session
}

func mustRefuse(t *testing.T, what string, result object.Object, want string) {
	t.Helper()
	_, errObj := unwrapPairNoFatal(result)
	if errObj == nil {
		t.Fatalf("%s was not refused", what)
	}
	if !strings.Contains(errObj.Message, want) {
		t.Fatalf("%s: %q does not say %q", what, errObj.Message, want)
	}
}

func openCaseUID(t *testing.T) string {
	t.Helper()
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	return custodyStore.session.caseUID
}

// forceLifecycle appends lifecycle events the way case_transition does, for
// the moves whose builtins do not exist yet, and moves the attached case's
// copy of the state with them when the case is attached.
func forceLifecycle(t *testing.T, ledger *ledgerSession, caseUID string, states ...string) {
	t.Helper()
	disclosureLedgerMu.Lock()
	events, state, err := caseLifecycleRead(ledger.graph, caseUID)
	if err != nil {
		disclosureLedgerMu.Unlock()
		t.Fatal(err)
	}
	head := caseChainHead(events)
	w, err := caseBeginWrite(ledger, caseUID, "IR-LIFE", custodyNow())
	if err == nil && head == nil {
		var first caseChainEvent
		if first, err = w.lifecycle(nil, "", caseStateRegistered, "forced"); err == nil {
			head, state = &first, caseStateRegistered
		}
	}
	for _, to := range states {
		if err != nil {
			break
		}
		var event caseChainEvent
		if event, err = w.lifecycle(head, state, to, "forced"); err == nil {
			head, state = &event, to
		}
	}
	if err == nil {
		err = w.tx.commit()
	}
	disclosureLedgerMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	custodyStore.Lock()
	if session := custodyStore.session; session != nil && session.attached != nil && session.attached.ledger == ledger {
		session.attached.state, session.attached.head = state, *head
	}
	custodyStore.Unlock()
}

// A label's number is written into every ledger that holds one of its nodes
// or edges, so once a number has named a label it names that label forever.
func TestTheLedgerLabelsAreAFormat(t *testing.T) {
	nodes, edges := disclosureTypeNames()
	wantNodes := map[string]uint16{
		"Actor": 1, "Record": 2, "Classification": 3, "View": 4, "Recipient": 5, "Disclosure": 6,
		"Withdrawal": 7, "ReclassEvent": 8, "Role": 9, "RoleBundle": 10, "Assignment": 11,
		"LifecycleEvent": 12, "CustodyEvent": 13, "ReviewRequest": 14, "ReviewDecision": 15,
		"RetentionEvent": 16, "ErasureEvent": 17, "ClassEvent": 18, "RedactionVersion": 19,
		"RedactionReview": 20,
	}
	wantEdges := map[string]uint16{
		"IN_CASE": 0, "CLASSIFIED_AS": 1, "GRANTS": 2, "DISCLOSED_TO": 3, "AUTHORISED_BY": 4,
		"PERFORMED_BY": 5, "WITHDREW": 6, "SUPERSEDES": 7, "HOLDS_ROLE": 8, "ASSIGNED_TO": 9,
		"BUNDLES": 10, "ISSUED_UNDER": 11, "REDACTED_AS": 12, "REVISES": 13, "TRANSITIONS": 14,
		"CUSTODIAN": 15, "REVIEWS": 16, "ERASES": 17,
	}
	if len(nodes) != len(wantNodes) || len(edges) != len(wantEdges) {
		t.Fatalf("the schema names %d node and %d edge labels, and this test pins %d and %d: pin the new ones",
			len(nodes), len(edges), len(wantNodes), len(wantEdges))
	}
	for label, name := range nodes {
		if want, ok := wantNodes[name]; !ok || label != store.CustomNodeType(disclosureTypeBase+want) {
			t.Errorf("node label %s is %d; it was pinned at base+%d", name, label, want)
		}
	}
	for label, name := range edges {
		if want, ok := wantEdges[name]; !ok || label != store.CustomEdgeType(disclosureTypeBase+want) {
			t.Errorf("edge label %s is %d; it was pinned at base+%d", name, label, want)
		}
	}
	if disclosureNodeCase != store.NodeTypeCase || disclosureNodeEvidence != store.NodeTypeEvidenceFile ||
		disclosureEdgeBelongsTo != store.EdgeTypeBelongsTo {
		t.Error("Case, EvidenceFile and BelongsTo are graphene's own built-in types")
	}
}

// The first attach registers the case; a later run's attach reads back its
// state, its assignments and the classes and views it declared, and a script
// that declares them again is answered rather than refused.
func TestTheFirstAttachRegistersTheCaseAndALaterOneReadsItBack(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	first := run.attach(t)
	if !mustHashBoolValue(t, first, "first_attach") || mustHashStringValue(t, first, "state") != caseStateRegistered {
		t.Fatalf("the first attach gave %s", first.Inspect())
	}
	if got := mustHashValue(t, first, "assignments").Inspect(); !strings.Contains(got, "case_owner") {
		t.Fatalf("the first attach assigned %s", got)
	}
	pii := mustHash(t, ClassDefine(stringObj("PII"), makeHashObject(map[string]object.Object{
		"description": stringObj("personal data")})))
	if !mustHashBoolValue(t, pii, "in_ledger") || mustHashBoolValue(t, pii, "already_defined") {
		t.Fatalf("class_define while attached gave %s", pii.Inspect())
	}
	mustHash(t, ClassDefine(stringObj("open")))
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open", "pii")))
	moved := mustHash(t, CaseTransition(intObj(run.ledger), stringObj("Active"), stringObj("work begins")))
	if mustHashStringValue(t, moved, "from") != caseStateRegistered || mustHashStringValue(t, moved, "state") != caseStateActive {
		t.Fatalf("case_transition gave %s", moved.Inspect())
	}
	tag := mustHashStringValue(t, pii, "tag")

	run = run.next(t, "examiner", "case_owner")
	manifest := mustHash(t, CaseManifest())
	if state := manifestSection(t, manifest, "ledger_state"); mustHashBoolValue(t, state, "attached") {
		t.Fatal("the manifest says a case is attached before case_attach")
	}
	again := run.attach(t)
	if mustHashBoolValue(t, again, "first_attach") || mustHashStringValue(t, again, "state") != caseStateActive ||
		mustHashIntValue(t, again, "classes_read") != 2 || mustHashIntValue(t, again, "views_read") != 1 ||
		len(mustHashArrayValue(t, again, "lifecycle")) != 2 {
		t.Fatalf("the later attach gave %s", again.Inspect())
	}
	classes := mustHashArrayValue(t, mustHash(t, ClassList()), "classes")
	if len(classes) != 2 || mustHashStringValue(t, classes[0].(*object.Hash), "tag") != tag ||
		mustHashStringValue(t, classes[0].(*object.Hash), "source") != "ledger" {
		t.Fatalf("class_list after the attach is %v", classes)
	}
	redeclared := mustHash(t, ClassDefine(stringObj("pii")))
	if !mustHashBoolValue(t, redeclared, "already_defined") || mustHashStringValue(t, redeclared, "tag") != tag {
		t.Fatalf("declaring a class the ledger defines gave %s", redeclared.Inspect())
	}
	mustRefuse(t, "a class the ledger defines, described differently", ClassDefine(stringObj("pii"),
		makeHashObject(map[string]object.Object{"description": stringObj("something else")})), "written once")
	if view := mustHash(t, ViewDefine(stringObj("Counsel"), viewArray("pii", "open"))); !mustHashBoolValue(t, view, "already_defined") {
		t.Fatalf("declaring a view the ledger defines gave %s", view.Inspect())
	}
	mustRefuse(t, "a view the ledger defines, granting something else", ViewDefine(stringObj("counsel"),
		viewArray("open")), "written once")

	state := manifestSection(t, mustHash(t, CaseManifest()), "ledger_state")
	if !mustHashBoolValue(t, state, "attached") || mustHashStringValue(t, state, "source") != "ledger" ||
		mustHashStringValue(t, state, "state") != caseStateActive || mustHashIntValue(t, state, "classes_read") != 2 {
		t.Fatalf("the manifest's ledger_state is %s", state.Inspect())
	}
}

// Every lookup this family makes is by an indexed key, and a lookup by a key
// the index does not hold finds nothing and says nothing: so every key every
// label is looked up by must find the node that carries it.
func TestEveryCaseLabelIsFoundByEachOfItsLookupKeys(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustHash(t, CaseTransition(intObj(run.ledger), stringObj("active"), stringObj("begin")))
	mustHash(t, CaseAssign(intObj(run.ledger), stringObj("bob"), stringObj("investigator"), stringObj("joins")))
	g := run.session(t).graph
	for _, label := range []store.NodeType{disclosureNodeRole, disclosureNodeLifecycle, disclosureNodeAssignment} {
		nodes, err := disclosureAll(g, label)
		if err != nil || len(nodes) == 0 {
			t.Fatalf("no %s node was written: %v", label.String(), err)
		}
		for _, node := range nodes {
			for _, key := range disclosureKeys[label] {
				ids, err := g.NodesByProperty(key, []byte(node.get(key)))
				if err != nil || !slices.Contains(ids, node.id) {
					t.Errorf("%s node %d is not found by %s = %q", label.String(), node.id, key, node.get(key))
				}
			}
		}
	}
}

// The ledger's assignments decide which role an examiner attaches under: an
// examiner it assigns nothing, or something else, is refused.
func TestAnAttachMustAgreeWithTheLedgersAssignments(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustRefuse(t, "a recipient role", CaseAssign(intObj(run.ledger), stringObj("bob"), stringObj("legal"),
		stringObj("x")), "recipient role")
	mustRefuse(t, "ending nothing", CaseAssign(intObj(run.ledger), stringObj("bob"), stringObj("none"),
		stringObj("x")), "no assignment to end")
	assigned := mustHash(t, CaseAssign(intObj(run.ledger), stringObj("bob"), stringObj("Investigator"),
		stringObj("joins the case")))
	if mustHashStringValue(t, assigned, "previous_role") != caseAssignmentEnded || !mustHashBoolValue(t, assigned, "in_force") {
		t.Fatalf("case_assign gave %s", assigned.Inspect())
	}
	mustRefuse(t, "the same assignment again", CaseAssign(intObj(run.ledger), stringObj("bob"),
		stringObj("investigator"), stringObj("x")), "already assigned")

	run = run.next(t, "examiner", "investigator")
	mustRefuse(t, "the owner as an investigator", CaseAttach(intObj(run.ledger)), "assigns examiner as case_owner")
	run = run.next(t, "carol", "investigator")
	mustRefuse(t, "an examiner the case never assigned", CaseAttach(intObj(run.ledger)), "assigns carol no role")
	run = run.next(t, "bob", "investigator")
	run.attach(t)
	mustHash(t, CaseAssign(intObj(run.ledger), stringObj("bob"), stringObj("none"), stringObj("leaves")))
	run = run.next(t, "bob", "investigator")
	mustRefuse(t, "an examiner whose assignment ended", CaseAttach(intObj(run.ledger)), "assigns bob no role")
}

func TestCaseAttachRefusesWhatItCannotRecordHonestly(t *testing.T) {
	openTestCase(t, "IR-LIFE", "examiner", makeHashObject(map[string]object.Object{"role": stringObj("case_owner")}))
	stubPassphrase(t, testCasePassphrase)
	dir := filepath.Join(t.TempDir(), "ledger")
	opened, errObj := ledgerOpenAs(t, dir, "examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	ledger := intObj(mustHashIntValue(t, opened, "handle"))
	mustRefuse(t, "an attach with no key", CaseAttach(ledger), "no case key is open")
	key := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(key)))
	mustHash(t, CaseKeyOpen(stringObj(key)))
	mustHash(t, ClassDefine(stringObj("open")))
	mustRefuse(t, "an attach after a definition", CaseAttach(ledger), "Attach before defining")

	run := openLifecycleRun(t, "examiner", "", "", "")
	mustRefuse(t, "an attach with no role", CaseAttach(intObj(run.ledger)), "asserted no role")
	other, errObj := ledgerOpenAs(t, filepath.Join(t.TempDir(), "other"), "someone else", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	mustRefuse(t, "an attach from another examiner's ledger", CaseAttach(intObj(mustHashIntValue(t, other, "handle"))),
		"opened by someone else")

	run = openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustRefuse(t, "a second attach", CaseAttach(intObj(run.ledger)), "already attached")
	LedgerClose(intObj(run.ledger))
	mustRefuse(t, "a definition once the ledger closed", ClassDefine(stringObj("late")), "has been closed")
	moved, errObj := ledgerOpenAs(t, filepath.Join(t.TempDir(), "moved"), "examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	mustRefuse(t, "an attach to a different ledger", CaseAttach(intObj(mustHashIntValue(t, moved, "handle"))),
		"Attach it to that ledger again")
	LedgerClose(intObj(mustHashIntValue(t, moved, "handle")))
	reopened, errObj := ledgerOpenAs(t, run.ledgerDir, "examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	back := mustHash(t, CaseAttach(intObj(mustHashIntValue(t, reopened, "handle"))))
	if mustHashBoolValue(t, back, "first_attach") {
		t.Fatalf("attaching the same ledger again registered the case again: %s", back.Inspect())
	}
	if class := mustHash(t, ClassDefine(stringObj("late"))); !mustHashBoolValue(t, class, "in_ledger") {
		t.Fatalf("a definition after reattaching is not in the ledger: %s", class.Inspect())
	}
}

// A case moves only along its lifecycle, and a refusal names where it is and
// where it can go.
func TestACaseMovesOnlyAlongItsLifecycle(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	ledger := intObj(run.ledger)
	mustRefuse(t, "a move before attaching", CaseTransition(ledger, stringObj("active"), stringObj("x")),
		"attached to no ledger")
	run.attach(t)
	mustRefuse(t, "an unknown state", CaseTransition(ledger, stringObj("finished"), stringObj("x")),
		"not a lifecycle state")
	mustRefuse(t, "an empty reason", CaseTransition(ledger, stringObj("active"), stringObj("  ")), "must not be empty")
	mustRefuse(t, "a skipped state", CaseTransition(ledger, stringObj("concluded"), stringObj("x")),
		"from registered, case_transition moves a case to active")
	mustHash(t, CaseTransition(ledger, stringObj("active"), stringObj("begin")))
	mustRefuse(t, "a move to where it is", CaseTransition(ledger, stringObj("active"), stringObj("x")), "already active")
	mustRefuse(t, "a move case_transition does not make", CaseTransition(ledger, stringObj("in_review"),
		stringObj("x")), "moves a case that is active nowhere")

	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateInReview, caseStateConcluded)
	reopened := mustHash(t, CaseTransition(ledger, stringObj("active"), stringObj("new evidence")))
	if mustHashStringValue(t, reopened, "from") != caseStateConcluded || mustHashIntValue(t, reopened, "seq") != 5 {
		t.Fatalf("reopening gave %s", reopened.Inspect())
	}
}

// Each state refuses what it says it refuses, in the builtins that ask the
// attached case and in the ones that ask the ledger, and none refuses a
// withdrawal.
func TestEachStateRefusesWhatItSays(t *testing.T) {
	for _, state := range []string{caseStateRegistered, caseStateActive, caseStateInReview, caseStateConcluded,
		caseStateRetained, caseStateDisposed} {
		t.Run(state, func(t *testing.T) {
			run := openLifecycleRun(t, "examiner", "case_owner", "", "")
			run.attach(t)
			mustHash(t, ClassDefine(stringObj("open")))
			var path []string
			for _, s := range caseStates[1:] {
				path = append(path, s)
				if s == state {
					break
				}
			}
			if state != caseStateRegistered {
				forceLifecycle(t, run.session(t), openCaseUID(t), path...)
			}
			source, dest, _ := recordFixture(t)
			for _, check := range []struct {
				action caseAction
				result object.Object
			}{
				{caseActSeal, RecordSeal(stringObj(source), stringObj(dest), recordArray(), recordSealOpts(nil))},
				{caseActDefine, ClassDefine(stringObj("another"))},
				{caseActAssign, CaseAssign(intObj(run.ledger), stringObj("bob"), stringObj("investigator"), stringObj("x"))},
			} {
				_, errObj := unwrapPairNoFatal(check.result)
				refused := errObj != nil && strings.Contains(errObj.Message, "takes no "+caseActionNames[check.action])
				if refused != caseStateBlocks(state, check.action) {
					t.Errorf("%s in state %s: refused %t (%v)", caseActionNames[check.action], state, refused, errObj)
				}
			}
			err := caseLedgerStateRefusal(run.session(t).graph, openCaseUID(t), caseActDisclose)
			if (err != nil) != caseStateBlocks(state, caseActDisclose) {
				t.Errorf("a disclosure in state %s: %v", state, err)
			}
		})
	}
}

// What each state refuses is written out here as well as in caseStateRefuses,
// so that a refusal dropped from or added to that table fails this test
// instead of changing what every test that asks caseStateBlocks expects.
func TestEachStateRefusesAFixedSetOfActs(t *testing.T) {
	want := map[string][]caseAction{
		caseStateInReview:  {caseActSeal, caseActDefine, caseActDisclose, caseActIntake, caseActRedact},
		caseStateConcluded: {caseActSeal, caseActIntake},
		caseStateRetained:  {caseActSeal, caseActIntake},
		caseStateDisposed:  {caseActSeal, caseActDefine, caseActDisclose, caseActAssign, caseActIntake, caseActRedact},
	}
	for _, state := range caseStates {
		for action, name := range caseActionNames {
			if got := caseStateBlocks(state, action); got != slices.Contains(want[state], action) {
				t.Errorf("a case that is %s refuses the %s: %t", state, name, got)
			}
		}
	}
}

// A builtin that takes the ledger asks the ledger, attached case or not: a
// disclosure of a case the ledger has in review is refused before any
// passphrase is asked for, and a withdrawal is taken in every state.
func TestADisclosureAsksTheLedgerForTheCaseState(t *testing.T) {
	f := newDiscloseFixture(t)
	issued := f.issue(t, "counsel", "Counsel for the defence")
	ledger, _ := ledgerGet(f.ledger)
	forceLifecycle(t, ledger, openCaseUID(t), caseStateActive, caseStateInReview)
	newRecord, _ := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(150), stringObj("restricted"))),
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	))
	purposeStub(t, map[string]string{})
	mustRefuse(t, "a disclosure in review", DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("regulator"),
		stringObj("The regulator")), "takes no disclosure")
	mustRefuse(t, "a reclassification in review", DiscloseReclassified(intObj(f.ledger), newRecord, f.record),
		"takes no definition")
	forceLifecycle(t, ledger, openCaseUID(t), caseStateConcluded, caseStateRetained, caseStateDisposed)
	mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(mustHashStringValue(t, issued, "disclosure_uid")),
		stringObj("the case is disposed")))
}

// M26-CUS-023. A builtin that takes the ledger asks that ledger for the case's
// state, so a case attached to one ledger and written through another was
// asked the other -- which records no lifecycle and refuses nothing -- and a
// disclosure or a reclassification made while the case was in review went
// ahead. A case's acts are recorded in the ledger it is attached to.
func TestACaseIsNotWrittenThroughAnotherLedger(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustHash(t, ClassDefine(stringObj("open")))
	mustHash(t, ClassDefine(stringObj("pii")))
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open", "pii")))
	source, dest, _ := recordFixture(t)
	seal := func(dest string, offset int64) object.Object {
		mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(
			mustHash(t, RecordClassifyRange(intObj(offset), intObj(20), stringObj("pii")))), recordSealOpts(nil)))
		handle := mustHashValue(t, mustHash(t, RecordOpen(stringObj(dest))), "handle")
		t.Cleanup(func() { RecordClose(handle) })
		return handle
	}
	record := seal(dest, 10)
	reclassified := seal(filepath.Join(t.TempDir(), "reclassified.mrec"), 40)
	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateActive, caseStateInReview)

	opened, errObj := ledgerOpenAs(t, filepath.Join(t.TempDir(), "other"), "examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	other := intObj(mustHashIntValue(t, opened, "handle"))
	t.Cleanup(func() { LedgerClose(other) })
	mustRefuse(t, "a disclosure through another ledger", DiscloseToPassphrase(other, record, stringObj("counsel"),
		stringObj("Counsel")), "attached to ledger "+run.ledgerDir)
	mustRefuse(t, "a reclassification through another ledger", DiscloseReclassified(other, reclassified, record),
		"attached to ledger "+run.ledgerDir)
	mustRefuse(t, "a recipient's role through another ledger", RoleAssign(other, stringObj("Counsel"),
		stringObj("legal"), stringObj("x")), "attached to ledger "+run.ledgerDir)
	mustRefuse(t, "a redaction version through another ledger", RedactionCommit(other, record, stringObj("counsel"),
		stringObj("x")), "attached to ledger "+run.ledgerDir)

	// The case's own ledger, closed and opened again, is another handle: the
	// case is attached through it before anything is written through it.
	LedgerClose(intObj(run.ledger))
	reopened, errObj := ledgerOpenAs(t, run.ledgerDir, "examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	again := intObj(mustHashIntValue(t, reopened, "handle"))
	t.Cleanup(func() { LedgerClose(again) })
	mustRefuse(t, "a disclosure through a reopened handle", DiscloseToPassphrase(again, record, stringObj("counsel"),
		stringObj("Counsel")), "through a handle that has since been closed")
}

// A chain with two events after one event, an event whose uid does not
// recompute from what it says, or one no walk from the start reaches, is
// refused by every reader rather than resolved.
func TestAChainThisProgramDidNotWriteIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(w *caseWriter, head *caseChainEvent) error
		want  string
	}{
		{"fork", func(w *caseWriter, head *caseChainEvent) error {
			_, err := w.lifecycle(nil, "", caseStateRegistered, "a second registration")
			return err
		}, "two lifecycle events after the start of the chain"},
		{"altered", func(w *caseWriter, head *caseChainEvent) error {
			props := map[string]string{}
			for key, value := range head.props {
				props[key] = value
			}
			props["lifecycle.state"], props["lifecycle.from"] = caseStateActive, caseStateRegistered
			props["lifecycle.prev_uid"], props["lifecycle.seq"] = head.uid, "2"
			props["lifecycle.uid"] = strings.Repeat("0", 64)
			_, err := w.tx.node(disclosureNodeLifecycle, props)
			return err
		}, "hashes to"},
		{"inconsistent", func(w *caseWriter, head *caseChainEvent) error {
			_, err := w.lifecycle(head, caseStateConcluded, caseStateActive, "from where the case never was")
			return err
		}, "moves the case from \"concluded\""},
		{"orphan", func(w *caseWriter, head *caseChainEvent) error {
			props := map[string]string{}
			for key, value := range head.props {
				props[key] = value
			}
			props["lifecycle.state"], props["lifecycle.from"] = caseStateConcluded, caseStateActive
			props["lifecycle.prev_uid"], props["lifecycle.seq"] = strings.Repeat("ab", 32), "8"
			props["lifecycle.uid"] = caseChainUID(caseLifecycleChain, props)
			_, err := w.tx.node(disclosureNodeLifecycle, props)
			return err
		}, "no walk from the chain's first event reaches"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := openLifecycleRun(t, "examiner", "case_owner", "", "")
			run.attach(t)
			ledger := run.session(t)
			caseUID := openCaseUID(t)
			disclosureLedgerMu.Lock()
			events, _, err := caseLifecycleRead(ledger.graph, caseUID)
			w, werr := caseBeginWrite(ledger, caseUID, "IR-LIFE", custodyNow())
			if err == nil && werr == nil {
				if err = tc.write(w, caseChainHead(events)); err == nil {
					err = w.tx.commit()
				}
			}
			disclosureLedgerMu.Unlock()
			if err != nil || werr != nil {
				t.Fatal(err, werr)
			}
			mustRefuse(t, "a move on the chain", CaseTransition(intObj(run.ledger), stringObj("active"),
				stringObj("x")), tc.want)
			run = run.next(t, "examiner", "case_owner")
			mustRefuse(t, "an attach to the chain", CaseAttach(intObj(run.ledger)), tc.want)
		})
	}
}

// A ledger that says a class carries a tag the open key does not give it is
// refused at the attach, not believed.
func TestAClassTheKeyDidNotTagIsRefusedAtTheAttach(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustHash(t, ClassDefine(stringObj("pii")))
	ledger := run.session(t)
	custodyStore.RLock()
	session := custodyStore.session
	forged := caseClass{Label: "secret", Canonical: "secret", Tag: strings.Repeat("cd", 32), Index: 1,
		DefinedAt: custodyNow()}
	custodyStore.RUnlock()
	custodyStore.Lock()
	err := session.recordClassLocked(ledger, forged)
	custodyStore.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	run = run.next(t, "examiner", "case_owner")
	mustRefuse(t, "an attach over a forged class", CaseAttach(intObj(run.ledger)), "the open case key tags it")
}

// M26-REC-021. findOrAdd asked the graph, which cannot see a node buffered in
// the same transaction, so a withdrawal on the examiner's own authority --
// the default -- by an examiner the ledger held no Actor node for wrote two
// Actor nodes for one name, and every later lookup of that name refused the
// ledger as written to by something else.
func TestOneNameIsOneActorNodeWithinATransaction(t *testing.T) {
	f := newDiscloseFixture(t)
	issued := f.issue(t, "counsel", "Counsel for the defence")
	LedgerClose(intObj(f.ledger))
	other, errObj := ledgerOpenAs(t, f.ledgerDir, "second examiner", "")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	handle := intObj(mustHashIntValue(t, other, "handle"))
	mustHash(t, DiscloseWithdraw(handle, stringObj(mustHashStringValue(t, issued, "disclosure_uid")),
		stringObj("withdrawn by the second examiner")))
	session, _ := ledgerGet(mustHashIntValue(t, other, "handle"))
	if _, _, err := disclosureFind(session.graph, disclosureNodeActor, "actor.id",
		strconv.FormatUint(ledgerIDFrom([]byte("second examiner")), 10)); err != nil {
		t.Fatalf("the withdrawal left the ledger unreadable for its examiner: %v", err)
	}
	mustHash(t, RoleAssign(handle, stringObj("The regulator"), stringObj("legal"), stringObj("the regulator")))
	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	mustHash(t, DiscloseToPassphrase(handle, f.record, stringObj("regulator"), stringObj("The regulator")))
}

// A definition is read back only under the key generation it was made under:
// a rotated key tags every label differently, and the old tags are not this
// key's to vouch for.
func TestDefinitionsUnderAnotherKeyAreNotReadBack(t *testing.T) {
	run := openLifecycleRun(t, "examiner", "case_owner", "", "")
	run.attach(t)
	mustHash(t, ClassDefine(stringObj("pii")))
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("pii")))
	LedgerClose(intObj(run.ledger))
	resetCustodyForTesting()
	openTestCase(t, "IR-LIFE", "examiner", makeHashObject(map[string]object.Object{"role": stringObj("case_owner")}))
	mustHash(t, CaseKeyRotate(stringObj(run.keyPath), makeHashObject(map[string]object.Object{"mode": stringObj("case_key")})))
	run = run.next(t, "examiner", "case_owner")
	attached := run.attach(t)
	if mustHashIntValue(t, attached, "classes_read") != 0 || mustHashIntValue(t, attached, "views_read") != 0 ||
		mustHashIntValue(t, attached, "definitions_other_keys") != 2 {
		t.Fatalf("an attach under a rotated key gave %s", attached.Inspect())
	}
	if class := mustHash(t, ClassDefine(stringObj("pii"))); mustHashBoolValue(t, class, "already_defined") {
		t.Fatalf("a class defined under the old key was taken as this key's: %s", class.Inspect())
	}
}
