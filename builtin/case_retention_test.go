package builtin

import (
	"maps"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// retentionCases reads retention_list and its rows.
func retentionCases(t *testing.T, ledger object.Object, options ...object.Object) (*object.Hash, []*object.Hash) {
	t.Helper()
	list := mustHash(t, RetentionList(append([]object.Object{ledger}, options...)...))
	var rows []*object.Hash
	for _, row := range mustHashArrayValue(t, list, "cases") {
		rows = append(rows, row.(*object.Hash))
	}
	return list, rows
}

func authorityOption(name string) object.Object {
	return makeHashObject(map[string]object.Object{"authority": stringObj(name)})
}

// A retention period is set on a concluded case, which it retains; a later
// one changes it and says what it was; a date that has passed is recorded and
// said to have lapsed.
func TestARetentionPeriodRetainsAConcludedCase(t *testing.T) {
	run := custodyRun(t)
	ledger := intObj(run.ledger)
	mustRefuse(t, "a period for an active case", RetentionSet(ledger, stringObj("2033-09-28"), stringObj("x")),
		"case IR-LIFE is active, and a retention period is set on a concluded case")
	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateInReview, caseStateConcluded)
	mustRefuse(t, "a date that is not one", RetentionSet(ledger, stringObj("28/09/2033"), stringObj("x")),
		"is not a date")
	set := mustHash(t, RetentionSet(ledger, stringObj(" 2033-09-28 "), stringObj("seven years after conclusion")))
	if mustHashStringValue(t, set, "until") != "2033-09-28T00:00:00Z" || mustHashStringValue(t, set, "previous_until") != "" ||
		mustHashStringValue(t, set, "from") != caseStateConcluded || mustHashStringValue(t, set, "state") != caseStateRetained ||
		!mustHashBoolValue(t, set, "moved") || mustHashBoolValue(t, set, "lapsed") ||
		mustHashStringValue(t, set, "kind") != retentionKindSet || mustHashIntValue(t, set, "seq") != 1 {
		t.Fatalf("retention_set gave %s", set.Inspect())
	}
	if state := manifestSection(t, mustHash(t, CaseManifest()), "ledger_state"); mustHashStringValue(t, state, "state") != caseStateRetained {
		t.Fatalf("the run's copy of the case is %s", state.Inspect())
	}
	if data := timelineData(t, BuiltinNameRetentionSet); mustHashStringValue(t, data, "until") != "2033-09-28T00:00:00Z" {
		t.Fatalf("the timeline records the period as %s", data.Inspect())
	}
	mustRefuse(t, "the period the case already has", RetentionSet(ledger, stringObj("2033-09-28T01:00:00+01:00"),
		stringObj("again")), "is already kept until 2033-09-28T00:00:00Z")
	mustRefuse(t, "a release of a period", RetentionRelease(ledger, stringObj(mustHashStringValue(t, set, "uid")),
		stringObj("x")), "has no hold")

	changed := mustHash(t, RetentionSet(ledger, stringObj("2034-01-01T12:00:00+01:00"), stringObj("the court extended it")))
	if mustHashStringValue(t, changed, "until") != "2034-01-01T11:00:00Z" ||
		mustHashStringValue(t, changed, "previous_until") != "2033-09-28T00:00:00Z" ||
		mustHashStringValue(t, changed, "from") != caseStateRetained || mustHashBoolValue(t, changed, "moved") ||
		mustHashIntValue(t, changed, "seq") != 2 {
		t.Fatalf("a change of period gave %s", changed.Inspect())
	}
	late := mustHash(t, RetentionSet(ledger, stringObj("2001-01-01"), stringObj("recorded long after it ran")))
	if !mustHashBoolValue(t, late, "lapsed") {
		t.Fatalf("a period that has run gave %s", late.Inspect())
	}
	list, rows := retentionCases(t, ledger)
	if mustHashIntValue(t, list, "count") != 1 || mustHashStringValue(t, rows[0], "until") != "2001-01-01T00:00:00Z" ||
		mustHashStringValue(t, rows[0], "basis") != "recorded long after it ran" || !mustHashBoolValue(t, rows[0], "lapsed") ||
		mustHashIntValue(t, rows[0], "event_count") != 3 || mustHashStringValue(t, rows[0], "case_uid") != strings.ToLower(openCaseUID(t)) ||
		mustHashStringValue(t, rows[0], "set_by") != "alice" {
		t.Fatalf("retention_list gave %s", list.Inspect())
	}

	run = run.next(t, "alice", "case_owner")
	lifecycle := mustHashArrayValue(t, run.attach(t), "lifecycle")
	last := lifecycle[len(lifecycle)-1].(*object.Hash)
	if mustHashStringValue(t, last, "state") != caseStateRetained ||
		mustHashStringValue(t, last, "retention_uid") != mustHashStringValue(t, set, "uid") {
		t.Fatalf("the move to retained is %s", last.Inspect())
	}
}

// A legal hold stops the disposal of anything in the case until it is lifted,
// each hold is lifted on its own, and a hold says whose authority it was
// placed on.
func TestAHoldStopsEveryDisposalUntilItIsLifted(t *testing.T) {
	run := custodyRun(t)
	ledger := intObj(run.ledger)
	run.intake(t, "EXH-1", exhibitFile(t, "the drive"))
	first := mustHash(t, RetentionHold(ledger, stringObj("litigation is pending")))
	if mustHashStringValue(t, first, "authority") != "alice" || mustHashStringValue(t, first, "authority_basis") != "self" ||
		mustHashIntValue(t, first, "holds_in_force") != 1 || mustHashStringValue(t, first, "state") != caseStateActive ||
		mustHashStringValue(t, first, "kind") != retentionKindHold || mustHashIntValue(t, first, "seq") != 1 {
		t.Fatalf("retention_hold gave %s", first.Inspect())
	}
	second := mustHash(t, RetentionHold(ledger, stringObj("the regulator's inquiry"), authorityOption(" Regulator ")))
	if mustHashStringValue(t, second, "authority") != "Regulator" || mustHashStringValue(t, second, "authority_basis") != "named" ||
		mustHashIntValue(t, second, "holds_in_force") != 2 {
		t.Fatalf("a hold on another's authority gave %s", second.Inspect())
	}
	own := mustHash(t, RetentionHold(ledger, stringObj("mine"), authorityOption("alice")))
	if mustHashStringValue(t, own, "authority_basis") != "self" || mustHashIntValue(t, own, "holds_in_force") != 3 {
		t.Fatalf("a hold naming its own examiner gave %s", own.Inspect())
	}
	if data := timelineData(t, BuiltinNameRetentionHold); mustHashStringValue(t, data, "uid") != mustHashStringValue(t, own, "uid") {
		t.Fatalf("the timeline records the hold as %s", data.Inspect())
	}
	mustRefuse(t, "an empty authority", RetentionHold(ledger, stringObj("x"), authorityOption("  ")),
		"an empty name is nobody's")

	firstUID := mustHashStringValue(t, first, "uid")
	mustRefuse(t, "a disposal under three holds", EvidenceDispose(ledger, stringObj("EXH-1"), stringObj("shredded")),
		"is under 3 legal holds -- the first placed at "+mustHashStringValue(t, first, "at"))
	mustRefuse(t, "a disposal under three holds", EvidenceDispose(ledger, stringObj("EXH-1"), stringObj("shredded")),
		"retention_release(ledger, \""+firstUID+"\", reason) lifts it")
	released := mustHash(t, RetentionRelease(ledger, stringObj(strings.ToUpper(firstUID)), stringObj("settled")))
	if mustHashStringValue(t, released, "hold_uid") != firstUID ||
		mustHashStringValue(t, released, "hold_reason") != "litigation is pending" ||
		mustHashStringValue(t, released, "held_since") != mustHashStringValue(t, first, "at") ||
		mustHashIntValue(t, released, "holds_in_force") != 2 || mustHashStringValue(t, released, "kind") != retentionKindRelease {
		t.Fatalf("retention_release gave %s", released.Inspect())
	}
	mustRefuse(t, "a hold lifted twice", RetentionRelease(ledger, stringObj(firstUID), stringObj("again")),
		"was lifted at")
	mustRefuse(t, "a hold the case never had", RetentionRelease(ledger, stringObj(strings.Repeat("ab", 32)),
		stringObj("x")), "has no hold")
	mustHash(t, RetentionRelease(ledger, stringObj(mustHashStringValue(t, own, "uid")), stringObj("not needed")))
	mustRefuse(t, "a disposal under one hold", EvidenceDispose(ledger, stringObj("EXH-1"), stringObj("shredded")),
		"is under a legal hold -- the first placed at "+mustHashStringValue(t, second, "at")+" by alice, on the "+
			"authority of Regulator")
	mustHash(t, RetentionRelease(ledger, stringObj(mustHashStringValue(t, second, "uid")), stringObj("inquiry closed")))
	disposed := mustHash(t, EvidenceDispose(ledger, stringObj("EXH-1"), stringObj("shredded")))
	if mustHashStringValue(t, disposed, "state") != evidenceDisposed {
		t.Fatalf("a disposal with no hold in force gave %s", disposed.Inspect())
	}

	list, rows := retentionCases(t, ledger)
	if mustHashIntValue(t, list, "holds_in_force") != 0 || mustHashIntValue(t, rows[0], "event_count") != 6 ||
		mustHashStringValue(t, rows[0], "until") != "" || mustHashBoolValue(t, rows[0], "lapsed") {
		t.Fatalf("retention_list gave %s", list.Inspect())
	}

	// The hold is AUTHORISED_BY the authority it names, as a withdrawal is.
	session := run.session(t)
	hold, found, err := disclosureFind(session.graph, disclosureNodeRetention, "retention.uid",
		mustHashStringValue(t, second, "uid"))
	if err != nil || !found {
		t.Fatal(err, found)
	}
	assertCaseRecordEdges(t, session, hold.id, openCaseUID(t), "alice")
	edges, err := session.store.EdgesOf(hold.id, store.DirectionOutbound, []store.EdgeType{disclosureEdgeAuthorisedBy})
	if err != nil || len(edges) != 1 {
		t.Fatalf("the hold has %d AUTHORISED_BY edges: %v", len(edges), err)
	}
	node, err := session.graph.GetNode(edges[0].Dst)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := disclosureDecode(node)
	if err != nil || !node.HasLabel(disclosureNodeActor) || actor.get("actor.name") != "Regulator" {
		t.Fatalf("the hold is authorised by %v (%v)", actor.props, err)
	}
}

// A hold is placed and lifted in every state but disposed, and a disposed case
// takes no retention period or hold at all.
func TestAHoldIsPlacedInEveryStateButDisposed(t *testing.T) {
	for _, state := range caseStates {
		t.Run(state, func(t *testing.T) {
			run := openLifecycleRun(t, "alice", "case_owner", "", "")
			run.attach(t)
			ledger := intObj(run.ledger)
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
			if state == caseStateDisposed {
				const refused = "takes no retention period, or legal hold placed or lifted"
				mustRefuse(t, "a hold", RetentionHold(ledger, stringObj("x")), refused)
				mustRefuse(t, "a period", RetentionSet(ledger, stringObj("2033-09-28"), stringObj("x")), refused)
				mustRefuse(t, "a release", RetentionRelease(ledger, stringObj(strings.Repeat("ab", 32)),
					stringObj("x")), refused)
				return
			}
			hold := mustHash(t, RetentionHold(ledger, stringObj("x")))
			if mustHashStringValue(t, hold, "state") != state {
				t.Fatalf("a hold on a case that is %s gave %s", state, hold.Inspect())
			}
			mustHash(t, RetentionRelease(ledger, stringObj(mustHashStringValue(t, hold, "uid")), stringObj("y")))
		})
	}
}

// A retention chain this program did not write is refused by every reader --
// the list, the writers, and the disposal a hold would stop -- rather than
// resolved.
func TestARetentionChainThisProgramDidNotWriteIsRefused(t *testing.T) {
	eventLike := func(w *caseWriter, kind string, extra map[string]string) map[string]string {
		props := map[string]string{"retention.case_uid": w.caseUID, "retention.case_id": w.caseID,
			"retention.kind": kind, "retention.reason": "forged", "retention.by": "mallory"}
		maps.Copy(props, extra)
		return props
	}
	// chain appends each event after the one before it.
	chain := func(events ...func(w *caseWriter, previous *caseChainEvent) map[string]string) func(w *caseWriter) error {
		return func(w *caseWriter) error {
			var head *caseChainEvent
			for _, props := range events {
				_, event, err := w.tx.chainAppend(retentionChain, w.caseUID, head, props(w, head))
				if err != nil {
					return err
				}
				head = &event
			}
			return nil
		}
	}
	event := func(kind string, extra map[string]string) func(w *caseWriter, previous *caseChainEvent) map[string]string {
		return func(w *caseWriter, previous *caseChainEvent) map[string]string { return eventLike(w, kind, extra) }
	}
	releaseOfPrevious := func(w *caseWriter, previous *caseChainEvent) map[string]string {
		return eventLike(w, retentionKindRelease, map[string]string{"retention.hold_uid": previous.uid})
	}
	for _, tc := range []struct {
		name  string
		forge func(w *caseWriter) error
		want  string
	}{
		{"an event of another case", chain(event(retentionKindHold, map[string]string{"retention.case_uid": "another"})),
			"names case another"},
		{"an event this program does not record", chain(event("extend", nil)), "records a \"extend\""},
		{"a period that is not a time", chain(event(retentionKindSet, map[string]string{"retention.until": "tomorrow"})),
			"keeps the case until \"tomorrow\", which is not a time"},
		{"a release of no hold", chain(event(retentionKindRelease, map[string]string{
			"retention.hold_uid": strings.Repeat("ab", 32)})), "which is not a hold in force before it"},
		{"a release of a period", chain(event(retentionKindSet, map[string]string{
			"retention.until": "2033-09-28T00:00:00Z"}), releaseOfPrevious), "which is not a hold in force before it"},
		{"a hold lifted twice", func(w *caseWriter) error {
			_, hold, err := w.tx.chainAppend(retentionChain, w.caseUID, nil, eventLike(w, retentionKindHold, nil))
			if err != nil {
				return err
			}
			head := &hold
			for range 2 {
				_, release, err := w.tx.chainAppend(retentionChain, w.caseUID, head, eventLike(w, retentionKindRelease,
					map[string]string{"retention.hold_uid": hold.uid}))
				if err != nil {
					return err
				}
				head = &release
			}
			return nil
		}, "which is not a hold in force before it"},
		{"two first events", func(w *caseWriter) error {
			if err := chain(event(retentionKindHold, nil))(w); err != nil {
				return err
			}
			return chain(event(retentionKindHold, map[string]string{"retention.reason": "another"}))(w)
		}, "two retention events after the start of the chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := custodyRun(t)
			ledger := intObj(run.ledger)
			run.intake(t, "EXH-1", exhibitFile(t, "the drive"))
			forgeCaseRecord(t, run.session(t), tc.forge)
			mustRefuse(t, "retention_list", RetentionList(ledger), tc.want)
			mustRefuse(t, "retention_hold", RetentionHold(ledger, stringObj("x")), tc.want)
			mustRefuse(t, "evidence_dispose", EvidenceDispose(ledger, stringObj("EXH-1"), stringObj("x")), tc.want)
		})
	}
}

// review_list and retention_list read every case in a ledger, or the one a
// case_uid names, and a reviewer attached to one case decides nothing of
// another's.
func TestTheReviewAndRetentionListsReadEveryCaseOrOne(t *testing.T) {
	useTestKeyStore(t)
	begin := func(run *lifecycleRun, note string) *object.Hash {
		ledger := intObj(run.ledger)
		run.attach(t)
		mustHash(t, CaseTransition(ledger, stringObj("active"), stringObj("begin")))
		mustHash(t, CaseAssign(ledger, stringObj("bob"), stringObj("reviewer"), stringObj("peer review")))
		mustHash(t, RetentionHold(ledger, stringObj(note+"'s hold")))
		return mustHash(t, ReviewRequest(ledger, stringObj("case"), stringObj(note), manifestOption(writeManifest(t))))
	}
	first := openLifecycleRun(t, "alice", "case_owner", "", "")
	firstRequest := begin(first, "the first case")
	firstUID := strings.ToLower(openCaseUID(t))
	LedgerClose(intObj(first.ledger))
	resetCustodyForTesting()
	// A new key is another case, attached to the same ledger.
	second := openLifecycleRun(t, "alice", "case_owner", "", first.ledgerDir)
	begin(second, "the second case")
	secondUID := strings.ToLower(openCaseUID(t))
	if firstUID == secondUID {
		t.Fatal("the two runs opened one case")
	}
	ledger := intObj(second.ledger)

	list, rows := reviewRows(t, ledger)
	if mustHashIntValue(t, list, "count") != 2 || mustHashIntValue(t, list, "pending") != 2 ||
		mustHashStringValue(t, rows[0], "case_uid") >= mustHashStringValue(t, rows[1], "case_uid") {
		t.Fatalf("review_list of both cases gave %s", list.Inspect())
	}
	for _, one := range []struct{ uid, note string }{{firstUID, "the first case"}, {secondUID, "the second case"}} {
		list, rows := reviewRows(t, ledger, makeHashObject(map[string]object.Object{
			"case_uid": stringObj(" " + strings.ToUpper(one.uid) + " ")}))
		if mustHashIntValue(t, list, "count") != 1 || mustHashStringValue(t, rows[0], "case_uid") != one.uid ||
			mustHashStringValue(t, rows[0], "note") != one.note {
			t.Fatalf("review_list of case %s gave %s", one.uid, list.Inspect())
		}
		list, cases := retentionCases(t, ledger, makeHashObject(map[string]object.Object{
			"case_uid": stringObj(" " + strings.ToUpper(one.uid) + " ")}))
		if mustHashIntValue(t, list, "count") != 1 || mustHashStringValue(t, cases[0], "case_uid") != one.uid ||
			mustHashIntValue(t, list, "holds_in_force") != 1 || mustHashIntValue(t, cases[0], "holds_in_force") != 1 {
			t.Fatalf("retention_list of case %s gave %s", one.uid, list.Inspect())
		}
		holds := mustHashArrayValue(t, cases[0], "holds")
		if len(holds) != 1 || mustHashStringValue(t, holds[0].(*object.Hash), "reason") != one.note+"'s hold" {
			t.Fatalf("retention_list of case %s holds %v", one.uid, holds)
		}
	}
	list, cases := retentionCases(t, ledger)
	if mustHashIntValue(t, list, "count") != 2 || mustHashIntValue(t, list, "holds_in_force") != 2 ||
		mustHashStringValue(t, cases[0], "case_uid") >= mustHashStringValue(t, cases[1], "case_uid") {
		t.Fatalf("retention_list of both cases gave %s", list.Inspect())
	}
	if list, _ := retentionCases(t, ledger, makeHashObject(map[string]object.Object{
		"case_uid": stringObj(strings.Repeat("0", 32))})); mustHashIntValue(t, list, "count") != 0 {
		t.Fatalf("retention_list of a case the ledger does not hold gave %s", list.Inspect())
	}

	second = second.next(t, "bob", "reviewer")
	second.attach(t)
	mustRefuse(t, "another case's request", ReviewDecide(intObj(second.ledger),
		stringObj(mustHashStringValue(t, firstRequest, "uid")), stringObj("approved"), stringObj("x")),
		"has no review request")
}
