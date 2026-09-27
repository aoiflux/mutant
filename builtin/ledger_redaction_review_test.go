package builtin

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// testLedgerSession resolves a test's ledger handle to its session.
func testLedgerSession(t *testing.T, handle int64) *ledgerSession {
	t.Helper()
	session, errObj := ledgerHandleArg(intObj(handle), "test")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	return session
}

// redactBeforeTheGuard redacts the way a build from before the disclosure
// schema was guarded could: through graphene, with no role, and without
// asking what the entity is.
func redactBeforeTheGuard(t *testing.T, handle int64, scope disk.RedactionScope, node store.NodeID,
	edge store.EdgeID) disk.RedactionRecord {
	t.Helper()
	session := testLedgerSession(t, handle)
	req := disk.RedactionRequest{ActorID: session.actorID, Reason: "made by a build that recorded no role"}
	var record disk.RedactionRecord
	var err error
	switch {
	case scope == disk.ScopeNode:
		record, err = session.store.RedactNode(node, req)
	case scope == disk.ScopeProperties && edge == 0:
		record, err = session.store.RedactNodeProperties(node, req)
	case scope == disk.ScopeProperties:
		record, err = session.store.RedactEdgeProperties(edge, req)
	default:
		record, err = session.store.RedactEdge(edge, req)
	}
	if err != nil {
		t.Fatalf("redacting before the guard: %v", err)
	}
	if record.RoleID != 0 {
		t.Fatalf("the redaction recorded role id %d, and a build before the guard recorded none", record.RoleID)
	}
	return record
}

// reopen closes the fixture's ledger and opens it again, as a later run
// would.
func (f *discloseFixture) reopen(t *testing.T) {
	t.Helper()
	LedgerClose(intObj(f.ledger))
	payload, errObj := unwrapPair(t, LedgerOpen(stringObj(f.ledgerDir), stringObj("examiner")))
	if errObj != nil {
		t.Fatalf("ledger_open: %s", errObj.Message)
	}
	f.ledger = mustHashIntValue(t, payload.(*object.Hash), "handle")
	reopened := f.ledger
	t.Cleanup(func() { LedgerClose(intObj(reopened)) })
}

// scriptNode writes a node the way a script does, and returns its id.
func (f *discloseFixture) scriptNode(t *testing.T, note string) int64 {
	t.Helper()
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(f.ledger),
		ledgerProps(map[string]string{"note": note}), intObj(3)))
	return mustHashIntValue(t, written, "id")
}

// scriptEdge writes an edge the way a script does, and returns its id.
func (f *discloseFixture) scriptEdge(t *testing.T, src, dst int64) int64 {
	t.Helper()
	written := mustLedgerHash(t, BuiltinNameLedgerAddEdge, LedgerAddEdge(intObj(f.ledger), intObj(src),
		intObj(dst), ledgerProps(map[string]string{"why": "seen together"})))
	return mustHashIntValue(t, written, "id")
}

// seqsOf reads an ARRAY of INTEGER field.
func seqsOf(t *testing.T, h *object.Hash, key string) []int64 {
	t.Helper()
	array, ok := mustHashValue(t, h, key).(*object.Array)
	if !ok {
		t.Fatalf("%s is not an ARRAY", key)
	}
	out := []int64{}
	for _, element := range array.Elements {
		n, ok := element.(*object.Integer)
		if !ok {
			t.Fatalf("%s holds %s, not an INTEGER", key, element.Inspect())
		}
		out = append(out, n.Value)
	}
	return out
}

func wantSeqs(t *testing.T, what string, h *object.Hash, key string, want ...int64) {
	t.Helper()
	if want == nil {
		want = []int64{}
	}
	if got := seqsOf(t, h, key); !slices.Equal(got, want) {
		t.Errorf("%s: %s = %v, want %v", what, key, got, want)
	}
}

// M26-CUS-021. The redaction builtins refuse a record of the disclosure schema
// now (M26-CUS-001), and a ledger redacted before that could have lost a
// withdrawal, a disclosure or a reclassification without a word: graphene's
// redaction record keeps what it removed by id and hash, never by label. On
// the tree before this fix, a withdrawal removed that way let the record be
// disclosed again to the recipient it was withdrawn from. Every grant from such
// a ledger now waits until an examiner answers for the redactions.
func TestAnUnguardedRedactionStopsGrantsUntilReviewed(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("classification under review")))
	withdrawal, found, err := disclosureWithdrawalOf(testLedgerSession(t, f.ledger).graph, uid)
	if err != nil || !found {
		t.Fatalf("no withdrawal to redact: %v", err)
	}
	record := redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, withdrawal.id, 0)
	f.reopen(t)

	want := fmt.Sprintf("ledger_redactions_review(ledger, %d, reason)", record.Seq)
	f.assign(t, "Someone new")
	for _, recipient := range []string{"Counsel", "Someone new"} {
		issued, prompts := countDisclosureWork(t)
		_, errObj := unwrapPairNoFatal(DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"),
			stringObj(recipient)))
		if errObj == nil || !strings.Contains(errObj.Message, want) {
			t.Fatalf("a grant to %s was not refused on a ledger an unguarded redaction may have taken a withdrawal "+
				"from: %v", recipient, errObj)
		}
		if *issued != 0 || *prompts != 0 {
			t.Errorf("the refusal came after %d grant(s) and %d passphrase prompt(s)", *issued, *prompts)
		}
	}
	history := mustHash(t, DiscloseHistory(intObj(f.ledger)))
	wantSeqs(t, "disclose_history before the review", history, "unguarded_redactions", int64(record.Seq))
	if got := mustHashIntValue(t, history, "withdrawn"); got != 0 {
		t.Fatalf("the history counts %d withdrawn; the redaction removed the only withdrawal", got)
	}

	// What can be recorded again is, and then the examiner answers for the
	// redaction.
	mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(uid),
		stringObj("recorded again: the first record of this withdrawal was redacted")))
	reviewed := mustHash(t, LedgerRedactionsReview(intObj(f.ledger), intObj(int64(record.Seq)),
		stringObj("redaction 1 was checked against the case notes; the withdrawal it removed is recorded again")))
	wantSeqs(t, "the review", reviewed, "reviewed", int64(record.Seq))
	wantSeqs(t, "the review", reviewed, "unguarded_redactions")
	if mustHashBoolValue(t, reviewed, "role_authenticated") {
		t.Error("a review says the role it was made under was authenticated")
	}

	history = mustHash(t, DiscloseHistory(intObj(f.ledger)))
	wantSeqs(t, "disclose_history after the review", history, "unguarded_redactions")
	if got := mustHashIntValue(t, history, "withdrawn"); got != 1 {
		t.Errorf("the history counts %d withdrawn after the withdrawal was recorded again, want 1", got)
	}
	mustRefuse(t, "a grant to the recipient withdrawn again", DiscloseToPassphrase(intObj(f.ledger), f.record,
		stringObj("counsel"), stringObj("Counsel")), "was withdrawn")
	f.issue(t, "counsel", "Someone new")
}

// Every answer read from the disclosure records names the redactions no review
// answers for, including the answer that the ledger knows nothing of a record.
func TestEveryAnswerFromTheDisclosureRecordsNamesTheUnguardedRedactions(t *testing.T) {
	f := newDiscloseFixture(t)
	recordUID := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "record_uid")
	record := redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, store.NodeID(f.scriptNode(t, "a scratch note")), 0)
	newRecord, _ := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(150), stringObj("restricted"))),
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	))
	unknown := strings.Repeat("0", 32)
	h := intObj(f.ledger)
	answers := func() []struct {
		name   string
		result object.Object
	} {
		return []struct {
			name   string
			result object.Object
		}{
			{"disclose_history", DiscloseHistory(h)},
			{"disclose_for_segment", DiscloseForSegment(h, stringObj(recordUID), intObj(0))},
			{"disclose_for_segment of a record the ledger does not know", DiscloseForSegment(h, stringObj(unknown),
				intObj(0))},
			{"redaction_versions", RedactionVersions(h, stringObj(recordUID))},
			{"redaction_versions of a record the ledger does not know", RedactionVersions(h, stringObj(unknown))},
			{"disclose_reclassified", DiscloseReclassified(h, newRecord, f.record)},
			{"ledger_redactions", LedgerRedactions(h)},
		}
	}
	for _, answer := range answers() {
		wantSeqs(t, answer.name+" before the review", mustHash(t, answer.result), "unguarded_redactions",
			int64(record.Seq))
	}
	mustHash(t, LedgerRedactionsReview(h, intObj(int64(record.Seq)), stringObj("a scratch node, not a record")))
	for _, answer := range answers() {
		wantSeqs(t, answer.name+" after the review", mustHash(t, answer.result), "unguarded_redactions")
	}
}

// A withdrawal names the record and the recipient itself, so one whose
// disclosure a redaction removed before the guard still stops a new grant --
// to that recipient, of that record, and to nobody else.
func TestAWithdrawalOutlivesTheDisclosureARedactionRemoved(t *testing.T) {
	f := newDiscloseFixture(t)
	counsel := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	other := keyFieldString(t, f.issue(t, "counsel", "Other"), "disclosure_uid")
	second, _ := f.reseal(t, recordArray(mustHash(t, RecordClassifyRange(intObj(100), intObj(60), stringObj("pii")))))
	registrar := keyFieldString(t, f.issueFrom(t, second, "counsel", "Registrar"), "disclosure_uid")
	for _, uid := range []string{counsel, other, registrar} {
		mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("classification under review")))
	}

	disclosure, found, err := disclosureFind(testLedgerSession(t, f.ledger).graph, disclosureNodeDisclosure,
		"disclosure.uid", counsel)
	if err != nil || !found {
		t.Fatalf("no disclosure to redact: %v", err)
	}
	record := redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, disclosure.id, 0)
	mustHash(t, LedgerRedactionsReview(intObj(f.ledger), intObj(int64(record.Seq)),
		stringObj("the disclosure to Counsel was removed; its withdrawal is still in the ledger")))
	if got := mustHashIntValue(t, mustHash(t, DiscloseHistory(intObj(f.ledger))), "count"); got != 2 {
		t.Fatalf("the history lists %d disclosures; the redaction was to have removed one of three", got)
	}

	mustRefuse(t, "a grant to the recipient whose disclosure was removed", DiscloseToPassphrase(intObj(f.ledger),
		f.record, stringObj("counsel"), stringObj("Counsel")), "disclosure "+counsel+", withdrawn at")
	// Withdrawn from the second record only.
	f.issue(t, "counsel", "Registrar")
	// Nobody withdrew anything from this recipient; Other's withdrawal is
	// Other's.
	f.issue(t, "counsel", "Somebody else")
}

// Only a redaction the schema's guard may not have seen is in question: one
// recorded with no role, unless it stripped the properties of a node or an
// edge a script wrote that the ledger still holds.
func TestOnlyARedactionTheGuardMayNotHaveSeenIsInQuestion(t *testing.T) {
	f := newDiscloseFixture(t)
	f.issue(t, "counsel", "Counsel")
	p, q, r, s, u, v, w := f.scriptNode(t, "p"), f.scriptNode(t, "q"), f.scriptNode(t, "r"), f.scriptNode(t, "s"),
		f.scriptNode(t, "u"), f.scriptNode(t, "v"), f.scriptNode(t, "w")
	kept, removed := f.scriptEdge(t, s, u), f.scriptEdge(t, s, v)
	g := testLedgerSession(t, f.ledger).graph
	recipients, err := disclosureAll(g, disclosureNodeRecipient)
	if err != nil || len(recipients) == 0 {
		t.Fatalf("the fixture wrote no Recipient node: %v", err)
	}
	disclosures, err := disclosureAll(g, disclosureNodeDisclosure)
	if err != nil || len(disclosures) == 0 {
		t.Fatalf("the fixture wrote no Disclosure node: %v", err)
	}
	grants, err := g.EdgesOf(disclosures[0].id, store.DirectionOutbound, []store.EdgeType{disclosureEdgeGrants})
	if err != nil || len(grants) != 1 {
		t.Fatalf("the disclosure has %d GRANTS edges: %v", len(grants), err)
	}

	listed := func() *object.Hash {
		return mustLedgerHash(t, BuiltinNameLedgerRedactions, LedgerRedactions(intObj(f.ledger)))
	}
	rows := func() map[int64]bool {
		out := map[int64]bool{}
		for _, row := range mustHashValue(t, listed(), "redactions").(*object.Array).Elements {
			out[mustHashIntValue(t, row.(*object.Hash), "seq")] = mustHashBoolValue(t, row.(*object.Hash), "unguarded")
		}
		return out
	}

	cases := []struct {
		what      string
		record    disk.RedactionRecord
		unguarded bool
	}{
		{"a script node's properties, the node still here",
			redactBeforeTheGuard(t, f.ledger, disk.ScopeProperties, store.NodeID(p), 0), false},
		{"a script edge's properties, the edge still here",
			redactBeforeTheGuard(t, f.ledger, disk.ScopeProperties, 0, store.EdgeID(kept)), false},
		{"a script node removed outright",
			redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, store.NodeID(q), 0), true},
		{"a script edge removed outright",
			redactBeforeTheGuard(t, f.ledger, disk.ScopeEdge, 0, store.EdgeID(removed)), true},
		{"a schema record's properties",
			redactBeforeTheGuard(t, f.ledger, disk.ScopeProperties, recipients[0].id, 0), true},
		{"a schema edge's properties",
			redactBeforeTheGuard(t, f.ledger, disk.ScopeProperties, 0, grants[0].ID), true},
	}
	stripped := redactBeforeTheGuard(t, f.ledger, disk.ScopeProperties, store.NodeID(r), 0)
	got := rows()
	for _, c := range cases {
		if got[int64(c.record.Seq)] != c.unguarded {
			t.Errorf("%s (redaction %d): unguarded = %v, want %v", c.what, c.record.Seq, got[int64(c.record.Seq)],
				c.unguarded)
		}
	}
	if got[int64(stripped.Seq)] {
		t.Errorf("a script node's properties, stripped with the node still here, are in question")
	}

	// Once the node or the edge goes too -- under a role, so that redaction
	// is not in question -- the one before it is: nothing is left to say what
	// it was.
	var underRole []*object.Hash
	for _, c := range []struct {
		name   string
		result object.Object
	}{
		{BuiltinNameLedgerRedactNode, LedgerRedactNode(intObj(f.ledger), intObj(r), stringObj("court order 12"))},
		{BuiltinNameLedgerRedactEdge, LedgerRedactEdge(intObj(f.ledger), intObj(kept), stringObj("court order 13"))},
		{BuiltinNameLedgerRedactNode, LedgerRedactNode(intObj(f.ledger), intObj(w), stringObj("court order 14"))},
	} {
		underRole = append(underRole, mustLedgerHash(t, c.name, c.result))
	}
	got = rows()
	if !got[int64(stripped.Seq)] {
		t.Error("a property redaction of a node since removed is not in question")
	}
	if !got[int64(cases[1].record.Seq)] {
		t.Error("a property redaction of an edge since removed is not in question")
	}
	for _, guarded := range underRole {
		if seq := mustHashIntValue(t, guarded, "seq"); got[seq] {
			t.Errorf("redaction %d, made under a role, is in question", seq)
		}
	}
	wantSeqs(t, "ledger_redactions", listed(), "unguarded_redactions", int64(cases[1].record.Seq),
		int64(cases[2].record.Seq), int64(cases[3].record.Seq), int64(cases[4].record.Seq),
		int64(cases[5].record.Seq), int64(stripped.Seq))

	// A grant is refused naming every one of them, and the review that would
	// answer for them all.
	_, errObj := unwrapPairNoFatal(DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"),
		stringObj("Counsel")))
	for _, want := range []string{
		fmt.Sprintf("(%d, %d, %d, %d, %d and %d), made by a build", cases[1].record.Seq, cases[2].record.Seq,
			cases[3].record.Seq, cases[4].record.Seq, cases[5].record.Seq, stripped.Seq),
		fmt.Sprintf("ledger_redactions_review(ledger, %d, reason)", stripped.Seq),
	} {
		if errObj == nil || !strings.Contains(errObj.Message, want) {
			t.Errorf("the grant was not refused saying %q: %v", want, errObj)
		}
	}
}

// A review answers for the redactions in question up to the one it names, and
// for no other; the chain of reviews only moves forward.
func TestAReviewAnswersForTheRedactionsItNamesAndNoMore(t *testing.T) {
	f := newDiscloseFixture(t)
	h := intObj(f.ledger)
	reason := stringObj("checked against the case notes")
	mustRefuse(t, "a review of a ledger with no redactions", LedgerRedactionsReview(h, intObj(1), reason),
		"records no redactions")

	first := redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, store.NodeID(f.scriptNode(t, "a")), 0)
	guarded := mustLedgerHash(t, BuiltinNameLedgerRedactNode, LedgerRedactNode(h, intObj(f.scriptNode(t, "c")),
		stringObj("court order 14")))
	second := redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, store.NodeID(f.scriptNode(t, "b")), 0)
	if first.Seq != 1 || mustHashIntValue(t, guarded, "seq") != 2 || second.Seq != 3 {
		t.Fatalf("the redactions are %d, %d and %d, and this test is written for 1, 2 and 3", first.Seq,
			mustHashIntValue(t, guarded, "seq"), second.Seq)
	}

	for _, c := range []struct {
		what string
		args []object.Object
		want string
	}{
		{"no arguments", nil, "wrong number of arguments"},
		{"a missing reason", []object.Object{h, intObj(1)}, "wrong number of arguments"},
		{"a sequence number that is not an integer", []object.Object{h, stringObj("1"), reason}, "must be INTEGER"},
		{"sequence number 0", []object.Object{h, intObj(0), reason}, "numbered from 1"},
		{"a sequence number past the last", []object.Object{h, intObj(4), reason}, "no redaction 4; its last is 3"},
		{"a reason of spaces", []object.Object{h, intObj(1), stringObj("   ")}, "must not be empty"},
	} {
		mustRefuse(t, c.what, LedgerRedactionsReview(c.args...), c.want)
	}

	one := mustHash(t, LedgerRedactionsReview(h, intObj(1), stringObj("redaction 1 removed a scratch node")))
	wantSeqs(t, "the first review", one, "reviewed", 1)
	wantSeqs(t, "the first review", one, "unguarded_redactions", 3)
	if mustHashIntValue(t, one, "seq") != 1 || mustHashIntValue(t, one, "through_seq") != 1 ||
		mustHashIntValue(t, one, "previous_through") != 0 {
		t.Fatalf("the first review is %s", one.Inspect())
	}
	f.assign(t, "Counsel")
	mustRefuse(t, "a grant while redaction 3 is unreviewed", DiscloseToPassphrase(h, f.record, stringObj("counsel"),
		stringObj("Counsel")), "(3), made by a build")
	mustRefuse(t, "the same range again", LedgerRedactionsReview(h, intObj(1), reason),
		"the redactions through 1 were answered for by review 1")
	mustRefuse(t, "a range holding only a redaction made under a role", LedgerRedactionsReview(h, intObj(2), reason),
		"no redaction after 1 up to 2 is in question")

	two := mustHash(t, LedgerRedactionsReview(h, intObj(3), stringObj("redaction 3 removed a scratch node too")))
	wantSeqs(t, "the second review", two, "reviewed", 3)
	wantSeqs(t, "the second review", two, "unguarded_redactions")
	if mustHashIntValue(t, two, "seq") != 2 || mustHashIntValue(t, two, "previous_through") != 1 {
		t.Fatalf("the second review is %s", two.Inspect())
	}
	// The open case's timeline says what was reviewed, and under which review.
	var event custodyEvent
	custodyStore.RLock()
	for _, e := range slices.Backward(custodyStore.session.timeline) {
		if e.Event == BuiltinNameLedgerRedactionsReview {
			event = e
			break
		}
	}
	custodyStore.RUnlock()
	if data, _ := event.Data.(map[string]any); !strings.Contains(event.Detail, "redactions 3 of ledger") ||
		data["through_seq"] != int64(3) || data["remaining"] != int64(0) ||
		data["review_uid"] != keyFieldString(t, two, "uid") {
		t.Errorf("the case's timeline records the review as %q %v", event.Detail, event.Data)
	}

	listed := mustLedgerHash(t, BuiltinNameLedgerRedactions, LedgerRedactions(h))
	if got := mustHashIntValue(t, listed, "reviewed_through"); got != 3 {
		t.Errorf("reviewed_through = %d, want 3", got)
	}
	if !mustHashBoolValue(t, listed, "reviews_intact") || mustHashStringValue(t, listed, "reviews_reason") != "" {
		t.Errorf("the reviews read as not intact: %s", listed.Inspect())
	}
	for i, row := range mustHashValue(t, listed, "redactions").(*object.Array).Elements {
		// A review answers for a redaction; it does not change what the
		// redaction was.
		if got, want := mustHashBoolValue(t, row.(*object.Hash), "unguarded"), i != 1; got != want {
			t.Errorf("redaction %d: unguarded = %v, want %v", i+1, got, want)
		}
		if i == 0 && keyFieldString(t, row.(*object.Hash), "hash") != keyFieldString(t, one, "through_hash") {
			t.Error("the first review is not bound to the hash of the redaction record it names")
		}
	}

	// The reviews are one chain, each joined to the one before it and to the
	// examiner who recorded it, under the role they asserted.
	session := testLedgerSession(t, f.ledger)
	reviews, err := caseChainRead(session.graph, redactionReviewChain, redactionReviewChainKey)
	if err != nil || len(reviews) != 2 {
		t.Fatalf("the ledger holds %d reviews: %v", len(reviews), err)
	}
	edges, err := session.graph.EdgesOf(reviews[1].id, store.DirectionOutbound, nil)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[store.EdgeType]store.NodeID{}
	for _, edge := range edges {
		for _, label := range edge.Labels {
			labels[label] = edge.Dst
		}
	}
	if labels[disclosureEdgeRevises] != reviews[0].id || len(labels) != 2 {
		t.Errorf("the second review's edges are %v", labels)
	}
	if actor, err := session.graph.GetNode(labels[disclosureEdgePerformedBy]); err != nil ||
		!actor.HasLabel(disclosureNodeActor) {
		t.Errorf("the second review is not performed by an Actor: %v", err)
	}
	f.issue(t, "counsel", "Counsel")
}

// A review is bound to the hash of the redaction record it names, and each
// reaches further than the one before it. A chain of reviews that says
// otherwise was not written by this program: it counts for nothing, every
// answer that acts on it refuses, and ledger_redactions still lists the
// redactions and says why.
func TestAReviewIsBoundToTheRedactionRecordItNames(t *testing.T) {
	for _, c := range []struct {
		name    string
		through func(first disk.RedactionRecord) (string, string)
		want    string
	}{
		{"a hash the record never had", func(first disk.RedactionRecord) (string, string) {
			return "1", strings.Repeat("ab", 32)
		}, "the review was not made of the redactions this ledger holds"},
		{"a redaction the ledger does not hold", func(first disk.RedactionRecord) (string, string) {
			return "7", ledgerHash(first.Hash)
		}, "the review was not made of the redactions this ledger holds"},
		{"a review that reaches nowhere", func(first disk.RedactionRecord) (string, string) {
			return "0", ledgerHash(first.Hash)
		}, "which is not after the review before it (0)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newDiscloseFixture(t)
			first := redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, store.NodeID(f.scriptNode(t, "a")), 0)
			session := testLedgerSession(t, f.ledger)
			seq, hash := c.through(first)
			tx := disclosureBegin(session)
			if _, _, err := tx.chainAppend(redactionReviewChain, redactionReviewChainKey, nil, map[string]string{
				"redaction_review.through_seq":  seq,
				"redaction_review.through_hash": hash,
				"redaction_review.reason":       "written by something else",
			}); err != nil {
				t.Fatal(err)
			}
			if err := tx.commit(); err != nil {
				t.Fatal(err)
			}

			listed := mustLedgerHash(t, BuiltinNameLedgerRedactions, LedgerRedactions(intObj(f.ledger)))
			if mustHashBoolValue(t, listed, "reviews_intact") ||
				!strings.Contains(mustHashStringValue(t, listed, "reviews_reason"), c.want) {
				t.Fatalf("ledger_redactions reads a forged review as %s", listed.Inspect())
			}
			if got := mustHashIntValue(t, listed, "reviewed_through"); got != 0 {
				t.Errorf("a forged review counts through %d", got)
			}
			wantSeqs(t, "ledger_redactions", listed, "unguarded_redactions", int64(first.Seq))
			if got := mustHashIntValue(t, listed, "count"); got != 1 {
				t.Errorf("ledger_redactions listed %d redactions, want 1", got)
			}

			f.assign(t, "Counsel")
			issued, prompts := countDisclosureWork(t)
			mustRefuse(t, "a grant", DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"),
				stringObj("Counsel")), c.want)
			if *issued != 0 || *prompts != 0 {
				t.Errorf("the refusal came after %d grant(s) and %d passphrase prompt(s)", *issued, *prompts)
			}
			mustRefuse(t, "disclose_history", DiscloseHistory(intObj(f.ledger)), c.want)
			mustRefuse(t, "a review after it", LedgerRedactionsReview(intObj(f.ledger), intObj(1),
				stringObj("checked")), c.want)
			// Refused before it writes, not after.
			newRecord, _ := f.reseal(t, recordArray(mustHash(t, RecordClassifyRange(intObj(100), intObj(60),
				stringObj("restricted")))))
			mustRefuse(t, "a reclassification", DiscloseReclassified(intObj(f.ledger), newRecord, f.record), c.want)
			if events, err := disclosureAll(session.graph, disclosureNodeReclass); err != nil || len(events) != 0 {
				t.Errorf("a refused reclassification left %d ReclassEvent node(s): %v", len(events), err)
			}
		})
	}
}

// The keys every reader looks a review up by are indexed. Named here, not read
// from disclosureKeys, so that a key dropped from that table fails this test.
func TestARedactionReviewIsFoundByEachOfItsLookupKeys(t *testing.T) {
	f := newDiscloseFixture(t)
	record := redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, store.NodeID(f.scriptNode(t, "a")), 0)
	mustHash(t, LedgerRedactionsReview(intObj(f.ledger), intObj(int64(record.Seq)), stringObj("checked")))
	g := testLedgerSession(t, f.ledger).graph
	reviews, err := disclosureAll(g, disclosureNodeRedactionReview)
	if err != nil || len(reviews) != 1 {
		t.Fatalf("the ledger holds %d reviews: %v", len(reviews), err)
	}
	for _, key := range []string{"redaction_review.uid", "redaction_review.chain"} {
		ids, err := g.NodesByProperty(key, []byte(reviews[0].get(key)))
		if err != nil || !slices.Contains(ids, reviews[0].id) {
			t.Errorf("the review is not found by %s = %q: %v %v", key, reviews[0].get(key), ids, err)
		}
	}
}

// The review and every answer that names what it answers for return the
// fields their documentation declares.
func TestTheReviewAndTheAnswersNamingUnguardedRedactionsReturnTheDeclaredFields(t *testing.T) {
	f := newDiscloseFixture(t)
	recordUID := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "record_uid")
	record := redactBeforeTheGuard(t, f.ledger, disk.ScopeNode, store.NodeID(f.scriptNode(t, "a")), 0)
	newRecord, _ := f.reseal(t, recordArray(mustHash(t, RecordClassifyRange(intObj(100), intObj(60),
		stringObj("restricted")))))
	h := intObj(f.ledger)
	for _, c := range []struct {
		name   string
		result object.Object
	}{
		{BuiltinNameDiscloseHistory, DiscloseHistory(h)},
		{BuiltinNameDiscloseForSegment, DiscloseForSegment(h, stringObj(recordUID), intObj(0))},
		{BuiltinNameRedactionVersions, RedactionVersions(h, stringObj(recordUID))},
		{BuiltinNameDiscloseReclassified, DiscloseReclassified(h, newRecord, f.record)},
		{BuiltinNameLedgerRedactionsReview, LedgerRedactionsReview(h, intObj(int64(record.Seq)), stringObj("checked"))},
	} {
		payload, errObj := unwrapPair(t, c.result)
		if errObj != nil {
			t.Fatalf("%s: %s", c.name, errObj.Message)
		}
		assertLedgerDeclaredFields(t, c.name, payload)
	}
}
