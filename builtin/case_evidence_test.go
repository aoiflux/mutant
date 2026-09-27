package builtin

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// exhibitFile writes a file an exhibit is taken in from.
func exhibitFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exhibit.img")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// custodyRun is a lifecycle run with the case attached, active, and bob
// assigned as an investigator beside its owner.
func custodyRun(t *testing.T) *lifecycleRun {
	t.Helper()
	run := openLifecycleRun(t, "alice", "case_owner", "", "")
	run.attach(t)
	mustHash(t, CaseTransition(intObj(run.ledger), stringObj("active"), stringObj("work begins")))
	mustHash(t, CaseAssign(intObj(run.ledger), stringObj("bob"), stringObj("investigator"), stringObj("joins")))
	return run
}

func (r *lifecycleRun) intake(t *testing.T, exhibit, path string) *object.Hash {
	t.Helper()
	return mustHash(t, EvidenceIntake(intObj(r.ledger), stringObj(exhibit), stringObj(path)))
}

// exhibitHistory reads one exhibit's history row.
func exhibitHistory(t *testing.T, ledger int64, exhibit string) *object.Hash {
	t.Helper()
	history := mustHash(t, EvidenceHistory(intObj(ledger), makeHashObject(map[string]object.Object{
		"exhibit": stringObj(exhibit)})))
	rows := mustHashArrayValue(t, history, "exhibits")
	if len(rows) != 1 {
		t.Fatalf("evidence_history found %d exhibits named %s", len(rows), exhibit)
	}
	return rows[0].(*object.Hash)
}

// An exhibit is taken in, released, accepted by the person it was released
// to after they hash it, and returned; the ledger holds each step, a later
// run reads them back, and the exhibit is where the last step left it.
func TestAnExhibitsCustodyIsAChainOfHandOffs(t *testing.T) {
	run := custodyRun(t)
	path := exhibitFile(t, "the drive, imaged")
	taken := run.intake(t, "EXH-1", path)
	if mustHashStringValue(t, taken, "state") != evidenceHeld || mustHashStringValue(t, taken, "holder") != "alice" ||
		mustHashStringValue(t, taken, "hash") != sha256Hex([]byte("the drive, imaged")) {
		t.Fatalf("evidence_intake gave %s", taken.Inspect())
	}
	manifest := mustHash(t, CaseManifest())
	if got := mustHashValue(t, manifest, "evidence").Inspect(); !strings.Contains(got, sha256Hex([]byte("the drive, imaged"))) {
		t.Fatalf("the intake is not in the run's custody, so case_verify would not re-measure it: %s", got)
	}
	released := mustHash(t, EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"), stringObj("bob"),
		stringObj("to the lab")))
	if mustHashStringValue(t, released, "state") != evidenceInTransit || mustHashStringValue(t, released, "to") != "bob" {
		t.Fatalf("evidence_release gave %s", released.Inspect())
	}
	mustRefuse(t, "an accept by the releaser", EvidenceAccept(intObj(run.ledger), stringObj("EXH-1"),
		stringObj(path)), "was released to bob, and alice is accepting it")

	run = run.next(t, "bob", "investigator")
	run.attach(t)
	accepted := mustHash(t, EvidenceAccept(intObj(run.ledger), stringObj("EXH-1"), stringObj(path)))
	if !mustHashBoolValue(t, accepted, "matches_intake") || mustHashStringValue(t, accepted, "holder") != "bob" ||
		mustHashStringValue(t, accepted, "from") != "alice" {
		t.Fatalf("evidence_accept gave %s", accepted.Inspect())
	}
	mustHash(t, EvidenceReturn(intObj(run.ledger), stringObj("EXH-1"), stringObj("the owner"),
		stringObj("case closed")))
	mustRefuse(t, "a release of a returned exhibit", EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"),
		stringObj("alice"), stringObj("x")), "is returned (returned to the owner)")

	row := exhibitHistory(t, run.ledger, "EXH-1")
	if mustHashStringValue(t, row, "state") != evidenceReturned || mustHashStringValue(t, row, "holder") != "" ||
		mustHashIntValue(t, row, "event_count") != 4 || mustHashIntValue(t, row, "discrepancies") != 0 {
		t.Fatalf("evidence_history gave %s", row.Inspect())
	}
	var kinds []string
	for _, event := range mustHashArrayValue(t, row, "events") {
		kinds = append(kinds, mustHashStringValue(t, event.(*object.Hash), "kind"))
	}
	if want := []string{"intake", "release", "accept", "return"}; !slices.Equal(kinds, want) {
		t.Fatalf("the chain is %v, want %v", kinds, want)
	}
}

// An accept hashes what it was handed: a file that does not match the intake
// is refused with nothing recorded, unless the examiner says what happened,
// and then both digests and the statement are recorded.
func TestAnAcceptHashesWhatItWasHanded(t *testing.T) {
	run := custodyRun(t)
	path := exhibitFile(t, "original")
	run.intake(t, "EXH-1", path)
	mustHash(t, EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"), stringObj("bob"), stringObj("lab")))
	run = run.next(t, "bob", "investigator")
	run.attach(t)
	altered := exhibitFile(t, "altered")
	mustRefuse(t, "a mismatched accept", EvidenceAccept(intObj(run.ledger), stringObj("EXH-1"), stringObj(altered)),
		"Nothing has been recorded")
	if n := mustHashIntValue(t, exhibitHistory(t, run.ledger, "EXH-1"), "event_count"); n != 2 {
		t.Fatalf("a refused accept left %d events", n)
	}
	mustRefuse(t, "an empty discrepancy", EvidenceAccept(intObj(run.ledger), stringObj("EXH-1"), stringObj(altered),
		makeHashObject(map[string]object.Object{"discrepancy": stringObj("  ")})), "must not be empty")
	accepted := mustHash(t, EvidenceAccept(intObj(run.ledger), stringObj("EXH-1"), stringObj(altered),
		makeHashObject(map[string]object.Object{"discrepancy": stringObj("re-imaged after a read error")})))
	if mustHashBoolValue(t, accepted, "matches_intake") || mustHashStringValue(t, accepted, "hash") != sha256Hex([]byte("altered")) ||
		mustHashStringValue(t, accepted, "intake_hash") != sha256Hex([]byte("original")) {
		t.Fatalf("the accept with a discrepancy gave %s", accepted.Inspect())
	}
	row := exhibitHistory(t, run.ledger, "EXH-1")
	if mustHashIntValue(t, row, "discrepancies") != 1 {
		t.Fatalf("evidence_history counts %d discrepancies", mustHashIntValue(t, row, "discrepancies"))
	}
	events := mustHashArrayValue(t, row, "events")
	release, accept := events[1].(*object.Hash), events[2].(*object.Hash)
	if mustHashBoolValue(t, release, "hash_checked") || !mustHashBoolValue(t, accept, "hash_checked") ||
		mustHashStringValue(t, accept, "discrepancy") != "re-imaged after a read error" {
		t.Fatalf("the history's hash checks are %s and %s", release.Inspect(), accept.Inspect())
	}
}

// A returned exhibit that comes back is taken in again under its own name, as
// the next event of its chain, by anybody the case assigns, and what came
// back is compared with what was first taken in: a match is recorded as one,
// and a mismatch is refused with nothing recorded unless the examiner says
// what happened.
func TestAReturnedExhibitIsTakenInAgainUnderItsOwnName(t *testing.T) {
	run := custodyRun(t)
	path := exhibitFile(t, "the phone, imaged")
	first := run.intake(t, "EXH-1", path)
	if mustHashBoolValue(t, first, "hash_checked") || mustHashBoolValue(t, first, "matches_intake") ||
		mustHashStringValue(t, first, "intake_hash") != mustHashStringValue(t, first, "hash") {
		t.Fatalf("a first intake says it compared something: %s", first.Inspect())
	}
	mustRefuse(t, "a discrepancy on a first intake", EvidenceIntake(intObj(run.ledger), stringObj("EXH-2"),
		stringObj(path), makeHashObject(map[string]object.Object{"discrepancy": stringObj("scratched")})),
		"has never held exhibit \"EXH-2\"")
	mustHash(t, EvidenceReturn(intObj(run.ledger), stringObj("EXH-1"), stringObj("the owner"),
		stringObj("not needed for now")))

	run = run.next(t, "bob", "investigator")
	run.attach(t)
	mustRefuse(t, "a re-intake that describes the exhibit again", EvidenceIntake(intObj(run.ledger),
		stringObj("EXH-1"), stringObj(path), makeHashObject(map[string]object.Object{
			"description": stringObj("a phone")})), "was described when it was first taken in")
	back := mustHash(t, EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"), stringObj(path),
		makeHashObject(map[string]object.Object{"received_from": stringObj("the owner")})))
	if mustHashStringValue(t, back, "kind") != evidenceKindReintake || mustHashStringValue(t, back, "holder") != "bob" ||
		mustHashIntValue(t, back, "seq") != 3 || !mustHashBoolValue(t, back, "hash_checked") ||
		!mustHashBoolValue(t, back, "matches_intake") || mustHashStringValue(t, back, "received_from") != "the owner" {
		t.Fatalf("the re-intake gave %s", back.Inspect())
	}

	// Returned again, it comes back changed.
	mustHash(t, EvidenceReturn(intObj(run.ledger), stringObj("EXH-1"), stringObj("the owner"), stringObj("again")))
	reset := exhibitFile(t, "the phone, reset")
	mustRefuse(t, "a changed exhibit with nothing said", EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"),
		stringObj(reset)), "Nothing has been recorded")
	if n := mustHashIntValue(t, exhibitHistory(t, run.ledger, "EXH-1"), "event_count"); n != 4 {
		t.Fatalf("a refused re-intake left %d events", n)
	}
	changed := mustHash(t, EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"), stringObj(reset),
		makeHashObject(map[string]object.Object{"discrepancy": stringObj("reset by the owner before handing it back")})))
	if mustHashBoolValue(t, changed, "matches_intake") || !mustHashBoolValue(t, changed, "hash_checked") ||
		mustHashStringValue(t, changed, "intake_hash") != sha256Hex([]byte("the phone, imaged")) ||
		mustHashStringValue(t, changed, "hash") != sha256Hex([]byte("the phone, reset")) {
		t.Fatalf("the re-intake with a discrepancy gave %s", changed.Inspect())
	}
	manifest := mustHash(t, CaseManifest())
	if got := mustHashValue(t, manifest, "evidence").Inspect(); !strings.Contains(got, sha256Hex([]byte("the phone, reset"))) {
		t.Fatalf("the re-intake is not in the run's custody, so case_verify would not re-measure it: %s", got)
	}

	row := exhibitHistory(t, run.ledger, "EXH-1")
	if mustHashStringValue(t, row, "where") != "held by bob" || mustHashIntValue(t, row, "discrepancies") != 1 ||
		mustHashStringValue(t, row, "hash") != sha256Hex([]byte("the phone, imaged")) {
		t.Fatalf("evidence_history gave %s", row.Inspect())
	}
	events := mustHashArrayValue(t, row, "events")
	var kinds []string
	for _, event := range events {
		kinds = append(kinds, mustHashStringValue(t, event.(*object.Hash), "kind"))
	}
	if want := []string{"intake", "return", "reintake", "return", "reintake"}; !slices.Equal(kinds, want) {
		t.Fatalf("the chain is %v, want %v", kinds, want)
	}
	if got := mustHashStringValue(t, events[2].(*object.Hash), "received_from"); got != "the owner" {
		t.Fatalf("the re-intake's history says it came back from %q", got)
	}
}

// Every evidence builtin returns what its metadata declares -- which is what
// hover, completion and the conformance probes read -- and evidence_intake
// returns one shape whether it takes an exhibit in or takes it back.
func TestEveryEvidenceBuiltinReturnsTheDeclaredFields(t *testing.T) {
	run := custodyRun(t)
	path := exhibitFile(t, "x")
	type call struct {
		name   string
		result object.Object
	}
	ledger := intObj(run.ledger)
	calls := []call{
		{BuiltinNameEvidenceIntake, EvidenceIntake(ledger, stringObj("EXH-1"), stringObj(path))},
		{BuiltinNameEvidenceRelease, EvidenceRelease(ledger, stringObj("EXH-1"), stringObj("bob"), stringObj("lab"))},
	}
	run = run.next(t, "bob", "investigator")
	run.attach(t)
	ledger = intObj(run.ledger)
	calls = append(calls,
		call{BuiltinNameEvidenceAccept, EvidenceAccept(ledger, stringObj("EXH-1"), stringObj(path))},
		call{BuiltinNameEvidenceReturn, EvidenceReturn(ledger, stringObj("EXH-1"), stringObj("the owner"),
			stringObj("done"))},
		call{BuiltinNameEvidenceIntake, EvidenceIntake(ledger, stringObj("EXH-1"), stringObj(path))},
	)
	run = run.next(t, "alice", "case_owner")
	run.attach(t)
	ledger = intObj(run.ledger)
	calls = append(calls,
		call{BuiltinNameEvidenceIntake, EvidenceIntake(ledger, stringObj("EXH-2"), stringObj(path))},
		call{BuiltinNameEvidenceDispose, EvidenceDispose(ledger, stringObj("EXH-2"), stringObj("shredded"))},
		call{BuiltinNameEvidenceHistory, EvidenceHistory(ledger)},
	)
	for _, c := range calls {
		payload, errObj := unwrapPairNoFatal(c.result)
		if errObj != nil {
			t.Fatalf("%s: %s", c.name, errObj.Message)
		}
		assertDeclaredFieldsNoHandle(t, c.name, payload)
	}
}

// Whoever holds an exhibit records where it goes, and only to somebody the
// case assigns.
func TestOnlyTheHolderHandsAnExhibitOn(t *testing.T) {
	run := custodyRun(t)
	path := exhibitFile(t, "x")
	run.intake(t, "EXH-1", path)
	mustRefuse(t, "a second intake of one exhibit", EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"),
		stringObj(path)), "already holds exhibit \"EXH-1\"")
	mustRefuse(t, "a release to nobody the case assigns", EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"),
		stringObj("bbo"), stringObj("x")), "assigns bbo no role")
	mustRefuse(t, "a release to the holder", EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"),
		stringObj("alice"), stringObj("x")), "a release is to somebody else")
	mustRefuse(t, "an unknown exhibit", EvidenceRelease(intObj(run.ledger), stringObj("EXH-9"), stringObj("bob"),
		stringObj("x")), "holds no exhibit \"EXH-9\"")
	mustRefuse(t, "an accept of a held exhibit", EvidenceAccept(intObj(run.ledger), stringObj("EXH-1"),
		stringObj(path)), "only a released exhibit is accepted")

	run = run.next(t, "bob", "investigator")
	run.attach(t)
	mustRefuse(t, "a release by somebody not holding it", EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"),
		stringObj("alice"), stringObj("x")), "the ledger says alice holds exhibit")
	mustRefuse(t, "a return by somebody not holding it", EvidenceReturn(intObj(run.ledger), stringObj("EXH-1"),
		stringObj("owner"), stringObj("x")), "the ledger says alice holds exhibit")
}

// An exhibit is taken in by somebody working the case.
func TestAnExhibitIsTakenInByAnExaminerTheCaseAssigns(t *testing.T) {
	run := openLifecycleRun(t, "alice", "case_owner", "", "")
	path := exhibitFile(t, "x")
	mustRefuse(t, "an intake into an unattached case", EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"),
		stringObj(path)), "attached to no ledger")
	run.attach(t)
	mustRefuse(t, "an intake of a directory", EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"),
		stringObj(t.TempDir())), "is a directory")
	mustRefuse(t, "an intake of nothing", EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"),
		stringObj(filepath.Join(t.TempDir(), "absent"))), "no such file")
	mustRefuse(t, "an unnamed exhibit", EvidenceIntake(intObj(run.ledger), stringObj(" "), stringObj(path)),
		"must not be empty")
	mustHash(t, CaseAssign(intObj(run.ledger), stringObj("alice"), stringObj("none"), stringObj("leaves")))
	mustRefuse(t, "an intake by an examiner whose assignment ended", EvidenceIntake(intObj(run.ledger),
		stringObj("EXH-1"), stringObj(path)), "assigns alice no role")
}

// A disposal is recorded by a case owner or an administrator holding the
// exhibit, and it is a statement: the file is still there.
func TestADisposalIsAStatementAndDeletesNothing(t *testing.T) {
	run := custodyRun(t)
	path := exhibitFile(t, "to be destroyed")
	run.intake(t, "EXH-1", path)
	mustHash(t, EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"), stringObj("bob"), stringObj("lab")))
	run = run.next(t, "bob", "investigator")
	run.attach(t)
	mustHash(t, EvidenceAccept(intObj(run.ledger), stringObj("EXH-1"), stringObj(path)))
	mustRefuse(t, "a disposal by an investigator", EvidenceDispose(intObj(run.ledger), stringObj("EXH-1"),
		stringObj("shredded")), "is not access control")
	mustHash(t, EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"), stringObj("alice"), stringObj("back")))

	run = run.next(t, "alice", "case_owner")
	run.attach(t)
	mustHash(t, EvidenceAccept(intObj(run.ledger), stringObj("EXH-1"), stringObj(path)))
	disposed := mustHash(t, EvidenceDispose(intObj(run.ledger), stringObj("EXH-1"),
		stringObj("drive shredded by the vendor, certificate 7")))
	if mustHashBoolValue(t, disposed, "deleted") || mustHashStringValue(t, disposed, "state") != evidenceDisposed {
		t.Fatalf("evidence_dispose gave %s", disposed.Inspect())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a disposal touched the file: %v", err)
	}
	mustRefuse(t, "a return of a disposed exhibit", EvidenceReturn(intObj(run.ledger), stringObj("EXH-1"),
		stringObj("owner"), stringObj("x")), "is disposed (disposed of by alice)")
	mustRefuse(t, "an intake of a disposed exhibit", EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"),
		stringObj(path)), "a disposal is final")
	history := mustHash(t, EvidenceHistory(intObj(run.ledger)))
	if mustHashIntValue(t, history, "disposed") != 1 || mustHashIntValue(t, history, "count") != 1 {
		t.Fatalf("evidence_history gave %s", history.Inspect())
	}
}

// A new exhibit is refused in the states that take nothing new; the movement
// of one the case has taken in -- a returned one coming back included -- is
// refused in none.
func TestTheCaseStateRefusesANewExhibitAndNeverAMovement(t *testing.T) {
	// From active on: custodyRun has moved the case past registered, which
	// refuses nothing, and neither does active.
	for _, state := range caseStates[1:] {
		t.Run(state, func(t *testing.T) {
			run := custodyRun(t)
			path := exhibitFile(t, "x")
			run.intake(t, "EXH-0", path)
			run.intake(t, "EXH-R", path)
			var moves []string
			for _, s := range caseStates[2:] {
				if caseStateIndex(state) < caseStateIndex(s) {
					break
				}
				moves = append(moves, s)
			}
			if len(moves) > 0 {
				forceLifecycle(t, run.session(t), openCaseUID(t), moves...)
			}
			mustHash(t, EvidenceRelease(intObj(run.ledger), stringObj("EXH-0"), stringObj("bob"), stringObj("moved")))
			mustHash(t, EvidenceReturn(intObj(run.ledger), stringObj("EXH-R"), stringObj("the owner"),
				stringObj("returned")))
			mustHash(t, EvidenceIntake(intObj(run.ledger), stringObj("EXH-R"), stringObj(path)))
			_, errObj := unwrapPairNoFatal(EvidenceIntake(intObj(run.ledger), stringObj("EXH-1"), stringObj(path)))
			refused := errObj != nil && strings.Contains(errObj.Message, "takes no intake of evidence")
			if refused != caseStateBlocks(state, caseActIntake) {
				t.Errorf("an intake of a new exhibit in state %s: refused %t (%v)", state, refused, errObj)
			}
		})
	}
}

func caseStateIndex(state string) int { return slices.Index(caseStates, state) }

// Every key an exhibit or its custody is looked up by is indexed. The keys
// are named here, not read from disclosureKeys, so that a key dropped from
// that table fails this test instead of quietly leaving it.
func TestEveryEvidenceLabelIsFoundByEachOfItsLookupKeys(t *testing.T) {
	run := custodyRun(t)
	run.intake(t, "EXH-1", exhibitFile(t, "x"))
	mustHash(t, EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"), stringObj("bob"), stringObj("lab")))
	g := run.session(t).graph
	for _, lookup := range []struct {
		label store.NodeType
		keys  []string
	}{
		{disclosureNodeEvidence, []string{"evidence.uid", "evidence.case_uid"}},
		{disclosureNodeCustodyEvent, []string{"custody.uid", "custody.chain"}},
	} {
		label := lookup.label
		nodes, err := disclosureAll(g, label)
		if err != nil || len(nodes) == 0 {
			t.Fatalf("no %s node was written: %v", label.String(), err)
		}
		for _, node := range nodes {
			for _, key := range lookup.keys {
				ids, err := g.NodesByProperty(key, []byte(node.get(key)))
				if err != nil || !slices.Contains(ids, node.id) {
					t.Errorf("%s node %d is not found by %s = %q", label.String(), node.id, key, node.get(key))
				}
			}
		}
	}
}

// evidence_history needs no case open: an auditor reads a ledger's custody
// with nothing but the ledger, and can narrow it to one case or one exhibit.
func TestAnAuditorReadsCustodyWithTheLedgerAlone(t *testing.T) {
	run := custodyRun(t)
	run.intake(t, "EXH-1", exhibitFile(t, "x"))
	run.intake(t, "EXH-2", exhibitFile(t, "y"))
	caseUID := openCaseUID(t)
	LedgerClose(intObj(run.ledger))
	resetCustodyForTesting()

	opened, errObj := ledgerOpenAs(t, run.ledgerDir, "auditor", "auditor")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	ledger := mustHashIntValue(t, opened, "handle")
	defer LedgerClose(intObj(ledger))
	all := mustHash(t, EvidenceHistory(intObj(ledger)))
	if mustHashIntValue(t, all, "count") != 2 || mustHashIntValue(t, all, "held") != 2 {
		t.Fatalf("evidence_history under an auditor gave %s", all.Inspect())
	}
	mine := mustHash(t, EvidenceHistory(intObj(ledger), makeHashObject(map[string]object.Object{
		"case_uid": stringObj(caseUID)})))
	if mustHashIntValue(t, mine, "count") != 2 {
		t.Fatalf("the case's own history gave %s", mine.Inspect())
	}
	other := mustHash(t, EvidenceHistory(intObj(ledger), makeHashObject(map[string]object.Object{
		"case_uid": stringObj(strings.Repeat("0", len(caseUID)))})))
	if mustHashIntValue(t, other, "count") != 0 {
		t.Fatalf("another case's history gave %s", other.Inspect())
	}
	one := mustHash(t, EvidenceHistory(intObj(ledger), makeHashObject(map[string]object.Object{
		"exhibit": stringObj("EXH-2")})))
	rows := mustHashArrayValue(t, one, "exhibits")
	if mustHashIntValue(t, one, "count") != 1 || mustHashIntValue(t, one, "held") != 1 ||
		mustHashStringValue(t, rows[0].(*object.Hash), "exhibit") != "EXH-2" {
		t.Fatalf("one exhibit's history gave %s", one.Inspect())
	}
	mustRefuse(t, "an auditor's intake", EvidenceIntake(intObj(ledger), stringObj("EXH-3"),
		stringObj(exhibitFile(t, "y"))), "an auditor reads what it audits")
}

// Every reader refuses each of these custody chains rather than resolving it,
// and this program writes none of them: two events after one; an event that
// skips a state or leaves the exhibit where its kind does not; one recorded by
// somebody who could not have recorded it, or leaving the exhibit with
// somebody else; a hash check that is missing, claimed where none is made,
// contradicted by its own digests, or a mismatch with nothing said; an intake
// that measured something other than what its exhibit says; an event of a
// kind this program does not write, or one in an exhibit's chain that names
// another; an exhibit with no custody at all; and an exhibit filed under
// another's uid.
func TestACustodyChainThisProgramDidNotWriteIsRefused(t *testing.T) {
	// after forges an event of kind after EXH-1's head, recorded by `by` and
	// left with them, with props laid over what custody writes.
	after := func(kind, by string, props map[string]string) func(*caseWriter, evidenceItem) error {
		return func(w *caseWriter, item evidenceItem) error {
			head := item.head()
			all := map[string]string{"custody.by": by, "custody.holder": by}
			maps.Copy(all, props)
			_, err := w.custody(item.node.id, item.node.get("evidence.uid"), item.exhibit(), kind, &head, "forged",
				all, nil)
			return err
		}
	}
	// forgeExhibit forges exhibit, filed under the uid of uidOf, whose node
	// says it was taken in as nodeDigest, with a first event of kind that
	// measured firstDigest -- or with no custody at all, when kind is empty.
	forgeExhibit := func(uidOf, exhibit, nodeDigest, kind, firstDigest string) func(*caseWriter, evidenceItem) error {
		return func(w *caseWriter, _ evidenceItem) error {
			uid := evidenceUID(w.caseUID, uidOf)
			id, err := w.tx.node(disclosureNodeEvidence, map[string]string{"evidence.uid": uid,
				"evidence.case_uid": w.caseUID, "evidence.exhibit": exhibit, "evidence.digest": nodeDigest})
			if err == nil && kind != "" {
				_, err = w.custody(id, uid, exhibit, kind, nil, "forged",
					map[string]string{"custody.digest": firstDigest}, nil)
			}
			return err
		}
	}
	for _, tc := range []struct {
		name, want string
		// released is whether EXH-1 is released to bob before the forgery;
		// reads is whether evidence_release of EXH-1 reads what was forged.
		released, reads bool
		forge           func(w *caseWriter, item evidenceItem) error
	}{
		{"fork", "two custody events after", true, true, func(w *caseWriter, item evidenceItem) error {
			head := item.events[0]
			_, err := w.custody(item.node.id, item.node.get("evidence.uid"), item.exhibit(), evidenceKindRelease,
				&head, "a second history", map[string]string{"custody.to": "bob"}, nil)
			return err
		}},
		{"skipped state", `moves the exhibit from "in_transit"`, false, true,
			after(evidenceKindAccept, "bob", nil)},
		{"wrong end state", `(release) leaves the exhibit "held"`, false, true,
			after(evidenceKindRelease, "alice", map[string]string{"custody.to": "bob", "custody.state": evidenceHeld})},
		{"a hand-off by somebody not holding it", "(release) was recorded by bob, and the event before it left " +
			"the exhibit held by alice", false, true,
			after(evidenceKindRelease, "bob", map[string]string{"custody.to": "carol"})},
		{"an accept by somebody it was not released to", "(accept) was recorded by carol, and the exhibit was " +
			"released to bob", true, true, after(evidenceKindAccept, "carol", nil)},
		{"a holder the event does not leave", `(release) leaves the exhibit with "mallory"`, false, true,
			after(evidenceKindRelease, "alice", map[string]string{"custody.to": "bob", "custody.holder": "mallory"})},
		{"an accept that compares nothing", "(accept) compares no digest with the intake's", true, true,
			after(evidenceKindAccept, "bob", nil)},
		{"a hand-off that says it compared", "(release) says it compared a digest with the intake's", false, true,
			after(evidenceKindRelease, "alice", map[string]string{"custody.to": "bob", "custody.matches_intake": "true"})},
		{"a check its digests contradict", "says matches_intake is true, and it measured ff", true, true,
			after(evidenceKindAccept, "bob", map[string]string{"custody.digest": "ff", "custody.matches_intake": "true"})},
		{"a mismatch nobody explained", "does not match the intake's and no discrepancy", true, true,
			after(evidenceKindAccept, "bob", map[string]string{"custody.digest": "ff", "custody.matches_intake": "false"})},
		{"an event naming another exhibit", `custody event 2 of exhibit "EXH-1" names another exhibit`, false, true,
			func(w *caseWriter, item evidenceItem) error {
				return after(evidenceKindRelease, "alice", map[string]string{"custody.to": "bob",
					"custody.evidence_uid": evidenceUID(w.caseUID, "EXH-2")})(w, item)
			}},
		{"intake digest", "says it was taken in with digest aa", false, false,
			forgeExhibit("EXH-2", "EXH-2", "aa", evidenceKindIntake, "bb")},
		{"a kind this program does not write", `records "borrow", which is not a kind`, false, false,
			forgeExhibit("EXH-5", "EXH-5", "dd", "borrow", "dd")},
		{"an exhibit with no custody", `exhibit "EXH-6" is in the ledger with no custody record`, false, false,
			forgeExhibit("EXH-6", "EXH-6", "ee", "", "")},
		{"another exhibit's uid", "under a uid that is not that exhibit's", false, false,
			forgeExhibit("EXH-3", "EXH-4", "cc", evidenceKindIntake, "cc")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := custodyRun(t)
			run.intake(t, "EXH-1", exhibitFile(t, "x"))
			if tc.released {
				mustHash(t, EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"), stringObj("bob"), stringObj("lab")))
			}
			ledger := run.session(t)
			disclosureLedgerMu.Lock()
			item, found, err := evidenceRead(ledger.graph, openCaseUID(t), "EXH-1")
			if err == nil && found {
				var w *caseWriter
				if w, err = caseBeginWrite(ledger, openCaseUID(t), "IR-LIFE", custodyNow()); err == nil {
					if err = tc.forge(w, item); err == nil {
						err = w.tx.commit()
					}
				}
			}
			disclosureLedgerMu.Unlock()
			if err != nil || !found {
				t.Fatalf("forging: %v (found %t)", err, found)
			}
			mustRefuse(t, "the history", EvidenceHistory(intObj(run.ledger)), tc.want)
			if tc.reads {
				mustRefuse(t, "a release", EvidenceRelease(intObj(run.ledger), stringObj("EXH-1"), stringObj("bob"),
					stringObj("x")), tc.want)
			}
		})
	}
}
