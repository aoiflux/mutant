package builtin

import (
	"maps"
	"strings"
	"testing"

	"mutant/object"
)

// versionRows reads redaction_versions' versions by view and number.
func versionRows(t *testing.T, versions *object.Hash) map[string]*object.Hash {
	t.Helper()
	out := map[string]*object.Hash{}
	for _, row := range mustHashArrayValue(t, versions, "versions") {
		h := row.(*object.Hash)
		out[mustHashStringValue(t, h, "view")+" v"+mustHashValue(t, h, "version").Inspect()] = h
	}
	return out
}

// staleRecipients lists the recipients redaction_versions calls stale.
func staleRecipients(t *testing.T, versions *object.Hash) []string {
	t.Helper()
	var out []string
	for _, row := range mustHashArrayValue(t, versions, "disclosures") {
		h := row.(*object.Hash)
		if mustHashBoolValue(t, h, "stale") {
			out = append(out, mustHashStringValue(t, h, "recipient")+"@"+mustHashStringValue(t, h, "view"))
		}
	}
	return out
}

// A version is written when what a view releases from the evidence changes,
// and not otherwise: two disclosures under one view share one, a commit of
// the redaction in force writes nothing, and a reclassification that moves
// what counsel is given writes the next -- in the same line, found through the
// reclassification -- after which the disclosures under the first are stale.
func TestARedactionVersionIsWrittenOnlyWhenWhatAViewReleasesChanges(t *testing.T) {
	f := newDiscloseFixture(t)
	ledger := intObj(f.ledger)
	oldUID := recordUIDOf(t, f.record)
	first := f.issue(t, "counsel", "Counsel")
	second := f.issue(t, "counsel", "The regulator")
	if mustHashIntValue(t, first, "redaction_version") != 1 ||
		mustHashStringValue(t, second, "redaction_uid") != mustHashStringValue(t, first, "redaction_uid") {
		t.Fatalf("two disclosures under one view gave versions %s and %s", first.Inspect(), second.Inspect())
	}
	again := mustHash(t, RedactionCommit(ledger, f.record, stringObj("counsel"), stringObj("asked again")))
	if mustHashBoolValue(t, again, "committed") || !mustHashBoolValue(t, again, "already_committed") ||
		mustHashStringValue(t, again, "uid") != mustHashStringValue(t, first, "redaction_uid") {
		t.Fatalf("committing the redaction in force gave %s", again.Inspect())
	}
	regulator := f.issue(t, "regulator", "The regulator")
	if mustHashIntValue(t, regulator, "redaction_version") != 1 ||
		mustHashStringValue(t, regulator, "redaction_uid") == mustHashStringValue(t, first, "redaction_uid") {
		t.Fatalf("another view shares counsel's version: %s", regulator.Inspect())
	}

	// The first pii span, 100-160, becomes restricted: counsel is given 60
	// bytes fewer from the new record.
	newRecord, newUID := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(150), stringObj("restricted"))),
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	))
	mustHash(t, DiscloseReclassified(ledger, newRecord, f.record))
	third := f.issueFrom(t, newRecord, "counsel", "Later counsel")
	if mustHashIntValue(t, third, "redaction_version") != 2 {
		t.Fatalf("a changed redaction gave %s", third.Inspect())
	}

	for _, uid := range []string{newUID, oldUID} {
		versions := mustHash(t, RedactionVersions(ledger, stringObj(uid)))
		rows := versionRows(t, versions)
		v1, v2, reg := rows["counsel v1"], rows["counsel v2"], rows["regulator v1"]
		if mustHashStringValue(t, versions, "line") != oldUID || len(rows) != 3 || v1 == nil || v2 == nil || reg == nil {
			t.Fatalf("redaction_versions of %s gave %s", uid, versions.Inspect())
		}
		if mustHashStringValue(t, v1, "granted") != "0+160,250+150" || mustHashBoolValue(t, v1, "in_force") ||
			mustHashIntValue(t, v1, "disclosures") != 2 || mustHashStringValue(t, v1, "record_uid") != oldUID {
			t.Fatalf("counsel's first version is %s", v1.Inspect())
		}
		if mustHashStringValue(t, v2, "granted") != "0+100,250+150" || !mustHashBoolValue(t, v2, "in_force") ||
			mustHashIntValue(t, v2, "granted_bytes") != 250 || mustHashIntValue(t, v2, "withheld_bytes") != 150 ||
			mustHashStringValue(t, v2, "record_uid") != newUID ||
			!strings.HasPrefix(mustHashStringValue(t, v2, "reason"), "issued with disclosure ") {
			t.Fatalf("counsel's second version is %s", v2.Inspect())
		}
		if got := strings.Join(staleRecipients(t, versions), ", "); got != "Counsel@counsel, The regulator@counsel" ||
			mustHashIntValue(t, versions, "stale") != 2 || mustHashIntValue(t, versions, "disclosure_count") != 4 {
			t.Fatalf("redaction_versions calls stale: %s (%s)", got, versions.Inspect())
		}
	}
}

// A reclassification that moves bytes between two classes a view both grants
// releases what it released before: the same redaction, and no new version.
func TestAReclassificationThatReleasesTheSameBytesIsTheSameRedaction(t *testing.T) {
	f := newDiscloseFixture(t)
	ledger := intObj(f.ledger)
	first := f.issue(t, "counsel", "Counsel")
	// The first pii span becomes open. Counsel grants both.
	newRecord, _ := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(160), intObj(90), stringObj("restricted"))),
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	))
	mustHash(t, DiscloseReclassified(ledger, newRecord, f.record))
	again := f.issueFrom(t, newRecord, "counsel", "Second counsel")
	if mustHashIntValue(t, again, "redaction_version") != 1 ||
		mustHashStringValue(t, again, "redaction_uid") != mustHashStringValue(t, first, "redaction_uid") {
		t.Fatalf("the same bytes under a new record gave %s", again.Inspect())
	}
	versions := mustHash(t, RedactionVersions(ledger, stringObj(recordUIDOf(t, f.record))))
	if mustHashIntValue(t, versions, "count") != 1 || mustHashIntValue(t, versions, "stale") != 0 ||
		mustHashIntValue(t, versions, "disclosure_count") != 2 {
		t.Fatalf("redaction_versions gave %s", versions.Inspect())
	}
}

// A redaction is committed ahead of the disclosure that carries it out, which
// then names that version; a record another record reclassified is not the
// redaction in force, and is refused.
func TestRedactionCommitRecordsAVersionAheadOfItsDisclosure(t *testing.T) {
	f := newDiscloseFixture(t)
	ledger := intObj(f.ledger)
	uid := recordUIDOf(t, f.record)
	committed := mustHash(t, RedactionCommit(ledger, f.record, stringObj(" Counsel "), stringObj("for the reviewer")))
	if !mustHashBoolValue(t, committed, "committed") || mustHashIntValue(t, committed, "version") != 1 ||
		mustHashStringValue(t, committed, "reason") != "for the reviewer" || mustHashStringValue(t, committed, "by") != "examiner" ||
		mustHashStringValue(t, committed, "granted") != "0+160,250+150" || mustHashIntValue(t, committed, "granted_bytes") != 310 ||
		mustHashIntValue(t, committed, "withheld_bytes") != 90 || mustHashStringValue(t, committed, "line") != uid ||
		mustHashStringValue(t, committed, "computed_on") != uid || mustHashStringValue(t, committed, "previous_uid") != "" ||
		mustHashBoolValue(t, committed, "role_authenticated") {
		t.Fatalf("redaction_commit gave %s", committed.Inspect())
	}
	issued := f.issue(t, "counsel", "Counsel")
	if mustHashStringValue(t, issued, "redaction_uid") != mustHashStringValue(t, committed, "uid") {
		t.Fatalf("the disclosure did not issue under the committed version: %s", issued.Inspect())
	}
	versions := mustHash(t, RedactionVersions(ledger, stringObj(uid)))
	row := versionRows(t, versions)["counsel v1"]
	if row == nil || mustHashStringValue(t, row, "reason") != "for the reviewer" || mustHashIntValue(t, row, "disclosures") != 1 {
		t.Fatalf("redaction_versions gave %s", versions.Inspect())
	}

	newRecord, _ := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(150), stringObj("restricted"))),
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	))
	mustHash(t, DiscloseReclassified(ledger, newRecord, f.record))
	mustRefuse(t, "a superseded record", RedactionCommit(ledger, f.record, stringObj("counsel"), stringObj("x")),
		"was reclassified by record")
}

// Versions are never left behind. A record disclosed before it was recorded as
// reclassifying another keeps its own line when the reclassification is
// recorded, and a record reclassifying it joins that line.
func TestTheLineIsKeptByTheNearestRecordWithVersions(t *testing.T) {
	f := newDiscloseFixture(t)
	ledger := intObj(f.ledger)
	oldUID := recordUIDOf(t, f.record)
	f.issue(t, "counsel", "Counsel")
	second, secondUID := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(150), stringObj("restricted"))),
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	))
	f.issueFrom(t, second, "counsel", "Second")
	mustHash(t, DiscloseReclassified(ledger, second, f.record))
	line := func(uid string) string {
		return mustHashStringValue(t, mustHash(t, RedactionVersions(ledger, stringObj(uid))), "line")
	}
	if line(secondUID) != secondUID || line(oldUID) != oldUID {
		t.Fatalf("the lines are %s and %s", line(secondUID), line(oldUID))
	}

	third, thirdUID := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(60), stringObj("pii"))),
		mustHash(t, RecordClassifyRange(intObj(160), intObj(140), stringObj("restricted"))),
	))
	mustHash(t, DiscloseReclassified(ledger, third, second))
	issued := f.issueFrom(t, third, "counsel", "Third")
	if line(thirdUID) != secondUID || mustHashIntValue(t, issued, "redaction_version") != 2 {
		t.Fatalf("the third record's line is %s and its version %d", line(thirdUID),
			mustHashIntValue(t, issued, "redaction_version"))
	}
}

// supersedesEdge records one record as reclassifying another by writing the
// edge directly, bypassing disclose_reclassified. That is how a ledger comes to
// hold a shape the builtin refuses to write -- a store written by an older
// version of this program, or edited by hand -- and the walk has to be sound on
// one, so the test that proves it builds one deliberately (M26-REC-023).
func (f *discloseFixture) supersedesEdge(t *testing.T, session *ledgerSession, newUID, oldUID string) {
	t.Helper()
	caseUID := openCaseUID(t)
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	find := func(uid string) disclosureNode {
		node, found, err := disclosureFind(session.graph, disclosureNodeRecord, "record.uid", uid)
		if err != nil || !found {
			t.Fatalf("record %s is not in the ledger: found=%v err=%v", uid, found, err)
		}
		return node
	}
	newNode, oldNode := find(newUID), find(oldUID)
	w, err := caseBeginWrite(session, caseUID, "IR-REC", custodyNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.tx.edge(newNode.id, oldNode.id, disclosureEdgeSupersedes, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.tx.commit(); err != nil {
		t.Fatal(err)
	}
}

// A record is reclassified once. Two records reclassifying one both walk back to
// its line and share the single chain of versions kept there, so disclosing them
// in turn wrote a version apiece -- alternating between their two partitions --
// and called every disclosure but the last stale, although neither
// reclassification had changed what a view releases. Whichever had been
// disclosed last was the one in force for the evidence. The second is refused
// instead, and the refusal names where the line now ends so the caller can
// record it there (M26-REC-023).
func TestARecordIsReclassifiedOnce(t *testing.T) {
	f := newDiscloseFixture(t)
	ledger := intObj(f.ledger)
	first, firstUID := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(0), intObj(160), stringObj("restricted"))),
	))
	second, _ := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(0), intObj(160), stringObj("open"))),
	))
	mustHash(t, DiscloseReclassified(ledger, first, f.record))
	mustRefuse(t, "a second record reclassifying one", DiscloseReclassified(ledger, second, f.record),
		"is already recorded as reclassified by record "+firstUID)

	// Asking the first question again is still free: the same pair is found and
	// nothing is written, which the refusal must not have taken away.
	if again := mustHash(t, DiscloseReclassified(ledger, first, f.record)); mustHashBoolValue(t, again, "recorded") {
		t.Fatalf("the same reclassification was recorded twice: %s", again.Inspect())
	}
	// And the refusal's advice is accepted: the line ends at first, so second
	// reclassifying first is recorded.
	if ok := mustHash(t, DiscloseReclassified(ledger, second, first)); !mustHashBoolValue(t, ok, "recorded") {
		t.Fatalf("reclassifying the head of the line was not recorded: %s", ok.Inspect())
	}
}

// The walk back ends where the ledger gives it no single way back: at a record
// that reclassifies two, which starts a line of its own, and -- rather than
// going round -- in a ledger recording two records as reclassifying each other.
func TestALineWalkEndsWhereTheLedgerGivesItNoSingleWayBack(t *testing.T) {
	f := newDiscloseFixture(t)
	ledger := intObj(f.ledger)
	a, aUID := f.record, recordUIDOf(t, f.record)
	b, bUID := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(150), stringObj("restricted"))),
	))
	c, cUID := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	))
	mustHash(t, DiscloseReclassified(ledger, c, a))
	mustHash(t, DiscloseReclassified(ledger, c, b))
	session, _ := ledgerGet(f.ledger)
	if got, err := redactionLine(session, cUID); err != nil || got != cUID {
		t.Fatalf("the line of a record reclassifying two is %q: %v", got, err)
	}
	// b reclassifying a, and a reclassifying b, are both refused now: a and b
	// each already have c recorded as reclassifying them, and a record is
	// reclassified once (M26-REC-023). The walk still has to end rather than go
	// round on a ledger that holds the cycle anyway, so the two edges are
	// written directly.
	f.supersedesEdge(t, session, bUID, aUID)
	f.supersedesEdge(t, session, aUID, bUID)
	for _, uid := range []string{aUID, bUID} {
		if got, err := redactionLine(session, uid); err != nil || (got != aUID && got != bUID) {
			t.Fatalf("the line of %s, in a ledger going round, is %q: %v", uid, got, err)
		}
	}
}

// Every reader refuses a version chain this program did not write: two
// versions after one, a version in the chain of another view, a version that
// keeps another case's line, and a disclosure naming a version other than the
// one it is recorded as redacted as.
func TestAVersionChainThisProgramDidNotWriteIsRefused(t *testing.T) {
	type forgery struct {
		name      string
		forge     func(w *caseWriter, caseUID, uid string, v1 caseChainEvent) error
		want      string
		discloses bool
	}
	appendAfter := func(w *caseWriter, caseUID, uid string, v1 caseChainEvent, props map[string]string) error {
		all := map[string]string{"redaction.case_uid": caseUID, "redaction.line": uid,
			"redaction.view_canonical": "counsel"}
		maps.Copy(all, props)
		_, _, err := w.tx.chainAppend(redactionChain, redactionChainKey(caseUID, uid, "counsel"), &v1, all)
		return err
	}
	for _, c := range []forgery{
		{"two versions after one", func(w *caseWriter, caseUID, uid string, v1 caseChainEvent) error {
			if err := appendAfter(w, caseUID, uid, v1, map[string]string{"redaction.partition": "0"}); err != nil {
				return err
			}
			return appendAfter(w, caseUID, uid, v1, map[string]string{"redaction.partition": "00"})
		}, "two redaction events after", true},
		{"a version of another view", func(w *caseWriter, caseUID, uid string, v1 caseChainEvent) error {
			return appendAfter(w, caseUID, uid, v1, map[string]string{"redaction.view_canonical": "regulator"})
		}, `under view "counsel" and names line`, true},
		{"a version keeping another case's line", func(w *caseWriter, caseUID, uid string, v1 caseChainEvent) error {
			_, err := w.tx.node(disclosureNodeRedactionVersion, map[string]string{"redaction.line": uid,
				"redaction.case_uid": strings.Repeat("f", 32), "redaction.uid": strings.Repeat("e", 64),
				"redaction.chain": "elsewhere", "redaction.view_canonical": "counsel"})
			return err
		}, "names case ffff", false},
		{"a disclosure naming another version", func(w *caseWriter, caseUID, uid string, v1 caseChainEvent) error {
			id, err := w.tx.node(disclosureNodeDisclosure, map[string]string{"disclosure.uid": strings.Repeat("d", 32),
				"disclosure.record_uid": uid, "disclosure.redaction_uid": strings.Repeat("0", 64)})
			if err != nil {
				return err
			}
			return w.tx.edge(id, v1.id, disclosureEdgeRedactedAs, nil)
		}, "and names version", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newDiscloseFixture(t)
			f.issue(t, "counsel", "Counsel")
			session, _ := ledgerGet(f.ledger)
			uid := recordUIDOf(t, f.record)
			caseUID := openCaseUID(t)
			disclosureLedgerMu.Lock()
			events, err := redactionChainOf(session.graph, caseUID, uid, "counsel")
			if err == nil {
				var w *caseWriter
				if w, err = caseBeginWrite(session, caseUID, "IR-REC", custodyNow()); err == nil {
					if err = c.forge(w, caseUID, uid, events[0]); err == nil {
						err = w.tx.commit()
					}
				}
			}
			disclosureLedgerMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			mustRefuse(t, "redaction_versions", RedactionVersions(intObj(f.ledger), stringObj(uid)), c.want)
			if !c.discloses {
				return
			}
			issued, prompts := countDisclosureWork(t)
			mustRefuse(t, "a disclosure", DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"),
				stringObj("Counsel")), c.want)
			if *issued != 0 || *prompts != 0 {
				t.Fatalf("the disclosure was refused after %d grants and %d passphrases", *issued, *prompts)
			}
		})
	}
}

// redaction_versions needs no case open: an auditor reads it with the ledger
// alone. A record the ledger does not know is an answer, and a disclosure
// that names no version is counted.
func TestRedactionVersionsNeedNoCase(t *testing.T) {
	f := newDiscloseFixture(t)
	f.issue(t, "counsel", "Counsel")
	uid := recordUIDOf(t, f.record)
	// A disclosure recorded before versions were, which names none.
	session, _ := ledgerGet(f.ledger)
	disclosureLedgerMu.Lock()
	tx := disclosureBegin(session)
	_, err := tx.node(disclosureNodeDisclosure, map[string]string{"disclosure.uid": strings.Repeat("ab", 16),
		"disclosure.record_uid": uid})
	if err == nil {
		err = tx.commit()
	}
	disclosureLedgerMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	LedgerClose(intObj(f.ledger))
	resetCustodyForTesting()

	opened, errObj := ledgerOpenAs(t, f.ledgerDir, "auditor", "auditor")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	handle := intObj(mustHashIntValue(t, opened, "handle"))
	versions := mustHash(t, RedactionVersions(handle, stringObj(strings.ToUpper(uid))))
	if !mustHashBoolValue(t, versions, "record_known") || mustHashIntValue(t, versions, "count") != 1 ||
		mustHashIntValue(t, versions, "disclosure_count") != 1 || mustHashIntValue(t, versions, "unversioned") != 1 {
		t.Fatalf("an auditor's redaction_versions gave %s", versions.Inspect())
	}
	unknown := mustHash(t, RedactionVersions(handle, stringObj(strings.Repeat("cd", 16))))
	if mustHashBoolValue(t, unknown, "record_known") || mustHashIntValue(t, unknown, "count") != 0 {
		t.Fatalf("a record the ledger does not know gave %s", unknown.Inspect())
	}
	mustRefuse(t, "not a record uid", RedactionVersions(handle, stringObj("xyz")), "is not a record uid")
}
