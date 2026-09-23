package builtin

// What the ledger says about disclosures after the fact: withdrawing one, the
// history of all of them, and who holds a given segment.
//
// # A withdrawal is not a revocation, and nothing here is named like one
//
// Once a recipient holds the record and the grant, both halves are theirs. No
// key deletion, ledger entry or re-encryption reaches their copy, so there is
// no builtin in this family called anything like revoke and no field that
// could be read as "revoked". What a withdrawal achieves is exactly three
// things, and `disclose_withdraw` returns all three as fields:
//
//   - it is attributed and permanent: a Withdrawal node, in its own signed
//     commit, pointing at the disclosure it withdraws;
//   - it stops further grants: `disclose_to_passphrase` refuses to issue this
//     record to this recipient again, and `disclose_bundle` refuses to
//     package the withdrawn disclosure if it has not been packaged yet;
//   - it changes nothing the recipient holds, which `bytes_recoverable: false`
//     says in a field rather than a footnote.
//
// # Who holds what is a query, and it counts the withdrawn
//
// `disclose_for_segment` answers the question a withdrawal cannot: which
// recipients were given the material for this segment. A withdrawn disclosure
// is still listed -- with `withdrawn: true` beside it -- because the recipient
// still holds what they were given, and a list that dropped them would be the
// revocation this family refuses to pretend to.

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// maxWithdrawalReason bounds a reason. It is written into a signed commit that
// is never compacted away, and it is read by a person.
const maxWithdrawalReason = 4096

// disclosureRow is one disclosure as the history reports it, joined with its
// withdrawal if there is one.
type disclosureRow struct {
	node       disclosureNode
	withdrawal disclosureNode
	withdrawn  bool
}

func (r disclosureRow) render() object.Object {
	get := r.node.get
	count := func(key string) object.Object {
		n, _ := strconv.ParseInt(get(key), 10, 64)
		return intObj(n)
	}
	return makeHashObject(map[string]object.Object{
		"disclosure_uid":    stringObj(get("disclosure.uid")),
		"issued_at":         stringObj(get("disclosure.at")),
		"recipient":         stringObj(get("disclosure.recipient")),
		"view":              stringObj(get("disclosure.view")),
		"record_uid":        stringObj(get("disclosure.record_uid")),
		"examiner":          stringObj(get("disclosure.examiner")),
		"method":            stringObj(get("disclosure.method")),
		"segments":          count("disclosure.segments"),
		"granted_segments":  count("disclosure.granted_segments"),
		"withheld_segments": count("disclosure.withheld_segments"),
		"granted_runs":      stringObj(get("disclosure.granted_runs")),
		"grant_sha256":      stringObj(get("disclosure.grant_sha256")),
		"ledger_node":       intObj(int64(r.node.id)),
		"withdrawn":         boolObj(r.withdrawn),
		"withdrawn_at":      stringObj(r.withdrawal.get("withdrawal.at")),
		"withdrawal_reason": stringObj(r.withdrawal.get("withdrawal.reason")),
		// On every row, withdrawn or not: it is true of none of them.
		"bytes_recoverable": boolObj(false),
	})
}

// disclosureRows reads every disclosure and joins each to its withdrawal,
// oldest first.
func disclosureHistoryRows(session *ledgerSession) ([]disclosureRow, error) {
	disclosures, err := disclosureAll(session.graph, disclosureNodeDisclosure)
	if err != nil {
		return nil, err
	}
	withdrawals, err := disclosureAll(session.graph, disclosureNodeWithdrawal)
	if err != nil {
		return nil, err
	}
	byUID := make(map[string]disclosureNode, len(withdrawals))
	for _, w := range withdrawals {
		byUID[w.get("withdrawal.disclosure_uid")] = w
	}
	rows := make([]disclosureRow, 0, len(disclosures))
	for _, d := range disclosures {
		w, withdrawn := byUID[d.get("disclosure.uid")]
		rows = append(rows, disclosureRow{node: d, withdrawal: w, withdrawn: withdrawn})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, _ := strconv.ParseInt(rows[i].node.get("disclosure.unix_nano"), 10, 64)
		b, _ := strconv.ParseInt(rows[j].node.get("disclosure.unix_nano"), 10, 64)
		return a < b
	})
	return rows, nil
}

// ---------------------------------------------------------------------------
// disclose_withdraw
// ---------------------------------------------------------------------------

// DiscloseWithdraw records that a disclosure is withdrawn: disclose_withdraw(ledger, disclosure, reason).
func DiscloseWithdraw(args ...object.Object) object.Object {
	op := BuiltinNameDiscloseWithdraw
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	uid, errObj := disclosureUIDArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reasonArg, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason := strings.TrimSpace(reasonArg)
	switch {
	case reason == "":
		return resultAndError(nil, newError("%s: a withdrawal must state a reason, and whitespace is not one. "+
			"It is the only account anybody will have of why a disclosure was withdrawn", op))
	case len(reason) > maxWithdrawalReason:
		return resultAndError(nil, newError("%s: a reason is at most %d bytes, and this one is %d", op,
			maxWithdrawalReason, len(reason)))
	case !utf8.ValidString(reason):
		return resultAndError(nil, custodyDocumentName(op, "reason", reason))
	}

	withdrawal, errObj := disclosureWriteWithdrawal(op, ledger, uid, reason)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The run's copy, if this run issued it, is marked too, so that the case
	// manifest and disclose_bundle see the withdrawal without asking the
	// ledger again. The ledger is the authority either way.
	custodyStore.Lock()
	if session := custodyStore.session; session != nil && !session.Closed {
		for _, d := range session.disclosures {
			if d.UID == uid {
				d.Withdrawn = withdrawal.get("withdrawal.at")
			}
		}
	}
	custodyStore.Unlock()
	custodyRecordArtifact(op, fmt.Sprintf("disclosure %s withdrawn: %s", uid, reason), map[string]any{
		"disclosure_uid": uid,
		"withdrawal_uid": withdrawal.get("withdrawal.uid"),
		"reason":         reason,
		"ledger_node":    int64(withdrawal.id),
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"disclosure_uid": stringObj(uid),
		"withdrawal_uid": stringObj(withdrawal.get("withdrawal.uid")),
		"withdrawn_at":   stringObj(withdrawal.get("withdrawal.at")),
		"reason":         stringObj(reason),
		"recipient":      stringObj(withdrawal.get("withdrawal.recipient")),
		"record_uid":     stringObj(withdrawal.get("withdrawal.record_uid")),
		"ledger_node":    intObj(int64(withdrawal.id)),
		// The three things a withdrawal is, each one a field.
		"recorded":          boolObj(true),
		"further_grants":    stringObj("refused: this record will not be disclosed to this recipient again, and the withdrawn disclosure will not be packaged"),
		"bytes_recoverable": boolObj(false),
		"does_not": stringArrayObj([]string{
			"reach the recipient's copy: they hold the record and the grant, and both are theirs",
			"make the granted bytes unreadable to anybody who already has them",
			"change what any package already written says",
		}),
	}), nil)
}

// disclosureWriteWithdrawal commits one Withdrawal node and its edges, after
// checking there is something to withdraw and that it has not been withdrawn.
func disclosureWriteWithdrawal(op string, session *ledgerSession, uid, reason string) (disclosureNode, *object.Error) {
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()

	g := session.graph
	nodes, edges := disclosureTypeNames()
	if err := g.DeclareTypeNames(nodes, edges); err != nil {
		return disclosureNode{}, newError("%s: %s", op, err.Error())
	}
	disclosure, found, err := disclosureFind(g, disclosureNodeDisclosure, "disclosure.uid", uid)
	if err != nil {
		return disclosureNode{}, newError("%s: %s", op, err.Error())
	}
	if !found {
		return disclosureNode{}, newError("%s: this ledger records no disclosure %s", op, uid)
	}
	if existing, withdrawn, err := disclosureWithdrawalOf(g, uid); err != nil {
		return disclosureNode{}, newError("%s: %s", op, err.Error())
	} else if withdrawn {
		return disclosureNode{}, newError("%s: disclosure %s was already withdrawn at %s (%q). A withdrawal is "+
			"recorded once", op, uid, existing.get("withdrawal.at"), existing.get("withdrawal.reason"))
	}

	raw, err := security.RandomDisclosureUID()
	if err != nil {
		return disclosureNode{}, newError("%s: %s", op, err.Error())
	}
	now := custodyNow()
	props := map[string]string{
		"withdrawal.uid":               hex.EncodeToString(raw[:]),
		"withdrawal.disclosure_uid":    uid,
		"withdrawal.recipient":         disclosure.get("disclosure.recipient"),
		"withdrawal.record_uid":        disclosure.get("disclosure.record_uid"),
		"withdrawal.reason":            reason,
		"withdrawal.at":                now.UTC().Format(time.RFC3339Nano),
		"withdrawal.unix_nano":         strconv.FormatInt(now.UnixNano(), 10),
		"withdrawal.bytes_recoverable": "false",
	}

	tx := disclosureBegin(session)
	actorID, _, err := tx.findOrAdd(g, disclosureNodeActor, "actor.id", map[string]string{
		"actor.id":   strconv.FormatUint(session.actorID, 10),
		"actor.name": session.actor,
	})
	if err != nil {
		return disclosureNode{}, newError("%s: %s", op, err.Error())
	}
	id, err := tx.node(disclosureNodeWithdrawal, props)
	if err != nil {
		return disclosureNode{}, newError("%s: %s", op, err.Error())
	}
	for _, e := range []struct {
		dst   store.NodeID
		label store.EdgeType
	}{
		{disclosure.id, disclosureEdgeWithdrew},
		{actorID, disclosureEdgePerformedBy},
	} {
		if err := tx.edge(id, e.dst, e.label, nil); err != nil {
			return disclosureNode{}, newError("%s: %s", op, err.Error())
		}
	}
	if err := tx.commit(); err != nil {
		return disclosureNode{}, newError("%s: the withdrawal could not be recorded: %s", op, err.Error())
	}
	return disclosureNode{id: id, props: props}, nil
}

// ---------------------------------------------------------------------------
// disclose_history
// ---------------------------------------------------------------------------

// DiscloseHistory lists every disclosure this ledger records: disclose_history(ledger).
func DiscloseHistory(args ...object.Object) object.Object {
	op := BuiltinNameDiscloseHistory
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	rows, err := disclosureHistoryRows(ledger)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	rendered := make([]object.Object, 0, len(rows))
	recipients := map[string]bool{}
	records := map[string]bool{}
	var withdrawn int64
	for _, row := range rows {
		rendered = append(rendered, row.render())
		recipients[row.node.get("disclosure.recipient_fp")] = true
		records[row.node.get("disclosure.record_uid")] = true
		if row.withdrawn {
			withdrawn++
		}
	}

	// Nodes carrying a disclosure uid that are not Disclosure nodes: written
	// into this ledger by something other than this family. They are not in
	// the history, and they are counted, because a history that silently
	// skipped them would be the one reader who never learned they were there.
	var carrying uint64
	if counts, err := ledger.graph.CountNodesByProperty("disclosure.uid"); err == nil {
		for _, n := range counts {
			carrying += n
		}
	}
	foreign := int64(carrying) - int64(len(rows))
	if foreign < 0 {
		foreign = 0
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"disclosures": &object.Array{Elements: rendered},
		"count":       intObj(int64(len(rows))),
		"withdrawn":   intObj(withdrawn),
		"recipients":  intObj(int64(len(recipients))),
		"records":     intObj(int64(len(records))),
		"foreign":     intObj(foreign),
		"ledger":      stringObj(ledger.path),
		// A history is what this ledger recorded. A disclosure made with some
		// other tool, or from some other ledger, is not in it, and nothing
		// here could know.
		"does_not_say": stringArrayObj([]string{
			"what was disclosed outside this ledger: a history is complete for the ledger it is read from and says nothing about any other",
			"that a recipient received what was issued: issuing and handing over are different acts, and only the first is recorded",
		}),
	}), nil)
}

// ---------------------------------------------------------------------------
// disclose_for_segment
// ---------------------------------------------------------------------------

// DiscloseForSegment reports who was given one segment: disclose_for_segment(ledger, record_uid, segment).
func DiscloseForSegment(args ...object.Object) object.Object {
	op := BuiltinNameDiscloseForSegment
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	recordArg, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	recordUID := strings.ToLower(strings.TrimSpace(recordArg))
	if raw, err := hex.DecodeString(recordUID); err != nil || len(raw) != security.RecordUIDSize {
		return resultAndError(nil, newError("%s: %q is not a record uid; a record uid is %d hex characters",
			op, recordArg, security.RecordUIDSize*2))
	}
	index, errObj := requireIntArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if index < 0 {
		return resultAndError(nil, newError("%s: segments are numbered from 0, and %d is not one", op, index))
	}

	record, known, err := disclosureFind(ledger.graph, disclosureNodeRecord, "record.uid", recordUID)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	out := map[string]object.Object{
		"record_uid":   stringObj(recordUID),
		"segment":      intObj(index),
		"record_known": boolObj(known),
		"offset":       intObj(0),
		"length":       intObj(0),
		"class":        stringObj(""),
		"label":        stringObj(""),
	}
	if !known {
		// Not an error: "nobody, as far as this ledger knows" is an answer.
		out["held_by"] = &object.Array{Elements: []object.Object{}}
		out["count"] = intObj(0)
		out["note"] = stringObj("this ledger records no disclosure of this record, so it records nobody holding any of it")
		return resultAndError(makeHashObject(out), nil)
	}
	segment, errObj := disclosureSegmentOf(op, record, uint64(index))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	out["offset"] = intObj(int64(segment.Offset))
	out["length"] = intObj(int64(segment.Length))
	class := hex.EncodeToString(segment.Class[:])
	out["class"] = stringObj(class)
	if labelled, found, _ := disclosureFind(ledger.graph, disclosureNodeClass, "class.tag", class); found {
		out["label"] = stringObj(labelled.get("class.label"))
	}

	rows, err := disclosureHistoryRows(ledger)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	held := make([]object.Object, 0)
	var holders int64
	for _, row := range rows {
		if row.node.get("disclosure.record_uid") != recordUID {
			continue
		}
		runs, err := disclosureParseRuns(row.node.get("disclosure.granted_runs"))
		if err != nil {
			return resultAndError(nil, newError("%s: disclosure %s: %s", op, row.node.get("disclosure.uid"), err.Error()))
		}
		if !disclosureRunsContain(runs, uint64(index)) {
			continue
		}
		held = append(held, row.render())
		holders++
	}
	out["held_by"] = &object.Array{Elements: held}
	out["count"] = intObj(holders)
	out["note"] = stringObj("every recipient listed holds this segment's material, withdrawn or not: a withdrawal stops further grants and reaches nobody's copy")
	return resultAndError(makeHashObject(out), nil)
}

// disclosureSegmentOf derives one segment of a record from what its Record
// node records -- the spans, the segment size and the length -- by the same
// derivation the record format itself uses, so the ledger and the file cannot
// number segments differently.
func disclosureSegmentOf(op string, record disclosureNode, index uint64) (security.RecordSegment, *object.Error) {
	size, err := strconv.ParseUint(record.get("record.segment_size"), 10, 32)
	if err != nil {
		return security.RecordSegment{}, newError("%s: the ledger's record of %s has no usable segment size", op, record.get("record.uid"))
	}
	length, err := strconv.ParseUint(record.get("record.plaintext_length"), 10, 64)
	if err != nil {
		return security.RecordSegment{}, newError("%s: the ledger's record of %s has no usable length", op, record.get("record.uid"))
	}
	header := &security.RecordHeader{PlaintextLength: length, SegmentSize: uint32(size)}
	for _, part := range strings.Split(record.get("record.spans"), ";") {
		var offset, spanLength uint64
		var tag string
		if _, err := fmt.Sscanf(strings.Replace(part, ":", " ", 1), "%d+%d %s", &offset, &spanLength, &tag); err != nil {
			return security.RecordSegment{}, newError("%s: the ledger's record of %s has a span %q it cannot read", op, record.get("record.uid"), part)
		}
		header.Spans = append(header.Spans, security.RecordSpan{Offset: offset, Length: spanLength, Class: tag})
	}
	count, err := header.SegmentCount()
	if err != nil {
		return security.RecordSegment{}, newError("%s: the ledger's record of %s: %s", op, record.get("record.uid"), err.Error())
	}
	if index >= count {
		return security.RecordSegment{}, newError("%s: record %s has %d segments, numbered from 0, and %d is not one of them",
			op, record.get("record.uid"), count, index)
	}
	segments, err := header.Segments()
	if err != nil {
		return security.RecordSegment{}, newError("%s: %s", op, err.Error())
	}
	return segments[index], nil
}
