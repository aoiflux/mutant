package builtin

// Reclassification, and the one question it raises that a disclosure record
// can answer.
//
// A classification that changes after a disclosure cannot reach what was
// disclosed: the recipient holds the record and the material, and both are
// theirs. The honest substitute for taking it back is a query -- which
// recipients hold bytes whose class has since changed, and would their posture
// still grant those bytes today? -- and this file is that query, together with
// the ledger entry that makes it answerable later.
//
// # Append-only, by construction
//
// A record is sealed once, so a reclassification is never an edit. It is a NEW
// record over the same evidence, and a SUPERSEDES edge from the new record to
// the old. The old Record node is never updated -- graphene keeps no history of
// an update, and the next compaction would erase what it said -- and the old
// record stays disclosable by nobody: `disclose_to_passphrase` refuses a record
// that has been superseded and names the one that superseded it.
//
// # "Raised" is not a word this file uses
//
// The design asked which recipients hold segments whose class was RAISED.
// Nothing in the record format or the class table orders one class above
// another -- the rounding work established that the hard way -- so "raised"
// cannot be computed, and a tool that printed it would be supplying a judgement
// that belongs to the examiner. What can be computed is exact: which byte
// ranges changed class, from what to what, which disclosures granted any of
// them, and whether each disclosure's view grants the NEW class. A recipient
// whose view does not grant the new class holds bytes that the classification
// now in force would withhold from them. That is the list a reviewer needs,
// and it is stated in those terms rather than in terms of up and down.
//
// # Same evidence, checked rather than assumed
//
// Two records are the same evidence only if they decrypt to the same
// plaintext. Each record's footer carries the whole-plaintext SHA-256 sealed
// under its own record key, so both are opened -- which needs the case key,
// and is why both handles must have been opened with it -- and compared. The
// digest is never written anywhere: a published digest over plaintext confirms
// guessed plaintext, which is why the format encrypts it in the first place.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// reclassRange is one run of bytes whose class differs between two records.
type reclassRange struct {
	offset uint64
	length uint64
	from   string
	to     string
}

// recordPlaintextDigest opens a record's sealed meta and returns the
// whole-plaintext SHA-256 it carries. It needs the case key.
func recordPlaintextDigest(session *recordSession) (string, error) {
	if session.keys == nil {
		return "", fmt.Errorf("%s was opened under a grant, and a grant does not open a record's sealed "+
			"metadata; open it with the case key", session.path)
	}
	nonceBytes, err := hex.DecodeString(session.footer.SealedMeta.Nonce)
	if err != nil {
		return "", err
	}
	nonce, err := security.XNonceFromSlice(nonceBytes)
	if err != nil {
		return "", err
	}
	blob, err := hex.DecodeString(session.footer.SealedMeta.Blob)
	if err != nil {
		return "", err
	}
	plain, err := session.keys.OpenMeta(nonce, blob)
	if err != nil {
		return "", fmt.Errorf("%s: its sealed metadata does not open under its own record key", session.path)
	}
	var meta security.RecordMeta
	if err := json.Unmarshal(plain, &meta); err != nil {
		return "", fmt.Errorf("%s: its sealed metadata is not what a record seals: %w", session.path, err)
	}
	return meta.PlaintextSHA256, nil
}

// reclassChanges walks two span lists over the same plaintext and returns every
// byte range where the class differs, merged where adjacent ranges moved
// between the same two classes.
func reclassChanges(before, after []security.RecordSpan) []reclassRange {
	var out []reclassRange
	i, j := 0, 0
	for i < len(before) && j < len(after) {
		a, b := before[i], after[j]
		start := a.Offset
		if b.Offset > start {
			start = b.Offset
		}
		aEnd, bEnd := a.Offset+a.Length, b.Offset+b.Length
		end := aEnd
		if bEnd < end {
			end = bEnd
		}
		from, to := strings.ToLower(a.Class), strings.ToLower(b.Class)
		if end > start && from != to {
			if n := len(out); n > 0 && out[n-1].offset+out[n-1].length == start &&
				out[n-1].from == from && out[n-1].to == to {
				out[n-1].length += end - start
			} else {
				out = append(out, reclassRange{offset: start, length: end - start, from: from, to: to})
			}
		}
		if aEnd == end {
			i++
		}
		if bEnd == end {
			j++
		}
	}
	return out
}

func reclassText(ranges []reclassRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		parts = append(parts, fmt.Sprintf("%d+%d:%s>%s", r.offset, r.length, r.from, r.to))
	}
	return strings.Join(parts, ";")
}

// DiscloseReclassified records that one record reclassifies another and reports
// who holds bytes whose class changed: disclose_reclassified(ledger, record, superseded).
func DiscloseReclassified(args ...object.Object) object.Object {
	op := BuiltinNameDiscloseReclassified
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	current, errObj := disclosureRecordArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	previous, errObj := disclosureRecordArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	facts, errObj := disclosureCase(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	newUID := strings.ToLower(current.header.RecordUID)
	oldUID := strings.ToLower(previous.header.RecordUID)
	switch {
	case newUID == oldUID:
		return resultAndError(nil, newError("%s: a record cannot reclassify itself", op))
	case !strings.EqualFold(current.header.CaseUID, facts.caseUID) || !strings.EqualFold(previous.header.CaseUID, facts.caseUID):
		return resultAndError(nil, newError("%s: both records must belong to the open case", op))
	case current.header.PlaintextLength != previous.header.PlaintextLength:
		return resultAndError(nil, newError("%s: record %s holds %d bytes and record %s holds %d, so they are not "+
			"the same evidence; a reclassification is the same bytes under different classes", op,
			newUID, current.header.PlaintextLength, oldUID, previous.header.PlaintextLength))
	}
	newDigest, err := recordPlaintextDigest(current)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	oldDigest, err := recordPlaintextDigest(previous)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	if newDigest != oldDigest {
		return resultAndError(nil, newError("%s: records %s and %s do not decrypt to the same plaintext, so one "+
			"cannot reclassify the other. A reclassification is the same evidence sealed again under different "+
			"classes", op, newUID, oldUID))
	}
	changes := reclassChanges(previous.header.Spans, current.header.Spans)

	labels := map[string]string{}
	custodyStore.RLock()
	if session := custodyStore.session; session != nil {
		for _, class := range session.classes {
			labels[strings.ToLower(class.Tag)] = class.Label
		}
	}
	custodyStore.RUnlock()

	event, recorded, errObj := reclassWrite(op, ledger, facts, current, previous, changes, labels)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	affected, changedHeld, errObj := reclassAffected(op, ledger, previous, changes, labels)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var changedBytes uint64
	rows := make([]object.Object, 0, len(changes))
	for _, c := range changes {
		changedBytes += c.length
		rows = append(rows, makeHashObject(map[string]object.Object{
			"offset":     intObj(int64(c.offset)),
			"length":     intObj(int64(c.length)),
			"from_class": stringObj(c.from),
			"from_label": stringObj(labels[c.from]),
			"to_class":   stringObj(c.to),
			"to_label":   stringObj(labels[c.to]),
		}))
	}
	if recorded {
		custodyRecordArtifact(op, fmt.Sprintf("record %s recorded as reclassifying record %s: %d bytes changed class",
			newUID, oldUID, changedBytes), map[string]any{
			"record_uid":     newUID,
			"superseded_uid": oldUID,
			"changed_bytes":  int64(changedBytes),
			"ledger_node":    int64(event.id),
		})
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"record_uid":         stringObj(newUID),
		"superseded_uid":     stringObj(oldUID),
		"same_plaintext":     boolObj(true),
		"changed":            &object.Array{Elements: rows},
		"changed_bytes":      intObj(int64(changedBytes)),
		"recorded":           boolObj(recorded),
		"already_recorded":   boolObj(!recorded),
		"reclassified_at":    stringObj(event.get("reclass.at")),
		"ledger_node":        intObj(int64(event.id)),
		"affected":           &object.Array{Elements: affected},
		"affected_count":     intObj(int64(len(affected))),
		"now_withheld_bytes": intObj(int64(changedHeld)),
		"bytes_recoverable":  boolObj(false),
		"does_not_say": stringArrayObj([]string{
			"whether a class changed upward or downward: nothing in this tool orders one class above another, and that judgement is the examiner's",
			"that a recipient has read, kept or passed on what they hold",
		}),
	}), nil)
}

// reclassWrite records the reclassification once. A second call for the same
// pair finds the first and writes nothing, so asking the question again is
// free and does not multiply the record of the answer.
func reclassWrite(op string, session *ledgerSession, facts disclosureCaseFacts, current, previous *recordSession,
	changes []reclassRange, labels map[string]string) (disclosureNode, bool, *object.Error) {
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()

	g := session.graph
	nodes, edges := disclosureTypeNames()
	if err := g.DeclareTypeNames(nodes, edges); err != nil {
		return disclosureNode{}, false, newError("%s: %s", op, err.Error())
	}
	newUID := strings.ToLower(current.header.RecordUID)
	oldUID := strings.ToLower(previous.header.RecordUID)
	pair := oldUID + ">" + newUID
	if existing, found, err := disclosureFind(g, disclosureNodeReclass, "reclass.pair", pair); err != nil {
		return disclosureNode{}, false, newError("%s: %s", op, err.Error())
	} else if found {
		if existing.get("reclass.changed") != reclassText(changes) {
			return disclosureNode{}, false, newError("%s: the ledger already records this reclassification with "+
				"different changed ranges; the records on disk are not the ones it was recorded from", op)
		}
		return existing, false, nil
	}

	tx := disclosureBegin(session)
	caseID, _, err := tx.findOrAdd(g, disclosureNodeCase, "case.uid", map[string]string{
		"case.uid": strings.ToLower(facts.caseUID),
		"case.id":  facts.id,
	})
	if err != nil {
		return disclosureNode{}, false, newError("%s: %s", op, err.Error())
	}
	actorID, _, err := tx.findOrAdd(g, disclosureNodeActor, "actor.id", map[string]string{
		"actor.id":   strconv.FormatUint(session.actorID, 10),
		"actor.name": session.actor,
	})
	if err != nil {
		return disclosureNode{}, false, newError("%s: %s", op, err.Error())
	}
	classNode := tx.classNodes(g, labels)
	recordIDs := make([]store.NodeID, 0, 2)
	for _, record := range []*recordSession{current, previous} {
		sha, size, err := disclosureFileDigest(record.path)
		if err != nil {
			return disclosureNode{}, false, newError("%s: hashing %s: %s", op, record.path, err.Error())
		}
		split := viewPartition(record, map[string]bool{})
		tallies := make([]disclosureClassTally, 0, len(split.order))
		for _, tag := range split.order {
			tallies = append(tallies, disclosureClassTally{tag: tag, segments: split.tallies[tag].segments,
				bytes: split.tallies[tag].bytes})
		}
		id, err := tx.recordNode(g, disclosureRecordFacts{
			record:       record,
			sha256:       sha,
			bytes:        size,
			headerSHA256: ledgerHash(sha256.Sum256(record.headerRaw)),
			classes:      tallies,
		}, caseID, classNode)
		if err != nil {
			return disclosureNode{}, false, newError("%s: %s", op, err.Error())
		}
		recordIDs = append(recordIDs, id)
	}
	raw, err := security.RandomDisclosureUID()
	if err != nil {
		return disclosureNode{}, false, newError("%s: %s", op, err.Error())
	}
	var changed uint64
	for _, c := range changes {
		changed += c.length
	}
	now := custodyNow()
	props := map[string]string{
		"reclass.uid":            hex.EncodeToString(raw[:]),
		"reclass.pair":           pair,
		"reclass.record_uid":     newUID,
		"reclass.superseded_uid": oldUID,
		"reclass.changed":        reclassText(changes),
		"reclass.changed_bytes":  strconv.FormatUint(changed, 10),
		"reclass.at":             now.UTC().Format(time.RFC3339Nano),
		"reclass.unix_nano":      strconv.FormatInt(now.UnixNano(), 10),
	}
	eventID, err := tx.node(disclosureNodeReclass, props)
	if err != nil {
		return disclosureNode{}, false, newError("%s: %s", op, err.Error())
	}
	for _, e := range []struct {
		src, dst store.NodeID
		label    store.EdgeType
	}{
		{recordIDs[0], recordIDs[1], disclosureEdgeSupersedes},
		{eventID, caseID, disclosureEdgeInCase},
		{eventID, actorID, disclosureEdgePerformedBy},
	} {
		if err := tx.edge(e.src, e.dst, e.label, nil); err != nil {
			return disclosureNode{}, false, newError("%s: %s", op, err.Error())
		}
	}
	if err := tx.commit(); err != nil {
		return disclosureNode{}, false, newError("%s: the reclassification could not be recorded: %s", op, err.Error())
	}
	return disclosureNode{id: eventID, props: props}, true, nil
}

// reclassAffected lists every disclosure of the superseded record whose granted
// bytes include a range that changed class, withdrawn or not, and says for each
// range whether that disclosure's view grants the new class.
func reclassAffected(op string, session *ledgerSession, previous *recordSession, changes []reclassRange,
	labels map[string]string) ([]object.Object, uint64, *object.Error) {
	rows, err := disclosureHistoryRows(session)
	if err != nil {
		return nil, 0, newError("%s: %s", op, err.Error())
	}
	oldUID := strings.ToLower(previous.header.RecordUID)
	var out []object.Object
	var nowWithheld uint64
	for _, row := range rows {
		if row.node.get("disclosure.record_uid") != oldUID {
			continue
		}
		runs, err := disclosureParseRuns(row.node.get("disclosure.granted_runs"))
		if err != nil {
			return nil, 0, newError("%s: disclosure %s: %s", op, row.node.get("disclosure.uid"), err.Error())
		}
		grants := map[string]bool{}
		if view, found, err := disclosureFind(session.graph, disclosureNodeView, "view.fp",
			row.node.get("disclosure.view_fp")); err == nil && found {
			for _, tag := range strings.Split(view.get("view.tags"), ",") {
				if tag != "" {
					grants[strings.ToLower(tag)] = true
				}
			}
		}
		// One pass over the granted segments, each located among the changed
		// ranges by binary search: changes are ascending and disjoint, so the
		// ones a segment overlaps are a contiguous run starting at the first
		// that ends past the segment's start. Rows are merged where they
		// touch, so a large granted span that changed class is one row and
		// not one per segment.
		type heldRange struct {
			start, end   uint64
			first, last  uint64
			change       reclassRange
			stillGranted bool
		}
		var merged []heldRange
		var heldBytes, withheldNow uint64
		for _, run := range runs {
			for index := run[0]; index <= run[1] && index < uint64(len(previous.segments)); index++ {
				segment := previous.segments[index]
				segStart, segEnd := segment.Offset, segment.Offset+uint64(segment.Length)
				k := sort.Search(len(changes), func(k int) bool { return changes[k].offset+changes[k].length > segStart })
				for ; k < len(changes) && changes[k].offset < segEnd; k++ {
					c := changes[k]
					start, end := segStart, segEnd
					if c.offset > start {
						start = c.offset
					}
					if c.offset+c.length < end {
						end = c.offset + c.length
					}
					if end <= start {
						continue
					}
					stillGranted := grants[c.to]
					heldBytes += end - start
					if !stillGranted {
						withheldNow += end - start
					}
					if n := len(merged); n > 0 && merged[n-1].end == start && merged[n-1].change == c {
						merged[n-1].end = end
						merged[n-1].last = index
						continue
					}
					merged = append(merged, heldRange{start: start, end: end, first: index, last: index,
						change: c, stillGranted: stillGranted})
				}
			}
		}
		if len(merged) == 0 {
			continue
		}
		held := make([]object.Object, 0, len(merged))
		for _, h := range merged {
			held = append(held, makeHashObject(map[string]object.Object{
				"offset":            intObj(int64(h.start)),
				"length":            intObj(int64(h.end - h.start)),
				"first_segment":     intObj(int64(h.first)),
				"last_segment":      intObj(int64(h.last)),
				"from_label":        stringObj(labels[h.change.from]),
				"to_label":          stringObj(labels[h.change.to]),
				"view_grants_new":   boolObj(h.stillGranted),
				"bytes_recoverable": boolObj(false),
			}))
		}
		nowWithheld += withheldNow
		out = append(out, makeHashObject(map[string]object.Object{
			"disclosure_uid": stringObj(row.node.get("disclosure.uid")),
			"recipient":      stringObj(row.node.get("disclosure.recipient")),
			"view":           stringObj(row.node.get("disclosure.view")),
			"issued_at":      stringObj(row.node.get("disclosure.at")),
			"withdrawn":      boolObj(row.withdrawn),
			"changed_held":   &object.Array{Elements: held},
			"changed_bytes":  intObj(int64(heldBytes)),
			// The number a reviewer acts on: bytes this recipient holds that
			// the classification now in force would not give them.
			"now_withheld_bytes": intObj(int64(withheldNow)),
		}))
	}
	if out == nil {
		out = []object.Object{}
	}
	return out, nowWithheld, nil
}
