package builtin

// Redaction versions: what a view releases from a piece of evidence, recorded
// each time it changes, so that every disclosure says which redaction it was
// issued under and a reviewer can ask which ones were issued under a redaction
// that is no longer the one in force.
//
// # What a version records
//
// A view divides a record into the segments it grants and the segments it
// withholds. A RedactionVersion node records that division as plaintext byte
// ranges rather than segment indices, because the evidence outlives its
// record: a reclassification seals the same bytes again under other classes,
// as a new record with its own segments, and the two can only be compared in
// bytes. If the new record's view releases exactly the bytes the old one's
// did, the redaction has not changed and no version is written. A version is
// written only when what the view releases changes.
//
// # The line
//
// The versions of one piece of evidence under one view are a chain, hash-linked
// like a case's lifecycle (case_chain.go). Which chain -- the line -- is found
// by walking back from the record through the reclassifications the ledger
// records, SUPERSEDES by SUPERSEDES, and it stops at the first record that
// already keys a line: versions are never left behind by a reclassification
// recorded after they were written. With no such record on the way, it stops at
// the first record of the evidence, at a record that reclassifies more than one
// (a consolidation starts a line of its own), or at a record already passed,
// which a ledger recording two records as reclassifying each other would
// otherwise walk forever.
//
// # Stale
//
// A disclosure names the version it was issued under, and `redaction_versions`
// calls every disclosure issued under a version that is no longer the head of
// its chain stale: its recipient holds a redaction this evidence is no longer
// disclosed under. Like a withdrawal, that reaches nobody's copy. It is a
// question a reviewer can now ask of the ledger, and the answer is exact.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

var redactionChain = caseChainSpec{label: disclosureNodeRedactionVersion, prefix: "redaction"}

// maxRedactionLine bounds the walk back through a record's reclassifications.
// Each step is a reclassification an examiner recorded, so a line longer than
// this is not one anybody recorded by hand, and the walk refuses it rather than
// following it.
//
//mutant:limit count
const maxRedactionLine = 4096

// redactionPartition is what a view releases from a record, in the terms every
// record of the same evidence shares: its plaintext length and the byte ranges
// granted, merged across classes.
type redactionPartition struct {
	length        uint64
	granted       string // "offset+length,..."
	grantedBytes  uint64
	withheldBytes uint64
	digest        string
}

// redactionPartitionOf reads a record's partition by a view from the split
// every disclose_* builtin computes, so that the version a disclosure names is
// the division it issued.
func redactionPartitionOf(record *recordSession, split viewSplit) redactionPartition {
	var ranges [][2]uint64
	for _, run := range split.grantedRuns {
		if n := len(ranges); n > 0 && ranges[n-1][0]+ranges[n-1][1] == run.offset {
			ranges[n-1][1] += run.length
			continue
		}
		ranges = append(ranges, [2]uint64{run.offset, run.length})
	}
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		parts = append(parts, strconv.FormatUint(r[0], 10)+"+"+strconv.FormatUint(r[1], 10))
	}
	p := redactionPartition{
		length:        record.header.PlaintextLength,
		granted:       strings.Join(parts, ","),
		grantedBytes:  split.grantedBytes,
		withheldBytes: split.withheldBytes,
	}
	p.digest = redactionPartitionDigest(p.length, p.granted)
	return p
}

// redactionPartitionDigest is the SHA-256 two partitions are compared by,
// over length-prefixed fields so that no two partitions hash alike by moving a
// separator.
func redactionPartitionDigest(length uint64, granted string) string {
	h := sha256.New()
	for _, field := range []string{"mutant-redaction-v1", strconv.FormatUint(length, 10), granted} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		h.Write(n[:])
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// redactionChainKey names the chain of one line's versions under one view. The
// view is named by its canonical name, hashed, because a view name may carry
// any character the separator could be.
func redactionChainKey(caseUID, line, canonical string) string {
	return strings.ToLower(caseUID) + "|" + line + "|" + ledgerHash(sha256Of("mutant-view-name-v1|"+canonical))
}

// redactionKeysALine reports whether any version is kept in the line a record
// keys.
func redactionKeysALine(g *graphene.Graph, recordUID string) (bool, error) {
	ids, err := g.NodesByProperty("redaction.line", []byte(recordUID))
	if err != nil || len(ids) == 0 {
		return false, err
	}
	nodes, _, err := g.GetNodes(ids)
	if err != nil {
		return false, err
	}
	for _, node := range nodes {
		if node.HasLabel(disclosureNodeRedactionVersion) {
			return true, nil
		}
	}
	return false, nil
}

// redactionReclassifies returns the uids of the records the ledger records a
// record as reclassifying, sorted and without repeats.
func redactionReclassifies(ledger *ledgerSession, recordUID string) ([]string, error) {
	record, found, err := disclosureFind(ledger.graph, disclosureNodeRecord, "record.uid", recordUID)
	if err != nil || !found {
		return nil, err
	}
	edges, err := ledger.store.EdgesOf(record.id, store.DirectionOutbound, []store.EdgeType{disclosureEdgeSupersedes})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, edge := range edges {
		node, err := ledger.graph.GetNode(edge.Dst)
		if err != nil {
			return nil, err
		}
		if !node.HasLabel(disclosureNodeRecord) {
			return nil, fmt.Errorf("record %s is recorded as reclassifying node %d, which is not a record",
				recordUID, edge.Dst)
		}
		decoded, err := disclosureDecode(node)
		if err != nil {
			return nil, err
		}
		if previous := decoded.get("record.uid"); !seen[previous] {
			seen[previous] = true
			out = append(out, previous)
		}
	}
	sort.Strings(out)
	return out, nil
}

// redactionLine returns the record whose uid keys the line of versions a
// record's redaction is kept in. See the file comment for where the walk
// stops, and why there.
func redactionLine(ledger *ledgerSession, recordUID string) (string, error) {
	current := strings.ToLower(recordUID)
	visited := map[string]bool{}
	for steps := 0; ; steps++ {
		if steps == maxRedactionLine {
			return "", fmt.Errorf("record %s is reached by more than %d reclassifications, and a line that long is "+
				"not one this program walks", recordUID, maxRedactionLine)
		}
		visited[current] = true
		keyed, err := redactionKeysALine(ledger.graph, current)
		if err != nil || keyed {
			return current, err
		}
		previous, err := redactionReclassifies(ledger, current)
		if err != nil {
			return "", err
		}
		if len(previous) != 1 || visited[previous[0]] {
			return current, nil
		}
		current = previous[0]
	}
}

// redactionChainOf reads one line's versions under one view, first to head,
// and refuses a version that does not name the case, the line and the view its
// chain is for.
func redactionChainOf(g *graphene.Graph, caseUID, line, canonical string) ([]caseChainEvent, error) {
	caseUID = strings.ToLower(caseUID)
	events, err := caseChainRead(g, redactionChain, redactionChainKey(caseUID, line, canonical))
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if event.get("redaction.case_uid") != caseUID || event.get("redaction.line") != line ||
			event.get("redaction.view_canonical") != canonical {
			return nil, fmt.Errorf("redaction version node %d is in the chain of line %s under view %q and names "+
				"line %s under view %q", event.id, line, canonical, event.get("redaction.line"),
				event.get("redaction.view_canonical"))
		}
	}
	return events, nil
}

// redactionResolve finds the line a record's redaction under a view is kept
// in, and returns its versions and, when its head already divides the evidence
// as partition does, the head to reuse. The caller holds disclosureLedgerMu.
func redactionResolve(ledger *ledgerSession, caseUID, recordUID string, view caseView,
	partition redactionPartition) (string, []caseChainEvent, *caseChainEvent, error) {
	line, err := redactionLine(ledger, recordUID)
	if err != nil {
		return "", nil, nil, err
	}
	events, err := redactionChainOf(ledger.graph, caseUID, line, view.Canonical)
	if err != nil {
		return "", nil, nil, err
	}
	if head := caseChainHead(events); head != nil && head.get("redaction.partition") == partition.digest {
		return line, events, head, nil
	}
	return line, events, nil, nil
}

// redactionTerms is one version as it is about to be written.
type redactionTerms struct {
	line      string
	view      caseView
	record    *recordSession
	partition redactionPartition
	// runs are the granted segment runs of record.
	runs   [][2]uint64
	reason string
}

// redactionAppend buffers a version after head, with its edges: IN_CASE to the
// case, GRANTS to the record it divides, AUTHORISED_BY to the view that divides
// it, PERFORMED_BY to the actor, and -- from chainAppend -- REVISES to head.
// These are the edges a Disclosure has, because a version is what a disclosure
// under the view would release from the record.
func (w *caseWriter) redactionAppend(head *caseChainEvent, terms redactionTerms, recordN,
	viewN store.NodeID) (caseChainEvent, error) {
	runs := disclosureRunsText(terms.runs)
	id, event, err := w.tx.chainAppend(redactionChain, redactionChainKey(w.caseUID, terms.line, terms.view.Canonical),
		head, map[string]string{
			"redaction.case_uid":         w.caseUID,
			"redaction.line":             terms.line,
			"redaction.view":             terms.view.Label,
			"redaction.view_canonical":   terms.view.Canonical,
			"redaction.view_fp":          disclosureViewFingerprint(terms.view),
			"redaction.record_uid":       strings.ToLower(terms.record.header.RecordUID),
			"redaction.segments":         strconv.Itoa(len(terms.record.segments)),
			"redaction.granted_runs":     runs,
			"redaction.plaintext_length": strconv.FormatUint(terms.partition.length, 10),
			"redaction.granted":          terms.partition.granted,
			"redaction.granted_bytes":    strconv.FormatUint(terms.partition.grantedBytes, 10),
			"redaction.withheld_bytes":   strconv.FormatUint(terms.partition.withheldBytes, 10),
			"redaction.partition":        terms.partition.digest,
			"redaction.reason":           terms.reason,
			"redaction.by":               w.ledger.actor,
			"redaction.by_role":          w.ledger.role.Name,
			"redaction.at":               w.at.UTC().Format(time.RFC3339Nano),
			"redaction.unix_nano":        strconv.FormatInt(w.at.UnixNano(), 10),
		})
	if err != nil {
		return caseChainEvent{}, err
	}
	for _, e := range []struct {
		dst   store.NodeID
		label store.EdgeType
		props map[string]string
	}{
		{w.caseN, disclosureEdgeInCase, nil},
		{recordN, disclosureEdgeGrants, map[string]string{"granted_runs": runs}},
		{viewN, disclosureEdgeAuthorisedBy, nil},
		{w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(w.ledger)},
	} {
		if err := w.tx.edge(id, e.dst, e.label, e.props); err != nil {
			return caseChainEvent{}, err
		}
	}
	return event, nil
}

// redactionVersionRow is one version as redaction_commit and
// redaction_versions report it.
func redactionVersionRow(event caseChainEvent, inForce bool) map[string]object.Object {
	count := func(key string) object.Object {
		n, _ := strconv.ParseInt(event.get(key), 10, 64)
		return intObj(n)
	}
	return map[string]object.Object{
		"version":          intObj(int64(event.seq)),
		"uid":              stringObj(event.uid),
		"view":             stringObj(event.get("redaction.view")),
		"record_uid":       stringObj(event.get("redaction.record_uid")),
		"partition":        stringObj(event.get("redaction.partition")),
		"granted":          stringObj(event.get("redaction.granted")),
		"granted_bytes":    count("redaction.granted_bytes"),
		"withheld_bytes":   count("redaction.withheld_bytes"),
		"plaintext_length": count("redaction.plaintext_length"),
		"granted_runs":     stringObj(event.get("redaction.granted_runs")),
		"reason":           stringObj(event.get("redaction.reason")),
		"by":               stringObj(event.get("redaction.by")),
		"by_role":          stringObj(event.get("redaction.by_role")),
		"at":               stringObj(event.get("redaction.at")),
		"in_force":         boolObj(inForce),
	}
}

// ---------------------------------------------------------------------------
// redaction_commit
// ---------------------------------------------------------------------------

// RedactionCommit records how a view divides a record as a version of that
// evidence's redaction, ahead of any disclosure under it:
// redaction_commit(ledger, record, view, reason).
func RedactionCommit(args ...object.Object) object.Object {
	op := BuiltinNameRedactionCommit
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	record, errObj := disclosureRecordArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	viewName, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason, errObj := caseTextArg(op, args[3], 4, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	facts, errObj := disclosureCase(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if !strings.EqualFold(record.header.CaseUID, facts.caseUID) {
		return resultAndError(nil, newError("%s: the record belongs to case %s and the open case is %s; a view "+
			"is a posture over one case's classes and cannot divide another's", op, record.header.CaseUID,
			facts.caseUID))
	}
	view, labels, errObj := viewResolve(op, viewName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	// The same partition view_preview reports and a disclosure issues.
	split := viewPartition(record, viewGrantedTags(view))
	partition := redactionPartitionOf(record, split)
	recordSHA, recordBytes, err := disclosureFileDigest(record.path)
	if err != nil {
		return resultAndError(nil, newError("%s: hashing %s: %s", op, record.path, err.Error()))
	}
	classLabel := map[string]string{}
	for tag, class := range labels {
		classLabel[strings.ToLower(tag)] = class.Label
	}
	tallies := make([]disclosureClassTally, 0, len(split.order))
	for _, tag := range split.order {
		tallies = append(tallies, disclosureClassTally{tag: tag, segments: split.tallies[tag].segments,
			bytes: split.tallies[tag].bytes})
	}
	recordUID := strings.ToLower(record.header.RecordUID)

	custodyStore.Lock()
	defer custodyStore.Unlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := session.ledgerElsewhereLocked(op, ledger); errObj != nil {
		return resultAndError(nil, errObj)
	}

	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	g := ledger.graph
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := disclosureDeclareNames(ledger); err != nil {
		return fail(err)
	}
	if err := caseLedgerStateRefusal(g, facts.caseUID, caseActRedact); err != nil {
		return fail(err)
	}
	if event, superseded, err := disclosureFind(g, disclosureNodeReclass, "reclass.superseded_uid", recordUID); err != nil {
		return fail(err)
	} else if superseded {
		return fail(fmt.Errorf("record %s was reclassified by record %s at %s, so what a view releases from it is "+
			"not the redaction in force. Commit the record that superseded it", recordUID,
			event.get("reclass.record_uid"), event.get("reclass.at")))
	}
	line, events, reuse, err := redactionResolve(ledger, facts.caseUID, recordUID, view, partition)
	if err != nil {
		return fail(err)
	}
	result := func(event caseChainEvent, committed bool) object.Object {
		fields := redactionVersionRow(event, true)
		fields["record_uid"] = stringObj(recordUID)
		fields["computed_on"] = stringObj(event.get("redaction.record_uid"))
		fields["line"] = stringObj(line)
		fields["previous_uid"] = stringObj(event.prev)
		fields["committed"] = boolObj(committed)
		fields["already_committed"] = boolObj(!committed)
		fields["role_authenticated"] = boolObj(false)
		return makeHashObject(fields)
	}
	if reuse != nil {
		// Committing the redaction in force again writes nothing, so asking
		// is free and does not multiply the record of the answer.
		return resultAndError(result(*reuse, false), nil)
	}

	now := custodyNow()
	w, err := caseBeginWrite(ledger, facts.caseUID, facts.id, now)
	if err != nil {
		return fail(err)
	}
	classNode := w.tx.classNodes(g, classLabel)
	recordN, err := w.tx.recordNode(g, disclosureRecordFacts{
		record:       record,
		sha256:       recordSHA,
		bytes:        recordBytes,
		headerSHA256: ledgerHash(sha256.Sum256(record.headerRaw)),
		classes:      tallies,
	}, w.caseN, classNode)
	if err != nil {
		return fail(err)
	}
	viewN, err := w.tx.viewNode(g, view, disclosureViewFingerprint(view), classNode)
	if err != nil {
		return fail(err)
	}
	event, err := w.redactionAppend(caseChainHead(events), redactionTerms{
		line:      line,
		view:      view,
		record:    record,
		partition: partition,
		runs:      disclosureSegmentRuns(split.granted),
		reason:    reason,
	}, recordN, viewN)
	if err != nil {
		return fail(err)
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	session.appendEvent(now, op, fmt.Sprintf("redaction of record %s under view %q committed as version %d: %s",
		recordUID, view.Label, event.seq, reason), map[string]any{
		"record_uid": recordUID, "view": view.Label, "version": int64(event.seq), "uid": event.uid, "line": line,
		"granted_bytes": int64(partition.grantedBytes), "withheld_bytes": int64(partition.withheldBytes),
	})
	return resultAndError(result(event, true), nil)
}

// ---------------------------------------------------------------------------
// redaction_versions
// ---------------------------------------------------------------------------

// redactionDisclosure is one disclosure issued under a version.
type redactionDisclosure struct {
	node    disclosureNode
	version caseChainEvent
	stale   bool
}

// RedactionVersions lists the versions of a record's redaction and the
// disclosures issued under each: redaction_versions(ledger, record_uid).
func RedactionVersions(args ...object.Object) object.Object {
	op := BuiltinNameRedactionVersions
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
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
		return resultAndError(nil, newError("%s: %q is not a record uid; a record uid is %d hex characters", op,
			recordArg, security.RecordUIDSize*2))
	}
	g := ledger.graph
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }

	out := map[string]object.Object{
		"record_uid":       stringObj(recordUID),
		"record_known":     boolObj(false),
		"case_uid":         stringObj(""),
		"line":             stringObj(""),
		"versions":         &object.Array{Elements: []object.Object{}},
		"count":            intObj(0),
		"disclosures":      &object.Array{Elements: []object.Object{}},
		"disclosure_count": intObj(0),
		"stale":            intObj(0),
		"unversioned":      intObj(0),
		"does_not_say": stringArrayObj([]string{
			"whether the bytes a version releases are the right ones: a version records a redaction, it does not judge it",
			"what the recipient of a stale disclosure has done with it: a later version reaches nobody's copy",
			"versions of this evidence kept in another line: a reclassification recorded after a record's " +
				"redaction already had versions of its own leaves them in that record's line, which " +
				"redaction_versions of that record reads",
		}),
	}
	record, known, err := disclosureFind(g, disclosureNodeRecord, "record.uid", recordUID)
	if err != nil {
		return fail(err)
	}
	if !known {
		// Not an error: "nothing, as far as this ledger knows" is an answer.
		return resultAndError(makeHashObject(out), nil)
	}
	caseUID := record.get("record.case_uid")
	line, err := redactionLine(ledger, recordUID)
	if err != nil {
		return fail(err)
	}
	out["record_known"], out["case_uid"], out["line"] = boolObj(true), stringObj(caseUID), stringObj(line)

	// Every view this line holds versions under, from the versions keyed to it.
	ids, err := g.NodesByProperty("redaction.line", []byte(line))
	if err != nil {
		return fail(err)
	}
	nodes, _, err := g.GetNodes(ids)
	if err != nil {
		return fail(err)
	}
	views := map[string]bool{}
	for _, node := range nodes {
		if !node.HasLabel(disclosureNodeRedactionVersion) {
			continue
		}
		decoded, err := disclosureDecode(node)
		if err != nil {
			return fail(fmt.Errorf("redaction version node %d: %w", node.ID, err))
		}
		if decoded.get("redaction.case_uid") != caseUID {
			return fail(fmt.Errorf("redaction version node %d keeps a version of record %s, of case %s, and names "+
				"case %s", node.ID, line, caseUID, decoded.get("redaction.case_uid")))
		}
		views[decoded.get("redaction.view_canonical")] = true
	}
	canonicals := make([]string, 0, len(views))
	for canonical := range views {
		canonicals = append(canonicals, canonical)
	}
	sort.Strings(canonicals)

	var versionRows []object.Object
	var issued []redactionDisclosure
	for _, canonical := range canonicals {
		events, err := redactionChainOf(g, caseUID, line, canonical)
		if err != nil {
			return fail(err)
		}
		for i, event := range events {
			under, err := redactionIssuedUnder(ledger, event)
			if err != nil {
				return fail(err)
			}
			inForce := i == len(events)-1
			for _, d := range under {
				issued = append(issued, redactionDisclosure{node: d, version: event, stale: !inForce})
			}
			row := redactionVersionRow(event, inForce)
			row["disclosures"] = intObj(int64(len(under)))
			versionRows = append(versionRows, makeHashObject(row))
		}
	}
	sort.SliceStable(issued, func(i, j int) bool {
		a, _ := strconv.ParseInt(issued[i].node.get("disclosure.unix_nano"), 10, 64)
		b, _ := strconv.ParseInt(issued[j].node.get("disclosure.unix_nano"), 10, 64)
		return a < b
	})
	var stale int64
	disclosureRows := make([]object.Object, 0, len(issued))
	for _, d := range issued {
		_, withdrawn, err := disclosureWithdrawalOf(g, d.node.get("disclosure.uid"))
		if err != nil {
			return fail(err)
		}
		if d.stale {
			stale++
		}
		disclosureRows = append(disclosureRows, makeHashObject(map[string]object.Object{
			"disclosure_uid": stringObj(d.node.get("disclosure.uid")),
			"recipient":      stringObj(d.node.get("disclosure.recipient")),
			"recipient_role": stringObj(d.node.get("disclosure.role")),
			"view":           stringObj(d.node.get("disclosure.view")),
			"record_uid":     stringObj(d.node.get("disclosure.record_uid")),
			"issued_at":      stringObj(d.node.get("disclosure.at")),
			"version":        intObj(int64(d.version.seq)),
			"redaction_uid":  stringObj(d.version.uid),
			"withdrawn":      boolObj(withdrawn),
			"stale":          boolObj(d.stale),
		}))
	}

	// Disclosures of this record that name no version were issued before
	// versions were recorded. They are counted, because a list that skipped
	// them silently would be the one reader who never learned they were there;
	// disclose_history lists them.
	var unversioned int64
	if ids, err := g.NodesByProperty("disclosure.record_uid", []byte(recordUID)); err != nil {
		return fail(err)
	} else if len(ids) > 0 {
		nodes, _, err := g.GetNodes(ids)
		if err != nil {
			return fail(err)
		}
		for _, node := range nodes {
			if !node.HasLabel(disclosureNodeDisclosure) {
				continue
			}
			decoded, err := disclosureDecode(node)
			if err != nil {
				return fail(err)
			}
			if decoded.get("disclosure.redaction_uid") == "" {
				unversioned++
			}
		}
	}

	if versionRows == nil {
		versionRows = []object.Object{}
	}
	out["versions"] = &object.Array{Elements: versionRows}
	out["count"] = intObj(int64(len(versionRows)))
	out["disclosures"] = &object.Array{Elements: disclosureRows}
	out["disclosure_count"] = intObj(int64(len(disclosureRows)))
	out["stale"] = intObj(stale)
	out["unversioned"] = intObj(unversioned)
	return resultAndError(makeHashObject(out), nil)
}

// redactionIssuedUnder returns the disclosures REDACTED_AS a version, each
// checked to name that version itself.
func redactionIssuedUnder(ledger *ledgerSession, version caseChainEvent) ([]disclosureNode, error) {
	edges, err := ledger.store.EdgesOf(version.id, store.DirectionInbound, []store.EdgeType{disclosureEdgeRedactedAs})
	if err != nil {
		return nil, err
	}
	out := make([]disclosureNode, 0, len(edges))
	for _, edge := range edges {
		node, err := ledger.graph.GetNode(edge.Src)
		if err != nil {
			return nil, err
		}
		if !node.HasLabel(disclosureNodeDisclosure) {
			return nil, fmt.Errorf("node %d is recorded as redacted as version %s and is not a disclosure",
				edge.Src, version.uid)
		}
		decoded, err := disclosureDecode(node)
		if err != nil {
			return nil, err
		}
		if decoded.get("disclosure.redaction_uid") != version.uid {
			return nil, fmt.Errorf("disclosure %s is recorded as redacted as version %s and names version %q",
				decoded.get("disclosure.uid"), version.uid, decoded.get("disclosure.redaction_uid"))
		}
		out = append(out, decoded)
	}
	return out, nil
}
