package builtin

// Attributed redaction: destroying content without destroying the record that
// it existed, and being honest about which copy was destroyed.
//
// `db_delete_node` removes an entity and records nothing about who did it or
// why. After a compaction the entity is gone and so is any trace that it was
// ever there, which makes lawful erasure and evidence destruction the same
// operation performed by the same call. These builtins are the other one: the
// content goes, and a signed, hash-chained record of the decision stays.
//
// A redaction keeps five things and destroys one:
//
//	the fact       a record exists that a redaction happened
//	the actor      who did it, under whose key, and when
//	the reason     why, in the examiner's own words, and it is required
//	the shape      which entity, and everything cascaded with it
//	the identity   the version hash of what was removed
//	                                    -- and the content is what goes
//
// The version hash is the load-bearing part. A party holding the removed
// content can prove it is what was removed; a party holding only the ledger can
// prove something specific was removed without learning what.
//
// # Four scopes, because they are four different decisions
//
// Removing a node takes every edge touching it. Stripping its properties leaves
// the node, its labels and all its relationships in place -- the graph's shape
// survives and only the data the order was about goes. The same pair exists for
// edges. Collapsing them into one builtin with a scope argument would make the
// ledger say "something was removed" where it can say which thing, and would
// let a script erase a subgraph while believing it erased a field.
//
// The property scopes are the lawful-erasure case. Removing a whole node to
// erase one property destroys evidence that was never in scope.
//
// # A redaction is all of an entity's properties or none of them
//
// There is no per-key form, because graphene has none: the property blob is one
// value and the index purge is unconditional. An entity with one sensitive
// field and four innocuous ones loses all five. Write the sensitive field on an
// entity of its own if it may have to go separately -- which is a decision
// taken at ingest, not at redaction, and is the reason it is said here.
//
// # The reason is written where it cannot be taken back
//
// graphene records the reason twice: in the redaction ledger, and again in the
// audit log's detail line. Neither file is redactable -- that is the point of
// both -- so a reason that quotes the value being destroyed re-publishes it in
// two append-only records at the moment of erasure. Every builtin here reads
// the entity's properties first and refuses a reason that repeats one of them.
// Like every runtime check of this kind it catches accidents, not adversaries:
// it compares whole values of at least ledgerReasonLeakMin bytes and cannot see
// a value the caller paraphrased, reformatted or split.
//
// # The window: recorded is not yet provable
//
// `RedactNodeProperties` rewrites the live graph and purges the property index
// immediately. The compacted image is untouched until the next compaction, so
// for that window the store's own image still contains the content, and no
// tombstone in it records the removal. Custody reports `removal_provable:
// false` and these builtins report `provable: false` rather than writing a
// claim the recipient cannot check.
//
// # And the copy this language cannot reach
//
// A ledger keeps every retired write-ahead segment, because that is what makes
// each commit's actor, timestamp and signature survive compaction -- the
// retention policy ledger_open sets, for the reason ledger_open gives. A
// segment is an immutable signed record of past commits, and a redaction does
// not rewrite one.
//
// So the entity's content as originally written stays in the write-ahead log.
// Redacting before the first compaction does not avoid it: the compaction that
// makes a redaction permanent is the same operation that rotates the live log
// into a retired segment, content and all. Under a retention policy that
// discarded old segments the content would go with them -- and so would the
// attribution of every commit they carry.
//
// That is the trade, and it does not have a right answer that this file could
// pick: **attribution and erasure want the same bytes**, and a ledger whose
// purpose is to say who wrote what cannot throw away what they wrote without
// throwing away that they wrote it. This family reports the segments rather
// than resolving it -- retained_segments on every redaction, and a gap in
// ledger_custody -- so that an examiner handing over a ledger directory knows
// what is in it. The byte-level guarantee belongs to encrypted records, where
// destroying a key destroys the content in every copy at once, and that is a
// different layer of this system.

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/merkle"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// ledgerReasonLeakMin is the shortest property value the reason check compares
// against.
//
// Below it a match says nothing: a two-character value collides with ordinary
// prose often enough that the refusal would be noise, and noise is how a check
// comes to be worked around. Above it a match is a value the caller typed out,
// which is the case worth refusing.
const ledgerReasonLeakMin = 4

// ledgerEdgeArg resolves an edge id argument.
//
// Separate from ledgerNodeArg although the shape is identical, because the
// refusal has to name the right namespace: an edge id and a node id are
// different numbers that look the same, and "node ids start at 1" sends a
// caller to check the wrong thing.
func ledgerEdgeArg(arg object.Object, op string, pos int) (store.EdgeID, *object.Error) {
	idArg, ok := arg.(*object.Integer)
	if !ok {
		return 0, newError("argument %d to `%s` must be INTEGER, got %s", pos, op, arg.Type())
	}
	if idArg.Value <= 0 {
		return 0, newError("%s: edge ids start at 1, got %d", op, idArg.Value)
	}
	return store.EdgeID(idArg.Value), nil
}

// ledgerReasonArg resolves the reason every redaction must state.
//
// graphene refuses only the empty string. A reason of spaces passes it and
// lands in the ledger as a redaction nobody explained, which is the exact thing
// ErrRedactionUnexplained exists to prevent -- so the check here is on the
// trimmed value, the same line ledger_open draws for the actor's name.
func ledgerReasonArg(arg object.Object, op string) (string, *object.Error) {
	reasonArg, ok := arg.(*object.String)
	if !ok {
		return "", newError("argument 3 to `%s` must be STRING, got %s", op, arg.Type())
	}
	reason := strings.TrimSpace(reasonArg.Value)
	if reason == "" {
		return "", newError("%s: a redaction must state a reason, and whitespace is not one; an unexplained redaction is indistinguishable from evidence destruction, which is the distinction this builtin exists to draw", op)
	}
	return reason, nil
}

// ledgerReasonLeak refuses a reason that repeats a value about to be destroyed.
//
// See the file header. The entries are the entity's own property index rows,
// which are the values a redaction purges; comparing against them rather than
// against the encoded blob means the check sees what the caller wrote rather
// than msgpack's framing of it.
func ledgerReasonLeak(entries []store.PropertyEntry, reason, subject, op string) *object.Error {
	for _, entry := range entries {
		value := string(entry.Value)
		if len(value) < ledgerReasonLeakMin {
			continue
		}
		if !strings.Contains(reason, value) {
			continue
		}
		return newError("%s: the reason repeats the value of %s on %s, which this redaction is about to destroy. The reason is written to the redaction ledger and again to the audit log, and neither is redactable -- so this would erase the value and publish it in the same call. Say why, not what", op, entry.Key, subject)
	}
	return nil
}

// ledgerSegmentFacts reports the retired write-ahead segments this ledger
// is keeping, and their size.
//
// Not decoration on a redaction result. These files are the pre-redaction
// commits, content included, and the retention policy that keeps them is what
// makes attribution survive a compaction. An examiner about to hand over a
// ledger directory is entitled to know how much of it is history.
func ledgerSegmentFacts(session *ledgerSession) (count, bytes int64) {
	segments, err := disk.ListSegments(session.path)
	if err != nil {
		return 0, 0
	}
	for _, segment := range segments {
		count++
		bytes += segment.Bytes
	}
	return count, bytes
}

// ledgerRetainedContentGap is the finding graphene does not make.
//
// graphene's redaction layer reports whether the *image* records the removal.
// It says nothing about the retired segments, because a library cannot know
// what retention policy it was opened under. This one does: ledger_open keeps
// every segment, so the pre-redaction write is still on disk and will stay
// there. Non-fatal -- nothing is broken, and the alternative is worse -- but
// unreported it would let a directory be handed over as redacted.
func ledgerRetainedContentGap(count, bytes int64) []ledgerAddedGap {
	if count == 0 {
		return nil
	}
	return []ledgerAddedGap{{
		gap: disk.CustodyGap{
			Layer:  disk.LayerRedaction,
			Detail: fmt.Sprintf("this entity was redacted, and the ledger is keeping %d retired write-ahead segment(s) totalling %d bytes. A segment is an immutable record of the commits it carries, so it still holds this entity's content as originally written; a redaction rewrites the live graph and the next compacted image, and rewrites no segment", count, bytes),
		},
		remedy: "none in this language, by design: the retention policy ledger_open sets is what makes each commit's actor, timestamp and signature survive a compaction, and the same bytes carry both. Treat the ledger directory as holding pre-redaction content, and do not hand it to a recipient the redaction was performed for",
	}}
}

// --- rendering a record ------------------------------------------------------

// ledgerHashList renders version hashes as hex, in the order graphene gave
// them, which is the order that binds each hash to an id in the list beside it.
func ledgerHashList(hashes []merkle.Hash) object.Object {
	elements := make([]object.Object, 0, len(hashes))
	for _, hash := range hashes {
		elements = append(elements, stringObj(ledgerHash(hash)))
	}
	return &object.Array{Elements: elements}
}

// ledgerEdgeList renders cascaded edge ids.
func ledgerEdgeList(edges []store.EdgeID) object.Object {
	elements := make([]object.Object, 0, len(edges))
	for _, edge := range edges {
		elements = append(elements, intObj(int64(edge)))
	}
	return &object.Array{Elements: elements}
}

// ledgerRecordInto writes one redaction record's fields.
//
// actor is the name the session asserted, which graphene never sees -- it
// records the id this process derived from the name. Both are reported: the id
// is what the record carries and the name is what a reader needs, and a report
// showing only the name would invite it to be read as something the store
// vouches for.
func ledgerRecordInto(session *ledgerSession, record disk.RedactionRecord, out map[string]object.Object) {
	out["seq"] = intObj(int64(record.Seq))
	out["scope"] = stringObj(record.Scope.String())
	out["node_id"] = intObj(int64(record.NodeID))
	out["edge_id"] = intObj(int64(record.EdgeID))
	out["reason"] = stringObj(record.Reason)

	out["actor"] = stringObj(session.actor)
	out["actor_id"] = stringObj(fmt.Sprintf("%d", record.ActorID))
	out["key_id"] = stringObj(fmt.Sprintf("%d", record.KeyID))
	// An unsigned record is still hash-chained, so it is tamper-evident and
	// unattributed to a key. Reported rather than assumed: a strict ledger
	// always signs, and a record that is not signed did not come from one.
	out["signed"] = boolObj(len(record.Signature) > 0)

	out["unix"] = intObj(record.UnixNano / 1e9)
	out["at"] = stringObj(formatTime(ledgerTime(record.UnixNano)))

	// version_hash identifies the destroyed content; surviving_hash the entity
	// that was left, zero when nothing was; prior_properties_hash is what makes
	// a property redaction provable without revealing what it removed.
	out["version_hash"] = stringObj(ledgerHash(record.VersionHash))
	out["surviving_hash"] = stringObj(ledgerHash(record.SurvivingHash))
	out["prior_properties_hash"] = stringObj(ledgerHash(record.PriorPropertiesHash))

	out["cascaded_edges"] = ledgerEdgeList(record.CascadedEdges)
	out["cascaded_hashes"] = ledgerHashList(record.CascadedHashes)
	out["cascade_count"] = intObj(int64(len(record.CascadedEdges)))

	out["prev"] = stringObj(ledgerHash(record.PrevHash))
	out["hash"] = stringObj(ledgerHash(record.Hash))
}

// ledgerRedactResult is what every one of the four redaction builtins returns.
//
// One shape for all four, because a caller writing a manifest should not have
// to branch on which scope was used to find out what happened, and because the
// fields that differ between scopes -- an edge id on a node redaction, a
// surviving hash where nothing survived -- are zero rather than absent, which
// is readable.
func ledgerRedactResult(session *ledgerSession, record disk.RedactionRecord) object.Object {
	out := make(map[string]object.Object, 22)
	ledgerRecordInto(session, record, out)

	// Always false here, and not computed. A redaction is bound into the image
	// by the next compaction, and this call is always before it -- so the field
	// is a statement about the ledger's state at the moment it returned, not a
	// check that came back negative. ledger_custody reports it live.
	out["provable"] = boolObj(false)

	count, bytes := ledgerSegmentFacts(session)
	out["retained_segments"] = intObj(count)
	out["retained_segment_bytes"] = intObj(bytes)
	return makeHashObject(out)
}

// ledgerRedactRefusal turns graphene's redaction errors into answers.
//
// Two of them need translating. "carries no properties to redact" is returned
// both for an entity written without properties and for one already stripped,
// and the second is a redaction that already happened rather than an error.
// ErrNotFound on a node is returned for an id the ledger never held *and* for
// one redacted outright, which is the same conflation ledger_prove_node had to
// undo -- an entity deliberately removed is not an entity that never existed,
// and telling an examiner to check the id sends them to look for a typo that is
// not there.
func ledgerRedactRefusal(session *ledgerSession, err error, nodeID store.NodeID, edgeID store.EdgeID, op string) *object.Error {
	var notFound *store.ErrNotFound
	switch {
	case errors.Is(err, disk.ErrRedactionUnexplained):
		// Unreachable: ledgerReasonArg refuses first, and more strictly.
		return newError("%s: %s", op, err.Error())
	case errors.As(err, &notFound) && nodeID != 0:
		if record, _, found := ledgerLastRedaction(session, nodeID, 0); found {
			return newError("%s: node %d is not here because it was redacted at %s by actor %d (%s): %q. A redaction is recorded, not undone -- see ledger_redactions", op, nodeID, formatTime(ledgerTime(record.UnixNano)), record.ActorID, record.Scope.String(), record.Reason)
		}
		return newError("%s: this ledger has no node %d, and no record of ever having had one. Check the id against what ledger_add_node returned", op, nodeID)
	case errors.As(err, &notFound) && edgeID != 0:
		switch record, cascaded, found := ledgerLastRedaction(session, 0, edgeID); {
		case found && cascaded:
			return newError("%s: edge %d is not here because redaction %d took it as collateral when node %d was removed at %s: %q. It was not the subject of that decision, and ledger_prove_edge_redaction proves its removal from the image", op, edgeID, record.Seq, record.NodeID, formatTime(ledgerTime(record.UnixNano)), record.Reason)
		case found:
			return newError("%s: edge %d is not here because it was redacted at %s by actor %d (%s): %q. A redaction is recorded, not undone -- see ledger_redactions", op, edgeID, formatTime(ledgerTime(record.UnixNano)), record.ActorID, record.Scope.String(), record.Reason)
		}
		return newError("%s: this ledger has no edge %d, and no record of ever having had one. Check the id against what ledger_add_edge returned", op, edgeID)
	case strings.Contains(err.Error(), "carries no properties to redact"):
		subject := fmt.Sprintf("node %d", nodeID)
		if edgeID != 0 {
			subject = fmt.Sprintf("edge %d", edgeID)
		}
		if record, _, found := ledgerLastRedaction(session, nodeID, edgeID); found && record.Scope == disk.ScopeProperties {
			return newError("%s: %s has no properties because they were already redacted at %s: %q. Redaction %d is the record of it", op, subject, formatTime(ledgerTime(record.UnixNano)), record.Reason, record.Seq)
		}
		return newError("%s: %s was written without properties, so there is nothing here to destroy and a record saying there was would be false", op, subject)
	default:
		return newError("%s: %s", op, err.Error())
	}
}

// ledgerLastRedaction finds the most recent record about one entity, and says
// whether the entity was named by that record or cascaded out by it.
//
// The most recent and not the first: an entity whose properties were stripped
// and which was later removed outright has two records, and the one describing
// its present state is the later one -- the same rule graphene's tombstone
// lookup follows, applied to the ledger so the two agree.
//
// The cascade is searched too, and separately. An edge removed as collateral is
// as absent as one removed deliberately and its removal is as recorded, so
// reporting it as an edge the ledger never held would be false; but it was not
// the subject of the decision, and a message calling a court order against a
// node an edge redaction would be false in the other direction.
//
// Read off disk on the failure path only, which is where a caller is about to
// be told something wrong otherwise.
func ledgerLastRedaction(session *ledgerSession, nodeID store.NodeID, edgeID store.EdgeID) (record disk.RedactionRecord, cascaded, found bool) {
	records, err := session.store.Redactions()
	if err != nil {
		return disk.RedactionRecord{}, false, false
	}
	for _, candidate := range records {
		named := false
		switch {
		case edgeID != 0 && candidate.EdgeID == edgeID:
			named = true
		case nodeID != 0 && candidate.EdgeID == 0 && candidate.NodeID == nodeID:
			named = true
		case edgeID != 0 && slices.Contains(candidate.CascadedEdges, edgeID):
		default:
			continue
		}
		record, cascaded, found = candidate, !named, true
	}
	return record, cascaded, found
}

// --- the four scopes ---------------------------------------------------------

// ledgerRedactNodeScope is the shared body of the two node-scoped builtins.
//
// The scopes differ in one call and in nothing else: the same handle, the same
// id check, the same reason check, the same leak check against the same
// entries, and the same result. Writing that twice would let the two drift, and
// the pair a caller most needs to behave identically is the one that removes an
// entity and the one that spares it.
func ledgerRedactNodeScope(args []object.Object, op string, redact func(*ledgerSession, store.NodeID, disk.RedactionRequest) (disk.RedactionRecord, error)) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, errObj := ledgerNodeArg(args[1], op, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason, errObj := ledgerReasonArg(args[2], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := ledgerReasonLeak(session.graph.NodePropertyEntries(nodeID), reason,
		fmt.Sprintf("node %d", nodeID), op); errObj != nil {
		return resultAndError(nil, errObj)
	}

	record, err := redact(session, nodeID, disk.RedactionRequest{ActorID: session.actorID, Reason: reason})
	if err != nil {
		return resultAndError(nil, ledgerRedactRefusal(session, err, nodeID, 0, op))
	}

	custodyRecordArtifact(op, fmt.Sprintf("redacted node %d (%s): %s", nodeID, record.Scope, reason),
		map[string]any{
			"path":           session.path,
			"actor":          session.actor,
			"node_id":        fmt.Sprintf("%d", nodeID),
			"scope":          record.Scope.String(),
			"redaction_seq":  fmt.Sprintf("%d", record.Seq),
			"redaction_hash": ledgerHash(record.Hash),
			"reason":         reason,
		})

	return resultAndError(ledgerRedactResult(session, record), nil)
}

// ledgerRedactEdgeScope is the same for the two edge-scoped builtins.
func ledgerRedactEdgeScope(args []object.Object, op string, redact func(*ledgerSession, store.EdgeID, disk.RedactionRequest) (disk.RedactionRecord, error)) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	edgeID, errObj := ledgerEdgeArg(args[1], op, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason, errObj := ledgerReasonArg(args[2], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := ledgerReasonLeak(session.graph.EdgePropertyEntries(edgeID), reason,
		fmt.Sprintf("edge %d", edgeID), op); errObj != nil {
		return resultAndError(nil, errObj)
	}

	record, err := redact(session, edgeID, disk.RedactionRequest{ActorID: session.actorID, Reason: reason})
	if err != nil {
		return resultAndError(nil, ledgerRedactRefusal(session, err, 0, edgeID, op))
	}

	custodyRecordArtifact(op, fmt.Sprintf("redacted edge %d (%s): %s", edgeID, record.Scope, reason),
		map[string]any{
			"path":           session.path,
			"actor":          session.actor,
			"edge_id":        fmt.Sprintf("%d", edgeID),
			"scope":          record.Scope.String(),
			"redaction_seq":  fmt.Sprintf("%d", record.Seq),
			"redaction_hash": ledgerHash(record.Hash),
			"reason":         reason,
		})

	return resultAndError(ledgerRedactResult(session, record), nil)
}

// LedgerRedactNode removes an entity and everything joined to it.
func LedgerRedactNode(args ...object.Object) object.Object {
	return ledgerRedactNodeScope(args, BuiltinNameLedgerRedactNode,
		func(session *ledgerSession, id store.NodeID, req disk.RedactionRequest) (disk.RedactionRecord, error) {
			return session.store.RedactNode(id, req)
		})
}

// LedgerRedactNodeProperties strips an entity's properties and keeps the entity.
func LedgerRedactNodeProperties(args ...object.Object) object.Object {
	return ledgerRedactNodeScope(args, BuiltinNameLedgerRedactNodeProperties,
		func(session *ledgerSession, id store.NodeID, req disk.RedactionRequest) (disk.RedactionRecord, error) {
			return session.store.RedactNodeProperties(id, req)
		})
}

// LedgerRedactEdge removes one relationship, leaving both endpoints.
func LedgerRedactEdge(args ...object.Object) object.Object {
	return ledgerRedactEdgeScope(args, BuiltinNameLedgerRedactEdge,
		func(session *ledgerSession, id store.EdgeID, req disk.RedactionRequest) (disk.RedactionRecord, error) {
			return session.store.RedactEdge(id, req)
		})
}

// LedgerRedactEdgeProperties strips a relationship's properties and keeps it.
func LedgerRedactEdgeProperties(args ...object.Object) object.Object {
	return ledgerRedactEdgeScope(args, BuiltinNameLedgerRedactEdgeProperties,
		func(session *ledgerSession, id store.EdgeID, req disk.RedactionRequest) (disk.RedactionRecord, error) {
			return session.store.RedactEdgeProperties(id, req)
		})
}

// --- before anything is destroyed --------------------------------------------

// LedgerRedactionImpact reports what redacting a node would remove.
func LedgerRedactionImpact(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerRedactionImpact)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, errObj := ledgerNodeArg(args[1], BuiltinNameLedgerRedactionImpact, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	impact, err := session.store.RedactionImpactFor(nodeID)
	if err != nil {
		return resultAndError(nil, ledgerRedactRefusal(session, err, nodeID, 0, BuiltinNameLedgerRedactionImpact))
	}

	count, bytes := ledgerSegmentFacts(session)
	return resultAndError(makeHashObject(map[string]object.Object{
		"node_id": intObj(int64(nodeID)),
		// The hashes are computed here rather than at deletion time, which is
		// what lets a manifest record the set this preview showed and a
		// recipient check that it is the set the record describes.
		"version_hash":    stringObj(ledgerHash(impact.VersionHash)),
		"cascaded_edges":  ledgerEdgeList(impact.CascadedEdges),
		"cascaded_hashes": ledgerHashList(impact.CascadedHashes),
		"cascade_count":   intObj(int64(len(impact.CascadedEdges))),

		"retained_segments":      intObj(count),
		"retained_segment_bytes": intObj(bytes),
	}), nil)
}

// --- reading the ledger back -------------------------------------------------

// LedgerRedactions returns every redaction this ledger records.
func LedgerRedactions(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerRedactions)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	records, err := session.store.Redactions()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerRedactions, err.Error()))
	}

	elements := make([]object.Object, 0, len(records))
	head := ""
	for _, record := range records {
		out := make(map[string]object.Object, 18)
		ledgerRecordInto(session, record, out)
		elements = append(elements, makeHashObject(out))
		head = ledgerHash(record.Hash)
	}

	// The keyring this ledger was opened with, so a signature that does not
	// verify is a finding rather than a check nobody ran. graphene accepts a
	// nil verifier and checks only the hash chain, which would report an edited
	// record and miss a re-signed one.
	chainErr := disk.VerifyRedactionChain(records, session.verifier)
	reason := ""
	if chainErr != nil {
		reason = chainErr.Error()
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"count":      intObj(int64(len(records))),
		"redactions": &object.Array{Elements: elements},
		"head":       stringObj(head),
		// chain_intact rather than a bare "verified": it recomputes each
		// record's hash and each link, which catches an edited or removed
		// record. It cannot catch a ledger rewritten forward from the start by
		// whoever holds the key -- that is what the head bound into a published
		// checkpoint is for. Named chain_reason so it cannot be read as the
		// reason a redaction was performed, which is the field beside it.
		"chain_intact": boolObj(chainErr == nil),
		"chain_reason": stringObj(reason),
	}), nil)
}

// --- proving a removal from the image alone ----------------------------------

// ledgerRemovalProofResult renders a removal proof and its exported bytes.
func ledgerRemovalProofResult(proof disk.RedactionInclusionProof, blob []byte, kind disk.ProofKind, subject string) object.Object {
	out := map[string]object.Object{
		"node_id": intObj(int64(proof.Tombstone.NodeID)),
		"edge_id": intObj(int64(proof.Tombstone.EdgeID)),
		"scope":   stringObj(proof.Tombstone.Scope.String()),

		"proof":       &object.Bytes{Value: blob},
		"proof_bytes": intObj(int64(len(blob))),
		"kind":        stringObj(kind.String()),
		"subject":     stringObj(subject),

		// The ledger record this tombstone came from. Carrying the hash and not
		// just the sequence is what lets a recipient handed a ledger record
		// confirm it is the one this proof refers to.
		"redaction_seq":  intObj(int64(proof.Tombstone.RedactionSeq)),
		"redaction_hash": stringObj(ledgerHash(proof.Tombstone.RedactionHash)),
		"version_hash":   stringObj(ledgerHash(proof.Tombstone.VersionHash)),

		"leaf_bytes": intObj(int64(len(proof.LeafData))),
		"leaf_index": intObj(int64(proof.Proof.Index)),
		"tree_size":  intObj(int64(proof.Proof.Size)),
		"siblings":   intObj(int64(len(proof.Proof.Siblings))),
	}
	ledgerRootsInto(proof.Roots, "", out)
	return makeHashObject(out)
}

// ledgerRemovalRefusal separates graphene's one tombstone error into the three
// situations it covers.
//
// ErrNoTombstone means the image has no marker for this entity, which is true
// of an entity never redacted, of one redacted since the last compaction, and
// of one whose redaction predates the image. They need opposite responses and
// the ledger on disk is what tells them apart.
func ledgerRemovalRefusal(session *ledgerSession, err error, nodeID store.NodeID, edgeID store.EdgeID, op string) *object.Error {
	subject := fmt.Sprintf("node %d", nodeID)
	if edgeID != 0 {
		subject = fmt.Sprintf("edge %d", edgeID)
	}
	switch {
	case errors.Is(err, disk.ErrNoSnapshotRoots):
		return newError("%s: this ledger has never been compacted, so it has no snapshot for a removal proof to resolve against; call ledger_compact first", op)
	case errors.Is(err, disk.ErrNoTombstone):
		if record, _, found := ledgerLastRedaction(session, nodeID, edgeID); found {
			return newError("%s: %s was redacted at %s (redaction %d), but the compacted image does not record it yet, so there is nothing under the snapshot root to prove. Call ledger_compact -- until then the removal is the ledger's word rather than the image's", op, subject, formatTime(ledgerTime(record.UnixNano)), record.Seq)
		}
		return newError("%s: this ledger records no redaction of %s. A removal proof says an entity was deliberately taken out; for an entity that is present use ledger_prove_node", op, subject)
	default:
		return newError("%s: %s", op, err.Error())
	}
}

// LedgerProveRedaction proves the image records a node as deliberately removed.
func LedgerProveRedaction(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerProveRedaction)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, errObj := ledgerNodeArg(args[1], BuiltinNameLedgerProveRedaction, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	proof, err := session.store.ProveRedaction(nodeID)
	if err != nil {
		return resultAndError(nil, ledgerRemovalRefusal(session, err, nodeID, 0, BuiltinNameLedgerProveRedaction))
	}
	blob, err := session.store.ExportRedactionProof(nodeID)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerProveRedaction, err.Error()))
	}

	custodyRecordArtifact(BuiltinNameLedgerProveRedaction,
		fmt.Sprintf("exported a removal proof for node %d", nodeID),
		map[string]any{
			"path":          session.path,
			"actor":         session.actor,
			"node_id":       fmt.Sprintf("%d", nodeID),
			"redaction_seq": fmt.Sprintf("%d", proof.Tombstone.RedactionSeq),
			"snapshot_root": ledgerHash(proof.Roots.Snapshot),
			"proof_bytes":   len(blob),
		})

	return resultAndError(ledgerRemovalProofResult(proof, blob, disk.ProofKindRedaction,
		fmt.Sprintf("node %d", nodeID)), nil)
}

// LedgerProveEdgeRedaction proves the image records an edge as removed.
func LedgerProveEdgeRedaction(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerProveEdgeRedaction)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	edgeID, errObj := ledgerEdgeArg(args[1], BuiltinNameLedgerProveEdgeRedaction, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	proof, err := session.store.ProveEdgeRedaction(edgeID)
	if err != nil {
		return resultAndError(nil, ledgerRemovalRefusal(session, err, 0, edgeID, BuiltinNameLedgerProveEdgeRedaction))
	}
	blob, err := session.store.ExportEdgeRedactionProof(edgeID)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerProveEdgeRedaction, err.Error()))
	}

	custodyRecordArtifact(BuiltinNameLedgerProveEdgeRedaction,
		fmt.Sprintf("exported a removal proof for edge %d", edgeID),
		map[string]any{
			"path":          session.path,
			"actor":         session.actor,
			"edge_id":       fmt.Sprintf("%d", edgeID),
			"redaction_seq": fmt.Sprintf("%d", proof.Tombstone.RedactionSeq),
			"snapshot_root": ledgerHash(proof.Roots.Snapshot),
			"proof_bytes":   len(blob),
		})

	return resultAndError(ledgerRemovalProofResult(proof, blob, disk.ProofKindRedaction,
		fmt.Sprintf("edge %d", edgeID)), nil)
}

// LedgerProvePropertyRedaction proves an entity's properties were removed and
// nothing else about it was.
func LedgerProvePropertyRedaction(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerProvePropertyRedaction)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, errObj := ledgerNodeArg(args[1], BuiltinNameLedgerProvePropertyRedaction, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	proof, err := session.store.ProvePropertyRedaction(nodeID)
	if err != nil {
		return resultAndError(nil, ledgerPropertyProofRefusal(session, err, nodeID))
	}
	blob, err := session.store.ExportPropertyRedactionProof(nodeID)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerProvePropertyRedaction, err.Error()))
	}

	out := map[string]object.Object{
		"node_id": intObj(int64(nodeID)),

		"proof":       &object.Bytes{Value: blob},
		"proof_bytes": intObj(int64(len(blob))),
		"kind":        stringObj(disk.ProofKindPropertyRedaction.String()),
		"subject":     stringObj(fmt.Sprintf("node %d", nodeID)),

		"redaction_seq":  intObj(int64(proof.Removal.Tombstone.RedactionSeq)),
		"redaction_hash": stringObj(ledgerHash(proof.Removal.Tombstone.RedactionHash)),
		"version_hash":   stringObj(ledgerHash(proof.Removal.Tombstone.VersionHash)),

		// Three leaves, three lengths. The prior and surviving leaves are the
		// same shape and differ only in their last 32 bytes, which is the whole
		// claim -- a reader who sees two different lengths is looking at a
		// proof that is not about one entity's properties.
		"prior_leaf_bytes":     intObj(int64(len(proof.PriorLeafData))),
		"surviving_leaf_bytes": intObj(int64(len(proof.Surviving.LeafData))),
		"removal_leaf_bytes":   intObj(int64(len(proof.Removal.LeafData))),

		"leaf_index": intObj(int64(proof.Surviving.Proof.Index)),
		"tree_size":  intObj(int64(proof.Surviving.Proof.Size)),
		"siblings":   intObj(int64(len(proof.Surviving.Proof.Siblings))),
	}
	// The surviving proof's roots: that is the proof placing the entity in the
	// snapshot being verified against, and the removal proof's roots are the
	// same snapshot's.
	ledgerRootsInto(proof.Surviving.Roots, "", out)

	custodyRecordArtifact(BuiltinNameLedgerProvePropertyRedaction,
		fmt.Sprintf("exported a property-redaction proof for node %d", nodeID),
		map[string]any{
			"path":          session.path,
			"actor":         session.actor,
			"node_id":       fmt.Sprintf("%d", nodeID),
			"redaction_seq": fmt.Sprintf("%d", proof.Removal.Tombstone.RedactionSeq),
			"snapshot_root": ledgerHash(proof.Surviving.Roots.Snapshot),
			"proof_bytes":   len(blob),
		})

	return resultAndError(makeHashObject(out), nil)
}

// ledgerPropertyProofRefusal adds the property proof's own two refusals to the
// removal proof's three.
//
// ErrNoPropertyRedaction means the image's most recent tombstone for this
// entity is not a property strip -- which is what an entity removed outright
// looks like, including one whose properties were stripped first. The
// distinction matters: the property proof's claim is "this entity is still
// here and only its properties went", and it is false about an entity that is
// not there any more.
func ledgerPropertyProofRefusal(session *ledgerSession, err error, nodeID store.NodeID) *object.Error {
	op := BuiltinNameLedgerProvePropertyRedaction
	if errors.Is(err, disk.ErrNoPropertyRedaction) {
		if record, _, found := ledgerLastRedaction(session, nodeID, 0); found {
			return newError("%s: node %d was redacted at %s, but as a %s rather than a property strip, so the entity is not in the image and this proof's claim -- that it is still here and only its properties went -- is not true of it. Use ledger_prove_redaction", op, nodeID, formatTime(ledgerTime(record.UnixNano)), record.Scope.String())
		}
		return newError("%s: this ledger records no property redaction of node %d", op, nodeID)
	}
	return ledgerRemovalRefusal(session, err, nodeID, 0, op)
}
