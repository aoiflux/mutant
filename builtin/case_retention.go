package builtin

// Retention: how long a concluded case is kept and on what basis, and the
// legal holds that stop anything in it being disposed of, recorded in the
// case's ledger.
//
// # The period
//
// retention_set records the date the case is kept until and the basis for
// keeping it -- a statute, a policy, a court's order. The first one retains a
// concluded case: the lifecycle moves concluded -> retained in the same commit.
// A later one changes a retained case's period, and says what it was. A date is
// taken as its first instant in UTC, and a time as given. The date may already
// have passed -- a case concluded long ago whose period has run -- and the
// result says so in `lapsed`; nothing here disposes of anything when it does.
//
// # Holds
//
// retention_hold places a legal hold on the case in any state but disposed,
// and retention_release lifts one, by name. Each hold is its own event, so two
// holds for two matters are two holds, and lifting one leaves the other in
// force. While any hold is in force, nothing in the case is disposed of:
// evidence_dispose refuses. A hold says whose authority it was placed on, as a
// withdrawal does -- the examiner's own, or one they name -- and neither is
// checked.
//
// # The chain
//
// A case's retention events are one chain (case_chain.go), keyed by the case,
// and every reader walks it: each event must be the case's and of a kind this
// program records, a period must name a time it can read, and a release must
// lift a hold placed earlier in the chain and still in force. The chain says
// what was recorded and in what order; it does not say anybody was entitled to
// record it.

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// What a retention event records.
const (
	retentionKindSet     = "set"
	retentionKindHold    = "hold"
	retentionKindRelease = "release"
)

var retentionKinds = []string{retentionKindSet, retentionKindHold, retentionKindRelease}

var retentionChain = caseChainSpec{label: disclosureNodeRetention, prefix: "retention"}

// The options retention_hold and retention_list take.
var (
	retentionHoldOptions = []string{"authority"}
	retentionListOptions = []string{"case_uid"}
)

// caseRetention is what a case's retention chain leaves in force.
type caseRetention struct {
	events []caseChainEvent
	// period is the latest period set, nil when none was.
	period *caseChainEvent
	until  time.Time
	// holds are the holds in force, the first placed first.
	holds []caseChainEvent
}

// lapsed reports whether the period has run at now. A case with no period has
// not.
func (r caseRetention) lapsed(now time.Time) bool {
	return r.period != nil && !now.Before(r.until)
}

// ---------------------------------------------------------------------------
// Reading the retention back
// ---------------------------------------------------------------------------

// retentionRead reads one case's retention chain and what it leaves in force.
// It refuses an event that names another case or is of a kind this program
// does not record, a period whose date it cannot read, and a release of
// anything but a hold placed earlier in the chain and still in force.
func retentionRead(g *graphene.Graph, caseUID string) (caseRetention, error) {
	events, err := caseChainRead(g, retentionChain, caseUID)
	if err != nil {
		return caseRetention{}, err
	}
	out := caseRetention{events: events}
	placed, lifted := map[string]bool{}, map[string]bool{}
	for i, event := range events {
		kind := event.get("retention.kind")
		switch {
		case event.get("retention.case_uid") != caseUID:
			return caseRetention{}, fmt.Errorf("retention event node %d names case %s, in the chain of case %s",
				event.id, event.get("retention.case_uid"), caseUID)
		case !slices.Contains(retentionKinds, kind):
			return caseRetention{}, fmt.Errorf("retention event node %d records a %q, which this program does not "+
				"record", event.id, kind)
		}
		switch kind {
		case retentionKindSet:
			until, err := time.Parse(time.RFC3339Nano, event.get("retention.until"))
			if err != nil {
				return caseRetention{}, fmt.Errorf("retention event node %d keeps the case until %q, which is not a "+
					"time", event.id, event.get("retention.until"))
			}
			out.period, out.until = &events[i], until
		case retentionKindHold:
			placed[event.uid] = true
		case retentionKindRelease:
			hold := event.get("retention.hold_uid")
			if !placed[hold] || lifted[hold] {
				return caseRetention{}, fmt.Errorf("retention event node %d lifts hold %q, which is not a hold in "+
					"force before it", event.id, hold)
			}
			lifted[hold] = true
		}
	}
	for _, event := range events {
		if event.get("retention.kind") == retentionKindHold && !lifted[event.uid] {
			out.holds = append(out.holds, event)
		}
	}
	return out, nil
}

// retentionReadAll reads the retention of every case in the ledger that has
// any, ordered by case, or of one case when caseUID is given.
func retentionReadAll(g *graphene.Graph, caseUID string) ([]caseRetention, error) {
	var chains []string
	if caseUID != "" {
		chains = []string{caseUID}
	} else {
		nodes, err := disclosureAll(g, disclosureNodeRetention)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, node := range nodes {
			seen[node.get("retention.chain")] = true
		}
		chains = slices.Sorted(maps.Keys(seen))
	}
	var out []caseRetention
	for _, chain := range chains {
		retention, err := retentionRead(g, chain)
		if err != nil {
			return nil, err
		}
		if len(retention.events) > 0 {
			out = append(out, retention)
		}
	}
	return out, nil
}

// retentionHoldRefusal refuses a disposal while a legal hold is in force in
// the case, naming the first hold placed. The caller holds disclosureLedgerMu.
func retentionHoldRefusal(op string, session *custodySession, g *graphene.Graph) *object.Error {
	retention, err := retentionRead(g, strings.ToLower(session.caseUID))
	if err != nil {
		return newError("%s: %s", op, err.Error())
	}
	if len(retention.holds) == 0 {
		return nil
	}
	holds := "a legal hold"
	if n := len(retention.holds); n > 1 {
		holds = fmt.Sprintf("%d legal holds", n)
	}
	first := retention.holds[0]
	return newError("%s: case %s is under %s -- the first placed at %s by %s, on the authority of %s: %q -- and "+
		"nothing in a case under a hold is disposed of. retention_release(ledger, %q, reason) lifts it", op,
		session.ID, holds, first.get("retention.at"), first.get("retention.by"), first.get("retention.authority"),
		first.get("retention.reason"), first.uid)
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

// retentionUntilArg reads the date a case is kept until: a date, taken as its
// first instant in UTC, or an RFC 3339 time.
func retentionUntilArg(op string, arg object.Object) (time.Time, *object.Error) {
	given, errObj := requireStringArg(op, arg, 2)
	if errObj != nil {
		return time.Time{}, errObj
	}
	text := strings.TrimSpace(given)
	if day, err := time.Parse(time.DateOnly, text); err == nil {
		return day.UTC(), nil
	}
	if at, err := time.Parse(time.RFC3339Nano, text); err == nil {
		return at.UTC(), nil
	}
	return time.Time{}, newError("%s: %q is not a date. A case is kept until a date (2033-09-28, taken as its "+
		"first instant in UTC) or an RFC 3339 time (2033-09-28T17:00:00+01:00)", op, given)
}

// retentionHoldAuthority reads retention_hold's authority option. Left out,
// or naming the examiner placing the hold, the authority is that examiner's
// own; otherwise it is the name given. The answers are a withdrawal's.
func retentionHoldAuthority(op string, ledger *ledgerSession, opts *formatOptions) (string, string, *object.Error) {
	if _, present := opts.pairs["authority"]; !present {
		return ledger.actor, withdrawalAuthoritySelf, nil
	}
	named, errObj := opts.str("authority", "")
	if errObj != nil {
		return "", "", errObj
	}
	authority := strings.TrimSpace(named)
	switch {
	case authority == "":
		return "", "", newError("%s: authority names whose authority a hold was placed on, and an empty name is "+
			"nobody's. Leave it out to record that you placed it on your own", op)
	case len(authority) > maxCaseReason:
		return "", "", newError("%s: an authority's name is at most %d bytes, and this one is %d", op, maxCaseReason,
			len(authority))
	}
	if errObj := custodyDocumentName(op, "authority's name", authority); errObj != nil {
		return "", "", errObj
	}
	if authority == ledger.actor {
		return authority, withdrawalAuthoritySelf, nil
	}
	return authority, withdrawalAuthorityNamed, nil
}

// retentionAppend writes one retention event after the chain's head, with its
// IN_CASE and PERFORMED_BY edges and any others given. It does not commit.
func (w *caseWriter) retentionAppend(retention caseRetention, kind string, props map[string]string,
	edges ...caseEdge) (caseChainEvent, error) {
	all := map[string]string{
		"retention.case_uid":  w.caseUID,
		"retention.case_id":   w.caseID,
		"retention.kind":      kind,
		"retention.by":        w.ledger.actor,
		"retention.by_role":   w.ledger.role.Name,
		"retention.at":        w.at.UTC().Format(time.RFC3339Nano),
		"retention.unix_nano": strconv.FormatInt(w.at.UnixNano(), 10),
	}
	maps.Copy(all, props)
	id, event, err := w.tx.chainAppend(retentionChain, w.caseUID, caseChainHead(retention.events), all)
	if err != nil {
		return caseChainEvent{}, err
	}
	edges = append(edges, caseEdge{w.caseN, disclosureEdgeInCase, nil},
		caseEdge{w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(w.ledger)})
	for _, e := range edges {
		if err := w.tx.edge(id, e.dst, e.label, e.props); err != nil {
			return caseChainEvent{}, err
		}
	}
	return event, nil
}

// caseEdge is one edge a case record is written with.
type caseEdge struct {
	dst   store.NodeID
	label store.EdgeType
	props map[string]string
}

// retentionResult is what every retention writer returns beside its own
// fields: the case, the event just recorded, and who recorded it as what.
func retentionResult(session *custodySession, ledger *ledgerSession, event caseChainEvent, state string,
	holds int, extra map[string]object.Object) object.Object {
	fields := map[string]object.Object{
		"case_id":            stringObj(session.ID),
		"uid":                stringObj(event.uid),
		"seq":                intObj(int64(event.seq)),
		"kind":               stringObj(event.get("retention.kind")),
		"state":              stringObj(state),
		"holds_in_force":     intObj(int64(holds)),
		"by":                 stringObj(ledger.actor),
		"by_role":            stringObj(ledger.role.Name),
		"at":                 stringObj(event.get("retention.at")),
		"role_authenticated": boolObj(false),
	}
	maps.Copy(fields, extra)
	return resultAndError(makeHashObject(fields), nil)
}

// ---------------------------------------------------------------------------
// retention_set
// ---------------------------------------------------------------------------

// RetentionSet records how long the attached case is kept and why, retaining
// a concluded case: retention_set(ledger, until, basis).
func RetentionSet(args ...object.Object) object.Object {
	op := BuiltinNameRetentionSet
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	until, errObj := retentionUntilArg(op, args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	basis, errObj := caseTextArg(op, args[2], 3, "basis")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	session, errObj := caseLedgerWrite(op, ledger)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	g := ledger.graph
	caseUID := strings.ToLower(session.caseUID)
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := caseLedgerStateRefusal(g, caseUID, caseActRetain); err != nil {
		return fail(err)
	}
	lifecycle, from, err := caseLifecycleRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	if from != caseStateConcluded && from != caseStateRetained {
		return resultAndError(nil, newError("%s: case %s is %s, and a retention period is set on a concluded case, "+
			"whose findings are what is kept, or on a retained one to change it", op, session.ID, from))
	}
	retention, err := retentionRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	previous := ""
	if retention.period != nil {
		previous = retention.period.get("retention.until")
		if retention.until.Equal(until) {
			return resultAndError(nil, newError("%s: case %s is already kept until %s, on the basis %q", op,
				session.ID, previous, retention.period.get("retention.basis")))
		}
	}

	now := custodyNow()
	w, err := caseBeginWrite(ledger, caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	event, err := w.retentionAppend(retention, retentionKindSet, map[string]string{
		"retention.until":          until.Format(time.RFC3339Nano),
		"retention.basis":          basis,
		"retention.previous_until": previous,
	})
	if err != nil {
		return fail(err)
	}
	to := from
	var moved caseChainEvent
	if from == caseStateConcluded {
		to = caseStateRetained
		if moved, err = w.lifecycleFor(caseChainHead(lifecycle), from, to, basis,
			map[string]string{"lifecycle.retention_uid": event.uid}); err != nil {
			return fail(err)
		}
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	if to != from {
		session.attached.state, session.attached.head = to, moved
	}
	session.appendEvent(now, op, fmt.Sprintf("case %s kept until %s: %s", session.ID, event.get("retention.until"),
		basis), map[string]any{
		"until": event.get("retention.until"), "previous_until": previous, "seq": int64(event.seq), "uid": event.uid,
		"state": to,
	})
	return retentionResult(session, ledger, event, to, len(retention.holds), map[string]object.Object{
		"until":          stringObj(event.get("retention.until")),
		"previous_until": stringObj(previous),
		"basis":          stringObj(basis),
		"lapsed":         boolObj(!now.Before(until)),
		"from":           stringObj(from),
		"moved":          boolObj(to != from),
	})
}

// ---------------------------------------------------------------------------
// retention_hold and retention_release
// ---------------------------------------------------------------------------

// RetentionHold places a legal hold on the attached case:
// retention_hold(ledger, reason, options?).
func RetentionHold(args ...object.Object) object.Object {
	op := BuiltinNameRetentionHold
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 3, retentionHoldOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason, errObj := caseTextArg(op, args[1], 2, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	authority, basis, errObj := retentionHoldAuthority(op, ledger, opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	session, errObj := caseLedgerWrite(op, ledger)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	g := ledger.graph
	caseUID := strings.ToLower(session.caseUID)
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := caseLedgerStateRefusal(g, caseUID, caseActRetain); err != nil {
		return fail(err)
	}
	_, state, err := caseLifecycleRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	retention, err := retentionRead(g, caseUID)
	if err != nil {
		return fail(err)
	}

	now := custodyNow()
	w, err := caseBeginWrite(ledger, caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	authorityN, err := w.tx.actorNode(g, authority)
	if err != nil {
		return fail(err)
	}
	event, err := w.retentionAppend(retention, retentionKindHold, map[string]string{
		"retention.reason":          reason,
		"retention.authority":       authority,
		"retention.authority_basis": basis,
	}, caseEdge{authorityN, disclosureEdgeAuthorisedBy, map[string]string{"basis": basis}})
	if err != nil {
		return fail(err)
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	session.appendEvent(now, op, fmt.Sprintf("legal hold placed on case %s by %s, on the authority of %s: %s",
		session.ID, ledger.actor, authority, reason), map[string]any{
		"authority": authority, "authority_basis": basis, "seq": int64(event.seq), "uid": event.uid,
	})
	return retentionResult(session, ledger, event, state, len(retention.holds)+1, map[string]object.Object{
		"reason":          stringObj(reason),
		"authority":       stringObj(authority),
		"authority_basis": stringObj(basis),
	})
}

// RetentionRelease lifts a legal hold on the attached case:
// retention_release(ledger, hold, reason).
func RetentionRelease(args ...object.Object) object.Object {
	op := BuiltinNameRetentionRelease
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	holdArg, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	holdUID := choiceFold(holdArg)
	reason, errObj := caseTextArg(op, args[2], 3, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	session, errObj := caseLedgerWrite(op, ledger)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	g := ledger.graph
	caseUID := strings.ToLower(session.caseUID)
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := caseLedgerStateRefusal(g, caseUID, caseActRetain); err != nil {
		return fail(err)
	}
	_, state, err := caseLifecycleRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	retention, err := retentionRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	var hold *caseChainEvent
	for i := range retention.holds {
		if retention.holds[i].uid == holdUID {
			hold = &retention.holds[i]
		}
	}
	if hold == nil {
		for _, event := range retention.events {
			if event.get("retention.kind") == retentionKindRelease && event.get("retention.hold_uid") == holdUID {
				return resultAndError(nil, newError("%s: hold %s on case %s was lifted at %s by %s: %q", op, holdUID,
					session.ID, event.get("retention.at"), event.get("retention.by"), event.get("retention.reason")))
			}
		}
		return resultAndError(nil, newError("%s: case %s has no hold %s; retention_list lists the holds in force",
			op, session.ID, holdUID))
	}

	now := custodyNow()
	w, err := caseBeginWrite(ledger, caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	event, err := w.retentionAppend(retention, retentionKindRelease, map[string]string{
		"retention.hold_uid": holdUID,
		"retention.reason":   reason,
	})
	if err != nil {
		return fail(err)
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	session.appendEvent(now, op, fmt.Sprintf("legal hold %s on case %s lifted by %s: %s", holdUID, session.ID,
		ledger.actor, reason), map[string]any{"hold_uid": holdUID, "seq": int64(event.seq), "uid": event.uid})
	return retentionResult(session, ledger, event, state, len(retention.holds)-1, map[string]object.Object{
		"hold_uid":    stringObj(holdUID),
		"hold_reason": stringObj(hold.get("retention.reason")),
		"held_since":  stringObj(hold.get("retention.at")),
		"reason":      stringObj(reason),
	})
}

// ---------------------------------------------------------------------------
// retention_list
// ---------------------------------------------------------------------------

// RetentionList reads the retention of every case in a ledger, or of one:
// retention_list(ledger, options?). It needs no case open, so an auditor reads
// it with the ledger alone.
func RetentionList(args ...object.Object) object.Object {
	op := BuiltinNameRetentionList
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 2, retentionListOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	caseUID, errObj := opts.str("case_uid", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	disclosureLedgerMu.Lock()
	cases, err := retentionReadAll(ledger.graph, strings.ToLower(strings.TrimSpace(caseUID)))
	disclosureLedgerMu.Unlock()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	now := custodyNow()
	holds := 0
	rows := make([]object.Object, 0, len(cases))
	for _, retention := range cases {
		holds += len(retention.holds)
		rows = append(rows, retentionRow(retention, now))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"cases":          &object.Array{Elements: rows},
		"count":          intObj(int64(len(rows))),
		"holds_in_force": intObj(int64(holds)),
		"source":         stringObj("ledger"),
	}), nil)
}

func retentionRow(retention caseRetention, now time.Time) object.Object {
	first := retention.events[0]
	var period caseChainEvent
	if retention.period != nil {
		period = *retention.period
	}
	holds := make([]object.Object, 0, len(retention.holds))
	for _, hold := range retention.holds {
		holds = append(holds, makeHashObject(map[string]object.Object{
			"uid":             stringObj(hold.uid),
			"seq":             intObj(int64(hold.seq)),
			"reason":          stringObj(hold.get("retention.reason")),
			"authority":       stringObj(hold.get("retention.authority")),
			"authority_basis": stringObj(hold.get("retention.authority_basis")),
			"by":              stringObj(hold.get("retention.by")),
			"by_role":         stringObj(hold.get("retention.by_role")),
			"at":              stringObj(hold.get("retention.at")),
		}))
	}
	events := make([]object.Object, 0, len(retention.events))
	for _, event := range retention.events {
		events = append(events, makeHashObject(map[string]object.Object{
			"seq":             intObj(int64(event.seq)),
			"uid":             stringObj(event.uid),
			"kind":            stringObj(event.get("retention.kind")),
			"until":           stringObj(event.get("retention.until")),
			"previous_until":  stringObj(event.get("retention.previous_until")),
			"basis":           stringObj(event.get("retention.basis")),
			"reason":          stringObj(event.get("retention.reason")),
			"authority":       stringObj(event.get("retention.authority")),
			"authority_basis": stringObj(event.get("retention.authority_basis")),
			"hold_uid":        stringObj(event.get("retention.hold_uid")),
			"by":              stringObj(event.get("retention.by")),
			"by_role":         stringObj(event.get("retention.by_role")),
			"at":              stringObj(event.get("retention.at")),
		}))
	}
	return makeHashObject(map[string]object.Object{
		"case_uid":       stringObj(first.get("retention.case_uid")),
		"case_id":        stringObj(first.get("retention.case_id")),
		"until":          stringObj(period.get("retention.until")),
		"basis":          stringObj(period.get("retention.basis")),
		"set_by":         stringObj(period.get("retention.by")),
		"set_at":         stringObj(period.get("retention.at")),
		"lapsed":         boolObj(retention.lapsed(now)),
		"holds":          &object.Array{Elements: holds},
		"holds_in_force": intObj(int64(len(retention.holds))),
		"events":         &object.Array{Elements: events},
		"event_count":    intObj(int64(len(events))),
	})
}
