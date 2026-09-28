package builtin

// Evidence in the case's ledger: which exhibits a case holds, who holds each
// one now, and every hand-off it went through, written as it happens and kept
// after the run.
//
// case_evidence and the evidence openers say what this run read. They cannot
// say where the drive was on Tuesday, because a run does not know. The
// builtins here record custody itself: an exhibit taken in, released by the
// person holding it to somebody the case assigns, accepted by that person --
// who hashes what they were handed and compares it with what was taken in --
// and finally returned to whoever it came from, or disposed of.
//
// # The chain
//
// Each exhibit is an EvidenceFile node, BELONGS_TO the Case, carrying the
// SHA-256 taken at intake. Its custody is a chain of CustodyEvent nodes
// (case_chain.go), each BELONGS_TO the exhibit, PERFORMED_BY the examiner who
// recorded it, and CUSTODIAN to whoever holds or is receiving it:
//
//	intake -> held -> release -> in_transit -> accept   -> held -> ...
//	          held -> return  -> returned   -> reintake -> held -> ...
//	          held -> dispose -> disposed
//
// A returned exhibit that comes back is taken in again under its own name,
// by evidence_intake: the re-intake is the next event of the same chain, and
// what came back is hashed and compared with what was first taken in, as an
// accept compares what it was handed. So the question a returned exhibit
// raises -- is this the thing that left? -- is answered every time it comes
// back, and cannot be skipped by giving it a new name and forgetting the
// old one. A disposal is final: what comes back after one is another
// exhibit, taken in under another name.
//
// Every reader walks the chain from its intake and refuses one that forks,
// skips a state, or holds an event whose uid does not recompute, whose kind
// this program does not write, or that names another exhibit; one whose
// event was recorded by somebody who could not have recorded it, or leaves
// the exhibit with somebody else; and one whose hash check is missing,
// claimed where none is made, disagrees with its own digests, or finds a
// mismatch nobody explained. That is the chain's account of where the
// exhibit is, who holds it and whether it is what was taken in, and a chain
// whose account does not add up is refused rather than reported. What an
// event says beyond that -- its reason, whom it names as recipient or
// source, the path it read, its time and the role its recorder acted as --
// evidence_history reports as the event records it.
//
// # Consistent, not controlled
//
// A release or a return is recorded by the person the ledger says holds the
// exhibit, and an accept by the person it was released to; a release is to
// somebody the case assigns a role, so a misspelt name is refused rather
// than left holding an exhibit nobody can accept. An intake and a re-intake
// are recorded by somebody the case assigns. A disposal is recorded by a
// case_owner or an administrator. Each of these keeps the record consistent
// with itself -- the ledger never says one person holds an exhibit while
// another hands it on -- and none is access control: the names are
// asserted, and every refusal says so where a role decides it.
//
// # What is refused, and what never is
//
// A new exhibit is refused while the case is in review, concluded, retained
// or disposed, with the reasons case_lifecycle.go gives. A movement of an
// exhibit the case has taken in -- a release, an accept, a return, a
// disposal, and a returned exhibit taken back in -- is refused in no state:
// where a drive is, is a fact, and a record that could not say the drive
// moved would be a record that is wrong. A returned exhibit coming back adds
// no exhibit to the case; it is compared with its intake as an accept is,
// and an accept is a movement too.
//
// A disposal records a statement and deletes nothing. The file the exhibit
// was taken in from is opened read-only, to hash it, and nothing else;
// policy.EvidenceReadOnlyFiles holds this file to that.

import (
	"fmt"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// What a custody event records.
const (
	evidenceKindIntake   = "intake"
	evidenceKindRelease  = "release"
	evidenceKindAccept   = "accept"
	evidenceKindReturn   = "return"
	evidenceKindReintake = "reintake"
	evidenceKindDispose  = "dispose"
)

// Where an exhibit is.
const (
	evidenceHeld      = "held"
	evidenceInTransit = "in_transit"
	evidenceReturned  = "returned"
	evidenceDisposed  = "disposed"
)

// evidenceStates is every state, in the order an exhibit can pass through
// them.
var evidenceStates = []string{evidenceHeld, evidenceInTransit, evidenceReturned, evidenceDisposed}

// evidenceMove is what one kind of custody event does: the state it needs the
// exhibit in, the state it leaves it in, and whether it hashes the file it is
// recorded with and compares the digest with the one taken at intake.
//
// Who records an event follows from the state it needs: the holder moves an
// exhibit somebody holds, the person it was released to accepts one in
// transit, and anybody the case assigns takes one in, new or returned.
type evidenceMove struct {
	from, to string
	compares bool
}

var evidenceMoves = map[string]evidenceMove{
	evidenceKindIntake:   {"", evidenceHeld, false},
	evidenceKindRelease:  {evidenceHeld, evidenceInTransit, false},
	evidenceKindAccept:   {evidenceInTransit, evidenceHeld, true},
	evidenceKindReturn:   {evidenceHeld, evidenceReturned, false},
	evidenceKindReintake: {evidenceReturned, evidenceHeld, true},
	evidenceKindDispose:  {evidenceHeld, evidenceDisposed, false},
}

// evidenceHolderAfter is who holds an exhibit once an event recorded by `by`
// leaves it in state: the recorder while it is held or in transit -- a release
// leaves it with the releaser until it is accepted -- and nobody once it has
// been returned or disposed of.
func evidenceHolderAfter(state, by string) string {
	if state == evidenceHeld || state == evidenceInTransit {
		return by
	}
	return ""
}

// evidenceDigestAlgo is the digest every exhibit is taken in and accepted
// under, whatever the case's hash policy: an accept compares a digest with
// the intake's, and a case opened with no hash policy would otherwise have
// nothing to compare.
const evidenceDigestAlgo = "sha256"

// The options evidence_intake, evidence_accept and evidence_history take.
var (
	evidenceIntakeOptions  = []string{"description", "received_from", "discrepancy"}
	evidenceAcceptOptions  = []string{"discrepancy"}
	evidenceHistoryOptions = []string{"exhibit", "case_uid"}
)

var evidenceCustodyChain = caseChainSpec{label: disclosureNodeCustodyEvent, prefix: "custody"}

// evidenceUID names one exhibit of one case. A case uid is hex and holds no
// separator, so no two (case, exhibit) pairs hash alike.
func evidenceUID(caseUID, exhibit string) string {
	return ledgerHash(sha256Of("mutant-evidence-v1|" + strings.ToLower(caseUID) + "|" + exhibit))
}

// evidenceItem is one exhibit as read back: its EvidenceFile node and its
// custody chain, first to head.
type evidenceItem struct {
	node   disclosureNode
	events []caseChainEvent
}

func (e evidenceItem) head() caseChainEvent { return e.events[len(e.events)-1] }
func (e evidenceItem) state() string        { return e.head().get("custody.state") }
func (e evidenceItem) holder() string       { return e.head().get("custody.holder") }
func (e evidenceItem) exhibit() string      { return e.node.get("evidence.exhibit") }

// ---------------------------------------------------------------------------
// Reading custody back
// ---------------------------------------------------------------------------

// evidenceReadNode reads one exhibit's custody chain and checks, event by
// event, that it is one this program wrote.
func evidenceReadNode(g *graphene.Graph, node disclosureNode) (evidenceItem, error) {
	uid := node.get("evidence.uid")
	events, err := caseChainRead(g, evidenceCustodyChain, uid)
	if err != nil {
		return evidenceItem{}, err
	}
	exhibit := node.get("evidence.exhibit")
	if len(events) == 0 {
		return evidenceItem{}, fmt.Errorf("exhibit %q is in the ledger with no custody record, which this "+
			"program never writes", exhibit)
	}
	var prev caseChainEvent
	for _, event := range events {
		if err := evidenceCheck(event, prev, uid, exhibit, node.get("evidence.digest")); err != nil {
			return evidenceItem{}, err
		}
		prev = event
	}
	return evidenceItem{node: node, events: events}, nil
}

// evidenceCheck refuses a custody event that does not follow from prev, the
// event before it (none, for the first).
//
// The program writes an event of a kind it knows, for this exhibit, that
// moves the exhibit from where prev left it to where its kind leaves it; the
// first is the intake, and measured the digest the exhibit says it was taken
// in as. An event that moves an exhibit somebody holds is recorded by that
// person, and an accept by the person the exhibit was released to; whoever
// records an event that leaves the exhibit held or in transit holds it after.
// An accept and a re-intake each compare a digest with the intake's and say
// whether it matched -- truthfully, and with a discrepancy when it did not --
// and no other event says it compared anything.
func evidenceCheck(event, prev caseChainEvent, uid, exhibit, intake string) error {
	kind := event.get("custody.kind")
	move, known := evidenceMoves[kind]
	state, by, matches := prev.get("custody.state"), event.get("custody.by"), event.get("custody.matches_intake")
	which := fmt.Sprintf("custody event %d of exhibit %q (%s)", event.seq, exhibit, kind)
	switch {
	case !known:
		return fmt.Errorf("custody event %d of exhibit %q records %q, which is not a kind of custody event "+
			"this program writes", event.seq, exhibit, kind)
	case event.get("custody.evidence_uid") != uid:
		return fmt.Errorf("custody event %d of exhibit %q names another exhibit", event.seq, exhibit)
	case event.get("custody.from") != state || move.from != state:
		return fmt.Errorf("%s moves the exhibit from %q, and the event before it left the exhibit %q", which,
			event.get("custody.from"), state)
	case event.get("custody.state") != move.to:
		return fmt.Errorf("%s leaves the exhibit %q, and every %s leaves it %s", which, event.get("custody.state"),
			kind, move.to)
	case event.seq == 1 && event.get("custody.digest") != intake:
		return fmt.Errorf("exhibit %q says it was taken in with digest %s, and its intake measured %s", exhibit,
			intake, event.get("custody.digest"))
	case move.from == evidenceHeld && by != prev.get("custody.holder"):
		return fmt.Errorf("%s was recorded by %s, and the event before it left the exhibit held by %s", which, by,
			prev.get("custody.holder"))
	case move.from == evidenceInTransit && by != prev.get("custody.to"):
		return fmt.Errorf("%s was recorded by %s, and the exhibit was released to %s", which, by,
			prev.get("custody.to"))
	case event.get("custody.holder") != evidenceHolderAfter(move.to, by):
		return fmt.Errorf("%s leaves the exhibit with %q, and a %s recorded by %s leaves it with %q", which,
			event.get("custody.holder"), kind, by, evidenceHolderAfter(move.to, by))
	case move.compares && (matches == "" || event.get("custody.digest") == ""):
		return fmt.Errorf("%s compares no digest with the intake's, and every %s does", which, kind)
	case !move.compares && matches != "":
		return fmt.Errorf("%s says it compared a digest with the intake's, and no %s does", which, kind)
	case move.compares && matches != strconv.FormatBool(event.get("custody.digest") == intake):
		return fmt.Errorf("%s says matches_intake is %s, and it measured %s where the intake measured %s", which,
			matches, event.get("custody.digest"), intake)
	case matches == "false" && event.get("custody.discrepancy") == "":
		return fmt.Errorf("%s records a digest that does not match the intake's and no discrepancy, and this "+
			"program records neither without the other", which)
	}
	return nil
}

// evidenceRead reads one exhibit of a case, or reports that the case holds
// none by that name.
func evidenceRead(g *graphene.Graph, caseUID, exhibit string) (evidenceItem, bool, error) {
	uid := evidenceUID(caseUID, exhibit)
	node, found, err := disclosureFind(g, disclosureNodeEvidence, "evidence.uid", uid)
	if err != nil || !found {
		return evidenceItem{}, false, err
	}
	if node.get("evidence.case_uid") != strings.ToLower(caseUID) || node.get("evidence.exhibit") != exhibit {
		return evidenceItem{}, false, fmt.Errorf("evidence node %d is found as exhibit %q of case %s and says "+
			"it is exhibit %q of case %s", node.id, exhibit, caseUID, node.get("evidence.exhibit"),
			node.get("evidence.case_uid"))
	}
	item, err := evidenceReadNode(g, node)
	return item, err == nil, err
}

// evidenceReadAll reads every exhibit of a case, or of every case when
// caseUID is empty, ordered by case and then by exhibit.
func evidenceReadAll(g *graphene.Graph, caseUID string) ([]evidenceItem, error) {
	var nodes []disclosureNode
	if caseUID == "" {
		all, err := disclosureAll(g, disclosureNodeEvidence)
		if err != nil {
			return nil, err
		}
		nodes = all
	} else {
		ids, err := g.NodesByProperty("evidence.case_uid", []byte(strings.ToLower(caseUID)))
		if err != nil {
			return nil, err
		}
		found, _, err := g.GetNodes(ids)
		if err != nil {
			return nil, err
		}
		for _, node := range found {
			if !node.HasLabel(disclosureNodeEvidence) {
				continue
			}
			decoded, err := disclosureDecode(node)
			if err != nil {
				return nil, fmt.Errorf("evidence node %d: %w", node.ID, err)
			}
			nodes = append(nodes, decoded)
		}
	}
	out := make([]evidenceItem, 0, len(nodes))
	for _, node := range nodes {
		// An EvidenceFile is graphene's built-in type, and a node of it that
		// carries no uid of ours is somebody else's record of a file.
		uid := node.get("evidence.uid")
		if uid == "" {
			continue
		}
		if uid != evidenceUID(node.get("evidence.case_uid"), node.get("evidence.exhibit")) {
			return nil, fmt.Errorf("evidence node %d says it is exhibit %q of case %s under a uid that is not "+
				"that exhibit's", node.id, node.get("evidence.exhibit"), node.get("evidence.case_uid"))
		}
		item, err := evidenceReadNode(g, node)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].node, out[j].node
		if a.get("evidence.case_uid") != b.get("evidence.case_uid") {
			return a.get("evidence.case_uid") < b.get("evidence.case_uid")
		}
		return a.get("evidence.exhibit") < b.get("evidence.exhibit")
	})
	return out, nil
}

// ---------------------------------------------------------------------------
// Writing custody
// ---------------------------------------------------------------------------

// evidenceCustodian is one CUSTODIAN edge of a custody event: who, and as
// what.
type evidenceCustodian struct {
	name, as string
}

// custody appends a custody event of kind after head -- the intake, when
// head is nil -- to the chain of the exhibit whose node is evidenceN. props
// are what this kind records beyond what every event does.
func (w *caseWriter) custody(evidenceN store.NodeID, uid, exhibit, kind string, head *caseChainEvent,
	reason string, props map[string]string, custodians []evidenceCustodian) (caseChainEvent, error) {
	move := evidenceMoves[kind]
	all := map[string]string{
		"custody.case_uid":     w.caseUID,
		"custody.evidence_uid": uid,
		"custody.exhibit":      exhibit,
		"custody.kind":         kind,
		"custody.from":         move.from,
		"custody.state":        move.to,
		"custody.holder":       evidenceHolderAfter(move.to, w.ledger.actor),
		"custody.reason":       reason,
		"custody.by":           w.ledger.actor,
		"custody.by_role":      w.ledger.role.Name,
		"custody.at":           w.at.UTC().Format(time.RFC3339Nano),
		"custody.unix_nano":    strconv.FormatInt(w.at.UnixNano(), 10),
	}
	maps.Copy(all, props)
	id, event, err := w.tx.chainAppend(evidenceCustodyChain, uid, head, all)
	if err != nil {
		return caseChainEvent{}, err
	}
	if err := w.tx.edge(id, evidenceN, disclosureEdgeBelongsTo, nil); err != nil {
		return caseChainEvent{}, err
	}
	if err := w.tx.edge(id, w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(w.ledger)); err != nil {
		return caseChainEvent{}, err
	}
	for _, c := range custodians {
		n, err := w.tx.actorNode(w.g, c.name)
		if err != nil {
			return caseChainEvent{}, err
		}
		if err := w.tx.edge(id, n, disclosureEdgeCustodian, map[string]string{"as": c.as}); err != nil {
			return caseChainEvent{}, err
		}
	}
	return event, nil
}

// ---------------------------------------------------------------------------
// Arguments and the shared preamble
// ---------------------------------------------------------------------------

// evidenceMeasured is a file hashed before any lock is taken: hashing a disk
// image is the slowest thing a custody builtin does.
type evidenceMeasured struct {
	source custodySource
	digest string
}

// evidenceMeasure resolves and hashes the file an exhibit is taken in or
// accepted from. It opens the file read-only and does nothing else to it.
func evidenceMeasure(op string, arg object.Object, position int) (evidenceMeasured, *object.Error) {
	path, errObj := requireStringArg(op, arg, position)
	if errObj != nil {
		return evidenceMeasured{}, errObj
	}
	if strings.TrimSpace(path) == "" {
		return evidenceMeasured{}, newError("%s: the path must not be empty", op)
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return evidenceMeasured{}, newError("%s: %s is a directory; an exhibit is taken in as one file, "+
			"and a directory has no digest", op, path)
	}
	source := custodyStatSource(path)
	if !source.onDisk {
		return evidenceMeasured{}, newError("%s: %s cannot be read: no such file", op, path)
	}
	digest, err := custodyHashFile(source.path, evidenceDigestAlgo)
	if err != nil {
		return evidenceMeasured{}, newError("%s: hashing %s: %s", op, source.path, err.Error())
	}
	return evidenceMeasured{source: source, digest: digest}, nil
}

// evidenceDiscrepancyOption reads the discrepancy an accept or a re-intake
// records: none when the option is absent, and something said when it is
// present.
func evidenceDiscrepancyOption(op string, opts *formatOptions, position int) (string, *object.Error) {
	if _, given := opts.pairs["discrepancy"]; !given {
		return "", nil
	}
	value, errObj := opts.str("discrepancy", "")
	if errObj != nil {
		return "", errObj
	}
	return caseTextArg(op, stringObj(value), position, "discrepancy")
}

// evidenceUnexplained refuses a file whose digest is not the one its exhibit
// was taken in with, unless the examiner has said what happened to it. what
// is the event that would have been recorded.
func evidenceUnexplained(op, what string, measured evidenceMeasured, exhibit, intake,
	discrepancy string) *object.Error {
	if measured.digest == intake || discrepancy != "" {
		return nil
	}
	return newError("%s: %s hashes to %s %s, and exhibit %q was taken in as %s. If this is that exhibit, say "+
		"what happened to it with {\"discrepancy\": \"...\"}: the %s is then recorded with both digests and "+
		"your statement. Nothing has been recorded", op, measured.source.path, evidenceDigestAlgo,
		measured.digest, exhibit, intake, what)
}

// evidenceComparison is what an accept or a re-intake records of the file it
// hashed: the file, its digest, whether that is the digest the exhibit was
// taken in with, and the examiner's statement when it is not.
func evidenceComparison(measured evidenceMeasured, intake, discrepancy string) map[string]string {
	return map[string]string{
		"custody.path":           measured.source.path,
		"custody.size":           strconv.FormatInt(measured.source.size, 10),
		"custody.algo":           evidenceDigestAlgo,
		"custody.digest":         measured.digest,
		"custody.matches_intake": strconv.FormatBool(measured.digest == intake),
		"custody.discrepancy":    discrepancy,
	}
}

// evidenceHeldBy reads an exhibit of the attached case and refuses unless
// the ledger says the examiner writing holds it.
func evidenceHeldBy(op string, session *custodySession, ledger *ledgerSession, exhibit string) (evidenceItem,
	*object.Error) {
	item, errObj := evidenceExisting(op, session, ledger, exhibit)
	if errObj != nil {
		return evidenceItem{}, errObj
	}
	switch {
	case item.state() != evidenceHeld:
		return evidenceItem{}, newError("%s: exhibit %q is %s (%s), and only an exhibit somebody holds is "+
			"handed on", op, exhibit, item.state(), evidenceWhere(item))
	case item.holder() != ledger.actor:
		return evidenceItem{}, newError("%s: the ledger says %s holds exhibit %q, and %s is recording what "+
			"happens to it next. Whoever holds an exhibit records where it goes, so the ledger never says "+
			"one person holds it while another hands it on", op, item.holder(), exhibit, ledger.actor)
	}
	return item, nil
}

// evidenceExisting reads an exhibit of the attached case, and refuses one the
// case does not hold.
func evidenceExisting(op string, session *custodySession, ledger *ledgerSession, exhibit string) (evidenceItem,
	*object.Error) {
	item, found, err := evidenceRead(ledger.graph, session.caseUID, exhibit)
	if err != nil {
		return evidenceItem{}, newError("%s: %s", op, err.Error())
	}
	if !found {
		return evidenceItem{}, newError("%s: case %s holds no exhibit %q; evidence_intake takes one in, and "+
			"evidence_history lists what the case holds", op, session.ID, exhibit)
	}
	return item, nil
}

// evidenceWhere says where an exhibit is, in words.
func evidenceWhere(item evidenceItem) string {
	head := item.head()
	switch item.state() {
	case evidenceHeld:
		return "held by " + item.holder()
	case evidenceInTransit:
		return fmt.Sprintf("released by %s to %s, who has not accepted it", item.holder(), head.get("custody.to"))
	case evidenceReturned:
		return "returned to " + head.get("custody.to")
	default:
		return "disposed of by " + head.get("custody.by")
	}
}

// evidenceAssignedInForce refuses a name the case's ledger assigns no role in
// force.
func evidenceAssignedInForce(op string, session *custodySession, g *graphene.Graph, name, why string) *object.Error {
	assignments, err := caseAssignmentsRead(g, session.caseUID)
	if err != nil {
		return newError("%s: %s", op, err.Error())
	}
	if a, found := caseAssignmentOf(assignments, name); found && a.role != caseAssignmentEnded {
		return nil
	}
	return newError("%s: the ledger assigns %s no role in case %s, and %s. case_assign records one", op, name,
		session.ID, why)
}

// evidenceCommitted is what every custody writer does after its commit: the
// run's copy of the case learns the event, and the timeline records it.
func evidenceCommitted(session *custodySession, op, detail string, item evidenceItem, event caseChainEvent) {
	session.appendEvent(evidenceEventAt(event), op, detail, map[string]any{
		"exhibit":      item.exhibit(),
		"evidence_uid": item.node.get("evidence.uid"),
		"kind":         event.get("custody.kind"),
		"state":        event.get("custody.state"),
		"seq":          int64(event.seq),
		"uid":          event.uid,
	})
}

// evidenceEventAt is when a custody event was recorded, as its writer's
// clock said.
func evidenceEventAt(e caseChainEvent) time.Time {
	n, err := strconv.ParseInt(e.get("custody.unix_nano"), 10, 64)
	if err != nil {
		return custodyNow()
	}
	return time.Unix(0, n)
}

// evidenceResult is what every custody writer returns: the exhibit as its
// chain now leaves it, and the event just recorded.
func evidenceResult(session *custodySession, item evidenceItem, event caseChainEvent,
	extra map[string]object.Object) object.Object {
	fields := map[string]object.Object{
		"case_id":            stringObj(session.ID),
		"exhibit":            stringObj(item.exhibit()),
		"evidence_uid":       stringObj(item.node.get("evidence.uid")),
		"kind":               stringObj(event.get("custody.kind")),
		"state":              stringObj(event.get("custody.state")),
		"holder":             stringObj(event.get("custody.holder")),
		"seq":                intObj(int64(event.seq)),
		"uid":                stringObj(event.uid),
		"at":                 stringObj(event.get("custody.at")),
		"by":                 stringObj(event.get("custody.by")),
		"by_role":            stringObj(event.get("custody.by_role")),
		"role_authenticated": boolObj(false),
	}
	maps.Copy(fields, extra)
	return resultAndError(makeHashObject(fields), nil)
}

// ---------------------------------------------------------------------------
// evidence_intake
// ---------------------------------------------------------------------------

// EvidenceIntake takes an exhibit into the attached case's custody, or takes
// back in one the case returned: evidence_intake(ledger, exhibit, path,
// options?).
func EvidenceIntake(args ...object.Object) object.Object {
	op := BuiltinNameEvidenceIntake
	if len(args) < 3 || len(args) > 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 4, evidenceIntakeOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	exhibit, errObj := caseTextArg(op, args[1], 2, "exhibit")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	description, errObj := opts.str("description", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	receivedFrom, errObj := opts.str("received_from", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	for _, text := range []struct{ what, value string }{{"description", description}, {"received_from", receivedFrom}} {
		if len(text.value) > maxCaseReason {
			return resultAndError(nil, newError("%s: the %s is at most %d bytes, and this one is %d", op, text.what,
				maxCaseReason, len(text.value)))
		}
		if errObj := custodyDocumentName(op, text.what, text.value); errObj != nil {
			return resultAndError(nil, errObj)
		}
	}
	discrepancy, errObj := evidenceDiscrepancyOption(op, opts, 4)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	measured, errObj := evidenceMeasure(op, args[2], 3)
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
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if errObj := evidenceAssignedInForce(op, session, g, ledger.actor,
		"an exhibit is taken into a case by somebody working it"); errObj != nil {
		return resultAndError(nil, errObj)
	}
	existing, found, err := evidenceRead(g, session.caseUID, exhibit)
	if err != nil {
		return fail(err)
	}
	switch {
	case found && existing.state() == evidenceReturned:
		// An exhibit coming back is a movement of one the case has taken in,
		// and like every movement it is taken in whatever state the case is in.
		return evidenceReintake(op, session, ledger, existing, measured, description, receivedFrom, discrepancy)
	case found && existing.state() == evidenceDisposed:
		return resultAndError(nil, newError("%s: exhibit %q of case %s was disposed of by %s at %s, and a "+
			"disposal is final: what comes back after one is another exhibit, taken in under another name", op,
			exhibit, session.ID, existing.head().get("custody.by"), existing.head().get("custody.at")))
	case found:
		return resultAndError(nil, newError("%s: case %s already holds exhibit %q, taken in by %s at %s and %s "+
			"now. An exhibit is taken in again only after it has been returned; give another exhibit another "+
			"name", op, session.ID, exhibit, existing.events[0].get("custody.by"),
			existing.events[0].get("custody.at"), evidenceWhere(existing)))
	}
	if err := caseLedgerStateRefusal(g, session.caseUID, caseActIntake); err != nil {
		return fail(err)
	}
	if discrepancy != "" {
		return resultAndError(nil, newError("%s: case %s has never held exhibit %q, so there is no intake for it "+
			"to differ from; a discrepancy is recorded when an exhibit comes back", op, session.ID, exhibit))
	}

	now := custodyNow()
	w, err := caseBeginWrite(ledger, session.caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	uid := evidenceUID(session.caseUID, exhibit)
	size := strconv.FormatInt(measured.source.size, 10)
	props := map[string]string{
		"evidence.uid":           uid,
		"evidence.case_uid":      w.caseUID,
		"evidence.case_id":       session.ID,
		"evidence.exhibit":       exhibit,
		"evidence.path":          measured.source.path,
		"evidence.size":          size,
		"evidence.algo":          evidenceDigestAlgo,
		"evidence.digest":        measured.digest,
		"evidence.description":   description,
		"evidence.received_from": receivedFrom,
		"evidence.by":            ledger.actor,
		"evidence.at":            now.UTC().Format(time.RFC3339Nano),
	}
	evidenceN, err := w.tx.node(disclosureNodeEvidence, props)
	if err != nil {
		return fail(err)
	}
	if err := w.tx.edge(evidenceN, w.caseN, disclosureEdgeBelongsTo, nil); err != nil {
		return fail(err)
	}
	reason := "taken in"
	if receivedFrom != "" {
		reason = "received from " + receivedFrom
	}
	event, err := w.custody(evidenceN, uid, exhibit, evidenceKindIntake, nil, reason,
		map[string]string{
			"custody.path":          measured.source.path,
			"custody.size":          size,
			"custody.algo":          evidenceDigestAlgo,
			"custody.digest":        measured.digest,
			"custody.received_from": receivedFrom,
		}, []evidenceCustodian{{ledger.actor, "holder"}})
	if err != nil {
		return fail(err)
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}

	item := evidenceItem{node: disclosureNode{id: evidenceN, props: props}}
	session.registerFileLocked(measured.source, evidenceDigestAlgo, measured.digest, now,
		fmt.Sprintf("%s took in exhibit %s from %s", op, exhibit, measured.source.path))
	evidenceCommitted(session, op, fmt.Sprintf("exhibit %s taken in by %s, %s %s", exhibit, ledger.actor,
		evidenceDigestAlgo, measured.digest), item, event)
	return evidenceResult(session, item, event, evidenceIntakeFields(measured, description, receivedFrom,
		measured.digest, false, ""))
}

// evidenceReintake takes a returned exhibit back into its case, as the next
// event of its custody chain, after comparing what came back with what was
// first taken in. EvidenceIntake calls it with both locks held and the
// examiner found assigned; the case's state is not asked, because this is a
// movement of an exhibit the case has taken in.
func evidenceReintake(op string, session *custodySession, ledger *ledgerSession, item evidenceItem,
	measured evidenceMeasured, description, receivedFrom, discrepancy string) object.Object {
	exhibit := item.exhibit()
	if description != "" {
		return resultAndError(nil, newError("%s: exhibit %q was described when it was first taken in, and "+
			"taking it in again records who it came back from and, if it came back changed, a discrepancy; "+
			"the description stays the one it was taken in with", op, exhibit))
	}
	intake := item.node.get("evidence.digest")
	if errObj := evidenceUnexplained(op, "re-intake", measured, exhibit, intake, discrepancy); errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason := "taken in again"
	if receivedFrom != "" {
		reason = "received back from " + receivedFrom
	}
	props := evidenceComparison(measured, intake, discrepancy)
	props["custody.received_from"] = receivedFrom
	event, errObj := evidenceAppend(op, session, ledger, item, evidenceKindReintake, reason, props,
		[]evidenceCustodian{{ledger.actor, "holder"}})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	session.registerFileLocked(measured.source, evidenceDigestAlgo, measured.digest, evidenceEventAt(event),
		fmt.Sprintf("%s took exhibit %s back in from %s", op, exhibit, measured.source.path))
	detail := fmt.Sprintf("exhibit %s taken in again by %s; digest matches intake", exhibit, ledger.actor)
	if measured.digest != intake {
		detail = fmt.Sprintf("exhibit %s taken in again by %s with a digest that does not match intake: %s",
			exhibit, ledger.actor, discrepancy)
	}
	evidenceCommitted(session, op, detail, item, event)
	return evidenceResult(session, item, event, evidenceIntakeFields(measured,
		item.node.get("evidence.description"), receivedFrom, intake, true, discrepancy))
}

// evidenceIntakeFields are what evidence_intake returns beyond what every
// custody writer does, for a first intake and a re-intake alike.
func evidenceIntakeFields(measured evidenceMeasured, description, receivedFrom, intake string, checked bool,
	discrepancy string) map[string]object.Object {
	return map[string]object.Object{
		"path":          stringObj(measured.source.path),
		"size":          intObj(measured.source.size),
		"hash_algo":     stringObj(evidenceDigestAlgo),
		"hash":          stringObj(measured.digest),
		"description":   stringObj(description),
		"received_from": stringObj(receivedFrom),
		"intake_hash":   stringObj(intake),
		// A first intake is what every later digest is compared with, and is
		// compared with nothing: not checked, and so not a match either.
		"hash_checked":   boolObj(checked),
		"matches_intake": boolObj(checked && measured.digest == intake),
		"discrepancy":    stringObj(discrepancy),
	}
}

// ---------------------------------------------------------------------------
// evidence_release
// ---------------------------------------------------------------------------

// EvidenceRelease records the holder of an exhibit handing it to somebody the
// case assigns: evidence_release(ledger, exhibit, to, reason).
func EvidenceRelease(args ...object.Object) object.Object {
	op := BuiltinNameEvidenceRelease
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	exhibit, errObj := caseTextArg(op, args[1], 2, "exhibit")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	to, errObj := caseTextArg(op, args[2], 3, "recipient")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason, errObj := caseTextArg(op, args[3], 4, "reason")
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
	item, errObj := evidenceHeldBy(op, session, ledger, exhibit)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if to == ledger.actor {
		return resultAndError(nil, newError("%s: %s already holds exhibit %q, and a release is to somebody else",
			op, to, exhibit))
	}
	if errObj := evidenceAssignedInForce(op, session, ledger.graph, to,
		"an exhibit is released to somebody working the case, who can then accept it; evidence_return "+
			"records one leaving the case"); errObj != nil {
		return resultAndError(nil, errObj)
	}
	event, errObj := evidenceAppend(op, session, ledger, item, evidenceKindRelease, reason,
		map[string]string{"custody.to": to},
		[]evidenceCustodian{{ledger.actor, "releasing"}, {to, "receiving"}})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	evidenceCommitted(session, op, fmt.Sprintf("exhibit %s released by %s to %s: %s", exhibit, ledger.actor, to,
		reason), item, event)
	return evidenceResult(session, item, event, map[string]object.Object{
		"to":     stringObj(to),
		"reason": stringObj(reason),
	})
}

// evidenceAppend writes one custody event after an exhibit's head and
// commits it.
func evidenceAppend(op string, session *custodySession, ledger *ledgerSession, item evidenceItem, kind,
	reason string, props map[string]string, custodians []evidenceCustodian) (caseChainEvent, *object.Error) {
	w, err := caseBeginWrite(ledger, session.caseUID, session.ID, custodyNow())
	if err != nil {
		return caseChainEvent{}, newError("%s: %s", op, err.Error())
	}
	head := item.head()
	event, err := w.custody(item.node.id, item.node.get("evidence.uid"), item.exhibit(), kind, &head, reason,
		props, custodians)
	if err == nil {
		err = w.tx.commit()
	}
	if err != nil {
		return caseChainEvent{}, newError("%s: %s", op, err.Error())
	}
	return event, nil
}

// ---------------------------------------------------------------------------
// evidence_accept
// ---------------------------------------------------------------------------

// EvidenceAccept records the person an exhibit was released to taking it,
// after hashing what they were handed: evidence_accept(ledger, exhibit, path,
// options?).
func EvidenceAccept(args ...object.Object) object.Object {
	op := BuiltinNameEvidenceAccept
	if len(args) < 3 || len(args) > 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 4, evidenceAcceptOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	exhibit, errObj := caseTextArg(op, args[1], 2, "exhibit")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	discrepancy, errObj := evidenceDiscrepancyOption(op, opts, 4)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	measured, errObj := evidenceMeasure(op, args[2], 3)
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
	item, errObj := evidenceExisting(op, session, ledger, exhibit)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	head := item.head()
	switch {
	case item.state() != evidenceInTransit:
		return resultAndError(nil, newError("%s: exhibit %q is %s (%s), and only a released exhibit is accepted",
			op, exhibit, item.state(), evidenceWhere(item)))
	case head.get("custody.to") != ledger.actor:
		return resultAndError(nil, newError("%s: exhibit %q was released to %s, and %s is accepting it. The "+
			"person an exhibit was released to records taking it, so the ledger never says one person was "+
			"handed what another took", op, exhibit, head.get("custody.to"), ledger.actor))
	}
	intake := item.node.get("evidence.digest")
	if errObj := evidenceUnexplained(op, "accept", measured, exhibit, intake, discrepancy); errObj != nil {
		return resultAndError(nil, errObj)
	}
	matches := measured.digest == intake
	props := evidenceComparison(measured, intake, discrepancy)
	reason := "accepted from " + item.holder()
	event, errObj := evidenceAppend(op, session, ledger, item, evidenceKindAccept, reason, props,
		[]evidenceCustodian{{ledger.actor, "holder"}})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	session.registerFileLocked(measured.source, evidenceDigestAlgo, measured.digest, evidenceEventAt(event),
		fmt.Sprintf("%s accepted exhibit %s at %s", op, exhibit, measured.source.path))
	detail := fmt.Sprintf("exhibit %s accepted by %s from %s; digest matches intake", exhibit, ledger.actor,
		item.holder())
	if !matches {
		detail = fmt.Sprintf("exhibit %s accepted by %s from %s with a digest that does not match intake: %s",
			exhibit, ledger.actor, item.holder(), discrepancy)
	}
	evidenceCommitted(session, op, detail, item, event)
	return evidenceResult(session, item, event, map[string]object.Object{
		"from":           stringObj(item.holder()),
		"path":           stringObj(measured.source.path),
		"hash_algo":      stringObj(evidenceDigestAlgo),
		"hash":           stringObj(measured.digest),
		"intake_hash":    stringObj(intake),
		"matches_intake": boolObj(matches),
		"discrepancy":    stringObj(discrepancy),
	})
}

// ---------------------------------------------------------------------------
// evidence_return and evidence_dispose
// ---------------------------------------------------------------------------

// EvidenceReturn records the holder of an exhibit returning it out of the
// case -- to its owner, or the agency that submitted it:
// evidence_return(ledger, exhibit, to, reason).
func EvidenceReturn(args ...object.Object) object.Object {
	op := BuiltinNameEvidenceReturn
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	exhibit, errObj := caseTextArg(op, args[1], 2, "exhibit")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	to, errObj := caseTextArg(op, args[2], 3, "recipient")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason, errObj := caseTextArg(op, args[3], 4, "reason")
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
	item, errObj := evidenceHeldBy(op, session, ledger, exhibit)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	event, errObj := evidenceAppend(op, session, ledger, item, evidenceKindReturn, reason,
		map[string]string{"custody.to": to},
		[]evidenceCustodian{{to, "returned_to"}})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	evidenceCommitted(session, op, fmt.Sprintf("exhibit %s returned by %s to %s: %s", exhibit, ledger.actor, to,
		reason), item, event)
	return evidenceResult(session, item, event, map[string]object.Object{
		"to":     stringObj(to),
		"reason": stringObj(reason),
	})
}

// EvidenceDispose records the holder of an exhibit disposing of it, in a
// statement: evidence_dispose(ledger, exhibit, statement). It deletes nothing.
func EvidenceDispose(args ...object.Object) object.Object {
	op := BuiltinNameEvidenceDispose
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	exhibit, errObj := caseTextArg(op, args[1], 2, "exhibit")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	statement, errObj := caseTextArg(op, args[2], 3, "statement")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := disposerRefusal(op, ledger, "a disposal"); errObj != nil {
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
	item, errObj := evidenceHeldBy(op, session, ledger, exhibit)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := retentionHoldRefusal(op, session, ledger.graph); errObj != nil {
		return resultAndError(nil, errObj)
	}
	event, errObj := evidenceAppend(op, session, ledger, item, evidenceKindDispose, statement, nil, nil)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	evidenceCommitted(session, op, fmt.Sprintf("exhibit %s disposed of by %s: %s", exhibit, ledger.actor,
		statement), item, event)
	return evidenceResult(session, item, event, map[string]object.Object{
		"statement": stringObj(statement),
		// A disposal is a statement about the exhibit; the file it was taken
		// in from is where it was.
		"deleted": boolObj(false),
	})
}

// ---------------------------------------------------------------------------
// evidence_history
// ---------------------------------------------------------------------------

// EvidenceHistory reads the custody of every exhibit in a ledger, or of one
// case or one exhibit: evidence_history(ledger, options?). It needs no case
// open, so an auditor reads it with nothing but the ledger.
func EvidenceHistory(args ...object.Object) object.Object {
	op := BuiltinNameEvidenceHistory
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 2, evidenceHistoryOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	exhibit, errObj := opts.str("exhibit", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	caseUID, errObj := opts.str("case_uid", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	disclosureLedgerMu.Lock()
	items, err := evidenceReadAll(ledger.graph, caseUID)
	disclosureLedgerMu.Unlock()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	counts := map[string]int64{}
	rows := make([]object.Object, 0, len(items))
	for _, item := range items {
		if exhibit != "" && item.exhibit() != exhibit {
			continue
		}
		counts[item.state()]++
		rows = append(rows, evidenceHistoryRow(item))
	}
	fields := map[string]object.Object{
		"exhibits": &object.Array{Elements: rows},
		"count":    intObj(int64(len(rows))),
		"source":   stringObj("ledger"),
	}
	for _, state := range evidenceStates {
		fields[state] = intObj(counts[state])
	}
	return resultAndError(makeHashObject(fields), nil)
}

func evidenceHistoryRow(item evidenceItem) object.Object {
	events := make([]object.Object, 0, len(item.events))
	discrepancies := int64(0)
	for _, event := range item.events {
		checked := event.get("custody.matches_intake") != ""
		matches := event.get("custody.matches_intake") == "true"
		if checked && !matches {
			discrepancies++
		}
		events = append(events, makeHashObject(map[string]object.Object{
			"seq":           intObj(int64(event.seq)),
			"uid":           stringObj(event.uid),
			"kind":          stringObj(event.get("custody.kind")),
			"from":          stringObj(event.get("custody.from")),
			"state":         stringObj(event.get("custody.state")),
			"holder":        stringObj(event.get("custody.holder")),
			"to":            stringObj(event.get("custody.to")),
			"received_from": stringObj(event.get("custody.received_from")),
			"reason":        stringObj(event.get("custody.reason")),
			"path":          stringObj(event.get("custody.path")),
			"hash":          stringObj(event.get("custody.digest")),
			"hash_checked":  boolObj(checked),
			// Checked and passed are two answers: an event that hashed
			// nothing has not matched anything, and has not failed to.
			"matches_intake": boolObj(matches),
			"discrepancy":    stringObj(event.get("custody.discrepancy")),
			"by":             stringObj(event.get("custody.by")),
			"by_role":        stringObj(event.get("custody.by_role")),
			"at":             stringObj(event.get("custody.at")),
		}))
	}
	head := item.head()
	n := item.node
	size, _ := strconv.ParseInt(n.get("evidence.size"), 10, 64)
	return makeHashObject(map[string]object.Object{
		"exhibit":       stringObj(n.get("evidence.exhibit")),
		"evidence_uid":  stringObj(n.get("evidence.uid")),
		"case_uid":      stringObj(n.get("evidence.case_uid")),
		"case_id":       stringObj(n.get("evidence.case_id")),
		"path":          stringObj(n.get("evidence.path")),
		"size":          intObj(size),
		"hash_algo":     stringObj(n.get("evidence.algo")),
		"hash":          stringObj(n.get("evidence.digest")),
		"description":   stringObj(n.get("evidence.description")),
		"received_from": stringObj(n.get("evidence.received_from")),
		"state":         stringObj(item.state()),
		"holder":        stringObj(item.holder()),
		"to":            stringObj(head.get("custody.to")),
		"where":         stringObj(evidenceWhere(item)),
		"events":        &object.Array{Elements: events},
		"event_count":   intObj(int64(len(events))),
		"discrepancies": intObj(discrepancies),
		"head_uid":      stringObj(head.uid),
	})
}
