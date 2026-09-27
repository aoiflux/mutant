package builtin

// The case in the ledger: where a case's state, who holds which role in it,
// and the classes and views it declared outlive the process that declared
// them.
//
// A case session is a process-global in-memory structure, and until now it
// ended with the run: the next run of the same case started with no state, no
// roles and no classes, and redeclared them. `case_attach(ledger)` binds the
// open case to a ledger. The first attach registers the case there -- a Case
// node, a `registered` lifecycle event, and the examiner's assignment -- and
// every later one reads the case back: its lifecycle state, the assignments in
// force, and the classes and views declared under the open key.
//
// # What is read back, and what never is
//
// State, assignments and definitions are read back. Keys and grants never
// are: the case key stays in its key file, and a grant is still bundled by the
// run that issued it. A definition is read back only when it was declared
// under the key generation that is open now, and each class is tagged again
// under that key and compared with the tag the ledger holds, so a ledger that
// says a label carries a tag the key does not give it is refused rather than
// believed.
//
// # The lifecycle
//
//	registered -> active -> in_review -> concluded <-> active
//	                                   concluded -> retained -> disposed
//
// case_transition makes the moves that are an examiner's decision alone:
// registered to active, and reopening a concluded case. The review and
// retention moves are made by the builtins that record the review and the
// retention, and a disposal by the one that checks what disposal requires.
// A refusal names the state the case is in and the moves available from it.
//
// Each state takes what it can, and refuses what it cannot, in both the
// builtins that take the ledger -- which ask the ledger -- and the ones that
// do not, which ask the case attached in this run:
//
//	in_review            no sealing, no definitions or reclassifications, no disclosures,
//	                     no new evidence
//	concluded, retained  no sealing, no new evidence
//	disposed             nothing but a withdrawal and the movement of evidence
//
// A withdrawal is taken in every state: it stops further grants, which is
// never the wrong thing to be able to do. So is the release, accept, return,
// disposal or re-intake of an exhibit already taken in (case_evidence.go):
// where a drive is, is a fact, and a record that could not say it moved would
// be wrong.
//
// # Roles, again
//
// The assignments are records. case_attach refuses an examiner the ledger
// assigns no role in the case, or assigns a different role than the one this
// run asserts, because the two records would then disagree about the same
// person; it is not access control, and the refusal says so. Anybody attached
// can assign anybody: who may assign is a policy of the organisation, and this
// program does not hold one.
//
// # Lock order
//
// The custody lock, then disclosureLedgerMu. Every function here that takes
// both takes them in that order, and nothing that holds disclosureLedgerMu
// takes the custody lock.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// The lifecycle states.
const (
	caseStateRegistered = "registered"
	caseStateActive     = "active"
	caseStateInReview   = "in_review"
	caseStateConcluded  = "concluded"
	caseStateRetained   = "retained"
	caseStateDisposed   = "disposed"
)

// caseStates is every state, in the order a case passes through them.
var caseStates = []string{caseStateRegistered, caseStateActive, caseStateInReview, caseStateConcluded,
	caseStateRetained, caseStateDisposed}

// caseMove is one move of the lifecycle and the builtin that makes it.
type caseMove struct {
	from, to, by string
}

// caseMoves are the moves case_transition makes. The review, retention and
// disposal moves are added with the builtins that make them.
var caseMoves = []caseMove{
	{caseStateRegistered, caseStateActive, BuiltinNameCaseTransition},
	{caseStateConcluded, caseStateActive, BuiltinNameCaseTransition},
}

// caseAction is a kind of write a lifecycle state can refuse.
type caseAction int

const (
	caseActSeal caseAction = iota
	caseActDefine
	caseActDisclose
	caseActAssign
	caseActIntake
)

var caseActionNames = map[caseAction]string{
	caseActSeal:     "sealing of a record",
	caseActDefine:   "definition of a class or a view, or record of a reclassification",
	caseActDisclose: "disclosure",
	caseActAssign:   "assignment of a role",
	caseActIntake:   "intake of evidence",
}

// caseStateRefuses is what each state refuses. A state not listed refuses
// nothing, and no state refuses a withdrawal.
var caseStateRefuses = map[string][]caseAction{
	caseStateInReview:  {caseActSeal, caseActDefine, caseActDisclose, caseActIntake},
	caseStateConcluded: {caseActSeal, caseActIntake},
	caseStateRetained:  {caseActSeal, caseActIntake},
	caseStateDisposed:  {caseActSeal, caseActDefine, caseActDisclose, caseActAssign, caseActIntake},
}

var caseStateWhy = map[string]string{
	caseStateInReview: "what is under review is what was submitted for it, and a change made during the " +
		"review is one the reviewer never saw",
	caseStateConcluded: "its findings are concluded; case_transition(ledger, \"active\", reason) reopens it",
	caseStateRetained:  "it is held for retention, and a retained case is not added to",
	caseStateDisposed:  "a disposed case is final",
}

// caseAssignmentEnded is the role an assignment names when it ends one.
const caseAssignmentEnded = "none"

// caseAssignRoles are the words case_assign's role takes.
func caseAssignRoles() []string { return append(ExaminerRoles(), caseAssignmentEnded) }

// maxCaseReason bounds a reason or a name written into a case record. It is
// written into a signed commit that is never compacted away, so it is a
// sentence and not a document.
//
//mutant:limit bytes
const maxCaseReason = 4096

var (
	caseLifecycleChain  = caseChainSpec{label: disclosureNodeLifecycle, prefix: "lifecycle"}
	caseAssignmentChain = caseChainSpec{label: disclosureNodeAssignment, prefix: "assignment"}
)

// caseAssignment is one examiner's assignment in force -- or ended, when
// role is caseAssignmentEnded -- as the head of their chain.
type caseAssignment struct {
	subject string
	role    string
	head    caseChainEvent
}

// caseAttachment is the ledger a case is attached to in this run, and what
// was read from it.
type caseAttachment struct {
	ledger     *ledgerSession
	path       string
	state      string
	head       caseChainEvent
	first      bool
	attachedAt time.Time
	// assignments is every examiner's latest assignment, in force or ended,
	// ordered by name.
	assignments []caseAssignment
}

// ---------------------------------------------------------------------------
// Reading the case back
// ---------------------------------------------------------------------------

// caseLifecycleRead reads a case's lifecycle and the state it leaves the case
// in: "" when the ledger holds no lifecycle for the case. Every event must
// move the case from the state the one before it left, and the first must
// register it.
func caseLifecycleRead(g *graphene.Graph, caseUID string) ([]caseChainEvent, string, error) {
	events, err := caseChainRead(g, caseLifecycleChain, strings.ToLower(caseUID))
	if err != nil {
		return nil, "", err
	}
	state := ""
	for _, event := range events {
		from, to := event.get("lifecycle.from"), event.get("lifecycle.state")
		switch {
		case from != state:
			return nil, "", fmt.Errorf("lifecycle event %d of case %s moves the case from %q, and the event "+
				"before it left the case %q", event.seq, caseUID, from, state)
		case !slices.Contains(caseStates, to):
			return nil, "", fmt.Errorf("lifecycle event %d of case %s names a state this program does not "+
				"know (%q)", event.seq, caseUID, to)
		case event.seq == 1 && to != caseStateRegistered:
			return nil, "", fmt.Errorf("the first lifecycle event of case %s is %q, and a case's first "+
				"event registers it", caseUID, to)
		}
		state = to
	}
	return events, state, nil
}

// caseAssignmentChainKey names the chain of one examiner's assignments in one
// case.
func caseAssignmentChainKey(caseUID, subject string) string {
	return strings.ToLower(caseUID) + "|" + ledgerHash(sha256Of("mutant-examiner-v1|"+subject))
}

// caseAssignmentsRead reads the latest assignment of every examiner the ledger
// assigns in a case, ordered by name.
func caseAssignmentsRead(g *graphene.Graph, caseUID string) ([]caseAssignment, error) {
	caseUID = strings.ToLower(caseUID)
	ids, err := g.NodesByProperty("assignment.case_uid", []byte(caseUID))
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	nodes, _, err := g.GetNodes(ids)
	if err != nil {
		return nil, err
	}
	chains := map[string]bool{}
	for _, node := range nodes {
		if !node.HasLabel(disclosureNodeAssignment) {
			continue
		}
		decoded, err := disclosureDecode(node)
		if err != nil {
			return nil, fmt.Errorf("assignment node %d: %w", node.ID, err)
		}
		chains[decoded.get("assignment.chain")] = true
	}
	out := make([]caseAssignment, 0, len(chains))
	for chain := range chains {
		events, err := caseChainRead(g, caseAssignmentChain, chain)
		if err != nil {
			return nil, err
		}
		head := caseChainHead(events)
		if head == nil {
			continue
		}
		subject := head.get("assignment.subject")
		if caseAssignmentChainKey(caseUID, subject) != chain {
			return nil, fmt.Errorf("assignment node %d names %q in a chain that is not theirs", head.id, subject)
		}
		out = append(out, caseAssignment{subject: subject, role: head.get("assignment.role"), head: *head})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].subject < out[j].subject })
	return out, nil
}

// caseAssignmentOf returns an examiner's latest assignment.
func caseAssignmentOf(assignments []caseAssignment, subject string) (caseAssignment, bool) {
	for _, a := range assignments {
		if a.subject == subject {
			return a, true
		}
	}
	return caseAssignment{}, false
}

// caseDefinitions is what a later attach reads back of a case's classes and
// views.
type caseDefinitions struct {
	classes []caseClass
	views   []caseView
	// otherKeys counts definitions made under a key generation that is not
	// the open one, which are not read back: their tags are not this key's.
	otherKeys int
}

// caseDefinitionsRead reads the classes and views declared in a case under
// the key generation fingerprint names, from the IN_CASE edges class_define
// and view_define write while a case is attached. Each class is tagged again
// under tagKey and compared with the tag the ledger holds; each view's
// fingerprint is recomputed from what it grants.
func caseDefinitionsRead(ledger *ledgerSession, caseNode store.NodeID, fingerprint string,
	tagKey []byte) (caseDefinitions, error) {
	edges, err := ledger.store.EdgesOf(caseNode, store.DirectionInbound, []store.EdgeType{disclosureEdgeInCase})
	if err != nil {
		return caseDefinitions{}, err
	}
	type definition struct {
		props map[string]string
		node  disclosureNode
	}
	var classDefs, viewDefs []definition
	var out caseDefinitions
	for _, edge := range edges {
		raw, err := ledgerDecodeProperties(edge.Properties)
		if err != nil || len(raw) == 0 {
			continue // not a definition: a Record or a Disclosure in the case
		}
		props := make(map[string]string, len(raw))
		for key, value := range raw {
			props[key] = string(value)
		}
		kind := props["def.kind"]
		if kind == "" {
			continue
		}
		if props["def.key_fingerprint"] != fingerprint {
			out.otherKeys++
			continue
		}
		node, err := ledger.graph.GetNode(edge.Src)
		if err != nil {
			return caseDefinitions{}, fmt.Errorf("definition edge %d: %w", edge.ID, err)
		}
		decoded, err := disclosureDecode(node)
		if err != nil {
			return caseDefinitions{}, fmt.Errorf("definition node %d: %w", node.ID, err)
		}
		switch {
		case kind == "class" && node.HasLabel(disclosureNodeClass):
			classDefs = append(classDefs, definition{props, decoded})
		case kind == "view" && node.HasLabel(disclosureNodeView):
			viewDefs = append(viewDefs, definition{props, decoded})
		default:
			return caseDefinitions{}, fmt.Errorf("definition edge %d says it defines a %s and starts at a node "+
				"that is not one", edge.ID, kind)
		}
	}

	index := func(d definition, kind string, want int) (time.Time, error) {
		if got := d.props["def.index"]; got != strconv.Itoa(want) {
			return time.Time{}, fmt.Errorf("the ledger's %s definitions are not numbered 0 to %d in order: "+
				"%q is at index %s", kind, want, d.props["def.label"], got)
		}
		at, err := time.Parse(time.RFC3339Nano, d.props["def.at"])
		if err != nil {
			return time.Time{}, fmt.Errorf("%s %q has no time it was defined at", kind, d.props["def.label"])
		}
		return at, nil
	}
	byIndex := func(defs []definition) {
		sort.Slice(defs, func(i, j int) bool {
			a, _ := strconv.Atoi(defs[i].props["def.index"])
			b, _ := strconv.Atoi(defs[j].props["def.index"])
			return a < b
		})
	}

	byTag := map[string]caseClass{}
	byIndex(classDefs)
	for i, d := range classDefs {
		at, err := index(d, "class", i)
		if err != nil {
			return caseDefinitions{}, err
		}
		label, canonical := d.props["def.label"], d.props["def.canonical"]
		if again, errObj := canonicalClassLabel(BuiltinNameCaseAttach, label); errObj != nil || again != canonical {
			return caseDefinitions{}, fmt.Errorf("the ledger defines class %q with the canonical form %q, which "+
				"is not what the label canonicalises to", label, canonical)
		}
		tag, err := security.TagForClass(tagKey, canonical)
		if err != nil {
			return caseDefinitions{}, err
		}
		stored, tagged := strings.ToLower(d.node.get("class.tag")), hex.EncodeToString(tag[:])
		if tagged != stored {
			return caseDefinitions{}, fmt.Errorf("the ledger says class %q carries tag %s, and the open case key "+
				"tags it %s. A class's tag is the key's to give, so the ledger's record of this class is not "+
				"the one this key made", label, stored, tagged)
		}
		if _, repeated := byTag[stored]; repeated {
			return caseDefinitions{}, fmt.Errorf("the ledger defines class %q twice", label)
		}
		class := caseClass{Label: label, Canonical: canonical, Description: d.props["def.description"],
			Tag: stored, Index: i, DefinedAt: at, FromLedger: true, InLedger: true}
		byTag[stored] = class
		out.classes = append(out.classes, class)
	}

	seenViews := map[string]bool{}
	byIndex(viewDefs)
	for i, d := range viewDefs {
		at, err := index(d, "view", i)
		if err != nil {
			return caseDefinitions{}, err
		}
		label, canonical := d.props["def.label"], d.props["def.canonical"]
		if canonical != d.node.get("view.canonical") || seenViews[canonical] {
			return caseDefinitions{}, fmt.Errorf("the ledger's definition of view %q does not match the view "+
				"it points at, or defines it twice", label)
		}
		seenViews[canonical] = true
		view := caseView{Label: label, Canonical: canonical, Description: d.props["def.description"], Index: i,
			DefinedAt: at, FromLedger: true, InLedger: true}
		if tags := d.node.get("view.tags"); tags != "" {
			for _, tag := range strings.Split(tags, ",") {
				class, found := byTag[strings.ToLower(tag)]
				if !found {
					return caseDefinitions{}, fmt.Errorf("the ledger says view %q grants a class (tag %s) that "+
						"this case did not define under the open key", label, tag)
				}
				view.Classes = append(view.Classes, class.Label)
				view.Tags = append(view.Tags, class.Tag)
			}
		}
		if disclosureViewFingerprint(view) != d.node.get("view.fp") {
			return caseDefinitions{}, fmt.Errorf("view %q's fingerprint in the ledger is not the one what it "+
				"grants gives", label)
		}
		out.views = append(out.views, view)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// What a state refuses
// ---------------------------------------------------------------------------

func caseStateBlocks(state string, action caseAction) bool {
	return slices.Contains(caseStateRefuses[state], action)
}

func caseStateRefusalText(caseID, state string, action caseAction) string {
	return fmt.Sprintf("case %s is %s, and a case that is %s takes no %s: %s", caseID, state, state,
		caseActionNames[action], caseStateWhy[state])
}

// caseLedgerStateRefusal is the lifecycle check of a builtin that takes the
// ledger: it asks the ledger, whether or not a case is attached in this run.
// The caller holds disclosureLedgerMu.
func caseLedgerStateRefusal(g *graphene.Graph, caseUID string, action caseAction) error {
	events, state, err := caseLifecycleRead(g, caseUID)
	if err != nil || state == "" || !caseStateBlocks(state, action) {
		return err
	}
	return errors.New(caseStateRefusalText(events[0].get("lifecycle.case_id"), state, action))
}

// stateRefusalLocked is the lifecycle check of a builtin that does not take
// the ledger: it asks the case attached in this run, and a case attached to
// no ledger has no state to refuse anything in. The caller holds the custody
// lock.
func (s *custodySession) stateRefusalLocked(op string, action caseAction) *object.Error {
	if s.attached == nil || !caseStateBlocks(s.attached.state, action) {
		return nil
	}
	return newError("%s: %s", op, caseStateRefusalText(s.ID, s.attached.state, action))
}

// caseAttachedStateRefusal is stateRefusalLocked for a caller that does not
// hold the custody lock.
func caseAttachedStateRefusal(op string, action caseAction) *object.Error {
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	session := custodyStore.session
	if session == nil || session.Closed {
		return nil
	}
	return session.stateRefusalLocked(op, action)
}

// attachedLedgerLocked returns the ledger the case is attached to, or nil when
// it is attached to none, and refuses when that ledger has been closed: a
// definition made then would be in the manifest and not in the ledger. The
// caller holds the custody lock.
func (s *custodySession) attachedLedgerLocked(op string) (*ledgerSession, *object.Error) {
	if s.attached == nil {
		return nil, nil
	}
	if open, ok := ledgerGet(s.attached.ledger.handle); !ok || open != s.attached.ledger {
		return nil, newError("%s: case %s is attached to ledger %s, which has been closed, and a definition "+
			"made now would be in the manifest and not in the ledger. Open it again and case_attach it", op,
			s.ID, s.attached.path)
	}
	return s.attached.ledger, nil
}

// attachedToLocked refuses unless the case is attached to this ledger.
func (s *custodySession) attachedToLocked(op string, ledger *ledgerSession) *object.Error {
	if s.attached == nil {
		return newError("%s: case %s is attached to no ledger; call `case_attach(ledger)` first, because a "+
			"case's lifecycle and assignments are kept in its ledger", op, s.ID)
	}
	if s.attached.ledger != ledger {
		return newError("%s: case %s is attached to ledger %s, not this one", op, s.ID, s.attached.path)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Writing the case
// ---------------------------------------------------------------------------

// roleNode finds or adds a role's node.
func (d *disclosureTx) roleNode(g *graphene.Graph, role caseRole) (store.NodeID, error) {
	id, _, err := d.findOrAdd(g, disclosureNodeRole, "role.name", map[string]string{
		"role.name": role.Name,
		"role.id":   strconv.FormatUint(uint64(role.ID), 10),
	}, "role.id")
	return id, err
}

// caseNode finds or adds the Case node.
func (d *disclosureTx) caseNode(g *graphene.Graph, caseUID, caseID string) (store.NodeID, error) {
	id, _, err := d.findOrAdd(g, disclosureNodeCase, "case.uid", map[string]string{
		"case.uid": strings.ToLower(caseUID),
		"case.id":  caseID,
	})
	return id, err
}

// caseWriter is what every case record is written with: the transaction, the
// case, and who is writing.
type caseWriter struct {
	tx      *disclosureTx
	g       *graphene.Graph
	ledger  *ledgerSession
	caseUID string
	caseID  string
	caseN   store.NodeID
	actorN  store.NodeID
	at      time.Time
}

func caseBeginWrite(ledger *ledgerSession, caseUID, caseID string, at time.Time) (*caseWriter, error) {
	w := &caseWriter{tx: disclosureBegin(ledger), g: ledger.graph, ledger: ledger,
		caseUID: strings.ToLower(caseUID), caseID: caseID, at: at}
	var err error
	if w.caseN, err = w.tx.caseNode(w.g, caseUID, caseID); err != nil {
		return nil, err
	}
	if w.actorN, err = w.tx.actorNode(w.g, ledger.actor); err != nil {
		return nil, err
	}
	return w, nil
}

// lifecycle appends a lifecycle event after head.
func (w *caseWriter) lifecycle(head *caseChainEvent, from, to, reason string) (caseChainEvent, error) {
	id, event, err := w.tx.chainAppend(caseLifecycleChain, w.caseUID, head, map[string]string{
		"lifecycle.case_id":   w.caseID,
		"lifecycle.from":      from,
		"lifecycle.state":     to,
		"lifecycle.reason":    reason,
		"lifecycle.by":        w.ledger.actor,
		"lifecycle.by_role":   w.ledger.role.Name,
		"lifecycle.at":        w.at.UTC().Format(time.RFC3339Nano),
		"lifecycle.unix_nano": strconv.FormatInt(w.at.UnixNano(), 10),
	})
	if err != nil {
		return caseChainEvent{}, err
	}
	if err := w.tx.edge(id, w.caseN, disclosureEdgeTransitions, nil); err != nil {
		return caseChainEvent{}, err
	}
	return event, w.tx.edge(id, w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(w.ledger))
}

// assign appends an assignment of subject to role -- caseAssignmentEnded to
// end one -- after head.
func (w *caseWriter) assign(head *caseChainEvent, subject, role, reason string) (caseChainEvent, error) {
	roleID := uint64(0)
	if named, ok := roleNamed(role); ok {
		roleID = uint64(named.ID)
	}
	id, event, err := w.tx.chainAppend(caseAssignmentChain, caseAssignmentChainKey(w.caseUID, subject), head,
		map[string]string{
			"assignment.case_uid":  w.caseUID,
			"assignment.subject":   subject,
			"assignment.role":      role,
			"assignment.role_id":   strconv.FormatUint(roleID, 10),
			"assignment.reason":    reason,
			"assignment.by":        w.ledger.actor,
			"assignment.by_role":   w.ledger.role.Name,
			"assignment.at":        w.at.UTC().Format(time.RFC3339Nano),
			"assignment.unix_nano": strconv.FormatInt(w.at.UnixNano(), 10),
		})
	if err != nil {
		return caseChainEvent{}, err
	}
	subjectN, err := w.tx.actorNode(w.g, subject)
	if err != nil {
		return caseChainEvent{}, err
	}
	edges := []struct {
		dst   store.NodeID
		label store.EdgeType
		props map[string]string
	}{
		{w.caseN, disclosureEdgeInCase, nil},
		{subjectN, disclosureEdgeAssignedTo, nil},
		{w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(w.ledger)},
	}
	if named, ok := roleNamed(role); ok {
		roleN, err := w.tx.roleNode(w.g, named)
		if err != nil {
			return caseChainEvent{}, err
		}
		edges = append(edges, struct {
			dst   store.NodeID
			label store.EdgeType
			props map[string]string
		}{roleN, disclosureEdgeHoldsRole, nil})
	}
	for _, e := range edges {
		if err := w.tx.edge(id, e.dst, e.label, e.props); err != nil {
			return caseChainEvent{}, err
		}
	}
	return event, nil
}

// definitionProps is what the IN_CASE edge of a definition carries.
func (s *custodySession) definitionProps(kind, label, canonical, description string, index int,
	at time.Time) map[string]string {
	ledger := s.attached.ledger
	return map[string]string{
		"def.kind":            kind,
		"def.label":           label,
		"def.canonical":       canonical,
		"def.description":     description,
		"def.index":           strconv.Itoa(index),
		"def.at":              at.UTC().Format(time.RFC3339Nano),
		"def.key_fingerprint": s.keyFingerprint,
		"def.key_generation":  strconv.FormatUint(uint64(s.keyGeneration), 10),
		"def.by":              ledger.actor,
		"def.by_role":         ledger.role.Name,
	}
}

// recordClassLocked writes a class definition into the attached ledger. The
// caller holds the custody lock.
func (s *custodySession) recordClassLocked(ledger *ledgerSession, class caseClass) error {
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	if err := disclosureDeclareNames(ledger); err != nil {
		return err
	}
	w, err := caseBeginWrite(ledger, s.caseUID, s.ID, class.DefinedAt)
	if err != nil {
		return err
	}
	classN, _, err := w.tx.findOrAdd(w.g, disclosureNodeClass, "class.tag", map[string]string{
		"class.tag":   class.Tag,
		"class.label": class.Label,
	})
	if err != nil {
		return err
	}
	if err := w.tx.edge(classN, w.caseN, disclosureEdgeInCase, s.definitionProps("class", class.Label,
		class.Canonical, class.Description, class.Index, class.DefinedAt)); err != nil {
		return err
	}
	return w.tx.commit()
}

// recordViewLocked writes a view definition into the attached ledger. The
// caller holds the custody lock.
func (s *custodySession) recordViewLocked(ledger *ledgerSession, view caseView) error {
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	if err := disclosureDeclareNames(ledger); err != nil {
		return err
	}
	w, err := caseBeginWrite(ledger, s.caseUID, s.ID, view.DefinedAt)
	if err != nil {
		return err
	}
	labels := map[string]string{}
	for _, class := range s.classes {
		labels[class.Tag] = class.Label
	}
	viewN, err := w.tx.viewNode(w.g, view, disclosureViewFingerprint(view), w.tx.classNodes(w.g, labels))
	if err != nil {
		return err
	}
	if err := w.tx.edge(viewN, w.caseN, disclosureEdgeInCase, s.definitionProps("view", view.Label,
		view.Canonical, view.Description, view.Index, view.DefinedAt)); err != nil {
		return err
	}
	return w.tx.commit()
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

// caseTextArg reads a reason or a name: trimmed, non-empty, bounded and valid
// UTF-8, because each is written into a signed commit and into the manifest.
func caseTextArg(op string, arg object.Object, position int, what string) (string, *object.Error) {
	value, errObj := requireStringArg(op, arg, position)
	if errObj != nil {
		return "", errObj
	}
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return "", newError("%s: the %s must not be empty, and whitespace is not one", op, what)
	case len(value) > maxCaseReason:
		return "", newError("%s: the %s is at most %d bytes, and this one is %d", op, what, maxCaseReason, len(value))
	case !utf8.ValidString(value):
		return "", custodyDocumentName(op, what, value)
	}
	return value, nil
}

// caseMovesFrom lists the states case_transition moves a case to from state.
func caseMovesFrom(state string) []string {
	var out []string
	for _, move := range caseMoves {
		if move.from == state {
			out = append(out, move.to)
		}
	}
	return out
}

func caseMovesText(state string) string {
	moves := caseMovesFrom(state)
	if len(moves) == 0 {
		return fmt.Sprintf("case_transition moves a case that is %s nowhere", state)
	}
	return fmt.Sprintf("from %s, case_transition moves a case to %s", state, strings.Join(moves, " or "))
}

// ---------------------------------------------------------------------------
// case_attach
// ---------------------------------------------------------------------------

// CaseAttach binds the open case to a ledger: case_attach(ledger).
func CaseAttach(args ...object.Object) object.Object {
	op := BuiltinNameCaseAttach
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if session.caseUID == "" {
		return resultAndError(nil, newError("%s: no case key is open; a case is found in its ledger by the "+
			"identity its key file carries. Call `case_key_open(path)` first", op))
	}
	reattach := false
	if a := session.attached; a != nil {
		if open, ok := ledgerGet(a.ledger.handle); ok && open == a.ledger {
			return resultAndError(nil, newError("%s: case %s is already attached to ledger %s; a case is "+
				"attached to one ledger", op, session.ID, a.path))
		}
		if ledger.path != a.path {
			return resultAndError(nil, newError("%s: case %s was attached to ledger %s in this run, and what it "+
				"defined while attached is there. Attach it to that ledger again", op, session.ID, a.path))
		}
		reattach = true
	}
	if ledger.actor != session.Examiner {
		return resultAndError(nil, newError("%s: case %s is %s's and this ledger was opened by %s. A case "+
			"is attached from a ledger its examiner opened, so that what the attach records is one person's",
			op, session.ID, session.Examiner, ledger.actor))
	}
	if !ledger.role.asserted() {
		return resultAndError(nil, newError("%s: %s asserted no role, and a case's ledger records who holds "+
			"which role in it. Assert one at case_open or ledger_open", op, ledger.actor))
	}
	if !reattach && (len(session.classes) > 0 || len(session.views) > 0) {
		return resultAndError(nil, newError("%s: this run has defined %d classes and %d views that are not in "+
			"the ledger. Attach before defining, so that every definition the case holds is one the ledger "+
			"holds", op, len(session.classes), len(session.views)))
	}

	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	g := ledger.graph
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := disclosureDeclareNames(ledger); err != nil {
		return fail(err)
	}
	caseUID := strings.ToLower(session.caseUID)
	events, state, err := caseLifecycleRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	assignments, err := caseAssignmentsRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	now := custodyNow()
	first := len(events) == 0
	var defs caseDefinitions
	if first {
		if len(assignments) > 0 {
			return fail(fmt.Errorf("the ledger assigns roles in case %s and records no lifecycle for it, which "+
				"this program never writes", session.ID))
		}
		w, err := caseBeginWrite(ledger, caseUID, session.ID, now)
		if err != nil {
			return fail(err)
		}
		registered, err := w.lifecycle(nil, "", caseStateRegistered, "registered by "+op)
		if err != nil {
			return fail(err)
		}
		owner, err := w.assign(nil, ledger.actor, ledger.role.Name, "assigned when the case was registered")
		if err != nil {
			return fail(err)
		}
		if err := w.tx.commit(); err != nil {
			return fail(err)
		}
		events, state = []caseChainEvent{registered}, caseStateRegistered
		assignments = []caseAssignment{{subject: ledger.actor, role: ledger.role.Name, head: owner}}
	} else {
		mine, found := caseAssignmentOf(assignments, ledger.actor)
		switch {
		case !found || mine.role == caseAssignmentEnded:
			return resultAndError(nil, newError("%s: the ledger assigns %s no role in case %s. Somebody "+
				"assigned in the case assigns them one with case_assign first. %s", op, ledger.actor,
				session.ID, roleNotAccessControl))
		case mine.role != ledger.role.Name:
			return resultAndError(nil, newError("%s: the ledger assigns %s as %s in case %s, and this run "+
				"asserts %s; the two records would disagree about the same person. Assert %s, or have "+
				"the assignment changed with case_assign. %s", op, ledger.actor, mine.role, session.ID,
				ledger.role.Name, mine.role, roleNotAccessControl))
		}
		if !reattach {
			caseNode, found, err := disclosureFind(g, disclosureNodeCase, "case.uid", caseUID)
			if err != nil {
				return fail(err)
			}
			if found {
				if defs, err = caseDefinitionsRead(ledger, caseNode.id, session.keyFingerprint,
					session.classTagKey); err != nil {
					return fail(err)
				}
			}
		}
	}

	session.attached = &caseAttachment{ledger: ledger, path: ledger.path, state: state,
		head: *caseChainHead(events), first: first, attachedAt: now, assignments: assignments}
	if !reattach {
		session.classes, session.views = defs.classes, defs.views
	}
	detail := fmt.Sprintf("case %s attached to ledger %s: %s", session.ID, ledger.path, state)
	if first {
		detail = fmt.Sprintf("case %s registered in ledger %s, %s assigned as %s", session.ID, ledger.path,
			ledger.actor, ledger.role.Name)
	}
	session.appendEvent(now, op, detail, map[string]any{
		"ledger":        ledger.path,
		"state":         state,
		"lifecycle_seq": int64(len(events)),
		"first_attach":  first,
		"classes_read":  int64(len(defs.classes)),
		"views_read":    int64(len(defs.views)),
	})

	lifecycle := make([]object.Object, 0, len(events))
	for _, event := range events {
		lifecycle = append(lifecycle, caseLifecycleRow(event))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":                stringObj(session.ID),
		"case_uid":               stringObj(caseUID),
		"ledger":                 stringObj(ledger.path),
		"state":                  stringObj(state),
		"moves":                  stringArrayObj(caseMovesFrom(state)),
		"first_attach":           boolObj(first),
		"lifecycle":              &object.Array{Elements: lifecycle},
		"assignments":            caseAssignmentRows(assignments),
		"classes_read":           intObj(int64(len(defs.classes))),
		"views_read":             intObj(int64(len(defs.views))),
		"definitions_other_keys": intObj(int64(defs.otherKeys)),
		"role":                   stringObj(ledger.role.Name),
		"role_authenticated":     boolObj(false),
		"source":                 stringObj("ledger"),
	}), nil)
}

func caseLifecycleRow(event caseChainEvent) object.Object {
	return makeHashObject(map[string]object.Object{
		"seq":     intObj(int64(event.seq)),
		"uid":     stringObj(event.uid),
		"from":    stringObj(event.get("lifecycle.from")),
		"state":   stringObj(event.get("lifecycle.state")),
		"reason":  stringObj(event.get("lifecycle.reason")),
		"by":      stringObj(event.get("lifecycle.by")),
		"by_role": stringObj(event.get("lifecycle.by_role")),
		"at":      stringObj(event.get("lifecycle.at")),
	})
}

func caseAssignmentRows(assignments []caseAssignment) *object.Array {
	rows := make([]object.Object, 0, len(assignments))
	for _, a := range assignments {
		rows = append(rows, makeHashObject(map[string]object.Object{
			"examiner": stringObj(a.subject),
			"role":     stringObj(a.role),
			"in_force": boolObj(a.role != caseAssignmentEnded),
			"seq":      intObj(int64(a.head.seq)),
			"uid":      stringObj(a.head.uid),
			"by":       stringObj(a.head.get("assignment.by")),
			"reason":   stringObj(a.head.get("assignment.reason")),
			"at":       stringObj(a.head.get("assignment.at")),
		}))
	}
	return &object.Array{Elements: rows}
}

// ---------------------------------------------------------------------------
// case_transition
// ---------------------------------------------------------------------------

// CaseTransition moves the attached case along its lifecycle:
// case_transition(ledger, to, reason).
func CaseTransition(args ...object.Object) object.Object {
	op := BuiltinNameCaseTransition
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	toArg, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	to := choiceFold(toArg)
	if !slices.Contains(caseStates, to) {
		return resultAndError(nil, newError("%s: %q is not a lifecycle state; a case is one of %s", op, toArg,
			strings.Join(caseStates, ", ")))
	}
	reason, errObj := caseTextArg(op, args[2], 3, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := session.attachedToLocked(op, ledger); errObj != nil {
		return resultAndError(nil, errObj)
	}

	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	events, from, err := caseLifecycleRead(ledger.graph, session.caseUID)
	if err != nil {
		return fail(err)
	}
	if from == to {
		return resultAndError(nil, newError("%s: case %s is already %s", op, session.ID, to))
	}
	if !slices.Contains(caseMovesFrom(from), to) {
		return resultAndError(nil, newError("%s: case %s is %s and case_transition does not move it to %s: %s",
			op, session.ID, from, to, caseMovesText(from)))
	}
	now := custodyNow()
	w, err := caseBeginWrite(ledger, session.caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	event, err := w.lifecycle(caseChainHead(events), from, to, reason)
	if err != nil {
		return fail(err)
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	session.attached.state, session.attached.head = to, event
	session.appendEvent(now, op, fmt.Sprintf("case %s moved from %s to %s: %s", session.ID, from, to, reason),
		map[string]any{"from": from, "to": to, "seq": int64(event.seq), "uid": event.uid})

	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":            stringObj(session.ID),
		"from":               stringObj(from),
		"state":              stringObj(to),
		"moves":              stringArrayObj(caseMovesFrom(to)),
		"seq":                intObj(int64(event.seq)),
		"uid":                stringObj(event.uid),
		"reason":             stringObj(reason),
		"at":                 stringObj(now.UTC().Format(time.RFC3339Nano)),
		"role":               stringObj(ledger.role.Name),
		"role_authenticated": boolObj(false),
	}), nil)
}

// ---------------------------------------------------------------------------
// case_assign
// ---------------------------------------------------------------------------

// CaseAssign records an examiner's role in the attached case, or ends it:
// case_assign(ledger, examiner, role, reason).
func CaseAssign(args ...object.Object) object.Object {
	op := BuiltinNameCaseAssign
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	subject, errObj := caseTextArg(op, args[1], 2, "examiner")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	roleArg, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	roleName := choiceFold(roleArg)
	if roleName != caseAssignmentEnded {
		role, known := roleNamed(roleName)
		switch {
		case !known:
			return resultAndError(nil, newError("%s: %q is not a role. An examiner is assigned one of %s, or "+
				"%q to end their assignment", op, roleArg, strings.Join(ExaminerRoles(), ", "),
				caseAssignmentEnded))
		case !role.examinerSide():
			return resultAndError(nil, newError("%s: %s is a recipient role: it names who a grant is issued "+
				"to, and nobody works a case as one. An examiner is assigned one of %s", op, role.Name,
				strings.Join(ExaminerRoles(), ", ")))
		}
	}
	reason, errObj := caseTextArg(op, args[3], 4, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := session.attachedToLocked(op, ledger); errObj != nil {
		return resultAndError(nil, errObj)
	}

	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := caseLedgerStateRefusal(ledger.graph, session.caseUID, caseActAssign); err != nil {
		return fail(err)
	}
	assignments, err := caseAssignmentsRead(ledger.graph, session.caseUID)
	if err != nil {
		return fail(err)
	}
	current, found := caseAssignmentOf(assignments, subject)
	previous := caseAssignmentEnded
	var head *caseChainEvent
	if found {
		previous, head = current.role, &current.head
	}
	switch {
	case roleName == caseAssignmentEnded && previous == caseAssignmentEnded:
		return resultAndError(nil, newError("%s: %s holds no role in case %s, so there is no assignment to end",
			op, subject, session.ID))
	case roleName == previous:
		return resultAndError(nil, newError("%s: %s is already assigned as %s in case %s", op, subject,
			roleName, session.ID))
	}
	now := custodyNow()
	w, err := caseBeginWrite(ledger, session.caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	event, err := w.assign(head, subject, roleName, reason)
	if err != nil {
		return fail(err)
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	updated := caseAssignment{subject: subject, role: roleName, head: event}
	replaced := false
	for i := range session.attached.assignments {
		if session.attached.assignments[i].subject == subject {
			session.attached.assignments[i], replaced = updated, true
		}
	}
	if !replaced {
		session.attached.assignments = append(session.attached.assignments, updated)
		sort.Slice(session.attached.assignments, func(i, j int) bool {
			return session.attached.assignments[i].subject < session.attached.assignments[j].subject
		})
	}
	session.appendEvent(now, op, fmt.Sprintf("%s assigned as %s in case %s (was %s): %s", subject, roleName,
		session.ID, previous, reason), map[string]any{
		"examiner": subject, "role": roleName, "previous_role": previous, "seq": int64(event.seq), "uid": event.uid,
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":            stringObj(session.ID),
		"examiner":           stringObj(subject),
		"role":               stringObj(roleName),
		"previous_role":      stringObj(previous),
		"in_force":           boolObj(roleName != caseAssignmentEnded),
		"seq":                intObj(int64(event.seq)),
		"uid":                stringObj(event.uid),
		"reason":             stringObj(reason),
		"at":                 stringObj(now.UTC().Format(time.RFC3339Nano)),
		"by":                 stringObj(ledger.actor),
		"by_role":            stringObj(ledger.role.Name),
		"role_authenticated": boolObj(false),
	}), nil)
}

// ---------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------

// ledgerStateRecord is the manifest's account of the case's ledger state:
// where it came from, and what it said when this run last read or wrote it.
func (s *custodySession) ledgerStateRecord() map[string]any {
	a := s.attached
	if a == nil {
		return map[string]any{"attached": false}
	}
	assignments := make([]any, 0, len(a.assignments))
	for _, assignment := range a.assignments {
		assignments = append(assignments, map[string]any{
			"examiner": assignment.subject,
			"role":     assignment.role,
			"in_force": assignment.role != caseAssignmentEnded,
			"seq":      int64(assignment.head.seq),
			"uid":      assignment.head.uid,
		})
	}
	fromLedger := func(n int, from func(int) bool) int64 {
		count := int64(0)
		for i := 0; i < n; i++ {
			if from(i) {
				count++
			}
		}
		return count
	}
	return map[string]any{
		"attached":       true,
		"source":         "ledger",
		"ledger":         a.path,
		"state":          a.state,
		"lifecycle_seq":  int64(a.head.seq),
		"lifecycle_head": a.head.uid,
		"first_attach":   a.first,
		"attached_at":    a.attachedAt.UTC().Format(time.RFC3339Nano),
		"assignments":    assignments,
		"classes_read":   fromLedger(len(s.classes), func(i int) bool { return s.classes[i].FromLedger }),
		"views_read":     fromLedger(len(s.views), func(i int) bool { return s.views[i].FromLedger }),
	}
}
