package builtin

// Recipient roles: which views somebody outside the case may be granted, and
// who has been named as holding which role.
//
// # A bundle is a list of views, and a grant is still one view
//
// `role_define(role, views)` says which of the case's views a recipient role
// may be granted: legal the view counsel reads, an external partner the view a
// malware desk reads, a restricted viewer nothing yet. `role_assign(ledger,
// recipient, role, reason)` records that a named recipient holds one of those
// roles, in a chain of assignments like an examiner's. `disclose_to_passphrase`
// then refuses unless its recipient holds a role in force, that role has a
// bundle, and the bundle holds the view -- before any key material is derived
// or any passphrase asked for.
//
// The grant is exactly the view, as it always was, so `view_preview` still
// says what a disclosure under that view releases. A bundle neither widens nor
// narrows a view; it says which views a role may be given at all.
//
// # Deny by default, and said
//
// A recipient nobody assigned is granted nothing, and so is one whose role has
// no bundle. A bundle defined empty grants nothing and says so in
// `grants_nothing`: "nobody decided" and "somebody decided nothing" are
// different answers to the question a disclosure review asks.
//
// # Not access control
//
// A recipient's role is asserted, like an examiner's, and the examiner who
// wants to disclose to somebody can assign them a role to do it. What this buys
// is that the ledger then says so, in a signed commit beside the disclosure,
// and that a disclosure the case's own definitions do not allow is refused
// instead of recorded. The one thing that stops a recipient reading a segment
// they were not granted is still the passphrase on their grant.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// roleDefineOptions is role_define's option surface. A description is prose
// for the manifest and is never part of what the bundle holds.
var roleDefineOptions = []string{"description"}

// maxRoleBundleViews bounds one bundle's view list. A bundle cannot usefully
// hold more views than a case would ever declare, and a longer list is one
// with repeats in it, which are refused on their own account anyway.
//
//mutant:limit count
const maxRoleBundleViews = 256

// caseBundle is the set of views one recipient role may be granted.
type caseBundle struct {
	Role caseRole
	// Views are the views the role may be granted, in the order given.
	Views       []caseView
	Description string
	Index       int
	DefinedAt   time.Time
	// FromLedger and InLedger are what they are on caseView.
	FromLedger bool
	InLedger   bool
}

func (b *caseBundle) add(view caseView) { b.Views = append(b.Views, view) }

// labels are the bundle's views by label, in the order given.
func (b caseBundle) labels() []string {
	out := make([]string, 0, len(b.Views))
	for _, view := range b.Views {
		out = append(out, view.Label)
	}
	return out
}

// viewFPs are the bundle's views by fingerprint, in the order given.
func (b caseBundle) viewFPs() []string {
	out := make([]string, 0, len(b.Views))
	for _, view := range b.Views {
		out = append(out, disclosureViewFingerprint(view))
	}
	return out
}

// classes are the labels of every class some view in the bundle grants,
// sorted: what a recipient holding the role could ever be given.
func (b caseBundle) classes() []string {
	seen := map[string]bool{}
	var out []string
	for _, view := range b.Views {
		for _, label := range view.Classes {
			if !seen[label] {
				seen[label] = true
				out = append(out, label)
			}
		}
	}
	sort.Strings(out)
	return out
}

// fingerprint names a bundle by its role and by what its views grant, as a
// view is named by what it grants: two runs that give legal a view called
// counsel over different classes have bundled two different things.
func (b caseBundle) fingerprint() string {
	fps := b.viewFPs()
	sort.Strings(fps)
	return ledgerHash(sha256Of("mutant-role-bundle-v1|" + b.Role.Name + "|" + strings.Join(fps, ",")))
}

// holds reports whether the bundle holds the view: the same name, granting
// the same classes.
func (b caseBundle) holds(view caseView) bool {
	fp := disclosureViewFingerprint(view)
	for _, held := range b.Views {
		if held.Canonical == view.Canonical && disclosureViewFingerprint(held) == fp {
			return true
		}
	}
	return false
}

// viewsText lists the bundle's views for a refusal.
func (b caseBundle) viewsText() string {
	if len(b.Views) == 0 {
		return "no view"
	}
	quoted := make([]string, 0, len(b.Views))
	for _, label := range b.labels() {
		quoted = append(quoted, strconv.Quote(label))
	}
	return strings.Join(quoted, ", ")
}

// render is one row of the manifest's role bundle block.
func (b caseBundle) render() map[string]any {
	return map[string]any{
		"role":           b.Role.Name,
		"views":          stringsToAny(b.labels()),
		"view_count":     int64(len(b.Views)),
		"classes":        stringsToAny(b.classes()),
		"fingerprint":    b.fingerprint(),
		"grants_nothing": len(b.Views) == 0,
		"description":    b.Description,
		"index":          int64(b.Index),
		"defined_at":     b.DefinedAt.UTC().Format(time.RFC3339Nano),
		"source":         definitionSource(b.FromLedger),
		"in_ledger":      b.InLedger,
	}
}

// row is the bundle as role_define and role_list return it.
func (b caseBundle) row() map[string]object.Object {
	return map[string]object.Object{
		"role":        stringObj(b.Role.Name),
		"views":       stringListObj(b.labels()),
		"view_count":  intObj(int64(len(b.Views))),
		"classes":     stringArrayObj(b.classes()),
		"fingerprint": stringObj(b.fingerprint()),
		// Said out loud, as a view granting no class is: an empty list is
		// also what a typo produces.
		"grants_nothing": boolObj(len(b.Views) == 0),
		"description":    stringObj(b.Description),
		"index":          intObj(int64(b.Index)),
		"source":         stringObj(definitionSource(b.FromLedger)),
		"in_ledger":      boolObj(b.InLedger),
	}
}

// bundleForLocked returns the case's bundle for a role. The caller holds the
// custody lock.
func (s *custodySession) bundleForLocked(role caseRole) (caseBundle, bool) {
	for _, bundle := range s.bundles {
		if bundle.Role.ID == role.ID {
			return bundle, true
		}
	}
	return caseBundle{}, false
}

// recipientAssignRoles are the words role_assign's role takes.
func recipientAssignRoles() []string { return append(RecipientRoles(), caseAssignmentEnded) }

// recipientRoleArg reads a recipient role by name. With allowEnd, "none" is
// accepted and ends an assignment.
func recipientRoleArg(op, arg string, allowEnd bool) (caseRole, bool, *object.Error) {
	name := choiceFold(arg)
	if allowEnd && name == caseAssignmentEnded {
		return caseRole{}, true, nil
	}
	ending := ""
	if allowEnd {
		ending = fmt.Sprintf(", or %q to end their assignment", caseAssignmentEnded)
	}
	role, known := roleNamed(name)
	switch {
	case !known:
		return caseRole{}, false, newError("%s: %q is not a role. A recipient is named as one of %s%s", op, arg,
			strings.Join(RecipientRoles(), ", "), ending)
	case !role.recipientSide():
		return caseRole{}, false, newError("%s: %s is an examiner role: it names who works the case, and nobody "+
			"is granted a disclosure as one. A recipient is named as one of %s%s", op, role.Name,
			strings.Join(RecipientRoles(), ", "), ending)
	}
	return role, false, nil
}

// ---------------------------------------------------------------------------
// role_define
// ---------------------------------------------------------------------------

// RoleDefine declares which views a recipient role may be granted:
// role_define(role, views, options?).
func RoleDefine(args ...object.Object) object.Object {
	op := BuiltinNameRoleDefine
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 3, roleDefineOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	name, errObj := requireStringArg(op, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	role, _, errObj := recipientRoleArg(op, name, false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	list, errObj := requireArrayArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	description, errObj := opts.str("description", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := custodyDocumentName(op, "description", description); errObj != nil {
		return resultAndError(nil, errObj)
	}
	if len(list.Elements) > maxRoleBundleViews {
		return resultAndError(nil, newError("%s: a bundle holds at most %d views and this one names %d", op,
			maxRoleBundleViews, len(list.Elements)))
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()

	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if session.classTagKey == nil {
		return resultAndError(nil, newError("%s: no case key is open; call `case_key_open(path)` first, because "+
			"a bundle names views, and a view names classes tagged under the case key", op))
	}
	var readBack *caseBundle
	for i := range session.bundles {
		existing := &session.bundles[i]
		if existing.Role.ID != role.ID {
			continue
		}
		if !existing.FromLedger {
			return resultAndError(nil, newError("%s: role %s already has a bundle in this case, holding %s. A "+
				"role's bundle is defined once, so that what a %s may be granted has one answer and not the "+
				"last of several", op, role.Name, existing.viewsText(), role.Name))
		}
		// Compared once the view list is resolved, below.
		readBack = existing
	}

	bundle := caseBundle{Role: role, Description: description}
	seen := make(map[string]string, len(list.Elements))
	for i, element := range list.Elements {
		text, ok := element.(*object.String)
		if !ok {
			return resultAndError(nil, newError("%s: entry %d of the view list must be STRING, got %s. A bundle "+
				"names views by the label `view_define` declared them under", op, i+1, element.Type()))
		}
		canonical, errObj := canonicalLabel(op, "view name", text.Value)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		if first, repeated := seen[canonical]; repeated {
			return resultAndError(nil, newError("%s: entry %d names %q, which this bundle already holds as %q. "+
				"A repeated view is a list whose author lost track of it, and collapsing it quietly would hide "+
				"exactly that", op, i+1, text.Value, first))
		}
		view, found := viewByCanonicalLocked(session, canonical)
		if !found {
			return resultAndError(nil, bundleUndeclaredView(op, session, i+1, text.Value))
		}
		seen[canonical] = text.Value
		bundle.add(view)
	}

	// A bundle case_attach read back is the same decision made again by the
	// same script in a later run, and that is not a mistake -- as long as it
	// holds what the ledger says it holds.
	if readBack != nil {
		if bundle.fingerprint() != readBack.fingerprint() ||
			(description != "" && description != readBack.Description) {
			return resultAndError(nil, newError("%s: the case's ledger defines role %s's bundle as holding %s, "+
				"with the description %q, and a definition there is written once", op, role.Name,
				readBack.viewsText(), readBack.Description))
		}
		return resultAndError(bundleDefineResult(*readBack, true), nil)
	}
	if errObj := session.stateRefusalLocked(op, caseActDefine); errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := session.attachedLedgerLocked(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	bundle.Index = len(session.bundles)
	bundle.DefinedAt = custodyNow()
	// Written through to the ledger of an attached case before it is in the
	// run, as class_define and view_define do.
	if ledger != nil {
		if err := session.recordBundleLocked(ledger, bundle); err != nil {
			return resultAndError(nil, newError("%s: recording the bundle in the case's ledger: %s", op, err.Error()))
		}
		bundle.InLedger = true
	}
	session.bundles = append(session.bundles, bundle)
	session.appendEvent(bundle.DefinedAt, op, fmt.Sprintf("role %s may be granted %s", role.Name, bundle.viewsText()),
		map[string]any{
			"role":        role.Name,
			"views":       strings.Join(bundle.labels(), ", "),
			"view_count":  int64(len(bundle.Views)),
			"fingerprint": bundle.fingerprint(),
			"index":       int64(bundle.Index),
			"in_ledger":   bundle.InLedger,
		})
	return resultAndError(bundleDefineResult(bundle, false), nil)
}

// bundleDefineResult is role_define's answer, for a bundle defined now or one
// the case's ledger already defined.
func bundleDefineResult(bundle caseBundle, already bool) object.Object {
	fields := bundle.row()
	fields["already_defined"] = boolObj(already)
	fields["status"] = stringObj("ok")
	return makeHashObject(fields)
}

// viewByCanonicalLocked finds a declared view by its canonical name. The caller
// holds the custody lock.
func viewByCanonicalLocked(session *custodySession, canonical string) (caseView, bool) {
	for _, view := range session.views {
		if view.Canonical == canonical {
			return view, true
		}
	}
	return caseView{}, false
}

// bundleUndeclaredView is the refusal for a bundle naming a view nobody
// declared, at the position that named it.
func bundleUndeclaredView(op string, session *custodySession, position int, label string) *object.Error {
	declared := make([]string, 0, len(session.views))
	for _, view := range session.views {
		declared = append(declared, view.Label)
	}
	if len(declared) == 0 {
		return newError("%s: entry %d names %q, which is not a declared view -- this case has declared none. "+
			"Call `view_define(label, classes)` first, so that a typo is an error rather than a bundle that "+
			"holds nothing and says so nowhere", op, position, label)
	}
	return newError("%s: entry %d names %q, which is not a declared view. This case declares %s", op, position,
		label, strings.Join(declared, ", "))
}

// recordBundleLocked writes a role's bundle into the attached ledger: its
// RoleBundle node, the views it holds, and the IN_CASE edge that makes it one
// of the case's definitions. The caller holds the custody lock.
func (s *custodySession) recordBundleLocked(ledger *ledgerSession, bundle caseBundle) error {
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	if err := disclosureDeclareNames(ledger); err != nil {
		return err
	}
	w, err := caseBeginWrite(ledger, s.caseUID, s.ID, bundle.DefinedAt)
	if err != nil {
		return err
	}
	labels := map[string]string{}
	for _, class := range s.classes {
		labels[class.Tag] = class.Label
	}
	bundleN, err := w.tx.bundleNode(w.g, bundle, w.tx.classNodes(w.g, labels))
	if err != nil {
		return err
	}
	if err := w.tx.edge(bundleN, w.caseN, disclosureEdgeInCase, s.definitionProps("role", bundle.Role.Name,
		bundle.Role.Name, bundle.Description, bundle.Index, bundle.DefinedAt)); err != nil {
		return err
	}
	return w.tx.commit()
}

// bundleNode finds or adds a role bundle's node, and on adding it writes one
// BUNDLES edge to the node of each view the bundle holds.
func (d *disclosureTx) bundleNode(g *graphene.Graph, bundle caseBundle,
	classNode func(string) (store.NodeID, error)) (store.NodeID, error) {
	id, added, err := d.findOrAdd(g, disclosureNodeRoleBundle, "bundle.fp", map[string]string{
		"bundle.fp":          bundle.fingerprint(),
		"bundle.role":        bundle.Role.Name,
		"bundle.role_id":     strconv.FormatUint(uint64(bundle.Role.ID), 10),
		"bundle.views":       strings.Join(bundle.labels(), ", "),
		"bundle.view_fps":    strings.Join(bundle.viewFPs(), ","),
		"bundle.description": bundle.Description,
	})
	if err != nil || !added {
		return id, err
	}
	for _, view := range bundle.Views {
		viewN, err := d.viewNode(g, view, disclosureViewFingerprint(view), classNode)
		if err != nil {
			return 0, err
		}
		if err := d.edge(id, viewN, disclosureEdgeBundles, nil); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Recipients' assignments
// ---------------------------------------------------------------------------

// recipientAssignmentChainKey names the chain of one recipient's assignments in
// one case. The recipient is named by the fingerprint every disclosure to them
// carries, so an assignment and a disclosure name one person the same way.
func recipientAssignmentChainKey(caseUID, recipient string) string {
	return strings.ToLower(caseUID) + "|" + disclosureRecipientFingerprint(recipient)
}

// recipientAssignmentOf reads a recipient's latest assignment in a case.
func recipientAssignmentOf(g *graphene.Graph, caseUID, recipient string) (caseAssignment, bool, error) {
	caseUID = strings.ToLower(caseUID)
	return assignmentChainRead(g, recipientAssignmentChainKey(caseUID, recipient), caseUID, caseAssignmentRecipient)
}

// recipientAssignmentsRead reads the latest assignment of every recipient the
// ledger assigns in a case, or in every case when caseUID is empty.
func recipientAssignmentsRead(g *graphene.Graph, caseUID string) ([]caseAssignment, error) {
	return assignmentsRead(g, strings.ToLower(caseUID), caseAssignmentRecipient)
}

// assignRecipient appends a recipient's assignment to role --
// caseAssignmentEnded to end one -- after head. The recipient's node is the
// Recipient node their disclosures are DISCLOSED_TO.
func (w *caseWriter) assignRecipient(head *caseChainEvent, recipient, role, reason string) (caseChainEvent, error) {
	fp := disclosureRecipientFingerprint(recipient)
	recipientN, _, err := w.tx.findOrAdd(w.g, disclosureNodeRecipient, "recipient.fp", map[string]string{
		"recipient.fp":   fp,
		"recipient.name": recipient,
	})
	if err != nil {
		return caseChainEvent{}, err
	}
	return w.assignment(head, caseAssignmentRecipient, recipient, recipientN, role, reason,
		map[string]string{"assignment.subject_fp": fp})
}

// ---------------------------------------------------------------------------
// role_assign
// ---------------------------------------------------------------------------

// RoleAssign records a recipient's role in the open case, or ends it:
// role_assign(ledger, recipient, role, reason).
func RoleAssign(args ...object.Object) object.Object {
	op := BuiltinNameRoleAssign
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	recipient, errObj := caseTextArg(op, args[1], 2, "recipient")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	roleArg, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	role, end, errObj := recipientRoleArg(op, roleArg, true)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	roleName := caseAssignmentEnded
	if !end {
		roleName = role.Name
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
	if session.caseUID == "" {
		return resultAndError(nil, newError("%s: no case key is open; a recipient is assigned a role in a case, "+
			"and a case is found in its ledger by the identity its key file carries. Call `case_key_open(path)` "+
			"first", op))
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
	if err := caseLedgerStateRefusal(g, session.caseUID, caseActAssign); err != nil {
		return fail(err)
	}
	current, found, err := recipientAssignmentOf(g, session.caseUID, recipient)
	if err != nil {
		return fail(err)
	}
	previous := caseAssignmentEnded
	var head *caseChainEvent
	if found {
		previous, head = current.role, &current.head
	}
	switch {
	case end && previous == caseAssignmentEnded:
		return resultAndError(nil, newError("%s: %q holds no recipient role in case %s, so there is no "+
			"assignment to end", op, recipient, session.ID))
	case roleName == previous:
		return resultAndError(nil, newError("%s: %q is already assigned as %s in case %s", op, recipient,
			roleName, session.ID))
	}
	now := custodyNow()
	w, err := caseBeginWrite(ledger, session.caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	event, err := w.assignRecipient(head, recipient, roleName, reason)
	if err != nil {
		return fail(err)
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	session.appendEvent(now, op, fmt.Sprintf("recipient %q assigned as %s in case %s (was %s): %s", recipient,
		roleName, session.ID, previous, reason), map[string]any{
		"recipient": recipient, "role": roleName, "previous_role": previous, "seq": int64(event.seq), "uid": event.uid,
	})

	// Whether a disclosure to them could be issued now is two records, and
	// this says what the second one holds: an assignment to a role with no
	// bundle is legal and grants nothing.
	bundle, bundled := caseBundle{}, false
	if !end {
		bundle, bundled = session.bundleForLocked(role)
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":            stringObj(session.ID),
		"recipient":          stringObj(recipient),
		"role":               stringObj(roleName),
		"previous_role":      stringObj(previous),
		"in_force":           boolObj(!end),
		"bundled":            boolObj(bundled),
		"grants":             stringListObj(bundle.labels()),
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
// role_list
// ---------------------------------------------------------------------------

// RoleList reports the recipient roles' bundles and, given a ledger, who it
// assigns which recipient role: role_list(ledger?).
//
// Same shape whether or not a case is open, for the reason view_list gives.
// With a ledger and no keyed case open, it lists every case's recipients, so an
// auditor reads them with the ledger alone.
func RoleList(args ...object.Object) object.Object {
	op := BuiltinNameRoleList
	if len(args) > 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0 or 1", len(args)))
	}
	var ledger *ledgerSession
	if len(args) == 1 {
		var errObj *object.Error
		if ledger, errObj = ledgerHandleArg(args[0], op); errObj != nil {
			return resultAndError(nil, errObj)
		}
	}

	custodyStore.RLock()
	session := custodyStore.session
	open := session != nil && !session.Closed
	var bundles []caseBundle
	caseID, caseUID, tagged := "", "", false
	if open {
		bundles = append(bundles, session.bundles...)
		caseID, caseUID, tagged = session.ID, strings.ToLower(session.caseUID), session.classTagKey != nil
	}
	custodyStore.RUnlock()

	rows := make([]object.Object, 0, len(bundles))
	byRole := make(map[string]caseBundle, len(bundles))
	for _, bundle := range bundles {
		rows = append(rows, makeHashObject(bundle.row()))
		byRole[bundle.Role.Name] = bundle
	}
	out := map[string]object.Object{
		"bundles":         &object.Array{Elements: rows},
		"count":           intObj(int64(len(bundles))),
		"case_id":         stringObj(caseID),
		"open":            boolObj(open),
		"tagged":          boolObj(tagged),
		"recipients":      &object.Array{Elements: []object.Object{}},
		"recipient_count": intObj(0),
		"in_force":        intObj(0),
		"ledger":          stringObj(""),
	}
	if ledger == nil {
		return resultAndError(makeHashObject(out), nil)
	}
	assignments, err := recipientAssignmentsRead(ledger.graph, caseUID)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	recipients := make([]object.Object, 0, len(assignments))
	var inForce int64
	for _, a := range assignments {
		// byRole is empty unless a keyed case is open, and then every row is
		// that case's: a bundle is only ever the open case's.
		bundle, bundled := byRole[a.role]
		if a.role != caseAssignmentEnded {
			inForce++
		}
		recipients = append(recipients, makeHashObject(map[string]object.Object{
			"recipient": stringObj(a.subject),
			"role":      stringObj(a.role),
			"in_force":  boolObj(a.role != caseAssignmentEnded),
			"bundled":   boolObj(bundled),
			"grants":    stringListObj(bundle.labels()),
			"case_uid":  stringObj(a.head.get("assignment.case_uid")),
			"seq":       intObj(int64(a.head.seq)),
			"uid":       stringObj(a.head.uid),
			"by":        stringObj(a.head.get("assignment.by")),
			"by_role":   stringObj(a.head.get("assignment.by_role")),
			"reason":    stringObj(a.head.get("assignment.reason")),
			"at":        stringObj(a.head.get("assignment.at")),
		}))
	}
	out["recipients"] = &object.Array{Elements: recipients}
	out["recipient_count"] = intObj(int64(len(recipients)))
	out["in_force"] = intObj(inForce)
	out["ledger"] = stringObj(ledger.path)
	return resultAndError(makeHashObject(out), nil)
}

// ---------------------------------------------------------------------------
// What a disclosure is issued on
// ---------------------------------------------------------------------------

// disclosureBasis is what a disclosure is issued on besides its view: the
// recipient's assignment in force, the role it names, and that role's bundle.
type disclosureBasis struct {
	assignment caseAssignment
	role       caseRole
	bundle     caseBundle
}

// disclosureRecipientTerms reads what a disclosure's basis is checked against
// in this run: the case's bundles, once the ledger is known to be the one the
// case is attached to, if it is attached to any.
func disclosureRecipientTerms(op string, ledger *ledgerSession) ([]caseBundle, *object.Error) {
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return nil, errObj
	}
	if errObj := session.ledgerElsewhereLocked(op, ledger); errObj != nil {
		return nil, errObj
	}
	return append([]caseBundle(nil), session.bundles...), nil
}

// disclosureBasisFor checks a recipient's assignment against the case's
// bundles: it must name a recipient role, the role must have a bundle, and the
// bundle must hold the view.
func disclosureBasisFor(op, recipient string, assignment caseAssignment, view caseView,
	bundles []caseBundle) (disclosureBasis, *object.Error) {
	role, known := roleNamed(assignment.role)
	if !known || !role.recipientSide() {
		return disclosureBasis{}, newError("%s: the ledger assigns %q as %q, which is not a recipient role this "+
			"program knows", op, recipient, assignment.role)
	}
	for _, bundle := range bundles {
		if bundle.Role.ID != role.ID {
			continue
		}
		switch {
		case bundle.holds(view):
			return disclosureBasis{assignment: assignment, role: role, bundle: bundle}, nil
		case len(bundle.Views) == 0:
			return disclosureBasis{}, newError("%s: %q is assigned as %s, and this case defined the %s bundle to "+
				"hold no view: a %s is granted nothing. %s", op, recipient, role.Name, role.Name, role.Name,
				roleNotAccessControl)
		}
		return disclosureBasis{}, newError("%s: %q is assigned as %s, and the %s bundle holds %s, not %q. A grant "+
			"is exactly one view, and it is one the recipient's role may be granted. %s", op, recipient, role.Name,
			role.Name, bundle.viewsText(), view.Label, roleNotAccessControl)
	}
	return disclosureBasis{}, newError("%s: %q is assigned as %s, and this case has no bundle for %s. "+
		"role_define(%q, views) says which views a %s may be granted, and until it does the answer is none. %s",
		op, recipient, role.Name, role.Name, role.Name, role.Name, roleNotAccessControl)
}
