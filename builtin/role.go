package builtin

// Roles: which of nine fixed hats an examiner says they are wearing, recorded
// beside everything they do, and never checked against anything.
//
// # Recorded, never checked
//
// Mutant authenticates nobody. The examiner's name is a string somebody typed,
// and a role is another one. What a role buys is attribution: every redaction
// record carries it (graphene persists RedactionRequest.RoleID), every
// disclosure-family event node and PERFORMED_BY edge names it, every custody
// timeline entry is stamped with it, and the manifest says in a field that it
// was not authenticated. A reader can then ask "who did this, acting as what"
// and get the answer the examiner gave at the time rather than a guess made
// later.
//
// A script's own ledger_add_node or ledger_add_edge commit is the gap. Every
// commit is begun with the role in TxContext.RoleID, but graphene v0.9.0 keeps
// only the actor, time, sequence and key of a commit and drops the role, so
// those commits say who and not as what. The role is passed anyway: a graphene
// that records it will then record it with no change here.
//
// It does not buy enforcement, and nothing here pretends it does. The one thing
// that stops a recipient reading a withheld segment is still the passphrase on
// their grant. The three refusals that do exist -- an auditor never writes;
// review and erasure need particular roles, in the builtins that do those --
// keep the record consistent with the role it claims. Anybody can reopen the
// ledger under another role, and each refusal says so.
//
// # Two sides, and two roles on both
//
// Examiner roles are asserted by whoever runs the program: at case_open and
// ledger_open. Recipient roles name who a grant is issued to. reviewer and
// auditor are both, because both people exist: an internal reviewer signing
// off and an external expert receiving a disclosure; a compliance auditor
// verifying the ledger in this process and an outside auditor handed a
// package. The act decides the side, not the name.
//
// # The ids are a format
//
// A role id is written into signed commits that are never compacted away, so
// once a number has meant a role it means that role forever. The list is
// append-only, and TestRoleIDsAreAFormat pins every id.

import (
	"strings"

	"mutant/object"
)

// roleSide says whether a role can be asserted by an examiner, named for a
// recipient, or both.
type roleSide uint8

const (
	roleSideExaminer roleSide = 1 << iota
	roleSideRecipient
)

// The role ids graphene records. Zero is not among them: graphene reads a
// commit whose actor, role and key are all zero as unattributed, and every
// commit a ledger received before roles were recorded carries RoleID 0, so zero
// stays the one value that means "written before roles were recorded".
const (
	roleIDAdministrator    uint32 = 1
	roleIDCaseOwner        uint32 = 2
	roleIDLeadInvestigator uint32 = 3
	roleIDInvestigator     uint32 = 4
	roleIDReviewer         uint32 = 5
	roleIDAuditor          uint32 = 6
	roleIDLegal            uint32 = 7
	roleIDExternalPartner  uint32 = 8
	roleIDRestrictedViewer uint32 = 9

	// roleIDUnasserted is what a commit carries when its examiner named no
	// role. Distinct from zero, so a ledger can tell "nobody said" from
	// "written before anybody could".
	roleIDUnasserted uint32 = 0xFFFFFFFF
)

// roleNameUnasserted is the name reported for roleIDUnasserted. It cannot be
// asserted: leaving the option out is how an examiner says nothing.
const roleNameUnasserted = "unasserted"

// caseRole is one of the fixed roles.
type caseRole struct {
	Name string
	ID   uint32
	side roleSide
}

// caseRoles is every role, in id order. Append only; see the file header.
var caseRoles = []caseRole{
	{"administrator", roleIDAdministrator, roleSideExaminer},
	{"case_owner", roleIDCaseOwner, roleSideExaminer},
	{"lead_investigator", roleIDLeadInvestigator, roleSideExaminer},
	{"investigator", roleIDInvestigator, roleSideExaminer},
	{"reviewer", roleIDReviewer, roleSideExaminer | roleSideRecipient},
	{"auditor", roleIDAuditor, roleSideExaminer | roleSideRecipient},
	{"legal", roleIDLegal, roleSideRecipient},
	{"external_partner", roleIDExternalPartner, roleSideRecipient},
	{"restricted_viewer", roleIDRestrictedViewer, roleSideRecipient},
}

// roleUnasserted is the role of an examiner who named none.
var roleUnasserted = caseRole{Name: roleNameUnasserted, ID: roleIDUnasserted, side: roleSideExaminer}

func (r caseRole) asserted() bool { return r.ID != roleIDUnasserted }

func (r caseRole) examinerSide() bool { return r.side&roleSideExaminer != 0 }

func (r caseRole) recipientSide() bool { return r.side&roleSideRecipient != 0 }

// roleNamed finds a role by name. The name is matched after trimming and
// lower-casing, because "Case_Owner" is a typing accident and not a tenth role.
func roleNamed(name string) (caseRole, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, role := range caseRoles {
		if role.Name == name {
			return role, true
		}
	}
	return caseRole{}, false
}

// roleNameForID names the role a commit or redaction record carries. Zero is
// reported as "" -- nothing was recorded -- and an id this build does not know
// is reported as unknown rather than guessed at.
func roleNameForID(id uint32) string {
	switch id {
	case 0:
		return ""
	case roleIDUnasserted:
		return roleNameUnasserted
	}
	for _, role := range caseRoles {
		if role.ID == id {
			return role.Name
		}
	}
	return "unknown"
}

func roleNames(keep func(caseRole) bool) []string {
	var out []string
	for _, role := range caseRoles {
		if keep(role) {
			out = append(out, role.Name)
		}
	}
	return out
}

// ExaminerRoles are the roles an examiner can assert at case_open and
// ledger_open, in id order. The editor's role_literal rule reads this list.
func ExaminerRoles() []string { return roleNames(caseRole.examinerSide) }

// RecipientRoles are the roles a recipient can be named under, in id order.
func RecipientRoles() []string { return roleNames(caseRole.recipientSide) }

// roleNotAccessControl ends every refusal a role causes.
const roleNotAccessControl = "A role is asserted, not authenticated: this refusal keeps the record " +
	"consistent with the role it names, and is not access control"

// roleOption reads the `role` option of case_open and ledger_open. given is
// false when the option was left out, and the role is then roleUnasserted.
func roleOption(op string, opts *formatOptions) (role caseRole, given bool, errObj *object.Error) {
	if _, present := opts.pairs["role"]; !present {
		return roleUnasserted, false, nil
	}
	name, errObj := opts.str("role", "")
	if errObj != nil {
		return caseRole{}, false, errObj
	}
	role, known := roleNamed(name)
	switch {
	case strings.EqualFold(strings.TrimSpace(name), roleNameUnasserted):
		return caseRole{}, false, newError("%s: %q is what is recorded when no role is given; to assert "+
			"none, leave the role option out", op, roleNameUnasserted)
	case !known:
		return caseRole{}, false, newError("%s: %q is not a role. The roles are fixed; an examiner acts as "+
			"one of %s", op, name, strings.Join(ExaminerRoles(), ", "))
	case !role.examinerSide():
		return caseRole{}, false, newError("%s: %s is a recipient role: it names who a grant is issued to, "+
			"not who is running this program. An examiner acts as one of %s", op, role.Name,
			strings.Join(ExaminerRoles(), ", "))
	}
	return role, true, nil
}

// roleConflict reports an examiner asserting a second role in one process.
//
// A case and a ledger opened by the same examiner, or two ledgers, record one
// person's acts; if they named different roles, the manifest would say one
// thing and the ledger another about the same hands. Only asserted roles
// conflict: a case opened without a role does not stop a ledger naming one.
// The caller holds no lock; this takes the custody read lock itself.
func roleConflict(op, actor string, role caseRole, exclude *ledgerSession) *object.Error {
	if !role.asserted() {
		return nil
	}
	custodyStore.RLock()
	session := custodyStore.session
	held, holds := caseRole{}, false
	if session != nil && !session.Closed && session.Examiner == actor {
		held, holds = session.Role, true
	}
	custodyStore.RUnlock()
	if holds && held.asserted() && held.ID != role.ID {
		return newError("%s: %s opened the case as %s and cannot act as %s in the same process: one "+
			"examiner has one role at a time, or the manifest and the ledger disagree about the same "+
			"hands. Close one, or open under the same role", op, actor, held.Name, role.Name)
	}
	var clash *ledgerSession
	ledgerHandles.Range(func(_, value any) bool {
		other, ok := value.(*ledgerSession)
		if ok && other != exclude && other.actor == actor && other.role.asserted() && other.role.ID != role.ID {
			clash = other
			return false
		}
		return true
	})
	if clash != nil {
		return newError("%s: %s has ledger %s open as %s and cannot act as %s in the same process: one "+
			"examiner has one role at a time. Close it, or open under the same role", op, actor, clash.path,
			clash.role.Name, role.Name)
	}
	return nil
}
