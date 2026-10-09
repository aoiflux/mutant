package analyzer

import (
	"strings"
	"testing"
)

func TestRoleLiteralFires(t *testing.T) {
	roles := "administrator, case_owner, lead_investigator, investigator, reviewer, auditor."
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a recipient's role asserted by an examiner",
			`case_open("IR-1", "examiner", {"role": "legal"});`,
			"`case_open` refuses this role: legal is a recipient role: it names who a grant is issued to, not who " +
				"is running this program. An examiner acts as one of " + roles,
		},
		{
			"a word that is not a role",
			`let opened, err = ledger_open("ledger", "examiner", {"role": "detective"});`,
			"`ledger_open` refuses this role: \"detective\" is not a role. The roles are fixed; an examiner acts " +
				"as one of " + roles,
		},
		{
			"the word recorded when no role is given",
			`case_open("IR-1", "examiner", {"hash": "sha256", "role": "unasserted"});`,
			"`case_open` refuses this role: \"unasserted\" is what is recorded when no role is given; to assert " +
				"none, leave the role option out.",
		},
		{
			// The run time folds case and surrounding space before it looks.
			"a recipient's role, spelt loosely",
			`case_open("IR-1", "examiner", {"role": " Restricted_Viewer "});`,
			"`case_open` refuses this role: restricted_viewer is a recipient role",
		},
		{
			"options bound once",
			`let options = {"role": "external_partner"};
let opened, err = ledger_open("ledger", "examiner", options);`,
			"`ledger_open` refuses this role: external_partner is a recipient role",
		},
		{
			"a role bound once",
			`let role = "legal";
case_open("IR-1", "examiner", {"role": role});`,
			"`case_open` refuses this role: legal is a recipient role",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caseRuleMessages(t, "roleLiteral", tc.src+"\n", DefaultLintConfig())
			if len(got) != 1 || !strings.HasPrefix(got[0], tc.want) {
				t.Fatalf("got %q, want one message starting %q", got, tc.want)
			}
		})
	}
}

func TestRoleLiteralIsSilentWhereTheRunTimeAccepts(t *testing.T) {
	sources := []string{
		`case_open("IR-1", "examiner", {"role": "administrator"});`,
		`case_open("IR-1", "examiner", {"role": "case_owner"});`,
		`case_open("IR-1", "examiner", {"role": "lead_investigator"});`,
		`case_open("IR-1", "examiner", {"role": "investigator"});`,
		// Both-sided: an examiner may assert them.
		`case_open("IR-1", "examiner", {"role": "reviewer"});`,
		`ledger_open("ledger", "examiner", {"role": "auditor"});`,
		`ledger_open("ledger", "examiner", {"role": " Case_Owner "});`,
		`case_open("IR-1", "examiner");`,
		// Not a builtin that reads a role from its options.
		`record_open("exhibit.mrec", {"role": "legal"});`,
		// A value this cannot read off the syntax.
		`case_open("IR-1", "examiner", {"role": str_lower("LEGAL")});`,
		"let role = \"legal\";\nrole = \"investigator\";\ncase_open(\"IR-1\", \"examiner\", {\"role\": role});",
		// A shadowed name is not the builtin.
		"let case_open = fn(id, who, opts) { opts };\ncase_open(\"IR-1\", \"examiner\", {\"role\": \"legal\"});",
		// A call the signature does not fit is the arity rule's.
		`case_open("IR-1", "examiner", {"role": "legal"}, 4);`,
	}
	for _, src := range sources {
		if got := caseRuleMessages(t, "roleLiteral", src+"\n", DefaultLintConfig()); len(got) != 0 {
			t.Errorf("%s: got %q, want no roleLiteral report", src, got)
		}
	}
}

// Two `role` keys in one literal are refused by the parser (M26-LEX-004), and
// the editor lints what is on screen whether or not it parses clean, so the
// rule still has to decide what to say about one. It says nothing: the literal
// names no single role, and the mistake already has a diagnostic of its own.
// This used to be a statement about order instead -- the pairs were a map, so a
// rule that read whichever pair came first reported on some runs and not
// others, which is why the source is analysed many times below.
func TestRoleLiteralIsSilentOnTwoRoleKeys(t *testing.T) {
	src := `case_open("IR-1", "examiner", {"role": "legal", "role": "investigator"});` + "\n"
	for range 32 {
		if got := caseRuleMessages(t, "roleLiteral", src, DefaultLintConfig()); len(got) != 0 {
			t.Fatalf("got %q, want no roleLiteral report", got)
		}
	}
}

// A role passed as an argument is a parameter that declares its words, and
// builtinArgChoice reports it; roleLiteral does not report it a second time.
func TestAPositionalRoleIsBuiltinArgChoices(t *testing.T) {
	for _, src := range []string{
		`case_assign(1, "bob", "legal", "joins the case");`,
		`role_define("investigator", ["counsel"]);`,
		`role_assign(1, "counsel", "case_owner", "instructed");`,
	} {
		if got := caseRuleMessages(t, "roleLiteral", src+"\n", DefaultLintConfig()); len(got) != 0 {
			t.Errorf("%s: roleLiteral reported %q", src, got)
		}
		if got := argChoiceMessages(t, src+"\n", DefaultLintConfig()); len(got) != 1 {
			t.Errorf("%s: builtinArgChoice reported %q, want one report", src, got)
		}
	}
}
