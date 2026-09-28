package analyzer

import (
	"strings"
	"testing"
)

func TestLifecycleStateFires(t *testing.T) {
	refused := "never moves a case to %s, so the call is refused whatever state the case is in: "
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"review is asked for, not moved to",
			`case_transition(ledger, "in_review", "ready for review");`,
			"`case_transition` " + strings.Replace(refused, "%s", "in_review", 1) +
				"review_request moves a case from active to in_review.",
		},
		{
			"a case is concluded by its review",
			`case_transition(ledger, "concluded", "done");`,
			"`case_transition` " + strings.Replace(refused, "%s", "concluded", 1) +
				"review_decide moves a case from in_review to concluded.",
		},
		{
			"a case is retained by setting its retention",
			`case_transition(ledger, "retained", "keep it");`,
			"`case_transition` " + strings.Replace(refused, "%s", "retained", 1) +
				"retention_set moves a case from concluded to retained.",
		},
		{
			"nothing moves a case back to where it started",
			`case_transition(ledger, "registered", "start again");`,
			"`case_transition` " + strings.Replace(refused, "%s", "registered", 1) +
				"a case starts out registered, and no move leads back to it.",
		},
		{
			// case_transition folds case and surrounding space, so the rule does.
			"a state spelt loosely",
			`case_transition(ledger, " In_Review ", "ready for review");`,
			"`case_transition` never moves a case to in_review,",
		},
		{
			"a state bound once",
			`let to = "concluded";
let moved, err = case_transition(ledger, to, "done");`,
			"`case_transition` never moves a case to concluded,",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caseRuleMessages(t, "lifecycleState", tc.src+"\n", DefaultLintConfig())
			if len(got) != 1 || !strings.HasPrefix(got[0], tc.want) {
				t.Fatalf("got %q, want one message starting %q", got, tc.want)
			}
		})
	}
}

func TestLifecycleStateIsSilentWhereCaseTransitionMoves(t *testing.T) {
	sources := []string{
		`case_transition(ledger, "active", "work starts");`,
		`case_transition(ledger, " Active ", "reopened");`,
		`case_transition(ledger, "disposed", "the period has run");`,
		// Another builtin handed a state's name.
		`let s = text_replace(line, "in_review", "reviewed");`,
		// A value this cannot read off the syntax.
		`case_transition(ledger, next_state(), "moving on");`,
		"let to = \"in_review\";\nto = \"active\";\ncase_transition(ledger, to, \"moving on\");",
		// A shadowed name is not the builtin.
		"let case_transition = fn(l, to, why) { to };\ncase_transition(ledger, \"in_review\", \"x\");",
		// A call the signature does not fit is the arity rule's.
		`case_transition(ledger, "in_review");`,
	}
	for _, src := range sources {
		if got := caseRuleMessages(t, "lifecycleState", src+"\n", DefaultLintConfig()); len(got) != 0 {
			t.Errorf("%s: got %q, want no lifecycleState report", src, got)
		}
	}
}

// A word that is not a state is builtinArgChoice's, which names the states;
// lifecycleState does not report it a second time.
func TestAWordThatIsNotAStateIsBuiltinArgChoices(t *testing.T) {
	src := `case_transition(ledger, "closed", "done");` + "\n"
	if got := caseRuleMessages(t, "lifecycleState", src, DefaultLintConfig()); len(got) != 0 {
		t.Errorf("lifecycleState reported %q", got)
	}
	if got := argChoiceMessages(t, src, DefaultLintConfig()); len(got) != 1 {
		t.Errorf("builtinArgChoice reported %q, want one report", got)
	}
}
