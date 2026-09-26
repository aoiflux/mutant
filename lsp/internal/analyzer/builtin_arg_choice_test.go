package analyzer

import (
	"strings"
	"testing"
)

// argChoiceMessages returns the messages of every builtinArgChoice diagnostic
// in src, which are the only lint messages that say "refuses any other word".
func argChoiceMessages(t *testing.T, src string, config LintConfig) []string {
	t.Helper()
	snapshot := New().Analyze(src)
	out := []string{}
	for _, d := range Diagnostics(snapshot, config) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "refuses any other word") {
			out = append(out, d.Message)
		}
	}
	return out
}

func TestBuiltinArgChoiceFiresOnAWordTheBuiltinRefuses(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{`db_bfs(1, 2, 3, "outbound");`, "argument 4 to `db_bfs` is one of out, in, both, not \"outbound\""},
		{`db_relations(1, 2, "sideways");`, "argument 3 to `db_relations` is one of out, in, both, not \"sideways\""},
		{`ledger_path(1, 2, 3, "cheapest");`, "argument 4 to `ledger_path` is one of hops, similarity, weight, not \"cheapest\""},
	}
	for _, tc := range cases {
		msgs := argChoiceMessages(t, tc.src+"\n", DefaultLintConfig())
		if len(msgs) != 1 || !strings.HasPrefix(msgs[0], tc.want) {
			t.Errorf("%s: got %q, want one message starting %q", tc.src, msgs, tc.want)
		}
	}
}

// The builtin folds case and surrounding space before it compares, so the rule
// does too; and it never guesses at a value it cannot read off the syntax.
func TestBuiltinArgChoiceIsSilentWhereTheBuiltinAccepts(t *testing.T) {
	sources := []string{
		`db_bfs(1, 2, 3, "out");`,
		`db_bfs(1, 2, 3, " BOTH ");`,
		`db_relations(1, 2, "In");`,
		`ledger_path(1, 2, 3, "Similarity");`,
		"let d = \"sideways\";\ndb_bfs(1, 2, 3, d);",
		`db_bfs(1, 2, 3, str_lower("OUT"));`,
		// A parameter with no declared words takes any string.
		`db_add_relation(1, 2, 3, "anything at all");`,
		// A shadowed name is not the builtin.
		"let db_bfs = fn(a, b, c, d) { d };\ndb_bfs(1, 2, 3, \"sideways\");",
	}
	for _, src := range sources {
		if msgs := argChoiceMessages(t, src+"\n", DefaultLintConfig()); len(msgs) != 0 {
			t.Errorf("%s: got %q, want no builtinArgChoice diagnostic", src, msgs)
		}
	}
}

func TestBuiltinArgChoiceCanBeSwitchedOffAlone(t *testing.T) {
	config := DefaultLintConfig()
	config.BuiltinArgChoice = LintSeverityOff
	src := "db_bfs(1, 2, 3, \"outbound\");\nstr_upper(42);\n"
	if msgs := argChoiceMessages(t, src, config); len(msgs) != 0 {
		t.Fatalf("builtinArgChoice=off still reported %q", msgs)
	}
	if msgs := argTypeMessagesWithConfig(t, src, config); len(msgs) != 1 {
		t.Fatalf("switching off builtinArgChoice also changed builtinArgType: %q", msgs)
	}
}
