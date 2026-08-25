package analyzer

import (
	"strings"
	"testing"
)

// singleReturnMessages returns the messages of every builtinSingleReturn
// diagnostic in src. That rule's messages are the only lint messages that read
// "not a (value, err) pair".
func singleReturnMessages(t *testing.T, src string) []string {
	t.Helper()
	return singleReturnMessagesWithConfig(t, src, DefaultLintConfig())
}

func singleReturnMessagesWithConfig(t *testing.T, src string, config LintConfig) []string {
	t.Helper()
	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, config) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "not a (value, err) pair") {
			out = append(out, d.Message)
		}
	}
	return out
}

// The mistake this catches shipped in 36 places across the examples before it
// was found, because nothing about it fails: the program runs and quietly uses
// the wrong value.
func TestBuiltinSingleReturnFiresOnPairBinding(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"array return is taken apart",
			`let items = ["a", "b"];
let updated, err = push(items, "c");`,
			"takes that array apart, so updated receives its first element",
		},
		{
			"non-array return leaves the second name null",
			`let hit, err = text_contains("abc", "b");`,
			"the second name is always null",
		},
		{
			"three names",
			`let a, b, c = text_split("a,b", ",");`,
			"takes that array apart",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := singleReturnMessages(t, tc.src)
			if len(got) != 1 {
				t.Fatalf("expected exactly one diagnostic, got %d: %v", len(got), got)
			}
			if !strings.Contains(got[0], tc.want) {
				t.Fatalf("message does not explain the problem.\ngot:  %s\nwant substring: %s", got[0], tc.want)
			}
		})
	}
}

// Everything below is a case the rule must stay silent on. A lint that cries
// wolf on the correct idiom is worse than no lint at all, because the correct
// idiom is what almost every line of real code uses.
func TestBuiltinSingleReturnStaysSilent(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"a genuinely fallible builtin", `let data, err = fs_read("f.txt");`},
		{"a pair-returning regex builtin", `let ok, err = regex_match("^a", "abc");`},
		{"one name from a single-return builtin", `let items = push([], 1);`},
		{"one name from a pair-returning builtin", `let data = fs_read("f.txt");`},
		{"a user function, not a builtin", `let pair = fn() { return 1, 2; };
let a, b = pair();`},
		{"an unknown name", `let a, b = not_a_builtin(1);`},
		{"the builtin name is shadowed by a local", `let f = fn() {
    let push = fn(a, b) { return 1, 2; };
    let x, err = push([], 1);
    return x;
};`},
		{"the builtin name is shadowed at the top level", `let push = fn(a, b) { return 1, 2; };
let x, err = push([], 1);`},
		{"destructuring an array literal, not a call", `let a, b = [1, 2];`},
		{"a call that is not an identifier callee", `let fns = [fn() { return 1; }];
let a, b = fns[0]();`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := singleReturnMessages(t, tc.src); len(got) != 0 {
				t.Fatalf("rule fired on correct code: %v", got)
			}
		})
	}
}

func TestBuiltinSingleReturnRespectsSeverityOff(t *testing.T) {
	src := `let updated, err = push([], 1);`

	config := DefaultLintConfig()
	if got := singleReturnMessagesWithConfig(t, src, config); len(got) != 1 {
		t.Fatalf("expected the rule on by default, got %d diagnostics", len(got))
	}

	config.BuiltinSingleReturn = LintSeverityOff
	if got := singleReturnMessagesWithConfig(t, src, config); len(got) != 0 {
		t.Fatalf("rule still fired with severity off: %v", got)
	}
}

// Turning this rule off must not disturb the two rules it shares a walk with.
func TestBuiltinSingleReturnOffLeavesTheOtherRulesAlone(t *testing.T) {
	config := DefaultLintConfig()
	config.BuiltinSingleReturn = LintSeverityOff

	arity := make([]string, 0, 1)
	for _, d := range Diagnostics(New().Analyze(`let x = abs(1, 2);`), config) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "takes") {
			arity = append(arity, d.Message)
		}
	}
	if len(arity) == 0 {
		t.Fatal("switching off builtinSingleReturn also silenced builtinArity")
	}
	if got := argTypeMessagesWithConfig(t, `let x = str_upper(42);`, config); len(got) == 0 {
		t.Fatal("switching off builtinSingleReturn also silenced builtinArgType")
	}
}
