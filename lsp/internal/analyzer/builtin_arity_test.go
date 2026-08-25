package analyzer

import (
	"strings"
	"testing"
)

// arityMessages returns the messages of every builtinArity diagnostic in src.
func arityMessages(t *testing.T, src string) []string {
	t.Helper()
	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "takes") {
			out = append(out, d.Message)
		}
	}
	return out
}

func hasArity(msgs []string, name string) bool {
	for _, m := range msgs {
		if strings.Contains(m, "builtin `"+name+"`") {
			return true
		}
	}
	return false
}

func TestBuiltinArityFiresOnWrongCount(t *testing.T) {
	cases := []struct {
		name string
		src  string
		call string // builtin name expected in the message
		want string // a substring the message must contain
	}{
		{"too many fixed", "abs(1, 2);\n", "abs", "takes 1 argument, got 2"},
		{"too few fixed", "sqrt();\n", "sqrt", "takes 1 argument, got 0"},
		{"three-arg short", "clamp(1);\n", "clamp", "takes 3 arguments, got 1"},
		{"two-arg short", "push([1]);\n", "push", "takes 2 arguments, got 1"},
		{"variadic empty", "min();\n", "min", "takes at least 1 argument, got 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := arityMessages(t, tc.src)
			if !hasArity(msgs, tc.call) {
				t.Fatalf("expected a builtinArity diagnostic for %q, got %+v", tc.call, msgs)
			}
			found := false
			for _, m := range msgs {
				if strings.Contains(m, tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("message for %q missing %q, got %+v", tc.call, tc.want, msgs)
			}
		})
	}
}

func TestBuiltinAritySilentOnValidCalls(t *testing.T) {
	// Correct arity, a valid variadic count, and builtins with no curated arity
	// must all stay silent.
	sources := []string{
		"abs(-1);\n",
		"pow(2, 3);\n",
		"clamp(1, 2, 3);\n",
		"push([1], 2);\n",
		"min(1);\n",
		"min(1, 2, 3);\n",
		"print(1, 2, 3, 4);\n", // print is not in the curated table
	}
	for _, src := range sources {
		if msgs := arityMessages(t, src); len(msgs) != 0 {
			t.Fatalf("expected no builtinArity diagnostics for %q, got %+v", src, msgs)
		}
	}
}

func TestBuiltinAritySilentWhenShadowed(t *testing.T) {
	// A user rebinding a builtin name means the call is not the builtin, so its
	// arity must not be checked.
	src := "let abs = fn(a, b) { a };\nabs(1, 2);\n"
	if msgs := arityMessages(t, src); len(msgs) != 0 {
		t.Fatalf("expected no diagnostic for shadowed `abs`, got %+v", msgs)
	}
}

func TestBuiltinAritySilentForShadowedParam(t *testing.T) {
	// A function parameter shadowing a builtin name inside the body.
	src := "let f = fn(len) { len(1, 2, 3) };\n"
	if msgs := arityMessages(t, src); len(msgs) != 0 {
		t.Fatalf("expected no diagnostic for parameter-shadowed `len`, got %+v", msgs)
	}
}

func TestBuiltinArityRespectsOffSeverity(t *testing.T) {
	snapshot := New().Analyze("abs(1, 2);\n")
	config := DefaultLintConfig()
	config.BuiltinArity = LintSeverityOff
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "builtin `abs`") {
			t.Fatalf("builtinArity=off should suppress the diagnostic, got %q", d.Message)
		}
	}
}
