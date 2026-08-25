package webrepl

import (
	"strings"
	"testing"
)

// docs/WASM_REPL_REFERENCE.md used to say macros were "intentionally excluded"
// in the browser. They are not -- Eval expands them before compiling, exactly as
// the CLI pipeline does. The document contradicted itself on the point, so the
// claim it now makes is pinned here rather than left to be re-derived by
// whoever reads the table next.

func TestMacrosWorkInTheBrowserRepl(t *testing.T) {
	repl := New()

	if got := evalInput(t, repl, `let seven = macro() { quote(7); }; putf(seven());`); !strings.Contains(got, "7") {
		t.Fatalf("a macro did not expand in the browser REPL: %q", got)
	}

	// The session is persistent, so a macro defined in one eval has to still be
	// there for the next -- and expand freshly against each call's arguments.
	evalInput(t, repl, `let add = macro(a, b) { quote(unquote(a) + unquote(b)); };`)

	if got := evalInput(t, repl, `putf(add(3, 9));`); !strings.Contains(got, "12") {
		t.Fatalf("a macro from an earlier eval did not expand: %q", got)
	}
	if got := evalInput(t, repl, `putf(add(100, 5));`); !strings.Contains(got, "105") {
		t.Fatalf("the second call replayed the first call's arguments: %q", got)
	}
}

// A broken macro must come back as an error the session reports, not as a panic
// that takes the page down with it.
func TestBrokenMacroIsAnErrorNotAPanic(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"body is not a quote", `let bad = macro() { 5; }; bad();`, "must return quote"},
		{"wrong arity", `let two = macro(a, b) { quote(unquote(a)); }; two(1);`, "wrong number of arguments"},
		{"unquote of an array", `let bad = macro() { quote(unquote([1,2])); }; bad();`, "no source form"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := New().Eval(tc.input)
			if err == nil {
				t.Fatalf("Eval(%q) succeeded, got %q; expected an error", tc.input, out)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not explain the problem: %s", err)
			}
		})
	}
}
