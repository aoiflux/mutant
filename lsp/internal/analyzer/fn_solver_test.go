package analyzer

import (
	"strings"
	"testing"

	mast "mutant/ast"
)

// cardFor renders the hover card for the first function bound in src.
func cardFor(t *testing.T, src string) string {
	t.Helper()

	s := New().Analyze(src)
	if len(s.ParseErrors) > 0 {
		t.Fatalf("fixture did not parse: %v", s.ParseErrors)
	}
	bindings := functionBindings(s.Program)
	if len(bindings) == 0 {
		t.Fatalf("fixture bound no function:\n%s", src)
	}
	return userFunctionCard(s, bindings[0].name, bindings[0].literal, leadingCommentBlock(src)).render()
}

// leadingCommentBlock returns the source's opening // block, which is what the
// hover path hands the card.
func leadingCommentBlock(src string) string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//") {
			break
		}
		out = append(out, strings.TrimSpace(strings.TrimPrefix(trimmed, "//")))
	}
	return strings.Join(out, "\n")
}

// TestSolverNarrowsParametersFromBuiltinContracts is the solver's whole reason
// for existing. Mutant has no type annotations, so a parameter's type can only
// come from what the body does with it — and the richest source of that is the
// 607 verified parameter contracts in builtin/metadata.go.
func TestSolverNarrowsParametersFromBuiltinContracts(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a chain of string builtins",
			src:  "let norm = fn(host) { return str_lower(str_trim(host)); };",
			want: "function `norm(host: STRING) -> STRING`",
		},
		{
			name: "a pair builtin destructured, then consumed",
			src:  `let lines = fn(path) { let data, err = fs_read(path); return text_split(data, "x"); };`,
			want: "function `lines(path: STRING) -> ARRAY of STRING`",
		},
		{
			name: "only the parameters the body actually uses",
			src:  "let digest = fn(payload, algo) { return hash_sha256(payload); };",
			want: "function `digest(payload: STRING, algo) -> STRING`",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if card := cardFor(t, test.src); !strings.Contains(card, test.want) {
				t.Errorf("card does not contain %q:\n%s", test.want, card)
			}
		})
	}
}

// TestSolverUsesTheVMsOperatorDomains checks the operator constraints match what
// the VM actually accepts, rather than what an arithmetic operator "obviously"
// takes. execBinaryStringOperation rejects every opcode but OpAdd, so `+` admits
// strings and `*` does not — a distinction worth getting right, because claiming
// `a` in `a + b` is numeric would be a type the program does not have.
func TestSolverUsesTheVMsOperatorDomains(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "addition admits strings",
			src:  "let join2 = fn(a, b) { return a + b; };",
			want: "join2(a: STRING|INTEGER|FLOAT, b: STRING|INTEGER|FLOAT)",
		},
		{
			name: "multiplication does not",
			src:  "let scale = fn(n, factor) { return n * factor; };",
			want: "scale(n: INTEGER|FLOAT, factor: INTEGER|FLOAT)",
		},
		{
			name: "ordering comparison is numeric",
			src:  "let over = fn(n) { if (n > 10) { return true; }; return false; };",
			want: "over(n: INTEGER|FLOAT)",
		},
		{
			name: "negation is numeric",
			src:  "let flip = fn(n) { return -n; };",
			want: "flip(n: INTEGER|FLOAT)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if card := cardFor(t, test.src); !strings.Contains(card, test.want) {
				t.Errorf("card does not contain %q:\n%s", test.want, card)
			}
		})
	}
}

// TestSolverPropagatesThroughUserFunctions covers the fixpoint. A parameter
// handed straight to another function has whatever type that function demands,
// which cannot be worked out in a single pass over one body.
func TestSolverPropagatesThroughUserFunctions(t *testing.T) {
	src := "let inner = fn(s) { return str_upper(s); };\n" +
		"let outer = fn(v) { return inner(v); };\n"

	s := New().Analyze(src)
	bindings := functionBindings(s.Program)
	if len(bindings) != 2 {
		t.Fatalf("expected two function bindings, got %d", len(bindings))
	}

	var outer *mast.FunctionLiteral
	for _, b := range bindings {
		if b.name == "outer" {
			outer = b.literal
		}
	}
	if outer == nil {
		t.Fatal("outer was not collected")
	}

	card := userFunctionCard(s, "outer", outer, "").render()
	if !strings.Contains(card, "outer(v: STRING)") {
		t.Errorf("the constraint did not propagate from inner to outer:\n%s", card)
	}
}

// TestSolverLeavesUnconstrainedParametersBare is the restraint half. A parameter
// the body never constrains has no type to show, and inventing one — from a call
// site, from a name that looks like a path — is the single way this feature could
// mislead rather than inform.
func TestSolverLeavesUnconstrainedParametersBare(t *testing.T) {
	card := cardFor(t, "let passthrough = fn(value) { return value; };\npassthrough(\"text\");\n")

	if !strings.Contains(card, "passthrough(value)") {
		t.Errorf("an unconstrained parameter reached the signature line:\n%s", card)
	}
	// The call-site evidence is still worth showing, but only as an observation
	// on the bullet, never as the parameter's type.
	if !strings.Contains(card, "- `value` · `STRING` _(observed at call sites)_") {
		t.Errorf("call-site evidence is missing from the bullet:\n%s", card)
	}
}

// TestSolverIgnoresNestedFunctionParameters guards the one place a name-based
// solver can go wrong. The inner `fn(host)` shadows the outer parameter, so the
// str_upper call inside it says nothing about the outer one.
func TestSolverIgnoresNestedFunctionParameters(t *testing.T) {
	src := "let outer = fn(host) { let inner = fn(host) { return str_upper(host); }; return inner(1); };"
	card := cardFor(t, src)

	if strings.Contains(card, "outer(host: STRING)") {
		t.Errorf("a shadowed parameter's constraint leaked to the outer function:\n%s", card)
	}
}

// TestSolverShowsNothingForContradictoryConstraints covers the empty set. A
// parameter both negated and passed to str_upper cannot exist, and the honest
// response is to say nothing — reporting it is the diagnostics' job, and this
// runs on best-effort inference that is not allowed to fail a build.
func TestSolverShowsNothingForContradictoryConstraints(t *testing.T) {
	card := cardFor(t, "let broken = fn(v) { let a = -v; return str_upper(v); };")

	if strings.Contains(card, "broken(v:") {
		t.Errorf("an impossible parameter was given a type:\n%s", card)
	}
}

// TestFunctionCardRendersDocTags checks the @param/@returns convention reaches
// the card, so a documented user function reads exactly like a builtin.
func TestFunctionCardRendersDocTags(t *testing.T) {
	src := "// Normalises a hostname for comparison.\n" +
		"// @param host — the raw hostname, with or without a scheme\n" +
		"// @returns the lower-cased, trimmed host\n" +
		"let norm = fn(host) { return str_lower(str_trim(host)); };\n"

	card := cardFor(t, src)
	for _, want := range []string{
		"Normalises a hostname for comparison.",
		"- `host` · `STRING` _(inferred)_ — the raw hostname, with or without a scheme",
		"- `STRING` _(inferred)_ — the lower-cased, trimmed host",
	} {
		if !strings.Contains(card, want) {
			t.Errorf("card is missing %q:\n%s", want, card)
		}
	}
	// A tag line must not also appear in the description.
	if strings.Contains(card, "@param") || strings.Contains(card, "@returns") {
		t.Errorf("tag lines leaked into the description:\n%s", card)
	}
}

// TestUntaggedDocCommentIsUnchanged is the compatibility check. Every doc comment
// in the corpus predates the tags, so adding them must leave those cards exactly
// as they were.
func TestUntaggedDocCommentIsUnchanged(t *testing.T) {
	card := cardFor(t, "// Adds two numbers together\nlet add = fn(a, b) { a + b; };\n")

	if !strings.Contains(card, "Adds two numbers together") {
		t.Errorf("an untagged doc comment was lost:\n%s", card)
	}
}

// TestFunctionCardMarksAnUninferredReturn keeps a user function's unknown apart
// from a builtin's verified ANY. Both render as ANY; only the note says whether
// that is a fact about the callable or a limit of the editor.
func TestFunctionCardMarksAnUninferredReturn(t *testing.T) {
	card := cardFor(t, "let opaque = fn(v) { return mystery_call(v); };")

	if !strings.Contains(card, "- `ANY` _(not inferred)_") {
		t.Errorf("an uninferred return did not say so:\n%s", card)
	}
}

// TestFunctionCardHasTheSameSectionsAsABuiltinCard is the requirement stated
// plainly: hovering a user function and hovering a builtin should teach a reader
// the same things in the same places.
func TestFunctionCardHasTheSameSectionsAsABuiltinCard(t *testing.T) {
	userCard := cardFor(t, "let norm = fn(host) { return str_lower(host); };")
	builtinCard, ok := builtinHoverText("str_lower")
	if !ok {
		t.Fatal("str_lower has no hover card")
	}

	for _, section := range []string{"**Parameters**", "**Returns**"} {
		if !strings.Contains(userCard, section) {
			t.Errorf("user function card is missing %q:\n%s", section, userCard)
		}
		if !strings.Contains(builtinCard, section) {
			t.Errorf("builtin card is missing %q:\n%s", section, builtinCard)
		}
	}

	// A zero-parameter function keeps the heading, exactly as a zero-parameter
	// builtin does.
	empty := cardFor(t, "let now = fn() { return 1; };")
	if !strings.Contains(empty, "**Parameters**\n- _none_") {
		t.Errorf("zero-parameter function dropped the section:\n%s", empty)
	}
}
