package analyzer

import (
	"strings"
	"testing"

	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// deprecatedDiagnostics returns every builtinDeprecated diagnostic in src. They
// are the only lint diagnostics that carry DiagnosticTagDeprecated, which is a
// sturdier filter than matching on message text.
func deprecatedDiagnostics(t *testing.T, src string, config LintConfig) []lsp.Diagnostic {
	t.Helper()
	out := make([]lsp.Diagnostic, 0, 2)
	for _, d := range Diagnostics(New().Analyze(src), config) {
		for _, tag := range d.Tags {
			if tag == lsp.DiagnosticTagDeprecated {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// aDeprecatedBuiltin is whatever the metadata currently marks deprecated. The
// test reads it rather than hard-coding net_syn_scan so that retiring that alias
// -- which named builtin operands finally make possible -- does not leave a
// test asserting a rule against a builtin that no longer exists.
func aDeprecatedBuiltin(t *testing.T) (name, replacement string) {
	t.Helper()
	for _, def := range builtin.Builtins {
		if to, deprecated := builtin.DeprecatedBy(def.Name); deprecated {
			return def.Name, to
		}
	}
	t.Skip("no builtin is currently marked deprecated")
	return "", ""
}

func TestDeprecatedBuiltinIsReportedAtTheCall(t *testing.T) {
	name, replacement := aDeprecatedBuiltin(t)

	found := deprecatedDiagnostics(t, name+"(\"host\", 1, 2, 3);", DefaultLintConfig())
	if len(found) != 1 {
		t.Fatalf("got %d deprecated diagnostics, want 1", len(found))
	}
	if !strings.Contains(found[0].Message, name) {
		t.Fatalf("the message must name the builtin; got %q", found[0].Message)
	}
	if replacement != "" && !strings.Contains(found[0].Message, replacement) {
		t.Fatalf("the message must name the replacement %q; got %q", replacement, found[0].Message)
	}
	// A deprecated builtin still works. Reporting it as a warning would put a
	// squiggle on a correct program.
	if found[0].Severity == nil || *found[0].Severity != lsp.DiagnosticSeverityHint {
		t.Fatalf("severity = %v, want hint", found[0].Severity)
	}
}

func TestDeprecatedBuiltinStaysSilentForLiveBuiltins(t *testing.T) {
	for _, src := range []string{
		`len([]);`,
		`net_connect_scan("host", 1, 2, 3);`,
		`putln("hello");`,
	} {
		if found := deprecatedDiagnostics(t, src, DefaultLintConfig()); len(found) != 0 {
			t.Fatalf("%s produced %d deprecated diagnostics: %v", src, len(found), found[0].Message)
		}
	}
}

func TestDeprecatedBuiltinRespectsAShadowingBinding(t *testing.T) {
	name, _ := aDeprecatedBuiltin(t)
	src := "let " + name + " = fn(a, b, c, d) { return 1; };\n" + name + "(\"host\", 1, 2, 3);"

	if found := deprecatedDiagnostics(t, src, DefaultLintConfig()); len(found) != 0 {
		t.Fatalf("a user binding shadows the builtin, so the call is not a builtin call; got %q",
			found[0].Message)
	}
}

func TestDeprecatedBuiltinRespectsSeverityOff(t *testing.T) {
	name, _ := aDeprecatedBuiltin(t)

	config := DefaultLintConfig()
	config.BuiltinDeprecated = LintSeverityOff
	if found := deprecatedDiagnostics(t, name+"(\"host\", 1, 2, 3);", config); len(found) != 0 {
		t.Fatalf("the rule is off; got %q", found[0].Message)
	}
}

// TestDeprecatedBuiltinIsReportedEvenWhenTheCallIsWrong keeps the deprecation
// independent of the arity rule. The two answer different questions, and a
// wrong-arity call to a deprecated builtin is still a call to a deprecated
// builtin.
func TestDeprecatedBuiltinIsReportedEvenWhenTheCallIsWrong(t *testing.T) {
	name, _ := aDeprecatedBuiltin(t)

	if found := deprecatedDiagnostics(t, name+"();", DefaultLintConfig()); len(found) != 1 {
		t.Fatalf("got %d deprecated diagnostics on a wrong-arity call, want 1", len(found))
	}
}

func TestDeprecatedBuiltinAppearsInHover(t *testing.T) {
	name, replacement := aDeprecatedBuiltin(t)

	card, ok := builtinCard(name)
	if !ok {
		t.Fatalf("no hover card for %q", name)
	}
	rendered := card.render()
	if !strings.Contains(rendered, "Deprecated") {
		t.Fatalf("the hover card must say the builtin is deprecated:\n%s", rendered)
	}
	if replacement != "" && !strings.Contains(rendered, replacement) {
		t.Fatalf("the hover card must name %q:\n%s", replacement, rendered)
	}
}

func TestStableBuiltinsSayNothingAboutStability(t *testing.T) {
	// Almost every builtin is stable; a footer line saying so would be noise on
	// every hover in the language.
	card, ok := builtinCard("len")
	if !ok {
		t.Fatal("no hover card for len")
	}
	for _, unwanted := range []string{"Deprecated", "Experimental", "stable"} {
		if strings.Contains(card.render(), unwanted) {
			t.Fatalf("a stable builtin's card mentions %q:\n%s", unwanted, card.render())
		}
	}
}
