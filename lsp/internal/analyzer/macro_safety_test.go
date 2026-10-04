package analyzer

// The editor and the expander have to agree about a macro body, and the only way
// to be sure of that is to ask both about the same source. Every test below that
// makes a claim about what the compiler does runs the compiler's own expander
// over the same string it hands the analyzer -- so a rule that drifts from the
// engine fails here rather than in a user's editor.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/evaluator"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
	"mutant/token"
)

// The three shapes a call can take in a macro body, which is the whole of what
// this rule decides about:
//
//   - plainShape runs while the compiler runs.
//   - unquotedShape also runs: the quote holds a template, and the unquote puts
//     its argument back into evaluation. It is the shape the engine's own
//     registry walk uses, because the refusal is raised when the name becomes a
//     builtin and nothing has looked at the arguments yet.
//   - quotedShape does not run. It is source the macro emits, and the builtin in
//     it is as ordinary as it would be anywhere else in the program.
const (
	plainShape    = "let m = macro() { %s(); quote(1) }; m();"
	unquotedShape = "let m = macro() { quote(unquote(%s())) }; m();"
	quotedShape   = "let m = macro() { quote(%s()) }; m();"
)

// refusalMarker is the part of the expander's sentence that says a refusal is
// what happened, as opposed to an arity or a shape complaint. It is the same
// marker evaluator's own registry walk looks for.
const refusalMarker = "not available at macro expansion time"

// macroSafetyMessages runs this rule, and only this rule, over src.
func macroSafetyMessages(t *testing.T, src string) []string {
	t.Helper()

	diagnostics := lintMacroSafety(New().Analyze(src), DefaultLintConfig())
	messages := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		messages = append(messages, diagnostic.Message)
	}
	return messages
}

type expansion struct {
	parsed   bool
	expanded bool
	message  string
}

func (e expansion) refused() bool {
	return e.parsed && !e.expanded && strings.Contains(e.message, refusalMarker)
}

// expand runs the real expander over src: the parser, DefineMacros and
// ExpandMacros, which is what `mutant gen` does before it compiles anything.
func expand(src string) expansion {
	p := parser.New(lexer.New(src))
	program := p.ParseProgram()
	if len(p.Errors()) > 0 {
		return expansion{message: strings.Join(p.Errors(), "; ")}
	}

	env := object.NewEnvironment()
	evaluator.DefineMacros(program, env)
	if _, err := evaluator.ExpandMacros(program, env); err != nil {
		return expansion{parsed: true, message: err.Error()}
	}
	return expansion{parsed: true, expanded: true}
}

// dottedSpelling is the second spelling of a builtin, split on the FIRST
// underscore exactly as sema's fold splits it, or "" when the language cannot
// express one -- a field has to be an identifier, so `sigma.match` does not
// parse, because match is a keyword.
func dottedSpelling(flat string, keywords []string) string {
	underscore := strings.Index(flat, "_")
	if underscore <= 0 {
		return ""
	}
	namespace, field := flat[:underscore], flat[underscore+1:]
	if slices.Contains(keywords, field) {
		return ""
	}
	return namespace + "." + field
}

// TestTheRefusalTheEditorShowsIsTheExpanders is the parity this rule exists for,
// and it is checked against the engine rather than against a copy of its words.
//
// The editor's message is the expander's sentence plus two pieces of formatting a
// diagnostic adds: backticks around the name, and a full stop. Strip those and
// the remainder has to appear in the compiler's error word for word. A rule that
// paraphrased the refusal, or that read a list of its own, would pass a test
// comparing it with builtin.MacroRefusal and fail this one.
//
// It covers the whole registry in both spellings, and asserts the counts, so a
// case quietly skipped fails rather than shrinking the coverage in silence.
func TestTheRefusalTheEditorShowsIsTheExpanders(t *testing.T) {
	keywords := token.KeywordLiterals()
	var wantFlat, gotFlat, wantDotted, gotDotted int

	for _, def := range builtin.Builtins {
		if def.Name == "" || builtin.MacroSafe(def.Name) {
			continue
		}

		wantFlat++
		if sameSentence(t, def.Name) {
			gotFlat++
		}

		dotted := dottedSpelling(def.Name, keywords)
		if dotted == "" {
			continue
		}
		wantDotted++
		if sameSentence(t, dotted) {
			gotDotted++
		}
	}

	if gotFlat != wantFlat || gotDotted != wantDotted {
		t.Fatalf("the editor and the expander agree on %d/%d flat spellings and %d/%d dotted ones",
			gotFlat, wantFlat, gotDotted, wantDotted)
	}
	if wantFlat == 0 || wantDotted == 0 {
		t.Fatal("the registry walk covered nothing, so this test proves nothing")
	}
	t.Logf("%d refused builtins, %d of them also under their dotted spelling, "+
		"each reported by the editor in the expander's own words", gotFlat, gotDotted)
}

// sameSentence asks the editor and the expander about one spelling and reports
// whether they said the same thing.
func sameSentence(t *testing.T, spelling string) bool {
	t.Helper()

	src := fmt.Sprintf(unquotedShape, spelling)
	messages := macroSafetyMessages(t, src)
	if len(messages) != 1 {
		t.Errorf("%s: the editor reported %d macro-safety diagnostics, want exactly 1: %v",
			spelling, len(messages), messages)
		return false
	}
	if !strings.Contains(messages[0], spelling) {
		t.Errorf("%s: the diagnostic does not name the spelling the author wrote: %s",
			spelling, messages[0])
		return false
	}

	sentence := strings.TrimSuffix(strings.ReplaceAll(messages[0], "`", ""), ".")
	outcome := expand(src)
	switch {
	case !outcome.parsed:
		t.Errorf("%s: the probe did not parse: %s", spelling, outcome.message)
	case outcome.expanded:
		t.Errorf("%s: the editor refused this call and the expander ran it", spelling)
	case !outcome.refused():
		t.Errorf("%s: the expander failed, but not with a refusal: %s", spelling, outcome.message)
	case !strings.Contains(outcome.message, sentence):
		t.Errorf("%s: the editor says\n  %s\nand the expander says\n  %s",
			spelling, sentence, outcome.message)
	default:
		return true
	}
	return false
}

// TestNothingInsideAQuoteIsReported is the false positive this rule could most
// easily have shipped, so it is checked over the whole registry and against the
// engine on both counts: the editor says nothing, and the expander really does
// let the call through.
//
// A quote holds the source the macro writes. A `fs_write` in it runs when the
// emitted program runs, which is the ordinary thing for a program to do, and a
// rule that squiggled it would be reporting the feature.
func TestNothingInsideAQuoteIsReported(t *testing.T) {
	var covered int

	for _, def := range builtin.Builtins {
		if def.Name == "" || builtin.MacroSafe(def.Name) {
			continue
		}
		src := fmt.Sprintf(quotedShape, def.Name)
		if messages := macroSafetyMessages(t, src); len(messages) != 0 {
			t.Errorf("%s inside a quote was reported: %v", def.Name, messages)
			continue
		}
		outcome := expand(src)
		switch {
		case !outcome.parsed:
			t.Errorf("%s: the probe did not parse: %s", def.Name, outcome.message)
		case !outcome.expanded:
			t.Errorf("%s inside a quote: the expander refused it after all: %s",
				def.Name, outcome.message)
		default:
			covered++
		}
	}

	if covered == 0 {
		t.Fatal("no refused builtin was checked inside a quote, so this test proves nothing")
	}
	t.Logf("%d refused builtins pass unreported inside a quote, the expander agreeing", covered)
}

// TestNoMacroSafeBuiltinIsReported is the other direction over the allowlist.
// Called with no arguments most of these complain about arity, and that is fine:
// what must not appear is a diagnostic, because that would mean the editor
// refusing a call the compiler runs.
func TestNoMacroSafeBuiltinIsReported(t *testing.T) {
	safe := builtin.MacroSafeBuiltins()
	if len(safe) == 0 {
		t.Fatal("the allowlist is empty, so this test proves nothing")
	}

	for _, name := range safe {
		src := fmt.Sprintf(plainShape, name)
		if messages := macroSafetyMessages(t, src); len(messages) != 0 {
			t.Errorf("%s is macro-safe and was reported: %v", name, messages)
		}
		if outcome := expand(src); outcome.refused() {
			t.Errorf("%s is macro-safe and the expander refused it: %s", name, outcome.message)
		}
	}
	t.Logf("%d allowlisted builtins pass unreported in a macro body", len(safe))
}

// TestEveryRefusedBuiltinIsReportedOutsideAQuote covers the other shape a call
// takes -- a statement in the body, with no quote around it -- over the whole
// registry, because unquotedShape above proves the unquote path and not this one.
func TestEveryRefusedBuiltinIsReportedOutsideAQuote(t *testing.T) {
	var covered int

	for _, def := range builtin.Builtins {
		if def.Name == "" || builtin.MacroSafe(def.Name) {
			continue
		}
		src := fmt.Sprintf(plainShape, def.Name)
		messages := macroSafetyMessages(t, src)
		if len(messages) != 1 {
			t.Errorf("%s in a macro body: %d diagnostics, want exactly 1: %v",
				def.Name, len(messages), messages)
			continue
		}
		if outcome := expand(src); !outcome.refused() {
			t.Errorf("%s: the editor refused it and the expander said %q", def.Name, outcome.message)
			continue
		}
		covered++
	}

	if covered == 0 {
		t.Fatal("no refused builtin was checked outside a quote, so this test proves nothing")
	}
	t.Logf("%d refused builtins reported as a plain statement in a macro body", covered)
}

// TestTheDiagnosticRepeatsTheSpellingTheAuthorWrote pins the half of the
// expander's contract that is easy to lose: resolveBuiltin is keyed on the flat
// name and reports the dotted one, so that the author reads the words they typed.
func TestTheDiagnosticRepeatsTheSpellingTheAuthorWrote(t *testing.T) {
	messages := lintMessages(t, fmt.Sprintf(plainShape, "fs.write"))
	if !mentions(messages, "`fs.write` is not available at macro expansion time") {
		t.Errorf("the dotted spelling was not repeated back: %v", messages)
	}
	if mentions(messages, "`fs_write` is not available") {
		t.Errorf("the flat name was reported for a call written dotted: %v", messages)
	}

	messages = lintMessages(t, fmt.Sprintf(plainShape, "fs_write"))
	if !mentions(messages, "`fs_write` is not available at macro expansion time") {
		t.Errorf("the flat spelling was not repeated back: %v", messages)
	}
}

// TestTheRuleReachesTheEditorThroughDiagnostics is not the same claim as the
// tests above, which call the rule directly. A rule that is never appended to
// Diagnostics is a rule no editor ever runs.
func TestTheRuleReachesTheEditorThroughDiagnostics(t *testing.T) {
	src := fmt.Sprintf(plainShape, "process_list")
	if !mentions(lintMessages(t, src), "not available at macro expansion time") {
		t.Errorf("the rule did not fire through Diagnostics: %v", lintMessages(t, src))
	}

	off := DefaultLintConfig()
	off.MacroSafety = LintSeverityOff
	if diagnostics := lintMacroSafety(New().Analyze(src), off); len(diagnostics) != 0 {
		t.Errorf("the rule still fired with macroSafety off: %v", diagnostics)
	}
}

// TestAMacroLiteralInsideAFunctionIsNotAMacro pins the scope the expander has:
// DefineMacros reads the program's top-level statements and nothing else, so a
// `macro` written inside a function is never registered and never expanded. The
// expander is asked too, because this is a claim about what it does.
func TestAMacroLiteralInsideAFunctionIsNotAMacro(t *testing.T) {
	src := "let f = fn() { let m = macro() { fs_write(); quote(1) }; 1 }; f();"
	if messages := macroSafetyMessages(t, src); len(messages) != 0 {
		t.Errorf("a macro literal inside a function was reported: %v", messages)
	}
	if outcome := expand(src); outcome.refused() {
		t.Errorf("the expander refused a macro literal inside a function: %s", outcome.message)
	}
}

// TestACallInAFunctionBodyIsNotAnExpansion is the boundary in the other
// direction. The same call in an ordinary function is the program doing its work.
func TestACallInAFunctionBodyIsNotAnExpansion(t *testing.T) {
	src := "let f = fn() { fs_write(\"a\", \"b\") }; f();"
	if messages := macroSafetyMessages(t, src); len(messages) != 0 {
		t.Errorf("a call in an ordinary function body was reported: %v", messages)
	}
}

// TestAnUnquoteInsideANestedQuoteIsStillEvaluated is the engine's flat rewrite
// rather than quasiquote depth: evalUnquoteCalls walks the whole quoted node in
// one pass, so an unquote two quotes deep is evaluated just the same. A rule that
// counted levels would be quiet here, and the compile would still fail.
func TestAnUnquoteInsideANestedQuoteIsStillEvaluated(t *testing.T) {
	src := "let m = macro() { quote(quote(unquote(fs_write()))) }; m();"
	if !mentions(macroSafetyMessages(t, src), "`fs_write` is not available") {
		t.Errorf("an unquote inside a nested quote was not reported: %v", macroSafetyMessages(t, src))
	}
	if outcome := expand(src); !outcome.refused() {
		t.Errorf("the expander did not refuse it, so this expectation is wrong: %+v", outcome)
	}
}

// TestAQuoteWithTheWrongArityCarriesNothingThatRuns follows the engine into its
// own error handling: eval checks quote's arity before quoting, and
// evalUnquoteCalls checks unquote's before evaluating, so neither looks at an
// argument of a call with any other count. Reporting one would be reporting code
// that never runs.
func TestAQuoteWithTheWrongArityCarriesNothingThatRuns(t *testing.T) {
	for _, src := range []string{
		"let m = macro() { quote(1, unquote(fs_write())) }; m();",
		"let m = macro() { quote(unquote(fs_write(), 2)) }; m();",
	} {
		if messages := macroSafetyMessages(t, src); len(messages) != 0 {
			t.Errorf("%s\n  reported %v", src, messages)
		}
		if outcome := expand(src); outcome.refused() {
			t.Errorf("%s\n  the expander refused it after all: %s", src, outcome.message)
		}
	}
}

// TestABoundNameIsNotTheBuiltin covers the three ways the name in a macro body
// can be something else: a parameter holding the quoted argument, a `let` in the
// body, and a `let` in the file. The expander resolves the environment first and
// only then the registry, so in each of these the builtin is not what runs.
func TestABoundNameIsNotTheBuiltin(t *testing.T) {
	for _, src := range []string{
		"let m = macro(fs_write) { fs_write(); quote(1) }; m(1);",
		"let m = macro() { let fs_write = fn() { 1 }; fs_write(); quote(1) }; m();",
		"let fs_write = fn() { 1 }; let m = macro() { fs_write(); quote(1) }; m();",
	} {
		if messages := macroSafetyMessages(t, src); len(messages) != 0 {
			t.Errorf("%s\n  reported %v", src, messages)
		}
	}
}

// TestANameThatIsNotABuiltinIsNotReported is the guard on the other side of
// MacroRefusal's contract: it answers with the general reason for any name no
// rule matches, so a rule that asked it about every callee would report every
// helper a macro body calls, and every name that is simply misspelled. The
// expander does not refuse those -- it runs the function, and refuses whatever
// builtin the function reaches.
func TestANameThatIsNotABuiltinIsNotReported(t *testing.T) {
	for _, src := range []string{
		"let helper = fn() { 1 }; let m = macro() { helper(); quote(1) }; m();",
		"let m = macro() { nothing_here(); quote(1) }; m();",
	} {
		if messages := macroSafetyMessages(t, src); len(messages) != 0 {
			t.Errorf("%s\n  reported %v", src, messages)
		}
		if outcome := expand(src); outcome.refused() {
			t.Errorf("%s\n  the expander refused it: %s", src, outcome.message)
		}
	}
}

// TestTheQuoteFormIsRecognisedByItsToken is how the engine recognises it: eval
// intercepts a call whose function's token is "quote" before it resolves the
// name, so a file that binds `quote` to something of its own still gets the quote
// form -- and so does this rule. Being narrower than the engine here would mean
// reporting a template as though it ran.
func TestTheQuoteFormIsRecognisedByItsToken(t *testing.T) {
	src := "let quote = fn(x) { x }; let m = macro() { quote(fs_write()) }; m();"
	if messages := macroSafetyMessages(t, src); len(messages) != 0 {
		t.Errorf("a shadowed quote stopped being a quote: %v", messages)
	}
	if outcome := expand(src); outcome.refused() {
		t.Errorf("the expander refused it, so the engine does not agree: %s", outcome.message)
	}
}

// TestAMacroNobodyCallsIsStillReported pins a deliberate difference from the
// compiler, and the one platformSupport and weakCrypto have as well: a macro body
// runs where the macro is called, so a macro nothing calls refuses nothing and
// the build succeeds. The claim here is about the call, not about this program's
// fate -- the day the macro is called the build fails, and the body is no less
// wrong before that. unusedDeclaration reports the macro itself, so the file is
// not silent about the other half of it either.
func TestAMacroNobodyCallsIsStillReported(t *testing.T) {
	src := "let m = macro() { fs_write(); quote(1) }; 1;"
	if !mentions(macroSafetyMessages(t, src), "`fs_write` is not available") {
		t.Errorf("an uncalled macro's body was not reported: %v", macroSafetyMessages(t, src))
	}
	if outcome := expand(src); !outcome.expanded {
		t.Errorf("the expander refused an uncalled macro, so this expectation is wrong: %+v", outcome)
	}
}

// TestEveryRefusalInABodyIsReported is the gain over the compiler, stated as a
// test: expansion is fail-fast, so a body with three refused calls costs three
// builds to find. The editor shows all three at once.
func TestEveryRefusalInABodyIsReported(t *testing.T) {
	src := "let m = macro() { fs_write(); process_list(); time_now(); quote(1) }; m();"
	messages := macroSafetyMessages(t, src)
	if len(messages) != 3 {
		t.Fatalf("want three diagnostics, one per refused call, got %d: %v", len(messages), messages)
	}
	for _, name := range []string{"fs_write", "process_list", "time_now"} {
		if !mentions(messages, "`"+name+"`") {
			t.Errorf("%s was not among the three: %v", name, messages)
		}
	}

	outcome := expand(src)
	if !outcome.refused() {
		t.Fatalf("the expander did not refuse the body: %+v", outcome)
	}
	if strings.Count(outcome.message, refusalMarker) != 1 {
		t.Errorf("the expander named more than one refusal, so it is not fail-fast: %s", outcome.message)
	}
}
