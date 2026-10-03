package evaluator

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
	"mutant/token"
)

// refusalMarker is the part of the refusal every case below looks for. An arity
// complaint or a shape complaint does not carry it, which is what lets one source
// shape serve every builtin in the registry: the refusal is raised when the name
// becomes a builtin, before anything looks at the arguments.
const refusalMarker = "not available at macro expansion time"

type probeOutcome struct {
	parsed   bool
	expanded bool
	message  string
}

func (p probeOutcome) refused() bool {
	return p.parsed && !p.expanded && strings.Contains(p.message, refusalMarker)
}

// probeCall expands `quote(unquote(<call>()))` and reports what happened, without
// judging it -- each test below decides what the right answer is for its case.
func probeCall(call string) probeOutcome {
	source := fmt.Sprintf("let m = macro() { quote(unquote(%s())) }; m();", call)
	p := parser.New(lexer.New(source))
	program := p.ParseProgram()
	if len(p.Errors()) > 0 {
		return probeOutcome{message: strings.Join(p.Errors(), "; ")}
	}

	env := object.NewEnvironment()
	DefineMacros(program, env)
	if _, err := ExpandMacros(program, env); err != nil {
		return probeOutcome{parsed: true, message: err.Error()}
	}
	return probeOutcome{parsed: true, expanded: true}
}

// dottedField splits a flat builtin name the way sema's fold does: on the FIRST
// underscore, so bytes_cursor_read_u8 is bytes.cursor_read_u8 and nothing else.
func dottedField(flat string) (namespace, field string, hasOne bool) {
	underscore := strings.Index(flat, "_")
	if underscore <= 0 {
		return "", "", false
	}
	return flat[:underscore], flat[underscore+1:], true
}

// TestEveryRefusedBuiltinIsRefusedByTheEngine covers the whole registry rather
// than a chosen handful, in both spellings.
//
// A handful of hand-written cases is not enough here, and the reason is specific:
// sema folds any `a.b` to `a_b` whenever `a` is unbound and `a_b` is registered,
// so every refused builtin whose flat name holds an underscore has a live dotted
// alias through the second door into the builtin table. A suite that named a few
// of them by hand would stay green if that door were reopened for the rest. This
// one goes red the moment any refused builtin becomes reachable under either
// spelling.
//
// It asserts the counts too, so a case quietly skipped fails rather than
// shrinking the coverage in silence -- and it accounts for the third possible
// answer as well: a few builtins have no dotted spelling the language can
// express, and that is asserted rather than passed over.
func TestEveryRefusedBuiltinIsRefusedByTheEngine(t *testing.T) {
	keywords := token.KeywordLiterals()
	var wantFlat, gotFlat, wantDotted, gotDotted, wantUnwritable, gotUnwritable int

	for _, def := range builtin.Builtins {
		if def.Name == "" || builtin.MacroSafe(def.Name) {
			continue
		}

		wantFlat++
		switch outcome := probeCall(def.Name); {
		case !outcome.parsed:
			t.Errorf("%s: the probe did not parse: %s", def.Name, outcome.message)
		case outcome.expanded:
			t.Errorf("%s: expansion SUCCEEDED -- the builtin ran during a compile", def.Name)
		case !outcome.refused():
			t.Errorf("%s: expansion failed, but not with the refusal: %s", def.Name, outcome.message)
		default:
			gotFlat++
		}

		namespace, field, hasOne := dottedField(def.Name)
		if !hasOne {
			continue
		}
		dotted := namespace + "." + field

		// A field name has to be an identifier, so a builtin whose name is
		// `sigma_match` has NO dotted spelling: `sigma.match` does not parse,
		// because match is a keyword. The second door does not exist for those,
		// which is stronger than their being refused at it -- and asserting it
		// here means the day a keyword is retired, or a builtin named x_import
		// is added, this test says so instead of quietly covering one case less.
		if slices.Contains(keywords, field) {
			wantUnwritable++
			if outcome := probeCall(dotted); outcome.parsed {
				t.Errorf("%s: %s parses now, so it needs refusing like every other dotted spelling",
					def.Name, dotted)
			} else {
				gotUnwritable++
			}
			continue
		}

		wantDotted++
		switch outcome := probeCall(dotted); {
		case !outcome.parsed:
			t.Errorf("%s: the dotted probe %s did not parse: %s", def.Name, dotted, outcome.message)
		case outcome.expanded:
			t.Errorf("%s: the dotted spelling %s SUCCEEDED -- the second door is open", def.Name, dotted)
		case !outcome.refused():
			t.Errorf("%s: the dotted spelling %s was not refused: %s", def.Name, dotted, outcome.message)
		default:
			gotDotted++
		}
	}

	if gotFlat != wantFlat || gotDotted != wantDotted || gotUnwritable != wantUnwritable {
		t.Fatalf("refused %d/%d flat, %d/%d dotted, %d/%d with no writable dotted spelling",
			gotFlat, wantFlat, gotDotted, wantDotted, gotUnwritable, wantUnwritable)
	}
	if wantFlat == 0 || wantDotted == 0 {
		t.Fatal("the registry walk covered nothing, so this test proves nothing")
	}
	t.Logf("%d refused builtins, %d of them also under their dotted spelling, "+
		"%d with no dotted spelling the language can express", gotFlat, gotDotted, gotUnwritable)
}

// TestNoMacroSafeBuiltinIsRefusedByTheEngine is the other direction. Called with
// no arguments most of the allowlist complains about arity, and that is fine --
// what must never appear is the refusal, because that would mean the table and
// the engine disagree about the same name.
func TestNoMacroSafeBuiltinIsRefusedByTheEngine(t *testing.T) {
	keywords := token.KeywordLiterals()
	safe := builtin.MacroSafeBuiltins()

	for _, name := range safe {
		if outcome := probeCall(name); outcome.refused() {
			t.Errorf("%s is macro-safe but the engine refused it: %s", name, outcome.message)
		}

		namespace, field, hasOne := dottedField(name)
		if !hasOne || slices.Contains(keywords, field) {
			continue
		}
		dotted := namespace + "." + field
		if outcome := probeCall(dotted); outcome.refused() {
			t.Errorf("%s is macro-safe but its dotted spelling %s was refused: %s",
				name, dotted, outcome.message)
		}
	}
	if len(safe) == 0 {
		t.Fatal("there are no macro-safe builtins, so this test proves nothing")
	}
}
