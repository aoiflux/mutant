package parity

// A `break` or a `continue` that escapes the call it was written in, held
// against what each engine does with it.
//
// This is M26-EVL-023, and it is the shape of defect this package exists to
// catch. The compiler refused it; the tree-walking engine ran it and let the
// signal leave the call as the call's VALUE, so the caller's loop obeyed a
// break written in a function it had merely called. One program, two answers,
// no diagnostic from either.
//
// It is not reachable only through the tree-walker's own entry point, which is
// what made it an S2 rather than a curiosity: `mutant gen` runs DefineMacros
// and ExpandMacros for every module with no flag behind it, so an `unquote`
// argument is user code this engine executes before anything has been
// compiled. A macro whose argument ran the shape spliced the wrong answer into
// the program.

import (
	"strings"
	"testing"

	"mutant/ast"
	"mutant/evaluator"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
)

// escapingShapes are the ways the signal can be written so that it leaves a
// call. Each loop form is included because the evaluator keeps a separate
// environment and a separate signal check per form, so a fix to one is not a
// fix to the others -- the row records that all three behaved the same way.
var escapingShapes = []struct{ name, src string }{
	{"break out of a closure inside for",
		"let out = 0; for (let i = 0; i < 3; i = i + 1) { let f = fn() { break; }; f(); out = out + 1; } out"},
	{"continue out of a closure inside for",
		"let out = 0; for (let i = 0; i < 3; i = i + 1) { let f = fn() { continue; }; f(); out = out + 1; } out"},
	{"break out of a closure inside while",
		"let n = 0; let out = 0; while (n < 3) { n = n + 1; let f = fn() { break; }; f(); out = out + 1; } out"},
	{"break out of a closure inside for-in",
		"let out = 0; for (v in [1, 2, 3]) { let f = fn() { break; }; f(); out = out + 1; } out"},
	// No enclosing loop at all. This half never depended on the compiler's
	// loop-context bookkeeping, because there was no context to corrupt: the
	// compiler always refused it and the evaluator always ran it.
	{"break out of a call with no loop anywhere",
		"let f = fn() { break; }; f(); 7"},
}

// TestABreakEscapingACallIsRefusedByBothEngines is the parity statement: not
// that the two engines produce the same number, but that neither produces one.
func TestABreakEscapingACallIsRefusedByBothEngines(t *testing.T) {
	for _, shape := range escapingShapes {
		t.Run(shape.name, func(t *testing.T) {
			message, refused := compilerComplaint(shape.src)
			if !refused {
				t.Fatalf("the compiler accepted a signal that escapes its call:\n  %s", shape.src)
			}
			if !strings.Contains(message, "outside of for loop") {
				t.Errorf("the compiler refused for some other reason: %q", message)
			}

			evaluated := evalViaEvaluator(shape.src)
			if got := normalize(evaluated); got != "ERROR" {
				t.Fatalf("the evaluator answered %s where the compiler refuses the same program;\n"+
					"a break that escapes its call must not become a value\n  %s", got, shape.src)
			}

			// The same words, not merely both refusing. sema owns the sentence
			// precisely so the two cannot drift into two phrasings of one rule,
			// and a test that only checked "both errored" would not notice the
			// drift coming back.
			raised, ok := evaluated.(*object.Error)
			if !ok {
				t.Fatalf("the evaluator produced %T, want *object.Error", evaluated)
			}
			if raised.Message != message {
				t.Errorf("the engines refuse it in different words:\n  compiler:  %s\n  evaluator: %s",
					message, raised.Message)
			}
		})
	}
}

// TestACallInsideALoopStillWorks is the control, and it is the half that makes
// the test above mean something: the backstop must catch a signal that escapes
// a call without catching a call made inside a loop, which is ordinary code.
func TestACallInsideALoopStillWorks(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{"a closure called in a loop body",
			"let out = 0; let bump = fn(n) { return n + 1; }; for (let i = 0; i < 3; i = i + 1) { out = bump(out); } out",
			"INTEGER(3)"},
		{"break in the loop body itself, not in a call",
			"let out = 0; for (let i = 0; i < 5; i = i + 1) { if (i == 2) { break; } out = out + 1; } out",
			"INTEGER(2)"},
		{"a loop inside the closure, with its own break",
			"let f = fn() { let n = 0; for (let j = 0; j < 9; j = j + 1) { if (j == 4) { break; } n = n + 1; } return n; }; f()",
			"INTEGER(4)"},
		{"continue in the loop body itself",
			"let out = 0; for (let i = 0; i < 5; i = i + 1) { if (i == 2) { continue; } out = out + 1; } out",
			"INTEGER(4)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			evaluated := normalize(evalViaEvaluator(c.src))
			vmObj, err := evalViaVM(t, c.src)
			if err != nil {
				t.Fatalf("VM refused the program: %v", err)
			}
			if compiled := normalize(vmObj); evaluated != compiled {
				t.Fatalf("engines disagree: evaluator %s, VM %s", evaluated, compiled)
			}
			if evaluated != c.want {
				t.Fatalf("both engines answered %s, want %s", evaluated, c.want)
			}
		})
	}
}

// expandOnly runs the macro pass and reports what it said, without compiling.
// It is deliberately non-fatal where evalViaVMWithMacros is fatal: here the
// expansion failing IS the assertion.
func expandOnly(src string) (string, bool) {
	program := parser.New(lexer.New(src)).ParseProgram()
	macroEnv := object.NewEnvironment()
	evaluator.DefineMacros(program, macroEnv)
	expanded, err := evaluator.ExpandMacros(program, macroEnv)
	if err != nil {
		return err.Error(), false
	}
	if _, ok := expanded.(*ast.Program); !ok {
		return "expansion did not yield a program", false
	}
	return "", true
}

// TestMacroExpansionReportsAnEscapingBreakInsteadOfSplicingIt is the reachable
// half of the row, and the one the compiler's own refusal cannot reach.
//
// Expansion happens before compilation, so the compiler never sees the program
// the author wrote -- it sees whatever the tree-walker computed. With the signal
// escaping the call, that was the literal 0, and `mutant gen` built it and the
// program printed `macro says out=0` with exit 0 and no diagnostic. The control
// below is the same macro over the same loop with no closure in it, which
// answers 3 and must go on expanding.
func TestMacroExpansionReportsAnEscapingBreakInsteadOfSplicingIt(t *testing.T) {
	escaping := `let m = macro() { quote(unquote(fn() {
		let out = 0;
		for (let i = 0; i < 3; i = i + 1) {
			let f = fn() { break; };
			f();
			out = out + 1;
		}
		return out;
	}())); };
	m()`

	message, expanded := expandOnly(escaping)
	if expanded {
		t.Fatalf("macro expansion spliced an answer for a program whose break escapes its call; " +
			"it has to report instead, because nothing compiles the author's version")
	}
	if !strings.Contains(message, "outside of for loop") {
		t.Errorf("expansion failed for some other reason: %q", message)
	}
	if !strings.Contains(message, "macro m") {
		t.Errorf("the report does not name the macro, which is where the reader has to look: %q", message)
	}

	sound := `let m = macro() { quote(unquote(fn() {
		let out = 0;
		for (let i = 0; i < 3; i = i + 1) { out = out + 1; }
		return out;
	}())); };
	m()`

	if message, expanded := expandOnly(sound); !expanded {
		t.Fatalf("the same macro over a loop with no closure in it must still expand: %q", message)
	}

	// Run it the way `mutant gen` does -- expand, then compile, then run --
	// rather than handing the raw source to the tree-walker. The raw source
	// still holds the macro definition, and this engine has no arm for a macro
	// literal: DefineMacros is what removes them. Asking it to evaluate an
	// unexpanded macro call is asking a different question, and the answer used
	// to be a panic.
	ran, err := evalViaVMWithMacros(t, sound)
	if err != nil {
		t.Fatalf("the expanded control did not run: %v", err)
	}
	if got := normalize(ran); got != "INTEGER(3)" {
		t.Fatalf("the control answers %s, want INTEGER(3)", got)
	}
}

// TestCallingANameWithNoValueIsReportedAndNotAPanic is the evaluator's half of
// M26-VM-003, which is FIXED in the VM and was not fixed here.
//
// Found while building this kit, in the function it edits, and reachable
// through the real CLI: DefineMacros removes only TOP-LEVEL `let x = macro(...)`
// statements, so a macro literal nested inside an `unquote` argument survives
// into code this engine runs. `eval` has no arm for *ast.MacroLiteral, so it
// yields a nil interface, the `let` binds it, and calling it reached
// applyFunction's default arm, which called fn.Type() on nothing. `mutant gen`
// died with a nil pointer dereference.
//
// The compiler refuses the same nesting cleanly, which is why only the
// expansion path was exposed.
func TestCallingANameWithNoValueIsReportedAndNotAPanic(t *testing.T) {
	src := `let show = macro() { quote(unquote(fn() {
		let inner = macro() { quote(2); };
		return inner();
	}())); };
	show()`

	message, expanded := expandOnly(src)
	if expanded {
		t.Fatalf("a nested macro definition has to be reported, not expanded")
	}
	if !strings.Contains(message, "no value") {
		t.Errorf("expansion failed for some other reason: %q", message)
	}
	if !strings.Contains(message, "top level") {
		t.Errorf("the report does not say what the rule is, which is the whole remedy: %q", message)
	}
}
