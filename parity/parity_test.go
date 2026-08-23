package parity

// Golden parity test between the two remaining evaluators of expressions.
//
// Mutant used to have three execution engines -- the compiler+stack-VM, the
// tree-walking evaluator, and a separate WASM web REPL -- and this test existed
// to stop them drifting. The web REPL now runs the compiler+VM directly, so it
// is the same engine rather than a third one to compare against.
//
// The evaluator still evaluates expressions, though, because macro expansion
// needs it: `unquote(2 + 3)` is computed by the evaluator at expansion time and
// spliced into the program the VM then runs. So the two implementations of
// operator semantics still both exist, and must still agree -- otherwise a value
// computed inside a macro differs from the same expression written inline.
// TestMacroExpansionMatchesDirectCompilation pins exactly that.

import (
	"fmt"
	"mutant/ast"
	"mutant/compiler"
	"mutant/evaluator"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/security"
	"mutant/vm"
	"testing"
)

// evalViaEvaluator runs the input through the tree-walking evaluator.
func evalViaEvaluator(input string) object.Object {
	l := lexer.New(input)
	p := parser.New(l)
	program := p.ParseProgram()
	env := object.NewEnvironment()
	return evaluator.Eval(program, env)
}

// evalViaVM compiles the input and runs it on the encrypted stack-VM, mirroring
// the production execution path (see vm/vm_test.go runVMTests). It returns the
// VM's Run() error separately: the VM signals division/modulo by zero as a Go
// runtime error rather than pushing an Error object, whereas the evaluator
// returns an *object.Error — both amount to "engine declined to yield a value",
// which normalize()/the caller reconcile to the ERROR form.
func evalViaVM(t *testing.T, input string) (object.Object, error) {
	t.Helper()
	l := lexer.New(input)
	p := parser.New(l)
	program := p.ParseProgram()

	comp := compiler.New()
	if err := comp.Compile(program); err != nil {
		t.Fatalf("compiler error for %q: %s", input, err)
	}

	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := vm.NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
	if err := machine.Run(); err != nil {
		return nil, err
	}
	return machine.LastPoppedStackElement(), nil
}

// evalViaVMWithMacros mirrors the production pipeline in generator/generate.go:
// define and expand macros over the AST first, then compile and run. evalViaVM
// deliberately skips expansion, so it cannot be used for macro input.
func evalViaVMWithMacros(t *testing.T, input string) (object.Object, error) {
	t.Helper()
	program := parser.New(lexer.New(input)).ParseProgram()

	macroEnv := object.NewEnvironment()
	evaluator.DefineMacros(program, macroEnv)
	expandedNode, expandErr := evaluator.ExpandMacros(program, macroEnv)
	if expandErr != nil {
		t.Fatalf("macro expansion failed for %q: %s", input, expandErr)
	}
	expanded, ok := expandedNode.(*ast.Program)
	if !ok {
		t.Fatalf("macro expansion did not yield a program for %q", input)
	}

	comp := compiler.New()
	if err := comp.Compile(expanded); err != nil {
		t.Fatalf("compiler error for %q: %s", input, err)
	}

	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := vm.NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
	if err := machine.Run(); err != nil {
		return nil, err
	}
	return machine.LastPoppedStackElement(), nil
}

// normalize collapses an object to a comparable (kind, value) shape. Integers and
// floats keep their kind distinct so 3 (INTEGER) never compares equal to 3.0
// (FLOAT); this is what makes the golden test able to catch the historical bug
// where the web REPL collapsed whole floats back to integers.
func normalize(o object.Object) string {
	switch v := o.(type) {
	case *object.Integer:
		return fmt.Sprintf("INTEGER(%d)", v.Value)
	case *object.Float:
		return fmt.Sprintf("FLOAT(%g)", v.Value)
	case *object.Boolean:
		return fmt.Sprintf("BOOLEAN(%t)", v.Value)
	case *object.String:
		return fmt.Sprintf("STRING(%q)", v.Value)
	case *object.Error:
		// Error message wording differs across engines by design; only the fact
		// that both engines errored is what parity requires here.
		return "ERROR"
	default:
		if o == nil {
			return "<nil>"
		}
		return fmt.Sprintf("%s(%s)", o.Type(), o.Inspect())
	}
}

func TestEvaluatorVMOperatorParity(t *testing.T) {
	inputs := []string{
		// integer arithmetic
		"1 + 2", "10 - 3", "6 * 7", "20 / 4", "7 % 3", "8 % 4", "-5 + 2",
		// integer comparison (all six operators)
		"2 < 3", "3 < 2", "5 > 4", "4 > 5", "2 <= 2", "2 <= 1", "3 >= 3", "3 >= 4",
		"5 == 5", "5 == 6", "5 != 6", "5 != 5",
		// float arithmetic
		"1.5 + 2.0", "5.0 - 1.25", "2.5 * 2.0", "9.0 / 2.0", "7.5 % 2.0",
		// whole-valued float results must stay FLOAT (not collapse to INTEGER)
		"2.0 * 3.0", "4.0 / 2.0", "1.0 + 1.0",
		// mixed int/float promotes to float
		"7 / 2.0", "3 + 0.5", "10 % 3.0", "2.0 * 4",
		// float comparison
		"1.5 < 2.5", "2.5 <= 2.5", "3.5 >= 4.5", "1.0 == 1.0", "1.0 != 2.0",
		// precedence / nesting still agree
		"2 + 3 * 4", "(2 + 3) * 4", "10 - 2 - 3", "2.0 + 3.0 * 4.0",
		// division / modulo by zero: both engines must error
		"1 / 0", "1 % 0",
		// string concatenation and equality
		`"ab" + "cd"`, `"x" == "x"`, `"x" != "y"`,
		// boolean logic (short-circuit operators)
		"true && false", "true || false", "false && true", "2 < 3 && 3 < 4",
		// compound assignment desugars identically in both engines
		"let i = 5; i += 3; i", "let i = 5; i -= 2; i", "let i = 4; i *= 3; i",
		"let i = 20; i /= 4; i", "let i = 17; i %= 5; i",
		"let s = \"ab\"; s += \"cd\"; s",
		"let x = 1.5; x += 2.0; x", "let x = 3.0; x *= 2.0; x",
		// postfix increment / decrement
		"let i = 0; i++; i", "let i = 0; i++; i++; i", "let i = 10; i--; i",
		// used as the tail expression value (assignment yields the stored value)
		"let i = 5; i += 1",
	}

	for _, input := range inputs {
		evalRes := normalize(evalViaEvaluator(input))
		vmObj, vmErr := evalViaVM(t, input)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			// A Go-level Run() error (e.g. division by zero) is the VM's way of
			// declining to yield a value; the evaluator declines by returning an
			// *object.Error. Both normalize to ERROR for parity purposes.
			vmRes = "ERROR"
		}
		if evalRes != vmRes {
			t.Errorf("engine divergence for %q: evaluator=%s vm=%s", input, evalRes, vmRes)
		}
	}
}

// A value computed by the evaluator during macro expansion must equal the same
// expression compiled straight to bytecode. This is the parity that still has
// teeth: `unquote(...)` runs in the evaluator and splices its result into the
// program, so any disagreement between the two operator implementations shows up
// as a macro silently producing a different number than the inline expression.
//
// unquote splices back integers, booleans, and quoted nodes (see
// convertObjectToASTNode), so the table stays within those.
func TestMacroExpansionMatchesDirectCompilation(t *testing.T) {
	inputs := []string{
		"1 + 2", "10 - 3", "6 * 7", "20 / 4", "7 % 3", "-5 + 2",
		"2 + 3 * 4", "(2 + 3) * 4", "10 - 2 - 3",
		"2 < 3", "5 > 4", "2 <= 2", "3 >= 4", "5 == 5", "5 != 6",
		"true && false", "true || false", "2 < 3 && 3 < 4",
		"!true", "!false",
	}

	for _, input := range inputs {
		direct, directErr := evalViaVM(t, input)
		if directErr != nil {
			t.Fatalf("direct compilation of %q failed: %s", input, directErr)
		}

		// The macro body evaluates `input` in the evaluator and splices the
		// resulting literal; the VM then runs that literal.
		viaMacro, macroErr := evalViaVMWithMacros(t, fmt.Sprintf("let m = macro() { quote(unquote(%s)); }; m();", input))
		if macroErr != nil {
			t.Fatalf("macro expansion of %q failed: %s", input, macroErr)
		}

		if normalize(direct) != normalize(viaMacro) {
			t.Errorf("macro/inline divergence for %q: inline=%s via-macro=%s",
				input, normalize(direct), normalize(viaMacro))
		}
	}
}
