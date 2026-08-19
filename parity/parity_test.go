package parity

// Cross-engine golden parity test. Mutant has three execution engines that must
// agree on documented operator semantics: the compiler+stack-VM (vm/vm.go), the
// tree-walking evaluator (evaluator/, used by CLI --macros mode), and the WASM
// web REPL (webrepl/repl.go). The evaluator and web REPL now share a single
// numeric operator core (object.NumericInfix); this test pins the evaluator and
// the VM to identical results for a table of expressions so the two independent
// implementations of the operator semantics can never silently drift apart.
//
// The web REPL is covered transitively: it routes numeric infix through the very
// same object.NumericInfix the evaluator uses, so evaluator==VM here implies
// webrepl==VM for these expressions.

import (
	"fmt"
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
