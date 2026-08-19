package evaluator

import (
	"testing"

	"mutant/object"
)

// TestEvaluatorOperatorParity covers operators that were previously missing from
// the tree-walking evaluator (`%`, `<=`, `>=`) but are documented and supported
// by the compiler/VM.
func TestEvaluatorOperatorParity(t *testing.T) {
	ints := map[string]int64{
		"7 % 3":  1,
		"10 % 5": 0,
		"9 % 4":  1,
	}
	for in, want := range ints {
		testIntegerObject(t, testEval(in), want)
	}

	bools := map[string]bool{
		"2 <= 2": true,
		"3 <= 2": false,
		"3 >= 3": true,
		"2 >= 3": false,
		"2 < 3":  true,
		"5 > 4":  true,
	}
	for in, want := range bools {
		testBooleanObject(t, testEval(in), want)
	}
}

// TestEvaluatorFloatArithmetic covers FLOAT and mixed INTEGER/FLOAT arithmetic,
// which previously fell through to an "unknown operator" error in the evaluator.
func TestEvaluatorFloatArithmetic(t *testing.T) {
	floats := map[string]float64{
		"1.5 + 2.0": 3.5,
		"2.0 * 3":   6.0, // mixed int/float
		"7 / 2.0":   3.5, // mixed int/float
		"5.5 % 2.0": 1.5,
		"10.0 - 4":  6.0,
	}
	for in, want := range floats {
		obj := testEval(in)
		f, ok := obj.(*object.Float)
		if !ok {
			t.Fatalf("%s: expected FLOAT, got %T (%s)", in, obj, obj.Inspect())
		}
		if f.Value != want {
			t.Errorf("%s = %v, want %v", in, f.Value, want)
		}
	}

	// Float and mixed comparisons.
	testBooleanObject(t, testEval("1.5 <= 1.5"), true)
	testBooleanObject(t, testEval("2.5 >= 3.0"), false)
	testBooleanObject(t, testEval("2 < 2.5"), true)   // mixed
	testBooleanObject(t, testEval("3.0 == 3"), true)  // mixed equality
}

// TestEvaluatorDivModByZero matches the VM: integer / and % by zero are errors,
// not panics.
func TestEvaluatorDivModByZero(t *testing.T) {
	for _, in := range []string{"5 / 0", "5 % 0"} {
		obj := testEval(in)
		if obj.Type() != object.ERROR_OBJ {
			t.Fatalf("%s: expected ERROR, got %s (%s)", in, obj.Type(), obj.Inspect())
		}
	}
}
