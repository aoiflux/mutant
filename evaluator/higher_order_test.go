package evaluator

import (
	"testing"

	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
)

func evalHO(t *testing.T, input string) object.Object {
	t.Helper()
	program := parser.New(lexer.New(input)).ParseProgram()
	return Eval(program, object.NewEnvironment())
}

func TestEvaluatorHigherOrder(t *testing.T) {
	// map / reduce / sort_by / each and index-aware callbacks, in the tree-walking
	// evaluator (REPL macro mode). (filter's predicate avoids `%`, which the
	// evaluator doesn't implement.)
	intArrayCases := map[string][]int64{
		`map([1,2,3], fn(x){x*2})`:                     {2, 4, 6},
		`map([10,20,30], fn(x,i){x+i})`:                {10, 21, 32},
		`filter([1,2,3,4], fn(x){x>2})`:                {3, 4},
		`sort_by([3,1,2], fn(x){x})`:                   {1, 2, 3},
		`let n=100; map([1,2,3], fn(x){x+n})`:          {101, 102, 103},
	}
	for input, want := range intArrayCases {
		arr, ok := evalHO(t, input).(*object.Array)
		if !ok {
			t.Errorf("%s: not an array", input)
			continue
		}
		if len(arr.Elements) != len(want) {
			t.Errorf("%s: len %d, want %d", input, len(arr.Elements), len(want))
			continue
		}
		for i, w := range want {
			if got, ok := arr.Elements[i].(*object.Integer); !ok || got.Value != w {
				t.Errorf("%s: [%d] = %v, want %d", input, i, arr.Elements[i].Inspect(), w)
			}
		}
	}

	if got := evalHO(t, `reduce([1,2,3,4], fn(a,x){a+x}, 0)`); got.Inspect() != "10" {
		t.Errorf("reduce = %s, want 10", got.Inspect())
	}
	if got := evalHO(t, `each([1,2,3], fn(x){x})`); got.Type() != object.NULL_OBJ {
		t.Errorf("each should return null, got %s", got.Type())
	}

	// Argument validation yields an error value.
	if got := evalHO(t, `map(5, fn(x){x})`); got.Type() != object.ERROR_OBJ {
		t.Errorf("map(non-array) should error, got %s", got.Inspect())
	}
}
