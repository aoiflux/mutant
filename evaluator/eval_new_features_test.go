package evaluator

import (
	"mutant/object"
	"testing"
)

func TestForLoops(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"let sum = 0; let i = 0; for(; i < 3; i = i + 1) { sum = sum + i; } sum", 3},
		{"let sum = 0; let i = 0; for(; i < 5; i = i + 1) { sum = sum + 1; } sum", 5},
		{"let x = 0; for(;;) { x = x + 1; if (x > 2) { break; } } x", 3},
	}

	for _, tt := range tests {
		evaluated := testEval(tt.input)
		testIntegerObject(t, evaluated, tt.expected)
	}
}

func TestForLoopWithBreak(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"let sum = 0; let i = 0; for(; i < 10; i = i + 1) { if (i == 3) { break; } sum = sum + 1; } sum", 3},
		{"let result = 0; let i = 0; for(; i < 100; i = i + 1) { result = i; if (i == 5) { break; } } result", 5},
	}

	for _, tt := range tests {
		evaluated := testEval(tt.input)
		testIntegerObject(t, evaluated, tt.expected)
	}
}

func TestForLoopWithContinue(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"let sum = 0; let i = 0; for(; i < 5; i = i + 1) { if (i == 2) { continue; } sum = sum + i; } sum", 8},
		{"let count = 0; let i = 0; for(; i < 3; i = i + 1) { if (i == 1) { continue; } count = count + 1; } count", 2},
	}

	for _, tt := range tests {
		evaluated := testEval(tt.input)
		testIntegerObject(t, evaluated, tt.expected)
	}
}

func TestNestedForLoops(t *testing.T) {
	input := `
	let outer_sum = 0;
	let i = 0;
	for(; i < 3; i = i + 1) {
		let j = 0;
		for(; j < 2; j = j + 1) {
			outer_sum = outer_sum + 1;
		}
	}
	outer_sum
	`
	evaluated := testEval(input)
	testIntegerObject(t, evaluated, 6)
}

func TestStructDefinition(t *testing.T) {
	input := "struct Point { x; y; } 42"
	evaluated := testEval(input)
	testIntegerObject(t, evaluated, 42)
}

// The struct statement in each of these is not decoration. This engine used to
// build a literal of any type name, declared or not, while the compiler refused
// all three ways a literal can be wrong -- so these tests were pinning a
// program the compiler has never accepted. evalStructLiteral validates the same
// three things now (M26-EVL-019), and the declaration is what makes them legal
// programs rather than what makes the tests pass.
func TestStructLiteral(t *testing.T) {
	input := "struct Point { x; y; }; Point { x: 10, y: 20 }"
	evaluated := testEval(input)
	result, ok := evaluated.(*object.Struct)
	if !ok {
		t.Fatalf("Eval didn't return Struct. got=%T (%+v)", evaluated, evaluated)
	}

	if result.TypeName != "Point" {
		t.Fatalf("Struct has wrong type name. got=%s", result.TypeName)
	}

	xVal, ok := result.Fields["x"]
	if !ok {
		t.Fatalf("Struct missing field x")
	}
	testIntegerObject(t, xVal, 10)

	yVal, ok := result.Fields["y"]
	if !ok {
		t.Fatalf("Struct missing field y")
	}
	testIntegerObject(t, yVal, 20)
}

func TestFieldAccess(t *testing.T) {
	input := `
	struct Point { x; y; };
	let p = Point { x: 5, y: 15 };
	p.x
	`
	evaluated := testEval(input)
	testIntegerObject(t, evaluated, 5)
}

func TestFieldAssignment(t *testing.T) {
	input := `
	struct Point { x; y; };
	let p = Point { x: 5, y: 15 };
	p.x = 25;
	p.x
	`
	evaluated := testEval(input)
	testIntegerObject(t, evaluated, 25)
}

func TestVariableAssignment(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"let x = 5; x = 10; x", 10},
		{"let x = 5; x = x + 3; x", 8},
	}

	for _, tt := range tests {
		evaluated := testEval(tt.input)
		testIntegerObject(t, evaluated, tt.expected)
	}
}

func TestEnumDefinition(t *testing.T) {
	input := "enum Color { Red, Green, Blue } 42"
	evaluated := testEval(input)
	testIntegerObject(t, evaluated, 42)
}

func TestEnumVariantAccess(t *testing.T) {
	input := `enum Color { Red, Green, Blue }; Color.Red`
	evaluated := testEval(input)
	result, ok := evaluated.(*object.EnumValue)
	if !ok {
		t.Fatalf("Eval didn't return EnumValue. got=%T (%+v)", evaluated, evaluated)
	}

	if result.TypeName != "Color" {
		t.Fatalf("EnumValue has wrong type name. got=%s", result.TypeName)
	}

	if result.Tag != "Red" {
		t.Fatalf("EnumValue has wrong tag. got=%s", result.Tag)
	}
}

func TestStructWithComplexValues(t *testing.T) {
	input := `
	struct Point { x; y; };
	let p = Point { x: 1 + 2, y: 3 * 4 };
	p.x + p.y
	`
	evaluated := testEval(input)
	testIntegerObject(t, evaluated, 15)
}

func TestStructInArray(t *testing.T) {
	input := `
	struct Point { x; y; };
	let p1 = Point { x: 1, y: 2 };
	let p2 = Point { x: 3, y: 4 };
	let points = [p1, p2];
	points[0].x
	`
	evaluated := testEval(input)
	testIntegerObject(t, evaluated, 1)
}
