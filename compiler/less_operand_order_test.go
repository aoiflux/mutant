package compiler

import (
	"testing"

	"mutant/code"
)

// `<` and `<=` compile their left operand first and emit opcodes of their own.
// They used to compile the right operand first and emit the greater family --
// `a < b` as `b > a` -- which gives the same answer for two literals and the
// opposite answer as soon as either operand has a side effect.
//
// The constant pool is what makes the order visible in a compiled program: the
// operand compiled first is the constant interned first, so a swap shows up
// here as a reversed pool even though the instructions themselves look the
// same. parity/ asserts the consequence; this asserts the cause.
func TestLessCompilesItsOperandsInSourceOrder(t *testing.T) {
	runCompilerTests(t, []compilerTestCase{
		{
			input:             "1 < 2",
			expectedConstants: []interface{}{1, 2},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpConstant, 1),
				code.Make(code.OpLess),
				code.Make(code.OpPop),
			},
		},
		{
			input:             "1 <= 2",
			expectedConstants: []interface{}{1, 2},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpConstant, 1),
				code.Make(code.OpLessEqual),
				code.Make(code.OpPop),
			},
		},
	})
}

// No path reuses the greater family for a lesser comparison any more --
// including the one an optimiser would be tempted to add back for operands it
// can prove side-effect-free. A compiler that swaps "only when it is safe" has
// to be right about every expression it is asked about; one that never swaps
// has nothing to be right about.
func TestNoLesserComparisonCompilesToTheGreaterFamily(t *testing.T) {
	for _, input := range []string{
		"1 < 2",
		"1 <= 2",
		"1.5 < 2",
		"let a = fn() { return 1; }; a() < a();",
		"let xs = [1, 2]; xs[0] <= xs[1];",
		"let i = 0; while (i < 2) { i = i + 1; }",
	} {
		program := parse(input)

		c := New()
		if err := c.Compile(program); err != nil {
			t.Fatalf("%s: compiler error: %s", input, err)
		}

		instructions := c.ByteCode().Instructions
		if containsOpcode(instructions, code.OpGreater) || containsOpcode(instructions, code.OpGreaterEqual) {
			t.Errorf("%s compiled to the greater family, so its operands run in the wrong order:\n%s",
				input, instructions)
		}
		if !containsOpcode(instructions, code.OpLess) && !containsOpcode(instructions, code.OpLessEqual) {
			t.Errorf("%s compiled to neither OpLess nor OpLessEqual:\n%s", input, instructions)
		}
	}
}
