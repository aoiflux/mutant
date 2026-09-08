package compiler

import (
	"testing"

	"mutant/code"
)

// One case per opcode, pinning the mapping from source operator to instruction.
// The binary operators all compile the same shape as `+` -- left, right, op --
// which is the point: none of them needs the operand swap `<` and `<=` use, and
// none of them carries an operand.
func TestBitwiseOperatorsCompileToTheirOpcodes(t *testing.T) {
	tests := []compilerTestCase{
		{
			input:             "12 & 10;",
			expectedConstants: []interface{}{12, 10},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpConstant, 1),
				code.Make(code.OpBitAnd),
				code.Make(code.OpPop),
			},
		},
		{
			input:             "12 | 10;",
			expectedConstants: []interface{}{12, 10},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpConstant, 1),
				code.Make(code.OpBitOr),
				code.Make(code.OpPop),
			},
		},
		{
			input:             "12 ^ 10;",
			expectedConstants: []interface{}{12, 10},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpConstant, 1),
				code.Make(code.OpBitXor),
				code.Make(code.OpPop),
			},
		},
		{
			input:             "1 << 4;",
			expectedConstants: []interface{}{1, 4},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpConstant, 1),
				code.Make(code.OpShiftLeft),
				code.Make(code.OpPop),
			},
		},
		{
			input:             "16 >> 4;",
			expectedConstants: []interface{}{16, 4},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpConstant, 1),
				code.Make(code.OpShiftRight),
				code.Make(code.OpPop),
			},
		},
		{
			input:             "~5;",
			expectedConstants: []interface{}{5},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpBitNot),
				code.Make(code.OpPop),
			},
		},
		{
			// Compound assignment is sugar with no opcode of its own: it
			// compiles to a load, the binary op, and a store -- the same shape
			// `x += 1` has. A missing base operator would show up here as the
			// OpBitOr disappearing.
			input:             "let x = 12; x |= 3;",
			expectedConstants: []interface{}{12, 3},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0),
				code.Make(code.OpSetGlobal, 0),
				code.Make(code.OpGetGlobal, 0),
				code.Make(code.OpConstant, 1),
				code.Make(code.OpBitOr),
				code.Make(code.OpSetGlobal, 0),
				code.Make(code.OpGetGlobal, 0),
				code.Make(code.OpPop),
			},
		},
	}

	runCompilerTests(t, tests)
}
