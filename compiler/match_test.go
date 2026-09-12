package compiler

import (
	"testing"

	"mutant/code"
)

// TestMatchCompilesToACompareAndJumpChain pins the shape the whole design
// rests on: the subject is pushed once and duplicated per alternative, because
// OpEqual and OpJumpFalse both consume what they read.
//
// A scratch local holding the subject would work too, and was rejected:
// SymbolTable.Define never reuses a slot, so a match inside a large function
// would spend one of the 256 local slots per occurrence and eventually panic
// inside code.Make.
func TestMatchCompilesToACompareAndJumpChain(t *testing.T) {
	runCompilerTests(t, []compilerTestCase{
		{
			input:             `match (1) { 2 => 3, _ => 4 }`,
			expectedConstants: []interface{}{1, 2, 3, 4},
			expectedInstructions: []code.Instructions{
				code.Make(code.OpConstant, 0), // the subject, pushed once
				code.Make(code.OpDup),         // 0003: a copy to test against
				code.Make(code.OpConstant, 1),
				code.Make(code.OpEqual),
				code.Make(code.OpJumpFalse, 18),
				code.Make(code.OpPop), // matched: the subject has done its work
				code.Make(code.OpConstant, 2),
				code.Make(code.OpJump, 25),
				code.Make(code.OpPop), // 0018: the wildcard, tested by nothing
				code.Make(code.OpConstant, 3),
				code.Make(code.OpJump, 25),
				code.Make(code.OpPop), // 0025: the statement drops the value
			},
		},
	})
}

// TestAMatchWithoutAWildcardEmitsOpMatchFail is the failure path. Falling off
// the end is an error naming the value rather than a null, because a match is
// an expression and a silent null would flow on as though an arm had produced
// it -- which is exactly what happens to every existing match when an enum
// gains a variant.
func TestAMatchWithoutAWildcardEmitsOpMatchFail(t *testing.T) {
	instructions := compileToInstructions(t, `match (1) { 2 => 3 }`)
	if !containsOpcode(instructions, code.OpMatchFail) {
		t.Errorf("a match with no wildcard compiled without OpMatchFail:\n%s", instructions)
	}
}

// TestAMatchWithAWildcardEmitsNoOpMatchFail is the other half: with a `_` there
// is no failure path, so emitting one would leave dead bytes in every match
// anyone actually writes.
func TestAMatchWithAWildcardEmitsNoOpMatchFail(t *testing.T) {
	instructions := compileToInstructions(t, `match (1) { 2 => 3, _ => 4 }`)
	if containsOpcode(instructions, code.OpMatchFail) {
		t.Errorf("a match with a wildcard still emitted OpMatchFail:\n%s", instructions)
	}
}

// TestEveryMatchArmShapeCompiles walks the arm-body shapes leaveOneValue has to
// tell apart. It proves only that each one compiles: the compiler does not
// model the stack, so whether a body actually left one value is asserted where
// it runs, in parity.TestAMatchArmAlwaysLeavesExactlyOneValue.
func TestEveryMatchArmShapeCompiles(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"a bare value", `match (1) { 2 => 3, _ => 4 }`},
		{"a block ending in a value", `match (1) { 2 => { 3 }, _ => { 4 } }`},
		{"a block ending in a let", `match (1) { 2 => { let a = 3; }, _ => 4 }`},
		{"an empty block", `match (1) { 2 => { }, _ => 4 }`},
		{"a block ending in a loop", `match (1) { 2 => { while (false) { } }, _ => 4 }`},
		{"alternatives", `match (1) { 2 | 3 | 4 => 5, _ => 6 }`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := compileErr(`let picked = ` + tt.input + `; picked;`); err != nil {
				t.Fatalf("compiling %q: %v", tt.input, err)
			}
		})
	}
}

func compileToInstructions(t *testing.T, input string) code.Instructions {
	t.Helper()
	compiler := New()
	if err := compiler.Compile(parse(input)); err != nil {
		t.Fatalf("compiler error: %s", err)
	}
	return compiler.ByteCode().Instructions
}

func compileErr(input string) error {
	compiler := New()
	return compiler.Compile(parse(input))
}

func containsOpcode(instructions code.Instructions, want code.Opcode) bool {
	for ip := 0; ip < len(instructions); {
		op := code.Opcode(instructions[ip])
		if op == want {
			return true
		}
		definition, err := code.Lookup(byte(op))
		if err != nil {
			return false
		}
		_, read := code.ReadOperands(definition, instructions[ip+1:])
		ip += 1 + read
	}
	return false
}
