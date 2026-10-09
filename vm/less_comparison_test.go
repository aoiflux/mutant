package vm

import (
	"fmt"
	"strings"
	"testing"

	"mutant/code"
	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// OpLess and OpLessEqual have to order exactly what OpGreater and
// OpGreaterEqual order. They were introduced so that `a < b` could stop being
// compiled as `b > a`, and an operator that answered for a type pair its
// mirror image refuses -- or refused one its mirror image answers -- would
// have made the two different questions rather than one question asked both
// ways (M26-CMP-005).
func TestLessOrdersTheSameOperandsAsGreater(t *testing.T) {
	runVMTests(t, []vmTestCase{
		{"1 < 2", true},
		{"2 < 1", false},
		{"2 < 2", false},
		{"2 <= 2", true},
		{"3 <= 2", false},
		{"-1 < 0", true},
		{"1.5 < 2.5", true},
		{"2.5 < 1.5", false},
		{"1.5 <= 1.5", true},
		{"2 < 2.5", true},  // mixed: both promoted to float
		{"2.5 < 2", false}, // mixed, the other way round
		{"2 <= 2.0", true}, // mixed, at the boundary
		{"2.0 <= 2", true},
	})
}

// The refusals mirror too. Strings, bytes, errors, enum values and structs are
// not ordered in this language -- only `==` and `!=` are defined for them --
// and a lesser comparison has to decline what the greater one declines. Had
// `<` quietly answered where `>` refuses, the operand domains the analyzer's
// diagnostics are derived from would describe one operator while the VM
// implemented another.
func TestLessRefusesWhatGreaterRefuses(t *testing.T) {
	for _, pair := range [][2]string{
		{`"a" < "b"`, `"a" > "b"`},
		{`"a" <= "b"`, `"a" >= "b"`},
	} {
		for _, input := range pair {
			if _, err := runEncryptedVM(input); err == nil {
				t.Errorf("%s was answered; strings are not ordered", input)
			} else if !strings.Contains(err.Error(), "unknown operator") ||
				!strings.Contains(err.Error(), "STRING") {
				t.Errorf("%s failed with %q, want it to name the operator and the types", input, err)
			}
		}
	}
}

// Bytecode compiled before `<` had an opcode of its own still runs. It emitted
// the operands swapped and OpGreater, whose value and meaning have not
// changed, which is the append-only rule being load-bearing rather than
// decorative. Nothing the current compiler emits can prove that, so the stream
// is built by hand: constants 2 then 1, which is how `1 < 2` used to compile.
func TestTheOldSwappedEncodingOfLessStillAnswers(t *testing.T) {
	instructions := code.Make(code.OpConstant, 0)
	instructions = append(instructions, code.Make(code.OpConstant, 1)...)
	instructions = append(instructions, code.Make(code.OpGreater)...)
	instructions = append(instructions, code.Make(code.OpPop)...)

	// Sealed the way runVMTests seals compiler output: the instruction stream
	// is decrypted with a key derived from its own length, so a plain stream
	// handed to New decodes as noise rather than as itself.
	byteCode := &compiler.ByteCode{
		Instructions: instructions,
		Constants: []object.Object{
			&object.Integer{Value: 2},
			&object.Integer{Value: 1},
		},
	}
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
	if err := machine.Run(); err != nil {
		t.Fatalf("a stream the previous compiler emitted no longer runs: %s", err)
	}

	answer, isBoolean := machine.LastPoppedStackElement().(*object.Boolean)
	if !isBoolean {
		t.Fatalf("OpGreater produced %T, want a boolean", machine.LastPoppedStackElement())
	}
	if !answer.Value {
		t.Error("the old encoding of `1 < 2` now answers false, so OpGreater's meaning moved")
	}
}
