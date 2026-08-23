package vm

import (
	"encoding/binary"
	"fmt"
	"testing"

	"mutant/code"
	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// Constant-pool randomization (mutation level >= 6) reorders ByteCode.Constants
// and rewrites the operands that point into it. It used to rewrite only
// OpConstant, so closures, struct literals, field access and enum values kept
// pointing at whatever the shuffle moved into their old slot.
//
// Nothing caught it at compile time -- the operand was still a valid pool index,
// just the wrong constant -- so `mutant gen --mutation 6` reported success and
// shipped a .mu that died in the VM with "not a function" or "type constant is
// not string".
//
// This program is built to emit every constant-referencing opcode there is:
// OpClosure (fn), OpMakeStruct + OpSetField (the literal and the assignment),
// OpGetField (p.x), OpEnumValue (Color.Green), and plain OpConstant.
const polymorphicProgram = `
struct Point { x; y; };
enum Color { Red, Green };
let add = fn(a, b) { return a + b; };
let p = Point { x: 10, y: 20 };
p.y = 32;
let c = Color.Green;
add(p.x, p.y);
`

// compileMutated mirrors what generator.encode does: compile at a mutation
// level, then strip the trailing polymorphic marker, which is compile-time
// metadata and not executable.
func compileMutated(t *testing.T, level int, seed int64) *compiler.ByteCode {
	t.Helper()

	comp := compiler.New()
	if level > 0 {
		comp.EnablePolymorphismWithSeed(level, seed)
	}
	if err := comp.Compile(parse(polymorphicProgram)); err != nil {
		t.Fatalf("compile at mutation %d: %s", level, err)
	}

	bc := comp.ByteCode()
	if compiler.DetectPolymorphicLevel(bc.Instructions) > 0 && len(bc.Instructions) >= 2 {
		bc.Instructions = bc.Instructions[:len(bc.Instructions)-2]
	}
	return bc
}

// The mutation level must not change what the program computes. This is the
// test that matters: it runs the real VM over real mutated bytecode.
func TestMutationLevelDoesNotChangeTheResult(t *testing.T) {
	for level := 0; level <= 10; level++ {
		t.Run(fmt.Sprintf("level%d", level), func(t *testing.T) {
			bc := compileMutated(t, level, 42)

			password := fmt.Sprint(security.DerivePasswordFromInstructions(bc.Instructions))
			machine := NewWithGlobalStoreAndPassword(
				mutil.EncryptByteCode(bc, password),
				make([]object.Object, global.GlobalSize),
				password,
			)
			if err := machine.Run(); err != nil {
				t.Fatalf("mutation level %d produced bytecode the VM cannot run: %s", level, err)
			}

			result, ok := machine.LastPoppedStackElement().(*object.Integer)
			if !ok {
				t.Fatalf("mutation level %d: expected an integer, got %T", level, machine.LastPoppedStackElement())
			}
			if result.Value != 42 {
				t.Fatalf("mutation level %d changed the answer: got %d, want 42", level, result.Value)
			}
		})
	}
}

// The stronger, more specific statement: after mutation every constant-pool
// operand still resolves to the kind of constant its opcode requires. Checked
// directly so a failure names the opcode rather than surfacing as a VM error
// several phases downstream.
func TestMutationKeepsConstantReferencesPointingAtTheRightConstants(t *testing.T) {
	wantKind := map[code.Opcode]object.ObjectType{
		code.OpClosure:    object.COMPILED_FN_OBJ,
		code.OpMakeStruct: object.STRING_OBJ,
		code.OpGetField:   object.STRING_OBJ,
		code.OpSetField:   object.STRING_OBJ,
		code.OpEnumValue:  object.STRING_OBJ,
	}

	for level := 0; level <= 10; level++ {
		bc := compileMutated(t, level, 42)

		streams := []code.Instructions{bc.Instructions}
		for _, c := range bc.Constants {
			if fn, ok := c.(*object.CompiledFunction); ok {
				streams = append(streams, fn.Instructions)
			}
		}

		seen := 0
		for _, ins := range streams {
			seen += checkConstantRefs(t, level, ins, bc.Constants, wantKind)
		}

		// If the program stopped emitting these opcodes the test would pass
		// while checking nothing at all.
		if seen < len(wantKind) {
			t.Fatalf("level %d: only %d constant-referencing opcodes found, expected at least %d -- the test program no longer covers them",
				level, seen, len(wantKind))
		}
	}
}

// checkConstantRefs walks one instruction stream and returns how many
// constant-referencing operands it verified.
func checkConstantRefs(
	t *testing.T,
	level int,
	ins code.Instructions,
	constants []object.Object,
	wantKind map[code.Opcode]object.ObjectType,
) int {
	t.Helper()

	checked := 0
	for i := 0; i < len(ins); {
		def, err := code.Lookup(ins[i])
		if err != nil {
			t.Fatalf("level %d: undecodable opcode %d at offset %d", level, ins[i], i)
		}

		width := 1
		for _, w := range def.OperandWidths {
			width += w
		}
		if i+width > len(ins) {
			t.Fatalf("level %d: %s at offset %d runs past the end of the stream", level, def.Name, i)
		}

		op := code.Opcode(ins[i])
		want, interesting := wantKind[op]

		offset := i + 1
		for operand, w := range def.OperandWidths {
			isConstRef := false
			for _, slot := range code.ConstantOperands[op] {
				if slot == operand {
					isConstRef = true
				}
			}

			if interesting && isConstRef && w == 2 {
				idx := int(binary.BigEndian.Uint16(ins[offset : offset+2]))
				if idx >= len(constants) {
					t.Fatalf("level %d: %s operand %d points at constant %d, past the end of a %d-entry pool",
						level, def.Name, operand, idx, len(constants))
				}
				if got := constants[idx].Type(); got != want {
					t.Fatalf("level %d: %s operand %d points at constant %d which is a %s, want %s",
						level, def.Name, operand, idx, got, want)
				}
				checked++
			}
			offset += w
		}

		i += width
	}
	return checked
}
