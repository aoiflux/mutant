package code

import (
	"fmt"
	"testing"
)

// operandKind is what a two-byte operand actually points at. The polymorphic
// engine rewrites two of the three, and each rewrite has to touch its own kind
// and nothing else.
type operandKind int

const (
	kindConstant operandKind = iota // index into ByteCode.Constants
	kindJump                        // absolute offset into its own instruction stream
	kindOther                       // globals slot, builtin index, element count
)

// Anything that reorders the constant pool rewrites the operands named in
// ConstantOperands; anything that shifts instruction offsets rewrites those in
// JumpOperands. An opcode missing from the map it belongs to does not fail
// loudly -- its operand still lands on a real pool entry or a real offset, just
// the wrong one, so the program compiles clean and misbehaves inside the VM.
// That is exactly how OpClosure, OpMakeStruct, OpGetField, OpSetField and
// OpEnumValue came to be silently broken at mutation level 6 and above.
//
// So every two-byte operand in the instruction set is pinned here as one of the
// three kinds. Adding an opcode with a wide operand fails this test until that
// call is made.
func TestWideOperandsAreClassified(t *testing.T) {
	classified := map[string]operandKind{
		"OpConstant/0":   kindConstant,
		"OpClosure/0":    kindConstant,
		"OpGetField/0":   kindConstant,
		"OpSetField/0":   kindConstant,
		"OpMakeStruct/0": kindConstant,
		"OpEnumValue/0":  kindConstant,
		"OpEnumValue/1":  kindConstant,

		"OpJump/0":      kindJump,
		"OpJumpFalse/0": kindJump,

		"OpGetGlobal/0":   kindOther, // globals slot
		"OpSetGlobal/0":   kindOther, // globals slot
		"OpGetBuiltin/0":  kindOther, // index into the builtin registry
		"OpArray/0":       kindOther, // element count
		"OpHash/0":        kindOther, // element count
		"OpMultiValue/0":  kindOther, // value count
		"OpDestructure/0": kindOther, // target count
	}

	for _, op := range AllOpcodes() {
		def, err := Lookup(byte(op))
		if err != nil {
			t.Fatalf("AllOpcodes returned %d but Lookup rejects it", op)
		}

		for operand, width := range def.OperandWidths {
			if width != 2 {
				continue
			}

			key := fmt.Sprintf("%s/%d", def.Name, operand)
			kind, pinned := classified[key]
			if !pinned {
				t.Fatalf("%s is a new two-byte operand. Decide what it points at: "+
					"a constant-pool index belongs in ConstantOperands (or every pool "+
					"reordering silently corrupts it), an instruction offset belongs in "+
					"JumpOperands (or every instruction-inserting mutation silently "+
					"corrupts it), then record the decision here.", key)
			}

			assertDeclared(t, key, ConstantOperands[op], operand, kind == kindConstant, "ConstantOperands", "indexes the constant pool")
			assertDeclared(t, key, JumpOperands[op], operand, kind == kindJump, "JumpOperands", "holds an instruction offset")
		}
	}
}

// assertDeclared checks one operand against one of the two tables: present when
// it is that kind, absent when it is not.
func assertDeclared(t *testing.T, key string, slots []int, operand int, want bool, table, role string) {
	t.Helper()

	declared := false
	for _, slot := range slots {
		if slot == operand {
			declared = true
		}
	}

	if want && !declared {
		t.Errorf("%s %s but is missing from %s", key, role, table)
	}
	if !want && declared {
		t.Errorf("%s does not %s but %s claims it does", key, role, table)
	}
}

// Every entry in JumpOperands must name an operand the opcode actually has, and
// that operand must be two bytes wide -- an instruction offset is a uint16.
func TestJumpOperandsEntriesAreWellFormed(t *testing.T) {
	for op, slots := range JumpOperands {
		def, err := Lookup(byte(op))
		if err != nil {
			t.Errorf("JumpOperands names opcode %d, which is not defined", op)
			continue
		}

		for _, slot := range slots {
			if slot < 0 || slot >= len(def.OperandWidths) {
				t.Errorf("%s has %d operands, but JumpOperands names operand %d",
					def.Name, len(def.OperandWidths), slot)
				continue
			}
			if got := def.OperandWidths[slot]; got != 2 {
				t.Errorf("%s operand %d is %d bytes wide; an instruction offset is two",
					def.Name, slot, got)
			}
		}
	}
}

// Every entry in ConstantOperands must name an operand the opcode actually has,
// and that operand must be two bytes wide -- a pool index is a uint16.
func TestConstantOperandsEntriesAreWellFormed(t *testing.T) {
	for op, slots := range ConstantOperands {
		def, err := Lookup(byte(op))
		if err != nil {
			t.Errorf("ConstantOperands names opcode %d, which is not defined", op)
			continue
		}

		for _, slot := range slots {
			if slot < 0 || slot >= len(def.OperandWidths) {
				t.Errorf("%s has %d operands, but ConstantOperands names operand %d",
					def.Name, len(def.OperandWidths), slot)
				continue
			}
			if got := def.OperandWidths[slot]; got != 2 {
				t.Errorf("%s operand %d is %d bytes wide; a constant-pool index is two",
					def.Name, slot, got)
			}
		}
	}
}

// AllOpcodes has to be complete and in ascending order: the polymorphic engine
// shuffles it with a seeded RNG, and a map's ranging order would give a
// different permutation for the same seed on every run.
func TestAllOpcodesIsCompleteAndOrdered(t *testing.T) {
	all := AllOpcodes()

	if len(all) != len(definitions) {
		t.Fatalf("AllOpcodes returned %d opcodes, but %d are defined", len(all), len(definitions))
	}

	for i := 1; i < len(all); i++ {
		if all[i-1] >= all[i] {
			t.Fatalf("AllOpcodes is not ascending at %d: %d then %d", i, all[i-1], all[i])
		}
	}
}
