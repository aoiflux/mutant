package code

import (
	"fmt"
	"testing"
)

// Anything that reorders the constant pool rewrites the operands named in
// ConstantOperands. An opcode that carries a constant index but is missing from
// that map does not fail loudly: its operand still lands on a real pool entry,
// just the wrong one, so the program compiles clean and misbehaves inside the
// VM. That is exactly how OpClosure, OpMakeStruct, OpGetField, OpSetField and
// OpEnumValue came to be silently broken at mutation level 6 and above.
//
// So every two-byte operand in the instruction set is pinned here as either a
// constant-pool index or explicitly something else. Adding an opcode with a
// wide operand fails this test until that call is made.
func TestConstantOperandsCoversEveryWideOperand(t *testing.T) {
	// what each two-byte operand actually indexes, keyed "OpName/operand"
	classified := map[string]bool{ // true == indexes the constant pool
		"OpConstant/0": true,
		"OpClosure/0":  true,
		"OpGetField/0": true,
		"OpSetField/0": true,

		"OpMakeStruct/0": true,
		"OpEnumValue/0":  true,
		"OpEnumValue/1":  true,

		"OpJump/0":        false, // instruction offset
		"OpJumpFalse/0":   false, // instruction offset
		"OpGetGlobal/0":   false, // globals slot
		"OpSetGlobal/0":   false, // globals slot
		"OpGetBuiltin/0":  false, // index into the builtin registry
		"OpArray/0":       false, // element count
		"OpHash/0":        false, // element count
		"OpMultiValue/0":  false, // value count
		"OpDestructure/0": false, // target count
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
			isConstant, pinned := classified[key]
			if !pinned {
				t.Fatalf("%s is a new two-byte operand. Decide what it indexes: "+
					"if it is a constant-pool index add it to ConstantOperands (or every "+
					"constant-pool reordering will silently corrupt it), then record the "+
					"decision here.", key)
			}

			declared := false
			for _, slot := range ConstantOperands[op] {
				if slot == operand {
					declared = true
				}
			}

			if isConstant && !declared {
				t.Errorf("%s indexes the constant pool but is missing from ConstantOperands", key)
			}
			if !isConstant && declared {
				t.Errorf("%s does not index the constant pool but ConstantOperands claims it does", key)
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
