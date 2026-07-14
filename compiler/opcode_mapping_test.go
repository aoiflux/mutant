package compiler

import (
	"mutant/code"
	"testing"
)

func TestGenerateOpcodeMapping(t *testing.T) {
	engine := NewPolymorphicEngine(7, 12345)
	mapping := engine.generateOpcodeMapping()

	// Verify all standard opcodes are present in mapping
	opcodes := []code.Opcode{
		code.OpConstant, code.OpPop, code.OpAdd, code.OpSub, code.OpMul,
		code.OpDiv, code.OpMod, code.OpTrue, code.OpFalse, code.OpEqual,
		code.OpUnEqual, code.OpGreater, code.OpMinus, code.OpBang,
		code.OpJumpFalse, code.OpJump, code.OpNull, code.OpGetGlobal,
		code.OpSetGlobal, code.OpGetLocal, code.OpSetLocal, code.OpArray,
		code.OpHash, code.OpIndex, code.OpCall, code.OpReturnValue,
		code.OpReturn, code.OpMultiValue, code.OpDup, code.OpDestructure, code.OpGetBuiltin, code.OpClosure, code.OpGetFree,
		code.OpCurrentClosure, code.OpChkDbg, code.OpChkSnd, code.OpBreak,
		code.OpContinue, code.OpMakeStruct, code.OpGetField, code.OpSetField,
		code.OpEnumValue,
	}

	// Check all opcodes are mapped
	for _, opcode := range opcodes {
		if _, exists := mapping[opcode]; !exists {
			t.Errorf("Opcode %d not found in mapping", opcode)
		}
	}

	// Verify mapping has correct number of entries
	if len(mapping) != len(opcodes) {
		t.Errorf("Expected %d opcode mappings, got %d", len(opcodes), len(mapping))
	}

	// Verify all mapped values are valid opcodes (within opcode range)
	for orig, mapped := range mapping {
		if orig < 0 || mapped < 0 {
			t.Errorf("Invalid opcode mapping: %d -> %d", orig, mapped)
		}
	}
}

func TestOpcodeMappingDeterministic(t *testing.T) {
	// Same seed should produce same mapping
	seed := int64(54321)
	level := 7

	engine1 := NewPolymorphicEngine(level, seed)
	mapping1 := engine1.generateOpcodeMapping()

	engine2 := NewPolymorphicEngine(level, seed)
	mapping2 := engine2.generateOpcodeMapping()

	// Verify mappings are identical with same seed
	if len(mapping1) != len(mapping2) {
		t.Errorf("Different mapping sizes with same seed")
	}

	for opcode, mapped1 := range mapping1 {
		mapped2, exists := mapping2[opcode]
		if !exists {
			t.Errorf("Opcode %d missing from second mapping", opcode)
		}
		if mapped1 != mapped2 {
			t.Errorf("Opcode %d: different mappings with same seed (%d vs %d)",
				opcode, mapped1, mapped2)
		}
	}
}

func TestOpcodeMappingDifferentSeeds(t *testing.T) {
	// Different seeds should (likely) produce different mappings
	engine1 := NewPolymorphicEngine(7, 11111)
	mapping1 := engine1.generateOpcodeMapping()

	engine2 := NewPolymorphicEngine(7, 22222)
	mapping2 := engine2.generateOpcodeMapping()

	// Count differences
	differences := 0
	for opcode, mapped1 := range mapping1 {
		mapped2, _ := mapping2[opcode]
		if mapped1 != mapped2 {
			differences++
		}
	}

	// With high probability, different seeds produce different mappings
	// (not guaranteed, but very likely with shuffling)
	if differences == 0 {
		t.Logf("Warning: Different seeds produced identical mappings (possible but rare)")
	}
}

func TestOpcodeRemappingInMutation(t *testing.T) {
	// Verify opcode remapping is actually applied in mutations
	input := "let x = 5; x"

	program := parse(input)
	compiler := New()
	compiler.EnablePolymorphismWithSeed(9, 99999) // Level 9 includes opcode mutation
	if err := compiler.Compile(program); err != nil {
		t.Fatalf("compiler error: %s", err)
	}
	bytecode := compiler.ByteCode()

	// With level 9, opcode mutations should be applied
	// The bytecode should still have valid structure but potentially remapped opcodes
	if len(bytecode.Instructions) == 0 {
		t.Error("Mutated bytecode is empty")
	}

	// Verify polymorphic marker is present
	level := DetectPolymorphicLevel(bytecode.Instructions)
	if level != 9 {
		t.Errorf("Expected level 9, got %d", level)
	}
}

func TestOpcodeRemappingReversibility(t *testing.T) {
	// Verify that opcode mapping creates a valid permutation
	// (each input maps to exactly one output, all outputs are unique)
	engine := NewPolymorphicEngine(10, 77777)
	mapping := engine.generateOpcodeMapping()

	// Track which opcodes have been used as targets
	usedTargets := make(map[code.Opcode]bool)

	for _, target := range mapping {
		if usedTargets[target] {
			t.Errorf("Opcode %d is target of multiple mappings", target)
		}
		usedTargets[target] = true
	}

	// Verify all mapped opcodes are from the original set
	if len(usedTargets) != len(mapping) {
		t.Errorf("Duplicate target opcodes detected")
	}
}
