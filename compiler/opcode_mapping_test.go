package compiler

import (
	"mutant/code"
	"testing"
)

// The mapping must cover every opcode the code package defines.
//
// This test used to carry its own hand-written list of opcodes and compare the
// mapping against that. The engine carried a second hand-written list. Both
// fell two opcodes behind the code package together (OpGreaterEqual and
// OpSetIndex), so the test agreed with the implementation and the drift was
// invisible. Both now derive from code.AllOpcodes.
func TestGenerateOpcodeMapping(t *testing.T) {
	engine := NewPolymorphicEngine(7, 12345)
	mapping := engine.generateOpcodeMapping()

	opcodes := code.AllOpcodes()

	for _, opcode := range opcodes {
		if _, exists := mapping[opcode]; !exists {
			def, err := code.Lookup(byte(opcode))
			name := "?"
			if err == nil {
				name = def.Name
			}
			t.Errorf("opcode %d (%s) is defined but missing from the mapping", opcode, name)
		}
	}

	if len(mapping) != len(opcodes) {
		t.Errorf("expected %d opcode mappings, got %d", len(opcodes), len(mapping))
	}
}

// The mapping has to be a bijection. A partial or many-to-one mapping is worse
// than no mapping at all: two opcodes collide on one value and the stream
// decodes as something else entirely.
//
// The old check here was `if orig < 0 || mapped < 0`, which cannot fire --
// code.Opcode is a byte.
func TestOpcodeMappingIsABijection(t *testing.T) {
	engine := NewPolymorphicEngine(7, 12345)
	mapping := engine.generateOpcodeMapping()

	seen := make(map[code.Opcode]code.Opcode, len(mapping))
	for orig, mapped := range mapping {
		if _, err := code.Lookup(byte(mapped)); err != nil {
			t.Errorf("opcode %d maps to %d, which is not a defined opcode", orig, mapped)
		}
		if prev, collision := seen[mapped]; collision {
			t.Errorf("opcodes %d and %d both map to %d", prev, orig, mapped)
		}
		seen[mapped] = orig
	}

	if len(seen) != len(mapping) {
		t.Errorf("mapping is not one-to-one: %d inputs collapsed onto %d outputs", len(mapping), len(seen))
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
