package compiler

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"math/big"
	mathrand "math/rand"
	"mutant/code"
	"mutant/object"
)

// PolymorphicEngine generates functionally equivalent but structurally different bytecode
type PolymorphicEngine struct {
	mutationLevel int            // 0-10: intensity of mutations
	randomSeed    int64          // seed for reproducible builds
	rng           *mathrand.Rand // deterministic RNG for reproducible opcode mapping
}

// MutationConfig controls which mutations are applied
type MutationConfig struct {
	InsertNOPs          bool
	ReorderInstructions bool
	MutateOpcodes       bool
	InsertDeadCode      bool
	RandomizeConstants  bool
	Level               int // 0-10
}

// NewPolymorphicEngine creates a new polymorphic engine
func NewPolymorphicEngine(level int, seed int64) *PolymorphicEngine {
	if level < 0 {
		level = 0
	}
	if level > 10 {
		level = 10
	}

	return &PolymorphicEngine{
		mutationLevel: level,
		randomSeed:    seed,
		rng:           mathrand.New(mathrand.NewSource(seed)),
	}
}

// Mutate applies polymorphic transformations to bytecode
func (pe *PolymorphicEngine) Mutate(bytecode *ByteCode) *ByteCode {
	if pe.mutationLevel == 0 {
		return bytecode // No mutations
	}

	config := pe.getConfig()

	// Apply mutations in stages
	if config.InsertNOPs {
		bytecode.Instructions = pe.insertNOPs(bytecode.Instructions)
	}

	if config.MutateOpcodes {
		bytecode = pe.mutateOpcodes(bytecode)
	}

	if config.RandomizeConstants {
		bytecode = pe.randomizeConstantPool(bytecode)
	}

	// Add polymorphic marker to indicate mutation level
	bytecode.Instructions = pe.AddPolymorphicMarker(bytecode.Instructions)

	return bytecode
}

// getConfig returns mutation configuration based on level
func (pe *PolymorphicEngine) getConfig() MutationConfig {
	safeStagesEnabled := polymorphicSafeStagesEnabled()

	return MutationConfig{
		// These transformations are intentionally gated off until instruction-boundary
		// aware rewriting and opcode remap reversal are implemented in VM/runtime.
		InsertNOPs:          false,
		ReorderInstructions: false,
		MutateOpcodes:       false,
		InsertDeadCode:      false,
		// First safe stage: deterministic constant-pool randomization with
		// instruction-boundary aware reference rewriting.
		RandomizeConstants: safeStagesEnabled && pe.mutationLevel >= 6,
		Level:              pe.mutationLevel,
	}
}

func polymorphicSafeStagesEnabled() bool {
	return true
}

// insertNOPs inserts no-operation instructions
func (pe *PolymorphicEngine) insertNOPs(instructions code.Instructions) code.Instructions {
	if len(instructions) == 0 {
		return instructions
	}

	// Calculate NOP insertion rate based on level
	// Level 3: ~5%, Level 10: ~15%
	insertionRate := float64(pe.mutationLevel) * 1.5 / 100.0

	result := make(code.Instructions, 0, int(float64(len(instructions))*(1+insertionRate)))

	for i := 0; i < len(instructions); i++ {
		result = append(result, instructions[i])

		// Randomly insert NOP after this instruction
		if pe.shouldInsertNOP(insertionRate) {
			nop := pe.generateNOP()
			result = append(result, nop...)
		}
	}

	return result
}

// shouldInsertNOP determines if a NOP should be inserted using cryptographic randomness
func (pe *PolymorphicEngine) shouldInsertNOP(rate float64) bool {
	max := big.NewInt(100)
	n, _ := cryptorand.Int(cryptorand.Reader, max)
	return float64(n.Int64()) < rate*100
}

// generateNOP creates a no-operation instruction sequence
func (pe *PolymorphicEngine) generateNOP() code.Instructions {
	// Generate different types of NOPs randomly
	nopType := pe.randomIntCrypto(4)

	switch nopType {
	case 0:
		// Push null then pop
		return append(code.Make(code.OpNull), code.Make(code.OpPop)...)
	case 1:
		// Push true then pop
		return append(code.Make(code.OpTrue), code.Make(code.OpPop)...)
	case 2:
		// Push false then pop
		return append(code.Make(code.OpFalse), code.Make(code.OpPop)...)
	default:
		// Just OpPop (safe if stack has something)
		return code.Make(code.OpPop)
	}
}

// mutateOpcodes remaps opcodes to different values
func (pe *PolymorphicEngine) mutateOpcodes(bytecode *ByteCode) *ByteCode {
	// Create a random opcode mapping
	mapping := pe.generateOpcodeMapping()

	// Apply mapping to instructions
	newInstructions := make(code.Instructions, len(bytecode.Instructions))
	copy(newInstructions, bytecode.Instructions)

	for i := 0; i < len(newInstructions); i++ {
		// Check if this is an opcode position
		if mapped, ok := mapping[code.Opcode(newInstructions[i])]; ok {
			newInstructions[i] = byte(mapped)
		}
	}

	// Apply mapping to compiled functions in constants
	for i, constant := range bytecode.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			newFnInsts := make(code.Instructions, len(fn.Instructions))
			copy(newFnInsts, fn.Instructions)

			for j := 0; j < len(newFnInsts); j++ {
				if mapped, ok := mapping[code.Opcode(newFnInsts[j])]; ok {
					newFnInsts[j] = byte(mapped)
				}
			}

			fn.Instructions = newFnInsts
			bytecode.Constants[i] = fn
		}
	}

	bytecode.Instructions = newInstructions
	return bytecode
}

// generateOpcodeMapping creates a random but valid opcode remapping using deterministic RNG.
//
// The set comes from code.AllOpcodes rather than a list written out here. The
// hand-written list had fallen two opcodes behind the code package
// (OpGreaterEqual and OpSetIndex), and a partial remapping is worse than none:
// the opcodes present get new values while the absent ones keep theirs, so the
// two collide and the program silently decodes as something else.
//
// This stage is gated off in getConfig (the VM has no reverse mapping), so the
// drift was latent. Deriving the set means it stays correct if the stage is
// ever turned on.
func (pe *PolymorphicEngine) generateOpcodeMapping() map[code.Opcode]code.Opcode {
	opcodes := code.AllOpcodes()

	// Create a copy for shuffling
	shuffled := make([]code.Opcode, len(opcodes))
	copy(shuffled, opcodes)

	// Fisher-Yates shuffle using deterministic RNG for reproducible opcode mapping
	for i := len(shuffled) - 1; i > 0; i-- {
		j := pe.rng.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	// Create mapping from original opcode to shuffled opcode
	mapping := make(map[code.Opcode]code.Opcode)
	for i, orig := range opcodes {
		mapping[orig] = shuffled[i]
	}

	return mapping
}

// randomizeConstantPool shuffles constant pool indices
func (pe *PolymorphicEngine) randomizeConstantPool(bytecode *ByteCode) *ByteCode {
	if len(bytecode.Constants) <= 1 {
		return bytecode
	}

	// Create a shuffled index mapping
	mapping := pe.generateShuffleMapping(len(bytecode.Constants))

	// Reorder constants
	newConstants := make([]object.Object, len(bytecode.Constants))
	for oldIdx, newIdx := range mapping {
		newConstants[newIdx] = bytecode.Constants[oldIdx]
	}

	// Update all OpConstant instructions
	bytecode.Instructions = pe.updateConstantReferences(bytecode.Instructions, mapping)

	// Update references in compiled functions
	for i, constant := range newConstants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			fn.Instructions = pe.updateConstantReferences(fn.Instructions, mapping)
			newConstants[i] = fn
		}
	}

	bytecode.Constants = newConstants
	return bytecode
}

// generateShuffleMapping creates a random permutation
func (pe *PolymorphicEngine) generateShuffleMapping(size int) []int {
	mapping := make([]int, size)
	for i := range mapping {
		mapping[i] = i
	}

	// Fisher-Yates shuffle using deterministic RNG
	for i := size - 1; i > 0; i-- {
		j := pe.rng.Intn(i + 1)
		mapping[i], mapping[j] = mapping[j], mapping[i]
	}

	return mapping
}

// updateConstantReferences rewrites every operand that indexes the constant
// pool so it follows its constant to the pool's new position.
//
// It walks instruction-by-instruction using the operand widths rather than
// scanning for opcode bytes, because an operand byte can hold any value and
// would otherwise be mistaken for an opcode.
//
// Which operands to rewrite comes from code.ConstantOperands, not from a list
// kept here: this used to rewrite only OpConstant, which left closures, struct
// literals, field access and enum values pointing at whatever the shuffle had
// moved into their old slots. Those programs compiled without complaint and
// died inside the VM.
func (pe *PolymorphicEngine) updateConstantReferences(instructions code.Instructions, mapping []int) code.Instructions {
	result := make(code.Instructions, len(instructions))
	copy(result, instructions)

	for i := 0; i < len(result); {
		def, err := code.Lookup(result[i])
		if err != nil {
			break
		}

		instLen := 1
		for _, width := range def.OperandWidths {
			instLen += width
		}
		if i+instLen > len(result) {
			break
		}

		slots := code.ConstantOperands[code.Opcode(result[i])]

		offset := i + 1
		for operand, width := range def.OperandWidths {
			if width == 2 && containsInt(slots, operand) {
				oldIdx := binary.BigEndian.Uint16(result[offset : offset+2])
				if int(oldIdx) < len(mapping) {
					binary.BigEndian.PutUint16(result[offset:offset+2], uint16(mapping[oldIdx]))
				}
			}
			offset += width
		}

		i += instLen
	}

	return result
}

func containsInt(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// randomIntCrypto generates a random integer in range [0, max) using cryptographic randomness
func (pe *PolymorphicEngine) randomIntCrypto(max int) int {
	if max <= 0 {
		return 0
	}

	n, _ := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

// AddPolymorphicMarker adds metadata to bytecode indicating polymorphic level
func (pe *PolymorphicEngine) AddPolymorphicMarker(instructions code.Instructions) code.Instructions {
	// Add a marker byte at the end indicating mutation level
	// Format: [original_instructions][0xFF][level]
	marker := []byte{0xFF, byte(pe.mutationLevel)}
	return append(instructions, marker...)
}

// DetectPolymorphicLevel reports the mutation level recorded in a trailing
// marker, or 0 if the last two bytes do not look like one.
//
// This is a heuristic and cannot be anything else: the marker is [0xFF, level]
// appended to an instruction stream, with nothing to distinguish it from
// instruction bytes that happen to end the same way. A program with 256
// constants ending in `OpConstant 255` (0x00 0x00 0xFF) followed by OpPop ends
// in 0xFF 0x01 and reads as "level 1".
//
// So it must never be used to decide whether to truncate. Doing that cut two
// real bytes from roughly a third of such programs, which then failed in the VM
// on "not enough bytes for operand". Ask the compiler instead:
// Compiler.PolymorphicLevel reports what was actually applied.
//
// It remains useful for asserting in tests that a marker was written, where the
// bytecode is known to be mutated.
func DetectPolymorphicLevel(instructions code.Instructions) int {
	if len(instructions) < 2 {
		return 0
	}

	// A level above the documented 0-10 range is not a marker this engine wrote.
	if instructions[len(instructions)-2] == 0xFF {
		if level := int(instructions[len(instructions)-1]); level <= 10 {
			return level
		}
	}

	return 0
}
