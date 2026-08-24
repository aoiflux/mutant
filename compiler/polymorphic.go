package compiler

import (
	"encoding/binary"
	"math"
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

// Mutate applies polymorphic transformations to bytecode.
//
// The order of the stages is load-bearing. NOP insertion and constant-pool
// randomization both walk the instruction stream by operand width, so they have
// to run while the opcode bytes still mean what code.Lookup says they mean.
// Opcode remapping destroys that and therefore runs last. It used to run in the
// middle, which would have left the constant-pool pass parsing a remapped
// stream -- one more reason the stage could not simply be switched on.
func (pe *PolymorphicEngine) Mutate(bytecode *ByteCode) *ByteCode {
	if pe.mutationLevel == 0 {
		return bytecode // No mutations
	}

	config := pe.getConfig()

	// Apply mutations in stages
	if config.InsertNOPs {
		bytecode = pe.insertNOPs(bytecode)
	}

	if config.RandomizeConstants {
		bytecode = pe.randomizeConstantPool(bytecode)
	}

	if config.MutateOpcodes {
		bytecode = pe.mutateOpcodes(bytecode)
	}

	// Add polymorphic marker to indicate mutation level
	bytecode.Instructions = pe.AddPolymorphicMarker(bytecode.Instructions)

	return bytecode
}

// getConfig returns mutation configuration based on level.
//
// Every implemented stage engages at any non-zero level. It used to take level 6
// to reach the only working stage while the CLI defaulted to 5, so the default
// shipped bytecode that had been through the engine and come out unchanged.
func (pe *PolymorphicEngine) getConfig() MutationConfig {
	active := polymorphicSafeStagesEnabled() && pe.mutationLevel >= 1

	return MutationConfig{
		// Splices stack-neutral instructions in and repoints the jump targets
		// they displace (code.JumpOperands). Its density scales with the level,
		// so this is the one stage where 1..10 grades rather than switches.
		InsertNOPs: active,
		// Permutes the instruction set and ships the inverse in
		// ByteCode.OpcodeMap; the VM applies it on every opcode fetch.
		MutateOpcodes: active,
		// Reorders the constant pool and rewrites the operands that index it
		// (code.ConstantOperands).
		RandomizeConstants: active,

		// Neither of these has an implementation anywhere in the package. They
		// are not stages held back by a flag, they are names with nothing behind
		// them, kept because MutationConfig is the record of what the engine
		// could grow. Setting either true does nothing at all.
		ReorderInstructions: false,
		InsertDeadCode:      false,

		Level: pe.mutationLevel,
	}
}

func polymorphicSafeStagesEnabled() bool {
	return true
}

// insertNOPs splices stack-neutral instructions into every instruction stream in
// the program -- the main one and each compiled function in the constant pool.
//
// The previous version walked the main stream a byte at a time, appended NOPs
// after arbitrary bytes rather than after instructions, and never touched a jump
// operand. Jump targets are absolute offsets, so a single inserted byte ahead of
// one silently redirects it into the middle of an instruction; the VM's
// control-flow integrity check then reports the program as tampered with. That
// is why the stage was gated off rather than fixed.
func (pe *PolymorphicEngine) insertNOPs(bytecode *ByteCode) *ByteCode {
	// Level 1: ~1.5% of instruction boundaries. Level 10: ~15%.
	rate := float64(pe.mutationLevel) * 1.5 / 100.0

	// Only the main stream needs its tail protected: LastPoppedStackElement reads
	// the slot above the stack pointer once the program has finished, so it is
	// the main stream's final pop that decides it. A function body's pops all
	// happen earlier, inside a frame that has since been unwound.
	bytecode.Instructions = pe.padInstructions(bytecode.Instructions, rate, true)

	for _, constant := range bytecode.Constants {
		fn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}
		fn.Instructions = pe.padInstructions(fn.Instructions, rate, false)
	}

	return bytecode
}

// padInstructions returns ins with NOPs spliced in and every jump operand
// repointed at its instruction's new offset.
//
// It hands back ins untouched whenever the stream does not add up -- an
// undecodable opcode, an instruction running off the end, a jump to an offset
// that is not an instruction boundary, an offset a uint16 operand cannot hold.
// Declining to mutate is always available; a half-rewritten stream is not
// recoverable, and obfuscation is never worth a corrupted program.
func (pe *PolymorphicEngine) padInstructions(ins code.Instructions, rate float64, protectFinalPop bool) code.Instructions {
	starts, widths, ok := decodeBoundaries(ins)
	if !ok || len(starts) == 0 {
		return ins
	}

	// Nothing is spliced in at or after cutoff.
	cutoff := starts[len(starts)-1] // never after the last instruction
	if protectFinalPop {
		cutoff = lastPopOffset(ins, starts)
	}

	// remap[oldOffset] is where that same instruction begins once padded.
	remap := make(map[int]int, len(starts)+1)
	padded := make(code.Instructions, 0, len(ins)+len(ins)/4)

	for i, start := range starts {
		remap[start] = len(padded)
		padded = append(padded, ins[start:start+widths[i]]...)

		if start < cutoff && pe.rng.Float64() < rate {
			padded = append(padded, pe.generateNOP()...)
		}
	}
	// A jump to one past the end means "leave this stream", and stays that.
	remap[len(ins)] = len(padded)

	if !rewriteJumpTargets(padded, remap) {
		return ins
	}

	return padded
}

// lastPopOffset returns the offset of the final OpPop in ins, which is the
// last insertion point padding may use. Nothing may be spliced in at or after
// it.
//
// A NOP is a push and a pop, so one placed after the program's final OpPop
// becomes the last pop -- and VM.LastPoppedStackElement, which is what the CLI
// prints and what the REPL echoes, then reports the NOP's value instead of the
// program's result. Guarding only the final *instruction* is not enough: when
// the compiler injects the required security checks it appends OpChkDbg and
// OpChkSnd after that OpPop, leaving two legal-looking insertion points past the
// end of the program's own value. Roughly one build in sixteen printed a stray
// `true`.
//
// Returning 0 when there is no OpPop disables padding for that stream, which is
// right: a stream with nothing to pop is a handful of instructions where padding
// buys nothing.
func lastPopOffset(ins code.Instructions, starts []int) int {
	for i := len(starts) - 1; i >= 0; i-- {
		if code.Opcode(ins[starts[i]]) == code.OpPop {
			return starts[i]
		}
	}
	return 0
}

// decodeBoundaries returns the start offset and total width of every
// instruction in ins, or ok=false if the stream cannot be decoded end to end.
func decodeBoundaries(ins code.Instructions) (starts, widths []int, ok bool) {
	for i := 0; i < len(ins); {
		def, err := code.Lookup(ins[i])
		if err != nil {
			return nil, nil, false
		}

		width := 1
		for _, w := range def.OperandWidths {
			width += w
		}
		if i+width > len(ins) {
			return nil, nil, false
		}

		starts = append(starts, i)
		widths = append(widths, width)
		i += width
	}

	return starts, widths, true
}

// rewriteJumpTargets repoints every operand named in code.JumpOperands through
// remap, in place.
//
// Reports false if a target is not an instruction boundary of the original
// stream, or if its new offset no longer fits the two-byte operand. Either way
// the caller must discard the padded stream rather than ship a jump landing
// mid-instruction.
func rewriteJumpTargets(padded code.Instructions, remap map[int]int) bool {
	for i := 0; i < len(padded); {
		def, err := code.Lookup(padded[i])
		if err != nil {
			return false
		}

		width := 1
		for _, w := range def.OperandWidths {
			width += w
		}
		if i+width > len(padded) {
			return false
		}

		slots := code.JumpOperands[code.Opcode(padded[i])]

		offset := i + 1
		for operand, w := range def.OperandWidths {
			if w == 2 && containsInt(slots, operand) {
				old := int(binary.BigEndian.Uint16(padded[offset : offset+2]))
				target, known := remap[old]
				if !known || target > math.MaxUint16 {
					return false
				}
				binary.BigEndian.PutUint16(padded[offset:offset+2], uint16(target))
			}
			offset += w
		}

		i += width
	}

	return true
}

// generateNOP returns a stack-neutral instruction pair: push a value, drop it
// again. The variants differ only so the padding does not read as one repeated
// signature.
//
// A bare OpPop used to be one of the four choices, commented "safe if stack has
// something". It is not safe: the stack at an arbitrary instruction boundary
// holds values belonging to the expression in progress, and popping one discards
// it. Randomness decided whether a program was correct.
func (pe *PolymorphicEngine) generateNOP() code.Instructions {
	push := code.OpNull
	switch pe.rng.Intn(3) {
	case 0:
		push = code.OpTrue
	case 1:
		push = code.OpFalse
	}

	return append(code.Make(push), code.Make(code.OpPop)...)
}

// mutateOpcodes replaces every opcode byte with its image under a seeded
// permutation of the instruction set, and records the inverse in
// ByteCode.OpcodeMap so the VM can read the result.
//
// Two separate things were wrong with the version this replaces, and either
// alone made the stage unusable. It walked each stream one byte at a time and
// rewrote anything that matched an opcode, so an operand byte holding a value
// that happens to equal an opcode was rewritten as though it were one. And
// nothing carried the inverse to the runtime, so even a correct rewrite produced
// a program no VM could decode -- which is what "the VM has no reverse mapping"
// in the old gating comment meant.
//
// All or nothing: every stream is rewritten or none is. A program with some
// streams remapped and some not cannot be described by one inverse table, since
// applying it would destroy the streams that were left alone.
func (pe *PolymorphicEngine) mutateOpcodes(bytecode *ByteCode) *ByteCode {
	forward, reverse := opcodeTables(pe.generateOpcodeMapping())

	remapped, ok := remapOpcodes(bytecode.Instructions, forward)
	if !ok {
		return bytecode
	}

	fnStreams := make([]code.Instructions, 0, len(bytecode.Constants))
	for _, constant := range bytecode.Constants {
		fn, isFn := constant.(*object.CompiledFunction)
		if !isFn {
			continue
		}

		fnRemapped, fnOK := remapOpcodes(fn.Instructions, forward)
		if !fnOK {
			return bytecode
		}
		fnStreams = append(fnStreams, fnRemapped)
	}

	bytecode.Instructions = remapped
	next := 0
	for _, constant := range bytecode.Constants {
		fn, isFn := constant.(*object.CompiledFunction)
		if !isFn {
			continue
		}
		fn.Instructions = fnStreams[next]
		next++
	}
	bytecode.OpcodeMap = reverse

	return bytecode
}

// remapOpcodes rewrites the opcode byte of each instruction and leaves every
// operand byte exactly as it was, walking the stream by operand width so the two
// are never confused.
func remapOpcodes(ins code.Instructions, forward []byte) (code.Instructions, bool) {
	out := make(code.Instructions, len(ins))
	copy(out, ins)

	for i := 0; i < len(out); {
		def, err := code.Lookup(ins[i])
		if err != nil {
			return nil, false
		}

		width := 1
		for _, w := range def.OperandWidths {
			width += w
		}
		if i+width > len(out) {
			return nil, false
		}

		out[i] = forward[ins[i]]
		i += width
	}

	return out, true
}

// opcodeTables turns the permutation into the two 256-entry lookups the rewrite
// and the VM need: forward maps a real opcode to the byte written into the
// stream, reverse maps that byte back to the real opcode.
//
// Bytes that are not defined opcodes map to themselves in both directions, so an
// undecodable byte stays undecodable instead of being laundered into a valid
// instruction on the way through.
func opcodeTables(mapping map[code.Opcode]code.Opcode) (forward, reverse []byte) {
	forward = make([]byte, 256)
	reverse = make([]byte, 256)
	for i := range forward {
		forward[i] = byte(i)
		reverse[i] = byte(i)
	}

	for orig, mapped := range mapping {
		forward[byte(orig)] = byte(mapped)
		reverse[byte(mapped)] = byte(orig)
	}

	return forward, reverse
}

// generateOpcodeMapping creates a random but valid opcode remapping using deterministic RNG.
//
// The set comes from code.AllOpcodes rather than a list written out here. The
// hand-written list had fallen two opcodes behind the code package
// (OpGreaterEqual and OpSetIndex), and a partial remapping is worse than none:
// the opcodes present get new values while the absent ones keep theirs, so the
// two collide and the program silently decodes as something else.
//
// The stage was gated off when that drift went in, so it stayed latent. Deriving
// the set is what makes it safe to have turned the stage on: an opcode added to
// the code package joins the permutation without anyone remembering to.
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
