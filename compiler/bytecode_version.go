package compiler

// Bytecode container versions.
//
// The version travels in ByteCode.Version and decides how an OpGetBuiltin
// operand is read. It is not a compatibility flag for the instruction set: an
// opcode's meaning has never depended on it, and a change there would need a
// different mechanism.
//
// The instruction set is versioned by a different rule, which is worth stating
// because it looks like an omission. Opcodes are append-only: a value once
// emitted never changes meaning, and new ones go on the end. So old bytecode
// runs unchanged on a new runtime, always, and the only failing direction is new
// bytecode on an old runtime -- where the old runtime meets an opcode it does
// not know and stops, naming it. Bumping this constant would not help that
// runtime, which does not know the new version either; the guarantee is the
// append-only rule plus a refusal, not a number.
//
// That refusal is recent. Until the boxed-cell opcodes went in, the dispatch
// switch had no default arm: an unknown opcode matched nothing, the instruction
// pointer advanced by one, and the operand bytes were executed as opcodes. See
// VM.execLoop's default case.
const (
	// BytecodeVersionOrdinalBuiltins is everything compiled up to and including
	// v2.4.0, when OpGetBuiltin carried an ordinal into the global builtin
	// registry. Such bytecode has no Version field at all, so it decodes to 0
	// and normalises to this. Its operands resolve through the frozen snapshot
	// in builtin/legacy_ordinals.go.
	BytecodeVersionOrdinalBuiltins = 1

	// BytecodeVersionNamedBuiltins is bytecode that carries ByteCode.BuiltinNames
	// and whose OpGetBuiltin operand indexes that table.
	BytecodeVersionNamedBuiltins = 2

	// BytecodeVersion is what this build emits.
	BytecodeVersion = BytecodeVersionNamedBuiltins
)

// NormalizeVersion reports the container version of decoded bytecode, mapping
// the absent field of a pre-versioning artifact onto the version it implies.
func NormalizeVersion(version int) int {
	if version <= 0 {
		return BytecodeVersionOrdinalBuiltins
	}
	return version
}
