package compiler

// Bytecode container versions.
//
// The version travels in ByteCode.Version and decides how an OpGetBuiltin
// operand is read. It is not a compatibility flag for the instruction set: an
// opcode's meaning has never depended on it, and a change there would need a
// different mechanism.
const (
	// BytecodeVersionOrdinalBuiltins is everything compiled up to and including
	// v2.4.0, when OpGetBuiltin carried an ordinal into the global builtin
	// registry. Such bytecode has no Version field at all, so it decodes to 0
	// and normalises to this. Its operands resolve through the frozen snapshot
	// in builtin/legacy_ordinals.go.
	BytecodeVersionOrdinalBuiltins = 1

	// BytecodeVersionNamedBuiltins is bytecode that carries ByteCode.BuiltinNames
	// and whose OpGetBuiltin operand indexes that table. (L-1)
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
