package compiler

import (
	"testing"

	"mutant/builtin"
	"mutant/code"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
)

// newBuiltinTable is the symbol table a real compilation starts from: every
// builtin defined at the top level.
func newBuiltinTable() *SymbolTable {
	table := NewSymbolTable()
	for i, def := range builtin.Builtins {
		table.DefineBuiltin(i, def.Name)
	}
	return table
}

// compileSource compiles src on the given symbol table, the way a REPL does when
// it carries one table and one constant pool across lines.
func compileSource(t *testing.T, table *SymbolTable, constants []object.Object, src string) *ByteCode {
	t.Helper()
	program := parser.New(lexer.New(src)).ParseProgram()
	comp := NewWithState(table, constants)
	if err := comp.Compile(program); err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return comp.ByteCode()
}

// nameTableIndices reads every OpGetBuiltin operand out of an instruction
// stream, checks each carries code.BuiltinNameTableFlag, and returns the index
// underneath. The flag check is not incidental: an untagged operand is what a
// pre-v2.5 runtime would read as a registry ordinal.
func nameTableIndices(t *testing.T, ins code.Instructions) []int {
	t.Helper()
	indices := []int{}
	for _, operand := range operandsOf(t, ins) {
		if operand&code.BuiltinNameTableFlag == 0 {
			t.Fatalf("OpGetBuiltin operand %d is missing the name-table flag", operand)
		}
		indices = append(indices, operand&^code.BuiltinNameTableFlag)
	}
	return indices
}

// operandsOf reads every OpGetBuiltin operand out of an instruction stream, in
// order, exactly as encoded.
func operandsOf(t *testing.T, ins code.Instructions) []int {
	t.Helper()
	operands := []int{}
	for ip := 0; ip < len(ins); {
		op := code.Opcode(ins[ip])
		def, err := code.Lookup(byte(op))
		if err != nil {
			t.Fatalf("undecodable opcode %d at %d: %v", op, ip, err)
		}
		read, width := code.ReadOperands(def, ins[ip+1:])
		if op == code.OpGetBuiltin {
			operands = append(operands, read[0])
		}
		ip += 1 + width
	}
	return operands
}

// TestBuiltinOperandIsNotARegistryOrdinal is the whole point stated as an
// assertion: the instruction stream must not carry a position in the global
// builtin registry, because that is what made the registry append-only forever.
//
// push is deliberately chosen -- it sits well down the registry, so an operand
// that accidentally went back to being an ordinal could not coincide with its
// first-use index.
func TestBuiltinOperandIsNotARegistryOrdinal(t *testing.T) {
	ordinal := -1
	for i, def := range builtin.Builtins {
		if def.Name == "push" {
			ordinal = i
			break
		}
	}
	if ordinal <= 0 {
		t.Fatalf("push is at registry ordinal %d; this test needs it to be non-zero", ordinal)
	}

	bytecode := compileSource(t, newBuiltinTable(), nil, `push([], 1);`)

	raw := operandsOf(t, bytecode.Instructions)
	if len(raw) != 1 {
		t.Fatalf("want 1 OpGetBuiltin, got %d", len(raw))
	}
	if raw[0] == ordinal {
		t.Fatalf("operand is the registry ordinal %d; it must index the program's own name table", ordinal)
	}
	if raw[0] <= len(builtin.Builtins) {
		t.Fatalf("operand %d is within the registry's %d entries, so a pre-v2.5 runtime would read it "+
			"as an ordinal and silently call the wrong builtin", raw[0], len(builtin.Builtins))
	}

	operands := nameTableIndices(t, bytecode.Instructions)
	if operands[0] != 0 {
		t.Fatalf("push is the program's first referenced builtin, so its index should be 0, got %d", operands[0])
	}
	if got := bytecode.BuiltinNames; len(got) != 1 || got[0] != "push" {
		t.Fatalf("BuiltinNames = %v, want [push]", got)
	}
}

func TestReferencedBuiltinsListsOnlyWhatTheProgramCalls(t *testing.T) {
	bytecode := compileSource(t, newBuiltinTable(), nil, `len([]); push([], 1); len([1]);`)

	want := []string{"len", "push"}
	if len(bytecode.BuiltinNames) != len(want) {
		t.Fatalf("BuiltinNames = %v, want %v", bytecode.BuiltinNames, want)
	}
	for i, name := range want {
		if bytecode.BuiltinNames[i] != name {
			t.Fatalf("BuiltinNames = %v, want %v (first-use order)", bytecode.BuiltinNames, want)
		}
	}

	// Three calls, two distinct builtins: the repeat must reuse len's index
	// rather than appending a second entry.
	operands := nameTableIndices(t, bytecode.Instructions)
	if len(operands) != 3 {
		t.Fatalf("want 3 OpGetBuiltin operands, got %v", operands)
	}
	if operands[0] != 0 || operands[1] != 1 || operands[2] != 0 {
		t.Fatalf("operands = %v, want [0 1 0]", operands)
	}
}

// TestBuiltinIndicesSurviveASharedSymbolTable is the regression the interning
// table lives on the symbol table to prevent.
//
// A REPL builds a fresh Compiler per line but keeps one symbol table and one
// constant pool. A closure compiled on line 1 goes into that pool with its
// operands already baked, and is called on line 3 against line 3's bytecode. If
// each Compiler restarted interning at 0, line 1's `len` operand would resolve
// through line 3's table and call whatever builtin happened to land at index 0.
func TestBuiltinIndicesSurviveASharedSymbolTable(t *testing.T) {
	table := newBuiltinTable()

	first := compileSource(t, table, nil, `let f = fn() { len([]) };`)
	second := compileSource(t, table, first.Constants, `push([], 1);`)

	if got := nameTableIndices(t, second.Instructions); len(got) != 1 || got[0] != 1 {
		t.Fatalf("second line's push operand = %v, want [1]: a shared table must keep appending", got)
	}
	want := []string{"len", "push"}
	if len(second.BuiltinNames) != 2 || second.BuiltinNames[0] != want[0] || second.BuiltinNames[1] != want[1] {
		t.Fatalf("BuiltinNames = %v, want %v: line 1's entry must still be at its original index",
			second.BuiltinNames, want)
	}

	// The closure compiled on line 1 is a constant carried into line 2, and its
	// baked operand must still name len under line 2's table.
	if len(second.BuiltinNames) > 0 && second.BuiltinNames[0] != "len" {
		t.Fatalf("index 0 was reassigned from len to %q", second.BuiltinNames[0])
	}
}

func TestNestedScopesShareOneBuiltinTable(t *testing.T) {
	bytecode := compileSource(t, newBuiltinTable(), nil, `let f = fn() { len([]) }; len([1]);`)
	if len(bytecode.BuiltinNames) != 1 || bytecode.BuiltinNames[0] != "len" {
		t.Fatalf("BuiltinNames = %v, want [len]: a call inside a function body and one at the top "+
			"level must intern to the same entry", bytecode.BuiltinNames)
	}
}

func TestByteCodeCarriesTheContainerVersion(t *testing.T) {
	bytecode := compileSource(t, newBuiltinTable(), nil, `len([]);`)
	if bytecode.Version != BytecodeVersionNamedBuiltins {
		t.Fatalf("Version = %d, want %d", bytecode.Version, BytecodeVersionNamedBuiltins)
	}
}

func TestNormalizeVersionTreatsAbsentAsOrdinalBuiltins(t *testing.T) {
	// gob omits a zero int, so bytecode written before the field existed decodes
	// to 0 -- which must mean "the ordinal era", not "version zero".
	for _, absent := range []int{0, -1} {
		if got := NormalizeVersion(absent); got != BytecodeVersionOrdinalBuiltins {
			t.Fatalf("NormalizeVersion(%d) = %d, want %d", absent, got, BytecodeVersionOrdinalBuiltins)
		}
	}
	if got := NormalizeVersion(BytecodeVersionNamedBuiltins); got != BytecodeVersionNamedBuiltins {
		t.Fatalf("NormalizeVersion left a real version alone: got %d", got)
	}
}
