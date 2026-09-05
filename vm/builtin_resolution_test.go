package vm

import (
	"fmt"
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/code"
	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// compileFresh compiles src through the ordinary pipeline, unencrypted, so a
// test can rewrite the container before it is sealed.
func compileFresh(t *testing.T, src string) *compiler.ByteCode {
	t.Helper()
	comp := compiler.New()
	if err := comp.Compile(parse(src)); err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return comp.ByteCode()
}

// runSealed encrypts and runs bytecode the way the runner does. The VM refuses
// to execute an unencrypted stream, so every path into it goes through here.
func runSealed(t *testing.T, bc *compiler.ByteCode) (*VM, error) {
	t.Helper()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(bc.Instructions))
	bc = mutil.EncryptByteCode(bc, password)
	vm := NewWithGlobalStoreAndPassword(bc, make([]object.Object, global.GlobalSize), password)
	return vm, vm.Run()
}

// downgradeToOrdinalEra rewrites bytecode into exactly what a pre-v2.5 mutant
// would have produced: no Version field, no name table, and every OpGetBuiltin
// operand a position in the global registry.
//
// Reconstructing the old artifact from the new compiler is deliberate. A
// checked-in .mu fixture would rot the moment anything else about the container
// changed, and it would prove nothing this does not -- the three facts that
// define the old format are the three lines below.
func downgradeToOrdinalEra(t *testing.T, bc *compiler.ByteCode) *compiler.ByteCode {
	t.Helper()
	for _, constant := range bc.Constants {
		if _, isFn := constant.(*object.CompiledFunction); isFn {
			t.Fatal("this helper rewrites only the main instruction stream; " +
				"use a program without function literals")
		}
	}

	ins := bc.Instructions
	for ip := 0; ip < len(ins); {
		op := code.Opcode(ins[ip])
		def, err := code.Lookup(byte(op))
		if err != nil {
			t.Fatalf("undecodable opcode %d at %d: %v", op, ip, err)
		}
		operands, width := code.ReadOperands(def, ins[ip+1:])
		if op == code.OpGetBuiltin {
			if operands[0]&code.BuiltinNameTableFlag == 0 {
				t.Fatalf("operand %d at %d is missing the name-table flag", operands[0], ip)
			}
			name := bc.BuiltinNames[operands[0]&^code.BuiltinNameTableFlag]
			// Untagged, because the tag is what distinguishes the two eras.
			copy(ins[ip:], code.Make(code.OpGetBuiltin, registryOrdinalOf(t, name)))
		}
		ip += 1 + width
	}

	bc.Version = 0
	bc.BuiltinNames = nil
	return bc
}

func registryOrdinalOf(t *testing.T, name string) int {
	t.Helper()
	for i, def := range builtin.Builtins {
		if def.Name == name {
			return i
		}
	}
	t.Fatalf("builtin %q is not registered", name)
	return -1
}

// TestOrdinalEraBytecodeStillRuns is the compatibility contract: a .mu written
// before builtin names travelled with the program still runs. Its operands are
// registry positions and it has no Version field at all, which gob decodes to 0.
func TestOrdinalEraBytecodeStillRuns(t *testing.T) {
	// push is the program's SECOND referenced builtin, so its name-table index is
	// 1 while its registry ordinal is well past that. The downgrade genuinely
	// changes the operand; a test using only len (ordinal 0, index 0) would pass
	// without either format being exercised.
	if ordinal := registryOrdinalOf(t, "push"); ordinal <= 1 {
		t.Fatalf("push is at registry ordinal %d; this test needs it past the name-table index", ordinal)
	}

	bc := downgradeToOrdinalEra(t, compileFresh(t, `len(push([1, 2], 3));`))
	vm, err := runSealed(t, bc)
	if err != nil {
		t.Fatalf("ordinal-era bytecode failed to run: %v", err)
	}
	if result, ok := vm.LastPoppedStackElement().(*object.Integer); !ok || result.Value != 3 {
		t.Fatalf("len(push([1,2], 3)) = %v, want 3", vm.LastPoppedStackElement())
	}
}

// TestOrdinalEraResolvesThroughTheFrozenTable is what makes the registry
// editable again: an old artifact's operand is looked up in the frozen snapshot,
// so appending, renaming or reordering builtin.Builtins cannot change which
// function that artifact calls.
func TestOrdinalEraResolvesThroughTheFrozenTable(t *testing.T) {
	vm := New(downgradeToOrdinalEra(t, compileFresh(t, `len([]);`)))
	if vm.builtinsErr != nil {
		t.Fatalf("resolving ordinal-era bytecode: %v", vm.builtinsErr)
	}
	if len(vm.builtins) != builtin.LegacyOrdinalCount() {
		t.Fatalf("resolved %d builtins, want the frozen table's %d",
			len(vm.builtins), builtin.LegacyOrdinalCount())
	}
	ordinal := registryOrdinalOf(t, "len")
	frozen, ok := builtin.LegacyOrdinalName(ordinal)
	if !ok || frozen != "len" {
		t.Fatalf("frozen table entry %d = %q, want len", ordinal, frozen)
	}
	if vm.builtins[ordinal] != builtin.GetBuiltinByName("len") {
		t.Fatal("the ordinal did not resolve to len")
	}
}

func TestNamedBytecodeResolvesThroughItsOwnTable(t *testing.T) {
	bc := compileFresh(t, `len([1, 2]);`)
	if bc.Version != compiler.BytecodeVersionNamedBuiltins {
		t.Fatalf("Version = %d, want %d", bc.Version, compiler.BytecodeVersionNamedBuiltins)
	}

	vm, err := runSealed(t, bc)
	if err != nil {
		t.Fatalf("name-indexed bytecode failed to run: %v", err)
	}
	if result, ok := vm.LastPoppedStackElement().(*object.Integer); !ok || result.Value != 2 {
		t.Fatalf("len([1,2]) = %v, want 2", vm.LastPoppedStackElement())
	}
}

// TestUnknownBuiltinFailsBeforeAnythingRuns is the other half of that
// contract. The instruction stream is empty, so nothing ever reaches the
// missing builtin -- and the program must still refuse to run, naming it.
// Failing at the call site instead would hide a missing dependency behind
// whichever branch happened not to be taken.
func TestUnknownBuiltinFailsBeforeAnythingRuns(t *testing.T) {
	_, err := runSealed(t, &compiler.ByteCode{
		Instructions: code.Instructions{},
		Constants:    []object.Object{},
		Version:      compiler.BytecodeVersionNamedBuiltins,
		BuiltinNames: []string{"len", "csv_parse"},
	})
	if err == nil {
		t.Fatal("a program naming a builtin this runtime does not have was allowed to run")
	}
	if !strings.Contains(err.Error(), "csv_parse") {
		t.Fatalf("the error must name the missing builtin; got: %v", err)
	}
}

// TestUntaggedOperandInANamedContainerIsRefused covers the mismatch the tag
// makes visible: a container that says it is name-indexed whose instructions
// carry bare ordinals. Reading the operand anyway would index the name table
// with a registry position.
func TestUntaggedOperandInANamedContainerIsRefused(t *testing.T) {
	bc := compileFresh(t, `len([]);`)
	copy(bc.Instructions, code.Make(code.OpGetBuiltin, 0))

	_, err := runSealed(t, bc)
	if err == nil {
		t.Fatal("an untagged operand was accepted in a name-indexed container")
	}
	if !strings.Contains(err.Error(), "name-table index") {
		t.Fatalf("got: %v", err)
	}
}

// TestAnArtifactNamingARetiredBuiltinRunsThroughItsAlias is the same guarantee for
// renaming, exercised through the VM: an artifact that names a builtin this
// runtime no longer registers still runs, because an alias says what replaced it.
//
// The old name is one that was never registered rather than a real builtin
// unregistered for the duration. Mutating the global registry mid-test would
// leak into every other test in the package, and the path under test is the same
// either way -- builtin.ResolveNames is handed a name the registry does not have.
func TestAnArtifactNamingARetiredBuiltinRunsThroughItsAlias(t *testing.T) {
	const retired = "array_push_former_spelling"

	if _, registered := builtin.ResolveName(retired); registered {
		t.Fatalf("%q is registered; pick a name for this test that is not", retired)
	}

	// An artifact compiled while `retired` was the builtin's name: the operand
	// says "the first name in my table", and the table says the old spelling.
	artifact := compileFresh(t, `push([1, 2], 3);`)
	if len(artifact.BuiltinNames) != 1 || artifact.BuiltinNames[0] != "push" {
		t.Fatalf("BuiltinNames = %v, want [push]", artifact.BuiltinNames)
	}
	artifact.BuiltinNames[0] = retired

	if _, err := runSealed(t, artifact); err == nil {
		t.Fatal("without an alias, an artifact naming an unregistered builtin must not run")
	}

	builtin.Aliases[retired] = "push"
	defer delete(builtin.Aliases, retired)

	artifact = compileFresh(t, `len(push([1, 2], 3));`)
	for i, name := range artifact.BuiltinNames {
		if name == "push" {
			artifact.BuiltinNames[i] = retired
		}
	}

	vm, err := runSealed(t, artifact)
	if err != nil {
		t.Fatalf("an artifact naming the pre-rename spelling did not run: %v", err)
	}
	if result, ok := vm.LastPoppedStackElement().(*object.Integer); !ok || result.Value != 3 {
		t.Fatalf("result = %v, want 3", vm.LastPoppedStackElement())
	}
}

func TestNewerContainerVersionIsRefused(t *testing.T) {
	_, err := runSealed(t, &compiler.ByteCode{
		Instructions: code.Instructions{},
		Constants:    []object.Object{},
		Version:      compiler.BytecodeVersion + 1,
	})
	if err == nil {
		t.Fatal("bytecode from a newer container version was accepted")
	}
	for _, want := range []string{"container", "recompile"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error should say what to do about a newer container; got: %v", err)
		}
	}
}

// TestBuiltinOperandIsBoundedByTheProgramsOwnTable pins the bound that moved:
// it used to be the length of the global registry, which would have let an
// operand of 5 through on a program that references one builtin.
func TestBuiltinOperandIsBoundedByTheProgramsOwnTable(t *testing.T) {
	bc := compileFresh(t, `len([]);`)
	copy(bc.Instructions, code.Make(code.OpGetBuiltin, code.BuiltinNameTableFlag|5))

	_, err := runSealed(t, bc)
	if err == nil {
		t.Fatal("an operand past the end of the program's own builtin table was accepted")
	}
	if !strings.Contains(err.Error(), "OpGetBuiltin") {
		t.Fatalf("got: %v", err)
	}
}
