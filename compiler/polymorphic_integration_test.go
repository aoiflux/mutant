package compiler_test

import (
	"bytes"
	"fmt"
	"mutant/ast"
	"mutant/code"
	"mutant/compiler"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/vm"
	"strings"
	"testing"
)

func TestPolymorphicSemanticEquivalenceSafeConstantStage(t *testing.T) {
	programText := "let a = 2; let b = 3; let c = 5; (a + b) * c"

	baselineObj := compileAndRun(t, programText, 0, 0)
	mutatedObj := compileAndRun(t, programText, 7, 424242)

	if baselineObj == nil || mutatedObj == nil {
		t.Fatalf("expected non-nil VM results")
	}
	if baselineObj.Type() != mutatedObj.Type() {
		t.Fatalf("type mismatch after polymorphic mutation: baseline=%s mutated=%s", baselineObj.Type(), mutatedObj.Type())
	}
	if baselineObj.Inspect() != mutatedObj.Inspect() {
		t.Fatalf("semantic mismatch after polymorphic mutation: baseline=%q mutated=%q", baselineObj.Inspect(), mutatedObj.Inspect())
	}
}

func TestPolymorphicReproducibilityBySeedForSafeStage(t *testing.T) {
	programText := "let x = 10; let y = 20; let z = 30; x + y + z"
	seed := int64(20260712)
	level := 7

	fingerprintA := compileFingerprint(t, programText, level, seed)
	fingerprintB := compileFingerprint(t, programText, level, seed)

	if fingerprintA != fingerprintB {
		t.Fatalf("expected deterministic bytecode fingerprint with same seed")
	}
}

// A non-zero mutation level has to actually change the program. This is the
// property the engine exists for, and the one it silently stopped delivering:
// the only implemented stage was gated at level 6 while the CLI defaulted to 5,
// so `mutant gen` ran the engine and emitted byte-identical output.
//
// What stood here asserted the opposite -- that level 7 left instructions and
// constant order untouched -- and passed only because the three-element pool it
// used happened to shuffle to itself under its hardcoded seed.
func TestNonZeroMutationChangesTheProgram(t *testing.T) {
	programText := "let a = 1; let b = 2; let c = 3; a + b + c"

	baseline := compileBytecode(t, programText, 0, 0)

	for level := 1; level <= 10; level++ {
		mutated := compileBytecode(t, programText, level, 99)

		if len(mutated.Instructions) < 2 {
			t.Fatalf("level %d: expected polymorphic marker bytes in mutated output", level)
		}
		trimmed := stripPolymorphicMarker(mutated.Instructions, level)

		if bytes.Equal(baseline.Instructions, trimmed) {
			t.Errorf("level %d produced byte-identical instructions -- the mutation level did nothing", level)
		}
		if mutated.OpcodeMap == nil {
			t.Errorf("level %d remapped opcodes without shipping the reverse table", level)
		}
	}
}

// Level 0 is the one level that must leave everything exactly as compiled: it is
// what `--mutation 0` promises and what reproducible-build comparisons rest on.
func TestZeroMutationLeavesTheProgramAlone(t *testing.T) {
	programText := "let a = 1; let b = 2; let c = 3; a + b + c"

	baseline := compileBytecode(t, programText, 0, 0)
	again := compileBytecode(t, programText, 0, 0)

	if !bytes.Equal(baseline.Instructions, again.Instructions) {
		t.Fatalf("compiling the same source at level 0 twice produced different instructions")
	}
	if constantsFingerprint(baseline.Constants) != constantsFingerprint(again.Constants) {
		t.Fatalf("compiling the same source at level 0 twice produced a different constant pool")
	}
	if baseline.OpcodeMap != nil {
		t.Fatalf("level 0 shipped an opcode map; nothing was remapped")
	}
}

func compileAndRun(t *testing.T, input string, level int, seed int64) object.Object {
	t.Helper()
	b := compileBytecodeWithSecurityChecks(t, input, level, seed)
	b.Instructions = stripPolymorphicMarker(b.Instructions, level)
	mutil.EncryptByteCode(b, "poly-test-pass")

	machine := vm.NewWithPasswordAndGlobalStoreMode(b, "poly-test-pass", make([]object.Object, global.GlobalSize), false)
	if err := machine.Run(); err != nil {
		t.Fatalf("vm run failed: %v", err)
	}

	return machine.LastPoppedStackElement()
}

func compileBytecode(t *testing.T, input string, level int, seed int64) *compiler.ByteCode {
	return compileBytecodeWithOptions(t, input, level, seed, false)
}

func compileBytecodeWithSecurityChecks(t *testing.T, input string, level int, seed int64) *compiler.ByteCode {
	return compileBytecodeWithOptions(t, input, level, seed, true)
}

func compileBytecodeWithOptions(t *testing.T, input string, level int, seed int64, injectSecurity bool) *compiler.ByteCode {
	t.Helper()

	program := parse(input)
	comp := compiler.New()
	if injectSecurity {
		comp.EnableSecurityOpcodeInjection()
	}
	if level > 0 {
		comp.EnablePolymorphismWithSeed(level, seed)
	}
	if err := comp.Compile(program); err != nil {
		t.Fatalf("compiler error: %v", err)
	}

	return comp.ByteCode()
}

func compileFingerprint(t *testing.T, input string, level int, seed int64) string {
	t.Helper()
	b := compileBytecode(t, input, level, seed)

	return fmt.Sprintf("ins=%x|const=%s", []byte(b.Instructions), constantsFingerprint(b.Constants))
}

func parse(input string) ast.Node {
	l := lexer.New(input)
	p := parser.New(l)
	return p.ParseProgram() // Updated to return ast.Node instead of parser.Program
}

// stripPolymorphicMarker removes the trailing [0xFF, level] the engine appends,
// which generator.encode strips before anything is written.
//
// The level is passed in rather than sniffed from the bytes. DetectPolymorphicLevel
// is a heuristic -- ordinary bytecode ends in 0xFF followed by a small byte often
// enough that trusting it truncated real programs -- and a test that guesses is a
// test that will one day cut two instructions off the program it is checking.
func stripPolymorphicMarker(instructions code.Instructions, level int) code.Instructions {
	if level <= 0 || len(instructions) < 2 {
		return instructions
	}
	return instructions[:len(instructions)-2]
}

func constantsFingerprint(constants []object.Object) string {
	parts := make([]string, 0, len(constants))
	for _, c := range constants {
		if c == nil {
			parts = append(parts, "<nil>")
			continue
		}
		parts = append(parts, string(c.Type())+":"+c.Inspect())
	}
	return strings.Join(parts, "|")
}
