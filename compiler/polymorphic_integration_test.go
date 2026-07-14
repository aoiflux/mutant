package compiler_test

import (
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
	t.Setenv("MUTANT_DEV_MODE", "1")

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
	t.Setenv("MUTANT_DEV_MODE", "1")

	programText := "let x = 10; let y = 20; let z = 30; x + y + z"
	seed := int64(20260712)
	level := 7

	fingerprintA := compileFingerprint(t, programText, level, seed)
	fingerprintB := compileFingerprint(t, programText, level, seed)

	if fingerprintA != fingerprintB {
		t.Fatalf("expected deterministic bytecode fingerprint with same seed")
	}
}

func TestPolymorphicSafeStagesRollbackPath(t *testing.T) {
	t.Setenv("MUTANT_DEV_MODE", "1")

	t.Setenv("MUTANT_POLYMORPHIC_SAFE_STAGES", "0")

	programText := "let a = 1; let b = 2; let c = 3; a + b + c"
	seed := int64(99)

	baseline := compileBytecode(t, programText, 0, 0)
	mutated := compileBytecode(t, programText, 7, seed)

	if len(mutated.Instructions) < 2 {
		t.Fatalf("expected polymorphic marker bytes in mutated output")
	}

	trimmed := mutated.Instructions[:len(mutated.Instructions)-2]
	if len(trimmed) != len(baseline.Instructions) {
		t.Fatalf("expected rollback path to keep instruction length unchanged")
	}
	for i := range baseline.Instructions {
		if baseline.Instructions[i] != trimmed[i] {
			t.Fatalf("expected rollback path to keep instructions unchanged")
		}
	}

	if constantsFingerprint(baseline.Constants) != constantsFingerprint(mutated.Constants) {
		t.Fatalf("expected rollback path to keep constant ordering unchanged")
	}
}

func compileAndRun(t *testing.T, input string, level int, seed int64) object.Object {
	t.Helper()
	b := compileBytecodeWithSecurityChecks(t, input, level, seed)
	b.Instructions = stripPolymorphicMarker(b.Instructions)
	mutil.EncryptByteCode(b, "poly-test-pass")

	machine := vm.NewWithPasswordAndGlobalStore(b, "poly-test-pass", make([]object.Object, global.GlobalSize))
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

func stripPolymorphicMarker(instructions code.Instructions) code.Instructions {
	if compiler.DetectPolymorphicLevel(instructions) == 0 || len(instructions) < 2 {
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
