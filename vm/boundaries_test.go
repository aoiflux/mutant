package vm

import (
	"fmt"
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// The instruction-boundary map is what verifyFrameControlFlow checks an ip
// against. Building it means decoding every compiled function byte by byte, so
// it has to happen once per VM -- but runIntegrityProbes used to ask for it
// before every single opcode, and the ask walked the whole constants pool. That
// made a program's speed depend on how many functions it declared rather than on
// what it did: a 2000-iteration loop cost 42ms with no other declarations and
// 108ms with two hundred of them.
//
// These tests pin the mechanism rather than a duration, so they mean the same
// thing on a slow machine.

func compileForBoundaries(t *testing.T, source string) (*VM, int) {
	t.Helper()

	comp := compiler.New()
	if err := comp.Compile(parse(source)); err != nil {
		t.Fatalf("compiling failed: %s", err)
	}

	bc := comp.ByteCode()
	functions := 0
	for _, constant := range bc.Constants {
		if _, ok := constant.(*object.CompiledFunction); ok {
			functions++
		}
	}

	password := fmt.Sprint(security.DerivePasswordFromInstructions(bc.Instructions))
	bc = mutil.EncryptByteCode(bc, password)

	return NewWithGlobalStoreAndPassword(bc, make([]object.Object, global.GlobalSize), password), functions
}

func declarations(count int) string {
	var b strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "let f%d = fn(x) { return x + %d; };\n", i, i)
	}
	return b.String()
}

// Every compiled function must get mapped, or a legitimate ip inside one would
// read as a control-flow violation the first time it is checked.
func TestEveryCompiledFunctionGetsBoundaries(t *testing.T) {
	machine, functions := compileForBoundaries(t, declarations(12)+"f3(1)")
	if functions == 0 {
		t.Fatal("the program compiled no functions, so this proves nothing")
	}

	machine.prepareForExecution()

	for _, constant := range machine.constants {
		fn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}
		if _, mapped := machine.frameBoundaries[fn]; !mapped {
			t.Fatal("a compiled function in the constants pool was never mapped")
		}
	}
}

// The pool is assigned once, in New, and never grows -- so mapping it is a
// one-time job. Deleting an entry and asking again must not rebuild it: if it
// does, the scan is running on a hot path again.
func TestConstantsPoolIsScannedOnlyOnce(t *testing.T) {
	machine, _ := compileForBoundaries(t, declarations(8)+"f5(1)")
	machine.prepareForExecution()

	var victim *object.CompiledFunction
	for _, constant := range machine.constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			victim = fn
			break
		}
	}
	if victim == nil {
		t.Fatal("the program compiled no functions, so this proves nothing")
	}

	delete(machine.frameBoundaries, victim)
	machine.ensureFrameBoundaries()

	if _, rebuilt := machine.frameBoundaries[victim]; rebuilt {
		t.Fatal("ensureFrameBoundaries re-scanned the constants pool; it runs before every opcode, so the scan must be one-time")
	}
}

// The probes run before every opcode. Whatever else they do, they must not be
// the thing that maps the pool.
func TestIntegrityProbesDoNotScanTheConstantsPool(t *testing.T) {
	machine, _ := compileForBoundaries(t, declarations(8)+"f5(1)")
	machine.prepareForExecution()

	var victim *object.CompiledFunction
	for _, constant := range machine.constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			victim = fn
			break
		}
	}
	if victim == nil {
		t.Fatal("the program compiled no functions, so this proves nothing")
	}

	delete(machine.frameBoundaries, victim)

	// Force both the probe and the sweep to be due on this call.
	machine.nextIntegrityAt = 0
	machine.nextSweepAt = 0
	if err := machine.runIntegrityProbes(); err != nil {
		t.Fatalf("integrity probes failed: %s", err)
	}

	if _, rebuilt := machine.frameBoundaries[victim]; rebuilt {
		t.Fatal("the integrity probes re-scanned the constants pool; that cost is charged to every step")
	}
}

// A function that is not in the constants pool still has to be mapped: New
// synthesises the main program's function rather than taking it from there.
func TestMainFunctionGetsBoundaries(t *testing.T) {
	machine, _ := compileForBoundaries(t, "let x = 1; x + 1")
	machine.prepareForExecution()

	mainFn := machine.currentFrame().cl.Fn
	if _, mapped := machine.frameBoundaries[mainFn]; !mapped {
		t.Fatal("the main program's function was never mapped")
	}
}

// Programs that declare a lot of functions must still run correctly -- the
// one-time scan is only safe if nothing later needs a boundary it skipped.
func TestProgramWithManyDeclarationsStillRuns(t *testing.T) {
	machine, _ := compileForBoundaries(t, declarations(200)+"f199(1)")
	if err := machine.Run(); err != nil {
		t.Fatalf("running failed: %s", err)
	}

	result := machine.LastPoppedStackElement()
	integer, ok := result.(*object.Integer)
	if !ok {
		t.Fatalf("expected an integer, got %s", result.Inspect())
	}
	if integer.Value != 200 {
		t.Fatalf("f199(1) returned %d, want 200", integer.Value)
	}
}
