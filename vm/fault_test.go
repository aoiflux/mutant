package vm

// Bytecode the VM cannot decode has to come back as an error. It used not to:
// the opcode handlers guard that an operand's *bytes* are present, but almost
// nothing guarded the slice element the operand then indexes, so a corrupted
// .mu file reached vm.stack[-1] and took the process down with a Go stack trace.
//
// Worse, which one you got depended on the path. pmap, spawn and net_serve each
// recover around their own goroutine, so the same file errored inside a worker
// and panicked on the main program's thread.

import (
	"fmt"
	"strings"
	"testing"

	"mutant/code"
	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// runRawStream runs a hand-built instruction stream the way the runner would:
// derive the password from the plaintext, encrypt, execute.
func runRawStream(t *testing.T, ins code.Instructions, constants []object.Object) error {
	t.Helper()

	bc := &compiler.ByteCode{Instructions: ins, Constants: constants}
	password := passwordFor(bc.Instructions)

	machine := NewWithGlobalStoreAndPassword(
		mutil.EncryptByteCode(bc, password),
		make([]object.Object, global.GlobalSize),
		password,
	)
	return machine.Run()
}

// Every case here is an operand that points somewhere it must not. None of them
// can be produced by this compiler; all of them can be produced by editing a
// .mu file.
func TestMalformedOperandsReportErrorsRatherThanPanicking(t *testing.T) {
	cases := []struct {
		name      string
		ins       code.Instructions
		constants []object.Object
		want      string
	}{
		{
			name: "constant index past the pool",
			ins:  join(code.Make(code.OpConstant, 900), code.Make(code.OpPop)),
			want: "constant index 900 out of range",
		},
		{
			name: "pop with nothing on the stack",
			ins:  join(code.Make(code.OpPop), code.Make(code.OpPop)),
			want: "stack underflow",
		},
		{
			name: "call reaching below the stack floor",
			ins:  join(code.Make(code.OpCall, 7), code.Make(code.OpPop)),
			want: "reaches outside the stack",
		},
		{
			name: "array of more elements than the stack holds",
			ins:  join(code.Make(code.OpTrue), code.Make(code.OpArray, 40), code.Make(code.OpPop)),
			want: "stack underflow",
		},
		{
			name: "hash with an odd number of slots",
			ins:  join(code.Make(code.OpTrue), code.Make(code.OpHash, 3), code.Make(code.OpPop)),
			want: "stack underflow",
		},
		{
			name: "struct type name past the pool",
			ins:  join(code.Make(code.OpMakeStruct, 900, 0), code.Make(code.OpPop)),
			want: "constant index 900 out of range",
		},
		{
			name:      "closure constant that is not a function",
			ins:       join(code.Make(code.OpClosure, 0, 0), code.Make(code.OpPop)),
			constants: []object.Object{&object.String{Value: "not a function"}},
			want:      "not a function",
		},
		{
			name: "closure constant past the pool",
			ins:  join(code.Make(code.OpClosure, 900, 0), code.Make(code.OpPop)),
			want: "constant index 900 out of range",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runRawStream(t, tc.ins, tc.constants)
			if err == nil {
				t.Fatal("malformed bytecode ran to completion; the operand was not checked at all")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not say what went wrong:\n got: %s\nwant substring: %s", err, tc.want)
			}
		})
	}
}

// A free-variable index is the one operand a hand-built stream cannot reach --
// it needs a real closure to be out of range against. So corrupt one in a real
// program, before encryption, the way an edited .mu file would be corrupt.
func TestCorruptedFreeVariableIndexIsAnError(t *testing.T) {
	comp := compiler.New()
	if err := comp.Compile(parse(`let outer = fn(a) { return fn() { return a; }; }; outer(1)();`)); err != nil {
		t.Fatalf("compile: %s", err)
	}
	bc := comp.ByteCode()

	corrupted := false
	for _, constant := range bc.Constants {
		fn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}
		for i := 0; i < len(fn.Instructions); {
			def, err := code.Lookup(fn.Instructions[i])
			if err != nil {
				t.Fatalf("compiled function does not decode at %d: %s", i, err)
			}
			if code.Opcode(fn.Instructions[i]) == code.OpGetFree {
				fn.Instructions[i+1] = 200 // no closure captures 201 values
				corrupted = true
			}
			i++
			for _, w := range def.OperandWidths {
				i += w
			}
		}
	}
	if !corrupted {
		t.Fatal("this program compiled without an OpGetFree, so it cannot exercise the guard")
	}

	password := passwordFor(bc.Instructions)
	machine := NewWithGlobalStoreAndPassword(
		mutil.EncryptByteCode(bc, password),
		make([]object.Object, global.GlobalSize),
		password,
	)

	err := machine.Run()
	if err == nil {
		t.Fatal("a free-variable index of 200 read something and the program finished")
	}
	if !strings.Contains(err.Error(), "free variable index") {
		t.Fatalf("error does not name the failing operand: %s", err)
	}
}

// The containment boundary lives in execLoop, which is the single door into the
// executor: Run goes through it, and so does CallClosureSync -- which is how
// pmap (vm/parallel.go), spawn (vm/spawn.go) and every net_serve handler reach
// it. Proving both entry points contain the same fault is what makes the
// per-path inconsistency gone rather than moved.
func TestBothExecutorEntryPointsContainTheSameFault(t *testing.T) {
	ins := join(code.Make(code.OpPop), code.Make(code.OpPop))

	if err := runRawStream(t, ins, nil); err == nil {
		t.Fatal("Run did not report the underflow")
	}

	// CallClosureSync runs a closure the same way a pmap or spawn worker does.
	// The malformed body has to travel in the constants pool so EncryptByteCode
	// XORs it with the same key the fetch loop will decode it with -- a
	// hand-built closure handed straight to the VM decodes as noise, which runs
	// and proves nothing.
	fn := &object.CompiledFunction{Instructions: ins}
	bc := &compiler.ByteCode{
		Instructions: join(code.Make(code.OpNull), code.Make(code.OpPop)),
		Constants:    []object.Object{fn},
	}
	password := passwordFor(bc.Instructions)
	machine := NewWithGlobalStoreAndPassword(
		mutil.EncryptByteCode(bc, password),
		make([]object.Object, global.GlobalSize),
		password,
	)
	if err := machine.Run(); err != nil {
		t.Fatalf("the harness program itself does not run: %s", err)
	}

	if _, err := machine.CallClosureSync(&object.Closure{Fn: fn}, nil); err == nil {
		t.Fatal("CallClosureSync did not report the underflow")
	}
}

// A fault is an integrity event: the program running is not the program that was
// compiled. Recording it is what lets warn mode keep an audit trail of bytecode
// that would not decode.
func TestAContainedFaultIsRecordedAsAnIntegrityFailure(t *testing.T) {
	before := security.SecurityTelemetrySnapshot()["integrity_failed"]

	if err := runRawStream(t, join(code.Make(code.OpPop), code.Make(code.OpPop)), nil); err == nil {
		t.Fatal("the underflow was not reported")
	}

	if after := security.SecurityTelemetrySnapshot()["integrity_failed"]; after <= before {
		t.Fatalf("integrity_failed did not move: %d -> %d", before, after)
	}
}

// The boundary must not launder an unexpected Go panic into a VM fault: they
// are recorded under different stages and read differently in an audit.
func TestContainFaultKeepsFaultsAndPanicsApart(t *testing.T) {
	var fromFault error
	containFault(vmFault{err: errString("operand out of range")}, &fromFault)
	if fromFault == nil || fromFault.Error() != "operand out of range" {
		t.Fatalf("a fault should pass its own message through, got %v", fromFault)
	}

	var fromPanic error
	containFault("something else entirely", &fromPanic)
	if fromPanic == nil || !strings.Contains(fromPanic.Error(), "recovered panic") {
		t.Fatalf("an unexpected panic should say so, got %v", fromPanic)
	}

	var none error
	containFault(nil, &none)
	if none != nil {
		t.Fatalf("no panic should leave the error alone, got %v", none)
	}
}

// LastPoppedStackElement runs after execution, outside the boundary, on the way
// to printing a result. Its callers in runner, repl and webrepl have no error
// return between here and the terminal.
func TestLastPoppedStackElementSurvivesAnImpossibleStackPointer(t *testing.T) {
	machine := &VM{stack: make([]object.Object, 4)}

	machine.stackPointer = 4
	if got := machine.LastPoppedStackElement(); got != global.Null {
		t.Fatalf("a stack pointer at the top reported %v, want null", got)
	}

	machine.stackPointer = -1
	if got := machine.LastPoppedStackElement(); got != global.Null {
		t.Fatalf("a negative stack pointer reported %v, want null", got)
	}
}

func passwordFor(ins code.Instructions) string {
	return fmt.Sprint(security.DerivePasswordFromInstructions(ins))
}

func join(parts ...code.Instructions) code.Instructions {
	var out code.Instructions
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

type errString string

func (e errString) Error() string { return string(e) }
