package vm

// A `return` at the top level ends the program, and what the program then
// reports as its result has to be the value it returned.
//
// It did not. Returning from the outermost frame leaves the value at stack[sp-1]
// and nothing pops afterwards, so LastPoppedStackElement -- which the CLI prints
// and the REPL echoes -- read stack[sp], still holding whatever the previous
// expression left there. `if (1 == 1) { return 7; }` printed 1: the leftover
// operand of the comparison.
//
// The reason it is worth a test rather than a shrug is the second half. Which
// leftover landed in that slot depended on the exact instruction layout, so the
// polymorphic engine could change a program's printed result without changing
// anything the program does -- and did, on two examples, once dead-code
// insertion started moving instructions around.

import (
	"fmt"
	"testing"

	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

func runSource(t *testing.T, src string, level int, seed int64) *VM {
	t.Helper()

	comp := compiler.New()
	if level > 0 {
		comp.EnablePolymorphismWithSeed(level, seed)
	}
	if err := comp.Compile(parse(src)); err != nil {
		t.Fatalf("compile: %s", err)
	}

	bc := comp.ByteCode()
	if level > 0 && len(bc.Instructions) >= 2 {
		bc.Instructions = bc.Instructions[:len(bc.Instructions)-2] // strip the marker
	}

	password := fmt.Sprint(security.DerivePasswordFromInstructions(bc.Instructions))
	machine := NewWithGlobalStoreAndPassword(
		mutil.EncryptByteCode(bc, password),
		make([]object.Object, global.GlobalSize),
		password,
	)
	if err := machine.Run(); err != nil {
		t.Fatalf("run: %s", err)
	}
	return machine
}

func TestATopLevelReturnReportsTheValueItReturned(t *testing.T) {
	machine := runSource(t, `putln("x"); if (1 == 1) { return 7; }; putln("unreached");`, 0, 0)

	result, ok := machine.LastPoppedStackElement().(*object.Integer)
	if !ok {
		t.Fatalf("the program reported %s, want the integer it returned",
			machine.LastPoppedStackElement().Inspect())
	}
	if result.Value != 7 {
		t.Fatalf("the program reported %d, want 7", result.Value)
	}
}

// The stability claim, over the program shape that exposed the defect: a
// top-level return reached from inside a conditional, with a comparison just
// before it to leave something in the slot.
func TestATopLevelReturnDoesNotDependOnTheMutationLevel(t *testing.T) {
	const src = `
let checked = fn(n) { if (n > 2) { return true; }; return false; };
putln("start");
let values = [1, 2, 3];
for (let i = 0; i < len(values); i = i + 1) {
	if (checked(values[i])) {
		let label, jerr = json_stringify(values[i]);
		return "stopped at " + label;
	};
};
putln("never reached");
`

	want := ""
	for level := 0; level <= 10; level++ {
		machine := runSource(t, src, level, 424242)
		got := machine.LastPoppedStackElement().Inspect()
		if level == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("level %d reported %q, level 0 reported %q", level, got, want)
		}
	}

	if want != `stopped at 3` && want != `"stopped at 3"` {
		t.Fatalf("the program reported %q, want the string it returned", want)
	}
}

// The adjustment must apply to the outermost frame only. A function returning to
// its caller has to leave its value where the caller expects it, and
// CallClosureSync -- the door pmap, spawn and net_serve handlers come through --
// pops its result from stack[sp-1].
func TestReturningFromAFunctionIsUnaffected(t *testing.T) {
	machine := runSource(t, `let double = fn(n) { return n * 2; }; double;`, 0, 0)

	closure, ok := machine.LastPoppedStackElement().(*object.Closure)
	if !ok {
		t.Fatalf("expected the closure as the program's value, got %T", machine.LastPoppedStackElement())
	}

	result, err := machine.CallClosureSync(closure, []object.Object{&object.Integer{Value: 21}})
	if err != nil {
		t.Fatalf("CallClosureSync: %s", err)
	}
	got, ok := result.(*object.Integer)
	if !ok || got.Value != 42 {
		t.Fatalf("the closure returned %s, want 42", result.Inspect())
	}
}
