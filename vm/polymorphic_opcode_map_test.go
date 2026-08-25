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

// Opcode remapping permutes the instruction set and ships the inverse in
// ByteCode.OpcodeMap. The VM has to apply it everywhere it turns a byte into an
// opcode, which is three places, not one: the fetch loop, the instruction
// boundary map that the control-flow integrity check reads, and the scan that
// proves the program still carries its security checks.
//
// This program is deliberately broader than the constant-pool one: it has loops
// and conditionals, so it exercises the jump targets NOP insertion repoints, on
// top of the closures, structs and enums that carry constant-pool operands.
const remappedProgram = `
struct Point { x; y; };
enum Color { Red, Green };

let add = fn(a, b) { return a + b; };

let total = 0;
for (let i = 0; i < 10; i = i + 1) {
	if (i % 2 == 0) { total = total + i; } else { total = total + 1; };
};

let p = Point { x: 10, y: 20 };
p.y = 32;
let c = Color.Green;

add(p.x, p.y) + total;
`

// wantRemapped is add(10, 32) + total, where total is 0+1+2+1+4+1+6+1+8+1.
const wantRemapped = 42 + 25

// The result must not depend on the mutation level. This runs the real VM over
// really mutated bytecode at every level the CLI accepts.
func TestRemappedProgramRunsThroughTheVM(t *testing.T) {
	for level := 0; level <= 10; level++ {
		t.Run(fmt.Sprintf("level%d", level), func(t *testing.T) {
			bc := compileRemapped(t, level, 20260824)

			if level > 0 && bc.OpcodeMap == nil {
				t.Fatalf("level %d shipped no reverse opcode table", level)
			}
			if level == 0 && bc.OpcodeMap != nil {
				t.Fatal("level 0 shipped a reverse opcode table; nothing was remapped")
			}

			if got := runRemapped(t, bc); got != wantRemapped {
				t.Fatalf("level %d changed the answer: got %d, want %d", level, got, wantRemapped)
			}
		})
	}
}

// The load-bearing check. Without the reverse table the same bytecode must not
// quietly produce the right answer -- if it did, the table would be decoration
// and every test above would be passing for the wrong reason.
func TestARemappedProgramNeedsItsReverseTable(t *testing.T) {
	bc := compileRemapped(t, 10, 20260824)
	if bc.OpcodeMap == nil {
		t.Fatal("level 10 shipped no reverse opcode table")
	}
	bc.OpcodeMap = nil

	password := fmt.Sprint(security.DerivePasswordFromInstructions(bc.Instructions))
	machine := NewWithGlobalStoreAndPassword(
		mutil.EncryptByteCode(bc, password),
		make([]object.Object, global.GlobalSize),
		password,
	)

	// A stream decoded with the wrong opcode widths runs instructions that were
	// never there. This used to have to recover a panic -- VM.pop() had no
	// underflow guard and died on stack[-1] -- which is the gap vm/fault.go
	// closes: undecodable bytecode is now an error on every path.
	ran, value := func() (ran bool, value int64) {
		if err := machine.Run(); err != nil {
			return false, 0
		}
		result, ok := machine.LastPoppedStackElement().(*object.Integer)
		if !ok {
			return false, 0
		}
		return true, result.Value
	}()

	if ran && value == wantRemapped {
		t.Fatal("a remapped program produced the right answer with no reverse table; the remapping is not actually being applied")
	}
}

// The security-opcode scan decodes the same streams as the fetch loop. Missing
// the remapping there does not corrupt anything -- it reports a program that
// carries its OpChkDbg and OpChkSnd checks as having lost them, and refuses to
// run it.
func TestRemappedProgramStillPassesTheSecurityOpcodeScan(t *testing.T) {
	comp := compiler.New()
	comp.EnableSecurityOpcodeInjection()
	comp.EnablePolymorphismWithSeed(10, 987654)
	if err := comp.Compile(parse(remappedProgram)); err != nil {
		t.Fatalf("compile: %s", err)
	}

	bc := comp.ByteCode()
	bc.Instructions = bc.Instructions[:len(bc.Instructions)-2] // polymorphic marker

	password := fmt.Sprint(security.DerivePasswordFromInstructions(bc.Instructions))
	// NewWithPasswordAndGlobalStoreMode is the constructor that turns the scan
	// on; the plain global-store one leaves it off and would not test this.
	machine := NewWithPasswordAndGlobalStoreMode(
		mutil.EncryptByteCode(bc, password),
		password,
		make([]object.Object, global.GlobalSize),
		false,
	)

	if err := machine.Run(); err != nil {
		if strings.Contains(err.Error(), "security check opcodes missing") {
			t.Fatalf("the scan could not see through the opcode remapping: %s", err)
		}
		t.Fatalf("remapped program with security checks failed to run: %s", err)
	}
}

// The end-to-end version of the tail guard, over the path the CLI actually
// takes: `mutant gen` compiles with security-opcode injection, which appends
// OpChkDbg and OpChkSnd after the program's final OpPop. A NOP spliced in there
// becomes the last pop, so LastPoppedStackElement -- what the CLI prints --
// returns the NOP's value instead of the program's result.
//
// It showed up as a stray `true` on roughly one build in sixteen, which is why
// this sweeps seeds: a single seed reproduces the bug only by luck.
func TestMutationNeverChangesTheReportedResult(t *testing.T) {
	seeds := []int64{1, 99, 4242, 987654, 20260824}

	for level := 0; level <= 10; level++ {
		for _, seed := range seeds {
			comp := compiler.New()
			comp.EnableSecurityOpcodeInjection()
			if level > 0 {
				comp.EnablePolymorphismWithSeed(level, seed)
			}
			if err := comp.Compile(parse(remappedProgram)); err != nil {
				t.Fatalf("compile at level %d seed %d: %s", level, seed, err)
			}

			bc := comp.ByteCode()
			if level > 0 && len(bc.Instructions) >= 2 {
				bc.Instructions = bc.Instructions[:len(bc.Instructions)-2]
			}

			if got := runRemapped(t, bc); got != wantRemapped {
				t.Errorf("level %d seed %d reported %d, want %d", level, seed, got, wantRemapped)
			}
		}
	}
}

// A reverse table that cannot address every byte an instruction stream might
// hold is treated as absent rather than used. Indexing past its end would panic
// on the first high opcode byte, and running as though unmapped fails at the
// first instruction instead of executing something else.
func TestMalformedReverseTableIsIgnored(t *testing.T) {
	cases := map[string][]byte{
		"nil":     nil,
		"empty":   {},
		"short":   make([]byte, 44),
		"too big": make([]byte, 512),
	}

	for name, table := range cases {
		if got := normalizeOpcodeMap(table); got != nil {
			t.Errorf("%s reverse table (%d entries) was accepted", name, len(table))
		}
	}

	if got := normalizeOpcodeMap(make([]byte, 256)); got == nil {
		t.Error("a full 256-entry reverse table was rejected")
	}
}

func compileRemapped(t *testing.T, level int, seed int64) *compiler.ByteCode {
	t.Helper()

	comp := compiler.New()
	if level > 0 {
		comp.EnablePolymorphismWithSeed(level, seed)
	}
	if err := comp.Compile(parse(remappedProgram)); err != nil {
		t.Fatalf("compile at mutation %d: %s", level, err)
	}

	bc := comp.ByteCode()
	if level > 0 && len(bc.Instructions) >= 2 {
		bc.Instructions = bc.Instructions[:len(bc.Instructions)-2]
	}
	return bc
}

func runRemapped(t *testing.T, bc *compiler.ByteCode) int64 {
	t.Helper()

	password := fmt.Sprint(security.DerivePasswordFromInstructions(bc.Instructions))
	machine := NewWithGlobalStoreAndPassword(
		mutil.EncryptByteCode(bc, password),
		make([]object.Object, global.GlobalSize),
		password,
	)

	if err := machine.Run(); err != nil {
		t.Fatalf("the VM could not run this bytecode: %s", err)
	}

	result, ok := machine.LastPoppedStackElement().(*object.Integer)
	if !ok {
		t.Fatalf("expected an integer result, got %T", machine.LastPoppedStackElement())
	}
	return result.Value
}
