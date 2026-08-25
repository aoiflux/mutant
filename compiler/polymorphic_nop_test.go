package compiler

import (
	"encoding/binary"
	"testing"

	"mutant/code"
	"mutant/object"
)

// NOP insertion moves every instruction after each splice point, and jump
// operands are absolute offsets. Repointing them is not a refinement of the
// stage, it is the whole of it: without the rewrite an inserted byte silently
// redirects a jump into the middle of an instruction, and the VM reports the
// program as tampered with rather than as mis-compiled.
//
// The stream below is hand-built so the expected result can be worked out by
// hand. At rate 1.0 a two-byte NOP follows every instruction except the last:
//
//	old  0 OpConstant 0    ->  new  0   (NOP at 3)
//	old  3 OpJumpFalse 9   ->  new  5   (NOP at 8)
//	old  6 OpJump 9        ->  new  10  (NOP at 13)
//	old  9 OpPop           ->  new  15  (no NOP: last instruction)
//
// so both jumps, which pointed at 9, must come out pointing at 15.
func TestPaddingRepointsJumpTargets(t *testing.T) {
	var original code.Instructions
	original = append(original, code.Make(code.OpConstant, 0)...)
	original = append(original, code.Make(code.OpJumpFalse, 9)...)
	original = append(original, code.Make(code.OpJump, 9)...)
	original = append(original, code.Make(code.OpPop)...)

	engine := NewPolymorphicEngine(10, 1)
	padded := padWithNOPs(engine, original, 1.0, true)

	if len(padded) != 16 {
		t.Fatalf("padded stream is %d bytes, want 16:\n%s", len(padded), padded)
	}

	for _, at := range []int{5, 10} {
		got := int(binary.BigEndian.Uint16(padded[at+1 : at+3]))
		if got != 15 {
			t.Errorf("jump at padded offset %d targets %d, want 15", at, got)
		}
	}
}

// The structural guarantee, stated over a real program rather than a synthetic
// stream: after padding, every jump lands exactly on an instruction boundary. A
// target one byte off decodes an operand as an opcode and runs something the
// source never said.
func TestPaddedJumpsLandOnInstructionBoundaries(t *testing.T) {
	// Loops and conditionals are the only things that emit jumps, so a program
	// without them would pass this test while checking nothing.
	const program = `
	let total = 0;
	let i = 0;
	for (i = 0; i < 10; i = i + 1) {
		if (i % 2 == 0) { total = total + i; } else { total = total + 100; };
	};
	total;
	`

	for level := 1; level <= 10; level++ {
		comp := New()
		if err := comp.Compile(parse(program)); err != nil {
			t.Fatalf("compile: %s", err)
		}
		bc := comp.ByteCode()

		if countJumps(t, bc.Instructions) == 0 {
			t.Fatal("the test program stopped emitting jumps; it no longer covers anything")
		}

		engine := NewPolymorphicEngine(level, int64(level)*31)
		padded := padWithNOPs(engine, bc.Instructions, float64(level)*1.5/100.0, true)
		assertJumpsHitBoundaries(t, level, padded)
	}
}

// Nothing may be spliced in at or after the main stream's final OpPop.
//
// A NOP is a push and a pop, so one placed after it becomes the last pop, and
// VM.LastPoppedStackElement -- what the CLI prints and the REPL echoes --
// reports the NOP's value instead of the program's result. Guarding only the
// final instruction is not enough: when the compiler injects the required
// security checks it appends OpChkDbg and OpChkSnd after that OpPop, leaving two
// insertion points that look legal and are not. This stream is shaped exactly
// like that tail.
func TestPaddingStopsAtTheFinalPop(t *testing.T) {
	var original code.Instructions
	original = append(original, code.Make(code.OpConstant, 0)...)
	original = append(original, code.Make(code.OpPop)...)
	original = append(original, code.Make(code.OpChkDbg)...)
	original = append(original, code.Make(code.OpChkSnd)...)

	padded := padWithNOPs(NewPolymorphicEngine(10, 3), original, 1.0, true)

	starts, _, ok := decodeBoundaries(padded)
	if !ok {
		t.Fatal("padded stream does not decode")
	}

	// The property is about which value the last pop takes off the stack, so it
	// has to be simulated rather than pattern-matched. Two weaker phrasings both
	// pass while the bug is present: "is anything spliced in after the last
	// OpPop" is vacuous, because an inserted NOP ends in a pop and simply
	// becomes the last OpPop; and "what precedes the last OpPop" answers OpPop
	// either way, because a NOP inserted just before the real pop is legitimate.
	//
	// The program pushes with OpConstant, which no NOP variant emits, so tagging
	// each push tells the two apart.
	const fromProgram, fromNOP = "program", "NOP"

	stack := []string{}
	lastPopped := ""
	for _, s := range starts {
		switch code.Opcode(padded[s]) {
		case code.OpConstant:
			stack = append(stack, fromProgram)
		case code.OpNull, code.OpTrue, code.OpFalse:
			stack = append(stack, fromNOP)
		case code.OpPop:
			if len(stack) == 0 {
				t.Fatalf("padding produced a pop with nothing on the stack at offset %d", s)
			}
			lastPopped = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		}
	}

	if lastPopped != fromProgram {
		t.Errorf("the last value popped came from an inserted %s, not from the program -- that is exactly what LastPoppedStackElement reports", lastPopped)
	}
	if len(stack) != 0 {
		t.Errorf("padding left %d value(s) on the stack", len(stack))
	}
}

// A function body is padded even though it never pops: LastPoppedStackElement
// reads the stack once the program has finished, so a function's pops all
// happened inside a frame that has since been unwound. Applying the main
// stream's tail guard here would strip padding from exactly the streams worth
// padding.
func TestFunctionBodiesArePaddedWithoutAPop(t *testing.T) {
	var body code.Instructions
	body = append(body, code.Make(code.OpGetLocal, 0)...)
	body = append(body, code.Make(code.OpReturnValue)...)

	guarded := padWithNOPs(NewPolymorphicEngine(10, 3), body, 1.0, true)
	if len(guarded) != len(body) {
		t.Errorf("the tail guard should suppress padding on a stream with no OpPop, got %d bytes from %d", len(guarded), len(body))
	}

	unguarded := padWithNOPs(NewPolymorphicEngine(10, 3), body, 1.0, false)
	if len(unguarded) <= len(body) {
		t.Error("a function body with no OpPop was left unpadded")
	}
}

// Padding declines rather than corrupts. A stream it cannot decode end to end
// comes back exactly as it went in: a half-rewritten stream cannot be recovered,
// and no amount of obfuscation is worth a broken program.
func TestPaddingDeclinesOnAnUndecodableStream(t *testing.T) {
	broken := code.Instructions{0xFE, 0xFE, 0xFE}

	engine := NewPolymorphicEngine(10, 7)
	got := padWithNOPs(engine, broken, 1.0, true)

	if len(got) != len(broken) {
		t.Fatalf("padding rewrote an undecodable stream: %d bytes in, %d out", len(broken), len(got))
	}
}

// A NOP has to leave the stack exactly as it found it. The variant this drops
// was a bare OpPop, commented "safe if stack has something": at an arbitrary
// instruction boundary the stack holds the expression in progress, so that
// variant discarded a live value and made correctness a coin flip.
func TestEveryNOPVariantIsStackNeutral(t *testing.T) {
	engine := NewPolymorphicEngine(10, 99)

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		nop := engine.generateNOP()

		pushes, pops := 0, 0
		for j := 0; j < len(nop); {
			def, err := code.Lookup(nop[j])
			if err != nil {
				t.Fatalf("NOP contains undecodable byte %d", nop[j])
			}

			switch code.Opcode(nop[j]) {
			case code.OpNull, code.OpTrue, code.OpFalse:
				pushes++
			case code.OpPop:
				pops++
			default:
				t.Fatalf("NOP contains %s, which is neither a push nor a pop", def.Name)
			}

			width := 1
			for _, w := range def.OperandWidths {
				width += w
			}
			j += width
		}

		if pushes != pops {
			t.Fatalf("a NOP pushed %d and popped %d", pushes, pops)
		}
		seen[nop.String()] = true
	}

	if len(seen) < 2 {
		t.Errorf("only %d distinct NOP shape(s) in 200 draws; padding would read as one repeated signature", len(seen))
	}
}

// Padding is driven by the seeded RNG, not crypto/rand. It used to use
// crypto/rand, which meant a build could not be reproduced from its seed -- the
// --seed flag existed and did not work.
func TestPaddingIsReproducibleFromTheSeed(t *testing.T) {
	comp := New()
	if err := comp.Compile(parse("let a = 1; let b = 2; if (a < b) { a; } else { b; };")); err != nil {
		t.Fatalf("compile: %s", err)
	}
	original := comp.ByteCode().Instructions

	first := padWithNOPs(NewPolymorphicEngine(10, 20260824), original, 0.5, true)
	again := padWithNOPs(NewPolymorphicEngine(10, 20260824), original, 0.5, true)
	other := padWithNOPs(NewPolymorphicEngine(10, 11111111), original, 0.5, true)

	if string(first) != string(again) {
		t.Error("the same seed produced two different padded streams")
	}
	if string(first) == string(other) {
		t.Error("two different seeds produced identical padding")
	}
}

// Every compiled function gets padded too, not just the main stream. Function
// bodies are where the loops usually are, and each carries its own jump targets.
func TestPaddingReachesCompiledFunctions(t *testing.T) {
	comp := New()
	if err := comp.Compile(parse(`let f = fn(n) { if (n > 0) { return n; }; return 0; }; f(1);`)); err != nil {
		t.Fatalf("compile: %s", err)
	}
	bc := comp.ByteCode()

	before := map[int]int{}
	for i, c := range bc.Constants {
		if fn, ok := c.(*object.CompiledFunction); ok {
			before[i] = len(fn.Instructions)
		}
	}
	if len(before) == 0 {
		t.Fatal("the test program compiled no functions")
	}

	NewPolymorphicEngine(10, 5).spliceFillers(bc, MutationConfig{InsertNOPs: true})

	grew := 0
	for i, c := range bc.Constants {
		fn, ok := c.(*object.CompiledFunction)
		if !ok {
			continue
		}
		assertJumpsHitBoundaries(t, 10, fn.Instructions)
		if len(fn.Instructions) > before[i] {
			grew++
		}
	}

	if grew == 0 {
		t.Error("no compiled function was padded; only the main stream was mutated")
	}
}

func countJumps(t *testing.T, ins code.Instructions) int {
	t.Helper()

	found := 0
	for i := 0; i < len(ins); {
		def, err := code.Lookup(ins[i])
		if err != nil {
			t.Fatalf("undecodable opcode %d at offset %d", ins[i], i)
		}
		if len(code.JumpOperands[code.Opcode(ins[i])]) > 0 {
			found++
		}

		width := 1
		for _, w := range def.OperandWidths {
			width += w
		}
		i += width
	}

	return found
}

// assertJumpsHitBoundaries decodes ins and checks every jump operand against the
// set of real instruction starts.
func assertJumpsHitBoundaries(t *testing.T, level int, ins code.Instructions) {
	t.Helper()

	starts, _, ok := decodeBoundaries(ins)
	if !ok {
		t.Fatalf("level %d: stream no longer decodes end to end", level)
	}

	boundary := make(map[int]bool, len(starts)+1)
	for _, s := range starts {
		boundary[s] = true
	}
	boundary[len(ins)] = true // falling out of the stream is a legal target

	for i := 0; i < len(ins); {
		def, _ := code.Lookup(ins[i])
		slots := code.JumpOperands[code.Opcode(ins[i])]

		offset := i + 1
		for operand, w := range def.OperandWidths {
			if w == 2 && containsInt(slots, operand) {
				target := int(binary.BigEndian.Uint16(ins[offset : offset+2]))
				if !boundary[target] {
					t.Errorf("level %d: %s at %d targets %d, which is not an instruction boundary",
						level, def.Name, i, target)
				}
			}
			offset += w
		}

		width := 1
		for _, w := range def.OperandWidths {
			width += w
		}
		i += width
	}
}

// padWithNOPs pins these cases to NOP insertion alone. Dead-code insertion goes
// through the same pass and the same jump repointing, so letting it in here
// would mean every assertion about NOP shape had to allow for a block that is
// jumped over instead -- which is what polymorphic_dead_code_test.go is for.
func padWithNOPs(pe *PolymorphicEngine, ins code.Instructions, rate float64, protectFinalPop bool) code.Instructions {
	return pe.padInstructions(ins, rate, protectFinalPop, pe.fillerGenerators(MutationConfig{InsertNOPs: true}))
}
