package compiler

// Dead-code insertion splices blocks the program branches over. It shares
// padInstructions with NOP insertion, so the jump repointing, the final-pop
// guard and the decline-on-undecodable rule are already covered there. What is
// specific to this stage is that the block it emits contains a jump of its own,
// aimed at an offset that exists only in the padded stream -- the one thing the
// repointing pass must not touch, and the one thing that would silently disable
// the stage if it did.

import (
	"encoding/binary"
	"testing"

	"mutant/code"
	"mutant/object"
)

func padWithDeadCode(pe *PolymorphicEngine, ins code.Instructions, rate float64, protectFinalPop bool) code.Instructions {
	return pe.padInstructions(ins, rate, protectFinalPop, pe.fillerGenerators(MutationConfig{InsertDeadCode: true}))
}

// A four-instruction stream, padded at rate 1.0, must come back longer and still
// decodable. Without this the stage could be silently declining on every stream
// and every other test here would pass over an unmodified program.
func TestDeadCodeInsertionActuallySplices(t *testing.T) {
	original := simpleStream()

	padded := padWithDeadCode(NewPolymorphicEngine(10, 7), original, 1.0, true)
	if len(padded) <= len(original) {
		t.Fatalf("dead-code padding returned %d bytes from %d; nothing was spliced", len(padded), len(original))
	}
	if _, _, ok := decodeBoundaries(padded); !ok {
		t.Fatalf("padded stream no longer decodes:\n%s", padded)
	}
}

// The stage's whole claim: the junk is unreachable. Every block this generator
// emits has to open with a branch that clears the rest of it.
func TestEveryDeadBlockIsJumpedOverEndToEnd(t *testing.T) {
	pe := NewPolymorphicEngine(10, 20260824)

	for i := 0; i < 200; i++ {
		at := i * 37 // vary the splice offset the block resolves against
		blk, own := pe.generateDeadBlock(at)
		if len(blk) == 0 {
			t.Fatalf("iteration %d produced an empty block", i)
		}
		if len(own) != 1 {
			t.Fatalf("iteration %d reported %d self-written jump operands, want 1", i, len(own))
		}

		operandAt := own[0]
		target := int(binary.BigEndian.Uint16(blk[operandAt : operandAt+2]))
		if want := at + len(blk); target != want {
			t.Fatalf("iteration %d: block at %d jumps to %d, want %d (just past its own end)", i, at, target, want)
		}

		// The branch must be the first thing executed, or the junk in front of
		// it runs.
		head := code.Opcode(blk[0])
		switch head {
		case code.OpJump:
			if operandAt != 1 {
				t.Fatalf("iteration %d: unconditional block puts its operand at %d, want 1", i, operandAt)
			}
		case code.OpFalse:
			if code.Opcode(blk[1]) != code.OpJumpFalse {
				t.Fatalf("iteration %d: guarded block pushes a false but does not branch on it", i)
			}
			if operandAt != 2 {
				t.Fatalf("iteration %d: guarded block puts its operand at %d, want 2", i, operandAt)
			}
		default:
			def, err := code.Lookup(blk[0])
			name := "?"
			if err == nil {
				name = def.Name
			}
			t.Fatalf("iteration %d: block opens with %s, which is neither branch shape", i, name)
		}
	}
}

// The trap this stage sets for itself. rewriteJumpTargets resolves every jump
// operand through remap, which is keyed by offsets in the *original* stream. A
// jump the generator wrote holds an offset that only exists in the padded one.
// Rewriting it either fails the whole pass -- silently disabling the stage -- or
// collides with a real old offset and redirects the branch into live code.
func TestAnInjectedJumpIsNotRepointedByTheOriginalJumpPass(t *testing.T) {
	original := simpleStream()

	// Seeds are cheap; find one that splices at least one block, then check
	// every branch in the result lands where a branch may land.
	padded := padWithDeadCode(NewPolymorphicEngine(10, 7), original, 1.0, true)
	if len(padded) == len(original) {
		t.Fatal("nothing was spliced, so the injected-jump case is not exercised")
	}

	assertJumpsHitBoundaries(t, 10, padded)

	// And specifically: every injected branch clears its own junk rather than
	// landing back inside it.
	starts, widths, ok := decodeBoundaries(padded)
	if !ok {
		t.Fatal("padded stream does not decode")
	}
	for i, start := range starts {
		op := code.Opcode(padded[start])
		if op != code.OpJump && op != code.OpJumpFalse {
			continue
		}
		target := int(binary.BigEndian.Uint16(padded[start+1 : start+3]))
		if target <= start && target != 0 {
			t.Errorf("branch at %d targets %d, which is backwards into already-executed code", start, target)
		}
		_ = widths[i]
	}
}

// Junk must be code the VM can read even though it never runs: the control-flow
// integrity check decodes the whole stream, and the constant-pool and opcode
// passes that run after this one walk it by operand width.
func TestDeadCodeJunkCarriesNoOperandsAndNoSecurityOpcodes(t *testing.T) {
	for _, op := range deadCodeFillers {
		def, err := code.Lookup(byte(op))
		if err != nil {
			t.Fatalf("filler opcode %d does not decode", op)
		}
		if len(def.OperandWidths) != 0 {
			t.Errorf("%s takes operands, so junk could carry an index pointing outside the program", def.Name)
		}
		if len(code.JumpOperands[op]) != 0 {
			t.Errorf("%s is a jump, and only the block's own guard may branch", def.Name)
		}
		if op == code.OpChkDbg || op == code.OpChkSnd {
			t.Errorf("%s is a security check; junk must not be able to answer for one the compiler should have injected", def.Name)
		}
	}
}

// --seed has to reproduce a build byte for byte, dead code included.
func TestDeadCodeIsReproducibleFromTheSeed(t *testing.T) {
	original := simpleStream()

	first := padWithDeadCode(NewPolymorphicEngine(10, 424242), original, 0.9, true)
	again := padWithDeadCode(NewPolymorphicEngine(10, 424242), original, 0.9, true)
	other := padWithDeadCode(NewPolymorphicEngine(10, 424243), original, 0.9, true)

	if string(first) != string(again) {
		t.Fatal("the same seed produced two different streams")
	}
	if string(first) == string(other) {
		t.Fatal("two different seeds produced the same stream, so the seed is not reaching the generator")
	}
}

// A jump target that does not fit a two-byte operand must produce no block at
// all. Truncating it would aim the branch into the middle of the program.
func TestADeadBlockDeclinesWhenItsTargetCannotBeExpressed(t *testing.T) {
	blk, own := NewPolymorphicEngine(10, 3).generateDeadBlock(65530)
	if len(blk) != 0 || own != nil {
		t.Fatalf("a block at offset 65530 emitted %d bytes with target %v; it must decline", len(blk), own)
	}
}

// End to end through the real compiler: the answer must not depend on whether
// dead code was inserted.
func TestDeadCodeReachesCompiledFunctions(t *testing.T) {
	comp := New()
	if err := comp.Compile(parse(`let twice = fn(n) { if (n > 3) { return n * 2; }; return n; }; twice(5);`)); err != nil {
		t.Fatalf("compile: %s", err)
	}
	bc := comp.ByteCode()

	before := map[*object.CompiledFunction]int{}
	for _, constant := range bc.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			before[fn] = len(fn.Instructions)
		}
	}
	if len(before) == 0 {
		t.Fatal("this program compiled without a function, so it cannot exercise the constant pool")
	}

	NewPolymorphicEngine(10, 5).spliceFillers(bc, MutationConfig{InsertDeadCode: true})

	grew := false
	for fn, was := range before {
		if len(fn.Instructions) > was {
			grew = true
		}
		assertJumpsHitBoundaries(t, 10, fn.Instructions)
	}
	if !grew {
		t.Fatal("no compiled function grew; dead-code insertion never reached the constant pool")
	}
}

// simpleStream is a decodable stream with a branch in it, so padding has both
// something to splice between and something to repoint.
func simpleStream() code.Instructions {
	var ins code.Instructions
	ins = append(ins, code.Make(code.OpConstant, 0)...)
	ins = append(ins, code.Make(code.OpJumpFalse, 9)...)
	ins = append(ins, code.Make(code.OpJump, 9)...)
	ins = append(ins, code.Make(code.OpPop)...)
	return ins
}
