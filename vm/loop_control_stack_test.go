package vm

import (
	"fmt"
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/sema"
)

// M26-CMP-003. A `break` or a `continue` compiles to a bare jump, and every
// target one can reach -- a loop's end, its head, a for's post section -- reads
// the stack at the depth the loop was entered with. Jumping out of the middle
// of an expression used to leave that expression's operands behind: the pop
// meant for a for-in's cursor took a leaked value instead, the cursor stayed
// put, and the next advance read it as whatever had piled up on top.
//
// Nothing reported any of it. The outer loop either stopped early with a
// plausible answer, or died on an ip inside the inner loop, depending only on
// what the leaked value happened to be.
//
// There is one case here per place the compiler holds operands across a nested
// compile, because the count is kept per place: a missed one leaks and a
// miscounted one pops a slot that belongs to whatever contains the loop. Each
// nests the control-flow jump inside a for-in, which is the only construct that
// notices -- see TestLoopNesting for why.
func TestBreakFromInsideAnExpressionLeavesNoOperands(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected interface{}
	}{
		// The reported shape: the break sits in an array element, so element 0
		// is pending. At abb42b4 this printed [1] -- the outer loop stopped
		// after one element and said nothing.
		{"array element", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = [0, if (b == 20) { break; } else { b }];
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// The other reported shape, and the loud one: `score` is the left
		// operand of the `+`, so the continue left it on the stack and the
		// outer for-in failed with "loop cursor was replaced on the stack".
		{"infix left operand, continue out of a match arm", `
		let score = 0;
		for (k in ["a", "skip", "b", "c"]) {
			score = score + match (k) { "skip" => { continue; }, "a" => 1, _ => 2 };
		}
		score;`, 5},

		{"infix right operand", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = 1 + 2 * (if (b == 20) { break; } else { b }) - 3;
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// Both operands of a `<` are compiled in source order, so the left one
		// has nothing of the comparison pending under it and the right one has
		// the left. This was the other way round until M26-CMP-005 gave `<` and
		// `<=` opcodes of their own; the spec for this fix carried a separate
		// edit for the swapped path, and dropping it is why both cases are here
		// rather than one.
		{"the left operand of a <, nothing pending", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = (if (b == 20) { break; } else { b }) < 5;
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"the right operand of a <", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = 5 < (if (b == 20) { break; } else { b });
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"an index", `
		let xs = [5, 6, 7];
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = xs[if (b == 20) { break; } else { 0 }];
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"a hash value", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let h = {"k": if (b == 20) { break; } else { b }};
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"a hash key, after an earlier pair", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let h = {"a": 1, if (b == 20) { break; } else { "k" }: 2};
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// The callee is on the stack under every argument, so even the first
		// argument has a slot pending.
		{"a call argument", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let s = len(if (b == 20) { break; } else { "xx" });
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"the third argument of a call", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let s = slice("abcdef", 1, if (b == 20) { break; } else { 3 });
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"an interpolated piece after a text piece", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let s = "x${if (b == 20) { break; } else { b }}";
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"a struct literal field", `
		struct Point { x, y }
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let p = Point{ x: 1, y: if (b == 20) { break; } else { b } };
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// The assignment chain holds the container, and the index joins it
		// while the value is compiled. Both halves get a case.
		{"the index of an index assignment", `
		let out = [];
		for (a in [1, 2, 3]) {
			let row = [0, 0];
			for (b in [10, 20]) {
				row[if (b == 20) { break; } else { 0 }] = 9;
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"the value of an index assignment", `
		let out = [];
		for (a in [1, 2, 3]) {
			let row = [0, 0];
			for (b in [10, 20]) {
				row[0] = if (b == 20) { break; } else { b };
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"two containers deep", `
		let out = [];
		for (a in [1, 2, 3]) {
			let grid = [[0, 0], [0, 0]];
			for (b in [10, 20]) {
				grid[0][if (b == 20) { break; } else { 0 }] = 9;
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"through a struct field", `
		struct Box { items }
		let out = [];
		for (a in [1, 2, 3]) {
			let bx = Box{ items: [0, 0] };
			for (b in [10, 20]) {
				bx.items[0] = if (b == 20) { break; } else { b };
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// A compound assignment desugars to `x = x <op> v`, so the break ends
		// up one operand deeper than the spelling suggests.
		{"a compound assignment through an index", `
		let out = [];
		for (a in [1, 2, 3]) {
			let acc = [0, 0];
			for (b in [10, 20]) {
				acc[0] += if (b == 20) { break; } else { b };
			}
			out = push(out, acc[0]);
		}
		out;`, []int{10, 10, 10}},

		{"nested literals, two slots pending", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = [1, [2, if (b == 20) { break; } else { 3 }]];
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"a match arm body inside an array element", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = [0, match (b) { 20 => { break; }, _ => b }];
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// A multi-value return pushes its values one after another, so every
		// expression after the first has the earlier ones pending. This is the
		// one site in the fix that no case reached: at abb42b4 the break left
		// `v` behind, the inner for-in's cursor pop took it, and the function
		// answered from a frame that had stopped making sense.
		{"the second value of a return, inner loop breaking", `
		let f = fn(xs) {
			let n = 0;
			for (v in xs) {
				for (w in [1, 2]) {
					return v, if (w == 1) { break; } else { w };
				}
				n = n + v;
			}
			return 100 + n, 0;
		};
		let g, h = f([3, 4]);
		g;`, 107},

		// The condition-driven loops reach the same targets, so they owe the
		// same pops. Both are nested in a for-in so a leak is fatal rather
		// than invisible.
		{"break out of a while, from an operand", `
		let out = [];
		for (a in [1, 2, 3]) {
			let i = 0;
			while (i < 9) {
				i = i + 1;
				let t = [0, if (i == 2) { break; } else { i }];
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"continue in a for, from an operand", `
		let total = 0;
		for (a in [1, 2, 3]) {
			for (let i = 0; i < 4; i++) {
				let t = [0, if (i < 2) { continue; } else { i }];
				total = total + 1;
			}
		}
		total;`, 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runVMTests(t, []vmTestCase{{input: tt.input, expected: tt.expected}})
		})
	}
}

// The other direction: a jump with nothing pending must keep emitting nothing
// extra, and a jump whose operands belong to something OUTSIDE the loop must
// leave those alone. Over-popping is the failure mode a fix like this invites,
// and it is quieter than the leak it replaces -- the slot it steals belongs to
// whatever contains the loop.
func TestLoopControlDropsOnlyItsOwnOperands(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected interface{}
	}{
		// The shape the language has always allowed: an `if` is an expression,
		// so this is a break in an operand position with nothing pending.
		{"break as the whole of a let initializer", `
		let sum = 0;
		for (a in [1, 2, 3]) {
			let v = if (a > 10) { break; } else { 1 };
			sum = sum + v;
		}
		sum;`, 3},

		{"break as the first array element", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = [if (b == 20) { break; } else { b }, 0];
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// && and || compile their operands behind OpJumpFalse, which pops what
		// it reads, so the right operand has nothing pending under it.
		{"the right operand of &&", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = true && (if (b == 20) { break; } else { true });
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		{"the operand of a prefix operator", `
		let out = [];
		for (a in [1, 2, 3]) {
			for (b in [10, 20]) {
				let t = -(if (b == 20) { break; } else { b });
			}
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// The subject is popped before an arm body runs, so a continue in an
		// arm body has nothing of the match's pending.
		{"continue in a match arm body at statement level", `
		let hits = 0;
		for (k in ["a", "skip", "b"]) {
			match (k) { "skip" => { continue; }, _ => 1 };
			hits = hits + 1;
		}
		hits;`, 2},

		// The loop is entered with the array's first element already pushed,
		// so the break's own depth equals the loop's entry depth and it owes
		// nothing. Popping to zero here would take the 0 the array still
		// needs.
		{"a loop entered with an operand already pending", `
		let out = [];
		for (a in [1, 2, 3]) {
			let t = [0, if (true) { for (b in [7, 8]) { break; } 5 }];
			out = push(out, a);
		}
		out;`, []int{1, 2, 3}},

		// A function body is a loop boundary, so the closure's own loop owns
		// the break -- and the enclosing array element is in another
		// instruction stream entirely.
		{"a closure in an operand keeps its own loop", `
		let out = [];
		for (a in [1, 2, 3]) {
			let fs = [0, fn(xs) { let t = 0; for (v in xs) { if (v > 1) { break; } t = t + v; } return t; }];
			out = push(out, fs[1]([1, 2, 3]));
		}
		out;`, []int{1, 1, 1}},

		// The case above enters the closure's loop with nothing pending, so it
		// cannot tell a count that resets at a function boundary from one that
		// carries across it. Here the closure's own loop has two array slots
		// pending inside it, and the array element the closure sits in has one
		// pending outside it, in another instruction stream. The break owes two
		// pops, not three: a function body is a boundary and the outer slot is
		// not its to drop.
		{"a closure in an operand, with operands pending inside it too", `
		let out = [];
		for (a in [1, 2, 3]) {
			let fs = [0, fn(xs) {
				let acc = 0;
				for (v in xs) {
					let u = [7, 8, if (v > 1) { break; } else { v }];
					acc = acc + v;
				}
				return acc;
			}];
			out = push(out, fs[1]([1, 2, 3]));
		}
		out;`, []int{1, 1, 1}},

		// A return unwinds the frame, which discards operands wholesale, so it
		// is not in the business of popping them one at a time.
		{"a return from inside a loop in a function", `
		let f = fn(xs) {
			for (v in xs) {
				if (v > 1) { return v, 0; }
			}
			return 0, 0;
		};
		let got, _ = f([1, 2, 3]);
		got;`, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runVMTests(t, []vmTestCase{{input: tt.input, expected: tt.expected}})
		})
	}
}

// The answer-level cases above only catch a leak that a for-in is there to
// trip over. In a while or a for the leaked slots just pile up: the program
// prints the right number and holds one stack slot per iteration for the rest
// of the run, which at abb42b4 was a hundred thousand slots for a hundred
// thousand iterations and no diagnostic at all.
//
// So this measures the stack directly. The same program is run twice with
// different iteration counts; a stack depth that depends on the count is a
// leak, whatever the answer says.
func TestLoopControlInAnExpressionLeaksNoStackSlot(t *testing.T) {
	programs := []struct {
		name   string
		render func(iterations int) string
	}{
		{
			"break in an array element of a while body",
			func(iterations int) string {
				// The break fires once per entry to the inner loop, so the
				// inner loop is entered once per outer iteration -- a break
				// cannot leak more than one slot per loop it leaves.
				return fmt.Sprintf(`
				let entries = 0;
				let hits = 0;
				while (entries < %d) {
					entries = entries + 1;
					let i = 0;
					while (i < 9) {
						i = i + 1;
						let t = [0, if (i == 2) { break; } else { i }];
					}
					hits = hits + 1;
				}
				hits;`, iterations)
			},
		},
		{
			"continue in an array element of a for body",
			func(iterations int) string {
				return fmt.Sprintf(`
				let hits = 0;
				for (let i = 0; i < %d; i++) {
					let t = [0, if (i >= 0) { continue; } else { i }];
					hits = hits + 1;
				}
				hits;`, iterations)
			},
		},
	}

	for _, program := range programs {
		t.Run(program.name, func(t *testing.T) {
			few, err := runEncryptedVM(program.render(2))
			if err != nil {
				t.Fatalf("2 iterations: %s", err)
			}
			many, err := runEncryptedVM(program.render(60))
			if err != nil {
				t.Fatalf("60 iterations: %s", err)
			}

			if few.stackPointer != many.stackPointer {
				t.Fatalf("stack depth after 2 iterations is %d and after 60 it is %d: %d slots leaked, one per iteration",
					few.stackPointer, many.stackPointer, many.stackPointer-few.stackPointer)
			}
		})
	}
}

// A counting for's post section is the one place a loop control statement had no
// resolvable target, and the two rows below are two different ways that ended in
// a finished program carrying `OpJump 9999` -- the placeholder the Compile arm
// emits before anything patches it.
//
// What that instruction does is decided by the program's length and layout, not
// by anything its author wrote. A stream shorter than 9999 bytes jumps off the
// end and the run is treated as having finished, so the program answers whatever
// was last popped: measured as BOOLEAN(true) for a program whose value is an
// integer. A longer stream decodes whatever byte 9999 happens to be -- measured
// as `unknown opcode 225: ... the bytecode may be damaged or decrypted with the
// wrong key, or it may have been built by a newer version of mutant`, three
// claims that are all false. And when 9999 falls on an instruction boundary the
// VM resumes in unrelated code: measured as a program that never returned.
//
// So both tests assert on the instruction stream as well as on the answer. A
// placeholder jump can land somewhere harmless and give the right answer by
// luck, which is how these lasted this long.
func TestNoLoopControlLeavesAnUnresolvedJump(t *testing.T) {
	// M26-CMP-021. A break in the post section is legal and means the loop
	// ends. It was compiled correctly until another loop appeared earlier in
	// the same post section: that loop's append reallocated c.loopContexts,
	// the break recorded its jump in the new array, and the patch loop read a
	// pointer into the old one.
	withNestedLoop := `let n = 0; for (let i = 0; i < 3; i = i + (if (i == 9) { 0 } else { for (v in [1]) { n = n + 1; } if (i == 1) { break; } 1 })) { n = n + 10; } n;`

	// The control, and the whole reason the nested loop is identified as the
	// cause: the same break in the same place, with nothing to reallocate the
	// slice, was always right.
	withoutNestedLoop := `let n = 0; for (let i = 0; i < 3; i = i + (if (i == 1) { break; } else { 1 })) { n = n + 10; } n;`

	// 22 and not 20, which is worth a line because the two programs look alike:
	// the nested loop in the first one runs `n = n + 1` on every pass through
	// the post section, and the post section runs twice before the break. Both
	// engines were asked and both answer 22; the control answers 20 in both.
	for _, tt := range []struct {
		name     string
		input    string
		expected interface{}
	}{
		{"a break in a post section, with a loop ahead of it there", withNestedLoop, 22},
		{"a break in a post section, nothing ahead of it", withoutNestedLoop, 20},
	} {
		t.Run(tt.name, func(t *testing.T) {
			comp := compiler.New()
			if err := comp.Compile(parse(tt.input)); err != nil {
				t.Fatalf("compiler error: %s", err)
			}
			listing := comp.ByteCode().Instructions.String()
			for _, line := range strings.Split(listing, "\n") {
				if strings.Contains(line, "9999") {
					t.Errorf("an unresolved jump survived into the finished stream: %s\n%s",
						strings.TrimSpace(line), listing)
				}
			}
			runVMTests(t, []vmTestCase{{input: tt.input, expected: tt.expected}})
		})
	}
}

// M26-CMP-020. A continue in a counting for's post section is refused, because
// no reading of it terminates: going on to the condition skips the step that
// advances the loop, and jumping to the start of the step -- where every other
// continue in the loop is patched -- reaches this same continue again.
//
// The tree-walking evaluator reached that conclusion first, under M26-EVL-025,
// and the sentence lives in sema so that the two engines cannot drift into
// refusing one program in two wordings. This asserts the message byte for byte
// for exactly that reason; parity/expression_signal_parity_test.go asserts the
// other engine against the same function.
func TestContinueInAForsStepIsRefused(t *testing.T) {
	refused := `let n = 0; for (let i = 0; i < 5; i = i + (if (i == 2) { continue; } else { 1 })) { n = n + 1; } n;`

	comp := compiler.New()
	err := comp.Compile(parse(refused))
	if err == nil {
		t.Fatalf("compiled a continue in a for's post section; it has no terminating reading, so it has to be refused")
	}
	if want := sema.ContinueInLoopStepRefusal().Message; err.Error() != want {
		t.Errorf("refused in different words than sema owns:\n  got:  %s\n  want: %s", err.Error(), want)
	}

	// The refusal has to be this narrow or it is a false flag on working code.
	// A break in the same position has exactly one meaning, both engines agree
	// on it, and it stays legal.
	sound := `let n = 0; for (let i = 0; i < 5; i = i + (if (i == 2) { break; } else { 1 })) { n = n + 1; } n;`
	runVMTests(t, []vmTestCase{{input: sound, expected: 3}})

	// And a continue in the loop BODY is untouched: it is the ordinary spelling
	// and it reaches the step, which is where the advance lives.
	body := `let hits = 0; for (let i = 0; i < 5; i = i + 1) { if (i == 2) { continue; } hits = hits + 1; } hits;`
	runVMTests(t, []vmTestCase{{input: body, expected: 4}})
}
