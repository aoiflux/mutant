package vm

import (
	"mutant/object"
	"testing"
)

// The for-in loop keeps its cursor on the stack for the whole loop and
// OpIterNext reads it at a fixed offset from the top, so anything the body
// leaves behind is read as the cursor on the next advance. That makes for-in
// the only construct that notices a loop body which is not stack-neutral:
// everywhere else a leaked slot is absorbed by frame teardown and nothing ever
// looks wrong.
//
// So these cases test the condition-driven loops as much as they test for-in.
// Each one nests a while or a C-style for whose body, post or init section
// ends in an expression statement -- which is exactly the shape whose pop the
// compiler used to strip, leaking one slot per iteration.
//
// Every case is named for the nesting it covers, and each runs as its own
// subtest, because a leak shows up as a hard "loop cursor was replaced" error
// and one shared runner would stop at the first shape that broke.
func TestLoopNesting(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected interface{}
	}{
		// The inner loop never runs, so nothing leaks and this shape worked
		// even while the rest did not. Kept so that a "fix" which skips the
		// body entirely cannot pass for a fix.
		{"while inner never runs", `
		let total = 0;
		for (v in [1, 2, 3]) {
			let i = 0;
			while (i < 0) { i = i + 1; }
			total = total + v;
		}
		total;`, 6},

		// One inner iteration is enough: one slot on top of the cursor.
		{"while inner runs once", `
		let total = 0;
		for (v in [1, 2, 3]) {
			let i = 0;
			while (i < 1) { i = i + 1; }
			total = total + v;
		}
		total;`, 6},

		{"while inner runs several times", `
		let total = 0;
		for (v in [1, 2, 3]) {
			let i = 0;
			while (i < 4) { i = i + 1; }
			total = total + i;
		}
		total;`, 12},

		// A while body that genuinely ends in a `let` emits no trailing pop,
		// so this shape always worked -- the leak was never about while as
		// such, only about what its last statement was.
		{"while body ending in let", `
		let total = 0;
		for (v in [1, 2, 3]) {
			while (true) { let sink = 0; break; }
			total = total + v;
		}
		total;`, 6},

		// C-style for with a stack-neutral body: the leak is the post
		// section's `i++`, which is an expression statement too. This is why
		// "make the body stack-neutral" fixes a while but not a for.
		{"for post section only", `
		let total = 0;
		for (v in [1, 2, 3]) {
			for (let i = 0; i < 2; i++) { let sink = 0; }
			total = total + v;
		}
		total;`, 6},

		{"for body and post section", `
		let total = 0;
		for (v in [1, 2, 3]) {
			let seen = 0;
			for (let i = 0; i < 3; i++) { seen = seen + 1; }
			total = total + seen;
		}
		total;`, 9},

		// An init section that is an assignment rather than a `let` leaks once
		// per loop entry rather than once per iteration -- and a for-in body
		// re-enters the loop on every pass, so once per entry is still once
		// per outer iteration.
		{"for init section", `
		let total = 0;
		let i = 0;
		for (i = 0; i < 2; i = i + 1) { let sink = 0; }
		for (v in [1, 2, 3]) {
			for (i = 0; i < 2; i = i + 1) { let sink = 0; }
			total = total + i;
		}
		total;`, 6},

		// A for-in nested in a for-in: the inner loop's own trailing pop
		// balances its cursor, so the outer cursor stays put. This is the
		// spelling the workshop scripts use to work around the leak.
		{"for-in inside for-in", `
		let total = 0;
		for (v in [1, 2, 3]) {
			for (w in [10, 20]) { total = total + w; }
			total = total + v;
		}
		total;`, 96},

		// break and continue leave the inner loop from the middle of the body,
		// so they have to leave the outer cursor alone too.
		{"break out of inner while", `
		let total = 0;
		for (v in [1, 2, 3]) {
			let i = 0;
			while (true) {
				i = i + 1;
				if (i > 2) { break; }
			}
			total = total + i;
		}
		total;`, 9},

		{"continue in inner for", `
		let total = 0;
		for (v in [1, 2, 3]) {
			for (let i = 0; i < 4; i++) {
				if (i < 2) { continue; }
				total = total + 1;
			}
		}
		total;`, 6},

		// Three deep, one of each loop form.
		{"for-in, for and while nested", `
		let total = 0;
		for (v in [1, 2]) {
			for (let i = 0; i < 2; i++) {
				let j = 0;
				while (j < 2) {
					j = j + 1;
					total = total + v;
				}
			}
		}
		total;`, 12},

		// The plain non-nested forms, so a fix that over-corrects and drops a
		// value a loop body still needs is caught here rather than in the
		// suites that happen to use loops.
		{"while alone", `
		let i = 0;
		let total = 0;
		while (i < 5) { i = i + 1; total = total + i; }
		total;`, 15},

		{"for alone", `
		let total = 0;
		for (let i = 0; i < 5; i++) { total = total + i; }
		total;`, 10},

		{"for-in alone", `
		let total = 0;
		for (v in [1, 2, 3, 4]) { total = total + v; }
		total;`, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runVMTests(t, []vmTestCase{{input: tt.input, expected: tt.expected}})
		})
	}
}

// A loop is a statement and owes no value to anyone, so a function whose body
// ends in one returns null. That includes for-in, whose last emitted
// instruction is the pop dropping its cursor: turning that pop into a return,
// the way a trailing expression statement's pop is turned into one, hands the
// caller the cursor itself.
func TestFunctionEndingInLoopReturnsNull(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"for-in", `let f = fn() { for (v in [1, 2, 3]) { let x = v; } }; f();`},
		{"while", `let f = fn() { let i = 0; while (i < 3) { i = i + 1; } }; f();`},
		{"for", `let f = fn() { for (let i = 0; i < 3; i++) { let x = i; } }; f();`},
		{"for-in after a value", `let f = fn() { let n = 7; for (v in [1, 2]) { let x = v; } }; f();`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm, err := runEncryptedVM(tt.input)
			if err != nil {
				t.Fatalf("vm error: %s", err)
			}
			got := vm.LastPoppedStackElement()
			if _, ok := got.(*object.Null); !ok {
				t.Errorf("returned %T (%s), want Null", got, got.Inspect())
			}
		})
	}
}
