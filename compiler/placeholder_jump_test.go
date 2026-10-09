package compiler

import (
	"strings"
	"testing"

	"mutant/code"
)

// A forward jump is emitted before anyone knows where it goes, with
// placeholderTarget standing in for the target, and something later has to come
// back and write the real one. Nothing used to check that anything did.
//
// Two defects fixed in the same commit as this guard were exactly that, and
// neither failed at the point of the mistake: M26-CMP-020, a continue in a
// counting for's post section, whose list of positions to patch had already
// been walked by the time the post section was compiled; and M26-CMP-021, a
// break in that same post section, recorded in a copy of loopContexts that an
// append had reallocated away from the one the patch loop read. In both the
// compiler reported nothing and the program ran.
//
// What it did then was decided by its own length. Measured, all three: a stream
// shorter than the placeholder jumped off the end, the run was treated as
// finished, and the program answered whatever was last popped -- BOOLEAN(true),
// for a program whose value is an integer. A longer one decoded whatever byte
// sat at that offset and said the bytecode may be damaged, or decrypted with
// the wrong key, or built by a newer version of mutant, none of which was true.
// And one whose offset happened to land on an instruction boundary resumed in
// unrelated code and did not come back.
//
// So the tests below are not about jumps. They are about the compiler being
// able to say that it finished, which is the one claim none of those three
// outcomes could contradict.

// TestAnUnresolvedPlaceholderIsNotLetThrough checks the guard where it is
// cheapest to be sure of: the record itself, driven directly rather than
// through a program, because no program can ask for an unpatched jump.
func TestAnUnresolvedPlaceholderIsNotLetThrough(t *testing.T) {
	c := New()
	c.posLine, c.posCol = 7, 13
	pos := c.emitPlaceholder(code.OpJump)

	err := c.assertJumpsResolved(0, "the program")
	if err == nil {
		t.Fatal("a jump emitted with the placeholder and never patched was let through")
	}
	for _, want := range []string{"OpJump", "line 7", "column 13", "the program"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to name %q", err, want)
		}
	}

	// And the debt is discharged by the one thing that discharges it.
	c.changeOperand(pos, 0)
	if err := c.assertJumpsResolved(0, "the program"); err != nil {
		t.Fatalf("a patched jump is still owed a target: %v", err)
	}
}

// TestAPatchWrittenSomewhereElseDoesNotDischargeTheDebt is M26-CMP-021 in
// miniature. That defect did not forget to patch: it patched, from a list that
// a reallocation had left behind, so the write landed on nothing while the jump
// it was meant for kept the placeholder. A guard that counted patches rather
// than naming positions would have called that discharged.
func TestAPatchWrittenSomewhereElseDoesNotDischargeTheDebt(t *testing.T) {
	c := New()
	c.emitPlaceholder(code.OpJumpFalse)
	elsewhere := c.emit(code.OpJump, 0)

	c.changeOperand(elsewhere, 4)

	err := c.assertJumpsResolved(0, "the program")
	if err == nil {
		t.Fatal("patching a different instruction counted as patching this one")
	}
	if !strings.Contains(err.Error(), "OpJumpFalse") {
		t.Fatalf("error = %q, want it to name the jump still owed a target", err)
	}
}

// TestTheMarkLeavesAnEnclosingConstructsJumpAlone covers the reason the check
// takes a mark at all. A program is not always the outermost thing compiled,
// and an `if` that has emitted its own forward jump is still holding it while
// everything inside the branch is compiled. Blaming the inner construct for it
// would turn a correct compile into an internal error.
func TestTheMarkLeavesAnEnclosingConstructsJumpAlone(t *testing.T) {
	c := New()
	c.emitPlaceholder(code.OpJumpFalse)

	mark := len(c.currentInstructions())
	if err := c.assertJumpsResolved(mark, "the inner program"); err != nil {
		t.Fatalf("an enclosing construct's jump was charged to the inner one: %v", err)
	}

	// From zero it is seen, which is what the scope-end check does.
	if err := c.assertJumpsResolved(0, "the program"); err == nil {
		t.Fatal("the enclosing jump was not seen from the start of the stream")
	}
}

// TestLeavingAScopeWithAnUnresolvedJumpIsRefused is the other check site. A
// function's stream stops being editable when the scope closes -- the positions
// a patch would use are offsets into it, and once it is a constant in the pool
// nothing holds those offsets any more -- so that is the last moment the
// question can be asked.
func TestLeavingAScopeWithAnUnresolvedJumpIsRefused(t *testing.T) {
	c := New()
	c.enterScope()
	c.emitPlaceholder(code.OpJump)

	if _, _, err := c.leaveScope(); err == nil {
		t.Fatal("a function body left with a jump owed a target")
	}

	// A scope whose jumps were all patched leaves normally. The one above is
	// still on the stack, since leaveScope refused before unwinding it.
	c.changeOperand(0, 2)
	if _, _, err := c.leaveScope(); err != nil {
		t.Fatalf("a body with every jump patched was refused: %v", err)
	}
}

// TestEveryConstructThatEmitsAPlaceholderResolvesIt is the breadth half. Each
// program below reaches at least one of the eighteen places the compiler emits
// a jump it cannot yet target, and the guard now runs on every compile, so
// reaching the end of Compile with no error is the assertion. The bytecode is
// checked as well, because the guard reasons about the compiler's own record
// and unpatchedJumps reads what a program would actually run.
func TestEveryConstructThatEmitsAPlaceholderResolvesIt(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"if with no else", `let a = 1; if (a == 1) { a = 2; } a;`},
		{"if with an else", `let a = 1; if (a == 2) { a = 2; } else { a = 3; } a;`},
		{"and", `let t = true; let f = false; t && f;`},
		{"or", `let t = true; let f = false; f || t;`},
		{"and inside or", `let t = true; (t && false) || (t || false);`},
		{"a counting for", `let n = 0; for (let i = 0; i < 3; i++) { n = n + i; } n;`},
		{"a while", `let n = 0; while (n < 3) { n = n + 1; } n;`},
		{"a for in", `let n = 0; for (v in [1, 2, 3]) { n = n + v; } n;`},
		{"break and continue in each loop kind", `
			let n = 0;
			for (let i = 0; i < 4; i++) { if (i == 1) { continue; } if (i == 3) { break; } n = n + 1; }
			let j = 0; while (j < 4) { j = j + 1; if (j == 2) { continue; } if (j == 3) { break; } n = n + 1; }
			for (v in [1, 2, 3, 4]) { if (v == 2) { continue; } if (v == 4) { break; } n = n + 1; }
			n;`},
		{"a break in an operand position", `
			let n = 0;
			for (v in [1, 2, 3]) { n = n + if (v == 2) { break; } else { v }; }
			n;`},
		{"a break in a for's post section", `
			let n = 0;
			for (let i = 0; i < 9; i = i + if (n > 1) { break; } else { 1 }) { n = n + 1; }
			n;`},
		{"a loop inside a for's post section", `
			let n = 0;
			for (let i = 0; i < 3; i = i + if (n > 4) { break; } else { for (w in [1, 2]) { n = n + 1; } 1 }) { n = n + 1; }
			n;`},
		{"match with alternatives and a wildcard", `
			let say = fn(x) { match (x) { 1 | 2 => "small", 9 => "big", _ => "middling" } };
			say(1); say(9); say(5);`},
		// No wildcard, so the chain ends in OpMatchFail rather than in an arm,
		// and the last arm's own test is the one jump that has to be patched past
		// it. A wildcard arm is emitted with no test at all, which is why it is
		// the one arm that patches nothing -- the case above covers that path.
		{"match with no wildcard", `let f = fn(x) { match (x) { 1 => "one", 2 => "two" } }; f(1);`},
		{"a loop inside a match arm", `match (1) { 2 => { while (false) { } }, _ => { for (v in [1]) { break; } } };`},
		{"a closure with its own loop", `
			let f = fn(xs) { let t = 0; for (y in xs) { if (y > 2) { break; } t = t + y; } return t; };
			f([1, 2, 3, 4]);`},
		{"a loop in a closure in a loop in a closure", `
			let g = fn(n) { let s = 0; let h = fn(m) { let u = 0; while (u < m) { u = u + 1; if (u == 2) { continue; } } return u; };
			                for (let k = 0; k < n; k++) { s = s + h(3); } return s; };
			g(2);`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bytecode, err := compileLoopCase(t, tc.input)
			if err != nil {
				t.Fatalf("Compile: %v\n%s", err, tc.input)
			}
			if left := unpatchedJumps(t, bytecode); len(left) != 0 {
				t.Fatalf("jumps left on the placeholder:\n  %s", strings.Join(left, "\n  "))
			}
		})
	}
}
