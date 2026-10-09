package compiler

import (
	"fmt"
	"strings"
	"testing"

	"mutant/code"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
)

// placeholderTarget is declared in compiler.go, where the jumps are emitted
// with it. One still sitting in a finished stream means the patch was written
// somewhere else -- which assertJumpsResolved now refuses at compile time, so
// these cases assert the same thing twice on purpose: once of the compiler's
// own record, and once of the bytecode, which is what a program actually runs.

// compileLoopCase parses and compiles input, failing the test on a parse error so
// that a typo in a case below cannot pass as an empty program. It hands back the
// compile error rather than failing on it, which is the point here and is why it
// is not builtin_names_test.go's compileSource.
func compileLoopCase(t *testing.T, input string) (*ByteCode, error) {
	t.Helper()

	p := parser.New(lexer.New(input))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) != 0 {
		t.Fatalf("parsing %q: %v", input, errs)
	}

	c := New()
	if err := c.Compile(program); err != nil {
		return nil, err
	}
	return c.ByteCode(), nil
}

// M26-CMP-002. loopContexts hangs off the Compiler rather than off the scope, so
// a break inside a closure used to find the *enclosing* loop's context and hand
// it a position that is an offset in the closure's stream. The loop then patched
// that offset in its own stream, overwriting operand 0 of whatever instruction
// sat there, and the closure kept its unpatched jump. Every case below compiled
// without complaint at e083ba7 and went wrong later instead: a silently wrong
// constant, a stack underflow blamed on an innocent line, or a nil dereference.
//
// There is no loop for these to leave, so the answer is the error the language
// already has for that.
func TestBreakOrContinueInsideAClosureIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		keyword string
	}{
		{
			"break in a closure in a for",
			`for (let i = 0; i < 2; i++) { let f = fn() { break; }; }`,
			"break",
		},
		{
			"continue in a closure in a for",
			`for (let i = 0; i < 2; i++) { let f = fn() { continue; }; }`,
			"continue",
		},
		{
			"break in a closure in a while",
			`let n = 0; while (n < 3) { let f = fn() { break; }; n = n + 1; }`,
			"break",
		},
		{
			"continue in a closure in a while",
			`let n = 0; while (n < 3) { let f = fn() { continue; }; n = n + 1; }`,
			"continue",
		},
		{
			"break in a closure in a for-in",
			`for (x in [1, 2, 3]) { let f = fn() { break; }; }`,
			"break",
		},
		{
			"continue in a closure in a for-in",
			`for (x in [1, 2, 3]) { let f = fn() { continue; }; }`,
			"continue",
		},
		{
			"break two closures deep",
			`for (x in [1]) { let f = fn() { let g = fn() { break; }; }; }`,
			"break",
		},
		{
			// The first break belongs to the closure's own loop and is fine; the
			// second has nothing to leave. One closure, both answers.
			"break after the closure's own loop has ended",
			`for (x in [1]) { let f = fn() { for (y in [2]) { break; } break; }; }`,
			"break",
		},
		{
			// The shape that printed a wrong number rather than failing: the
			// clobbered instruction was `marker`'s OpConstant, and the padding is
			// what made the overwritten operand land on a constant that exists.
			"the silently wrong constant",
			`let marker = 1; let pad = fn() { return [10, 11, 12, 13, 14, 15, 16, 17, 18, 19]; };
			 for (let i = 0; i < 2; i++) { let f = fn() { break; }; } marker;`,
			"break",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileLoopCase(t, tc.input)
			if err == nil {
				t.Fatalf("compiled; want it refused:\n%s", tc.input)
			}
			want := tc.keyword + " used outside of for loop"
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want it to contain %q", err, want)
			}
		})
	}
}

// The other half: a closure may still contain a loop of its own, and that loop's
// break belongs to it. Refusing these would trade one bug for a worse one, so
// each is compiled and then checked for a jump nobody patched.
func TestAClosureKeepsItsOwnLoop(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			"a loop inside a closure, the closure inside a loop",
			`let inner = fn(xs) { let t = 0; for (y in xs) { if (y > 2) { break; } t = t + y; } return t; };
			 for (let k = 0; k < 2; k++) { inner([1, 2, 3, 4]); }`,
		},
		{
			"a while inside a closure inside a while",
			`let outer = fn(limit) { let s = 0; let j = 0; while (j < limit) { j = j + 1; if (j == 2) { continue; } s = s + j; } return s; };
			 let n = 0; while (n < 2) { n = n + 1; outer(4); }`,
		},
		{
			"a closure in a loop that leaves no loop",
			`for (let q = 0; q < 3; q++) { let cb = fn(v) { return v * 2; }; cb(q); }`,
		},
		{
			"break and continue directly in each loop kind",
			`for (let i = 0; i < 4; i++) { if (i == 2) { break; } if (i == 1) { continue; } }
			 let n = 0; while (n < 4) { n = n + 1; if (n == 2) { continue; } if (n == 3) { break; } }
			 for (x in [1, 2, 3]) { if (x == 2) { continue; } if (x == 3) { break; } }`,
		},
		{
			"an inner loop's break leaves only the inner loop",
			`let hits = 0;
			 for (let m = 0; m < 3; m++) { for (n in [1, 2, 3]) { if (n == 2) { break; } hits = hits + 1; } }`,
		},
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

// unpatchedJumps names every jump in the program still pointing at
// placeholderTarget: the main stream and each compiled function in the constant
// pool, which is flat -- a nested literal is a constant of the program, not of
// its parent -- so no recursion is needed.
//
// A real target of exactly 9999 would need a stream that long, which none of
// these programs is anywhere near.
func unpatchedJumps(t *testing.T, bytecode *ByteCode) []string {
	t.Helper()

	streams := []struct {
		where string
		ins   code.Instructions
	}{{"<main>", bytecode.Instructions}}

	for i, constant := range bytecode.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			name := fn.Name
			if name == "" {
				name = "anonymous"
			}
			streams = append(streams, struct {
				where string
				ins   code.Instructions
			}{fmt.Sprintf("constant %d (%s)", i, name), fn.Instructions})
		}
	}

	var found []string
	for _, stream := range streams {
		for ip := 0; ip < len(stream.ins); {
			op := code.Opcode(stream.ins[ip])
			def, err := code.Lookup(byte(op))
			if err != nil {
				t.Fatalf("%s: unknown opcode %d at ip=%d", stream.where, op, ip)
			}
			operands, read := code.ReadOperands(def, stream.ins[ip+1:])
			switch op {
			case code.OpJump, code.OpJumpFalse, code.OpIterNext:
				if len(operands) > 0 && operands[0] == placeholderTarget {
					found = append(found, fmt.Sprintf("%s: %s at ip=%d", stream.where, def.Name, ip))
				}
			}
			ip += 1 + read
		}
	}
	return found
}
