package compiler

import (
	"strings"
	"testing"

	"mutant/code"
)

// A write through more than one container used to be emitted as a mutation of
// something nothing stored back. `grid[0][1] = 9` compiled, ran, changed
// nothing, and said nothing -- the worst answer a tool that reports on evidence
// can give, because the report is wrong and looks right.
//
// The behaviour these shapes produce belongs in parity/, where both engines run
// them. What is pinned here is the compiler's half: the target flattens to a
// base variable plus its hops, and a store lands back in that variable's slot.
// Without the final store the write is still lost, so `OpSetGlobal` appearing at
// all is the assertion that matters.
func TestNestedAssignmentStoresBackToItsBaseVariable(t *testing.T) {
	cases := []struct {
		name    string
		prelude string
		write   string
	}{
		{"array inside array", "let grid = [[1, 2], [3, 4]];", "grid[0][1] = 9;"},
		{"hash inside hash", `let h = {"a": {"b": 1}};`, `h["a"]["b"] = 2;`},
		{"hash inside array", `let rows = [{"n": 1}];`, `rows[0]["n"] = 99;`},
		{"array inside hash", `let deep = {"a": [1, 2]};`, `deep["a"][0] = 7;`},
		{"three deep", "let d3 = [[[1]]];", "d3[0][0][0] = 5;"},
		{"a field under two containers", `struct P { v; }; let db = {"r": [P { v: 1 }]};`, `db["r"][0].v = 7;`},
		{"a field under a field", "struct I { v; }; struct O { i; }; let o = O { i: I { v: 1 } };", "o.i.v = 42;"},
		{"an index under a field", `struct T { tags; }; let t = T { tags: ["a"] };`, `t.tags[0] = "z";`},
		{"a variable index", "let i = 0; let vi = [[1, 2]];", "vi[i][i] = 3;"},
		{"compound assignment", `let c = {"n": [10]};`, `c["n"][0] += 5;`},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// Counted against the same program without the write, because the
			// `let` that builds the container stores to a global too: what has
			// to be true is that the write adds one, not that one exists.
			before := countStores(t, testCase.prelude)
			after := countStores(t, testCase.prelude+" "+testCase.write)
			if after <= before {
				t.Errorf("%q emitted %d stores and the write added none: it is lost",
					testCase.write, after)
			}
		})
	}
}

// countStores compiles src and counts the instructions that put a value back
// into a variable -- every scope, because a nested write inside a function has
// exactly the same defect and the same fix.
func countStores(t *testing.T, src string) int {
	t.Helper()
	compiler := New()
	if err := compiler.Compile(parse(src)); err != nil {
		t.Fatalf("compile %q: %s", src, err)
	}
	stores := 0
	for _, scope := range compiler.scopes {
		instructions := scope.instructions
		for ip := 0; ip < len(instructions); {
			op := code.Opcode(instructions[ip])
			switch op {
			case code.OpSetGlobal, code.OpSetLocal, code.OpSetLocalCell, code.OpSetFree:
				stores++
			}
			definition, err := code.Lookup(byte(op))
			if err != nil {
				t.Fatalf("unknown opcode %d at %d", op, ip)
			}
			_, read := code.ReadOperands(definition, instructions[ip+1:])
			ip += 1 + read
		}
	}
	return stores
}

// What cannot be emitted correctly is a compile error, not a silent non-effect.
//
// Two shapes reach that rule. A target with no variable under it has nowhere to
// store its result, so the write would mutate a temporary and be dropped. And an
// index before the last one is loaded again on the way back out, so a call there
// would run a number of times the source does not say -- the workaround is one
// line, and the failure it replaces is not one anybody finds by reading.
func TestAssignmentsThatCannotBeEmittedAreRefused(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"an array literal is not a variable", "[1, 2][0] = 9;", "invalid assignment target"},
		{"a call is not a variable", "let a = [1]; foo()[0] = 1;", "invalid assignment target"},
		{"a call as an inner index", "let a = [[1]]; let f = fn() { return 0; }; a[f()][0] = 1;", "evaluated more than once"},
		{"an expression as an inner index", "let a = [[1]]; let i = 0; a[i + 0][0] = 1;", "evaluated more than once"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := compileErr(testCase.src)
			if err == nil {
				t.Fatalf("compiled, want a refusal naming %q", testCase.want)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Errorf("refusal was %q, want it to name %q", err, testCase.want)
			}
		})
	}
}

// The last index is compiled once, so it is free to be anything -- including a
// call. Refusing it too would be a restriction the implementation does not need.
func TestTheLastIndexMayHaveSideEffects(t *testing.T) {
	const src = "let f = fn() { return 0; }; let a = [[1]]; let i = 0; a[i][f()] = 1;"
	if err := compileErr(src); err != nil {
		t.Errorf("refused %q: %s", src, err)
	}
}
