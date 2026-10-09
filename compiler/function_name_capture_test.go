package compiler

import (
	"strings"
	"testing"

	"mutant/code"
	"mutant/lexer"
	"mutant/parser"
)

// A function's own name is not storage at any depth, and the refusal has to say
// so at any depth.
//
// The check used to ask freeOriginal, which answers for one hop. One hop is the
// whole chain only while the assignment sits directly inside the function that
// the name belongs to -- add a third function and the first hop is the middle
// one's capture of the name, a FreeScope symbol that reads as an ordinary
// captured variable. So three deep the write compiled, and the VM refused it
// instead: `op=OpSetFree: captured variable 0 is not assignable storage`, which
// is the opaque failure the compile-time refusal exists to replace.
//
// Depths one and two are here alongside three and four on purpose. They were
// always refused, and the thing worth seeing in one place is that the answer no
// longer depends on the depth.
func TestAssigningTheEnclosingFunctionsOwnNameIsRefusedAtEveryDepth(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"directly in the function itself",
			`let f = fn(x) { f = 1; return x; };`,
		},
		{
			"one closure in",
			`let f = fn(x) {
  let g = fn() { f = 1; return 0; };
  g();
  return x;
};`,
		},
		{
			// The first depth the old check let through.
			"two closures in",
			`let f = fn(x) {
  let g = fn() {
    let h = fn() { f = 1; return 0; };
    h();
    return 0;
  };
  g();
  return x;
};`,
		},
		{
			// Four, because a walk that follows exactly one extra hop would pass
			// at three and fail here.
			"three closures in",
			`let f = fn(x) {
  let g = fn() {
    let h = fn() {
      let i = fn() { f = 1; return 0; };
      i();
      return 0;
    };
    h();
    return 0;
  };
  g();
  return x;
};`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := compileForAssignTest(t, tc.src)
			if err == nil {
				t.Fatal("compiled; the name of the function being defined is not storage at any depth")
			}
			if !strings.Contains(err.Error(), "cannot assign to the name of the function being defined") {
				t.Errorf("error = %q, want the refusal that names the cause", err)
			}
			if !strings.Contains(err.Error(), "f") {
				t.Errorf("error = %q, want it to name f", err)
			}
		})
	}
}

// The refusal has to stay as narrow at depth as it is at one level: following
// the capture chain out must not swallow the writes that are to real cells.
//
// Each of these resolves to a FreeScope symbol at the point of assignment, so
// each one reaches the same arm of emitStoreOnly as the refused cases above --
// the only difference is where the chain ends.
func TestWritesThroughADeepCaptureStillCompile(t *testing.T) {
	cases := []struct {
		name string
		src  string
		// setsFree says the program must still emit a write through a captured
		// cell. "Compiles" alone would also be satisfied by a compiler that
		// stopped emitting the write, which is the other way to get this wrong.
		setsFree bool
	}{
		{
			// Reading the name is what recursion is, and it is reached by the
			// same chain. OpCurrentClosure is a read of a value, not of storage.
			name: "reading the function's own name two closures in",
			src: `let f = fn(x) {
  let g = fn() {
    let h = fn() { return f; };
    return h();
  };
  return g();
};`,
		},
		{
			name: "reading the function's own name three closures in",
			src: `let f = fn(x) {
  let g = fn() {
    let h = fn() {
      let i = fn() { return f; };
      return i();
    };
    return h();
  };
  return g();
};`,
		},
		{
			// The chain ends in a LocalScope original, so the write goes through
			// the cell the owner boxed. This is the case a refusal that merely
			// noticed "the chain has more than one hop" would have broken.
			name: "a different captured variable two closures in",
			src: `let f = fn(x) {
  let acc = 0;
  let g = fn() {
    let h = fn() { acc = 5; return 0; };
    h();
    return 0;
  };
  g();
  return acc;
};`,
			setsFree: true,
		},
		{
			name: "a different captured variable three closures in",
			src: `let f = fn(x) {
  let acc = 0;
  let g = fn() {
    let h = fn() {
      let i = fn() { acc = 5; return 0; };
      i();
      return 0;
    };
    h();
    return 0;
  };
  g();
  return acc;
};`,
			setsFree: true,
		},
		{
			// A local that shadows the function's own name. The chain ends in
			// that local, so the write is to storage and must be allowed -- the
			// refusal is about what the name means here, not about the spelling.
			name: "a local shadowing the function's own name, two closures in",
			src: `let f = fn(x) {
  let g = fn() {
    let f = 2;
    let h = fn() { f = 1; return 0; };
    h();
    return f;
  };
  return g();
};`,
			setsFree: true,
		},
		{
			// From outside there is no FunctionScope binding in sight: f is an
			// ordinary global, and rebinding it is an ordinary assignment.
			name: "assigning the name from outside the function",
			src:  `let f = fn(x) { return x; }; f = 2; f;`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New()
			if err := c.Compile(parser.New(lexer.New(tc.src)).ParseProgram()); err != nil {
				t.Fatalf("Compile failed on an assignment that is to real storage: %s", err)
			}
			if tc.setsFree && !emittedOpcodes(t, c.ByteCode())[code.OpSetFree] {
				t.Error("no OpSetFree: the write no longer goes through the captured cell")
			}
		})
	}
}

// The walk itself, against tables built by hand, because the compiler can only
// reach it through source that happens to produce the right chain.
//
// Resolving from the innermost table is what builds a chain: each table on the
// way back out files its own free symbol, so after the two Resolve calls below
// every table between deepest and fnTable holds two free entries -- the
// function's own name at 0 and an ordinary local at 1 -- and the two differ only
// in what the chain ends in.
func TestFreeCapturesFunctionNameFollowsTheWholeChain(t *testing.T) {
	global := NewSymbolTable()
	global.Define("top")

	fnTable := NewEnclosedSymbolTable(global)
	fnTable.DefineFunctionName("f")
	fnTable.Define("acc")

	mid := NewEnclosedSymbolTable(fnTable)
	inner := NewEnclosedSymbolTable(mid)
	deepest := NewEnclosedSymbolTable(inner)

	for _, name := range []string{"f", "acc"} {
		symbol, ok := deepest.Resolve(name)
		if !ok {
			t.Fatalf("%s is not resolvable from the innermost table", name)
		}
		if symbol.Scope != FreeScope {
			t.Fatalf("%s resolved to scope %s, want %s", name, symbol.Scope, FreeScope)
		}
	}

	// A global is reached directly and never captured, so nothing it does can
	// shift the two indices the assertions below name.
	if _, ok := deepest.Resolve("top"); !ok {
		t.Fatal("top is not resolvable from the innermost table")
	}
	if len(deepest.FreeSymbols) != 2 {
		t.Fatalf("the innermost table captured %d names, want 2", len(deepest.FreeSymbols))
	}

	tables := map[string]*SymbolTable{"one hop out": mid, "two hops out": inner, "three hops out": deepest}
	for where, table := range tables {
		if !table.freeCapturesFunctionName(0) {
			t.Errorf("%s: free 0 is the function's own name and was not recognised as one", where)
		}
		if table.freeCapturesFunctionName(1) {
			t.Errorf("%s: free 1 is an ordinary captured local and must stay assignable", where)
		}
	}

	// Nothing a walk can be asked that has no answer may invent one, and in
	// particular none of these may spin: the root holds no free symbols at all,
	// which is also what stops the walk above at fnTable's own binding.
	if global.freeCapturesFunctionName(0) {
		t.Error("the root table reported a captured function name; it captures nothing")
	}
	for _, index := range []int{-1, 2, 99} {
		if deepest.freeCapturesFunctionName(index) {
			t.Errorf("free %d does not exist and was reported as the function's own name", index)
		}
	}
}
