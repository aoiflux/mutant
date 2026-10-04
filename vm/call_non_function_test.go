package vm

import (
	"strings"
	"testing"

	"mutant/object"
)

// M26-VM-003. Calling a value that is not a function did not fail.
//
// execCall fell back to vm.stack[0] when the callee slot held anything that was
// not callable, and stack[0] is usually the function currently being run. So
// the call went somewhere, returned something, and the program carried on with
// a value it never computed. The refusal only appeared when stack[0] happened
// not to be callable either, which made the defect look like an occasional one.

// The row's own shape: the wrong call returns a plausible number. This is the
// case that must not pass silently, because nothing about the output says the
// program did something other than what it says.
func TestCallingANonFunctionDoesNotReinvokeTheCaller(t *testing.T) {
	// Under the fallback, x(1) called stack[0] -- outer -- with 1, took the
	// early return, and the program's value was 99.
	const source = `let outer = fn(n) { if (n > 0) { return 99; } let x = 5; return x(1); }; outer(0)`

	machine, err := runEncryptedVM(source)
	if err == nil {
		t.Fatalf("calling an integer succeeded and returned %s", machine.LastPoppedStackElement().Inspect())
	}
	if !strings.Contains(err.Error(), "calling non-function and non-built-in") {
		t.Fatalf("error = %q, want the non-function refusal", err)
	}
	if !strings.Contains(err.Error(), object.INTEGER_OBJ) {
		t.Fatalf("error = %q, want it to name INTEGER -- naming ENCRYPTED would be the stack's word, not the author's", err)
	}
}

func TestCallingANonFunctionFailsInsideAFunction(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   string
	}{
		{"an integer local", `let f = fn() { let x = 5; return x(); }; f();`, object.INTEGER_OBJ},
		{"a string local", `let f = fn() { let s = "hi"; return s(); }; f();`, object.STRING_OBJ},
		{"an array local", `let f = fn() { let a = [1]; return a(); }; f();`, object.ARRAY_OBJ},
		{"an integer at the top level", `let x = 5; x();`, object.INTEGER_OBJ},
		// The dispatch shape the row reports from a real program: a handler
		// looked up by a value from the evidence, with no handler for it.
		{"null from a missing hash key", `let f = fn() { let h = {"ntfs": fn() { 1 }}; let g = h["ext4"]; return g(); }; f();`, object.NULL_OBJ},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine, err := runEncryptedVM(tc.source)
			if err == nil {
				t.Fatalf("calling a %s succeeded and returned %s", tc.want, machine.LastPoppedStackElement().Inspect())
			}
			if !strings.Contains(err.Error(), "calling non-function and non-built-in") {
				t.Fatalf("error = %q, want the non-function refusal", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

// The fix must not cost a legitimate call anything, including the three shapes
// that reach the callee slot by a different route than a plain name.
func TestTheCallableShapesStillCall(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   int64
	}{
		{"a closure by name", `let f = fn() { 7 }; f()`, 7},
		{"a closure from a hash", `let h = {"go": fn() { 8 }}; let g = h["go"]; g()`, 8},
		{"a closure from an array", `let a = [fn() { 9 }]; let g = a[0]; g()`, 9},
		{"a closure returned by a call", `let mk = fn() { fn() { 10 } }; let g = mk(); g()`, 10},
		{"recursion through the enclosing name", `let fact = fn(n) { if (n < 2) { return 1; } return n * fact(n - 1); }; fact(5)`, 120},
		{"a builtin", `len("abcd")`, 4},
		{"a closure passed as an argument", `let apply = fn(g) { g() }; apply(fn() { 11 })`, 11},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runForInteger(t, tc.source); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// A variable captured by the closure being called is one location, not two.
// The fix changed which object reaches callClosure, and nothing else in this
// file calls a closure that captures anything.
//
// Worth being exact about what this does not catch, because the comment here
// first claimed more than it earned. The first version of this fix decrypted
// the callee slot before the type switch, so the refusal could name INTEGER
// instead of ENCRYPTED, and DecryptObject's CLOSURE_OBJ arm rebuilds a closure
// around a fresh Free slice: a copy per call. All three cases below pass
// against that version too. DecryptObject passes a cell through by pointer, so
// the copied Free slice still holds the same cells and a write through one
// still lands in the frame that owns it. What the copy cost was one allocation
// per call and two when the closure captures -- measured, not surmised -- which
// is a benchmark's finding and not a test's.
//
// So these cases are not a bite against that version. They are the floor under
// the object identity the call path now relies on: if the callee is ever copied
// again by something that does not pass cells by pointer, this is what says so.
func TestAWorkingCallGetsTheClosureOnTheStackNotACopy(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   int64
	}{
		{
			// Two calls through the same captured cell, and the write has to be
			// visible to the frame that declared n rather than to the closure.
			"a write through a captured variable reaches the enclosing frame",
			`let probe = fn() { let n = 0; let bump = fn() { n = n + 1; }; bump(); bump(); return n; }; probe()`,
			2,
		},
		{
			// The cell outlives the frame that made it: mk has returned by the
			// time c is called at all.
			"a counter called three times counts three times",
			`let mk = fn() { let n = 0; return fn() { n = n + 1; return n; }; }; let c = mk(); c(); c(); c()`,
			3,
		},
		{
			// A capture read and never written arrives with the value it
			// captured. This one is not a cell -- base is never assigned to --
			// so it travels in Free by value.
			"a read-only capture still reads",
			`let mk = fn(base) { fn(n) { base + n } }; let add10 = mk(10); add10(5)`,
			15,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runForInteger(t, tc.source); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}
