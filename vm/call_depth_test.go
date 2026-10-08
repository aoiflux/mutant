package vm

// M26-VM-006 measured, in the engine a compiled program runs on.
//
// There was no ceiling on how deeply calls could nest. global.MaxFrames read like
// one and was not one -- ensureFrameCapacity grows the slice -- so a recursion with
// no stopping case ran until the host gave out. Measured on the unfixed tree:
// `let f = fn(n) { return f(n + 1); }; f(0);` reached 73,298 frames in 8 seconds and
// returned no error, and the same recursion written through map() reached 82,366.
//
// The map form is the dangerous one. Each of map, filter, each, reduce, sort_by,
// with_resource and test re-enters execLoop through CallClosureSync, which is a Go
// call, so that form grows the goroutine stack as well as the frame slice. Measured:
// 10,000 nested re-entries fit in 32 MiB of Go stack and not in 16 MiB, so the
// ceiling holds the Go stack to about a thirtieth of its 1 GiB default. Past the
// default the runtime ends the process with `fatal error: stack overflow`, which no
// recover contains -- the probe that measured it had a recover in the goroutine and
// the test binary still died, skipping the runner's deferred cleanup.
//
// The ceiling is on depth, not on calls: TestTheDepthBudgetUnwinds is the test that
// tells those two apart, because a limit written as a counter would break every
// program that calls a function in a loop.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"mutant/compiler"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/security"
)

// seal parses, compiles and encrypts source on the test's own goroutine.
//
// It checks p.Errors(), which the package's shared parse() does not: that one
// hands back whatever it managed to build, so a test whose Mutant source has a
// typo runs a truncated program. This file was first written with `for i in
// range(0, 3)` -- no parentheses, which this language requires -- and the depth
// tests passed while running a program that did nothing at all. A regression test
// that cannot fail is worse than no test, so the check is here.
func seal(t *testing.T, source string) (*compiler.ByteCode, string) {
	t.Helper()
	p := parser.New(lexer.New(source))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("this test's own Mutant source does not parse: %v\n%s", errs, source)
	}
	comp := compiler.New()
	if err := comp.Compile(program); err != nil {
		t.Fatalf("this test's own Mutant source does not compile: %v\n%s", err, source)
	}
	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	return mutil.EncryptByteCode(byteCode, password), password
}

// answerWithin runs source and hands back the VM's error and its last value.
//
// The deadline is as much the point of these tests as the error is. Without a
// ceiling the run does not finish, so a test that simply waited for it would hang
// the suite instead of failing it, and `go test -timeout` would blame the package
// rather than the case. The deadlines here are far past the time the ceiling takes
// to report, and the goroutine is left behind only on a failure that is fatal
// anyway.
func answerWithin(t *testing.T, source string, deadline time.Duration) (object.Object, error, time.Duration) {
	t.Helper()
	byteCode, password := seal(t, source)
	machine := NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- machine.Run() }()
	select {
	case err := <-done:
		took := time.Since(start)
		if err != nil {
			return nil, err, took
		}
		return machine.LastPoppedStackElement(), nil, took
	case <-time.After(deadline):
		t.Fatalf("no answer within %s: the run did not stop, which is the fault itself", deadline)
		return nil, nil, deadline
	}
}

// assertNamesTheLimit holds an error to the one thing a reader needs from it: the
// number they have to get under.
func assertNamesTheLimit(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error, so the recursion was allowed to run on", what)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(maxCallDepth)) {
		t.Errorf("%s: %q does not name the limit (%d)", what, err.Error(), maxCallDepth)
	}
	if !strings.Contains(err.Error(), "nested calls") {
		t.Errorf("%s: %q does not say what the number counts", what, err.Error())
	}
	// The row is about a Go-level failure: it arrived as a dump that killed the
	// process. Reaching this line is half the result; the other half is that what
	// came back reads like a Mutant error and not like a runtime's.
	if err != nil && strings.Contains(err.Error(), "goroutine") {
		t.Errorf("%s: %q reads like a Go stack dump", what, err.Error())
	}
}

// The plain form: OpCall nesting, which grows only the frame slice.
func TestRunawayRecursionIsAnError(t *testing.T) {
	_, err, took := answerWithin(t, "let f = fn(n) { return f(n + 1); }; f(0);", 60*time.Second)
	assertNamesTheLimit(t, err, "plain recursion")
	t.Logf("reported in %s", took.Round(time.Millisecond))
}

// The form that also grows the Go stack. Every executor-native builtin reaches a
// closure through CallClosureSync, which is a Go call; the row's crash came through
// map, and the others share the one path, so each is held to it here rather than
// trusted to.
func TestRecursionThroughAnExecutorNativeBuiltinIsAnError(t *testing.T) {
	for _, through := range []struct {
		name   string
		source string
	}{
		{"map", "let f = fn(n) { let r = map([1], fn(x) { return f(n + 1); }); return r[0]; }; f(0);"},
		{"filter", "let f = fn(n) { let r = filter([1], fn(x) { return f(n + 1); }); return len(r); }; f(0);"},
		{"each", "let f = fn(n) { each([1], fn(x) { return f(n + 1); }); return n; }; f(0);"},
		{"reduce", "let f = fn(n) { return reduce([1], fn(a, x) { return f(n + 1); }, 0); }; f(0);"},
		{"sort_by", "let f = fn(n) { let r = sort_by([1], fn(x) { return f(n + 1); }); return r[0]; }; f(0);"},
	} {
		_, err, took := answerWithin(t, through.source, 120*time.Second)
		assertNamesTheLimit(t, err, "recursion through "+through.name)
		t.Logf("through %-8s reported in %s", through.name, took.Round(time.Millisecond))
	}
}

// The ceiling has to be where it says it is, in both directions. A fix that refused
// every deep call would pass the tests above and break real programs.
func TestTheCeilingIsWhereItSaysItIs(t *testing.T) {
	for _, tt := range []struct {
		depth   int
		wantErr bool
	}{
		{maxCallDepth - 100, false},
		{maxCallDepth + 100, true},
	} {
		source := fmt.Sprintf(
			"let f = fn(n) { if (n >= %d) { return n; } return f(n + 1); }; f(0);", tt.depth)
		_, err, took := answerWithin(t, source, 120*time.Second)
		switch {
		case tt.wantErr:
			assertNamesTheLimit(t, err, fmt.Sprintf("bounded recursion %d deep", tt.depth))
		case err != nil:
			t.Fatalf("bounded recursion %d deep was refused: %v", tt.depth, err)
		}
		t.Logf("depth %-6d err=%v in %s", tt.depth, err != nil, took.Round(time.Millisecond))
	}
}

// A frame slice that starts at initialFrameCapacity and grows is the whole reason
// the old name was wrong. A recursion deeper than that start must still run.
func TestTheFrameSliceStillGrowsPastItsStartingSize(t *testing.T) {
	depth := initialFrameCapacity * 3
	source := fmt.Sprintf(
		"let f = fn(n) { if (n >= %d) { return n; } return f(n + 1); }; f(0);", depth)
	_, err, _ := answerWithin(t, source, 60*time.Second)
	if err != nil {
		t.Fatalf("recursion %d deep, past the %d-frame starting size, was refused: %v",
			depth, initialFrameCapacity, err)
	}
}

// The one that tells a depth limit from a call counter. 300 calls of 200 frames is
// 60,000 calls and never more than 200 of them at once, which is what every program
// that calls a function in a loop looks like. A counter would refuse this.
func TestTheDepthBudgetUnwinds(t *testing.T) {
	last, err, _ := answerWithin(t, `let f = fn(n) { if (n >= 200) { return n; } return f(n + 1); };
let total = 0;
for (let i = 0; i < 300; i++) { total = total + f(0); }
total`, 120*time.Second)
	if err != nil {
		t.Fatalf("60,000 calls, never more than 200 deep, were refused: %v", err)
	}
	testExpectedObject(t, 60000, last)
}

// Unwinding through the native path as well: a callback that recurses deeply but
// finitely, run many times over, leaves no depth behind it.
func TestTheDepthBudgetUnwindsThroughANativeReentry(t *testing.T) {
	last, err, _ := answerWithin(t, `let f = fn(n) {
	if (n >= 50) { return n; }
	let r = map([1], fn(x) { return f(n + 1); });
	return r[0];
};
let total = 0;
for (let i = 0; i < 100; i++) { total = total + f(0); }
total`, 120*time.Second)
	if err != nil {
		t.Fatalf("100 runs of a 50-deep native re-entry were refused: %v", err)
	}
	testExpectedObject(t, 5000, last)
}

// Depth is depth whoever spends it. Two functions calling each other is the shape a
// recursive-descent walk over nested evidence actually has, and it must reach the
// same ceiling and no sooner. Each takes the other as an argument because a function
// cannot refer to one declared after it.
func TestMutualRecursionIsBoundedByTheSameCeiling(t *testing.T) {
	const pair = `let even = fn(n, odd) { if (n == 0) { return true; } return odd(n - 1, even); };
let odd = fn(n, even) { if (n == 0) { return false; } return even(n - 1, odd); };
`
	_, err, _ := answerWithin(t, pair+"even(4000, odd);", 60*time.Second)
	if err != nil {
		t.Fatalf("mutual recursion 4,000 deep was refused: %v", err)
	}
	_, err, _ = answerWithin(t, pair+"even(40000, odd);", 120*time.Second)
	assertNamesTheLimit(t, err, "mutual recursion 40,000 deep")
}
