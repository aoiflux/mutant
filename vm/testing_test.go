package vm

import (
	"fmt"
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// runTestLedger compiles and runs a program the way `mutant test` runs one --
// sealed like an artifact, and NOT in secure mode, because a test run catches
// what the program got wrong and secure mode is where nothing gets caught.
func runTestLedger(t *testing.T, source string) *VM {
	t.Helper()

	program := parse(source)
	comp := compiler.New()
	// The same injection generator.CompileForTest does. A VM built with a
	// password refuses to run a stream that is missing the security-check
	// opcodes, and a test helper that skipped them would be exercising a
	// program shape `mutant test` never produces.
	comp.EnableSecurityOpcodeInjection()
	if err := comp.Compile(program); err != nil {
		t.Fatalf("compiler error: %s", err)
	}

	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := NewWithPasswordAndGlobalStoreMode(byteCode, password, make([]object.Object, global.GlobalSize), false)
	if err := machine.Run(); err != nil {
		t.Fatalf("run error: %s", err)
	}
	return machine
}

// resultNames renders the ledger as "name:outcome" pairs, which is the whole
// answer for most of these tests in one line.
func resultNames(machine *VM) []string {
	var out []string
	for _, result := range machine.TestResults() {
		outcome := "ok"
		if !result.Passed() {
			outcome = "FAIL"
		}
		name := result.Name
		if name == "" {
			name = "<file>"
		}
		out = append(out, name+":"+outcome)
	}
	return out
}

func assertLedger(t *testing.T, machine *VM, want ...string) {
	t.Helper()
	got := resultNames(machine)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("ledger = %v, want %v", got, want)
	}
}

// A program that never touches the testing builtins has no ledger at all. That
// is what tells the runner a file is a plain program rather than a suite, so it
// has to stay nil rather than become an empty slice.
func TestAProgramThatAssertsNothingHasNoLedger(t *testing.T) {
	machine := runTestLedger(t, `let x = 1 + 1; x;`)
	if results := machine.TestResults(); results != nil {
		t.Fatalf("expected no ledger, got %d results", len(results))
	}
}

func TestEachAssertionPassesAndFails(t *testing.T) {
	cases := []struct {
		name     string
		pass     string
		fail     string
		wantText string
	}{
		{"assert", `assert(1 < 2)`, `assert(1 > 2)`, "assert: false is not true"},
		{"assert_eq", `assert_eq(2, 2)`, `assert_eq(2, 3)`, "assert_eq: got 2, want 3"},
		{"assert_ne", `assert_ne(2, 3)`, `assert_ne(2, 2)`, "assert_ne: both are 2"},
		{"assert_contains/string", `assert_contains("hello", "ell")`, `assert_contains("hello", "z")`, `does not contain the substring "z"`},
		{"assert_contains/array", `assert_contains([1, 2], 2)`, `assert_contains([1, 2], 9)`, "does not contain the element 9"},
		{"assert_contains/hash", `assert_contains({"a": 1}, "a")`, `assert_contains({"a": 1}, "b")`, `does not contain the key "b"`},
		{"assert_err", `assert_err(error("boom"))`, `assert_err(7)`, "want an error, got INTEGER 7"},
		{"assert_err/substring", `assert_err(error("boom"), "oom")`, `assert_err(error("boom"), "bang")`, `does not mention "bang"`},
		{"assert_ok", `assert_ok(7)`, `assert_ok(error("boom"))`, "assert_ok: boom"},
		{"fail", ``, `fail("nope")`, "nope"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.pass != "" {
				machine := runTestLedger(t, fmt.Sprintf("test(\"t\", fn() { %s; });", c.pass))
				assertLedger(t, machine, "t:ok")
			}

			machine := runTestLedger(t, fmt.Sprintf("test(\"t\", fn() { %s; });", c.fail))
			assertLedger(t, machine, "t:FAIL")

			failures := machine.TestResults()[0].Failures
			if len(failures) != 1 {
				t.Fatalf("expected 1 failure, got %d", len(failures))
			}
			if !strings.Contains(failures[0].Message, c.wantText) {
				t.Errorf("failure message %q does not contain %q", failures[0].Message, c.wantText)
			}
		})
	}
}

// A failure names the line it was written on. This is the whole reason the
// assertions are run by the executor rather than by the builtin package: the
// position comes from the frame's line table, the same table the traceback and
// the debugger read.
func TestAFailureCarriesItsLine(t *testing.T) {
	machine := runTestLedger(t, "test(\"t\", fn() {\n\n    assert_eq(1, 2);\n});")

	failures := machine.TestResults()[0].Failures
	if len(failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(failures))
	}
	if failures[0].Line != 3 {
		t.Errorf("failure line = %d, want 3", failures[0].Line)
	}
}

// An assertion is also a value, so a program that looks at what it returned
// sees the same verdict the ledger recorded. Without this a test file run as an
// ordinary program would be silently passing.
func TestAnAssertionIsAlsoAValue(t *testing.T) {
	machine := runTestLedger(t, `assert_eq(1, 2);`)
	if _, isError := machine.LastPoppedStackElement().(*object.Error); !isError {
		t.Fatalf("a failed assertion returned %s, want an error value", machine.LastPoppedStackElement().Type())
	}

	machine = runTestLedger(t, `assert_eq(1, 1);`)
	if boolean, ok := machine.LastPoppedStackElement().(*object.Boolean); !ok || !boolean.Value {
		t.Fatalf("a passing assertion returned %#v, want true", machine.LastPoppedStackElement())
	}
}

// An assertion outside every test belongs to the file, and the file's result
// exists only when something was actually recorded against it.
func TestAnAssertionOutsideEveryTestLandsOnTheFile(t *testing.T) {
	machine := runTestLedger(t, "test(\"t\", fn() { assert(true); });\nassert_eq(1, 2);")
	assertLedger(t, machine, "t:ok", "<file>:FAIL")

	machine = runTestLedger(t, `test("t", fn() { assert(true); });`)
	assertLedger(t, machine, "t:ok")
}

func TestSubtestsAreNamedAfterTheirParent(t *testing.T) {
	machine := runTestLedger(t, `
test("outer", fn() {
    test("inner", fn() { assert(true); });
});`)
	assertLedger(t, machine, "outer:ok", "outer/inner:ok")
}

// A parent whose subtest failed has failed, even though it asserted nothing
// itself -- otherwise a suite could report a green parent over a red child.
func TestAFailingSubtestFailsItsParent(t *testing.T) {
	machine := runTestLedger(t, `
test("outer", fn() {
    test("inner", fn() { fail("no"); });
});`)
	assertLedger(t, machine, "outer:FAIL", "outer/inner:FAIL")

	if failures := machine.TestResults()[0].Failures; len(failures) != 0 {
		t.Errorf("the parent recorded %d failures of its own, want 0", len(failures))
	}
}

// The point of catching a test that dies: the file keeps going. Without it one
// division by zero costs every test written after it.
func TestATestThatDiesDoesNotStopTheFile(t *testing.T) {
	machine := runTestLedger(t, `
test("dies", fn() { let x = 1 / 0; });
test("still runs", fn() { assert(true); });`)
	assertLedger(t, machine, "dies:FAIL", "still runs:ok")

	failed := machine.TestResults()[0]
	if failed.Err == nil {
		t.Fatal("the dying test recorded no error")
	}
	if !strings.Contains(failed.Err.Message, "division by zero") {
		t.Errorf("error = %q, want it to mention division by zero", failed.Err.Message)
	}
	if failed.Err.Line != 2 {
		t.Errorf("error line = %d, want 2", failed.Err.Line)
	}
}

func TestFixturesRunAroundEachTest(t *testing.T) {
	machine := runTestLedger(t, `
let log = [];
before_each(fn() { log = push(log, "before"); });
after_each(fn() { log = push(log, "after"); });

test("one", fn() { log = push(log, "one"); });
test("two", fn() { log = push(log, "two"); });
log;`)

	want := "[before, one, after, before, two, after]"
	if got := machine.LastPoppedStackElement().Inspect(); got != want {
		t.Errorf("log = %s, want %s", got, want)
	}
}

// A nested test inherits the fixtures of every scope outside it, and its own
// scope's fixtures apply to what it contains rather than to itself.
func TestFixturesNestWithTheTests(t *testing.T) {
	machine := runTestLedger(t, `
let log = [];
before_each(fn() { log = push(log, "outer-before"); });

test("parent", fn() {
    before_each(fn() { log = push(log, "inner-before"); });
    test("child", fn() { log = push(log, "child"); });
});
log;`)

	want := "[outer-before, outer-before, inner-before, child]"
	if got := machine.LastPoppedStackElement().Inspect(); got != want {
		t.Errorf("log = %s, want %s", got, want)
	}
}

// A fixture applies to the tests declared after it. Applying it to one declared
// before would mean setup running after the thing it was supposed to prepare.
func TestAFixtureDoesNotReachBackwards(t *testing.T) {
	machine := runTestLedger(t, `
let log = [];
test("first", fn() { log = push(log, "first"); });
before_each(fn() { log = push(log, "before"); });
test("second", fn() { log = push(log, "second"); });
log;`)

	want := "[first, before, second]"
	if got := machine.LastPoppedStackElement().Inspect(); got != want {
		t.Errorf("log = %s, want %s", got, want)
	}
}

// A fixture that dies is a real defect, so it fails the test it was attached to
// and says which fixture it was. The test body still runs: a broken teardown
// should not also hide the result of what it was tearing down.
func TestAFixtureThatDiesFailsTheTest(t *testing.T) {
	machine := runTestLedger(t, `
before_each(fn() { let x = 1 / 0; });
test("t", fn() { assert(true); });`)
	assertLedger(t, machine, "t:FAIL")

	failures := machine.TestResults()[0].Failures
	if len(failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(failures))
	}
	if !strings.HasPrefix(failures[0].Message, "before_each: ") {
		t.Errorf("failure %q does not name the fixture it came from", failures[0].Message)
	}
}

// Strings are quoted in a failure message, because half of what a string
// assertion catches is whitespace and "a " and "a" are the same picture unless
// something draws the quotes.
func TestStringsAreQuotedInFailures(t *testing.T) {
	machine := runTestLedger(t, `test("t", fn() { assert_eq("a ", "a"); });`)
	message := machine.TestResults()[0].Failures[0].Message
	if !strings.Contains(message, `got "a ", want "a"`) {
		t.Errorf("message = %q, want it to quote both strings", message)
	}
}

// Null renders as a word. It inspects as the empty string, which in a sentence
// reads as a missing value rather than as null.
func TestNullRendersAsAWord(t *testing.T) {
	machine := runTestLedger(t, `test("t", fn() { assert_eq([][0], 1); });`)
	message := machine.TestResults()[0].Failures[0].Message
	if !strings.Contains(message, "got null, want 1") {
		t.Errorf("message = %q, want it to name null", message)
	}
}

// Two hashes built in different orders are the same hash. Comparing rendered
// forms is what makes that true, since Hash.Inspect sorts its keys.
func TestHashesCompareRegardlessOfOrder(t *testing.T) {
	machine := runTestLedger(t, `test("t", fn() { assert_eq({"a": 1, "b": 2}, {"b": 2, "a": 1}); });`)
	assertLedger(t, machine, "t:ok")
}

// A very long value is cut short. A failure message is read in a terminal, and
// the difference has already been shown by the time the second line wraps.
func TestLongValuesAreTruncated(t *testing.T) {
	long := strings.Repeat("x", 500)
	machine := runTestLedger(t, fmt.Sprintf(`test("t", fn() { assert_eq("%s", "short"); });`, long))
	message := machine.TestResults()[0].Failures[0].Message
	if !strings.Contains(message, "bytes)") {
		t.Errorf("message = %q, want it to say how much was cut", message)
	}
	if len(message) > 400 {
		t.Errorf("message is %d bytes; truncation did not take", len(message))
	}
}

// The test body and every fixture take no parameters. Saying so at the call is
// better than calling with nothing and letting the body read an unset slot.
func TestTheTestBodyTakesNoParameters(t *testing.T) {
	machine := runTestLedger(t, `test("t", fn(x) { assert(true); });`)
	if machine.TestResults() != nil {
		t.Fatalf("a rejected test was still recorded: %v", resultNames(machine))
	}
	errObj, isError := machine.LastPoppedStackElement().(*object.Error)
	if !isError {
		t.Fatalf("got %s, want an error", machine.LastPoppedStackElement().Type())
	}
	if !strings.Contains(errObj.Message, "no parameters") {
		t.Errorf("error = %q, want it to say the function takes no parameters", errObj.Message)
	}
}

// The optional trailing message is prefixed to the failure, so a report says
// what the check was for before it says what it saw.
func TestTheOptionalMessageIsPrefixed(t *testing.T) {
	machine := runTestLedger(t, `test("t", fn() { assert_eq(1, 2, "counts match"); });`)
	message := machine.TestResults()[0].Failures[0].Message
	if !strings.HasPrefix(message, "counts match: ") {
		t.Errorf("message = %q, want it to lead with the note", message)
	}
}
