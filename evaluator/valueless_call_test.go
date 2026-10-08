package evaluator

// M26-EVL-020 and M26-VM-007 in the engine that expands macros.
//
// Two faults, both of them about what a value is worth.
//
// `!` compared rendered text. object.Null renders as the empty string, so the NULL
// arm also caught "" -- the right answer by accident -- and the FALSE arm also caught
// the string "false", which is a non-empty string and therefore truthy, so
// `!"false"` was true here and false in the VM. 0 and 0.0 matched nothing and came
// back false, as in the VM.
//
// And a function body that produces no value produced a Go nil rather than NULL.
// eval returns nil for an empty block and for a block whose last statement is a
// `let` -- which is how a function that works by side effect is written. The nil went
// to the program, and whatever touched it next dereferenced it. There is no recover
// above this: because this engine is what computes unquote(...) during macro
// expansion, `mutant prog.mut` ended with a Go stack trace at compile time.

import (
	"mutant/object"
	"testing"
)

// The bodies that produce no value, and every place the nil used to arrive.
//
// A test that only called the function would have passed before this change: the
// panic was at the point of USE, not of return. So each body is put to work.
func TestACallThatProducesNoValueIsNull(t *testing.T) {
	bodies := []struct{ what, body string }{
		{"an empty body", ``},
		{"a body ending in a let", `let x = 1;`},
		{"a body that works then lets", `let y = 1; let x = 2;`},
		{"a body ending in a multi-let", `let a, b = 1, 2;`},
	}

	for _, b := range bodies {
		prelude := "let f = fn() { " + b.body + " }; "

		// The call itself.
		if got := testEval(prelude + "f()"); got == nil {
			t.Errorf("%s: the call returned a Go nil, not an object", b.what)
		} else if got.Type() != object.NULL_OBJ {
			t.Errorf("%s: the call returned %s, want NULL", b.what, got.Type())
		}

		// type_of, which panicked inside builtin.TypeOf.
		if got := testEval(prelude + "type_of(f())"); got == nil {
			t.Errorf("%s: type_of panicked or returned nil", b.what)
		} else if str, ok := got.(*object.String); !ok || str.Value != "NULL" {
			t.Errorf("%s: type_of(f()) = %v, want NULL", b.what, got)
		}

		// `!`, which panicked inside evalBangOperatorExpression.
		testBooleanObject(t, testEval(prelude+"!f()"), true)
		testBooleanObject(t, testEval(prelude+"!!f()"), false)

		// Infix, which panicked inside evalInfixExpression.
		testBooleanObject(t, testEval(prelude+"f() == 1"), false)

		// A condition, which did not panic and was simply wrong: nil fell to
		// isTruthy's default arm and was therefore truthy, while the VM called the
		// same call falsy.
		testIntegerObject(t, testEval(prelude+"if (f()) { 1 } else { 0 }"), 0)

		// Bound to a name, and passed to a function.
		testNullObject(t, testEval(prelude+"let v = f(); v"))
		if got := testEval(prelude + "let id = fn(p) { return type_of(p); }; id(f())"); got == nil {
			t.Errorf("%s: passing the value as an argument panicked", b.what)
		} else if str, ok := got.(*object.String); !ok || str.Value != "NULL" {
			t.Errorf("%s: type_of of the argument = %v, want NULL", b.what, got)
		}
	}
}

// A valueless call as a loop condition must not run the body, and must terminate.
//
// In this engine it did neither: nil was truthy, the body could not change that, and
// the loop did not return. A hang in the engine that expands macros is a build that
// never finishes.
func TestAValuelessCallIsNotALoopCondition(t *testing.T) {
	testIntegerObject(t, testEval(
		`let f = fn() { let x = 1; }; let n = 0; while (f()) { n = n + 1; } n`), 0)
}

// A body that DOES produce a value is untouched, which is what keeps the guard from
// being a behaviour change.
func TestABodyThatProducesAValueIsUnchanged(t *testing.T) {
	testIntegerObject(t, testEval(`let f = fn() { 1; }; f()`), 1)
	testIntegerObject(t, testEval(`let f = fn() { return 2; }; f()`), 2)
	testIntegerObject(t, testEval(`let f = fn() { let x = 1; x = 3; }; f()`), 3)
	testIntegerObject(t, testEval(`let f = fn() { if (true) { 4 } }; f()`), 4)
	testNullObject(t, testEval(`let f = fn() { return; }; f()`))
	testNullObject(t, testEval(`let f = fn() { if (false) { 5 } }; f()`))
}

// `!` is the negation of truthiness here too (M26-VM-007), including the two values
// the Inspect comparison got wrong on its own: the empty string, which it answered
// correctly only because null renders the same way, and the string "false".
func TestBangNegatesTruthinessNotRenderedText(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  bool
	}{
		// What the Inspect comparison already answered correctly.
		{"!true", false},
		{"!false", true},
		{"!5", false},
		{`!""`, true},

		// What it did not.
		{"!0", true},
		{"!0.0", true},
		{`let b, e = string_to_bytes("", "raw"); !b`, true},
		{`!"false"`, false},

		// Strings that spell a keyword are strings. "true" and "null" happened to
		// come out right; "false" did not.
		{`!"true"`, false},
		{`!"null"`, false},
		{`!"0"`, false},
		{`!" "`, false},

		// Unchanged.
		{"!1", false},
		{"!1.5", false},
		{`!"a"`, false},
		{"![]", false},
		{"!{}", false},
		{`let b, e = string_to_bytes("ab", "raw"); !b`, false},
	} {
		testBooleanObject(t, testEval(tt.input), tt.want)
	}
}
